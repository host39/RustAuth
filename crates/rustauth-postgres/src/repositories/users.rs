//! `SqlxUserRepository`: accounts, password credentials, and lockout state in `auth.users` and
//! `auth.password_credentials`, plus the lockout state of usernames without an account in
//! `auth.login_failures`.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use rustauth_core::{
    AuthError, AuthResult, DisplayName, Lockout, NewPassword, NewUser, Page, PasswordCredential,
    RegisterPolicy, Reservation, Role, Subject, User, UserId, UserPatch, UserRepository, Username,
};
use sqlx::{PgConnection, PgPool};

use crate::repositories::rows::{AccountRow, LockoutRow, UserRow, lockout_columns, user_columns};
use crate::repositories::shared::{advisory_lock, count, internal, orphaned, violates};

/// The unique index on `lower(username)`.
const USERNAME_INDEX: &str = "users_username_key";

/// [`UserRepository`] on Postgres, with runtime-checked queries (builds never need a database).
///
/// Self-registration and every change the last-administrator guard checks (`update`, `delete`)
/// run in one transaction that first takes a fixed advisory lock, so these decisions are
/// serialized across connections and processes. Lockout steps are single atomic statements.
#[derive(Clone, Debug)]
pub struct SqlxUserRepository {
    pool: PgPool,
}

impl SqlxUserRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Inserts the user with `role` and its password credential on `conn` (inside the caller's
    /// transaction).
    async fn insert(
        conn: &mut PgConnection,
        user: NewUser,
        role: Role,
        credential: NewPassword,
    ) -> AuthResult<User> {
        let row: UserRow = sqlx::query_as(concat!(
            "INSERT INTO auth.users AS u (created_at, updated_at, id, username, display_name, role) ",
            "VALUES ($1, $1, $2, $3, $4, $5) RETURNING ",
            user_columns!()
        ))
        .bind(user.created_at)
        .bind(user.id.as_uuid())
        .bind(user.username.as_str())
        .bind(user.display_name.as_str())
        .bind(role.as_str())
        .fetch_one(&mut *conn)
        .await
        .map_err(|error| {
            if violates(&error, USERNAME_INDEX) {
                AuthError::UsernameTaken
            } else {
                AuthError::internal("rustauth.users.insert.failed", error)
            }
        })?;
        sqlx::query(
            "INSERT INTO auth.password_credentials (changed_at, user_id, hash) VALUES ($1, $2, $3)",
        )
        .bind(credential.changed_at)
        .bind(user.id.as_uuid())
        .bind(&credential.hash)
        .execute(&mut *conn)
        .await
        .map_err(internal("rustauth.users.insert.failed"))?;
        User::try_from(row)
    }

    /// The user with `id`, locked for the rest of the transaction on `conn`.
    async fn locked(
        conn: &mut PgConnection,
        id: UserId,
        key: &'static str,
    ) -> AuthResult<Option<User>> {
        let row: Option<UserRow> = sqlx::query_as(concat!(
            "SELECT ",
            user_columns!(),
            " FROM auth.users u WHERE u.id = $1 FOR UPDATE"
        ))
        .bind(id.as_uuid())
        .fetch_optional(&mut *conn)
        .await
        .map_err(internal(key))?;
        row.map(User::try_from).transpose()
    }

    /// The stored lockout of `subject`, `None` when there is none.
    async fn lockout(&self, subject: &Subject, key: &'static str) -> AuthResult<Option<Lockout>> {
        let row: Option<LockoutRow> = match subject {
            Subject::User(id) => sqlx::query_as(concat!(
                "SELECT ",
                lockout_columns!(),
                " FROM auth.users WHERE id = $1"
            ))
            .bind(id.as_uuid()),
            Subject::Name(name) => sqlx::query_as(concat!(
                "SELECT ",
                lockout_columns!(),
                " FROM auth.login_failures WHERE username = $1"
            ))
            .bind(name.canonical()),
        }
        .fetch_optional(&self.pool)
        .await
        .map_err(internal(key))?;
        row.map(Lockout::try_from).transpose()
    }

    /// Enabled administrators other than `id`, for [`User::ensure_admin_remains`].
    async fn other_admins(
        conn: &mut PgConnection,
        id: UserId,
        key: &'static str,
    ) -> AuthResult<u64> {
        let others: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM auth.users WHERE id <> $1 AND role = $2 AND disabled_at IS NULL",
        )
        .bind(id.as_uuid())
        .bind(Role::Administrator.as_str())
        .fetch_one(&mut *conn)
        .await
        .map_err(internal(key))?;
        Ok(count(others))
    }
}

#[async_trait]
impl UserRepository for SqlxUserRepository {
    async fn register(
        &self,
        user: NewUser,
        credential: NewPassword,
        policy: RegisterPolicy,
    ) -> AuthResult<User> {
        const KEY: &str = "rustauth.users.register.failed";
        let mut tx = self.pool.begin().await.map_err(internal(KEY))?;
        advisory_lock(&mut tx, KEY).await?;
        let existing: i64 = sqlx::query_scalar("SELECT count(*) FROM auth.users")
            .fetch_one(&mut *tx)
            .await
            .map_err(internal(KEY))?;
        let role = policy.decide(count(existing))?;
        let user = Self::insert(&mut tx, user, role, credential).await?;
        tx.commit().await.map_err(internal(KEY))?;
        Ok(user)
    }

    async fn create(&self, user: NewUser, credential: NewPassword) -> AuthResult<User> {
        const KEY: &str = "rustauth.users.create.failed";
        let mut tx = self.pool.begin().await.map_err(internal(KEY))?;
        let role = user.role;
        let user = Self::insert(&mut tx, user, role, credential).await?;
        tx.commit().await.map_err(internal(KEY))?;
        Ok(user)
    }

    async fn get(&self, id: UserId) -> AuthResult<Option<User>> {
        let row: Option<UserRow> = sqlx::query_as(concat!(
            "SELECT ",
            user_columns!(),
            " FROM auth.users u WHERE u.id = $1"
        ))
        .bind(id.as_uuid())
        .fetch_optional(&self.pool)
        .await
        .map_err(internal("rustauth.users.get.failed"))?;
        row.map(User::try_from).transpose()
    }

    async fn get_many(&self, ids: &[UserId]) -> AuthResult<Vec<User>> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let ids: Vec<uuid::Uuid> = ids.iter().map(|id| id.as_uuid()).collect();
        let rows: Vec<UserRow> = sqlx::query_as(concat!(
            "SELECT ",
            user_columns!(),
            " FROM auth.users u WHERE u.id = ANY($1)"
        ))
        .bind(ids)
        .fetch_all(&self.pool)
        .await
        .map_err(internal("rustauth.users.get-many.failed"))?;
        rows.into_iter().map(User::try_from).collect()
    }

    async fn find(
        &self,
        username: &Username,
    ) -> AuthResult<Option<(User, Option<PasswordCredential>)>> {
        let row: Option<AccountRow> = sqlx::query_as(concat!(
            "SELECT ",
            user_columns!(),
            ", c.hash, c.changed_at FROM auth.users u ",
            "LEFT JOIN auth.password_credentials c ON c.user_id = u.id ",
            "WHERE lower(u.username) = $1"
        ))
        .bind(username.canonical())
        .fetch_optional(&self.pool)
        .await
        .map_err(internal("rustauth.users.find.failed"))?;
        row.map(AccountRow::decode).transpose()
    }

    async fn list(&self, page: Page) -> AuthResult<(Vec<User>, u64)> {
        let offset = i64::try_from(page.offset()).unwrap_or(i64::MAX);
        let rows = sqlx::query_as::<_, UserRow>(concat!(
            "SELECT ",
            user_columns!(),
            " FROM auth.users u ORDER BY lower(u.username), u.id LIMIT $1 OFFSET $2"
        ))
        .bind(i64::from(page.limit()))
        .bind(offset);
        let total = sqlx::query_scalar::<_, i64>("SELECT count(*) FROM auth.users");
        let (rows, total) =
            tokio::try_join!(rows.fetch_all(&self.pool), total.fetch_one(&self.pool))
                .map_err(internal("rustauth.users.list.failed"))?;
        let users = rows
            .into_iter()
            .map(User::try_from)
            .collect::<AuthResult<_>>()?;
        Ok((users, count(total)))
    }

    async fn update(&self, id: UserId, patch: &UserPatch, at: DateTime<Utc>) -> AuthResult<User> {
        const KEY: &str = "rustauth.users.update.failed";
        let mut tx = self.pool.begin().await.map_err(internal(KEY))?;
        advisory_lock(&mut tx, KEY).await?;
        let user = Self::locked(&mut tx, id, KEY)
            .await?
            .ok_or_else(|| AuthError::not_found("User"))?;
        let next = user.patched(patch, at);
        let others = Self::other_admins(&mut tx, id, KEY).await?;
        user.ensure_admin_remains(Some(&next), others)?;
        // Only what `patch` sets is written: a stored value this release reads leniently (a role
        // from a newer release reads as `user`) stays as stored unless the patch replaces it.
        let row: UserRow = sqlx::query_as(concat!(
            "UPDATE auth.users AS u SET display_name = COALESCE($2, u.display_name), ",
            "role = COALESCE($3, u.role), disabled_at = $4, updated_at = $5 ",
            "WHERE u.id = $1 RETURNING ",
            user_columns!()
        ))
        .bind(id.as_uuid())
        .bind(patch.display_name.as_ref().map(DisplayName::as_str))
        .bind(patch.role.map(|role| role.as_str()))
        .bind(next.disabled_at)
        .bind(next.updated_at)
        .fetch_one(&mut *tx)
        .await
        .map_err(internal(KEY))?;
        tx.commit().await.map_err(internal(KEY))?;
        User::try_from(row)
    }

    async fn delete(&self, id: UserId) -> AuthResult<bool> {
        const KEY: &str = "rustauth.users.delete.failed";
        let mut tx = self.pool.begin().await.map_err(internal(KEY))?;
        advisory_lock(&mut tx, KEY).await?;
        let Some(user) = Self::locked(&mut tx, id, KEY).await? else {
            return Ok(false);
        };
        let others = Self::other_admins(&mut tx, id, KEY).await?;
        user.ensure_admin_remains(None, others)?;
        // The credential and sessions go with it (ON DELETE CASCADE). An application reference
        // without CASCADE or SET NULL refuses the delete, at once or (deferred) at commit.
        let in_use = |error: sqlx::Error| {
            if orphaned(&error) {
                AuthError::UserInUse
            } else {
                AuthError::internal(KEY, error)
            }
        };
        sqlx::query("DELETE FROM auth.users WHERE id = $1")
            .bind(id.as_uuid())
            .execute(&mut *tx)
            .await
            .map_err(in_use)?;
        tx.commit().await.map_err(in_use)?;
        Ok(true)
    }

    async fn count(&self) -> AuthResult<u64> {
        let total: i64 = sqlx::query_scalar("SELECT count(*) FROM auth.users")
            .fetch_one(&self.pool)
            .await
            .map_err(internal("rustauth.users.count.failed"))?;
        Ok(count(total))
    }

    async fn set_password(&self, user: UserId, hash: String, at: DateTime<Utc>) -> AuthResult<()> {
        let result = sqlx::query(concat!(
            "INSERT INTO auth.password_credentials (changed_at, user_id, hash) ",
            "SELECT $1, id, $3 FROM auth.users WHERE id = $2 ",
            "ON CONFLICT (user_id) DO UPDATE SET changed_at = EXCLUDED.changed_at, hash = EXCLUDED.hash"
        ))
        .bind(at)
        .bind(user.as_uuid())
        .bind(hash)
        .execute(&self.pool)
        .await;
        match result {
            Ok(done) if done.rows_affected() > 0 => Ok(()),
            Ok(_) => Err(AuthError::not_found("User")),
            // Deleted between the SELECT and the INSERT.
            Err(error) if orphaned(&error) => Err(AuthError::not_found("User")),
            Err(error) => Err(AuthError::internal(
                "rustauth.users.set-password.failed",
                error,
            )),
        }
    }

    /// [`Lockout::reserve`] in one statement: an `UPDATE` of the account, or an upsert of the
    /// username's row in `auth.login_failures`, whose `WHERE` repeats the refusal rule.
    /// Concurrent attempts queue on the row lock and each one re-checks the rule against the
    /// row as the previous one left it, so no more checks pass than the threshold allows.
    async fn reserve(
        &self,
        subject: &Subject,
        at: DateTime<Utc>,
        since: DateTime<Utc>,
        threshold: u32,
    ) -> AuthResult<Reservation> {
        const KEY: &str = "rustauth.users.reserve.failed";
        let threshold = i32::try_from(threshold).unwrap_or(i32::MAX);
        let granted: Option<LockoutRow> =
            match subject {
                Subject::User(id) => {
                    sqlx::query_as(concat!(
                        "UPDATE auth.users SET failed_login_count = CASE ",
                        "WHEN last_failed_login_at IS NULL OR last_failed_login_at < $3 THEN 1 ",
                        "ELSE failed_login_count + 1 END, last_failed_login_at = $2 ",
                        "WHERE id = $1 AND (locked_until IS NULL OR locked_until <= $2) ",
                        "AND (last_failed_login_at IS NULL OR last_failed_login_at < $3 ",
                        "OR failed_login_count < $4) RETURNING ",
                        lockout_columns!()
                    ))
                    .bind(id.as_uuid())
                    .bind(at)
                    .bind(since)
                    .bind(threshold)
                    .fetch_optional(&self.pool)
                    .await
                }
                Subject::Name(name) => sqlx::query_as(concat!(
                    "INSERT INTO auth.login_failures AS f ",
                    "(last_failed_login_at, failed_login_count, username) VALUES ($2, 1, $1) ",
                    "ON CONFLICT (username) DO UPDATE SET failed_login_count = CASE ",
                    "WHEN f.last_failed_login_at IS NULL OR f.last_failed_login_at < $3 THEN 1 ",
                    "ELSE f.failed_login_count + 1 END, last_failed_login_at = $2 ",
                    "WHERE (f.locked_until IS NULL OR f.locked_until <= $2) ",
                    "AND (f.last_failed_login_at IS NULL OR f.last_failed_login_at < $3 ",
                    "OR f.failed_login_count < $4) RETURNING ",
                    lockout_columns!()
                ))
                .bind(name.canonical())
                .bind(at)
                .bind(since)
                .bind(threshold)
                .fetch_optional(&self.pool)
                .await,
            }
            .map_err(internal(KEY))?;
        if let Some(row) = granted {
            return Ok(Reservation::Granted(Lockout::try_from(row)?));
        }
        match (self.lockout(subject, KEY).await?, subject) {
            (Some(stored), _) => Ok(Reservation::Refused(stored)),
            (None, Subject::User(_)) => Err(AuthError::not_found("User")),
            // Only a refused upsert returns no row, and it leaves the row in place.
            (None, Subject::Name(_)) => Ok(Reservation::Refused(Lockout::default())),
        }
    }

    /// [`Lockout::lock`], applied only while the row still [`Lockout::holds`] `seen`: the same
    /// lockout counter and at least the failures `seen` counted.
    async fn lock(
        &self,
        subject: &Subject,
        seen: Lockout,
        until: DateTime<Utc>,
    ) -> AuthResult<bool> {
        let (Ok(lockouts), Ok(failures)) = (
            i32::try_from(seen.lockouts),
            i32::try_from(seen.failed_count),
        ) else {
            // The stored counters are `integer`s, so they cannot hold these values.
            return Ok(false);
        };
        let done = match subject {
            Subject::User(id) => sqlx::query(concat!(
                "UPDATE auth.users SET failed_login_count = 0, ",
                "lockout_count = lockout_count + 1, locked_until = $2 ",
                "WHERE id = $1 AND lockout_count = $3 AND failed_login_count >= $4"
            ))
            .bind(id.as_uuid()),
            Subject::Name(name) => sqlx::query(concat!(
                "UPDATE auth.login_failures SET failed_login_count = 0, ",
                "lockout_count = lockout_count + 1, locked_until = $2 ",
                "WHERE username = $1 AND lockout_count = $3 AND failed_login_count >= $4"
            ))
            .bind(name.canonical()),
        }
        .bind(until)
        .bind(lockouts)
        .bind(failures)
        .execute(&self.pool)
        .await
        .map_err(internal("rustauth.users.lock.failed"))?;
        Ok(done.rows_affected() > 0)
    }

    /// Resets the account's columns, or deletes the username's row, in one statement that
    /// leaves a locked subject alone.
    async fn clear(&self, subject: &Subject, at: DateTime<Utc>) -> AuthResult<Option<Lockout>> {
        const KEY: &str = "rustauth.users.clear.failed";
        let done = match subject {
            Subject::User(id) => sqlx::query(concat!(
                "UPDATE auth.users SET failed_login_count = 0, lockout_count = 0, ",
                "last_failed_login_at = NULL, locked_until = NULL ",
                "WHERE id = $1 AND (locked_until IS NULL OR locked_until <= $2)"
            ))
            .bind(id.as_uuid()),
            Subject::Name(name) => sqlx::query(concat!(
                "DELETE FROM auth.login_failures ",
                "WHERE username = $1 AND (locked_until IS NULL OR locked_until <= $2)"
            ))
            .bind(name.canonical()),
        }
        .bind(at)
        .execute(&self.pool)
        .await
        .map_err(internal(KEY))?;
        if done.rows_affected() > 0 {
            return Ok(None);
        }
        match (self.lockout(subject, KEY).await?, subject) {
            (None, Subject::User(_)) => Err(AuthError::not_found("User")),
            (stored, _) => Ok(stored),
        }
    }

    async fn unlock(&self, user: UserId) -> AuthResult<()> {
        let done = sqlx::query(concat!(
            "UPDATE auth.users SET failed_login_count = 0, lockout_count = 0, ",
            "last_failed_login_at = NULL, locked_until = NULL WHERE id = $1"
        ))
        .bind(user.as_uuid())
        .execute(&self.pool)
        .await
        .map_err(internal("rustauth.users.unlock.failed"))?;
        if done.rows_affected() == 0 {
            return Err(AuthError::not_found("User"));
        }
        Ok(())
    }

    async fn prune(&self, since: DateTime<Utc>) -> AuthResult<u64> {
        let done = sqlx::query(concat!(
            "DELETE FROM auth.login_failures WHERE lockout_count = 0 AND locked_until IS NULL ",
            "AND (last_failed_login_at IS NULL OR last_failed_login_at < $1)"
        ))
        .bind(since)
        .execute(&self.pool)
        .await
        .map_err(internal("rustauth.users.prune.failed"))?;
        Ok(done.rows_affected())
    }
}
