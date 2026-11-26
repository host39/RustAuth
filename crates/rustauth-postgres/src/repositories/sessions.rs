//! `SqlxSessionRepository`: signed-in devices in `auth.sessions`, looked up by token hash.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use rustauth_core::{
    AuthError, AuthResult, Session, SessionId, SessionRepository, TokenHash, User, UserId,
};
use sqlx::PgPool;

use crate::repositories::rows::{SessionRow, SignedInRow, session_columns, user_columns};
use crate::repositories::shared::{internal, orphaned};

/// [`SessionRepository`] on Postgres, with runtime-checked queries (builds never need a
/// database). `find` runs on every authenticated request: one indexed lookup by token hash,
/// joined with the user.
#[derive(Clone, Debug)]
pub struct SqlxSessionRepository {
    pool: PgPool,
}

impl SqlxSessionRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl SessionRepository for SqlxSessionRepository {
    /// Fails with `NotFound` when the user no longer exists.
    async fn insert(&self, session: &Session) -> AuthResult<()> {
        let methods: Vec<&str> = session
            .methods
            .iter()
            .map(|method| method.as_str())
            .collect();
        sqlx::query(concat!(
            "INSERT INTO auth.sessions (created_at, last_used_at, expires_at, id, user_id, ",
            "token_hash, assurance, ip, user_agent, methods) ",
            "VALUES ($1, $2, $3, $4, $5, $6, $7, $8::inet, $9, $10)"
        ))
        .bind(session.created_at)
        .bind(session.last_used_at)
        .bind(session.expires_at)
        .bind(session.id.as_uuid())
        .bind(session.user_id.as_uuid())
        .bind(session.token_hash.as_bytes().as_slice())
        .bind(session.assurance.as_str())
        .bind(session.ip.map(|ip| ip.to_string()))
        .bind(&session.user_agent)
        .bind(methods)
        .execute(&self.pool)
        .await
        .map_err(|error| {
            if orphaned(&error) {
                AuthError::not_found("User")
            } else {
                AuthError::internal("rustauth.sessions.insert.failed", error)
            }
        })?;
        Ok(())
    }

    async fn find(&self, hash: &TokenHash) -> AuthResult<Option<(Session, User)>> {
        let row: Option<SignedInRow> = sqlx::query_as(concat!(
            "SELECT ",
            session_columns!(),
            ", ",
            user_columns!(),
            " FROM auth.sessions s JOIN auth.users u ON u.id = s.user_id WHERE s.token_hash = $1"
        ))
        .bind(hash.as_bytes().as_slice())
        .fetch_optional(&self.pool)
        .await
        .map_err(internal("rustauth.sessions.find.failed"))?;
        row.map(SignedInRow::decode).transpose()
    }

    async fn touch(
        &self,
        id: SessionId,
        last_used_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    ) -> AuthResult<()> {
        sqlx::query("UPDATE auth.sessions SET last_used_at = $2, expires_at = $3 WHERE id = $1")
            .bind(id.as_uuid())
            .bind(last_used_at)
            .bind(expires_at)
            .execute(&self.pool)
            .await
            .map_err(internal("rustauth.sessions.touch.failed"))?;
        Ok(())
    }

    /// Oldest first.
    async fn list(&self, user: UserId) -> AuthResult<Vec<Session>> {
        let rows: Vec<SessionRow> = sqlx::query_as(concat!(
            "SELECT ",
            session_columns!(),
            " FROM auth.sessions s WHERE s.user_id = $1 ORDER BY s.created_at, s.id"
        ))
        .bind(user.as_uuid())
        .fetch_all(&self.pool)
        .await
        .map_err(internal("rustauth.sessions.list.failed"))?;
        rows.into_iter().map(Session::try_from).collect()
    }

    async fn delete(&self, user: UserId, id: SessionId) -> AuthResult<bool> {
        let done = sqlx::query("DELETE FROM auth.sessions WHERE id = $1 AND user_id = $2")
            .bind(id.as_uuid())
            .bind(user.as_uuid())
            .execute(&self.pool)
            .await
            .map_err(internal("rustauth.sessions.delete.failed"))?;
        Ok(done.rows_affected() > 0)
    }

    async fn delete_all(&self, user: UserId, except: Option<SessionId>) -> AuthResult<u64> {
        let done = sqlx::query(
            "DELETE FROM auth.sessions WHERE user_id = $1 AND ($2::uuid IS NULL OR id <> $2)",
        )
        .bind(user.as_uuid())
        .bind(except.map(|id| id.as_uuid()))
        .execute(&self.pool)
        .await
        .map_err(internal("rustauth.sessions.delete-all.failed"))?;
        Ok(done.rows_affected())
    }

    async fn purge_expired(&self, before: DateTime<Utc>) -> AuthResult<u64> {
        let done = sqlx::query("DELETE FROM auth.sessions WHERE expires_at <= $1")
            .bind(before)
            .execute(&self.pool)
            .await
            .map_err(internal("rustauth.sessions.purge.failed"))?;
        Ok(done.rows_affected())
    }
}
