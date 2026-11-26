//! Row types and their conversion into core entities.
//!
//! Stored values are read leniently, with the `stored` constructors of core: a newer release on
//! the same schema may write values this one does not know (a new sign-in method or assurance
//! level, a new role, relaxed username rules), and a rolling deploy or a rollback must keep
//! working on them. Unknown methods are skipped, an unknown assurance level reads as the lowest,
//! and an unknown role as `user` (the least privilege). Only values no release writes, such as a
//! malformed token hash or address, fail with `rustauth.users.decode.failed` or
//! `rustauth.sessions.decode.failed`.

use std::net::IpAddr;

use chrono::{DateTime, Utc};
use rustauth_core::{
    Assurance, AuthError, AuthMethod, AuthResult, BoxError, DisplayName, Lockout,
    PasswordCredential, Role, Session, TokenHash, User, UserId, Username,
};
use uuid::Uuid;

/// The `auth.users` columns that [`UserRow`] reads, for a query that names the table `u`.
macro_rules! user_columns {
    () => {
        "u.id, u.username, u.display_name, u.role, u.disabled_at, u.created_at, u.updated_at, \
         u.failed_login_count, u.lockout_count, u.last_failed_login_at, u.locked_until"
    };
}
pub(crate) use user_columns;

/// The lockout columns, which `auth.users` and `auth.login_failures` share ([`LockoutRow`]).
macro_rules! lockout_columns {
    () => {
        "failed_login_count, lockout_count, last_failed_login_at, locked_until"
    };
}
pub(crate) use lockout_columns;

/// The `auth.sessions` columns that [`SessionRow`] reads, for a query that names the table `s`.
/// Aliased so they can sit next to [`user_columns`] in one joined row.
macro_rules! session_columns {
    () => {
        "s.id AS session_id, s.user_id AS session_user_id, s.token_hash, s.methods, \
         s.assurance, s.created_at AS session_created_at, s.last_used_at, s.expires_at, \
         s.user_agent, host(s.ip) AS ip"
    };
}
pub(crate) use session_columns;

fn user_error(error: impl Into<BoxError>) -> AuthError {
    AuthError::internal("rustauth.users.decode.failed", error)
}

fn session_error(error: impl Into<BoxError>) -> AuthError {
    AuthError::internal("rustauth.sessions.decode.failed", error)
}

/// The lockout columns of `auth.users` or `auth.login_failures` ([`lockout_columns`]).
#[derive(sqlx::FromRow)]
pub(crate) struct LockoutRow {
    failed_login_count: i32,
    lockout_count: i32,
    last_failed_login_at: Option<DateTime<Utc>>,
    locked_until: Option<DateTime<Utc>>,
}

impl TryFrom<LockoutRow> for Lockout {
    type Error = AuthError;

    fn try_from(row: LockoutRow) -> AuthResult<Self> {
        Ok(Self {
            failed_count: u32::try_from(row.failed_login_count).map_err(user_error)?,
            lockouts: u32::try_from(row.lockout_count).map_err(user_error)?,
            last_failed_at: row.last_failed_login_at,
            locked_until: row.locked_until,
        })
    }
}

/// One `auth.users` row ([`user_columns`]).
#[derive(sqlx::FromRow)]
pub(crate) struct UserRow {
    id: Uuid,
    username: String,
    display_name: String,
    role: String,
    disabled_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    #[sqlx(flatten)]
    lockout: LockoutRow,
}

impl TryFrom<UserRow> for User {
    type Error = AuthError;

    fn try_from(row: UserRow) -> AuthResult<Self> {
        Ok(Self {
            id: UserId::from(row.id),
            username: Username::stored(row.username),
            display_name: DisplayName::stored(row.display_name),
            role: Role::stored(&row.role),
            disabled_at: row.disabled_at,
            created_at: row.created_at,
            updated_at: row.updated_at,
            lockout: Lockout::try_from(row.lockout)?,
        })
    }
}

/// A user with the columns of its password credential, if it has one (a `LEFT JOIN`).
#[derive(sqlx::FromRow)]
pub(crate) struct AccountRow {
    #[sqlx(flatten)]
    user: UserRow,
    hash: Option<String>,
    changed_at: Option<DateTime<Utc>>,
}

impl AccountRow {
    pub(crate) fn decode(self) -> AuthResult<(User, Option<PasswordCredential>)> {
        let user = User::try_from(self.user)?;
        let credential = match (self.hash, self.changed_at) {
            (Some(hash), Some(changed_at)) => Some(PasswordCredential {
                user_id: user.id,
                hash,
                changed_at,
            }),
            _ => None,
        };
        Ok((user, credential))
    }
}

/// One `auth.sessions` row ([`session_columns`]).
#[derive(sqlx::FromRow)]
pub(crate) struct SessionRow {
    #[sqlx(rename = "session_id")]
    id: Uuid,
    #[sqlx(rename = "session_user_id")]
    user_id: Uuid,
    token_hash: Vec<u8>,
    methods: Vec<String>,
    assurance: String,
    #[sqlx(rename = "session_created_at")]
    created_at: DateTime<Utc>,
    last_used_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    user_agent: String,
    /// `host(ip)`: the address as text, without a prefix length.
    ip: Option<String>,
}

impl TryFrom<SessionRow> for Session {
    type Error = AuthError;

    fn try_from(row: SessionRow) -> AuthResult<Self> {
        let methods = row
            .methods
            .iter()
            .filter_map(|method| AuthMethod::stored(method))
            .collect();
        let ip = row
            .ip
            .as_deref()
            .map(str::parse::<IpAddr>)
            .transpose()
            .map_err(session_error)?;
        Ok(Self {
            id: row.id.into(),
            user_id: row.user_id.into(),
            token_hash: TokenHash::try_from(row.token_hash.as_slice()).map_err(session_error)?,
            methods,
            assurance: Assurance::stored(&row.assurance),
            created_at: row.created_at,
            last_used_at: row.last_used_at,
            expires_at: row.expires_at,
            user_agent: row.user_agent,
            ip,
        })
    }
}

/// A session joined with its user ([`session_columns`] plus [`user_columns`]).
#[derive(sqlx::FromRow)]
pub(crate) struct SignedInRow {
    #[sqlx(flatten)]
    session: SessionRow,
    #[sqlx(flatten)]
    user: UserRow,
}

impl SignedInRow {
    pub(crate) fn decode(self) -> AuthResult<(Session, User)> {
        Ok((Session::try_from(self.session)?, User::try_from(self.user)?))
    }
}
