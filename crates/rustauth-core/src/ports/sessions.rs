//! `SessionRepository`: signed-in devices, looked up by token hash.

use async_trait::async_trait;
use chrono::{DateTime, Utc};

use crate::entities::{Session, User};
use crate::error::AuthResult;
use crate::values::{SessionId, TokenHash, UserId};

#[async_trait]
pub trait SessionRepository: Send + Sync {
    async fn insert(&self, session: &Session) -> AuthResult<()>;

    /// The session with this token hash and its user (one joined query, on every authenticated
    /// request). `None` when either is missing.
    async fn find(&self, hash: &TokenHash) -> AuthResult<Option<(Session, User)>>;

    /// Moves `last_used_at` and `expires_at` forward.
    async fn touch(
        &self,
        id: SessionId,
        last_used_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    ) -> AuthResult<()>;

    /// Every stored session of the user, expired ones included.
    async fn list(&self, user: UserId) -> AuthResult<Vec<Session>>;

    /// Deletes one session of the user; `false` when it does not exist or belongs to someone
    /// else.
    async fn delete(&self, user: UserId, id: SessionId) -> AuthResult<bool>;

    /// Deletes every session of the user except `except`; returns how many were deleted.
    async fn delete_all(&self, user: UserId, except: Option<SessionId>) -> AuthResult<u64>;

    /// Deletes sessions whose `expires_at` is at or before `before`; returns how many.
    async fn purge_expired(&self, before: DateTime<Utc>) -> AuthResult<u64>;
}
