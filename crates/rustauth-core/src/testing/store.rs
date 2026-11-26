//! `MemoryStore`: both repositories over one in-memory state, with the same rules as the
//! Postgres adapter (case-insensitive usernames, registration decided under the lock, the
//! last-administrator guard, cascading deletes, and atomic lockout updates).

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};

use async_trait::async_trait;
use chrono::{DateTime, Utc};

use crate::entities::{
    Lockout, NewPassword, NewUser, PasswordCredential, RegisterPolicy, Session, User, UserPatch,
};
use crate::error::{AuthError, AuthResult};
use crate::ports::{SessionRepository, UserRepository};
use crate::values::{Page, Role, SessionId, TokenHash, UserId, Username};

#[derive(Debug, Default)]
struct State {
    users: HashMap<UserId, User>,
    credentials: HashMap<UserId, PasswordCredential>,
    sessions: HashMap<SessionId, Session>,
}

impl State {
    fn user(&mut self, id: UserId) -> AuthResult<&mut User> {
        self.users.get_mut(&id).ok_or(AuthError::not_found("User"))
    }

    /// Enabled administrators other than `id`.
    fn other_admins(&self, id: UserId) -> u64 {
        self.users
            .values()
            .filter(|user| user.id != id && user.is_active_administrator())
            .count() as u64
    }

    fn insert(&mut self, user: NewUser, role: Role, credential: NewPassword) -> AuthResult<User> {
        let canonical = user.username.canonical();
        if self
            .users
            .values()
            .any(|existing| existing.username.canonical() == canonical)
        {
            return Err(AuthError::UsernameTaken);
        }
        let user = User {
            id: user.id,
            username: user.username,
            display_name: user.display_name,
            role,
            disabled_at: None,
            created_at: user.created_at,
            updated_at: user.created_at,
            lockout: Lockout::default(),
        };
        self.credentials.insert(
            user.id,
            PasswordCredential {
                user_id: user.id,
                hash: credential.hash,
                changed_at: credential.changed_at,
            },
        );
        self.users.insert(user.id, user.clone());
        Ok(user)
    }
}

/// Implements `UserRepository` and `SessionRepository` over one shared state, the way the
/// Postgres adapter shares one database. One mutex serializes every call, which stands in for
/// the advisory lock and transactions.
#[derive(Debug, Default)]
pub struct MemoryStore {
    state: Mutex<State>,
    failing: AtomicBool,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// While on, every call fails with an internal error, as if the database were down.
    pub fn set_failing(&self, failing: bool) {
        self.failing.store(failing, Ordering::SeqCst);
    }

    /// Every stored session, for assertions.
    pub fn all_sessions(&self) -> Vec<Session> {
        self.state().sessions.values().cloned().collect()
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Locks the state, or fails while `set_failing(true)` is on.
    fn open(&self) -> AuthResult<MutexGuard<'_, State>> {
        if self.failing.load(Ordering::SeqCst) {
            return Err(AuthError::internal(
                "rustauth.memory.unavailable",
                "the store is set to fail",
            ));
        }
        Ok(self.state())
    }
}

#[async_trait]
impl UserRepository for MemoryStore {
    async fn register(
        &self,
        user: NewUser,
        credential: NewPassword,
        policy: RegisterPolicy,
    ) -> AuthResult<User> {
        let mut state = self.open()?;
        let role = policy.decide(state.users.len() as u64)?;
        state.insert(user, role, credential)
    }

    async fn create(&self, user: NewUser, credential: NewPassword) -> AuthResult<User> {
        let role = user.role;
        self.open()?.insert(user, role, credential)
    }

    async fn get(&self, id: UserId) -> AuthResult<Option<User>> {
        Ok(self.open()?.users.get(&id).cloned())
    }

    async fn find(
        &self,
        username: &Username,
    ) -> AuthResult<Option<(User, Option<PasswordCredential>)>> {
        let state = self.open()?;
        let canonical = username.canonical();
        Ok(state
            .users
            .values()
            .find(|user| user.username.canonical() == canonical)
            .map(|user| (user.clone(), state.credentials.get(&user.id).cloned())))
    }

    async fn list(&self, page: Page) -> AuthResult<(Vec<User>, u64)> {
        let state = self.open()?;
        let mut users: Vec<User> = state.users.values().cloned().collect();
        users.sort_by_key(|user| (user.username.canonical(), user.id));
        let total = users.len() as u64;
        let items = users
            .into_iter()
            .skip(usize::try_from(page.offset()).unwrap_or(usize::MAX))
            .take(page.limit() as usize)
            .collect();
        Ok((items, total))
    }

    async fn update(&self, id: UserId, patch: &UserPatch, at: DateTime<Utc>) -> AuthResult<User> {
        let mut state = self.open()?;
        let others = state.other_admins(id);
        let user = state.user(id)?;
        let updated = user.patched(patch, at);
        user.ensure_admin_remains(Some(&updated), others)?;
        *user = updated.clone();
        Ok(updated)
    }

    async fn delete(&self, id: UserId) -> AuthResult<bool> {
        let mut state = self.open()?;
        let others = state.other_admins(id);
        let Some(user) = state.users.get(&id) else {
            return Ok(false);
        };
        user.ensure_admin_remains(None, others)?;
        state.users.remove(&id);
        state.credentials.remove(&id);
        state.sessions.retain(|_, session| session.user_id != id);
        Ok(true)
    }

    async fn count(&self) -> AuthResult<u64> {
        Ok(self.open()?.users.len() as u64)
    }

    async fn set_password(&self, user: UserId, hash: String, at: DateTime<Utc>) -> AuthResult<()> {
        let mut state = self.open()?;
        state.user(user)?;
        state.credentials.insert(
            user,
            PasswordCredential {
                user_id: user,
                hash,
                changed_at: at,
            },
        );
        Ok(())
    }

    async fn record_failure(
        &self,
        user: UserId,
        at: DateTime<Utc>,
        since: DateTime<Utc>,
    ) -> AuthResult<Lockout> {
        let mut state = self.open()?;
        let user = state.user(user)?;
        user.lockout = user.lockout.fail(at, since);
        Ok(user.lockout)
    }

    async fn lock(&self, user: UserId, until: DateTime<Utc>, lockouts: u32) -> AuthResult<bool> {
        let mut state = self.open()?;
        let user = state.user(user)?;
        if user.lockout.lockouts != lockouts {
            return Ok(false);
        }
        user.lockout = user.lockout.lock(until);
        Ok(true)
    }

    async fn unlock(&self, user: UserId) -> AuthResult<()> {
        let mut state = self.open()?;
        state.user(user)?.lockout = Lockout::default();
        Ok(())
    }
}

#[async_trait]
impl SessionRepository for MemoryStore {
    async fn insert(&self, session: &Session) -> AuthResult<()> {
        let mut state = self.open()?;
        if state
            .sessions
            .values()
            .any(|existing| existing.token_hash == session.token_hash)
        {
            return Err(AuthError::internal(
                "rustauth.sessions.insert.failed",
                "duplicate token hash",
            ));
        }
        state.sessions.insert(session.id, session.clone());
        Ok(())
    }

    async fn find(&self, hash: &TokenHash) -> AuthResult<Option<(Session, User)>> {
        let state = self.open()?;
        Ok(state
            .sessions
            .values()
            .find(|session| session.token_hash == *hash)
            .and_then(|session| {
                state
                    .users
                    .get(&session.user_id)
                    .map(|user| (session.clone(), user.clone()))
            }))
    }

    async fn touch(
        &self,
        id: SessionId,
        last_used_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    ) -> AuthResult<()> {
        let mut state = self.open()?;
        if let Some(session) = state.sessions.get_mut(&id) {
            session.last_used_at = last_used_at;
            session.expires_at = expires_at;
        }
        Ok(())
    }

    async fn list(&self, user: UserId) -> AuthResult<Vec<Session>> {
        let state = self.open()?;
        Ok(state
            .sessions
            .values()
            .filter(|session| session.user_id == user)
            .cloned()
            .collect())
    }

    async fn delete(&self, user: UserId, id: SessionId) -> AuthResult<bool> {
        let mut state = self.open()?;
        let owned = state
            .sessions
            .get(&id)
            .is_some_and(|session| session.user_id == user);
        if owned {
            state.sessions.remove(&id);
        }
        Ok(owned)
    }

    async fn delete_all(&self, user: UserId, except: Option<SessionId>) -> AuthResult<u64> {
        let mut state = self.open()?;
        let before = state.sessions.len();
        state
            .sessions
            .retain(|id, session| session.user_id != user || Some(*id) == except);
        Ok((before - state.sessions.len()) as u64)
    }

    async fn purge_expired(&self, before: DateTime<Utc>) -> AuthResult<u64> {
        let mut state = self.open()?;
        let count = state.sessions.len();
        state
            .sessions
            .retain(|_, session| session.expires_at > before);
        Ok((count - state.sessions.len()) as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::values::DisplayName;

    fn new_user(username: &str) -> NewUser {
        NewUser {
            id: UserId::generate(),
            username: Username::new(username).expect("valid"),
            display_name: DisplayName::new(username).expect("valid"),
            role: Role::Manager,
            created_at: DateTime::UNIX_EPOCH,
        }
    }

    fn password() -> NewPassword {
        NewPassword {
            hash: "fake$password".to_owned(),
            changed_at: DateTime::UNIX_EPOCH,
        }
    }

    /// What a service decides while it still sees zero users.
    const STALE_FIRST: RegisterPolicy = RegisterPolicy {
        registration_open: false,
        setup_token_ok: true,
    };

    #[tokio::test]
    async fn decides_the_first_administrator_under_its_lock() {
        let store = MemoryStore::new();
        let first = store
            .register(new_user("alice"), password(), STALE_FIRST)
            .await
            .expect("first");
        assert_eq!(first.role, Role::Administrator);
        // A second caller that also saw zero users, with the right setup token, is refused.
        let second = store
            .register(new_user("bob"), password(), STALE_FIRST)
            .await
            .expect_err("closed");
        assert!(matches!(second, AuthError::RegistrationClosed));
        // With open registration it becomes a plain user, never a second administrator.
        let open = RegisterPolicy {
            registration_open: true,
            ..STALE_FIRST
        };
        let third = store
            .register(new_user("carol"), password(), open)
            .await
            .expect("open");
        assert_eq!(third.role, Role::User);
    }

    #[tokio::test]
    async fn compares_usernames_case_insensitively() {
        let store = MemoryStore::new();
        store
            .create(new_user("Alice"), password())
            .await
            .expect("created");
        let duplicate = store
            .create(new_user("aLiCe"), password())
            .await
            .expect_err("taken");
        assert!(matches!(duplicate, AuthError::UsernameTaken));
        let username = Username::new("ALICE").expect("valid");
        let (user, credential) = UserRepository::find(&store, &username)
            .await
            .expect("found")
            .expect("exists");
        assert_eq!(user.username.as_str(), "Alice");
        assert!(credential.is_some());
    }

    #[tokio::test]
    async fn locks_once_for_concurrent_failures() {
        let store = MemoryStore::new();
        let user = store
            .create(new_user("alice"), password())
            .await
            .expect("created");
        let until = DateTime::UNIX_EPOCH;
        assert!(store.lock(user.id, until, 0).await.expect("locked"));
        // A second failure that also decided on `lockouts == 0` does not lock again.
        assert!(!store.lock(user.id, until, 0).await.expect("not locked"));
        let stored = store.get(user.id).await.expect("read").expect("exists");
        assert_eq!(stored.lockout.lockouts, 1);
    }

    #[tokio::test]
    async fn fails_while_set_failing() {
        let store = MemoryStore::new();
        store.set_failing(true);
        let error = store.count().await.expect_err("failing");
        assert_eq!(error.code(), "INTERNAL_ERROR");
        store.set_failing(false);
        assert_eq!(store.count().await.expect("works"), 0);
    }
}
