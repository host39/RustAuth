//! `UserRepository`: accounts, their password credentials, and their lockout state.

use async_trait::async_trait;
use chrono::{DateTime, Utc};

use crate::entities::{
    Lockout, NewPassword, NewUser, PasswordCredential, RegisterPolicy, Reservation, Subject, User,
    UserPatch,
};
use crate::error::AuthResult;
use crate::values::{Page, UserId, Username};

/// Storage for accounts. Usernames are unique case-insensitively ([`Username::canonical`]);
/// inserting a duplicate fails with `AuthError::UsernameTaken`.
#[async_trait]
pub trait UserRepository: Send + Sync {
    /// Self-registration, in one transaction: take a fixed advisory lock, count users, call
    /// [`RegisterPolicy::decide`] with that count, and insert the user with the decided role
    /// (`user.role` is ignored) plus the credential. Because the decision is made inside the
    /// lock, two concurrent first registrations produce exactly one administrator; the other
    /// fails with `SetupRequired` or `RegistrationClosed`, or becomes a plain user.
    async fn register(
        &self,
        user: NewUser,
        credential: NewPassword,
        policy: RegisterPolicy,
    ) -> AuthResult<User>;

    /// An account created by an administrator, with `user.role`.
    async fn create(&self, user: NewUser, credential: NewPassword) -> AuthResult<User>;

    async fn get(&self, id: UserId) -> AuthResult<Option<User>>;

    /// The account and its password credential (if any), matched case-insensitively.
    async fn find(
        &self,
        username: &Username,
    ) -> AuthResult<Option<(User, Option<PasswordCredential>)>>;

    /// A page of accounts ordered by lowercase username, plus the total count.
    async fn list(&self, page: Page) -> AuthResult<(Vec<User>, u64)>;

    /// Applies `patch` at `at` and returns the updated user, in one transaction that loads the
    /// row, counts the other enabled administrators, and calls [`User::ensure_admin_remains`]
    /// (`AuthError::LastAdministrator`). Concurrent guard checks must be serialized (the
    /// Postgres adapter takes the same advisory lock as `register`). `NotFound` when missing.
    async fn update(&self, id: UserId, patch: &UserPatch, at: DateTime<Utc>) -> AuthResult<User>;

    /// Deletes the user with its credential and sessions; `false` when missing. Same guard and
    /// serialization as `update`.
    async fn delete(&self, id: UserId) -> AuthResult<bool>;

    async fn count(&self) -> AuthResult<u64>;

    /// Stores (or replaces) the password hash. `NotFound` when the user is missing.
    async fn set_password(&self, user: UserId, hash: String, at: DateTime<Utc>) -> AuthResult<()>;

    /// Starts a password check for `subject` at `at`: applies [`Lockout::reserve`] in one
    /// atomic step (concurrent attempts queue on it, so they cannot all pass the threshold
    /// check before any of them is counted) and returns its outcome. `since` is the start of the
    /// failure window. A [`Subject::Name`] without stored state starts from the default state.
    /// `NotFound` for a missing [`Subject::User`].
    async fn reserve(
        &self,
        subject: &Subject,
        at: DateTime<Utc>,
        since: DateTime<Utc>,
        threshold: u32,
    ) -> AuthResult<Reservation>;

    /// Applies [`Lockout::lock`] with `until`, but only while the stored state still
    /// [`Lockout::holds`] `seen` (what the caller's reservation returned), so concurrent
    /// failures lock once and a correct password that finished first is not undone. Returns
    /// whether this call locked; `false` for a missing subject.
    async fn lock(
        &self,
        subject: &Subject,
        seen: Lockout,
        until: DateTime<Utc>,
    ) -> AuthResult<bool>;

    /// Resets the state after a correct password, unless the subject is locked at `at` (a lock
    /// that a concurrent failure set during the check wins): then nothing changes and the stored
    /// state is returned. `NotFound` for a missing [`Subject::User`].
    async fn clear(&self, subject: &Subject, at: DateTime<Utc>) -> AuthResult<Option<Lockout>>;

    /// Resets an account's state (an administrator unlock or password reset). `NotFound` when
    /// the user is missing.
    async fn unlock(&self, user: UserId) -> AuthResult<()>;

    /// Deletes the stored state of usernames without an account that [`Lockout::is_stale`] at
    /// the window start `since`; returns how many.
    async fn prune(&self, since: DateTime<Utc>) -> AuthResult<u64>;
}
