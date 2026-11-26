//! `PasswordHasher`: turns passwords into stored hashes and checks them.

use async_trait::async_trait;

use crate::error::AuthResult;
use crate::values::Password;

/// Implemented by `rustauth-crypto` with Argon2id, run in `spawn_blocking` behind a small
/// semaphore so hashing cannot starve the async runtime.
#[async_trait]
pub trait PasswordHasher: Send + Sync {
    /// A self-describing hash (PHC string) with a fresh salt.
    async fn hash(&self, password: &Password) -> AuthResult<String>;

    /// Whether `password` matches `hash`. A malformed hash is an internal error, not `false`.
    async fn verify(&self, password: &Password, hash: &str) -> AuthResult<bool>;
}
