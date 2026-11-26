//! `FakeHasher`: a fast, deterministic stand-in for Argon2id that counts its calls.

use std::sync::atomic::{AtomicUsize, Ordering};

use async_trait::async_trait;

use crate::error::AuthResult;
use crate::ports::PasswordHasher;
use crate::values::Password;

/// Hashes are `fake$` plus the password, so tests stay fast. The call counters let tests check
/// that unknown usernames still cost a verification and that locked accounts cost none.
#[derive(Debug, Default)]
pub struct FakeHasher {
    hashes: AtomicUsize,
    verifies: AtomicUsize,
}

impl FakeHasher {
    const PREFIX: &'static str = "fake$";

    /// How many times `hash` ran.
    pub fn hashes(&self) -> usize {
        self.hashes.load(Ordering::SeqCst)
    }

    /// How many times `verify` ran.
    pub fn verifies(&self) -> usize {
        self.verifies.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl PasswordHasher for FakeHasher {
    async fn hash(&self, password: &Password) -> AuthResult<String> {
        self.hashes.fetch_add(1, Ordering::SeqCst);
        Ok(format!("{}{}", Self::PREFIX, password.expose()))
    }

    async fn verify(&self, password: &Password, hash: &str) -> AuthResult<bool> {
        self.verifies.fetch_add(1, Ordering::SeqCst);
        Ok(hash
            .strip_prefix(Self::PREFIX)
            .is_some_and(|stored| stored == password.expose()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn verifies_its_own_hashes() {
        let hasher = FakeHasher::default();
        let password = Password::candidate("correct horse".to_owned());
        let hash = hasher.hash(&password).await.expect("hashed");
        assert!(hasher.verify(&password, &hash).await.expect("verified"));
        let wrong = Password::candidate("wrong horse".to_owned());
        assert!(!hasher.verify(&wrong, &hash).await.expect("verified"));
        assert_eq!((hasher.hashes(), hasher.verifies()), (1, 2));
    }
}
