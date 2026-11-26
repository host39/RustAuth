//! Argon2id implementation of the `PasswordHasher` port.

use std::sync::Arc;

use argon2::password_hash::Error as HashError;
use argon2::{Argon2, PasswordHasher as _, PasswordVerifier as _};
use async_trait::async_trait;
use rustauth_core::{AuthError, AuthResult, Password, PasswordHasher};
use tokio::sync::Semaphore;

/// Argon2id with the `argon2` 0.6 defaults (m = 19 MiB, t = 2, p = 1; one of OWASP's minimum
/// configurations). Hashes are PHC strings with a fresh 16-byte salt from the OS RNG, so they
/// carry their own parameters and the defaults can be raised later without breaking stored
/// hashes.
///
/// Each hash or verification costs about 19 MiB and tens of milliseconds of CPU, so it runs in
/// `spawn_blocking` behind a semaphore: at most `permits` run at once (4 by default), and further
/// sign-ins wait their turn instead of starving the async runtime or exhausting memory. A permit
/// is held until the blocking work ends, even when the caller stops waiting (for example a
/// dropped request), so the bound holds under load.
#[derive(Clone, Debug)]
pub struct Argon2Hasher {
    permits: Arc<Semaphore>,
}

impl Argon2Hasher {
    /// Concurrent hashes and verifications when built with [`Argon2Hasher::new`].
    pub const DEFAULT_PERMITS: usize = 4;

    /// A hasher that runs at most [`Argon2Hasher::DEFAULT_PERMITS`] hashes at once.
    pub fn new() -> Self {
        Self::with_permits(Self::DEFAULT_PERMITS)
    }

    /// A hasher that runs at most `permits` hashes at once (at least one).
    pub fn with_permits(permits: usize) -> Self {
        Self {
            permits: Arc::new(Semaphore::new(permits.max(1))),
        }
    }

    /// Runs `work` on the blocking thread pool once a permit is free. `key` names the operation
    /// in the internal error when the work fails or panics.
    async fn run<T, F>(&self, key: &'static str, work: F) -> AuthResult<T>
    where
        T: Send + 'static,
        F: FnOnce() -> Result<T, HashError> + Send + 'static,
    {
        let permit = self
            .permits
            .clone()
            .acquire_owned()
            .await
            .map_err(|error| AuthError::internal(key, error))?;
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            work()
        })
        .await
        .map_err(|error| AuthError::internal(key, error))?
        .map_err(|error| AuthError::internal(key, error))
    }
}

impl Default for Argon2Hasher {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl PasswordHasher for Argon2Hasher {
    async fn hash(&self, password: &Password) -> AuthResult<String> {
        let password = password.clone();
        self.run("rustauth.password.hash.failed", move || {
            Argon2::default()
                .hash_password(password.expose().as_bytes())
                .map(|hash| hash.to_string())
        })
        .await
    }

    /// `Ok(false)` for a wrong password; an internal error when `hash` is not a PHC string that
    /// Argon2 can check (a corrupt or foreign hash must not look like a wrong password).
    async fn verify(&self, password: &Password, hash: &str) -> AuthResult<bool> {
        let password = password.clone();
        let hash = hash.to_owned();
        self.run(
            "rustauth.password.verify.failed",
            move || match Argon2::default()
                .verify_password(password.expose().as_bytes(), hash.as_str())
            {
                Ok(()) => Ok(true),
                Err(HashError::PasswordInvalid) => Ok(false),
                Err(error) => Err(error),
            },
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn password(value: &str) -> Password {
        Password::candidate(value.to_owned())
    }

    #[tokio::test]
    async fn verifies_its_own_hash() {
        let hasher = Argon2Hasher::new();
        let hash = hasher
            .hash(&password("correct horse battery staple"))
            .await
            .expect("hashed");
        assert!(
            hasher
                .verify(&password("correct horse battery staple"), &hash)
                .await
                .expect("verified")
        );
    }

    #[tokio::test]
    async fn rejects_a_wrong_password() {
        let hasher = Argon2Hasher::new();
        let hash = hasher
            .hash(&password("correct horse battery staple"))
            .await
            .expect("hashed");
        for wrong in [
            "correct horse battery stapl",
            "Correct horse battery staple",
            "",
        ] {
            assert!(
                !hasher
                    .verify(&password(wrong), &hash)
                    .await
                    .expect("verified"),
                "{wrong:?}"
            );
        }
    }

    #[tokio::test]
    async fn uses_argon2id_with_the_default_costs_and_a_fresh_salt() {
        let hasher = Argon2Hasher::new();
        let first = hasher
            .hash(&password("same password"))
            .await
            .expect("hashed");
        let second = hasher
            .hash(&password("same password"))
            .await
            .expect("hashed");
        assert!(
            first.starts_with("$argon2id$v=19$m=19456,t=2,p=1$"),
            "{first}"
        );
        assert_ne!(first, second, "each hash gets its own salt");
        assert!(!first.contains("same password"));
    }

    #[tokio::test]
    async fn treats_a_malformed_hash_as_an_internal_error() {
        let hasher = Argon2Hasher::new();
        for hash in ["", "not a hash", "$argon2id$v=19$m=19456,t=2,p=1$broken"] {
            let error = hasher
                .verify(&password("correct horse battery staple"), hash)
                .await
                .expect_err("malformed");
            assert!(
                matches!(&error, AuthError::Internal { key, .. } if key == "rustauth.password.verify.failed"),
                "{hash:?}: {error:?}"
            );
        }
    }

    #[tokio::test]
    async fn verifies_hashes_made_with_other_parameters() {
        // Stored hashes keep their own parameters, so raising the defaults later keeps old
        // accounts working. This one uses m = 8 MiB, t = 1.
        let params = argon2::Params::new(8 * 1024, 1, 1, None).expect("valid params");
        let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
        let hash = argon2
            .hash_password(b"older parameters")
            .expect("hashed")
            .to_string();
        let hasher = Argon2Hasher::new();
        assert!(
            hasher
                .verify(&password("older parameters"), &hash)
                .await
                .expect("verified")
        );
    }

    #[tokio::test]
    async fn runs_with_a_single_permit() {
        let hasher = Argon2Hasher::with_permits(0);
        assert_eq!(hasher.permits.available_permits(), 1);
        let (one, two) = (password("first password"), password("second password"));
        let (first, second) = tokio::join!(hasher.hash(&one), hasher.hash(&two));
        let (first, second) = (first.expect("hashed"), second.expect("hashed"));
        assert!(
            hasher
                .verify(&password("second password"), &second)
                .await
                .expect("verified")
        );
        assert!(
            !hasher
                .verify(&password("second password"), &first)
                .await
                .expect("verified")
        );
        assert_eq!(hasher.permits.available_permits(), 1);
    }
}
