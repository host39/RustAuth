//! `Password`: a plaintext password on its way to the hasher.

use std::fmt;

use crate::error::{AuthError, AuthResult};

/// A plaintext password. `Debug` prints `***`; there is no `Display`, so it cannot end up in a
/// log line or an error message by accident.
///
/// [`Password::new`] applies the password policy (12 to 256 bytes) and is for passwords being
/// set. [`Password::candidate`] skips it and is for sign-in attempts, so accounts keep working if
/// the policy tightens later.
#[derive(Clone)]
pub struct Password(String);

impl Password {
    pub const MIN_BYTES: usize = 12;
    pub const MAX_BYTES: usize = 256;

    /// A new password that must meet the policy.
    pub fn new(value: String) -> AuthResult<Self> {
        if value.len() < Self::MIN_BYTES {
            return Err(AuthError::validation(
                "password",
                "Password must be at least 12 characters long.",
            ));
        }
        if value.len() > Self::MAX_BYTES {
            return Err(AuthError::validation(
                "password",
                "Password must be at most 256 bytes long.",
            ));
        }
        Ok(Self(value))
    }

    /// A password typed at sign-in, checked against a stored hash only.
    pub fn candidate(value: String) -> Self {
        Self(value)
    }

    /// The plaintext, for the hasher only.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Password {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Password(***)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enforces_the_policy_in_bytes() {
        assert!(Password::new("a".repeat(12)).is_ok());
        assert!(Password::new("a".repeat(256)).is_ok());
        let short = Password::new("a".repeat(11)).expect_err("too short");
        assert_eq!(
            short.to_string(),
            "Password must be at least 12 characters long."
        );
        assert!(matches!(short, AuthError::Validation { field, .. } if field == "password"));
        let long = Password::new("a".repeat(257)).expect_err("too long");
        assert_eq!(long.to_string(), "Password must be at most 256 bytes long.");
        // Four characters but sixteen bytes: the policy counts bytes.
        assert!(Password::new("😀😀😀😀".to_owned()).is_ok());
    }

    #[test]
    fn candidates_skip_the_policy() {
        assert_eq!(Password::candidate("short".to_owned()).expose(), "short");
    }

    #[test]
    fn debug_is_redacted() {
        let password = Password::new("correct horse battery".to_owned()).expect("valid");
        assert_eq!(format!("{password:?}"), "Password(***)");
    }
}
