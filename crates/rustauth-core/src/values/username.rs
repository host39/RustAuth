//! `Username`: the sign-in name.

use std::fmt;

use crate::error::{AuthError, AuthResult};

/// 3 to 32 ASCII letters, digits, or underscores. Stored as typed; uniqueness and lookups compare
/// the lowercase form ([`Username::canonical`]), so `Alice` and `alice` are the same account.
///
/// `Eq` and `Hash` compare the stored spelling; compare `canonical()` to match accounts.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Username(String);

impl Username {
    pub const MIN_CHARS: usize = 3;
    pub const MAX_CHARS: usize = 32;

    /// Validates a username. Surrounding whitespace is ignored.
    pub fn new(value: &str) -> AuthResult<Self> {
        let value = value.trim();
        if !(Self::MIN_CHARS..=Self::MAX_CHARS).contains(&value.chars().count()) {
            return Err(AuthError::validation(
                "username",
                "Username must be 3 to 32 characters long.",
            ));
        }
        if !value
            .chars()
            .all(|char| char.is_ascii_alphanumeric() || char == '_')
        {
            return Err(AuthError::validation(
                "username",
                "Username may contain only letters, digits, and underscores.",
            ));
        }
        Ok(Self(value.to_owned()))
    }

    /// A username read back from storage, without the input rules: a newer release may have
    /// relaxed them, and a stored account must keep working on an older one. Inputs go through
    /// [`Username::new`].
    pub fn stored(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// The username as typed.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The lowercase form used for uniqueness and lookups.
    pub fn canonical(&self) -> String {
        self.0.to_ascii_lowercase()
    }
}

impl fmt::Display for Username {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn message(value: &str) -> String {
        Username::new(value).expect_err("invalid").to_string()
    }

    #[test]
    fn accepts_letters_digits_and_underscores() {
        let username = Username::new("Alice_99").expect("valid");
        assert_eq!(username.as_str(), "Alice_99");
        assert_eq!(username.canonical(), "alice_99");
        assert_eq!(username.to_string(), "Alice_99");
    }

    #[test]
    fn trims_surrounding_whitespace() {
        assert_eq!(Username::new("  bob ").expect("valid").as_str(), "bob");
    }

    #[test]
    fn enforces_the_length() {
        assert!(Username::new("abc").is_ok());
        assert!(Username::new(&"a".repeat(32)).is_ok());
        assert_eq!(message("ab"), "Username must be 3 to 32 characters long.");
        assert_eq!(
            message(&"a".repeat(33)),
            "Username must be 3 to 32 characters long."
        );
    }

    #[test]
    fn rejects_other_characters() {
        for value in ["al ice", "alice!", "al-ice", "élodie", "a.b.c"] {
            assert_eq!(
                message(value),
                "Username may contain only letters, digits, and underscores.",
                "{value}"
            );
        }
    }

    #[test]
    fn stored_values_skip_the_input_rules() {
        assert_eq!(Username::stored("élodie").as_str(), "élodie");
    }

    #[test]
    fn reports_the_username_field() {
        let error = Username::new("x").expect_err("invalid");
        assert!(matches!(error, AuthError::Validation { field, .. } if field == "username"));
    }
}
