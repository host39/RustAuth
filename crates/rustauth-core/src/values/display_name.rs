//! `DisplayName`: the name shown to other people.

use std::fmt;

use crate::error::{AuthError, AuthResult};

/// 1 to 80 characters after trimming, without control characters (such as line breaks).
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct DisplayName(String);

impl DisplayName {
    pub const MAX_CHARS: usize = 80;

    /// Validates and trims a display name.
    pub fn new(value: &str) -> AuthResult<Self> {
        let value = value.trim();
        if value.is_empty() {
            return Err(AuthError::validation(
                "displayName",
                "Display name is required.",
            ));
        }
        if value.chars().count() > Self::MAX_CHARS {
            return Err(AuthError::validation(
                "displayName",
                "Display name must be at most 80 characters long.",
            ));
        }
        if value.chars().any(char::is_control) {
            return Err(AuthError::validation(
                "displayName",
                "Display name must not contain control characters.",
            ));
        }
        Ok(Self(value.to_owned()))
    }

    /// A display name read back from storage, without the input rules (a newer release may have
    /// changed them). Inputs go through [`DisplayName::new`].
    pub fn stored(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for DisplayName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trims_the_value() {
        let name = DisplayName::new("  Ada Lovelace ").expect("valid");
        assert_eq!(name.as_str(), "Ada Lovelace");
    }

    #[test]
    fn requires_a_non_blank_value() {
        let error = DisplayName::new("   ").expect_err("blank");
        assert_eq!(error.to_string(), "Display name is required.");
        assert!(matches!(error, AuthError::Validation { field, .. } if field == "displayName"));
    }

    #[test]
    fn counts_characters_not_bytes() {
        assert!(DisplayName::new(&"é".repeat(80)).is_ok());
        let error = DisplayName::new(&"é".repeat(81)).expect_err("too long");
        assert_eq!(
            error.to_string(),
            "Display name must be at most 80 characters long."
        );
    }

    #[test]
    fn rejects_control_characters() {
        let error = DisplayName::new("Ada\nLovelace").expect_err("control character");
        assert_eq!(
            error.to_string(),
            "Display name must not contain control characters."
        );
    }
}
