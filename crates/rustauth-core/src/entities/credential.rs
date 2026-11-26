//! `PasswordCredential`: a user's password hash, kept apart from `User` so accounts without a
//! password (SSO, later) need no row.

use chrono::{DateTime, Utc};

use crate::values::UserId;

/// A stored password hash (Argon2id PHC string in production). Never logged.
#[derive(Clone, Eq, PartialEq)]
pub struct PasswordCredential {
    pub user_id: UserId,
    pub hash: String,
    pub changed_at: DateTime<Utc>,
}

impl std::fmt::Debug for PasswordCredential {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PasswordCredential")
            .field("user_id", &self.user_id)
            .field("hash", &"***")
            .field("changed_at", &self.changed_at)
            .finish()
    }
}

/// A password hash to store with a new user.
#[derive(Clone, Eq, PartialEq)]
pub struct NewPassword {
    pub hash: String,
    pub changed_at: DateTime<Utc>,
}

impl std::fmt::Debug for NewPassword {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NewPassword")
            .field("hash", &"***")
            .field("changed_at", &self.changed_at)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_hides_the_hash() {
        let credential = PasswordCredential {
            user_id: UserId::generate(),
            hash: "$argon2id$secret".to_owned(),
            changed_at: DateTime::UNIX_EPOCH,
        };
        assert!(!format!("{credential:?}").contains("argon2id"));
        let new = NewPassword {
            hash: "$argon2id$secret".to_owned(),
            changed_at: DateTime::UNIX_EPOCH,
        };
        assert!(!format!("{new:?}").contains("argon2id"));
    }
}
