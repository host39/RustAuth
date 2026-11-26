//! `Role`: what an account may do.

use std::fmt;
use std::str::FromStr;

use crate::error::AuthError;

/// Roles for authorization, ordered so `Administrator > Manager > User`. A check for a minimum
/// role (`role >= Role::Manager`) therefore admits every higher role too.
///
/// Stored and serialized as `administrator`, `manager`, `user`. More roles may appear in later
/// releases, so match with a wildcard arm.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[non_exhaustive]
pub enum Role {
    // Declared from lowest to highest: the derived `Ord` follows declaration order.
    User,
    Manager,
    Administrator,
}

impl Role {
    /// Every role, from highest to lowest.
    pub const ALL: [Role; 3] = [Role::Administrator, Role::Manager, Role::User];

    /// A role read back from storage. A value this release does not know (written by a newer
    /// one) reads as [`Role::User`], the least privilege, instead of failing the whole record.
    pub fn stored(value: &str) -> Self {
        value.parse().unwrap_or(Self::User)
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Administrator => "administrator",
            Self::Manager => "manager",
            Self::User => "user",
        }
    }
}

impl fmt::Display for Role {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for Role {
    type Err = AuthError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|role| role.as_str() == value)
            .ok_or_else(|| {
                AuthError::validation("role", "Role must be administrator, manager, or user.")
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn orders_administrator_above_manager_above_user() {
        assert!(Role::Administrator > Role::Manager);
        assert!(Role::Manager > Role::User);
        assert!(Role::Administrator > Role::User);
    }

    #[test]
    fn round_trips_through_text() {
        for role in Role::ALL {
            assert_eq!(role.as_str().parse::<Role>().expect("known"), role);
            assert_eq!(role.to_string(), role.as_str());
        }
    }

    #[test]
    fn stored_unknown_roles_read_as_the_least_privilege() {
        assert_eq!(Role::stored("manager"), Role::Manager);
        assert_eq!(Role::stored("owner"), Role::User);
    }

    #[test]
    fn rejects_unknown_roles() {
        let error = "owner".parse::<Role>().expect_err("unknown");
        assert_eq!(
            error.to_string(),
            "Role must be administrator, manager, or user."
        );
        assert!("Administrator".parse::<Role>().is_err());
    }
}
