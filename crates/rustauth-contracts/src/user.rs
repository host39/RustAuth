//! The account as clients see it, shared by the `/auth/*` and `/admin/users` routes.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

/// Roles, from highest to lowest. More roles may appear in a later release, so clients should
/// treat an unknown value like the lowest role.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize, ToSchema)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
#[serde(rename_all = "lowercase")]
#[schema(as = rustauth::UserRole)]
#[non_exhaustive]
pub enum UserRole {
    Administrator,
    Manager,
    User,
}

impl UserRole {
    /// Every role, from highest to lowest.
    pub const ALL: [UserRole; 3] = [UserRole::Administrator, UserRole::Manager, UserRole::User];

    /// The wire value: `administrator`, `manager`, or `user`.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Administrator => "administrator",
            Self::Manager => "manager",
            Self::User => "user",
        }
    }

    /// The role with this wire value, if there is one.
    pub fn parse(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|role| role.as_str() == value)
    }
}

/// An account.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, optional_fields))]
#[serde(rename_all = "camelCase")]
#[schema(as = rustauth::UserResponse)]
pub struct UserResponse {
    pub id: Uuid,
    /// The sign-in name as typed at registration; unique regardless of letter case.
    pub username: String,
    pub display_name: String,
    pub role: UserRole,
    /// A disabled account cannot sign in and its sessions stop working.
    pub disabled: bool,
    /// End of the most recent lockout after repeated wrong passwords. The account is locked
    /// while this lies in the future.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub locked_until: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roles_are_lowercase_strings() {
        assert_eq!(
            serde_json::to_value(UserRole::Administrator).expect("serializes"),
            "administrator"
        );
        let role: UserRole = serde_json::from_value(serde_json::json!("manager")).expect("known");
        assert_eq!(role, UserRole::Manager);
        assert!(serde_json::from_value::<UserRole>(serde_json::json!("owner")).is_err());
    }

    #[test]
    fn wire_values_match_serde() {
        for role in UserRole::ALL {
            assert_eq!(
                serde_json::to_value(role).expect("serializes"),
                role.as_str()
            );
            assert_eq!(UserRole::parse(role.as_str()), Some(role));
        }
        assert_eq!(UserRole::parse("Administrator"), None);
    }

    #[test]
    fn users_use_camel_case_and_omit_an_absent_lockout() {
        let at = DateTime::UNIX_EPOCH;
        let user = UserResponse {
            id: Uuid::nil(),
            username: "alice".to_owned(),
            display_name: "Alice".to_owned(),
            role: UserRole::User,
            disabled: false,
            locked_until: None,
            created_at: at,
            updated_at: at,
        };
        assert_eq!(
            serde_json::to_value(user).expect("serializes"),
            serde_json::json!({
                "id": "00000000-0000-0000-0000-000000000000",
                "username": "alice",
                "displayName": "Alice",
                "role": "user",
                "disabled": false,
                "createdAt": "1970-01-01T00:00:00Z",
                "updatedAt": "1970-01-01T00:00:00Z",
            })
        );
    }
}
