//! DTOs for the `/admin/users` routes: list, create, and update. Every route needs the
//! `administrator` role.

use std::fmt;

use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

use crate::user::UserRole;

/// What `Debug` prints instead of a password.
const REDACTED: &str = "***";

/// Query of `GET /admin/users`: accounts ordered by username, one page at a time.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, IntoParams, PartialEq, Serialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, optional_fields))]
#[serde(rename_all = "camelCase")]
#[into_params(parameter_in = Query)]
pub struct ListUsersQuery {
    /// Accounts to skip. Default 0.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offset: Option<u64>,
    /// Page size from 1 to 100 (values outside are clamped). Default 50.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
}

/// `POST /admin/users`: an account with a temporary password.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
#[serde(rename_all = "camelCase")]
#[schema(as = rustauth::CreateUserRequest)]
pub struct CreateUserRequest {
    /// 3 to 32 letters, digits, or underscores.
    pub username: String,
    /// 1 to 80 characters.
    pub display_name: String,
    /// 12 to 256 bytes. Share it with the person, who should change it after signing in.
    pub temporary_password: String,
    pub role: UserRole,
}

impl fmt::Debug for CreateUserRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CreateUserRequest")
            .field("username", &self.username)
            .field("display_name", &self.display_name)
            .field("temporary_password", &REDACTED)
            .field("role", &self.role)
            .finish()
    }
}

/// `PATCH /admin/users/{id}`: every field is optional and only the given ones change. Any change
/// signs the account out everywhere; a new password also clears a lockout.
#[derive(Clone, Default, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, optional_fields))]
#[serde(rename_all = "camelCase")]
#[schema(as = rustauth::UpdateUserRequest)]
pub struct UpdateUserRequest {
    /// 1 to 80 characters.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<UserRole>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disabled: Option<bool>,
    /// A new password (12 to 256 bytes); also unlocks the account.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
}

impl fmt::Debug for UpdateUserRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UpdateUserRequest")
            .field("display_name", &self.display_name)
            .field("role", &self.role)
            .field("disabled", &self.disabled)
            .field("password", &self.password.as_ref().map(|_| REDACTED))
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn update_reads_only_the_given_fields() {
        let request: UpdateUserRequest =
            serde_json::from_value(serde_json::json!({ "role": "manager", "disabled": true }))
                .expect("valid body");
        assert_eq!(request.role, Some(UserRole::Manager));
        assert_eq!(request.disabled, Some(true));
        assert_eq!(request.display_name, None);
        assert_eq!(request.password, None);
        assert_eq!(
            serde_json::to_value(UpdateUserRequest::default()).expect("serializes"),
            serde_json::json!({})
        );
    }

    #[test]
    fn create_reads_camel_case() {
        let request: CreateUserRequest = serde_json::from_value(serde_json::json!({
            "username": "bob",
            "displayName": "Bob",
            "temporaryPassword": "a temporary password",
            "role": "user",
        }))
        .expect("valid body");
        assert_eq!(request.temporary_password, "a temporary password");
        assert_eq!(request.role, UserRole::User);
    }

    #[test]
    fn debug_hides_passwords() {
        let create = CreateUserRequest {
            username: "bob".to_owned(),
            display_name: "Bob".to_owned(),
            temporary_password: "secret-password".to_owned(),
            role: UserRole::User,
        };
        let update = UpdateUserRequest {
            password: Some("secret-password".to_owned()),
            ..UpdateUserRequest::default()
        };
        let printed = format!("{create:?} {update:?}");
        assert!(!printed.contains("secret"), "{printed}");
    }
}
