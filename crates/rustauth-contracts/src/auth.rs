//! DTOs for the `/auth/*` routes: setup status, register, login, profile, password, and sessions.
//!
//! Types that carry a password or a token print `***` in `Debug`, so they cannot leak into logs.

use std::fmt;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::user::UserResponse;

/// What `Debug` prints instead of a secret.
const REDACTED: &str = "***";

/// `GET /auth/setup`: what a first-run screen needs to know.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
#[serde(rename_all = "camelCase")]
#[schema(as = rustauth::SetupStatusResponse)]
pub struct SetupStatusResponse {
    /// No account exists yet: the next registration needs the setup token and becomes the
    /// administrator.
    pub needs_setup: bool,
    /// Anyone may sign up once the first account exists.
    pub registration_open: bool,
}

/// `POST /auth/register`.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, optional_fields))]
#[serde(rename_all = "camelCase")]
#[schema(as = rustauth::RegisterRequest)]
pub struct RegisterRequest {
    /// 3 to 32 letters, digits, or underscores.
    pub username: String,
    /// 12 to 256 bytes.
    pub password: String,
    /// 1 to 80 characters.
    pub display_name: String,
    /// Required while no account exists (the first account becomes the administrator).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub setup_token: Option<String>,
}

impl fmt::Debug for RegisterRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RegisterRequest")
            .field("username", &self.username)
            .field("password", &REDACTED)
            .field("display_name", &self.display_name)
            .field("setup_token", &self.setup_token.as_ref().map(|_| REDACTED))
            .finish()
    }
}

/// `POST /auth/login`.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
#[serde(rename_all = "camelCase")]
#[schema(as = rustauth::LoginRequest)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

impl fmt::Debug for LoginRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LoginRequest")
            .field("username", &self.username)
            .field("password", &REDACTED)
            .finish()
    }
}

/// A new session after registration or sign-in.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
#[serde(rename_all = "camelCase")]
#[schema(as = rustauth::SignInResponse)]
pub struct SignInResponse {
    /// Send as `Authorization: Bearer <token>`. Returned only here; the server keeps a hash.
    pub token: String,
    /// When the session ends unless it is used; each use (at most hourly) moves this forward,
    /// up to the absolute session lifetime.
    pub expires_at: DateTime<Utc>,
    pub user: UserResponse,
}

impl fmt::Debug for SignInResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SignInResponse")
            .field("token", &REDACTED)
            .field("expires_at", &self.expires_at)
            .field("user", &self.user)
            .finish()
    }
}

/// `PATCH /auth/me`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
#[serde(rename_all = "camelCase")]
#[schema(as = rustauth::UpdateProfileRequest)]
pub struct UpdateProfileRequest {
    /// 1 to 80 characters.
    pub display_name: String,
}

/// `POST /auth/password`. Signs out every other session of the caller.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
#[serde(rename_all = "camelCase")]
#[schema(as = rustauth::ChangePasswordRequest)]
pub struct ChangePasswordRequest {
    /// The current password. A wrong one fails as a validation error on `current` and counts
    /// toward the account lockout.
    pub current: String,
    /// The new password, 12 to 256 bytes.
    pub new: String,
}

impl fmt::Debug for ChangePasswordRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ChangePasswordRequest")
            .field("current", &REDACTED)
            .field("new", &REDACTED)
            .finish()
    }
}

/// One signed-in device of the caller (`GET /auth/sessions`).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, optional_fields))]
#[serde(rename_all = "camelCase")]
#[schema(as = rustauth::SessionResponse)]
pub struct SessionResponse {
    pub id: Uuid,
    /// The session this request was made with.
    pub current: bool,
    /// How the session was established, for example `["password"]`. More methods may appear.
    pub methods: Vec<String>,
    /// Authenticator assurance level, for example `aal1`. More levels may appear.
    pub assurance: String,
    pub created_at: DateTime<Utc>,
    /// Updated at most once an hour.
    pub last_used_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    /// The first 256 characters of the `User-Agent` header at sign-in.
    pub user_agent: String,
    /// The client address at sign-in, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::user::UserRole;

    #[test]
    fn registration_reads_camel_case_and_an_optional_setup_token() {
        let request: RegisterRequest = serde_json::from_value(serde_json::json!({
            "username": "alice",
            "password": "a long password",
            "displayName": "Alice",
        }))
        .expect("valid body");
        assert_eq!(request.display_name, "Alice");
        assert_eq!(request.setup_token, None);
        let request: RegisterRequest = serde_json::from_value(serde_json::json!({
            "username": "alice",
            "password": "a long password",
            "displayName": "Alice",
            "setupToken": "token",
        }))
        .expect("valid body");
        assert_eq!(request.setup_token.as_deref(), Some("token"));
    }

    #[test]
    fn debug_hides_passwords_and_tokens() {
        let register = RegisterRequest {
            username: "alice".to_owned(),
            password: "secret-password".to_owned(),
            display_name: "Alice".to_owned(),
            setup_token: Some("secret-setup-token".to_owned()),
        };
        let login = LoginRequest {
            username: "alice".to_owned(),
            password: "secret-password".to_owned(),
        };
        let change = ChangePasswordRequest {
            current: "secret-password".to_owned(),
            new: "secret-new-password".to_owned(),
        };
        let at = DateTime::UNIX_EPOCH;
        let signed = SignInResponse {
            token: "secret-token".to_owned(),
            expires_at: at,
            user: UserResponse {
                id: Uuid::nil(),
                username: "alice".to_owned(),
                display_name: "Alice".to_owned(),
                role: UserRole::User,
                disabled: false,
                locked_until: None,
                created_at: at,
                updated_at: at,
            },
        };
        let printed = format!("{register:?} {login:?} {change:?} {signed:?}");
        assert!(!printed.contains("secret"), "{printed}");
        assert!(printed.contains("alice"));
    }

    #[test]
    fn sessions_omit_an_unknown_ip() {
        let at = DateTime::UNIX_EPOCH;
        let session = SessionResponse {
            id: Uuid::nil(),
            current: true,
            methods: vec!["password".to_owned()],
            assurance: "aal1".to_owned(),
            created_at: at,
            last_used_at: at,
            expires_at: at,
            user_agent: String::new(),
            ip: None,
        };
        let json = serde_json::to_value(session).expect("serializes");
        assert!(json.get("ip").is_none());
        assert_eq!(json["lastUsedAt"], "1970-01-01T00:00:00Z");
    }
}
