//! `AuthError`: every failure a service returns.
//!
//! Variants carry human-readable messages and stable codes (`INVALID_CREDENTIALS`,
//! `ACCOUNT_LOCKED`, ...). Only `Internal` uses a dotted key (`rustauth.users.insert.failed`),
//! which is for logs; clients only ever see a generic message for it. HTTP status mapping lives in
//! `rustauth-axum`, not here.

/// A boxed error from infrastructure code (database driver, hasher, and so on).
pub type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;

/// The result type of every port and service.
pub type AuthResult<T> = Result<T, AuthError>;

/// Every failure a RustAuth service returns. New variants may appear in any release, so match
/// with a wildcard arm and fall back on [`AuthError::code`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AuthError {
    /// Wrong username or password; deliberately does not say which. Maps to 401.
    #[error("Invalid username or password.")]
    InvalidCredentials,

    /// The bearer token is missing, expired, or revoked. Maps to 401.
    #[error("Sign in to continue.")]
    Unauthorized,

    /// The caller is signed in but may not do this. Maps to 403.
    #[error("{message}")]
    Forbidden { message: String },

    /// Input failed validation. `field` names the request field. Maps to 400.
    #[error("{message}")]
    Validation { field: String, message: String },

    /// The entity (`"User"`, `"Session"`) does not exist. Maps to 404.
    #[error("{entity} not found.")]
    NotFound { entity: &'static str },

    /// Another account already uses this username (compared case-insensitively). Maps to 409.
    #[error("This username is already taken.")]
    UsernameTaken,

    /// No account exists yet and the setup token was missing or wrong. Maps to 403.
    #[error("A valid setup token is required to create the first account.")]
    SetupRequired,

    /// Accounts exist and open registration is turned off. Maps to 403.
    #[error("Registration is closed. Ask an administrator to create your account.")]
    RegistrationClosed,

    /// The change would leave no enabled administrator. Maps to 422.
    #[error("At least one enabled administrator must remain.")]
    LastAdministrator,

    /// The account cannot be deleted while other records refer to it (an application table that
    /// references `auth.users (id)` without `ON DELETE CASCADE` or `SET NULL`). Maps to 409.
    #[error(
        "Other records still refer to this account, so it cannot be deleted. Disable it instead."
    )]
    UserInUse,

    /// The client sent too many requests or too many failed sign-ins. Maps to 429.
    #[error("Too many requests. Try again in {}.", seconds(.retry_after_secs))]
    RateLimited { retry_after_secs: u64 },

    /// The account is temporarily locked after repeated wrong passwords. Maps to 429.
    #[error("Too many failed sign-in attempts. Try again in {}.", minutes(.retry_after_secs))]
    AccountLocked { retry_after_secs: u64 },

    /// Infrastructure failure. `key` is a dotted log key, never shown to clients. Maps to 500.
    #[error("{key}")]
    Internal {
        key: String,
        #[source]
        source: Option<BoxError>,
    },
}

impl AuthError {
    /// The message every service uses when a role check fails.
    pub const FORBIDDEN: &'static str = "You do not have permission to do this.";

    pub fn forbidden(message: impl Into<String>) -> Self {
        Self::Forbidden {
            message: message.into(),
        }
    }

    pub fn validation(field: impl Into<String>, message: impl Into<String>) -> Self {
        Self::Validation {
            field: field.into(),
            message: message.into(),
        }
    }

    pub fn not_found(entity: &'static str) -> Self {
        Self::NotFound { entity }
    }

    /// Wraps an infrastructure failure under a dotted log key.
    pub fn internal(key: impl Into<String>, source: impl Into<BoxError>) -> Self {
        Self::Internal {
            key: key.into(),
            source: Some(source.into()),
        }
    }

    /// Renames the failing field of a [`AuthError::Validation`] (for example `password` to
    /// `new`); other variants are unchanged.
    #[must_use]
    pub fn with_field(mut self, name: impl Into<String>) -> Self {
        if let Self::Validation { field, .. } = &mut self {
            *field = name.into();
        }
        self
    }

    /// Stable machine-readable code for clients and log filters.
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidCredentials => "INVALID_CREDENTIALS",
            Self::Unauthorized => "UNAUTHORIZED",
            Self::Forbidden { .. } => "FORBIDDEN",
            Self::Validation { .. } => "VALIDATION_ERROR",
            Self::NotFound { .. } => "ENTITY_NOT_FOUND",
            Self::UsernameTaken => "USERNAME_TAKEN",
            Self::SetupRequired => "SETUP_REQUIRED",
            Self::RegistrationClosed => "REGISTRATION_CLOSED",
            Self::LastAdministrator => "LAST_ADMINISTRATOR",
            Self::UserInUse => "USER_IN_USE",
            Self::RateLimited { .. } => "RATE_LIMITED",
            Self::AccountLocked { .. } => "ACCOUNT_LOCKED",
            Self::Internal { .. } => "INTERNAL_ERROR",
        }
    }

    /// Seconds the client should wait (`Retry-After`) for the variants that limit retries.
    pub fn retry_after_secs(&self) -> Option<u64> {
        match self {
            Self::RateLimited { retry_after_secs } | Self::AccountLocked { retry_after_secs } => {
                Some(*retry_after_secs)
            }
            _ => None,
        }
    }
}

/// "1 second", "45 seconds".
fn seconds(secs: &u64) -> String {
    plural(*secs, "second")
}

/// Whole minutes, rounded up and at least one: "1 minute", "15 minutes".
fn minutes(secs: &u64) -> String {
    plural(secs.div_ceil(60).max(1), "minute")
}

fn plural(count: u64, unit: &str) -> String {
    if count == 1 {
        format!("1 {unit}")
    } else {
        format!("{count} {unit}s")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_are_stable() {
        let cases = [
            (AuthError::InvalidCredentials, "INVALID_CREDENTIALS"),
            (AuthError::Unauthorized, "UNAUTHORIZED"),
            (AuthError::forbidden("No."), "FORBIDDEN"),
            (
                AuthError::validation("username", "Bad."),
                "VALIDATION_ERROR",
            ),
            (AuthError::not_found("User"), "ENTITY_NOT_FOUND"),
            (AuthError::UsernameTaken, "USERNAME_TAKEN"),
            (AuthError::SetupRequired, "SETUP_REQUIRED"),
            (AuthError::RegistrationClosed, "REGISTRATION_CLOSED"),
            (AuthError::LastAdministrator, "LAST_ADMINISTRATOR"),
            (AuthError::UserInUse, "USER_IN_USE"),
            (
                AuthError::RateLimited {
                    retry_after_secs: 1,
                },
                "RATE_LIMITED",
            ),
            (
                AuthError::AccountLocked {
                    retry_after_secs: 1,
                },
                "ACCOUNT_LOCKED",
            ),
            (
                AuthError::internal("rustauth.users.insert.failed", "boom"),
                "INTERNAL_ERROR",
            ),
        ];
        for (error, code) in cases {
            assert_eq!(error.code(), code);
        }
    }

    #[test]
    fn messages_are_human_readable() {
        assert_eq!(
            AuthError::InvalidCredentials.to_string(),
            "Invalid username or password."
        );
        assert_eq!(
            AuthError::not_found("Session").to_string(),
            "Session not found."
        );
        assert_eq!(
            AuthError::validation("username", "Username is too short.").to_string(),
            "Username is too short."
        );
    }

    #[test]
    fn locked_message_rounds_up_to_whole_minutes() {
        let message = |secs| {
            AuthError::AccountLocked {
                retry_after_secs: secs,
            }
            .to_string()
        };
        assert_eq!(
            message(900),
            "Too many failed sign-in attempts. Try again in 15 minutes."
        );
        assert_eq!(
            message(61),
            "Too many failed sign-in attempts. Try again in 2 minutes."
        );
        assert_eq!(
            message(5),
            "Too many failed sign-in attempts. Try again in 1 minute."
        );
    }

    #[test]
    fn rate_limited_message_counts_seconds() {
        let error = AuthError::RateLimited {
            retry_after_secs: 1,
        };
        assert_eq!(
            error.to_string(),
            "Too many requests. Try again in 1 second."
        );
        assert_eq!(error.retry_after_secs(), Some(1));
        assert_eq!(AuthError::Unauthorized.retry_after_secs(), None);
    }

    #[test]
    fn renames_the_validation_field() {
        let error = AuthError::validation("password", "Too short.").with_field("new");
        assert!(matches!(error, AuthError::Validation { field, .. } if field == "new"));
        let other = AuthError::Unauthorized.with_field("new");
        assert!(matches!(other, AuthError::Unauthorized));
    }

    #[test]
    fn internal_errors_display_their_key_and_keep_the_source() {
        let error = AuthError::internal("rustauth.users.insert.failed", "connection reset");
        assert_eq!(error.to_string(), "rustauth.users.insert.failed");
        assert!(std::error::Error::source(&error).is_some());
    }
}
