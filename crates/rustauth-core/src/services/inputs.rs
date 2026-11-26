//! Service inputs (validated by their constructors) and outputs.

use crate::entities::{Session, User, UserPatch};
use crate::error::AuthResult;
use crate::values::{DisplayName, Password, Role, SessionToken, Username};

/// What `GET /auth/setup` reports, for first-run screens.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SetupStatus {
    /// No account exists yet: the next registration needs the setup token.
    pub needs_setup: bool,
    pub registration_open: bool,
}

/// A successful registration or sign-in. `token` is shown to the client once; only its hash is
/// stored.
#[derive(Clone, Debug)]
pub struct SignedIn {
    pub token: SessionToken,
    pub session: Session,
    pub user: User,
}

/// A self-registration request.
#[derive(Clone, Debug)]
pub struct Registration {
    pub(crate) username: Username,
    pub(crate) display_name: DisplayName,
    pub(crate) password: Password,
}

impl Registration {
    /// Validates every field; the first invalid one is reported.
    pub fn new(username: &str, display_name: &str, password: String) -> AuthResult<Self> {
        Ok(Self {
            username: Username::new(username)?,
            display_name: DisplayName::new(display_name)?,
            password: Password::new(password)?,
        })
    }
}

/// An account created by an administrator with a temporary password.
#[derive(Clone, Debug)]
pub struct NewAccount {
    pub(crate) username: Username,
    pub(crate) display_name: DisplayName,
    pub(crate) password: Password,
    pub(crate) role: Role,
}

impl NewAccount {
    /// Validates every field; a bad password is reported as `temporaryPassword`.
    pub fn new(
        username: &str,
        display_name: &str,
        temporary_password: String,
        role: Role,
    ) -> AuthResult<Self> {
        Ok(Self {
            username: Username::new(username)?,
            display_name: DisplayName::new(display_name)?,
            password: Password::new(temporary_password)
                .map_err(|error| error.with_field("temporaryPassword"))?,
            role,
        })
    }
}

/// An administrator's change to an account. Every setter is optional; a password reset also
/// unlocks the account.
#[derive(Clone, Debug, Default)]
pub struct UserChanges {
    pub(crate) patch: UserPatch,
    pub(crate) password: Option<Password>,
}

impl UserChanges {
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn display_name(mut self, display_name: DisplayName) -> Self {
        self.patch.display_name = Some(display_name);
        self
    }

    #[must_use]
    pub fn role(mut self, role: Role) -> Self {
        self.patch.role = Some(role);
        self
    }

    #[must_use]
    pub fn disabled(mut self, disabled: bool) -> Self {
        self.patch.disabled = Some(disabled);
        self
    }

    #[must_use]
    pub fn password(mut self, password: Password) -> Self {
        self.password = Some(password);
        self
    }

    pub fn is_empty(&self) -> bool {
        self.patch.is_empty() && self.password.is_none()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::AuthError;

    fn field(error: AuthError) -> String {
        match error {
            AuthError::Validation { field, .. } => field,
            other => panic!("expected a validation error, got {other:?}"),
        }
    }

    #[test]
    fn registration_validates_each_field() {
        assert!(Registration::new("alice", "Alice", "a long password".to_owned()).is_ok());
        let error = Registration::new("a", "Alice", "a long password".to_owned());
        assert_eq!(field(error.expect_err("bad username")), "username");
        let error = Registration::new("alice", " ", "a long password".to_owned());
        assert_eq!(field(error.expect_err("bad name")), "displayName");
        let error = Registration::new("alice", "Alice", "short".to_owned());
        assert_eq!(field(error.expect_err("bad password")), "password");
    }

    #[test]
    fn new_account_reports_the_temporary_password_field() {
        let error = NewAccount::new("bob", "Bob", "short".to_owned(), Role::User);
        assert_eq!(field(error.expect_err("bad password")), "temporaryPassword");
    }

    #[test]
    fn user_changes_start_empty() {
        assert!(UserChanges::new().is_empty());
        assert!(!UserChanges::new().disabled(true).is_empty());
        let password = Password::new("a new long password".to_owned()).expect("valid");
        assert!(!UserChanges::new().password(password).is_empty());
    }
}
