//! `Principal`: the caller of a verified request.

use crate::error::{AuthError, AuthResult};
use crate::values::{Assurance, Role, SessionId, UserId, Username};

/// What a verified request carries. `AuthService::verify` builds it from the database on every
/// request (never from a cached claim), so a role change or a disabled account takes effect at
/// once.
///
/// Fields stay readable; outside this crate it is built with [`Principal::new`] (applications do
/// so in tests), so fields added later do not break that code.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct Principal {
    pub user_id: UserId,
    pub username: Username,
    pub role: Role,
    pub session_id: SessionId,
    pub assurance: Assurance,
}

impl Principal {
    /// A caller signed in with one factor ([`Assurance::Aal1`]); see [`Principal::assurance`].
    pub fn new(user_id: UserId, username: Username, role: Role, session_id: SessionId) -> Self {
        Self {
            user_id,
            username,
            role,
            session_id,
            assurance: Assurance::Aal1,
        }
    }

    /// The same caller with another assurance level.
    #[must_use]
    pub fn assurance(mut self, assurance: Assurance) -> Self {
        self.assurance = assurance;
        self
    }

    /// Whether the caller has `minimum` or a higher role.
    pub fn has_role(&self, minimum: Role) -> bool {
        self.role >= minimum
    }

    /// Fails with [`AuthError::Forbidden`] unless the caller has `minimum` or a higher role.
    pub fn require(&self, minimum: Role) -> AuthResult<()> {
        if self.has_role(minimum) {
            Ok(())
        } else {
            Err(AuthError::forbidden(AuthError::FORBIDDEN))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn principal(role: Role) -> Principal {
        Principal::new(
            UserId::generate(),
            Username::new("alice").expect("valid"),
            role,
            SessionId::generate(),
        )
    }

    #[test]
    fn new_callers_have_one_factor() {
        let caller = principal(Role::User);
        assert_eq!(caller.assurance, Assurance::Aal1);
        assert_eq!(caller.clone().assurance(Assurance::Aal1), caller);
    }

    #[test]
    fn higher_roles_pass_lower_checks() {
        let manager = principal(Role::Manager);
        assert!(manager.has_role(Role::User));
        assert!(manager.has_role(Role::Manager));
        assert!(!manager.has_role(Role::Administrator));
        assert!(principal(Role::Administrator).has_role(Role::Manager));
    }

    #[test]
    fn require_fails_with_forbidden() {
        assert!(
            principal(Role::Administrator)
                .require(Role::Administrator)
                .is_ok()
        );
        let error = principal(Role::User)
            .require(Role::Manager)
            .expect_err("too low");
        assert_eq!(error.code(), "FORBIDDEN");
        assert_eq!(error.to_string(), "You do not have permission to do this.");
    }
}
