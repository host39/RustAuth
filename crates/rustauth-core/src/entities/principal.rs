//! `Principal`: the caller of a verified request.

use crate::error::{AuthError, AuthResult};
use crate::values::{Assurance, Role, SessionId, UserId, Username};

/// What a verified request carries. `AuthService::verify` builds it from the database on every
/// request (never from a cached claim), so a role change or a disabled account takes effect at
/// once.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Principal {
    pub user_id: UserId,
    pub username: Username,
    pub role: Role,
    pub session_id: SessionId,
    pub assurance: Assurance,
}

impl Principal {
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
        Principal {
            user_id: UserId::generate(),
            username: Username::new("alice").expect("valid"),
            role,
            session_id: SessionId::generate(),
            assurance: Assurance::Aal1,
        }
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
