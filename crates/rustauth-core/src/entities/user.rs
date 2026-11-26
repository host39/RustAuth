//! `User`, the inputs that create or change one, and the rules every `UserRepository` applies
//! inside its transaction (first-administrator decision, last-administrator guard).

use chrono::{DateTime, Utc};

use crate::entities::lockout::Lockout;
use crate::error::{AuthError, AuthResult};
use crate::values::{DisplayName, Role, UserId, Username};

/// An account.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct User {
    pub id: UserId,
    pub username: Username,
    pub display_name: DisplayName,
    pub role: Role,
    /// Set means the account cannot sign in and its sessions stop verifying.
    pub disabled_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub lockout: Lockout,
}

impl User {
    pub fn is_disabled(&self) -> bool {
        self.disabled_at.is_some()
    }

    /// An administrator that is not disabled: the kind the last-administrator guard protects.
    pub fn is_active_administrator(&self) -> bool {
        self.role == Role::Administrator && !self.is_disabled()
    }

    /// This user with `patch` applied at `at`. Disabling an already disabled account keeps the
    /// original `disabled_at`.
    #[must_use]
    pub fn patched(&self, patch: &UserPatch, at: DateTime<Utc>) -> Self {
        let disabled_at = match patch.disabled {
            Some(true) => self.disabled_at.or(Some(at)),
            Some(false) => None,
            None => self.disabled_at,
        };
        Self {
            display_name: patch
                .display_name
                .clone()
                .unwrap_or_else(|| self.display_name.clone()),
            role: patch.role.unwrap_or(self.role),
            disabled_at,
            updated_at: at,
            ..self.clone()
        }
    }

    /// The last-administrator guard: changing this user into `next` (or deleting it, `None`)
    /// must leave at least one enabled administrator. `others` is the number of enabled
    /// administrators besides this user, counted inside the same transaction as the change.
    pub fn ensure_admin_remains(&self, next: Option<&User>, others: u64) -> AuthResult<()> {
        let stays = next.is_some_and(User::is_active_administrator);
        if self.is_active_administrator() && !stays && others == 0 {
            return Err(AuthError::LastAdministrator);
        }
        Ok(())
    }
}

/// A user to insert. `UserRepository::register` ignores `role`: the role comes from
/// [`RegisterPolicy::decide`] inside the repository lock.
#[derive(Clone, Debug)]
pub struct NewUser {
    pub id: UserId,
    pub username: Username,
    pub display_name: DisplayName,
    pub role: Role,
    pub created_at: DateTime<Utc>,
}

/// The fields `UserRepository::update` may change. Unset fields keep their stored value, so two
/// concurrent changes to different fields do not overwrite each other.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct UserPatch {
    pub display_name: Option<DisplayName>,
    pub role: Option<Role>,
    pub disabled: Option<bool>,
}

impl UserPatch {
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

/// What `AuthService::register` decided before the repository lock: whether open registration is
/// on and whether the caller presented the right setup token. The repository counts users again
/// inside its lock and calls [`RegisterPolicy::decide`], so two concurrent first registrations
/// produce exactly one administrator.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RegisterPolicy {
    pub registration_open: bool,
    pub setup_token_ok: bool,
}

impl RegisterPolicy {
    /// The role for a new self-registered account, given the number of accounts that `existing`
    /// already counts. The first account becomes an administrator and needs the setup token;
    /// later ones need open registration and become plain users.
    pub fn decide(&self, existing: u64) -> AuthResult<Role> {
        if existing == 0 {
            if self.setup_token_ok {
                Ok(Role::Administrator)
            } else {
                Err(AuthError::SetupRequired)
            }
        } else if self.registration_open {
            Ok(Role::User)
        } else {
            Err(AuthError::RegistrationClosed)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn user(role: Role) -> User {
        let now = DateTime::UNIX_EPOCH;
        User {
            id: UserId::generate(),
            username: Username::new("alice").expect("valid"),
            display_name: DisplayName::new("Alice").expect("valid"),
            role,
            disabled_at: None,
            created_at: now,
            updated_at: now,
            lockout: Lockout::default(),
        }
    }

    #[test]
    fn first_registration_needs_the_setup_token() {
        let without = RegisterPolicy {
            registration_open: true,
            setup_token_ok: false,
        };
        assert!(matches!(without.decide(0), Err(AuthError::SetupRequired)));
        let with = RegisterPolicy {
            registration_open: false,
            setup_token_ok: true,
        };
        assert_eq!(with.decide(0).expect("first"), Role::Administrator);
    }

    #[test]
    fn later_registrations_follow_registration_open() {
        let closed = RegisterPolicy {
            registration_open: false,
            setup_token_ok: true,
        };
        assert!(matches!(
            closed.decide(1),
            Err(AuthError::RegistrationClosed)
        ));
        let open = RegisterPolicy {
            registration_open: true,
            setup_token_ok: true,
        };
        assert_eq!(open.decide(3).expect("open"), Role::User);
    }

    #[test]
    fn patches_only_the_given_fields() {
        let at = DateTime::UNIX_EPOCH + chrono::TimeDelta::hours(1);
        let before = user(Role::User);
        let after = before.patched(
            &UserPatch {
                role: Some(Role::Manager),
                ..UserPatch::default()
            },
            at,
        );
        assert_eq!(after.role, Role::Manager);
        assert_eq!(after.display_name, before.display_name);
        assert_eq!(after.updated_at, at);
        assert!(!after.is_disabled());
    }

    #[test]
    fn disabling_keeps_the_first_timestamp() {
        let disable = UserPatch {
            disabled: Some(true),
            ..UserPatch::default()
        };
        let first = DateTime::UNIX_EPOCH + chrono::TimeDelta::hours(1);
        let later = first + chrono::TimeDelta::hours(1);
        let disabled = user(Role::User).patched(&disable, first);
        assert_eq!(disabled.disabled_at, Some(first));
        assert_eq!(disabled.patched(&disable, later).disabled_at, Some(first));
        let enable = UserPatch {
            disabled: Some(false),
            ..UserPatch::default()
        };
        assert_eq!(disabled.patched(&enable, later).disabled_at, None);
        assert!(UserPatch::default().is_empty());
        assert!(!enable.is_empty());
    }

    #[test]
    fn guards_the_last_enabled_administrator() {
        let admin = user(Role::Administrator);
        let demoted = admin.patched(
            &UserPatch {
                role: Some(Role::Manager),
                ..UserPatch::default()
            },
            admin.created_at,
        );
        let disabled = admin.patched(
            &UserPatch {
                disabled: Some(true),
                ..UserPatch::default()
            },
            admin.created_at,
        );
        for next in [Some(&demoted), Some(&disabled), None] {
            assert!(matches!(
                admin.ensure_admin_remains(next, 0),
                Err(AuthError::LastAdministrator)
            ));
            assert!(admin.ensure_admin_remains(next, 1).is_ok());
        }
        // Renaming the last administrator is fine.
        assert!(admin.ensure_admin_remains(Some(&admin), 0).is_ok());
        // Removing someone who is not an enabled administrator never trips the guard.
        assert!(user(Role::User).ensure_admin_remains(None, 0).is_ok());
        assert!(disabled.ensure_admin_remains(None, 0).is_ok());
    }
}
