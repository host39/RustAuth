//! Core entities to contract DTOs and back. Kept here because neither the core crate nor the
//! contracts crate may know the other.

use rustauth_contracts::{SessionResponse, SignInResponse, UserResponse, UserRole};
use rustauth_core::{AuthResult, Role, Session, SessionId, SignedIn, User};

/// The core role for a role sent by a client.
pub(crate) fn to_role(role: UserRole) -> AuthResult<Role> {
    role.as_str().parse()
}

/// The wire role for a core role. A role the contracts do not know yet is shown as the lowest
/// one, which is what clients are told to assume for unknown values.
pub(crate) fn to_user_role(role: Role) -> UserRole {
    UserRole::parse(role.as_str()).unwrap_or(UserRole::User)
}

pub(crate) fn to_user(user: &User) -> UserResponse {
    UserResponse {
        id: user.id.as_uuid(),
        username: user.username.as_str().to_owned(),
        display_name: user.display_name.as_str().to_owned(),
        role: to_user_role(user.role),
        disabled: user.is_disabled(),
        locked_until: user.lockout.locked_until,
        created_at: user.created_at,
        updated_at: user.updated_at,
    }
}

/// A session of the caller; `current` is the session the request was made with.
pub(crate) fn to_session(session: &Session, current: SessionId) -> SessionResponse {
    SessionResponse {
        id: session.id.as_uuid(),
        current: session.id == current,
        methods: session
            .methods
            .iter()
            .map(|method| method.as_str().to_owned())
            .collect(),
        assurance: session.assurance.as_str().to_owned(),
        created_at: session.created_at,
        last_used_at: session.last_used_at,
        expires_at: session.expires_at,
        user_agent: session.user_agent.clone(),
        ip: session.ip.map(|ip| ip.to_string()),
    }
}

pub(crate) fn to_sign_in(signed: &SignedIn) -> SignInResponse {
    SignInResponse {
        token: signed.token.expose().to_owned(),
        expires_at: signed.session.expires_at,
        user: to_user(&signed.user),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_role_round_trips() {
        for role in Role::ALL {
            assert_eq!(to_role(to_user_role(role)).expect("known role"), role);
        }
        for role in UserRole::ALL {
            assert_eq!(to_user_role(to_role(role).expect("known role")), role);
        }
    }
}
