//! `AuthMethod` and `Assurance`: how a session was established.

use std::fmt;
use std::str::FromStr;

use crate::error::AuthError;

/// A sign-in method used for a session. v0.1 has `password`; `totp`, `passkey`, and `sso` come
/// later, so match with a wildcard arm.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum AuthMethod {
    Password,
}

impl AuthMethod {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Password => "password",
        }
    }
}

impl fmt::Display for AuthMethod {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for AuthMethod {
    type Err = AuthError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "password" => Ok(Self::Password),
            _ => Err(AuthError::validation(
                "method",
                "Sign-in method must be password.",
            )),
        }
    }
}

/// Authenticator assurance level of a session (NIST SP 800-63B). v0.1 has `aal1` (one factor);
/// `aal2` arrives with two-factor sign-in. Ordered so a check for a minimum level works.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[non_exhaustive]
pub enum Assurance {
    Aal1,
}

impl Assurance {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Aal1 => "aal1",
        }
    }
}

impl fmt::Display for Assurance {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for Assurance {
    type Err = AuthError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "aal1" => Ok(Self::Aal1),
            _ => Err(AuthError::validation(
                "assurance",
                "Assurance level must be aal1.",
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_through_text() {
        assert_eq!(
            "password".parse::<AuthMethod>().expect("known"),
            AuthMethod::Password
        );
        assert_eq!(AuthMethod::Password.to_string(), "password");
        assert_eq!("aal1".parse::<Assurance>().expect("known"), Assurance::Aal1);
        assert_eq!(Assurance::Aal1.to_string(), "aal1");
    }

    #[test]
    fn rejects_unknown_values() {
        assert!("passkey".parse::<AuthMethod>().is_err());
        assert!("aal3".parse::<Assurance>().is_err());
    }
}
