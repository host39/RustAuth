//! Identifiers: `UserId` and `SessionId`, UUID v7 generated in Rust.

use std::fmt;

use uuid::Uuid;

macro_rules! identifier {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(Uuid);

        impl $name {
            /// A new time-ordered (v7) identifier.
            pub fn generate() -> Self {
                Self(Uuid::now_v7())
            }

            pub fn as_uuid(&self) -> Uuid {
                self.0
            }
        }

        impl From<Uuid> for $name {
            fn from(value: Uuid) -> Self {
                Self(value)
            }
        }

        impl From<$name> for Uuid {
            fn from(value: $name) -> Self {
                value.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }
    };
}

identifier! {
    /// Identifies an account. Stored as `auth.users.id`, the one stable database contract.
    UserId
}

identifier! {
    /// Identifies a session (one signed-in device). Not secret: the bearer token is.
    SessionId
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_distinct_v7_ids() {
        let first = UserId::generate();
        let second = UserId::generate();
        assert_ne!(first, second);
        assert_eq!(first.as_uuid().get_version_num(), 7);
    }

    #[test]
    fn converts_to_and_from_uuid() {
        let uuid = Uuid::now_v7();
        let id = SessionId::from(uuid);
        assert_eq!(Uuid::from(id), uuid);
        assert_eq!(id.to_string(), uuid.to_string());
    }
}
