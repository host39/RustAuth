//! RustAuth domain layer: value objects, entities, ports, services, and `AuthError`.
//!
//! Services hold their ports as `Arc<dyn Trait>` (bundled in [`Ports`]). Adapter crates implement
//! the ports (`rustauth-crypto` for password hashing and session tokens, `rustauth-postgres` for
//! storage), and the `rustauth` facade wires them together.
//!
//! This crate must not depend on HTTP, database, OpenAPI, TypeScript, or hashing crates, or on any
//! other rustauth crate (`make boundaries`). See `docs/design/rustauth.md` for the domain model.
//!
//! The `testing` feature adds in-memory fakes of every port ([`testing`]) for unit tests here, in
//! the adapter crates, and in applications.

pub mod config;
pub mod entities;
pub mod error;
pub mod ports;
pub mod services;
#[cfg(any(test, feature = "testing"))]
pub mod testing;
pub mod values;

pub use crate::config::{AuthConfig, AuthConfigBuilder, ConfigError};
pub use crate::entities::{
    Lockout, NewPassword, NewUser, PasswordCredential, Principal, RegisterPolicy, Reservation,
    Session, Subject, User, UserPatch,
};
pub use crate::error::{AuthError, AuthResult, BoxError};
pub use crate::ports::{
    Clock, PasswordHasher, Ports, SessionRepository, SystemClock, TokenIssuer, UserRepository,
};
pub use crate::services::{
    AdminService, AuthService, LoginGuard, NewAccount, RateLimiter, Registration, SetupStatus,
    SignedIn, Slot, UserChanges,
};
pub use crate::values::{
    Assurance, AuthMethod, ClientInfo, DisplayName, IpRange, Page, Password, Role, SessionId,
    SessionToken, TokenHash, UserId, Username,
};
