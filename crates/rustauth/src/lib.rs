//! RustAuth: reusable authentication and authorization for axum + sqlx + Postgres applications.
//!
//! This facade is the only supported Rust surface; the inner crates (`rustauth-core`,
//! `rustauth-crypto`, `rustauth-postgres`, `rustauth-contracts`, `rustauth-axum`) may change in
//! any release. It holds [`RustAuth::builder()`], which wires the crypto and Postgres adapters
//! into the core services, [`migrate`], and the types applications use, re-exported by name.
//!
//! ```ignore
//! use rustauth::{AuthConfig, AuthUser, Role, RustAuth};
//!
//! // In the migrate step: the `auth` schema first, then the application's own migrations.
//! rustauth::migrate(&pool).await?;
//!
//! let auth = RustAuth::builder()
//!     .pool(pool.clone())
//!     .config(AuthConfig::parse(&std::env::vars().collect())?)
//!     .build()
//!     .await?;
//!
//! let (router, openapi) = OpenApiRouter::<AppState>::new()
//!     .nest("/api", auth.router().merge(widget_routes.layer(auth.guard())))
//!     .split_for_parts();
//! let app = router.with_state(app_state);
//! ```
//!
//! Features:
//!
//! - `axum` (default): HTTP routes, guard layer, and extractors.
//! - `postgres` (default): Postgres storage, the embedded `auth` schema migrations, and the
//!   schema check at startup.
//! - `testing`: in-memory fakes of every port ([`testing`]), for application tests.
//! - `ts`: `ts_rs::TS` derives on the [`contracts`].
//!
//! See `README.md` for the integration guide and `docs/design/rustauth.md` for the design.

mod builder;

pub use crate::builder::{BuildError, RustAuth, RustAuthBuilder};
pub use rustauth_core::{
    AdminService, Assurance, AuthConfig, AuthConfigBuilder, AuthError, AuthMethod, AuthResult,
    AuthService, ClientInfo, ConfigError, DisplayName, IpRange, Lockout, NewAccount, Page,
    Password, Principal, RateLimiter, Registration, Role, Session, SessionId, SessionToken,
    SetupStatus, SignedIn, User, UserChanges, UserId, Username,
};

#[cfg(feature = "axum")]
pub use rustauth_axum::{
    AuthUser, Guard, GuardService, HttpError, JsonBody, OptionalAuthUser, QueryParams,
    REQUEST_ID_HEADER, SECURITY_SCHEME, client_ip,
};

#[cfg(feature = "postgres")]
pub use rustauth_postgres::{SchemaStatus, migrate, schema_status};

/// The version of this library, from `Cargo.toml`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Request and response DTOs of the auth routes (camelCase JSON, `utoipa::ToSchema`, and
/// `ts_rs::TS` under the `ts` feature), for clients and for applications that export them.
pub mod contracts {
    pub use rustauth_contracts::{
        ChangePasswordRequest, CreateUserRequest, DetailsResponse, ErrorResponse, ListResponse,
        ListUsersQuery, LoginRequest, RegisterRequest, SessionResponse, SetupStatusResponse,
        SignInResponse, UpdateProfileRequest, UpdateUserRequest, UserResponse, UserRole,
    };
}

/// The ports the services run on, for [`RustAuthBuilder::ports`]: custom storage, or the fakes
/// from [`testing`]. The default crypto adapters are here too, to combine with custom storage.
pub mod ports {
    pub use rustauth_core::{
        Clock, NewPassword, NewUser, PasswordCredential, PasswordHasher, Ports, RegisterPolicy,
        SessionRepository, SystemClock, TokenHash, TokenIssuer, UserPatch, UserRepository,
    };
    pub use rustauth_crypto::{Argon2Hasher, RandomTokens};
}

/// In-memory fakes of every port, for tests without Postgres:
/// `RustAuth::builder().ports(Fakes::new().ports())`. Never use them in production: the
/// hasher keeps passwords almost in the clear and the tokens are predictable.
#[cfg(feature = "testing")]
pub mod testing {
    pub use rustauth_core::testing::{FakeClock, FakeHasher, FakeTokens, Fakes, MemoryStore};
}

#[cfg(all(test, feature = "axum"))]
mod tests;
