//! RustAuth: reusable authentication and authorization for axum + sqlx + Postgres applications.
//!
//! This facade is the only supported Rust surface; the inner crates (`rustauth-core`,
//! `rustauth-crypto`, `rustauth-postgres`, `rustauth-contracts`, `rustauth-axum`) may change in
//! any release. It holds [`RustAuth::builder()`], which wires the crypto and Postgres adapters
//! into the core services, [`migrate`], and the types applications use, re-exported by name.
//!
//! ```no_run
//! use std::collections::HashMap;
//! use std::net::SocketAddr;
//!
//! use rustauth::{AuthConfig, AuthUser, HttpError, Role, RustAuth};
//! use utoipa_axum::router::OpenApiRouter;
//!
//! #[derive(Clone)]
//! struct AppState;
//!
//! async fn delete_widget(user: AuthUser) -> Result<&'static str, HttpError> {
//!     user.require(Role::Manager)?; // 403 below manager
//!     Ok("deleted")
//! }
//!
//! # async fn example(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
//! // In the migrate step: the `auth` schema first, then the application's own migrations.
//! rustauth::migrate(&pool).await?;
//!
//! let env: HashMap<String, String> = std::env::vars().collect();
//! let auth = RustAuth::builder()
//!     .pool(pool.clone())
//!     .config(AuthConfig::parse(&env)?)
//!     .build()
//!     .await?;
//!
//! let widgets = OpenApiRouter::<AppState>::new()
//!     .route("/widgets/{id}", axum::routing::delete(delete_widget))
//!     .layer(auth.guard());
//! let (router, _openapi) = OpenApiRouter::<AppState>::new()
//!     .nest("/api", auth.router().merge(widgets))
//!     .split_for_parts();
//! let app = router.with_state(AppState);
//!
//! // The peer address feeds the per-IP limits and `AUTH_TRUSTED_PROXIES`.
//! let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await?;
//! axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await?;
//! # Ok(())
//! # }
//! ```
//!
//! Features:
//!
//! - `axum` (default): HTTP routes, guard layer, and extractors; turns on `contracts`.
//! - `postgres` (default): Postgres storage and the schema check at startup; turns on `migrate`
//!   and `crypto`.
//! - `migrate`: only `migrate` and `schema_status`, for a crate that runs the migrate step
//!   (`default-features = false, features = ["migrate"]` pulls in no HTTP, OpenAPI, or hashing
//!   crates).
//! - `contracts`: the request and response DTOs (`contracts`).
//! - `crypto`: the Argon2id hasher and random tokens in `ports`, for custom storage.
//! - `testing`: in-memory fakes of every port (`testing`), for application tests.
//! - `ts`: `ts_rs::TS` derives on the contracts; turns on `contracts`.
//!
//! See `docs/integration.md` for the integration guide and `docs/design/rustauth.md` for the design.

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
    ADMIN_TAG, AUTH_TAG, AuthUser, Guard, GuardService, HttpError, JsonBody, OptionalAuthUser,
    QueryParams, REQUEST_ID_HEADER, SECURITY_SCHEME, client_ip, request_scope,
};

#[cfg(feature = "migrate")]
pub use rustauth_postgres::{SchemaStatus, migrate, schema_status};

/// The version of this library, from `Cargo.toml`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Request and response DTOs of the auth routes (camelCase JSON, `utoipa::ToSchema`, and
/// `ts_rs::TS` under the `ts` feature), for clients and for applications that export them.
#[cfg(feature = "contracts")]
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
        Reservation, SessionRepository, Subject, SystemClock, TokenHash, TokenIssuer, UserPatch,
        UserRepository,
    };
    #[cfg(feature = "crypto")]
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
