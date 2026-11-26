//! RustAuth HTTP adapter for axum.
//!
//! - [`router`]: the `/auth/*` and `/admin/users` handlers as a `utoipa_axum` `OpenApiRouter`
//!   with its state applied, so applications merge it into their own router and OpenAPI
//!   document.
//! - [`Guard`]: a layer that verifies `Authorization: Bearer` and inserts [`AuthUser`], with
//!   optional and minimum-role variants.
//! - [`AuthUser`] and [`OptionalAuthUser`]: extractors for handlers behind the guard.
//! - [`client_ip`]: client IP resolution with trusted proxies.
//! - [`HttpError`]: maps `AuthError` to status codes, `Retry-After`, and the shared
//!   `ErrorResponse` envelope with the `X-Request-Id` echo.
//!
//! This crate talks to `rustauth-core` services only; it must not depend on database or crypto
//! crates (`make boundaries`).

pub mod error;
pub mod extract;
pub mod guard;
pub mod ip;
pub mod request_id;
pub mod routes;
pub mod state;

pub use crate::error::HttpError;
pub use crate::extract::{AuthUser, JsonBody, OptionalAuthUser, QueryParams};
pub use crate::guard::{Guard, GuardService};
pub use crate::ip::{client_info, client_ip};
pub use crate::request_id::{REQUEST_ID_HEADER, request_id, request_scope};
pub use crate::routes::{ADMIN_TAG, AUTH_TAG, SECURITY_SCHEME, router};
pub use crate::state::AuthState;
