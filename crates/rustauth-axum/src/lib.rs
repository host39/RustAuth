//! RustAuth HTTP adapter for axum.
//!
//! - `routes`: the `/auth/*` and `/admin/users` handlers as a `utoipa_axum` `OpenApiRouter` with
//!   its state applied, so applications merge it into their own router and OpenAPI document.
//! - `guard`: a layer that verifies `Authorization: Bearer` and inserts `AuthUser`.
//! - `extract`: the `AuthUser` and `OptionalAuthUser` extractors and role checks.
//! - `ip`: client IP resolution with trusted proxies.
//! - `error`: maps `AuthError` to status codes and the shared `ErrorResponse` envelope.
//!
//! This crate talks to `rustauth-core` services only; it must not depend on database or crypto
//! crates (`make boundaries`).

pub mod error;
pub mod extract;
pub mod guard;
pub mod ip;
pub mod routes;

// Re-export the public API of each module here as it lands, so callers import from the crate root.
