//! RustAuth: reusable authentication and authorization for axum + sqlx + Postgres applications.
//!
//! This facade is the only supported Rust surface; the inner crates (`rustauth-core`,
//! `rustauth-crypto`, `rustauth-postgres`, `rustauth-contracts`, `rustauth-axum`) may change in
//! any release. It will hold `RustAuth::builder()`, which wires the crypto and Postgres adapters
//! into the core services, plus `migrate` and curated re-exports of the types applications use.
//!
//! Features:
//!
//! - `axum` (default): HTTP routes, guard layer, and extractors.
//! - `postgres` (default): Postgres storage and the embedded `auth` schema migrations.
//! - `ts`: `ts_rs::TS` derives on the contracts.
//!
//! See `README.md` for the integration example and `docs/design/rustauth.md` for the design.

/// The version of this library, from `Cargo.toml`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

// Curated re-exports from the inner crates land here as their APIs do.
