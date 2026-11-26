//! RustAuth Postgres adapters: sqlx implementations of the `rustauth-core` repository ports and
//! the library's migrations.
//!
//! All tables live in the `auth` schema. Migrations are embedded in this crate and tracked in
//! `auth._sqlx_migrations`, so they never collide with an application's own migration history.
//! The library takes the application's `PgPool` (or a pool to a separate database).
//!
//! This crate must not depend on HTTP, OpenAPI, or crypto crates (`make boundaries`).

pub mod migrate;
pub mod repositories;

// Re-export the public API of each module here as it lands, so callers import from the crate root.
