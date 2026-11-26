//! RustAuth Postgres adapters: sqlx implementations of the `rustauth-core` repository ports and
//! the library's migrations.
//!
//! All tables live in the `auth` schema. Migrations are embedded in this crate and tracked in
//! `auth._sqlx_migrations`, so they never collide with an application's own migration history.
//! The library takes the application's `PgPool` (or a pool to a separate database).
//!
//! - [`migrate`]: creates the schema and applies pending migrations; [`MIGRATOR`] is the
//!   underlying `sqlx` migrator.
//! - [`schema_status`]: compares the applied migrations with the embedded ones (the facade's
//!   startup check).
//! - [`SqlxUserRepository`] and [`SqlxSessionRepository`]: the repository ports.
//!
//! This crate must not depend on HTTP, OpenAPI, or crypto crates (`make boundaries`).

pub mod migrate;
pub mod repositories;
pub mod schema;

pub use crate::migrate::{MIGRATIONS_TABLE, MIGRATOR, SCHEMA, migrate};
pub use crate::repositories::{SqlxSessionRepository, SqlxUserRepository};
pub use crate::schema::{SchemaStatus, schema_status};
