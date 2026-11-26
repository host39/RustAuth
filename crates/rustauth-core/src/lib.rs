//! RustAuth domain layer: value objects, entities, ports, services, and `AuthError`.
//!
//! Services hold their ports as `Arc<dyn Trait>`. Adapter crates implement the ports
//! (`rustauth-crypto` for password hashing and session tokens, `rustauth-postgres` for storage),
//! and the `rustauth` facade wires them together.
//!
//! This crate must not depend on HTTP, database, OpenAPI, TypeScript, or hashing crates, or on any
//! other rustauth crate (`make boundaries`). See `docs/design/rustauth.md` for the domain model.

pub mod entities;
pub mod error;
pub mod ports;
pub mod services;
#[cfg(feature = "testing")]
pub mod testing;
pub mod values;

// Re-export the public API of each module here as it lands, so callers import from the crate root.
