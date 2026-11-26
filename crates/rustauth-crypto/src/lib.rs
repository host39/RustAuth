//! RustAuth crypto adapters that implement `rustauth-core` ports.
//!
//! - `hasher`: Argon2id with the `argon2` defaults (m = 19 MiB, t = 2, p = 1), run in
//!   `spawn_blocking` behind a small semaphore.
//! - `tokens`: 256-bit session tokens from the OS RNG (base64url, no padding) and their SHA-256
//!   hashes, which are the only form ever stored.
//!
//! This crate must not depend on HTTP or database crates (`make boundaries`).

pub mod hasher;
pub mod tokens;

// Re-export the public API of each module here as it lands, so callers import from the crate root.
