//! RustAuth crypto adapters that implement `rustauth-core` ports.
//!
//! - [`Argon2Hasher`] (`PasswordHasher`): Argon2id with the `argon2` defaults (m = 19 MiB, t = 2,
//!   p = 1), run in `spawn_blocking` behind a small semaphore.
//! - [`RandomTokens`] (`TokenIssuer`): 256-bit session tokens from the OS RNG (base64url, no
//!   padding) and their SHA-256 hashes, which are the only form ever stored.
//!
//! This crate must not depend on HTTP or database crates (`make boundaries`).

pub mod hasher;
pub mod tokens;

pub use crate::hasher::Argon2Hasher;
pub use crate::tokens::RandomTokens;
