//! `TokenIssuer`: creates bearer tokens and hashes them for storage and lookup.

use crate::values::{SessionToken, TokenHash};

/// Implemented by `rustauth-crypto`: 32 random bytes from the OS RNG, base64url without padding,
/// hashed with SHA-256.
pub trait TokenIssuer: Send + Sync {
    /// A new random token and its hash.
    fn issue(&self) -> (SessionToken, TokenHash);

    /// The hash of a presented token, for lookups and constant-time comparisons.
    fn hash(&self, token: &str) -> TokenHash;
}
