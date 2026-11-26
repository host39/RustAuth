//! `SessionToken` (the bearer secret) and `TokenHash` (the only form ever stored).

use std::array::TryFromSliceError;
use std::fmt;
use std::hint::black_box;

/// An opaque bearer token: 32 random bytes, base64url without padding. Shown to the client once
/// at sign-in and never stored or logged. `Debug` prints `***`; there is no `Display` or `Eq`.
#[derive(Clone)]
pub struct SessionToken(String);

impl SessionToken {
    /// Wraps a token produced by a `TokenIssuer`.
    pub fn new(value: String) -> Self {
        Self(value)
    }

    /// The token text, for the response body only.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SessionToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SessionToken(***)")
    }
}

/// SHA-256 of a token string. Sessions are stored and looked up by this hash. `Debug` is
/// redacted as well, because hashes stay out of logs.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct TokenHash([u8; TokenHash::LEN]);

impl TokenHash {
    pub const LEN: usize = 32;

    pub fn new(bytes: [u8; Self::LEN]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; Self::LEN] {
        &self.0
    }

    /// Constant-time equality, for comparing secrets (such as the setup token) by their hashes.
    /// Both sides have the same fixed length, so neither content nor length leaks through timing.
    pub fn matches(&self, other: &TokenHash) -> bool {
        let mut difference = 0u8;
        for (left, right) in self.0.iter().zip(other.0.iter()) {
            difference |= black_box(left ^ right);
        }
        black_box(difference) == 0
    }
}

impl TryFrom<&[u8]> for TokenHash {
    type Error = TryFromSliceError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        Ok(Self(bytes.try_into()?))
    }
}

impl fmt::Debug for TokenHash {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TokenHash(***)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_is_redacted() {
        let token = SessionToken::new("secret-token".to_owned());
        assert_eq!(format!("{token:?}"), "SessionToken(***)");
        assert_eq!(token.expose(), "secret-token");
        let hash = TokenHash::new([7; 32]);
        assert_eq!(format!("{hash:?}"), "TokenHash(***)");
    }

    #[test]
    fn matches_only_identical_hashes() {
        let hash = TokenHash::new([1; 32]);
        assert!(hash.matches(&TokenHash::new([1; 32])));
        let mut other = [1; 32];
        other[31] = 2;
        assert!(!hash.matches(&TokenHash::new(other)));
        other[31] = 1;
        other[0] = 0;
        assert!(!hash.matches(&TokenHash::new(other)));
    }

    #[test]
    fn reads_exactly_32_bytes() {
        let bytes = vec![9u8; 32];
        let hash = TokenHash::try_from(bytes.as_slice()).expect("32 bytes");
        assert_eq!(hash.as_bytes(), &[9; 32]);
        assert!(TokenHash::try_from(&bytes[..31]).is_err());
    }
}
