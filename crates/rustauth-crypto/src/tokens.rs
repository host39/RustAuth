//! Implementation of the `TokenIssuer` port: random session tokens and their SHA-256 hashes.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rustauth_core::{SessionToken, TokenHash, TokenIssuer};
use sha2::{Digest as _, Sha256};

/// Session tokens of 32 bytes (256 bits) from the OS random number generator, encoded as
/// base64url without padding (43 characters). Only their SHA-256 hash is stored, and sessions
/// are looked up by it, so a database leak exposes no usable token.
#[derive(Clone, Copy, Debug, Default)]
pub struct RandomTokens;

impl RandomTokens {
    /// Random bytes per token.
    pub const BYTES: usize = 32;
}

impl TokenIssuer for RandomTokens {
    /// # Panics
    ///
    /// When the operating system's random number generator fails, which `getrandom` reports
    /// only on unsupported or badly broken platforms. Issuing a guessable token instead is not
    /// an option.
    fn issue(&self) -> (SessionToken, TokenHash) {
        let mut bytes = [0u8; Self::BYTES];
        getrandom::fill(&mut bytes).expect("the OS random number generator is available");
        let token = URL_SAFE_NO_PAD.encode(bytes);
        let hash = self.hash(&token);
        (SessionToken::new(token), hash)
    }

    /// SHA-256 of the token text as the client presents it.
    fn hash(&self, token: &str) -> TokenHash {
        TokenHash::new(Sha256::digest(token.as_bytes()).into())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    #[test]
    fn issues_32_random_bytes_as_unpadded_base64url() {
        let (token, _) = RandomTokens.issue();
        let text = token.expose();
        assert_eq!(text.len(), 43, "{text}");
        assert!(
            text.chars()
                .all(|char| char.is_ascii_alphanumeric() || char == '-' || char == '_'),
            "{text}"
        );
        let bytes = URL_SAFE_NO_PAD.decode(text).expect("base64url");
        assert_eq!(bytes.len(), RandomTokens::BYTES);
    }

    #[test]
    fn issues_unique_tokens_and_hashes() {
        let issued: Vec<_> = (0..1000).map(|_| RandomTokens.issue()).collect();
        let tokens: HashSet<&str> = issued.iter().map(|(token, _)| token.expose()).collect();
        let hashes: HashSet<TokenHash> = issued.iter().map(|(_, hash)| *hash).collect();
        assert_eq!(tokens.len(), issued.len());
        assert_eq!(hashes.len(), issued.len());
    }

    #[test]
    fn returns_the_hash_of_the_issued_token() {
        let (token, hash) = RandomTokens.issue();
        assert_eq!(RandomTokens.hash(token.expose()), hash);
    }

    #[test]
    fn hashes_with_sha256() {
        // FIPS 180-2 test vector: SHA-256("abc").
        let expected = [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
            0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
            0xf2, 0x00, 0x15, 0xad,
        ];
        assert_eq!(RandomTokens.hash("abc").as_bytes(), &expected);
        assert_ne!(RandomTokens.hash("abc"), RandomTokens.hash("abd"));
    }
}
