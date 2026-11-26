//! `FakeTokens`: predictable tokens (`token-1`, `token-2`, ...) with a deterministic hash.

use std::hash::{DefaultHasher, Hash, Hasher};
use std::sync::atomic::{AtomicU64, Ordering};

use crate::ports::TokenIssuer;
use crate::values::{SessionToken, TokenHash};

#[derive(Debug, Default)]
pub struct FakeTokens {
    issued: AtomicU64,
}

impl FakeTokens {
    /// How many tokens were issued. `AuthService::new` issues two (the generated setup token,
    /// or a filler when one is configured, then the dummy password), so the first session gets
    /// `token-3`.
    pub fn issued(&self) -> u64 {
        self.issued.load(Ordering::SeqCst)
    }
}

impl TokenIssuer for FakeTokens {
    fn issue(&self) -> (SessionToken, TokenHash) {
        let number = self.issued.fetch_add(1, Ordering::SeqCst) + 1;
        let token = format!("token-{number}");
        let hash = self.hash(&token);
        (SessionToken::new(token), hash)
    }

    /// Four seeded SipHash runs (fixed keys, so stable within a build) fill the 32 bytes.
    fn hash(&self, token: &str) -> TokenHash {
        let mut bytes = [0u8; TokenHash::LEN];
        for (seed, chunk) in bytes.chunks_exact_mut(8).enumerate() {
            let mut hasher = DefaultHasher::new();
            seed.hash(&mut hasher);
            token.hash(&mut hasher);
            chunk.copy_from_slice(&hasher.finish().to_le_bytes());
        }
        TokenHash::new(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issues_numbered_tokens_with_stable_hashes() {
        let tokens = FakeTokens::default();
        let (first, first_hash) = tokens.issue();
        let (second, second_hash) = tokens.issue();
        assert_eq!(first.expose(), "token-1");
        assert_eq!(second.expose(), "token-2");
        assert_eq!(tokens.hash("token-1"), first_hash);
        assert_ne!(first_hash, second_hash);
        assert_eq!(tokens.issued(), 2);
    }
}
