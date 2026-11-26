//! In-memory fakes of every port (enabled by the `testing` feature) for unit tests in this
//! workspace and in applications. Never use them in production: the hasher stores passwords
//! almost in the clear and the tokens are predictable.
//!
//! ```
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! use rustauth_core::testing::Fakes;
//! use rustauth_core::{AuthConfig, AuthService};
//!
//! let fakes = Fakes::new();
//! let config = AuthConfig::builder().setup_token("a-long-enough-setup-token").build()?;
//! let auth = AuthService::new(fakes.ports(), config).await?;
//! # let _ = auth;
//! # Ok(())
//! # }
//! ```

mod clock;
mod hasher;
mod store;
mod tokens;

use std::sync::Arc;

pub use crate::testing::clock::FakeClock;
pub use crate::testing::hasher::FakeHasher;
pub use crate::testing::store::MemoryStore;
pub use crate::testing::tokens::FakeTokens;

use crate::ports::Ports;

/// One of each fake, sharing state the way the real adapters share a database.
#[derive(Clone, Debug, Default)]
pub struct Fakes {
    pub clock: Arc<FakeClock>,
    pub hasher: Arc<FakeHasher>,
    pub store: Arc<MemoryStore>,
    pub tokens: Arc<FakeTokens>,
}

impl Fakes {
    pub fn new() -> Self {
        Self::default()
    }

    /// The fakes as service ports. `store` serves as both repositories.
    pub fn ports(&self) -> Ports {
        Ports::new(
            self.store.clone(),
            self.store.clone(),
            self.hasher.clone(),
            self.tokens.clone(),
            self.clock.clone(),
        )
    }
}
