//! Ports implemented by adapter crates: `Clock`, `PasswordHasher`, `TokenIssuer`,
//! `UserRepository`, and `SessionRepository`, bundled as `Ports` for the services.
//!
//! Every async method returns `AuthResult<_>`; traits are `Send + Sync` and used as
//! `Arc<dyn Trait>`. Infrastructure failures surface as `AuthError::internal("rustauth.<area>...")`.

mod clock;
mod hasher;
mod sessions;
mod tokens;
mod users;

use std::sync::Arc;

pub use crate::ports::clock::{Clock, SystemClock};
pub use crate::ports::hasher::PasswordHasher;
pub use crate::ports::sessions::SessionRepository;
pub use crate::ports::tokens::TokenIssuer;
pub use crate::ports::users::UserRepository;

/// The adapters the services run on. The `rustauth` facade fills it with the crypto and Postgres
/// adapters; tests fill it with the in-memory fakes from the `testing` module.
///
/// Built with [`Ports::new`] (fields stay readable). Later releases add ports for new sign-in
/// methods with defaults, so code that builds it keeps compiling.
#[derive(Clone)]
#[non_exhaustive]
pub struct Ports {
    pub users: Arc<dyn UserRepository>,
    pub sessions: Arc<dyn SessionRepository>,
    pub hasher: Arc<dyn PasswordHasher>,
    pub tokens: Arc<dyn TokenIssuer>,
    pub clock: Arc<dyn Clock>,
}

impl Ports {
    pub fn new(
        users: Arc<dyn UserRepository>,
        sessions: Arc<dyn SessionRepository>,
        hasher: Arc<dyn PasswordHasher>,
        tokens: Arc<dyn TokenIssuer>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            users,
            sessions,
            hasher,
            tokens,
            clock,
        }
    }
}
