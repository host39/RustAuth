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
#[derive(Clone)]
pub struct Ports {
    pub users: Arc<dyn UserRepository>,
    pub sessions: Arc<dyn SessionRepository>,
    pub hasher: Arc<dyn PasswordHasher>,
    pub tokens: Arc<dyn TokenIssuer>,
    pub clock: Arc<dyn Clock>,
}
