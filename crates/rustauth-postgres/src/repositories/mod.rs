//! sqlx implementations of `UserRepository` and `SessionRepository`.
//!
//! Queries are checked at runtime (`sqlx::query_as`), so builds never need a database. Driver
//! errors become `AuthError::internal("rustauth.<table>.<operation>.failed", error)`; a duplicate
//! username becomes `AuthError::UsernameTaken`.

mod rows;
mod sessions;
mod shared;
mod users;

pub use crate::repositories::sessions::SqlxSessionRepository;
pub use crate::repositories::users::SqlxUserRepository;
