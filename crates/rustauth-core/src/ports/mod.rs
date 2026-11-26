//! Ports implemented by adapter crates: `Clock`, `PasswordHasher`, `TokenIssuer`,
//! `UserRepository`, and `SessionRepository`.
//!
//! Every async method returns `Result<_, AuthError>`; traits are `Send + Sync` and used as
//! `Arc<dyn Trait>`.
