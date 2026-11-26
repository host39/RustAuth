//! Use cases over the ports: `AuthService` (setup, register, login, verify, sessions),
//! `AdminService` (account administration with the last-administrator guard), `LoginGuard`
//! (account lockout and per-IP failure limits), and `RateLimiter` (public route limits).

mod admin;
mod auth;
#[cfg(test)]
mod fixture;
mod guard;
mod inputs;
mod limiter;
mod shared;

pub use crate::services::admin::AdminService;
pub use crate::services::auth::AuthService;
pub use crate::services::guard::{LoginGuard, Slot};
pub use crate::services::inputs::{NewAccount, Registration, SetupStatus, SignedIn, UserChanges};
pub use crate::services::limiter::RateLimiter;
