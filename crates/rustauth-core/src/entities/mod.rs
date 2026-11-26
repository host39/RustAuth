//! Entities: `User` (with its `Lockout` state), `PasswordCredential`, `Session`, and the
//! `Principal` a verified request carries, plus the repository inputs that create or change them.
//!
//! Entity fields are public so adapters can build them from storage. Applications read them but
//! should not construct them; new fields may appear in any release.

mod credential;
mod lockout;
mod principal;
mod session;
mod user;

pub use crate::entities::credential::{NewPassword, PasswordCredential};
pub use crate::entities::lockout::Lockout;
pub use crate::entities::principal::Principal;
pub use crate::entities::session::Session;
pub use crate::entities::user::{NewUser, RegisterPolicy, User, UserPatch};
