//! Value objects that validate on construction: `UserId`, `SessionId`, `Username`, `DisplayName`,
//! `Password`, `Role`, `SessionToken`, `TokenHash`, `ClientInfo`, `AuthMethod`, `Assurance`,
//! `IpRange`, and `Page`.
//!
//! Secrets (`Password`, `SessionToken`, `TokenHash`) redact themselves in `Debug` and are never
//! logged.

mod client;
mod display_name;
mod ids;
mod ip_range;
mod method;
mod page;
mod password;
mod role;
mod token;
mod username;

pub use crate::values::client::ClientInfo;
pub use crate::values::display_name::DisplayName;
pub use crate::values::ids::{SessionId, UserId};
pub use crate::values::ip_range::IpRange;
pub use crate::values::method::{Assurance, AuthMethod};
pub use crate::values::page::Page;
pub use crate::values::password::Password;
pub use crate::values::role::Role;
pub use crate::values::token::{SessionToken, TokenHash};
pub use crate::values::username::Username;
