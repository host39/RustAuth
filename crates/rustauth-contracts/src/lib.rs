//! RustAuth HTTP contracts: request and response DTOs.
//!
//! - JSON fields are camelCase on the wire, and every type derives `utoipa::ToSchema` (schemas
//!   are named `rustauth.*`, so they cannot collide with an application's own schemas when it
//!   merges the auth routes into its OpenAPI document).
//! - Success bodies use the RustInit template's envelopes ([`DetailsResponse`] and
//!   [`ListResponse`]) and failures its [`ErrorResponse`], so applications parse one shape.
//! - Under the `ts` feature the types derive `ts_rs::TS`. `make contracts` exports them to
//!   `packages/contracts/ts/generated/`, which the Zod schemas in `packages/contracts/ts/index.ts`
//!   must satisfy.
//!
//! This crate must not depend on database or HTTP framework crates (`make boundaries`).

pub mod admin;
pub mod auth;
pub mod envelopes;
pub mod error;
pub mod user;

pub use crate::admin::{CreateUserRequest, ListUsersQuery, UpdateUserRequest};
pub use crate::auth::{
    ChangePasswordRequest, LoginRequest, RegisterRequest, SessionResponse, SetupStatusResponse,
    SignInResponse, UpdateProfileRequest,
};
pub use crate::envelopes::{DetailsResponse, ListResponse};
pub use crate::error::ErrorResponse;
pub use crate::user::{UserResponse, UserRole};
