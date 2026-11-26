//! RustAuth HTTP contracts: request and response DTOs.
//!
//! - JSON fields are camelCase on the wire, and every type derives `utoipa::ToSchema` so
//!   applications can merge the auth routes into their own OpenAPI document.
//! - Under the `ts` feature the types derive `ts_rs::TS`. `make contracts` exports them to
//!   `packages/contracts/ts/generated/`, which the Zod schemas in `packages/contracts/ts/index.ts`
//!   must satisfy.
//!
//! This crate must not depend on database or HTTP framework crates (`make boundaries`).

pub mod admin;
pub mod auth;
pub mod error;

pub use crate::error::ErrorResponse;
