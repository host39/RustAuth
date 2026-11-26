//! Route tests: the auth router and guard over core's in-memory fakes, driven with
//! `tower::ServiceExt::oneshot`.

mod admin;
mod auth;
mod limits;
mod merge;
mod support;
