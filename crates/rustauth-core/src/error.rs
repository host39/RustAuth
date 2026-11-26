//! `AuthError`: every failure a service returns.
//!
//! Variants carry human-readable messages and stable codes (`INVALID_CREDENTIALS`,
//! `ACCOUNT_LOCKED`, ...). Only `Internal` uses a dotted key (`rustauth.users.insert.failed`).
//! HTTP status mapping lives in `rustauth-axum`, not here.
