//! Helpers shared by the repositories: driver error mapping and the advisory lock.

use rustauth_core::{AuthError, AuthResult};
use sqlx::PgConnection;

/// Key of the transaction-scoped advisory lock that serializes self-registration and every
/// change the last-administrator guard checks: the ASCII bytes of `rustauth`. The two-integer
/// form of `pg_advisory_xact_lock` uses a separate key space, so applications that lock on
/// their own keys do not collide with it unless they pick this exact number.
pub(crate) const LOCK_KEY: i64 = i64::from_be_bytes(*b"rustauth");

/// Maps a driver error to `AuthError::Internal` under the dotted log key `key`.
pub(crate) fn internal(key: &'static str) -> impl FnOnce(sqlx::Error) -> AuthError {
    move |error| AuthError::internal(key, error)
}

/// Whether `error` violates the constraint or unique index called `name`.
pub(crate) fn violates(error: &sqlx::Error, name: &str) -> bool {
    error
        .as_database_error()
        .and_then(|error| error.constraint())
        == Some(name)
}

/// Whether `error` is a foreign key violation: the referenced user no longer exists, or (on a
/// delete) another row still references it.
pub(crate) fn orphaned(error: &sqlx::Error) -> bool {
    error
        .as_database_error()
        .is_some_and(|error| error.is_foreign_key_violation())
}

/// Takes the advisory lock until the transaction on `conn` ends. Every caller takes it before
/// any row lock, so lock order is the same everywhere and transactions cannot deadlock on it.
pub(crate) async fn advisory_lock(conn: &mut PgConnection, key: &'static str) -> AuthResult<()> {
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(LOCK_KEY)
        .execute(conn)
        .await
        .map_err(internal(key))?;
    Ok(())
}

/// A row count from Postgres (`bigint`) as the ports return it.
pub(crate) fn count(value: i64) -> u64 {
    u64::try_from(value).unwrap_or_default()
}
