//! Repository and migration tests against a real Postgres.
//!
//! `#[sqlx::test]` gives each test a throwaway database on the server that `DATABASE_URL` points
//! at (`make test-db` uses the server's `postgres` maintenance database for that). The tests are
//! ignored by default, so `make test` needs no database.

mod migrate;
mod newer;
mod services;
mod sessions;
mod support;
mod users;
