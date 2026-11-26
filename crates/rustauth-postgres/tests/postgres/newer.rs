//! Rows a newer release wrote on the same schema (a rolling deploy, or a rollback with
//! `allow_newer_schema`): this release must keep serving them, reading unknown values
//! leniently, and must not overwrite them.

use std::sync::Arc;

use rustauth_core::testing::Fakes;
use rustauth_core::{
    Assurance, AuthConfig, AuthMethod, AuthService, Clock, Page, Ports, Role, SessionRepository,
    TokenIssuer, UserPatch, UserRepository,
};
use rustauth_postgres::{SqlxSessionRepository, SqlxUserRepository};
use sqlx::PgPool;

use crate::support::{at, create, session};

/// What a newer release could do: allow a new role, and write it with a username that today's
/// input rules reject.
async fn newer_account(pool: &PgPool, users: &SqlxUserRepository) -> rustauth_core::User {
    sqlx::raw_sql(
        "ALTER TABLE auth.users DROP CONSTRAINT users_role_check; \
         ALTER TABLE auth.users ADD CONSTRAINT users_role_check \
         CHECK (role IN ('administrator', 'manager', 'user', 'owner'))",
    )
    .execute(pool)
    .await
    .expect("widened the role check");
    let user = create(users, "elodie", Role::User).await;
    sqlx::query("UPDATE auth.users SET role = 'owner', username = 'élodie' WHERE id = $1")
        .bind(user.id.as_uuid())
        .execute(pool)
        .await
        .expect("written as a newer release would");
    user
}

#[sqlx::test(migrator = "rustauth_postgres::MIGRATOR")]
#[ignore = "requires Postgres: run make test-db"]
async fn reads_sessions_with_unknown_methods_and_assurance(pool: PgPool) {
    let users = SqlxUserRepository::new(pool.clone());
    let sessions = SqlxSessionRepository::new(pool.clone());
    let fakes = Fakes::new();
    let user = create(&users, "alice", Role::User).await;
    let (token, hash) = fakes.tokens.issue();
    let mut newer = session(user.id, 1);
    newer.token_hash = hash;
    newer.expires_at = fakes.clock.now() + chrono::TimeDelta::days(1);
    sessions.insert(&newer).await.expect("inserted");
    sessions
        .insert(&session(user.id, 2))
        .await
        .expect("inserted");
    sqlx::query(
        "UPDATE auth.sessions SET assurance = 'aal2', methods = '{password,totp}' WHERE id = $1",
    )
    .bind(newer.id.as_uuid())
    .execute(&pool)
    .await
    .expect("written as a newer release would");

    let (found, _) = sessions.find(&hash).await.expect("read").expect("exists");
    assert_eq!(
        found.methods,
        [AuthMethod::Password],
        "unknown methods are skipped"
    );
    assert_eq!(
        found.assurance,
        Assurance::Aal1,
        "unknown levels read as the lowest"
    );
    assert_eq!(sessions.list(user.id).await.expect("listed").len(), 2);

    let ports = Ports {
        users: Arc::new(users),
        sessions: Arc::new(sessions),
        ..fakes.ports()
    };
    let config = AuthConfig::builder()
        .setup_token("a-long-enough-setup-token")
        .build()
        .expect("valid config");
    let auth = AuthService::new(ports, config).await.expect("starts");
    let principal = auth.verify(token.expose()).await.expect("still verifies");
    assert_eq!(principal.assurance, Assurance::Aal1);
}

#[sqlx::test(migrator = "rustauth_postgres::MIGRATOR")]
#[ignore = "requires Postgres: run make test-db"]
async fn reads_unknown_roles_as_users_and_keeps_them(pool: PgPool) {
    let users = SqlxUserRepository::new(pool.clone());
    create(&users, "admin", Role::Administrator).await;
    let user = newer_account(&pool, &users).await;

    let read = users.get(user.id).await.expect("read").expect("exists");
    assert_eq!(read.role, Role::User, "the least privilege");
    assert_eq!(read.username.as_str(), "élodie");
    let (listed, total) = users.list(Page::default()).await.expect("listed");
    assert_eq!((listed.len(), total), (2, 2));

    // Renaming leaves the role this release does not know as it was.
    let patch = UserPatch {
        display_name: Some(rustauth_core::DisplayName::new("Élodie").expect("valid")),
        ..UserPatch::default()
    };
    let renamed = users.update(user.id, &patch, at(1)).await.expect("renamed");
    assert_eq!(renamed.display_name.as_str(), "Élodie");
    let stored: String = sqlx::query_scalar("SELECT role FROM auth.users WHERE id = $1")
        .bind(user.id.as_uuid())
        .fetch_one(&pool)
        .await
        .expect("read");
    assert_eq!(stored, "owner");

    // An explicit role change still applies.
    let demote = UserPatch {
        role: Some(Role::Manager),
        ..UserPatch::default()
    };
    let changed = users
        .update(user.id, &demote, at(2))
        .await
        .expect("changed");
    assert_eq!(changed.role, Role::Manager);
}
