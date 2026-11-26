//! `SqlxSessionRepository`: lookups by token hash, sliding, listing, revocation, and purging.

use std::collections::HashSet;
use std::net::IpAddr;

use rustauth_core::{
    AuthError, Role, Session, SessionId, SessionRepository, TokenHash, UserId, UserPatch,
    UserRepository,
};
use rustauth_postgres::{SqlxSessionRepository, SqlxUserRepository};
use sqlx::PgPool;

use crate::support::{at, create, session};

fn repositories(pool: &PgPool) -> (SqlxUserRepository, SqlxSessionRepository) {
    (
        SqlxUserRepository::new(pool.clone()),
        SqlxSessionRepository::new(pool.clone()),
    )
}

fn ids(sessions: &[Session]) -> HashSet<SessionId> {
    sessions.iter().map(|session| session.id).collect()
}

#[sqlx::test(migrator = "rustauth_postgres::MIGRATOR")]
#[ignore = "requires Postgres: run make test-db"]
async fn finds_a_session_with_its_user_by_token_hash(pool: PgPool) {
    let (users, sessions) = repositories(&pool);
    let user = create(&users, "alice", Role::Manager).await;
    let addresses: [Option<IpAddr>; 4] = [
        Some("203.0.113.7".parse().expect("IPv4")),
        Some("2001:db8::1".parse().expect("IPv6")),
        Some("::ffff:192.0.2.1".parse().expect("IPv4-mapped IPv6")),
        None,
    ];
    for (seed, ip) in (1u8..).zip(addresses) {
        let mut stored = session(user.id, seed);
        stored.ip = ip;
        sessions.insert(&stored).await.expect("inserted");
        let (found, owner) = sessions
            .find(&stored.token_hash)
            .await
            .expect("looked up")
            .expect("exists");
        assert_eq!(found, stored, "{ip:?}");
        assert_eq!(owner, user);
    }
    let unknown = TokenHash::new([0xee; TokenHash::LEN]);
    assert!(sessions.find(&unknown).await.expect("looked up").is_none());

    // The joined user reflects its current state, so a disabled account is visible to `verify`.
    create(&users, "admin", Role::Administrator).await;
    let disable = UserPatch {
        disabled: Some(true),
        ..UserPatch::default()
    };
    users
        .update(user.id, &disable, at(1))
        .await
        .expect("disabled");
    let (_, owner) = sessions
        .find(&session(user.id, 1).token_hash)
        .await
        .expect("looked up")
        .expect("exists");
    assert!(owner.is_disabled());
}

#[sqlx::test(migrator = "rustauth_postgres::MIGRATOR")]
#[ignore = "requires Postgres: run make test-db"]
async fn refuses_sessions_of_missing_users_and_duplicate_hashes(pool: PgPool) {
    let (users, sessions) = repositories(&pool);
    let missing = sessions
        .insert(&session(UserId::generate(), 1))
        .await
        .expect_err("no such user");
    assert!(matches!(missing, AuthError::NotFound { entity: "User" }));

    let user = create(&users, "alice", Role::User).await;
    sessions
        .insert(&session(user.id, 1))
        .await
        .expect("inserted");
    let duplicate = sessions
        .insert(&session(user.id, 1))
        .await
        .expect_err("same token hash");
    assert!(
        matches!(&duplicate, AuthError::Internal { key, .. } if key == "rustauth.sessions.insert.failed"),
        "{duplicate:?}"
    );
}

#[sqlx::test(migrator = "rustauth_postgres::MIGRATOR")]
#[ignore = "requires Postgres: run make test-db"]
async fn touch_moves_last_use_and_expiry(pool: PgPool) {
    let (users, sessions) = repositories(&pool);
    let user = create(&users, "alice", Role::User).await;
    let stored = session(user.id, 1);
    sessions.insert(&stored).await.expect("inserted");
    sessions
        .touch(stored.id, at(90), at(150))
        .await
        .expect("touched");
    let (found, _) = sessions
        .find(&stored.token_hash)
        .await
        .expect("looked up")
        .expect("exists");
    assert_eq!((found.last_used_at, found.expires_at), (at(90), at(150)));
    assert_eq!(found.created_at, stored.created_at);
    // Touching a session that is gone is not an error.
    sessions
        .touch(SessionId::generate(), at(90), at(150))
        .await
        .expect("no-op");
}

#[sqlx::test(migrator = "rustauth_postgres::MIGRATOR")]
#[ignore = "requires Postgres: run make test-db"]
async fn lists_and_deletes_only_the_owners_sessions(pool: PgPool) {
    let (users, sessions) = repositories(&pool);
    let alice = create(&users, "alice", Role::User).await;
    let bob = create(&users, "bob", Role::User).await;
    let mine = [
        session(alice.id, 1),
        session(alice.id, 2),
        session(alice.id, 3),
    ];
    let theirs = session(bob.id, 4);
    for stored in mine.iter().chain([&theirs]) {
        sessions.insert(stored).await.expect("inserted");
    }
    let listed = sessions.list(alice.id).await.expect("listed");
    assert_eq!(ids(&listed), ids(&mine));
    assert!(
        sessions
            .list(UserId::generate())
            .await
            .expect("listed")
            .is_empty()
    );

    assert!(
        !sessions
            .delete(alice.id, theirs.id)
            .await
            .expect("not alice's")
    );
    assert!(
        sessions
            .delete(alice.id, mine[0].id)
            .await
            .expect("deleted")
    );
    assert!(!sessions.delete(alice.id, mine[0].id).await.expect("gone"));

    let revoked = sessions
        .delete_all(alice.id, Some(mine[1].id))
        .await
        .expect("deleted others");
    assert_eq!(revoked, 1);
    assert_eq!(
        ids(&sessions.list(alice.id).await.expect("listed")),
        ids(&mine[1..2])
    );
    assert_eq!(
        sessions.delete_all(alice.id, None).await.expect("deleted"),
        1
    );
    assert!(sessions.list(alice.id).await.expect("listed").is_empty());
    assert_eq!(sessions.list(bob.id).await.expect("listed").len(), 1);
}

#[sqlx::test(migrator = "rustauth_postgres::MIGRATOR")]
#[ignore = "requires Postgres: run make test-db"]
async fn purges_sessions_that_expired_at_or_before_the_cutoff(pool: PgPool) {
    let (users, sessions) = repositories(&pool);
    let user = create(&users, "alice", Role::User).await;
    let mut expired = session(user.id, 1);
    expired.expires_at = at(10);
    let mut boundary = session(user.id, 2);
    boundary.expires_at = at(20);
    let mut active = session(user.id, 3);
    active.expires_at = at(21);
    for stored in [&expired, &boundary, &active] {
        sessions.insert(stored).await.expect("inserted");
    }
    assert_eq!(sessions.purge_expired(at(20)).await.expect("purged"), 2);
    assert_eq!(
        ids(&sessions.list(user.id).await.expect("listed")),
        ids(std::slice::from_ref(&active))
    );
    assert_eq!(sessions.purge_expired(at(20)).await.expect("purged"), 0);
}
