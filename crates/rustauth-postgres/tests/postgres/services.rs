//! Core's services on the Postgres repositories (with the in-memory hasher, tokens, and clock
//! from core's `testing` feature): the adapters must uphold the rules the services rely on.

use std::sync::Arc;

use chrono::TimeDelta;
use rustauth_core::testing::Fakes;
use rustauth_core::{
    AdminService, AuthConfig, AuthError, AuthService, ClientInfo, NewAccount, Ports, Registration,
    Role, UserChanges,
};
use rustauth_postgres::{SqlxSessionRepository, SqlxUserRepository};
use sqlx::PgPool;

const SETUP_TOKEN: &str = "a-long-enough-setup-token";
const PASSWORD: &str = "correct horse battery staple";

fn ports(pool: &PgPool, fakes: &Fakes) -> Ports {
    Ports {
        users: Arc::new(SqlxUserRepository::new(pool.clone())),
        sessions: Arc::new(SqlxSessionRepository::new(pool.clone())),
        ..fakes.ports()
    }
}

async fn services(pool: &PgPool, fakes: &Fakes) -> (AuthService, AdminService) {
    let config = AuthConfig::builder()
        .setup_token(SETUP_TOKEN)
        .lockout_threshold(3)
        .build()
        .expect("valid config");
    let ports = ports(pool, fakes);
    let auth = AuthService::new(ports.clone(), config)
        .await
        .expect("auth service");
    (auth, AdminService::new(ports))
}

fn client() -> ClientInfo {
    ClientInfo::new(
        Some("198.51.100.4".parse().expect("valid address")),
        "example-agent/1.0",
    )
}

#[sqlx::test(migrator = "rustauth_postgres::MIGRATOR")]
#[ignore = "requires Postgres: run make test-db"]
async fn sets_up_signs_in_verifies_and_slides_sessions(pool: PgPool) {
    let fakes = Fakes::new();
    let (auth, _) = services(&pool, &fakes).await;
    assert!(auth.setup_status().await.expect("status").needs_setup);

    let registration = Registration::new("Alice", "Alice", PASSWORD.to_owned()).expect("valid");
    let first = auth
        .register(registration, Some(SETUP_TOKEN), &client())
        .await
        .expect("registered");
    assert_eq!(first.user.role, Role::Administrator);
    assert!(!auth.setup_status().await.expect("status").needs_setup);

    let second = auth
        .login("alice", PASSWORD.to_owned(), &client())
        .await
        .expect("signed in");
    let principal = auth.verify(second.token.expose()).await.expect("verified");
    assert_eq!(
        (principal.user_id, principal.role),
        (first.user.id, Role::Administrator)
    );
    assert_eq!(auth.sessions(&principal).await.expect("listed").len(), 2);

    // Used again after the touch interval: the session slides forward in the database.
    fakes.clock.advance(TimeDelta::hours(2));
    auth.verify(second.token.expose()).await.expect("verified");
    let slid = auth
        .sessions(&principal)
        .await
        .expect("listed")
        .into_iter()
        .find(|session| session.id == principal.session_id)
        .expect("current session");
    assert_eq!(
        slid.last_used_at,
        second.session.created_at + TimeDelta::hours(2)
    );
    assert!(slid.expires_at > second.session.expires_at);

    assert_eq!(auth.revoke_others(&principal).await.expect("revoked"), 1);
    let revoked = auth
        .verify(first.token.expose())
        .await
        .expect_err("revoked");
    assert!(matches!(revoked, AuthError::Unauthorized));
    auth.logout(&principal).await.expect("signed out");
    let signed_out = auth
        .verify(second.token.expose())
        .await
        .expect_err("signed out");
    assert!(matches!(signed_out, AuthError::Unauthorized));
}

#[sqlx::test(migrator = "rustauth_postgres::MIGRATOR")]
#[ignore = "requires Postgres: run make test-db"]
async fn locks_accounts_in_the_database_until_unlocked(pool: PgPool) {
    let fakes = Fakes::new();
    let (auth, admin) = services(&pool, &fakes).await;
    let registration = Registration::new("admin", "Admin", PASSWORD.to_owned()).expect("valid");
    let signed_in = auth
        .register(registration, Some(SETUP_TOKEN), &client())
        .await
        .expect("registered");
    let actor = auth
        .verify(signed_in.token.expose())
        .await
        .expect("verified");
    let account = NewAccount::new("bob", "Bob", PASSWORD.to_owned(), Role::User).expect("valid");
    let bob = admin.create(&actor, account).await.expect("created");

    for _ in 0..2 {
        let error = auth
            .login("bob", "wrong password".to_owned(), &client())
            .await
            .expect_err("wrong password");
        assert!(matches!(error, AuthError::InvalidCredentials), "{error:?}");
    }
    let locked = auth
        .login("bob", "wrong password".to_owned(), &client())
        .await
        .expect_err("third failure locks");
    assert!(
        matches!(locked, AuthError::AccountLocked { .. }),
        "{locked:?}"
    );
    let verifies = fakes.hasher.verifies();
    let refused = auth
        .login("bob", PASSWORD.to_owned(), &client())
        .await
        .expect_err("locked even with the right password");
    assert!(matches!(refused, AuthError::AccountLocked { .. }));
    assert_eq!(fakes.hasher.verifies(), verifies, "no hashing while locked");

    admin.unlock(&actor, bob.id).await.expect("unlocked");
    let signed_in = auth
        .login("bob", PASSWORD.to_owned(), &client())
        .await
        .expect("signed in after the unlock");

    // An administrator's change revokes the user's sessions; the guard keeps the last admin.
    let changes = UserChanges::new().role(Role::Manager);
    admin
        .update(&actor, bob.id, changes)
        .await
        .expect("changed");
    let revoked = auth
        .verify(signed_in.token.expose())
        .await
        .expect_err("revoked");
    assert!(matches!(revoked, AuthError::Unauthorized));
    let demote = UserChanges::new().role(Role::User);
    let error = admin
        .update(&actor, actor.user_id, demote)
        .await
        .expect_err("last administrator");
    assert!(matches!(error, AuthError::LastAdministrator));
}

#[sqlx::test(migrator = "rustauth_postgres::MIGRATOR")]
#[ignore = "requires Postgres: run make test-db"]
async fn unknown_usernames_lock_like_accounts_across_instances(pool: PgPool) {
    let fakes = Fakes::new();
    // Two instances on one database, as in a deployment with several servers.
    let (first, admin) = services(&pool, &fakes).await;
    let (second, _) = services(&pool, &fakes).await;
    let registration = Registration::new("admin", "Admin", PASSWORD.to_owned()).expect("valid");
    let signed_in = first
        .register(registration, Some(SETUP_TOKEN), &client())
        .await
        .expect("registered");
    let actor = first
        .verify(signed_in.token.expose())
        .await
        .expect("verified");
    let account = NewAccount::new("bob", "Bob", PASSWORD.to_owned(), Role::User).expect("valid");
    admin.create(&actor, account).await.expect("created");

    // The threshold is three: alternate instances for every attempt.
    for attempt in 1..=4 {
        let service = if attempt % 2 == 1 { &first } else { &second };
        let real = service
            .login("bob", "wrong password".to_owned(), &client())
            .await
            .expect_err("wrong password");
        let missing = service
            .login("nobody", "wrong password".to_owned(), &client())
            .await
            .expect_err("unknown");
        let expected = if attempt < 3 {
            "INVALID_CREDENTIALS"
        } else {
            "ACCOUNT_LOCKED"
        };
        assert_eq!(
            (real.code(), missing.code()),
            (expected, expected),
            "attempt {attempt}"
        );
        assert_eq!(real.retry_after_secs(), missing.retry_after_secs());
    }
}
