//! `AuthService` rules: setup token, first administrator, closed registration, sign-in with
//! lockout and per-IP limits, sliding and absolute session expiry, disabled users, session
//! revocation, and password changes.

use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, TimeDelta, Utc};

use crate::config::AuthConfig;
use crate::entities::{Session, User, UserPatch};
use crate::error::{AuthError, AuthResult};
use crate::ports::{Clock, Ports, SessionRepository, UserRepository};
use crate::services::AuthService;
use crate::services::fixture::{Harness, PASSWORD, SETUP, WRONG, client, client_at, registration};
use crate::testing::{Fakes, MemoryStore};
use crate::values::{
    Assurance, AuthMethod, DisplayName, Password, Role, SessionId, TokenHash, UserId, Username,
};

fn new_password(value: &str) -> Password {
    Password::new(value.to_owned()).expect("valid password")
}

/// Fails `count` sign-ins of `username` with a wrong password and returns the last error.
async fn fail(harness: &Harness, username: &str, count: u32) -> AuthError {
    let mut last = None;
    for _ in 0..count {
        last = Some(
            harness
                .login(username, WRONG)
                .await
                .expect_err("wrong password"),
        );
    }
    last.expect("at least one attempt")
}

// Setup and registration.

#[tokio::test]
async fn reports_first_run_until_an_account_exists() {
    let harness = Harness::start().await;
    let status = harness.auth.setup_status().await.expect("status");
    assert!(status.needs_setup);
    assert!(!status.registration_open);
    harness.root().await;
    let status = harness.auth.setup_status().await.expect("status");
    assert!(!status.needs_setup);
}

#[tokio::test]
async fn first_registration_needs_the_setup_token() {
    let harness = Harness::start().await;
    let hashes = harness.fakes.hasher.hashes();
    for token in [
        None,
        Some("wrong-token"),
        Some("setup-token-for-tests-but-longer"),
    ] {
        let error = harness
            .auth
            .register(registration("root"), token, &client())
            .await
            .expect_err("refused");
        assert!(matches!(error, AuthError::SetupRequired), "{error:?}");
    }
    // Refused before any hashing work.
    assert_eq!(harness.fakes.hasher.hashes(), hashes);
    assert_eq!(harness.fakes.store.count().await.expect("count"), 0);
}

#[tokio::test]
async fn first_account_becomes_an_administrator_and_is_signed_in() {
    let harness = Harness::start().await;
    let now = harness.fakes.clock.now();
    let signed = harness
        .auth
        .register(registration("root"), Some(SETUP), &client())
        .await
        .expect("registered");
    assert_eq!(signed.user.role, Role::Administrator);
    assert_eq!(signed.session.methods, [AuthMethod::Password]);
    assert_eq!(signed.session.assurance, Assurance::Aal1);
    assert_eq!(signed.session.expires_at, now + TimeDelta::days(30));
    assert_eq!(signed.session.ip, client().ip());
    assert_eq!(signed.session.user_agent, "test-agent/1.0");
    let principal = harness.principal(&signed).await;
    assert_eq!(principal.user_id, signed.user.id);
    assert_eq!(principal.role, Role::Administrator);
    assert_eq!(principal.session_id, signed.session.id);
}

#[tokio::test]
async fn generates_a_setup_token_when_none_is_configured() {
    let fakes = Fakes::new();
    let auth = AuthService::new(fakes.ports(), AuthConfig::default())
        .await
        .expect("starts");
    // The fake issuer numbers its tokens: the generated setup token is the first one.
    let error = auth
        .register(registration("root"), Some("token-2"), &client())
        .await
        .expect_err("not the setup token");
    assert!(matches!(error, AuthError::SetupRequired));
    let signed = auth
        .register(registration("root"), Some("token-1"), &client())
        .await
        .expect("generated token accepted");
    assert_eq!(signed.user.role, Role::Administrator);
}

#[tokio::test]
async fn computes_a_real_dummy_hash_at_startup() {
    let harness = Harness::start().await;
    assert_eq!(harness.fakes.hasher.hashes(), 1);
}

#[tokio::test]
async fn registration_is_closed_after_the_first_account_by_default() {
    let harness = Harness::start().await;
    harness.root().await;
    let error = harness.register("second").await.expect_err("closed");
    assert!(matches!(error, AuthError::RegistrationClosed), "{error:?}");
}

#[tokio::test]
async fn open_registration_creates_plain_users_only() {
    let harness = Harness::with(AuthConfig::builder().registration_open(true)).await;
    harness.root().await;
    // Presenting the setup token again does not make a second administrator.
    let signed = harness.register("second").await.expect("open registration");
    assert_eq!(signed.user.role, Role::User);
    let status = harness.auth.setup_status().await.expect("status");
    assert!(status.registration_open);
}

#[tokio::test]
async fn usernames_are_unique_case_insensitively() {
    let harness = Harness::with(AuthConfig::builder().registration_open(true)).await;
    harness.register("alice").await.expect("first");
    let error = harness.register("ALICE").await.expect_err("taken");
    assert!(matches!(error, AuthError::UsernameTaken), "{error:?}");
}

// Sign-in.

#[tokio::test]
async fn signs_in_with_any_letter_case() {
    let harness = Harness::start().await;
    harness.root().await;
    let signed = harness.login("ROOT", PASSWORD).await.expect("signed in");
    assert_eq!(signed.user.username.as_str(), "root");
    assert!(harness.verifies(&signed).await);
}

#[tokio::test]
async fn unknown_usernames_fail_like_wrong_passwords() {
    let harness = Harness::start().await;
    harness.root().await;
    let wrong = harness.login("root", WRONG).await.expect_err("wrong");
    let verifies = harness.fakes.hasher.verifies();
    let unknown = harness
        .login("nobody", PASSWORD)
        .await
        .expect_err("unknown");
    // The unknown username still cost one verification, against the dummy hash.
    assert_eq!(harness.fakes.hasher.verifies(), verifies + 1);
    let invalid = harness
        .login("not valid!", PASSWORD)
        .await
        .expect_err("invalid");
    assert_eq!(harness.fakes.hasher.verifies(), verifies + 2);
    for error in [&wrong, &unknown, &invalid] {
        assert!(matches!(error, AuthError::InvalidCredentials), "{error:?}");
        assert_eq!(error.to_string(), "Invalid username or password.");
    }
}

#[tokio::test]
async fn disabled_accounts_cannot_sign_in() {
    let harness = Harness::start().await;
    let root = harness.root().await;
    let user = harness.create(&root, "alice", Role::User).await;
    let disable = UserPatch {
        disabled: Some(true),
        ..UserPatch::default()
    };
    let now = harness.fakes.clock.now();
    UserRepository::update(&*harness.fakes.store, user.id, &disable, now)
        .await
        .expect("disabled");
    let wrong = harness.login("alice", WRONG).await.expect_err("wrong");
    assert!(matches!(wrong, AuthError::InvalidCredentials));
    let error = harness
        .login("alice", PASSWORD)
        .await
        .expect_err("disabled");
    assert_eq!(error.code(), "FORBIDDEN");
    assert_eq!(error.to_string(), "This account is disabled.");
}

// Account lockout.

#[tokio::test]
async fn locks_the_account_after_the_threshold() {
    let harness = Harness::start().await;
    harness.root().await;
    let error = fail(&harness, "root", 4).await;
    assert!(matches!(error, AuthError::InvalidCredentials), "{error:?}");
    let error = fail(&harness, "root", 1).await;
    assert!(
        matches!(
            error,
            AuthError::AccountLocked {
                retry_after_secs: 900
            }
        ),
        "{error:?}"
    );
    assert_eq!(
        error.to_string(),
        "Too many failed sign-in attempts. Try again in 15 minutes."
    );
    // Even the correct password is refused, before any hashing work.
    let verifies = harness.fakes.hasher.verifies();
    harness.fakes.clock.advance(TimeDelta::minutes(5));
    let error = harness.login("root", PASSWORD).await.expect_err("locked");
    assert!(
        matches!(
            error,
            AuthError::AccountLocked {
                retry_after_secs: 600
            }
        ),
        "{error:?}"
    );
    assert_eq!(harness.fakes.hasher.verifies(), verifies);
}

#[tokio::test]
async fn the_lock_ends_after_its_duration() {
    let harness = Harness::start().await;
    let root = harness.root().await;
    fail(&harness, "root", 5).await;
    harness.fakes.clock.advance(TimeDelta::minutes(15));
    harness.login("root", PASSWORD).await.expect("lock over");
    let user = harness.fakes.store.get(root.user_id).await.expect("read");
    assert!(user.expect("exists").lockout.is_clear());
}

#[tokio::test]
async fn consecutive_lockouts_double_up_to_the_maximum() {
    let config = AuthConfig::builder().lockout_max(TimeDelta::minutes(40));
    let harness = Harness::with(config).await;
    harness.root().await;
    let expected = [900, 1800, 2400, 2400];
    for retry_after_secs in expected {
        let error = fail(&harness, "root", 5).await;
        assert_eq!(error.retry_after_secs(), Some(retry_after_secs));
        harness.fakes.clock.advance(TimeDelta::seconds(
            retry_after_secs.try_into().expect("small"),
        ));
    }
}

#[tokio::test]
async fn a_successful_sign_in_resets_the_counters() {
    let harness = Harness::start().await;
    harness.root().await;
    fail(&harness, "root", 4).await;
    harness.login("root", PASSWORD).await.expect("signed in");
    // The count starts over.
    let error = fail(&harness, "root", 4).await;
    assert!(matches!(error, AuthError::InvalidCredentials));
    // And so does the doubling: after a lock and a successful sign-in, the next lock is short.
    fail(&harness, "root", 1).await;
    harness.fakes.clock.advance(TimeDelta::minutes(15));
    harness.login("root", PASSWORD).await.expect("lock over");
    let error = fail(&harness, "root", 5).await;
    assert_eq!(error.retry_after_secs(), Some(900));
}

#[tokio::test]
async fn failures_outside_the_window_start_a_new_count() {
    let harness = Harness::start().await;
    harness.root().await;
    fail(&harness, "root", 4).await;
    harness.fakes.clock.advance(TimeDelta::minutes(16));
    let error = fail(&harness, "root", 4).await;
    assert!(matches!(error, AuthError::InvalidCredentials), "{error:?}");
    let error = fail(&harness, "root", 1).await;
    assert!(
        matches!(error, AuthError::AccountLocked { .. }),
        "{error:?}"
    );
}

#[tokio::test]
async fn unknown_usernames_lock_like_real_accounts() {
    let harness = Harness::start().await;
    harness.root().await;
    let real = fail(&harness, "root", 5).await;
    let unknown = fail(&harness, "ghost", 5).await;
    assert_eq!(real.to_string(), unknown.to_string());
    assert_eq!(real.retry_after_secs(), unknown.retry_after_secs());
    let verifies = harness.fakes.hasher.verifies();
    let error = harness.login("ghost", PASSWORD).await.expect_err("locked");
    assert!(
        matches!(error, AuthError::AccountLocked { .. }),
        "{error:?}"
    );
    assert_eq!(harness.fakes.hasher.verifies(), verifies);
}

#[tokio::test]
async fn sessions_stay_valid_during_a_lockout() {
    let harness = Harness::start().await;
    harness.root().await;
    let signed = harness.login("root", PASSWORD).await.expect("signed in");
    fail(&harness, "root", 5).await;
    assert!(harness.verifies(&signed).await);
}

// Per-IP failure limit.

#[tokio::test]
async fn limits_failed_sign_ins_per_client_ip() {
    let config = AuthConfig::builder()
        .ip_failure_limit(3)
        .lockout_threshold(10);
    let harness = Harness::with(config).await;
    harness.root().await;
    let attacker = client_at("203.0.113.5");
    for username in ["root", "alice", "bob"] {
        let error = harness
            .login_from(username, WRONG, &attacker)
            .await
            .expect_err("wrong");
        assert!(matches!(error, AuthError::InvalidCredentials), "{error:?}");
    }
    let verifies = harness.fakes.hasher.verifies();
    let error = harness
        .login_from("root", PASSWORD, &attacker)
        .await
        .expect_err("over the limit");
    assert!(
        matches!(
            error,
            AuthError::RateLimited {
                retry_after_secs: 900
            }
        ),
        "{error:?}"
    );
    assert_eq!(harness.fakes.hasher.verifies(), verifies);
    // Other clients are unaffected, and the limit lifts after the window.
    harness.login("root", PASSWORD).await.expect("other client");
    harness.fakes.clock.advance(TimeDelta::minutes(15));
    harness
        .login_from("root", PASSWORD, &attacker)
        .await
        .expect("window over");
}

// Verification and session lifetime.

#[tokio::test]
async fn rejects_missing_and_unknown_tokens() {
    let harness = Harness::start().await;
    harness.root().await;
    for bearer in ["", "token-999", "not a token"] {
        let error = harness.auth.verify(bearer).await.expect_err("rejected");
        assert!(matches!(error, AuthError::Unauthorized), "{error:?}");
    }
}

#[tokio::test]
async fn sessions_slide_at_most_hourly() {
    let harness = Harness::start().await;
    harness.root().await;
    let signed = harness.login("root", PASSWORD).await.expect("signed in");
    let stored = || {
        harness
            .fakes
            .store
            .all_sessions()
            .into_iter()
            .find(|session| session.id == signed.session.id)
            .expect("stored")
    };
    harness.fakes.clock.advance(TimeDelta::minutes(59));
    assert!(harness.verifies(&signed).await);
    assert_eq!(stored().last_used_at, signed.session.last_used_at);
    assert_eq!(stored().expires_at, signed.session.expires_at);
    harness.fakes.clock.advance(TimeDelta::minutes(1));
    assert!(harness.verifies(&signed).await);
    let now = harness.fakes.clock.now();
    assert_eq!(stored().last_used_at, now);
    assert_eq!(stored().expires_at, now + TimeDelta::days(30));
}

#[tokio::test]
async fn idle_sessions_expire_after_the_sliding_lifetime() {
    let harness = Harness::start().await;
    harness.root().await;
    let signed = harness.login("root", PASSWORD).await.expect("signed in");
    harness
        .fakes
        .clock
        .advance(TimeDelta::days(30) - TimeDelta::seconds(1));
    assert!(harness.verifies(&signed).await);
    let other = harness.login("root", PASSWORD).await.expect("signed in");
    harness.fakes.clock.advance(TimeDelta::days(30));
    assert!(!harness.verifies(&other).await);
}

#[tokio::test]
async fn sessions_end_at_the_absolute_lifetime() {
    let harness = Harness::start().await;
    harness.root().await;
    let signed = harness.login("root", PASSWORD).await.expect("signed in");
    for _ in 0..4 {
        harness.fakes.clock.advance(TimeDelta::days(20));
        assert!(harness.verifies(&signed).await);
    }
    // Used on day 80: the slide stops at day 90, not day 110.
    let session = harness
        .fakes
        .store
        .all_sessions()
        .into_iter()
        .find(|session| session.id == signed.session.id)
        .expect("stored");
    assert_eq!(
        session.expires_at,
        signed.session.created_at + TimeDelta::days(90)
    );
    harness.fakes.clock.advance(TimeDelta::days(10));
    assert!(!harness.verifies(&signed).await);
}

#[tokio::test]
async fn a_lowered_absolute_lifetime_applies_to_existing_sessions() {
    let harness = Harness::start().await;
    harness.root().await;
    let signed = harness.login("root", PASSWORD).await.expect("signed in");
    let config = AuthConfig::builder()
        .session_ttl(TimeDelta::days(1))
        .session_max(TimeDelta::days(2))
        .build()
        .expect("valid");
    let stricter = AuthService::new(harness.fakes.ports(), config)
        .await
        .expect("starts");
    harness.fakes.clock.advance(TimeDelta::days(2));
    assert!(harness.verifies(&signed).await);
    assert!(stricter.verify(signed.token.expose()).await.is_err());
}

#[tokio::test]
async fn sessions_of_disabled_accounts_stop_verifying() {
    let harness = Harness::start().await;
    let root = harness.root().await;
    harness.create(&root, "alice", Role::User).await;
    let signed = harness.login("alice", PASSWORD).await.expect("signed in");
    let disable = UserPatch {
        disabled: Some(true),
        ..UserPatch::default()
    };
    let now = harness.fakes.clock.now();
    UserRepository::update(&*harness.fakes.store, signed.user.id, &disable, now)
        .await
        .expect("disabled");
    let error = harness
        .auth
        .verify(signed.token.expose())
        .await
        .expect_err("disabled");
    assert!(matches!(error, AuthError::Unauthorized), "{error:?}");
}

/// Sessions from the memory store, except that `touch` always fails.
struct FailingTouch(Arc<MemoryStore>);

#[async_trait]
impl SessionRepository for FailingTouch {
    async fn insert(&self, session: &Session) -> AuthResult<()> {
        self.0.insert(session).await
    }

    async fn find(&self, hash: &TokenHash) -> AuthResult<Option<(Session, User)>> {
        SessionRepository::find(&*self.0, hash).await
    }

    async fn touch(
        &self,
        _id: SessionId,
        _last_used_at: DateTime<Utc>,
        _expires_at: DateTime<Utc>,
    ) -> AuthResult<()> {
        Err(AuthError::internal(
            "rustauth.sessions.touch.failed",
            "connection reset",
        ))
    }

    async fn list(&self, user: UserId) -> AuthResult<Vec<Session>> {
        SessionRepository::list(&*self.0, user).await
    }

    async fn delete(&self, user: UserId, id: SessionId) -> AuthResult<bool> {
        SessionRepository::delete(&*self.0, user, id).await
    }

    async fn delete_all(&self, user: UserId, except: Option<SessionId>) -> AuthResult<u64> {
        self.0.delete_all(user, except).await
    }

    async fn purge_expired(&self, before: DateTime<Utc>) -> AuthResult<u64> {
        self.0.purge_expired(before).await
    }
}

#[tokio::test]
async fn a_failed_touch_does_not_fail_the_request() {
    let fakes = Fakes::new();
    let ports = Ports {
        sessions: Arc::new(FailingTouch(fakes.store.clone())),
        ..fakes.ports()
    };
    let config = AuthConfig::builder()
        .setup_token(SETUP)
        .build()
        .expect("valid");
    let auth = AuthService::new(ports, config).await.expect("starts");
    let signed = auth
        .register(registration("root"), Some(SETUP), &client())
        .await
        .expect("registered");
    fakes.clock.advance(TimeDelta::hours(2));
    auth.verify(signed.token.expose())
        .await
        .expect("still verifies");
    let session = fakes.store.all_sessions().remove(0);
    assert_eq!(session.last_used_at, signed.session.last_used_at);
}

// Session management.

#[tokio::test]
async fn logout_revokes_only_the_current_session() {
    let harness = Harness::start().await;
    harness.root().await;
    let first = harness.login("root", PASSWORD).await.expect("signed in");
    let second = harness.login("root", PASSWORD).await.expect("signed in");
    let principal = harness.principal(&first).await;
    harness.auth.logout(&principal).await.expect("signed out");
    assert!(!harness.verifies(&first).await);
    assert!(harness.verifies(&second).await);
}

#[tokio::test]
async fn lists_active_sessions_most_recent_first() {
    let harness = Harness::start().await;
    let root = harness.root().await;
    harness.fakes.clock.advance(TimeDelta::days(31));
    let older = harness.login("root", PASSWORD).await.expect("signed in");
    harness.fakes.clock.advance(TimeDelta::hours(1));
    let newer = harness.login("root", PASSWORD).await.expect("signed in");
    // Verifying `newer` does not touch it: it was just created.
    let principal = harness.principal(&newer).await;
    let sessions = harness.auth.sessions(&principal).await.expect("listed");
    // The registration session from day 0 has expired and is left out.
    let ids: Vec<_> = sessions.iter().map(|session| session.id).collect();
    assert_eq!(ids, [newer.session.id, older.session.id]);
    assert!(
        sessions
            .iter()
            .all(|session| session.user_id == root.user_id)
    );
}

#[tokio::test]
async fn revokes_one_session() {
    let harness = Harness::with(AuthConfig::builder().registration_open(true)).await;
    harness.root().await;
    let first = harness.login("root", PASSWORD).await.expect("signed in");
    let second = harness.login("root", PASSWORD).await.expect("signed in");
    let principal = harness.principal(&first).await;
    harness
        .auth
        .revoke(&principal, second.session.id)
        .await
        .expect("revoked");
    assert!(!harness.verifies(&second).await);
    assert!(harness.verifies(&first).await);
    let again = harness
        .auth
        .revoke(&principal, second.session.id)
        .await
        .expect_err("gone");
    assert!(matches!(again, AuthError::NotFound { entity: "Session" }));
    // Someone else's session is not found either.
    let other = harness.register("mallory").await.expect("registered");
    let error = harness
        .auth
        .revoke(&principal, other.session.id)
        .await
        .expect_err("not theirs");
    assert!(matches!(error, AuthError::NotFound { .. }));
    assert!(harness.verifies(&other).await);
}

#[tokio::test]
async fn revoke_others_keeps_the_current_session() {
    let harness = Harness::start().await;
    harness.root().await;
    let current = harness.login("root", PASSWORD).await.expect("signed in");
    let other = harness.login("root", PASSWORD).await.expect("signed in");
    let principal = harness.principal(&current).await;
    // The registration session and `other`.
    let revoked = harness
        .auth
        .revoke_others(&principal)
        .await
        .expect("revoked");
    assert_eq!(revoked, 2);
    assert!(harness.verifies(&current).await);
    assert!(!harness.verifies(&other).await);
}

#[tokio::test]
async fn purges_expired_sessions() {
    let harness = Harness::start().await;
    harness.root().await;
    harness.fakes.clock.advance(TimeDelta::days(31));
    let current = harness.login("root", PASSWORD).await.expect("signed in");
    assert_eq!(harness.auth.purge().await.expect("purged"), 1);
    assert_eq!(harness.fakes.store.all_sessions().len(), 1);
    assert!(harness.verifies(&current).await);
}

// Profile and password.

#[tokio::test]
async fn me_and_update_profile() {
    let harness = Harness::start().await;
    let root = harness.root().await;
    let name = DisplayName::new("The Root").expect("valid");
    let updated = harness
        .auth
        .update_profile(&root, name.clone())
        .await
        .expect("updated");
    assert_eq!(updated.display_name, name);
    let me = harness.auth.me(&root).await.expect("found");
    assert_eq!(me.display_name, name);
    assert_eq!(me.role, Role::Administrator);
}

#[tokio::test]
async fn changing_the_password_revokes_other_sessions() {
    let harness = Harness::start().await;
    harness.root().await;
    let current = harness.login("root", PASSWORD).await.expect("signed in");
    let other = harness.login("root", PASSWORD).await.expect("signed in");
    let principal = harness.principal(&current).await;
    harness
        .auth
        .change_password(
            &principal,
            PASSWORD.to_owned(),
            new_password("a brand new password"),
            &client(),
        )
        .await
        .expect("changed");
    assert!(harness.verifies(&current).await);
    assert!(!harness.verifies(&other).await);
    let error = harness.login("root", PASSWORD).await.expect_err("old");
    assert!(matches!(error, AuthError::InvalidCredentials));
    harness
        .login("root", "a brand new password")
        .await
        .expect("new password works");
}

#[tokio::test]
async fn changing_the_password_checks_the_current_one() {
    let config = AuthConfig::builder().lockout_threshold(2);
    let harness = Harness::with(config).await;
    let root = harness.root().await;
    let client = client();
    let attempt = || {
        harness.auth.change_password(
            &root,
            WRONG.to_owned(),
            new_password("a brand new password"),
            &client,
        )
    };
    let error = attempt().await.expect_err("wrong current password");
    assert!(
        matches!(&error, AuthError::Validation { field, .. } if field == "current"),
        "{error:?}"
    );
    assert_eq!(error.to_string(), "Current password is incorrect.");
    // Wrong current passwords count toward the lockout like sign-ins do.
    let error = attempt().await.expect_err("locked");
    assert!(
        matches!(error, AuthError::AccountLocked { .. }),
        "{error:?}"
    );
    let error = harness.login("root", PASSWORD).await.expect_err("locked");
    assert!(
        matches!(error, AuthError::AccountLocked { .. }),
        "{error:?}"
    );
}

#[tokio::test]
async fn stale_principals_cannot_change_the_password() {
    let harness = Harness::start().await;
    let mut root = harness.root().await;
    root.username = Username::new("someone").expect("valid");
    let error = harness
        .auth
        .change_password(
            &root,
            PASSWORD.to_owned(),
            new_password("a brand new password"),
            &client(),
        )
        .await
        .expect_err("unknown user");
    assert!(matches!(error, AuthError::Unauthorized), "{error:?}");
}

#[tokio::test]
async fn reads_accounts_without_a_caller() {
    let harness = Harness::start().await;
    let root = harness.root().await;
    let alice = harness.create(&root, "alice", Role::Manager).await;
    let read = harness.auth.user(alice.id).await.expect("read");
    assert_eq!(read.map(|user| user.role), Some(Role::Manager));
    assert!(
        harness
            .auth
            .user(UserId::generate())
            .await
            .expect("read")
            .is_none()
    );
    let mut ids: Vec<UserId> = harness
        .auth
        .users(&[root.user_id, alice.id, UserId::generate()])
        .await
        .expect("read")
        .into_iter()
        .map(|user| user.id)
        .collect();
    ids.sort();
    let mut expected = vec![root.user_id, alice.id];
    expected.sort();
    assert_eq!(ids, expected);
    assert!(harness.auth.users(&[]).await.expect("read").is_empty());
}
