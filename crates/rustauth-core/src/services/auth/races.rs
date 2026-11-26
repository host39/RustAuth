//! `AuthService` under concurrency: password checks held back by a gate so that many sign-ins
//! run at once, as a burst against a real server would. The lockout and the per-IP limit must
//! hold for attempts that are still running, and storage shared by several instances must give
//! every instance the same answers.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use async_trait::async_trait;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

use crate::config::AuthConfig;
use crate::entities::{NewPassword, NewUser, User};
use crate::error::{AuthError, AuthResult};
use crate::ports::{Clock, PasswordHasher, Ports, UserRepository};
use crate::services::AuthService;
use crate::services::fixture::{PASSWORD, SETUP, WRONG, client, client_at};
use crate::testing::{FakeHasher, Fakes};
use crate::values::{DisplayName, Password, Role, UserId, Username};

/// The fake hasher, but every `verify` waits for a permit the test hands out.
#[derive(Debug)]
struct Gate {
    inner: FakeHasher,
    permits: Semaphore,
    waiting: AtomicUsize,
}

impl Gate {
    fn closed() -> Self {
        Self {
            inner: FakeHasher::default(),
            permits: Semaphore::new(0),
            waiting: AtomicUsize::new(0),
        }
    }

    /// Lets `count` held-back checks (or future ones) through, oldest first.
    fn allow(&self, count: usize) {
        self.permits.add_permits(count);
    }

    /// Checks that have started, finished or not.
    fn started(&self) -> usize {
        self.waiting.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl PasswordHasher for Gate {
    async fn hash(&self, password: &Password) -> AuthResult<String> {
        self.inner.hash(password).await
    }

    async fn verify(&self, password: &Password, hash: &str) -> AuthResult<bool> {
        self.waiting.fetch_add(1, Ordering::SeqCst);
        let permit = self.permits.acquire().await.expect("never closed");
        permit.forget();
        self.inner.verify(password, hash).await
    }
}

struct Setup {
    fakes: Fakes,
    gate: Arc<Gate>,
    auth: Arc<AuthService>,
}

async fn setup(config: AuthConfig) -> Setup {
    let fakes = Fakes::new();
    let gate = Arc::new(Gate::closed());
    let ports = Ports {
        hasher: gate.clone(),
        ..fakes.ports()
    };
    let auth = AuthService::new(ports, config).await.expect("starts");
    Setup {
        fakes,
        gate,
        auth: Arc::new(auth),
    }
}

fn config() -> AuthConfig {
    AuthConfig::builder()
        .setup_token(SETUP)
        .build()
        .expect("valid config")
}

/// An account with [`PASSWORD`], stored directly.
async fn account(fakes: &Fakes, username: &str) -> User {
    let hash = fakes
        .hasher
        .hash(&Password::candidate(PASSWORD.to_owned()))
        .await
        .expect("hashed");
    fakes
        .store
        .create(
            NewUser {
                id: UserId::generate(),
                username: Username::new(username).expect("valid"),
                display_name: DisplayName::new(username).expect("valid"),
                role: Role::User,
                created_at: fakes.clock.now(),
            },
            NewPassword {
                hash,
                changed_at: fakes.clock.now(),
            },
        )
        .await
        .expect("created")
}

/// Lets the other tasks run until `done` holds (each task runs until it waits at the gate or
/// finishes; the test runtime has one thread).
async fn settle(done: impl Fn() -> bool) {
    for _ in 0..10_000 {
        if done() {
            return;
        }
        tokio::task::yield_now().await;
    }
    panic!("the tasks did not settle");
}

/// Starts `logins` concurrently and waits until each one is held at the gate or has finished.
/// Returns the running set and the counter of finished ones.
async fn burst(
    setup: &Setup,
    logins: Vec<(String, &'static str, &'static str)>,
) -> (JoinSet<AuthResult<()>>, Arc<AtomicUsize>) {
    let finished = Arc::new(AtomicUsize::new(0));
    let mut running = JoinSet::new();
    let count = logins.len();
    let before = setup.gate.started();
    for (username, password, ip) in logins {
        let auth = setup.auth.clone();
        let finished = finished.clone();
        running.spawn(async move {
            let result = auth
                .login(&username, password.to_owned(), &client_at(ip))
                .await
                .map(|_| ());
            finished.fetch_add(1, Ordering::SeqCst);
            result
        });
    }
    let gate = setup.gate.clone();
    let done = finished.clone();
    settle(move || gate.started() - before + done.load(Ordering::SeqCst) == count).await;
    (running, finished)
}

fn codes(results: &[AuthResult<()>]) -> Vec<&'static str> {
    let mut codes: Vec<&'static str> = results
        .iter()
        .map(|result| result.as_ref().map_or_else(AuthError::code, |()| "OK"))
        .collect();
    codes.sort_unstable();
    codes
}

#[tokio::test]
async fn a_burst_gets_no_more_password_checks_than_the_threshold() {
    let setup = setup(config()).await;
    let alice = account(&setup.fakes, "alice").await;
    let wrong = (0..39)
        .map(|_| ("alice".to_owned(), WRONG, "203.0.113.7"))
        .collect();
    let (running, finished) = burst(&setup, wrong).await;
    // Five checks hold the five failures the window allows; the other 34 were refused at once.
    assert_eq!(setup.gate.started(), 5);
    assert_eq!(finished.load(Ordering::SeqCst), 34);

    // The right password, while those five run: refused before any hashing.
    let error = setup
        .auth
        .login("alice", PASSWORD.to_owned(), &client())
        .await
        .expect_err("window full");
    assert!(
        matches!(error, AuthError::AccountLocked { .. }),
        "{error:?}"
    );
    assert_eq!(setup.gate.started(), 5);

    setup.gate.allow(5);
    let held = running.join_all().await;
    let failures: Vec<_> = held.iter().filter(|result| result.is_err()).collect();
    assert_eq!(failures.len(), 39);
    assert_eq!(setup.gate.inner.verifies(), 5);
    let stored = setup.fakes.store.get(alice.id).await.expect("read");
    let lockout = stored.expect("exists").lockout;
    assert_eq!(
        lockout.lockouts, 1,
        "one burst locks once, for the first duration"
    );
    assert!(lockout.locked(setup.fakes.clock.now()).is_some());

    // Locked now: the right password still fails, without a check.
    let error = setup
        .auth
        .login("alice", PASSWORD.to_owned(), &client())
        .await
        .expect_err("locked");
    assert!(
        matches!(error, AuthError::AccountLocked { .. }),
        "{error:?}"
    );
    assert_eq!(setup.gate.started(), 5);
}

#[tokio::test]
async fn a_lock_set_during_the_right_password_check_wins() {
    let setup = setup(config()).await;
    let alice = account(&setup.fakes, "alice").await;
    setup.gate.allow(4);
    for _ in 0..4 {
        setup
            .auth
            .login("alice", WRONG.to_owned(), &client())
            .await
            .expect_err("wrong");
    }
    // The fifth failure and the right password run at once; the failure finishes first.
    let logins = vec![
        ("alice".to_owned(), WRONG, "198.51.100.1"),
        ("alice".to_owned(), PASSWORD, "198.51.100.2"),
    ];
    let (mut running, _) = burst(&setup, logins).await;
    // The window held one more failure: only the first of the two got a check.
    assert_eq!(setup.gate.started(), 4 + 1);
    setup.gate.allow(1);
    let mut results = Vec::new();
    while let Some(result) = running.join_next().await {
        results.push(result.expect("no panic"));
    }
    assert_eq!(codes(&results), ["ACCOUNT_LOCKED", "ACCOUNT_LOCKED"]);
    assert!(setup.fakes.store.all_sessions().is_empty());
    let stored = setup.fakes.store.get(alice.id).await.expect("read");
    assert_eq!(stored.expect("exists").lockout.lockouts, 1);
}

#[tokio::test]
async fn a_right_password_running_beside_the_last_failure_cannot_be_undone_by_it() {
    let setup = setup(config()).await;
    let alice = account(&setup.fakes, "alice").await;
    setup.gate.allow(3);
    for _ in 0..3 {
        setup
            .auth
            .login("alice", WRONG.to_owned(), &client())
            .await
            .expect_err("wrong");
    }
    // The right password takes the fourth check, a wrong one the fifth.
    let logins = vec![
        ("alice".to_owned(), PASSWORD, "198.51.100.1"),
        ("alice".to_owned(), WRONG, "198.51.100.2"),
    ];
    let (mut running, _) = burst(&setup, logins).await;
    assert_eq!(setup.gate.started(), 3 + 2);
    // The right password finishes first and clears the count; the failure then cannot lock on
    // the count it saw, which no longer exists.
    setup.gate.allow(2);
    let mut results = Vec::new();
    while let Some(result) = running.join_next().await {
        results.push(result.expect("no panic"));
    }
    assert!(results.iter().any(Result::is_ok), "{:?}", codes(&results));
    let stored = setup.fakes.store.get(alice.id).await.expect("read");
    assert!(
        stored
            .expect("exists")
            .lockout
            .locked(setup.fakes.clock.now())
            .is_none()
    );
}

#[tokio::test]
async fn the_ip_limit_counts_running_attempts() {
    let setup = setup(config()).await;
    let names = (0..60)
        .map(|index| (format!("nobody_{index}"), WRONG, "203.0.113.7"))
        .collect();
    let (running, finished) = burst(&setup, names).await;
    assert_eq!(setup.gate.started(), 30, "the limit is 30 per client IP");
    assert_eq!(finished.load(Ordering::SeqCst), 30);
    setup.gate.allow(30);
    let results = running.join_all().await;
    let limited = results
        .iter()
        .filter(|result| matches!(result, Err(AuthError::RateLimited { .. })))
        .count();
    assert_eq!(limited, 30);
    assert_eq!(setup.gate.inner.verifies(), 30);
}

#[tokio::test]
async fn unknown_usernames_lock_like_accounts_on_every_instance() {
    let fakes = Fakes::new();
    // Two instances over one store, as two servers share one database.
    let first = AuthService::new(fakes.ports(), config())
        .await
        .expect("starts");
    let second = AuthService::new(fakes.ports(), config())
        .await
        .expect("starts");
    account(&fakes, "alice").await;
    for attempt in 1..=6 {
        let service = if attempt % 2 == 1 { &first } else { &second };
        let real = service
            .login("alice", WRONG.to_owned(), &client())
            .await
            .expect_err("wrong");
        let missing = service
            .login("nobody", WRONG.to_owned(), &client())
            .await
            .expect_err("unknown");
        assert_eq!(real.code(), missing.code(), "attempt {attempt}");
        assert_eq!(
            real.retry_after_secs(),
            missing.retry_after_secs(),
            "attempt {attempt}"
        );
        let expected = if attempt < 5 {
            "INVALID_CREDENTIALS"
        } else {
            "ACCOUNT_LOCKED"
        };
        assert_eq!(real.code(), expected, "attempt {attempt}");
    }
}

#[tokio::test]
async fn input_that_is_no_username_never_shares_a_lockout_with_one() {
    let fakes = Fakes::new();
    let auth = AuthService::new(fakes.ports(), config())
        .await
        .expect("starts");
    account(&fakes, "kevin").await;
    // U+212A KELVIN SIGN lowercases to an ASCII `k` in Unicode, but is no valid username.
    for _ in 0..5 {
        for input in ["\u{212A}evin", "\u{212A}yle"] {
            let error = auth
                .login(input, WRONG.to_owned(), &client())
                .await
                .expect_err("invalid");
            assert!(matches!(error, AuthError::InvalidCredentials), "{error:?}");
        }
    }
    for username in ["kevin", "kyle"] {
        let error = auth
            .login(username, WRONG.to_owned(), &client())
            .await
            .expect_err("wrong");
        assert!(
            matches!(error, AuthError::InvalidCredentials),
            "{username}: {error:?}"
        );
    }
    // Only `kyle` was tracked by name; the invalid input left nothing behind.
    let later = fakes.clock.now() + chrono::TimeDelta::seconds(1);
    assert_eq!(fakes.store.prune(later).await.expect("ok"), 1);
}
