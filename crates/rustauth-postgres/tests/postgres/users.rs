//! `SqlxUserRepository`: registration under the advisory lock, case-insensitive usernames, the
//! last-administrator guard, and the atomic lockout updates.

use chrono::TimeDelta;
use rustauth_core::{
    AuthError, AuthResult, DisplayName, Lockout, Page, RegisterPolicy, Role, SessionRepository,
    User, UserId, UserPatch, UserRepository, Username,
};
use rustauth_postgres::{SqlxSessionRepository, SqlxUserRepository};
use sqlx::PgPool;
use tokio::task::JoinSet;

use crate::support::{at, create, credential, new_user, race, session};

/// What a service decides while it still sees zero accounts and the setup token matched.
const FIRST: RegisterPolicy = RegisterPolicy {
    registration_open: false,
    setup_token_ok: true,
};

const DEMOTE: UserPatch = UserPatch {
    display_name: None,
    role: Some(Role::Manager),
    disabled: None,
};

const DISABLE: UserPatch = UserPatch {
    display_name: None,
    role: None,
    disabled: Some(true),
};

fn rename(name: &str) -> UserPatch {
    UserPatch {
        display_name: Some(DisplayName::new(name).expect("valid name")),
        ..UserPatch::default()
    }
}

async fn stored(users: &SqlxUserRepository, id: UserId) -> User {
    users.get(id).await.expect("read").expect("exists")
}

async fn enabled_admins(pool: &PgPool) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM auth.users WHERE role = 'administrator' AND disabled_at IS NULL",
    )
    .fetch_one(pool)
    .await
    .expect("counted")
}

/// Races `count` registrations (at most five), each with its own username and `policy`.
async fn register_concurrently(
    pool: &PgPool,
    count: usize,
    policy: RegisterPolicy,
) -> Vec<AuthResult<User>> {
    let users = SqlxUserRepository::new(pool.clone());
    let tasks = (0..count)
        .map(|index| {
            let users = users.clone();
            async move {
                users
                    .register(
                        new_user(&format!("racer_{index}"), Role::User),
                        credential("stored-hash"),
                        policy,
                    )
                    .await
            }
        })
        .collect();
    race(pool, tasks).await
}

#[sqlx::test(migrator = "rustauth_postgres::MIGRATOR")]
#[ignore = "requires Postgres: run make test-db"]
async fn registers_the_first_account_as_administrator(pool: PgPool) {
    let users = SqlxUserRepository::new(pool);
    let missing = users
        .register(
            new_user("alice", Role::User),
            credential("hash"),
            RegisterPolicy::default(),
        )
        .await
        .expect_err("no setup token");
    assert!(matches!(missing, AuthError::SetupRequired));
    assert_eq!(users.count().await.expect("counted"), 0);

    let input = new_user("Alice", Role::User);
    let first = users
        .register(input.clone(), credential("alice-hash"), FIRST)
        .await
        .expect("first");
    assert_eq!(
        first.role,
        Role::Administrator,
        "the stored role is decided"
    );
    assert_eq!(first.id, input.id);
    assert_eq!(first.username.as_str(), "Alice");
    assert_eq!(first.display_name, input.display_name);
    assert_eq!((first.created_at, first.updated_at), (at(0), at(0)));
    assert_eq!(first.disabled_at, None);
    assert!(first.lockout.is_clear());
    assert_eq!(stored(&users, first.id).await, first);

    let closed = users
        .register(new_user("bob", Role::User), credential("hash"), FIRST)
        .await
        .expect_err("registration closed");
    assert!(matches!(closed, AuthError::RegistrationClosed));
    let open = RegisterPolicy {
        registration_open: true,
        setup_token_ok: false,
    };
    let second = users
        .register(
            new_user("bob", Role::Administrator),
            credential("hash"),
            open,
        )
        .await
        .expect("open registration");
    assert_eq!(second.role, Role::User);
    assert_eq!(users.count().await.expect("counted"), 2);
}

#[sqlx::test(migrator = "rustauth_postgres::MIGRATOR")]
#[ignore = "requires Postgres: run make test-db"]
async fn concurrent_first_registrations_produce_one_administrator(pool: PgPool) {
    let users = SqlxUserRepository::new(pool.clone());
    let results = register_concurrently(&pool, 5, FIRST).await;
    let admins = results
        .iter()
        .filter(|result| matches!(result, Ok(user) if user.role == Role::Administrator))
        .count();
    let closed = results
        .iter()
        .filter(|result| matches!(result, Err(AuthError::RegistrationClosed)))
        .count();
    assert_eq!((admins, closed), (1, 4), "{results:?}");
    assert_eq!(users.count().await.expect("counted"), 1);
    assert_eq!(enabled_admins(&pool).await, 1);
}

#[sqlx::test(migrator = "rustauth_postgres::MIGRATOR")]
#[ignore = "requires Postgres: run make test-db"]
async fn concurrent_open_registrations_still_produce_one_administrator(pool: PgPool) {
    let open = RegisterPolicy {
        registration_open: true,
        setup_token_ok: true,
    };
    let results = register_concurrently(&pool, 5, open).await;
    let roles: Vec<Role> = results
        .into_iter()
        .map(|result| result.expect("registered").role)
        .collect();
    assert_eq!(
        roles
            .iter()
            .filter(|role| **role == Role::Administrator)
            .count(),
        1,
        "{roles:?}"
    );
    assert_eq!(roles.iter().filter(|role| **role == Role::User).count(), 4);
    assert_eq!(enabled_admins(&pool).await, 1);
}

#[sqlx::test(migrator = "rustauth_postgres::MIGRATOR")]
#[ignore = "requires Postgres: run make test-db"]
async fn usernames_are_unique_case_insensitively(pool: PgPool) {
    let users = SqlxUserRepository::new(pool.clone());
    create(&users, "Alice", Role::User).await;
    let taken = users
        .create(new_user("aLiCe", Role::Manager), credential("hash"))
        .await
        .expect_err("taken");
    assert!(matches!(taken, AuthError::UsernameTaken));
    let open = RegisterPolicy {
        registration_open: true,
        setup_token_ok: false,
    };
    let taken = users
        .register(new_user("ALICE", Role::User), credential("hash"), open)
        .await
        .expect_err("taken");
    assert!(matches!(taken, AuthError::UsernameTaken));
    // Nothing of the refused accounts was kept.
    let credentials: i64 = sqlx::query_scalar("SELECT count(*) FROM auth.password_credentials")
        .fetch_one(&pool)
        .await
        .expect("counted");
    assert_eq!((users.count().await.expect("counted"), credentials), (1, 1));
    // A duplicate id is a different failure: an internal error, not a taken username.
    let mut duplicate = new_user("carol", Role::User);
    duplicate.id = users.list(Page::default()).await.expect("listed").0[0].id;
    let error = users
        .create(duplicate, credential("hash"))
        .await
        .expect_err("duplicate id");
    assert!(
        matches!(&error, AuthError::Internal { key, .. } if key == "rustauth.users.insert.failed"),
        "{error:?}"
    );
}

#[sqlx::test(migrator = "rustauth_postgres::MIGRATOR")]
#[ignore = "requires Postgres: run make test-db"]
async fn finds_accounts_with_their_credential(pool: PgPool) {
    let users = SqlxUserRepository::new(pool.clone());
    let alice = users
        .create(new_user("Alice_1", Role::Manager), credential("alice-hash"))
        .await
        .expect("created");
    let lookup = Username::new("alice_1").expect("valid");
    let (user, found) = users.find(&lookup).await.expect("found").expect("exists");
    assert_eq!(user, alice);
    let found = found.expect("has a password");
    assert_eq!(
        (found.user_id, found.hash.as_str()),
        (alice.id, "alice-hash")
    );
    assert_eq!(found.changed_at, at(0));

    let unknown = Username::new("nobody").expect("valid");
    assert!(users.find(&unknown).await.expect("looked up").is_none());
    assert!(
        users
            .get(UserId::generate())
            .await
            .expect("looked up")
            .is_none()
    );

    // An account without a password row (single sign-on, later) is found without one.
    sqlx::query("DELETE FROM auth.password_credentials")
        .execute(&pool)
        .await
        .expect("deleted");
    let (_, found) = users.find(&lookup).await.expect("found").expect("exists");
    assert!(found.is_none());
}

#[sqlx::test(migrator = "rustauth_postgres::MIGRATOR")]
#[ignore = "requires Postgres: run make test-db"]
async fn lists_pages_in_username_order_with_the_total(pool: PgPool) {
    let users = SqlxUserRepository::new(pool);
    for name in ["delta", "Bravo", "alpha", "Charlie", "echo"] {
        create(&users, name, Role::User).await;
    }
    let names = |page: &[User]| -> Vec<String> {
        page.iter()
            .map(|user| user.username.as_str().to_owned())
            .collect()
    };
    let (first, total) = users.list(Page::new(0, 2)).await.expect("listed");
    assert_eq!(
        (names(&first), total),
        (vec!["alpha".into(), "Bravo".into()], 5)
    );
    let (second, _) = users.list(Page::new(2, 2)).await.expect("listed");
    assert_eq!(names(&second), ["Charlie", "delta"]);
    let (last, _) = users.list(Page::new(4, 2)).await.expect("listed");
    assert_eq!(names(&last), ["echo"]);
    let (beyond, total) = users.list(Page::new(u64::MAX, 2)).await.expect("listed");
    assert_eq!((beyond.len(), total), (0, 5));
}

#[sqlx::test(migrator = "rustauth_postgres::MIGRATOR")]
#[ignore = "requires Postgres: run make test-db"]
async fn updates_only_the_patched_fields(pool: PgPool) {
    let users = SqlxUserRepository::new(pool);
    create(&users, "admin", Role::Administrator).await;
    let user = create(&users, "alice", Role::User).await;
    users
        .record_failure(user.id, at(1), at(-14))
        .await
        .expect("recorded");

    let renamed = users
        .update(user.id, &rename("Alice Example"), at(2))
        .await
        .expect("renamed");
    assert_eq!(renamed.display_name.as_str(), "Alice Example");
    assert_eq!((renamed.role, renamed.updated_at), (Role::User, at(2)));
    assert_eq!(renamed.lockout.failed_count, 1, "lockout state is kept");
    assert_eq!(stored(&users, user.id).await, renamed);

    let disabled = users
        .update(user.id, &DISABLE, at(3))
        .await
        .expect("disabled");
    assert_eq!(disabled.disabled_at, Some(at(3)));
    assert_eq!(disabled.display_name.as_str(), "Alice Example");
    let again = users
        .update(user.id, &DISABLE, at(4))
        .await
        .expect("disabled");
    assert_eq!(again.disabled_at, Some(at(3)), "keeps the first timestamp");
    let enable = UserPatch {
        disabled: Some(false),
        ..UserPatch::default()
    };
    let enabled = users
        .update(user.id, &enable, at(5))
        .await
        .expect("enabled");
    assert_eq!(enabled.disabled_at, None);

    let promoted = users
        .update(user.id, &DEMOTE, at(6))
        .await
        .expect("changed");
    assert_eq!(promoted.role, Role::Manager);
    assert_eq!(stored(&users, user.id).await, promoted);

    let missing = users
        .update(UserId::generate(), &rename("Nobody"), at(7))
        .await
        .expect_err("missing");
    assert!(matches!(missing, AuthError::NotFound { entity: "User" }));
}

#[sqlx::test(migrator = "rustauth_postgres::MIGRATOR")]
#[ignore = "requires Postgres: run make test-db"]
async fn guards_the_last_enabled_administrator(pool: PgPool) {
    let users = SqlxUserRepository::new(pool);
    let admin = create(&users, "admin", Role::Administrator).await;
    for patch in [&DEMOTE, &DISABLE] {
        let error = users
            .update(admin.id, patch, at(1))
            .await
            .expect_err("last administrator");
        assert!(matches!(error, AuthError::LastAdministrator), "{patch:?}");
    }
    let error = users
        .delete(admin.id)
        .await
        .expect_err("last administrator");
    assert!(matches!(error, AuthError::LastAdministrator));
    assert_eq!(stored(&users, admin.id).await, admin, "nothing changed");
    users
        .update(admin.id, &rename("Head Admin"), at(1))
        .await
        .expect("renaming is fine");

    // A disabled administrator does not count.
    let dormant = create(&users, "dormant", Role::Administrator).await;
    users
        .update(dormant.id, &DISABLE, at(2))
        .await
        .expect("disabled while another remains");
    let error = users
        .update(admin.id, &DEMOTE, at(3))
        .await
        .expect_err("dormant does not count");
    assert!(matches!(error, AuthError::LastAdministrator));
    assert!(users.delete(dormant.id).await.expect("deleted"));

    // A second enabled administrator does.
    let second = create(&users, "second", Role::Administrator).await;
    users
        .update(admin.id, &DEMOTE, at(4))
        .await
        .expect("demoted");
    let error = users.delete(second.id).await.expect_err("now the last one");
    assert!(matches!(error, AuthError::LastAdministrator));

    // Accounts that are not enabled administrators never trip the guard.
    let plain = create(&users, "plain", Role::User).await;
    assert!(users.delete(plain.id).await.expect("deleted"));
    assert!(!users.delete(plain.id).await.expect("already gone"));
}

#[sqlx::test(migrator = "rustauth_postgres::MIGRATOR")]
#[ignore = "requires Postgres: run make test-db"]
async fn concurrent_changes_keep_one_administrator(pool: PgPool) {
    let users = SqlxUserRepository::new(pool.clone());
    let refused = |results: &[AuthResult<()>]| {
        results
            .iter()
            .filter(|result| matches!(result, Err(AuthError::LastAdministrator)))
            .count()
    };

    // Two administrators demote each other at the same moment.
    let first = create(&users, "first", Role::Administrator).await;
    let second = create(&users, "second", Role::Administrator).await;
    let demotions = [first.id, second.id]
        .map(|id| {
            let users = users.clone();
            async move { users.update(id, &DEMOTE, at(1)).await.map(drop) }
        })
        .into();
    let results = race(&pool, demotions).await;
    assert_eq!(refused(&results), 1, "{results:?}");
    assert_eq!(enabled_admins(&pool).await, 1);

    // The remaining administrator and a new one are deleted at the same moment.
    let third = create(&users, "third", Role::Administrator).await;
    let remaining = if stored(&users, first.id).await.role == Role::Administrator {
        first.id
    } else {
        second.id
    };
    let deletions = [remaining, third.id]
        .map(|id| {
            let users = users.clone();
            async move { users.delete(id).await.map(drop) }
        })
        .into();
    let results = race(&pool, deletions).await;
    assert_eq!(refused(&results), 1, "{results:?}");
    assert_eq!(enabled_admins(&pool).await, 1);
}

#[sqlx::test(migrator = "rustauth_postgres::MIGRATOR")]
#[ignore = "requires Postgres: run make test-db"]
async fn deleting_a_user_removes_its_credential_and_sessions(pool: PgPool) {
    let users = SqlxUserRepository::new(pool.clone());
    let sessions = SqlxSessionRepository::new(pool.clone());
    create(&users, "admin", Role::Administrator).await;
    let user = create(&users, "alice", Role::User).await;
    sessions
        .insert(&session(user.id, 1))
        .await
        .expect("inserted");
    assert!(users.delete(user.id).await.expect("deleted"));
    assert!(users.get(user.id).await.expect("read").is_none());
    let leftovers: i64 = sqlx::query_scalar(
        "SELECT (SELECT count(*) FROM auth.password_credentials WHERE user_id = $1) \
         + (SELECT count(*) FROM auth.sessions WHERE user_id = $1)",
    )
    .bind(user.id.as_uuid())
    .fetch_one(&pool)
    .await
    .expect("counted");
    assert_eq!(leftovers, 0);
}

#[sqlx::test(migrator = "rustauth_postgres::MIGRATOR")]
#[ignore = "requires Postgres: run make test-db"]
async fn sets_and_replaces_the_password_hash(pool: PgPool) {
    let users = SqlxUserRepository::new(pool.clone());
    let user = create(&users, "alice", Role::User).await;
    let lookup = Username::new("alice").expect("valid");
    users
        .set_password(user.id, "new-hash".to_owned(), at(5))
        .await
        .expect("replaced");
    let (_, found) = users.find(&lookup).await.expect("found").expect("exists");
    let found = found.expect("has a password");
    assert_eq!((found.hash.as_str(), found.changed_at), ("new-hash", at(5)));

    // Also works for an account that has no password yet.
    sqlx::query("DELETE FROM auth.password_credentials")
        .execute(&pool)
        .await
        .expect("deleted");
    users
        .set_password(user.id, "first-hash".to_owned(), at(6))
        .await
        .expect("inserted");
    let (_, found) = users.find(&lookup).await.expect("found").expect("exists");
    assert_eq!(found.expect("has a password").hash, "first-hash");

    let missing = users
        .set_password(UserId::generate(), "hash".to_owned(), at(7))
        .await
        .expect_err("missing");
    assert!(matches!(missing, AuthError::NotFound { entity: "User" }));
}

#[sqlx::test(migrator = "rustauth_postgres::MIGRATOR")]
#[ignore = "requires Postgres: run make test-db"]
async fn records_failures_like_the_core_rule(pool: PgPool) {
    let users = SqlxUserRepository::new(pool);
    let user = create(&users, "alice", Role::User).await;
    let window = TimeDelta::minutes(15);
    let mut expected = Lockout::default();
    // Three failures inside the window, two after a gap longer than the window, and one exactly
    // a window after the previous failure (which still counts).
    for minute in [0, 5, 10, 30, 31, 46] {
        let (now, since) = (at(minute), at(minute) - window);
        expected = expected.fail(now, since);
        let recorded = users
            .record_failure(user.id, now, since)
            .await
            .expect("recorded");
        assert_eq!(recorded, expected, "minute {minute}");
        assert_eq!(stored(&users, user.id).await.lockout, expected);
    }
    assert_eq!(expected.failed_count, 3);

    let missing = users
        .record_failure(UserId::generate(), at(0), at(-15))
        .await
        .expect_err("missing");
    assert!(matches!(missing, AuthError::NotFound { entity: "User" }));
}

#[sqlx::test(migrator = "rustauth_postgres::MIGRATOR")]
#[ignore = "requires Postgres: run make test-db"]
async fn counts_every_concurrent_failure(pool: PgPool) {
    let users = SqlxUserRepository::new(pool);
    let user = create(&users, "alice", Role::User).await;
    let mut tasks = JoinSet::new();
    for _ in 0..10 {
        let users = users.clone();
        tasks.spawn(async move { users.record_failure(user.id, at(0), at(-15)).await });
    }
    for result in tasks.join_all().await {
        result.expect("recorded");
    }
    assert_eq!(stored(&users, user.id).await.lockout.failed_count, 10);
}

#[sqlx::test(migrator = "rustauth_postgres::MIGRATOR")]
#[ignore = "requires Postgres: run make test-db"]
async fn locks_once_per_lockout_counter_and_unlocks(pool: PgPool) {
    let users = SqlxUserRepository::new(pool);
    let user = create(&users, "alice", Role::User).await;
    let failed = users
        .record_failure(user.id, at(0), at(-15))
        .await
        .expect("recorded");
    assert!(users.lock(user.id, at(15), 0).await.expect("locked"));
    // A second failure that also decided on `lockouts == 0` does not lock again.
    assert!(!users.lock(user.id, at(30), 0).await.expect("not locked"));
    let locked = stored(&users, user.id).await.lockout;
    assert_eq!(locked, failed.lock(at(15)));
    assert_eq!(locked.locked(at(14)), Some(at(15)));

    assert!(users.lock(user.id, at(45), 1).await.expect("locked again"));
    assert_eq!(stored(&users, user.id).await.lockout.lockouts, 2);
    assert!(
        !users
            .lock(UserId::generate(), at(15), 0)
            .await
            .expect("missing")
    );
    assert!(
        !users
            .lock(user.id, at(15), u32::MAX)
            .await
            .expect("out of range")
    );

    users.unlock(user.id).await.expect("unlocked");
    assert!(stored(&users, user.id).await.lockout.is_clear());
    let missing = users.unlock(UserId::generate()).await.expect_err("missing");
    assert!(matches!(missing, AuthError::NotFound { entity: "User" }));
}
