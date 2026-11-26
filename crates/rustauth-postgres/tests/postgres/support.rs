//! Builders shared by the tests, and the write gate that lines up concurrent transactions.

use std::future::Future;
use std::time::Duration;

use chrono::{DateTime, TimeDelta, Utc};
use rustauth_core::{
    Assurance, AuthMethod, DisplayName, NewPassword, NewUser, Role, Session, SessionId, TokenHash,
    User, UserId, UserRepository, Username,
};
use rustauth_postgres::SqlxUserRepository;
use sqlx::{Connection, PgConnection, PgPool};
use tokio::task::JoinSet;

/// A fixed instant `minutes` after a whole second, so values survive Postgres' microsecond
/// precision unchanged.
pub fn at(minutes: i64) -> DateTime<Utc> {
    DateTime::from_timestamp(1_800_000_000, 0).expect("valid timestamp")
        + TimeDelta::minutes(minutes)
}

pub fn new_user(username: &str, role: Role) -> NewUser {
    NewUser {
        id: UserId::generate(),
        username: Username::new(username).expect("valid username"),
        display_name: DisplayName::new(&format!("{username} display")).expect("valid name"),
        role,
        created_at: at(0),
    }
}

pub fn credential(hash: &str) -> NewPassword {
    NewPassword {
        hash: hash.to_owned(),
        changed_at: at(0),
    }
}

/// Creates an account the way an administrator would.
pub async fn create(users: &SqlxUserRepository, username: &str, role: Role) -> User {
    users
        .create(new_user(username, role), credential("stored-hash"))
        .await
        .expect("created")
}

/// A session of `user` whose token hash is 32 bytes of `seed`.
pub fn session(user: UserId, seed: u8) -> Session {
    Session {
        id: SessionId::generate(),
        user_id: user,
        token_hash: TokenHash::new([seed; TokenHash::LEN]),
        methods: vec![AuthMethod::Password],
        assurance: Assurance::Aal1,
        created_at: at(0),
        last_used_at: at(0),
        expires_at: at(60),
        user_agent: "example-agent/1.0".to_owned(),
        ip: Some("203.0.113.7".parse().expect("valid address")),
    }
}

/// Runs `tasks` concurrently with writes to `auth.users` held back until every one of them is
/// blocked, then lets them all go, and returns their results (in completion order).
///
/// A separate connection holds `SHARE` on `auth.users`, which lets reads and `SELECT ... FOR
/// UPDATE` through but blocks `INSERT`, `UPDATE`, and `DELETE`. So each transaction makes its
/// decision and then waits at its first write, or waits earlier on the repository's advisory
/// lock. Without that lock, every transaction would decide on the same state before any of
/// them commits, which is exactly the race the lock prevents. At most five tasks: the test pool
/// has five connections and each task holds one.
pub async fn race<T, F>(pool: &PgPool, tasks: Vec<F>) -> Vec<T>
where
    T: Send + 'static,
    F: Future<Output = T> + Send + 'static,
{
    let mut gate = PgConnection::connect_with(&pool.connect_options())
        .await
        .expect("gate connected");
    sqlx::raw_sql("BEGIN; LOCK TABLE auth.users IN SHARE MODE")
        .execute(&mut gate)
        .await
        .expect("gate closed");
    let count = i64::try_from(tasks.len()).expect("few tasks");
    let mut running = JoinSet::new();
    for task in tasks {
        running.spawn(task);
    }
    let mut blocked = 0;
    for _ in 0..1000 {
        // Statistics views keep one snapshot per transaction unless it is cleared.
        sqlx::query("SELECT pg_stat_clear_snapshot()")
            .execute(&mut gate)
            .await
            .expect("cleared the statistics snapshot");
        blocked = sqlx::query_scalar(
            "SELECT count(*) FROM pg_stat_activity \
             WHERE datname = current_database() AND wait_event_type = 'Lock'",
        )
        .fetch_one(&mut gate)
        .await
        .expect("counted blocked transactions");
        if blocked >= count {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(
        blocked, count,
        "every task should be blocked before the gate opens"
    );
    sqlx::query("COMMIT")
        .execute(&mut gate)
        .await
        .expect("gate opened");
    gate.close().await.expect("gate disconnected");
    running.join_all().await
}
