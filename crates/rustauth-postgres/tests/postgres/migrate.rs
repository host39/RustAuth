//! `migrate`: the `auth` schema, its own history table, idempotence, and coexistence with an
//! application's migrations; `schema_status` before and after.

use rustauth_postgres::{MIGRATOR, SchemaStatus, migrate, schema_status};
use sqlx::migrate::{Migration, MigrationType, Migrator};
use sqlx::{PgPool, SqlSafeStr};

/// Every table outside the system schemas, as `schema.table`.
async fn tables(pool: &PgPool) -> Vec<String> {
    sqlx::query_scalar(
        "SELECT table_schema || '.' || table_name FROM information_schema.tables \
         WHERE table_schema NOT IN ('pg_catalog', 'information_schema') ORDER BY 1",
    )
    .fetch_all(pool)
    .await
    .expect("listed tables")
}

/// Versions recorded in a migrations table, oldest first.
async fn applied(pool: &PgPool, table: &str) -> Vec<i64> {
    let sql = format!("SELECT version FROM {table} WHERE success ORDER BY version");
    sqlx::query_scalar(sqlx::AssertSqlSafe(sql))
        .fetch_all(pool)
        .await
        .expect("listed applied migrations")
}

fn embedded() -> Vec<i64> {
    MIGRATOR
        .iter()
        .filter(|migration| !migration.migration_type.is_down_migration())
        .map(|migration| migration.version)
        .collect()
}

#[sqlx::test(migrations = false)]
#[ignore = "requires Postgres: run make test-db"]
async fn creates_the_auth_schema_and_tracks_it_there(pool: PgPool) {
    migrate(&pool).await.expect("migrated");
    assert_eq!(
        tables(&pool).await,
        [
            "auth._sqlx_migrations",
            "auth.login_failures",
            "auth.password_credentials",
            "auth.sessions",
            "auth.users",
        ]
    );
    assert_eq!(applied(&pool, "auth._sqlx_migrations").await, embedded());
}

#[sqlx::test(migrations = false)]
#[ignore = "requires Postgres: run make test-db"]
async fn migrating_again_changes_nothing(pool: PgPool) {
    migrate(&pool).await.expect("first run");
    let before = tables(&pool).await;
    let checksums: Vec<Vec<u8>> =
        sqlx::query_scalar("SELECT checksum FROM auth._sqlx_migrations ORDER BY version")
            .fetch_all(&pool)
            .await
            .expect("read checksums");
    migrate(&pool).await.expect("second run");
    migrate(&pool).await.expect("third run");
    assert_eq!(tables(&pool).await, before);
    let after: Vec<Vec<u8>> =
        sqlx::query_scalar("SELECT checksum FROM auth._sqlx_migrations ORDER BY version")
            .fetch_all(&pool)
            .await
            .expect("read checksums");
    assert_eq!(after, checksums);
    assert_eq!(applied(&pool, "auth._sqlx_migrations").await, embedded());
}

#[sqlx::test(migrations = false)]
#[ignore = "requires Postgres: run make test-db"]
async fn concurrent_migrations_apply_once(pool: PgPool) {
    let (first, second) = tokio::join!(migrate(&pool), migrate(&pool));
    first.expect("first migrator");
    second.expect("second migrator");
    assert_eq!(applied(&pool, "auth._sqlx_migrations").await, embedded());
}

#[sqlx::test(migrations = false)]
#[ignore = "requires Postgres: run make test-db"]
async fn application_migrations_run_afterwards_without_collision(pool: PgPool) {
    migrate(&pool).await.expect("auth migrated");
    // An application migration that reuses the version of the first auth migration and
    // references `auth.users (id)`, recorded in the default `_sqlx_migrations`.
    let version = embedded()[0];
    let application = Migrator::with_migrations(vec![Migration::new(
        version,
        "create widgets".into(),
        MigrationType::Simple,
        "CREATE TABLE widgets (\
           id uuid PRIMARY KEY, \
           user_id uuid NOT NULL REFERENCES auth.users (id) ON DELETE CASCADE)"
            .into_sql_str(),
        false,
    )]);
    application.run(&pool).await.expect("application migrated");
    application.run(&pool).await.expect("application again");
    migrate(&pool).await.expect("auth again");

    assert_eq!(applied(&pool, "public._sqlx_migrations").await, [version]);
    assert_eq!(applied(&pool, "auth._sqlx_migrations").await, embedded());
    assert!(tables(&pool).await.contains(&"public.widgets".to_owned()));
}

#[sqlx::test(migrations = false)]
#[ignore = "requires Postgres: run make test-db"]
async fn down_migrations_revert_to_an_empty_schema(pool: PgPool) {
    migrate(&pool).await.expect("migrated");
    MIGRATOR.undo(&pool, 0).await.expect("reverted");
    assert_eq!(tables(&pool).await, ["auth._sqlx_migrations"]);
    assert!(applied(&pool, "auth._sqlx_migrations").await.is_empty());
    migrate(&pool).await.expect("migrated again");
    assert_eq!(tables(&pool).await.len(), 5);
}

#[sqlx::test(migrator = "rustauth_postgres::MIGRATOR")]
#[ignore = "requires Postgres: run make test-db"]
async fn constraints_reject_unknown_roles_and_assurance_levels(pool: PgPool) {
    let role = sqlx::query(
        "INSERT INTO auth.users (created_at, updated_at, id, username, display_name, role) \
         VALUES (now(), now(), gen_random_uuid(), 'alice', 'Alice', 'owner')",
    )
    .execute(&pool)
    .await
    .expect_err("unknown role");
    assert_eq!(
        role.as_database_error()
            .and_then(|error| error.constraint()),
        Some("users_role_check")
    );

    sqlx::query(
        "INSERT INTO auth.users (created_at, updated_at, id, username, display_name, role) \
         VALUES (now(), now(), gen_random_uuid(), 'alice', 'Alice', 'user')",
    )
    .execute(&pool)
    .await
    .expect("valid user");
    let assurance = sqlx::query(
        "INSERT INTO auth.sessions (created_at, last_used_at, expires_at, id, user_id, \
         token_hash, assurance, methods) \
         SELECT now(), now(), now(), gen_random_uuid(), id, '\\x00', 'aal3', '{password}' \
         FROM auth.users",
    )
    .execute(&pool)
    .await
    .expect_err("unknown assurance level");
    assert_eq!(
        assurance
            .as_database_error()
            .and_then(|error| error.constraint()),
        Some("sessions_assurance_check")
    );
}

#[sqlx::test(migrations = false)]
#[ignore = "requires Postgres: run make test-db"]
async fn schema_status_follows_the_history_table(pool: PgPool) {
    let fresh = schema_status(&pool).await.expect("status before migrating");
    assert_eq!(
        fresh,
        SchemaStatus {
            pending: embedded(),
            ..SchemaStatus::default()
        }
    );
    migrate(&pool).await.expect("migrated");
    assert!(schema_status(&pool).await.expect("status").is_current());

    // A migration recorded by a newer version of the library.
    sqlx::query(
        "INSERT INTO auth._sqlx_migrations \
         (version, description, success, checksum, execution_time) \
         VALUES (99990101000000, 'from a newer release', true, '\\x00', 0)",
    )
    .execute(&pool)
    .await
    .expect("recorded a newer migration");
    let newer = schema_status(&pool).await.expect("status");
    assert_eq!(newer.unknown, [99_990_101_000_000]);
    assert!(newer.pending.is_empty() && newer.changed.is_empty());

    // An applied file that no longer matches, and one whose run failed.
    let first = embedded()[0];
    sqlx::query("UPDATE auth._sqlx_migrations SET checksum = '\\x01' WHERE version = $1")
        .bind(first)
        .execute(&pool)
        .await
        .expect("changed a checksum");
    assert_eq!(schema_status(&pool).await.expect("status").changed, [first]);
    sqlx::query("UPDATE auth._sqlx_migrations SET success = false WHERE version = $1")
        .bind(first)
        .execute(&pool)
        .await
        .expect("marked as failed");
    assert_eq!(schema_status(&pool).await.expect("status").pending, [first]);
}
