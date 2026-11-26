//! `migrate(&pool)`: creates the `auth` schema, applies the embedded migrations, and records them
//! in `auth._sqlx_migrations`, apart from the application's own `_sqlx_migrations`.

use std::sync::LazyLock;

use rustauth_core::{AuthError, AuthResult};
use sqlx::PgPool;
use sqlx::migrate::Migrator;

/// The Postgres schema that holds every RustAuth table.
pub const SCHEMA: &str = "auth";

/// Where the migrator records applied RustAuth migrations.
pub const MIGRATIONS_TABLE: &str = "auth._sqlx_migrations";

/// The SQL files in `crates/rustauth-postgres/migrations`, embedded at compile time.
static EMBEDDED: Migrator = sqlx::migrate!("./migrations");

/// The embedded migrations, set up to create the `auth` schema and to track their history in
/// [`MIGRATIONS_TABLE`]. [`migrate`] runs it; tests pass it to `#[sqlx::test(migrator = ...)]`.
///
/// Never run these migrations with a migrator that uses the default table: it would record them
/// in the application's `_sqlx_migrations`, where versions can collide.
pub static MIGRATOR: LazyLock<Migrator> = LazyLock::new(|| {
    let mut migrator = Migrator::with_migrations(EMBEDDED.iter().cloned().collect());
    migrator.dangerous_set_table_name(MIGRATIONS_TABLE);
    migrator.create_schema(SCHEMA);
    migrator
});

/// Applies pending RustAuth migrations. Applications call it in their migrate step before their
/// own migrations (which may then reference `auth.users (id)`). Safe to run on every start and
/// from several processes at once: applied migrations are skipped, and the migrator holds a
/// Postgres advisory lock while it runs.
///
/// Fails with `rustauth.migrate.failed` when a migration fails or an applied migration no longer
/// matches the embedded file (the error's source says which).
pub async fn migrate(pool: &PgPool) -> AuthResult<()> {
    MIGRATOR
        .run(pool)
        .await
        .map_err(|error| AuthError::internal("rustauth.migrate.failed", error))?;
    tracing::debug!(
        migrations = MIGRATOR.iter().count(),
        table = MIGRATIONS_TABLE,
        "rustauth.migrate.done"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embeds_the_migrations_with_the_auth_history_table() {
        assert!(MIGRATOR.iter().count() > 0);
        assert_eq!(MIGRATOR.iter().count(), EMBEDDED.iter().count());
        assert_eq!(MIGRATOR.table_name, MIGRATIONS_TABLE);
        assert_eq!(MIGRATOR.create_schemas.as_ref(), [SCHEMA]);
        assert!(MIGRATOR.locking);
    }
}
