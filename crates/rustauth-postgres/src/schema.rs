//! `schema_status(&pool)`: how the applied `auth` migrations compare with the ones this version
//! embeds, so an application can refuse to start against a schema that is behind or ahead.

use std::collections::BTreeMap;

use rustauth_core::{AuthError, AuthResult};
use sqlx::PgPool;

use crate::migrate::{MIGRATIONS_TABLE, MIGRATOR};

/// The difference between the applied and the embedded migrations, by version. All lists are
/// sorted and empty when the schema matches this version of the library.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SchemaStatus {
    /// Embedded migrations not applied yet, or whose last run failed.
    pub pending: Vec<i64>,
    /// Applied migrations this version does not embed: the database was migrated by a newer
    /// version of the library.
    pub unknown: Vec<i64>,
    /// Applied migrations whose file has changed since (a different checksum).
    pub changed: Vec<i64>,
}

impl SchemaStatus {
    /// Whether the applied migrations are exactly the embedded ones.
    pub fn is_current(&self) -> bool {
        self.pending.is_empty() && self.unknown.is_empty() && self.changed.is_empty()
    }
}

/// One row of `auth._sqlx_migrations`.
#[derive(Clone, Debug, Eq, PartialEq)]
struct Applied {
    success: bool,
    checksum: Vec<u8>,
}

/// Reads `auth._sqlx_migrations` (missing means nothing is applied) and compares it with the
/// embedded migrations. Changes nothing.
pub async fn schema_status(pool: &PgPool) -> AuthResult<SchemaStatus> {
    let failed = |error| AuthError::internal("rustauth.migrate.status-failed", error);
    let exists: bool = sqlx::query_scalar("SELECT to_regclass($1) IS NOT NULL")
        .bind(MIGRATIONS_TABLE)
        .fetch_one(pool)
        .await
        .map_err(failed)?;
    let rows: Vec<(i64, bool, Vec<u8>)> = if exists {
        sqlx::query_as("SELECT version, success, checksum FROM auth._sqlx_migrations")
            .fetch_all(pool)
            .await
            .map_err(failed)?
    } else {
        Vec::new()
    };
    let applied = rows
        .into_iter()
        .map(|(version, success, checksum)| (version, Applied { success, checksum }))
        .collect();
    Ok(compare(&embedded(), &applied))
}

/// Version and checksum of every embedded up migration.
fn embedded() -> BTreeMap<i64, Vec<u8>> {
    MIGRATOR
        .iter()
        .filter(|migration| migration.migration_type.is_up_migration())
        .map(|migration| (migration.version, migration.checksum.to_vec()))
        .collect()
}

fn compare(embedded: &BTreeMap<i64, Vec<u8>>, applied: &BTreeMap<i64, Applied>) -> SchemaStatus {
    let mut status = SchemaStatus::default();
    for (version, checksum) in embedded {
        match applied.get(version) {
            Some(row) if !row.success => status.pending.push(*version),
            Some(row) if row.checksum != *checksum => status.changed.push(*version),
            Some(_) => {}
            None => status.pending.push(*version),
        }
    }
    status.unknown = applied
        .keys()
        .filter(|version| !embedded.contains_key(version))
        .copied()
        .collect();
    status
}

#[cfg(test)]
mod tests {
    use super::*;

    fn embedded_pairs(pairs: &[(i64, u8)]) -> BTreeMap<i64, Vec<u8>> {
        pairs
            .iter()
            .map(|(version, checksum)| (*version, vec![*checksum]))
            .collect()
    }

    fn applied(rows: &[(i64, bool, u8)]) -> BTreeMap<i64, Applied> {
        rows.iter()
            .map(|(version, success, checksum)| {
                (
                    *version,
                    Applied {
                        success: *success,
                        checksum: vec![*checksum],
                    },
                )
            })
            .collect()
    }

    #[test]
    fn matching_histories_are_current() {
        let status = compare(
            &embedded_pairs(&[(1, 1), (2, 2)]),
            &applied(&[(1, true, 1), (2, true, 2)]),
        );
        assert!(status.is_current());
    }

    #[test]
    fn reports_pending_unknown_and_changed_versions() {
        let status = compare(
            &embedded_pairs(&[(1, 1), (2, 2), (3, 3), (4, 4)]),
            &applied(&[(1, true, 1), (2, true, 9), (3, false, 3), (5, true, 5)]),
        );
        assert_eq!(
            status,
            SchemaStatus {
                pending: vec![3, 4],
                unknown: vec![5],
                changed: vec![2],
            }
        );
        assert!(!status.is_current());
    }

    #[test]
    fn nothing_applied_means_everything_is_pending() {
        let status = compare(&embedded_pairs(&[(1, 1), (2, 2)]), &BTreeMap::new());
        assert_eq!(status.pending, [1, 2]);
        assert!(status.unknown.is_empty() && status.changed.is_empty());
    }

    #[test]
    fn embeds_at_least_one_up_migration() {
        assert!(!embedded().is_empty());
    }
}
