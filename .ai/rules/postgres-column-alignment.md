# PostgreSQL Column Alignment

PostgreSQL pads fixed-width columns to their alignment boundary, so mixing widths wastes space in every row. Order columns in each `CREATE TABLE` in a new migration under `crates/rustauth-postgres/migrations/`.

## Rule

Within each `CREATE TABLE`, list columns in this order:

1. **8-byte**: `timestamptz`, `timestamp`, `bigint`, `bigserial`, `double precision`
2. **4-byte**: `integer`, `serial`, `real`, `date`
3. **16-byte**: `uuid`
4. **1-byte**: `boolean`
5. **Variable-length last**: `text`, `varchar`, `numeric`, `bytea`, `inet`, `json`, `jsonb`, arrays

When a migration creates a table, sort the whole column list. `ALTER TABLE ... ADD COLUMN` always appends at the end; that is acceptable for small additions, and a rebuild to restore alignment is a deliberate migration of its own (and must follow the expand-then-contract rule below).

The Rust row structs (`sqlx::FromRow`) map columns by name, so their field order does not need to match.

## Library Conventions

- Every table lives in the `auth` schema and is created with a schema-qualified name (`auth.widgets`).
- Use `text` plus a `CHECK` constraint instead of enum types, so adding a value later is a plain migration.
- Committed migrations are append-only once a release tag includes them (sqlx checksums applied files). Breaking changes ship as expand, then contract, across two releases; see "Upgrades and Compatibility" in `docs/design/rustauth.md`.
- `auth.users (id uuid primary key)` is the one stable contract applications reference. Never rename, retype, or drop it.

## Example

```sql
CREATE TABLE auth.widgets (
  created_at   timestamptz NOT NULL,
  updated_at   timestamptz NOT NULL,
  position     integer     NOT NULL,
  id           uuid        PRIMARY KEY,
  user_id      uuid        NOT NULL REFERENCES auth.users (id) ON DELETE CASCADE,
  archived     boolean     NOT NULL DEFAULT false,
  status       text        NOT NULL CHECK (status IN ('active', 'retired')),
  name         text        NOT NULL,
  settings     jsonb       NOT NULL DEFAULT '{}'
);
```
