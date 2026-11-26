-- create_auth_tables: revert everything the .up.sql file does. The `auth` schema and its
-- `_sqlx_migrations` table belong to the migrator and stay.
DROP TABLE auth.sessions;
DROP TABLE auth.password_credentials;
DROP TABLE auth.users;
