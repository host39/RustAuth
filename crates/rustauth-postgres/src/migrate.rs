//! `migrate(&pool)`: creates the `auth` schema, applies the embedded migrations, and records them
//! in `auth._sqlx_migrations`. Also the startup schema check that compares applied and embedded
//! migrations.
