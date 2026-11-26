-- create_auth_tables: accounts, password credentials, and sessions in the `auth` schema.
-- The schema itself is created by the migrator (`create_schema("auth")`), which also keeps its
-- history in `auth._sqlx_migrations`. Columns follow .ai/rules/postgres-column-alignment.md.

-- Accounts. `id` is the one stable database contract: application tables may declare
-- `REFERENCES auth.users (id) ON DELETE CASCADE`, so no release renames, retypes, or drops it.
CREATE TABLE auth.users (
  created_at           timestamptz NOT NULL,
  updated_at           timestamptz NOT NULL,
  disabled_at          timestamptz,
  last_failed_login_at timestamptz,
  locked_until         timestamptz,
  failed_login_count   integer     NOT NULL DEFAULT 0,
  lockout_count        integer     NOT NULL DEFAULT 0,
  id                   uuid        PRIMARY KEY,
  username             text        NOT NULL,
  display_name         text        NOT NULL,
  role                 text        NOT NULL CHECK (role IN ('administrator', 'manager', 'user'))
);

-- Usernames are stored as typed and unique case-insensitively; lookups use the same expression.
CREATE UNIQUE INDEX users_username_key ON auth.users (lower(username));

-- Password hashes (Argon2id PHC strings), apart from `auth.users` so that accounts without a
-- password (single sign-on, later) need no row.
CREATE TABLE auth.password_credentials (
  changed_at timestamptz NOT NULL,
  user_id    uuid        PRIMARY KEY REFERENCES auth.users (id) ON DELETE CASCADE,
  hash       text        NOT NULL
);

-- Signed-in devices. Only the SHA-256 hash of the bearer token is stored.
CREATE TABLE auth.sessions (
  created_at   timestamptz NOT NULL,
  last_used_at timestamptz NOT NULL,
  expires_at   timestamptz NOT NULL,
  id           uuid        PRIMARY KEY,
  user_id      uuid        NOT NULL REFERENCES auth.users (id) ON DELETE CASCADE,
  token_hash   bytea       NOT NULL UNIQUE,
  assurance    text        NOT NULL CHECK (assurance IN ('aal1', 'aal2')),
  ip           inet,
  user_agent   text        NOT NULL DEFAULT '',
  methods      text[]      NOT NULL
);

CREATE INDEX sessions_user_id_idx ON auth.sessions (user_id);
CREATE INDEX sessions_expires_at_idx ON auth.sessions (expires_at);
