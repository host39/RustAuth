-- create_login_failures: the failed sign-in state of usernames that have no account.
-- Accounts keep this state on auth.users. A username without one keeps the same columns here,
-- keyed by its lowercase form, so it locks exactly like a real account on every instance and
-- across restarts, and lockout cannot reveal which usernames exist. `AuthService::purge`
-- deletes rows that no longer count. Columns follow .ai/rules/postgres-column-alignment.md.
CREATE TABLE auth.login_failures (
  last_failed_login_at timestamptz,
  locked_until         timestamptz,
  failed_login_count   integer     NOT NULL DEFAULT 0,
  lockout_count        integer     NOT NULL DEFAULT 0,
  username             text        PRIMARY KEY
);
