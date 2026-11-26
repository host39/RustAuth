# Changelog

All notable changes to RustAuth are recorded here. The format follows [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/), and releases follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html) with tags `vMAJOR.MINOR.PATCH`. The `rustauth` crate and the npm package `@rustauth/contracts` share one version.

Before `1.0`, a minor release may break. Every release lists its breaking changes, its schema changes, and whether it may be skipped under "Upgrade Notes", with the exact steps. The compatibility rules behind them are in [Upgrades and Compatibility](./docs/design/rustauth.md#upgrades-and-compatibility).

## [Unreleased]

The first release, planned as `v0.1.0`.

### Added

#### Rust Library

- The `rustauth` facade crate, the only supported Rust surface. `RustAuth::builder()` takes the application's `PgPool` (`pool`) or custom ports (`ports`), the settings (`config`), and `allow_newer_schema`; `build()` checks the `auth` schema and starts the services. A built `RustAuth` gives `router()`, `guard()`, `service()` (`AuthService`), `admin()` (`AdminService`), `limiter()`, and `config()`.
- Features: `axum` and `postgres` (default), `migrate` (only `migrate` and `schema_status`, without HTTP, OpenAPI, or hashing crates), `contracts`, `crypto`, `testing` (in-memory fakes of every port), and `ts` (`ts_rs::TS` on the contracts).
- `rustauth::migrate(&pool)` applies the embedded migrations, and `rustauth::schema_status(&pool)` compares the applied ones with them. `rustauth::VERSION` holds the library version.
- Username and password sign-in with Argon2id hashes (`argon2` 0.6 defaults, run off the async threads behind a semaphore). Unknown usernames are checked against a dummy hash and get the same error, so neither timing nor messages reveal accounts.
- Opaque 256-bit bearer session tokens, stored only as SHA-256 hashes and revocable at once. Sessions slide for 30 days up to 90 days from sign-in, record the client IP and user agent, and are rebuilt into a `Principal` from the database on every request.
- First-run setup: while no account exists, registration needs the setup token (configured, or generated and logged once at startup) and creates the first administrator. Later registrations follow `AUTH_REGISTRATION_OPEN` and create plain users.
- Roles `administrator`, `manager`, and `user`, ordered by privilege: `Principal::has_role`, `Principal::require`, `AuthUser::require`, and `guard().require(role)`.
- Account administration: list, get, create with a temporary password, change display name, role, or disabled state, reset the password, unlock, and delete. The last enabled administrator cannot be removed, disabled, or demoted, and every change revokes the account's sessions.
- Session management: the caller's own sessions (current one flagged), revoke one, revoke all others; a password change revokes every other session.
- Brute-force protection: account lockout after 5 wrong passwords within 15 minutes (each check reserved before the password is checked, so concurrent attempts get no extra guesses), doubling up to 24 hours; unknown usernames lock the same way; per-IP failure limits and per-IP request limits on the public routes, with trusted-proxy handling.
- `AuthService::purge` deletes expired sessions and failure records of unknown usernames that no longer count.
- `guard().optional()`, `OptionalAuthUser`, `client_ip`, and `request_scope` for applications that need them.
- Lenient readers: a newer release's rows keep working (an unknown sign-in method is skipped, an unknown assurance level reads as `aal1`, an unknown role as `user`).
- Structured logs under `rustauth.*` dotted keys (for example `rustauth.login.failed`, `rustauth.login.locked`, `rustauth.setup.token-issued`); passwords, tokens, and hashes are never logged.
- Dependency versions matching the RustInit template: `axum` 0.8.9, `sqlx` 0.9.1, `utoipa` 6.0.0, `utoipa-axum` 0.3.0, `ts-rs` 12.0.1, `tokio` 1.48. The library turns on no sqlx TLS backend and makes no outbound HTTP calls. Minimum Rust version 1.94.

#### HTTP Routes

Relative to where the application mounts `auth.router()` (for example `/api`):

| Route | Auth | Purpose |
| --- | --- | --- |
| `GET /auth/setup` | public | `needsSetup` and `registrationOpen`, for first-run screens |
| `POST /auth/register` | public | Create an account and sign in (`setupToken` while no account exists) |
| `POST /auth/login` | public | Sign in with username and password |
| `POST /auth/logout` | user | Revoke the current session |
| `GET /auth/me` | user | The caller's account |
| `PATCH /auth/me` | user | Change the display name |
| `POST /auth/password` | user | Change the password; revokes the other sessions |
| `GET /auth/sessions` | user | The caller's sessions |
| `DELETE /auth/sessions/{id}` | user | Revoke one session |
| `POST /auth/sessions/revoke-others` | user | Revoke every other session |
| `GET /admin/users` | administrator | Paginated account list |
| `POST /admin/users` | administrator | Create an account with a temporary password and a role |
| `GET /admin/users/{id}` | administrator | One account |
| `PATCH /admin/users/{id}` | administrator | Display name, role, disabled state, password reset (also unlocks) |
| `POST /admin/users/{id}/unlock` | administrator | Clear the lockout |
| `DELETE /admin/users/{id}` | administrator | Delete the account |

- Bodies use the RustInit envelopes: `{ "data": ... }`, `{ "items": [...], "total": n }`, and an empty `204` for revocations, unlock, and delete. Error bodies are `{ "error", "code", "field", "details", "requestId" }`; `429` responses carry `Retry-After` and `details.retryAfterSecs`, and `401` responses `WWW-Authenticate: Bearer`.
- Error codes: `INVALID_CREDENTIALS`, `UNAUTHORIZED`, `FORBIDDEN`, `VALIDATION_ERROR`, `ENTITY_NOT_FOUND`, `USERNAME_TAKEN`, `USER_IN_USE`, `SETUP_REQUIRED`, `REGISTRATION_CLOSED`, `LAST_ADMINISTRATOR`, `RATE_LIMITED`, `ACCOUNT_LOCKED`, `PAYLOAD_TOO_LARGE`, `UNSUPPORTED_MEDIA_TYPE`, `INTERNAL_ERROR`.
- OpenAPI: schemas named `rustauth.*`, operation ids `rustauth_*`, tags `rustauth.auth` and `rustauth.admin`, and the `bearerAuth` security scheme, so the routes merge into the application's document without collisions.
- `X-Request-Id` from the request is echoed as `requestId` in error bodies.

#### Configuration

`AuthConfig::parse(&env)` reads these variables; `AuthConfig::builder()` sets the same values in code.

| Variable | Default | Purpose |
| --- | --- | --- |
| `AUTH_REGISTRATION_OPEN` | `false` | Allow sign-ups after the first (administrator) account |
| `AUTH_SETUP_TOKEN` | random, logged once at startup | Token required for the first registration |
| `AUTH_SESSION_TTL_DAYS` | `30` | Sliding session lifetime |
| `AUTH_SESSION_MAX_DAYS` | `90` | Absolute session lifetime |
| `AUTH_TRUSTED_PROXIES` | empty | Comma-separated IPs or CIDRs whose `X-Forwarded-For` is trusted |
| `AUTH_LOCKOUT_THRESHOLD` | `5` | Wrong passwords within the failure window before the account locks |
| `AUTH_LOCKOUT_MINUTES` | `15` | First lockout length (doubles with each lockout) |
| `AUTH_LOCKOUT_MAX_MINUTES` | `1440` | Longest lockout |
| `AUTH_IP_FAILURE_LIMIT` | `30` | Failed sign-ins per client IP per 15 minutes |
| `AUTH_RATE_LIMIT_PER_MINUTE` | `60` | Requests per client IP per minute to the public auth routes |

Two settings exist only on the builder: `failure_window` (15 minutes) and `touch_interval` (1 hour).

#### Database Schema

Every table lives in the Postgres schema `auth`, which the migrations create. The applied migrations are recorded in `auth._sqlx_migrations`, apart from the application's own `_sqlx_migrations`.

| Migration | Creates |
| --- | --- |
| `20261126170000_create_auth_tables` | `auth.users` (unique index `users_username_key` on `lower(username)`), `auth.password_credentials`, and `auth.sessions` (indexes on `user_id` and `expires_at`) |
| `20261126200000_create_login_failures` | `auth.login_failures`, the lockout state of usernames without an account |

`auth.users (id uuid primary key)` is the stable database contract: application tables may declare `REFERENCES auth.users (id) ON DELETE CASCADE`, and no release renames, retypes, or drops it.

#### Web Package

- `@rustauth/contracts` 0.1.0, installed from git (`github:host39/lib-rustauth#<tag>&path:packages/contracts`): TypeScript types generated from the Rust DTOs, Zod schemas that `satisfies` them, `authRoutes`, `AUTH_ERROR_CODES`, `USER_ROLES`, `REQUEST_ID_HEADER`, `hasRole`, and `retryAfterSecs`. It ships TypeScript sources and needs `zod` 4 as a peer dependency.
- Response schemas accept a newer server within the same major version: unknown fields are dropped and an unknown role reads as `user`.

#### Documentation

- The [design](./docs/design/rustauth.md), the [integration guide](./docs/integration.md), [ADRs](./docs/adr/README.md), and the example server (`examples/server`).

### Upgrade Notes

#### How to Upgrade an Application

1. Read the "Upgrade Notes" of every release after the one you run, up to the target, oldest first. Each one says whether its schema change is expand only (safe to roll back across with `allow_newer_schema(true)`), whether it must not be skipped, and which code changes it needs.
2. Bump the `tag` of `rustauth` in `Cargo.toml` and of `@rustauth/contracts` in `package.json` together, in one commit. Run `cargo tree -d`: it should list no second copy of `axum`, `sqlx`, or `utoipa` (a release that moves one of them to a new major version says so here).
3. Make the code changes the notes list. They stay inside the application's one rustauth adapter module when the application keeps all rustauth usage there.
4. Run the migrate step (`rustauth::migrate(&pool)`, then the application's own migrations). New auth migrations apply automatically; applied ones never change.
5. Run the full test suite, including the database tests, which run the same migrate step.
6. Deploy: run the migrate step before the new version serves traffic. `RustAuth::build()` refuses to start while auth migrations are pending ("Auth schema is out of date: run migrations"). Instances of the previous version keep working against the migrated schema during a rolling deploy, because breaking schema changes ship as expand, then contract, across two releases.
7. Rolling back: once the new migrations ran, the previous version refuses to start ("Auth schema is newer than this version of rustauth") unless it is built with `allow_newer_schema(true)`. Allow it only when every release rolled back across is marked expand only. Never revert auth migrations or edit `auth` tables by hand: the library owns the schema.
8. Skipping releases is fine unless a release says it must not be skipped (it contracts what an earlier release expanded). Then upgrade to that earlier release first, deploy it everywhere, and continue from there.

#### This Release

- First release; there is no earlier release to upgrade from. Pin `rustauth = { git = "https://github.com/host39/lib-rustauth", tag = "v0.1.0" }` and `@rustauth/contracts` at `#v0.1.0`, and follow the [integration guide](./docs/integration.md).
- Schema: expand only. Creates the `auth` schema with the two migrations listed above.
- Applications that pinned a pre-release `rev`: the auth migrations were only ever added, never edited, so the migrate step brings the schema up to date (it adds `auth.login_failures` when missing). Rust names may have changed before the first tag; the integration guide shows the released ones.

[Unreleased]: https://github.com/host39/lib-rustauth/commits/HEAD
