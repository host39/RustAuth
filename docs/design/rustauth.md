# RustAuth Design

Status: draft v1 (2026-11-26). Working spec for `v0.1.0`.

## Goal

A reusable authentication and authorization library for the owner's Rust (axum + sqlx + Postgres) applications. An application adds the library, runs its migrations, mounts its router, and puts its guard in front of protected routes. Every application becomes a client of this library, so security fixes and new sign-in methods land once.

### Generic by Design

RustAuth knows nothing about the applications that use it. Code, docs, examples, tests, table and column names, error codes, and configuration must not mention any particular application or its features. Anything application-specific (profile fields, settings, per-app permissions, product names) stays in the application, which keeps its own tables that reference `auth.users (id)`. When an application needs something new from the library, it is added here only as a general capability that any application could use. Examples use neutral names (`example`, `my-app`, `widgets`).

The design follows the same clean/DDD layering as the RustInit template (`host39/template-rust-init`): domain logic in a pure core crate, adapters in their own crates, and dependency rules checked by a script.

### Scope of v0.1

- Username and password sign-in.
- Opaque bearer session tokens stored as SHA-256 hashes (immediately revocable, no signing keys to manage).
- First-run setup: the first account becomes an administrator and needs a setup token.
- Roles for authorization: `administrator`, `manager`, `user`.
- Account administration: create, disable, reset password, change role, delete, with a last-administrator guard.
- Session management: list own sessions (devices), revoke one, revoke all others.
- Brute-force protection: temporary account lockout after repeated wrong passwords (even the correct password is refused until the lock ends), per-IP failure limits, and request rate limits on the public auth routes, with trusted-proxy handling.
- Safe upgrades: the library is maintained and released separately from the apps that use it, so its schema, Rust API, and HTTP API follow the compatibility rules in [Upgrades and Compatibility](#upgrades-and-compatibility).
- Postgres storage in its own schema, `auth`, with its own migrations.

### Later (Designed For, Not Built)

| Feature | Extension point |
| --- | --- |
| TOTP two-factor | `auth.totp_factors` table; sessions already record `methods` and `assurance` |
| Passkeys (WebAuthn) | `auth.passkeys` table; a `Credential` port per method |
| SSO (OIDC) | `auth.identities` (provider, subject, user id); users may exist without a password credential |
| Email and recovery | Optional `email` column with verification; recovery tokens table |
| Fine-grained permissions | `Permission` values checked through `Policy`; roles map to permission sets |
| JWT access tokens for other services | A token issuer port beside opaque sessions (the owner's GoAuth uses Ed25519 JWTs + JWKS) |

Each later feature adds tables and services; none changes the v0.1 tables except by adding columns.

## Repository Layout

```text
lib-rustauth/
  Cargo.toml                  workspace (resolver 3, edition 2024)
  crates/
    rustauth-core/            domain: entities, value objects, ports, services, AuthError
    rustauth-crypto/          Argon2id hasher, token issuer (implements core ports)
    rustauth-postgres/        sqlx repositories + migrations in schema `auth`
    rustauth-contracts/       DTOs (serde + utoipa; optional ts-rs under the `ts` feature)
    rustauth-axum/            router, guard layer, extractors, HTTP error mapping
    rustauth/                 facade: re-exports + `RustAuth::builder()`; features `postgres`, `axum`, `testing`, `ts`
  packages/contracts/         npm package `@rustauth/contracts`: generated TS types + Zod schemas
  examples/server/            minimal axum app using the facade (docs and smoke tests)
  docs/                       design, ADRs, integration guide
```

Dependency rules (checked by `scripts/boundaries.mjs`, like the template):

| Crate | Must not depend on |
| --- | --- |
| `rustauth-core` | `axum`, `sqlx`, `utoipa`, `ts-rs`, `argon2`, any other rustauth crate |
| `rustauth-crypto` | `axum`, `sqlx`, `rustauth-postgres`, `rustauth-axum` |
| `rustauth-postgres` | `axum`, `utoipa`, `rustauth-axum`, `rustauth-crypto` |
| `rustauth-contracts` | `sqlx`, `axum`, `rustauth-postgres` |
| `rustauth-axum` | `sqlx`, `rustauth-postgres` (it talks to core services only) |

Versions match the RustInit template so applications get one copy of each crate: `axum` 0.8.9, `sqlx` 0.9.1 (Postgres, rustls with ring), `utoipa` 6.0.0, `utoipa-axum` 0.3.0, `ts-rs` 12.0.1, `tokio` 1.48, `argon2` 0.6, `sha2`, `getrandom`, `chrono`, `uuid`. Keep `reqwest`-free: the library makes no outbound HTTP calls in v0.1.

## Domain Model (`rustauth-core`)

### Value Objects

| Type | Rules |
| --- | --- |
| `UserId` | `Uuid` (v7, generated in Rust) |
| `Username` | 3 to 32 characters: ASCII letters, digits, underscore. Unique case-insensitively; stored as typed, compared lowercased |
| `DisplayName` | 1 to 80 characters after trimming |
| `Password` | 12 to 256 bytes; never logged (`Debug` prints `***`) |
| `Role` | `administrator`, `manager`, `user`; ordered so `administrator > manager > user` |
| `SessionToken` | 32 random bytes, base64url without padding; shown once; `Debug` redacted |
| `TokenHash` | SHA-256 of the token string |
| `ClientInfo` | client IP (after trusted-proxy resolution) and the first 256 characters of the user agent |
| `AuthMethod` | `password` now; `totp`, `passkey`, `sso` later |
| `Assurance` | `aal1` now; `aal2` once a second factor exists |

### Entities

```rust
struct User {
    id: UserId, username: Username, display_name: DisplayName, role: Role,
    disabled_at: Option<DateTime<Utc>>, created_at, updated_at,
    lockout: Lockout,
}
struct Lockout { failed_count: u32, lockouts: u32, last_failed_at: Option<DateTime<Utc>>, locked_until: Option<DateTime<Utc>> }
struct PasswordCredential { user_id: UserId, hash: String, changed_at: DateTime<Utc> }
struct Session {
    id: SessionId, user_id: UserId, token_hash: TokenHash,
    methods: Vec<AuthMethod>, assurance: Assurance,
    created_at, last_used_at, expires_at, user_agent: String, ip: Option<IpAddr>,
}
```

### Principal

What a verified request carries, built from the database on every request (never from a cached claim):

```rust
struct Principal { user_id: UserId, username: Username, role: Role, session_id: SessionId, assurance: Assurance }
impl Principal {
    fn has_role(&self, minimum: Role) -> bool;   // role >= minimum
    fn require(&self, minimum: Role) -> Result<(), AuthError>; // Forbidden otherwise
}
```

### Ports

Every async method returns `Result<_, AuthError>`; traits are `Send + Sync` and used as `Arc<dyn Trait>`.

```rust
trait Clock { fn now(&self) -> DateTime<Utc>; }
trait PasswordHasher {
    async fn hash(&self, password: &Password) -> Result<String>;                   // spawn_blocking behind a small semaphore
    async fn verify(&self, password: &Password, hash: &str) -> Result<bool>;
}
trait TokenIssuer { fn issue(&self) -> (SessionToken, TokenHash); fn hash(&self, token: &str) -> TokenHash; }

trait UserRepository {
    /// One transaction: pg_advisory_xact_lock(<fixed key>), count users, insert. With zero users the
    /// new user becomes `administrator` (only if `policy.setup_token_ok`); otherwise `policy.registration_open`
    /// must be true and the role is `user`. Decided inside the lock, so two concurrent first registrations
    /// produce exactly one administrator.
    async fn register(&self, user: NewUser, credential: NewPassword, policy: RegisterPolicy) -> Result<User>;
    async fn create(&self, user: NewUser, credential: NewPassword) -> Result<User>;  // admin-created accounts
    async fn get(&self, id: UserId) -> Result<Option<User>>;
    async fn find(&self, username: &Username) -> Result<Option<(User, Option<PasswordCredential>)>>;
    async fn list(&self, page: Page) -> Result<(Vec<User>, u64)>;
    /// Applies only the fields set in `patch` (display name, role, disabled), so concurrent changes to
    /// different fields cannot overwrite each other; fails LastAdministrator in the same tx when no
    /// enabled admin would remain.
    async fn update(&self, id: UserId, patch: &UserPatch, at: DateTime<Utc>) -> Result<User>;
    async fn delete(&self, id: UserId) -> Result<bool>;  // same guard
    async fn count(&self) -> Result<u64>;
    async fn set_password(&self, user: UserId, hash: String, at: DateTime<Utc>) -> Result<()>;
    // Lockout state (see Brute-Force Protection):
    async fn record_failure(&self, user: UserId, at: DateTime<Utc>, since: DateTime<Utc>) -> Result<Lockout>; // one UPDATE ... RETURNING
    async fn lock(&self, user: UserId, until: DateTime<Utc>, lockouts: u32) -> Result<bool>; // only if `lockouts` is unchanged
    async fn unlock(&self, user: UserId) -> Result<()>;
}
trait SessionRepository {
    async fn insert(&self, session: &Session) -> Result<()>;
    async fn find(&self, hash: &TokenHash) -> Result<Option<(Session, User)>>;     // joins users
    async fn touch(&self, id: SessionId, last_used_at, expires_at) -> Result<()>;
    async fn list(&self, user: UserId) -> Result<Vec<Session>>;
    async fn delete(&self, user: UserId, id: SessionId) -> Result<bool>;
    async fn delete_all(&self, user: UserId, except: Option<SessionId>) -> Result<u64>;
    async fn purge_expired(&self, before: DateTime<Utc>) -> Result<u64>;
}
```

`RegisterPolicy` holds what the service decided before the lock (`registration_open`, the setup token check result); the repository repeats the count check inside the lock and returns `SetupRequired` or `RegistrationClosed` when the state changed.

The rules the repositories apply inside their transactions are defined in core so every implementation shares them: `RegisterPolicy::decide(count)` (first administrator), `User::ensure_admin_remains(next, others)` (last-administrator guard), and `Lockout::fail` / `Lockout::lock` (the lockout transitions). The services receive their adapters bundled as `Ports`.

### Services

| Service | Operations |
| --- | --- |
| `AuthService` | `setup_status()` (needs setup, registration open), `register(input, setup_token, client)`, `login(username, password, client)`, `logout(principal)`, `verify(bearer)` (hash, load session plus user, reject expired, disabled, or deleted; slide `last_used_at` at most hourly), `me`, `update_profile(display_name)`, `change_password(current, new, client)` (revokes other sessions; a wrong current password counts toward the lockout and fails as a validation error on `current`), `sessions`, `revoke(session_id)`, `revoke_others`, `purge` (deletes expired sessions) |
| `AdminService` | `list`, `get`, `create` (temporary password, role), `update` (role, disabled, display name, password reset; every change revokes that user's sessions), `unlock`, `delete`; refuses to remove, disable, or demote the last enabled administrator; caller must be `administrator` |
| `LoginGuard` | Brute-force protection; see [Brute-Force Protection](#brute-force-protection) |
| `RateLimiter` | In-memory token buckets per client IP for the public routes |

Rules:

- Unknown usernames verify against a fixed dummy hash and return the same "Invalid username or password." error, so timing and messages do not reveal accounts.
- Disabled users cannot sign in and their sessions stop verifying immediately.
- Sessions slide for `session_ttl` (30 days) up to `session_max` (90 days) from creation.
- While no user exists, registration needs the setup token (configured, or 32 random bytes generated at startup and logged once). Comparison is constant-time. The first user becomes `administrator`. After that, registration follows `registration_open` and creates `user` accounts only.

### Brute-Force Protection

Three layers, all on by default:

1. **Account lockout (persisted).** Each wrong password for an existing account increments `failed_count` atomically in the database (`UPDATE ... SET failed_count = failed_count + 1 ... RETURNING`, so concurrent attempts cannot skip the count). When it reaches `lockout_threshold` (default 5), the account is locked until `now + lockout_duration`. The duration doubles with each consecutive lockout (`lockouts` counter): 15 minutes, 30, 60, and so on, capped at `lockout_max` (default 24 hours). While locked, login is refused **before** the password is checked, so even the correct password fails, and no Argon2 work is spent. A successful login resets `failed_count` and `lockouts`. Failures older than the lockout window (15 minutes) start a new count. An administrator can unlock an account, and an administrator password reset also unlocks it. Existing sessions stay valid during a lockout (the lock is about guessing, not compromise).
2. **Unknown usernames behave the same.** Attempts on usernames that do not exist are counted in memory with the same threshold and produce the same "locked" response, so lockout cannot be used to discover which usernames exist.
3. **Per-IP limits (in memory).** Failed logins per client IP: 30 per 15 minutes. Requests to the public routes (`/auth/login`, `/auth/register`, `/auth/setup`) per client IP: 60 per minute (token bucket). Over either limit: `429` with `Retry-After`. These stop one client from locking out many accounts quickly.

The locked response is `429` with `Retry-After` and the code `ACCOUNT_LOCKED`, message "Too many failed sign-in attempts. Try again in N minutes." Logs: `rustauth.login.failed` (user id or `unknown`, client IP, count), `rustauth.login.locked` (user id, until), `rustauth.login.unlocked` (by administrator). Passwords and tokens are never logged.

Tradeoff: lockout lets an attacker who knows a username lock that person out temporarily. The capped, doubling duration, the per-IP limits, and the administrator unlock keep this bounded; the alternative (no lockout) allows unlimited slow guessing.

### Errors

`AuthError` variants carry human-readable messages and stable codes (dotted keys only for `Internal`):

| Variant | HTTP | Code |
| --- | --- | --- |
| `InvalidCredentials` | 401 | `INVALID_CREDENTIALS` |
| `Unauthorized` (missing, expired, or revoked token) | 401 | `UNAUTHORIZED` |
| `Forbidden` | 403 | `FORBIDDEN` |
| `Validation { field, message }` | 400 | `VALIDATION_ERROR` |
| `NotFound` | 404 | `ENTITY_NOT_FOUND` |
| `UsernameTaken` | 409 | `USERNAME_TAKEN` |
| `SetupRequired`, `RegistrationClosed` | 403 | same names, upper snake case |
| `LastAdministrator` | 422 | `LAST_ADMINISTRATOR` |
| `RateLimited { retry_after_secs }` | 429 + `Retry-After` | `RATE_LIMITED` |
| `AccountLocked { retry_after_secs }` | 429 + `Retry-After` | `ACCOUNT_LOCKED` |
| `Internal { key, source }` | 500 | `INTERNAL_ERROR` |

Applications that have their own error type map `AuthError` with a `From` impl in their adapter layer.

## Storage (`rustauth-postgres`)

All tables live in the Postgres schema `auth`. The library's migrations are embedded in the crate and tracked in `auth._sqlx_migrations` (`Migrator::dangerous_set_table_name` plus `create_schema("auth")`), so they never collide with the application's own `_sqlx_migrations`. Applications call `rustauth_postgres::migrate(&pool)` before their own migrations and may reference `auth.users (id)` from their tables.

The library takes a `PgPool`. It can be the application's pool (same database, separate schema, foreign keys possible) or a pool to another database (no cross-database foreign keys).

Column order follows the template's `postgres-column-alignment` rule. Constraints use `text` plus `CHECK` rather than enum types, so adding values later is a plain migration.

The repositories (`SqlxUserRepository`, `SqlxSessionRepository`) use runtime-checked queries, never the `query!` macros, so building needs no database. `register`, `update`, and `delete` run in one transaction that first takes `pg_advisory_xact_lock` on a fixed key (the ASCII bytes of `rustauth`) and then locks the row, so the first-administrator decision and the last-administrator guard are serialized across connections and processes. `record_failure`, `lock`, and `unlock` are single statements. Driver errors become `AuthError::Internal` with `rustauth.<table>.<operation>.failed` keys; a violation of the `lower(username)` unique index becomes `UsernameTaken`. Client IPs are bound as text and cast to `inet` (read back with `host(ip)`), so the crate needs no sqlx `ipnet` feature.

### `auth.users`

| Column | Type | Notes |
| --- | --- | --- |
| `created_at` | `timestamptz` | not null |
| `updated_at` | `timestamptz` | not null |
| `disabled_at` | `timestamptz` | null; set means the account cannot sign in |
| `last_failed_login_at` | `timestamptz` | null |
| `locked_until` | `timestamptz` | null; set and in the future means login is refused |
| `failed_login_count` | `integer` | not null, default 0 |
| `lockout_count` | `integer` | not null, default 0 |
| `id` | `uuid` | primary key |
| `username` | `text` | not null; unique index on `lower(username)` |
| `display_name` | `text` | not null |
| `role` | `text` | not null, `CHECK (role IN ('administrator','manager','user'))` |

### `auth.password_credentials`

| Column | Type | Notes |
| --- | --- | --- |
| `changed_at` | `timestamptz` | not null |
| `user_id` | `uuid` | primary key, references `auth.users` on delete cascade |
| `hash` | `text` | not null; Argon2id PHC string |

A separate table so that SSO-only users later need no password row.

### `auth.sessions`

| Column | Type | Notes |
| --- | --- | --- |
| `created_at` | `timestamptz` | not null |
| `last_used_at` | `timestamptz` | not null; written at most once per hour |
| `expires_at` | `timestamptz` | not null; index for purging |
| `id` | `uuid` | primary key |
| `user_id` | `uuid` | not null, references `auth.users` on delete cascade; index |
| `token_hash` | `bytea` | not null, unique |
| `assurance` | `text` | not null, `CHECK (assurance IN ('aal1','aal2'))` |
| `ip` | `inet` | null |
| `user_agent` | `text` | not null, default `''` |
| `methods` | `text[]` | not null; for example `{password}` |

## HTTP (`rustauth-axum`)

### Integration Shape

```rust
rustauth::migrate(&pool).await?;        // in the migrate step, before the application's migrations

let auth = RustAuth::builder()
    .pool(pool.clone())
    .config(AuthConfig::parse(&env)?)   // or build AuthConfig by hand
    .build()                            // checks the schema, wires crypto + postgres into core services
    .await?;                            // async: the service counts accounts and prepares its dummy hash

let (router, openapi) = OpenApiRouter::<AppState>::new()
    .nest("/api", auth.router()         // public + self-protected auth routes, OpenAPI documented
        .merge(app_routes.layer(auth.guard())))   // guard: 401 unless a valid bearer token
    .split_for_parts();
let app = router.with_state(app_state);
axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await?;

async fn handler(user: AuthUser) -> ... { user.require(Role::Administrator)?; ... }
```

- `auth.router::<S>()` returns a `utoipa_axum::router::OpenApiRouter<S>` for any application state `S`: the routes run on their own state (applied with `with_state`), so applications merge them into their own router and OpenAPI document without adding the auth services to their state. Schemas are named `rustauth.*` and operation ids `rustauth_*`, so they cannot collide with the application's; the signed-in routes use the `bearerAuth` security scheme.
- `auth.guard()` is a `tower` layer: it reads `Authorization: Bearer`, calls `AuthService::verify`, and inserts `AuthUser` (wrapping `Principal`) into request extensions; otherwise it answers `401` with the error body. `auth.guard().require(Role::Manager)` answers `403` below a role; `auth.guard().optional()` also admits anonymous requests and stale tokens (but not storage failures). A request an outer guard verified is not verified again.
- `AuthUser` and `OptionalAuthUser` are extractors; `AuthUser::require(role)` checks a role in a handler. Used on a route without a guard in front, they answer `500` and log `rustauth.guard.missing`. (`RequireRole<const R>` would need const generics over an enum, which stable Rust lacks; the guard's `require` covers it.)
- Client IP: the peer address from `ConnectInfo<SocketAddr>` (so the server must run with `into_make_service_with_connect_info`; without it per-IP limits are off and `rustauth.client.peer-unknown` is logged once). When the peer is in `trusted_proxies`, the `X-Forwarded-For` hops are read from the right (nearest proxy first) while they are trusted proxies too; the first untrusted hop is the client, or the left-most hop when all are trusted. Hops left of the first untrusted one are ignored, because the client could have written them.

### Routes

Relative to where the application mounts the router (for example `/api`):

| Route | Auth | Purpose |
| --- | --- | --- |
| `GET /auth/setup` | public | `{ needsSetup, registrationOpen }` for first-run screens |
| `POST /auth/register` | public | `username`, `password`, `displayName`, `setupToken` (while no user exists); returns token, expiry, and user |
| `POST /auth/login` | public | `username`, `password`; returns token, expiry, and user |
| `POST /auth/logout` | user | revokes the current session; `204` |
| `GET /auth/me` | user | current user |
| `PATCH /auth/me` | user | `displayName` |
| `POST /auth/password` | user | `current`, `new`; revokes other sessions |
| `GET /auth/sessions` | user | own sessions (current one flagged) |
| `DELETE /auth/sessions/{id}` | user | revoke one; `204` |
| `POST /auth/sessions/revoke-others` | user | `204` |
| `GET /admin/users` | administrator | paginated list |
| `POST /admin/users` | administrator | `username`, `displayName`, `temporaryPassword`, `role` |
| `GET /admin/users/{id}` | administrator | one account |
| `PATCH /admin/users/{id}` | administrator | `displayName`, `role`, `disabled`, `password` (a reset also unlocks) |
| `POST /admin/users/{id}/unlock` | administrator | clears the lockout; `204` |
| `DELETE /admin/users/{id}` | administrator | `204` |

Bodies use the same envelopes as the RustInit template so applications parse one shape: `{ "data": ... }` for single results (`201` for register and admin create), `{ "items": [...], "total": n }` for lists, an empty `204` for revocations, unlock, and delete. Error bodies: `{ "error": "<message>", "code": "<CODE>", "field": "<name>", "details": {...}, "requestId": "<id>" }`, where `field` names the invalid input on `400`, `details.retryAfterSecs` repeats `Retry-After` on `429` (browsers cannot read that header across origins unless it is exposed), `details.entityName` names what was not found on `404`, and `401` responses carry `WWW-Authenticate: Bearer`. `requestId` comes from the `X-Request-Id` request header when present. Malformed JSON answers `400 VALIDATION_ERROR` (field `body`), an oversized body `413 PAYLOAD_TOO_LARGE`, and a missing JSON content type `415 UNSUPPORTED_MEDIA_TYPE`.

### Configuration

`AuthConfig::parse(env)` reads these variables (applications may also build the struct directly):

| Variable | Default | Purpose |
| --- | --- | --- |
| `AUTH_REGISTRATION_OPEN` | `false` | Allow sign-ups after the first (administrator) account |
| `AUTH_SETUP_TOKEN` | random, logged once at startup | Token required for the first registration |
| `AUTH_SESSION_TTL_DAYS` | `30` | Sliding session lifetime |
| `AUTH_SESSION_MAX_DAYS` | `90` | Absolute session lifetime |
| `AUTH_TRUSTED_PROXIES` | empty | Comma-separated IPs or CIDRs whose `X-Forwarded-For` is trusted |
| `AUTH_LOCKOUT_THRESHOLD` | `5` | Wrong passwords in a row before the account locks |
| `AUTH_LOCKOUT_MINUTES` | `15` | First lockout length (doubles each time) |
| `AUTH_LOCKOUT_MAX_MINUTES` | `1440` | Longest lockout |
| `AUTH_IP_FAILURE_LIMIT` | `30` | Failed logins per client IP per 15 minutes |
| `AUTH_RATE_LIMIT_PER_MINUTE` | `60` | Requests per client IP per minute to the public auth routes |

Validation: numbers are whole and at least 1; session lifetimes are at most 3650 days and lockout lengths at most one year; `AUTH_SESSION_MAX_DAYS` must be at least `AUTH_SESSION_TTL_DAYS` and `AUTH_LOCKOUT_MAX_MINUTES` at least `AUTH_LOCKOUT_MINUTES`; `AUTH_SETUP_TOKEN` needs 16 or more characters without whitespace; `AUTH_REGISTRATION_OPEN` is `true` or `false`; blank values count as unset. One `ConfigError` (`rustauth.config.invalid AUTH_...`) names every invalid variable. Two settings exist only on the builder: `failure_window` (15 minutes, the account and per-IP failure window) and `touch_interval` (1 hour). Per-IP limits group IPv6 clients by /64 prefix.

## Contracts

`rustauth-contracts` holds the request and response DTOs (camelCase JSON, RFC 3339 timestamps, UUID ids) with `utoipa::ToSchema`, the template's `DetailsResponse<T>` and `ListResponse<T>` envelopes, and `ErrorResponse`. OpenAPI schema names carry a `rustauth.` prefix. Types that hold a password or token print `***` in `Debug`. Under the `ts` feature they derive `ts_rs::TS` so applications can export them into their own generated TypeScript; the facade re-exports them as `rustauth::contracts::*`. The repository also ships `packages/contracts` (`@rustauth/contracts`): the generated types plus Zod schemas that `satisfies` them, the envelope helpers, route paths, and error codes, for web apps that install it from git.

## Security Notes

- Argon2id with the `argon2` 0.6 defaults (m = 19 MiB, t = 2, p = 1), run in `spawn_blocking` behind a semaphore (4 permits by default).
- Tokens: 256 bits from the OS RNG; only the SHA-256 is stored; lookups are by hash.
- Every admin change to a user and every password change revokes that user's sessions (password change keeps the current session).
- Logs use dotted keys (`rustauth.login.failed`, `rustauth.setup.token-issued`) and never include passwords, tokens, or hashes.
- No `unsafe`; Clippy denies `print_*` and `dbg!`.

## Testing

- Core: unit tests with in-memory fakes (behind a `testing` feature) for every service rule: setup token, first-admin, closed registration, throttling windows, sliding and absolute expiry, disabled users, last-administrator guard, session revocation on changes.
- Postgres: `#[sqlx::test]` tests (ignored unless Postgres is available, `make test-db`) for the repositories, including two concurrent first registrations where exactly one becomes administrator.
- Axum: route tests with `tower::ServiceExt::oneshot` against an in-memory service stack, and end-to-end tests against Postgres through the facade.
- Applications: the facade's `testing` feature re-exports the in-memory fakes, so `RustAuth::builder().ports(Fakes::new().ports())` builds the real router and guard without a database.
- CI: a slim lint job (`ubuntu-slim`) and a Rust plus Postgres job (`ubuntu-latest`).

## Upgrades and Compatibility

The library is developed and released on its own schedule. New features (for example passkeys) will add tables and columns while applications keep running older and newer versions. These rules make upgrades routine.

### Versions and Releases

- Semantic version tags `vMAJOR.MINOR.PATCH`. Before 1.0, a minor bump may break; every break is listed in `CHANGELOG.md` under "Upgrade notes" with the exact steps.
- Applications pin a tag: `rustauth = { git = "https://github.com/host39/lib-rustauth", tag = "v0.1.0" }` (a `rev` is fine before the first tag). The npm package `@rustauth/contracts` carries the same version.
- The facade crate `rustauth` is the only supported Rust surface. The inner crates may change in any release.

### Schema Ownership

- The library owns the whole `auth` schema. Applications never write to `auth` tables and never read them directly; they use the library's services and HTTP routes.
- The one stable database contract is `auth.users (id uuid primary key)`, so application tables can declare `REFERENCES auth.users (id) ON DELETE CASCADE`. No release renames, retypes, or drops it.

### Migrations

- Embedded in the crate and tracked in `auth._sqlx_migrations`, separate from the application's own history. Applications call `rustauth::migrate(&pool)` first, then their own migrations, in their single migrate step. Upgrading the library and running that step applies the new auth migrations automatically.
- Append-only once released: a released migration file never changes (sqlx checksums it).
- Expand, then contract. A change that would break the previous release (rename, drop, new NOT NULL column without a default) ships in two releases: first add the new shape and keep the old one working, then remove the old shape in a later release. So a rolling deploy, where the old app version still runs against the new schema for a few minutes, keeps working. The changelog says when a release must not be skipped.
- **Schema check at startup.** `RustAuth::build()` compares the applied `auth` migrations with the embedded ones (`rustauth::schema_status`). Pending migrations: build fails with "Auth schema is out of date: run migrations". Applied migrations the library does not know (the database is newer than the code, for example after a rollback): build fails with "Auth schema is newer than this version of rustauth" unless the application opts in with `allow_newer_schema(true)`, which is safe only across expand-only releases. An applied migration whose checksum differs from the embedded file always fails the build.

### Rust API

- Public enums that may grow (`AuthError`, `Role`, `AuthMethod`, `Assurance`) are `#[non_exhaustive]`; applications keep a wildcard arm.
- Configuration and inputs use builders or constructors, never public struct literals, so new options are additive.
- Removals go through `#[deprecated]` for at least one minor release.
- Dependency ranges (`axum`, `sqlx`, `utoipa`) match the RustInit template; bumping a major of one of them is called out in the changelog.

### HTTP API and Contracts

- Within a major version, routes and fields are only added. New response fields are additive; new request fields are optional.
- Error codes are stable strings; new codes may appear, so clients handle unknown codes generically.

### Consumer Checklist (Applications)

1. Keep all rustauth usage in one adapter module of the application, which maps `AuthError` into the application's error type and `AuthUser` into the application's own actor type. An upgrade then touches one module.
2. Run `rustauth::migrate` before the application's migrations in the same migrate step and in CI.
3. Upgrade by bumping the tag, reading the changelog's upgrade notes, running the migrate step, and running the full test suite (CI does this on the upgrade branch).

### Upgrade Testing

- The library's CI has an upgrade job: it applies the migrations of the previous release tag, inserts sample data, upgrades to the current code, runs `migrate` again, and runs the Postgres test suite. (Active from the first tag on.)
- A compatibility test keeps the documented integration example compiling against the facade.
