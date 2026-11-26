# Integration Guide

How an axum + sqlx + Postgres application adopts RustAuth, step by step: the Rust dependency, the migrate step, the router and guard, error mapping, the database contract, configuration, tests, and the web client. The design behind each step is in [design/rustauth.md](./design/rustauth.md).

Two rules make upgrades cheap:

- Use the `rustauth` facade crate only. The inner crates (`rustauth-core`, `rustauth-axum`, and so on) may change in any release.
- Keep all rustauth usage in one adapter module of the application. It maps `AuthError` into the application's error type and `AuthUser` into the application's own actor type, so an upgrade touches one module.

## 1. Add the Rust Dependency

Pin a commit with `rev` until the first release tag exists, then a tag. Cargo records the exact commit in `Cargo.lock` either way.

```toml
# Cargo.toml (workspace root)
[workspace.dependencies]
rustauth = { git = "https://github.com/host39/lib-rustauth", rev = "<commit>", default-features = false }
# After the first release: tag = "v0.1.0" instead of rev.

# Same versions as rustauth, so Cargo builds one copy of each.
axum = "0.8.9"
sqlx = { version = "0.9.1", default-features = false }
utoipa = "6.0.0"
utoipa-axum = "0.3.0"
```

Each member enables only the features it needs:

| Feature | Gives | Typical member |
| --- | --- | --- |
| `axum` | `RustAuth::router`, `guard`, `AuthUser`, `OptionalAuthUser`, `HttpError`, `request_scope` (turns on `contracts`) | HTTP crate |
| `postgres` | `RustAuth::builder().pool`, the startup schema check (turns on `migrate` and `crypto`) | HTTP crate |
| `migrate` | `migrate`, `schema_status`; Postgres and sqlx only, no HTTP, OpenAPI, or hashing crates | the crate that runs migrations |
| `contracts` | `rustauth::contracts::*`, the request and response DTOs | contracts crate |
| `crypto` | `rustauth::ports::{Argon2Hasher, RandomTokens}`, to combine with custom storage | crate with custom storage |
| `testing` | `rustauth::testing::Fakes`, in-memory ports for tests without Postgres | `[dev-dependencies]` |
| `ts` | `ts_rs::TS` on `rustauth::contracts::*`, for applications whose own ts-rs types embed them (turns on `contracts`) | contracts crate |

```toml
# apps/api/Cargo.toml
rustauth = { workspace = true, features = ["axum", "postgres"] }

[dev-dependencies]
rustauth = { workspace = true, features = ["axum", "postgres", "testing"] }

# packages/database/Cargo.toml: the crate with the migrate step stays free of HTTP crates.
rustauth = { workspace = true, features = ["migrate"] }
```

Depend on the facade with the `migrate` feature there, not on `rustauth-postgres`: the inner crates may change in any release. Dependency rules of the application (for example a boundaries check that keeps the database crate free of HTTP crates) should allow `rustauth` in that crate.

The library turns on no sqlx TLS backend: the application builds the `PgPool` and picks one, for example `features = ["postgres", "runtime-tokio", "tls-rustls-ring-webpki"]` on its own `sqlx` line. `cargo tree -d` should list no second copy of `axum`, `sqlx`, or `utoipa`; if it does, align the application's versions with the library's `Cargo.toml`.

## 2. Run the Auth Migrations First

The library owns the Postgres schema `auth` and tracks its migrations in `auth._sqlx_migrations`, apart from the application's `_sqlx_migrations`. The application's migrate step runs them first, because the application's tables reference `auth.users`:

```rust
/// The migrate step: the `auth` schema first, then the application's own migrations.
async fn migrate(pool: &PgPool) -> Result<(), Box<dyn std::error::Error>> {
    rustauth::migrate(pool).await?;
    sqlx::migrate!().run(pool).await?;
    Ok(())
}
```

- `rustauth::migrate` is safe on every start and from several processes at once: applied migrations are skipped, and a Postgres advisory lock serializes the runs. Auth migrations from a newer release (after a rollback, or while an older instance restarts during a rolling deploy) are left alone; `build()` decides whether to start against them (below).
- `sqlx migrate run` (sqlx-cli) only knows the application's migrations. Use a migrate binary or startup code like the function above, also in deploy scripts and containers.
- Database tests use the same order. With `#[sqlx::test]`, turn off the automatic migrations and call the function:

```rust
#[sqlx::test(migrations = false)]
#[ignore = "requires Postgres"]
async fn widgets_follow_their_owner(pool: PgPool) {
    crate::migrate(&pool).await.expect("migrated");
    // ...
}
```

- `RustAuth::build()` checks the schema at startup. Pending auth migrations fail it with "Auth schema is out of date: run migrations". Auth migrations the library does not know (the database is newer, for example after rolling the application back) fail it with "Auth schema is newer than this version of rustauth" unless the builder has `allow_newer_schema(true)`, which is safe only across releases whose changelog says they only added to the schema.
- The pool can be the application's own (same database, separate schema, foreign keys possible) or a pool to another database (no foreign keys across databases).

## 3. Reference `auth.users` From Your Tables

`auth.users (id uuid primary key)` is the one stable database contract: no release renames, retypes, or drops it. Application tables reference it, with column order following the alignment rule (8-byte, 4-byte, `uuid`, `boolean`, variable length):

```sql
CREATE TABLE widgets (
  created_at timestamptz NOT NULL,
  id         uuid        PRIMARY KEY,
  owner_id   uuid        NOT NULL REFERENCES auth.users (id) ON DELETE CASCADE,
  name       text        NOT NULL
);

CREATE INDEX widgets_owner_id_idx ON widgets (owner_id);
```

- `ON DELETE CASCADE` removes the application's rows when an administrator deletes the account; use `ON DELETE SET NULL` on a nullable column for rows that outlive their author.
- Application data about a person (profile fields, settings, per-application permissions) lives in the application's tables keyed by the user id, for example `user_settings (user_id uuid PRIMARY KEY REFERENCES auth.users (id) ON DELETE CASCADE, ...)`.
- Never write to `auth` tables and never read them directly: they can change in any release, and they hold password and token hashes. Use the services (`auth.service()`, `auth.admin()`) and the HTTP routes. If the application needs account data that the library does not offer, add it to the library as a general capability.
- Do not grant read-only reporting roles access to the `auth` schema.

## 4. Configure

`AuthConfig::parse(&env)` reads these variables from a `HashMap` of the environment; blank values count as unset. One `ConfigError` (`rustauth.config.invalid AUTH_...`) names every invalid variable, so startup fails with the whole list.

| Variable | Default | Purpose |
| --- | --- | --- |
| `AUTH_REGISTRATION_OPEN` | `false` | Allow sign-ups after the first (administrator) account |
| `AUTH_SETUP_TOKEN` | random, logged once at startup | Token required for the first registration (16 or more characters, no whitespace) |
| `AUTH_SESSION_TTL_DAYS` | `30` | Sliding session lifetime |
| `AUTH_SESSION_MAX_DAYS` | `90` | Absolute session lifetime (at least the TTL) |
| `AUTH_TRUSTED_PROXIES` | empty | Comma-separated IPs or CIDRs whose `X-Forwarded-For` is trusted |
| `AUTH_LOCKOUT_THRESHOLD` | `5` | Wrong passwords in a row before the account locks |
| `AUTH_LOCKOUT_MINUTES` | `15` | First lockout length (doubles each time) |
| `AUTH_LOCKOUT_MAX_MINUTES` | `1440` | Longest lockout (at least the first) |
| `AUTH_IP_FAILURE_LIMIT` | `30` | Failed logins per client IP per 15 minutes |
| `AUTH_RATE_LIMIT_PER_MINUTE` | `60` | Requests per client IP per minute to the public auth routes |

- While no account exists and `AUTH_SETUP_TOKEN` is unset, `build()` generates a token and logs it once (`rustauth.setup.token-issued`); the operator copies it into the first registration. Set `AUTH_SETUP_TOKEN` when several instances run, since each would generate its own.
- Behind a reverse proxy, list the proxy in `AUTH_TRUSTED_PROXIES`, or every client shares the proxy's address in the per-IP limits.
- Applications that keep configuration elsewhere build it with `AuthConfig::builder()` (for example `.registration_open(true).setup_token(token).build()?`). Two settings exist only there: `failure_window` (15 minutes) and `touch_interval` (1 hour).
- Document the `AUTH_*` variables with the application's own environment variables.

## 5. Build and Mount

```rust
use rustauth::{AuthConfig, Role, RustAuth};
use utoipa::OpenApi;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

let env: HashMap<String, String> = std::env::vars().collect();
let auth = RustAuth::builder()
    .pool(pool.clone())
    .config(AuthConfig::parse(&env)?)
    .build() // checks the `auth` schema, wires the crypto and Postgres adapters
    .await?;

let signed_in = OpenApiRouter::new()
    .routes(routes!(list_widgets))
    .layer(auth.guard()); // 401 unless a valid bearer token
let managers = OpenApiRouter::new()
    .routes(routes!(delete_widget))
    .layer(auth.guard().require(Role::Manager)); // and 403 below manager
let (router, openapi) = OpenApiRouter::with_openapi(ApiDoc::openapi())
    .nest("/api", auth.router().merge(signed_in).merge(managers))
    .split_for_parts();
let app = router.with_state(AppState { pool });

// The peer address feeds the per-IP limits and AUTH_TRUSTED_PROXIES.
axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await?;
```

- `auth.router::<S>()` works with any application state `S`: the auth routes carry their own state. Their schemas are named `rustauth.*`, their operation ids `rustauth_*`, and their tags `rustauth.auth` and `rustauth.admin` (`rustauth::AUTH_TAG`, `rustauth::ADMIN_TAG`), so they join the application's OpenAPI document without collisions. The signed-in routes use the `bearerAuth` security scheme (`rustauth::SECURITY_SCHEME`); list it on the application's guarded routes too: `security(("bearerAuth" = []))`.
- `auth.guard()` loads the session and user on every request, so a disabled account or a revoked session loses access at once. `auth.guard().optional()` also lets anonymous requests through, for routes that read the caller with `OptionalAuthUser`.
- Without `into_make_service_with_connect_info`, per-IP limits are off and `rustauth.client.peer-unknown` is logged once.
- Error bodies echo the `X-Request-Id` request header as `requestId`, and `rustauth.http.*` logs carry it as `request_id`. An application middleware that generates ids for requests without one must write the id into that request header (not only into a request extension or its own task-local) and run outside the auth router and the guard, for example as the outermost layer.
- A web app on another origin needs CORS that allows the `Authorization` and `Content-Type` request headers. Bodies of `429` responses repeat `Retry-After` as `details.retryAfterSecs`, so the header need not be exposed.
- Delete expired sessions, and the sign-in failure records of usernames without an account that no longer count, now and then with `auth.service().purge()`:

```rust
fn purge_hourly(auth: &RustAuth) {
    let service = auth.service().clone();
    tokio::spawn(async move {
        let mut hourly = tokio::time::interval(Duration::from_secs(60 * 60));
        loop {
            hourly.tick().await;
            if let Err(error) = service.purge().await {
                tracing::warn!(error = %error, "my-app.sessions.purge-failed");
            }
        }
    });
}
```

## 6. Map `AuthError` Into Your Error Type

Services and `AuthUser::require` fail with `AuthError`. It is `#[non_exhaustive]`: match with a wildcard arm and fall back on `error.code()`.

The simplest mapping wraps `HttpError`, which answers like the auth routes (status, error body, `Retry-After`, `WWW-Authenticate: Bearer`, and the `rustauth.http.*` log line). Its body echoes the request id as `requestId` in handlers behind `auth.guard()`; for application routes without a guard, add `.layer(axum::middleware::from_fn(rustauth::request_scope))` (see the request id note in step 5):

```rust
//! The application's rustauth adapter module.

use axum::extract::FromRequestParts;
use axum::http::StatusCode;
use axum::http::request::Parts;
use axum::response::{IntoResponse, Response};
use rustauth::{AuthError, AuthUser, HttpError, Role};
use uuid::Uuid;

pub enum AppError {
    /// A rustauth failure, answered exactly like the auth routes answer it.
    Auth(HttpError),
    Database(sqlx::Error),
}

impl From<AuthError> for AppError {
    fn from(error: AuthError) -> Self {
        Self::Auth(HttpError::from(error))
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        match self {
            Self::Auth(error) => error.into_response(),
            Self::Database(error) => {
                tracing::error!(error = %error, "my-app.database.failed");
                StatusCode::INTERNAL_SERVER_ERROR.into_response()
            }
        }
    }
}
```

An application with its own error body takes the status and body from `HttpError` and adds the headers itself. The body is already the shared envelope (`error`, `code`, `field`, `details`, `requestId`), and internal errors carry only a generic message, so log their key and source:

```rust
use std::error::Error as _;

use rustauth::contracts::ErrorResponse;

impl From<AuthError> for ApiError {
    fn from(error: AuthError) -> Self {
        let retry_after = error.retry_after_secs(); // send as `Retry-After` on 429
        let http = HttpError::from(error);
        let status = http.status(); // 401 also needs `WWW-Authenticate: Bearer`
        if let Some(error) = http.error().filter(|_| status.is_server_error()) {
            tracing::error!(error = %error, source = ?error.source(), "my-app.auth.failed");
        }
        Self { status, body: http.body(), retry_after }
    }
}
```

## 7. Read the Caller in Handlers

`AuthUser` derefs to `Principal`: `user_id` (`UserId`, `.as_uuid()` for the raw `Uuid`), `username`, `role`, `session_id`, and `assurance`. It is rebuilt from the database on every request. `user.require(Role::Manager)?` answers `403` below a role.

The adapter module turns it into the application's own actor type, so handlers and services never name rustauth types:

```rust
/// The application's own view of the caller.
pub struct Actor {
    pub user_id: Uuid,
    pub role: Role,
}

impl From<&AuthUser> for Actor {
    fn from(user: &AuthUser) -> Self {
        Self { user_id: user.user_id.as_uuid(), role: user.role }
    }
}

/// Extractor for handlers: the signed-in caller as an `Actor`. Needs `auth.guard()` in front.
pub struct Caller(pub Actor);

impl<S: Send + Sync> FromRequestParts<S> for Caller {
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let user = AuthUser::from_request_parts(parts, state).await.map_err(AppError::Auth)?;
        Ok(Self(Actor::from(&user)))
    }
}
```

`AuthUser`, `OptionalAuthUser`, and therefore `Caller` answer `500` and log `rustauth.guard.missing` on a route without a guard in front, so a wiring mistake shows at once instead of exposing the route.

## 8. Test the Application

The `testing` feature builds the real router and guard on in-memory fakes, so route tests need no database:

```rust
use rustauth::testing::Fakes;

let config = AuthConfig::builder().setup_token("a-long-enough-setup-token").build()?;
let auth = RustAuth::builder().ports(Fakes::new().ports()).config(config).build().await?;
// Register the first account through POST /api/auth/register with that setup token, then send
// its token as `Authorization: Bearer <token>` to the guarded routes.
```

Handler tests that skip the guard insert a caller directly: `request.extensions_mut().insert(AuthUser::new(Principal::new(user_id, username, Role::Manager, session_id)))`. `Principal` and `Ports` are built with their constructors (`Principal::new`, `Ports::new`), never struct literals, so fields added later do not break the application.

The fakes hash and issue tokens insecurely on purpose: never use them outside tests. Tests that touch the application's tables use `#[sqlx::test(migrations = false)]` and the migrate function from step 2, then build `RustAuth` on the test pool.

## 9. Use the Web Client Package

`@rustauth/contracts` holds the TypeScript types generated from the Rust DTOs, Zod schemas that `satisfies` them, route paths, error codes, and small helpers. Install it from the same commit or tag as the Rust crate:

```sh
pnpm add "@rustauth/contracts@github:host39/lib-rustauth#<commit-or-tag>&path:packages/contracts"
```

```json
"dependencies": {
  "@rustauth/contracts": "github:host39/lib-rustauth#<commit-or-tag>&path:packages/contracts",
  "zod": "^4.6.7"
}
```

`zod` 4 is a peer dependency, so the schemas use the application's copy.

### Compile the Sources

The package ships TypeScript sources, not JavaScript, so the application compiles them:

- `tsconfig.json` needs `"moduleResolution": "bundler"` (the package uses `exports` and `#generated/*` subpath imports). `strict`, `verbatimModuleSyntax`, `noUnusedLocals`, `noUnusedParameters`, `noUncheckedIndexedAccess`, and `noPropertyAccessFromIndexSignature` are fine; `exactOptionalPropertyTypes` is not supported.
- Rsbuild compiles TypeScript under `node_modules` by default (checked with Rsbuild 2.3). If the application's `source.exclude` covers it, or with another bundler, include the package explicitly:

```ts
// rsbuild.config.ts
import { defineConfig } from "@rsbuild/core";

export default defineConfig({
  source: {
    include: [/[\\/]node_modules[\\/]@rustauth[\\/]contracts[\\/]/],
  },
});
```

- Node cannot run the package from `node_modules` directly (it does not strip types there); scripts that need it go through the bundler.

An application with its own contracts package can re-export the auth types and schemas from it, so its web code imports one package.

### Call the Routes

The routes are relative to where the application mounts the auth router, `/api` in these examples. A small client parses every success body with the matching schema and turns failures into an error that carries the server's body:

```ts
import { type ErrorResponse, errorResponseSchema } from "@rustauth/contracts";
import type { z } from "zod";

const API = "/api";

export class ApiError extends Error {
  readonly status: number;
  readonly body: ErrorResponse;

  constructor(status: number, body: ErrorResponse) {
    super(body.error);
    this.status = status;
    this.body = body;
  }
}

type Options = { method?: string; body?: unknown; token?: string | null };

/** Sends a request and parses the success body with `schema`; throws `ApiError` otherwise. */
export async function apiFetch<T extends z.ZodType>(
  schema: T,
  path: string,
  { method = "GET", body, token }: Options = {}
): Promise<z.output<T>> {
  const headers = new Headers();
  if (body !== undefined) headers.set("content-type", "application/json");
  if (token) headers.set("authorization", `Bearer ${token}`);
  const response = await fetch(`${API}${path}`, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const json: unknown =
    response.status === 204 ? undefined : await response.json().catch(() => undefined);
  if (!response.ok) {
    const error = errorResponseSchema.safeParse(json);
    throw new ApiError(response.status, error.success ? error.data : { error: response.statusText });
  }
  return schema.parse(json);
}
```

```ts
import {
  authRoutes,
  hasRole,
  type LoginRequest,
  retryAfterSecs,
  sessionListBodySchema,
  setupStatusBodySchema,
  signInBodySchema,
  type UserResponse,
} from "@rustauth/contracts";
import { z } from "zod";

let token: string | null = null;

export async function needsSetup(): Promise<boolean> {
  const { data } = await apiFetch(setupStatusBodySchema, authRoutes.setup);
  return data.needsSetup;
}

export async function signIn(credentials: LoginRequest): Promise<UserResponse> {
  const { data } = await apiFetch(signInBodySchema, authRoutes.login, {
    method: "POST",
    body: credentials,
  });
  token = data.token;
  return data.user;
}

export async function signOut(): Promise<void> {
  await apiFetch(z.undefined(), authRoutes.logout, { method: "POST", token }); // 204
  token = null;
}

export async function devices() {
  return (await apiFetch(sessionListBodySchema, authRoutes.sessions, { token })).items;
}

export function canManageUsers(user: UserResponse): boolean {
  return hasRole(user.role, "administrator"); // UI only: the server checks every request
}

/** What a form shows for a failure. */
export function describe(error: unknown): { message: string; field?: string; wait?: number } {
  if (!(error instanceof ApiError)) return { message: "The server cannot be reached." };
  if (error.status === 401 && error.body.code === "UNAUTHORIZED") token = null; // sign in again
  return { message: error.body.error, field: error.body.field, wait: retryAfterSecs(error.body) };
}
```

### Screens and Errors

- **First run.** `GET /auth/setup` answers `needsSetup`. While it is true, show a registration form with a setup token field; the first account becomes the administrator. Afterwards, `registrationOpen` says whether to offer sign-up at all.
- **Forms.** The request schemas (`registerRequestSchema`, `changePasswordRequestSchema`, `createUserRequestSchema`, and the others) repeat the server's rules and messages, so forms can validate before sending. The server stays the authority: a `400 VALIDATION_ERROR` names the failing request field in `field` (the same camelCase names, `current` and `new` for a password change, `body` for malformed JSON).
- **Messages.** Every error body has a human-readable `error` that can be shown as is, for example "Too many failed sign-in attempts. Try again in 15 minutes." Branch on `code` (`AUTH_ERROR_CODES`), never on the message, and handle unknown codes like a generic failure.
- **Waiting.** On `429` (`RATE_LIMITED` or `ACCOUNT_LOCKED`), `retryAfterSecs(body)` says how long to keep the submit button disabled.
- **Signed out.** A `401` with `UNAUTHORIZED` on any route means the session expired or was revoked: clear the token and show the sign-in screen. A wrong password answers `INVALID_CREDENTIALS` instead.
- **Devices.** `GET /auth/sessions` lists the caller's sessions with the current one flagged; `DELETE /auth/sessions/{id}` and `POST /auth/sessions/revoke-others` revoke them.
- **Roles.** Responses parse an unknown role from a newer server as `user`, and drop unknown fields, so an older web build keeps working after a server upgrade within the same major version.
- **Request ids.** Sending `X-Request-Id` (`REQUEST_ID_HEADER`) makes error bodies echo it as `requestId`, for support and log correlation.

### Storing the Token

The token is a bearer credential: whoever holds it acts as the user until it expires (sliding 30 days, at most 90 by default) or is revoked. Keeping it in memory loses it on reload; `sessionStorage` keeps it per tab; `localStorage` keeps it across restarts. Any script running on the page can read the two storages, so pair them with a strict Content Security Policy and no untrusted scripts. Signing out calls `POST /auth/logout`, which revokes the session on the server, not only in the browser.

## 10. Upgrade

1. Bump the `rev` or `tag` of `rustauth` in `Cargo.toml` and of `@rustauth/contracts` in `package.json` together, in one commit.
2. Read the upgrade notes in the changelog (from the first release on); before `1.0`, a minor release may break and lists the exact steps.
3. Run the migrate step: new auth migrations apply automatically. Breaking schema changes ship as expand, then contract, across two releases, so a rolling deploy keeps working; the changelog says when a release must not be skipped.
4. Run the full test suite, including the database tests.

## Checklist

- [ ] `rustauth` from git, pinned by `rev` or `tag`, with only the needed features; one copy of `axum`, `sqlx`, and `utoipa` in `cargo tree -d`.
- [ ] Migrate step runs `rustauth::migrate` before the application's migrations, in deployments and in database tests.
- [ ] Application tables reference `auth.users (id)` and never read or write other `auth` tables.
- [ ] `AUTH_*` variables documented; `AUTH_SETUP_TOKEN` set when several instances run; proxies listed in `AUTH_TRUSTED_PROXIES`.
- [ ] `auth.router()` merged into the API router and its OpenAPI document; `auth.guard()` in front of every other protected route; served with `into_make_service_with_connect_info`.
- [ ] One adapter module maps `AuthError` and `AuthUser` into the application's own types.
- [ ] Expired sessions and stale failure records purged periodically (`auth.service().purge()`).
- [ ] Web app installs `@rustauth/contracts` at the same ref, compiles its sources, and parses responses with its schemas.
