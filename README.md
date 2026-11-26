# RustAuth

Reusable authentication and authorization for Rust applications built on axum, sqlx, and Postgres. An application adds the `rustauth` crate, runs its migrations, mounts its router, and puts its guard in front of protected routes. Every application becomes a client of this library, so security fixes and new sign-in methods land once.

## Status

**v0.1 in progress.** The domain, Postgres storage, crypto, HTTP routes, guard, the `rustauth` facade, the `@rustauth/contracts` TypeScript package, and the [integration guide](./docs/integration.md) are in place and tested (unit tests with in-memory fakes, route tests, end-to-end tests against Postgres, Zod tests on captured responses, and a scratch application that installs the package from git). Still to come before `v0.1.0`: the upgrade test job and the first release tag. Until then, pin a `rev`. What each release adds and how to upgrade to it: [CHANGELOG.md](./CHANGELOG.md).

## What v0.1 Covers

- Username and password sign-in, with Argon2id password hashes.
- Opaque bearer session tokens, stored only as SHA-256 hashes, so they are revocable immediately and need no signing keys.
- First-run setup: the first account becomes an administrator and needs a setup token.
- Roles for authorization: `administrator`, `manager`, `user`.
- Account administration: create, disable, reset password, change role, unlock, delete, with a last-administrator guard.
- Session management: list your own sessions, revoke one, revoke all others.
- Brute-force protection: temporary account lockout, per-IP failure limits, and rate limits on the public routes, with trusted-proxy handling.
- Postgres storage in its own schema, `auth`, with its own migration history and a schema check at startup.

Two-factor (TOTP), passkeys, SSO, email recovery, and fine-grained permissions are designed for and will arrive in later releases without changing the v0.1 tables except by adding columns.

## Quick Integration

The [integration guide](./docs/integration.md) walks through every step: dependency, migrate order, router and guard, error mapping, `auth.users` references, configuration, tests, and the web client. In short, pin a release tag (or a `rev` before the first tag):

```toml
[dependencies]
rustauth = { git = "https://github.com/host39/lib-rustauth", rev = "<commit>" } # tag = "v0.1.0" once released
```

Run the auth migrations before your own, build the library from your pool and configuration, merge its routes into your `OpenApiRouter`, and guard your own routes (this example is compiled as a test of the `rustauth` crate, so it stays in step with the API):

```rust
use std::collections::HashMap;
use std::net::SocketAddr;

use axum::http::StatusCode;
use rustauth::{AuthConfig, AuthUser, HttpError, Role, RustAuth};
use utoipa::OpenApi;
use utoipa_axum::router::OpenApiRouter;

#[derive(Clone)]
struct AppState;

#[derive(OpenApi)]
#[openapi(info(title = "my-app", version = "1.0.0"))]
struct ApiDoc;

async fn serve(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    // In your migrate step: the `auth` schema first, then your own migrations.
    rustauth::migrate(&pool).await?;

    let env: HashMap<String, String> = std::env::vars().collect();
    let auth = RustAuth::builder()
        .pool(pool.clone())
        .config(AuthConfig::parse(&env)?) // or AuthConfig::builder()
        .build() // checks the `auth` schema, wires the crypto and Postgres adapters
        .await?;

    let widgets = OpenApiRouter::<AppState>::new()
        .route("/widgets/{id}", axum::routing::delete(delete_widget))
        .layer(auth.guard()); // 401 unless a valid bearer token
    let (router, _openapi) = OpenApiRouter::<AppState>::with_openapi(ApiDoc::openapi())
        .nest("/api", auth.router().merge(widgets)) // auth routes join your OpenAPI document
        .split_for_parts();
    let app = router.with_state(AppState);

    // Serve with the peer address, so per-IP limits and AUTH_TRUSTED_PROXIES work.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await?;
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await?;
    Ok(())
}

async fn delete_widget(user: AuthUser) -> Result<StatusCode, HttpError> {
    user.require(Role::Manager)?; // 403 below manager
    // user.user_id, user.username, user.role, user.session_id ...
    Ok(StatusCode::NO_CONTENT)
}
```

- `auth.router::<S>()` works with any application state `S`; the auth routes carry their own. Schemas are named `rustauth.*`, operation ids `rustauth_*`, tags `rustauth.auth` and `rustauth.admin`, and signed-in routes use the `bearerAuth` security scheme, which your guarded routes can list too.
- `auth.guard()` loads the session and user on every request, so a disabled user or revoked session loses access at once. `auth.guard().require(Role::Manager)` answers `403` below a role, and `auth.guard().optional()` also lets anonymous requests through (read the caller with `OptionalAuthUser`).
- `AuthUser` used on a route without a guard answers `500` and logs `rustauth.guard.missing`, so a wiring mistake shows at once.
- `build()` refuses to start when `auth` migrations are pending ("Auth schema is out of date: run migrations") or when the database is newer than the library (unless `allow_newer_schema(true)`).
- While no account exists and no `AUTH_SETUP_TOKEN` is set, `build()` logs a generated setup token once (`rustauth.setup.token-issued`). Set `AUTH_SETUP_TOKEN` when several instances run.
- `auth.service()` and `auth.admin()` are the core services, for calls from your own code (for example `auth.service().purge()` to delete expired sessions and stale sign-in failure records).

Your own tables may reference `auth.users (id)`, for example `user_id uuid NOT NULL REFERENCES auth.users (id) ON DELETE CASCADE`. Keep all rustauth usage in one adapter module of your application, which maps `AuthError` into your error type and `AuthUser` into your own actor type; an upgrade then touches one module.

For tests without a database, enable the `testing` feature and build on the in-memory fakes: `RustAuth::builder().ports(rustauth::testing::Fakes::new().ports())`.

Web apps install `@rustauth/contracts` (generated TypeScript types, Zod schemas, route paths, error codes) from this repository at the same ref, and compile its TypeScript sources with their bundler:

```sh
pnpm add "@rustauth/contracts@github:host39/lib-rustauth#<commit-or-tag>&path:packages/contracts"
```

## HTTP API

Relative to where you mount the router (for example `/api`). Full request and response shapes are in the OpenAPI document and the [design](./docs/design/rustauth.md#http-rustauth-axum).

| Route | Auth | Purpose |
| --- | --- | --- |
| `GET /auth/setup` | public | `{ needsSetup, registrationOpen }` |
| `POST /auth/register` | public | First account with `setupToken`; later ones while registration is open |
| `POST /auth/login` | public | Username and password; returns token, expiry, and user |
| `POST /auth/logout` | user | Revokes the current session |
| `GET`, `PATCH /auth/me` | user | The caller's account; change the display name |
| `POST /auth/password` | user | `current`, `new`; revokes other sessions |
| `GET /auth/sessions` | user | Own sessions, the current one flagged |
| `DELETE /auth/sessions/{id}` | user | Revoke one |
| `POST /auth/sessions/revoke-others` | user | Revoke all but the current one |
| `GET`, `POST /admin/users` | administrator | List (paged) and create |
| `GET`, `PATCH`, `DELETE /admin/users/{id}` | administrator | Read, change (role, disabled, display name, password reset), delete |
| `POST /admin/users/{id}/unlock` | administrator | Clear a lockout |

Bodies use the RustInit template envelopes: `{ "data": ... }`, `{ "items": [...], "total": n }`, and on failure `{ "error", "code", "field"?, "details"?, "requestId"? }`. `429` responses carry `Retry-After` (and `details.retryAfterSecs`); `requestId` echoes the `X-Request-Id` request header.

## Configuration

`AuthConfig::parse` reads `AUTH_REGISTRATION_OPEN`, `AUTH_SETUP_TOKEN`, `AUTH_SESSION_TTL_DAYS`, `AUTH_SESSION_MAX_DAYS`, `AUTH_TRUSTED_PROXIES`, `AUTH_LOCKOUT_THRESHOLD`, `AUTH_LOCKOUT_MINUTES`, `AUTH_LOCKOUT_MAX_MINUTES`, `AUTH_IP_FAILURE_LIMIT`, and `AUTH_RATE_LIMIT_PER_MINUTE`. Defaults and validation rules are in the [design](./docs/design/rustauth.md#configuration).

## Example Server

[`examples/server`](./examples/server/src/main.rs) is a small axum application that uses the facade the way an application should: it reads `DATABASE_URL` and the `AUTH_*` variables, runs `rustauth::migrate`, builds `RustAuth`, mounts the auth routes and a guarded `GET /api/widgets` under `/api`, serves the merged OpenAPI document at `/api/openapi.json`, and listens with `ConnectInfo` on `EXAMPLE_ADDR` (default `127.0.0.1:3100`).

```sh
pnpm db:start   # local Postgres on port 5433 (or point EXAMPLE_DATABASE_URL elsewhere)
make example    # DATABASE_URL=$(EXAMPLE_DATABASE_URL) cargo run -p example-server
```

On first start it logs `rustauth.setup.token-issued setup_token="..."`. Then:

```sh
API=http://127.0.0.1:3100/api
curl -s $API/auth/setup
curl -s -X POST $API/auth/register -H 'content-type: application/json' \
  -d '{"username":"admin","password":"a long password","displayName":"Admin","setupToken":"<token from the log>"}'
curl -s $API/widgets -H "authorization: Bearer <token from the response>"
```

The example's tests (`cargo test -p example-server`) run the same application on the in-memory fakes, so the documented integration keeps compiling against the facade.

## Repository Layout

| Path | Role |
| --- | --- |
| `crates/rustauth` | Facade: the only supported Rust surface; features `axum`, `postgres`, `testing`, `ts` |
| `crates/rustauth-core` | Domain: value objects, entities, ports, services, `AuthError` |
| `crates/rustauth-crypto` | Argon2id hasher and session token issuer |
| `crates/rustauth-postgres` | sqlx repositories and embedded migrations in the `auth` schema |
| `crates/rustauth-contracts` | Request and response DTOs (serde, utoipa, optional ts-rs) |
| `crates/rustauth-axum` | Router, guard layer, extractors, HTTP error mapping |
| `packages/contracts` | npm package `@rustauth/contracts`, installed from git |
| `examples/server` | Minimal axum application that uses the facade |
| `docs` | [Design](./docs/design/rustauth.md), [integration guide](./docs/integration.md), and [ADRs](./docs/adr/README.md) |

## Development

Prerequisites: Rust stable (1.94 or newer), Node.js 22.18 or newer with pnpm 10 (the TypeScript tests run on Node's built-in type stripping), and Docker for the local Postgres.

```sh
make install         # pnpm and Cargo dependencies
make check           # format, lint, type-check, test, boundaries
pnpm db:start        # local Postgres 18 on port 5433
make test-db         # tests that need Postgres, one throwaway database each (DATABASE_URL overrides)
make contracts       # regenerate TypeScript bindings after changing a contract
make package         # install @rustauth/contracts from git (HEAD) into a scratch app and type-check it
```

`make help` lists every target. [AGENTS.md](./AGENTS.md) holds the project rules for people and coding assistants.

## License

[PolyForm Noncommercial 1.0.0](./LICENSE).
