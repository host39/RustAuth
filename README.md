# RustAuth

Reusable authentication and authorization for Rust applications built on axum, sqlx, and Postgres. An application adds the `rustauth` crate, runs its migrations, mounts its router, and puts its guard in front of protected routes. Every application becomes a client of this library, so security fixes and new sign-in methods land once.

## Status

**v0.1 in progress.** The workspace, tooling, and CI are in place; the domain, storage, and HTTP layers are being built. The API below is the target shape from the [design](./docs/design/rustauth.md) and does not compile yet. There is no release tag yet.

## What v0.1 Covers

- Username and password sign-in, with Argon2id password hashes.
- Opaque bearer session tokens, stored only as SHA-256 hashes, so they are revocable immediately and need no signing keys.
- First-run setup: the first account becomes an administrator and needs a setup token.
- Roles for authorization: `administrator`, `manager`, `user`.
- Account administration: create, disable, reset password, change role, unlock, delete, with a last-administrator guard.
- Session management: list your own sessions, revoke one, revoke all others.
- Brute-force protection: temporary account lockout, per-IP failure limits, and rate limits on the public routes, with trusted-proxy handling.
- Postgres storage in its own schema, `auth`, with its own migration history.

Two-factor (TOTP), passkeys, SSO, email recovery, and fine-grained permissions are designed for and will arrive in later releases without changing the v0.1 tables except by adding columns.

## Quick Integration

Pin a release tag (or a `rev` before the first tag):

```toml
[dependencies]
rustauth = { git = "https://github.com/host39/lib-rustauth", tag = "v0.1.0" }
```

Run the auth migrations before your own, build the library from your pool and configuration, mount its routes, and guard your own routes:

```rust
use rustauth::{AuthConfig, AuthUser, Role, RustAuth};

// In your migrate step: the `auth` schema first, then your own migrations.
rustauth::migrate(&pool).await?;

let auth = RustAuth::builder()
    .pool(pool.clone())
    .config(AuthConfig::parse(&env)?) // or build AuthConfig by hand
    .build()?; // wires the crypto and Postgres adapters into the core services

let app = Router::new()
    .nest(
        "/api",
        auth.router() // public and self-protected auth routes, OpenAPI documented
            .merge(widget_routes.layer(auth.guard())), // 401 unless a valid bearer token
    )
    .with_state(app_state);

async fn delete_widget(user: AuthUser) -> Result<StatusCode, AppError> {
    user.require(Role::Manager)?;
    // ...
}
```

Your own tables may reference `auth.users (id)`, for example `user_id uuid NOT NULL REFERENCES auth.users (id) ON DELETE CASCADE`. Keep all rustauth usage in one adapter module of your application, which maps `AuthError` into your error type; an upgrade then touches one module.

Web apps can install `@rustauth/contracts` (generated TypeScript types plus Zod schemas) from this repository. The routes, error envelope, and configuration variables are listed in the [design](./docs/design/rustauth.md#http-rustauth-axum).

## Repository Layout

| Path | Role |
| --- | --- |
| `crates/rustauth` | Facade: the only supported Rust surface; features `axum`, `postgres`, `ts` |
| `crates/rustauth-core` | Domain: value objects, entities, ports, services, `AuthError` |
| `crates/rustauth-crypto` | Argon2id hasher and session token issuer |
| `crates/rustauth-postgres` | sqlx repositories and embedded migrations in the `auth` schema |
| `crates/rustauth-contracts` | Request and response DTOs (serde, utoipa, optional ts-rs) |
| `crates/rustauth-axum` | Router, guard layer, extractors, HTTP error mapping |
| `packages/contracts` | npm package `@rustauth/contracts` |
| `examples/server` | Minimal axum application that uses the facade |
| `docs` | [Design](./docs/design/rustauth.md) and [ADRs](./docs/adr/README.md) |

## Development

Prerequisites: Rust stable (1.94 or newer), Node.js 22 with pnpm 10, and Docker for the local Postgres.

```sh
make install         # pnpm and Cargo dependencies
make check           # format, lint, type-check, test, boundaries
pnpm db:start        # local Postgres 18 on port 5433
make test-db         # tests that need Postgres (DATABASE_URL overrides the default)
make contracts       # regenerate TypeScript bindings after changing a contract
```

`make help` lists every target. [AGENTS.md](./AGENTS.md) holds the project rules for people and coding assistants.

## License

[PolyForm Noncommercial 1.0.0](./LICENSE).
