# AGENTS.md

RustAuth: a reusable authentication and authorization library for Rust applications built on axum, sqlx, and Postgres. Applications add the `rustauth` crate, run its migrations, mount its router, and put its guard in front of protected routes. The design is [docs/design/rustauth.md](./docs/design/rustauth.md); read it before changing behavior.

## Commands

Run these yourself from the repo root to verify work:

| Command | Checks |
| --- | --- |
| `make lint` | rustfmt, Clippy (`-D warnings`), Rust import paths, Biome, markdownlint |
| `make type-check` | `cargo check` (all targets, all features) + `tsc` |
| `make test` | `cargo test --workspace` + TypeScript tests |
| `make boundaries` | Crate dependency rules in `boundaries.config.mjs` |
| `make contracts` | Regenerates `packages/contracts/ts/generated/` after contract changes |
| `make package` | Installs `@rustauth/contracts` from git (the committed HEAD) into a scratch app and type-checks it |
| `make check` | format + lint + type-check + test + boundaries |
| `make ci` | lint + type-check + test + boundaries + contract drift + package check, without writes |
| `make test-db` | Tests marked `#[ignore]` that need Postgres (`DATABASE_URL`, default the maintenance database `localhost:5433/postgres`; each test gets a throwaway database) |

Run `make check` before considering work done. If a check needs infrastructure that is not running (Postgres for `test-db`), say so instead of skipping it silently. Point `make test-db` at another server with `make test-db DATABASE_URL=postgres://.../postgres`.

**User-only** (these start Docker or delete data): give the user the command instead of running it.

| Command | Purpose |
| --- | --- |
| `pnpm db:start` / `pnpm db:stop` | Start or stop the local Postgres from `docker-compose.yml` (host port 5433) |
| `pnpm db:reset` | Recreate the local Postgres volume |
| `make install` / `make update` | Install or update pnpm and Cargo dependencies |
| `make clean` | Remove build output, dependencies, and the database volume |

## Package Map

| Path | Role |
| --- | --- |
| `crates/rustauth-core` | Domain: value objects, entities, `Principal`, ports, services (`AuthService`, `AdminService`, `LoginGuard`, `RateLimiter`), `AuthError`; in-memory fakes under the `testing` feature |
| `crates/rustauth-crypto` | Argon2id `PasswordHasher` and session `TokenIssuer` (implements core ports) |
| `crates/rustauth-postgres` | sqlx repositories and embedded migrations in the `auth` schema, tracked in `auth._sqlx_migrations` |
| `crates/rustauth-contracts` | Request and response DTOs (serde + utoipa; `ts-rs` under the `ts` feature) |
| `crates/rustauth-axum` | Router (`OpenApiRouter<S>` with its own state), guard layer, `AuthUser` extractors, client IP, `AuthError` to HTTP mapping; route tests in `tests/routes` |
| `crates/rustauth` | Facade: `RustAuth::builder()` (the composition root, with the startup schema check), `migrate`, curated re-exports; features `axum`, `postgres`, `migrate`, `contracts`, `crypto`, `testing`, `ts` |
| `packages/contracts` | npm package `@rustauth/contracts`: generated TS types + Zod schemas |
| `examples/server` | Minimal axum application that uses the facade (docs and smoke tests) |
| `docs` | Design spec, integration guide, ADRs |

## Non-Negotiables

- **Generic by design.** Code, docs, examples, tests, table and column names, error codes, and configuration never mention a particular application. Application-specific data stays in the application, in its own tables that reference `auth.users (id)`. Examples use neutral names (`example`, `my-app`, `widgets`).
- Domain rules live in `rustauth-core`. Adapters (`rustauth-crypto`, `rustauth-postgres`, `rustauth-axum`) implement ports or translate HTTP; no domain logic in repositories or handlers.
- `rustauth-core` must not depend on `axum`, `sqlx`, `utoipa`, `ts-rs`, `argon2`, or any other rustauth crate; the other crates follow the table in the design (`make boundaries`).
- The `rustauth` facade is the only supported Rust surface and the composition root: it wires the adapters into the core services. Applications and `examples/server` use the facade, never the inner crates.
- Services fail with `AuthError` variants that carry human-readable messages and stable codes. Only `Internal` uses a dotted key (`AuthError::internal("rustauth.users.insert.failed", error)`). HTTP mapping lives in `rustauth-axum`.
- Compatibility: public enums that may grow are `#[non_exhaustive]`; configuration and inputs use builders or constructors; routes, JSON fields, and error codes are only added within a major version; removals go through `#[deprecated]` first. See "Upgrades and Compatibility" in the design.
- Migrations: every table lives in the `auth` schema; use `text` plus `CHECK` instead of enum types; a migration is append-only once a release tag includes it; breaking schema changes ship as expand, then contract.
- Never log passwords, tokens, or hashes. Log with `tracing` macros and `rustauth.*` dotted keys; no `println!` / `eprintln!` / `dbg!` (Clippy denies them). Library crates never install a subscriber.
- Dependency versions match the RustInit template (`axum` 0.8.9, `sqlx` 0.9.1, `utoipa` 6.0.0, `utoipa-axum` 0.3.0, `ts-rs` 12.0.1, `tokio` 1.48) so applications compile one copy of each crate. Crates enable only the features they use; the application picks the sqlx TLS backend. No `reqwest`: the library makes no outbound HTTP calls in v0.1.
- After changing a contract struct, run `make contracts` and update the Zod schema in `packages/contracts/ts/index.ts` (it must `satisfies` the generated type). Internal TypeScript imports use the `#generated/*` subpath import, never `./` or `../`.
- Rust uses `crate::` paths (no `super::` outside test modules), barrels in `lib.rs` and `mod.rs`, and no glob imports outside tests.
- No em-dashes in docs, code comments, or commit messages.

## Where to Look

- Design spec: [docs/design/rustauth.md](./docs/design/rustauth.md)
- Integration guide for applications (keep it in step with the facade and the package): [docs/integration.md](./docs/integration.md)
- Architecture and storage decisions: [docs/adr/001-architecture.md](./docs/adr/001-architecture.md)
- Dependency boundaries: [boundaries.config.mjs](./boundaries.config.mjs)

## AI Assistants

| Kind | Location |
| --- | --- |
| Rules | `.ai/rules/*.md`, loaded by path through `.claude/rules/*.md` wrappers |
| Skills | `.claude/skills/agent-workflows`: the owner's settings for multi-agent work (2 agents at a time, risk-based reviews, when a smaller model is allowed, smallest CI runners). Use it whenever you plan or run agents, reviews, or CI jobs |

## Project Rules

| Rule | Topic |
| --- | --- |
| `rust-imports` | `crate::` paths; no `super::` outside test modules; facade re-exports by name |
| `naming` | Short names; no `From` / `Of` connectors in function names; generic names only |
| `structured-logging` | `rustauth.*` dotted keys for tracing logs and infrastructure errors; never log secrets |
| `markdown-title-case` | Title case for Markdown headings; no em-dashes |
| `postgres-column-alignment` | Column order in `CREATE TABLE`; `auth` schema conventions |
| `parallel-db-reads` | Parallel SELECTs outside transactions, bounded by a shared pool |
