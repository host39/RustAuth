# Structured Logging Keys

Operational logs use stable dot-notation keys so operators can filter on the message and correlate requests with `request_id` (the `X-Request-Id` header). Applications see these logs in their own output, so every library key starts with `rustauth.`.

## Keys

Use `rustauth.area.outcome` as the message:

- Lowercase segments separated by **dots**
- Multi-word segments use **kebab-case** (`rustauth.setup.token-issued`)
- No underscores in keys
- IDs, client IPs, counts, and errors go in **fields**, never in the key
- **Bounded detail** may follow the key after a space in error messages (`rustauth.config.invalid AUTH_SESSION_TTL_DAYS`)

## Rust

Log through the `tracing` macros. The message string is the key; context is structured fields with `snake_case` names. Use `%value` for `Display` and `?value` for `Debug`.

```rust
// GOOD
tracing::warn!(user_id = %user_id, ip = ?client.ip, count, "rustauth.login.failed");
tracing::info!(user_id = %user_id, until = %locked_until, "rustauth.login.locked");

// BAD
tracing::warn!("Login failed for {username}");
tracing::info!("Account locked");
```

The library crates depend on `tracing` only, never on `tracing-subscriber`: the application installs the subscriber. The example server installs its own.

`println!`, `eprintln!`, and `dbg!` are denied workspace-wide by Clippy. The only exception is an `#[allow(clippy::print_stderr)]` block in a binary that reports a failure before the logger is installed.

## Never Log Secrets

Passwords, session tokens, token hashes, password hashes, and the setup token never appear in logs or error messages. The one exception is the generated setup token, which is logged once at startup (`rustauth.setup.token-issued`) so the operator can create the first account. Value objects that hold secrets redact themselves in `Debug`.

## Infrastructure Errors

Persistence, config, and integration failures carry the same dotted keys and surface as `500` responses with a generic body:

```rust
AuthError::internal("rustauth.users.insert.failed", error)

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("rustauth.config.invalid {0}")]
    Invalid(&'static str),
}
```

## API and Domain Errors

Do **not** use dotted keys as client-facing `AuthError` messages. Use human-readable sentences ("Invalid username or password.") and put machine identifiers in the stable `code` (`INVALID_CREDENTIALS`), `field`, and `details`.

## Out of Scope

- Test-only panics and assertion messages
- Programming invariant panics (`expect("...")` explaining why a value must exist)
