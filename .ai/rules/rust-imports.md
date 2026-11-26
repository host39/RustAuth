# Rust Imports

One absolute way to name every item.

- **Within a crate**: absolute `crate::` paths in `use` and `pub use` (`use crate::values::Username;`).
- **Never `super::`** or bare relative module paths. The one exception is `use super::*;` as the first line of a colocated `#[cfg(test)] mod tests`. `scripts/lint-rust-imports.sh` (part of `make lint`) enforces the `super::` part.
- **Cross-crate**: the crate name (`use rustauth_core::AuthError;`), declared in the crate's `Cargo.toml` as `rustauth-core = { workspace = true }`.
- **Barrels**: re-export each crate's public API from `lib.rs`, and each module's from its `mod.rs`. Import from the crate root when a re-export exists.
- **No glob imports** (`use some::module::*;`) outside test modules.
- **Grouping**: `std`, then external and workspace crates, then `crate::`, with one blank line between groups. rustfmt sorts within each group.

```rust
// BAD
use super::values::Username;
use self::services::AuthService;
use rustauth_core::error::AuthError; // a deep path when the root re-exports it

// GOOD
use crate::services::AuthService;
use crate::values::Username;
use rustauth_core::AuthError;
```

## Facade Surface

Applications use the `rustauth` facade only; the inner crates may change in any release. When a type becomes part of what applications need (`RustAuth`, `AuthConfig`, `AuthUser`, `Role`, `AuthError`), re-export it from `crates/rustauth/src/lib.rs` by name. Do not re-export whole inner crates.

## New Crates

Add the path to `[workspace.dependencies]` in the root `Cargo.toml`, depend on it with `{ workspace = true }`, and add its rules to `boundaries.config.mjs`.
