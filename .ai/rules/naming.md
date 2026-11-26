# Naming

Applies to new code and to code you touch. Do not mass-rename existing code unless asked. Never rename contract-bound names: API/JSON fields, error codes, DB columns, env vars, route params, serialized or snapshot keys. Those are part of the compatibility promise in `docs/design/rustauth.md`.

## No "From" or "Of" in Function Names

Do not use `From` or `Of` as a connector in function or method names. Let the parameter types carry that meaning, or pick a verb that already implies it.

```rust
// BAD
fn user_from_row(row: UserRow) -> User {}
fn count_of_sessions(sessions: &[Session]) -> u64 {}
fn parse_role_from_string(value: &str) -> Role {}

// GOOD
impl From<UserRow> for User {} // or fn to_user(row: UserRow) -> User
fn count(sessions: &[Session]) -> u64 {}
fn parse_role(value: &str) -> Role {}
```

```typescript
// BAD
function userFromResponse(body: UserResponse): User {}

// GOOD
function toUser(body: UserResponse): User {}
```

Trait methods that std defines (`From::from`, `FromStr::from_str`, `TryFrom::try_from`) are exempt, and implementing those traits beats a free `x_from_y` function. Constructors that read configuration are `parse` or `load` (`AuthConfig::parse(&env)`), not `from_env`.

## Keep Names Short

- Aim for 1 to 3 words. Four only when genuinely needed; more than four is always too long.
- Rely on the surrounding module, type, and parameter types for context instead of repeating it in the name.
- Drop words the module or type already makes clear (`SessionRepository::delete_session` becomes `SessionRepository::delete`; `RustAuth::builder`, not `create_rust_auth_builder`).
- No type suffixes the type already says (`users_vec`, `config_struct`, `sessionsArray`).
- Prefer a precise verb over a verb plus qualifiers (`revoke`, `parse`, `to_x`).
- Short does not mean cryptic: whole words, no invented abbreviations, no single letters except loop indexes and very short closures.
- Follow each language's casing: Rust `snake_case` functions, modules, and files, `UpperCamelCase` types, `SCREAMING_SNAKE_CASE` constants; TypeScript `camelCase` functions and `PascalCase` types.

## Generic Names Only

The library knows nothing about the applications that use it. Names, examples, tests, table and column names, error codes, and configuration never mention a particular application or its features. Examples use neutral names (`example`, `my-app`, `widgets`).
