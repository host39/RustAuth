# ADR-002: Brute-Force Protection and Upgrade Policy

## Status

Accepted

## Context

Two properties of RustAuth outweigh most others: it must stop password guessing, and applications must be able to upgrade it without fear. Both are decided once in the library and inherited by every application, so they are recorded together here.

**Brute-force protection.** Username and password is the only sign-in method in v0.1, so online guessing is the main threat. The forces:

- Applications run several instances behind load balancers and restart them freely. Protection that lives in one process can be spread across instances or reset by a restart.
- Every password check costs an Argon2id hash (about 19 MiB and tens of milliseconds). Checking first and counting later lets a concurrent burst get one guess per request, and lets an attacker spend the server's CPU on attempts that should have been refused.
- The sign-in answer must not reveal whether an account exists, neither in its message nor in its timing nor in how lockout behaves.
- Protection must not become a denial-of-service tool against known usernames, and it must work behind reverse proxies.
- The library makes no outbound calls and has no user interface of its own, so it cannot use CAPTCHAs or emailed unlock links.

**Upgrades.** The library is released on its own schedule while applications pin tags and upgrade when they choose:

- Applications deploy by rolling restart, so for a few minutes the previous application version runs against the schema the new one migrated. They also roll back.
- The library's tables live in the application's database, often next to application tables that reference `auth.users (id)`, so a careless migration breaks data the library does not own.
- sqlx checksums applied migrations; a changed file stops every database that applied it.
- Later features (two-factor, passkeys, SSO) will add tables, columns, and enum values while older and newer versions coexist.

## Decision

### Brute-Force Protection

Three layers, all on by default and configurable:

1. **Persisted account lockout.** The failure count, the lockout counter, and the lock end are stored with the account, so every instance sees the same state and restarts change nothing. After `lockout_threshold` wrong passwords (default 5) within the failure window (15 minutes), the account locks. The lock length doubles with each consecutive lockout, from 15 minutes up to a cap (default 24 hours); a correct password resets both counters. While locked, sign-in is refused **before** the password is checked, so even the correct password fails. Existing sessions stay valid: the lock is about guessing, not about compromise. Administrators can unlock an account, and an administrator password reset unlocks it.
2. **Reserve before checking.** Every password check first reserves an attempt in one atomic statement, which counts it as a failure and is refused while the account is locked or the window already holds the threshold (finished or still running). Concurrent attempts queue on the row, so a burst gets no more guesses than the threshold, and a refused attempt costs no Argon2 work. A correct password clears the count only if no lock was set meanwhile; a wrong one locks only while the stored state still holds what it saw.
3. **Unknown usernames behave the same.** A username without an account goes through the same steps with the same columns, in a table of its own keyed by the lowercase name, and is checked against a dummy hash. It locks after the same number of attempts, costs the same storage work, and gets the same answer, so neither messages, timing, nor lockout reveal which accounts exist. Input that is not a valid username is never tracked by name. Records that no longer count are purged; locked ones stay so their doubling continues.
4. **Per-IP limits, in memory.** Failed sign-ins per client IP (30 per 15 minutes) and requests to the public routes per client IP (60 per minute, token bucket) are limited per instance; IPv6 clients are grouped by /64. They stop one client from locking out many accounts quickly and are a cheap first layer, not the authoritative one. The client IP is the peer address, or for configured trusted proxies the first untrusted hop of `X-Forwarded-For` read from the right.
5. **Clear answers.** Locked and rate-limited requests answer `429` with `Retry-After` and the stable codes `ACCOUNT_LOCKED` and `RATE_LIMITED`. Failures, locks, and unlocks are logged with dotted keys; passwords and tokens never are.

### Upgrade Policy

1. **Versions.** Semantic version tags; before `1.0` a minor release may break. The `rustauth` crate and `@rustauth/contracts` share one version, and applications pin a tag.
2. **One supported Rust surface.** Only the facade is stable; inner crates may change in any release. Enums that may grow are `#[non_exhaustive]`, configuration and inputs use builders or constructors, and removals go through `#[deprecated]` for at least one minor release.
3. **Additive HTTP API.** Within a major version, routes, response fields, and error codes are only added and new request fields are optional. Clients handle unknown codes generically and unknown fields and roles leniently.
4. **The library owns its schema.** Every table is in `auth`, with its own migration history. `auth.users (id uuid primary key)` is the one stable database contract applications may reference. Applications never read or write `auth` tables directly.
5. **Append-only migrations, expand then contract.** A migration is never edited once a release tag includes it. A change that would break the previous release (rename, drop, new required column) ships in two releases: first the new shape alongside the old, then the removal. New allowed values use `text` plus `CHECK`, not enum types. Readers are lenient (an unknown role reads as the least privilege), and updates write only the fields they change, so rows a newer release wrote survive an older one.
6. **Startup schema check.** The library refuses to start while its migrations are pending, refuses a schema newer than itself unless the application opts in (safe only across releases that only expanded the schema), and always refuses applied migrations whose checksum changed. The migrate step itself leaves newer migrations alone, so an older version's migrate step still runs during a rolling deploy.
7. **The changelog is the upgrade contract.** Every release lists its breaking changes with exact steps, whether its schema change is expand only, and whether it must not be skipped, under "Upgrade Notes", next to the procedure applications follow (bump, read notes, migrate, test, deploy, roll back).
8. **Upgrades are tested in CI.** An upgrade job checks out the previous release tag, has that release write sample data through its own code into a fresh database (accounts in every state, sessions, lockouts, rows of an application table that references `auth.users (id)`), then migrates the database with the current code and checks that the data still works through the current code. It also runs the Postgres test suite with the current code, on throwaway databases of its own, so the upgraded data is covered by the harness's check alone. The harness that writes and checks the data is itself a contract between releases. Before the first tag, the job runs the harness on the current code alone, so the first tag ships a harness that is known to work.

## Consequences

### Positive

- Guessing is bounded per account however many instances run and however often they restart; a burst of concurrent attempts gets no extra guesses.
- Attempts the lockout refuses cost no Argon2 work, which limits CPU exhaustion through the sign-in route.
- Lockout, messages, and timing do not reveal which usernames exist.
- Upgrades follow one written procedure; rolling deploys keep working, and rollbacks across expand-only releases are possible.
- A migration that breaks the data an older release wrote, or an application table that references `auth.users (id)`, fails CI before it is released.

### Negative

- Anyone who knows a username can lock that account temporarily. The doubling cap, the per-IP limits, and the administrator unlock keep this bounded; the alternative is unlimited slow guessing.
- Every sign-in attempt writes to the database (the reservation), and unknown usernames create rows until they are purged; applications must call `purge` periodically.
- Per-IP limits are per instance, so N instances allow N times the configured rate from one client.
- Breaking schema changes take two releases, and some upgrades must not skip a release.
- Lenient readers can mask data a newer release wrote (an unknown role acts as `user` in an older release).
- The upgrade harness constrains later changes: its newer `check` must keep reading what older `seed`s wrote. The upgrade job adds CI time.

### Neutral

- The lockout columns live on `auth.users`; later sign-in methods (TOTP, passkeys) could count their failures into the same state.
- Lock lengths, thresholds, and limits are configuration; the defaults follow common guidance rather than a measured threat model.

## Alternatives Considered

| Alternative | Why rejected |
| --- | --- |
| Rate limits only, no account lockout | A distributed attacker guesses one account slowly from many IPs without limit |
| Lockout state in process memory | Differs per instance and resets on restart, so attempts can be spread to get around it |
| Check the password, then record the failure | A concurrent burst gets one guess per request, and the correct password can succeed on an account that a parallel failure just locked |
| Fixed lockout length | A patient attacker gets the threshold of guesses every period forever; doubling makes repeated guessing slower and slower |
| Lock until an administrator unlocks | Turns every known username into a lasting denial of service |
| Track unknown usernames differently, or not at all | The difference reveals which accounts exist |
| CAPTCHA or emailed unlock links | Need a user interface and outbound calls the library does not have; applications can add them in front of the routes |
| Per-IP limits in Postgres or Redis | A write on every request, or new infrastructure, for a layer the persisted account lockout already backs up |
| Editing or squashing released migrations | Changes checksums of migrations databases already applied, which stops them at startup |
| Reverting migrations on rollback | Loses data; expand-only releases plus `allow_newer_schema` roll back without touching the schema |
| Breaking schema changes in one release | The previous application version fails during a rolling deploy |
| Upgrade tests that only run the current code, or seed with hand-written SQL | Miss the data shapes an older release actually writes (hashes, token hashes, lockout state) |

## References

- [ADR-001: Layered Crates and Storage in the `auth` Schema](./001-architecture.md)
- [RustAuth design spec](../design/rustauth.md): "Brute-Force Protection" and "Upgrades and Compatibility"
- [Changelog](../../CHANGELOG.md): "Upgrade Notes"
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/) and [Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html)
