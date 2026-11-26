//! The upgrade harness of CI (`scripts/check-upgrade.sh`, `make test-upgrade`), not an
//! integration example. It plays an application across a library upgrade:
//!
//! - `upgrade seed` recreates the database, runs this version's migrate step (the auth
//!   migrations, then an application table that references `auth.users (id)`), and writes sample
//!   data through the facade: accounts in every state, sessions, lockouts of an account and of an
//!   unknown username, and application rows. It records what it wrote in a manifest.
//! - `upgrade check` runs this version's migrate step on that database and checks, through the
//!   facade, that everything the manifest lists still works.
//!
//! The upgrade job runs `seed` from the previous release tag and `check` from the current code,
//! so the command line, the variables, and the manifest are a contract between releases: `check`
//! must keep reading every manifest an older release wrote (`format` names the shape).
//!
//! - `RUSTAUTH_UPGRADE_DATABASE_URL`: the database. `seed` drops and recreates it, so its name
//!   must start with `rustauth_upgrade`.
//! - `RUSTAUTH_UPGRADE_MANIFEST`: the JSON file `seed` writes and `check` reads. It holds the
//!   sample passwords and session tokens; keep it out of anything shared.

use std::collections::HashMap;
use std::error::Error;
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
use std::str::FromStr;

use rustauth::{
    AuthConfig, AuthResult, AuthService, ClientInfo, NewAccount, Page, Principal, Registration,
    Role, RustAuth, UserChanges,
};
use serde_json::{Value, json};
use sqlx::migrate::MigrateDatabase;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::{PgPool, Postgres};

type Result<T = ()> = std::result::Result<T, Box<dyn Error>>;

const DATABASE_VAR: &str = "RUSTAUTH_UPGRADE_DATABASE_URL";
const MANIFEST_VAR: &str = "RUSTAUTH_UPGRADE_MANIFEST";

/// `seed` drops the database, so it refuses one whose name does not start with this.
const DATABASE_PREFIX: &str = "rustauth_upgrade";

/// The manifest shape this version writes. `check` reads this one and every older one.
const FORMAT: u64 = 1;

const SETUP_TOKEN: &str = "upgrade-setup-token-0123456789";
const WRONG_PASSWORD: &str = "not the right password";

/// Wrong passwords that lock an account (`AUTH_LOCKOUT_THRESHOLD` of the seed).
const LOCKOUT_THRESHOLD: usize = 2;

/// The sample accounts: username, role, and the state `seed` leaves them in. The first one
/// registers with the setup token and creates the others.
const ACCOUNTS: [(&str, Role, &str); 5] = [
    ("admin", Role::Administrator, "active"),
    ("manager", Role::Manager, "active"),
    ("member", Role::User, "active"),
    ("retired", Role::User, "disabled"),
    ("locked", Role::User, "locked"),
];

/// Usernames without an account that `seed` locks.
const UNKNOWN_LOCKED: [&str; 1] = ["ghost"];

/// Application rows: owner and name.
const WIDGETS: [(&str, &str); 3] = [
    ("member", "sprocket"),
    ("member", "gear"),
    ("admin", "flange"),
];

/// The application's own migration, after the auth ones: a table keyed by `auth.users (id)`.
const WIDGETS_TABLE: &str = "CREATE TABLE widgets (\
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(), \
    user_id uuid NOT NULL REFERENCES auth.users (id) ON DELETE CASCADE, \
    name text NOT NULL)";

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result {
    tracing_subscriber::fmt().init();
    let url = std::env::var(DATABASE_VAR)
        .map_err(|_| format!("upgrade.config.invalid {DATABASE_VAR}"))?;
    let manifest = PathBuf::from(
        std::env::var(MANIFEST_VAR)
            .map_err(|_| format!("upgrade.config.invalid {MANIFEST_VAR}"))?,
    );
    match std::env::args().nth(1).as_deref() {
        Some("seed") => seed(&url, &manifest).await,
        Some("check") => check(&url, &manifest).await,
        _ => Err("usage: upgrade seed|check".into()),
    }
}

/// Every sample account signs in with its own password.
fn password(username: &str) -> String {
    format!("{username} sample password")
}

fn client() -> ClientInfo {
    ClientInfo::new(
        Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))),
        "rustauth-upgrade/1",
    )
}

async fn connect(url: &str) -> Result<PgPool> {
    Ok(PgPoolOptions::new().max_connections(4).connect(url).await?)
}

/// The error code of a failed call, `None` when it succeeded.
fn code<T>(result: &AuthResult<T>) -> Option<&'static str> {
    result.as_ref().err().map(|error| error.code())
}

fn expect_code<T>(result: &AuthResult<T>, expected: &str, username: &str) -> Result {
    match code(result) {
        Some(found) if found == expected => Ok(()),
        found => Err(format!(
            "upgrade.check.failed sign-in of {username} answered {found:?}, expected {expected}"
        )
        .into()),
    }
}

/// Drops and recreates the database, which must be one made for this harness.
async fn reset(url: &str) -> Result {
    let options = PgConnectOptions::from_str(url)?;
    let name = options.get_database().unwrap_or_default();
    if !name.starts_with(DATABASE_PREFIX) {
        return Err(format!(
            "upgrade.config.invalid {DATABASE_VAR} names {name:?}: seed drops it, so the name must start with {DATABASE_PREFIX}"
        )
        .into());
    }
    if Postgres::database_exists(url).await? {
        Postgres::force_drop_database(url).await?;
    }
    Postgres::create_database(url).await?;
    Ok(())
}

async fn seed(url: &str, manifest: &Path) -> Result {
    reset(url).await?;
    let pool = connect(url).await?;
    rustauth::migrate(&pool).await?;
    sqlx::raw_sql(WIDGETS_TABLE).execute(&pool).await?;

    let threshold = LOCKOUT_THRESHOLD.to_string();
    let env = HashMap::from([
        ("AUTH_SETUP_TOKEN", SETUP_TOKEN),
        ("AUTH_LOCKOUT_THRESHOLD", threshold.as_str()),
        // Long enough that the locks still hold when `check` runs.
        ("AUTH_LOCKOUT_MINUTES", "720"),
    ]);
    let auth = RustAuth::builder()
        .pool(pool.clone())
        .config(AuthConfig::parse(&env)?)
        .build()
        .await?;
    let service = auth.service();
    let client = client();

    let (first, _, _) = ACCOUNTS[0];
    let registered = service
        .register(
            Registration::new(first, "Sample administrator", password(first))?,
            Some(SETUP_TOKEN),
            &client,
        )
        .await?;
    let admin = service.verify(registered.token.expose()).await?;
    let mut ids = HashMap::from([(first, registered.user.id)]);
    let mut sessions = vec![json!({ "username": first, "token": registered.token.expose() })];
    for (username, role, state) in &ACCOUNTS[1..] {
        let account = NewAccount::new(username, "Sample account", password(username), *role)?;
        let user = auth.admin().create(&admin, account).await?;
        ids.insert(*username, user.id);
        match *state {
            "active" => {
                let signed = service.login(username, password(username), &client).await?;
                sessions.push(json!({ "username": username, "token": signed.token.expose() }));
            }
            "disabled" => {
                let changes = UserChanges::new().disabled(true);
                auth.admin().update(&admin, user.id, changes).await?;
            }
            "locked" => lock(service, username, &client).await?,
            other => return Err(format!("upgrade.seed.failed unknown state {other}").into()),
        }
    }
    for username in UNKNOWN_LOCKED {
        lock(service, username, &client).await?;
    }
    for (owner, name) in WIDGETS {
        sqlx::query("INSERT INTO widgets (user_id, name) VALUES ($1::uuid, $2)")
            .bind(ids[owner].to_string())
            .bind(name)
            .execute(&pool)
            .await?;
    }

    let accounts: Vec<Value> = ACCOUNTS
        .iter()
        .map(|(username, role, state)| {
            json!({
                "username": username,
                "password": password(username),
                "role": role.as_str(),
                "state": state,
            })
        })
        .collect();
    let written = json!({
        "format": FORMAT,
        "version": rustauth::VERSION,
        "accounts": accounts,
        "sessions": sessions,
        "unknownLocked": UNKNOWN_LOCKED,
        "widgets": WIDGETS.len(),
    });
    std::fs::write(manifest, serde_json::to_string_pretty(&written)?)?;
    pool.close().await;
    tracing::info!(version = rustauth::VERSION, "upgrade.seed.done");
    Ok(())
}

/// Fails sign-in until the lockout holds, then makes sure even the right password is refused.
async fn lock(service: &AuthService, username: &str, client: &ClientInfo) -> Result {
    for _ in 0..LOCKOUT_THRESHOLD {
        let attempt = service
            .login(username, WRONG_PASSWORD.to_owned(), client)
            .await;
        if !matches!(
            code(&attempt),
            Some("INVALID_CREDENTIALS" | "ACCOUNT_LOCKED")
        ) {
            return Err(
                format!("upgrade.seed.failed wrong password of {username} was accepted").into(),
            );
        }
    }
    let refused = service.login(username, password(username), client).await;
    expect_code(&refused, "ACCOUNT_LOCKED", username)
}

/// The string field `key` of a manifest entry.
fn text<'a>(entry: &'a Value, key: &str) -> Result<&'a str> {
    entry[key]
        .as_str()
        .ok_or_else(|| format!("upgrade.check.failed manifest entry without {key}: {entry}").into())
}

fn entries(manifest: &Value, key: &str) -> Vec<Value> {
    manifest[key].as_array().cloned().unwrap_or_default()
}

async fn check(url: &str, manifest: &Path) -> Result {
    let manifest: Value = serde_json::from_str(&std::fs::read_to_string(manifest)?)?;
    let format = manifest["format"].as_u64();
    if format != Some(FORMAT) {
        return Err(format!("upgrade.check.failed unknown manifest format {format:?}").into());
    }
    let pool = connect(url).await?;
    rustauth::migrate(&pool).await?;
    let status = rustauth::schema_status(&pool).await?;
    assert!(status.is_current(), "auth schema after migrate: {status:?}");
    let auth = RustAuth::builder().pool(pool.clone()).build().await?;
    let service = auth.service();
    let client = client();

    for session in entries(&manifest, "sessions") {
        let username = text(&session, "username")?;
        let principal = service
            .verify(text(&session, "token")?)
            .await
            .map_err(|error| format!("upgrade.check.failed session of {username}: {error}"))?;
        assert_eq!(principal.username.as_str(), username, "session owner");
    }
    let admin = check_accounts(service, &manifest, &client).await?;
    for username in entries(&manifest, "unknownLocked") {
        let username = username.as_str().unwrap_or_default();
        let attempt = service
            .login(username, WRONG_PASSWORD.to_owned(), &client)
            .await;
        expect_code(&attempt, "ACCOUNT_LOCKED", username)?;
    }
    let (_, total) = auth.admin().list(&admin, Page::default()).await?;
    let accounts = u64::try_from(entries(&manifest, "accounts").len())?;
    assert_eq!(total, accounts, "accounts after the upgrade");
    let widgets = manifest["widgets"].as_i64().unwrap_or_default();
    check_widgets(&auth, &admin, &pool, widgets).await?;

    pool.close().await;
    tracing::info!(
        seeded_by = manifest["version"].as_str().unwrap_or("unknown"),
        version = rustauth::VERSION,
        "upgrade.check.done"
    );
    Ok(())
}

/// Signs in to every account and checks its role and state. Returns an administrator.
async fn check_accounts(
    service: &AuthService,
    manifest: &Value,
    client: &ClientInfo,
) -> Result<Principal> {
    let mut admin = None;
    for account in entries(manifest, "accounts") {
        let username = text(&account, "username")?;
        let attempt = service
            .login(username, text(&account, "password")?.to_owned(), client)
            .await;
        match text(&account, "state")? {
            "active" => {
                let signed = attempt.map_err(|error| {
                    format!("upgrade.check.failed sign-in of {username}: {error}")
                })?;
                assert_eq!(signed.user.role.as_str(), text(&account, "role")?, "role");
                let principal = service.verify(signed.token.expose()).await?;
                if principal.role == Role::Administrator {
                    admin.get_or_insert(principal);
                }
            }
            "disabled" => expect_code(&attempt, "FORBIDDEN", username)?,
            "locked" => expect_code(&attempt, "ACCOUNT_LOCKED", username)?,
            other => return Err(format!("upgrade.check.failed unknown state {other}").into()),
        }
    }
    admin.ok_or_else(|| "upgrade.check.failed no active administrator".into())
}

/// The application's table still references `auth.users (id)`, keeps its rows, and loses an
/// account's rows when the library deletes that account.
async fn check_widgets(auth: &RustAuth, admin: &Principal, pool: &PgPool, expected: i64) -> Result {
    let references: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM pg_constraint WHERE contype = 'f' \
         AND conrelid = 'widgets'::regclass AND confrelid = 'auth.users'::regclass",
    )
    .fetch_one(pool)
    .await?;
    assert_eq!(references, 1, "widgets references auth.users (id)");
    let owners: Vec<(String, i64)> = sqlx::query_as(
        "SELECT user_id::text, count(*) FROM widgets GROUP BY user_id ORDER BY user_id",
    )
    .fetch_all(pool)
    .await?;
    let total: i64 = owners.iter().map(|(_, count)| count).sum();
    assert_eq!(total, expected, "widgets after the upgrade");

    let (users, _) = auth.admin().list(admin, Page::default()).await?;
    let caller = admin.user_id.to_string();
    let Some((owner, owned)) = owners.iter().find(|(owner, _)| *owner != caller) else {
        return Ok(());
    };
    let user = users
        .iter()
        .find(|user| user.id.to_string() == *owner)
        .ok_or("upgrade.check.failed a widget owner is not listed")?;
    auth.admin().delete(admin, user.id).await?;
    let left: i64 = sqlx::query_scalar("SELECT count(*) FROM widgets")
        .fetch_one(pool)
        .await?;
    assert_eq!(left, total - owned, "widgets after deleting their owner");
    Ok(())
}
