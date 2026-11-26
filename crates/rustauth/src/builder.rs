//! `RustAuth::builder()`: the composition root. Wires the crypto and Postgres adapters (or the
//! ports a caller supplies) into the core services.

use std::fmt;
use std::sync::Arc;

use rustauth_core::{AdminService, AuthConfig, AuthError, AuthService, Ports, RateLimiter};

/// Why [`RustAuthBuilder::build`] failed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum BuildError {
    /// Neither `pool()` nor `ports()` was called.
    #[error("RustAuth needs storage: call pool() or ports() on the builder before build()")]
    MissingStorage,

    /// Embedded migrations are not applied yet: run `rustauth::migrate` first.
    #[error("Auth schema is out of date: run migrations")]
    SchemaOutdated { pending: Vec<i64> },

    /// The database holds migrations this version does not know, for example after a rollback
    /// of the application. Safe to allow (`allow_newer_schema(true)`) only across releases that
    /// only added to the schema.
    #[error("Auth schema is newer than this version of rustauth")]
    SchemaNewer { unknown: Vec<i64> },

    /// Applied migrations differ from the embedded files, which a release never does.
    #[error("Auth schema does not match this version of rustauth: applied migrations changed")]
    SchemaChanged { changed: Vec<i64> },

    /// The services could not start (for example the database is unreachable).
    #[error(transparent)]
    Auth(#[from] AuthError),
}

/// The configured library: the core services plus the HTTP router and guard (feature `axum`).
/// Cheap to clone; every clone shares the services and their in-memory limiters.
///
/// ```no_run
/// # use std::collections::HashMap;
/// # use rustauth::{AuthConfig, RustAuth};
/// # async fn example(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
/// rustauth::migrate(&pool).await?;
/// let env: HashMap<String, String> = std::env::vars().collect();
/// let auth = RustAuth::builder()
///     .pool(pool.clone())
///     .config(AuthConfig::parse(&env)?)
///     .build()
///     .await?;
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct RustAuth {
    auth: Arc<AuthService>,
    admin: Arc<AdminService>,
    limiter: Arc<RateLimiter>,
}

impl RustAuth {
    pub fn builder() -> RustAuthBuilder {
        RustAuthBuilder::default()
    }

    /// Setup, registration, sign-in, token verification, and the caller's account and sessions.
    pub fn service(&self) -> &Arc<AuthService> {
        &self.auth
    }

    /// Account administration (administrators only).
    pub fn admin(&self) -> &Arc<AdminService> {
        &self.admin
    }

    /// Per-IP request limits of the public routes.
    pub fn limiter(&self) -> &Arc<RateLimiter> {
        &self.limiter
    }

    pub fn config(&self) -> &AuthConfig {
        self.auth.config()
    }

    /// The `/auth/*` and `/admin/users` routes with their state applied, for any application
    /// state `S`: merge them into the application's `OpenApiRouter<S>` (and so its OpenAPI
    /// document), usually under `/api`.
    #[cfg(feature = "axum")]
    pub fn router<S>(&self) -> utoipa_axum::router::OpenApiRouter<S>
    where
        S: Clone + Send + Sync + 'static,
    {
        rustauth_axum::router(self.state())
    }

    /// A layer that answers `401` unless the request carries a valid bearer token, and inserts
    /// [`crate::AuthUser`] for the handlers. See [`crate::Guard`] for the optional and
    /// minimum-role variants.
    #[cfg(feature = "axum")]
    pub fn guard(&self) -> rustauth_axum::Guard {
        rustauth_axum::Guard::new(self.auth.clone())
    }

    #[cfg(feature = "axum")]
    fn state(&self) -> rustauth_axum::AuthState {
        rustauth_axum::AuthState::new(self.auth.clone(), self.admin.clone(), self.limiter.clone())
    }
}

impl fmt::Debug for RustAuth {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RustAuth")
            .field("config", self.config())
            .finish_non_exhaustive()
    }
}

/// Where the services keep their data.
#[derive(Default)]
enum Storage {
    #[default]
    Missing,
    #[cfg(feature = "postgres")]
    Pool(sqlx::PgPool),
    Ports(Ports),
}

/// Builds a [`RustAuth`]. Call [`RustAuthBuilder::pool`] (or [`RustAuthBuilder::ports`]), then
/// [`RustAuthBuilder::build`]. Without [`RustAuthBuilder::config`] the defaults apply.
#[derive(Default)]
pub struct RustAuthBuilder {
    storage: Storage,
    config: Option<AuthConfig>,
    allow_newer_schema: bool,
}

impl RustAuthBuilder {
    /// Postgres storage on `pool` (the application's pool, or one to a separate database), with
    /// Argon2id password hashes, random session tokens, and the system clock. `build()` checks
    /// that the `auth` migrations are applied.
    #[cfg(feature = "postgres")]
    #[must_use]
    pub fn pool(mut self, pool: sqlx::PgPool) -> Self {
        self.storage = Storage::Pool(pool);
        self
    }

    /// Supplies every adapter: custom storage, or the in-memory fakes of the `testing` feature
    /// (`rustauth::testing::Fakes::ports()`). No schema check runs.
    #[must_use]
    pub fn ports(mut self, ports: Ports) -> Self {
        self.storage = Storage::Ports(ports);
        self
    }

    /// The settings, from `AuthConfig::parse(&env)` or `AuthConfig::builder()`.
    #[must_use]
    pub fn config(mut self, config: AuthConfig) -> Self {
        self.config = Some(config);
        self
    }

    /// Starts even when the database holds `auth` migrations this version does not know (for
    /// example after rolling the application back). Safe only across releases whose changelog
    /// says they only added to the schema. Default `false`.
    #[must_use]
    pub fn allow_newer_schema(mut self, allow: bool) -> Self {
        self.allow_newer_schema = allow;
        self
    }

    /// Checks the schema (Postgres storage), then starts the services. While no account exists
    /// and no setup token is configured, the service generates one and logs it once
    /// (`rustauth.setup.token-issued`); configure `AUTH_SETUP_TOKEN` when several instances run.
    ///
    /// Needs a reachable database (the schema check, and an account count without a configured
    /// setup token, run here without retries): with a lazy pool, call it once the database
    /// answers.
    pub async fn build(self) -> Result<RustAuth, BuildError> {
        let ports = match self.storage {
            Storage::Missing => return Err(BuildError::MissingStorage),
            #[cfg(feature = "postgres")]
            Storage::Pool(pool) => {
                check_schema(&pool, self.allow_newer_schema).await?;
                postgres_ports(pool)
            }
            Storage::Ports(ports) => ports,
        };
        let config = self.config.unwrap_or_default();
        let limiter = RateLimiter::new(ports.clock.clone(), config.rate_limit_per_minute());
        let auth = AuthService::new(ports.clone(), config).await?;
        let admin = AdminService::new(ports);
        Ok(RustAuth {
            auth: Arc::new(auth),
            admin: Arc::new(admin),
            limiter: Arc::new(limiter),
        })
    }
}

impl fmt::Debug for RustAuthBuilder {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let storage = match self.storage {
            Storage::Missing => "missing",
            #[cfg(feature = "postgres")]
            Storage::Pool(_) => "postgres",
            Storage::Ports(_) => "ports",
        };
        formatter
            .debug_struct("RustAuthBuilder")
            .field("storage", &storage)
            .field("config", &self.config)
            .field("allow_newer_schema", &self.allow_newer_schema)
            .finish()
    }
}

/// The schema check at startup (see "Upgrades and Compatibility" in the design).
#[cfg(feature = "postgres")]
async fn check_schema(pool: &sqlx::PgPool, allow_newer: bool) -> Result<(), BuildError> {
    let status = rustauth_postgres::schema_status(pool).await?;
    if !status.changed.is_empty() {
        return Err(BuildError::SchemaChanged {
            changed: status.changed,
        });
    }
    if !status.pending.is_empty() {
        return Err(BuildError::SchemaOutdated {
            pending: status.pending,
        });
    }
    if !status.unknown.is_empty() {
        if !allow_newer {
            return Err(BuildError::SchemaNewer {
                unknown: status.unknown,
            });
        }
        tracing::warn!(unknown = ?status.unknown, "rustauth.schema.newer-allowed");
    }
    Ok(())
}

#[cfg(feature = "postgres")]
fn postgres_ports(pool: sqlx::PgPool) -> Ports {
    Ports::new(
        Arc::new(rustauth_postgres::SqlxUserRepository::new(pool.clone())),
        Arc::new(rustauth_postgres::SqlxSessionRepository::new(pool)),
        Arc::new(rustauth_crypto::Argon2Hasher::new()),
        Arc::new(rustauth_crypto::RandomTokens),
        Arc::new(rustauth_core::SystemClock),
    )
}
