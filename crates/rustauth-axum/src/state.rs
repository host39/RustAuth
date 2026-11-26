//! `AuthState`: the services the auth routes and the guard run on.

use std::sync::Arc;

use rustauth_core::{AdminService, AuthService, IpRange, RateLimiter};

use crate::guard::Guard;

/// The core services behind the HTTP adapter. The `rustauth` facade builds it; the router
/// applies it as its own state, so it never mixes with the application's state.
#[derive(Clone)]
pub struct AuthState {
    auth: Arc<AuthService>,
    admin: Arc<AdminService>,
    limiter: Arc<RateLimiter>,
    proxies: Arc<[IpRange]>,
}

impl AuthState {
    /// The trusted proxies come from the auth service's configuration.
    pub fn new(
        auth: Arc<AuthService>,
        admin: Arc<AdminService>,
        limiter: Arc<RateLimiter>,
    ) -> Self {
        let proxies = auth.config().trusted_proxies().into();
        Self {
            auth,
            admin,
            limiter,
            proxies,
        }
    }

    pub fn auth(&self) -> &AuthService {
        &self.auth
    }

    pub fn admin(&self) -> &AdminService {
        &self.admin
    }

    pub fn limiter(&self) -> &RateLimiter {
        &self.limiter
    }

    /// Peers whose `X-Forwarded-For` header is trusted (`AUTH_TRUSTED_PROXIES`).
    pub fn proxies(&self) -> &[IpRange] {
        &self.proxies
    }

    /// A guard layer on these services: `401` unless the request carries a valid bearer token.
    pub fn guard(&self) -> Guard {
        Guard::new(self.auth.clone())
    }
}
