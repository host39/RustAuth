//! Shared setup for the service tests: both services over one set of fakes.

use crate::config::{AuthConfig, AuthConfigBuilder};
use crate::entities::{Principal, User};
use crate::error::AuthResult;
use crate::services::{AdminService, AuthService, NewAccount, Registration, SignedIn};
use crate::testing::Fakes;
use crate::values::{ClientInfo, Role};

pub(crate) const SETUP: &str = "setup-token-for-tests";
pub(crate) const PASSWORD: &str = "correct horse battery";
pub(crate) const WRONG: &str = "wrong horse battery";

pub(crate) struct Harness {
    pub fakes: Fakes,
    pub auth: AuthService,
    pub admin: AdminService,
}

impl Harness {
    /// Both services with `config` plus the test setup token.
    pub async fn with(config: AuthConfigBuilder) -> Self {
        let config = config.setup_token(SETUP).build().expect("valid config");
        let fakes = Fakes::new();
        let auth = AuthService::new(fakes.ports(), config)
            .await
            .expect("service starts");
        let admin = AdminService::new(fakes.ports());
        Self { fakes, auth, admin }
    }

    /// Both services with the default configuration.
    pub async fn start() -> Self {
        Self::with(AuthConfig::builder()).await
    }

    /// Self-registration with the setup token and [`PASSWORD`].
    pub async fn register(&self, username: &str) -> AuthResult<SignedIn> {
        self.auth
            .register(registration(username), Some(SETUP), &client())
            .await
    }

    /// Registers the first account (`root`) and returns its principal.
    pub async fn root(&self) -> Principal {
        let signed = self.register("root").await.expect("first registration");
        self.principal(&signed).await
    }

    /// An account created by `actor` with [`PASSWORD`].
    pub async fn create(&self, actor: &Principal, username: &str, role: Role) -> User {
        let account =
            NewAccount::new(username, username, PASSWORD.to_owned(), role).expect("valid account");
        self.admin
            .create(actor, account)
            .await
            .expect("account created")
    }

    pub async fn login(&self, username: &str, password: &str) -> AuthResult<SignedIn> {
        self.login_from(username, password, &client()).await
    }

    pub async fn login_from(
        &self,
        username: &str,
        password: &str,
        client: &ClientInfo,
    ) -> AuthResult<SignedIn> {
        self.auth.login(username, password.to_owned(), client).await
    }

    pub async fn principal(&self, signed: &SignedIn) -> Principal {
        self.auth
            .verify(signed.token.expose())
            .await
            .expect("token verifies")
    }

    pub async fn verifies(&self, signed: &SignedIn) -> bool {
        self.auth.verify(signed.token.expose()).await.is_ok()
    }
}

pub(crate) fn registration(username: &str) -> Registration {
    Registration::new(username, username, PASSWORD.to_owned()).expect("valid registration")
}

/// A client with a fixed documentation address.
pub(crate) fn client() -> ClientInfo {
    client_at("192.0.2.10")
}

pub(crate) fn client_at(ip: &str) -> ClientInfo {
    ClientInfo::new(Some(ip.parse().expect("valid address")), "test-agent/1.0")
}
