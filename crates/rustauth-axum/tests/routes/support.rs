//! The auth router over core's in-memory fakes, and a small request builder.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{HeaderMap, Method, Request, StatusCode};
use http_body_util::BodyExt;
use rustauth_axum::{AuthState, router};
use rustauth_core::testing::Fakes;
use rustauth_core::{AdminService, AuthConfig, AuthConfigBuilder, AuthService, RateLimiter};
use serde_json::{Value, json};
use tower::ServiceExt;

pub const SETUP: &str = "setup-token-for-tests";
pub const PASSWORD: &str = "correct horse battery";
pub const WRONG: &str = "wrong horse battery";
/// The client address of requests unless a test says otherwise.
pub const CLIENT: &str = "203.0.113.10";

pub struct App {
    pub fakes: Fakes,
    pub state: AuthState,
    pub router: Router,
}

impl App {
    /// The router on fresh fakes with `config` plus the test setup token.
    pub async fn with(config: AuthConfigBuilder) -> Self {
        let config = config.setup_token(SETUP).build().expect("valid config");
        let fakes = Fakes::new();
        let limiter = RateLimiter::new(fakes.clock.clone(), config.rate_limit_per_minute());
        let auth = AuthService::new(fakes.ports(), config)
            .await
            .expect("service starts");
        let admin = AdminService::new(fakes.ports());
        let state = AuthState::new(Arc::new(auth), Arc::new(admin), Arc::new(limiter));
        let router = router::<()>(state.clone()).into();
        Self {
            fakes,
            state,
            router,
        }
    }

    pub async fn start() -> Self {
        Self::with(AuthConfig::builder()).await
    }

    pub async fn send(&self, call: Call) -> Reply {
        send(&self.router, call).await
    }

    /// Registers the first account (`root`, an administrator) and returns its token.
    pub async fn root(&self) -> String {
        let reply = self
            .send(post("/auth/register").json(json!({
                "username": "root",
                "password": PASSWORD,
                "displayName": "Root",
                "setupToken": SETUP,
            })))
            .await;
        assert_eq!(reply.status, StatusCode::CREATED, "{}", reply.body);
        reply.token()
    }

    /// Creates an account through the admin route and returns its id.
    pub async fn create(&self, admin: &str, username: &str, role: &str) -> String {
        let reply = self
            .send(post("/admin/users").token(admin).json(json!({
                "username": username,
                "displayName": username,
                "temporaryPassword": PASSWORD,
                "role": role,
            })))
            .await;
        assert_eq!(reply.status, StatusCode::CREATED, "{}", reply.body);
        reply.body["data"]["id"]
            .as_str()
            .expect("user id")
            .to_owned()
    }

    /// Signs in with [`PASSWORD`] and returns the token.
    pub async fn login(&self, username: &str) -> String {
        let reply = self
            .send(post("/auth/login").json(json!({ "username": username, "password": PASSWORD })))
            .await;
        assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
        reply.token()
    }
}

/// Sends `call` through any router.
pub async fn send(router: &Router, call: Call) -> Reply {
    let response = router
        .clone()
        .oneshot(call.build())
        .await
        .expect("infallible");
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    let body = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes)
            .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned()))
    };
    Reply {
        status,
        headers,
        body,
    }
}

pub struct Reply {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Value,
}

impl Reply {
    /// The `code` of an error body.
    pub fn code(&self) -> &str {
        self.body["code"].as_str().unwrap_or_default()
    }

    /// The token of a sign-in body.
    pub fn token(&self) -> String {
        self.body["data"]["token"]
            .as_str()
            .expect("token in the body")
            .to_owned()
    }

    /// Asserts an error status and code.
    #[track_caller]
    pub fn assert_error(&self, status: StatusCode, code: &str) {
        assert_eq!(self.status, status, "{}", self.body);
        assert_eq!(self.code(), code, "{}", self.body);
    }
}

pub struct Call {
    method: Method,
    uri: String,
    token: Option<String>,
    body: Option<Body>,
    content_type: Option<&'static str>,
    peer: Option<IpAddr>,
    headers: Vec<(&'static str, String)>,
}

pub fn call(method: Method, uri: &str) -> Call {
    Call {
        method,
        uri: uri.to_owned(),
        token: None,
        body: None,
        content_type: None,
        peer: Some(CLIENT.parse().expect("valid address")),
        headers: Vec::new(),
    }
}

pub fn get(uri: &str) -> Call {
    call(Method::GET, uri)
}

pub fn post(uri: &str) -> Call {
    call(Method::POST, uri)
}

pub fn patch(uri: &str) -> Call {
    call(Method::PATCH, uri)
}

pub fn delete(uri: &str) -> Call {
    call(Method::DELETE, uri)
}

impl Call {
    pub fn token(mut self, token: &str) -> Self {
        self.token = Some(token.to_owned());
        self
    }

    pub fn json(mut self, body: Value) -> Self {
        self.body = Some(Body::from(body.to_string()));
        self.content_type = Some("application/json");
        self
    }

    /// A raw body with a content type.
    pub fn raw(mut self, content_type: &'static str, body: &'static str) -> Self {
        self.body = Some(Body::from(body));
        self.content_type = Some(content_type);
        self
    }

    /// The peer address (`ConnectInfo`); `None` as if the server ran without connect info.
    pub fn peer(mut self, peer: Option<&str>) -> Self {
        self.peer = peer.map(|value| value.parse().expect("valid address"));
        self
    }

    pub fn header(mut self, name: &'static str, value: &str) -> Self {
        self.headers.push((name, value.to_owned()));
        self
    }

    fn build(self) -> Request<Body> {
        let mut builder = Request::builder().method(self.method).uri(self.uri);
        if let Some(token) = self.token {
            builder = builder.header("authorization", format!("Bearer {token}"));
        }
        if let Some(content_type) = self.content_type {
            builder = builder.header("content-type", content_type);
        }
        for (name, value) in self.headers {
            builder = builder.header(name, value);
        }
        if let Some(peer) = self.peer {
            builder = builder.extension(ConnectInfo(SocketAddr::new(peer, 50_000)));
        }
        builder
            .body(self.body.unwrap_or_default())
            .expect("valid request")
    }
}
