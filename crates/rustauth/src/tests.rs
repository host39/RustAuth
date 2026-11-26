//! The builder over core's in-memory fakes: storage choice, the setup-token log, and the router
//! and guard it hands out.

use std::io::{self, Write};
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use rustauth_core::testing::Fakes;
use serde_json::{Value, json};
use tower::ServiceExt;
use tracing_subscriber::fmt::MakeWriter;
use utoipa_axum::router::OpenApiRouter;

use crate::{AuthConfig, AuthUser, BuildError, ClientInfo, Registration, RustAuth};

const SETUP: &str = "a-long-enough-setup-token";
const PASSWORD: &str = "correct horse battery";

/// Log output captured by a test subscriber.
#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl Capture {
    fn text(&self) -> String {
        String::from_utf8(self.0.lock().expect("capture lock").clone()).expect("utf-8 logs")
    }
}

impl Write for Capture {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0
            .lock()
            .expect("capture lock")
            .extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for Capture {
    type Writer = Capture;

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

/// Builds on `fakes` with `config` while capturing the logs.
async fn build_logged(fakes: &Fakes, config: AuthConfig) -> (RustAuth, String) {
    let capture = Capture::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(capture.clone())
        .with_ansi(false)
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);
    let auth = RustAuth::builder()
        .ports(fakes.ports())
        .config(config)
        .build()
        .await
        .expect("built");
    (auth, capture.text())
}

async fn send(router: &Router, request: Request<Body>) -> (StatusCode, Value) {
    let response = router.clone().oneshot(request).await.expect("infallible");
    let status = response.status();
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

fn register(setup_token: &str) -> Request<Body> {
    let body = json!({
        "username": "root",
        "password": PASSWORD,
        "displayName": "Root",
        "setupToken": setup_token,
    });
    Request::post("/api/auth/register")
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .expect("valid request")
}

#[tokio::test]
async fn build_needs_storage() {
    let error = RustAuth::builder().build().await.expect_err("no storage");
    assert!(matches!(error, BuildError::MissingStorage));
    assert_eq!(
        error.to_string(),
        "RustAuth needs storage: call pool() or ports() on the builder before build()"
    );
}

#[tokio::test]
async fn logs_a_generated_setup_token_that_registers_the_first_account() {
    let fakes = Fakes::new();
    let (auth, logs) = build_logged(&fakes, AuthConfig::default()).await;
    assert_eq!(
        logs.matches("rustauth.setup.token-issued").count(),
        1,
        "{logs}"
    );
    // The fake issuer's first token is the generated setup token.
    assert!(logs.contains("token-1"), "{logs}");

    let router: Router = OpenApiRouter::<()>::new()
        .nest("/api", auth.router())
        .into();
    let (status, _) = send(&router, register("not-the-token")).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, body) = send(&router, register("token-1")).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_eq!(body["data"]["user"]["role"], "administrator");
}

#[tokio::test]
async fn does_not_log_a_configured_setup_token() {
    let config = AuthConfig::builder()
        .setup_token(SETUP)
        .build()
        .expect("valid config");
    let (_, logs) = build_logged(&Fakes::new(), config).await;
    assert!(!logs.contains("rustauth.setup.token-issued"), "{logs}");
    assert!(!logs.contains(SETUP), "{logs}");
}

#[tokio::test]
async fn does_not_log_a_setup_token_once_an_account_exists() {
    let fakes = Fakes::new();
    let config = AuthConfig::builder()
        .setup_token(SETUP)
        .build()
        .expect("valid config");
    let (first, _) = build_logged(&fakes, config).await;
    let registration =
        Registration::new("root", "Root", PASSWORD.to_owned()).expect("valid registration");
    first
        .service()
        .register(registration, Some(SETUP), &ClientInfo::default())
        .await
        .expect("registered");

    let (_, logs) = build_logged(&fakes, AuthConfig::default()).await;
    assert!(!logs.contains("rustauth.setup.token-issued"), "{logs}");
}

#[tokio::test]
async fn hands_out_a_router_and_guard_for_any_application_state() {
    #[derive(Clone)]
    struct AppState {
        name: &'static str,
    }

    let config = AuthConfig::builder()
        .setup_token(SETUP)
        .rate_limit_per_minute(7)
        .build()
        .expect("valid config");
    let auth = RustAuth::builder()
        .ports(Fakes::new().ports())
        .config(config)
        .build()
        .await
        .expect("built");
    assert_eq!(auth.config().rate_limit_per_minute(), 7);
    assert!(format!("{auth:?}").contains("RustAuth"));
    assert!(!format!("{auth:?}").contains(SETUP));

    let widgets = OpenApiRouter::<AppState>::new()
        .route(
            "/widgets",
            axum::routing::get(
                |axum::extract::State(app): axum::extract::State<AppState>, user: AuthUser| async move {
                    format!("{} for {}", app.name, user.username)
                },
            ),
        )
        .layer(auth.guard());
    let (router, document) = OpenApiRouter::<AppState>::new()
        .nest("/api", auth.router().merge(widgets))
        .split_for_parts();
    let router = router.with_state(AppState { name: "widgets" });
    assert!(document.paths.paths.contains_key("/api/auth/login"));

    let (status, body) = send(&router, register(SETUP)).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let token = body["data"]["token"].as_str().expect("token");
    let request = Request::get("/api/widgets")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .expect("valid request");
    let response = router.clone().oneshot(request).await.expect("infallible");
    assert_eq!(response.status(), StatusCode::OK);
    let text = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    assert_eq!(&text[..], b"widgets for root");
    let (status, body) = send(
        &router,
        Request::get("/api/widgets")
            .body(Body::empty())
            .expect("valid request"),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["code"], "UNAUTHORIZED");
}

#[tokio::test]
async fn uses_the_default_configuration_without_one() {
    let auth = RustAuth::builder()
        .ports(Fakes::new().ports())
        .build()
        .await
        .expect("built");
    assert!(!auth.config().registration_open());
    assert_eq!(auth.config().rate_limit_per_minute(), 60);
}
