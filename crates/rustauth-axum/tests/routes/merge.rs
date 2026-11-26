//! The auth router merged into an application router with its own state, the guard on the
//! application's routes, and the merged OpenAPI document.

use std::io;
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::extract::State;
use axum::http::StatusCode;
use rustauth_axum::{AuthUser, OptionalAuthUser, request_scope, router};
use rustauth_core::{AuthError, Role};
use serde_json::json;
use tracing_subscriber::fmt::MakeWriter;
use utoipa::OpenApi;
use utoipa::openapi::OpenApi as Document;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use crate::support::{App, PASSWORD, get, post, send};

/// An application state the auth router knows nothing about.
#[derive(Clone)]
struct AppState {
    greeting: &'static str,
}

#[derive(OpenApi)]
#[openapi(
    info(title = "example-app", version = "1.0.0"),
    tags(
        (name = "auth", description = "The application's own sign-in pages"),
        (name = "admin", description = "The application's own administration"),
    )
)]
struct ApiDoc;

/// A widget route of the application: needs a signed-in user and the application's state.
#[utoipa::path(get, path = "/widgets", security(("bearerAuth" = [])), responses((status = 200, body = String)))]
async fn widgets(State(app): State<AppState>, user: AuthUser) -> String {
    format!("{} {}", app.greeting, user.username)
}

/// Managers and administrators only, checked in the handler.
async fn reports(user: AuthUser) -> Result<&'static str, rustauth_axum::HttpError> {
    user.require(Role::Manager)?;
    Ok("reports")
}

/// Anyone; signed-in callers are greeted by name.
async fn feed(OptionalAuthUser(user): OptionalAuthUser) -> String {
    user.map_or_else(
        || "hello stranger".to_owned(),
        |user| format!("hello {}", user.username),
    )
}

/// Uses the extractor without a guard in front: a wiring mistake.
async fn unguarded(user: AuthUser) -> String {
    user.username.to_string()
}

/// A public route of the application that answers with a rustauth error.
async fn public() -> Result<&'static str, rustauth_axum::HttpError> {
    Err(AuthError::validation("widget", "Widget name is required.").into())
}

/// The documented integration: the auth routes and the guarded application routes under `/api`.
fn application(app: &App) -> (Router, Document) {
    let guarded = OpenApiRouter::<AppState>::new()
        .routes(routes!(widgets))
        .route("/reports", axum::routing::get(reports))
        .layer(app.state.guard());
    let optional = OpenApiRouter::<AppState>::new()
        .route("/feed", axum::routing::get(feed))
        .layer(app.state.guard().optional());
    let managers = OpenApiRouter::<AppState>::new()
        .route("/managers", axum::routing::get(|| async { "managers" }))
        .layer(app.state.guard().require(Role::Manager));
    let (router, document) = OpenApiRouter::<AppState>::with_openapi(ApiDoc::openapi())
        .nest(
            "/api",
            router(app.state.clone())
                .merge(guarded)
                .merge(optional)
                .merge(managers)
                .route("/unguarded", axum::routing::get(unguarded))
                .merge(
                    OpenApiRouter::<AppState>::new()
                        .route("/public", axum::routing::get(public))
                        .layer(axum::middleware::from_fn(request_scope)),
                ),
        )
        .split_for_parts();
    (router.with_state(AppState { greeting: "hello" }), document)
}

#[tokio::test]
async fn merges_into_a_router_with_another_state() {
    let app = App::start().await;
    let (router, _) = application(&app);
    let register = send(
        &router,
        post("/api/auth/register").json(json!({
            "username": "root",
            "password": PASSWORD,
            "displayName": "Root",
            "setupToken": crate::support::SETUP,
        })),
    )
    .await;
    assert_eq!(register.status, StatusCode::CREATED, "{}", register.body);
    let token = register.token();

    let reply = send(&router, get("/api/widgets").token(&token)).await;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(reply.body, json!("hello root"));
    let me = send(&router, get("/api/auth/me").token(&token)).await;
    assert_eq!(me.body["data"]["username"], "root");

    let anonymous = send(&router, get("/api/widgets")).await;
    anonymous.assert_error(StatusCode::UNAUTHORIZED, "UNAUTHORIZED");
    let forged = send(&router, get("/api/widgets").token("not-a-real-token")).await;
    forged.assert_error(StatusCode::UNAUTHORIZED, "UNAUTHORIZED");
    let echoed = send(&router, get("/api/widgets").header("x-request-id", "req-7")).await;
    assert_eq!(echoed.body["requestId"], "req-7");
}

#[tokio::test]
async fn roles_are_enforced_by_the_guard_or_in_the_handler() {
    let app = App::start().await;
    let (router, _) = application(&app);
    let root = app.root().await;
    app.create(&root, "manny", "manager").await;
    app.create(&root, "alice", "user").await;
    let manager = app.login("manny").await;
    let user = app.login("alice").await;

    for token in [&root, &manager] {
        assert_eq!(
            send(&router, get("/api/reports").token(token)).await.status,
            StatusCode::OK
        );
        assert_eq!(
            send(&router, get("/api/managers").token(token))
                .await
                .status,
            StatusCode::OK
        );
    }
    send(&router, get("/api/reports").token(&user))
        .await
        .assert_error(StatusCode::FORBIDDEN, "FORBIDDEN");
    send(&router, get("/api/managers").token(&user))
        .await
        .assert_error(StatusCode::FORBIDDEN, "FORBIDDEN");
}

#[tokio::test]
async fn the_optional_guard_admits_anonymous_requests() {
    let app = App::start().await;
    let (router, _) = application(&app);
    let token = app.root().await;
    let named = send(&router, get("/api/feed").token(&token)).await;
    assert_eq!(named.body, json!("hello root"));
    let anonymous = send(&router, get("/api/feed")).await;
    assert_eq!(anonymous.body, json!("hello stranger"));
    let stale = send(&router, get("/api/feed").token("expired-or-revoked")).await;
    assert_eq!(stale.status, StatusCode::OK);
    assert_eq!(stale.body, json!("hello stranger"));
    // A storage failure is not mistaken for an anonymous request.
    app.fakes.store.set_failing(true);
    send(&router, get("/api/feed").token(&token))
        .await
        .assert_error(StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL_ERROR");
}

#[tokio::test]
async fn a_disabled_user_loses_access_at_once() {
    let app = App::start().await;
    let (router, _) = application(&app);
    let root = app.root().await;
    let id = app.create(&root, "alice", "user").await;
    let alice = app.login("alice").await;
    assert_eq!(
        send(&router, get("/api/widgets").token(&alice))
            .await
            .status,
        StatusCode::OK
    );
    let disabled = send(
        &router,
        crate::support::patch(&format!("/api/admin/users/{id}"))
            .token(&root)
            .json(json!({ "disabled": true })),
    )
    .await;
    assert_eq!(disabled.status, StatusCode::OK);
    send(&router, get("/api/widgets").token(&alice))
        .await
        .assert_error(StatusCode::UNAUTHORIZED, "UNAUTHORIZED");
}

#[tokio::test]
async fn the_extractor_without_a_guard_is_a_server_error() {
    let app = App::start().await;
    let (router, _) = application(&app);
    let token = app.root().await;
    let capture = Capture::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(capture.clone())
        .with_ansi(false)
        .finish();
    let reply = {
        let _guard = tracing::subscriber::set_default(subscriber);
        send(
            &router,
            get("/api/unguarded")
                .token(&token)
                .header("x-request-id", "req-wiring"),
        )
        .await
    };
    reply.assert_error(StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL_ERROR");
    assert_eq!(reply.body["requestId"], "req-wiring");
    // Operators filter on the key the docs name, as the message of its own line.
    let logs = capture.text();
    let line = logs
        .lines()
        .find(|line| line.contains(": rustauth.guard.missing"))
        .unwrap_or_else(|| panic!("no rustauth.guard.missing message in {logs}"));
    assert!(line.contains("ERROR"), "{line}");
    assert!(line.contains("req-wiring"), "{line}");
}

#[tokio::test]
async fn handler_errors_behind_the_guard_echo_the_request_id() {
    let app = App::start().await;
    let (router, _) = application(&app);
    let root = app.root().await;
    app.create(&root, "alice", "user").await;
    let user = app.login("alice").await;
    // `user.require(Role::Manager)?` in the handler, not the guard.
    let reply = send(
        &router,
        get("/api/reports")
            .token(&user)
            .header("x-request-id", "req-42"),
    )
    .await;
    reply.assert_error(StatusCode::FORBIDDEN, "FORBIDDEN");
    assert_eq!(reply.body["requestId"], "req-42");
    // An application route without a guard gets the id from `request_scope`.
    let public = send(&router, get("/api/public").header("x-request-id", "req-43")).await;
    public.assert_error(StatusCode::BAD_REQUEST, "VALIDATION_ERROR");
    assert_eq!(public.body["requestId"], "req-43");
}

#[tokio::test]
async fn the_document_holds_both_route_sets_with_namespaced_schemas() {
    let app = App::start().await;
    let (_, document) = application(&app);
    assert_eq!(document.info.title, "example-app");
    let paths: Vec<&str> = document.paths.paths.keys().map(String::as_str).collect();
    for path in [
        "/api/auth/setup",
        "/api/auth/register",
        "/api/auth/login",
        "/api/auth/logout",
        "/api/auth/me",
        "/api/auth/password",
        "/api/auth/sessions",
        "/api/auth/sessions/{id}",
        "/api/auth/sessions/revoke-others",
        "/api/admin/users",
        "/api/admin/users/{id}",
        "/api/admin/users/{id}/unlock",
        "/api/widgets",
    ] {
        assert!(paths.contains(&path), "{path} missing from {paths:?}");
    }
    let json = serde_json::to_value(&document).expect("serializes");
    let schemas = json["components"]["schemas"].as_object().expect("schemas");
    for name in [
        "rustauth.ErrorResponse",
        "rustauth.LoginRequest",
        "rustauth.RegisterRequest",
        "rustauth.UserResponse",
        "rustauth.UserRole",
        "rustauth.SessionResponse",
        "rustauth.UpdateUserRequest",
    ] {
        assert!(
            schemas.contains_key(name),
            "{name} missing: {:?}",
            schemas.keys()
        );
    }
    assert!(
        schemas.keys().all(|name| name.starts_with("rustauth.")),
        "{:?}",
        schemas.keys()
    );
    assert_eq!(
        json["components"]["securitySchemes"]["bearerAuth"]["scheme"],
        "bearer"
    );
    let me = &json["paths"]["/api/auth/me"];
    assert_eq!(me["get"]["security"], json!([{ "bearerAuth": [] }]));
    assert!(me["patch"].is_object());
    let operations: Vec<&str> = json["paths"]
        .as_object()
        .expect("paths")
        .iter()
        .filter(|(path, _)| path.starts_with("/api/auth") || path.starts_with("/api/admin"))
        .flat_map(|(_, item)| item.as_object().expect("path item").values())
        .map(|operation| operation["operationId"].as_str().expect("operation id"))
        .collect();
    assert_eq!(operations.len(), 16);
    let unique: std::collections::BTreeSet<&str> = operations.iter().copied().collect();
    assert_eq!(unique.len(), operations.len(), "{operations:?}");
    assert!(
        operations.iter().all(|id| id.starts_with("rustauth_")),
        "{operations:?}"
    );
    let login = &json["paths"]["/api/auth/login"]["post"];
    assert!(login.get("security").is_none());
    assert!(login["responses"]["429"]["headers"]["Retry-After"].is_object());

    // The application's own `auth` and `admin` tags stay apart from the library's.
    let tags: Vec<&str> = json["tags"]
        .as_array()
        .expect("tags")
        .iter()
        .map(|tag| tag["name"].as_str().expect("tag name"))
        .collect();
    let unique: std::collections::BTreeSet<&str> = tags.iter().copied().collect();
    assert_eq!(unique.len(), tags.len(), "{tags:?}");
    for name in [
        "auth",
        "admin",
        rustauth_axum::AUTH_TAG,
        rustauth_axum::ADMIN_TAG,
    ] {
        assert!(tags.contains(&name), "{name} missing from {tags:?}");
    }
    let operation_tags: std::collections::BTreeSet<&str> = json["paths"]
        .as_object()
        .expect("paths")
        .iter()
        .filter(|(path, _)| path.starts_with("/api/auth") || path.starts_with("/api/admin"))
        .flat_map(|(_, item)| item.as_object().expect("path item").values())
        .flat_map(|operation| operation["tags"].as_array().expect("operation tags"))
        .map(|tag| tag.as_str().expect("tag"))
        .collect();
    assert_eq!(
        operation_tags,
        [rustauth_axum::ADMIN_TAG, rustauth_axum::AUTH_TAG].into()
    );
}

/// Log output captured by a test subscriber.
#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl Capture {
    fn text(&self) -> String {
        String::from_utf8(self.0.lock().expect("capture lock").clone()).expect("utf-8 logs")
    }
}

impl io::Write for Capture {
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

#[test]
fn auth_errors_convert_into_the_handler_error() {
    let error: rustauth_axum::HttpError = AuthError::Unauthorized.into();
    assert_eq!(error.status(), StatusCode::UNAUTHORIZED);
}
