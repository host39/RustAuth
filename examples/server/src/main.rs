//! Minimal axum application that uses RustAuth through the `rustauth` facade, the way an
//! application integrates it:
//!
//! 1. Reads `DATABASE_URL` and the `AUTH_*` variables (`AuthConfig::parse`).
//! 2. Runs `rustauth::migrate` (an application would run its own migrations right after).
//! 3. Builds `RustAuth` on the pool, which checks the `auth` schema.
//! 4. Mounts the auth routes and a guarded `GET /api/widgets` under `/api`, merged into one
//!    OpenAPI document served at `/api/openapi.json`.
//! 5. Serves with `ConnectInfo`, so per-IP limits see the client address.
//!
//! `EXAMPLE_ADDR` sets the listen address (default `127.0.0.1:3100`).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::State;
use axum::routing::get;
use axum::{Json, Router};
use rustauth::{AuthConfig, AuthUser, RustAuth};
use serde::Serialize;
use sqlx::postgres::PgPoolOptions;
use tokio::net::TcpListener;
use utoipa::{OpenApi, ToSchema};
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

/// Listen address when `EXAMPLE_ADDR` is not set.
const DEFAULT_ADDR: &str = "127.0.0.1:3100";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt().init();

    let env: HashMap<String, String> = std::env::vars().collect();
    let config = AuthConfig::parse(&env)?;
    let database_url = env
        .get("DATABASE_URL")
        .ok_or("example.config.invalid DATABASE_URL")?;
    let addr: SocketAddr = env
        .get("EXAMPLE_ADDR")
        .map_or(DEFAULT_ADDR, String::as_str)
        .parse()?;

    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(database_url)
        .await?;
    // The `auth` schema first; an application's own migrations would follow here.
    rustauth::migrate(&pool).await?;
    let auth = RustAuth::builder()
        .pool(pool.clone())
        .config(config)
        .build()
        .await?;

    let listener = TcpListener::bind(addr).await?;
    tracing::info!(%addr, version = rustauth::VERSION, "example.server.listening");
    axum::serve(
        listener,
        app(&auth).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown())
    .await?;
    pool.close().await;
    Ok(())
}

/// The application's own state, which the auth routes know nothing about.
#[derive(Clone)]
struct AppState {
    widgets: Arc<[&'static str]>,
}

#[derive(OpenApi)]
#[openapi(info(
    title = "example-server",
    description = "RustAuth example application."
))]
struct ApiDoc;

/// The widgets the caller may see.
#[derive(Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
struct WidgetsResponse {
    owner: String,
    items: Vec<String>,
}

/// The application's routes and the auth routes under `/api`, plus `/health`.
fn app(auth: &RustAuth) -> Router {
    let widgets = OpenApiRouter::new()
        .routes(routes!(list_widgets))
        .layer(auth.guard());
    let (api, openapi) = OpenApiRouter::with_openapi(ApiDoc::openapi())
        .nest("/api", auth.router().merge(widgets))
        .split_for_parts();
    let openapi = Arc::new(openapi);
    api.route(
        "/api/openapi.json",
        get(move || {
            let openapi = openapi.clone();
            async move { Json(openapi) }
        }),
    )
    .route("/health", get(health))
    .with_state(AppState {
        widgets: Arc::new(["sprocket", "gear", "flange"]),
    })
}

/// Lists widgets for any signed-in user (the guard in front answers `401` otherwise).
#[utoipa::path(
    get,
    path = "/widgets",
    security(("bearerAuth" = [])),
    responses((status = 200, description = "Widgets of the caller", body = WidgetsResponse))
)]
async fn list_widgets(State(state): State<AppState>, user: AuthUser) -> Json<WidgetsResponse> {
    Json(WidgetsResponse {
        owner: user.username.to_string(),
        items: state
            .widgets
            .iter()
            .map(|widget| (*widget).to_owned())
            .collect(),
    })
}

async fn health() -> &'static str {
    "ok"
}

/// Resolves on Ctrl+C. If the signal handler cannot be installed, the server keeps running.
async fn shutdown() {
    if let Err(error) = tokio::signal::ctrl_c().await {
        tracing::error!(error = %error, "example.server.signal-failed");
        std::future::pending::<()>().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use http_body_util::BodyExt;
    use rustauth::testing::Fakes;
    use serde_json::{Value, json};
    use tower::ServiceExt;

    const SETUP: &str = "a-long-enough-setup-token";

    async fn example() -> Router {
        let config = AuthConfig::builder()
            .setup_token(SETUP)
            .build()
            .expect("valid config");
        let auth = RustAuth::builder()
            .ports(Fakes::new().ports())
            .config(config)
            .build()
            .await
            .expect("built");
        app(&auth)
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

    #[tokio::test]
    async fn health_answers_ok() {
        let request = Request::get("/health")
            .body(Body::empty())
            .expect("valid request");
        let response = example().await.oneshot(request).await.expect("responds");
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn widgets_need_a_signed_in_user() {
        let router = example().await;
        let anonymous = Request::get("/api/widgets")
            .body(Body::empty())
            .expect("valid request");
        let (status, body) = send(&router, anonymous).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body["code"], "UNAUTHORIZED");

        let register = Request::post("/api/auth/register")
            .header("content-type", "application/json")
            .body(Body::from(
                json!({
                    "username": "root",
                    "password": "correct horse battery",
                    "displayName": "Root",
                    "setupToken": SETUP,
                })
                .to_string(),
            ))
            .expect("valid request");
        let (status, body) = send(&router, register).await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        let token = body["data"]["token"].as_str().expect("token");

        let signed_in = Request::get("/api/widgets")
            .header("authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .expect("valid request");
        let (status, body) = send(&router, signed_in).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            body,
            json!({ "owner": "root", "items": ["sprocket", "gear", "flange"] })
        );
    }

    #[tokio::test]
    async fn serves_one_openapi_document_for_both_route_sets() {
        let request = Request::get("/api/openapi.json")
            .body(Body::empty())
            .expect("valid request");
        let (status, body) = send(&example().await, request).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["info"]["title"], "example-server");
        for path in ["/api/auth/login", "/api/admin/users", "/api/widgets"] {
            assert!(body["paths"][path].is_object(), "{path} missing");
        }
        assert!(body["components"]["securitySchemes"]["bearerAuth"].is_object());
    }
}
