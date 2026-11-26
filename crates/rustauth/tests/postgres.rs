//! End to end through the facade on a real Postgres: migrate, the startup schema check, and the
//! auth routes plus a guarded application route over HTTP (`tower` oneshot), with the real
//! Argon2id hasher and random tokens.
//!
//! `#[sqlx::test]` gives each test a throwaway database on the server that `DATABASE_URL` points
//! at. The tests are ignored by default; `make test-db` runs them.

#![cfg(all(feature = "axum", feature = "postgres"))]

use std::net::SocketAddr;

use axum::Router;
use axum::body::Body;
use axum::extract::{ConnectInfo, State};
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use rustauth::{AuthConfig, AuthUser, BuildError, Role, RustAuth};
use serde_json::{Value, json};
use sqlx::PgPool;
use tower::ServiceExt;
use utoipa_axum::router::OpenApiRouter;

const SETUP: &str = "a-long-enough-setup-token";
const PASSWORD: &str = "correct horse battery staple";

fn config() -> AuthConfig {
    AuthConfig::builder()
        .setup_token(SETUP)
        .lockout_threshold(2)
        .build()
        .expect("valid config")
}

#[derive(Clone)]
struct AppState {
    label: &'static str,
}

/// The documented integration: auth routes and a guarded application route under `/api`.
fn app(auth: &RustAuth) -> Router {
    let widgets = OpenApiRouter::<AppState>::new()
        .route(
            "/widgets",
            axum::routing::get(|State(app): State<AppState>, user: AuthUser| async move {
                format!("{} of {} ({})", app.label, user.username, user.role)
            }),
        )
        .layer(auth.guard());
    let admin_only = OpenApiRouter::<AppState>::new()
        .route("/reports", axum::routing::get(|| async { "reports" }))
        .layer(auth.guard().require(Role::Administrator));
    let (router, _) = OpenApiRouter::<AppState>::new()
        .nest("/api", auth.router().merge(widgets).merge(admin_only))
        .split_for_parts();
    router.with_state(AppState { label: "widgets" })
}

async fn send(
    router: &Router,
    method: &str,
    uri: &str,
    token: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut request = Request::builder()
        .method(method)
        .uri(uri)
        .extension(ConnectInfo(SocketAddr::from(([198, 51, 100, 4], 40_000))))
        .header("user-agent", "example-agent/1.0");
    if let Some(token) = token {
        request = request.header("authorization", format!("Bearer {token}"));
    }
    let request = match body {
        Some(body) => request
            .header("content-type", "application/json")
            .body(Body::from(body.to_string())),
        None => request.body(Body::empty()),
    }
    .expect("valid request");
    let response = router.clone().oneshot(request).await.expect("infallible");
    let status = response.status();
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    let body = serde_json::from_slice(&bytes)
        .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned()));
    (status, body)
}

#[sqlx::test(migrations = false)]
#[ignore = "requires Postgres: run make test-db"]
async fn serves_the_auth_routes_on_postgres(pool: PgPool) {
    let before = RustAuth::builder()
        .pool(pool.clone())
        .config(config())
        .build()
        .await
        .expect_err("not migrated yet");
    assert!(
        matches!(before, BuildError::SchemaOutdated { ref pending } if !pending.is_empty()),
        "{before:?}"
    );
    assert_eq!(
        before.to_string(),
        "Auth schema is out of date: run migrations"
    );

    rustauth::migrate(&pool).await.expect("migrated");
    let auth = RustAuth::builder()
        .pool(pool.clone())
        .config(config())
        .build()
        .await
        .expect("built");
    let router = app(&auth);

    let (status, body) = send(&router, "GET", "/api/auth/setup", None, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["data"]["needsSetup"], true);
    let registration = json!({
        "username": "root",
        "password": PASSWORD,
        "displayName": "Root",
        "setupToken": SETUP,
    });
    let (status, body) = send(
        &router,
        "POST",
        "/api/auth/register",
        None,
        Some(registration),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_eq!(body["data"]["user"]["role"], "administrator");
    let root = body["data"]["token"].as_str().expect("token").to_owned();
    assert_eq!(root.len(), 43);

    // The token is stored as a hash only, and the session records the client.
    let stored: Vec<Vec<u8>> = sqlx::query_scalar("SELECT token_hash FROM auth.sessions")
        .fetch_all(&pool)
        .await
        .expect("sessions");
    assert_eq!(stored.len(), 1);
    assert_ne!(stored[0], root.as_bytes());
    let (status, body) = send(&router, "GET", "/api/auth/sessions", Some(&root), None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["items"][0]["ip"], "198.51.100.4");
    assert_eq!(body["items"][0]["userAgent"], "example-agent/1.0");
    assert_eq!(body["items"][0]["current"], true);

    let (status, body) = send(&router, "GET", "/api/widgets", Some(&root), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, json!("widgets of root (administrator)"));
    let (status, _) = send(&router, "GET", "/api/reports", Some(&root), None).await;
    assert_eq!(status, StatusCode::OK);

    // An administrator creates a user, who signs in and is kept out of admin-only routes.
    let (status, body) = send(
        &router,
        "POST",
        "/api/admin/users",
        Some(&root),
        Some(json!({
            "username": "alice",
            "displayName": "Alice",
            "temporaryPassword": PASSWORD,
            "role": "user",
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let alice_id = body["data"]["id"].as_str().expect("id").to_owned();
    let login = json!({ "username": "Alice", "password": PASSWORD });
    let (status, body) = send(&router, "POST", "/api/auth/login", None, Some(login)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let alice = body["data"]["token"].as_str().expect("token").to_owned();
    let (status, body) = send(&router, "GET", "/api/widgets", Some(&alice), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, json!("widgets of alice (user)"));
    let (status, body) = send(&router, "GET", "/api/reports", Some(&alice), None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["code"], "FORBIDDEN");
    let (status, _) = send(&router, "GET", "/api/admin/users", Some(&alice), None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Two wrong passwords lock the account, persisted in auth.users.
    let wrong = json!({ "username": "alice", "password": "a wrong password" });
    let (status, _) = send(
        &router,
        "POST",
        "/api/auth/login",
        None,
        Some(wrong.clone()),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, body) = send(&router, "POST", "/api/auth/login", None, Some(wrong)).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(body["code"], "ACCOUNT_LOCKED");
    let (status, body) = send(
        &router,
        "GET",
        &format!("/api/admin/users/{alice_id}"),
        Some(&root),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["data"]["lockedUntil"].is_string(), "{body}");
    let (status, _) = send(
        &router,
        "POST",
        &format!("/api/admin/users/{alice_id}/unlock"),
        Some(&root),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let login = json!({ "username": "alice", "password": PASSWORD });
    let (status, _) = send(&router, "POST", "/api/auth/login", None, Some(login)).await;
    assert_eq!(status, StatusCode::OK);

    // Logging out revokes the session at once; deleting the account removes its rows.
    let (status, _) = send(&router, "POST", "/api/auth/logout", Some(&alice), None).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = send(&router, "GET", "/api/widgets", Some(&alice), None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = send(
        &router,
        "DELETE",
        &format!("/api/admin/users/{alice_id}"),
        Some(&root),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let left: i64 = sqlx::query_scalar(
        "SELECT (SELECT count(*) FROM auth.users) + (SELECT count(*) FROM auth.sessions)",
    )
    .fetch_one(&pool)
    .await
    .expect("counted");
    // root and root's one session.
    assert_eq!(left, 2);
}

#[sqlx::test(migrations = false)]
#[ignore = "requires Postgres: run make test-db"]
async fn refuses_a_newer_schema_unless_allowed(pool: PgPool) {
    rustauth::migrate(&pool).await.expect("migrated");
    sqlx::query(
        "INSERT INTO auth._sqlx_migrations \
         (version, description, success, checksum, execution_time) \
         VALUES (99990101000000, 'from a newer release', true, '\\x00', 0)",
    )
    .execute(&pool)
    .await
    .expect("recorded a newer migration");
    // The documented startup order of an older version: its migrate step runs first and must
    // not fail, so that `build()` gets to decide.
    rustauth::migrate(&pool)
        .await
        .expect("an older version migrates a newer schema");

    let error = RustAuth::builder()
        .pool(pool.clone())
        .config(config())
        .build()
        .await
        .expect_err("newer schema");
    assert!(
        matches!(error, BuildError::SchemaNewer { ref unknown } if unknown == &[99_990_101_000_000]),
        "{error:?}"
    );
    assert_eq!(
        error.to_string(),
        "Auth schema is newer than this version of rustauth"
    );
    RustAuth::builder()
        .pool(pool)
        .config(config())
        .allow_newer_schema(true)
        .build()
        .await
        .expect("allowed");
}

#[sqlx::test(migrations = false)]
#[ignore = "requires Postgres: run make test-db"]
async fn refuses_a_changed_migration(pool: PgPool) {
    rustauth::migrate(&pool).await.expect("migrated");
    sqlx::query("UPDATE auth._sqlx_migrations SET checksum = '\\x01'")
        .execute(&pool)
        .await
        .expect("changed checksums");
    let error = RustAuth::builder()
        .pool(pool)
        .config(config())
        .allow_newer_schema(true)
        .build()
        .await
        .expect_err("changed schema");
    assert!(
        matches!(error, BuildError::SchemaChanged { .. }),
        "{error:?}"
    );
}
