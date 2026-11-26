//! `429` with `Retry-After`, trusted proxies, the request id echo, and internal errors.

use axum::http::StatusCode;
use chrono::TimeDelta;
use rustauth_core::{AuthConfig, IpRange};
use serde_json::json;

use crate::support::{App, PASSWORD, WRONG, get, post};

#[tokio::test]
async fn public_routes_are_rate_limited_per_client_ip() {
    let app = App::with(AuthConfig::builder().rate_limit_per_minute(2)).await;
    for _ in 0..2 {
        assert_eq!(app.send(get("/auth/setup")).await.status, StatusCode::OK);
    }
    let limited = app.send(get("/auth/setup")).await;
    limited.assert_error(StatusCode::TOO_MANY_REQUESTS, "RATE_LIMITED");
    assert_eq!(limited.headers["retry-after"], "30");
    assert_eq!(limited.body["details"]["retryAfterSecs"], 30);
    // Login and registration share the bucket.
    app.send(post("/auth/login").json(json!({ "username": "root", "password": PASSWORD })))
        .await
        .assert_error(StatusCode::TOO_MANY_REQUESTS, "RATE_LIMITED");
    // Another client has its own bucket.
    let other = app
        .send(get("/auth/setup").peer(Some("198.51.100.20")))
        .await;
    assert_eq!(other.status, StatusCode::OK);
    // The bucket refills.
    app.fakes.clock.advance(TimeDelta::seconds(30));
    assert_eq!(app.send(get("/auth/setup")).await.status, StatusCode::OK);
}

#[tokio::test]
async fn signed_in_routes_are_not_rate_limited() {
    let app = App::with(AuthConfig::builder().rate_limit_per_minute(1)).await;
    let token = app.root().await;
    for _ in 0..5 {
        let reply = app.send(get("/auth/me").token(&token)).await;
        assert_eq!(reply.status, StatusCode::OK);
    }
}

#[tokio::test]
async fn without_a_peer_address_requests_are_not_limited() {
    let app = App::with(AuthConfig::builder().rate_limit_per_minute(1)).await;
    for _ in 0..3 {
        let reply = app.send(get("/auth/setup").peer(None)).await;
        assert_eq!(reply.status, StatusCode::OK);
    }
}

#[tokio::test]
async fn trusted_proxies_pass_the_client_address_on() {
    let config = AuthConfig::builder()
        .rate_limit_per_minute(1)
        .trusted_proxies(vec!["10.0.0.0/8".parse::<IpRange>().expect("valid range")]);
    let app = App::with(config).await;
    let through = |client: &str| {
        get("/auth/setup")
            .peer(Some("10.0.0.1"))
            .header("x-forwarded-for", &format!("192.0.2.99, {client}"))
    };
    assert_eq!(
        app.send(through("198.51.100.1")).await.status,
        StatusCode::OK
    );
    // Same client behind the proxy, with a different forged left-most hop: still limited.
    app.send(through("198.51.100.1"))
        .await
        .assert_error(StatusCode::TOO_MANY_REQUESTS, "RATE_LIMITED");
    assert_eq!(
        app.send(through("198.51.100.2")).await.status,
        StatusCode::OK
    );
    // An untrusted peer cannot pick its address with the header.
    let direct = get("/auth/setup")
        .peer(Some("203.0.113.50"))
        .header("x-forwarded-for", "198.51.100.3");
    assert_eq!(app.send(direct).await.status, StatusCode::OK);
    let again = get("/auth/setup")
        .peer(Some("203.0.113.50"))
        .header("x-forwarded-for", "198.51.100.4");
    app.send(again)
        .await
        .assert_error(StatusCode::TOO_MANY_REQUESTS, "RATE_LIMITED");
}

#[tokio::test]
async fn repeated_wrong_passwords_lock_the_account_with_retry_after() {
    let app = App::with(AuthConfig::builder().lockout_threshold(2)).await;
    app.root().await;
    let wrong = || post("/auth/login").json(json!({ "username": "root", "password": WRONG }));
    app.send(wrong())
        .await
        .assert_error(StatusCode::UNAUTHORIZED, "INVALID_CREDENTIALS");
    let locked = app.send(wrong()).await;
    locked.assert_error(StatusCode::TOO_MANY_REQUESTS, "ACCOUNT_LOCKED");
    assert_eq!(locked.headers["retry-after"], "900");
    assert_eq!(
        locked.body["error"],
        "Too many failed sign-in attempts. Try again in 15 minutes."
    );
    // Even the correct password is refused while the lock lasts.
    let correct = app
        .send(post("/auth/login").json(json!({ "username": "root", "password": PASSWORD })))
        .await;
    correct.assert_error(StatusCode::TOO_MANY_REQUESTS, "ACCOUNT_LOCKED");
    app.fakes.clock.advance(TimeDelta::minutes(15));
    let later = app
        .send(post("/auth/login").json(json!({ "username": "root", "password": PASSWORD })))
        .await;
    assert_eq!(later.status, StatusCode::OK);
}

#[tokio::test]
async fn too_many_failures_from_one_client_answer_429() {
    let config = AuthConfig::builder()
        .ip_failure_limit(2)
        .lockout_threshold(10);
    let app = App::with(config).await;
    for username in ["ghost_one", "ghost_two"] {
        app.send(post("/auth/login").json(json!({ "username": username, "password": WRONG })))
            .await
            .assert_error(StatusCode::UNAUTHORIZED, "INVALID_CREDENTIALS");
    }
    let limited = app
        .send(post("/auth/login").json(json!({ "username": "ghost_three", "password": WRONG })))
        .await;
    limited.assert_error(StatusCode::TOO_MANY_REQUESTS, "RATE_LIMITED");
    assert_eq!(limited.headers["retry-after"], "900");
}

#[tokio::test]
async fn error_bodies_echo_the_request_id() {
    let app = App::start().await;
    let reply = app
        .send(get("/auth/me").header("x-request-id", "req-42"))
        .await;
    reply.assert_error(StatusCode::UNAUTHORIZED, "UNAUTHORIZED");
    assert_eq!(reply.body["requestId"], "req-42");
    let reply = app
        .send(
            post("/auth/login")
                .header("x-request-id", "req-43")
                .json(json!({ "username": "nobody", "password": WRONG })),
        )
        .await;
    assert_eq!(reply.body["requestId"], "req-43");
    let reply = app.send(get("/auth/me")).await;
    assert!(reply.body.get("requestId").is_none());
}

#[tokio::test]
async fn storage_failures_answer_500_without_details() {
    let app = App::start().await;
    let token = app.root().await;
    app.fakes.store.set_failing(true);
    for call in [get("/auth/setup"), get("/auth/me").token(&token)] {
        let reply = app.send(call.header("x-request-id", "req-500")).await;
        reply.assert_error(StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL_ERROR");
        assert_eq!(
            reply.body,
            json!({
                "error": "An unexpected error occurred.",
                "code": "INTERNAL_ERROR",
                "requestId": "req-500",
            })
        );
    }
}
