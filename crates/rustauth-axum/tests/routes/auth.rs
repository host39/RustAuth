//! `/auth/*`: setup, registration, sign-in, profile, password, and sessions.

use axum::http::StatusCode;
use rustauth_core::AuthConfig;
use serde_json::json;

use crate::support::{App, PASSWORD, SETUP, WRONG, delete, get, patch, post};

fn registration(username: &str, setup_token: Option<&str>) -> serde_json::Value {
    let mut body = json!({
        "username": username,
        "password": PASSWORD,
        "displayName": format!("{username} name"),
    });
    if let Some(token) = setup_token {
        body["setupToken"] = json!(token);
    }
    body
}

#[tokio::test]
async fn setup_status_reports_the_first_run() {
    let app = App::start().await;
    let reply = app.send(get("/auth/setup")).await;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(
        reply.body,
        json!({ "data": { "needsSetup": true, "registrationOpen": false } })
    );
    app.root().await;
    let reply = app.send(get("/auth/setup")).await;
    assert_eq!(reply.body["data"]["needsSetup"], false);
}

#[tokio::test]
async fn the_first_registration_needs_the_setup_token_and_becomes_administrator() {
    let app = App::start().await;
    let missing = app
        .send(post("/auth/register").json(registration("root", None)))
        .await;
    missing.assert_error(StatusCode::FORBIDDEN, "SETUP_REQUIRED");
    let wrong = app
        .send(post("/auth/register").json(registration("root", Some("not-the-setup-token"))))
        .await;
    wrong.assert_error(StatusCode::FORBIDDEN, "SETUP_REQUIRED");

    let reply = app
        .send(post("/auth/register").json(registration("Root", Some(SETUP))))
        .await;
    assert_eq!(reply.status, StatusCode::CREATED, "{}", reply.body);
    let data = &reply.body["data"];
    assert!(!data["token"].as_str().expect("token").is_empty());
    assert!(data["expiresAt"].is_string());
    assert_eq!(data["user"]["username"], "Root");
    assert_eq!(data["user"]["displayName"], "Root name");
    assert_eq!(data["user"]["role"], "administrator");
    assert_eq!(data["user"]["disabled"], false);

    let me = app.send(get("/auth/me").token(&reply.token())).await;
    assert_eq!(me.status, StatusCode::OK);
    assert_eq!(me.body["data"]["id"], data["user"]["id"]);
}

#[tokio::test]
async fn later_registrations_follow_registration_open() {
    let closed = App::start().await;
    closed.root().await;
    let reply = closed
        .send(post("/auth/register").json(registration("alice", None)))
        .await;
    reply.assert_error(StatusCode::FORBIDDEN, "REGISTRATION_CLOSED");

    let open = App::with(AuthConfig::builder().registration_open(true)).await;
    open.root().await;
    let reply = open
        .send(post("/auth/register").json(registration("alice", None)))
        .await;
    assert_eq!(reply.status, StatusCode::CREATED, "{}", reply.body);
    assert_eq!(reply.body["data"]["user"]["role"], "user");
    let taken = open
        .send(post("/auth/register").json(registration("ALICE", None)))
        .await;
    taken.assert_error(StatusCode::CONFLICT, "USERNAME_TAKEN");
}

#[tokio::test]
async fn registration_reports_the_invalid_field() {
    let app = App::start().await;
    let reply = app
        .send(post("/auth/register").json(registration("a!", Some(SETUP))))
        .await;
    reply.assert_error(StatusCode::BAD_REQUEST, "VALIDATION_ERROR");
    assert_eq!(reply.body["field"], "username");
    let mut short = registration("alice", Some(SETUP));
    short["password"] = json!("short");
    let reply = app.send(post("/auth/register").json(short)).await;
    assert_eq!(reply.body["field"], "password");
}

#[tokio::test]
async fn malformed_bodies_answer_with_the_error_envelope() {
    let app = App::start().await;
    let reply = app
        .send(post("/auth/login").raw("application/json", "{ not json"))
        .await;
    reply.assert_error(StatusCode::BAD_REQUEST, "VALIDATION_ERROR");
    assert_eq!(reply.body["field"], "body");
    let reply = app
        .send(post("/auth/login").json(json!({ "username": "root" })))
        .await;
    reply.assert_error(StatusCode::BAD_REQUEST, "VALIDATION_ERROR");
    let reply = app
        .send(post("/auth/login").raw("text/plain", "username=root"))
        .await;
    reply.assert_error(StatusCode::UNSUPPORTED_MEDIA_TYPE, "UNSUPPORTED_MEDIA_TYPE");
}

#[tokio::test]
async fn login_signs_in_and_refuses_wrong_or_unknown_credentials_alike() {
    let app = App::start().await;
    app.root().await;
    let reply = app
        .send(post("/auth/login").json(json!({ "username": "ROOT", "password": PASSWORD })))
        .await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
    assert_eq!(reply.body["data"]["user"]["username"], "root");

    let wrong = app
        .send(post("/auth/login").json(json!({ "username": "root", "password": WRONG })))
        .await;
    wrong.assert_error(StatusCode::UNAUTHORIZED, "INVALID_CREDENTIALS");
    assert_eq!(wrong.body["error"], "Invalid username or password.");
    assert_eq!(wrong.headers["www-authenticate"], "Bearer");
    let unknown = app
        .send(post("/auth/login").json(json!({ "username": "nobody", "password": WRONG })))
        .await;
    assert_eq!(unknown.status, wrong.status);
    assert_eq!(unknown.body, wrong.body);
}

#[tokio::test]
async fn me_reads_and_updates_the_display_name() {
    let app = App::start().await;
    let token = app.root().await;
    let reply = app
        .send(
            patch("/auth/me")
                .token(&token)
                .json(json!({ "displayName": "  The Root  " })),
        )
        .await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
    assert_eq!(reply.body["data"]["displayName"], "The Root");
    let me = app.send(get("/auth/me").token(&token)).await;
    assert_eq!(me.body["data"]["displayName"], "The Root");

    let blank = app
        .send(
            patch("/auth/me")
                .token(&token)
                .json(json!({ "displayName": " " })),
        )
        .await;
    blank.assert_error(StatusCode::BAD_REQUEST, "VALIDATION_ERROR");
    assert_eq!(blank.body["field"], "displayName");
}

#[tokio::test]
async fn logout_revokes_the_current_session() {
    let app = App::start().await;
    let token = app.root().await;
    let reply = app.send(post("/auth/logout").token(&token)).await;
    assert_eq!(reply.status, StatusCode::NO_CONTENT);
    assert_eq!(reply.body, serde_json::Value::Null);
    let me = app.send(get("/auth/me").token(&token)).await;
    me.assert_error(StatusCode::UNAUTHORIZED, "UNAUTHORIZED");
}

#[tokio::test]
async fn sessions_list_flag_and_revoke() {
    let app = App::start().await;
    let first = app.root().await;
    let second = app.login("root").await;
    let third = app.login("root").await;

    let reply = app.send(get("/auth/sessions").token(&first)).await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
    assert_eq!(reply.body["total"], 3);
    let items = reply.body["items"].as_array().expect("items");
    assert_eq!(items.len(), 3);
    let current: Vec<_> = items
        .iter()
        .filter(|item| item["current"] == true)
        .collect();
    assert_eq!(current.len(), 1);
    assert_eq!(current[0]["methods"], json!(["password"]));
    assert_eq!(current[0]["assurance"], "aal1");
    assert_eq!(current[0]["ip"], crate::support::CLIENT);

    // Revoke the session behind `second`, found as a non-current one from its own listing.
    let own = app.send(get("/auth/sessions").token(&second)).await;
    let second_id = own.body["items"]
        .as_array()
        .expect("items")
        .iter()
        .find(|item| item["current"] == true)
        .expect("current session")["id"]
        .as_str()
        .expect("id")
        .to_owned();
    let reply = app
        .send(delete(&format!("/auth/sessions/{second_id}")).token(&first))
        .await;
    assert_eq!(reply.status, StatusCode::NO_CONTENT);
    let gone = app.send(get("/auth/me").token(&second)).await;
    gone.assert_error(StatusCode::UNAUTHORIZED, "UNAUTHORIZED");
    let again = app
        .send(delete(&format!("/auth/sessions/{second_id}")).token(&first))
        .await;
    again.assert_error(StatusCode::NOT_FOUND, "ENTITY_NOT_FOUND");
    assert_eq!(again.body["details"]["entityName"], "Session");
    let malformed = app
        .send(delete("/auth/sessions/not-a-uuid").token(&first))
        .await;
    malformed.assert_error(StatusCode::BAD_REQUEST, "VALIDATION_ERROR");
    assert_eq!(malformed.body["field"], "id");

    let reply = app
        .send(post("/auth/sessions/revoke-others").token(&first))
        .await;
    assert_eq!(reply.status, StatusCode::NO_CONTENT);
    let other = app.send(get("/auth/me").token(&third)).await;
    other.assert_error(StatusCode::UNAUTHORIZED, "UNAUTHORIZED");
    let listing = app.send(get("/auth/sessions").token(&first)).await;
    assert_eq!(listing.body["total"], 1);
}

#[tokio::test]
async fn a_session_of_another_user_cannot_be_revoked() {
    let app = App::start().await;
    let root = app.root().await;
    app.create(&root, "alice", "user").await;
    let alice = app.login("alice").await;
    let listing = app.send(get("/auth/sessions").token(&alice)).await;
    let alice_session = listing.body["items"][0]["id"]
        .as_str()
        .expect("id")
        .to_owned();
    let reply = app
        .send(delete(&format!("/auth/sessions/{alice_session}")).token(&root))
        .await;
    reply.assert_error(StatusCode::NOT_FOUND, "ENTITY_NOT_FOUND");
    let still = app.send(get("/auth/me").token(&alice)).await;
    assert_eq!(still.status, StatusCode::OK);
}

#[tokio::test]
async fn password_change_checks_the_current_password_and_revokes_other_sessions() {
    let app = App::start().await;
    let current = app.root().await;
    let other = app.login("root").await;

    let wrong = app
        .send(
            post("/auth/password")
                .token(&current)
                .json(json!({ "current": WRONG, "new": "a brand new password" })),
        )
        .await;
    wrong.assert_error(StatusCode::BAD_REQUEST, "VALIDATION_ERROR");
    assert_eq!(wrong.body["field"], "current");
    let weak = app
        .send(
            post("/auth/password")
                .token(&current)
                .json(json!({ "current": PASSWORD, "new": "short" })),
        )
        .await;
    weak.assert_error(StatusCode::BAD_REQUEST, "VALIDATION_ERROR");
    assert_eq!(weak.body["field"], "new");

    let reply = app
        .send(
            post("/auth/password")
                .token(&current)
                .json(json!({ "current": PASSWORD, "new": "a brand new password" })),
        )
        .await;
    assert_eq!(reply.status, StatusCode::NO_CONTENT, "{}", reply.body);
    assert_eq!(
        app.send(get("/auth/me").token(&current)).await.status,
        StatusCode::OK
    );
    app.send(get("/auth/me").token(&other))
        .await
        .assert_error(StatusCode::UNAUTHORIZED, "UNAUTHORIZED");
    let old = app
        .send(post("/auth/login").json(json!({ "username": "root", "password": PASSWORD })))
        .await;
    old.assert_error(StatusCode::UNAUTHORIZED, "INVALID_CREDENTIALS");
    let new = app
        .send(post("/auth/login").json(json!({
            "username": "root",
            "password": "a brand new password",
        })))
        .await;
    assert_eq!(new.status, StatusCode::OK);
}
