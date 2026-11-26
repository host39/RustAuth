//! `/admin/users`: account administration, administrators only.

use axum::http::StatusCode;
use serde_json::json;

use crate::support::{App, PASSWORD, delete, get, patch, post};

#[tokio::test]
async fn administrators_create_list_get_update_unlock_and_delete_accounts() {
    let app = App::start().await;
    let root = app.root().await;
    let created = app
        .send(post("/admin/users").token(&root).json(json!({
            "username": "Alice",
            "displayName": "Alice A.",
            "temporaryPassword": PASSWORD,
            "role": "manager",
        })))
        .await;
    assert_eq!(created.status, StatusCode::CREATED, "{}", created.body);
    assert_eq!(created.body["data"]["role"], "manager");
    let id = created.body["data"]["id"].as_str().expect("id").to_owned();
    app.create(&root, "bob", "user").await;

    let page = app
        .send(get("/admin/users?offset=1&limit=1").token(&root))
        .await;
    assert_eq!(page.status, StatusCode::OK, "{}", page.body);
    assert_eq!(page.body["total"], 3);
    assert_eq!(page.body["items"].as_array().expect("items").len(), 1);
    assert_eq!(page.body["items"][0]["username"], "bob");
    let all = app.send(get("/admin/users").token(&root)).await;
    let names: Vec<&str> = all.body["items"]
        .as_array()
        .expect("items")
        .iter()
        .map(|user| user["username"].as_str().expect("username"))
        .collect();
    assert_eq!(names, ["Alice", "bob", "root"]);

    let one = app
        .send(get(&format!("/admin/users/{id}")).token(&root))
        .await;
    assert_eq!(one.body["data"]["displayName"], "Alice A.");

    let alice = app.login("alice").await;
    let updated = app
        .send(
            patch(&format!("/admin/users/{id}"))
                .token(&root)
                .json(json!({ "role": "user", "disabled": true, "displayName": "Alice B." })),
        )
        .await;
    assert_eq!(updated.status, StatusCode::OK, "{}", updated.body);
    assert_eq!(updated.body["data"]["role"], "user");
    assert_eq!(updated.body["data"]["disabled"], true);
    assert_eq!(updated.body["data"]["displayName"], "Alice B.");
    // Every admin change signs the account out, and a disabled account cannot sign in.
    app.send(get("/auth/me").token(&alice))
        .await
        .assert_error(StatusCode::UNAUTHORIZED, "UNAUTHORIZED");
    app.send(post("/auth/login").json(json!({ "username": "alice", "password": PASSWORD })))
        .await
        .assert_error(StatusCode::FORBIDDEN, "FORBIDDEN");

    let unlocked = app
        .send(post(&format!("/admin/users/{id}/unlock")).token(&root))
        .await;
    assert_eq!(unlocked.status, StatusCode::NO_CONTENT);

    let deleted = app
        .send(delete(&format!("/admin/users/{id}")).token(&root))
        .await;
    assert_eq!(deleted.status, StatusCode::NO_CONTENT);
    app.send(get(&format!("/admin/users/{id}")).token(&root))
        .await
        .assert_error(StatusCode::NOT_FOUND, "ENTITY_NOT_FOUND");
    app.send(delete(&format!("/admin/users/{id}")).token(&root))
        .await
        .assert_error(StatusCode::NOT_FOUND, "ENTITY_NOT_FOUND");
}

#[tokio::test]
async fn a_password_reset_lets_the_user_sign_in_with_it() {
    let app = App::start().await;
    let root = app.root().await;
    let id = app.create(&root, "alice", "user").await;
    let reply = app
        .send(
            patch(&format!("/admin/users/{id}"))
                .token(&root)
                .json(json!({ "password": "a reset password" })),
        )
        .await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
    let login = app
        .send(post("/auth/login").json(json!({
            "username": "alice",
            "password": "a reset password",
        })))
        .await;
    assert_eq!(login.status, StatusCode::OK);
    let weak = app
        .send(
            patch(&format!("/admin/users/{id}"))
                .token(&root)
                .json(json!({ "password": "short" })),
        )
        .await;
    weak.assert_error(StatusCode::BAD_REQUEST, "VALIDATION_ERROR");
    assert_eq!(weak.body["field"], "password");
}

#[tokio::test]
async fn non_administrators_get_403_on_every_admin_route() {
    let app = App::start().await;
    let root = app.root().await;
    let id = app.create(&root, "manny", "manager").await;
    let manager = app.login("manny").await;
    let calls = [
        get("/admin/users"),
        post("/admin/users").json(json!({
            "username": "eve",
            "displayName": "Eve",
            "temporaryPassword": PASSWORD,
            "role": "administrator",
        })),
        get(&format!("/admin/users/{id}")),
        patch(&format!("/admin/users/{id}")).json(json!({ "role": "administrator" })),
        post(&format!("/admin/users/{id}/unlock")),
        delete(&format!("/admin/users/{id}")),
        // The role check comes before the body is read.
        post("/admin/users").raw("application/json", "{ not json"),
    ];
    for call in calls {
        let reply = app.send(call.token(&manager)).await;
        reply.assert_error(StatusCode::FORBIDDEN, "FORBIDDEN");
        assert_eq!(
            reply.body["error"],
            "You do not have permission to do this."
        );
    }
    let me = app.send(get("/auth/me").token(&manager)).await;
    assert_eq!(me.body["data"]["role"], "manager");
}

#[tokio::test]
async fn the_last_administrator_stays() {
    let app = App::start().await;
    let root = app.root().await;
    let me = app.send(get("/auth/me").token(&root)).await;
    let id = me.body["data"]["id"].as_str().expect("id").to_owned();
    for body in [json!({ "role": "manager" }), json!({ "disabled": true })] {
        let reply = app
            .send(patch(&format!("/admin/users/{id}")).token(&root).json(body))
            .await;
        reply.assert_error(StatusCode::UNPROCESSABLE_ENTITY, "LAST_ADMINISTRATOR");
    }
    app.send(delete(&format!("/admin/users/{id}")).token(&root))
        .await
        .assert_error(StatusCode::UNPROCESSABLE_ENTITY, "LAST_ADMINISTRATOR");
}

#[tokio::test]
async fn create_validates_and_refuses_taken_usernames() {
    let app = App::start().await;
    let root = app.root().await;
    let taken = app
        .send(post("/admin/users").token(&root).json(json!({
            "username": "ROOT",
            "displayName": "Another root",
            "temporaryPassword": PASSWORD,
            "role": "user",
        })))
        .await;
    taken.assert_error(StatusCode::CONFLICT, "USERNAME_TAKEN");
    let weak = app
        .send(post("/admin/users").token(&root).json(json!({
            "username": "alice",
            "displayName": "Alice",
            "temporaryPassword": "short",
            "role": "user",
        })))
        .await;
    weak.assert_error(StatusCode::BAD_REQUEST, "VALIDATION_ERROR");
    assert_eq!(weak.body["field"], "temporaryPassword");
    let role = app
        .send(post("/admin/users").token(&root).json(json!({
            "username": "alice",
            "displayName": "Alice",
            "temporaryPassword": PASSWORD,
            "role": "owner",
        })))
        .await;
    role.assert_error(StatusCode::BAD_REQUEST, "VALIDATION_ERROR");
    let query = app.send(get("/admin/users?limit=many").token(&root)).await;
    query.assert_error(StatusCode::BAD_REQUEST, "VALIDATION_ERROR");
    assert_eq!(query.body["field"], "query");
}
