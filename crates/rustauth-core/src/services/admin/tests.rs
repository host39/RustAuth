//! `AdminService` rules: administrators only, every change revokes the user's sessions, a
//! password reset unlocks, an explicit unlock, and the last-administrator guard.

use crate::entities::Principal;
use crate::error::AuthError;
use crate::services::fixture::{Harness, PASSWORD, WRONG};
use crate::services::{NewAccount, SignedIn, UserChanges};
use crate::values::{DisplayName, Page, Password, Role, UserId};

fn is_last_administrator(error: &AuthError) -> bool {
    matches!(error, AuthError::LastAdministrator)
}

/// The root administrator plus a signed-in account `alice` with `role`.
async fn with_alice(role: Role) -> (Harness, Principal, SignedIn) {
    let harness = Harness::start().await;
    let root = harness.root().await;
    harness.create(&root, "alice", role).await;
    let alice = harness.login("alice", PASSWORD).await.expect("signed in");
    (harness, root, alice)
}

#[tokio::test]
async fn every_operation_requires_an_administrator() {
    let (harness, root, alice) = with_alice(Role::Manager).await;
    let manager = harness.principal(&alice).await;
    let target = root.user_id;
    let account = NewAccount::new("bob", "Bob", PASSWORD.to_owned(), Role::User).expect("valid");
    let errors = [
        harness.admin.list(&manager, Page::default()).await.err(),
        harness.admin.get(&manager, target).await.err(),
        harness.admin.create(&manager, account).await.err(),
        harness
            .admin
            .update(&manager, target, UserChanges::new().role(Role::User))
            .await
            .err(),
        harness.admin.unlock(&manager, target).await.err(),
        harness.admin.delete(&manager, target).await.err(),
    ];
    for error in errors {
        let error = error.expect("refused");
        assert!(matches!(error, AuthError::Forbidden { .. }), "{error:?}");
    }
    // Nothing changed.
    let me = harness.auth.me(&root).await.expect("found");
    assert_eq!(me.role, Role::Administrator);
}

#[tokio::test]
async fn creates_accounts_with_a_temporary_password_and_a_role() {
    let harness = Harness::start().await;
    let root = harness.root().await;
    let user = harness.create(&root, "Manny", Role::Manager).await;
    assert_eq!(user.role, Role::Manager);
    let signed = harness.login("manny", PASSWORD).await.expect("signed in");
    assert_eq!(harness.principal(&signed).await.role, Role::Manager);
    let account =
        NewAccount::new("MANNY", "Other", PASSWORD.to_owned(), Role::User).expect("valid");
    let error = harness
        .admin
        .create(&root, account)
        .await
        .expect_err("taken");
    assert!(matches!(error, AuthError::UsernameTaken), "{error:?}");
}

#[tokio::test]
async fn lists_and_gets_accounts() {
    let harness = Harness::start().await;
    let root = harness.root().await;
    for username in ["delta", "Alpha", "charlie", "bravo"] {
        harness.create(&root, username, Role::User).await;
    }
    let (users, total) = harness
        .admin
        .list(&root, Page::new(1, 2))
        .await
        .expect("listed");
    assert_eq!(total, 5);
    let names: Vec<&str> = users.iter().map(|user| user.username.as_str()).collect();
    assert_eq!(names, ["bravo", "charlie"]);
    let user = harness.admin.get(&root, users[0].id).await.expect("found");
    assert_eq!(user.username.as_str(), "bravo");
    let error = harness
        .admin
        .get(&root, UserId::generate())
        .await
        .expect_err("missing");
    assert!(matches!(error, AuthError::NotFound { entity: "User" }));
}

#[tokio::test]
async fn changing_the_role_revokes_sessions() {
    let (harness, root, alice) = with_alice(Role::User).await;
    let user = harness
        .admin
        .update(&root, alice.user.id, UserChanges::new().role(Role::Manager))
        .await
        .expect("updated");
    assert_eq!(user.role, Role::Manager);
    assert!(!harness.verifies(&alice).await);
    let again = harness.login("alice", PASSWORD).await.expect("signed in");
    assert_eq!(harness.principal(&again).await.role, Role::Manager);
}

#[tokio::test]
async fn renaming_revokes_sessions() {
    let (harness, root, alice) = with_alice(Role::User).await;
    let name = DisplayName::new("Alice A.").expect("valid");
    let user = harness
        .admin
        .update(
            &root,
            alice.user.id,
            UserChanges::new().display_name(name.clone()),
        )
        .await
        .expect("updated");
    assert_eq!(user.display_name, name);
    assert!(!harness.verifies(&alice).await);
}

#[tokio::test]
async fn disabling_revokes_sessions_and_blocks_sign_in() {
    let (harness, root, alice) = with_alice(Role::User).await;
    let user = harness
        .admin
        .update(&root, alice.user.id, UserChanges::new().disabled(true))
        .await
        .expect("disabled");
    assert!(user.is_disabled());
    assert!(!harness.verifies(&alice).await);
    let error = harness
        .login("alice", PASSWORD)
        .await
        .expect_err("disabled");
    assert_eq!(error.code(), "FORBIDDEN");
    harness
        .admin
        .update(&root, alice.user.id, UserChanges::new().disabled(false))
        .await
        .expect("enabled");
    harness
        .login("alice", PASSWORD)
        .await
        .expect("signed in again");
}

#[tokio::test]
async fn a_password_reset_unlocks_and_revokes_sessions() {
    let (harness, root, alice) = with_alice(Role::User).await;
    for _ in 0..5 {
        harness.login("alice", WRONG).await.expect_err("wrong");
    }
    let locked = harness.login("alice", PASSWORD).await.expect_err("locked");
    assert!(matches!(locked, AuthError::AccountLocked { .. }));
    let password = Password::new("a temporary password".to_owned()).expect("valid");
    let user = harness
        .admin
        .update(&root, alice.user.id, UserChanges::new().password(password))
        .await
        .expect("reset");
    assert!(user.lockout.is_clear());
    assert!(!harness.verifies(&alice).await);
    let error = harness.login("alice", PASSWORD).await.expect_err("old");
    assert!(matches!(error, AuthError::InvalidCredentials), "{error:?}");
    harness
        .login("alice", "a temporary password")
        .await
        .expect("new password, no lock");
}

#[tokio::test]
async fn unlock_clears_the_lockout() {
    let (harness, root, alice) = with_alice(Role::User).await;
    for _ in 0..5 {
        harness.login("alice", WRONG).await.expect_err("wrong");
    }
    harness
        .admin
        .unlock(&root, alice.user.id)
        .await
        .expect("unlocked");
    harness
        .login("alice", PASSWORD)
        .await
        .expect("signed in at once");
    let error = harness
        .admin
        .unlock(&root, UserId::generate())
        .await
        .expect_err("missing");
    assert!(matches!(error, AuthError::NotFound { .. }));
}

#[tokio::test]
async fn the_last_administrator_cannot_be_demoted_disabled_or_deleted() {
    let harness = Harness::start().await;
    let root = harness.root().await;
    let session = harness.login("root", PASSWORD).await.expect("signed in");
    let refused = [
        harness
            .admin
            .update(&root, root.user_id, UserChanges::new().role(Role::Manager))
            .await
            .err(),
        harness
            .admin
            .update(&root, root.user_id, UserChanges::new().disabled(true))
            .await
            .err(),
        harness.admin.delete(&root, root.user_id).await.err(),
    ];
    for error in refused {
        let error = error.expect("refused");
        assert!(is_last_administrator(&error), "{error:?}");
        assert_eq!(
            error.to_string(),
            "At least one enabled administrator must remain."
        );
    }
    // A refused change revokes nothing.
    assert!(harness.verifies(&session).await);
    let me = harness.auth.me(&root).await.expect("found");
    assert_eq!(me.role, Role::Administrator);
    assert!(!me.is_disabled());
}

#[tokio::test]
async fn a_second_enabled_administrator_lifts_the_guard() {
    let harness = Harness::start().await;
    let root = harness.root().await;
    let second = harness.create(&root, "second", Role::Administrator).await;
    // A disabled administrator does not count.
    harness
        .admin
        .update(&root, second.id, UserChanges::new().disabled(true))
        .await
        .expect("disabled");
    let error = harness
        .admin
        .update(&root, root.user_id, UserChanges::new().role(Role::User))
        .await
        .expect_err("still the last one");
    assert!(is_last_administrator(&error), "{error:?}");
    harness
        .admin
        .update(&root, second.id, UserChanges::new().disabled(false))
        .await
        .expect("enabled");
    let demoted = harness
        .admin
        .update(&root, root.user_id, UserChanges::new().role(Role::User))
        .await
        .expect("demoted");
    assert_eq!(demoted.role, Role::User);
}

#[tokio::test]
async fn deleting_removes_the_account_and_its_sessions() {
    let (harness, root, alice) = with_alice(Role::User).await;
    harness
        .admin
        .delete(&root, alice.user.id)
        .await
        .expect("deleted");
    assert!(!harness.verifies(&alice).await);
    let error = harness
        .admin
        .get(&root, alice.user.id)
        .await
        .expect_err("gone");
    assert!(matches!(error, AuthError::NotFound { .. }));
    let again = harness
        .admin
        .delete(&root, alice.user.id)
        .await
        .expect_err("gone");
    assert!(matches!(again, AuthError::NotFound { .. }));
    let login = harness.login("alice", PASSWORD).await.expect_err("gone");
    assert!(matches!(login, AuthError::InvalidCredentials));
}

#[tokio::test]
async fn empty_changes_change_nothing() {
    let (harness, root, alice) = with_alice(Role::User).await;
    let user = harness
        .admin
        .update(&root, alice.user.id, UserChanges::new())
        .await
        .expect("unchanged");
    assert_eq!(user, alice.user);
    assert!(harness.verifies(&alice).await);
}

#[tokio::test]
async fn updating_a_missing_account_fails_with_not_found() {
    let harness = Harness::start().await;
    let root = harness.root().await;
    for changes in [
        UserChanges::new().role(Role::User),
        UserChanges::new()
            .password(Password::new("a temporary password".to_owned()).expect("valid")),
    ] {
        let error = harness
            .admin
            .update(&root, UserId::generate(), changes)
            .await
            .expect_err("missing");
        assert!(matches!(error, AuthError::NotFound { .. }), "{error:?}");
    }
}

#[tokio::test]
async fn role_changes_apply_to_the_next_request() {
    let harness = Harness::start().await;
    let root = harness.root().await;
    let second = harness.create(&root, "second", Role::Administrator).await;
    let signed = harness.login("second", PASSWORD).await.expect("signed in");
    assert_eq!(harness.principal(&signed).await.role, Role::Administrator);
    harness
        .admin
        .update(&root, second.id, UserChanges::new().role(Role::Manager))
        .await
        .expect("demoted");
    // Sessions were revoked; a new sign-in carries the new role straight from storage.
    let again = harness.login("second", PASSWORD).await.expect("signed in");
    let principal = harness.principal(&again).await;
    assert!(!principal.has_role(Role::Administrator));
    let error = harness
        .admin
        .list(&principal, Page::default())
        .await
        .expect_err("no longer an administrator");
    assert!(matches!(error, AuthError::Forbidden { .. }));
}
