//! `/admin/users`: account administration. The guard in front of these routes admits
//! administrators only, and `AdminService` checks the role again.

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use rustauth_contracts::{
    CreateUserRequest, DetailsResponse, ErrorResponse, ListResponse, ListUsersQuery,
    UpdateUserRequest, UserResponse,
};
use rustauth_core::{DisplayName, NewAccount, Page, Password, UserChanges, UserId};

use crate::error::HttpError;
use crate::extract::{AuthUser, IdPath, JsonBody, QueryParams};
use crate::routes::convert::{to_role, to_user};
use crate::state::AuthState;

type Details<T> = Json<DetailsResponse<T>>;

fn details<T>(data: T) -> Details<T> {
    Json(DetailsResponse { data })
}

/// Accounts ordered by username, one page at a time.
#[utoipa::path(
    get,
    path = "/admin/users",
    operation_id = "rustauth_list_users",
    tag = "rustauth.admin",
    security(("bearerAuth" = [])),
    params(ListUsersQuery),
    responses(
        (status = 200, description = "A page of accounts and the total count", body = ListResponse<UserResponse>),
        (status = 400, description = "Invalid query (`VALIDATION_ERROR`)", body = ErrorResponse),
        (status = 401, description = "Missing, expired, or revoked token (`UNAUTHORIZED`)", body = ErrorResponse),
        (status = 403, description = "Not an administrator (`FORBIDDEN`)", body = ErrorResponse),
    )
)]
pub(crate) async fn list(
    State(state): State<AuthState>,
    user: AuthUser,
    QueryParams(query): QueryParams<ListUsersQuery>,
) -> Result<Json<ListResponse<UserResponse>>, HttpError> {
    let page = Page::new(
        query.offset.unwrap_or(0),
        query.limit.unwrap_or(Page::DEFAULT_LIMIT),
    );
    let (users, total) = state.admin().list(&user, page).await?;
    Ok(Json(ListResponse {
        items: users.iter().map(to_user).collect(),
        total,
    }))
}

/// Creates an account with a temporary password and any role.
#[utoipa::path(
    post,
    path = "/admin/users",
    operation_id = "rustauth_create_user",
    tag = "rustauth.admin",
    security(("bearerAuth" = [])),
    request_body = CreateUserRequest,
    responses(
        (status = 201, description = "The new account", body = DetailsResponse<UserResponse>),
        (status = 400, description = "Invalid input (`VALIDATION_ERROR` with `field`)", body = ErrorResponse),
        (status = 401, description = "Missing, expired, or revoked token (`UNAUTHORIZED`)", body = ErrorResponse),
        (status = 403, description = "Not an administrator (`FORBIDDEN`)", body = ErrorResponse),
        (status = 409, description = "Username taken (`USERNAME_TAKEN`)", body = ErrorResponse),
    )
)]
pub(crate) async fn create(
    State(state): State<AuthState>,
    user: AuthUser,
    JsonBody(body): JsonBody<CreateUserRequest>,
) -> Result<(StatusCode, Details<UserResponse>), HttpError> {
    let account = NewAccount::new(
        &body.username,
        &body.display_name,
        body.temporary_password,
        to_role(body.role)?,
    )?;
    let created = state.admin().create(&user, account).await?;
    Ok((StatusCode::CREATED, details(to_user(&created))))
}

/// One account.
#[utoipa::path(
    get,
    path = "/admin/users/{id}",
    operation_id = "rustauth_get_user",
    tag = "rustauth.admin",
    security(("bearerAuth" = [])),
    params(("id" = Uuid, Path, description = "User id")),
    responses(
        (status = 200, description = "The account", body = DetailsResponse<UserResponse>),
        (status = 400, description = "Malformed id (`VALIDATION_ERROR`)", body = ErrorResponse),
        (status = 401, description = "Missing, expired, or revoked token (`UNAUTHORIZED`)", body = ErrorResponse),
        (status = 403, description = "Not an administrator (`FORBIDDEN`)", body = ErrorResponse),
        (status = 404, description = "No such account (`ENTITY_NOT_FOUND`)", body = ErrorResponse),
    )
)]
pub(crate) async fn get(
    State(state): State<AuthState>,
    user: AuthUser,
    IdPath(id): IdPath,
) -> Result<Details<UserResponse>, HttpError> {
    let account = state.admin().get(&user, UserId::from(id)).await?;
    Ok(details(to_user(&account)))
}

/// Changes display name, role, disabled state, or password. Any change signs the account out
/// everywhere, and a new password also clears a lockout.
#[utoipa::path(
    patch,
    path = "/admin/users/{id}",
    operation_id = "rustauth_update_user",
    tag = "rustauth.admin",
    security(("bearerAuth" = [])),
    params(("id" = Uuid, Path, description = "User id")),
    request_body = UpdateUserRequest,
    responses(
        (status = 200, description = "The updated account", body = DetailsResponse<UserResponse>),
        (status = 400, description = "Invalid input (`VALIDATION_ERROR` with `field`)", body = ErrorResponse),
        (status = 401, description = "Missing, expired, or revoked token (`UNAUTHORIZED`)", body = ErrorResponse),
        (status = 403, description = "Not an administrator (`FORBIDDEN`)", body = ErrorResponse),
        (status = 404, description = "No such account (`ENTITY_NOT_FOUND`)", body = ErrorResponse),
        (status = 422, description = "Would leave no enabled administrator (`LAST_ADMINISTRATOR`)", body = ErrorResponse),
    )
)]
pub(crate) async fn update(
    State(state): State<AuthState>,
    user: AuthUser,
    IdPath(id): IdPath,
    JsonBody(body): JsonBody<UpdateUserRequest>,
) -> Result<Details<UserResponse>, HttpError> {
    let mut changes = UserChanges::new();
    if let Some(display_name) = &body.display_name {
        changes = changes.display_name(DisplayName::new(display_name)?);
    }
    if let Some(role) = body.role {
        changes = changes.role(to_role(role)?);
    }
    if let Some(disabled) = body.disabled {
        changes = changes.disabled(disabled);
    }
    if let Some(password) = body.password {
        changes = changes.password(Password::new(password)?);
    }
    let account = state
        .admin()
        .update(&user, UserId::from(id), changes)
        .await?;
    Ok(details(to_user(&account)))
}

/// Clears the account's lockout so the person can sign in again at once.
#[utoipa::path(
    post,
    path = "/admin/users/{id}/unlock",
    operation_id = "rustauth_unlock_user",
    tag = "rustauth.admin",
    security(("bearerAuth" = [])),
    params(("id" = Uuid, Path, description = "User id")),
    responses(
        (status = 204, description = "Unlocked"),
        (status = 400, description = "Malformed id (`VALIDATION_ERROR`)", body = ErrorResponse),
        (status = 401, description = "Missing, expired, or revoked token (`UNAUTHORIZED`)", body = ErrorResponse),
        (status = 403, description = "Not an administrator (`FORBIDDEN`)", body = ErrorResponse),
        (status = 404, description = "No such account (`ENTITY_NOT_FOUND`)", body = ErrorResponse),
    )
)]
pub(crate) async fn unlock(
    State(state): State<AuthState>,
    user: AuthUser,
    IdPath(id): IdPath,
) -> Result<StatusCode, HttpError> {
    state.admin().unlock(&user, UserId::from(id)).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Deletes the account with its sessions. Application rows that reference `auth.users (id)`
/// with `ON DELETE CASCADE` go with it.
#[utoipa::path(
    delete,
    path = "/admin/users/{id}",
    operation_id = "rustauth_delete_user",
    tag = "rustauth.admin",
    security(("bearerAuth" = [])),
    params(("id" = Uuid, Path, description = "User id")),
    responses(
        (status = 204, description = "Deleted"),
        (status = 400, description = "Malformed id (`VALIDATION_ERROR`)", body = ErrorResponse),
        (status = 401, description = "Missing, expired, or revoked token (`UNAUTHORIZED`)", body = ErrorResponse),
        (status = 403, description = "Not an administrator (`FORBIDDEN`)", body = ErrorResponse),
        (status = 404, description = "No such account (`ENTITY_NOT_FOUND`)", body = ErrorResponse),
        (status = 422, description = "Would leave no enabled administrator (`LAST_ADMINISTRATOR`)", body = ErrorResponse),
    )
)]
pub(crate) async fn delete(
    State(state): State<AuthState>,
    user: AuthUser,
    IdPath(id): IdPath,
) -> Result<StatusCode, HttpError> {
    state.admin().delete(&user, UserId::from(id)).await?;
    Ok(StatusCode::NO_CONTENT)
}
