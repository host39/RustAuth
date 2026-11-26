//! `/auth/*`: setup status, registration, sign-in, and the caller's own account and sessions.

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use rustauth_contracts::{
    ChangePasswordRequest, DetailsResponse, ErrorResponse, ListResponse, LoginRequest,
    RegisterRequest, SessionResponse, SetupStatusResponse, SignInResponse, UpdateProfileRequest,
    UserResponse,
};
use rustauth_core::{DisplayName, Password, Registration, SessionId};

use crate::error::HttpError;
use crate::extract::{AuthUser, Client, IdPath, JsonBody};
use crate::routes::convert::{to_session, to_sign_in, to_user};
use crate::state::AuthState;

type Details<T> = Json<DetailsResponse<T>>;

fn details<T>(data: T) -> Details<T> {
    Json(DetailsResponse { data })
}

/// Whether the first account still has to be created, and whether sign-ups are open.
#[utoipa::path(
    get,
    path = "/auth/setup",
    operation_id = "rustauth_setup_status",
    tag = "rustauth.auth",
    responses(
        (status = 200, description = "Setup status", body = DetailsResponse<SetupStatusResponse>),
        (status = 429, description = "Too many requests from this client (`RATE_LIMITED`)", body = ErrorResponse,
            headers(("Retry-After" = u64, description = "Seconds to wait"))),
    )
)]
pub(crate) async fn setup(
    State(state): State<AuthState>,
) -> Result<Details<SetupStatusResponse>, HttpError> {
    let status = state.auth().setup_status().await?;
    Ok(details(SetupStatusResponse {
        needs_setup: status.needs_setup,
        registration_open: status.registration_open,
    }))
}

/// Creates an account and signs it in. The first account needs the setup token and becomes the
/// administrator; later ones need open registration and become plain users.
#[utoipa::path(
    post,
    path = "/auth/register",
    operation_id = "rustauth_register",
    tag = "rustauth.auth",
    request_body = RegisterRequest,
    responses(
        (status = 201, description = "Account created and signed in", body = DetailsResponse<SignInResponse>),
        (status = 400, description = "Invalid input (`VALIDATION_ERROR` with `field`)", body = ErrorResponse),
        (status = 403, description = "Setup token missing or wrong (`SETUP_REQUIRED`), or registration closed (`REGISTRATION_CLOSED`)", body = ErrorResponse),
        (status = 409, description = "Username taken (`USERNAME_TAKEN`)", body = ErrorResponse),
        (status = 429, description = "Too many requests from this client (`RATE_LIMITED`)", body = ErrorResponse,
            headers(("Retry-After" = u64, description = "Seconds to wait"))),
    )
)]
pub(crate) async fn register(
    State(state): State<AuthState>,
    Client(client): Client,
    JsonBody(body): JsonBody<RegisterRequest>,
) -> Result<(StatusCode, Details<SignInResponse>), HttpError> {
    let registration = Registration::new(&body.username, &body.display_name, body.password)?;
    let signed = state
        .auth()
        .register(registration, body.setup_token.as_deref(), &client)
        .await?;
    Ok((StatusCode::CREATED, details(to_sign_in(&signed))))
}

/// Signs in with a username and password.
#[utoipa::path(
    post,
    path = "/auth/login",
    operation_id = "rustauth_login",
    tag = "rustauth.auth",
    request_body = LoginRequest,
    responses(
        (status = 200, description = "Signed in", body = DetailsResponse<SignInResponse>),
        (status = 401, description = "Wrong username or password (`INVALID_CREDENTIALS`)", body = ErrorResponse),
        (status = 403, description = "The account is disabled (`FORBIDDEN`)", body = ErrorResponse),
        (status = 429, description = "Account locked (`ACCOUNT_LOCKED`) or too many requests or failures from this client (`RATE_LIMITED`)", body = ErrorResponse,
            headers(("Retry-After" = u64, description = "Seconds to wait"))),
    )
)]
pub(crate) async fn login(
    State(state): State<AuthState>,
    Client(client): Client,
    JsonBody(body): JsonBody<LoginRequest>,
) -> Result<Details<SignInResponse>, HttpError> {
    let signed = state
        .auth()
        .login(&body.username, body.password, &client)
        .await?;
    Ok(details(to_sign_in(&signed)))
}

/// Signs out the current session.
#[utoipa::path(
    post,
    path = "/auth/logout",
    operation_id = "rustauth_logout",
    tag = "rustauth.auth",
    security(("bearerAuth" = [])),
    responses(
        (status = 204, description = "Signed out"),
        (status = 401, description = "Missing, expired, or revoked token (`UNAUTHORIZED`)", body = ErrorResponse),
    )
)]
pub(crate) async fn logout(
    State(state): State<AuthState>,
    user: AuthUser,
) -> Result<StatusCode, HttpError> {
    state.auth().logout(&user).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// The caller's account.
#[utoipa::path(
    get,
    path = "/auth/me",
    operation_id = "rustauth_get_me",
    tag = "rustauth.auth",
    security(("bearerAuth" = [])),
    responses(
        (status = 200, description = "The caller's account", body = DetailsResponse<UserResponse>),
        (status = 401, description = "Missing, expired, or revoked token (`UNAUTHORIZED`)", body = ErrorResponse),
    )
)]
pub(crate) async fn me(
    State(state): State<AuthState>,
    user: AuthUser,
) -> Result<Details<UserResponse>, HttpError> {
    let account = state.auth().me(&user).await?;
    Ok(details(to_user(&account)))
}

/// Changes the caller's display name.
#[utoipa::path(
    patch,
    path = "/auth/me",
    operation_id = "rustauth_update_me",
    tag = "rustauth.auth",
    security(("bearerAuth" = [])),
    request_body = UpdateProfileRequest,
    responses(
        (status = 200, description = "The updated account", body = DetailsResponse<UserResponse>),
        (status = 400, description = "Invalid display name (`VALIDATION_ERROR`)", body = ErrorResponse),
        (status = 401, description = "Missing, expired, or revoked token (`UNAUTHORIZED`)", body = ErrorResponse),
    )
)]
pub(crate) async fn update_me(
    State(state): State<AuthState>,
    user: AuthUser,
    JsonBody(body): JsonBody<UpdateProfileRequest>,
) -> Result<Details<UserResponse>, HttpError> {
    let display_name = DisplayName::new(&body.display_name)?;
    let account = state.auth().update_profile(&user, display_name).await?;
    Ok(details(to_user(&account)))
}

/// Changes the caller's password and signs out their other sessions.
#[utoipa::path(
    post,
    path = "/auth/password",
    operation_id = "rustauth_change_password",
    tag = "rustauth.auth",
    security(("bearerAuth" = [])),
    request_body = ChangePasswordRequest,
    responses(
        (status = 204, description = "Password changed"),
        (status = 400, description = "Wrong current password or invalid new one (`VALIDATION_ERROR` on `current` or `new`)", body = ErrorResponse),
        (status = 401, description = "Missing, expired, or revoked token (`UNAUTHORIZED`)", body = ErrorResponse),
        (status = 429, description = "Account locked (`ACCOUNT_LOCKED`) or too many failures from this client (`RATE_LIMITED`)", body = ErrorResponse,
            headers(("Retry-After" = u64, description = "Seconds to wait"))),
    )
)]
pub(crate) async fn change_password(
    State(state): State<AuthState>,
    user: AuthUser,
    Client(client): Client,
    JsonBody(body): JsonBody<ChangePasswordRequest>,
) -> Result<StatusCode, HttpError> {
    let new = Password::new(body.new).map_err(|error| error.with_field("new"))?;
    state
        .auth()
        .change_password(&user, body.current, new, &client)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// The caller's active sessions (signed-in devices), most recently used first.
#[utoipa::path(
    get,
    path = "/auth/sessions",
    operation_id = "rustauth_list_sessions",
    tag = "rustauth.auth",
    security(("bearerAuth" = [])),
    responses(
        (status = 200, description = "Active sessions; `current` marks this one", body = ListResponse<SessionResponse>),
        (status = 401, description = "Missing, expired, or revoked token (`UNAUTHORIZED`)", body = ErrorResponse),
    )
)]
pub(crate) async fn sessions(
    State(state): State<AuthState>,
    user: AuthUser,
) -> Result<Json<ListResponse<SessionResponse>>, HttpError> {
    let sessions = state.auth().sessions(&user).await?;
    let items: Vec<SessionResponse> = sessions
        .iter()
        .map(|session| to_session(session, user.session_id))
        .collect();
    Ok(Json(ListResponse {
        total: items.len() as u64,
        items,
    }))
}

/// Signs out one of the caller's sessions.
#[utoipa::path(
    delete,
    path = "/auth/sessions/{id}",
    operation_id = "rustauth_revoke_session",
    tag = "rustauth.auth",
    security(("bearerAuth" = [])),
    params(("id" = Uuid, Path, description = "Session id")),
    responses(
        (status = 204, description = "Session revoked"),
        (status = 400, description = "Malformed id (`VALIDATION_ERROR`)", body = ErrorResponse),
        (status = 401, description = "Missing, expired, or revoked token (`UNAUTHORIZED`)", body = ErrorResponse),
        (status = 404, description = "No such session of the caller (`ENTITY_NOT_FOUND`)", body = ErrorResponse),
    )
)]
pub(crate) async fn revoke(
    State(state): State<AuthState>,
    user: AuthUser,
    IdPath(id): IdPath,
) -> Result<StatusCode, HttpError> {
    state.auth().revoke(&user, SessionId::from(id)).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Signs out every session of the caller except this one.
#[utoipa::path(
    post,
    path = "/auth/sessions/revoke-others",
    operation_id = "rustauth_revoke_other_sessions",
    tag = "rustauth.auth",
    security(("bearerAuth" = [])),
    responses(
        (status = 204, description = "Other sessions revoked"),
        (status = 401, description = "Missing, expired, or revoked token (`UNAUTHORIZED`)", body = ErrorResponse),
    )
)]
pub(crate) async fn revoke_others(
    State(state): State<AuthState>,
    user: AuthUser,
) -> Result<StatusCode, HttpError> {
    state.auth().revoke_others(&user).await?;
    Ok(StatusCode::NO_CONTENT)
}
