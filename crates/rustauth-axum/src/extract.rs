//! Extractors: `AuthUser` (wraps the core `Principal`) and `OptionalAuthUser` for handlers behind
//! the guard, plus the body, query, and path extractors of the auth routes, which fail with the
//! shared error body instead of axum's plain text.

use std::convert::Infallible;
use std::ops::Deref;

use axum::extract::rejection::JsonRejection;
use axum::extract::{FromRequest, FromRequestParts, Path, Query, Request};
use axum::http::StatusCode;
use axum::http::request::Parts;
use rustauth_core::{AuthError, AuthResult, ClientInfo, Principal, Role};
use serde::de::DeserializeOwned;
use uuid::Uuid;

use crate::error::HttpError;
use crate::ip::client_info;
use crate::request_id::request_id;
use crate::state::AuthState;

/// The signed-in caller, inserted by the guard. Derefs to the core [`Principal`] (`user_id`,
/// `username`, `role`, `session_id`, `assurance`), which is rebuilt from the database on every
/// request.
///
/// As an extractor it answers `401` when the guard let an anonymous request through
/// ([`crate::Guard::optional`]), and `500` (logged as `rustauth.guard.missing`) when no guard
/// runs in front of the route, which is a wiring mistake.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthUser(Principal);

impl AuthUser {
    /// Wraps a principal. Applications use it in tests, to insert a caller without a guard.
    pub fn new(principal: Principal) -> Self {
        Self(principal)
    }

    pub fn principal(&self) -> &Principal {
        &self.0
    }

    pub fn into_principal(self) -> Principal {
        self.0
    }

    /// Whether the caller has `minimum` or a higher role.
    pub fn has_role(&self, minimum: Role) -> bool {
        self.0.has_role(minimum)
    }

    /// Fails with [`AuthError::Forbidden`] (`403`) unless the caller has `minimum` or a higher
    /// role: `user.require(Role::Manager)?;` in a handler whose error type converts `AuthError`.
    pub fn require(&self, minimum: Role) -> AuthResult<()> {
        self.0.require(minimum)
    }
}

impl Deref for AuthUser {
    type Target = Principal;

    fn deref(&self) -> &Principal {
        &self.0
    }
}

impl From<AuthUser> for Principal {
    fn from(user: AuthUser) -> Self {
        user.0
    }
}

impl<S: Send + Sync> FromRequestParts<S> for AuthUser {
    type Rejection = HttpError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        if let Some(user) = parts.extensions.get::<AuthUser>() {
            return Ok(user.clone());
        }
        let error = if parts.extensions.get::<Guarded>().is_some() {
            AuthError::Unauthorized
        } else {
            missing_guard()
        };
        Err(HttpError::from(error).with_request_id(request_id(&parts.headers)))
    }
}

/// The caller when the request carries a valid token, `None` otherwise. For routes behind
/// `auth.guard().optional()`; without a guard in front it fails like [`AuthUser`].
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct OptionalAuthUser(pub Option<AuthUser>);

impl<S: Send + Sync> FromRequestParts<S> for OptionalAuthUser {
    type Rejection = HttpError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        if parts.extensions.get::<Guarded>().is_none() {
            return Err(
                HttpError::from(missing_guard()).with_request_id(request_id(&parts.headers))
            );
        }
        Ok(Self(parts.extensions.get::<AuthUser>().cloned()))
    }
}

/// Marks a request the guard has seen, so the extractors can tell an anonymous request from a
/// route without a guard.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Guarded;

fn missing_guard() -> AuthError {
    AuthError::internal(
        "rustauth.guard.missing",
        "AuthUser and OptionalAuthUser need the rustauth guard layer in front of the route",
    )
}

/// JSON request body. Malformed JSON or missing fields answer `400` (`VALIDATION_ERROR`, field
/// `body`), an oversized body `413`, and a missing JSON content type `415`.
#[derive(Clone, Copy, Debug, Default)]
pub struct JsonBody<T>(pub T);

impl<S, T> FromRequest<S> for JsonBody<T>
where
    S: Send + Sync,
    T: DeserializeOwned,
{
    type Rejection = HttpError;

    async fn from_request(request: Request, state: &S) -> Result<Self, Self::Rejection> {
        match axum::Json::<T>::from_request(request, state).await {
            Ok(axum::Json(value)) => Ok(Self(value)),
            Err(rejection) => Err(reject(&rejection)),
        }
    }
}

fn reject(rejection: &JsonRejection) -> HttpError {
    match rejection.status() {
        StatusCode::PAYLOAD_TOO_LARGE => HttpError::transport(
            StatusCode::PAYLOAD_TOO_LARGE,
            "Request body is too large.",
            "PAYLOAD_TOO_LARGE",
        ),
        StatusCode::UNSUPPORTED_MEDIA_TYPE => HttpError::transport(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "Request body must be JSON (Content-Type: application/json).",
            "UNSUPPORTED_MEDIA_TYPE",
        ),
        _ => HttpError::from(AuthError::validation("body", rejection.body_text())),
    }
}

/// Query string parameters; invalid ones answer `400` (`VALIDATION_ERROR`, field `query`).
#[derive(Clone, Copy, Debug, Default)]
pub struct QueryParams<T>(pub T);

impl<S, T> FromRequestParts<S> for QueryParams<T>
where
    S: Send + Sync,
    T: DeserializeOwned,
{
    type Rejection = HttpError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        match Query::<T>::from_request_parts(parts, state).await {
            Ok(Query(value)) => Ok(Self(value)),
            Err(rejection) => Err(HttpError::from(AuthError::validation(
                "query",
                rejection.body_text(),
            ))),
        }
    }
}

/// The `{id}` path parameter as a UUID; anything else answers `400` (`VALIDATION_ERROR`, field
/// `id`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct IdPath(pub Uuid);

impl<S: Send + Sync> FromRequestParts<S> for IdPath {
    type Rejection = HttpError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let invalid = || HttpError::from(AuthError::validation("id", "Id must be a UUID."));
        let Path(value) = Path::<String>::from_request_parts(parts, state)
            .await
            .map_err(|_| invalid())?;
        Uuid::parse_str(&value).map(Self).map_err(|_| invalid())
    }
}

/// Where the request came from (client IP after trusted-proxy resolution, user agent).
#[derive(Clone, Debug)]
pub(crate) struct Client(pub ClientInfo);

impl FromRequestParts<AuthState> for Client {
    type Rejection = Infallible;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AuthState,
    ) -> Result<Self, Self::Rejection> {
        Ok(Self(client_info(
            &parts.extensions,
            &parts.headers,
            state.proxies(),
        )))
    }
}
