//! `AuthError` to HTTP: status code, `Retry-After` where it applies, and the `ErrorResponse` body
//! with the request id from `X-Request-Id`.
//!
//! | `AuthError` | Status | Code |
//! | --- | --- | --- |
//! | `InvalidCredentials` | 401 | `INVALID_CREDENTIALS` |
//! | `Unauthorized` | 401 | `UNAUTHORIZED` |
//! | `Forbidden` | 403 | `FORBIDDEN` |
//! | `Validation` | 400 | `VALIDATION_ERROR` (with `field`) |
//! | `NotFound` | 404 | `ENTITY_NOT_FOUND` (with `details.entityName`) |
//! | `UsernameTaken` | 409 | `USERNAME_TAKEN` |
//! | `SetupRequired`, `RegistrationClosed` | 403 | `SETUP_REQUIRED`, `REGISTRATION_CLOSED` |
//! | `LastAdministrator` | 422 | `LAST_ADMINISTRATOR` |
//! | `RateLimited`, `AccountLocked` | 429 + `Retry-After` | `RATE_LIMITED`, `ACCOUNT_LOCKED` (with `details.retryAfterSecs`) |
//! | `Internal` | 500 | `INTERNAL_ERROR` (generic message; the key and source go to the log) |
//!
//! `401` responses carry `WWW-Authenticate: Bearer`.

use std::collections::BTreeMap;
use std::error::Error as _;

use axum::Json;
use axum::http::header::{RETRY_AFTER, WWW_AUTHENTICATE};
use axum::http::{HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use rustauth_contracts::ErrorResponse;
use rustauth_core::AuthError;
use serde_json::Value;

use crate::request_id::current;

/// What clients see instead of an internal error's key and source.
const INTERNAL_MESSAGE: &str = "An unexpected error occurred.";

/// The error type of every auth route, extractor, and the guard: an [`AuthError`] (or a
/// transport rejection such as an oversized body) that answers with the shared error body.
///
/// Handlers return `Result<_, HttpError>` and `?` converts an `AuthError`.
#[derive(Debug)]
pub struct HttpError {
    kind: Kind,
    request_id: Option<String>,
}

#[derive(Debug)]
enum Kind {
    Auth(AuthError),
    /// A rejection before any service ran, with its own status.
    Transport {
        status: StatusCode,
        body: ErrorResponse,
    },
}

impl HttpError {
    /// A rejection that is not an `AuthError`, for example `413` for an oversized body.
    pub fn transport(status: StatusCode, message: &str, code: &str) -> Self {
        Self {
            kind: Kind::Transport {
                status,
                body: ErrorResponse::new(message, code),
            },
            request_id: None,
        }
    }

    /// Sets the request id the body echoes. Inside the auth router it defaults to the
    /// `X-Request-Id` header of the request being handled.
    #[must_use]
    pub fn with_request_id(mut self, request_id: Option<String>) -> Self {
        self.request_id = request_id;
        self
    }

    pub fn status(&self) -> StatusCode {
        match &self.kind {
            Kind::Auth(error) => status(error),
            Kind::Transport { status, .. } => *status,
        }
    }

    /// The service error, unless this is a transport rejection.
    pub fn error(&self) -> Option<&AuthError> {
        match &self.kind {
            Kind::Auth(error) => Some(error),
            Kind::Transport { .. } => None,
        }
    }

    /// The service error, for applications that map it into their own error type.
    pub fn into_error(self) -> Option<AuthError> {
        match self.kind {
            Kind::Auth(error) => Some(error),
            Kind::Transport { .. } => None,
        }
    }

    /// The response body, with `requestId` filled in.
    pub fn body(&self) -> ErrorResponse {
        let mut body = match &self.kind {
            Kind::Auth(error) => body(error),
            Kind::Transport { body, .. } => body.clone(),
        };
        body.request_id = self.request_id.clone().or_else(current);
        body
    }
}

impl From<AuthError> for HttpError {
    fn from(error: AuthError) -> Self {
        Self {
            kind: Kind::Auth(error),
            request_id: None,
        }
    }
}

impl IntoResponse for HttpError {
    fn into_response(self) -> Response {
        let status = self.status();
        let body = self.body();
        log(&self, status, &body);
        let mut response = (status, Json(body)).into_response();
        let headers = response.headers_mut();
        if let Some(secs) = self.error().and_then(AuthError::retry_after_secs) {
            headers.insert(RETRY_AFTER, HeaderValue::from(secs));
        }
        if status == StatusCode::UNAUTHORIZED {
            headers.insert(WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
        }
        response
    }
}

/// The status code for `error`. Variants added in later releases map to `500` until this crate
/// learns them.
pub fn status(error: &AuthError) -> StatusCode {
    match error {
        AuthError::InvalidCredentials | AuthError::Unauthorized => StatusCode::UNAUTHORIZED,
        AuthError::Forbidden { .. } | AuthError::SetupRequired | AuthError::RegistrationClosed => {
            StatusCode::FORBIDDEN
        }
        AuthError::Validation { .. } => StatusCode::BAD_REQUEST,
        AuthError::NotFound { .. } => StatusCode::NOT_FOUND,
        AuthError::UsernameTaken => StatusCode::CONFLICT,
        AuthError::LastAdministrator => StatusCode::UNPROCESSABLE_ENTITY,
        AuthError::RateLimited { .. } | AuthError::AccountLocked { .. } => {
            StatusCode::TOO_MANY_REQUESTS
        }
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

/// The error body for `error`, without `requestId`. Server errors get a generic message, so the
/// internal key and source never reach clients.
pub fn body(error: &AuthError) -> ErrorResponse {
    if status(error).is_server_error() {
        return ErrorResponse::new(INTERNAL_MESSAGE, "INTERNAL_ERROR");
    }
    let mut body = ErrorResponse::new(error.to_string(), error.code());
    match error {
        AuthError::Validation { field, .. } => body.field = Some(field.clone()),
        AuthError::NotFound { entity } => {
            body.details = Some(BTreeMap::from([(
                "entityName".to_owned(),
                Value::from(*entity),
            )]));
        }
        _ => {}
    }
    if let Some(secs) = error.retry_after_secs() {
        body.details = Some(BTreeMap::from([(
            "retryAfterSecs".to_owned(),
            Value::from(secs),
        )]));
    }
    body
}

fn log(error: &HttpError, status: StatusCode, body: &ErrorResponse) {
    let status_code = status.as_u16();
    let code = body.code.as_deref();
    let request_id = body.request_id.as_deref();
    if status.is_server_error() {
        let (reason, source) = match &error.kind {
            Kind::Auth(error) => (error.to_string(), error.source().map(ToString::to_string)),
            Kind::Transport { body, .. } => (body.error.clone(), None),
        };
        tracing::error!(
            status = status_code,
            code,
            reason,
            source,
            request_id,
            "rustauth.http.internal-error"
        );
    } else {
        tracing::debug!(
            status = status_code,
            code,
            request_id,
            "rustauth.http.client-error"
        );
    }
}

#[cfg(test)]
mod tests {
    use http_body_util::BodyExt;
    use serde_json::json;

    use super::*;

    async fn respond(error: HttpError) -> (StatusCode, axum::http::HeaderMap, Value) {
        let response = error.into_response();
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = response
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes();
        (
            status,
            headers,
            serde_json::from_slice(&bytes).expect("json body"),
        )
    }

    #[test]
    fn maps_every_variant_to_its_status() {
        let cases = [
            (AuthError::InvalidCredentials, 401),
            (AuthError::Unauthorized, 401),
            (AuthError::forbidden("No."), 403),
            (AuthError::validation("username", "Bad."), 400),
            (AuthError::not_found("User"), 404),
            (AuthError::UsernameTaken, 409),
            (AuthError::SetupRequired, 403),
            (AuthError::RegistrationClosed, 403),
            (AuthError::LastAdministrator, 422),
            (
                AuthError::RateLimited {
                    retry_after_secs: 3,
                },
                429,
            ),
            (
                AuthError::AccountLocked {
                    retry_after_secs: 900,
                },
                429,
            ),
            (
                AuthError::internal("rustauth.users.get.failed", "boom"),
                500,
            ),
        ];
        for (error, code) in cases {
            assert_eq!(status(&error).as_u16(), code, "{error:?}");
        }
    }

    #[test]
    fn validation_names_the_field() {
        let body = body(&AuthError::validation("username", "Username is too short."));
        assert_eq!(
            serde_json::to_value(body).expect("serializes"),
            json!({
                "error": "Username is too short.",
                "code": "VALIDATION_ERROR",
                "field": "username",
            })
        );
    }

    #[test]
    fn not_found_names_the_entity() {
        let body = body(&AuthError::not_found("Session"));
        assert_eq!(body.error, "Session not found.");
        assert_eq!(body.code.as_deref(), Some("ENTITY_NOT_FOUND"));
        assert_eq!(
            body.details.expect("details")["entityName"],
            json!("Session")
        );
    }

    #[tokio::test]
    async fn locked_accounts_answer_429_with_retry_after() {
        let error = HttpError::from(AuthError::AccountLocked {
            retry_after_secs: 900,
        });
        let (status, headers, body) = respond(error).await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(headers[RETRY_AFTER], "900");
        assert_eq!(
            body,
            json!({
                "error": "Too many failed sign-in attempts. Try again in 15 minutes.",
                "code": "ACCOUNT_LOCKED",
                "details": { "retryAfterSecs": 900 },
            })
        );
    }

    #[tokio::test]
    async fn internal_errors_hide_their_key_and_source() {
        let error = HttpError::from(AuthError::internal(
            "rustauth.users.get.failed",
            "password authentication failed for user postgres",
        ));
        let (status, headers, body) = respond(error).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert!(headers.get(RETRY_AFTER).is_none());
        assert_eq!(
            body,
            json!({ "error": "An unexpected error occurred.", "code": "INTERNAL_ERROR" })
        );
    }

    #[tokio::test]
    async fn unauthorized_asks_for_a_bearer_token_and_echoes_the_request_id() {
        let error = HttpError::from(AuthError::Unauthorized).with_request_id(Some("req-9".into()));
        let (status, headers, body) = respond(error).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(headers[WWW_AUTHENTICATE], "Bearer");
        assert_eq!(body["requestId"], "req-9");
        assert_eq!(body["code"], "UNAUTHORIZED");
    }

    #[tokio::test]
    async fn transport_rejections_keep_their_status() {
        let error = HttpError::transport(
            StatusCode::PAYLOAD_TOO_LARGE,
            "Request body is too large.",
            "PAYLOAD_TOO_LARGE",
        );
        assert!(error.error().is_none());
        let (status, _, body) = respond(error).await;
        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(body["code"], "PAYLOAD_TOO_LARGE");
    }

    #[test]
    fn hands_back_the_service_error() {
        let error = HttpError::from(AuthError::UsernameTaken);
        assert_eq!(error.status(), StatusCode::CONFLICT);
        assert!(matches!(error.into_error(), Some(AuthError::UsernameTaken)));
    }
}
