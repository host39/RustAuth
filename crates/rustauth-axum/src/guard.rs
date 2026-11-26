//! The guard layer: reads `Authorization: Bearer`, calls `AuthService::verify`, and inserts
//! `AuthUser` into the request extensions, or answers `401` with the error body.

use std::convert::Infallible;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use axum::extract::Request;
use axum::http::HeaderMap;
use axum::http::header::AUTHORIZATION;
use axum::response::{IntoResponse, Response};
use rustauth_core::{AuthError, AuthResult, AuthService, Role};
use tower::{Layer, Service};

use crate::error::HttpError;
use crate::extract::{AuthUser, Guarded};
use crate::request_id::{request_id, within};

/// Longest bearer token read; issued tokens have 43 characters.
const MAX_TOKEN_CHARS: usize = 512;

/// A `tower` layer that admits requests with a valid bearer token.
///
/// ```ignore
/// let widgets = OpenApiRouter::new()
///     .routes(routes!(list_widgets, create_widget))
///     .layer(auth.guard());                                 // any signed-in user
/// let reports = OpenApiRouter::new()
///     .routes(routes!(reports))
///     .layer(auth.guard().require(Role::Manager));          // managers and administrators
/// let feed = OpenApiRouter::new()
///     .routes(routes!(feed))
///     .layer(auth.guard().optional());                      // anyone; `OptionalAuthUser` tells
/// ```
///
/// - Without a valid token the guard answers `401` (`UNAUTHORIZED`), and with a role below
///   [`Guard::require`] it answers `403` (`FORBIDDEN`), both with the shared error body.
/// - The session and user are loaded on every request, so a disabled user or a revoked session
///   loses access at once. A request an outer guard already verified is not verified again.
/// - Handlers read the caller with the [`AuthUser`] or `OptionalAuthUser` extractor, and their
///   [`HttpError`] responses echo the `X-Request-Id` header as `requestId`.
#[derive(Clone)]
pub struct Guard {
    auth: Arc<AuthService>,
    optional: bool,
    minimum: Role,
}

impl Guard {
    /// Admits every signed-in user.
    pub fn new(auth: Arc<AuthService>) -> Self {
        Self {
            auth,
            optional: false,
            minimum: Role::User,
        }
    }

    /// Also admits anonymous requests: a missing or invalid token passes without a user (other
    /// failures, such as a database error, still answer with an error). A signed-in user must
    /// still have the role from [`Guard::require`].
    #[must_use]
    pub fn optional(mut self) -> Self {
        self.optional = true;
        self
    }

    /// Admits only users with `minimum` or a higher role; others get `403`.
    #[must_use]
    pub fn require(mut self, minimum: Role) -> Self {
        self.minimum = minimum;
        self
    }

    /// The caller of a request, `None` for an anonymous request the guard lets through.
    /// `verified` is the caller an outer guard found already.
    async fn check(
        &self,
        verified: Option<AuthUser>,
        headers: &HeaderMap,
    ) -> AuthResult<Option<AuthUser>> {
        let user = match verified {
            Some(user) => Some(user),
            None => self.verify(headers).await?,
        };
        if let Some(user) = &user {
            user.require(self.minimum)?;
        }
        Ok(user)
    }

    async fn verify(&self, headers: &HeaderMap) -> AuthResult<Option<AuthUser>> {
        let Some(token) = bearer(headers) else {
            return if self.optional {
                Ok(None)
            } else {
                Err(AuthError::Unauthorized)
            };
        };
        match self.auth.verify(token).await {
            Ok(principal) => Ok(Some(AuthUser::new(principal))),
            Err(AuthError::Unauthorized) if self.optional => Ok(None),
            Err(error) => Err(error),
        }
    }
}

impl fmt::Debug for Guard {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Guard")
            .field("optional", &self.optional)
            .field("minimum", &self.minimum)
            .finish_non_exhaustive()
    }
}

impl<S> Layer<S> for Guard {
    type Service = GuardService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        GuardService {
            inner,
            guard: self.clone(),
        }
    }
}

/// The service [`Guard`] wraps around a route.
#[derive(Clone, Debug)]
pub struct GuardService<S> {
    inner: S,
    guard: Guard,
}

impl<S> Service<Request> for GuardService<S>
where
    S: Service<Request, Error = Infallible> + Clone + Send + 'static,
    S::Response: IntoResponse,
    S::Future: Send + 'static,
{
    type Response = Response;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Response, Infallible>> + Send>>;

    fn poll_ready(&mut self, context: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(context)
    }

    fn call(&mut self, mut request: Request) -> Self::Future {
        // `inner` was polled ready; a fresh clone takes its place for the next call.
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);
        let guard = self.guard.clone();
        Box::pin(async move {
            let id = request_id(request.headers());
            let verified = request.extensions().get::<AuthUser>().cloned();
            match guard.check(verified, request.headers()).await {
                Ok(user) => {
                    request.extensions_mut().insert(Guarded);
                    if let Some(user) = user {
                        request.extensions_mut().insert(user);
                    }
                    // `HttpError` responses of the handlers behind the guard echo the id too.
                    within(id, inner.call(request))
                        .await
                        .map(IntoResponse::into_response)
                }
                Err(error) => Ok(HttpError::from(error).with_request_id(id).into_response()),
            }
        })
    }
}

/// The token of an `Authorization: Bearer <token>` header (scheme in any letter case), or `None`
/// when the header is missing, uses another scheme, or holds no plausible token.
fn bearer(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get(AUTHORIZATION)?.to_str().ok()?;
    let (scheme, token) = value.trim().split_once(' ')?;
    let token = token.trim();
    (scheme.eq_ignore_ascii_case("bearer")
        && !token.is_empty()
        && token.len() <= MAX_TOKEN_CHARS
        && !token.contains(char::is_whitespace))
    .then_some(token)
}

#[cfg(test)]
mod tests {
    use axum::http::HeaderValue;

    use super::*;

    fn headers(value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(value).expect("valid header"),
        );
        headers
    }

    #[test]
    fn reads_bearer_tokens() {
        assert_eq!(bearer(&headers("Bearer abc")), Some("abc"));
        assert_eq!(bearer(&headers("bearer  abc ")), Some("abc"));
        assert_eq!(bearer(&headers("BEARER abc")), Some("abc"));
    }

    #[test]
    fn rejects_other_schemes_and_malformed_tokens() {
        assert_eq!(bearer(&HeaderMap::new()), None);
        assert_eq!(bearer(&headers("Basic YWxpY2U6c2VjcmV0")), None);
        assert_eq!(bearer(&headers("Bearer")), None);
        assert_eq!(bearer(&headers("Bearer ")), None);
        assert_eq!(bearer(&headers("Bearer a b")), None);
        assert_eq!(bearer(&headers("abc")), None);
        assert_eq!(
            bearer(&headers(&format!("Bearer {}", "a".repeat(513)))),
            None
        );
        assert!(bearer(&headers(&format!("Bearer {}", "a".repeat(512)))).is_some());
    }
}
