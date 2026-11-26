//! The `/auth/*` and `/admin/users` routes as a `utoipa_axum` `OpenApiRouter`.
//!
//! [`router`] applies [`AuthState`] itself and returns `OpenApiRouter<S>` for any application
//! state `S`, so applications merge it into their own router (and OpenAPI document) without
//! adding the auth services to their state:
//!
//! ```ignore
//! let (router, openapi) = OpenApiRouter::<AppState>::new()
//!     .nest("/api", auth.router().merge(widget_routes.layer(auth.guard())))
//!     .split_for_parts();
//! let app = router.with_state(app_state);
//! ```

mod admin;
mod auth;
mod convert;

use axum::extract::{Request, State};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use rustauth_core::Role;
use utoipa::openapi::OpenApi;
use utoipa::openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme};
use utoipa::openapi::tag::TagBuilder;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use crate::error::HttpError;
use crate::ip::client_info;
use crate::request_id::scope;
use crate::state::AuthState;

/// Name of the OpenAPI security scheme (`Authorization: Bearer <token>`) the signed-in routes
/// require. Applications can list it on their own guarded routes:
/// `#[utoipa::path(..., security(("bearerAuth" = [])))]`.
pub const SECURITY_SCHEME: &str = "bearerAuth";

/// Every auth route, with its own state applied.
///
/// - Public, rate limited per client IP: `GET /auth/setup`, `POST /auth/register`,
///   `POST /auth/login`.
/// - Signed-in users: `POST /auth/logout`, `GET` and `PATCH /auth/me`, `POST /auth/password`,
///   `GET /auth/sessions`, `DELETE /auth/sessions/{id}`, `POST /auth/sessions/revoke-others`.
/// - Administrators: `GET` and `POST /admin/users`, `GET`, `PATCH`, and `DELETE
///   /admin/users/{id}`, `POST /admin/users/{id}/unlock`.
///
/// Error bodies echo the `X-Request-Id` request header as `requestId`.
pub fn router<S>(state: AuthState) -> OpenApiRouter<S>
where
    S: Clone + Send + Sync + 'static,
{
    let public = OpenApiRouter::default()
        .routes(routes!(auth::setup))
        .routes(routes!(auth::register))
        .routes(routes!(auth::login))
        .route_layer(middleware::from_fn_with_state(state.clone(), limit));
    let signed_in = OpenApiRouter::default()
        .routes(routes!(auth::logout))
        .routes(routes!(auth::me, auth::update_me))
        .routes(routes!(auth::change_password))
        .routes(routes!(auth::sessions))
        .routes(routes!(auth::revoke))
        .routes(routes!(auth::revoke_others))
        .route_layer(state.guard());
    let admin = OpenApiRouter::default()
        .routes(routes!(admin::list, admin::create))
        .routes(routes!(admin::get, admin::update, admin::delete))
        .routes(routes!(admin::unlock))
        .route_layer(state.guard().require(Role::Administrator));
    let mut router = public
        .merge(signed_in)
        .merge(admin)
        .layer(middleware::from_fn(scope));
    document(router.get_openapi_mut());
    router.with_state(state)
}

/// Request rate limit of the public routes, per client IP.
async fn limit(State(state): State<AuthState>, request: Request, next: Next) -> Response {
    let client = client_info(request.extensions(), request.headers(), state.proxies());
    match state.limiter().check(client.ip()) {
        Ok(()) => next.run(request).await,
        Err(error) => HttpError::from(error).into_response(),
    }
}

/// Adds the bearer security scheme and the tag descriptions.
fn document(openapi: &mut OpenApi) {
    openapi
        .components
        .get_or_insert_with(Default::default)
        .add_security_scheme(
            SECURITY_SCHEME,
            SecurityScheme::Http(
                HttpBuilder::new()
                    .scheme(HttpAuthScheme::Bearer)
                    .description(Some(
                        "Session token from `POST /auth/login` or `POST /auth/register`.",
                    ))
                    .build(),
            ),
        );
    openapi.tags = Some(vec![
        TagBuilder::new()
            .name("auth")
            .description(Some(
                "RustAuth: setup, registration, sign-in, and the caller's account and sessions.",
            ))
            .build(),
        TagBuilder::new()
            .name("admin")
            .description(Some(
                "RustAuth: account administration (administrators only).",
            ))
            .build(),
    ]);
}
