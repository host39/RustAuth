//! Minimal axum application that uses RustAuth through the `rustauth` facade.
//!
//! For now it serves `GET /health` only. Once the facade's builder lands, it connects to
//! `DATABASE_URL`, runs `rustauth::migrate`, mounts the auth routes under `/api`, and puts the
//! guard in front of an example `widgets` route.

use std::net::SocketAddr;

use axum::Router;
use axum::routing::get;
use tokio::net::TcpListener;

/// Listen address when `EXAMPLE_ADDR` is not set.
const DEFAULT_ADDR: &str = "127.0.0.1:3100";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt().init();

    let addr: SocketAddr = std::env::var("EXAMPLE_ADDR")
        .unwrap_or_else(|_| DEFAULT_ADDR.to_owned())
        .parse()?;
    let listener = TcpListener::bind(addr).await?;
    tracing::info!(%addr, version = rustauth::VERSION, "example.server.listening");

    axum::serve(listener, app())
        .with_graceful_shutdown(shutdown())
        .await?;
    Ok(())
}

fn app() -> Router {
    Router::new().route("/health", get(health))
}

async fn health() -> &'static str {
    "ok"
}

/// Resolves on Ctrl+C. If the signal handler cannot be installed, the server keeps running.
async fn shutdown() {
    if let Err(error) = tokio::signal::ctrl_c().await {
        tracing::error!(error = %error, "example.server.signal-failed");
        std::future::pending::<()>().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    #[tokio::test]
    async fn health_answers_ok() {
        let request = Request::get("/health")
            .body(Body::empty())
            .expect("valid request");
        let response = app().oneshot(request).await.expect("responds");
        assert_eq!(response.status(), StatusCode::OK);
    }
}
