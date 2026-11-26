//! The `X-Request-Id` header, echoed as `requestId` in error bodies so clients can quote it and
//! operators can find the matching log lines.

use axum::extract::Request;
use axum::http::{HeaderMap, HeaderName};
use axum::middleware::Next;
use axum::response::Response;

/// The request header whose value error bodies echo as `requestId`.
pub const REQUEST_ID_HEADER: HeaderName = HeaderName::from_static("x-request-id");

/// Longest request id echoed; longer values are ignored.
const MAX_CHARS: usize = 128;

tokio::task_local! {
    /// The request id of the request the auth router is handling.
    static CURRENT: Option<String>;
}

/// The `X-Request-Id` header when it is present, printable ASCII, and at most 128 characters.
pub fn request_id(headers: &HeaderMap) -> Option<String> {
    let value = headers.get(REQUEST_ID_HEADER)?.to_str().ok()?.trim();
    (!value.is_empty() && value.len() <= MAX_CHARS).then(|| value.to_owned())
}

/// Layer function of the auth router: keeps the request id available to the error responses of
/// the request's handlers and extractors.
pub(crate) async fn scope(request: Request, next: Next) -> Response {
    let id = request_id(request.headers());
    CURRENT.scope(id, next.run(request)).await
}

/// The request id of the request in progress, inside the auth router.
pub(crate) fn current() -> Option<String> {
    CURRENT.try_with(Clone::clone).ok().flatten()
}

#[cfg(test)]
mod tests {
    use axum::http::HeaderValue;

    use super::*;

    fn headers(value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            REQUEST_ID_HEADER,
            HeaderValue::from_str(value).expect("valid header"),
        );
        headers
    }

    #[test]
    fn reads_the_header() {
        assert_eq!(request_id(&headers("req-1")), Some("req-1".to_owned()));
        assert_eq!(request_id(&headers(" req-2 ")), Some("req-2".to_owned()));
        assert_eq!(request_id(&HeaderMap::new()), None);
    }

    #[test]
    fn ignores_blank_and_oversized_values() {
        assert_eq!(request_id(&headers("  ")), None);
        assert_eq!(request_id(&headers(&"a".repeat(129))), None);
        assert!(request_id(&headers(&"a".repeat(128))).is_some());
    }

    #[tokio::test]
    async fn is_available_inside_the_scope_only() {
        assert_eq!(current(), None);
        let inside = CURRENT
            .scope(Some("req-3".to_owned()), async { current() })
            .await;
        assert_eq!(inside.as_deref(), Some("req-3"));
    }
}
