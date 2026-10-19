use axum::response::Response;
use http::{header, HeaderValue};

/// Applied outside CORS/auth so API responses, errors and the bundled frontend
/// all receive the same headers. Browsers ignore HSTS on local HTTP development.
pub async fn security_headers(mut response: Response) -> Response {
    let headers = response.headers_mut();
    headers.insert(
        header::STRICT_TRANSPORT_SECURITY,
        HeaderValue::from_static("max-age=31536000; includeSubDomains"),
    );
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    headers
        .entry(header::REFERRER_POLICY)
        .or_insert(HeaderValue::from_static("strict-origin-when-cross-origin"));
    // An additional policy intersects with existing CSP instead of weakening it.
    // Script elements remain governed by the frontend policy: the current wallet
    // SDK requires inline scripts in its sandboxed srcdoc document.
    headers.append(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("frame-ancestors 'none'; script-src-attr 'none'"),
    );
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, middleware::map_response, routing::get, Router};
    use http::{Request, StatusCode};
    use tower::ServiceExt;

    #[tokio::test]
    async fn headers_cover_success_errors_and_fallback_without_replacing_csp() {
        let app = Router::new()
            .route("/ok", get(|| async { "healthy" }))
            .route("/denied", get(|| async { StatusCode::UNAUTHORIZED }))
            .route(
                "/csp",
                get(|| async {
                    [
                        (header::CONTENT_SECURITY_POLICY, "script-src 'self'"),
                        (header::REFERRER_POLICY, "no-referrer"),
                    ]
                }),
            )
            .layer(map_response(security_headers));

        for (path, status) in [
            ("/ok", StatusCode::OK),
            ("/denied", StatusCode::UNAUTHORIZED),
            ("/missing", StatusCode::NOT_FOUND),
            ("/csp", StatusCode::OK),
        ] {
            let response = app
                .clone()
                .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), status);
            assert_eq!(
                response.headers()[header::STRICT_TRANSPORT_SECURITY],
                "max-age=31536000; includeSubDomains"
            );
            assert_eq!(
                response.headers()[header::X_CONTENT_TYPE_OPTIONS],
                "nosniff"
            );
            assert_eq!(response.headers()[header::X_FRAME_OPTIONS], "DENY");
            let policies: Vec<_> = response
                .headers()
                .get_all(header::CONTENT_SECURITY_POLICY)
                .iter()
                .map(|v| v.to_str().unwrap())
                .collect();
            assert!(policies.contains(&"frame-ancestors 'none'; script-src-attr 'none'"));
            if path == "/csp" {
                assert!(policies.contains(&"script-src 'self'"));
                assert_eq!(response.headers()[header::REFERRER_POLICY], "no-referrer");
            }
        }
    }
}
