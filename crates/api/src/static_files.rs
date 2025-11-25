use axum::{
    body::Body,
    http::{header, Request, StatusCode},
    response::{IntoResponse, Response},
};
use tower::ServiceExt;
use tower_http::services::{ServeDir, ServeFile};

/// Path to the frontend static files directory.
pub const FRONTEND_DIR: &str = "crates/api/frontend/dist";

/// Serve static files with SPA fallback and proper cache headers.
pub async fn static_handler(req: Request<Body>) -> Response {
    let has_extension = req
        .uri()
        .path()
        .rsplit('/')
        .next()
        .map(|segment| segment.contains('.'))
        .unwrap_or(false);

    // Serve static files if they have an extension, otherwise fallback to the index.html file
    let result = if has_extension {
        ServeDir::new(FRONTEND_DIR).oneshot(req).await
    } else {
        ServeDir::new(FRONTEND_DIR)
            .not_found_service(ServeFile::new(
                std::path::Path::new(FRONTEND_DIR).join("index.html"),
            ))
            .oneshot(req)
            .await
    };

    match result {
        Ok(mut res) => {
            if let Some(content_type) = res.headers().get(header::CONTENT_TYPE) {
                let is_html = content_type
                    .to_str()
                    .map(|ct| ct.contains("text/html"))
                    .unwrap_or(false);
                // Don't cache HTML files to allow for SPA updates
                let cache_value = if is_html {
                    "no-cache"
                } else {
                    "public, max-age=31536000, immutable"
                };
                res.headers_mut().insert(
                    header::CACHE_CONTROL,
                    header::HeaderValue::from_static(cache_value),
                );
            }
            res.into_response()
        }
        Err(err) => {
            tracing::error!(error = ?err, "Failed to serve static asset");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}
