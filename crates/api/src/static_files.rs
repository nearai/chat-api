use axum::{
    body::Body,
    http::{header, Request, StatusCode},
    response::{IntoResponse, Response},
};
use std::{env, path::PathBuf};
use tower::ServiceExt;
use tower_http::services::{ServeDir, ServeFile};

/// Path to the frontend static files directory.
pub const DEFAULT_FRONTEND_DIR: &str = "crates/api/frontend/dist";

fn frontend_dir() -> PathBuf {
    env::var("FRONTEND_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(DEFAULT_FRONTEND_DIR))
}

/// Serve static files with SPA fallback and proper cache headers.
pub async fn static_handler(req: Request<Body>) -> Response {
    let frontend_dir = frontend_dir();

    let has_extension = req
        .uri()
        .path()
        .rsplit('/')
        .next()
        .map(|segment| segment.contains('.'))
        .unwrap_or(false);

    // Serve static files if they have an extension, otherwise fallback to the index.html file
    let result = if has_extension {
        ServeDir::new(frontend_dir.clone()).oneshot(req).await
    } else {
        ServeDir::new(frontend_dir.clone())
            .not_found_service(ServeFile::new(frontend_dir.join("index.html")))
            .oneshot(req)
            .await
    };

    match result {
        Ok(mut res) => {
            // SPA history-based routing: unknown non-asset routes should return index.html with 200.
            // tower_http's `not_found_service` serves the fallback body but keeps the 404 status.
            // IMPORTANT: When converting 404 to 200 for SPA routes, set no-cache headers to prevent
            // browsers from caching incorrect responses (e.g., API routes that were incorrectly
            // handled as static files).
            if !has_extension && res.status() == StatusCode::NOT_FOUND {
                *res.status_mut() = StatusCode::OK;
                res.headers_mut().insert(
                    header::CACHE_CONTROL,
                    header::HeaderValue::from_static("no-cache, no-store, must-revalidate"),
                );
            }

            if let Some(content_type) = res.headers().get(header::CONTENT_TYPE) {
                let is_html = content_type
                    .to_str()
                    .map(|ct| ct.contains("text/html"))
                    .unwrap_or(false);
                // Don't cache HTML files to allow for SPA updates
                let cache_value = if is_html {
                    "no-cache, no-store, must-revalidate"
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
