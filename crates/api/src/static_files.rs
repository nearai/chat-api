use axum::{
    body::Body,
    http::{header, StatusCode, Uri},
    response::{IntoResponse, Response},
};
use std::path::PathBuf;

/// Path to the frontend static files directory
pub const FRONTEND_DIR: &str = "crates/api/frontend/dist";

/// Static file handler with SPA fallback
///
/// This handler:
/// 1. First tries to serve the requested file from the filesystem
/// 2. If the file doesn't exist, serves index.html for SPA routing
/// 3. Returns 404 only if index.html is also missing
pub async fn static_file_handler(uri: Uri) -> impl IntoResponse {
    let requested_path = uri.path().trim_start_matches('/');
    let base_dir = PathBuf::from(FRONTEND_DIR);

    // Try to serve the requested file
    if !requested_path.is_empty() {
        let file_path = base_dir.join(requested_path);

        // Security: prevent directory traversal
        if !file_path.starts_with(&base_dir) {
            return not_found();
        }

        // Check if it's a file (not a directory) and exists
        if file_path.is_file() {
            if let Ok(content) = tokio::fs::read(&file_path).await {
                return serve_file(requested_path, content);
            }
        }
    }

    // SPA fallback: serve index.html for routes that don't match files
    let index_path = base_dir.join("index.html");
    match tokio::fs::read(&index_path).await {
        Ok(content) => Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
            .header(header::CACHE_CONTROL, "no-cache")
            .body(Body::from(content))
            .expect("Failed to build response for index.html"),
        Err(_) => not_found(),
    }
}

/// Serve a file with appropriate headers
fn serve_file(path: &str, content: Vec<u8>) -> Response {
    let mime_type = mime_guess::from_path(path).first_or_octet_stream();

    let mut response = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, mime_type.as_ref());

    // Add cache headers for assets (except HTML files for SPA)
    if !path.ends_with(".html") {
        response = response.header(header::CACHE_CONTROL, "public, max-age=604800, immutable");
    } else {
        // Don't cache HTML files to allow for SPA updates
        response = response.header(header::CACHE_CONTROL, "no-cache");
    }

    response
        .body(Body::from(content))
        .expect("Failed to build response for static file")
}

/// Return a 404 Not Found response
fn not_found() -> Response {
    Response::builder()
        .status(StatusCode::NOT_FOUND)
        .body(Body::from("Not Found"))
        .expect("Failed to build 404 Not Found response")
}
