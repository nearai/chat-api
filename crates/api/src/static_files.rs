use axum::{
    body::Body,
    http::{header, StatusCode, Uri},
    response::{IntoResponse, Response},
};
use rust_embed::RustEmbed;

/// Embedded static assets from the React frontend build
#[derive(RustEmbed)]
#[folder = "frontend/dist"]
pub struct Assets;

/// Serve static files with SPA fallback
///
/// This handler serves embedded static files and falls back to index.html
/// for any route that doesn't match a static asset (SPA routing).
pub async fn static_handler(uri: Uri) -> impl IntoResponse {
    let path = uri.path().trim_start_matches('/');

    // Try to serve the requested file
    if let Some(content) = Assets::get(path) {
        return serve_asset(path, content);
    }

    // If path is empty or doesn't exist, try adding index.html
    let index_path = if path.is_empty() || path == "/" {
        "index.html"
    } else {
        // For SPA routing, check if we should fall back to index.html
        // We do this for paths that don't have an extension (likely routes)
        if !path.contains('.') {
            "index.html"
        } else {
            // If it has an extension but wasn't found, return 404
            return not_found();
        }
    };

    // Try to serve index.html
    if let Some(content) = Assets::get(index_path) {
        return serve_asset(index_path, content);
    }

    // If even index.html is not found, return 404
    not_found()
}

/// Serve an embedded asset with appropriate headers
fn serve_asset(path: &str, content: rust_embed::EmbeddedFile) -> Response {
    let mime_type = mime_guess::from_path(path).first_or_octet_stream();

    let mut response = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, mime_type.as_ref());

    // Add cache headers for assets (except HTML files for SPA)
    if !path.ends_with(".html") {
        response = response.header(header::CACHE_CONTROL, "public, max-age=31536000, immutable");
    } else {
        // Don't cache HTML files to allow for SPA updates
        response = response.header(header::CACHE_CONTROL, "no-cache");
    }

    response.body(Body::from(content.data)).unwrap()
}

/// Return a 404 Not Found response
fn not_found() -> Response {
    Response::builder()
        .status(StatusCode::NOT_FOUND)
        .body(Body::from("Not Found"))
        .unwrap()
}
