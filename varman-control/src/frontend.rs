//! Embedded frontend asset serving.
//!
//! The React dashboard is compiled into `web/dist/` and embedded into the
//! binary at compile time via `rust-embed`. This module provides an Axum
//! fallback handler that serves those assets, with SPA routing support
//! (any unmatched path returns `index.html`).

use axum::body::Body;
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use rust_embed::RustEmbed;

#[derive(RustEmbed)]
#[folder = "../web/dist/"]
struct FrontendAssets;

/// Serve an embedded static file, or fall back to `index.html` for SPA routing.
///
/// This handler is mounted as the router's fallback so that:
/// - Known static assets (JS, CSS, images) are served with proper MIME types
/// - Unknown paths return `index.html` so the React router can handle them
/// - API routes are unaffected (they are matched before the fallback)
pub async fn serve_frontend(uri: axum::http::Uri) -> Response {
    let path = uri.path().trim_start_matches('/');

    // Try to serve the exact file first
    if let Some(file) = FrontendAssets::get(path) {
        return build_asset_response(file, path);
    }

    // SPA fallback: serve index.html for non-API, non-asset paths
    if let Some(index) = FrontendAssets::get("index.html") {
        return build_asset_response(index, "index.html");
    }

    // No frontend embedded (e.g. web/dist/ was empty at build time)
    (
        StatusCode::NOT_FOUND,
        [(header::CONTENT_TYPE, "application/json")],
        Body::from(r#"{"error":{"code":"not_found","message":"no frontend assets embedded"}}"#),
    )
        .into_response()
}

fn build_asset_response(
    file: rust_embed::EmbeddedFile,
    _path: &str,
) -> Response {
    // rust-embed's mime-guess feature provides mimetype()
    let content_type = file.metadata.mimetype().to_string();

    // HTML files should not be cached (they reference hashed asset filenames)
    let cache_control = if content_type.contains("text/html") {
        "no-cache, no-store, must-revalidate"
    } else {
        // Static assets with content hashes can be cached aggressively
        "public, max-age=31536000, immutable"
    };

    // Use the file length and a simple hash as ETag
    let hash = file.metadata.sha256_hash();
    let etag = format!(
        "\"{:x}-{:02x}{:02x}{:02x}{:02x}\"",
        file.data.len(),
        hash[0],
        hash[1],
        hash[2],
        hash[3]
    );

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, &content_type)
        .header(header::CACHE_CONTROL, cache_control)
        .header(header::ETAG, &etag)
        .body(Body::from(file.data.to_vec()))
        .unwrap_or_else(|_| {
            (StatusCode::INTERNAL_SERVER_ERROR, "internal error")
                .into_response()
        })
}
