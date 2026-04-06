//! Embedded web UI serving via rust-embed.
//!
//! Static frontend assets are compiled into the binary at build time.
//! The UI is a lightweight SPA that connects to the REST API and SSE stream.
//!
//! During development, when the `ui/dist` directory doesn't exist yet,
//! the server returns a placeholder page with setup instructions.

use axum::http::{StatusCode, header};
use axum::response::{Html, IntoResponse, Response};
use rust_embed::Embed;

/// Embedded static assets from the `ui/dist` directory.
///
/// When building the crate, `rust-embed` includes all files from this path.
/// If the directory doesn't exist, the embed is empty and we fall back to
/// the placeholder page.
#[derive(Embed)]
#[folder = "ui/dist"]
#[allow(clippy::upper_case_acronyms)]
struct Assets;

/// Serve an embedded static file by path.
///
/// Falls back to `index.html` for SPA client-side routing (any path that
/// doesn't match a static file gets the SPA shell).
pub async fn serve_ui(uri: axum::http::Uri) -> Response {
    let path = uri.path().trim_start_matches('/');

    // Try exact path first, then fall back to index.html for SPA routing
    let file = if path.is_empty() {
        Assets::get("index.html")
    } else {
        Assets::get(path).or_else(|| Assets::get("index.html"))
    };

    match file {
        Some(content) => {
            let mime = mime_guess::from_path(path)
                .first_or_octet_stream()
                .to_string();

            (
                StatusCode::OK,
                [(header::CONTENT_TYPE, mime)],
                content.data.into_owned(),
            )
                .into_response()
        }
        None => {
            // No UI built yet — serve a helpful placeholder
            Html(placeholder_html()).into_response()
        }
    }
}

/// Full SPA — single HTML file with embedded CSS + JS.
/// No build tooling, no npm, no CDN. Pure vanilla JS.
fn placeholder_html() -> String {
    include_str!("inspector_ui.html").to_string()
}
