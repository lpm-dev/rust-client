//! Embedded web UI serving via rust-embed.
//!
//! Static frontend assets are compiled into the binary at build time.
//! The UI is a lightweight SPA that connects to the REST API and SSE stream.
//!
//! During development, when the `ui/dist` directory doesn't exist yet,
//! the server returns a placeholder page with setup instructions.
//!
//! # Auth token handoff
//!
//! The inspector binds to `127.0.0.1:<port>`. Cookies on `127.0.0.1` are
//! **not** port-scoped per RFC 6265 — a cookie set by the inspector at
//! `:4400` would be sent by the browser to any same-host service the
//! user later visits (`localhost:3000`, another dev tool, a malicious
//! local listener bound to a different port). `SameSite=Strict` does
//! not fix this because same-site is about top-level navigation
//! origin, not port isolation.
//!
//! Web Storage (`localStorage` / `sessionStorage`), in contrast, IS
//! port-scoped (per the HTML5 origin definition). So we hand the token
//! off via an inline bootstrap script that:
//!   1. Reads `?token=<X>` from `window.location.search`.
//!   2. Stores the token in `sessionStorage` (cleared on tab close,
//!      stricter than `localStorage` which persists across sessions).
//!   3. Patches `window.fetch` to add `Authorization: Bearer <X>` to
//!      same-origin `/api/*` requests.
//!   4. Patches `EventSource` to append `?token=<X>` to URLs (the SSE
//!      spec has no header-customization API).
//!   5. `history.replaceState`s the address bar to a token-less URL so
//!      the token doesn't leak via screenshots, browser history,
//!      Referer headers, or new-tab inheritance.
//!
//! The bootstrap is injected into the HTML response BEFORE the embedded
//! UI's own scripts run, so by the time the UI calls `fetch()` the
//! `Authorization` header is already auto-attached. Non-HTML assets
//! (JS, CSS, images) are returned unmodified.

use axum::extract::State;
use axum::http::{StatusCode, header};
use axum::response::{Html, IntoResponse, Response};
use rust_embed::Embed;

use crate::state::InspectorState;

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
///
/// HTML responses are post-processed to inject the auth-token bootstrap
/// script (see module-level docs). Non-HTML assets pass through
/// unmodified.
pub async fn serve_ui(State(state): State<InspectorState>, uri: axum::http::Uri) -> Response {
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
            let bytes = content.data.into_owned();
            if mime.starts_with("text/html") {
                let html = String::from_utf8_lossy(&bytes);
                let injected = inject_auth_bootstrap(&html, state.auth_token());
                (
                    StatusCode::OK,
                    [(header::CONTENT_TYPE, mime)],
                    injected.into_bytes(),
                )
                    .into_response()
            } else {
                (StatusCode::OK, [(header::CONTENT_TYPE, mime)], bytes).into_response()
            }
        }
        None => {
            // No UI built yet — serve a helpful placeholder with the
            // bootstrap injected.
            let placeholder = inject_auth_bootstrap(&placeholder_html(), state.auth_token());
            Html(placeholder).into_response()
        }
    }
}

/// Inject the auth-token bootstrap script into an HTML document.
///
/// Inserts at `</head>` if present, otherwise prepends to `<body>`,
/// otherwise prepends to the document. The script is the FIRST thing
/// the browser runs in the document so `fetch` / `EventSource` are
/// patched before the embedded UI's own scripts execute.
fn inject_auth_bootstrap(html: &str, token: &str) -> String {
    let script = build_bootstrap_script(token);
    if let Some(idx) = html.find("</head>") {
        let (before, after) = html.split_at(idx);
        return format!("{before}{script}{after}");
    }
    if let Some(idx) = html.find("<body") {
        let (before, after) = html.split_at(idx);
        return format!("{before}{script}{after}");
    }
    format!("{script}{html}")
}

/// The bootstrap script as a single inline `<script>` tag. The token
/// is embedded directly as a JS string literal; we JSON-encode it
/// defensively so an unexpected character can't break parsing.
fn build_bootstrap_script(token: &str) -> String {
    // JSON-encode the token. Token is hex-only by construction, so
    // this is paranoia; keeps the wire shape stable if that ever
    // changes.
    let token_js = serde_json::to_string(token).unwrap_or_else(|_| "\"\"".to_string());
    format!(
        r#"<script>
(function () {{
  var T = {token_js};
  try {{ sessionStorage.setItem("lpm_inspector_token", T); }} catch (_) {{}}

  // Strip ?token=... from the address bar so the token doesn't leak
  // via screenshots, browser history, Referer headers, or new-tab
  // inheritance. Falls back silently on browsers without
  // history.replaceState (none in practice).
  try {{
    var u = new URL(window.location.href);
    if (u.searchParams.has("token")) {{
      u.searchParams.delete("token");
      window.history.replaceState({{}}, "", u.pathname + (u.search || "") + (u.hash || ""));
    }}
  }} catch (_) {{}}

  // Wrap fetch so every same-origin /api/* request gets Bearer auth
  // without the UI having to thread the token through call sites.
  var origFetch = window.fetch.bind(window);
  window.fetch = function (input, init) {{
    var url = typeof input === "string" ? input : (input && input.url) || "";
    var sameOrigin = false;
    try {{ sameOrigin = new URL(url, window.location.href).origin === window.location.origin; }}
    catch (_) {{ sameOrigin = false; }}
    if (sameOrigin && url.indexOf("/api/") !== -1) {{
      init = init || {{}};
      var headers = new Headers(init.headers || (input instanceof Request ? input.headers : undefined));
      if (!headers.has("Authorization")) headers.set("Authorization", "Bearer " + T);
      init.headers = headers;
    }}
    return origFetch(input, init);
  }};

  // EventSource has no header API, so the SSE auth channel is the
  // query string. Append ?token=... transparently.
  if (typeof window.EventSource === "function") {{
    var OrigES = window.EventSource;
    function PatchedES(url, opts) {{
      try {{
        var u = new URL(url, window.location.href);
        if (u.origin === window.location.origin && !u.searchParams.has("token")) {{
          u.searchParams.set("token", T);
          url = u.toString();
        }}
      }} catch (_) {{}}
      return new OrigES(url, opts);
    }}
    PatchedES.prototype = OrigES.prototype;
    PatchedES.CONNECTING = OrigES.CONNECTING;
    PatchedES.OPEN = OrigES.OPEN;
    PatchedES.CLOSED = OrigES.CLOSED;
    window.EventSource = PatchedES;
  }}
}})();
</script>"#,
    )
}

/// Full SPA — single HTML file with embedded CSS + JS.
/// No build tooling, no npm, no CDN. Pure vanilla JS.
fn placeholder_html() -> String {
    include_str!("inspector_ui.html").to_string()
}
