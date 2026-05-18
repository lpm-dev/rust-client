//! Embedded web UI serving via rust-embed.
//!
//! Static frontend assets are compiled into the binary at build time.
//! HTML responses are post-processed to inject an inline bootstrap
//! script that reads the `?token=` query param into `sessionStorage`
//! and patches `fetch` / `EventSource` to attach the token on every
//! same-origin API call. Cookies are avoided on purpose: cookies on
//! `127.0.0.1` are host-scoped, not port-scoped, so they would leak
//! to any other localhost service the user visits. `sessionStorage`
//! is port-scoped under the HTML5 origin rule.

use axum::extract::State;
use axum::http::{StatusCode, header};
use axum::response::{Html, IntoResponse, Response};
use rust_embed::Embed;

use crate::state::InspectorState;

#[derive(Embed)]
#[folder = "ui/dist"]
#[allow(clippy::upper_case_acronyms)]
struct Assets;

/// Serve an embedded static file by path. Falls back to `index.html`
/// for SPA client-side routing. HTML responses get the auth-token
/// bootstrap injected; everything else passes through unmodified.
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

/// Insert the bootstrap script as the first thing the browser executes
/// — before `</head>` if present, else before `<body`, else at the top.
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

fn build_bootstrap_script(token: &str) -> String {
    let token_js = serde_json::to_string(token).unwrap_or_else(|_| "\"\"".to_string());
    format!(
        r#"<script>
(function () {{
  var T = {token_js};
  try {{ sessionStorage.setItem("lpm_inspector_token", T); }} catch (_) {{}}

  try {{
    var u = new URL(window.location.href);
    if (u.searchParams.has("token")) {{
      u.searchParams.delete("token");
      window.history.replaceState({{}}, "", u.pathname + (u.search || "") + (u.hash || ""));
    }}
  }} catch (_) {{}}

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

fn placeholder_html() -> String {
    include_str!("inspector_ui.html").to_string()
}
