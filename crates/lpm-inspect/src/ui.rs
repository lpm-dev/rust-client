//! Embedded web UI serving via rust-embed.
//!
//! Static frontend assets are compiled into the binary at build time. The
//! pages hold no secret: the launch URL carries the access token in its
//! fragment, which the browser never sends, and an inline bootstrap moves it
//! into `sessionStorage` and attaches it to every same-origin API call.
//! Cookies are avoided on purpose: cookies on `127.0.0.1` are host-scoped,
//! not port-scoped, so they would leak to any other localhost service the
//! user visits. `sessionStorage` is port-scoped under the HTML5 origin rule.
//!
//! Every HTML response gets its own script nonce and a Content Security
//! Policy that runs only nonced scripts, so text a capture carries can't run
//! as script even if a template places it where markup goes.

use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use base64::Engine;
use rust_embed::Embed;

#[derive(Embed)]
#[folder = "ui/dist"]
#[allow(clippy::upper_case_acronyms)]
struct Assets;

/// Serve an embedded static file by path. Falls back to `index.html`
/// for SPA client-side routing, and to the built-in page when no UI is
/// embedded.
pub async fn serve_ui(uri: axum::http::Uri) -> Response {
    let path = uri.path().trim_start_matches('/');

    let file = if path.is_empty() {
        Assets::get("index.html")
    } else {
        Assets::get(path).or_else(|| Assets::get("index.html"))
    };

    let Some(content) = file else {
        return html_response(include_str!("inspector_ui.html"));
    };
    let mime = mime_guess::from_path(path).first_or_octet_stream();
    let bytes = content.data.into_owned();
    if mime.type_() == mime_guess::mime::TEXT && mime.subtype() == mime_guess::mime::HTML {
        return html_response(&String::from_utf8_lossy(&bytes));
    }
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, mime.to_string()),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff".to_owned()),
        ],
        bytes,
    )
        .into_response()
}

fn html_response(html: &str) -> Response {
    let nonce = new_nonce();
    let policy = content_security_policy(&nonce);
    (
        StatusCode::OK,
        [
            (
                header::CONTENT_TYPE,
                HeaderValue::from_static("text/html; charset=utf-8"),
            ),
            (
                header::CONTENT_SECURITY_POLICY,
                HeaderValue::from_str(&policy).expect("the policy is ASCII without controls"),
            ),
            (header::CACHE_CONTROL, HeaderValue::from_static("no-store")),
            (
                header::X_CONTENT_TYPE_OPTIONS,
                HeaderValue::from_static("nosniff"),
            ),
            (
                header::REFERRER_POLICY,
                HeaderValue::from_static("no-referrer"),
            ),
        ],
        render_page(html, &nonce),
    )
        .into_response()
}

/// 128 random bits, unpadded base64url: a CSP nonce no page can guess.
fn new_nonce() -> String {
    use rand::Rng;
    let mut bytes = [0u8; 16];
    rand::rng().fill_bytes(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn content_security_policy(nonce: &str) -> String {
    format!(
        "default-src 'none'; script-src 'nonce-{nonce}'; style-src 'self' 'unsafe-inline'; \
         connect-src 'self'; img-src 'self' data:; font-src 'self'; base-uri 'none'; \
         form-action 'none'; frame-ancestors 'none'"
    )
}

/// `html` with the bootstrap as the first script the browser runs, and
/// every script tag carrying `nonce`.
fn render_page(html: &str, nonce: &str) -> String {
    let at = html
        .find("</head>")
        .or_else(|| html.find("<body"))
        .unwrap_or(0);
    let mut page = String::with_capacity(html.len() + BOOTSTRAP.len() + 128);
    push_with_nonce(&mut page, &html[..at], nonce);
    page.push_str("<script nonce=\"");
    page.push_str(nonce);
    page.push_str("\">");
    page.push_str(BOOTSTRAP);
    page.push_str("</script>");
    push_with_nonce(&mut page, &html[at..], nonce);
    page
}

/// Appends `html` with `nonce` added to each script start tag.
fn push_with_nonce(page: &mut String, html: &str, nonce: &str) {
    const OPEN: &str = "<script";
    let mut rest = html;
    while let Some(at) = rest.find(OPEN) {
        let (before, after) = rest.split_at(at + OPEN.len());
        page.push_str(before);
        if after.starts_with(['>', ' ', '\t', '\n', '\r']) {
            page.push_str(" nonce=\"");
            page.push_str(nonce);
            page.push('"');
        }
        rest = after;
    }
    page.push_str(rest);
}

const BOOTSTRAP: &str = r#"
(function () {
  var KEY = "lpm_inspector_token";
  var T = null;
  try {
    var u = new URL(window.location.href);
    var given = new URLSearchParams(u.hash.slice(1)).get("token") || u.searchParams.get("token");
    if (given) {
      sessionStorage.setItem("lpm_inspector_token", given);
      u.searchParams.delete("token");
      window.history.replaceState(null, "", u.pathname + u.search);
    }
    T = sessionStorage.getItem(KEY);
  } catch (_) {}
  if (!T) return;

  var origFetch = window.fetch.bind(window);
  window.fetch = function (input, init) {
    var url = typeof input === "string" ? input : (input && input.url) || "";
    var sameOrigin = false;
    try { sameOrigin = new URL(url, window.location.href).origin === window.location.origin; }
    catch (_) { sameOrigin = false; }
    if (sameOrigin && url.indexOf("/api/") !== -1) {
      init = init || {};
      var headers = new Headers(init.headers || (input instanceof Request ? input.headers : undefined));
      if (!headers.has("Authorization")) headers.set("Authorization", "Bearer " + T);
      init.headers = headers;
    }
    return origFetch(input, init);
  };

  if (typeof window.EventSource === "function") {
    var OrigES = window.EventSource;
    function PatchedES(url, opts) {
      try {
        var target = new URL(url, window.location.href);
        if (target.origin === window.location.origin && !target.searchParams.has("token")) {
          target.searchParams.set("token", T);
          url = target.toString();
        }
      } catch (_) {}
      return new OrigES(url, opts);
    }
    PatchedES.prototype = OrigES.prototype;
    PatchedES.CONNECTING = OrigES.CONNECTING;
    PatchedES.OPEN = OrigES.OPEN;
    PatchedES.CLOSED = OrigES.CLOSED;
    window.EventSource = PatchedES;
  }
})();
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_script_tag_carries_the_nonce_and_the_bootstrap_runs_first() {
        let page = render_page(
            "<html><head><title>x</title></head><body><script>run()</script><script type=\"module\" src=\"/m.js\"></script></body></html>",
            "N0nce",
        );
        assert_eq!(page.matches("<script").count(), 3);
        assert_eq!(page.matches("<script nonce=\"N0nce\">").count(), 2);
        assert_eq!(
            page.matches("<script nonce=\"N0nce\" type=\"module\"")
                .count(),
            1
        );
        assert!(!page.contains("nonce=\"N0nce\" nonce="), "{page}");
        let bootstrap = page.find("lpm_inspector_token").unwrap();
        assert!(bootstrap < page.find("</head>").unwrap());
        assert!(bootstrap < page.find("run()").unwrap());
    }

    #[test]
    fn nonces_are_unguessable_and_fit_the_policy_grammar() {
        let first = new_nonce();
        assert_ne!(first, new_nonce());
        assert_eq!(first.len(), 22);
        assert!(
            first
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        );
    }
}
