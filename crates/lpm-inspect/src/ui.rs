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

    let (served, file) = match Assets::get(path).filter(|_| !path.is_empty()) {
        Some(file) => (path, Some(file)),
        None => ("index.html", Assets::get("index.html")),
    };

    let Some(content) = file else {
        return html_response(include_str!("inspector_ui.html"));
    };
    let mime = mime_guess::from_path(served).first_or_octet_stream();
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

/// `html` with the bootstrap as the first script the browser runs, right
/// after the `<head>` start tag, and every script start tag carrying `nonce`.
fn render_page(html: &str, nonce: &str) -> String {
    let at = head_content_start(html)
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

/// Where the `<head>` element's content begins, past its start tag. A tag
/// such as `<header>` shares the prefix but isn't the head.
fn head_content_start(html: &str) -> Option<usize> {
    let lower = html.to_ascii_lowercase();
    let mut from = 0;
    while let Some(found) = lower[from..].find("<head") {
        let name_end = from + found + "<head".len();
        if lower[name_end..].starts_with(['>', ' ', '\t', '\n', '\r', '/']) {
            return lower[name_end..]
                .find('>')
                .map(|close| name_end + close + 1);
        }
        from = name_end;
    }
    None
}

/// Appends `html` with `nonce` added to each script start tag, matched in any
/// case. A script's own text runs to its end tag untouched, so `"<script>"`
/// inside JavaScript stays as written.
fn push_with_nonce(page: &mut String, html: &str, nonce: &str) {
    const OPEN: &str = "<script";
    const CLOSE: &str = "</script";
    let lower = html.to_ascii_lowercase();
    let mut from = 0;
    while let Some(found) = lower[from..].find(OPEN) {
        let name_end = from + found + OPEN.len();
        page.push_str(&html[from..name_end]);
        from = name_end;
        if !lower[name_end..].starts_with(['>', ' ', '\t', '\n', '\r', '/']) {
            continue;
        }
        page.push_str(" nonce=\"");
        page.push_str(nonce);
        page.push('"');
        let script_end = lower[name_end..]
            .find(CLOSE)
            .map_or(html.len(), |close| name_end + close);
        page.push_str(&html[name_end..script_end]);
        from = script_end;
    }
    page.push_str(&html[from..]);
}

const BOOTSTRAP: &str = r#"
(function () {
  var KEY = "lpm_inspector_token";
  var T = null;
  function suppliedToken() {
    try {
      var u = new URL(window.location.href);
      return new URLSearchParams(u.hash.slice(1)).get("token") || u.searchParams.get("token");
    } catch (_) { return null; }
  }
  function forgetSuppliedToken() {
    try {
      var u = new URL(window.location.href);
      u.searchParams.delete("token");
      window.history.replaceState(null, "", u.pathname + u.search);
    } catch (_) {}
  }
  function remember(token) {
    try { sessionStorage.setItem(KEY, token); return true; } catch (_) { return false; }
  }

  var supplied = suppliedToken();
  if (supplied) {
    T = supplied;
    forgetSuppliedToken();
    remember(T);
  } else {
    try { T = sessionStorage.getItem(KEY); } catch (_) { T = null; }
  }
  Object.defineProperty(window, "lpmInspectorHasToken", { value: Boolean(T) });

  // A link pasted into an open tab changes only the fragment, which doesn't
  // load the page again. When the key can't be stored, the reload carries it
  // in the fragment instead.
  window.addEventListener("hashchange", function () {
    var next = suppliedToken();
    if (!next) return;
    if (remember(next)) forgetSuppliedToken();
    window.location.reload();
  });
  if (!T) return;

  var origFetch = window.fetch.bind(window);
  window.fetch = function (input, init) {
    var url = typeof input === "string" ? input : (input && input.url) || "";
    var api = false;
    try {
      var target = new URL(url, window.location.href);
      api = target.origin === window.location.origin && target.pathname.indexOf("/api/") === 0;
    } catch (_) { api = false; }
    if (api) {
      init = init || {};
      var headers = new Headers(init.headers || (input instanceof Request ? input.headers : undefined));
      if (!headers.has("Authorization")) headers.set("Authorization", "Bearer " + T);
      init.headers = headers;
    }
    var response = origFetch(input, init);
    if (!api) return response;
    return response.then(function (r) {
      if (r.status === 401) {
        try { sessionStorage.removeItem(KEY); } catch (_) {}
        window.dispatchEvent(new Event("lpm-inspector-unauthorized"));
      }
      return r;
    });
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
    fn a_script_tag_inside_a_script_stays_text_and_tags_match_in_any_case() {
        let page = render_page(
            "<html><head></head><body><script>const t = \"<script>\";</script><SCRIPT>b()</SCRIPT><scripts></scripts></body></html>",
            "N0nce",
        );
        assert!(page.contains("const t = \"<script>\";"), "{page}");
        assert!(page.contains("<SCRIPT nonce=\"N0nce\">b()"), "{page}");
        assert!(page.contains("<scripts>"), "{page}");
        assert_eq!(page.matches("nonce=\"N0nce\"").count(), 3, "{page}");
    }

    #[test]
    fn the_bootstrap_runs_before_any_script_in_the_head() {
        let page = render_page(
            "<html><head><header-like></header-like><script>early()</script></head><body></body></html>",
            "N0nce",
        );
        let bootstrap = page.find("lpm_inspector_token").unwrap();
        assert!(bootstrap < page.find("early()").unwrap(), "{page}");
        assert!(page.find("<head>").unwrap() < bootstrap, "{page}");
    }

    #[test]
    fn the_bootstrap_reloads_for_a_link_pasted_into_an_open_tab_and_reports_a_refused_key() {
        assert!(BOOTSTRAP.contains("\"hashchange\""));
        assert!(BOOTSTRAP.contains("lpm-inspector-unauthorized"));
        assert!(BOOTSTRAP.contains("lpmInspectorHasToken"));
    }

    #[test]
    fn every_control_in_the_page_names_an_action_the_page_defines() {
        let page = include_str!("inspector_ui.html");
        let used: std::collections::BTreeSet<&str> = page
            .match_indices("data-action=\"")
            .map(|(at, marker)| {
                let rest = &page[at + marker.len()..];
                &rest[..rest.find('"').unwrap()]
            })
            .collect();
        let table = &page[page.find("const ACTIONS = {").unwrap()..];
        let table = &table[..table.find("\n}").unwrap()];
        let defined: std::collections::BTreeSet<&str> = table
            .lines()
            .filter_map(|line| line.trim().strip_prefix('"')?.split('"').next())
            .collect();
        assert!(!used.is_empty());
        assert_eq!(used, defined);
    }

    #[test]
    fn nonces_differ_per_page_and_fit_the_policy_grammar() {
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
