//! Request Annotations & Export — tag requests and export as cURL, test fixtures, or JSON.
//!
//! # Annotations
//!
//! Requests can be tagged with free-form strings (e.g., "bug repro #234",
//! "edge case: negative amount"). Tags are stored as a JSON array in the
//! SQLite `tags` column and are searchable via FTS.
//!
//! # Export Formats
//!
//! - **cURL**: Runnable cURL command that reproduces the exact request
//! - **JSON**: Full request/response data as a portable `.lpm-webhook` file
//! - **Test fixture**: Framework-specific test skeleton (Vitest/Jest)
//! - **Provider CLI**: Provider-specific replay commands (e.g., `stripe events resend`)

use lpm_tunnel::webhook::CapturedWebhook;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ── cURL Export ───────────────────────────────────────────────────────

/// Escape a string for safe interpolation inside a single-quoted shell
/// word: each `'` closes the quoted run, emits `\'` and reopens it, the
/// canonical POSIX form. A backslash is taken out of the quotes the same
/// way, as `\\`, because fish reads `\'` inside single quotes as an
/// escaped quote, which would let a value close the word early.
fn shell_single_quote_escape(s: &str) -> String {
    let mut escaped = String::with_capacity(s.len());
    for character in s.chars() {
        match character {
            '\'' => escaped.push_str("'\\''"),
            '\\' => escaped.push_str("'\\\\'"),
            character => escaped.push(character),
        }
    }
    escaped
}

/// `s` as one shell word: bare when it holds only characters no shell
/// treats specially, otherwise single-quoted, so a captured value pasted
/// as part of a command can't add a command of its own.
fn shell_word(s: &str) -> std::borrow::Cow<'_, str> {
    let plain = !s.is_empty()
        && s.bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'));
    if plain {
        std::borrow::Cow::Borrowed(s)
    } else {
        std::borrow::Cow::Owned(format!("'{}'", shell_single_quote_escape(s)))
    }
}

/// Generate a runnable cURL command from a captured request.
///
/// Preserves method, path, headers, and body. The resulting command can be
/// copied and pasted directly into a terminal.
pub fn to_curl(webhook: &CapturedWebhook, target_url: Option<&str>) -> String {
    let url = target_url.unwrap_or(&webhook.path);
    // The path comes from whoever sent the request to a public tunnel
    // endpoint, so it's quoted as shell text.
    let url_escaped = shell_single_quote_escape(url);
    // `--url` keeps a URL starting with `-` from being read as an option,
    // and `--globoff` keeps `[1-100]` or `{a,b}` in it from fanning out
    // into many requests.
    let mut parts = vec![format!(
        "curl --globoff -X {} --url '{}'",
        shell_word(&webhook.method),
        url_escaped
    )];

    // Headers (sorted for deterministic output)
    let mut headers: Vec<(&String, &String)> = webhook.request_headers.iter().collect();
    headers.sort_by_key(|(k, _)| k.to_lowercase());

    for (key, value) in headers {
        let lower = key.to_lowercase();
        // Skip hop-by-hop headers that curl manages
        // curl reads `-H @<file>` as a file of headers.
        if lower == "host"
            || lower == "content-length"
            || lower == "transfer-encoding"
            || key.starts_with('@')
        {
            continue;
        }
        // Both header NAME and VALUE flow from the captured request,
        // so both need the same single-quote escape — a `'` in either
        // would otherwise break out of the quoted `-H` argument.
        let key_escaped = shell_single_quote_escape(key);
        let value_escaped = shell_single_quote_escape(value);
        parts.push(format!("  -H '{key_escaped}: {value_escaped}'"));
    }

    // Body
    if !webhook.request_body.is_empty() {
        if let Ok(body_str) = std::str::from_utf8(&webhook.request_body) {
            // Try to compact JSON for readability
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(body_str) {
                let compact = serde_json::to_string(&json).unwrap_or_else(|_| body_str.to_string());
                parts.push(format!(
                    "  --data-raw '{}'",
                    shell_single_quote_escape(&compact)
                ));
            } else {
                // `--data-raw`, unlike `-d`, sends a body starting with `@`
                // as text instead of uploading the file it names.
                parts.push(format!(
                    "  --data-raw '{}'",
                    shell_single_quote_escape(body_str)
                ));
            }
        } else {
            // Binary body — use base64 with decode pipe. Base64 output
            // is `[A-Za-z0-9+/=]` so it has no shell-metacharacters,
            // but escape defensively so a future change to the encoder
            // can't introduce one.
            use base64::Engine;
            let b64 = base64::engine::general_purpose::STANDARD.encode(&webhook.request_body);
            parts.push(format!(
                "  --data-binary @<(echo '{}' | base64 -d)",
                shell_single_quote_escape(&b64)
            ));
        }
    }

    parts.join(" \\\n")
}

// ── JSON Export (.lpm-webhook format) ─────────────────────────────────

/// Export a captured request as a portable JSON object.
///
/// This is the `.lpm-webhook` format — a single file containing the full
/// request/response pair with metadata. Can be imported by teammates.
pub fn to_webhook_json(webhook: &CapturedWebhook) -> WebhookExport {
    WebhookExport {
        version: 1,
        id: webhook.id.clone(),
        timestamp: webhook.timestamp.clone(),
        method: webhook.method.clone(),
        path: webhook.path.clone(),
        request_headers: webhook.request_headers.clone(),
        request_body: body_to_export(&webhook.request_body),
        response_status: webhook.response_status,
        response_headers: webhook.response_headers.clone(),
        response_body: body_to_export(&webhook.response_body),
        duration_ms: webhook.duration_ms,
        provider: webhook.provider.map(|p| p.to_string()),
        summary: webhook.summary.clone(),
    }
}

/// Portable webhook export format.
#[derive(Debug, Serialize, Deserialize)]
pub struct WebhookExport {
    /// Schema version for forward compatibility.
    pub version: u8,
    pub id: String,
    pub timestamp: String,
    pub method: String,
    pub path: String,
    pub request_headers: HashMap<String, String>,
    pub request_body: ExportBody,
    pub response_status: u16,
    pub response_headers: HashMap<String, String>,
    pub response_body: ExportBody,
    pub duration_ms: u64,
    pub provider: Option<String>,
    pub summary: String,
}

/// Body representation in the export format.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "encoding", rename_all = "lowercase")]
pub enum ExportBody {
    /// UTF-8 text content.
    Utf8 { data: String },
    /// Base64-encoded binary content.
    Base64 { data: String },
    /// Empty body.
    Empty,
}

fn body_to_export(body: &[u8]) -> ExportBody {
    if body.is_empty() {
        return ExportBody::Empty;
    }
    match std::str::from_utf8(body) {
        Ok(s) => ExportBody::Utf8 {
            data: s.to_string(),
        },
        Err(_) => {
            use base64::Engine;
            ExportBody::Base64 {
                data: base64::engine::general_purpose::STANDARD.encode(body),
            }
        }
    }
}

// ── Test Fixture Generation ───────────────────────────────────────────

/// Generate a Vitest/Jest test fixture from a captured webhook.
///
/// Every captured value lands in the module as a JSON literal, which is
/// valid JavaScript, or in a comment with its line breaks removed, so no
/// captured text can become a statement of the generated module.
pub fn to_test_fixture(webhook: &CapturedWebhook) -> String {
    let provider_name = webhook
        .provider
        .map_or_else(|| "webhook".to_string(), |p| p.to_string());

    let event_type = webhook
        .summary
        .split(": ")
        .nth(1)
        .unwrap_or(&webhook.summary);

    let safe_name = event_type.replace(['.', ' ', '/'], "_");

    let body_fixture =
        if let Ok(json) = serde_json::from_slice::<serde_json::Value>(&webhook.request_body) {
            serde_json::to_string_pretty(&json).map_or_else(|_| js_string(""), js_source)
        } else {
            js_string(&String::from_utf8_lossy(&webhook.request_body))
        };

    let mut headers_sorted: Vec<(&String, &String)> = webhook.request_headers.iter().collect();
    headers_sorted.sort_by_key(|(k, _)| k.to_lowercase());
    let headers_entries: Vec<String> = headers_sorted
        .iter()
        .filter(|(k, _)| {
            let lower = k.to_lowercase();
            lower != "host" && lower != "content-length" && lower != "transfer-encoding"
        })
        .map(|(k, v)| format!("\t\t{}: {}", js_string(k), js_string(v)))
        .collect();
    let headers_js = headers_entries.join(",\n");

    format!(
        r#"import {{ describe, it, expect }} from "vitest"

// Captured {provider_comment} webhook: {event_comment}
// Original status: {status} | Duration: {duration}ms
// Timestamp: {timestamp_comment}

const mockPayload = {body}

const mockHeaders = {{
{headers}
}}

describe({suite}, () => {{
	it({case}, async () => {{
		const response = await app.inject({{
			method: {method},
			url: {path},
			headers: mockHeaders,
			payload: mockPayload,
		}})

		expect(response.statusCode).toBe(200)
	}})
}})
"#,
        provider_comment = comment_text(&provider_name),
        event_comment = comment_text(event_type),
        status = webhook.response_status,
        duration = webhook.duration_ms,
        timestamp_comment = comment_text(&webhook.timestamp),
        body = body_fixture,
        headers = headers_js,
        suite = js_string(&format!("{provider_name} webhook: {safe_name}")),
        case = js_string(&format!("should handle {event_type}")),
        method = js_string(&webhook.method),
        path = js_string(&webhook.path),
    )
}

/// `s` as a JavaScript string literal.
fn js_string(s: &str) -> String {
    js_source(serde_json::Value::from(s).to_string())
}

/// JSON text as JavaScript source. JSON leaves U+2028 and U+2029 bare
/// inside strings, where engines before ES2019 end the line, so they are
/// escaped as JSON.stringify output meant for a script should be.
fn js_source(json: String) -> String {
    if !json.contains(['\u{2028}', '\u{2029}']) {
        return json;
    }
    json.replace('\u{2028}', "\\u2028")
        .replace('\u{2029}', "\\u2029")
}

/// `s` on one line of a `//` comment: JavaScript ends a line comment at any
/// line terminator, so each one, and every other control character,
/// becomes a space.
fn comment_text(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_control() || matches!(c, '\u{2028}' | '\u{2029}') {
                ' '
            } else {
                c
            }
        })
        .collect()
}

// ── Provider CLI Export ───────────────────────────────────────────────

/// Generate a provider-specific CLI command for replaying the webhook.
pub fn to_provider_cli(webhook: &CapturedWebhook) -> Option<String> {
    let provider = webhook.provider?;
    let event_type = extract_event_type(webhook);

    match provider {
        lpm_tunnel::webhook::WebhookProvider::Stripe => {
            let event = event_type.unwrap_or("charge.succeeded".to_string());
            is_stripe_event_name(&event).then(|| format!("stripe trigger {event}"))
        }
        lpm_tunnel::webhook::WebhookProvider::GitHub => {
            Some("gh api repos/OWNER/REPO/dispatches -f event_type=webhook_test".to_string())
        }
        _ => None,
    }
}

/// Stripe event names are lowercase words joined by `.` and `_`. Anything
/// else, such as a type starting with `-`, would reach `stripe trigger` as
/// something other than an event.
fn is_stripe_event_name(name: &str) -> bool {
    !name.is_empty()
        && !name.starts_with(['.', '_'])
        && name.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_')
        })
}

fn extract_event_type(webhook: &CapturedWebhook) -> Option<String> {
    let json: serde_json::Value = serde_json::from_slice(&webhook.request_body).ok()?;
    json.get("type")?.as_str().map(|s| s.to_string())
}

// ── Tag Management ────────────────────────────────────────────────────

/// Parse tags from the JSON array string stored in SQLite.
pub fn parse_tags(tags_json: Option<&str>) -> Vec<String> {
    tags_json
        .and_then(|s| serde_json::from_str::<Vec<String>>(s).ok())
        .unwrap_or_default()
}

/// Serialize tags to a JSON array string for SQLite storage.
pub fn serialize_tags(tags: &[String]) -> String {
    serde_json::to_string(tags).unwrap_or_else(|_| "[]".to_string())
}

// ── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use lpm_tunnel::webhook::WebhookProvider;

    fn make_webhook() -> CapturedWebhook {
        CapturedWebhook {
            id: "evt_123".to_string(),
            timestamp: "2026-04-06T12:00:00Z".to_string(),
            method: "POST".to_string(),
            path: "/api/webhook/stripe".to_string(),
            request_headers: HashMap::from([
                ("content-type".to_string(), "application/json".to_string()),
                ("stripe-signature".to_string(), "t=123,v1=abc".to_string()),
            ]),
            request_body:
                br#"{"type":"charge.succeeded","data":{"object":{"id":"ch_1","amount":2000}}}"#
                    .to_vec(),
            response_status: 200,
            response_headers: HashMap::from([(
                "content-type".to_string(),
                "application/json".to_string(),
            )]),
            response_body: br#"{"received":true}"#.to_vec(),
            duration_ms: 42,
            provider: Some(WebhookProvider::Stripe),
            summary: "Stripe: charge.succeeded".to_string(),
            signature_diagnostic: None,
            auto_acked: false,
            response_body_incomplete: false,
        }
    }

    // ── cURL export ─────────────────────────────────────────

    #[test]
    fn curl_basic() {
        let wh = make_webhook();
        let curl = to_curl(&wh, None);
        assert!(curl.starts_with("curl --globoff -X POST --url '/api/webhook/stripe'"));
        assert!(curl.contains("-H 'content-type: application/json'"));
        assert!(curl.contains("-H 'stripe-signature: t=123,v1=abc'"));
        assert!(curl.contains("--data-raw '"));
        assert!(curl.contains("charge.succeeded"));
    }

    #[test]
    fn curl_with_custom_url() {
        let wh = make_webhook();
        let curl = to_curl(&wh, Some("http://localhost:4000/api/webhook"));
        assert!(curl.contains("http://localhost:4000/api/webhook"));
    }

    #[test]
    fn curl_skips_hop_by_hop_headers() {
        let mut wh = make_webhook();
        wh.request_headers
            .insert("host".to_string(), "example.com".to_string());
        wh.request_headers
            .insert("content-length".to_string(), "42".to_string());
        let curl = to_curl(&wh, None);
        assert!(!curl.contains("host:"));
        assert!(!curl.contains("content-length:"));
    }

    #[test]
    fn curl_empty_body() {
        let mut wh = make_webhook();
        wh.request_body = Vec::new();
        let curl = to_curl(&wh, None);
        assert!(!curl.contains("--data"));
    }

    #[test]
    fn curl_sends_one_request_for_a_path_with_brackets_or_braces() {
        let mut wh = make_webhook();
        wh.path = "/x[1-100000]{a,b}".to_string();
        let curl = to_curl(&wh, None);
        assert!(
            curl.starts_with("curl --globoff -X POST --url '/x[1-100000]{a,b}'"),
            "{curl}"
        );
    }

    #[test]
    fn curl_sends_a_body_starting_with_at_as_text_rather_than_a_file() {
        let mut wh = make_webhook();
        wh.request_body = b"@/tmp/file".to_vec();
        let curl = to_curl(&wh, None);
        assert!(curl.contains("--data-raw '@/tmp/file'"), "{curl}");
        assert!(!curl.contains(" -d "), "{curl}");
    }

    #[test]
    fn curl_passes_the_url_as_an_option_value_so_a_path_cannot_become_an_option() {
        let mut wh = make_webhook();
        wh.path = "-K/tmp/config".to_string();
        let curl = to_curl(&wh, None);
        assert!(
            curl.starts_with("curl --globoff -X POST --url '-K/tmp/config'"),
            "{curl}"
        );
    }

    #[test]
    fn curl_leaves_out_a_header_whose_name_would_make_curl_read_a_file() {
        let mut wh = make_webhook();
        wh.request_headers
            .insert("@/etc/passwd".to_string(), String::new());
        let curl = to_curl(&wh, None);
        assert!(!curl.contains("@/etc/passwd"), "{curl}");
    }

    #[test]
    fn curl_keeps_backslashes_outside_single_quotes_for_shells_that_read_them_there() {
        let mut wh = make_webhook();
        wh.request_headers
            .insert("x-test".to_string(), r"\'; echo x #".to_string());
        let curl = to_curl(&wh, None);
        assert!(curl.contains(r"-H 'x-test: '\\''\''; echo x #'"), "{curl}");
    }

    #[test]
    fn curl_escapes_single_quotes() {
        let mut wh = make_webhook();
        wh.request_headers
            .insert("x-test".to_string(), "it's a test".to_string());
        let curl = to_curl(&wh, None);
        assert!(curl.contains("it'\\''s a test"));
    }

    /// M45: the captured webhook URL/path is upstream-controlled. A
    /// path like `/hook'; touch /tmp/pwn #` must NOT close our quoted
    /// `curl '<url>'` argument and execute arbitrary shell when the
    /// user pastes the command. Pre-fix the path interpolated raw.
    #[test]
    fn curl_escapes_single_quotes_in_url_path() {
        let mut wh = make_webhook();
        wh.path = "/hook'; touch /tmp/pwn #".to_string();
        let curl = to_curl(&wh, None);
        assert!(
            !curl.contains("/hook'; touch /tmp/pwn #"),
            "raw quote in URL path must not survive into the cURL command: {curl}"
        );
        assert!(
            curl.contains("/hook'\\''; touch /tmp/pwn #"),
            "URL path single-quote should be POSIX-escaped (`'\\''`); got: {curl}"
        );
    }

    #[test]
    fn curl_escapes_single_quotes_in_target_url_override() {
        let wh = make_webhook();
        let curl = to_curl(&wh, Some("http://localhost:4000/x'$(id)"));
        assert!(!curl.contains("/x'$(id)"));
        assert!(curl.contains("/x'\\''$(id)"));
    }

    /// Header names are also upstream-controlled (any HTTP client can
    /// send a custom header key). A key like `X-Bad'; rm -rf /; #`
    /// must not break out of the quoted `-H '<key>: <value>'` arg.
    #[test]
    fn curl_escapes_single_quotes_in_header_name() {
        let mut wh = make_webhook();
        wh.request_headers
            .insert("X-Bad'; rm -rf /; #".to_string(), "v".to_string());
        let curl = to_curl(&wh, None);
        assert!(!curl.contains("X-Bad'; rm -rf /; #"));
        assert!(curl.contains("X-Bad'\\''; rm -rf /; #"));
    }

    #[test]
    fn curl_deterministic_header_order() {
        let wh = make_webhook();
        let curl1 = to_curl(&wh, None);
        let curl2 = to_curl(&wh, None);
        assert_eq!(curl1, curl2);
    }

    // ── JSON export ─────────────────────────────────────────

    #[test]
    fn json_export_structure() {
        let wh = make_webhook();
        let export = to_webhook_json(&wh);
        assert_eq!(export.version, 1);
        assert_eq!(export.id, "evt_123");
        assert_eq!(export.method, "POST");
        assert!(matches!(export.request_body, ExportBody::Utf8 { .. }));
        assert!(matches!(export.response_body, ExportBody::Utf8 { .. }));
    }

    #[test]
    fn json_export_roundtrip() {
        let wh = make_webhook();
        let export = to_webhook_json(&wh);
        let json = serde_json::to_string(&export).unwrap();
        let roundtrip: WebhookExport = serde_json::from_str(&json).unwrap();
        assert_eq!(roundtrip.id, export.id);
        assert_eq!(roundtrip.version, 1);
    }

    #[test]
    fn json_export_binary_body() {
        let mut wh = make_webhook();
        wh.request_body = vec![0xFF, 0x00, 0xAB];
        let export = to_webhook_json(&wh);
        assert!(matches!(export.request_body, ExportBody::Base64 { .. }));
    }

    #[test]
    fn json_export_empty_body() {
        let mut wh = make_webhook();
        wh.response_body = Vec::new();
        let export = to_webhook_json(&wh);
        assert!(matches!(export.response_body, ExportBody::Empty));
    }

    // ── Test fixture ────────────────────────────────────────

    #[test]
    fn test_fixture_contains_essentials() {
        let wh = make_webhook();
        let fixture = to_test_fixture(&wh);
        assert!(fixture.contains("import { describe, it, expect }"));
        assert!(fixture.contains("Stripe"));
        assert!(fixture.contains("charge.succeeded"));
        assert!(fixture.contains("mockPayload"));
        assert!(fixture.contains("mockHeaders"));
        assert!(fixture.contains("/api/webhook/stripe"));
        assert!(fixture.contains("POST"));
    }

    #[test]
    fn test_fixture_has_pretty_json_body() {
        let wh = make_webhook();
        let fixture = to_test_fixture(&wh);
        // Pretty-printed JSON should have indentation
        assert!(fixture.contains("  \"type\": \"charge.succeeded\""));
    }

    #[test]
    fn test_fixture_emits_a_body_that_is_not_json_as_a_string_literal() {
        let mut wh = make_webhook();
        wh.request_body = b"0; await import('node:fs')".to_vec();
        let fixture = to_test_fixture(&wh);
        assert!(
            fixture.contains(r#"const mockPayload = "0; await import('node:fs')""#),
            "{fixture}"
        );
    }

    #[test]
    fn test_fixture_keeps_captured_text_from_starting_a_statement() {
        let mut wh = make_webhook();
        wh.summary = "Stripe: charge.succeeded\u{2028}marker()".to_string();
        wh.timestamp = "2026-01-01\nmarker()".to_string();
        wh.method = "POST\"\nmarker()\n\"".to_string();
        wh.path = "/x\u{2029}marker()".to_string();
        wh.request_headers = HashMap::from([("x\"\nmarker()\n\"".to_string(), "v".to_string())]);
        let fixture = to_test_fixture(&wh);
        for line in fixture.split(['\n', '\r', '\u{2028}', '\u{2029}']) {
            assert!(
                !line.trim_start().starts_with("marker()"),
                "a captured value started a statement:\n{fixture}"
            );
        }
    }

    #[test]
    fn curl_quotes_a_method_carrying_shell_syntax() {
        let mut wh = make_webhook();
        wh.method = "POST$(echo x)".to_string();
        let curl = to_curl(&wh, None);
        assert!(
            curl.starts_with("curl --globoff -X 'POST$(echo x)' --url '/api/webhook/stripe'"),
            "{curl}"
        );
    }

    #[test]
    fn provider_cli_offers_no_command_for_a_type_that_is_not_a_stripe_event_name() {
        let mut wh = make_webhook();
        for event_type in ["charge.succeeded; echo x", "--flag=value", "it's"] {
            wh.request_body = serde_json::json!({ "type": event_type })
                .to_string()
                .into_bytes();
            assert_eq!(to_provider_cli(&wh), None, "{event_type}");
        }
    }

    // ── Provider CLI ────────────────────────────────────────

    #[test]
    fn provider_cli_stripe() {
        let wh = make_webhook();
        let cmd = to_provider_cli(&wh).unwrap();
        assert_eq!(cmd, "stripe trigger charge.succeeded");
    }

    #[test]
    fn provider_cli_github() {
        let mut wh = make_webhook();
        wh.provider = Some(WebhookProvider::GitHub);
        let cmd = to_provider_cli(&wh).unwrap();
        assert!(cmd.contains("gh api"));
    }

    #[test]
    fn provider_cli_none_for_unknown() {
        let mut wh = make_webhook();
        wh.provider = None;
        assert!(to_provider_cli(&wh).is_none());
    }

    // ── Tag management ──────────────────────────────────────

    #[test]
    fn parse_tags_from_json() {
        let tags = parse_tags(Some(r#"["bug","repro"]"#));
        assert_eq!(tags, vec!["bug", "repro"]);
    }

    #[test]
    fn parse_tags_empty() {
        assert!(parse_tags(None).is_empty());
        assert!(parse_tags(Some("")).is_empty());
        assert!(parse_tags(Some("null")).is_empty());
    }

    #[test]
    fn serialize_tags_roundtrip() {
        let tags = vec!["a".to_string(), "b".to_string()];
        let json = serialize_tags(&tags);
        let parsed = parse_tags(Some(&json));
        assert_eq!(parsed, tags);
    }
}
