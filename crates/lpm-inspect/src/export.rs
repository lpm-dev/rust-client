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

/// Generate a runnable cURL command from a captured request.
///
/// Preserves method, path, headers, and body. The resulting command can be
/// copied and pasted directly into a terminal.
pub fn to_curl(webhook: &CapturedWebhook, target_url: Option<&str>) -> String {
    let url = target_url.unwrap_or(&webhook.path);
    let mut parts = vec![format!("curl -X {} '{url}'", webhook.method)];

    // Headers (sorted for deterministic output)
    let mut headers: Vec<(&String, &String)> = webhook.request_headers.iter().collect();
    headers.sort_by_key(|(k, _)| k.to_lowercase());

    for (key, value) in headers {
        let lower = key.to_lowercase();
        // Skip hop-by-hop headers that curl manages
        if lower == "host" || lower == "content-length" || lower == "transfer-encoding" {
            continue;
        }
        // Escape single quotes in values
        let escaped = value.replace('\'', "'\\''");
        parts.push(format!("  -H '{key}: {escaped}'"));
    }

    // Body
    if !webhook.request_body.is_empty() {
        if let Ok(body_str) = std::str::from_utf8(&webhook.request_body) {
            // Try to compact JSON for readability
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(body_str) {
                let compact = serde_json::to_string(&json).unwrap_or_else(|_| body_str.to_string());
                let escaped = compact.replace('\'', "'\\''");
                parts.push(format!("  -d '{escaped}'"));
            } else {
                let escaped = body_str.replace('\'', "'\\''");
                parts.push(format!("  -d '{escaped}'"));
            }
        } else {
            // Binary body — use base64 with decode pipe
            use base64::Engine;
            let b64 = base64::engine::general_purpose::STANDARD.encode(&webhook.request_body);
            parts.push(format!("  --data-binary @<(echo '{b64}' | base64 -d)"));
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
pub fn to_test_fixture(webhook: &CapturedWebhook) -> String {
    let provider_name = webhook
        .provider
        .map(|p| p.to_string())
        .unwrap_or_else(|| "webhook".to_string());

    let event_type = webhook
        .summary
        .split(": ")
        .nth(1)
        .unwrap_or(&webhook.summary);

    let safe_name = event_type.replace(['.', ' ', '/'], "_");

    // Format the body as pretty JSON if possible, otherwise raw string
    let body_fixture =
        if let Ok(json) = serde_json::from_slice::<serde_json::Value>(&webhook.request_body) {
            serde_json::to_string_pretty(&json)
                .unwrap_or_else(|_| String::from_utf8_lossy(&webhook.request_body).into_owned())
        } else {
            String::from_utf8_lossy(&webhook.request_body).into_owned()
        };

    // Format headers as a JS object literal
    let mut headers_sorted: Vec<(&String, &String)> = webhook.request_headers.iter().collect();
    headers_sorted.sort_by_key(|(k, _)| k.to_lowercase());
    let headers_entries: Vec<String> = headers_sorted
        .iter()
        .filter(|(k, _)| {
            let lower = k.to_lowercase();
            lower != "host" && lower != "content-length" && lower != "transfer-encoding"
        })
        .map(|(k, v)| {
            let escaped_v = v.replace('\\', "\\\\").replace('"', "\\\"");
            format!("\t\t\"{k}\": \"{escaped_v}\"")
        })
        .collect();
    let headers_js = headers_entries.join(",\n");

    format!(
        r#"import {{ describe, it, expect }} from "vitest"

// Captured {provider_name} webhook: {event_type}
// Original status: {status} | Duration: {duration}ms
// Timestamp: {timestamp}

const mockPayload = {body}

const mockHeaders = {{
{headers}
}}

describe("{provider_name} webhook: {safe_name}", () => {{
	it("should handle {event_type}", async () => {{
		const response = await app.inject({{
			method: "{method}",
			url: "{path}",
			headers: mockHeaders,
			payload: mockPayload,
		}})

		expect(response.statusCode).toBe(200)
	}})
}})
"#,
        provider_name = provider_name,
        event_type = event_type,
        status = webhook.response_status,
        duration = webhook.duration_ms,
        timestamp = webhook.timestamp,
        body = body_fixture,
        headers = headers_js,
        safe_name = safe_name,
        method = webhook.method,
        path = webhook.path,
    )
}

// ── Provider CLI Export ───────────────────────────────────────────────

/// Generate a provider-specific CLI command for replaying the webhook.
pub fn to_provider_cli(webhook: &CapturedWebhook) -> Option<String> {
    let provider = webhook.provider?;
    let event_type = extract_event_type(webhook);

    match provider {
        lpm_tunnel::webhook::WebhookProvider::Stripe => {
            let event = event_type.unwrap_or("charge.succeeded".to_string());
            Some(format!("stripe trigger {event}"))
        }
        lpm_tunnel::webhook::WebhookProvider::GitHub => {
            Some("gh api repos/OWNER/REPO/dispatches -f event_type=webhook_test".to_string())
        }
        _ => None,
    }
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
        }
    }

    // ── cURL export ─────────────────────────────────────────

    #[test]
    fn curl_basic() {
        let wh = make_webhook();
        let curl = to_curl(&wh, None);
        assert!(curl.starts_with("curl -X POST '/api/webhook/stripe'"));
        assert!(curl.contains("-H 'content-type: application/json'"));
        assert!(curl.contains("-H 'stripe-signature: t=123,v1=abc'"));
        assert!(curl.contains("-d '"));
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
        assert!(!curl.contains("-d "));
    }

    #[test]
    fn curl_escapes_single_quotes() {
        let mut wh = make_webhook();
        wh.request_headers
            .insert("x-test".to_string(), "it's a test".to_string());
        let curl = to_curl(&wh, None);
        assert!(curl.contains("it'\\''s a test"));
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
