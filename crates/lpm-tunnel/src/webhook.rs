//! Webhook capture types, provider detection, and summary generation.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A captured webhook request/response pair.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapturedWebhook {
    pub id: String,
    pub timestamp: String,
    pub method: String,
    pub path: String,
    pub request_headers: HashMap<String, String>,
    #[serde(with = "base64_bytes")]
    pub request_body: Vec<u8>,
    pub response_status: u16,
    pub response_headers: HashMap<String, String>,
    #[serde(with = "base64_bytes")]
    pub response_body: Vec<u8>,
    pub duration_ms: u64,
    pub provider: Option<WebhookProvider>,
    pub summary: String,
    pub signature_diagnostic: Option<String>,
    /// Whether this request was auto-acknowledged (200 OK returned to the
    /// provider without forwarding to the local server). This happens when
    /// `--auto-ack` is enabled and the local server is unreachable.
    #[serde(default)]
    pub auto_acked: bool,
}

/// Known webhook providers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WebhookProvider {
    Stripe,
    GitHub,
    Clerk,
    Resend,
    SendGrid,
    Twilio,
    Svix,
}

impl std::fmt::Display for WebhookProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Stripe => write!(f, "Stripe"),
            Self::GitHub => write!(f, "GitHub"),
            Self::Clerk => write!(f, "Clerk"),
            Self::Resend => write!(f, "Resend"),
            Self::SendGrid => write!(f, "SendGrid"),
            Self::Twilio => write!(f, "Twilio"),
            Self::Svix => write!(f, "Svix"),
        }
    }
}

impl CapturedWebhook {
    /// Size of the request body in bytes.
    pub fn body_size(&self) -> usize {
        self.request_body.len()
    }

    /// Whether the response indicates an error (status >= 400).
    pub fn is_error(&self) -> bool {
        self.response_status >= 400
    }
}

/// Detect the webhook provider from request path and headers.
///
/// Checks specific headers first (most reliable), then falls back to
/// path-based heuristics.
pub fn detect_provider(path: &str, headers: &HashMap<String, String>) -> Option<WebhookProvider> {
    // Normalize header keys to lowercase for case-insensitive matching.
    // Build a set of lowercase keys to avoid repeated allocations.
    let lower_keys: HashMap<String, &String> =
        headers.iter().map(|(k, v)| (k.to_lowercase(), v)).collect();

    // Header-based detection (ordered by specificity)
    if lower_keys.contains_key("stripe-signature") {
        return Some(WebhookProvider::Stripe);
    }
    if lower_keys.contains_key("x-github-event") {
        return Some(WebhookProvider::GitHub);
    }
    if lower_keys.contains_key("svix-id") {
        // Clerk uses Svix under the hood. Check if the path hints at Clerk,
        // otherwise report as Svix.
        let path_lower = path.to_lowercase();
        if path_lower.contains("clerk") {
            return Some(WebhookProvider::Clerk);
        }
        return Some(WebhookProvider::Svix);
    }
    if lower_keys.contains_key("x-sendgrid-event-id") {
        return Some(WebhookProvider::SendGrid);
    }
    if lower_keys.contains_key("x-twilio-signature") {
        return Some(WebhookProvider::Twilio);
    }
    if lower_keys.contains_key("x-resend-signature") {
        return Some(WebhookProvider::Resend);
    }

    // Path-based fallback
    let path_lower = path.to_lowercase();
    if path_lower.contains("stripe") {
        return Some(WebhookProvider::Stripe);
    }
    if path_lower.contains("github") {
        return Some(WebhookProvider::GitHub);
    }

    None
}

/// Generate a human-readable summary for a captured webhook.
///
/// Provider-specific summaries extract the event type from the request body
/// or headers. Falls back to a generic method + path + size summary.
pub fn summarize_webhook(webhook: &CapturedWebhook) -> String {
    match webhook.provider {
        Some(WebhookProvider::Stripe) => summarize_stripe(webhook),
        Some(WebhookProvider::GitHub) => summarize_github(webhook),
        Some(WebhookProvider::Clerk) => summarize_clerk(webhook),
        Some(provider) => {
            // For other known providers, try to extract a `.type` field
            if let Some(event_type) = extract_json_type(&webhook.request_body) {
                format!("{provider}: {event_type}")
            } else {
                format_generic(webhook)
            }
        }
        None => format_generic(webhook),
    }
}

/// Stripe: extract `.type` from the JSON body.
fn summarize_stripe(webhook: &CapturedWebhook) -> String {
    if let Some(event_type) = extract_json_type(&webhook.request_body) {
        format!("Stripe: {event_type}")
    } else {
        format_generic(webhook)
    }
}

/// GitHub: read the `x-github-event` header.
fn summarize_github(webhook: &CapturedWebhook) -> String {
    let lower_headers: HashMap<String, &String> = webhook
        .request_headers
        .iter()
        .map(|(k, v)| (k.to_lowercase(), v))
        .collect();

    if let Some(event) = lower_headers.get("x-github-event") {
        format!("GitHub: {event}")
    } else {
        format_generic(webhook)
    }
}

/// Clerk: extract `.type` from the JSON body (Svix-wrapped events).
fn summarize_clerk(webhook: &CapturedWebhook) -> String {
    if let Some(event_type) = extract_json_type(&webhook.request_body) {
        format!("Clerk: {event_type}")
    } else {
        format_generic(webhook)
    }
}

/// Try to parse JSON and extract the top-level `.type` field.
fn extract_json_type(body: &[u8]) -> Option<String> {
    let value: serde_json::Value = serde_json::from_slice(body).ok()?;
    value.get("type")?.as_str().map(|s| s.to_string())
}

/// Generic summary: `METHOD /path (size)`.
fn format_generic(webhook: &CapturedWebhook) -> String {
    let size = format_size(webhook.body_size());
    format!("{} {} ({size})", webhook.method, webhook.path)
}

/// Format byte size into a human-readable string.
fn format_size(bytes: usize) -> String {
    if bytes < 1024 {
        format!("{bytes}B")
    } else if bytes < 1024 * 1024 {
        format!("{:.1}KB", bytes as f64 / 1024.0)
    } else {
        format!("{:.1}MB", bytes as f64 / (1024.0 * 1024.0))
    }
}

/// Serde helper for base64-encoding `Vec<u8>` fields.
mod base64_bytes {
    use base64::Engine;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(bytes: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
        base64::engine::general_purpose::STANDARD
            .encode(bytes)
            .serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        base64::engine::general_purpose::STANDARD
            .decode(&s)
            .map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_headers(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    fn make_webhook(overrides: impl FnOnce(&mut CapturedWebhook)) -> CapturedWebhook {
        let mut wh = CapturedWebhook {
            id: "test-id".to_string(),
            timestamp: "2026-01-01T00:00:00Z".to_string(),
            method: "POST".to_string(),
            path: "/webhook".to_string(),
            request_headers: HashMap::new(),
            request_body: Vec::new(),
            response_status: 200,
            response_headers: HashMap::new(),
            response_body: Vec::new(),
            duration_ms: 42,
            provider: None,
            summary: String::new(),
            signature_diagnostic: None,
            auto_acked: false,
        };
        overrides(&mut wh);
        wh
    }

    // -- Provider detection tests --

    #[test]
    fn detect_stripe_by_header() {
        let headers = make_headers(&[("stripe-signature", "t=123,v1=abc")]);
        assert_eq!(
            detect_provider("/hook", &headers),
            Some(WebhookProvider::Stripe)
        );
    }

    #[test]
    fn detect_github_by_header() {
        let headers = make_headers(&[("x-github-event", "push")]);
        assert_eq!(
            detect_provider("/hook", &headers),
            Some(WebhookProvider::GitHub)
        );
    }

    #[test]
    fn detect_svix_by_header() {
        let headers = make_headers(&[("svix-id", "msg_123")]);
        assert_eq!(
            detect_provider("/hook", &headers),
            Some(WebhookProvider::Svix)
        );
    }

    #[test]
    fn detect_clerk_by_svix_header_and_path() {
        let headers = make_headers(&[("svix-id", "msg_123")]);
        assert_eq!(
            detect_provider("/api/clerk/webhook", &headers),
            Some(WebhookProvider::Clerk)
        );
    }

    #[test]
    fn detect_sendgrid_by_header() {
        let headers = make_headers(&[("x-sendgrid-event-id", "ev_123")]);
        assert_eq!(
            detect_provider("/hook", &headers),
            Some(WebhookProvider::SendGrid)
        );
    }

    #[test]
    fn detect_twilio_by_header() {
        let headers = make_headers(&[("x-twilio-signature", "sig")]);
        assert_eq!(
            detect_provider("/hook", &headers),
            Some(WebhookProvider::Twilio)
        );
    }

    #[test]
    fn detect_resend_by_header() {
        let headers = make_headers(&[("x-resend-signature", "sig")]);
        assert_eq!(
            detect_provider("/hook", &headers),
            Some(WebhookProvider::Resend)
        );
    }

    #[test]
    fn detect_stripe_by_path_fallback() {
        let headers = HashMap::new();
        assert_eq!(
            detect_provider("/api/stripe/webhook", &headers),
            Some(WebhookProvider::Stripe)
        );
    }

    #[test]
    fn detect_github_by_path_fallback() {
        let headers = HashMap::new();
        assert_eq!(
            detect_provider("/api/github/webhook", &headers),
            Some(WebhookProvider::GitHub)
        );
    }

    #[test]
    fn detect_none_when_no_match() {
        let headers = make_headers(&[("content-type", "application/json")]);
        assert_eq!(detect_provider("/api/webhook", &headers), None);
    }

    #[test]
    fn detect_header_case_insensitive() {
        let headers = make_headers(&[("Stripe-Signature", "t=123,v1=abc")]);
        assert_eq!(
            detect_provider("/hook", &headers),
            Some(WebhookProvider::Stripe)
        );
    }

    // -- Summary tests --

    #[test]
    fn summarize_stripe_event() {
        let body = br#"{"type":"checkout.session.completed","id":"evt_123"}"#;
        let wh = make_webhook(|w| {
            w.provider = Some(WebhookProvider::Stripe);
            w.request_body = body.to_vec();
        });
        assert_eq!(summarize_webhook(&wh), "Stripe: checkout.session.completed");
    }

    #[test]
    fn summarize_github_event() {
        let wh = make_webhook(|w| {
            w.provider = Some(WebhookProvider::GitHub);
            w.request_headers
                .insert("x-github-event".to_string(), "push".to_string());
        });
        assert_eq!(summarize_webhook(&wh), "GitHub: push");
    }

    #[test]
    fn summarize_clerk_event() {
        let body = br#"{"type":"user.created","data":{}}"#;
        let wh = make_webhook(|w| {
            w.provider = Some(WebhookProvider::Clerk);
            w.request_body = body.to_vec();
        });
        assert_eq!(summarize_webhook(&wh), "Clerk: user.created");
    }

    #[test]
    fn summarize_generic_fallback() {
        let wh = make_webhook(|w| {
            w.method = "POST".to_string();
            w.path = "/api/hook".to_string();
            w.request_body = vec![0u8; 2500];
        });
        assert_eq!(summarize_webhook(&wh), "POST /api/hook (2.4KB)");
    }

    // -- CapturedWebhook methods --

    #[test]
    fn body_size_returns_request_body_length() {
        let wh = make_webhook(|w| {
            w.request_body = vec![0u8; 1234];
        });
        assert_eq!(wh.body_size(), 1234);
    }

    #[test]
    fn is_error_for_4xx() {
        let wh = make_webhook(|w| w.response_status = 400);
        assert!(wh.is_error());
    }

    #[test]
    fn is_error_for_5xx() {
        let wh = make_webhook(|w| w.response_status = 500);
        assert!(wh.is_error());
    }

    #[test]
    fn is_not_error_for_2xx() {
        let wh = make_webhook(|w| w.response_status = 200);
        assert!(!wh.is_error());
    }

    #[test]
    fn is_not_error_for_3xx() {
        let wh = make_webhook(|w| w.response_status = 302);
        assert!(!wh.is_error());
    }

    // -- auto_acked field --

    #[test]
    fn auto_acked_default_false() {
        let wh = make_webhook(|_| {});
        assert!(!wh.auto_acked);
    }

    #[test]
    fn auto_acked_serde_default() {
        // JSON without auto_acked field should deserialize with default false
        let json = r#"{
            "id":"test","timestamp":"2026-01-01T00:00:00Z","method":"POST",
            "path":"/hook","request_headers":{},"request_body":"",
            "response_status":200,"response_headers":{},"response_body":"",
            "duration_ms":10,"provider":null,"summary":"","signature_diagnostic":null
        }"#;
        let wh: CapturedWebhook = serde_json::from_str(json).unwrap();
        assert!(!wh.auto_acked);
    }

    #[test]
    fn auto_acked_roundtrip() {
        let mut wh = make_webhook(|_| {});
        wh.auto_acked = true;
        let json = serde_json::to_string(&wh).unwrap();
        let deserialized: CapturedWebhook = serde_json::from_str(&json).unwrap();
        assert!(deserialized.auto_acked);
    }

    // -- Serde roundtrip --

    #[test]
    fn serde_roundtrip() {
        let wh = make_webhook(|w| {
            w.request_body = b"hello world".to_vec();
            w.response_body = b"ok".to_vec();
            w.provider = Some(WebhookProvider::Stripe);
            w.signature_diagnostic = Some("test diagnostic".to_string());
        });

        let json = serde_json::to_string(&wh).unwrap();
        let deserialized: CapturedWebhook = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.id, wh.id);
        assert_eq!(deserialized.request_body, b"hello world");
        assert_eq!(deserialized.response_body, b"ok");
        assert_eq!(deserialized.provider, Some(WebhookProvider::Stripe));
        assert_eq!(
            deserialized.signature_diagnostic,
            Some("test diagnostic".to_string())
        );
    }

    #[test]
    fn serde_base64_encoding() {
        let wh = make_webhook(|w| {
            w.request_body = vec![0xFF, 0x00, 0xAB]; // non-UTF-8 bytes
        });
        let json = serde_json::to_string(&wh).unwrap();
        // Should contain base64, not raw bytes
        assert!(json.contains("/wCr")); // base64 for [0xFF, 0x00, 0xAB]
    }

    // -- Display --

    #[test]
    fn provider_display() {
        assert_eq!(WebhookProvider::Stripe.to_string(), "Stripe");
        assert_eq!(WebhookProvider::GitHub.to_string(), "GitHub");
        assert_eq!(WebhookProvider::SendGrid.to_string(), "SendGrid");
    }

    // -- format_size --

    #[test]
    fn format_size_bytes() {
        assert_eq!(format_size(0), "0B");
        assert_eq!(format_size(512), "512B");
        assert_eq!(format_size(1023), "1023B");
    }

    #[test]
    fn format_size_kilobytes() {
        assert_eq!(format_size(1024), "1.0KB");
        assert_eq!(format_size(2560), "2.5KB");
    }

    #[test]
    fn format_size_megabytes() {
        assert_eq!(format_size(1024 * 1024), "1.0MB");
    }
}
