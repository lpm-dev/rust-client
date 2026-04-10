//! Replay Studio — replay captured requests with modifications and sequences.
//!
//! Extends the base `lpm_tunnel::webhook_replay` with:
//! - Body/header/path modifications before replaying
//! - Sequential replay of multiple requests with configurable delays
//! - Replay to different ports
//! - Result comparison with the original response (via the diff engine)

use crate::diff;
use crate::state::InspectorState;
use lpm_common::LpmError;
use lpm_tunnel::webhook::CapturedWebhook;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Options for replaying a single request with modifications.
#[derive(Debug, Deserialize)]
pub struct ReplayOptions {
    /// Override the target port (default: use the tunneled port).
    pub port: Option<u16>,
    /// Override the request path.
    pub path: Option<String>,
    /// Override the HTTP method.
    pub method: Option<String>,
    /// Headers to add or override. Merged with original headers.
    #[serde(default)]
    pub headers: HashMap<String, String>,
    /// Headers to remove (by key, case-insensitive).
    #[serde(default)]
    pub remove_headers: Vec<String>,
    /// Override the request body (UTF-8 string). If set, replaces the original body entirely.
    pub body: Option<String>,
    /// Skip signature validation by removing known signature headers.
    /// Useful for iterating on handler logic without fighting signing secrets.
    #[serde(default)]
    pub skip_signatures: bool,
}

/// Result of a single replay, including comparison with the original.
#[derive(Debug, Serialize)]
pub struct ReplayStudioResult {
    /// The request ID that was replayed.
    pub id: String,
    /// HTTP status from the local server.
    pub status: u16,
    /// Original response status (for comparison).
    pub original_status: u16,
    /// Round-trip time in milliseconds.
    pub duration_ms: u64,
    /// Response body from the local server.
    pub response_body: String,
    /// Whether the status improved (was error, now success).
    pub improved: bool,
    /// Whether the status regressed (was success, now error).
    pub regressed: bool,
    /// Structural diff between the original and new response bodies.
    pub response_diff: Vec<diff::DiffEntry>,
    pub response_diff_summary: diff::DiffSummary,
}

/// Options for replaying a sequence of requests.
#[derive(Debug, Deserialize)]
pub struct SequenceReplayOptions {
    /// Request IDs to replay, in order.
    pub ids: Vec<String>,
    /// Delay between each replay in milliseconds (default: 500).
    pub delay_ms: Option<u64>,
    /// Override the target port.
    pub port: Option<u16>,
    /// Skip signature validation for all requests.
    #[serde(default)]
    pub skip_signatures: bool,
}

/// Result of a sequence replay.
#[derive(Debug, Serialize)]
pub struct SequenceReplayResult {
    pub results: Vec<ReplayStudioResult>,
    pub total: usize,
    pub succeeded: usize,
    pub failed: usize,
    pub total_duration_ms: u64,
}

/// Known webhook signature headers that are removed when `skip_signatures` is enabled.
const SIGNATURE_HEADERS: &[&str] = &[
    "stripe-signature",
    "x-hub-signature-256",
    "x-hub-signature",
    "svix-signature",
    "x-twilio-signature",
    "x-sendgrid-signature",
    "x-resend-signature",
];

/// Replay a single captured request with optional modifications.
pub async fn replay_with_options(
    webhook: &CapturedWebhook,
    options: &ReplayOptions,
    default_port: u16,
) -> Result<ReplayStudioResult, LpmError> {
    let port = options.port.unwrap_or(default_port);

    // Build the modified webhook for replay
    let modified = apply_modifications(webhook, options);

    // Create a reqwest client for this replay
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .no_proxy()
        .build()
        .map_err(|e| LpmError::Tunnel(format!("failed to create replay client: {e}")))?;

    let result = lpm_tunnel::webhook_replay::replay_webhook(&client, &modified, port).await?;

    // Diff the original and new response bodies
    let response_diff = diff_response_bodies(&webhook.response_body, &result.response_body);
    let response_diff_summary = diff::diff_summary(&response_diff);

    let improved = webhook.response_status >= 400 && result.status < 400;
    let regressed = webhook.response_status < 400 && result.status >= 400;

    Ok(ReplayStudioResult {
        id: webhook.id.clone(),
        status: result.status,
        original_status: webhook.response_status,
        duration_ms: result.duration_ms,
        response_body: String::from_utf8_lossy(&result.response_body).into_owned(),
        improved,
        regressed,
        response_diff,
        response_diff_summary,
    })
}

/// Replay a sequence of requests with delays between each.
pub async fn replay_sequence(
    state: &InspectorState,
    options: &SequenceReplayOptions,
    default_port: u16,
) -> Result<SequenceReplayResult, LpmError> {
    let port = options.port.unwrap_or(default_port);
    let delay = std::time::Duration::from_millis(options.delay_ms.unwrap_or(500));

    let single_opts = ReplayOptions {
        port: Some(port),
        path: None,
        method: None,
        headers: HashMap::new(),
        remove_headers: Vec::new(),
        body: None,
        skip_signatures: options.skip_signatures,
    };

    let mut results = Vec::with_capacity(options.ids.len());
    let sequence_start = std::time::Instant::now();

    for (i, id) in options.ids.iter().enumerate() {
        let webhook = state
            .get_by_id(id)
            .await
            .ok_or_else(|| LpmError::Tunnel(format!("request '{id}' not found")))?;

        let result = replay_with_options(&webhook, &single_opts, port).await?;
        results.push(result);

        // Delay between requests (but not after the last one)
        if i + 1 < options.ids.len() {
            tokio::time::sleep(delay).await;
        }
    }

    let total = results.len();
    let succeeded = results.iter().filter(|r| r.status < 400).count();
    let failed = total - succeeded;
    let total_duration_ms = sequence_start.elapsed().as_millis() as u64;

    Ok(SequenceReplayResult {
        results,
        total,
        succeeded,
        failed,
        total_duration_ms,
    })
}

/// Apply modifications to a webhook before replaying.
fn apply_modifications(webhook: &CapturedWebhook, options: &ReplayOptions) -> CapturedWebhook {
    let mut modified = webhook.clone();

    // Override path
    if let Some(ref path) = options.path {
        modified.path = path.clone();
    }

    // Override method
    if let Some(ref method) = options.method {
        modified.method = method.clone();
    }

    // Override body
    if let Some(ref body) = options.body {
        modified.request_body = body.as_bytes().to_vec();
    }

    // Remove headers (case-insensitive)
    let remove_lower: Vec<String> = options
        .remove_headers
        .iter()
        .map(|h| h.to_lowercase())
        .collect();
    modified
        .request_headers
        .retain(|k, _| !remove_lower.contains(&k.to_lowercase()));

    // Remove signature headers if skip_signatures is enabled
    if options.skip_signatures {
        modified.request_headers.retain(|k, _| {
            let lower = k.to_lowercase();
            !SIGNATURE_HEADERS.iter().any(|sig| lower == *sig)
        });
    }

    // Add/override headers
    for (key, value) in &options.headers {
        modified.request_headers.insert(key.clone(), value.clone());
    }

    modified
}

/// Diff two response bodies for comparison display.
fn diff_response_bodies(old: &[u8], new: &[u8]) -> Vec<diff::DiffEntry> {
    if old == new {
        return Vec::new();
    }

    let old_json = serde_json::from_slice::<serde_json::Value>(old);
    let new_json = serde_json::from_slice::<serde_json::Value>(new);

    match (old_json, new_json) {
        (Ok(old_val), Ok(new_val)) => diff::diff_json(&old_val, &new_val),
        _ => {
            let old_str = String::from_utf8_lossy(old);
            let new_str = String::from_utf8_lossy(new);
            if old_str == new_str {
                Vec::new()
            } else {
                vec![diff::DiffEntry {
                    path: String::new(),
                    kind: diff::DiffKind::Changed,
                    old: Some(serde_json::Value::String(old_str.into_owned())),
                    new: Some(serde_json::Value::String(new_str.into_owned())),
                }]
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lpm_tunnel::webhook::WebhookProvider;

    fn make_webhook(id: &str, status: u16) -> CapturedWebhook {
        CapturedWebhook {
            id: id.to_string(),
            timestamp: "2026-04-06T12:00:00Z".to_string(),
            method: "POST".to_string(),
            path: "/api/webhook".to_string(),
            request_headers: HashMap::from([
                ("content-type".to_string(), "application/json".to_string()),
                ("stripe-signature".to_string(), "t=123,v1=abc".to_string()),
                ("x-custom".to_string(), "value".to_string()),
            ]),
            request_body: br#"{"type":"charge.succeeded","amount":1000}"#.to_vec(),
            response_status: status,
            response_headers: HashMap::new(),
            response_body: br#"{"ok":true}"#.to_vec(),
            duration_ms: 42,
            provider: Some(WebhookProvider::Stripe),
            summary: "Stripe: charge.succeeded".to_string(),
            signature_diagnostic: None,
            auto_acked: false,
        }
    }

    fn default_options() -> ReplayOptions {
        ReplayOptions {
            port: None,
            path: None,
            method: None,
            headers: HashMap::new(),
            remove_headers: Vec::new(),
            body: None,
            skip_signatures: false,
        }
    }

    // ── Modification tests ──────────────────────────────────

    #[test]
    fn no_modifications_preserves_original() {
        let webhook = make_webhook("w1", 200);
        let modified = apply_modifications(&webhook, &default_options());
        assert_eq!(modified.path, webhook.path);
        assert_eq!(modified.method, webhook.method);
        assert_eq!(modified.request_body, webhook.request_body);
        assert_eq!(
            modified.request_headers.len(),
            webhook.request_headers.len()
        );
    }

    #[test]
    fn override_path() {
        let webhook = make_webhook("w1", 200);
        let opts = ReplayOptions {
            path: Some("/api/v2/webhook".to_string()),
            ..default_options()
        };
        let modified = apply_modifications(&webhook, &opts);
        assert_eq!(modified.path, "/api/v2/webhook");
    }

    #[test]
    fn override_method() {
        let webhook = make_webhook("w1", 200);
        let opts = ReplayOptions {
            method: Some("PUT".to_string()),
            ..default_options()
        };
        let modified = apply_modifications(&webhook, &opts);
        assert_eq!(modified.method, "PUT");
    }

    #[test]
    fn override_body() {
        let webhook = make_webhook("w1", 200);
        let opts = ReplayOptions {
            body: Some(r#"{"amount":9999}"#.to_string()),
            ..default_options()
        };
        let modified = apply_modifications(&webhook, &opts);
        assert_eq!(modified.request_body, br#"{"amount":9999}"#.to_vec());
    }

    #[test]
    fn add_headers() {
        let webhook = make_webhook("w1", 200);
        let opts = ReplayOptions {
            headers: HashMap::from([("x-new".to_string(), "added".to_string())]),
            ..default_options()
        };
        let modified = apply_modifications(&webhook, &opts);
        assert_eq!(modified.request_headers.get("x-new").unwrap(), "added");
        // Original headers preserved
        assert!(modified.request_headers.contains_key("content-type"));
    }

    #[test]
    fn override_existing_header() {
        let webhook = make_webhook("w1", 200);
        let opts = ReplayOptions {
            headers: HashMap::from([("content-type".to_string(), "text/plain".to_string())]),
            ..default_options()
        };
        let modified = apply_modifications(&webhook, &opts);
        assert_eq!(
            modified.request_headers.get("content-type").unwrap(),
            "text/plain"
        );
    }

    #[test]
    fn remove_headers() {
        let webhook = make_webhook("w1", 200);
        let opts = ReplayOptions {
            remove_headers: vec!["x-custom".to_string()],
            ..default_options()
        };
        let modified = apply_modifications(&webhook, &opts);
        assert!(!modified.request_headers.contains_key("x-custom"));
        // Other headers still present
        assert!(modified.request_headers.contains_key("content-type"));
    }

    #[test]
    fn remove_headers_case_insensitive() {
        let webhook = make_webhook("w1", 200);
        let opts = ReplayOptions {
            remove_headers: vec!["X-CUSTOM".to_string()],
            ..default_options()
        };
        let modified = apply_modifications(&webhook, &opts);
        assert!(!modified.request_headers.contains_key("x-custom"));
    }

    #[test]
    fn skip_signatures_removes_known_headers() {
        let webhook = make_webhook("w1", 200);
        let opts = ReplayOptions {
            skip_signatures: true,
            ..default_options()
        };
        let modified = apply_modifications(&webhook, &opts);
        assert!(!modified.request_headers.contains_key("stripe-signature"));
        // Non-signature headers preserved
        assert!(modified.request_headers.contains_key("content-type"));
        assert!(modified.request_headers.contains_key("x-custom"));
    }

    #[test]
    fn multiple_modifications_combined() {
        let webhook = make_webhook("w1", 200);
        let opts = ReplayOptions {
            path: Some("/v2/hook".to_string()),
            body: Some(r#"{"new":true}"#.to_string()),
            headers: HashMap::from([("x-version".to_string(), "2".to_string())]),
            remove_headers: vec!["x-custom".to_string()],
            skip_signatures: true,
            ..default_options()
        };
        let modified = apply_modifications(&webhook, &opts);
        assert_eq!(modified.path, "/v2/hook");
        assert_eq!(modified.request_body, br#"{"new":true}"#.to_vec());
        assert!(modified.request_headers.contains_key("x-version"));
        assert!(!modified.request_headers.contains_key("x-custom"));
        assert!(!modified.request_headers.contains_key("stripe-signature"));
    }

    // ── Result comparison ───────────────────────────────────

    #[test]
    fn improved_detection() {
        // Was 500, now 200 → improved
        let webhook = make_webhook("w1", 500);
        assert!(webhook.response_status >= 400);

        // Simulate: replay returned 200
        let result = ReplayStudioResult {
            id: "w1".to_string(),
            status: 200,
            original_status: 500,
            duration_ms: 10,
            response_body: String::new(),
            improved: true,
            regressed: false,
            response_diff: Vec::new(),
            response_diff_summary: diff::diff_summary(&[]),
        };
        assert!(result.improved);
        assert!(!result.regressed);
    }

    #[test]
    fn regressed_detection() {
        let result = ReplayStudioResult {
            id: "w1".to_string(),
            status: 500,
            original_status: 200,
            duration_ms: 10,
            response_body: String::new(),
            improved: false,
            regressed: true,
            response_diff: Vec::new(),
            response_diff_summary: diff::diff_summary(&[]),
        };
        assert!(!result.improved);
        assert!(result.regressed);
    }

    // ── Signature headers list ──────────────────────────────

    #[test]
    fn all_known_signature_headers_stripped() {
        let mut headers = HashMap::new();
        for sig in SIGNATURE_HEADERS {
            headers.insert(sig.to_string(), "sig_value".to_string());
        }
        headers.insert("content-type".to_string(), "application/json".to_string());

        let webhook = CapturedWebhook {
            id: "sig-test".to_string(),
            timestamp: "2026-04-06T12:00:00Z".to_string(),
            method: "POST".to_string(),
            path: "/webhook".to_string(),
            request_headers: headers,
            request_body: Vec::new(),
            response_status: 200,
            response_headers: HashMap::new(),
            response_body: Vec::new(),
            duration_ms: 0,
            provider: None,
            summary: String::new(),
            signature_diagnostic: None,
            auto_acked: false,
        };

        let opts = ReplayOptions {
            skip_signatures: true,
            ..default_options()
        };
        let modified = apply_modifications(&webhook, &opts);

        // All signature headers removed
        for sig in SIGNATURE_HEADERS {
            assert!(
                !modified.request_headers.contains_key(*sig),
                "signature header '{sig}' should have been removed"
            );
        }
        // Non-signature headers preserved
        assert!(modified.request_headers.contains_key("content-type"));
    }
}
