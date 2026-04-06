//! Shareable Webhook Snapshots.
//!
//! Export captured requests as portable `.lpm-webhook` files that teammates
//! can import, inspect, and replay against their own local server.
//!
//! # Workflow
//!
//! 1. Developer captures a webhook that reproduces a bug
//! 2. Exports it as a snapshot (with automatic redaction)
//! 3. Shares the `.lpm-webhook` file via Slack/GitHub/email
//! 4. Teammate imports the snapshot into their inspector
//! 5. Teammate replays it against their local server
//!
//! # Format
//!
//! A snapshot is a JSON file containing one or more `WebhookExport` objects
//! with metadata (creator, timestamp, description). The format is versioned
//! for forward compatibility.

use crate::export::{WebhookExport, to_webhook_json};
use crate::redact::{self, RedactionRules};
use lpm_tunnel::webhook::CapturedWebhook;
use serde::{Deserialize, Serialize};

/// Snapshot file format — wraps one or more exported webhooks with metadata.
#[derive(Debug, Serialize, Deserialize)]
pub struct Snapshot {
    /// Schema version.
    pub version: u8,
    /// Snapshot metadata.
    pub metadata: SnapshotMetadata,
    /// The exported webhooks (always redacted before inclusion).
    pub webhooks: Vec<WebhookExport>,
}

/// Metadata about when and why the snapshot was created.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SnapshotMetadata {
    /// When the snapshot was created (ISO 8601).
    pub created_at: String,
    /// Optional description (e.g., "bug repro for #234").
    pub description: Option<String>,
    /// Number of webhooks in the snapshot.
    pub count: usize,
    /// Provider names found in the snapshot.
    pub providers: Vec<String>,
    /// Summary of redactions applied.
    pub redaction_summary: RedactionSummary,
}

/// Summary of what was redacted when creating the snapshot.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RedactionSummary {
    pub total_headers_redacted: usize,
    pub total_body_patterns_redacted: usize,
    pub pattern_types: Vec<String>,
}

/// Options for creating a snapshot.
#[derive(Debug, Deserialize)]
pub struct SnapshotOptions {
    /// Request IDs to include in the snapshot.
    pub ids: Vec<String>,
    /// Optional description.
    pub description: Option<String>,
    /// Redaction rules (defaults applied if not provided).
    pub redaction: Option<RedactionRules>,
}

/// Create a snapshot from a list of captured webhooks.
///
/// Applies redaction to every webhook before inclusion. Returns the
/// snapshot structure ready for serialization to a `.lpm-webhook` file.
pub fn create_snapshot(
    webhooks: &[CapturedWebhook],
    description: Option<String>,
    rules: &RedactionRules,
) -> Snapshot {
    let mut exported: Vec<WebhookExport> = Vec::with_capacity(webhooks.len());
    let mut total_headers = 0;
    let mut total_body = 0;
    let mut all_pattern_types: Vec<String> = Vec::new();
    let mut providers: Vec<String> = Vec::new();

    for webhook in webhooks {
        let raw_export = to_webhook_json(webhook);
        let result = redact::redact(&raw_export, rules);

        total_headers += result.report.headers_redacted;
        total_body += result.report.body_patterns_redacted;
        for pt in &result.report.pattern_types {
            if !all_pattern_types.contains(pt) {
                all_pattern_types.push(pt.clone());
            }
        }

        if let Some(ref provider) = webhook.provider {
            let name = provider.to_string();
            if !providers.contains(&name) {
                providers.push(name);
            }
        }

        exported.push(result.export);
    }

    Snapshot {
        version: 1,
        metadata: SnapshotMetadata {
            created_at: chrono::Utc::now().to_rfc3339(),
            description,
            count: exported.len(),
            providers,
            redaction_summary: RedactionSummary {
                total_headers_redacted: total_headers,
                total_body_patterns_redacted: total_body,
                pattern_types: all_pattern_types,
            },
        },
        webhooks: exported,
    }
}

/// Import a snapshot from a JSON string.
///
/// Validates the schema version and returns the parsed snapshot.
pub fn import_snapshot(json: &str) -> Result<Snapshot, SnapshotError> {
    let snapshot: Snapshot =
        serde_json::from_str(json).map_err(|e| SnapshotError::InvalidFormat(e.to_string()))?;

    if snapshot.version == 0 || snapshot.version > 1 {
        return Err(SnapshotError::UnsupportedVersion(snapshot.version));
    }

    if snapshot.webhooks.is_empty() {
        return Err(SnapshotError::Empty);
    }

    if snapshot.webhooks.len() > 100 {
        return Err(SnapshotError::TooLarge(snapshot.webhooks.len()));
    }

    Ok(snapshot)
}

/// Convert a snapshot webhook back into a `CapturedWebhook` for replay.
///
/// Note: redacted fields will contain `[REDACTED:...]` markers. The replay
/// will send these as-is, which is usually fine for testing handler logic
/// (the handler doesn't validate the body content against the signature
/// when `skip_signatures` is used in the Replay Studio).
pub fn snapshot_to_captured(export: &WebhookExport) -> CapturedWebhook {
    CapturedWebhook {
        id: export.id.clone(),
        timestamp: export.timestamp.clone(),
        method: export.method.clone(),
        path: export.path.clone(),
        request_headers: export.request_headers.clone(),
        request_body: export_body_to_bytes(&export.request_body),
        response_status: export.response_status,
        response_headers: export.response_headers.clone(),
        response_body: export_body_to_bytes(&export.response_body),
        duration_ms: export.duration_ms,
        provider: None, // Lost in export — provider detection re-runs on import
        summary: export.summary.clone(),
        signature_diagnostic: None,
        auto_acked: false,
    }
}

fn export_body_to_bytes(body: &crate::export::ExportBody) -> Vec<u8> {
    match body {
        crate::export::ExportBody::Utf8 { data } => data.as_bytes().to_vec(),
        crate::export::ExportBody::Base64 { data } => {
            use base64::Engine;
            base64::engine::general_purpose::STANDARD
                .decode(data)
                .unwrap_or_default()
        }
        crate::export::ExportBody::Empty => Vec::new(),
    }
}

/// Errors that can occur during snapshot import.
#[derive(Debug)]
pub enum SnapshotError {
    /// The JSON couldn't be parsed as a valid snapshot.
    InvalidFormat(String),
    /// The snapshot version is not supported by this client.
    UnsupportedVersion(u8),
    /// The snapshot contains no webhooks.
    Empty,
    /// The snapshot contains too many webhooks (max 100).
    TooLarge(usize),
}

impl std::fmt::Display for SnapshotError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidFormat(e) => write!(f, "invalid snapshot format: {e}"),
            Self::UnsupportedVersion(v) => write!(f, "unsupported snapshot version: {v}"),
            Self::Empty => write!(f, "snapshot contains no webhooks"),
            Self::TooLarge(n) => write!(f, "snapshot too large: {n} webhooks (max 100)"),
        }
    }
}

impl std::error::Error for SnapshotError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::export::ExportBody;
    use lpm_tunnel::webhook::WebhookProvider;
    use std::collections::HashMap;

    fn make_webhook(id: &str) -> CapturedWebhook {
        CapturedWebhook {
            id: id.to_string(),
            timestamp: "2026-04-06T12:00:00Z".to_string(),
            method: "POST".to_string(),
            path: "/api/webhook".to_string(),
            request_headers: HashMap::from([
                ("content-type".to_string(), "application/json".to_string()),
                (
                    "authorization".to_string(),
                    "Bearer sk_live_secret123".to_string(),
                ),
            ]),
            request_body: br#"{"type":"charge.succeeded","key":"sk_test_abc"}"#.to_vec(),
            response_status: 200,
            response_headers: HashMap::new(),
            response_body: br#"{"ok":true}"#.to_vec(),
            duration_ms: 42,
            provider: Some(WebhookProvider::Stripe),
            summary: "Stripe: charge.succeeded".to_string(),
            signature_diagnostic: None,
            auto_acked: false,
        }
    }

    // ── Snapshot creation ───────────────────────────────────

    #[test]
    fn create_single_webhook_snapshot() {
        let wh = make_webhook("w1");
        let rules = redact::default_rules();
        let snapshot = create_snapshot(&[wh], Some("bug repro".to_string()), &rules);

        assert_eq!(snapshot.version, 1);
        assert_eq!(snapshot.metadata.count, 1);
        assert_eq!(snapshot.metadata.description, Some("bug repro".to_string()));
        assert_eq!(snapshot.metadata.providers, vec!["Stripe"]);
        assert_eq!(snapshot.webhooks.len(), 1);
    }

    #[test]
    fn create_multi_webhook_snapshot() {
        let w1 = make_webhook("w1");
        let mut w2 = make_webhook("w2");
        w2.provider = Some(WebhookProvider::GitHub);

        let rules = redact::default_rules();
        let snapshot = create_snapshot(&[w1, w2], None, &rules);

        assert_eq!(snapshot.metadata.count, 2);
        assert!(snapshot.metadata.providers.contains(&"Stripe".to_string()));
        assert!(snapshot.metadata.providers.contains(&"GitHub".to_string()));
    }

    #[test]
    fn snapshot_applies_redaction() {
        let wh = make_webhook("w1");
        let rules = redact::default_rules();
        let snapshot = create_snapshot(&[wh], None, &rules);

        // Authorization header should be redacted
        let export = &snapshot.webhooks[0];
        assert_eq!(
            export.request_headers.get("authorization").unwrap(),
            "[REDACTED]"
        );

        // Body should have redacted API key
        match &export.request_body {
            ExportBody::Utf8 { data } => {
                assert!(!data.contains("sk_test_abc"));
                assert!(data.contains("[REDACTED:stripe_key]"));
            }
            _ => panic!("expected utf8 body"),
        }

        // Redaction summary should be populated
        assert!(snapshot.metadata.redaction_summary.total_headers_redacted > 0);
    }

    #[test]
    fn snapshot_tracks_redaction_summary() {
        let wh = make_webhook("w1");
        let rules = redact::default_rules();
        let snapshot = create_snapshot(&[wh], None, &rules);

        let summary = &snapshot.metadata.redaction_summary;
        assert!(summary.total_headers_redacted > 0);
        assert!(summary.total_body_patterns_redacted > 0);
        assert!(!summary.pattern_types.is_empty());
    }

    // ── Snapshot serialization ──────────────────────────────

    #[test]
    fn snapshot_roundtrip() {
        let wh = make_webhook("w1");
        let rules = redact::default_rules();
        let snapshot = create_snapshot(&[wh], Some("test".to_string()), &rules);

        let json = serde_json::to_string_pretty(&snapshot).unwrap();
        let imported = import_snapshot(&json).unwrap();

        assert_eq!(imported.version, 1);
        assert_eq!(imported.metadata.count, 1);
        assert_eq!(imported.metadata.description, Some("test".to_string()));
        assert_eq!(imported.webhooks.len(), 1);
    }

    // ── Import validation ───────────────────────────────────

    #[test]
    fn import_invalid_json() {
        let result = import_snapshot("not json");
        assert!(matches!(result, Err(SnapshotError::InvalidFormat(_))));
    }

    #[test]
    fn import_unsupported_version() {
        let json = r#"{"version":99,"metadata":{"created_at":"","description":null,"count":1,"providers":[],"redaction_summary":{"total_headers_redacted":0,"total_body_patterns_redacted":0,"pattern_types":[]}},"webhooks":[{"version":1,"id":"x","timestamp":"","method":"POST","path":"/","request_headers":{},"request_body":{"encoding":"empty"},"response_status":200,"response_headers":{},"response_body":{"encoding":"empty"},"duration_ms":0,"provider":null,"summary":""}]}"#;
        let result = import_snapshot(json);
        assert!(matches!(result, Err(SnapshotError::UnsupportedVersion(99))));
    }

    #[test]
    fn import_empty_snapshot() {
        let json = r#"{"version":1,"metadata":{"created_at":"","description":null,"count":0,"providers":[],"redaction_summary":{"total_headers_redacted":0,"total_body_patterns_redacted":0,"pattern_types":[]}},"webhooks":[]}"#;
        let result = import_snapshot(json);
        assert!(matches!(result, Err(SnapshotError::Empty)));
    }

    // ── Snapshot to CapturedWebhook ─────────────────────────

    #[test]
    fn snapshot_to_captured_roundtrip() {
        let wh = make_webhook("w1");
        let export = to_webhook_json(&wh);
        let captured = snapshot_to_captured(&export);

        assert_eq!(captured.id, "w1");
        assert_eq!(captured.method, "POST");
        assert_eq!(captured.path, "/api/webhook");
        assert_eq!(captured.request_body, wh.request_body);
        assert_eq!(captured.response_status, 200);
    }

    #[test]
    fn snapshot_to_captured_empty_body() {
        let mut wh = make_webhook("w1");
        wh.request_body = Vec::new();
        let export = to_webhook_json(&wh);
        let captured = snapshot_to_captured(&export);
        assert!(captured.request_body.is_empty());
    }

    #[test]
    fn snapshot_to_captured_binary_body() {
        let mut wh = make_webhook("w1");
        wh.request_body = vec![0xFF, 0x00, 0xAB];
        let export = to_webhook_json(&wh);
        let captured = snapshot_to_captured(&export);
        assert_eq!(captured.request_body, vec![0xFF, 0x00, 0xAB]);
    }

    // ── Error display ───────────────────────────────────────

    #[test]
    fn error_display() {
        assert!(SnapshotError::Empty.to_string().contains("no webhooks"));
        assert!(
            SnapshotError::UnsupportedVersion(5)
                .to_string()
                .contains("5")
        );
        assert!(SnapshotError::TooLarge(200).to_string().contains("200"));
    }
}
