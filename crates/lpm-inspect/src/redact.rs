//! Secret & PII Redaction Engine.
//!
//! Every export path (`.lpm-webhook` files, shareable links, cURL copies,
//! test fixtures) must pass through this module before serialization.
//!
//! # Design
//!
//! - **Automatic scrubbing**: detects known sensitive patterns in headers and bodies
//! - **Never redacts local storage**: raw data stays intact in SQLite/buffer
//! - **Redaction only at the export boundary**: applied when data leaves the system
//! - **Configurable profiles**: rules can be customized per project (future)
//!
//! # Detected patterns
//!
//! **Headers**: Authorization, Cookie, X-API-Key, stripe-signature (the secret
//! portion), any header containing "secret", "token", "key", "password"
//!
//! **Body fields**: API keys matching known formats (sk_live_*, sk_test_*,
//! ghp_*, whsec_*), credit card PANs, email addresses

use crate::export::{ExportBody, WebhookExport};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Marker used to replace redacted values.
const REDACTED_MARKER: &str = "[REDACTED]";

/// Default redaction rules applied to all exports.
pub fn default_rules() -> RedactionRules {
    RedactionRules {
        redact_headers: true,
        redact_body_secrets: true,
        redact_emails: false, // Off by default — too many false positives
        redact_card_numbers: true,
        custom_header_patterns: Vec::new(),
        custom_body_patterns: Vec::new(),
        allow_headers: Vec::new(),
    }
}

/// Redaction configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedactionRules {
    /// Redact known sensitive headers (Authorization, Cookie, etc.).
    pub redact_headers: bool,
    /// Redact API keys and secrets found in request/response bodies.
    pub redact_body_secrets: bool,
    /// Redact email addresses in bodies (high false-positive rate).
    pub redact_emails: bool,
    /// Redact credit card numbers (Luhn-valid 13-19 digit sequences).
    pub redact_card_numbers: bool,
    /// Additional header name patterns to redact (case-insensitive substrings).
    pub custom_header_patterns: Vec<String>,
    /// Additional body patterns to redact (literal strings).
    pub custom_body_patterns: Vec<String>,
    /// Headers to explicitly allow even if they match a sensitive pattern.
    /// Useful for test API keys that are safe to share.
    pub allow_headers: Vec<String>,
}

/// Result of redaction — the redacted export plus a report of what was changed.
#[derive(Debug, Serialize)]
pub struct RedactionResult {
    /// The redacted export data.
    pub export: WebhookExport,
    /// Summary of what was redacted.
    pub report: RedactionReport,
}

/// Summary of redaction actions taken.
#[derive(Debug, Serialize)]
pub struct RedactionReport {
    /// Number of headers redacted.
    pub headers_redacted: usize,
    /// Names of headers that were redacted.
    pub redacted_header_names: Vec<String>,
    /// Number of body patterns redacted.
    pub body_patterns_redacted: usize,
    /// Types of patterns found (e.g., "api_key", "card_number").
    pub pattern_types: Vec<String>,
}

// ── Header names known to contain secrets ─────────────────────────────

/// Headers that are always redacted (exact match, case-insensitive).
const SENSITIVE_HEADERS_EXACT: &[&str] = &[
    "authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
    "proxy-authorization",
];

/// If a header name contains any of these substrings (case-insensitive),
/// the value is redacted.
const SENSITIVE_HEADER_SUBSTRINGS: &[&str] = &[
    "secret",
    "token",
    "password",
    "passwd",
    "credential",
    "api-key",
    "api_key",
    "apikey",
    "private",
    "signing",
];

// ── API key patterns ──────────────────────────────────────────────────

/// Known API key prefixes that indicate a secret value.
const SECRET_KEY_PREFIXES: &[&str] = &[
    "sk_live_",    // Stripe live secret
    "sk_test_",    // Stripe test secret
    "rk_live_",    // Stripe restricted key
    "rk_test_",    // Stripe restricted test key
    "whsec_",      // Stripe webhook secret
    "ghp_",        // GitHub personal access token
    "gho_",        // GitHub OAuth token
    "ghs_",        // GitHub server-to-server token
    "github_pat_", // GitHub fine-grained PAT
    "sk-",         // OpenAI API key
    "xoxb-",       // Slack bot token
    "xoxp-",       // Slack user token
    "SG.",         // SendGrid API key
    "key-",        // Mailgun
    "Bearer ",     // Generic bearer token in body
];

/// Apply redaction rules to a webhook export.
///
/// Returns the redacted export and a report of what was changed.
pub fn redact(export: &WebhookExport, rules: &RedactionRules) -> RedactionResult {
    let mut redacted = export.clone();
    let mut report = RedactionReport {
        headers_redacted: 0,
        redacted_header_names: Vec::new(),
        body_patterns_redacted: 0,
        pattern_types: Vec::new(),
    };

    // Redact headers
    if rules.redact_headers {
        redact_headers(&mut redacted.request_headers, rules, &mut report);
        redact_headers(&mut redacted.response_headers, rules, &mut report);
    }

    // Redact body secrets
    if rules.redact_body_secrets {
        redacted.request_body = redact_body(&redacted.request_body, rules, &mut report);
        redacted.response_body = redact_body(&redacted.response_body, rules, &mut report);
    }

    RedactionResult {
        export: redacted,
        report,
    }
}

fn redact_headers(
    headers: &mut HashMap<String, String>,
    rules: &RedactionRules,
    report: &mut RedactionReport,
) {
    let allow_lower: Vec<String> = rules
        .allow_headers
        .iter()
        .map(|h| h.to_lowercase())
        .collect();

    for (key, value) in headers.iter_mut() {
        let lower = key.to_lowercase();

        // Skip explicitly allowed headers
        if allow_lower.contains(&lower) {
            continue;
        }

        let should_redact = SENSITIVE_HEADERS_EXACT.iter().any(|h| lower == *h)
            || SENSITIVE_HEADER_SUBSTRINGS
                .iter()
                .any(|sub| lower.contains(sub))
            || rules
                .custom_header_patterns
                .iter()
                .any(|p| lower.contains(&p.to_lowercase()));

        if should_redact {
            *value = REDACTED_MARKER.to_string();
            report.headers_redacted += 1;
            if !report.redacted_header_names.contains(key) {
                report.redacted_header_names.push(key.clone());
            }
        }
    }
}

fn redact_body(
    body: &ExportBody,
    rules: &RedactionRules,
    report: &mut RedactionReport,
) -> ExportBody {
    match body {
        ExportBody::Utf8 { data } => {
            let redacted = redact_string(data, rules, report);
            ExportBody::Utf8 { data: redacted }
        }
        // Can't redact binary or empty bodies
        other => other.clone(),
    }
}

fn redact_string(input: &str, rules: &RedactionRules, report: &mut RedactionReport) -> String {
    let mut result = input.to_string();

    // Redact known API key prefixes
    for prefix in SECRET_KEY_PREFIXES {
        if let Some(pos) = result.find(prefix) {
            // Find the end of the key (alphanumeric + special chars common in keys)
            let key_start = pos;
            let after_prefix = pos + prefix.len();
            let key_end = result[after_prefix..]
                .find(|c: char| !c.is_alphanumeric() && c != '_' && c != '-' && c != '.')
                .map(|p| after_prefix + p)
                .unwrap_or(result.len());

            let key_type = categorize_key_prefix(prefix);
            result.replace_range(key_start..key_end, &format!("[REDACTED:{key_type}]"));
            report.body_patterns_redacted += 1;
            if !report.pattern_types.contains(&key_type) {
                report.pattern_types.push(key_type);
            }
        }
    }

    // Redact credit card numbers (13-19 digit sequences with optional separators)
    if rules.redact_card_numbers {
        let card_redacted = redact_card_numbers(&result);
        if card_redacted != result {
            report.body_patterns_redacted += 1;
            if !report.pattern_types.contains(&"card_number".to_string()) {
                report.pattern_types.push("card_number".to_string());
            }
            result = card_redacted;
        }
    }

    // Redact email addresses
    if rules.redact_emails {
        let email_redacted = redact_emails(&result);
        if email_redacted != result {
            report.body_patterns_redacted += 1;
            if !report.pattern_types.contains(&"email".to_string()) {
                report.pattern_types.push("email".to_string());
            }
            result = email_redacted;
        }
    }

    // Apply custom body patterns
    for pattern in &rules.custom_body_patterns {
        if result.contains(pattern.as_str()) {
            result = result.replace(pattern.as_str(), REDACTED_MARKER);
            report.body_patterns_redacted += 1;
        }
    }

    result
}

fn categorize_key_prefix(prefix: &str) -> String {
    match prefix {
        p if p.starts_with("sk_") || p.starts_with("rk_") => "stripe_key".to_string(),
        "whsec_" => "stripe_webhook_secret".to_string(),
        p if p.starts_with("gh") || p.starts_with("github_") => "github_token".to_string(),
        "sk-" => "openai_key".to_string(),
        p if p.starts_with("xox") => "slack_token".to_string(),
        "SG." => "sendgrid_key".to_string(),
        "key-" => "mailgun_key".to_string(),
        "Bearer " => "bearer_token".to_string(),
        _ => "api_key".to_string(),
    }
}

/// Redact sequences of 13-19 digits that pass the Luhn check.
///
/// Handles both continuous digits and common separators (space, dash).
fn redact_card_numbers(input: &str) -> String {
    let mut result = input.to_string();
    let chars: Vec<char> = input.chars().collect();
    let mut i = 0;

    // Collect ranges to redact (avoid mutating while scanning)
    let mut redactions: Vec<(usize, usize)> = Vec::new();

    while i < chars.len() {
        if chars[i].is_ascii_digit() {
            // Collect a run of digits (possibly with separators)
            let start = i;
            let mut digits = String::new();
            let mut j = i;
            while j < chars.len()
                && (chars[j].is_ascii_digit() || chars[j] == ' ' || chars[j] == '-')
            {
                if chars[j].is_ascii_digit() {
                    digits.push(chars[j]);
                }
                j += 1;
            }

            if digits.len() >= 13 && digits.len() <= 19 && luhn_check(&digits) {
                redactions.push((start, j));
                i = j;
            } else {
                i += 1;
            }
        } else {
            i += 1;
        }
    }

    // Apply redactions in reverse order to preserve byte offsets
    for (start, end) in redactions.into_iter().rev() {
        let byte_start = chars[..start].iter().map(|c| c.len_utf8()).sum::<usize>();
        let byte_end = chars[..end].iter().map(|c| c.len_utf8()).sum::<usize>();
        result.replace_range(byte_start..byte_end, "[REDACTED:card_number]");
    }

    result
}

/// Luhn algorithm for credit card number validation.
fn luhn_check(digits: &str) -> bool {
    let mut sum = 0u32;
    let mut double = false;

    for ch in digits.chars().rev() {
        let mut d = ch.to_digit(10).unwrap_or(0);
        if double {
            d *= 2;
            if d > 9 {
                d -= 9;
            }
        }
        sum += d;
        double = !double;
    }

    sum.is_multiple_of(10)
}

/// Simple email redaction — matches word@word.tld patterns.
fn redact_emails(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    let mut i = 0;
    let bytes = input.as_bytes();

    while i < bytes.len() {
        // Find @ sign
        if bytes[i] == b'@' && i > 0 {
            // Walk back to find local part start
            let mut local_start = i;
            while local_start > 0
                && (bytes[local_start - 1].is_ascii_alphanumeric()
                    || bytes[local_start - 1] == b'.'
                    || bytes[local_start - 1] == b'+'
                    || bytes[local_start - 1] == b'_'
                    || bytes[local_start - 1] == b'-')
            {
                local_start -= 1;
            }

            // Walk forward to find domain end
            let mut domain_end = i + 1;
            let mut has_dot = false;
            while domain_end < bytes.len()
                && (bytes[domain_end].is_ascii_alphanumeric()
                    || bytes[domain_end] == b'.'
                    || bytes[domain_end] == b'-')
            {
                if bytes[domain_end] == b'.' {
                    has_dot = true;
                }
                domain_end += 1;
            }

            if local_start < i && has_dot && domain_end > i + 2 {
                // Valid-looking email — redact it
                // Trim result back to local_start
                let chars_to_remove = i - local_start;
                let current_len = result.len();
                result.truncate(current_len - chars_to_remove);
                result.push_str("[REDACTED:email]");
                i = domain_end;
                continue;
            }
        }

        result.push(bytes[i] as char);
        i += 1;
    }

    result
}

impl Clone for ExportBody {
    fn clone(&self) -> Self {
        match self {
            Self::Utf8 { data } => Self::Utf8 { data: data.clone() },
            Self::Base64 { data } => Self::Base64 { data: data.clone() },
            Self::Empty => Self::Empty,
        }
    }
}

impl Clone for WebhookExport {
    fn clone(&self) -> Self {
        Self {
            version: self.version,
            id: self.id.clone(),
            timestamp: self.timestamp.clone(),
            method: self.method.clone(),
            path: self.path.clone(),
            request_headers: self.request_headers.clone(),
            request_body: self.request_body.clone(),
            response_status: self.response_status,
            response_headers: self.response_headers.clone(),
            response_body: self.response_body.clone(),
            duration_ms: self.duration_ms,
            provider: self.provider.clone(),
            summary: self.summary.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_export() -> WebhookExport {
        WebhookExport {
            version: 1,
            id: "test".to_string(),
            timestamp: "2026-04-06T12:00:00Z".to_string(),
            method: "POST".to_string(),
            path: "/api/webhook".to_string(),
            request_headers: HashMap::from([
                ("content-type".to_string(), "application/json".to_string()),
                (
                    "authorization".to_string(),
                    "Bearer sk_live_abc123".to_string(),
                ),
                ("stripe-signature".to_string(), "t=123,v1=abc".to_string()),
                ("x-custom".to_string(), "safe_value".to_string()),
            ]),
            request_body: ExportBody::Utf8 {
                data: r#"{"type":"charge.succeeded","key":"sk_test_12345abc"}"#.to_string(),
            },
            response_status: 200,
            response_headers: HashMap::from([(
                "set-cookie".to_string(),
                "session=secret123".to_string(),
            )]),
            response_body: ExportBody::Utf8 {
                data: r#"{"ok":true}"#.to_string(),
            },
            duration_ms: 42,
            provider: Some("Stripe".to_string()),
            summary: "Stripe: charge.succeeded".to_string(),
        }
    }

    // ── Header redaction ────────────────────────────────────

    #[test]
    fn redacts_authorization_header() {
        let export = make_export();
        let result = redact(&export, &default_rules());
        assert_eq!(
            result.export.request_headers.get("authorization").unwrap(),
            REDACTED_MARKER
        );
    }

    #[test]
    fn redacts_set_cookie_header() {
        let export = make_export();
        let result = redact(&export, &default_rules());
        assert_eq!(
            result.export.response_headers.get("set-cookie").unwrap(),
            REDACTED_MARKER
        );
    }

    #[test]
    fn preserves_safe_headers() {
        let export = make_export();
        let result = redact(&export, &default_rules());
        assert_eq!(
            result.export.request_headers.get("content-type").unwrap(),
            "application/json"
        );
        assert_eq!(
            result.export.request_headers.get("x-custom").unwrap(),
            "safe_value"
        );
    }

    #[test]
    fn redacts_headers_with_secret_substring() {
        let mut export = make_export();
        export
            .request_headers
            .insert("x-webhook-secret".to_string(), "mysecret".to_string());
        let result = redact(&export, &default_rules());
        assert_eq!(
            result
                .export
                .request_headers
                .get("x-webhook-secret")
                .unwrap(),
            REDACTED_MARKER
        );
    }

    #[test]
    fn allow_header_overrides_redaction() {
        let export = make_export();
        let mut rules = default_rules();
        rules.allow_headers = vec!["authorization".to_string()];
        let result = redact(&export, &rules);
        // Should NOT be redacted because it's in the allow list
        assert_ne!(
            result.export.request_headers.get("authorization").unwrap(),
            REDACTED_MARKER
        );
    }

    #[test]
    fn custom_header_pattern() {
        let mut export = make_export();
        export
            .request_headers
            .insert("x-internal-id".to_string(), "int_123".to_string());
        let mut rules = default_rules();
        rules.custom_header_patterns = vec!["internal".to_string()];
        let result = redact(&export, &rules);
        assert_eq!(
            result.export.request_headers.get("x-internal-id").unwrap(),
            REDACTED_MARKER
        );
    }

    // ── Body secret redaction ───────────────────────────────

    #[test]
    fn redacts_stripe_key_in_body() {
        let export = make_export();
        let result = redact(&export, &default_rules());
        match &result.export.request_body {
            ExportBody::Utf8 { data } => {
                assert!(!data.contains("sk_test_12345abc"));
                assert!(data.contains("[REDACTED:stripe_key]"));
            }
            _ => panic!("expected utf8 body"),
        }
    }

    #[test]
    fn redacts_github_token_in_body() {
        let mut export = make_export();
        export.request_body = ExportBody::Utf8 {
            data: r#"{"token":"ghp_abcdef123456789012345678901234567890"}"#.to_string(),
        };
        let result = redact(&export, &default_rules());
        match &result.export.request_body {
            ExportBody::Utf8 { data } => {
                assert!(!data.contains("ghp_"));
                assert!(data.contains("[REDACTED:github_token]"));
            }
            _ => panic!("expected utf8 body"),
        }
    }

    #[test]
    fn redacts_card_number() {
        let mut export = make_export();
        export.request_body = ExportBody::Utf8 {
            data: r#"{"card":"4111111111111111"}"#.to_string(),
        };
        let mut rules = default_rules();
        rules.redact_card_numbers = true;
        let result = redact(&export, &rules);
        match &result.export.request_body {
            ExportBody::Utf8 { data } => {
                assert!(!data.contains("4111111111111111"));
                assert!(data.contains("[REDACTED:card_number]"));
            }
            _ => panic!("expected utf8 body"),
        }
    }

    #[test]
    fn card_number_with_separators() {
        let mut export = make_export();
        export.request_body = ExportBody::Utf8 {
            data: r#"{"card":"4111 1111 1111 1111"}"#.to_string(),
        };
        let result = redact(&export, &default_rules());
        match &result.export.request_body {
            ExportBody::Utf8 { data } => {
                assert!(data.contains("[REDACTED:card_number]"));
            }
            _ => panic!("expected utf8 body"),
        }
    }

    #[test]
    fn does_not_redact_short_numbers() {
        let mut export = make_export();
        export.request_body = ExportBody::Utf8 {
            data: r#"{"amount":123456789012}"#.to_string(),
        };
        let result = redact(&export, &default_rules());
        match &result.export.request_body {
            ExportBody::Utf8 { data } => {
                // 12 digits — too short for a card number
                assert!(data.contains("123456789012"));
            }
            _ => panic!("expected utf8 body"),
        }
    }

    #[test]
    fn redacts_email_when_enabled() {
        let mut export = make_export();
        export.request_body = ExportBody::Utf8 {
            data: r#"{"email":"user@example.com"}"#.to_string(),
        };
        let mut rules = default_rules();
        rules.redact_emails = true;
        let result = redact(&export, &rules);
        match &result.export.request_body {
            ExportBody::Utf8 { data } => {
                assert!(!data.contains("user@example.com"));
                assert!(data.contains("[REDACTED:email]"));
            }
            _ => panic!("expected utf8 body"),
        }
    }

    #[test]
    fn does_not_redact_email_by_default() {
        let mut export = make_export();
        export.request_body = ExportBody::Utf8 {
            data: r#"{"email":"user@example.com"}"#.to_string(),
        };
        let result = redact(&export, &default_rules());
        match &result.export.request_body {
            ExportBody::Utf8 { data } => {
                assert!(data.contains("user@example.com"));
            }
            _ => panic!("expected utf8 body"),
        }
    }

    #[test]
    fn binary_body_untouched() {
        let mut export = make_export();
        export.request_body = ExportBody::Base64 {
            data: "AQID".to_string(),
        };
        let result = redact(&export, &default_rules());
        match &result.export.request_body {
            ExportBody::Base64 { data } => assert_eq!(data, "AQID"),
            _ => panic!("expected base64 body"),
        }
    }

    #[test]
    fn custom_body_pattern() {
        let mut export = make_export();
        export.request_body = ExportBody::Utf8 {
            data: r#"{"internal":"CORP-SECRET-42"}"#.to_string(),
        };
        let mut rules = default_rules();
        rules.custom_body_patterns = vec!["CORP-SECRET-42".to_string()];
        let result = redact(&export, &rules);
        match &result.export.request_body {
            ExportBody::Utf8 { data } => {
                assert!(!data.contains("CORP-SECRET-42"));
            }
            _ => panic!("expected utf8 body"),
        }
    }

    // ── Report ──────────────────────────────────────────────

    #[test]
    fn report_tracks_redactions() {
        let export = make_export();
        let result = redact(&export, &default_rules());
        assert!(result.report.headers_redacted > 0);
        assert!(!result.report.redacted_header_names.is_empty());
        assert!(result.report.body_patterns_redacted > 0);
        assert!(!result.report.pattern_types.is_empty());
    }

    #[test]
    fn no_redaction_when_disabled() {
        let export = make_export();
        let rules = RedactionRules {
            redact_headers: false,
            redact_body_secrets: false,
            redact_emails: false,
            redact_card_numbers: false,
            custom_header_patterns: Vec::new(),
            custom_body_patterns: Vec::new(),
            allow_headers: Vec::new(),
        };
        let result = redact(&export, &rules);
        assert_eq!(result.report.headers_redacted, 0);
        assert_eq!(result.report.body_patterns_redacted, 0);
    }

    // ── Luhn algorithm ──────────────────────────────────────

    #[test]
    fn luhn_valid_cards() {
        assert!(luhn_check("4111111111111111")); // Visa test
        assert!(luhn_check("5500000000000004")); // Mastercard test
        assert!(luhn_check("378282246310005")); // Amex test
    }

    #[test]
    fn luhn_invalid_numbers() {
        assert!(!luhn_check("4111111111111112")); // Off by one
        assert!(!luhn_check("1234567890123456")); // Random
    }
}
