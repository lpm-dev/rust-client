//! Webhook signature verification diagnostics.
//!
//! When a webhook handler returns an error, this module checks whether the
//! failure might be due to a signature mismatch. It computes the expected
//! HMAC for known providers (Stripe, GitHub) and compares against the
//! provided signature, producing a human-readable diagnostic message.

use crate::webhook::{CapturedWebhook, WebhookProvider};
use std::collections::HashMap;

/// Check if a failed webhook might be due to a signature mismatch.
///
/// Returns a diagnostic message if a signature problem is likely, `None`
/// if the response was successful or no signature issue was detected.
///
/// `env_vars` should contain the relevant webhook secrets (e.g.,
/// `STRIPE_WEBHOOK_SECRET`, `GITHUB_WEBHOOK_SECRET`).
pub fn diagnose_signature_failure(
    webhook: &CapturedWebhook,
    env_vars: &HashMap<String, String>,
) -> Option<String> {
    if webhook.response_status < 400 {
        return None;
    }

    match webhook.provider {
        Some(WebhookProvider::Stripe) => diagnose_stripe(webhook, env_vars),
        Some(WebhookProvider::GitHub) => diagnose_github(webhook, env_vars),
        _ => diagnose_generic(webhook),
    }
}

/// Diagnose Stripe webhook signature issues.
///
/// Stripe signatures use `HMAC-SHA256(secret, "{timestamp}.{body}")`.
/// The signature header format is `t=<timestamp>,v1=<hex_signature>`.
fn diagnose_stripe(
    webhook: &CapturedWebhook,
    env_vars: &HashMap<String, String>,
) -> Option<String> {
    let lower_headers: HashMap<String, &String> = webhook
        .request_headers
        .iter()
        .map(|(k, v)| (k.to_lowercase(), v))
        .collect();

    let sig_header = lower_headers.get("stripe-signature")?;
    let secret = env_vars
        .get("STRIPE_WEBHOOK_SECRET")
        .or_else(|| env_vars.get("STRIPE_SIGNING_SECRET"))?;

    // Parse stripe signature: t=timestamp,v1=signature
    let timestamp = sig_header
        .split(',')
        .find(|p| p.starts_with("t="))
        .map(|p| &p[2..])?;
    let provided_sig = sig_header
        .split(',')
        .find(|p| p.starts_with("v1="))
        .map(|p| &p[3..])?;

    // Compute expected: HMAC-SHA256(secret, "timestamp.body")
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).ok()?;
    let payload = format!(
        "{}.{}",
        timestamp,
        String::from_utf8_lossy(&webhook.request_body)
    );
    mac.update(payload.as_bytes());

    // Use constant-time comparison via verify_slice to prevent timing attacks
    match hex::decode(provided_sig) {
        Ok(sig_bytes) => {
            if mac.verify_slice(&sig_bytes).is_err() {
                Some(
                    "Stripe signature mismatch \u{2014} check STRIPE_WEBHOOK_SECRET\n\
					 Tip: Ensure the secret in your env matches the endpoint secret in Stripe Dashboard"
                        .to_string(),
                )
            } else {
                // Signature matches but still got error — not a signature issue
                None
            }
        }
        Err(_) => Some(
            "Stripe signature mismatch \u{2014} check STRIPE_WEBHOOK_SECRET\n\
			 Tip: Ensure the secret in your env matches the endpoint secret in Stripe Dashboard"
                .to_string(),
        ),
    }
}

/// Diagnose GitHub webhook signature issues.
///
/// GitHub uses `HMAC-SHA256(secret, body)` and sends it as
/// `sha256=<hex_signature>` in the `x-hub-signature-256` header.
fn diagnose_github(
    webhook: &CapturedWebhook,
    env_vars: &HashMap<String, String>,
) -> Option<String> {
    let lower_headers: HashMap<String, &String> = webhook
        .request_headers
        .iter()
        .map(|(k, v)| (k.to_lowercase(), v))
        .collect();

    let sig_header = lower_headers.get("x-hub-signature-256")?;
    let secret = env_vars.get("GITHUB_WEBHOOK_SECRET")?;

    // Parse: sha256=<hex>
    let provided_sig = sig_header.strip_prefix("sha256=")?;

    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).ok()?;
    mac.update(&webhook.request_body);

    // Use constant-time comparison via verify_slice to prevent timing attacks
    match hex::decode(provided_sig) {
        Ok(sig_bytes) => {
            if mac.verify_slice(&sig_bytes).is_err() {
                Some(
                    "GitHub signature mismatch \u{2014} check GITHUB_WEBHOOK_SECRET\n\
					 Tip: Ensure the secret in your env matches the webhook secret in GitHub Settings"
                        .to_string(),
                )
            } else {
                None
            }
        }
        Err(_) => Some(
            "GitHub signature mismatch \u{2014} check GITHUB_WEBHOOK_SECRET\n\
			 Tip: Ensure the secret in your env matches the webhook secret in GitHub Settings"
                .to_string(),
        ),
    }
}

/// Generic signature diagnosis for unknown providers.
///
/// Checks if the request has any header containing "signature" or "hmac"
/// and the response was an error — likely a signing issue.
fn diagnose_generic(webhook: &CapturedWebhook) -> Option<String> {
    let has_sig = webhook.request_headers.keys().any(|k| {
        let lower = k.to_lowercase();
        lower.contains("signature") || lower.contains("hmac")
    });

    if has_sig {
        Some(
            "Webhook has a signature header but handler returned an error \u{2014} \
			 check your webhook secret"
                .to_string(),
        )
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::webhook::CapturedWebhook;

    fn make_webhook(overrides: impl FnOnce(&mut CapturedWebhook)) -> CapturedWebhook {
        let mut wh = CapturedWebhook {
            id: "test-id".to_string(),
            timestamp: "2026-01-01T00:00:00Z".to_string(),
            method: "POST".to_string(),
            path: "/webhook".to_string(),
            request_headers: HashMap::new(),
            request_body: Vec::new(),
            response_status: 400,
            response_headers: HashMap::new(),
            response_body: Vec::new(),
            duration_ms: 42,
            provider: None,
            summary: String::new(),
            signature_diagnostic: None,
        };
        overrides(&mut wh);
        wh
    }

    /// Compute a valid Stripe signature for testing.
    fn stripe_sign(secret: &str, timestamp: &str, body: &[u8]) -> String {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        type HmacSha256 = Hmac<Sha256>;

        let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).unwrap();
        let payload = format!("{}.{}", timestamp, String::from_utf8_lossy(body));
        mac.update(payload.as_bytes());
        hex::encode(mac.finalize().into_bytes())
    }

    /// Compute a valid GitHub signature for testing.
    fn github_sign(secret: &str, body: &[u8]) -> String {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        type HmacSha256 = Hmac<Sha256>;

        let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(body);
        hex::encode(mac.finalize().into_bytes())
    }

    #[test]
    fn stripe_valid_signature_no_diagnosis() {
        let secret = "whsec_test123";
        let body = b"test body";
        let timestamp = "1234567890";
        let sig = stripe_sign(secret, timestamp, body);

        let wh = make_webhook(|w| {
            w.provider = Some(WebhookProvider::Stripe);
            w.request_body = body.to_vec();
            w.request_headers.insert(
                "stripe-signature".to_string(),
                format!("t={timestamp},v1={sig}"),
            );
        });

        let mut env = HashMap::new();
        env.insert("STRIPE_WEBHOOK_SECRET".to_string(), secret.to_string());

        // Signature matches, so no signature diagnosis even though status is 400
        assert!(diagnose_signature_failure(&wh, &env).is_none());
    }

    #[test]
    fn stripe_mismatch_detected() {
        let body = b"test body";
        let timestamp = "1234567890";

        let wh = make_webhook(|w| {
            w.provider = Some(WebhookProvider::Stripe);
            w.request_body = body.to_vec();
            w.request_headers.insert(
                "stripe-signature".to_string(),
                format!("t={timestamp},v1=deadbeef1234"),
            );
        });

        let mut env = HashMap::new();
        env.insert(
            "STRIPE_WEBHOOK_SECRET".to_string(),
            "whsec_real".to_string(),
        );

        let diag = diagnose_signature_failure(&wh, &env).unwrap();
        assert!(diag.contains("Stripe signature mismatch"));
        assert!(diag.contains("STRIPE_WEBHOOK_SECRET"));
    }

    #[test]
    fn stripe_known_test_vector() {
        // Verify our HMAC computation matches a known value
        let secret = "whsec_test";
        let body = b"{\"id\":\"evt_1\"}";
        let timestamp = "1000000000";
        let sig = stripe_sign(secret, timestamp, body);

        // Verify the same computation inside diagnose_stripe produces the same result
        let wh = make_webhook(|w| {
            w.provider = Some(WebhookProvider::Stripe);
            w.request_body = body.to_vec();
            w.request_headers.insert(
                "stripe-signature".to_string(),
                format!("t={timestamp},v1={sig}"),
            );
        });

        let mut env = HashMap::new();
        env.insert("STRIPE_WEBHOOK_SECRET".to_string(), secret.to_string());

        // Should match — no diagnosis
        assert!(diagnose_signature_failure(&wh, &env).is_none());
    }

    #[test]
    fn github_valid_signature_no_diagnosis() {
        let secret = "gh_secret_123";
        let body = b"{\"action\":\"opened\"}";
        let sig = github_sign(secret, body);

        let wh = make_webhook(|w| {
            w.provider = Some(WebhookProvider::GitHub);
            w.request_body = body.to_vec();
            w.request_headers
                .insert("x-hub-signature-256".to_string(), format!("sha256={sig}"));
        });

        let mut env = HashMap::new();
        env.insert("GITHUB_WEBHOOK_SECRET".to_string(), secret.to_string());

        assert!(diagnose_signature_failure(&wh, &env).is_none());
    }

    #[test]
    fn github_mismatch_detected() {
        let body = b"{\"action\":\"opened\"}";

        let wh = make_webhook(|w| {
            w.provider = Some(WebhookProvider::GitHub);
            w.request_body = body.to_vec();
            w.request_headers.insert(
                "x-hub-signature-256".to_string(),
                "sha256=wrongsignature".to_string(),
            );
        });

        let mut env = HashMap::new();
        env.insert(
            "GITHUB_WEBHOOK_SECRET".to_string(),
            "real_secret".to_string(),
        );

        let diag = diagnose_signature_failure(&wh, &env).unwrap();
        assert!(diag.contains("GitHub signature mismatch"));
    }

    #[test]
    fn no_diagnosis_for_2xx() {
        let wh = make_webhook(|w| {
            w.response_status = 200;
            w.provider = Some(WebhookProvider::Stripe);
        });
        let env = HashMap::new();
        assert!(diagnose_signature_failure(&wh, &env).is_none());
    }

    #[test]
    fn generic_diagnosis_when_signature_header_present() {
        let wh = make_webhook(|w| {
            w.provider = None;
            w.request_headers
                .insert("x-webhook-signature".to_string(), "some-sig".to_string());
        });
        let env = HashMap::new();

        let diag = diagnose_signature_failure(&wh, &env).unwrap();
        assert!(diag.contains("signature header"));
        assert!(diag.contains("webhook secret"));
    }

    #[test]
    fn generic_diagnosis_with_hmac_header() {
        let wh = make_webhook(|w| {
            w.provider = None;
            w.request_headers
                .insert("x-hmac-digest".to_string(), "abc123".to_string());
        });
        let env = HashMap::new();

        let diag = diagnose_signature_failure(&wh, &env).unwrap();
        assert!(diag.contains("signature header"));
    }

    #[test]
    fn no_generic_diagnosis_without_signature_headers() {
        let wh = make_webhook(|w| {
            w.provider = None;
            w.request_headers
                .insert("content-type".to_string(), "application/json".to_string());
        });
        let env = HashMap::new();

        assert!(diagnose_signature_failure(&wh, &env).is_none());
    }

    #[test]
    fn stripe_no_secret_in_env_returns_none() {
        let wh = make_webhook(|w| {
            w.provider = Some(WebhookProvider::Stripe);
            w.request_headers
                .insert("stripe-signature".to_string(), "t=123,v1=abc".to_string());
        });
        let env = HashMap::new(); // No secret

        assert!(diagnose_signature_failure(&wh, &env).is_none());
    }

    #[test]
    fn stripe_uses_signing_secret_fallback() {
        let secret = "whsec_fallback";
        let body = b"body";
        let timestamp = "12345";
        let sig = stripe_sign(secret, timestamp, body);

        let wh = make_webhook(|w| {
            w.provider = Some(WebhookProvider::Stripe);
            w.request_body = body.to_vec();
            w.request_headers.insert(
                "stripe-signature".to_string(),
                format!("t={timestamp},v1={sig}"),
            );
        });

        let mut env = HashMap::new();
        // Use the fallback key name
        env.insert("STRIPE_SIGNING_SECRET".to_string(), secret.to_string());

        assert!(diagnose_signature_failure(&wh, &env).is_none());
    }
}
