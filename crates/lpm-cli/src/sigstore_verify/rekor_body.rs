use crate::sigstore::DsseEnvelope;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use sha2::{Digest, Sha256};

use super::VerifyError;

// `tlogEntries[i].canonicalizedBody` is base64(JSON) of the in-toto
// Rekor entry the bundle references. The verifier must prove the entry
// describes the same payload and signer as the DSSE envelope we're about
// to trust, without byte-comparing JSON serializations.
//
// Policy:
//   - hard-fail: cert identity match (Rekor body's publicKey and leaf cert)
//   - hard-fail: payload-hash match
//   - advisory: envelope-hash observation, debug-log only, never rejects
#[derive(Debug, serde::Deserialize)]
struct RekorHashRef {
    /// Hash algorithm. Today only `"sha256"` is meaningful; recorded
    /// for forward-compat. Treated as advisory by the verifier — the
    /// value field is sha256 hex regardless because that's all Rekor
    /// emits today, and a future non-sha256 algorithm would be a
    /// breaking-change moment for the rest of the verifier anyway.
    #[allow(dead_code)]
    algorithm: String,
    value: String,
}

/// Verify that a Rekor transparency-log entry's `canonicalizedBody`
/// describes the same payload + signing identity as the DSSE
/// envelope and leaf cert from the bundle.
///
/// This is the "Rekor entry references the bundle we're about to
/// trust" check. See the module comment above for the policy
/// (two hard-fails + one advisory). The function returns `Ok(())`
/// when both hard-fails pass, regardless of envelope-hash agreement.
///
/// Two Rekor body kinds are accepted:
/// - `intoto` (apiVersion 0.0.1 / 0.0.2) — LPM's publish-side type;
///   nested under `spec.content.{envelope, payloadHash, hash}`.
/// - `dsse` (apiVersion 0.0.1) — what npm and GitHub
///   `attest-build-provenance` actually emit; flat
///   `spec.{signatures, payloadHash, envelopeHash}`. The cert is
///   carried as the `verifier` field (PEM, base64'd) on each
///   signatures entry, analogous to intoto's `publicKey`.
///
/// Both shapes carry the same load-bearing information; the
/// extraction handles the field-name differences and the verifier
/// runs identical hard-fail checks against the unified view.
#[allow(dead_code)] // wired into provenance_bundle
pub fn verify_rekor_body(
    tlog_entry: &crate::sigstore::TlogEntry,
    envelope: &DsseEnvelope,
    leaf_cert_der: &[u8],
) -> Result<(), VerifyError> {
    let body_bytes = BASE64
        .decode(tlog_entry.canonicalized_body.as_bytes())
        .map_err(|e| {
            VerifyError::RekorBodyMalformed(format!("canonicalizedBody not valid base64: {e}"))
        })?;
    let body: serde_json::Value = serde_json::from_slice(&body_bytes).map_err(|e| {
        VerifyError::RekorBodyMalformed(format!(
            "canonicalizedBody base64-decoded bytes were not valid JSON: {e}"
        ))
    })?;

    let kind = body.get("kind").and_then(|v| v.as_str()).ok_or_else(|| {
        VerifyError::RekorBodyMalformed("Rekor body missing string `kind` field".into())
    })?;
    let api_version = body
        .get("apiVersion")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            VerifyError::RekorBodyMalformed("Rekor body missing string `apiVersion` field".into())
        })?;
    let spec = body
        .get("spec")
        .and_then(|v| v.as_object())
        .ok_or_else(|| {
            VerifyError::RekorBodyMalformed("Rekor body `spec` is not an object".into())
        })?;

    let view = match kind {
        "intoto" => extract_intoto_view(spec, api_version)?,
        "dsse" => extract_dsse_view(spec, api_version)?,
        other => {
            return Err(VerifyError::RekorBodyMalformed(format!(
                "Rekor body `kind` is `{other}` (expected `intoto` or `dsse`)",
            )));
        }
    };

    match api_version {
        "0.0.2" | "0.0.1" => {}
        other => {
            return Err(VerifyError::RekorBodyUnknownVersion {
                api_version: other.to_string(),
            });
        }
    }

    // Hard-fail check #1: cert identity match.
    check_rekor_body_cert_pem_matches_leaf(&view.public_key_b64, leaf_cert_der)?;

    // Hard-fail check #2: payload hash match. Required by policy —
    // absence is a structural defect that prevents binding the
    // Rekor entry to the envelope payload.
    if let Some(hash_ref) = view.payload_hash.as_ref() {
        check_rekor_body_payload_hash_matches_envelope(hash_ref, envelope)?;
    } else {
        return Err(VerifyError::RekorBodyMalformed(
            "Rekor body is missing payloadHash; cannot bind entry to envelope payload".into(),
        ));
    }

    // Advisory observation #3: envelope hash. Never rejects.
    observe_rekor_body_envelope_hash(view.envelope_hash.as_ref(), envelope);

    Ok(())
}

/// Unified view of a Rekor body's load-bearing fields, regardless
/// of whether the body was the `intoto` or `dsse` Rekor type.
struct RekorBodyView {
    /// Base64-encoded PEM of the signing cert. Both Rekor kinds
    /// ship this; only the field name differs (intoto's
    /// `signatures[0].publicKey` vs dsse's `signatures[0].verifier`).
    public_key_b64: String,
    /// Optional sha256 of raw envelope.payload — the load-bearing
    /// payload-binding hash.
    payload_hash: Option<RekorHashRef>,
    /// Optional sha256 of canonical envelope JSON — advisory only.
    envelope_hash: Option<RekorHashRef>,
}

fn extract_intoto_view(
    spec: &serde_json::Map<String, serde_json::Value>,
    _api_version: &str,
) -> Result<RekorBodyView, VerifyError> {
    let content = spec
        .get("content")
        .and_then(|v| v.as_object())
        .ok_or_else(|| {
            VerifyError::RekorBodyMalformed(
                "intoto Rekor body missing `spec.content` object".into(),
            )
        })?;
    let envelope = content.get("envelope").ok_or_else(|| {
        VerifyError::RekorBodyMalformed(
            "intoto Rekor body missing `spec.content.envelope` field".into(),
        )
    })?;
    let inner = extract_intoto_inner_envelope(envelope)?;
    let public_key_b64 = inner
        .get("signatures")
        .and_then(|v| v.as_array())
        .and_then(|arr| arr.first())
        .and_then(|v| v.as_object())
        .and_then(|s| s.get("publicKey"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            VerifyError::RekorBodyMalformed(
                "intoto Rekor body inner envelope has no `signatures[0].publicKey`".into(),
            )
        })?
        .to_string();
    let payload_hash = content
        .get("payloadHash")
        .and_then(|v| serde_json::from_value::<RekorHashRef>(v.clone()).ok());
    let envelope_hash = content
        .get("hash")
        .and_then(|v| serde_json::from_value::<RekorHashRef>(v.clone()).ok());
    Ok(RekorBodyView {
        public_key_b64,
        payload_hash,
        envelope_hash,
    })
}

fn extract_dsse_view(
    spec: &serde_json::Map<String, serde_json::Value>,
    _api_version: &str,
) -> Result<RekorBodyView, VerifyError> {
    let public_key_b64 = spec
        .get("signatures")
        .and_then(|v| v.as_array())
        .and_then(|arr| arr.first())
        .and_then(|v| v.as_object())
        .and_then(|s| s.get("verifier"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            VerifyError::RekorBodyMalformed(
                "dsse Rekor body has no `spec.signatures[0].verifier`".into(),
            )
        })?
        .to_string();
    let payload_hash = spec
        .get("payloadHash")
        .and_then(|v| serde_json::from_value::<RekorHashRef>(v.clone()).ok());
    let envelope_hash = spec
        .get("envelopeHash")
        .and_then(|v| serde_json::from_value::<RekorHashRef>(v.clone()).ok());
    Ok(RekorBodyView {
        public_key_b64,
        payload_hash,
        envelope_hash,
    })
}

/// Extract the in-toto inner envelope object from `spec.content.envelope`.
/// 0.0.2 puts an envelope object here; 0.0.1 puts a base64-encoded
/// string of the envelope JSON.
fn extract_intoto_inner_envelope(
    envelope: &serde_json::Value,
) -> Result<serde_json::Map<String, serde_json::Value>, VerifyError> {
    match envelope {
        serde_json::Value::Object(map) => Ok(map.clone()),
        serde_json::Value::String(b64) => {
            let envelope_bytes = BASE64.decode(b64.as_bytes()).map_err(|e| {
                VerifyError::RekorBodyMalformed(format!(
                    "intoto 0.0.1 envelope string is not valid base64: {e}"
                ))
            })?;
            let value: serde_json::Value =
                serde_json::from_slice(&envelope_bytes).map_err(|e| {
                    VerifyError::RekorBodyMalformed(format!(
                        "intoto 0.0.1 envelope did not decode to JSON: {e}"
                    ))
                })?;
            match value {
                serde_json::Value::Object(map) => Ok(map),
                other => Err(VerifyError::RekorBodyMalformed(format!(
                    "intoto 0.0.1 envelope JSON root is {} (expected object)",
                    json_value_kind(&other)
                ))),
            }
        }
        other => Err(VerifyError::RekorBodyMalformed(format!(
            "intoto `spec.content.envelope` is {} (expected object for 0.0.2 or \
             base64 string for 0.0.1)",
            json_value_kind(other)
        ))),
    }
}

/// Verify the Rekor body's certificate-PEM field binds to the same
/// cert as the bundle's leaf cert. Used for both the intoto type
/// (where the field is `signatures[0].publicKey` on the inner
/// envelope) and the dsse type (where the field is
/// `signatures[0].verifier` on `spec.signatures`).
///
/// Encoding chain: base64(PEM) → PEM → strict
/// [`crate::sigstore::pem_to_der`] → DER. Byte-compare DER directly
/// to `leaf_cert_der` — DER is the canonical binary form.
fn check_rekor_body_cert_pem_matches_leaf(
    public_key_b64: &str,
    leaf_cert_der: &[u8],
) -> Result<(), VerifyError> {
    let pem_bytes = BASE64.decode(public_key_b64.as_bytes()).map_err(|e| {
        VerifyError::RekorBodyMalformed(format!(
            "Rekor body cert-PEM field is not valid base64: {e}"
        ))
    })?;
    let pem_str = std::str::from_utf8(&pem_bytes).map_err(|e| {
        VerifyError::RekorBodyMalformed(format!(
            "Rekor body cert-PEM did not base64-decode to UTF-8: {e}"
        ))
    })?;
    let body_cert_der = crate::sigstore::pem_to_der(pem_str).map_err(|e| {
        VerifyError::RekorBodyMalformed(format!("Rekor body cert-PEM did not parse: {e}"))
    })?;

    if body_cert_der != leaf_cert_der {
        return Err(VerifyError::RekorBodyMismatch {
            field: "publicKey",
            expected_sha256: hex::encode(Sha256::digest(leaf_cert_der)),
            actual_sha256: hex::encode(Sha256::digest(&body_cert_der)),
        });
    }

    Ok(())
}

/// Verify the body's `payloadHash.value` equals sha256 of the
/// envelope's raw (pre-base64) payload bytes.
///
/// Payload hash is signer-independent (it's a hash of raw bytes, not
/// of any JSON), so this check works identically for LPM-, npm-, and
/// GitHub-produced bundles.
fn check_rekor_body_payload_hash_matches_envelope(
    hash_ref: &RekorHashRef,
    envelope: &DsseEnvelope,
) -> Result<(), VerifyError> {
    let raw_payload = BASE64.decode(envelope.payload.as_bytes()).map_err(|e| {
        VerifyError::RekorBodyMalformed(format!(
            "DSSE envelope.payload is not valid base64 — cannot compute payload hash: {e}"
        ))
    })?;
    let actual_hash = hex::encode(Sha256::digest(&raw_payload));
    if actual_hash != hash_ref.value {
        return Err(VerifyError::RekorBodyMismatch {
            field: "payloadHash",
            expected_sha256: hash_ref.value.clone(),
            actual_sha256: actual_hash,
        });
    }
    Ok(())
}

/// Advisory observation on the body's envelope hash. Never rejects.
/// Computes LPM's canonical envelope form (the same JSON the publish
/// path hashes at `sigstore.rs::rekor_upload`) and compares to the
/// body's `hash.value`. Both match and mismatch are debug-logged so
/// telemetry can spot when a new signer's canonicalization diverges.
fn observe_rekor_body_envelope_hash(hash_ref: Option<&RekorHashRef>, envelope: &DsseEnvelope) {
    let Some(hash_ref) = hash_ref else {
        tracing::debug!(
            target: "lpm_cli::sigstore_verify",
            "rekor body has no envelope `hash` field — advisory observation skipped",
        );
        return;
    };

    let canonical = build_lpm_canonical_envelope_json(envelope);
    let actual = hex::encode(Sha256::digest(canonical.as_bytes()));
    if actual == hash_ref.value {
        tracing::debug!(
            target: "lpm_cli::sigstore_verify",
            expected = %hash_ref.value,
            "rekor body envelope hash matched LPM canonical form",
        );
    } else {
        tracing::debug!(
            target: "lpm_cli::sigstore_verify",
            expected = %hash_ref.value,
            actual = %actual,
            "rekor body envelope hash differs from LPM canonical form \
             (canonicalization variance, expected behavior for non-LPM signers)",
        );
    }
}

/// Reproduce the publish-side canonical envelope JSON the publish
/// path hashes at `crate::sigstore::rekor_upload`. Used only by the
/// advisory envelope-hash observation; agreement is not load-bearing.
fn build_lpm_canonical_envelope_json(envelope: &DsseEnvelope) -> String {
    let payload_double_b64 = BASE64.encode(envelope.payload.as_bytes());
    let mut sig_entry = serde_json::Map::new();
    if let Some(sig) = envelope.signatures.first() {
        let sig_double_b64 = BASE64.encode(sig.sig.as_bytes());
        sig_entry.insert("sig".into(), serde_json::Value::String(sig_double_b64));
    }
    let rekor_envelope = serde_json::json!({
        "payloadType": &envelope.payload_type,
        "payload": payload_double_b64,
        "signatures": [sig_entry],
    });
    serde_json::to_string(&rekor_envelope).unwrap_or_default()
}

pub(super) fn json_value_kind(v: &serde_json::Value) -> &'static str {
    match v {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "bool",
        serde_json::Value::Number(_) => "number",
        serde_json::Value::String(_) => "string",
        serde_json::Value::Array(_) => "array",
        serde_json::Value::Object(_) => "object",
    }
}
