//! Sigstore attestation verifier.
//!
//! Cryptographic-verification primitives that prove every claim in an
//! in-toto statement attached to a Sigstore bundle. Phase 1.0's schema
//! bump on [`crate::sigstore`] is the precondition; phases land
//! incrementally:
//!
//! - Phase 1.1: vendored Sigstore trust root.
//! - Phase 1.2: DSSE envelope verification against the leaf cert (this commit).
//! - Phase 1.3: X.509 chain validation at `integratedTime`.
//! - Phase 1.4: embedded SCT verification.
//! - Phase 1.5: semantic Rekor body match.
//! - Phase 1.6: Rekor SET verification.
//! - Phase 1.7: Merkle inclusion proof verification.
//! - Phase 1.8: composed `verify_sigstore_bundle` entry point.
//!
//! Phase 1.2 details: PAE is re-encoded from the envelope's
//! `payload_type` and raw decoded `payload`, and verified against the
//! leaf cert's SPKI via ECDSA-P256 (constant-time, via the `ecdsa`
//! crate). Both raw R||S (64 bytes) and DER signature encodings are
//! accepted; Sigstore's profile is fixed at P-256, so any non-P256
//! SPKI on the leaf cert is rejected before signature work runs.
//!
//! See `private/plan-security-findings-c1-c2.md` for the architecture
//! and the GPT-audit revision log.

use crate::sigstore::DsseEnvelope;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};
use x509_parser::oid_registry::{OID_EC_P256, OID_KEY_TYPE_EC_PUBLIC_KEY};
use x509_parser::prelude::*;

/// Errors surfaced by every primitive in this module. Variants land
/// incrementally as phases ship. `#[non_exhaustive]` so consumers
/// cannot pattern-match on a closed set — adding a new variant in a
/// later phase is not a breaking change for the dispatcher in
/// Phase 2.1 (`provenance_fetch.rs`'s map to
/// `LpmError::ProvenanceVerification`).
///
/// `#[allow(dead_code)]` while Phase 1 is being built up — the only
/// production consumer (`provenance_fetch.rs` after Phase 2.1) is
/// pending. Tests cover the type already.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
#[allow(dead_code)]
pub enum VerifyError {
    /// DSSE envelope verification failed. Reasons: envelope carried
    /// no signatures, payload was not valid base64, every signature
    /// failed to parse as either raw R||S or DER, the leaf cert's
    /// SPKI was not a Sigstore-profile P-256 key, or no signature
    /// verified against the leaf cert's signing key (tampered
    /// payload or signing key did not match the cert).
    #[error("DSSE signature verification failed: {0}")]
    DsseSignature(String),

    /// A semantically-checked Rekor body field disagreed with the
    /// bundle's DSSE envelope or the leaf cert. Today's hard-fail
    /// fields: `publicKey` (binds the Rekor entry to the same
    /// signing identity that signed the DSSE envelope) and
    /// `payloadHash` (binds the Rekor entry to exactly the in-toto
    /// statement we're about to trust). Envelope hash is advisory
    /// only and never produces this variant; see
    /// [`verify_rekor_body`].
    #[error(
        "Rekor body field `{field}` mismatch: expected sha256={expected_sha256}, \
         actual sha256={actual_sha256}"
    )]
    RekorBodyMismatch {
        field: &'static str,
        expected_sha256: String,
        actual_sha256: String,
    },

    /// Rekor body's `apiVersion` is not in the supported set
    /// (`0.0.2`, `0.0.1`). Reject rather than skip so a future signer
    /// emitting an unknown shape doesn't bypass verification silently.
    #[error("Rekor body apiVersion `{api_version}` is not in the supported set (0.0.1, 0.0.2)")]
    RekorBodyUnknownVersion { api_version: String },

    /// Rekor body could not be parsed at all: `canonicalizedBody`
    /// wasn't base64, the decoded bytes weren't JSON, top-level
    /// `kind` wasn't `intoto`, or required fields were missing /
    /// of the wrong shape. Distinct from [`Self::RekorBodyMismatch`]
    /// which is reserved for "we parsed the body but its claims
    /// disagree with the bundle."
    #[error("Rekor body is malformed: {0}")]
    RekorBodyMalformed(String),
}

/// DSSE Pre-Authentication Encoding.
///
/// `PAE(type, payload) = "DSSEv1" SP len(type) SP type SP len(payload) SP payload`
///
/// Both the publish path ([`crate::sigstore::sign_and_record_with_endpoints`])
/// and the install-side verifier ([`verify_dsse`]) re-encode PAE
/// from the same inputs; keeping a single definition here avoids the
/// "publish and verify disagree about PAE by one byte" footgun.
pub(crate) fn pae(payload_type: &str, payload: &[u8]) -> Vec<u8> {
    let mut pae = Vec::new();
    pae.extend_from_slice(b"DSSEv1 ");
    pae.extend_from_slice(payload_type.len().to_string().as_bytes());
    pae.push(b' ');
    pae.extend_from_slice(payload_type.as_bytes());
    pae.push(b' ');
    pae.extend_from_slice(payload.len().to_string().as_bytes());
    pae.push(b' ');
    pae.extend_from_slice(payload);
    pae
}

/// Verify a DSSE envelope's signatures against the leaf cert's
/// signing key.
///
/// Per the DSSE spec (<https://github.com/secure-systems-lab/dsse>),
/// each signature covers `PAE(payload_type, decoded_payload)` where
/// `decoded_payload` is the base64-decoded `envelope.payload` bytes.
/// Verification succeeds when at least one signature in the envelope
/// verifies against the leaf cert's SPKI; envelopes carrying multiple
/// signatures are common when several signers attest to the same
/// statement, and any one valid signature attests the leaf cert's
/// key signed this exact PAE.
///
/// Sigstore's profile fixes the signing algorithm at ECDSA P-256;
/// the leaf cert's SPKI must encode an `ecPublicKey` with the P-256
/// named-curve parameter or this function rejects without attempting
/// signature verification.
///
/// Both signature encodings are accepted:
/// - **Raw R||S** (64 bytes for P-256). What LPM's publish path emits
///   and what npm's signers use.
/// - **DER** (variable-length ECDSA-Sig-Value). What some third-party
///   signers (GitHub `attest-build-provenance` cohorts, older
///   sigstore-rs versions) emit.
///
/// The fallback decoding tries raw first; DER second.
#[allow(dead_code)] // wired into provenance_fetch in Phase 2.1
pub fn verify_dsse(envelope: &DsseEnvelope, cert: &X509Certificate<'_>) -> Result<(), VerifyError> {
    if envelope.signatures.is_empty() {
        return Err(VerifyError::DsseSignature(
            "envelope carries no signatures".into(),
        ));
    }

    let verifying_key = extract_p256_verifying_key(cert)?;

    let raw_payload = BASE64
        .decode(envelope.payload.as_bytes())
        .map_err(|e| VerifyError::DsseSignature(format!("payload not valid base64: {e}")))?;
    let pae_bytes = pae(&envelope.payload_type, &raw_payload);

    let mut parse_errors: Vec<String> = Vec::new();
    for sig in &envelope.signatures {
        let sig_bytes = BASE64
            .decode(sig.sig.as_bytes())
            .map_err(|e| VerifyError::DsseSignature(format!("signature not valid base64: {e}")))?;

        // Raw R||S first — the simpler form, what the LPM publish
        // path emits. Fall back to DER for signers that prefer the
        // longer encoding. A signature that parses as neither is
        // not a verification miss on this leaf cert; record it and
        // move on so a multi-signature envelope with one malformed
        // entry can still verify on a sibling.
        let signature = match Signature::from_slice(&sig_bytes) {
            Ok(s) => s,
            Err(_) => match Signature::from_der(&sig_bytes) {
                Ok(s) => s,
                Err(e) => {
                    parse_errors.push(format!("(tried raw and DER) {e}"));
                    continue;
                }
            },
        };

        if verifying_key.verify(&pae_bytes, &signature).is_ok() {
            return Ok(());
        }
    }

    if parse_errors.is_empty() {
        Err(VerifyError::DsseSignature(
            "no signature in the envelope verified against the leaf cert's signing key".into(),
        ))
    } else {
        Err(VerifyError::DsseSignature(format!(
            "no signature in the envelope verified; \
             {} entr{} also failed to parse: {}",
            parse_errors.len(),
            if parse_errors.len() == 1 { "y" } else { "ies" },
            parse_errors.join("; ")
        )))
    }
}

/// Extract the ECDSA P-256 verifying key from a Sigstore-issued
/// leaf certificate. Reject any non-P-256 SPKI explicitly — Sigstore's
/// profile is fixed and a different curve indicates either a
/// misissue or a substitution attack.
#[allow(dead_code)] // consumer (`verify_dsse`) is allow-dead; transitively dead until Phase 2.1
fn extract_p256_verifying_key(cert: &X509Certificate<'_>) -> Result<VerifyingKey, VerifyError> {
    let spki = cert.public_key();

    // The ecPublicKey OID is 1.2.840.10045.2.1; the P-256 named-curve
    // parameter OID is 1.2.840.10045.3.1.7. `x509_parser::prelude`
    // re-exports `oid_registry::*` constants for both.
    let algo_oid = &spki.algorithm.algorithm;
    if *algo_oid != OID_KEY_TYPE_EC_PUBLIC_KEY {
        return Err(VerifyError::DsseSignature(format!(
            "leaf cert SPKI algorithm is {algo_oid} (expected ecPublicKey \
             {OID_KEY_TYPE_EC_PUBLIC_KEY})"
        )));
    }

    let params = spki.algorithm.parameters.as_ref().ok_or_else(|| {
        VerifyError::DsseSignature("leaf cert SPKI ecPublicKey is missing curve parameters".into())
    })?;
    let curve_oid = params.as_oid().map_err(|e| {
        VerifyError::DsseSignature(format!(
            "leaf cert SPKI curve parameters did not decode as an OID: {e}"
        ))
    })?;
    if curve_oid != OID_EC_P256 {
        return Err(VerifyError::DsseSignature(format!(
            "leaf cert SPKI curve is {curve_oid} (expected P-256 {OID_EC_P256})"
        )));
    }

    // The EC SPKI subject_public_key is a SEC1 uncompressed point:
    // 0x04 || X (32 bytes) || Y (32 bytes) = 65 bytes for P-256.
    let point_bytes = &spki.subject_public_key.data;
    VerifyingKey::from_sec1_bytes(point_bytes).map_err(|e| {
        VerifyError::DsseSignature(format!(
            "leaf cert SPKI is not a valid SEC1 P-256 point: {e}"
        ))
    })
}

// ─────────────────────────────────────────────────────────────────────
// Phase 1.5 — semantic Rekor body match.
// ─────────────────────────────────────────────────────────────────────
//
// `tlogEntries[i].canonicalizedBody` is base64(JSON) of the in-toto
// Rekor entry the bundle references. The verifier must prove the entry
// describes the same payload + signer as the DSSE envelope we're about
// to trust, WITHOUT byte-comparing JSON serializations — in-the-wild
// bundles from npm, GitHub `attest-build-provenance`, etc. canonicalize
// JSON differently and a byte-exact comparator false-rejects them.
//
// Policy (single rule, no fallback):
//   - hard-fail: cert identity match (Rekor body's publicKey ⇔ leaf cert)
//   - hard-fail: payload-hash match (Rekor body's payloadHash ⇔ sha256 of
//     base64-decoded `envelope.payload`)
//   - advisory: envelope-hash observation, debug-log only, NEVER rejects
//
// Together the two hard-fails close "Rekor entry from a different
// payload swapped in" and "Rekor entry from a different signer swapped
// in" without coupling install-side verification to publish-side JSON.

/// Top-level shape of an in-toto Rekor entry. `apiVersion` decides
/// how to read `spec.content.envelope`; `kind` must be `"intoto"`.
#[derive(Debug, serde::Deserialize)]
struct RekorIntotoBody {
    #[serde(rename = "apiVersion")]
    api_version: String,
    kind: String,
    spec: RekorIntotoSpec,
}

#[derive(Debug, serde::Deserialize)]
struct RekorIntotoSpec {
    content: RekorIntotoContent,
}

#[derive(Debug, serde::Deserialize)]
struct RekorIntotoContent {
    /// 0.0.2 puts an envelope object here; 0.0.1 puts a base64-encoded
    /// string of the envelope JSON. Kept as `Value` so a single
    /// deserialization handles both shapes — version-specific reading
    /// happens in [`extract_inner_envelope_object`].
    envelope: serde_json::Value,

    /// sha256 of the canonicalized envelope JSON. Advisory only —
    /// varies across signer canonicalization, so mismatch is a debug
    /// log, never a reject.
    #[serde(default)]
    hash: Option<RekorHashRef>,

    /// sha256 of the raw decoded payload bytes (pre-base64).
    /// Hard-fail: this binds the Rekor entry to exactly the in-toto
    /// statement carried by the DSSE envelope.
    #[serde(rename = "payloadHash", default)]
    payload_hash: Option<RekorHashRef>,
}

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
#[allow(dead_code)] // wired into provenance_fetch in Phase 2.1
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
    let body: RekorIntotoBody = serde_json::from_slice(&body_bytes).map_err(|e| {
        VerifyError::RekorBodyMalformed(format!(
            "canonicalizedBody base64-decoded bytes were not valid intoto JSON: {e}"
        ))
    })?;

    if body.kind != "intoto" {
        return Err(VerifyError::RekorBodyMalformed(format!(
            "Rekor body `kind` is `{}` (expected `intoto`)",
            body.kind
        )));
    }

    match body.api_version.as_str() {
        "0.0.2" | "0.0.1" => {}
        other => {
            return Err(VerifyError::RekorBodyUnknownVersion {
                api_version: other.to_string(),
            });
        }
    }

    // The "inner envelope" is a JSON object holding `payloadType`,
    // `payload`, and `signatures`. In 0.0.2 it sits directly under
    // `spec.content.envelope`; in 0.0.1 it's base64-wrapped as a
    // string.
    let inner_envelope = extract_inner_envelope_object(&body)?;

    // Hard-fail check #1: cert identity match.
    check_rekor_body_public_key_matches_leaf_cert(&inner_envelope, leaf_cert_der)?;

    // Hard-fail check #2: payload hash match.
    if let Some(hash_ref) = body.spec.content.payload_hash.as_ref() {
        check_rekor_body_payload_hash_matches_envelope(hash_ref, envelope)?;
    } else {
        // The plan flags this as a known 0.0.1 gap and a strict-mode
        // future-proofing concern. Treat absence as a structural defect
        // — the policy is "this check is required."
        return Err(VerifyError::RekorBodyMalformed(
            "Rekor body is missing `spec.content.payloadHash`; cannot bind entry to \
             envelope payload"
                .into(),
        ));
    }

    // Advisory observation #3: envelope hash. Never rejects.
    observe_rekor_body_envelope_hash(body.spec.content.hash.as_ref(), envelope);

    Ok(())
}

/// Read the inner envelope object out of `body.spec.content.envelope`,
/// handling both 0.0.2 (object directly) and 0.0.1 (base64-encoded
/// JSON string) shapes.
fn extract_inner_envelope_object(
    body: &RekorIntotoBody,
) -> Result<serde_json::Map<String, serde_json::Value>, VerifyError> {
    match &body.spec.content.envelope {
        serde_json::Value::Object(map) => Ok(map.clone()),
        serde_json::Value::String(b64) => {
            let envelope_bytes = BASE64.decode(b64.as_bytes()).map_err(|e| {
                VerifyError::RekorBodyMalformed(format!(
                    "Rekor body 0.0.1 envelope string is not valid base64: {e}"
                ))
            })?;
            let value: serde_json::Value =
                serde_json::from_slice(&envelope_bytes).map_err(|e| {
                    VerifyError::RekorBodyMalformed(format!(
                        "Rekor body 0.0.1 envelope did not decode to JSON: {e}"
                    ))
                })?;
            match value {
                serde_json::Value::Object(map) => Ok(map),
                other => Err(VerifyError::RekorBodyMalformed(format!(
                    "Rekor body 0.0.1 envelope JSON root is {} (expected object)",
                    json_value_kind(&other)
                ))),
            }
        }
        other => Err(VerifyError::RekorBodyMalformed(format!(
            "Rekor body `spec.content.envelope` is {} (expected object for 0.0.2 or \
             base64 string for 0.0.1)",
            json_value_kind(other)
        ))),
    }
}

/// Verify the `signatures[0].publicKey` field of the Rekor body's
/// inner envelope binds to the same cert as the bundle's leaf cert.
///
/// Encoding chain: body publicKey is base64(PEM); decode → PEM →
/// strict [`crate::sigstore::pem_to_der`] → DER. Compare DER bytes
/// directly to `leaf_cert_der` — DER is the canonical binary form,
/// so a byte equality there is the strongest possible "same cert"
/// claim without re-encoding round-trips that could introduce
/// canonicalization variance.
fn check_rekor_body_public_key_matches_leaf_cert(
    inner_envelope: &serde_json::Map<String, serde_json::Value>,
    leaf_cert_der: &[u8],
) -> Result<(), VerifyError> {
    let sig_entry = inner_envelope
        .get("signatures")
        .and_then(|v| v.as_array())
        .and_then(|arr| arr.first())
        .and_then(|v| v.as_object())
        .ok_or_else(|| {
            VerifyError::RekorBodyMalformed(
                "Rekor body envelope has no `signatures[0]` object".into(),
            )
        })?;

    let public_key_b64 = sig_entry
        .get("publicKey")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            VerifyError::RekorBodyMalformed(
                "Rekor body envelope `signatures[0]` has no string `publicKey` field".into(),
            )
        })?;

    let pem_bytes = BASE64.decode(public_key_b64.as_bytes()).map_err(|e| {
        VerifyError::RekorBodyMalformed(format!(
            "Rekor body envelope `signatures[0].publicKey` is not valid base64: {e}"
        ))
    })?;
    let pem_str = std::str::from_utf8(&pem_bytes).map_err(|e| {
        VerifyError::RekorBodyMalformed(format!(
            "Rekor body envelope `signatures[0].publicKey` did not base64-decode to UTF-8: {e}"
        ))
    })?;
    let body_cert_der = crate::sigstore::pem_to_der(pem_str).map_err(|e| {
        VerifyError::RekorBodyMalformed(format!(
            "Rekor body envelope `signatures[0].publicKey` PEM did not parse: {e}"
        ))
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
        sig_entry.insert(
            "sig".into(),
            serde_json::Value::String(sig_double_b64.clone()),
        );
    }
    let rekor_envelope = serde_json::json!({
        "payloadType": &envelope.payload_type,
        "payload": payload_double_b64,
        "signatures": [sig_entry],
    });
    serde_json::to_string(&rekor_envelope).unwrap_or_default()
}

fn json_value_kind(v: &serde_json::Value) -> &'static str {
    match v {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "bool",
        serde_json::Value::Number(_) => "number",
        serde_json::Value::String(_) => "string",
        serde_json::Value::Array(_) => "array",
        serde_json::Value::Object(_) => "object",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sigstore::{DsseEnvelope, DsseSignature};
    use ecdsa::signature::Signer;
    use p256::ecdsa::SigningKey;
    use p256::pkcs8::DecodePrivateKey;
    use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256};

    const PAYLOAD_TYPE: &str = "application/vnd.in-toto+json";
    const PAYLOAD: &[u8] = br#"{"_type":"https://in-toto.io/Statement/v0.1"}"#;

    /// Extract the message from a [`VerifyError::DsseSignature`], or
    /// panic with the unexpected variant. Reduces line noise across
    /// the negative-path DSSE tests.
    fn expect_dsse_sig_msg(err: VerifyError) -> String {
        match err {
            VerifyError::DsseSignature(msg) => msg,
            other => panic!("expected VerifyError::DsseSignature, got: {other:?}"),
        }
    }

    // ── pae() ─────────────────────────────────────────────────────

    #[test]
    fn pae_encoding_matches_spec() {
        let result = pae("application/vnd.in-toto+json", b"{}");
        let expected = b"DSSEv1 28 application/vnd.in-toto+json 2 {}";
        assert_eq!(result, expected);
    }

    // ── verify_dsse() positive cases ──────────────────────────────

    /// Helper: generate a P-256 keypair, build a self-signed cert
    /// holding that key's SPKI, return both the parsed cert DER and a
    /// `SigningKey` matching the cert's public key. The keypair is
    /// generated through rcgen so the resulting cert is structurally
    /// what a Sigstore-issued leaf would look like; we re-parse the
    /// PKCS#8 PEM to get a p256 `SigningKey` for producing
    /// DSSE-compatible signatures.
    fn p256_cert_and_signing_key() -> (Vec<u8>, SigningKey) {
        let kp = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let pem = kp.serialize_pem();
        let signing_key = SigningKey::from_pkcs8_pem(&pem).unwrap();
        let params = CertificateParams::default();
        let cert = params.self_signed(&kp).unwrap();
        (cert.der().to_vec(), signing_key)
    }

    fn dsse_envelope_signed_with(signing_key: &SigningKey, raw_payload: &[u8]) -> DsseEnvelope {
        let payload_b64 = BASE64.encode(raw_payload);
        let pae_bytes = pae(PAYLOAD_TYPE, raw_payload);
        let signature: Signature = signing_key.sign(&pae_bytes);
        let signature_b64 = BASE64.encode(signature.to_bytes().as_slice());
        DsseEnvelope {
            payload_type: PAYLOAD_TYPE.into(),
            payload: payload_b64,
            signatures: vec![DsseSignature {
                keyid: String::new(),
                sig: signature_b64,
            }],
        }
    }

    fn dsse_envelope_signed_with_der(signing_key: &SigningKey, raw_payload: &[u8]) -> DsseEnvelope {
        let payload_b64 = BASE64.encode(raw_payload);
        let pae_bytes = pae(PAYLOAD_TYPE, raw_payload);
        let signature: Signature = signing_key.sign(&pae_bytes);
        let signature_b64 = BASE64.encode(signature.to_der().as_bytes());
        DsseEnvelope {
            payload_type: PAYLOAD_TYPE.into(),
            payload: payload_b64,
            signatures: vec![DsseSignature {
                keyid: String::new(),
                sig: signature_b64,
            }],
        }
    }

    #[test]
    fn verifies_raw_r_s_signature_against_matching_leaf_cert() {
        let (cert_der, signing_key) = p256_cert_and_signing_key();
        let envelope = dsse_envelope_signed_with(&signing_key, PAYLOAD);
        let (_, cert) = X509Certificate::from_der(&cert_der).unwrap();
        verify_dsse(&envelope, &cert).expect("raw-encoded P-256 signature must verify");
    }

    #[test]
    fn verifies_der_signature_against_matching_leaf_cert() {
        let (cert_der, signing_key) = p256_cert_and_signing_key();
        let envelope = dsse_envelope_signed_with_der(&signing_key, PAYLOAD);
        let (_, cert) = X509Certificate::from_der(&cert_der).unwrap();
        verify_dsse(&envelope, &cert).expect(
            "DER-encoded P-256 signature must verify — the verifier falls back when raw \
             parse fails",
        );
    }

    #[test]
    fn verifies_when_at_least_one_of_multiple_signatures_matches() {
        // Real-world: multi-signer envelopes carry several signatures.
        // The verifier accepts the envelope when at least one signature
        // validates against the leaf cert's key. Pin this so a future
        // refactor that flipped to require-every-signature doesn't
        // silently break npm bundles.
        let (cert_der, signing_key) = p256_cert_and_signing_key();
        let mut envelope = dsse_envelope_signed_with(&signing_key, PAYLOAD);
        // Prepend a garbage signature; the second (valid) one must carry it.
        envelope.signatures.insert(
            0,
            DsseSignature {
                keyid: String::new(),
                sig: BASE64.encode([0u8; 64]),
            },
        );
        let (_, cert) = X509Certificate::from_der(&cert_der).unwrap();
        verify_dsse(&envelope, &cert)
            .expect("verifier must accept the envelope when one signature verifies");
    }

    // ── verify_dsse() failure cases ───────────────────────────────

    #[test]
    fn rejects_envelope_with_no_signatures() {
        let (cert_der, _) = p256_cert_and_signing_key();
        let envelope = DsseEnvelope {
            payload_type: PAYLOAD_TYPE.into(),
            payload: BASE64.encode(PAYLOAD),
            signatures: vec![],
        };
        let (_, cert) = X509Certificate::from_der(&cert_der).unwrap();
        let err = verify_dsse(&envelope, &cert).expect_err("empty signatures must reject");
        let msg = expect_dsse_sig_msg(err);
        assert!(
            msg.contains("no signatures"),
            "expected empty-sig diagnostic, got: {msg}"
        );
    }

    #[test]
    fn rejects_envelope_with_tampered_payload() {
        let (cert_der, signing_key) = p256_cert_and_signing_key();
        let mut envelope = dsse_envelope_signed_with(&signing_key, PAYLOAD);
        // Swap the payload after signing — the existing signature
        // covers the original bytes' PAE and must fail to verify
        // against the new PAE.
        envelope.payload = BASE64.encode(b"{\"_type\":\"tampered\"}");
        let (_, cert) = X509Certificate::from_der(&cert_der).unwrap();
        let err =
            verify_dsse(&envelope, &cert).expect_err("tampered payload must fail verification");
        let msg = expect_dsse_sig_msg(err);
        assert!(
            msg.contains("verified"),
            "expected verification-failed diagnostic, got: {msg}"
        );
    }

    #[test]
    fn rejects_envelope_signed_with_wrong_key() {
        // Cert holds key A's SPKI; envelope is signed by key B. The
        // signature parses fine but verifies as a "no signature
        // matched" error — NOT a parse error, NOT a chain error.
        let (cert_der, _key_a) = p256_cert_and_signing_key();
        let (_, key_b) = p256_cert_and_signing_key();
        let envelope = dsse_envelope_signed_with(&key_b, PAYLOAD);
        let (_, cert) = X509Certificate::from_der(&cert_der).unwrap();
        let err = verify_dsse(&envelope, &cert)
            .expect_err("signature from a non-matching key must fail verification");
        let msg = expect_dsse_sig_msg(err);
        assert!(
            msg.contains("verified"),
            "expected verification-failed diagnostic, got: {msg}"
        );
    }

    #[test]
    fn rejects_envelope_whose_payload_is_not_valid_base64() {
        let (cert_der, signing_key) = p256_cert_and_signing_key();
        let mut envelope = dsse_envelope_signed_with(&signing_key, PAYLOAD);
        envelope.payload = "not!!base64".into();
        let (_, cert) = X509Certificate::from_der(&cert_der).unwrap();
        let err = verify_dsse(&envelope, &cert).expect_err("malformed payload must reject");
        let msg = expect_dsse_sig_msg(err);
        assert!(
            msg.contains("base64"),
            "expected base64 diagnostic, got: {msg}"
        );
    }

    #[test]
    fn rejects_envelope_whose_signature_is_not_valid_base64() {
        let (cert_der, signing_key) = p256_cert_and_signing_key();
        let mut envelope = dsse_envelope_signed_with(&signing_key, PAYLOAD);
        envelope.signatures[0].sig = "not!!base64".into();
        let (_, cert) = X509Certificate::from_der(&cert_der).unwrap();
        let err = verify_dsse(&envelope, &cert).expect_err("malformed signature must reject");
        let msg = expect_dsse_sig_msg(err);
        assert!(
            msg.contains("base64"),
            "expected base64 diagnostic, got: {msg}"
        );
    }

    #[test]
    fn rejects_envelope_whose_signature_is_neither_raw_nor_der() {
        // A 7-byte signature is neither 64-byte raw nor valid DER.
        // Single-signature envelopes must fail-closed with a parse-
        // attempt diagnostic; the "tried raw and DER" wording is the
        // contract.
        let (cert_der, signing_key) = p256_cert_and_signing_key();
        let mut envelope = dsse_envelope_signed_with(&signing_key, PAYLOAD);
        envelope.signatures[0].sig = BASE64.encode(b"garbage");
        let (_, cert) = X509Certificate::from_der(&cert_der).unwrap();
        let err = verify_dsse(&envelope, &cert).expect_err("unparseable signature must fail");
        let msg = expect_dsse_sig_msg(err);
        assert!(
            msg.contains("raw and DER"),
            "expected parse-attempt diagnostic, got: {msg}"
        );
    }

    #[test]
    fn rejects_cert_with_non_ec_public_key() {
        // Sigstore profile is ecPublicKey-only. An Ed25519 leaf has a
        // structurally different SPKI algorithm OID (id-Ed25519, not
        // ecPublicKey) and must reject before any signature work runs.
        // Ed25519 is the convenient "non-EC SPKI" generator in rcgen
        // 0.13 without enabling extra backend features.
        let ed_kp = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let cert_der = CertificateParams::default()
            .self_signed(&ed_kp)
            .unwrap()
            .der()
            .to_vec();
        let (_, cert) = X509Certificate::from_der(&cert_der).unwrap();

        // Envelope contents don't matter — the verifier must reject
        // before it tries to verify.
        let (_, signing_key) = p256_cert_and_signing_key();
        let envelope = dsse_envelope_signed_with(&signing_key, PAYLOAD);

        let err = verify_dsse(&envelope, &cert)
            .expect_err("non-EC SPKI must reject before signature verification");
        let msg = expect_dsse_sig_msg(err);
        assert!(
            msg.contains("ecPublicKey"),
            "expected SPKI-algorithm diagnostic, got: {msg}"
        );
    }

    #[test]
    fn rejects_cert_with_non_p256_ec_curve() {
        // Sigstore profile pins the named curve to P-256. A P-384 cert
        // is structurally an ecPublicKey but with the wrong curve OID
        // — must reject explicitly so a misissued cert never reaches
        // the signature path.
        let p384_kp = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
        let cert_der = CertificateParams::default()
            .self_signed(&p384_kp)
            .unwrap()
            .der()
            .to_vec();
        let (_, cert) = X509Certificate::from_der(&cert_der).unwrap();

        let (_, signing_key) = p256_cert_and_signing_key();
        let envelope = dsse_envelope_signed_with(&signing_key, PAYLOAD);

        let err = verify_dsse(&envelope, &cert)
            .expect_err("non-P-256 curve must reject before signature verification");
        let msg = expect_dsse_sig_msg(err);
        assert!(
            msg.contains("P-256"),
            "expected curve-mismatch diagnostic, got: {msg}"
        );
    }

    // ── verify_rekor_body() — Phase 1.5 ───────────────────────────

    use crate::sigstore::{LogId, TlogEntry};

    /// Build an LPM-canonical Rekor body 0.0.2 JSON for the given
    /// envelope + leaf cert. Mirrors the publish-side construction in
    /// `crate::sigstore::rekor_upload` so positive-path tests bind to
    /// the production code's wire shape, while mutation tests can
    /// surgically edit individual fields.
    fn build_rekor_body_0_0_2(envelope: &DsseEnvelope, leaf_cert_der: &[u8]) -> serde_json::Value {
        let cert_pem = der_to_canonical_pem(leaf_cert_der);
        let cert_pem_b64 = BASE64.encode(cert_pem.as_bytes());
        let raw_payload = BASE64.decode(envelope.payload.as_bytes()).unwrap();
        let payload_hash = hex::encode(Sha256::digest(&raw_payload));

        let payload_double_b64 = BASE64.encode(envelope.payload.as_bytes());
        let sig_double_b64 = BASE64.encode(envelope.signatures[0].sig.as_bytes());
        let inner_envelope = serde_json::json!({
            "payloadType": &envelope.payload_type,
            "payload": payload_double_b64,
            "signatures": [{
                "sig": sig_double_b64,
                "publicKey": cert_pem_b64,
            }],
        });
        let envelope_hash = hex::encode(Sha256::digest(
            serde_json::to_string(&inner_envelope).unwrap().as_bytes(),
        ));

        serde_json::json!({
            "apiVersion": "0.0.2",
            "kind": "intoto",
            "spec": {
                "content": {
                    "envelope": inner_envelope,
                    "hash": { "algorithm": "sha256", "value": envelope_hash },
                    "payloadHash": { "algorithm": "sha256", "value": payload_hash },
                },
            },
        })
    }

    /// Build a Rekor body 0.0.1 JSON for the given envelope + cert.
    /// Difference vs 0.0.2: the inner envelope is base64-encoded as a
    /// string instead of nested as an object.
    fn build_rekor_body_0_0_1(envelope: &DsseEnvelope, leaf_cert_der: &[u8]) -> serde_json::Value {
        let cert_pem = der_to_canonical_pem(leaf_cert_der);
        let cert_pem_b64 = BASE64.encode(cert_pem.as_bytes());
        let raw_payload = BASE64.decode(envelope.payload.as_bytes()).unwrap();
        let payload_hash = hex::encode(Sha256::digest(&raw_payload));

        let payload_double_b64 = BASE64.encode(envelope.payload.as_bytes());
        let sig_double_b64 = BASE64.encode(envelope.signatures[0].sig.as_bytes());
        let inner_envelope = serde_json::json!({
            "payloadType": &envelope.payload_type,
            "payload": payload_double_b64,
            "signatures": [{
                "sig": sig_double_b64,
                "publicKey": cert_pem_b64,
            }],
        });
        let envelope_b64 = BASE64.encode(serde_json::to_vec(&inner_envelope).unwrap());

        serde_json::json!({
            "apiVersion": "0.0.1",
            "kind": "intoto",
            "spec": {
                "content": {
                    "envelope": envelope_b64,
                    "payloadHash": { "algorithm": "sha256", "value": payload_hash },
                },
            },
        })
    }

    /// Encode a DER certificate as canonical PEM-with-LF, the format
    /// the strict `crate::sigstore::pem_to_der` parser round-trips.
    fn der_to_canonical_pem(der: &[u8]) -> String {
        let mut out = String::with_capacity(der.len() * 2);
        out.push_str("-----BEGIN CERTIFICATE-----\n");
        let b64 = BASE64.encode(der);
        for chunk in b64.as_bytes().chunks(64) {
            out.push_str(std::str::from_utf8(chunk).unwrap());
            out.push('\n');
        }
        out.push_str("-----END CERTIFICATE-----\n");
        out
    }

    /// Wrap a Rekor body JSON in a `TlogEntry` whose
    /// `canonicalized_body` is base64-encoded — what `verify_rekor_body`
    /// expects on input.
    fn tlog_entry_with_body(body: &serde_json::Value) -> TlogEntry {
        TlogEntry {
            log_index: "0".into(),
            log_id: LogId {
                key_id: String::new(),
            },
            integrated_time: "0".into(),
            inclusion_promise: None,
            inclusion_proof: None,
            verification: None,
            canonicalized_body: BASE64.encode(serde_json::to_vec(body).unwrap()),
        }
    }

    /// Helper: assert err is RekorBodyMismatch on the named field.
    fn expect_rekor_body_mismatch(err: VerifyError, expected_field: &str) {
        match err {
            VerifyError::RekorBodyMismatch { field, .. } => {
                assert_eq!(
                    field, expected_field,
                    "expected mismatch on `{expected_field}`, got `{field}`"
                );
            }
            other => panic!(
                "expected VerifyError::RekorBodyMismatch on `{expected_field}`, got: {other:?}"
            ),
        }
    }

    fn expect_rekor_body_malformed(err: VerifyError) -> String {
        match err {
            VerifyError::RekorBodyMalformed(msg) => msg,
            other => panic!("expected VerifyError::RekorBodyMalformed, got: {other:?}"),
        }
    }

    #[test]
    fn verifies_valid_rekor_body_0_0_2() {
        let (cert_der, signing_key) = p256_cert_and_signing_key();
        let envelope = dsse_envelope_signed_with(&signing_key, PAYLOAD);
        let body = build_rekor_body_0_0_2(&envelope, &cert_der);
        let tlog = tlog_entry_with_body(&body);
        verify_rekor_body(&tlog, &envelope, &cert_der)
            .expect("LPM-canonical 0.0.2 body must verify against its own envelope + cert");
    }

    #[test]
    fn verifies_valid_rekor_body_0_0_1() {
        let (cert_der, signing_key) = p256_cert_and_signing_key();
        let envelope = dsse_envelope_signed_with(&signing_key, PAYLOAD);
        let body = build_rekor_body_0_0_1(&envelope, &cert_der);
        let tlog = tlog_entry_with_body(&body);
        verify_rekor_body(&tlog, &envelope, &cert_der)
            .expect("LPM-canonical 0.0.1 body must verify against its own envelope + cert");
    }

    #[test]
    fn accepts_rekor_body_with_field_reordered_or_extra_whitespace() {
        // Build a canonical body, then re-serialize it through a JSON
        // parse → pretty-print round-trip. The resulting bytes carry
        // different field ordering (serde_json::Value is a BTreeMap)
        // and lots of extra whitespace. The semantic verifier must
        // still accept it — proves we are NOT byte-comparing JSON.
        let (cert_der, signing_key) = p256_cert_and_signing_key();
        let envelope = dsse_envelope_signed_with(&signing_key, PAYLOAD);
        let body = build_rekor_body_0_0_2(&envelope, &cert_der);

        // Strip → pretty: reorders keys (BTreeMap) and adds whitespace.
        let pretty = serde_json::to_string_pretty(&body).unwrap();
        let reparsed: serde_json::Value = serde_json::from_str(&pretty).unwrap();
        let tlog = TlogEntry {
            log_index: "0".into(),
            log_id: LogId {
                key_id: String::new(),
            },
            integrated_time: "0".into(),
            inclusion_promise: None,
            inclusion_proof: None,
            verification: None,
            canonicalized_body: BASE64.encode(serde_json::to_vec(&reparsed).unwrap()),
        };

        verify_rekor_body(&tlog, &envelope, &cert_der).expect(
            "verifier must accept a Rekor body with reordered keys and pretty-print \
             whitespace — semantic, not byte-bound",
        );
    }

    #[test]
    fn accepts_rekor_body_with_envelope_hash_mismatch_alone() {
        // Pin the "envelope hash is advisory, never a rejection
        // reason" rule from the plan (Phase 1.5, GPT round-4 H1).
        // The body's `spec.content.hash.value` is mutated to a wrong
        // sha256 (all zeros) while payloadHash and publicKey stay
        // correct; verification must still succeed.
        let (cert_der, signing_key) = p256_cert_and_signing_key();
        let envelope = dsse_envelope_signed_with(&signing_key, PAYLOAD);
        let mut body = build_rekor_body_0_0_2(&envelope, &cert_der);
        body["spec"]["content"]["hash"]["value"] = serde_json::Value::String("0".repeat(64));
        let tlog = tlog_entry_with_body(&body);
        verify_rekor_body(&tlog, &envelope, &cert_der).expect(
            "envelope-hash mismatch alone must NOT reject — it is advisory only \
             (the hard-fails on publicKey + payloadHash carry the security claim)",
        );
    }

    #[test]
    fn rejects_bundle_with_rekor_body_payload_hash_mismatch() {
        // Mutate `spec.content.payloadHash.value` to a fake sha256
        // while leaving the envelope intact. The verifier must
        // reject with a `payloadHash` field mismatch — closes the
        // "Rekor entry from a different payload swapped in" attack.
        let (cert_der, signing_key) = p256_cert_and_signing_key();
        let envelope = dsse_envelope_signed_with(&signing_key, PAYLOAD);
        let mut body = build_rekor_body_0_0_2(&envelope, &cert_der);
        body["spec"]["content"]["payloadHash"]["value"] = serde_json::Value::String("f".repeat(64));
        let tlog = tlog_entry_with_body(&body);
        let err = verify_rekor_body(&tlog, &envelope, &cert_der)
            .expect_err("payloadHash mismatch must reject");
        expect_rekor_body_mismatch(err, "payloadHash");
    }

    #[test]
    fn rejects_bundle_with_rekor_body_cert_mismatch() {
        // Build the body referencing cert A, but pass cert B as the
        // leaf to verify_rekor_body. The verifier must reject with a
        // `publicKey` field mismatch — closes the "Rekor entry from a
        // different signer swapped in" attack.
        let (cert_der_a, signing_key) = p256_cert_and_signing_key();
        let (cert_der_b, _) = p256_cert_and_signing_key();
        let envelope = dsse_envelope_signed_with(&signing_key, PAYLOAD);
        let body = build_rekor_body_0_0_2(&envelope, &cert_der_a);
        let tlog = tlog_entry_with_body(&body);
        let err = verify_rekor_body(&tlog, &envelope, &cert_der_b)
            .expect_err("publicKey mismatch must reject");
        expect_rekor_body_mismatch(err, "publicKey");
    }

    #[test]
    fn rejects_bundle_with_rekor_body_unknown_api_version() {
        let (cert_der, signing_key) = p256_cert_and_signing_key();
        let envelope = dsse_envelope_signed_with(&signing_key, PAYLOAD);
        let mut body = build_rekor_body_0_0_2(&envelope, &cert_der);
        body["apiVersion"] = serde_json::Value::String("0.0.99".into());
        let tlog = tlog_entry_with_body(&body);
        let err = verify_rekor_body(&tlog, &envelope, &cert_der)
            .expect_err("unknown apiVersion must reject");
        match err {
            VerifyError::RekorBodyUnknownVersion { api_version } => {
                assert_eq!(api_version, "0.0.99");
            }
            other => panic!("expected RekorBodyUnknownVersion, got: {other:?}"),
        }
    }

    #[test]
    fn rejects_bundle_with_rekor_body_unknown_kind() {
        let (cert_der, signing_key) = p256_cert_and_signing_key();
        let envelope = dsse_envelope_signed_with(&signing_key, PAYLOAD);
        let mut body = build_rekor_body_0_0_2(&envelope, &cert_der);
        body["kind"] = serde_json::Value::String("rekord".into());
        let tlog = tlog_entry_with_body(&body);
        let err = verify_rekor_body(&tlog, &envelope, &cert_der)
            .expect_err("non-intoto kind must reject");
        let msg = expect_rekor_body_malformed(err);
        assert!(msg.contains("kind"), "expected kind diagnostic, got: {msg}");
    }

    #[test]
    fn rejects_bundle_with_canonicalized_body_not_base64() {
        let (cert_der, signing_key) = p256_cert_and_signing_key();
        let envelope = dsse_envelope_signed_with(&signing_key, PAYLOAD);
        let tlog = TlogEntry {
            log_index: "0".into(),
            log_id: LogId {
                key_id: String::new(),
            },
            integrated_time: "0".into(),
            inclusion_promise: None,
            inclusion_proof: None,
            verification: None,
            canonicalized_body: "not!!base64!!".into(),
        };
        let err = verify_rekor_body(&tlog, &envelope, &cert_der)
            .expect_err("malformed base64 must reject");
        let msg = expect_rekor_body_malformed(err);
        assert!(
            msg.contains("base64"),
            "expected base64 diagnostic, got: {msg}"
        );
    }

    #[test]
    fn rejects_bundle_with_canonicalized_body_not_json() {
        let (cert_der, signing_key) = p256_cert_and_signing_key();
        let envelope = dsse_envelope_signed_with(&signing_key, PAYLOAD);
        let tlog = TlogEntry {
            log_index: "0".into(),
            log_id: LogId {
                key_id: String::new(),
            },
            integrated_time: "0".into(),
            inclusion_promise: None,
            inclusion_proof: None,
            verification: None,
            canonicalized_body: BASE64.encode(b"this is not JSON"),
        };
        let err =
            verify_rekor_body(&tlog, &envelope, &cert_der).expect_err("non-JSON body must reject");
        let msg = expect_rekor_body_malformed(err);
        assert!(
            msg.contains("intoto JSON"),
            "expected JSON-parse diagnostic, got: {msg}"
        );
    }

    #[test]
    fn rejects_bundle_with_missing_payload_hash_field() {
        // The plan flags absent payloadHash as a structural defect —
        // the verifier cannot bind the entry to the envelope payload
        // without it. Pin that the verifier rejects rather than
        // silently passing.
        let (cert_der, signing_key) = p256_cert_and_signing_key();
        let envelope = dsse_envelope_signed_with(&signing_key, PAYLOAD);
        let mut body = build_rekor_body_0_0_2(&envelope, &cert_der);
        body["spec"]["content"]
            .as_object_mut()
            .unwrap()
            .remove("payloadHash");
        let tlog = tlog_entry_with_body(&body);
        let err = verify_rekor_body(&tlog, &envelope, &cert_der)
            .expect_err("missing payloadHash must reject");
        let msg = expect_rekor_body_malformed(err);
        assert!(
            msg.contains("payloadHash"),
            "expected payloadHash diagnostic, got: {msg}"
        );
    }
}
