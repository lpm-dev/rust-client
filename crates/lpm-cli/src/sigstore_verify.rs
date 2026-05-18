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
use chrono::{DateTime, Duration, Utc};
use ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};
use std::sync::{Arc, OnceLock};
use std::time::SystemTime;
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

    /// The vendored Sigstore trust root could not be parsed (JSON
    /// shape drift, base64 decode failure on cert / key material,
    /// missing required field, etc.).
    #[error("vendored Sigstore trust root failed to load: {0}")]
    TrustRoot(String),

    /// The vendored trust root no longer has at least one currently-
    /// active key for every role (Fulcio CA, Rekor signing key, CT
    /// log key). The artifact is stale; the user must update `lpm`
    /// to a release that ships a refreshed root before any Sigstore
    /// verification can succeed.
    ///
    /// Trust roots intentionally carry retired entries alongside
    /// active ones so that bundles signed during retired windows
    /// can still verify against the integratedTime they declare
    /// — so a single past `validFor.end` is NOT expiry; the
    /// artifact is expired when an entire role has gone retired-
    /// only.
    #[error(
        "vendored Sigstore trust root has no currently-active key for role(s): {missing_roles}; \
         update lpm to refresh (see private/sigstore-root-provenance.md)"
    )]
    TrustRootExpired { missing_roles: String },
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

// ─────────────────────────────────────────────────────────────────────
// Phase 1.1 — vendored Sigstore trust root.
// ─────────────────────────────────────────────────────────────────────
//
// `assets/sigstore_trusted_root.json` is embedded at compile time via
// `include_bytes!` and parsed once at first call into a `TrustRoot`
// holding the Fulcio CA chains, Rekor signing keys, and CT log keys
// the verifier walks against. Provenance + rotation discipline lives
// in `private/sigstore-root-provenance.md`.
//
// The plan rejects a live TUF client for the C1 scope (see "What it
// explicitly does NOT deliver"); rotation is an operational
// release-engineering step that re-embeds a fresh artifact and ships
// a new lpm-cli binary.
//
// Expiry policy (Phase 4 of the plan):
//   - On first load: if wall-clock > expires_at_soonest, hard-fail
//     with `VerifyError::TrustRootExpired`.
//   - On first load: if `expires_at_soonest - 30 days < wall-clock`,
//     emit a `tracing::warn` so a release-imminent user is nudged
//     toward updating before the artifact actually expires.
//   - "expires_at_soonest" is the minimum `validFor.end` across all
//     entries that have one; entries with no `end` (still in service
//     per Sigstore) don't constrain expiry. If every entry is
//     open-ended, the artifact never auto-expires and the warn never
//     fires — Sigstore hasn't yet announced a retirement date.

const EMBEDDED_TRUST_ROOT_JSON: &[u8] = include_bytes!("../assets/sigstore_trusted_root.json");

/// Warn-window in days before `expires_at_soonest`. Operator hint
/// only — does not affect fail-closed behaviour.
const TRUST_ROOT_EXPIRY_WARN_DAYS: i64 = 30;

/// Vendored Sigstore trust root. Parsed once at startup from
/// `assets/sigstore_trusted_root.json` and cached via [`trust_root`].
///
/// `#[allow(dead_code)]` while Phase 1 is being built up — Phase 1.3
/// (chain validation), 1.4 (SCT), and 1.6 (SET) are the production
/// consumers; this commit ships the data model alone.
#[allow(dead_code)]
#[derive(Debug)]
pub struct TrustRoot {
    pub fulcio_roots: Vec<FulcioRoot>,
    pub rekor_keys: Vec<RekorKey>,
    pub ctlog_keys: Vec<CtLogKey>,
}

#[allow(dead_code)]
#[derive(Debug)]
pub struct FulcioRoot {
    /// DER-encoded certs in chain order — the trust anchor (root)
    /// is `[0]`. Most public-good Fulcio roots ship a single cert,
    /// but the schema permits a chain (root + intermediates) when
    /// Sigstore rotates a cross-signed root through.
    pub cert_chain_der: Vec<Vec<u8>>,
    pub valid_for: ValidityWindow,
}

#[allow(dead_code)]
#[derive(Debug)]
pub struct RekorKey {
    /// Sha-256 of the SPKI bytes — what Rekor embeds as `logID` in
    /// transparency-log entries. Stored raw so the verifier
    /// (Phase 1.6) compares by byte slice; Rekor's API exposes it
    /// as hex, the trust root carries it as base64 — both decode to
    /// the same 32-byte hash, that's the canonical form.
    pub log_id: Vec<u8>,
    /// DER-encoded SubjectPublicKeyInfo for verifying the SET.
    pub spki_der: Vec<u8>,
    pub valid_for: ValidityWindow,
}

#[allow(dead_code)]
#[derive(Debug)]
pub struct CtLogKey {
    pub log_id: Vec<u8>,
    pub spki_der: Vec<u8>,
    pub valid_for: ValidityWindow,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ValidityWindow {
    pub start: DateTime<Utc>,
    /// `None` means open-ended — entry is still in service per
    /// Sigstore; no announced retirement date.
    pub end: Option<DateTime<Utc>>,
}

impl ValidityWindow {
    /// Inclusive lower bound, exclusive upper bound. An open-ended
    /// window contains every `t >= start`.
    #[allow(dead_code)]
    pub fn contains(&self, t: SystemTime) -> bool {
        let t: DateTime<Utc> = t.into();
        t >= self.start && self.end.is_none_or(|end| t < end)
    }
}

// ─── JSON DTOs matching trusted_root.json (protobuf-JSON shape) ──

#[derive(Debug, serde::Deserialize)]
struct TrustedRootJson {
    #[serde(rename = "certificateAuthorities", default)]
    certificate_authorities: Vec<TrustedRootCa>,
    #[serde(default)]
    tlogs: Vec<TrustedRootLog>,
    #[serde(default)]
    ctlogs: Vec<TrustedRootLog>,
}

#[derive(Debug, serde::Deserialize)]
struct TrustedRootCa {
    #[serde(rename = "certChain")]
    cert_chain: TrustedRootCertChain,
    #[serde(rename = "validFor")]
    valid_for: TrustedRootValidFor,
}

#[derive(Debug, serde::Deserialize)]
struct TrustedRootCertChain {
    certificates: Vec<TrustedRootCertEntry>,
}

#[derive(Debug, serde::Deserialize)]
struct TrustedRootCertEntry {
    #[serde(rename = "rawBytes")]
    raw_bytes: String,
}

#[derive(Debug, serde::Deserialize)]
struct TrustedRootLog {
    #[serde(rename = "logId")]
    log_id: TrustedRootLogId,
    #[serde(rename = "publicKey")]
    public_key: TrustedRootKey,
}

#[derive(Debug, serde::Deserialize)]
struct TrustedRootLogId {
    #[serde(rename = "keyId")]
    key_id: String,
}

#[derive(Debug, serde::Deserialize)]
struct TrustedRootKey {
    #[serde(rename = "rawBytes")]
    raw_bytes: String,
    #[serde(rename = "validFor")]
    valid_for: TrustedRootValidFor,
}

#[derive(Debug, serde::Deserialize)]
struct TrustedRootValidFor {
    start: DateTime<Utc>,
    #[serde(default)]
    end: Option<DateTime<Utc>>,
}

impl From<TrustedRootValidFor> for ValidityWindow {
    fn from(v: TrustedRootValidFor) -> Self {
        ValidityWindow {
            start: v.start,
            end: v.end,
        }
    }
}

// ─── Parser + accessors ──────────────────────────────────────────

#[allow(dead_code)]
impl TrustRoot {
    /// Parse a trust root from raw JSON bytes. Pure — no I/O, no
    /// global state. Use [`trust_root`] for the production
    /// embedded-bytes entry; this is the test seam and is also
    /// available for future code that wants to consume a non-embedded
    /// root (e.g. enterprise Sigstore deployments — but adding that
    /// requires careful audit, see Phase 1.1 in the plan).
    pub fn parse(bytes: &[u8]) -> Result<TrustRoot, VerifyError> {
        let raw: TrustedRootJson = serde_json::from_slice(bytes)
            .map_err(|e| VerifyError::TrustRoot(format!("JSON parse: {e}")))?;

        let fulcio_roots = raw
            .certificate_authorities
            .into_iter()
            .map(parse_fulcio_root)
            .collect::<Result<Vec<_>, _>>()?;

        let rekor_keys = raw
            .tlogs
            .into_iter()
            .map(parse_log_key)
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .map(|(log_id, spki_der, valid_for)| RekorKey {
                log_id,
                spki_der,
                valid_for,
            })
            .collect();

        let ctlog_keys = raw
            .ctlogs
            .into_iter()
            .map(parse_log_key)
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .map(|(log_id, spki_der, valid_for)| CtLogKey {
                log_id,
                spki_der,
                valid_for,
            })
            .collect();

        Ok(TrustRoot {
            fulcio_roots,
            rekor_keys,
            ctlog_keys,
        })
    }

    /// Fulcio roots whose CA-level validity window contains `t`. The
    /// individual certs inside also have intrinsic notBefore/notAfter
    /// that Phase 1.3's chain walker checks; this filter is the
    /// outer gate from Sigstore's published service-window metadata.
    pub fn fulcio_roots_at(&self, t: SystemTime) -> Vec<&FulcioRoot> {
        self.fulcio_roots
            .iter()
            .filter(|r| r.valid_for.contains(t))
            .collect()
    }

    /// Rekor signing key for the entry's `logID`, valid at `t`.
    /// `log_id` is the raw 32-byte sha256 of the SPKI — callers
    /// hex-decode (Rekor canonical body) or base64-decode (TUF
    /// metadata) into this form.
    pub fn rekor_key_at(&self, log_id: &[u8], t: SystemTime) -> Option<&RekorKey> {
        self.rekor_keys
            .iter()
            .find(|k| k.log_id == log_id && k.valid_for.contains(t))
    }

    /// CT log key for an SCT's `logID`, valid at `t`.
    pub fn ctlog_key_at(&self, log_id: &[u8], t: SystemTime) -> Option<&CtLogKey> {
        self.ctlog_keys
            .iter()
            .find(|k| k.log_id == log_id && k.valid_for.contains(t))
    }

    /// Hard-fail path: error if any role (Fulcio, Rekor, CT log)
    /// has zero currently-active keys at `now`. Pure for testability.
    /// Wall-clock invocation lives in [`trust_root`].
    ///
    /// "Currently active at `now`" = `valid_for.contains(now)` — both
    /// `start <= now` and (`end is None` OR `end > now`). Retired
    /// entries (end <= now) don't count.
    pub fn check_expiry(&self, now: SystemTime) -> Result<(), VerifyError> {
        let mut missing: Vec<&str> = Vec::new();
        if !self.fulcio_roots.iter().any(|r| r.valid_for.contains(now)) {
            missing.push("Fulcio CA");
        }
        if !self.rekor_keys.iter().any(|k| k.valid_for.contains(now)) {
            missing.push("Rekor signing key");
        }
        if !self.ctlog_keys.iter().any(|k| k.valid_for.contains(now)) {
            missing.push("CT log key");
        }
        if missing.is_empty() {
            return Ok(());
        }
        Err(VerifyError::TrustRootExpired {
            missing_roles: missing.join(", "),
        })
    }

    /// Soonest "next currently-active key retirement" date. Per
    /// role, the role's retirement date is the LATEST `end` among
    /// currently-active keys (because the artifact remains useful
    /// while at least one key is active). The artifact's effective
    /// retirement is the EARLIEST such per-role retirement.
    ///
    /// Returns `None` when at least one currently-active key for
    /// every role is open-ended — no announced retirement, so no
    /// warn anchor.
    pub fn next_role_retirement_at(&self, now: SystemTime) -> Option<DateTime<Utc>> {
        fn latest_active_end<'a, I>(windows: I, now: SystemTime) -> Option<DateTime<Utc>>
        where
            I: IntoIterator<Item = &'a ValidityWindow>,
        {
            let mut latest: Option<DateTime<Utc>> = None;
            let mut saw_active = false;
            for w in windows {
                if !w.contains(now) {
                    continue;
                }
                saw_active = true;
                match w.end {
                    // Open-ended active entry → role has no retirement anchor.
                    None => return None,
                    Some(end) => {
                        latest = Some(latest.map_or(end, |l| l.max(end)));
                    }
                }
            }
            if saw_active { latest } else { None }
        }
        let fulcio = latest_active_end(self.fulcio_roots.iter().map(|r| &r.valid_for), now);
        let rekor = latest_active_end(self.rekor_keys.iter().map(|k| &k.valid_for), now);
        let ctlog = latest_active_end(self.ctlog_keys.iter().map(|k| &k.valid_for), now);
        [fulcio, rekor, ctlog].into_iter().flatten().min()
    }

    /// Whether [`Self::next_role_retirement_at`] is within
    /// `TRUST_ROOT_EXPIRY_WARN_DAYS` of `now`. Used by [`trust_root`]'s
    /// startup `tracing::warn`. Returns `None` when no anchor or
    /// when the anchor is further out than the warn window.
    pub fn within_warn_window(&self, now: SystemTime) -> Option<DateTime<Utc>> {
        let soonest = self.next_role_retirement_at(now)?;
        let now_dt: DateTime<Utc> = now.into();
        let warn_at = soonest - Duration::days(TRUST_ROOT_EXPIRY_WARN_DAYS);
        if now_dt > warn_at && now_dt <= soonest {
            Some(soonest)
        } else {
            None
        }
    }
}

fn parse_fulcio_root(raw: TrustedRootCa) -> Result<FulcioRoot, VerifyError> {
    let mut cert_chain_der = Vec::with_capacity(raw.cert_chain.certificates.len());
    for cert in raw.cert_chain.certificates {
        let der = BASE64.decode(cert.raw_bytes.as_bytes()).map_err(|e| {
            VerifyError::TrustRoot(format!("Fulcio CA cert rawBytes not base64: {e}"))
        })?;
        cert_chain_der.push(der);
    }
    if cert_chain_der.is_empty() {
        return Err(VerifyError::TrustRoot(
            "Fulcio CA entry has an empty certChain".into(),
        ));
    }
    Ok(FulcioRoot {
        cert_chain_der,
        valid_for: raw.valid_for.into(),
    })
}

fn parse_log_key(raw: TrustedRootLog) -> Result<(Vec<u8>, Vec<u8>, ValidityWindow), VerifyError> {
    let log_id = BASE64
        .decode(raw.log_id.key_id.as_bytes())
        .map_err(|e| VerifyError::TrustRoot(format!("logId.keyId not base64: {e}")))?;
    let spki_der = BASE64
        .decode(raw.public_key.raw_bytes.as_bytes())
        .map_err(|e| VerifyError::TrustRoot(format!("log publicKey.rawBytes not base64: {e}")))?;
    Ok((log_id, spki_der, raw.public_key.valid_for.into()))
}

/// Cached parsed trust root, populated on first [`trust_root`] call.
static TRUST_ROOT_CELL: OnceLock<Result<Arc<TrustRoot>, String>> = OnceLock::new();

/// Production accessor: lazily loads the embedded trust root, runs
/// the startup expiry check, and emits the 30-day warn if applicable.
/// Subsequent calls return a cheap `Arc::clone` of the cached root.
///
/// Error semantics: parse failures and post-expiry rejection are both
/// surfaced via the cached `Err` variant — once this function
/// returns an error for the process lifetime, it always will. That's
/// load-bearing: a verifier path that succeeded the first call must
/// not silently start failing mid-install because something flapped.
#[allow(dead_code)] // wired into provenance_fetch in Phase 2.1
pub fn trust_root() -> Result<Arc<TrustRoot>, VerifyError> {
    let cached = TRUST_ROOT_CELL.get_or_init(|| {
        let parsed =
            TrustRoot::parse(EMBEDDED_TRUST_ROOT_JSON).map_err(|e| format!("parse failed: {e}"))?;
        let now = SystemTime::now();

        if let Some(expires) = parsed.within_warn_window(now) {
            tracing::warn!(
                target: "lpm_cli::sigstore_verify",
                expires_at = %expires,
                "vendored Sigstore trust root expires within {} days; update lpm to refresh \
                 (see private/sigstore-root-provenance.md)",
                TRUST_ROOT_EXPIRY_WARN_DAYS,
            );
        }

        if let Err(VerifyError::TrustRootExpired { missing_roles }) = parsed.check_expiry(now) {
            return Err(format!(
                "vendored Sigstore trust root has no currently-active key for role(s) \
                 {missing_roles}; update lpm to refresh"
            ));
        }

        Ok(Arc::new(parsed))
    });
    match cached {
        Ok(arc) => Ok(Arc::clone(arc)),
        Err(msg) => Err(VerifyError::TrustRoot(msg.clone())),
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

    // ── TrustRoot — Phase 1.1 ─────────────────────────────────────

    fn ts(rfc3339: &str) -> SystemTime {
        DateTime::parse_from_rfc3339(rfc3339)
            .unwrap()
            .with_timezone(&Utc)
            .into()
    }

    #[test]
    fn vendored_trust_root_parses_cleanly() {
        let root = TrustRoot::parse(EMBEDDED_TRUST_ROOT_JSON)
            .expect("the vendored sigstore_trusted_root.json must parse");
        assert!(
            !root.fulcio_roots.is_empty(),
            "vendored trust root must carry at least one Fulcio CA"
        );
        assert!(
            !root.rekor_keys.is_empty(),
            "vendored trust root must carry at least one Rekor signing key"
        );
        assert!(
            !root.ctlog_keys.is_empty(),
            "vendored trust root must carry at least one CT log key"
        );
        // logId is the raw 32-byte sha256 of the SPKI per protobuf-specs.
        for key in &root.rekor_keys {
            assert_eq!(
                key.log_id.len(),
                32,
                "Rekor logId must be a 32-byte sha256 hash, got {}",
                key.log_id.len()
            );
        }
        for key in &root.ctlog_keys {
            assert_eq!(
                key.log_id.len(),
                32,
                "CT log logId must be a 32-byte sha256 hash, got {}",
                key.log_id.len()
            );
        }
    }

    #[test]
    fn trust_root_oncelock_returns_arc_to_same_parse_result() {
        // The OnceLock-cached production accessor must hand back the
        // same underlying allocation across calls (cheap Arc clone),
        // not a fresh parse each time.
        let a = trust_root().expect("production trust_root() must succeed");
        let b = trust_root().expect("production trust_root() must succeed");
        assert!(
            Arc::ptr_eq(&a, &b),
            "trust_root() must return Arc::clone of the cached parse, not a fresh allocation"
        );
    }

    #[test]
    fn trust_root_fulcio_roots_at_filters_by_validity_window() {
        let root = TrustRoot::parse(EMBEDDED_TRUST_ROOT_JSON).unwrap();
        // The vendored artifact carries at least one retired CA
        // (`validFor.end` < 2023). Sanity: with a SystemTime well
        // before any embedded `start`, no CA is valid.
        let pre_history = ts("1990-01-01T00:00:00Z");
        assert!(
            root.fulcio_roots_at(pre_history).is_empty(),
            "no Fulcio root should match a time before any embedded start"
        );
        // At a time the public-good roots are universally valid
        // (this artifact has at least one root spanning 2022-2025),
        // at least one root must match.
        let mid_history = ts("2023-06-15T12:00:00Z");
        assert!(
            !root.fulcio_roots_at(mid_history).is_empty(),
            "at least one Fulcio root must be valid in mid-2023"
        );
    }

    #[test]
    fn trust_root_rekor_key_lookup_by_log_id() {
        let root = TrustRoot::parse(EMBEDDED_TRUST_ROOT_JSON).unwrap();
        // Use the first embedded key's own logId as the lookup key —
        // robust against artifact rotations that change specific
        // byte values.
        let first = root
            .rekor_keys
            .first()
            .expect("vendored trust root must carry a Rekor key");
        let log_id = first.log_id.clone();
        let valid_t = SystemTime::from(first.valid_for.start) + std::time::Duration::from_secs(60);
        let found = root
            .rekor_key_at(&log_id, valid_t)
            .expect("rekor_key_at must return the key whose logId we just used");
        assert_eq!(found.log_id, log_id);

        // Unknown logId returns None.
        let bogus = vec![0u8; 32];
        assert!(
            root.rekor_key_at(&bogus, valid_t).is_none(),
            "unknown logId must not resolve"
        );
    }

    #[test]
    fn trust_root_rekor_key_lookup_filters_by_validity_window() {
        let root = TrustRoot::parse(EMBEDDED_TRUST_ROOT_JSON).unwrap();
        let first = root.rekor_keys.first().unwrap();
        let log_id = first.log_id.clone();

        // Before the validity window starts, lookup returns None
        // even with a matching logId.
        let pre_history = ts("1990-01-01T00:00:00Z");
        assert!(
            root.rekor_key_at(&log_id, pre_history).is_none(),
            "matching logId with out-of-window time must NOT resolve — \
             the verifier picks keys valid at integratedTime, not at any time"
        );
    }

    #[test]
    fn trust_root_ctlog_key_lookup_by_log_id() {
        let root = TrustRoot::parse(EMBEDDED_TRUST_ROOT_JSON).unwrap();
        let first = root.ctlog_keys.first().unwrap();
        let valid_t = SystemTime::from(first.valid_for.start) + std::time::Duration::from_secs(60);
        let found = root
            .ctlog_key_at(&first.log_id, valid_t)
            .expect("ctlog_key_at must resolve a logId valid at the requested time");
        assert_eq!(found.log_id, first.log_id);
    }

    /// Build a synthetic trust root JSON with one entry per role,
    /// each with the given validity window. Used by the expiry
    /// tests so they don't depend on the vendored artifact's
    /// specific dates (which change at rotation).
    fn synth_trust_root_json(
        fulcio_validfor: serde_json::Value,
        rekor_validfor: serde_json::Value,
        ctlog_validfor: serde_json::Value,
    ) -> serde_json::Value {
        serde_json::json!({
            "mediaType": "application/vnd.dev.sigstore.trustedroot+json;version=0.1",
            "certificateAuthorities": [{
                "certChain": { "certificates": [{ "rawBytes": BASE64.encode(b"d") }] },
                "validFor": fulcio_validfor,
            }],
            "tlogs": [{
                "logId": { "keyId": BASE64.encode([0u8; 32]) },
                "publicKey": {
                    "rawBytes": BASE64.encode(b"d"),
                    "validFor": rekor_validfor,
                }
            }],
            "ctlogs": [{
                "logId": { "keyId": BASE64.encode([1u8; 32]) },
                "publicKey": {
                    "rawBytes": BASE64.encode(b"d"),
                    "validFor": ctlog_validfor,
                }
            }]
        })
    }

    #[test]
    fn trust_root_check_expiry_passes_when_every_role_has_an_active_key() {
        // Every role has an open-ended entry; check_expiry always
        // passes, no matter how far the wall-clock has advanced.
        let json = synth_trust_root_json(
            serde_json::json!({"start": "2020-01-01T00:00:00Z"}),
            serde_json::json!({"start": "2020-01-01T00:00:00Z"}),
            serde_json::json!({"start": "2020-01-01T00:00:00Z"}),
        );
        let root = TrustRoot::parse(serde_json::to_vec(&json).unwrap().as_slice()).unwrap();
        root.check_expiry(ts("2099-01-01T00:00:00Z"))
            .expect("every role open-ended ⇒ check_expiry never rejects");
    }

    #[test]
    fn trust_root_check_expiry_hard_fails_when_any_role_has_no_active_key() {
        // Vendored shape: a real Sigstore artifact carries
        // retired + active entries side by side. The artifact
        // becomes "expired" not when ANY entry retires, but when
        // an entire role goes retired-only. Use a synth artifact
        // where the Rekor role's only entry retired in 2024;
        // wall-clock past that date must reject with the role
        // named explicitly.
        let json = synth_trust_root_json(
            serde_json::json!({"start": "2020-01-01T00:00:00Z"}), // Fulcio open-ended
            serde_json::json!({"start": "2020-01-01T00:00:00Z", "end": "2024-01-01T00:00:00Z"}),
            serde_json::json!({"start": "2020-01-01T00:00:00Z"}), // CT log open-ended
        );
        let root = TrustRoot::parse(serde_json::to_vec(&json).unwrap().as_slice()).unwrap();
        let after_rekor_end = ts("2024-06-01T00:00:00Z");
        let err = root
            .check_expiry(after_rekor_end)
            .expect_err("retired-only Rekor role must reject");
        match err {
            VerifyError::TrustRootExpired { missing_roles } => {
                assert!(
                    missing_roles.contains("Rekor"),
                    "expected Rekor role to be flagged, got: {missing_roles}"
                );
                assert!(
                    !missing_roles.contains("Fulcio"),
                    "Fulcio is still open-ended; must NOT be in the missing-roles diagnostic"
                );
            }
            other => panic!("expected TrustRootExpired, got: {other:?}"),
        }
        // Before the Rekor end, all roles have an active key.
        root.check_expiry(ts("2023-06-01T00:00:00Z"))
            .expect("check_expiry before Rekor end must pass");
    }

    #[test]
    fn trust_root_check_expiry_passes_when_role_has_multiple_keys_and_one_still_active() {
        // Real-world: a role often carries multiple keys, some
        // retired, some active. The artifact stays usable while
        // at least one key per role is active. Synthesize an
        // artifact with one retired and one open-ended Rekor key
        // and confirm check_expiry passes well past the retired
        // key's end-date.
        let json = serde_json::json!({
            "mediaType": "application/vnd.dev.sigstore.trustedroot+json;version=0.1",
            "certificateAuthorities": [{
                "certChain": { "certificates": [{ "rawBytes": BASE64.encode(b"d") }] },
                "validFor": {"start": "2020-01-01T00:00:00Z"}
            }],
            "tlogs": [
                {
                    "logId": { "keyId": BASE64.encode([0u8; 32]) },
                    "publicKey": {
                        "rawBytes": BASE64.encode(b"d"),
                        "validFor": {"start": "2020-01-01T00:00:00Z", "end": "2022-01-01T00:00:00Z"}
                    }
                },
                {
                    "logId": { "keyId": BASE64.encode([2u8; 32]) },
                    "publicKey": {
                        "rawBytes": BASE64.encode(b"d"),
                        "validFor": {"start": "2022-01-01T00:00:00Z"}
                    }
                }
            ],
            "ctlogs": [{
                "logId": { "keyId": BASE64.encode([1u8; 32]) },
                "publicKey": {
                    "rawBytes": BASE64.encode(b"d"),
                    "validFor": {"start": "2020-01-01T00:00:00Z"}
                }
            }]
        });
        let root = TrustRoot::parse(serde_json::to_vec(&json).unwrap().as_slice()).unwrap();
        // Well past the first Rekor key's retirement, but the
        // second is open-ended and still active.
        root.check_expiry(ts("2030-06-01T00:00:00Z"))
            .expect("at least one Rekor key still active ⇒ check_expiry passes");
    }

    #[test]
    fn vendored_trust_root_check_expiry_currently_passes() {
        // Sanity: at this commit, the vendored artifact has at
        // least one active key per role at wall-clock now. If a
        // future rotation lets one role go retired-only, this test
        // fails loudly — that's the signal to vendor a fresh root
        // and update private/sigstore-root-provenance.md.
        let root = TrustRoot::parse(EMBEDDED_TRUST_ROOT_JSON).unwrap();
        root.check_expiry(SystemTime::now()).expect(
            "the vendored trust root must still have at least one active key per role; \
             if this fails, fetch a fresh trusted_root.json and re-vendor",
        );
    }

    #[test]
    fn trust_root_next_role_retirement_at_returns_soonest_per_role_max() {
        // Two roles have multiple keys with declared ends; one
        // role has open-ended keys (no anchor). The per-role
        // retirement is the LATEST end among currently-active
        // keys for that role; the artifact's retirement is the
        // SOONEST such per-role value.
        let json = serde_json::json!({
            "mediaType": "application/vnd.dev.sigstore.trustedroot+json;version=0.1",
            "certificateAuthorities": [{
                "certChain": { "certificates": [{ "rawBytes": BASE64.encode(b"d") }] },
                "validFor": {"start": "2020-01-01T00:00:00Z", "end": "2028-01-01T00:00:00Z"}
            }],
            "tlogs": [
                // Two active Rekor keys; latest end is 2026.
                {
                    "logId": { "keyId": BASE64.encode([0u8; 32]) },
                    "publicKey": {
                        "rawBytes": BASE64.encode(b"d"),
                        "validFor": {"start": "2020-01-01T00:00:00Z", "end": "2024-01-01T00:00:00Z"}
                    }
                },
                {
                    "logId": { "keyId": BASE64.encode([2u8; 32]) },
                    "publicKey": {
                        "rawBytes": BASE64.encode(b"d"),
                        "validFor": {"start": "2023-01-01T00:00:00Z", "end": "2026-01-01T00:00:00Z"}
                    }
                }
            ],
            // CT log is open-ended ⇒ doesn't constrain the anchor.
            "ctlogs": [{
                "logId": { "keyId": BASE64.encode([1u8; 32]) },
                "publicKey": {
                    "rawBytes": BASE64.encode(b"d"),
                    "validFor": {"start": "2020-01-01T00:00:00Z"}
                }
            }]
        });
        let root = TrustRoot::parse(serde_json::to_vec(&json).unwrap().as_slice()).unwrap();
        // At a time both Rekor keys are active: per-role retirement
        // is the LATEST end (2026), Fulcio retirement is 2028.
        // Soonest across roles is 2026.
        let now = ts("2023-06-01T00:00:00Z");
        let anchor = root.next_role_retirement_at(now).unwrap();
        assert_eq!(
            anchor,
            DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
        );
    }

    #[test]
    fn trust_root_next_role_retirement_at_returns_none_when_all_roles_open_ended() {
        let json = synth_trust_root_json(
            serde_json::json!({"start": "2020-01-01T00:00:00Z"}),
            serde_json::json!({"start": "2020-01-01T00:00:00Z"}),
            serde_json::json!({"start": "2020-01-01T00:00:00Z"}),
        );
        let root = TrustRoot::parse(serde_json::to_vec(&json).unwrap().as_slice()).unwrap();
        assert!(
            root.next_role_retirement_at(ts("2099-01-01T00:00:00Z"))
                .is_none(),
            "all roles open-ended ⇒ no retirement anchor"
        );
    }

    #[test]
    fn trust_root_within_warn_window_fires_in_last_30_days() {
        let json = synth_trust_root_json(
            serde_json::json!({"start": "2020-01-01T00:00:00Z", "end": "2026-12-31T00:00:00Z"}),
            serde_json::json!({"start": "2020-01-01T00:00:00Z"}), // open-ended
            serde_json::json!({"start": "2020-01-01T00:00:00Z"}), // open-ended
        );
        let root = TrustRoot::parse(serde_json::to_vec(&json).unwrap().as_slice()).unwrap();

        // 60 days before Fulcio end: NOT in the warn window.
        assert!(
            root.within_warn_window(ts("2026-10-31T00:00:00Z"))
                .is_none()
        );
        // 15 days before end: IS in the warn window.
        assert!(
            root.within_warn_window(ts("2026-12-16T00:00:00Z"))
                .is_some(),
            "warn window must fire inside the last {} days",
            TRUST_ROOT_EXPIRY_WARN_DAYS
        );
        // Past end: NOT in warn window — that's the hard-fail
        // regime (`check_expiry` rejects there because Fulcio has
        // no active key anymore).
        assert!(
            root.within_warn_window(ts("2027-01-15T00:00:00Z"))
                .is_none()
        );
    }

    #[test]
    fn trust_root_parse_rejects_malformed_json() {
        let err = TrustRoot::parse(b"this is not JSON").expect_err("malformed JSON must reject");
        match err {
            VerifyError::TrustRoot(msg) => assert!(msg.contains("JSON parse"), "got: {msg}"),
            other => panic!("expected VerifyError::TrustRoot, got: {other:?}"),
        }
    }

    #[test]
    fn trust_root_parse_rejects_invalid_base64_cert() {
        let json = serde_json::json!({
            "mediaType": "application/vnd.dev.sigstore.trustedroot+json;version=0.1",
            "certificateAuthorities": [{
                "certChain": { "certificates": [{ "rawBytes": "not!!base64" }] },
                "validFor": { "start": "2020-01-01T00:00:00Z" }
            }],
            "tlogs": [],
            "ctlogs": []
        });
        let err = TrustRoot::parse(serde_json::to_vec(&json).unwrap().as_slice())
            .expect_err("malformed cert base64 must reject");
        match err {
            VerifyError::TrustRoot(msg) => assert!(msg.contains("not base64"), "got: {msg}"),
            other => panic!("expected VerifyError::TrustRoot, got: {other:?}"),
        }
    }

    #[test]
    fn trust_root_parse_rejects_empty_cert_chain() {
        let json = serde_json::json!({
            "mediaType": "application/vnd.dev.sigstore.trustedroot+json;version=0.1",
            "certificateAuthorities": [{
                "certChain": { "certificates": [] },
                "validFor": { "start": "2020-01-01T00:00:00Z" }
            }],
            "tlogs": [],
            "ctlogs": []
        });
        let err = TrustRoot::parse(serde_json::to_vec(&json).unwrap().as_slice())
            .expect_err("empty certChain must reject");
        match err {
            VerifyError::TrustRoot(msg) => {
                assert!(msg.contains("empty certChain"), "got: {msg}")
            }
            other => panic!("expected VerifyError::TrustRoot, got: {other:?}"),
        }
    }

    #[test]
    fn validity_window_open_ended_contains_anything_after_start() {
        let window = ValidityWindow {
            start: DateTime::parse_from_rfc3339("2020-01-01T00:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
            end: None,
        };
        assert!(!window.contains(ts("2019-12-31T23:59:59Z")));
        assert!(window.contains(ts("2020-01-01T00:00:00Z")));
        assert!(window.contains(ts("2999-12-31T00:00:00Z")));
    }

    #[test]
    fn validity_window_closed_excludes_end_exclusively() {
        let window = ValidityWindow {
            start: DateTime::parse_from_rfc3339("2020-01-01T00:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
            end: Some(
                DateTime::parse_from_rfc3339("2024-01-01T00:00:00Z")
                    .unwrap()
                    .with_timezone(&Utc),
            ),
        };
        assert!(window.contains(ts("2020-01-01T00:00:00Z")));
        assert!(window.contains(ts("2023-12-31T23:59:59Z")));
        assert!(
            !window.contains(ts("2024-01-01T00:00:00Z")),
            "end is exclusive: a key valid until midnight Jan 1 must NOT be picked at midnight Jan 1"
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
