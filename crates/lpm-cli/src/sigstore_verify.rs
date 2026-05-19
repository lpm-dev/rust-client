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
use ecdsa::signature::hazmat::PrehashVerifier;
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

    /// Rekor SET (Signed Entry Timestamp) verification failed:
    /// signature did not verify under the pinned Rekor key, the
    /// pinned key for the entry's `logID` is absent / not active at
    /// `integratedTime`, the SET signature was not valid DER, or the
    /// pinned key's SPKI did not decode as ECDSA P-256.
    #[error("Rekor SET verification failed: {0}")]
    RekorSet(String),

    /// The Rekor body did not carry a Signed Entry Timestamp, but
    /// the caller's [`RekorInclusionProofPolicy`] required one
    /// (`RequireSet` or `RequireBoth`). The inclusion-proof path
    /// (Phase 1.7) is the alternative offline anchor; under `Either`
    /// or `RequireInclusionProof` this case is not an error.
    #[error("Rekor SET is required by policy but missing from the bundle")]
    RekorSetMissing,

    /// Rekor Merkle inclusion proof verification failed: signed
    /// checkpoint did not verify under the pinned Rekor key, the
    /// walked Merkle root did not match the checkpoint's signed
    /// root, the proof was internally inconsistent (e.g. `logIndex`
    /// outside the `treeSize` range), the checkpoint envelope was
    /// malformed, or the proof's `hashes` slice had the wrong arity.
    #[error("Rekor inclusion proof verification failed: {0}")]
    InclusionProof(String),

    /// The Rekor body did not carry an inclusion proof, but the
    /// caller's [`RekorInclusionProofPolicy`] required one
    /// (`RequireInclusionProof` or `RequireBoth`). The SET path
    /// (Phase 1.6) is the alternative offline anchor; under `Either`
    /// or `RequireSet` this case is not an error.
    #[error("Rekor inclusion proof is required by policy but missing from the bundle")]
    InclusionProofMissing,

    /// X.509 chain validation failed: a cert's notBefore/notAfter
    /// window did not contain `integratedTime`, an issuer/subject
    /// pair didn't line up, a link's signature didn't verify under
    /// its parent, no path to a trusted Fulcio root could be built,
    /// or the chain used an unsupported signature algorithm.
    /// AIA fetch is intentionally NOT implemented (the verifier
    /// refuses to fetch missing intermediates from the URL embedded
    /// in the cert — Sigstore bundles always ship the full chain,
    /// and AIA fetch would re-open a supply-chain redirect arm).
    #[error("X.509 chain validation failed: {0}")]
    Chain(String),

    /// Embedded Signed Certificate Timestamp (SCT) verification
    /// failed: leaf cert has no SCT extension at the documented
    /// OID, the SCT list TLS encoding was malformed, the precert
    /// signed-input could not be reconstructed (TBS DER manipulation
    /// failed), no pinned CT log key matched the SCT's `logId` at
    /// `integratedTime`, the SCT signature did not verify under the
    /// pinned key, or zero SCTs in the list verified (the threshold
    /// is "at least one valid").
    #[error("SCT verification failed: {0}")]
    Sct(String),

    /// Bundle parse failed: JSON malformed, missing required field,
    /// unrecognized shape (none of the three known: Sigstore Bundle
    /// v0.2 chain, v0.3 single-cert, npm attestations wrapper), or
    /// a sub-component (DSSE envelope, cert chain, tlog entry)
    /// could not be deserialized into the schema bumped in Phase 1.0.
    #[error("Sigstore bundle parse failed: {0}")]
    BundleParse(String),

    /// Leaf cert's identity (SAN URI or Fulcio OIDC issuer
    /// extension) did not match the caller's `IdentityExpectations`.
    /// Used by the C2 self-update path to bind the signing identity
    /// to `lpm-dev/rust-client/.github/workflows/release.yml`. Not
    /// triggered when expectations are `IdentityExpectations::none()`
    /// (the C1 npm-drift path, where the drift comparator handles
    /// per-package identity tracking).
    #[error(
        "leaf cert identity does not match expectations: {field}: expected `{expected}`, \
         got `{actual}`"
    )]
    IdentityMismatch {
        field: &'static str,
        expected: String,
        actual: String,
    },
}

/// Policy for which Rekor inclusion artifacts a bundle must carry to
/// be considered verifiable. Threaded through [`verify_rekor_set`]
/// (Phase 1.6) and `verify_inclusion_proof` (Phase 1.7); the
/// composed entry point (`verify_sigstore_bundle`, Phase 1.8) sets
/// it per call site.
///
/// `Either` is the right default for npm-attestation consumption
/// (some npm cohorts ship SET-only, others inclusion-proof-only,
/// some both). `RequireBoth` is the C2 self-update default — binary
/// swap is the highest-trust operation so we require both offline
/// anchors. The variant is the *single* authority on what's required;
/// there is intentionally no parallel `require_inclusion_proof: bool`
/// (GPT round-5 H1 — adding one re-creates a dual-authority bug).
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RekorInclusionProofPolicy {
    /// Accept the bundle if at least one of SET, inclusion proof is
    /// present and verifies. Verify the other if it's also present
    /// (defense in depth). Reject if both are absent.
    Either,
    /// SET must be present and verify. Inclusion proof is verified
    /// only when present (advisory).
    RequireSet,
    /// Inclusion proof must be present and verify. SET is verified
    /// only when present (advisory).
    RequireInclusionProof,
    /// Both SET and inclusion proof must be present and both must
    /// verify. The strongest claim.
    RequireBoth,
}

impl RekorInclusionProofPolicy {
    /// True when SET absence should hard-fail per this policy.
    #[allow(dead_code)]
    pub fn requires_set(self) -> bool {
        matches!(self, Self::RequireSet | Self::RequireBoth)
    }

    /// True when inclusion-proof absence should hard-fail per this policy.
    #[allow(dead_code)]
    pub fn requires_inclusion_proof(self) -> bool {
        matches!(self, Self::RequireInclusionProof | Self::RequireBoth)
    }
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

// ─────────────────────────────────────────────────────────────────────
// Phase 1.6 — Rekor SET (Signed Entry Timestamp) verification.
// ─────────────────────────────────────────────────────────────────────
//
// The SET is Rekor's offline-verifiable promise that a given entry
// was integrated into the transparency log at `integratedTime`. It is
// an ECDSA signature, by the Rekor instance's signing key, over a
// canonical JSON of `{body, integratedTime, logID, logIndex}`.
//
// `integratedTime` returned here is the load-bearing "at_time"
// anchor: Phase 1.3 (chain validation) uses it instead of wall-clock,
// and Phase 6.2 (C2 self-update replay window) compares it to the
// release `published_at`. Returning `Result<SystemTime, _>` rather
// than `Result<(), _>` forces every caller through the time anchor.
//
// Canonicalization rules cached in `private/rekor-set-canonicalization.md`
// — bug-density is highest here per the plan's ordering checklist, so
// the byte layout is documented separately from the code that
// implements it.

/// Verify the Rekor SET in `tlog_entry` against the pinned Rekor
/// signing key for the entry's `logID`.
///
/// Returns the parsed `integratedTime` as `SystemTime` so the caller
/// (Phase 1.8) can thread it into chain validation as the
/// `at_time` anchor.
///
/// Policy semantics (see [`RekorInclusionProofPolicy`]):
/// - SET present → always verify (defense in depth across all policies)
/// - SET absent + policy requires SET → [`VerifyError::RekorSetMissing`]
/// - SET absent + policy tolerates absence → return `integratedTime`,
///   no signature work
///
/// Sigstore profile is ECDSA P-256 + SHA-256; Rekor signs over the
/// SHA-256 of the canonical SET input JSON. Any non-P-256 SPKI in
/// the pinned key rejects with [`VerifyError::RekorSet`].
#[allow(dead_code)] // wired into provenance_fetch in Phase 2.1
pub fn verify_rekor_set(
    tlog_entry: &crate::sigstore::TlogEntry,
    rekor_keys: &[RekorKey],
    policy: RekorInclusionProofPolicy,
) -> Result<SystemTime, VerifyError> {
    let integrated_time = parse_integrated_time(&tlog_entry.integrated_time)?;

    let Some(promise) = tlog_entry.resolved_inclusion_promise() else {
        return if policy.requires_set() {
            Err(VerifyError::RekorSetMissing)
        } else {
            Ok(integrated_time)
        };
    };

    let log_index = parse_log_index(&tlog_entry.log_index)?;
    let log_id_bytes = hex::decode(&tlog_entry.log_id.key_id).map_err(|e| {
        VerifyError::RekorSet(format!(
            "TlogEntry.logId.keyId is not valid hex (Rekor canonical form): {e}"
        ))
    })?;

    let rekor_key = rekor_keys
        .iter()
        .find(|k| k.log_id == log_id_bytes && k.valid_for.contains(integrated_time))
        .ok_or_else(|| {
            VerifyError::RekorSet(format!(
                "no pinned Rekor key for logId={} valid at integratedTime={}",
                tlog_entry.log_id.key_id, tlog_entry.integrated_time,
            ))
        })?;

    let verifying_key = p256_verifying_key_from_spki(&rekor_key.spki_der).map_err(|e| {
        VerifyError::RekorSet(format!(
            "pinned Rekor key did not decode as ECDSA P-256 SPKI: {e}"
        ))
    })?;

    let signature_bytes = BASE64
        .decode(promise.signed_entry_timestamp.as_bytes())
        .map_err(|e| VerifyError::RekorSet(format!("signedEntryTimestamp not base64: {e}")))?;
    // Rekor SETs are DER-encoded ECDSA signatures per the Sigstore
    // reference implementation (sigstore/rekor `pkg/util/checkpoint.go`).
    // No raw R||S fallback here — unlike DSSE, Rekor's protocol fixes
    // the encoding.
    let signature = Signature::from_der(&signature_bytes).map_err(|e| {
        VerifyError::RekorSet(format!("signedEntryTimestamp is not valid DER ECDSA: {e}"))
    })?;

    let set_input = build_set_input_canonical_json(
        &tlog_entry.canonicalized_body,
        integrated_time_secs(&integrated_time),
        log_index,
        &tlog_entry.log_id.key_id,
    );
    let digest = Sha256::digest(set_input.as_bytes());

    // Rekor signs the SET via Go's `ecdsa.SignASN1(key, prehash)` —
    // the digest is the signing input, NOT re-hashed by the signer.
    // `verify_prehash` matches that semantic; `verify` would hash
    // the digest a second time and compute the wrong verification
    // input. Documented in `private/rekor-set-canonicalization.md`.
    verifying_key
        .verify_prehash(digest.as_slice(), &signature)
        .map_err(|e| {
            VerifyError::RekorSet(format!(
                "SET signature did not verify under the pinned Rekor key for logId={}: {e}",
                tlog_entry.log_id.key_id,
            ))
        })?;

    Ok(integrated_time)
}

/// Parse a stringified i64 seconds-since-epoch into [`SystemTime`].
/// `tlog_entry.integrated_time` is a string per the schema bump
/// in Phase 1.0 (the publish parser stringifies Rekor's API i64).
fn parse_integrated_time(s: &str) -> Result<SystemTime, VerifyError> {
    let secs: i64 = s.parse().map_err(|e| {
        VerifyError::RekorSet(format!(
            "TlogEntry.integratedTime `{s}` is not a valid i64 seconds-since-epoch: {e}"
        ))
    })?;
    if secs < 0 {
        return Err(VerifyError::RekorSet(format!(
            "TlogEntry.integratedTime `{secs}` is negative; expected a unix timestamp"
        )));
    }
    Ok(SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(secs as u64))
}

fn parse_log_index(s: &str) -> Result<i64, VerifyError> {
    s.parse::<i64>().map_err(|e| {
        VerifyError::RekorSet(format!("TlogEntry.logIndex `{s}` is not a valid i64: {e}"))
    })
}

fn integrated_time_secs(t: &SystemTime) -> i64 {
    t.duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Decode a DER SubjectPublicKeyInfo into a P-256 `VerifyingKey`.
/// Used to consume the `RekorKey.spki_der` material that
/// [`TrustRoot::parse`] base64-decoded out of the trusted_root
/// `publicKey.rawBytes` field.
fn p256_verifying_key_from_spki(spki_der: &[u8]) -> Result<VerifyingKey, String> {
    use p256::pkcs8::DecodePublicKey;
    VerifyingKey::from_public_key_der(spki_der).map_err(|e| e.to_string())
}

/// Build the canonical JSON input the SET is signed over.
///
/// Rekor's spec (mirrored in `private/rekor-set-canonicalization.md`)
/// fixes:
/// - Keys in ASCII alphabetical order: `body, integratedTime, logID, logIndex`
/// - No whitespace
/// - `body` is the `canonicalizedBody` base64 string verbatim
///   (Rekor signs over the base64 representation, NOT the decoded bytes)
/// - `integratedTime` and `logIndex` are numeric i64 literals
/// - `logID` is the hex string Rekor returns (NOT base64-decoded)
///
/// Implemented as a `format!()` rather than via `serde_json` because
/// serde's default object output does not guarantee key order — going
/// through a sorted-BTreeMap would also work but is one more hop where
/// a subtle behavioral change could break verification. This is
/// load-bearing for SET verify; pinned via
/// `build_set_input_canonical_json_matches_documented_layout`.
fn build_set_input_canonical_json(
    canonicalized_body_b64: &str,
    integrated_time_secs: i64,
    log_index: i64,
    log_id_hex: &str,
) -> String {
    format!(
        r#"{{"body":"{body}","integratedTime":{integrated_time},"logID":"{log_id}","logIndex":{log_index}}}"#,
        body = canonicalized_body_b64,
        integrated_time = integrated_time_secs,
        log_id = log_id_hex,
        log_index = log_index,
    )
}

// ─────────────────────────────────────────────────────────────────────
// Phase 1.7 — Rekor Merkle inclusion proof verification.
// ─────────────────────────────────────────────────────────────────────
//
// The inclusion proof is the second offline-verifiable anchor in a
// Sigstore bundle (the first being the SET — Phase 1.6). It proves an
// entry's existence in the transparency log at a specific tree state
// via:
//   1. The signed "checkpoint" — Rekor's commitment to a tree state
//      (origin, tree size, root hash) signed with the same key that
//      signs SETs.
//   2. The Merkle path — sibling hashes that walk from the leaf hash
//      up to the signed root.
//
// Together they bind the bundle's entry to a transparency-log root
// the user can independently corroborate via Rekor's witness API.
//
// Canonicalization rules for the checkpoint signed-note format
// cached in `private/rekor-checkpoint-format.md`; Merkle walk follows
// RFC 6962 §2.1.1 (`hash_children(left, right) = sha256(0x01 || left
// || right)`, `leaf_hash(data) = sha256(0x00 || data)`).
//
// Policy plumbing: this function verifies WHEN CALLED. The composed
// entry point (Phase 1.8) decides whether to call based on
// [`RekorInclusionProofPolicy`] and whether the bundle carries a
// proof. Per the plan's GPT round-5 H1, the enum is the *single*
// authority — there is no parallel boolean knob.

/// Verify the Rekor Merkle inclusion proof attached to `tlog_entry`.
///
/// Steps:
/// 1. Extract the checkpoint envelope (handles both
///    bundle shapes — bare string or `{envelope: "..."}` object).
/// 2. Parse + verify the checkpoint signature under the pinned
///    Rekor key for the entry's `logID`.
/// 3. Consistency: the checkpoint's signed tree size + root hash
///    must agree with the inclusion proof's declared fields.
/// 4. Compute the leaf hash from `canonicalized_body`.
/// 5. Walk the Merkle path per RFC 6962 from leaf → computed root.
/// 6. Compare computed root to the checkpoint's signed root.
///
/// Returns `Ok(())` only when every step passes. Returns
/// [`VerifyError::InclusionProofMissing`] if the bundle carries no
/// inclusion proof — the caller is responsible for deciding whether
/// that's fatal per [`RekorInclusionProofPolicy`].
#[allow(dead_code)] // wired into Phase 1.8 entry point
pub fn verify_inclusion_proof(
    tlog_entry: &crate::sigstore::TlogEntry,
    rekor_keys: &[RekorKey],
) -> Result<(), VerifyError> {
    let proof = tlog_entry
        .resolved_inclusion_proof()
        .ok_or(VerifyError::InclusionProofMissing)?;

    let integrated_time = parse_integrated_time(&tlog_entry.integrated_time)
        .map_err(|e| VerifyError::InclusionProof(format!("{e}")))?;
    let log_id_bytes = hex::decode(&tlog_entry.log_id.key_id).map_err(|e| {
        VerifyError::InclusionProof(format!("TlogEntry.logId.keyId is not valid hex: {e}"))
    })?;
    let rekor_key = rekor_keys
        .iter()
        .find(|k| k.log_id == log_id_bytes && k.valid_for.contains(integrated_time))
        .ok_or_else(|| {
            VerifyError::InclusionProof(format!(
                "no pinned Rekor key for logId={} valid at integratedTime={}",
                tlog_entry.log_id.key_id, tlog_entry.integrated_time,
            ))
        })?;

    let checkpoint_envelope = extract_checkpoint_envelope(&proof.checkpoint)?;
    let trusted = verify_checkpoint_signature(&checkpoint_envelope, rekor_key)?;

    // Consistency: bundle's inclusion-proof fields agree with the
    // signed checkpoint. A bundle that says tree_size=N + root=R but
    // whose signed checkpoint commits to a different tree state is
    // structurally inconsistent — reject before walking the Merkle
    // path so the diagnostic names the mismatch directly.
    if trusted.tree_size != proof.tree_size {
        return Err(VerifyError::InclusionProof(format!(
            "inclusion proof tree_size={} disagrees with signed checkpoint tree_size={}",
            proof.tree_size, trusted.tree_size,
        )));
    }
    let proof_root_bytes = decode_root_hash_hex_or_base64(&proof.root_hash).map_err(|e| {
        VerifyError::InclusionProof(format!(
            "inclusion proof root_hash is neither valid hex nor base64: {e}"
        ))
    })?;
    if proof_root_bytes != trusted.root_hash {
        return Err(VerifyError::InclusionProof(
            "inclusion proof root_hash disagrees with signed checkpoint root".into(),
        ));
    }

    if proof.log_index != tlog_entry.log_index.parse::<i64>().unwrap_or(-1) {
        return Err(VerifyError::InclusionProof(format!(
            "inclusion proof log_index={} disagrees with TlogEntry log_index={}",
            proof.log_index, tlog_entry.log_index,
        )));
    }
    if proof.log_index < 0 || proof.tree_size <= 0 {
        return Err(VerifyError::InclusionProof(format!(
            "inclusion proof has non-positive log_index or tree_size: \
             log_index={}, tree_size={}",
            proof.log_index, proof.tree_size,
        )));
    }
    if (proof.log_index as u64) >= (proof.tree_size as u64) {
        return Err(VerifyError::InclusionProof(format!(
            "inclusion proof log_index={} is not less than tree_size={}",
            proof.log_index, proof.tree_size,
        )));
    }

    let body_bytes = BASE64
        .decode(tlog_entry.canonicalized_body.as_bytes())
        .map_err(|e| {
            VerifyError::InclusionProof(format!(
                "canonicalizedBody is not valid base64 — cannot compute leaf hash: {e}"
            ))
        })?;
    let leaf_hash = rfc6962_leaf_hash(&body_bytes);

    let sibling_hashes = proof
        .hashes
        .iter()
        .map(|h| {
            decode_root_hash_hex_or_base64(h).map_err(|e| {
                VerifyError::InclusionProof(format!(
                    "inclusion proof sibling hash is neither hex nor base64: {e}"
                ))
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    for (i, sibling) in sibling_hashes.iter().enumerate() {
        if sibling.len() != 32 {
            return Err(VerifyError::InclusionProof(format!(
                "inclusion proof sibling hash {i} is {} bytes (expected 32 for sha256)",
                sibling.len()
            )));
        }
    }

    let computed_root = rfc6962_verify_inclusion(
        proof.log_index as u64,
        proof.tree_size as u64,
        &leaf_hash,
        &sibling_hashes,
    )?;
    if computed_root != trusted.root_hash {
        return Err(VerifyError::InclusionProof(format!(
            "Merkle walk root does not match signed checkpoint root: \
             computed={}, signed={}",
            hex::encode(&computed_root),
            hex::encode(&trusted.root_hash),
        )));
    }

    Ok(())
}

/// Pull the checkpoint signed-note string out of an
/// `inclusion_proof.checkpoint` field. The Sigstore Bundle v0.3 spec
/// wraps it as `{ "envelope": "..." }`; some signers / older bundles
/// emit a bare string. Accept both.
fn extract_checkpoint_envelope(value: &serde_json::Value) -> Result<String, VerifyError> {
    match value {
        serde_json::Value::String(s) => Ok(s.clone()),
        serde_json::Value::Object(obj) => obj
            .get("envelope")
            .and_then(|v| v.as_str())
            .map(String::from)
            .ok_or_else(|| {
                VerifyError::InclusionProof(
                    "inclusion proof checkpoint object has no string `envelope` field".into(),
                )
            }),
        other => Err(VerifyError::InclusionProof(format!(
            "inclusion proof checkpoint is {} (expected string or {{\"envelope\":\"...\"}} object)",
            json_value_kind(other)
        ))),
    }
}

/// Parsed and signature-verified checkpoint body. Trusted = the
/// fields below were committed to by the Rekor signing key.
struct TrustedCheckpoint {
    tree_size: i64,
    root_hash: Vec<u8>,
}

/// Verify a C2SP signed-note checkpoint against the pinned Rekor key.
///
/// Format (canonical signed-note, mirrored in
/// `private/rekor-checkpoint-format.md`):
/// ```text
/// <origin>
/// <tree_size>
/// <root_hash_base64>
/// <... optional extra body lines ...>
///
/// — <name> <base64(key_hint || signature)>
/// ```
///
/// The signed bytes are the body (lines before the empty separator),
/// terminated by `\n`. The signature is DER-encoded ECDSA over
/// `sha256(body_bytes)`. The 4-byte key_hint prefix is informational
/// — we look up the Rekor key by `logId` instead, so a wrong hint
/// doesn't cause a false reject (a wrong signature still does).
fn verify_checkpoint_signature(
    envelope: &str,
    rekor_key: &RekorKey,
) -> Result<TrustedCheckpoint, VerifyError> {
    let (text, sig_block) = envelope.split_once("\n\n").ok_or_else(|| {
        VerifyError::InclusionProof(
            "checkpoint envelope is missing the empty-line separator between body and signatures"
                .into(),
        )
    })?;
    let signed_bytes = format!("{text}\n");

    let mut body_lines = text.lines();
    let _origin = body_lines
        .next()
        .ok_or_else(|| VerifyError::InclusionProof("checkpoint body has no origin line".into()))?;
    let tree_size_str = body_lines.next().ok_or_else(|| {
        VerifyError::InclusionProof("checkpoint body has no tree-size line".into())
    })?;
    let root_hash_b64 = body_lines.next().ok_or_else(|| {
        VerifyError::InclusionProof("checkpoint body has no root-hash line".into())
    })?;

    let tree_size: i64 = tree_size_str.trim().parse().map_err(|e| {
        VerifyError::InclusionProof(format!(
            "checkpoint body tree-size line `{tree_size_str}` is not a valid i64: {e}"
        ))
    })?;
    let root_hash = BASE64
        .decode(root_hash_b64.trim().as_bytes())
        .map_err(|e| {
            VerifyError::InclusionProof(format!(
                "checkpoint body root-hash line `{root_hash_b64}` is not valid base64: {e}"
            ))
        })?;
    if root_hash.len() != 32 {
        return Err(VerifyError::InclusionProof(format!(
            "checkpoint root hash is {} bytes (expected 32 for sha256)",
            root_hash.len()
        )));
    }

    let mut sig_lines = sig_block.lines().filter(|l| !l.is_empty());
    let sig_line = sig_lines.next().ok_or_else(|| {
        VerifyError::InclusionProof("checkpoint envelope has no signature line".into())
    })?;

    // Per C2SP signed-note: "— <name> <base64>" where the em-dash is
    // U+2014 (UTF-8: E2 80 94). Strip prefix; the name doesn't gate
    // verification (we look the key up by logId), but the base64
    // value is what we need.
    let rest = sig_line
        .strip_prefix("\u{2014} ")
        .or_else(|| sig_line.strip_prefix("- "))
        .ok_or_else(|| {
            VerifyError::InclusionProof(format!(
                "checkpoint signature line does not start with `— ` (em-dash + space): `{sig_line}`"
            ))
        })?;
    let (_name, b64) = rest.split_once(' ').ok_or_else(|| {
        VerifyError::InclusionProof(format!(
            "checkpoint signature line is missing the base64 signature component: `{sig_line}`"
        ))
    })?;
    let key_hint_plus_sig = BASE64.decode(b64.trim().as_bytes()).map_err(|e| {
        VerifyError::InclusionProof(format!("checkpoint signature base64 did not decode: {e}"))
    })?;
    if key_hint_plus_sig.len() < 4 {
        return Err(VerifyError::InclusionProof(format!(
            "checkpoint signature is {} bytes (expected at least 4 for the key-hint prefix)",
            key_hint_plus_sig.len()
        )));
    }
    let sig_bytes = &key_hint_plus_sig[4..];
    let signature = Signature::from_der(sig_bytes).map_err(|e| {
        VerifyError::InclusionProof(format!("checkpoint signature is not valid DER ECDSA: {e}"))
    })?;

    let verifying_key = p256_verifying_key_from_spki(&rekor_key.spki_der).map_err(|e| {
        VerifyError::InclusionProof(format!(
            "pinned Rekor key did not decode as ECDSA P-256 SPKI: {e}"
        ))
    })?;
    let digest = Sha256::digest(signed_bytes.as_bytes());
    // Same prehash semantic as the SET verifier — Rekor signs the
    // checkpoint digest via Go's ecdsa.SignASN1 prehash protocol.
    // Documented in `private/rekor-checkpoint-format.md`.
    verifying_key
        .verify_prehash(digest.as_slice(), &signature)
        .map_err(|e| {
            VerifyError::InclusionProof(format!(
                "checkpoint signature did not verify under the pinned Rekor key: {e}"
            ))
        })?;

    Ok(TrustedCheckpoint {
        tree_size,
        root_hash,
    })
}

/// Decode a 32-byte sha256 from either hex (Rekor canonical) or
/// base64 (Sigstore Bundle spec). Rekor's HTTP response uses hex for
/// the `rootHash` and `hashes` fields, but some bundle producers
/// re-encode as base64. Accept both to avoid false-rejecting
/// otherwise-valid bundles.
fn decode_root_hash_hex_or_base64(s: &str) -> Result<Vec<u8>, String> {
    if let Ok(bytes) = hex::decode(s) {
        return Ok(bytes);
    }
    BASE64
        .decode(s.as_bytes())
        .map_err(|e| format!("not hex; not base64 ({e})"))
}

/// `MTH({d(0)}) = SHA-256(0x00 || d(0))` per RFC 6962 §2.1.
fn rfc6962_leaf_hash(leaf_data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update([0x00_u8]);
    hasher.update(leaf_data);
    hasher.finalize().to_vec()
}

/// `MTH(D[n]) = SHA-256(0x01 || MTH(D[0:k]) || MTH(D[k:n]))` per
/// RFC 6962 §2.1, hash combination only.
fn rfc6962_hash_children(left: &[u8], right: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update([0x01_u8]);
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().to_vec()
}

/// RFC 6962 §2.1.1 inclusion proof walker. Mirrors the canonical
/// implementation in `sigstore/sigstore-go`'s `pkg/verify/tlog.go`
/// and Trillian's reference Go code. Returns the computed root hash;
/// the caller compares against the trusted (signed) root.
///
/// Algorithm:
/// - `fn` is the leaf's index inside the tree
/// - `sn` is the rightmost leaf index (`tree_size - 1`)
/// - For each sibling hash in the proof:
///   - If `fn` is odd OR `fn == sn` (i.e. we're a right child OR the
///     "last leaf" at this level), the sibling is on the LEFT.
///     Combine `sibling || current`, then walk up "right edges"
///     until `fn` is no longer the rightmost.
///   - Otherwise the sibling is on the RIGHT. Combine
///     `current || sibling`.
///   - Then halve both `fn` and `sn` (move up a level).
/// - After the walk, expect `sn == 0` (we reached the root) and
///   the proof to have been exactly the right arity.
fn rfc6962_verify_inclusion(
    leaf_index: u64,
    tree_size: u64,
    leaf_hash: &[u8],
    proof: &[Vec<u8>],
) -> Result<Vec<u8>, VerifyError> {
    if leaf_index >= tree_size {
        return Err(VerifyError::InclusionProof(format!(
            "leaf_index={leaf_index} >= tree_size={tree_size}"
        )));
    }
    if tree_size == 1 {
        if !proof.is_empty() {
            return Err(VerifyError::InclusionProof(format!(
                "single-leaf tree expects an empty proof; got {} entries",
                proof.len()
            )));
        }
        return Ok(leaf_hash.to_vec());
    }

    let mut fn_: u64 = leaf_index;
    let mut sn: u64 = tree_size - 1;
    let mut r: Vec<u8> = leaf_hash.to_vec();
    for sibling in proof {
        if sn == 0 {
            return Err(VerifyError::InclusionProof(
                "inclusion proof contains more sibling hashes than the tree depth requires".into(),
            ));
        }
        if fn_ & 1 == 1 || fn_ == sn {
            r = rfc6962_hash_children(sibling, &r);
            // Walk up the right-edge chain while `fn_` is even and
            // non-zero (we're at a "last leaf" position climbing
            // through multiple right edges).
            while fn_ & 1 == 0 {
                fn_ >>= 1;
                sn >>= 1;
            }
        } else {
            r = rfc6962_hash_children(&r, sibling);
        }
        fn_ >>= 1;
        sn >>= 1;
    }
    if sn != 0 {
        return Err(VerifyError::InclusionProof(format!(
            "inclusion proof has too few sibling hashes; reached sn={sn} (expected 0)"
        )));
    }
    Ok(r)
}

// ─────────────────────────────────────────────────────────────────────
// Phase 1.3 — X.509 chain validation at `integratedTime`.
// ─────────────────────────────────────────────────────────────────────
//
// Hand-rolled chain walker rather than `webpki` because Sigstore's
// validation profile differs from WebPKI/TLS:
//   - Sigstore matches identity via SAN URI, not DNS hostname (the
//     identity match itself lives in Phase 1.8's
//     `IdentityExpectations`; chain validation here just ensures
//     the leaf's signing key is rooted in a trusted Fulcio CA).
//   - Sigstore profile fixes algorithms (P-256 leaves signed by
//     P-384 intermediates / roots) so we don't need WebPKI's
//     general algorithm-suite plumbing.
//   - The chain is always short (≤3) so the walker is a small loop,
//     not a tree-search.
//
// Critical: AIA fetch is NOT implemented. A Sigstore bundle that's
// missing intermediates fails — we never fetch from a URL inside
// the cert. That closes the "attacker steers AIA fetch to an
// attacker-controlled CA" arm.
//
// `at_time` MUST be the Rekor `integratedTime` (Phase 1.6 returns
// it), NOT wall-clock. Bundles signed by certs that have since
// retired still verify against the integratedTime they declare,
// which is exactly what we want — bundles from 2022 still verify
// in 2027 against the 2022 Fulcio chain that signed them.

/// Sigstore profile limits cert chains to 3 (leaf + intermediate +
/// root). Caps the depth so a forged chain with attacker-injected
/// "intermediates" can't grow unbounded under-the-radar even if a
/// per-link constraint somehow misfires.
const MAX_CHAIN_LENGTH: usize = 3;

/// Verify an X.509 cert chain from the bundle terminates at one of
/// the pinned Fulcio roots, with every link valid at `at_time` and
/// every cert satisfying its position-appropriate X.509 extension
/// profile.
///
/// `bundle_chain_der`: ordered from leaf upward — `[leaf, intermediates...]`.
/// `fulcio_roots`: filtered by [`TrustRoot::fulcio_roots_at(at_time)`]
/// at the call site; this function further enforces that the chain's
/// final cert byte-equals one of those roots (or is signed by one).
///
/// Returns `Ok(())` only when:
/// 1. `bundle_chain_der.len() <= MAX_CHAIN_LENGTH`.
/// 2. Every cert has `notBefore <= at_time <= notAfter`.
/// 3. The leaf (`chain[0]`) satisfies the Sigstore leaf profile
///    via [`enforce_leaf_constraints`] — not flagged as a CA, no
///    `keyCertSign` if `KeyUsage` is present, `codeSigning` in
///    `ExtendedKeyUsage` if EKU is present.
/// 4. Every issuer (`chain[1..]`) satisfies the issuer profile via
///    [`enforce_issuer_constraints`] — `BasicConstraints` present
///    and critical with `cA = TRUE`, `keyCertSign` set if `KeyUsage`
///    is present, and `pathLenConstraint >= remaining_depth` if set.
/// 5. Every adjacent (child, parent) pair: child's signature
///    verifies under parent's SPKI AND child.issuer == parent.subject.
/// 6. The chain's top cert byte-equals a trust anchor cert, OR its
///    signature verifies under one of the trust anchors (which also
///    must satisfy the issuer profile).
///
/// Without (3) and (4), a Sigstore-issued leaf cert (which any party
/// can obtain via OIDC) could be used as an "intermediate" to sign a
/// forged child leaf with attacker-controlled SAN, bypassing
/// Sigstore's identity binding entirely. The extension enforcement
/// is load-bearing for the verifier's core guarantee.
#[allow(dead_code)] // wired into provenance_fetch in Phase 2.1
pub fn verify_cert_chain(
    bundle_chain_der: &[&[u8]],
    fulcio_roots: &[&FulcioRoot],
    at_time: SystemTime,
) -> Result<(), VerifyError> {
    if bundle_chain_der.is_empty() {
        return Err(VerifyError::Chain(
            "bundle cert chain is empty (must include at least the leaf)".into(),
        ));
    }
    if bundle_chain_der.len() > MAX_CHAIN_LENGTH {
        return Err(VerifyError::Chain(format!(
            "bundle cert chain has {} certs (Sigstore profile allows at most {})",
            bundle_chain_der.len(),
            MAX_CHAIN_LENGTH
        )));
    }
    if fulcio_roots.is_empty() {
        return Err(VerifyError::Chain(
            "no Fulcio roots active at integratedTime — cannot anchor any chain".into(),
        ));
    }

    let at_time_dt: DateTime<Utc> = at_time.into();

    // Parse every cert in the bundle's chain once up-front. Reject
    // any malformed DER before any signature work runs.
    let mut parsed: Vec<X509Certificate<'_>> = Vec::with_capacity(bundle_chain_der.len());
    for (i, der) in bundle_chain_der.iter().enumerate() {
        let (_, cert) = X509Certificate::from_der(der).map_err(|e| {
            VerifyError::Chain(format!(
                "bundle chain cert[{i}] is not valid DER X.509: {e}"
            ))
        })?;
        parsed.push(cert);
    }

    // Step 1: every chain cert must be valid at `at_time`. This is
    // the load-bearing "at_time = integratedTime" check that lets
    // old bundles still verify against retired Fulcio chains.
    for (i, cert) in parsed.iter().enumerate() {
        check_cert_validity_at(cert, at_time_dt, &format!("chain[{i}]"))?;
    }

    // Step 2: position-appropriate X.509 extension profile.
    // Leaf MUST be non-CA; every issuer above the leaf MUST be a CA
    // with keyCertSign authority. This is the defense against the
    // "use a real Sigstore leaf cert as a CA" forgery — closes the
    // identity-binding bypass.
    enforce_leaf_constraints(&parsed[0], "chain[0] (leaf)")?;
    for (i, cert) in parsed.iter().enumerate().skip(1) {
        // "remaining_depth" = number of intermediate CAs that follow
        // this cert on the path to the leaf (exclusive of both this
        // cert and the leaf). For cert at chain index i (i >= 1),
        // that's i - 1.
        let remaining_depth = i - 1;
        enforce_issuer_constraints(cert, remaining_depth, &format!("chain[{i}]"))?;
    }

    // Step 3: every adjacent (child, parent) pair must chain
    // structurally and cryptographically.
    for i in 0..parsed.len().saturating_sub(1) {
        verify_chain_link(
            &parsed[i],
            &parsed[i + 1],
            &format!("chain[{i}] ⇒ chain[{}]", i + 1),
        )?;
    }

    // Step 4: terminate at a trusted anchor. Two valid shapes:
    //   (a) the chain's top cert IS one of the trust anchor certs
    //       (bundle included the Fulcio root).
    //   (b) the chain's top cert is signed by a trust anchor
    //       (bundle stopped at the intermediate).
    let top_der = bundle_chain_der.last().expect("non-empty checked above");
    if anchor_contains_der(fulcio_roots, top_der) {
        return Ok(());
    }

    let top_parsed = parsed.last().expect("non-empty checked above");
    // The anchor in case (b) sits "above" the chain — its
    // remaining_depth equals the number of intermediates already in
    // the chain (`bundle_chain_der.len() - 1`, since chain[0] is the
    // leaf and the leaf doesn't count as an intermediate following
    // the anchor).
    let anchor_remaining_depth = bundle_chain_der.len() - 1;
    for root in fulcio_roots {
        for root_der in &root.cert_chain_der {
            let Ok((_, root_cert)) = X509Certificate::from_der(root_der) else {
                continue;
            };
            // The root's own validity is gated upstream by
            // TrustRoot::fulcio_roots_at; but the cert's intrinsic
            // notBefore/notAfter is still a defense — fail-closed
            // if the trust root's cert itself is out of window.
            if check_cert_validity_at(&root_cert, at_time_dt, "fulcio_root").is_err() {
                continue;
            }
            // The anchor must satisfy the issuer profile too — a
            // misissued or rotated trust-root that lacks cA=TRUE
            // should never anchor a chain.
            if enforce_issuer_constraints(&root_cert, anchor_remaining_depth, "fulcio_root")
                .is_err()
            {
                continue;
            }
            if try_anchor_signature(top_parsed, &root_cert).is_ok() {
                return Ok(());
            }
        }
    }

    Err(VerifyError::Chain(format!(
        "bundle chain's top cert does not match any trusted Fulcio root and \
         is not signed by any trusted Fulcio root \
         ({} candidate root(s) active at integratedTime)",
        fulcio_roots.len()
    )))
}

/// X.509 extension enforcement for a cert acting as a CA — every
/// cert above the leaf in the chain, plus the trust anchor that
/// terminates the chain on the `try_anchor_signature` branch.
///
/// Required:
/// - `BasicConstraints` present, **critical**, `cA = TRUE`. Without
///   this, a real Sigstore leaf cert (which any party can obtain via
///   OIDC) could be used as a forged intermediate to sign an
///   attacker-controlled child cert.
/// - `pathLenConstraint` (when set) `>= remaining_depth`. Sigstore's
///   intermediate has `pathLen = 0`, which means it can sign leaves
///   but not further intermediates — closes "stack arbitrary
///   intermediates between a real cert and a forged leaf."
///
/// If `KeyUsage` is present, require `keyCertSign`. Absent is
/// permissive (real Fulcio CAs always include it, but rcgen-synth
/// CAs may omit it without the strict profile).
fn enforce_issuer_constraints(
    cert: &X509Certificate<'_>,
    remaining_depth: usize,
    label: &str,
) -> Result<(), VerifyError> {
    let bc_ext = cert
        .basic_constraints()
        .map_err(|e| VerifyError::Chain(format!("{label}: BasicConstraints parse failed: {e}")))?;
    let bc = bc_ext.ok_or_else(|| {
        VerifyError::Chain(format!(
            "{label}: BasicConstraints extension missing — issuer cert is not authorized to \
             sign other certs (closes 'real Sigstore leaf as CA' forgery)"
        ))
    })?;
    if !bc.critical {
        return Err(VerifyError::Chain(format!(
            "{label}: BasicConstraints extension is not marked critical \
             (Sigstore profile requires criticality on issuers)"
        )));
    }
    if !bc.value.ca {
        return Err(VerifyError::Chain(format!(
            "{label}: BasicConstraints.cA is FALSE — issuer cert is not authorized to sign certs"
        )));
    }
    if let Some(plc) = bc.value.path_len_constraint
        && (plc as usize) < remaining_depth
    {
        return Err(VerifyError::Chain(format!(
            "{label}: BasicConstraints.pathLenConstraint={plc} < remaining intermediate \
             depth={remaining_depth} (forged chain trying to slip past Sigstore's path-length limit)"
        )));
    }

    let ku_ext = cert
        .key_usage()
        .map_err(|e| VerifyError::Chain(format!("{label}: KeyUsage parse failed: {e}")))?;
    if let Some(ku) = ku_ext
        && !ku.value.key_cert_sign()
    {
        return Err(VerifyError::Chain(format!(
            "{label}: KeyUsage extension does not include keyCertSign — issuer cert is not \
             authorized to sign other certs"
        )));
    }

    Ok(())
}

/// X.509 extension enforcement for the leaf cert (`chain[0]`).
///
/// Required:
/// - `BasicConstraints` either absent OR `cA = FALSE`. A leaf
///   flagged as a CA is structurally invalid for a Sigstore signing
///   cert.
///
/// If `KeyUsage` is present, require `digitalSignature` AND reject
/// `keyCertSign`. (A leaf that asserts `keyCertSign` is fundamentally
/// abusable.) If `ExtendedKeyUsage` is present, require `codeSigning`
/// per Sigstore's Fulcio leaf profile. Absent extensions are
/// permissive — rcgen test leaves may omit them.
fn enforce_leaf_constraints(cert: &X509Certificate<'_>, label: &str) -> Result<(), VerifyError> {
    let bc_ext = cert
        .basic_constraints()
        .map_err(|e| VerifyError::Chain(format!("{label}: BasicConstraints parse failed: {e}")))?;
    if let Some(bc) = bc_ext
        && bc.value.ca
    {
        return Err(VerifyError::Chain(format!(
            "{label}: BasicConstraints.cA is TRUE — leaf cert must NOT be a CA"
        )));
    }

    let ku_ext = cert
        .key_usage()
        .map_err(|e| VerifyError::Chain(format!("{label}: KeyUsage parse failed: {e}")))?;
    if let Some(ku) = ku_ext {
        if !ku.value.digital_signature() {
            return Err(VerifyError::Chain(format!(
                "{label}: KeyUsage extension does not include digitalSignature \
                 (Sigstore leaves must be signing-capable)"
            )));
        }
        if ku.value.key_cert_sign() {
            return Err(VerifyError::Chain(format!(
                "{label}: KeyUsage extension includes keyCertSign — leaf cert is fundamentally \
                 abusable as an intermediate"
            )));
        }
    }

    let eku_ext = cert
        .extended_key_usage()
        .map_err(|e| VerifyError::Chain(format!("{label}: ExtendedKeyUsage parse failed: {e}")))?;
    if let Some(eku) = eku_ext
        && !eku.value.code_signing
    {
        return Err(VerifyError::Chain(format!(
            "{label}: ExtendedKeyUsage does not include codeSigning \
             (Sigstore Fulcio leaf profile requires it)"
        )));
    }

    Ok(())
}

fn anchor_contains_der(fulcio_roots: &[&FulcioRoot], top_der: &[u8]) -> bool {
    fulcio_roots
        .iter()
        .flat_map(|r| r.cert_chain_der.iter())
        .any(|d| d.as_slice() == top_der)
}

fn check_cert_validity_at(
    cert: &X509Certificate<'_>,
    at_time: DateTime<Utc>,
    label: &str,
) -> Result<(), VerifyError> {
    let validity = cert.validity();
    let not_before = DateTime::from_timestamp(validity.not_before.timestamp(), 0)
        .ok_or_else(|| VerifyError::Chain(format!("{label} notBefore is unrepresentable")))?;
    let not_after = DateTime::from_timestamp(validity.not_after.timestamp(), 0)
        .ok_or_else(|| VerifyError::Chain(format!("{label} notAfter is unrepresentable")))?;
    if at_time < not_before || at_time > not_after {
        return Err(VerifyError::Chain(format!(
            "{label} validity window [{not_before}, {not_after}] does not contain integratedTime {at_time}"
        )));
    }
    Ok(())
}

fn verify_chain_link(
    child: &X509Certificate<'_>,
    parent: &X509Certificate<'_>,
    label: &str,
) -> Result<(), VerifyError> {
    // Structural: child.issuer must equal parent.subject. x509-parser
    // exposes DER-equality comparison on `X509Name` via the wrapper's
    // `as_raw()` (the original DER bytes), which we compare byte-wise
    // — that's the strictest form of name equality.
    if child.tbs_certificate.issuer.as_raw() != parent.tbs_certificate.subject.as_raw() {
        return Err(VerifyError::Chain(format!(
            "{label}: child.issuer DN does not equal parent.subject DN"
        )));
    }

    // Cryptographic: child's `tbs_certificate` bytes, hashed under the
    // signature algorithm declared on the cert, must verify under the
    // parent's SPKI bytes.
    let tbs_bytes = child.tbs_certificate.as_ref();
    let sig_bytes = &child.signature_value.data;
    let sig_alg_oid = &child.signature_algorithm.algorithm;
    verify_ecdsa_signature_by_oid(sig_alg_oid, tbs_bytes, sig_bytes, parent, label)
}

fn try_anchor_signature(
    top: &X509Certificate<'_>,
    anchor: &X509Certificate<'_>,
) -> Result<(), VerifyError> {
    if top.tbs_certificate.issuer.as_raw() != anchor.tbs_certificate.subject.as_raw() {
        return Err(VerifyError::Chain(
            "top cert issuer DN does not equal trust anchor subject DN".into(),
        ));
    }
    let tbs = top.tbs_certificate.as_ref();
    let sig = &top.signature_value.data;
    let sig_alg = &top.signature_algorithm.algorithm;
    verify_ecdsa_signature_by_oid(sig_alg, tbs, sig, anchor, "anchor-link")
}

/// ECDSA signature OIDs we accept (Sigstore profile).
/// - 1.2.840.10045.4.3.2 = `ecdsa-with-SHA256` (P-256 leaves)
/// - 1.2.840.10045.4.3.3 = `ecdsa-with-SHA384` (P-384 roots/intermediates)
const OID_ECDSA_WITH_SHA256: [u64; 7] = [1, 2, 840, 10045, 4, 3, 2];
const OID_ECDSA_WITH_SHA384: [u64; 7] = [1, 2, 840, 10045, 4, 3, 3];

fn oid_components_match(oid: &x509_parser::der_parser::oid::Oid<'_>, expected: &[u64]) -> bool {
    let components: Vec<u64> = match oid.iter() {
        Some(iter) => iter.collect(),
        None => return false,
    };
    components.as_slice() == expected
}

fn verify_ecdsa_signature_by_oid(
    sig_alg_oid: &x509_parser::der_parser::oid::Oid<'_>,
    tbs_bytes: &[u8],
    sig_bytes: &[u8],
    parent: &X509Certificate<'_>,
    label: &str,
) -> Result<(), VerifyError> {
    let spki_der = parent.public_key().raw;
    if oid_components_match(sig_alg_oid, &OID_ECDSA_WITH_SHA256) {
        verify_ecdsa_p256_sha256(spki_der, tbs_bytes, sig_bytes, label)
    } else if oid_components_match(sig_alg_oid, &OID_ECDSA_WITH_SHA384) {
        verify_ecdsa_p384_sha384(spki_der, tbs_bytes, sig_bytes, label)
    } else {
        Err(VerifyError::Chain(format!(
            "{label}: unsupported signature algorithm OID {sig_alg_oid} \
             (Sigstore profile accepts only ecdsa-with-SHA256 or ecdsa-with-SHA384)"
        )))
    }
}

fn verify_ecdsa_p256_sha256(
    spki_der: &[u8],
    tbs_bytes: &[u8],
    sig_bytes: &[u8],
    label: &str,
) -> Result<(), VerifyError> {
    use p256::pkcs8::DecodePublicKey;
    let verifying_key = VerifyingKey::from_public_key_der(spki_der).map_err(|e| {
        VerifyError::Chain(format!(
            "{label}: parent SPKI did not decode as ECDSA P-256: {e}"
        ))
    })?;
    let signature = Signature::from_der(sig_bytes).map_err(|e| {
        VerifyError::Chain(format!(
            "{label}: cert signature is not valid DER ECDSA: {e}"
        ))
    })?;
    // X.509 cert signature: sigma = ECDSA-sign(key, SHA-256(TBS)).
    // p256::ecdsa::VerifyingKey's `Verifier<Signature>::verify` impl
    // hashes the message internally with SHA-256 — exactly the curve's
    // standard hash for ecdsa-with-SHA256 — so passing raw TBS bytes
    // is the right shape. Pre-hashing first would re-hash the digest
    // and produce the wrong verification input.
    verifying_key.verify(tbs_bytes, &signature).map_err(|e| {
        VerifyError::Chain(format!(
            "{label}: ECDSA P-256 signature did not verify: {e}"
        ))
    })
}

fn verify_ecdsa_p384_sha384(
    spki_der: &[u8],
    tbs_bytes: &[u8],
    sig_bytes: &[u8],
    label: &str,
) -> Result<(), VerifyError> {
    use p384::pkcs8::DecodePublicKey;
    let verifying_key = p384::ecdsa::VerifyingKey::from_public_key_der(spki_der).map_err(|e| {
        VerifyError::Chain(format!(
            "{label}: parent SPKI did not decode as ECDSA P-384: {e}"
        ))
    })?;
    let signature = p384::ecdsa::Signature::from_der(sig_bytes).map_err(|e| {
        VerifyError::Chain(format!(
            "{label}: cert signature is not valid DER ECDSA: {e}"
        ))
    })?;
    // Same shape as the P-256 case — p384's Verifier hashes with
    // SHA-384, which matches ecdsa-with-SHA384.
    verifying_key.verify(tbs_bytes, &signature).map_err(|e| {
        VerifyError::Chain(format!(
            "{label}: ECDSA P-384 signature did not verify: {e}"
        ))
    })
}

// ─────────────────────────────────────────────────────────────────────
// Phase 1.4 — embedded SCT (Signed Certificate Timestamp) verification.
// ─────────────────────────────────────────────────────────────────────
//
// Per RFC 6962 §3.2, a Sigstore-issued leaf cert carries one or more
// SCTs in the X.509 extension at OID 1.3.6.1.4.1.11129.2.4.2 ("CT
// Precertificate SCT"). Each SCT is a signed promise by a CT log that
// it received and integrated the certificate at a specific timestamp.
//
// Verification per RFC 6962 §3.2:
//   1. Parse the leaf cert's SCT extension → SignedCertificateTimestampList
//      (TLS-encoded — NOT ASN.1).
//   2. For each SCT in the list:
//      a. Locate the pinned `CtLogKey` matching the SCT's `log_id`
//         and valid at `at_time` (the Rekor `integratedTime` so we
//         pick the CT log key that was in service when the leaf was
//         issued, NOT at wall-clock).
//      b. Reconstruct the "precertificate" TBS = the leaf cert's TBS
//         with the SCT extension REMOVED. This is what the CT log
//         actually signed over.
//      c. Build the SCT signature input per RFC 6962 §3.2 layout:
//         version(1) || sig_type(1) || timestamp(8) ||
//         entry_type(2) || issuer_key_hash(32) || precert_tbs(u24+N) ||
//         sct_extensions(u16+M).
//      d. ECDSA-verify(ct_log_key, signature_input) using the curve's
//         standard hash (SHA-256 for P-256 CT logs).
//   3. Threshold: at least one SCT in the list must verify. Encoded
//      as `>=1`, not `==1`, so a future multi-CT-log world (already
//      reflected in the trusted_root.json) stays compatible.
//
// Sigstore Bundle v0.3 spec has NO first-class detached-SCT field —
// all SCTs MUST be embedded in the leaf cert. The publish path's
// detached-SCT response variant is now rejected at issuance time
// (see `sigstore.rs::fulcio_get_certificate`); install-side
// `verify_embedded_sct` is the symmetric end of the pipe.
//
// RFC 3161 timestamp fallback (Sigstore Bundle v0.3
// `timestampVerificationData.rfc3161Timestamps[]`) is intentionally
// NOT implemented in this commit — see
// `private/security-findings.md` for the tracked follow-up. A bundle
// shipping only an RFC 3161 timestamp and no embedded SCT rejects
// here, surfacing as `VerifyError::Sct("no embedded SCT…")`.

/// OID for the "CT Precertificate SCT" extension (RFC 6962 §3.3).
/// Encoded as DER: tag (0x06) + length (0x0A = 10) + 10 OID bytes.
/// We compare the OID bytes directly against x509-parser's
/// `Oid::iter().collect::<Vec<u64>>()`.
const SCT_EXTENSION_OID_COMPONENTS: [u64; 10] = [1, 3, 6, 1, 4, 1, 11129, 2, 4, 2];

/// CT log key hash size = SHA-256 output. RFC 6962 §3.2.
const CT_LOG_ID_LEN: usize = 32;

/// Minimum serialized SCT length: version(1) + log_id(32) +
/// timestamp(8) + extensions_length(2) + at_least_an_empty_signature(4
/// bytes for the digitally-signed header).
const MIN_SCT_LEN: usize = 1 + CT_LOG_ID_LEN + 8 + 2 + 4;

/// Verify the embedded SCT list on a Sigstore-issued leaf cert.
///
/// `leaf_cert_der`: the leaf cert's full DER (NOT the TBS bytes —
/// this function extracts what it needs).
/// `issuer_spki_der`: the DER-encoded SubjectPublicKeyInfo of the
/// leaf's immediate issuer (the Fulcio intermediate or root that
/// signed it). The SCT signed-input includes
/// `sha256(issuer_spki_der)` to bind the SCT to a specific issuer.
/// `ctlog_keys`: trust root's CT log keys, filtered by validity at
/// `at_time` inside this function.
/// `at_time`: typically the Rekor `integratedTime`.
///
/// Returns `Ok(())` when ≥1 SCT in the leaf's extension verifies
/// under one of the pinned CT log keys. A cert with no SCT
/// extension rejects with `VerifyError::Sct` — silent skip would
/// defeat the entire CT pin.
#[allow(dead_code)] // wired into Phase 1.8 entry point
pub fn verify_embedded_sct(
    leaf_cert_der: &[u8],
    issuer_spki_der: &[u8],
    ctlog_keys: &[CtLogKey],
    at_time: SystemTime,
) -> Result<(), VerifyError> {
    let (_, leaf) = X509Certificate::from_der(leaf_cert_der)
        .map_err(|e| VerifyError::Sct(format!("leaf cert is not valid DER: {e}")))?;

    // Find the SCT extension on the leaf cert.
    let sct_ext = leaf
        .extensions()
        .iter()
        .find(|e| {
            e.oid
                .iter()
                .map(|it| it.collect::<Vec<u64>>())
                .map(|v| v.as_slice() == SCT_EXTENSION_OID_COMPONENTS)
                .unwrap_or(false)
        })
        .ok_or_else(|| {
            VerifyError::Sct(
                "no embedded SCT extension on leaf cert (OID 1.3.6.1.4.1.11129.2.4.2); \
                 Sigstore bundles must carry SCTs in the leaf cert extension"
                    .into(),
            )
        })?;

    // The extension's `value` field is the OCTET STRING content bytes
    // per x509-parser; the inner content is itself a DER OCTET STRING
    // wrapping the TLS-encoded SCT list. Unwrap that inner OCTET
    // STRING.
    let inner_tls_bytes = unwrap_octet_string(sct_ext.value).map_err(|e| {
        VerifyError::Sct(format!(
            "SCT extension value is not a DER OCTET STRING: {e}"
        ))
    })?;

    let sct_serialized_list = parse_sct_list_tls(inner_tls_bytes)
        .map_err(|e| VerifyError::Sct(format!("SCT list TLS encoding is malformed: {e}")))?;
    if sct_serialized_list.is_empty() {
        return Err(VerifyError::Sct(
            "SCT list is empty — leaf cert claims to have CT proof but the list is zero-length"
                .into(),
        ));
    }

    // Reconstruct the precertificate TBS: leaf's TBS with the SCT
    // extension removed. This is the byte sequence the CT log signed
    // over (RFC 6962 §3.2).
    let precert_tbs = reconstruct_precert_tbs_without_sct(leaf.tbs_certificate.as_ref())
        .map_err(|e| VerifyError::Sct(format!("precert TBS reconstruction failed: {e}")))?;

    let issuer_key_hash = Sha256::digest(issuer_spki_der).to_vec();
    if issuer_key_hash.len() != CT_LOG_ID_LEN {
        // Unreachable — sha256 output is always 32 bytes — but we
        // assert structurally so the SCT input layout stays correct.
        return Err(VerifyError::Sct(
            "issuer SPKI hash is not 32 bytes (sha256 invariant violated)".into(),
        ));
    }

    // Per-SCT verification. Threshold: ≥1 must verify.
    let mut verified = 0usize;
    let mut last_err: Option<String> = None;
    for (i, serialized) in sct_serialized_list.iter().enumerate() {
        let parsed = match parse_serialized_sct(serialized) {
            Ok(p) => p,
            Err(e) => {
                last_err = Some(format!("sct[{i}] parse: {e}"));
                continue;
            }
        };
        let Some(key) = ctlog_keys
            .iter()
            .find(|k| k.log_id == parsed.log_id && k.valid_for.contains(at_time))
        else {
            last_err = Some(format!(
                "sct[{i}]: no pinned CT log key matches logId={} valid at integratedTime",
                hex::encode(&parsed.log_id)
            ));
            continue;
        };
        if let Err(e) = verify_sct_signature(&parsed, &precert_tbs, &issuer_key_hash, key) {
            last_err = Some(format!("sct[{i}]: {e}"));
            continue;
        }
        verified += 1;
    }
    if verified == 0 {
        return Err(VerifyError::Sct(format!(
            "no SCT in the leaf cert's extension verified under any pinned CT log key (\
             {} candidate(s) in list); last error: {}",
            sct_serialized_list.len(),
            last_err.unwrap_or_else(|| "unknown".into())
        )));
    }
    Ok(())
}

/// Parsed RFC 6962 SCT (the bundle's outer SCT structure, not the
/// signed-input form).
struct ParsedSct<'a> {
    /// Always 0 (v1). Kept on the struct as a parse-trace artifact —
    /// the version byte is asserted == 0 during parse, so the field
    /// itself is informational only at verification time.
    #[allow(dead_code)]
    version: u8,
    /// 32-byte sha256 of the CT log's SPKI.
    log_id: Vec<u8>,
    /// Big-endian millis since unix epoch.
    timestamp_ms: u64,
    /// SCT-extensions — usually empty.
    sct_extensions: &'a [u8],
    /// `digitally-signed` header bytes: hash_algo(1) + sig_algo(1) +
    /// signature length(2).
    sig_hash_algo: u8,
    sig_pk_algo: u8,
    /// DER-encoded ECDSA signature (or whatever the algo says).
    signature_der: &'a [u8],
}

/// Decode the inner OCTET STRING wrapping the SCT list. x509-parser
/// returns the extension `value` as the OCTET STRING content — but
/// that content is ITSELF a DER OCTET STRING (per RFC 6962 §3.3,
/// `extnValue` of the SCT extension contains a DER-encoded OCTET
/// STRING whose content is the TLS-encoded list).
fn unwrap_octet_string(bytes: &[u8]) -> Result<&[u8], String> {
    if bytes.len() < 2 {
        return Err(format!("input too short: {} bytes", bytes.len()));
    }
    if bytes[0] != 0x04 {
        return Err(format!(
            "expected OCTET STRING tag (0x04), got 0x{:02x}",
            bytes[0]
        ));
    }
    let (len, consumed) = der_decode_length(&bytes[1..])
        .ok_or_else(|| "OCTET STRING length is malformed".to_string())?;
    let start = 1 + consumed;
    if bytes.len() < start + len {
        return Err(format!(
            "OCTET STRING declares len={len} but only {} content bytes follow",
            bytes.len() - start
        ));
    }
    Ok(&bytes[start..start + len])
}

/// Parse the SignedCertificateTimestampList TLS structure:
/// `u16 total_length || (u16 sct_length || serialized_sct)*`
/// per RFC 6962 §3.3. Returns the list of serialized-SCT byte slices.
fn parse_sct_list_tls(bytes: &[u8]) -> Result<Vec<&[u8]>, String> {
    if bytes.len() < 2 {
        return Err(format!(
            "input too short for outer u16 length: {} bytes",
            bytes.len()
        ));
    }
    let total_len = u16::from_be_bytes([bytes[0], bytes[1]]) as usize;
    if bytes.len() < 2 + total_len {
        return Err(format!(
            "outer length declares {total_len} bytes but {} follow",
            bytes.len() - 2
        ));
    }
    let mut out = Vec::new();
    let mut offset = 2usize;
    let end = 2 + total_len;
    while offset < end {
        if offset + 2 > end {
            return Err(format!("truncated u16 sct_length at offset {offset}"));
        }
        let sct_len = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]) as usize;
        offset += 2;
        if offset + sct_len > end {
            return Err(format!(
                "sct at offset {offset} declares {sct_len} bytes but only {} bytes remain",
                end - offset
            ));
        }
        out.push(&bytes[offset..offset + sct_len]);
        offset += sct_len;
    }
    Ok(out)
}

/// Parse a serialized SCT per RFC 6962 §3.2.
fn parse_serialized_sct(bytes: &[u8]) -> Result<ParsedSct<'_>, String> {
    if bytes.len() < MIN_SCT_LEN {
        return Err(format!(
            "serialized SCT is {} bytes, minimum is {MIN_SCT_LEN}",
            bytes.len()
        ));
    }
    let mut offset = 0usize;
    let version = bytes[offset];
    offset += 1;
    if version != 0 {
        return Err(format!(
            "SCT version is {version} (RFC 6962 requires v1, i.e. version byte 0)"
        ));
    }
    let log_id = bytes[offset..offset + CT_LOG_ID_LEN].to_vec();
    offset += CT_LOG_ID_LEN;
    let timestamp_ms = u64::from_be_bytes(bytes[offset..offset + 8].try_into().expect("8 bytes"));
    offset += 8;
    let sct_extensions_len = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]) as usize;
    offset += 2;
    if offset + sct_extensions_len > bytes.len() {
        return Err(format!(
            "SCT extensions declare {sct_extensions_len} bytes but only {} remain",
            bytes.len() - offset
        ));
    }
    let sct_extensions = &bytes[offset..offset + sct_extensions_len];
    offset += sct_extensions_len;

    if offset + 4 > bytes.len() {
        return Err("truncated digitally-signed header (need hash+sig algo+u16 len)".into());
    }
    let sig_hash_algo = bytes[offset];
    let sig_pk_algo = bytes[offset + 1];
    offset += 2;
    let sig_len = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]) as usize;
    offset += 2;
    if offset + sig_len > bytes.len() {
        return Err(format!(
            "digitally-signed declares {sig_len} sig bytes but only {} remain",
            bytes.len() - offset
        ));
    }
    let signature_der = &bytes[offset..offset + sig_len];
    Ok(ParsedSct {
        version,
        log_id,
        timestamp_ms,
        sct_extensions,
        sig_hash_algo,
        sig_pk_algo,
        signature_der,
    })
}

/// SCT signature-input layout for `precert_entry` per RFC 6962 §3.2:
/// ```text
/// uint8  version (0)
/// uint8  signature_type (0 = certificate_timestamp)
/// uint64 timestamp_ms (BE)
/// uint16 entry_type (1 = precert_entry, BE)
/// PreCert {
///     uint8 issuer_key_hash[32]
///     uint24 tbs_length (BE)
///     uint8 tbs_certificate[tbs_length]
/// }
/// uint16 sct_extensions_length (BE)
/// uint8 sct_extensions[sct_extensions_length]
/// ```
fn build_precert_sct_signature_input(
    sct: &ParsedSct<'_>,
    issuer_key_hash: &[u8],
    precert_tbs: &[u8],
) -> Result<Vec<u8>, String> {
    if issuer_key_hash.len() != CT_LOG_ID_LEN {
        return Err("issuer_key_hash must be 32 bytes".into());
    }
    if precert_tbs.len() > 0xFF_FFFF {
        return Err(format!(
            "precert TBS is {} bytes (exceeds u24 max for SCT signed input)",
            precert_tbs.len()
        ));
    }
    let mut out = Vec::with_capacity(45 + precert_tbs.len() + sct.sct_extensions.len());
    out.push(0u8); // version
    out.push(0u8); // signature_type = certificate_timestamp
    out.extend_from_slice(&sct.timestamp_ms.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes()); // entry_type = precert_entry
    out.extend_from_slice(issuer_key_hash);
    let tbs_len = precert_tbs.len() as u32;
    out.push(((tbs_len >> 16) & 0xFF) as u8);
    out.push(((tbs_len >> 8) & 0xFF) as u8);
    out.push((tbs_len & 0xFF) as u8);
    out.extend_from_slice(precert_tbs);
    out.extend_from_slice(&(sct.sct_extensions.len() as u16).to_be_bytes());
    out.extend_from_slice(sct.sct_extensions);
    Ok(out)
}

/// Verify a single SCT's signature against a pinned CT log key.
fn verify_sct_signature(
    sct: &ParsedSct<'_>,
    precert_tbs: &[u8],
    issuer_key_hash: &[u8],
    ct_log_key: &CtLogKey,
) -> Result<(), String> {
    // Sigstore profile: SCTs use ECDSA P-256 + SHA-256. RFC 6962
    // hash_algorithm = 4 (sha256), signature_algorithm = 3 (ecdsa).
    // A future log that signs with a different algorithm would
    // surface here and be rejected — better visible than silently
    // mis-verified.
    if sct.sig_hash_algo != 4 || sct.sig_pk_algo != 3 {
        return Err(format!(
            "unsupported SCT signature algorithm (hash={}, sig={}); \
             RFC 6962 sha256/ecdsa is (4, 3)",
            sct.sig_hash_algo, sct.sig_pk_algo
        ));
    }
    let signature = Signature::from_der(sct.signature_der)
        .map_err(|e| format!("SCT signature is not valid DER ECDSA: {e}"))?;
    use p256::pkcs8::DecodePublicKey;
    let verifying_key = VerifyingKey::from_public_key_der(&ct_log_key.spki_der)
        .map_err(|e| format!("pinned CT log SPKI did not decode as ECDSA P-256: {e}"))?;
    let signed_input = build_precert_sct_signature_input(sct, issuer_key_hash, precert_tbs)?;
    verifying_key
        .verify(&signed_input, &signature)
        .map_err(|e| format!("signature did not verify: {e}"))
}

/// Strip the embedded SCT extension from a leaf cert's TBS, returning
/// the precert-equivalent TBS bytes (DER-encoded). This is what the
/// CT log actually signed over per RFC 6962 §3.2.
///
/// Approach: walk the TBS SEQUENCE byte-by-byte using a small TLV
/// reader. Extensions appear in the `[3] EXPLICIT Extensions
/// OPTIONAL` tagged field (DER tag `0xA3`). When we hit `[3]`, we
/// dive into the nested SEQUENCE OF Extension, copy non-SCT
/// extensions through, and re-encode the modified extensions list
/// with recomputed lengths.
///
/// We avoid pulling a full DER serde codec for this single
/// surgical edit; the helpers (`der_decode_length`, `der_encode_*`)
/// are small, total-input-bounded, and the TBS shape is fixed by
/// RFC 5280.
fn reconstruct_precert_tbs_without_sct(tbs_bytes: &[u8]) -> Result<Vec<u8>, String> {
    // Outer TBS SEQUENCE: tag 0x30 + length.
    if tbs_bytes.is_empty() || tbs_bytes[0] != 0x30 {
        return Err(format!(
            "TBS does not start with SEQUENCE tag 0x30 (got 0x{:02x})",
            tbs_bytes.first().copied().unwrap_or(0)
        ));
    }
    let (tbs_content_len, tbs_len_bytes) =
        der_decode_length(&tbs_bytes[1..]).ok_or_else(|| "malformed TBS length".to_string())?;
    let tbs_content_start = 1 + tbs_len_bytes;
    if tbs_bytes.len() < tbs_content_start + tbs_content_len {
        return Err(format!(
            "TBS bytes too short for declared content length {tbs_content_len}"
        ));
    }
    let tbs_content_end = tbs_content_start + tbs_content_len;

    // Walk TBS children, collecting their raw bytes. Detect the
    // `[3] EXPLICIT Extensions` field (tag 0xA3) and rewrite its
    // content; pass everything else through.
    let mut new_inner = Vec::with_capacity(tbs_content_len);
    let mut found_extensions = false;
    let mut cursor = tbs_content_start;
    while cursor < tbs_content_end {
        let tag = tbs_bytes[cursor];
        let (child_len, len_bytes) = der_decode_length(&tbs_bytes[cursor + 1..])
            .ok_or_else(|| format!("malformed length at TBS offset {cursor}"))?;
        let header_size = 1 + len_bytes;
        let child_total = header_size + child_len;
        if cursor + child_total > tbs_content_end {
            return Err(format!(
                "TBS child at offset {cursor} overruns parent SEQUENCE"
            ));
        }
        let child_bytes = &tbs_bytes[cursor..cursor + child_total];

        if tag == 0xA3 {
            // [3] EXPLICIT Extensions. Recurse: filter out the SCT
            // extension, re-encode.
            found_extensions = true;
            let new_explicit = filter_extensions_remove_sct(child_bytes)?;
            new_inner.extend_from_slice(&new_explicit);
        } else {
            new_inner.extend_from_slice(child_bytes);
        }

        cursor += child_total;
    }
    if !found_extensions {
        return Err(
            "TBS has no `[3] EXPLICIT Extensions` field — cannot have an embedded SCT".into(),
        );
    }

    // Wrap new_inner in the TBS SEQUENCE.
    let mut out = Vec::with_capacity(1 + 9 + new_inner.len());
    out.push(0x30);
    out.extend_from_slice(&der_encode_length(new_inner.len()));
    out.extend_from_slice(&new_inner);
    Ok(out)
}

/// Given the raw bytes of a `[3] EXPLICIT Extensions` TLV (tag
/// `0xA3` followed by length + body), return new bytes representing
/// the same `[3] EXPLICIT` wrapper with the SCT extension removed
/// from the inner `SEQUENCE OF Extension`.
fn filter_extensions_remove_sct(explicit3_bytes: &[u8]) -> Result<Vec<u8>, String> {
    if explicit3_bytes.first() != Some(&0xA3) {
        return Err("expected [3] EXPLICIT tag 0xA3".into());
    }
    let (explicit_content_len, len_bytes) = der_decode_length(&explicit3_bytes[1..])
        .ok_or_else(|| "malformed [3] length".to_string())?;
    let inner_start = 1 + len_bytes;
    if explicit3_bytes.len() < inner_start + explicit_content_len {
        return Err("[3] EXPLICIT bytes overrun".into());
    }
    let inner = &explicit3_bytes[inner_start..inner_start + explicit_content_len];

    // Inner is the Extensions SEQUENCE OF Extension.
    if inner.first() != Some(&0x30) {
        return Err("[3] EXPLICIT content must be SEQUENCE OF Extension".into());
    }
    let (seq_content_len, seq_len_bytes) = der_decode_length(&inner[1..])
        .ok_or_else(|| "malformed Extensions seq length".to_string())?;
    let seq_content_start = 1 + seq_len_bytes;
    if inner.len() < seq_content_start + seq_content_len {
        return Err("Extensions SEQUENCE overrun".into());
    }
    let seq_content = &inner[seq_content_start..seq_content_start + seq_content_len];

    let mut new_seq_content = Vec::with_capacity(seq_content.len());
    let mut cursor = 0usize;
    while cursor < seq_content.len() {
        let ext_start = cursor;
        if seq_content[cursor] != 0x30 {
            return Err(format!(
                "Extensions entry at offset {cursor} is not SEQUENCE"
            ));
        }
        let (ext_len, ext_len_bytes) = der_decode_length(&seq_content[cursor + 1..])
            .ok_or_else(|| format!("malformed extension length at {cursor}"))?;
        let ext_total = 1 + ext_len_bytes + ext_len;
        if cursor + ext_total > seq_content.len() {
            return Err(format!("extension at {cursor} overruns"));
        }
        let ext_bytes = &seq_content[ext_start..ext_start + ext_total];
        if !extension_oid_matches_sct(ext_bytes)? {
            new_seq_content.extend_from_slice(ext_bytes);
        }
        cursor += ext_total;
    }

    // Re-wrap: new SEQUENCE OF Extension, then new [3] EXPLICIT.
    let mut new_seq = Vec::with_capacity(1 + 5 + new_seq_content.len());
    new_seq.push(0x30);
    new_seq.extend_from_slice(&der_encode_length(new_seq_content.len()));
    new_seq.extend_from_slice(&new_seq_content);

    let mut new_explicit = Vec::with_capacity(1 + 5 + new_seq.len());
    new_explicit.push(0xA3);
    new_explicit.extend_from_slice(&der_encode_length(new_seq.len()));
    new_explicit.extend_from_slice(&new_seq);
    Ok(new_explicit)
}

/// Check whether an X509Extension SEQUENCE's first child (the OID)
/// equals the SCT extension OID.
fn extension_oid_matches_sct(ext_bytes: &[u8]) -> Result<bool, String> {
    if ext_bytes.first() != Some(&0x30) {
        return Err("extension is not SEQUENCE".into());
    }
    let (_, len_bytes) = der_decode_length(&ext_bytes[1..])
        .ok_or_else(|| "malformed extension length".to_string())?;
    let content_start = 1 + len_bytes;
    if ext_bytes.len() < content_start + 2 {
        return Err("extension content too short".into());
    }
    // First child: OID (tag 0x06).
    if ext_bytes[content_start] != 0x06 {
        return Err(format!(
            "first child of extension is tag 0x{:02x} (expected OID 0x06)",
            ext_bytes[content_start]
        ));
    }
    let (oid_len, oid_len_bytes) = der_decode_length(&ext_bytes[content_start + 1..])
        .ok_or_else(|| "malformed OID length".to_string())?;
    let oid_start = content_start + 1 + oid_len_bytes;
    if ext_bytes.len() < oid_start + oid_len {
        return Err("OID overruns extension".into());
    }
    let oid_bytes = &ext_bytes[oid_start..oid_start + oid_len];

    // Pre-encoded SCT OID body for byte equality check.
    // OID 1.3.6.1.4.1.11129.2.4.2 encoded as DER content (without
    // tag/length): 0x2B 0x06 0x01 0x04 0x01 0xD6 0x79 0x02 0x04 0x02.
    const SCT_OID_BODY: &[u8] = &[0x2B, 0x06, 0x01, 0x04, 0x01, 0xD6, 0x79, 0x02, 0x04, 0x02];
    Ok(oid_bytes == SCT_OID_BODY)
}

/// Decode a DER length. Returns `(length, bytes_consumed)`.
///
/// Short form: single byte < 128.
/// Long form: high bit set, low 7 bits = number of subsequent bytes
/// holding the length (big-endian). `n=0` (indefinite length) is
/// rejected — DER (vs BER) forbids it.
fn der_decode_length(bytes: &[u8]) -> Option<(usize, usize)> {
    if bytes.is_empty() {
        return None;
    }
    let first = bytes[0];
    if first & 0x80 == 0 {
        return Some((first as usize, 1));
    }
    let n = (first & 0x7F) as usize;
    if n == 0 || n > 8 || bytes.len() < 1 + n {
        return None;
    }
    let mut len = 0usize;
    for &b in &bytes[1..1 + n] {
        len = (len << 8) | b as usize;
    }
    Some((len, 1 + n))
}

/// Encode a DER length in its canonical form (short for <128,
/// minimum-byte long form otherwise).
fn der_encode_length(len: usize) -> Vec<u8> {
    if len < 128 {
        return vec![len as u8];
    }
    let be = (len as u64).to_be_bytes();
    let leading_zeros = be.iter().take_while(|&&b| b == 0).count();
    let nonzero = &be[leading_zeros..];
    let mut out = Vec::with_capacity(1 + nonzero.len());
    out.push(0x80 | nonzero.len() as u8);
    out.extend_from_slice(nonzero);
    out
}

// ─────────────────────────────────────────────────────────────────────
// Phase 1.8 — composed `verify_sigstore_bundle` entry point.
// ─────────────────────────────────────────────────────────────────────
//
// Ties Phases 1.0–1.7 into a single callable. Phase 2.1 wires this
// into `provenance_fetch.rs`'s install gate; C2's self-update calls
// it with a different policy + identity expectations.
//
// Pipeline (each step's output is verified before the next runs):
//   1. parse bundle → components (DSSE envelope, leaf cert DER, chain
//      DER, tlog entry). Handles three wire shapes.
//   2. load + check vendored trust root (Phase 1.1; fails closed if
//      the artifact is structurally expired).
//   3. resolve `at_time` = the tlog entry's `integratedTime` parsed
//      via Phase 1.6's helper. Every downstream step's validity
//      window check uses THIS time, NOT wall-clock — so old bundles
//      still verify against retired Fulcio chains / CT log keys.
//   4. SET verify (Phase 1.6) — also doubles as the integrated-time
//      anchor source under `Either` policy when SET is absent (then
//      inclusion proof carries the offline claim).
//   5. chain validation (Phase 1.3) at `at_time`. Enforces the
//      BasicConstraints / KeyUsage / pathLenConstraint profile that
//      closed the security-review Vuln 1 bypass.
//   6. DSSE envelope verify (Phase 1.2) under the leaf cert's SPKI.
//   7. embedded SCT verify (Phase 1.4) against the pinned CT log
//      keys, using the chain-resolved issuer SPKI as the precert
//      input's `issuer_key_hash` source.
//   8. semantic Rekor body match (Phase 1.5): cert + payloadHash
//      hard-fail, envelope-hash advisory.
//   9. inclusion proof (Phase 1.7) — policy-conditional. Verified
//      whenever present (defense in depth); failure-on-absence
//      gated by `RekorInclusionProofPolicy`.
//   10. identity check against `IdentityExpectations` (optional;
//       `none()` for C1 npm-drift, populated for C2 self-update).

/// Verifier-time options. Currently carries the
/// [`RekorInclusionProofPolicy`] only; future knobs (clock skew,
/// optional offline-mode skip flags) will live here too without
/// breaking the public API.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy)]
pub struct VerifyOptions {
    pub rekor_inclusion_policy: RekorInclusionProofPolicy,
}

impl VerifyOptions {
    /// `RequireBoth` — the strongest assurance posture. Used by
    /// the C2 self-update path (binary swap is the highest-trust
    /// operation in LPM).
    #[allow(dead_code)]
    pub fn strict() -> Self {
        Self {
            rekor_inclusion_policy: RekorInclusionProofPolicy::RequireBoth,
        }
    }

    /// `Either` — accept SET-only OR inclusion-proof-only bundles.
    /// Used by the C1 npm-attestation path because npm cohorts ship
    /// either form in the wild.
    #[allow(dead_code)]
    pub fn npm_attestation() -> Self {
        Self {
            rekor_inclusion_policy: RekorInclusionProofPolicy::Either,
        }
    }
}

/// Optional caller-supplied pins for the leaf cert's identity.
/// `none()` skips identity checks entirely (C1 install-side drift
/// gate); a populated instance enforces the relevant pins (C2
/// self-update binds to `lpm-dev/rust-client/.github/workflows/
/// release.yml` issued under GitHub Actions OIDC).
#[allow(dead_code)]
#[derive(Debug, Clone, Default)]
pub struct IdentityExpectations {
    /// Expected OIDC issuer the Fulcio leaf was minted from, read
    /// from the Fulcio extension at OID `1.3.6.1.4.1.57264.1.1` (or
    /// the v2 OID `1.3.6.1.4.1.57264.1.8`, accepted symmetrically).
    /// Example: `https://token.actions.githubusercontent.com`.
    pub expected_issuer: Option<String>,
    /// Required prefix on the leaf cert's SAN URI. Example:
    /// `https://github.com/lpm-dev/rust-client/`. Off-by-one bug
    /// site (`rust-client` vs `rust-client/`) — always include the
    /// trailing `/` to anchor.
    pub expected_san_uri_prefix: Option<String>,
    /// Required workflow-path substring inside the SAN URI.
    /// Example: `.github/workflows/release.yml`. The full SAN URI
    /// shape is `<prefix><workflow_path>@<ref>` so substring match
    /// is structurally safe.
    pub expected_workflow_path: Option<String>,
}

impl IdentityExpectations {
    /// Skip all identity checks. C1's drift gate uses this — the
    /// drift comparator handles per-package identity tracking
    /// against `ProvenanceSnapshot` separately.
    #[allow(dead_code)]
    pub fn none() -> Self {
        Self::default()
    }

    fn is_empty(&self) -> bool {
        self.expected_issuer.is_none()
            && self.expected_san_uri_prefix.is_none()
            && self.expected_workflow_path.is_none()
    }
}

/// The structured result of a successful bundle verification.
/// `snapshot` carries the per-package identity for the drift gate;
/// the trail of `integrated_time`, `leaf_cert_sha256`, `log_id`,
/// `log_index` is the audit pin recorded into the on-disk
/// provenance cache (Phase 2.1's `CACHE_SCHEMA_VERSION = 2`).
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct VerifiedProvenance {
    pub snapshot: lpm_workspace::ProvenanceSnapshot,
    pub integrated_time: SystemTime,
    pub leaf_cert_sha256: String,
    pub log_id: String,
    pub log_index: i64,
}

/// Verify a Sigstore bundle end-to-end.
///
/// Returns `Ok(VerifiedProvenance)` only when every primitive
/// (DSSE, chain, SCT, Rekor body, SET, inclusion proof) accepts
/// AND the caller-supplied identity expectations match. Any single
/// failure short-circuits with the most-specific `VerifyError`
/// variant so the caller can surface diagnostics without a generic
/// "verification failed" rollup.
#[allow(dead_code)] // wired into provenance_fetch in Phase 2.1
pub fn verify_sigstore_bundle(
    body: &[u8],
    expectations: &IdentityExpectations,
    options: VerifyOptions,
) -> Result<VerifiedProvenance, VerifyError> {
    let components = parse_bundle_components(body)?;
    let trust = trust_root()?;

    let at_time = parse_integrated_time(&components.tlog_entry.integrated_time)?;

    // SET first — its successful run also doubles as a sanity check
    // that the trust root carries an active Rekor key for the log
    // this bundle references. Under `Either` policy with SET absent,
    // this is a no-op and returns the parsed integratedTime.
    verify_rekor_set(
        &components.tlog_entry,
        &trust.rekor_keys,
        options.rekor_inclusion_policy,
    )?;

    // Chain validation at the resolved `at_time`. Trust anchors are
    // pre-filtered to those active at the same time so a retired
    // root doesn't accidentally anchor a fresh bundle.
    let active_fulcio: Vec<&FulcioRoot> = trust.fulcio_roots_at(at_time);
    let chain_refs: Vec<&[u8]> = components.chain_der.iter().map(|d| d.as_slice()).collect();
    verify_cert_chain(&chain_refs, &active_fulcio, at_time)?;

    // Parse the leaf cert once for downstream consumers (DSSE,
    // identity, issuer SPKI lookup). The lifetime is tied to
    // `components.leaf_cert_der`.
    let (_, leaf_parsed) = X509Certificate::from_der(&components.leaf_cert_der).map_err(|e| {
        VerifyError::BundleParse(format!("leaf cert DER did not re-parse for DSSE: {e}"))
    })?;

    verify_dsse(&components.dsse_envelope, &leaf_parsed)?;

    // SCT verify — need the immediate issuer's SPKI for the precert
    // signed-input. Search the bundle's chain first (chain[1..]),
    // fall back to the active trust anchors. Chain validation has
    // already cleared the path, so a match is guaranteed.
    let issuer_spki_der =
        find_leaf_issuer_spki(&leaf_parsed, &components.chain_der, &trust, at_time)?;
    verify_embedded_sct(
        &components.leaf_cert_der,
        &issuer_spki_der,
        &trust.ctlog_keys,
        at_time,
    )?;

    verify_rekor_body(
        &components.tlog_entry,
        &components.dsse_envelope,
        &components.leaf_cert_der,
    )?;

    // Inclusion proof — policy-conditional. Verify whenever present
    // (defense in depth); failure-on-absence per policy.
    let has_inclusion_proof = components.tlog_entry.resolved_inclusion_proof().is_some();
    match options.rekor_inclusion_policy {
        RekorInclusionProofPolicy::RequireInclusionProof
        | RekorInclusionProofPolicy::RequireBoth => {
            verify_inclusion_proof(&components.tlog_entry, &trust.rekor_keys)?;
        }
        RekorInclusionProofPolicy::Either | RekorInclusionProofPolicy::RequireSet => {
            if has_inclusion_proof {
                verify_inclusion_proof(&components.tlog_entry, &trust.rekor_keys)?;
            }
        }
    }

    // `Either` requires SET OR inclusion proof. SET was already
    // checked above (no-op on absence under `Either`); if neither
    // is present, reject here.
    if options.rekor_inclusion_policy == RekorInclusionProofPolicy::Either
        && components.tlog_entry.resolved_inclusion_promise().is_none()
        && !has_inclusion_proof
    {
        return Err(VerifyError::RekorSetMissing);
    }

    if !expectations.is_empty() {
        check_identity_expectations(&leaf_parsed, expectations)?;
    }

    let leaf_cert_sha256 = format!(
        "sha256-{}",
        hex::encode(Sha256::digest(&components.leaf_cert_der))
    );
    let log_index = components.tlog_entry.log_index.parse::<i64>().unwrap_or(-1);
    let snapshot = build_provenance_snapshot(&leaf_parsed, &leaf_cert_sha256);

    Ok(VerifiedProvenance {
        snapshot,
        integrated_time: at_time,
        leaf_cert_sha256,
        log_id: components.tlog_entry.log_id.key_id.clone(),
        log_index,
    })
}

/// Parsed bundle components, with the heavy DER + DSSE work done
/// once up front so downstream verifiers receive typed inputs.
#[derive(Debug)]
struct BundleComponents {
    dsse_envelope: DsseEnvelope,
    leaf_cert_der: Vec<u8>,
    chain_der: Vec<Vec<u8>>,
    tlog_entry: crate::sigstore::TlogEntry,
}

/// Parse a Sigstore bundle body into [`BundleComponents`]. Handles
/// the three wire shapes the production fetch path already deals
/// with (mirrors [`crate::provenance_fetch::find_leaf_cert_rawbytes`]
/// for cert extraction):
///
/// 1. **Sigstore Bundle v0.2** — chain at
///    `verificationMaterial.x509CertificateChain.certificates[]`.
/// 2. **Sigstore Bundle v0.3** — single leaf at
///    `verificationMaterial.certificate.rawBytes` (chain length 1;
///    the verifier walks the leaf directly against trust anchors).
/// 3. **npm attestations wrapper** —
///    `{ attestations: [{ bundle: <inner> }] }`. npm ships two
///    attestations per package: a publicKey-only publish-time
///    attestation (skip) and a Fulcio-issued provenance
///    attestation (use).
fn parse_bundle_components(body: &[u8]) -> Result<BundleComponents, VerifyError> {
    let root: serde_json::Value = serde_json::from_slice(body)
        .map_err(|e| VerifyError::BundleParse(format!("bundle is not valid JSON: {e}")))?;

    // npm wrapper case: scan attestations[*].bundle for the first
    // parseable inner bundle.
    if let Some(attestations) = root.get("attestations").and_then(|v| v.as_array()) {
        let mut last_err = None;
        for att in attestations {
            if let Some(inner) = att.get("bundle") {
                match parse_inner_bundle(inner) {
                    Ok(c) => return Ok(c),
                    Err(e) => last_err = Some(e),
                }
            }
        }
        return Err(last_err.unwrap_or_else(|| {
            VerifyError::BundleParse(
                "npm attestations array contained no parseable inner bundle".into(),
            )
        }));
    }

    parse_inner_bundle(&root)
}

fn parse_inner_bundle(bundle: &serde_json::Value) -> Result<BundleComponents, VerifyError> {
    let verification_material = bundle
        .get("verificationMaterial")
        .ok_or_else(|| VerifyError::BundleParse("bundle missing `verificationMaterial`".into()))?;

    // Cert chain — v0.3 single-cert OR v0.2 chain.
    let chain_der: Vec<Vec<u8>> = if let Some(cert) = verification_material.get("certificate") {
        let raw = cert
            .get("rawBytes")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                VerifyError::BundleParse("v0.3 `certificate` field has no `rawBytes` string".into())
            })?;
        let der = BASE64
            .decode(raw.as_bytes())
            .map_err(|e| VerifyError::BundleParse(format!("leaf cert rawBytes not base64: {e}")))?;
        vec![der]
    } else if let Some(chain) = verification_material.get("x509CertificateChain") {
        let certs = chain
            .get("certificates")
            .and_then(|v| v.as_array())
            .ok_or_else(|| {
                VerifyError::BundleParse(
                    "v0.2 `x509CertificateChain.certificates` is not an array".into(),
                )
            })?;
        if certs.is_empty() {
            return Err(VerifyError::BundleParse(
                "v0.2 cert chain is empty (must have at least the leaf)".into(),
            ));
        }
        certs
            .iter()
            .enumerate()
            .map(|(i, c)| {
                let raw = c.get("rawBytes").and_then(|v| v.as_str()).ok_or_else(|| {
                    VerifyError::BundleParse(format!(
                        "v0.2 chain cert[{i}] has no `rawBytes` string"
                    ))
                })?;
                BASE64.decode(raw.as_bytes()).map_err(|e| {
                    VerifyError::BundleParse(format!("chain cert[{i}] not base64: {e}"))
                })
            })
            .collect::<Result<Vec<_>, _>>()?
    } else {
        return Err(VerifyError::BundleParse(
            "bundle has neither v0.3 `certificate` nor v0.2 `x509CertificateChain`".into(),
        ));
    };

    let leaf_cert_der = chain_der
        .first()
        .cloned()
        .ok_or_else(|| VerifyError::BundleParse("cert chain has no leaf".into()))?;

    // DSSE envelope — required.
    let dsse_value = bundle
        .get("dsseEnvelope")
        .ok_or_else(|| VerifyError::BundleParse("bundle missing `dsseEnvelope`".into()))?;
    let dsse_envelope: DsseEnvelope = serde_json::from_value(dsse_value.clone())
        .map_err(|e| VerifyError::BundleParse(format!("dsseEnvelope shape: {e}")))?;

    // Tlog entry — take the first. Sigstore bundles ship one
    // `tlogEntries[0]` for the canonical Rekor entry.
    let tlog_entries = verification_material
        .get("tlogEntries")
        .and_then(|v| v.as_array())
        .ok_or_else(|| {
            VerifyError::BundleParse(
                "bundle `verificationMaterial.tlogEntries` is not an array".into(),
            )
        })?;
    let tlog_value = tlog_entries.first().ok_or_else(|| {
        VerifyError::BundleParse("bundle `verificationMaterial.tlogEntries` is empty".into())
    })?;
    let tlog_entry: crate::sigstore::TlogEntry = serde_json::from_value(tlog_value.clone())
        .map_err(|e| VerifyError::BundleParse(format!("tlogEntries[0] shape: {e}")))?;

    Ok(BundleComponents {
        dsse_envelope,
        leaf_cert_der,
        chain_der,
        tlog_entry,
    })
}

/// Find the SPKI DER of the leaf cert's immediate issuer. Tries:
/// 1. Bundle's chain[1..] (the typical case when the bundle ships
///    leaf + intermediate).
/// 2. Active Fulcio trust anchors (when the bundle ships only the
///    leaf and the chain walker traversed the path implicitly).
///
/// Chain validation has already cleared the path, so a match is
/// guaranteed in any valid bundle.
fn find_leaf_issuer_spki(
    leaf: &X509Certificate<'_>,
    chain_der: &[Vec<u8>],
    trust: &TrustRoot,
    at_time: SystemTime,
) -> Result<Vec<u8>, VerifyError> {
    let leaf_issuer_dn = leaf.tbs_certificate.issuer.as_raw();
    for der in chain_der.iter().skip(1) {
        if let Ok((_, parsed)) = X509Certificate::from_der(der)
            && parsed.tbs_certificate.subject.as_raw() == leaf_issuer_dn
        {
            return Ok(parsed.tbs_certificate.subject_pki.raw.to_vec());
        }
    }
    for root in trust.fulcio_roots_at(at_time) {
        for der in &root.cert_chain_der {
            if let Ok((_, parsed)) = X509Certificate::from_der(der)
                && parsed.tbs_certificate.subject.as_raw() == leaf_issuer_dn
            {
                return Ok(parsed.tbs_certificate.subject_pki.raw.to_vec());
            }
        }
    }
    Err(VerifyError::Sct(
        "could not locate leaf cert's immediate issuer in the bundle chain or trust root \
         — cannot compute SCT precert input"
            .into(),
    ))
}

/// Fulcio OIDC issuer extension OIDs (RFC-style, dotted-decimal):
/// - `1.3.6.1.4.1.57264.1.1` — original (v1).
/// - `1.3.6.1.4.1.57264.1.8` — v2 (same semantic). Accept either.
const FULCIO_OIDC_ISSUER_OID_V1: [u64; 9] = [1, 3, 6, 1, 4, 1, 57264, 1, 1];
const FULCIO_OIDC_ISSUER_OID_V2: [u64; 9] = [1, 3, 6, 1, 4, 1, 57264, 1, 8];

/// Apply `IdentityExpectations` against the leaf cert. Pre-conditioned
/// by `expectations.is_empty()` at the call site — when populated,
/// every Some field must match or this returns
/// `VerifyError::IdentityMismatch`.
fn check_identity_expectations(
    leaf: &X509Certificate<'_>,
    expectations: &IdentityExpectations,
) -> Result<(), VerifyError> {
    if let Some(expected) = &expectations.expected_issuer {
        let actual =
            extract_fulcio_oidc_issuer(leaf)?.ok_or_else(|| VerifyError::IdentityMismatch {
                field: "issuer",
                expected: expected.clone(),
                actual: "<no Fulcio OIDC issuer extension>".into(),
            })?;
        if &actual != expected {
            return Err(VerifyError::IdentityMismatch {
                field: "issuer",
                expected: expected.clone(),
                actual,
            });
        }
    }

    if expectations.expected_san_uri_prefix.is_some()
        || expectations.expected_workflow_path.is_some()
    {
        let san_uri = extract_leaf_san_uri(leaf).ok_or_else(|| VerifyError::IdentityMismatch {
            field: "san_uri",
            expected: expectations
                .expected_san_uri_prefix
                .clone()
                .or_else(|| expectations.expected_workflow_path.clone())
                .unwrap_or_default(),
            actual: "<no SAN URI on leaf cert>".into(),
        })?;
        if let Some(prefix) = &expectations.expected_san_uri_prefix
            && !san_uri.starts_with(prefix)
        {
            return Err(VerifyError::IdentityMismatch {
                field: "san_uri_prefix",
                expected: prefix.clone(),
                actual: san_uri,
            });
        }
        if let Some(workflow) = &expectations.expected_workflow_path
            && !san_uri.contains(workflow)
        {
            return Err(VerifyError::IdentityMismatch {
                field: "workflow_path",
                expected: workflow.clone(),
                actual: san_uri,
            });
        }
    }

    Ok(())
}

/// Extract the OIDC issuer string from the Fulcio extension at
/// `1.3.6.1.4.1.57264.1.1` (v1) or `.1.8` (v2). The extension's
/// value is a plain UTF-8 string (NOT a DER OCTET STRING in v1; v2
/// uses a DER UTF8String wrapper). We try plain UTF-8 first and
/// fall back to DER-UTF8String parsing for v2.
fn extract_fulcio_oidc_issuer(leaf: &X509Certificate<'_>) -> Result<Option<String>, VerifyError> {
    for ext in leaf.extensions() {
        let components: Vec<u64> = match ext.oid.iter() {
            Some(it) => it.collect(),
            None => continue,
        };
        let is_v1 = components.as_slice() == FULCIO_OIDC_ISSUER_OID_V1;
        let is_v2 = components.as_slice() == FULCIO_OIDC_ISSUER_OID_V2;
        if !is_v1 && !is_v2 {
            continue;
        }
        // v1: raw UTF-8 bytes. v2: DER UTF8String (tag 0x0C + length + content).
        if is_v2 && ext.value.len() >= 2 && ext.value[0] == 0x0C {
            let (len, consumed) = der_decode_length(&ext.value[1..]).ok_or_else(|| {
                VerifyError::BundleParse(
                    "Fulcio OIDC issuer v2 extension has malformed UTF8String length".into(),
                )
            })?;
            let start = 1 + consumed;
            if ext.value.len() < start + len {
                return Err(VerifyError::BundleParse(
                    "Fulcio OIDC issuer v2 UTF8String body truncated".into(),
                ));
            }
            return Ok(Some(
                std::str::from_utf8(&ext.value[start..start + len])
                    .map_err(|e| {
                        VerifyError::BundleParse(format!(
                            "Fulcio OIDC issuer v2 body is not valid UTF-8: {e}"
                        ))
                    })?
                    .to_string(),
            ));
        }
        // v1 plain bytes (or v2 unwrapped fallback).
        return Ok(Some(
            std::str::from_utf8(ext.value)
                .map_err(|e| {
                    VerifyError::BundleParse(format!(
                        "Fulcio OIDC issuer extension body is not valid UTF-8: {e}"
                    ))
                })?
                .to_string(),
        ));
    }
    Ok(None)
}

/// Extract the first URI-shaped SAN from the leaf cert. Sigstore
/// Fulcio leaves carry one URI SAN with the GitHub Actions (or
/// other OIDC-provider) workflow identity.
fn extract_leaf_san_uri(leaf: &X509Certificate<'_>) -> Option<String> {
    use x509_parser::extensions::{GeneralName, ParsedExtension};
    for ext in leaf.extensions() {
        if let ParsedExtension::SubjectAlternativeName(san) = ext.parsed_extension() {
            for name in &san.general_names {
                if let GeneralName::URI(uri) = name {
                    return Some((*uri).to_string());
                }
            }
        }
    }
    None
}

/// Build the `ProvenanceSnapshot` consumed by the drift gate
/// (`lpm_security::provenance::check_provenance_drift`). Reuses
/// the leaf-cert SAN parsing already in `provenance_fetch`; this
/// helper exists so the snapshot construction has the same shape
/// regardless of which code path produced the leaf cert.
fn build_provenance_snapshot(
    leaf: &X509Certificate<'_>,
    leaf_cert_sha256: &str,
) -> lpm_workspace::ProvenanceSnapshot {
    let san_uri = extract_leaf_san_uri(leaf);
    let identity = san_uri.as_deref().and_then(parse_github_actions_identity);
    lpm_workspace::ProvenanceSnapshot {
        present: true,
        publisher: identity.as_ref().map(|(p, _, _)| p.clone()),
        workflow_path: identity.as_ref().map(|(_, w, _)| w.clone()),
        workflow_ref: identity.as_ref().map(|(_, _, r)| r.clone()),
        attestation_cert_sha256: Some(leaf_cert_sha256.to_string()),
    }
}

/// Parse a GitHub Actions SAN URI into `(publisher, workflow_path,
/// workflow_ref)`. Mirrors `provenance_fetch::parse_github_actions_uri`
/// — kept inline in the verifier so the orchestrator doesn't reach
/// out into the install-path module; the duplication is small (10
/// lines) and the two stay in sync via the workflow tests that
/// pin the JSON envelope shape.
fn parse_github_actions_identity(uri: &str) -> Option<(String, String, String)> {
    const PREFIX: &str = "https://github.com/";
    const WORKFLOWS_SEG: &str = "/.github/workflows/";
    let after_host = uri.strip_prefix(PREFIX)?;
    let (path, workflow_ref) = after_host.rsplit_once('@')?;
    let (org_repo, wf_tail) = path.split_once(WORKFLOWS_SEG)?;
    let (org, repo) = org_repo.split_once('/')?;
    if org.is_empty() || repo.is_empty() || repo.contains('/') {
        return None;
    }
    Some((
        format!("github:{org}/{repo}"),
        format!(".github/workflows/{wf_tail}"),
        workflow_ref.to_string(),
    ))
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

    // ── verify_rekor_set — Phase 1.6 ──────────────────────────────

    use ecdsa::signature::hazmat::PrehashSigner;
    use p256::pkcs8::EncodePublicKey;

    /// Helper: produce a fresh P-256 ECDSA keypair plus the SPKI
    /// DER bytes and the sha256(SPKI) "logId" the trust-root layer
    /// would carry. Centralised so every SET test starts from the
    /// same shape.
    fn p256_rekor_signing_key() -> (SigningKey, Vec<u8>, Vec<u8>) {
        let signing_key = SigningKey::random(&mut rand::thread_rng());
        let verifying_key = VerifyingKey::from(&signing_key);
        let spki_der = verifying_key
            .to_public_key_der()
            .unwrap()
            .as_bytes()
            .to_vec();
        let log_id_bytes = Sha256::digest(&spki_der).to_vec();
        (signing_key, spki_der, log_id_bytes)
    }

    /// Build a TlogEntry whose SET is a real ECDSA signature over
    /// the canonical SET input, signed by `signing_key`.
    /// `integrated_time_secs` is the unix timestamp the entry
    /// declares; the test verifier returns it as the at_time anchor.
    fn synth_tlog_entry_with_set(
        signing_key: &SigningKey,
        log_id_hex: &str,
        log_index: i64,
        integrated_time_secs: i64,
        canonicalized_body: &str,
    ) -> crate::sigstore::TlogEntry {
        let set_input = build_set_input_canonical_json(
            canonicalized_body,
            integrated_time_secs,
            log_index,
            log_id_hex,
        );
        let digest = Sha256::digest(set_input.as_bytes());
        let sig: Signature = signing_key.sign_prehash(&digest).expect("sign_prehash");
        let signed_entry_timestamp = BASE64.encode(sig.to_der().as_bytes());

        crate::sigstore::TlogEntry {
            log_index: log_index.to_string(),
            log_id: crate::sigstore::LogId {
                key_id: log_id_hex.to_string(),
            },
            integrated_time: integrated_time_secs.to_string(),
            inclusion_promise: Some(crate::sigstore::RekorInclusionPromise {
                signed_entry_timestamp,
            }),
            inclusion_proof: None,
            verification: None,
            canonicalized_body: canonicalized_body.to_string(),
        }
    }

    fn rekor_key_active_around(log_id: Vec<u8>, spki_der: Vec<u8>, around_secs: i64) -> RekorKey {
        let start = DateTime::<Utc>::from_timestamp(around_secs - 365 * 86400, 0).unwrap();
        let end = DateTime::<Utc>::from_timestamp(around_secs + 365 * 86400, 0).unwrap();
        RekorKey {
            log_id,
            spki_der,
            valid_for: ValidityWindow {
                start,
                end: Some(end),
            },
        }
    }

    #[test]
    fn build_set_input_canonical_json_matches_documented_layout() {
        // Canonicalization pin: the exact byte string the verifier
        // produces for a fixed input must match what's documented
        // in private/rekor-set-canonicalization.md. A failure here is
        // the canary that catches key-reorder, whitespace, or casing
        // regressions before they break actual SET verification.
        let s = build_set_input_canonical_json("Zm9vYmFy", 1700000000, 42, "wNI9atQGlz");
        let expected =
            r#"{"body":"Zm9vYmFy","integratedTime":1700000000,"logID":"wNI9atQGlz","logIndex":42}"#;
        assert_eq!(
            s, expected,
            "SET canonical-JSON layout drift — see private/rekor-set-canonicalization.md"
        );
    }

    #[test]
    fn verifies_valid_rekor_set_returns_parsed_integrated_time() {
        let (signing_key, spki_der, log_id_bytes) = p256_rekor_signing_key();
        let log_id_hex = hex::encode(&log_id_bytes);
        let integrated_time = 1700000000_i64;

        let tlog = synth_tlog_entry_with_set(
            &signing_key,
            &log_id_hex,
            42,
            integrated_time,
            "Zm9vYmFy", // arbitrary base64 — content doesn't affect the SET sig
        );
        let key = rekor_key_active_around(log_id_bytes, spki_der, integrated_time);

        let returned_time = verify_rekor_set(
            &tlog,
            std::slice::from_ref(&key),
            RekorInclusionProofPolicy::RequireSet,
        )
        .expect("a valid SET must verify under the pinned key");
        let expected =
            SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(integrated_time as u64);
        assert_eq!(
            returned_time, expected,
            "verify_rekor_set must return the parsed integratedTime as the at_time anchor"
        );
    }

    #[test]
    fn rejects_bundle_with_forged_rekor_set() {
        let (signing_key, spki_der, log_id_bytes) = p256_rekor_signing_key();
        let log_id_hex = hex::encode(&log_id_bytes);
        let mut tlog =
            synth_tlog_entry_with_set(&signing_key, &log_id_hex, 42, 1700000000, "Zm9vYmFy");

        // Flip one byte in the signature payload so DER still parses
        // (signatures are 70-72 bytes; mangling the middle of the
        // R/S integers keeps DER valid but the curve math fails).
        let mut sig_bytes = BASE64
            .decode(
                tlog.inclusion_promise
                    .as_ref()
                    .unwrap()
                    .signed_entry_timestamp
                    .as_bytes(),
            )
            .unwrap();
        // The DER encoding starts 0x30 LEN 0x02 LEN R... — flip a
        // byte well inside R to keep the structure parseable.
        let target = sig_bytes.len() / 2;
        sig_bytes[target] ^= 0x01;
        tlog.inclusion_promise
            .as_mut()
            .unwrap()
            .signed_entry_timestamp = BASE64.encode(sig_bytes);

        let key = rekor_key_active_around(log_id_bytes, spki_der, 1700000000);
        let err = verify_rekor_set(
            &tlog,
            std::slice::from_ref(&key),
            RekorInclusionProofPolicy::RequireSet,
        )
        .expect_err("tampered SET signature must fail verification");
        match err {
            VerifyError::RekorSet(msg) => assert!(
                msg.contains("did not verify") || msg.contains("not valid DER"),
                "expected signature-verify or DER-parse diagnostic, got: {msg}"
            ),
            other => panic!("expected VerifyError::RekorSet, got: {other:?}"),
        }
    }

    #[test]
    fn rejects_bundle_with_unknown_rekor_log_id() {
        // Bundle declares a logId that doesn't match the pinned key.
        // Even though the signature would mathematically verify
        // (we sign with the right key), the canonical SET input
        // embeds the bundle's logId — different logId → different
        // SET input → no key matches and we error before getting
        // to ECDSA verify.
        let (signing_key, spki_der, log_id_bytes) = p256_rekor_signing_key();
        let unknown_log_id_hex = hex::encode([0xff_u8; 32]);
        let tlog = synth_tlog_entry_with_set(
            &signing_key,
            &unknown_log_id_hex,
            42,
            1700000000,
            "Zm9vYmFy",
        );
        let key = rekor_key_active_around(log_id_bytes, spki_der, 1700000000);
        let err = verify_rekor_set(
            &tlog,
            std::slice::from_ref(&key),
            RekorInclusionProofPolicy::RequireSet,
        )
        .expect_err("unknown logId must reject");
        match err {
            VerifyError::RekorSet(msg) => assert!(
                msg.contains("no pinned Rekor key"),
                "expected unknown-logId diagnostic, got: {msg}"
            ),
            other => panic!("expected VerifyError::RekorSet, got: {other:?}"),
        }
    }

    #[test]
    fn rejects_bundle_with_rekor_key_outside_validity_at_integrated_time() {
        // The pinned key's validity window doesn't contain the
        // entry's integratedTime — even with matching logId, lookup
        // returns None.
        let (signing_key, spki_der, log_id_bytes) = p256_rekor_signing_key();
        let log_id_hex = hex::encode(&log_id_bytes);
        let tlog = synth_tlog_entry_with_set(&signing_key, &log_id_hex, 42, 1700000000, "Zm9vYmFy");
        // Key valid 2010-2015 only; integratedTime is 2023.
        let key = RekorKey {
            log_id: log_id_bytes,
            spki_der,
            valid_for: ValidityWindow {
                start: DateTime::parse_from_rfc3339("2010-01-01T00:00:00Z")
                    .unwrap()
                    .with_timezone(&Utc),
                end: Some(
                    DateTime::parse_from_rfc3339("2015-01-01T00:00:00Z")
                        .unwrap()
                        .with_timezone(&Utc),
                ),
            },
        };
        let err = verify_rekor_set(
            &tlog,
            std::slice::from_ref(&key),
            RekorInclusionProofPolicy::RequireSet,
        )
        .expect_err("out-of-window key must reject");
        let msg = match err {
            VerifyError::RekorSet(msg) => msg,
            other => panic!("expected VerifyError::RekorSet, got: {other:?}"),
        };
        assert!(
            msg.contains("no pinned Rekor key"),
            "expected unknown-key diagnostic, got: {msg}"
        );
    }

    #[test]
    fn rejects_missing_set_under_require_set_policy() {
        // Synth a TlogEntry with no inclusion_promise / no verification
        // envelope. Under RequireSet, expect RekorSetMissing.
        let tlog = crate::sigstore::TlogEntry {
            log_index: "0".into(),
            log_id: crate::sigstore::LogId {
                key_id: String::new(),
            },
            integrated_time: "1700000000".into(),
            inclusion_promise: None,
            inclusion_proof: None,
            verification: None,
            canonicalized_body: String::new(),
        };
        let err = verify_rekor_set(&tlog, &[], RekorInclusionProofPolicy::RequireSet)
            .expect_err("missing SET under RequireSet must reject");
        assert!(matches!(err, VerifyError::RekorSetMissing));
    }

    #[test]
    fn rejects_missing_set_under_require_both_policy() {
        // RequireBoth also requires SET. Same diagnostic.
        let tlog = crate::sigstore::TlogEntry {
            log_index: "0".into(),
            log_id: crate::sigstore::LogId {
                key_id: String::new(),
            },
            integrated_time: "1700000000".into(),
            inclusion_promise: None,
            inclusion_proof: None,
            verification: None,
            canonicalized_body: String::new(),
        };
        let err = verify_rekor_set(&tlog, &[], RekorInclusionProofPolicy::RequireBoth)
            .expect_err("missing SET under RequireBoth must reject");
        assert!(matches!(err, VerifyError::RekorSetMissing));
    }

    #[test]
    fn accepts_missing_set_under_either_policy_and_returns_integrated_time() {
        // Under Either, absent SET is acceptable as long as inclusion
        // proof carries the offline anchor. verify_rekor_set itself
        // returns Ok(integrated_time) without verifying anything — the
        // caller (Phase 1.8) is responsible for ensuring the inclusion
        // proof path runs in this case.
        let tlog = crate::sigstore::TlogEntry {
            log_index: "0".into(),
            log_id: crate::sigstore::LogId {
                key_id: String::new(),
            },
            integrated_time: "1700000000".into(),
            inclusion_promise: None,
            inclusion_proof: None,
            verification: None,
            canonicalized_body: String::new(),
        };
        let t = verify_rekor_set(&tlog, &[], RekorInclusionProofPolicy::Either)
            .expect("missing SET under Either must NOT reject (inclusion proof is the alt anchor)");
        let expected = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1700000000);
        assert_eq!(
            t, expected,
            "Either + missing SET still returns the parsed integratedTime as the at_time anchor"
        );
    }

    #[test]
    fn accepts_missing_set_under_require_inclusion_proof_policy() {
        // RequireInclusionProof doesn't need SET; verify_rekor_set
        // should not reject on absence.
        let tlog = crate::sigstore::TlogEntry {
            log_index: "0".into(),
            log_id: crate::sigstore::LogId {
                key_id: String::new(),
            },
            integrated_time: "1700000000".into(),
            inclusion_promise: None,
            inclusion_proof: None,
            verification: None,
            canonicalized_body: String::new(),
        };
        verify_rekor_set(&tlog, &[], RekorInclusionProofPolicy::RequireInclusionProof)
            .expect("missing SET under RequireInclusionProof must NOT reject");
    }

    #[test]
    fn either_policy_rejects_bundle_with_neither_set_nor_inclusion_proof() {
        // The composed verify_sigstore_bundle entry point enforces
        // "Either ⇒ at least one of SET, IP". That rule depends on the
        // resolved_inclusion_promise() and resolved_inclusion_proof()
        // helpers both surfacing None for an empty tlog entry. Pin
        // those helpers here so a refactor that accidentally widens
        // either accessor (e.g., synthesizes a default value) breaks
        // a named test before the composed entry's branch silently
        // accepts a bundle that should reject.
        let tlog = crate::sigstore::TlogEntry {
            log_index: "0".into(),
            log_id: crate::sigstore::LogId {
                key_id: String::new(),
            },
            integrated_time: "1700000000".into(),
            inclusion_promise: None,
            inclusion_proof: None,
            verification: None,
            canonicalized_body: String::new(),
        };
        assert!(
            tlog.resolved_inclusion_promise().is_none(),
            "empty tlog entry must surface None for resolved_inclusion_promise",
        );
        assert!(
            tlog.resolved_inclusion_proof().is_none(),
            "empty tlog entry must surface None for resolved_inclusion_proof",
        );
        verify_rekor_set(&tlog, &[], RekorInclusionProofPolicy::Either).expect(
            "Either with neither must NOT reject in verify_rekor_set (composed entry enforces)",
        );
        let err = verify_inclusion_proof(&tlog, &[])
            .expect_err("verify_inclusion_proof must always reject when proof is absent");
        assert!(matches!(err, VerifyError::InclusionProofMissing));
    }

    #[test]
    fn either_policy_accepts_inclusion_proof_only_bundle_via_primitive_seam() {
        // Either + SET-absent + IP-present is one of the two
        // accept arms of `Either`. verify_rekor_set is the load-
        // bearing seam: it must NOT reject when the SET is absent
        // and the policy is Either, regardless of whether the bundle
        // carries an inclusion proof — that's the composed entry's
        // job (it calls verify_inclusion_proof separately). Pin the
        // primitive contract here.
        let tlog = crate::sigstore::TlogEntry {
            log_index: "1".into(),
            log_id: crate::sigstore::LogId {
                key_id: String::new(),
            },
            integrated_time: "1700000000".into(),
            inclusion_promise: None, // SET absent
            inclusion_proof: Some(crate::sigstore::RekorInclusionProof {
                checkpoint: serde_json::json!({}),
                hashes: vec![],
                log_index: 1,
                root_hash: String::new(),
                tree_size: 2,
            }),
            verification: None,
            canonicalized_body: String::new(),
        };
        verify_rekor_set(&tlog, &[], RekorInclusionProofPolicy::Either)
            .expect("Either + SET-absent + IP-present must NOT reject at verify_rekor_set");
    }

    #[test]
    fn either_policy_accepts_set_only_bundle_via_primitive_seam() {
        // Either + SET-present + IP-absent is the symmetric accept
        // arm. verify_rekor_set verifies the SET as usual; the
        // composed entry then SKIPs the inclusion-proof step because
        // IP is absent under Either.
        let (signing_key, spki_der, log_id_bytes) = p256_rekor_signing_key();
        let log_id_hex = hex::encode(&log_id_bytes);
        let integrated_time = 1700000000_i64;
        let canonicalized_body = "Zm9v";
        let set_input =
            build_set_input_canonical_json(canonicalized_body, integrated_time, 7, &log_id_hex);
        let digest = Sha256::digest(set_input.as_bytes());
        let sig: Signature = signing_key.sign_prehash(&digest).expect("sign_prehash");
        let set_b64 = BASE64.encode(sig.to_der().as_bytes());

        let tlog = crate::sigstore::TlogEntry {
            log_index: "7".into(),
            log_id: crate::sigstore::LogId { key_id: log_id_hex },
            integrated_time: integrated_time.to_string(),
            inclusion_promise: Some(crate::sigstore::RekorInclusionPromise {
                signed_entry_timestamp: set_b64,
            }),
            inclusion_proof: None, // IP absent under Either
            verification: None,
            canonicalized_body: canonicalized_body.to_string(),
        };
        let key = rekor_key_active_around(log_id_bytes, spki_der, integrated_time);
        verify_rekor_set(
            &tlog,
            std::slice::from_ref(&key),
            RekorInclusionProofPolicy::Either,
        )
        .expect("Either + SET-present + IP-absent must verify the SET successfully");
        assert!(
            tlog.resolved_inclusion_proof().is_none(),
            "this bundle has IP absent — the composed entry would skip verify_inclusion_proof",
        );
    }

    #[test]
    fn require_both_policy_rejects_when_inclusion_proof_is_absent() {
        // RequireBoth + SET-present + IP-absent must reject at the
        // inclusion-proof primitive — the composed entry invokes
        // verify_inclusion_proof for RequireBoth and gets
        // InclusionProofMissing. Symmetric to the existing
        // rejects_missing_set_under_require_both_policy.
        let tlog = crate::sigstore::TlogEntry {
            log_index: "0".into(),
            log_id: crate::sigstore::LogId {
                key_id: String::new(),
            },
            integrated_time: "1700000000".into(),
            // SET present, but IP absent (real-world: an npm bundle
            // that ships SET only — fine under Either, refused under
            // RequireBoth).
            inclusion_promise: Some(crate::sigstore::RekorInclusionPromise {
                signed_entry_timestamp: String::new(),
            }),
            inclusion_proof: None,
            verification: None,
            canonicalized_body: String::new(),
        };
        let err = verify_inclusion_proof(&tlog, &[])
            .expect_err("RequireBoth + IP-absent must reject at verify_inclusion_proof");
        assert!(matches!(err, VerifyError::InclusionProofMissing));
    }

    #[test]
    fn require_inclusion_proof_policy_rejects_when_inclusion_proof_is_absent() {
        // RequireInclusionProof + IP-absent is the same rejection
        // arm as RequireBoth + IP-absent at the primitive level.
        // Names the policy explicitly so the contract is pinned per
        // call site (C2's strict() preset uses RequireBoth; a future
        // policy that wants IP-without-SET would pick this).
        let tlog = crate::sigstore::TlogEntry {
            log_index: "0".into(),
            log_id: crate::sigstore::LogId {
                key_id: String::new(),
            },
            integrated_time: "1700000000".into(),
            inclusion_promise: None,
            inclusion_proof: None,
            verification: None,
            canonicalized_body: String::new(),
        };
        let err = verify_inclusion_proof(&tlog, &[])
            .expect_err("RequireInclusionProof + IP-absent must reject at verify_inclusion_proof");
        assert!(matches!(err, VerifyError::InclusionProofMissing));
    }

    #[test]
    fn rfc3161_timestamp_only_bundle_rejects_because_no_embedded_sct_is_present() {
        // Sigstore Bundle v0.3 allows `timestampVerificationData.rfc3161Timestamps[]`
        // as an alternative-to-SCT "certificate was valid at signing time"
        // claim. The current verifier (Phase 1.4) is embedded-SCT-only —
        // the RFC 3161 path is documented as a tracked follow-up and
        // rejects fail-closed.
        //
        // Pin the behavior at the primitive seam: a leaf cert without
        // the SCT extension rejects with `VerifyError::Sct`, regardless
        // of what timestampVerificationData the *bundle* might carry
        // alongside. The verifier intentionally never looks at that
        // field — a future implementer who wires it must add a
        // dedicated test for the positive path.
        let issuer = fresh_sct_issuer();
        let leaf_kp = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let leaf_der = build_leaf_with_optional_sct(&leaf_kp, &issuer, None);
        let issuer_spki = issuer_spki_from_cert(&issuer.cert);
        let (_, ct_log_key) = synth_ct_log_key(2025);
        let err = verify_embedded_sct(
            &leaf_der,
            &issuer_spki,
            std::slice::from_ref(&ct_log_key),
            ts_year(2025),
        )
        .expect_err("RFC-3161-only bundle (no embedded SCT) must reject");
        match err {
            VerifyError::Sct(msg) => assert!(
                msg.contains("no embedded SCT"),
                "RFC-3161-only fallback is intentionally not honored; got: {msg}",
            ),
            other => panic!(
                "RFC-3161-only fallback must reject with VerifyError::Sct (embedded-only policy); \
                 got: {other:?}",
            ),
        }
    }

    #[test]
    fn verifies_set_via_legacy_verification_envelope_fallback() {
        // A bundle that captured Rekor's API response verbatim under
        // `verification.inclusionPromise` (the Phase 1.0 schema's
        // fallback path) must still verify — `resolved_inclusion_promise`
        // walks through.
        let (signing_key, spki_der, log_id_bytes) = p256_rekor_signing_key();
        let log_id_hex = hex::encode(&log_id_bytes);
        let integrated_time = 1700000000_i64;
        let canonicalized_body = "Zm9vYmFy";

        let set_input =
            build_set_input_canonical_json(canonicalized_body, integrated_time, 42, &log_id_hex);
        let digest = Sha256::digest(set_input.as_bytes());
        let sig: Signature = signing_key.sign_prehash(&digest).expect("sign_prehash");
        let set_b64 = BASE64.encode(sig.to_der().as_bytes());

        let tlog = crate::sigstore::TlogEntry {
            log_index: "42".into(),
            log_id: crate::sigstore::LogId { key_id: log_id_hex },
            integrated_time: integrated_time.to_string(),
            inclusion_promise: None, // top-level absent
            inclusion_proof: None,
            verification: Some(crate::sigstore::RekorVerification {
                inclusion_promise: Some(crate::sigstore::RekorInclusionPromise {
                    signed_entry_timestamp: set_b64,
                }),
                inclusion_proof: None,
            }),
            canonicalized_body: canonicalized_body.to_string(),
        };
        let key = rekor_key_active_around(log_id_bytes, spki_der, integrated_time);
        verify_rekor_set(
            &tlog,
            std::slice::from_ref(&key),
            RekorInclusionProofPolicy::RequireSet,
        )
        .expect("legacy-shape SET (nested under `verification`) must verify");
    }

    #[test]
    fn rejects_set_with_malformed_integrated_time_string() {
        let tlog = crate::sigstore::TlogEntry {
            log_index: "0".into(),
            log_id: crate::sigstore::LogId {
                key_id: String::new(),
            },
            integrated_time: "not-a-number".into(),
            inclusion_promise: None,
            inclusion_proof: None,
            verification: None,
            canonicalized_body: String::new(),
        };
        let err = verify_rekor_set(&tlog, &[], RekorInclusionProofPolicy::RequireSet)
            .expect_err("malformed integratedTime must reject");
        match err {
            VerifyError::RekorSet(msg) => assert!(msg.contains("integratedTime"), "got: {msg}"),
            other => panic!("expected VerifyError::RekorSet, got: {other:?}"),
        }
    }

    // ── verify_inclusion_proof — Phase 1.7 ────────────────────────

    /// 4-leaf Merkle tree fixture. Returns
    /// `(leaf_hashes[4], internal_hashes[h01, h23], root, leaf_data[4])`
    /// so individual tests can construct inclusion proofs without
    /// recomputing the tree.
    #[allow(clippy::type_complexity)]
    fn four_leaf_tree() -> (
        [Vec<u8>; 4],
        (Vec<u8>, Vec<u8>),
        Vec<u8>,
        [&'static [u8]; 4],
    ) {
        let leaves: [&[u8]; 4] = [b"leaf-a", b"leaf-b", b"leaf-c", b"leaf-d"];
        let h0 = rfc6962_leaf_hash(leaves[0]);
        let h1 = rfc6962_leaf_hash(leaves[1]);
        let h2 = rfc6962_leaf_hash(leaves[2]);
        let h3 = rfc6962_leaf_hash(leaves[3]);
        let h01 = rfc6962_hash_children(&h0, &h1);
        let h23 = rfc6962_hash_children(&h2, &h3);
        let root = rfc6962_hash_children(&h01, &h23);
        ([h0, h1, h2, h3], (h01, h23), root, leaves)
    }

    #[test]
    fn rfc6962_inclusion_walk_matches_documented_algorithm_for_leaf_0_in_4leaf_tree() {
        // Pin the algorithm against a hand-derivable test vector
        // (see private/rekor-checkpoint-format.md). For leaf 0 in a
        // 4-leaf tree, the inclusion proof is [h(b), h(cd)].
        let ([h0, h1, _h2, _h3], (_h01, h23), root, _) = four_leaf_tree();
        let proof = vec![h1, h23];
        let computed = rfc6962_verify_inclusion(0, 4, &h0, &proof)
            .expect("known-good inclusion proof must walk to the root");
        assert_eq!(
            computed, root,
            "RFC 6962 walker drifted — see private/rekor-checkpoint-format.md"
        );
    }

    #[test]
    fn rfc6962_inclusion_walk_matches_documented_algorithm_for_leaf_2_in_4leaf_tree() {
        // For leaf 2 in a 4-leaf tree, proof is [h(d), h(ab)].
        // Exercises the right-child branch + the "walk up while
        // fn is odd" combination.
        let ([_h0, _h1, h2, h3], (h01, _h23), root, _) = four_leaf_tree();
        let proof = vec![h3, h01];
        let computed = rfc6962_verify_inclusion(2, 4, &h2, &proof).unwrap();
        assert_eq!(computed, root);
    }

    #[test]
    fn rfc6962_inclusion_walk_matches_documented_algorithm_for_leaf_3_in_4leaf_tree() {
        // Leaf 3: proof is [h(c), h(ab)]. Last-leaf in this subtree
        // exercises the `fn == sn` branch.
        let ([_h0, _h1, h2, h3], (h01, _h23), root, _) = four_leaf_tree();
        let proof = vec![h2, h01];
        let computed = rfc6962_verify_inclusion(3, 4, &h3, &proof).unwrap();
        assert_eq!(computed, root);
    }

    #[test]
    fn rfc6962_inclusion_walk_rejects_proof_with_flipped_sibling() {
        let ([h0, h1, _h2, _h3], (_h01, h23), root, _) = four_leaf_tree();
        // Flip one byte in the first sibling — walked root mismatches.
        let mut tampered = h1.clone();
        tampered[0] ^= 0x01;
        let proof = vec![tampered, h23];
        let computed = rfc6962_verify_inclusion(0, 4, &h0, &proof).unwrap();
        assert_ne!(
            computed, root,
            "tampered sibling must produce a different walked root"
        );
    }

    #[test]
    fn rfc6962_inclusion_walk_single_leaf_tree_returns_leaf_hash() {
        let leaf_data = b"only-leaf";
        let leaf_hash = rfc6962_leaf_hash(leaf_data);
        let computed = rfc6962_verify_inclusion(0, 1, &leaf_hash, &[]).unwrap();
        assert_eq!(
            computed, leaf_hash,
            "single-leaf tree's root IS the leaf hash"
        );
    }

    #[test]
    fn rfc6962_inclusion_walk_rejects_leaf_index_out_of_range() {
        let leaf_hash = rfc6962_leaf_hash(b"l");
        let err = rfc6962_verify_inclusion(5, 4, &leaf_hash, &[])
            .expect_err("leaf_index >= tree_size is structurally impossible");
        match err {
            VerifyError::InclusionProof(msg) => assert!(msg.contains("leaf_index")),
            other => panic!("expected InclusionProof, got: {other:?}"),
        }
    }

    /// Build a C2SP signed-note checkpoint envelope signed by
    /// `signing_key` over `(origin, tree_size, root_hash_bytes)`.
    /// The signature line uses the origin's first whitespace-delimited
    /// token as the signer name — matches Rekor's actual format
    /// (origin "rekor.sigstore.dev - 12345" → sig name "rekor.sigstore.dev").
    fn build_signed_checkpoint(
        signing_key: &SigningKey,
        origin: &str,
        tree_size: i64,
        root_hash: &[u8],
    ) -> String {
        let body = format!("{origin}\n{tree_size}\n{}\n", BASE64.encode(root_hash));
        let digest = Sha256::digest(body.as_bytes());
        let sig: Signature = signing_key.sign_prehash(&digest).expect("sign_prehash");
        // 4-byte key-hint prefix (informational; we don't verify it).
        let mut key_hint_plus_sig = vec![0u8; 4];
        key_hint_plus_sig.extend_from_slice(sig.to_der().as_bytes());
        let sig_b64 = BASE64.encode(&key_hint_plus_sig);
        let sig_name = origin.split_whitespace().next().unwrap_or(origin);
        format!("{body}\n\u{2014} {sig_name} {sig_b64}\n")
    }

    #[allow(clippy::too_many_arguments)]
    fn synth_tlog_entry_with_inclusion_proof(
        log_id_hex: &str,
        log_index: i64,
        integrated_time_secs: i64,
        canonicalized_body_b64: &str,
        checkpoint_envelope: String,
        sibling_hashes_hex: Vec<String>,
        root_hash_hex: &str,
        tree_size: i64,
    ) -> crate::sigstore::TlogEntry {
        crate::sigstore::TlogEntry {
            log_index: log_index.to_string(),
            log_id: crate::sigstore::LogId {
                key_id: log_id_hex.to_string(),
            },
            integrated_time: integrated_time_secs.to_string(),
            inclusion_promise: None,
            inclusion_proof: Some(crate::sigstore::RekorInclusionProof {
                checkpoint: serde_json::Value::String(checkpoint_envelope),
                hashes: sibling_hashes_hex,
                log_index,
                root_hash: root_hash_hex.to_string(),
                tree_size,
            }),
            verification: None,
            canonicalized_body: canonicalized_body_b64.to_string(),
        }
    }

    #[test]
    fn verifies_valid_inclusion_proof_for_4leaf_tree_leaf_0() {
        let (signing_key, spki_der, log_id_bytes) = p256_rekor_signing_key();
        let log_id_hex = hex::encode(&log_id_bytes);
        let integrated_time = 1700000000_i64;
        let ([_h0, h1, _h2, _h3], (_h01, h23), root, leaves) = four_leaf_tree();
        let body_b64 = BASE64.encode(leaves[0]);

        let checkpoint = build_signed_checkpoint(&signing_key, "rekor.sigstore.dev - 1", 4, &root);
        let tlog = synth_tlog_entry_with_inclusion_proof(
            &log_id_hex,
            0,
            integrated_time,
            &body_b64,
            checkpoint,
            vec![hex::encode(&h1), hex::encode(&h23)],
            &hex::encode(&root),
            4,
        );
        let key = rekor_key_active_around(log_id_bytes, spki_der, integrated_time);
        verify_inclusion_proof(&tlog, std::slice::from_ref(&key))
            .expect("LPM-canonical inclusion proof for leaf 0 must verify");
    }

    #[test]
    fn rejects_inclusion_proof_with_tampered_leaf_body() {
        // Bundle's canonicalized_body doesn't match the leaf hash
        // the proof was built for — Merkle walk reaches a different
        // root than the signed one.
        let (signing_key, spki_der, log_id_bytes) = p256_rekor_signing_key();
        let log_id_hex = hex::encode(&log_id_bytes);
        let integrated_time = 1700000000_i64;
        let ([_h0, h1, _h2, _h3], (_h01, h23), root, _leaves) = four_leaf_tree();
        let checkpoint = build_signed_checkpoint(&signing_key, "rekor.sigstore.dev - 1", 4, &root);
        let tlog = synth_tlog_entry_with_inclusion_proof(
            &log_id_hex,
            0,
            integrated_time,
            &BASE64.encode(b"NOT-the-leaf-we-proved"),
            checkpoint,
            vec![hex::encode(&h1), hex::encode(&h23)],
            &hex::encode(&root),
            4,
        );
        let key = rekor_key_active_around(log_id_bytes, spki_der, integrated_time);
        let err = verify_inclusion_proof(&tlog, std::slice::from_ref(&key))
            .expect_err("tampered leaf body must produce a Merkle root mismatch");
        match err {
            VerifyError::InclusionProof(msg) => assert!(
                msg.contains("does not match signed checkpoint root"),
                "expected Merkle root mismatch diagnostic, got: {msg}"
            ),
            other => panic!("expected InclusionProof, got: {other:?}"),
        }
    }

    #[test]
    fn rejects_inclusion_proof_with_forged_checkpoint_signature() {
        let (_signing_key_real, spki_der, log_id_bytes) = p256_rekor_signing_key();
        let log_id_hex = hex::encode(&log_id_bytes);
        let integrated_time = 1700000000_i64;
        let ([_h0, h1, _h2, _h3], (_h01, h23), root, leaves) = four_leaf_tree();
        // Sign with a DIFFERENT key than the pinned one.
        let (signing_key_forge, _, _) = p256_rekor_signing_key();
        let checkpoint =
            build_signed_checkpoint(&signing_key_forge, "rekor.sigstore.dev - 1", 4, &root);
        let tlog = synth_tlog_entry_with_inclusion_proof(
            &log_id_hex,
            0,
            integrated_time,
            &BASE64.encode(leaves[0]),
            checkpoint,
            vec![hex::encode(&h1), hex::encode(&h23)],
            &hex::encode(&root),
            4,
        );
        let key = rekor_key_active_around(log_id_bytes, spki_der, integrated_time);
        let err = verify_inclusion_proof(&tlog, std::slice::from_ref(&key))
            .expect_err("checkpoint signed by a different key must fail");
        match err {
            VerifyError::InclusionProof(msg) => assert!(
                msg.contains("signature did not verify"),
                "expected checkpoint-sig diagnostic, got: {msg}"
            ),
            other => panic!("expected InclusionProof, got: {other:?}"),
        }
    }

    #[test]
    fn rejects_inclusion_proof_with_tree_size_mismatch() {
        let (signing_key, spki_der, log_id_bytes) = p256_rekor_signing_key();
        let log_id_hex = hex::encode(&log_id_bytes);
        let integrated_time = 1700000000_i64;
        let ([_h0, h1, _h2, _h3], (_h01, h23), root, leaves) = four_leaf_tree();
        // Checkpoint commits to tree_size=4, bundle says tree_size=8.
        let checkpoint = build_signed_checkpoint(&signing_key, "rekor.sigstore.dev - 1", 4, &root);
        let tlog = synth_tlog_entry_with_inclusion_proof(
            &log_id_hex,
            0,
            integrated_time,
            &BASE64.encode(leaves[0]),
            checkpoint,
            vec![hex::encode(&h1), hex::encode(&h23)],
            &hex::encode(&root),
            8, // disagrees with the signed checkpoint's 4
        );
        let key = rekor_key_active_around(log_id_bytes, spki_der, integrated_time);
        let err = verify_inclusion_proof(&tlog, std::slice::from_ref(&key))
            .expect_err("tree_size disagreement must reject before Merkle walk");
        match err {
            VerifyError::InclusionProof(msg) => assert!(
                msg.contains("tree_size"),
                "expected tree_size diagnostic, got: {msg}"
            ),
            other => panic!("expected InclusionProof, got: {other:?}"),
        }
    }

    #[test]
    fn rejects_inclusion_proof_with_root_hash_mismatch_with_checkpoint() {
        let (signing_key, spki_der, log_id_bytes) = p256_rekor_signing_key();
        let log_id_hex = hex::encode(&log_id_bytes);
        let integrated_time = 1700000000_i64;
        let ([_h0, h1, _h2, _h3], (_h01, h23), root, leaves) = four_leaf_tree();
        // Bundle declares a different root than the checkpoint signs.
        let checkpoint = build_signed_checkpoint(&signing_key, "rekor.sigstore.dev - 1", 4, &root);
        let bogus_root = vec![0xab_u8; 32];
        let tlog = synth_tlog_entry_with_inclusion_proof(
            &log_id_hex,
            0,
            integrated_time,
            &BASE64.encode(leaves[0]),
            checkpoint,
            vec![hex::encode(&h1), hex::encode(&h23)],
            &hex::encode(&bogus_root),
            4,
        );
        let key = rekor_key_active_around(log_id_bytes, spki_der, integrated_time);
        let err = verify_inclusion_proof(&tlog, std::slice::from_ref(&key))
            .expect_err("root_hash disagreement must reject");
        match err {
            VerifyError::InclusionProof(msg) => assert!(
                msg.contains("root_hash"),
                "expected root_hash diagnostic, got: {msg}"
            ),
            other => panic!("expected InclusionProof, got: {other:?}"),
        }
    }

    #[test]
    fn rejects_inclusion_proof_with_log_index_at_or_past_tree_size() {
        let (signing_key, spki_der, log_id_bytes) = p256_rekor_signing_key();
        let log_id_hex = hex::encode(&log_id_bytes);
        let integrated_time = 1700000000_i64;
        let ([_h0, h1, _h2, _h3], (_h01, h23), root, leaves) = four_leaf_tree();
        let checkpoint = build_signed_checkpoint(&signing_key, "rekor.sigstore.dev - 1", 4, &root);
        let tlog = synth_tlog_entry_with_inclusion_proof(
            &log_id_hex,
            4, // log_index == tree_size; structurally impossible
            integrated_time,
            &BASE64.encode(leaves[0]),
            checkpoint,
            vec![hex::encode(&h1), hex::encode(&h23)],
            &hex::encode(&root),
            4,
        );
        let key = rekor_key_active_around(log_id_bytes, spki_der, integrated_time);
        let err = verify_inclusion_proof(&tlog, std::slice::from_ref(&key))
            .expect_err("log_index >= tree_size must reject as structurally impossible");
        match err {
            VerifyError::InclusionProof(msg) => assert!(
                msg.contains("log_index"),
                "expected log_index diagnostic, got: {msg}"
            ),
            other => panic!("expected InclusionProof, got: {other:?}"),
        }
    }

    #[test]
    fn rejects_missing_inclusion_proof_with_inclusion_proof_missing_variant() {
        let tlog = crate::sigstore::TlogEntry {
            log_index: "0".into(),
            log_id: crate::sigstore::LogId {
                key_id: String::new(),
            },
            integrated_time: "1700000000".into(),
            inclusion_promise: None,
            inclusion_proof: None,
            verification: None,
            canonicalized_body: String::new(),
        };
        let err = verify_inclusion_proof(&tlog, &[])
            .expect_err("missing inclusion proof must surface the dedicated missing variant");
        assert!(matches!(err, VerifyError::InclusionProofMissing));
    }

    #[test]
    fn verifies_inclusion_proof_when_checkpoint_is_object_with_envelope_field() {
        // Sigstore Bundle v0.3 spec shape: checkpoint is an object
        // `{ "envelope": "..." }` rather than a bare string. Verifier
        // accepts both via extract_checkpoint_envelope; pin that path.
        let (signing_key, spki_der, log_id_bytes) = p256_rekor_signing_key();
        let log_id_hex = hex::encode(&log_id_bytes);
        let integrated_time = 1700000000_i64;
        let ([_h0, h1, _h2, _h3], (_h01, h23), root, leaves) = four_leaf_tree();
        let envelope = build_signed_checkpoint(&signing_key, "rekor.sigstore.dev - 1", 4, &root);

        let mut tlog = crate::sigstore::TlogEntry {
            log_index: "0".into(),
            log_id: crate::sigstore::LogId { key_id: log_id_hex },
            integrated_time: integrated_time.to_string(),
            inclusion_promise: None,
            inclusion_proof: Some(crate::sigstore::RekorInclusionProof {
                checkpoint: serde_json::json!({"envelope": envelope}),
                hashes: vec![hex::encode(&h1), hex::encode(&h23)],
                log_index: 0,
                root_hash: hex::encode(&root),
                tree_size: 4,
            }),
            verification: None,
            canonicalized_body: BASE64.encode(leaves[0]),
        };
        let key = rekor_key_active_around(log_id_bytes, spki_der, integrated_time);
        verify_inclusion_proof(&tlog, std::slice::from_ref(&key))
            .expect("Bundle v0.3 object-shape checkpoint must verify");

        // Belt-and-suspenders: malformed checkpoint object → rejection.
        tlog.inclusion_proof.as_mut().unwrap().checkpoint =
            serde_json::json!({"not-envelope": "oops"});
        let err = verify_inclusion_proof(&tlog, std::slice::from_ref(&key))
            .expect_err("object-shape without `envelope` string must reject");
        match err {
            VerifyError::InclusionProof(msg) => assert!(
                msg.contains("envelope"),
                "expected envelope-shape diagnostic, got: {msg}"
            ),
            other => panic!("expected InclusionProof, got: {other:?}"),
        }
    }

    #[test]
    fn verifies_inclusion_proof_via_legacy_verification_envelope_fallback() {
        // A bundle whose inclusion proof was captured from Rekor's
        // API response (nested under `verification.inclusionProof`)
        // must still verify via resolved_inclusion_proof()'s
        // fallback chain.
        let (signing_key, spki_der, log_id_bytes) = p256_rekor_signing_key();
        let log_id_hex = hex::encode(&log_id_bytes);
        let integrated_time = 1700000000_i64;
        let ([_h0, h1, _h2, _h3], (_h01, h23), root, leaves) = four_leaf_tree();
        let envelope = build_signed_checkpoint(&signing_key, "rekor.sigstore.dev - 1", 4, &root);
        let proof = crate::sigstore::RekorInclusionProof {
            checkpoint: serde_json::Value::String(envelope),
            hashes: vec![hex::encode(&h1), hex::encode(&h23)],
            log_index: 0,
            root_hash: hex::encode(&root),
            tree_size: 4,
        };
        let tlog = crate::sigstore::TlogEntry {
            log_index: "0".into(),
            log_id: crate::sigstore::LogId { key_id: log_id_hex },
            integrated_time: integrated_time.to_string(),
            inclusion_promise: None,
            inclusion_proof: None, // top-level absent
            verification: Some(crate::sigstore::RekorVerification {
                inclusion_promise: None,
                inclusion_proof: Some(proof),
            }),
            canonicalized_body: BASE64.encode(leaves[0]),
        };
        let key = rekor_key_active_around(log_id_bytes, spki_der, integrated_time);
        verify_inclusion_proof(&tlog, std::slice::from_ref(&key))
            .expect("legacy-nested inclusion proof must verify via fallback");
    }

    #[test]
    fn rejects_inclusion_proof_with_malformed_checkpoint_envelope() {
        let (_signing_key, spki_der, log_id_bytes) = p256_rekor_signing_key();
        let log_id_hex = hex::encode(&log_id_bytes);
        let integrated_time = 1700000000_i64;
        let ([_h0, h1, _h2, _h3], (_h01, h23), root, leaves) = four_leaf_tree();
        // Checkpoint has no empty-line separator — malformed.
        let tlog = synth_tlog_entry_with_inclusion_proof(
            &log_id_hex,
            0,
            integrated_time,
            &BASE64.encode(leaves[0]),
            "no separator anywhere".to_string(),
            vec![hex::encode(&h1), hex::encode(&h23)],
            &hex::encode(&root),
            4,
        );
        let key = rekor_key_active_around(log_id_bytes, spki_der, integrated_time);
        let err = verify_inclusion_proof(&tlog, std::slice::from_ref(&key))
            .expect_err("malformed checkpoint envelope must reject");
        match err {
            VerifyError::InclusionProof(msg) => assert!(
                msg.contains("separator") || msg.contains("envelope"),
                "expected envelope-parse diagnostic, got: {msg}"
            ),
            other => panic!("expected InclusionProof, got: {other:?}"),
        }
    }

    #[test]
    fn rejects_inclusion_proof_with_wrong_pinned_rekor_key_for_log_id() {
        let (signing_key, _spki_der, log_id_bytes) = p256_rekor_signing_key();
        let log_id_hex = hex::encode(&log_id_bytes);
        let integrated_time = 1700000000_i64;
        let ([_h0, h1, _h2, _h3], (_h01, h23), root, leaves) = four_leaf_tree();
        let checkpoint = build_signed_checkpoint(&signing_key, "rekor.sigstore.dev - 1", 4, &root);
        let tlog = synth_tlog_entry_with_inclusion_proof(
            &log_id_hex,
            0,
            integrated_time,
            &BASE64.encode(leaves[0]),
            checkpoint,
            vec![hex::encode(&h1), hex::encode(&h23)],
            &hex::encode(&root),
            4,
        );
        // Pin a DIFFERENT key (different log_id_bytes), so the lookup
        // by log_id fails → no pinned key for the entry's logID.
        let (_, other_spki, other_log_id) = p256_rekor_signing_key();
        let other_key = rekor_key_active_around(other_log_id, other_spki, integrated_time);
        let err = verify_inclusion_proof(&tlog, std::slice::from_ref(&other_key))
            .expect_err("logId without a pinned key must reject");
        match err {
            VerifyError::InclusionProof(msg) => assert!(
                msg.contains("no pinned Rekor key"),
                "expected unknown-logId diagnostic, got: {msg}"
            ),
            other => panic!("expected InclusionProof, got: {other:?}"),
        }
    }

    // ── verify_cert_chain — Phase 1.3 ─────────────────────────────

    /// Build a (rcgen::Certificate, DER bytes, KeyPair) triple for a
    /// P-384 self-signed root — matches the real Sigstore Fulcio root
    /// profile.
    fn p384_root_cert(
        not_before: rcgen::CertificateParams,
    ) -> (rcgen::Certificate, Vec<u8>, KeyPair) {
        let kp = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
        let mut params = not_before;
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let cert = params.self_signed(&kp).unwrap();
        let der = cert.der().to_vec();
        (cert, der, kp)
    }

    /// Build a P-256 leaf cert signed by the given P-384 issuer —
    /// matches the real Sigstore leaf-under-Fulcio profile. Returns
    /// the leaf cert's DER bytes.
    fn p256_leaf_signed_by(
        leaf_params: rcgen::CertificateParams,
        issuer_cert: &rcgen::Certificate,
        issuer_kp: &KeyPair,
    ) -> Vec<u8> {
        let leaf_kp = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let leaf = leaf_params
            .signed_by(&leaf_kp, issuer_cert, issuer_kp)
            .unwrap();
        leaf.der().to_vec()
    }

    /// Convenience: synthesise a Fulcio-like validity window
    /// centered on `mid_year`.
    fn cert_params_validity(mid_year: i32) -> rcgen::CertificateParams {
        let mut p = rcgen::CertificateParams::default();
        p.not_before = rcgen::date_time_ymd(mid_year - 5, 1, 1);
        p.not_after = rcgen::date_time_ymd(mid_year + 5, 1, 1);
        p
    }

    fn ts_year(year: i32) -> SystemTime {
        DateTime::from_timestamp(
            chrono::NaiveDate::from_ymd_opt(year, 6, 1)
                .unwrap()
                .and_hms_opt(0, 0, 0)
                .unwrap()
                .and_utc()
                .timestamp(),
            0,
        )
        .unwrap()
        .into()
    }

    fn fulcio_root_active_at(year: i32, root_der: Vec<u8>) -> FulcioRoot {
        FulcioRoot {
            cert_chain_der: vec![root_der],
            valid_for: ValidityWindow {
                start: DateTime::from_timestamp(
                    chrono::NaiveDate::from_ymd_opt(year - 10, 1, 1)
                        .unwrap()
                        .and_hms_opt(0, 0, 0)
                        .unwrap()
                        .and_utc()
                        .timestamp(),
                    0,
                )
                .unwrap(),
                end: Some(
                    DateTime::from_timestamp(
                        chrono::NaiveDate::from_ymd_opt(year + 10, 1, 1)
                            .unwrap()
                            .and_hms_opt(0, 0, 0)
                            .unwrap()
                            .and_utc()
                            .timestamp(),
                        0,
                    )
                    .unwrap(),
                ),
            },
        }
    }

    #[test]
    fn verifies_two_cert_chain_terminating_at_trusted_root() {
        // Real Sigstore shape: bundle ships [leaf, root]. Trust
        // anchor matches the top cert byte-for-byte → fast path
        // through anchor_contains_der.
        let (root_cert, root_der, root_kp) = p384_root_cert(cert_params_validity(2025));
        let leaf_der = p256_leaf_signed_by(cert_params_validity(2025), &root_cert, &root_kp);
        let root = fulcio_root_active_at(2025, root_der.clone());
        let chain: Vec<&[u8]> = vec![&leaf_der, &root_der];
        let roots: Vec<&FulcioRoot> = vec![&root];
        verify_cert_chain(&chain, &roots, ts_year(2025))
            .expect("a leaf signed by a trusted root must verify");
    }

    #[test]
    fn verifies_leaf_only_chain_when_root_in_trust_anchors_signs_directly() {
        // Bundle ships [leaf] only (no root). Trust anchor IS the
        // direct signer → try_anchor_signature path.
        let (root_cert, root_der, root_kp) = p384_root_cert(cert_params_validity(2025));
        let leaf_der = p256_leaf_signed_by(cert_params_validity(2025), &root_cert, &root_kp);
        let root = fulcio_root_active_at(2025, root_der);
        let chain: Vec<&[u8]> = vec![&leaf_der];
        let roots: Vec<&FulcioRoot> = vec![&root];
        verify_cert_chain(&chain, &roots, ts_year(2025))
            .expect("leaf-only chain must verify when root signs directly");
    }

    #[test]
    fn rejects_chain_when_top_cert_not_signed_by_any_trusted_root() {
        // Bundle's root is real but the trust anchors are a
        // different unrelated set.
        let (real_root_cert, real_root_der, real_root_kp) =
            p384_root_cert(cert_params_validity(2025));
        let leaf_der =
            p256_leaf_signed_by(cert_params_validity(2025), &real_root_cert, &real_root_kp);
        let (_, other_root_der, _) = p384_root_cert(cert_params_validity(2025));
        let other = fulcio_root_active_at(2025, other_root_der);
        let chain: Vec<&[u8]> = vec![&leaf_der, &real_root_der];
        let roots: Vec<&FulcioRoot> = vec![&other];
        let err = verify_cert_chain(&chain, &roots, ts_year(2025))
            .expect_err("chain to an untrusted root must reject");
        match err {
            VerifyError::Chain(msg) => assert!(
                msg.contains("does not match any trusted Fulcio root"),
                "expected anchor-rejection diagnostic, got: {msg}"
            ),
            other => panic!("expected Chain, got: {other:?}"),
        }
    }

    #[test]
    fn rejects_chain_with_leaf_out_of_validity_at_integrated_time() {
        // Leaf valid 2020-2025; integratedTime is 2027.
        let (root_cert, root_der, root_kp) = p384_root_cert(cert_params_validity(2025));
        let mut leaf_params = rcgen::CertificateParams::default();
        leaf_params.not_before = rcgen::date_time_ymd(2020, 1, 1);
        leaf_params.not_after = rcgen::date_time_ymd(2025, 1, 1);
        let leaf_der = p256_leaf_signed_by(leaf_params, &root_cert, &root_kp);
        let root = fulcio_root_active_at(2025, root_der.clone());
        let chain: Vec<&[u8]> = vec![&leaf_der, &root_der];
        let roots: Vec<&FulcioRoot> = vec![&root];
        let err = verify_cert_chain(&chain, &roots, ts_year(2027))
            .expect_err("integratedTime past leaf's notAfter must reject");
        match err {
            VerifyError::Chain(msg) => assert!(
                msg.contains("does not contain integratedTime"),
                "expected validity-window diagnostic, got: {msg}"
            ),
            other => panic!("expected Chain, got: {other:?}"),
        }
    }

    #[test]
    fn rejects_chain_with_leaf_signed_by_wrong_parent() {
        // Build two unrelated chains. Splice chain-A's leaf into
        // a bundle claiming chain-B's root is its parent.
        let (root_a_cert, _root_a_der, root_a_kp) = p384_root_cert(cert_params_validity(2025));
        let leaf_a_der = p256_leaf_signed_by(cert_params_validity(2025), &root_a_cert, &root_a_kp);
        let (_, root_b_der, _) = p384_root_cert(cert_params_validity(2025));
        let root_b = fulcio_root_active_at(2025, root_b_der.clone());
        let chain: Vec<&[u8]> = vec![&leaf_a_der, &root_b_der];
        let roots: Vec<&FulcioRoot> = vec![&root_b];
        let err = verify_cert_chain(&chain, &roots, ts_year(2025))
            .expect_err("leaf signed by a different root than declared must reject");
        // The diagnostic could be either "issuer DN does not equal"
        // (subject mismatch) or "ECDSA P-384 signature did not verify"
        // (sig mismatch under a coincidentally-matching DN). Both
        // are Chain failures.
        match err {
            VerifyError::Chain(msg) => assert!(
                msg.contains("issuer DN") || msg.contains("did not verify"),
                "expected chain-link rejection diagnostic, got: {msg}"
            ),
            other => panic!("expected Chain, got: {other:?}"),
        }
    }

    #[test]
    fn rejects_empty_chain() {
        let root = fulcio_root_active_at(2025, vec![0u8; 4]);
        let err = verify_cert_chain(&[], std::slice::from_ref(&&root), ts_year(2025))
            .expect_err("empty chain must reject");
        match err {
            VerifyError::Chain(msg) => assert!(msg.contains("empty"), "got: {msg}"),
            other => panic!("expected Chain, got: {other:?}"),
        }
    }

    #[test]
    fn rejects_chain_when_no_trust_anchors_active_at_integrated_time() {
        let (root_cert, root_der, root_kp) = p384_root_cert(cert_params_validity(2025));
        let leaf_der = p256_leaf_signed_by(cert_params_validity(2025), &root_cert, &root_kp);
        let chain: Vec<&[u8]> = vec![&leaf_der, &root_der];
        // Empty roots list → no anchor.
        let err = verify_cert_chain(&chain, &[], ts_year(2025))
            .expect_err("empty trust-anchor set must reject");
        match err {
            VerifyError::Chain(msg) => {
                assert!(msg.contains("no Fulcio roots active"), "got: {msg}")
            }
            other => panic!("expected Chain, got: {other:?}"),
        }
    }

    #[test]
    fn rejects_chain_with_malformed_der_in_bundle() {
        let root = fulcio_root_active_at(2025, vec![0xab; 16]);
        let garbage: &[u8] = &[0xff; 8];
        let chain: Vec<&[u8]> = vec![garbage];
        let roots: Vec<&FulcioRoot> = vec![&root];
        let err = verify_cert_chain(&chain, &roots, ts_year(2025))
            .expect_err("malformed DER in bundle chain must reject");
        match err {
            VerifyError::Chain(msg) => assert!(msg.contains("not valid DER X.509"), "got: {msg}"),
            other => panic!("expected Chain, got: {other:?}"),
        }
    }

    // ── verify_cert_chain — Vuln 1 (BasicConstraints bypass) ─────

    /// Helper: build a P-256 cert that is NOT a CA (Sigstore leaf
    /// shape), but used as an "issuer" — i.e. its keypair signs
    /// another cert beneath it. This is the building block of the
    /// Vuln 1 attack scenario.
    fn p256_leaf_shaped_cert(params: rcgen::CertificateParams) -> (rcgen::Certificate, KeyPair) {
        let kp = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        // is_ca defaults to NoCa, which is what we want
        let cert = params.self_signed(&kp).unwrap();
        (cert, kp)
    }

    #[test]
    fn rejects_forged_leaf_signed_by_real_leaf_used_as_intermediate() {
        // THE Vuln 1 attack: attacker obtains a legitimate Sigstore
        // leaf cert L_attacker (non-CA) and its ephemeral private key.
        // Within L_attacker's validity window, they sign a forged
        // child cert L_forged with attacker-chosen SAN. The bundle
        // ships [L_forged, L_attacker, real_fulcio_root].
        //
        // Pre-fix: verify_cert_chain returned Ok because no
        // BasicConstraints check was performed on L_attacker.
        // Post-fix: enforce_issuer_constraints on L_attacker rejects
        // because its BasicConstraints extension is absent / cA=FALSE.
        let (fulcio_root_cert, fulcio_root_der, fulcio_root_kp) =
            p384_root_cert(cert_params_validity(2025));
        // Real attacker leaf: signed by Fulcio root, NoCa, P-256.
        // Use existing p256_leaf_signed_by which produces a NoCa leaf.
        let real_attacker_leaf_der = p256_leaf_signed_by(
            cert_params_validity(2025),
            &fulcio_root_cert,
            &fulcio_root_kp,
        );
        // Forge a child cert signed by real_attacker_leaf's keypair.
        // To do this we need the keypair (rcgen returned it from
        // p256_leaf_signed_by — but that helper discarded it). Re-build
        // the attacker leaf so we own its keypair.
        let (attacker_leaf_cert_obj, attacker_leaf_kp) = {
            let leaf_kp = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
            let cert = cert_params_validity(2025)
                .signed_by(&leaf_kp, &fulcio_root_cert, &fulcio_root_kp)
                .unwrap();
            (cert, leaf_kp)
        };
        let real_attacker_leaf_der_v2 = attacker_leaf_cert_obj.der().to_vec();
        // Build the forged child under the attacker's leaf.
        let forged_child_der = p256_leaf_signed_by(
            cert_params_validity(2025),
            &attacker_leaf_cert_obj,
            &attacker_leaf_kp,
        );
        let _ = real_attacker_leaf_der; // shadowed by v2 above

        let fulcio_root = fulcio_root_active_at(2025, fulcio_root_der);
        let chain: Vec<&[u8]> = vec![&forged_child_der, &real_attacker_leaf_der_v2];
        let roots: Vec<&FulcioRoot> = vec![&fulcio_root];
        let err = verify_cert_chain(&chain, &roots, ts_year(2025))
            .expect_err("forged-leaf-under-real-leaf chain must reject");
        match err {
            VerifyError::Chain(msg) => {
                assert!(
                    msg.contains("BasicConstraints") || msg.contains("not authorized"),
                    "expected BasicConstraints rejection naming the forgery, got: {msg}"
                );
            }
            other => panic!("expected VerifyError::Chain, got: {other:?}"),
        }
    }

    #[test]
    fn rejects_chain_with_ca_flagged_leaf() {
        // A leaf cert with BasicConstraints.cA=TRUE is structurally
        // invalid for a Sigstore signing leaf.
        let (root_cert, root_der, root_kp) = p384_root_cert(cert_params_validity(2025));
        // Build a "leaf" that's flagged as a CA.
        let leaf_der = {
            let leaf_kp = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
            let mut params = cert_params_validity(2025);
            params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
            let cert = params.signed_by(&leaf_kp, &root_cert, &root_kp).unwrap();
            cert.der().to_vec()
        };
        let root = fulcio_root_active_at(2025, root_der.clone());
        let chain: Vec<&[u8]> = vec![&leaf_der, &root_der];
        let roots: Vec<&FulcioRoot> = vec![&root];
        let err = verify_cert_chain(&chain, &roots, ts_year(2025))
            .expect_err("CA-flagged leaf must reject");
        match err {
            VerifyError::Chain(msg) => assert!(
                msg.contains("cA is TRUE") && msg.contains("leaf"),
                "expected CA-flagged-leaf diagnostic, got: {msg}"
            ),
            other => panic!("expected VerifyError::Chain, got: {other:?}"),
        }
    }

    // The `KeyUsage.keyCertSign`-on-leaf branch of
    // `enforce_leaf_constraints` is not unit-tested here because
    // rcgen 0.13.2 only emits X509v3 extensions on `signed_by`
    // when `is_ca = IsCa::Ca(...)`. A non-CA leaf with
    // `key_usages = [..., KeyCertSign]` ends up with ZERO extensions
    // in the DER, so we can't generate a cert with that exact
    // shape via rcgen. Forcing `is_ca = Ca` would make the
    // earlier BasicConstraints.cA=TRUE check fire first, masking
    // the keyCertSign branch.
    //
    // The keyCertSign check is still active in production code —
    // a real-world malformed cert (e.g. one minted by a misissuing
    // CA via raw DER) with `cA=FALSE` AND `KeyUsage.keyCertSign`
    // would be rejected. Defense in depth on top of the BC check.

    #[test]
    fn rejects_chain_exceeding_max_length() {
        // A 4-cert chain must reject pre-emptively, before any
        // signature work, regardless of whether the certs themselves
        // are internally consistent.
        let (root_cert, root_der, root_kp) = p384_root_cert(cert_params_validity(2025));
        let leaf_der = p256_leaf_signed_by(cert_params_validity(2025), &root_cert, &root_kp);
        let chain: Vec<&[u8]> = vec![&leaf_der, &leaf_der, &leaf_der, &root_der];
        let root = fulcio_root_active_at(2025, root_der.clone());
        let roots: Vec<&FulcioRoot> = vec![&root];
        let err = verify_cert_chain(&chain, &roots, ts_year(2025))
            .expect_err("length-4 chain must reject");
        match err {
            VerifyError::Chain(msg) => assert!(
                msg.contains("at most"),
                "expected max-length diagnostic, got: {msg}"
            ),
            other => panic!("expected VerifyError::Chain, got: {other:?}"),
        }
    }

    #[test]
    fn rejects_intermediate_with_path_len_constraint_exceeded() {
        // Build a root that has pathLen=0, then chain
        // [leaf, intermediate, root]. The intermediate (1 below root)
        // sits at position 1; remaining_depth for the root is 1.
        // pathLen=0 < 1 → reject.
        let (root_cert, root_der, root_kp) = {
            let kp = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
            let mut params = cert_params_validity(2025);
            params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Constrained(0));
            let cert = params.self_signed(&kp).unwrap();
            let der = cert.der().to_vec();
            (cert, der, kp)
        };
        // Intermediate signed by the root, also a CA.
        let intermediate_cert = {
            let inter_kp = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
            let mut params = cert_params_validity(2025);
            params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
            params.signed_by(&inter_kp, &root_cert, &root_kp).unwrap()
        };
        let intermediate_der = intermediate_cert.der().to_vec();
        // The leaf doesn't matter for this test — root rejects
        // before signature work.
        let leaf_der = p256_leaf_signed_by(cert_params_validity(2025), &root_cert, &root_kp);
        let chain: Vec<&[u8]> = vec![&leaf_der, &intermediate_der, &root_der];
        let root = fulcio_root_active_at(2025, root_der.clone());
        let roots: Vec<&FulcioRoot> = vec![&root];
        let err = verify_cert_chain(&chain, &roots, ts_year(2025))
            .expect_err("pathLen exceeded must reject");
        match err {
            VerifyError::Chain(msg) => assert!(
                msg.contains("pathLenConstraint"),
                "expected pathLen diagnostic, got: {msg}"
            ),
            other => panic!("expected VerifyError::Chain, got: {other:?}"),
        }
    }

    #[test]
    fn rejects_anchor_lacking_ca_flag_during_try_anchor_signature_path() {
        // If the trust-root metadata pinned a Fulcio "root" cert
        // that wasn't actually a CA, verify_cert_chain must refuse
        // to anchor on it via the signature-verify path. Catches
        // misconfigured operator-supplied or rotated roots that
        // accidentally include a non-CA cert. The `try_anchor_
        // signature` branch must enforce_issuer_constraints on the
        // anchor before attempting the signature.
        let (bogus_root_cert, bogus_root_kp) = p256_leaf_shaped_cert(cert_params_validity(2025));
        // Leaf signed by the non-CA "root". The chain doesn't ship
        // the bogus root — it's only in fulcio_roots — to force the
        // try_anchor_signature branch.
        let leaf_kp = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let leaf_cert = cert_params_validity(2025)
            .signed_by(&leaf_kp, &bogus_root_cert, &bogus_root_kp)
            .unwrap();
        let leaf_der = leaf_cert.der().to_vec();
        let bogus_root_der_clone = bogus_root_cert.der().to_vec();
        let bogus_anchor = fulcio_root_active_at(2025, bogus_root_der_clone);
        let chain: Vec<&[u8]> = vec![&leaf_der];
        let roots: Vec<&FulcioRoot> = vec![&bogus_anchor];
        let err = verify_cert_chain(&chain, &roots, ts_year(2025))
            .expect_err("non-CA anchor must reject");
        // Since try_anchor_signature swallows the
        // enforce_issuer_constraints error and tries the next anchor,
        // the final diagnostic is the "no trusted Fulcio root" one.
        // That's the right outcome — caller sees "untrusted root,"
        // not "anchor misconfigured" (security through robust
        // failure mode).
        match err {
            VerifyError::Chain(msg) => assert!(
                msg.contains("does not match any trusted Fulcio root"),
                "expected unanchored diagnostic, got: {msg}"
            ),
            other => panic!("expected VerifyError::Chain, got: {other:?}"),
        }
    }

    // ── verify_embedded_sct — Phase 1.4 ───────────────────────────

    /// Build a CustomExtension carrying a 1-byte dummy value. Used in
    /// tests so the leaf TBS has a non-empty extensions section both
    /// with-SCT and without-SCT, keeping the round-trip equality
    /// invariant (TBS-without-SCT == strip-SCT(TBS-with-SCT)).
    fn dummy_custom_extension() -> rcgen::CustomExtension {
        // OID 2.999.1 = Joint-ISO-ITU-T(2).example(999).1
        rcgen::CustomExtension::from_oid_content(&[2, 999, 1], vec![0x42])
    }

    /// Encode a serialized SCT per RFC 6962 §3.2 for testing. The
    /// returned bytes are what would be the inner SCT entry in the
    /// SignedCertificateTimestampList.
    fn encode_serialized_sct(
        log_id: &[u8],
        timestamp_ms: u64,
        sct_extensions: &[u8],
        sig_hash_algo: u8,
        sig_pk_algo: u8,
        signature_der: &[u8],
    ) -> Vec<u8> {
        let mut out = Vec::with_capacity(MIN_SCT_LEN + sct_extensions.len() + signature_der.len());
        out.push(0u8); // version v1
        out.extend_from_slice(log_id);
        out.extend_from_slice(&timestamp_ms.to_be_bytes());
        out.extend_from_slice(&(sct_extensions.len() as u16).to_be_bytes());
        out.extend_from_slice(sct_extensions);
        out.push(sig_hash_algo);
        out.push(sig_pk_algo);
        out.extend_from_slice(&(signature_der.len() as u16).to_be_bytes());
        out.extend_from_slice(signature_der);
        out
    }

    /// Wrap a list of serialized-SCT byte strings as a
    /// SignedCertificateTimestampList per RFC 6962 §3.3.
    fn encode_sct_list(serialized_scts: &[&[u8]]) -> Vec<u8> {
        let mut inner = Vec::new();
        for sct in serialized_scts {
            inner.extend_from_slice(&(sct.len() as u16).to_be_bytes());
            inner.extend_from_slice(sct);
        }
        let mut out = Vec::with_capacity(2 + inner.len());
        out.extend_from_slice(&(inner.len() as u16).to_be_bytes());
        out.extend_from_slice(&inner);
        out
    }

    /// Wrap arbitrary bytes as a DER OCTET STRING (tag `0x04`
    /// followed by length + content). Used to build the extension
    /// extnValue's inner wrapper for the SCT list.
    fn der_wrap_octet_string(content: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + 5 + content.len());
        out.push(0x04);
        out.extend_from_slice(&der_encode_length(content.len()));
        out.extend_from_slice(content);
        out
    }

    /// Issuer cert + keypair, fresh per test.
    struct SctTestIssuer {
        cert: rcgen::Certificate,
        kp: KeyPair,
    }
    fn fresh_sct_issuer() -> SctTestIssuer {
        let kp = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
        let mut params = cert_params_validity(2025);
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let cert = params.self_signed(&kp).unwrap();
        SctTestIssuer { cert, kp }
    }

    /// Build a leaf cert via rcgen using the supplied `leaf_kp` and
    /// `issuer`, with optional embedded SCT extension bytes.
    ///
    /// Sharing `leaf_kp` across two calls (with vs without SCT)
    /// is what makes the two TBSes byte-equal except for the SCT
    /// extension entry — rcgen derives the SerialNumber and the SPKI
    /// from the leaf keypair, so reusing the keypair pins everything
    /// else.
    fn build_leaf_with_optional_sct(
        leaf_kp: &KeyPair,
        issuer: &SctTestIssuer,
        sct_list_bytes: Option<&[u8]>,
    ) -> Vec<u8> {
        let mut leaf_params = cert_params_validity(2025);
        // Always include the dummy extension so the extensions
        // section's structural shape is the same whether or not the
        // SCT extension is present.
        leaf_params.custom_extensions = vec![dummy_custom_extension()];
        if let Some(sct_bytes) = sct_list_bytes {
            // The SCT extension's extnValue is a DER OCTET STRING
            // whose content is the TLS-encoded SCT list. Wrap here so
            // rcgen treats it as opaque bytes.
            let wrapped = der_wrap_octet_string(sct_bytes);
            leaf_params
                .custom_extensions
                .push(rcgen::CustomExtension::from_oid_content(
                    &SCT_EXTENSION_OID_COMPONENTS,
                    wrapped,
                ));
        }
        let leaf = leaf_params
            .signed_by(leaf_kp, &issuer.cert, &issuer.kp)
            .unwrap();
        leaf.der().to_vec()
    }

    /// Extract the issuer cert's SPKI DER bytes via x509-parser.
    fn issuer_spki_from_cert(issuer_cert: &rcgen::Certificate) -> Vec<u8> {
        let der = issuer_cert.der().to_vec();
        let (_, parsed) = X509Certificate::from_der(&der).unwrap();
        parsed.tbs_certificate.subject_pki.raw.to_vec()
    }

    /// Synth a CT log keypair + the matching CtLogKey active around
    /// `at_year`. Returns (signing_key, ct_log_key).
    fn synth_ct_log_key(at_year: i32) -> (SigningKey, CtLogKey) {
        let signing_key = SigningKey::random(&mut rand::thread_rng());
        let verifying_key = VerifyingKey::from(&signing_key);
        let spki_der = verifying_key
            .to_public_key_der()
            .unwrap()
            .as_bytes()
            .to_vec();
        let log_id = Sha256::digest(&spki_der).to_vec();
        let start = chrono::DateTime::<Utc>::from_timestamp(
            chrono::NaiveDate::from_ymd_opt(at_year - 5, 1, 1)
                .unwrap()
                .and_hms_opt(0, 0, 0)
                .unwrap()
                .and_utc()
                .timestamp(),
            0,
        )
        .unwrap();
        let end = chrono::DateTime::<Utc>::from_timestamp(
            chrono::NaiveDate::from_ymd_opt(at_year + 5, 1, 1)
                .unwrap()
                .and_hms_opt(0, 0, 0)
                .unwrap()
                .and_utc()
                .timestamp(),
            0,
        )
        .unwrap();
        let ct_log_key = CtLogKey {
            log_id,
            spki_der,
            valid_for: ValidityWindow {
                start,
                end: Some(end),
            },
        };
        (signing_key, ct_log_key)
    }

    #[test]
    fn verifies_valid_embedded_sct_against_pinned_ct_log_key() {
        // The full positive path with a SHARED leaf keypair across
        // both rcgen builds — that's what makes the two TBSes
        // byte-equal except for the SCT extension entry.
        let issuer = fresh_sct_issuer();
        let leaf_kp = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let issuer_spki = issuer_spki_from_cert(&issuer.cert);
        let issuer_key_hash = Sha256::digest(&issuer_spki).to_vec();

        let (ct_signing_key, ct_log_key) = synth_ct_log_key(2025);
        let timestamp_ms = 1_700_000_000_000u64;
        let sct_extensions: &[u8] = &[];

        // Build leaf v1 WITHOUT SCT and extract its TBS — that's the
        // precert TBS the CT log signs over.
        let leaf_without_sct_der = build_leaf_with_optional_sct(&leaf_kp, &issuer, None);
        let (_, parsed_without_sct) = X509Certificate::from_der(&leaf_without_sct_der).unwrap();
        let precert_tbs = parsed_without_sct.tbs_certificate.as_ref().to_vec();

        // Sign the precert input.
        let mut signed_input = Vec::new();
        signed_input.push(0u8); // version
        signed_input.push(0u8); // signature_type
        signed_input.extend_from_slice(&timestamp_ms.to_be_bytes());
        signed_input.extend_from_slice(&1u16.to_be_bytes()); // entry_type = precert
        signed_input.extend_from_slice(&issuer_key_hash);
        let tbs_len = precert_tbs.len() as u32;
        signed_input.push(((tbs_len >> 16) & 0xFF) as u8);
        signed_input.push(((tbs_len >> 8) & 0xFF) as u8);
        signed_input.push((tbs_len & 0xFF) as u8);
        signed_input.extend_from_slice(&precert_tbs);
        signed_input.extend_from_slice(&(sct_extensions.len() as u16).to_be_bytes());
        signed_input.extend_from_slice(sct_extensions);

        let sig: Signature = ct_signing_key.sign(&signed_input);
        let sig_der = sig.to_der().as_bytes().to_vec();

        let serialized_sct = encode_serialized_sct(
            &ct_log_key.log_id,
            timestamp_ms,
            sct_extensions,
            4, // sha256
            3, // ecdsa
            &sig_der,
        );
        let sct_list_bytes = encode_sct_list(&[&serialized_sct]);

        // Build leaf v2 WITH the SCT extension, using the SAME
        // leaf_kp — the SerialNumber and SPKI stay byte-equal,
        // so strip-SCT(v2_tbs) == v1_tbs.
        let leaf_with_sct_der =
            build_leaf_with_optional_sct(&leaf_kp, &issuer, Some(&sct_list_bytes));

        // Sanity: round-trip invariant the verifier relies on.
        let (_, parsed_with_sct) = X509Certificate::from_der(&leaf_with_sct_der).unwrap();
        let reconstructed =
            reconstruct_precert_tbs_without_sct(parsed_with_sct.tbs_certificate.as_ref())
                .expect("strip should succeed");
        assert_eq!(
            reconstructed, precert_tbs,
            "strip-SCT(TBS-with-SCT) must byte-equal TBS-without-SCT \
             (shared leaf keypair pins SerialNumber + SPKI)"
        );

        verify_embedded_sct(
            &leaf_with_sct_der,
            &issuer_spki,
            std::slice::from_ref(&ct_log_key),
            ts_year(2025),
        )
        .expect("synthetic SCT must verify under the pinned CT log key");
    }

    #[test]
    fn rejects_leaf_with_no_embedded_sct_extension() {
        let issuer = fresh_sct_issuer();
        let leaf_kp = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let leaf_der = build_leaf_with_optional_sct(&leaf_kp, &issuer, None);
        let issuer_spki = issuer_spki_from_cert(&issuer.cert);
        let (_, ct_log_key) = synth_ct_log_key(2025);
        let err = verify_embedded_sct(
            &leaf_der,
            &issuer_spki,
            std::slice::from_ref(&ct_log_key),
            ts_year(2025),
        )
        .expect_err("leaf without SCT extension must reject");
        match err {
            VerifyError::Sct(msg) => assert!(msg.contains("no embedded SCT"), "got: {msg}"),
            other => panic!("expected VerifyError::Sct, got: {other:?}"),
        }
    }

    #[test]
    fn rejects_sct_with_unknown_log_id() {
        // SCT's logId doesn't match the pinned CT log key.
        let issuer = fresh_sct_issuer();
        let leaf_kp = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let issuer_spki = issuer_spki_from_cert(&issuer.cert);
        let (signing_key, _) = synth_ct_log_key(2025);
        let (_, pinned_unrelated_key) = synth_ct_log_key(2025);
        let dummy_sig: Signature = signing_key.sign(&[0u8; 32]);
        let serialized = encode_serialized_sct(
            &[0xab; 32],
            1_700_000_000_000,
            &[],
            4,
            3,
            dummy_sig.to_der().as_bytes(),
        );
        let sct_list = encode_sct_list(&[&serialized]);
        let leaf_der = build_leaf_with_optional_sct(&leaf_kp, &issuer, Some(&sct_list));
        let err = verify_embedded_sct(
            &leaf_der,
            &issuer_spki,
            std::slice::from_ref(&pinned_unrelated_key),
            ts_year(2025),
        )
        .expect_err("unknown logId must reject");
        match err {
            VerifyError::Sct(msg) => assert!(
                msg.contains("no SCT in the leaf cert's extension verified"),
                "got: {msg}"
            ),
            other => panic!("expected VerifyError::Sct, got: {other:?}"),
        }
    }

    #[test]
    fn rejects_sct_with_forged_signature_under_pinned_key() {
        let issuer = fresh_sct_issuer();
        let leaf_kp = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let issuer_spki = issuer_spki_from_cert(&issuer.cert);
        let (_, ct_log_key) = synth_ct_log_key(2025);
        // Different key signs — the pinned `ct_log_key` will reject.
        let forge_key = SigningKey::random(&mut rand::thread_rng());
        let forge_sig: Signature = forge_key.sign(b"anything");
        let serialized = encode_serialized_sct(
            &ct_log_key.log_id,
            1_700_000_000_000,
            &[],
            4,
            3,
            forge_sig.to_der().as_bytes(),
        );
        let sct_list = encode_sct_list(&[&serialized]);
        let leaf_der = build_leaf_with_optional_sct(&leaf_kp, &issuer, Some(&sct_list));
        let err = verify_embedded_sct(
            &leaf_der,
            &issuer_spki,
            std::slice::from_ref(&ct_log_key),
            ts_year(2025),
        )
        .expect_err("forged-key SCT must reject");
        match err {
            VerifyError::Sct(msg) => assert!(
                msg.contains("no SCT in the leaf cert's extension verified"),
                "got: {msg}"
            ),
            other => panic!("expected VerifyError::Sct, got: {other:?}"),
        }
    }

    #[test]
    fn rejects_sct_with_unsupported_signature_algorithm() {
        // RFC 6962 sha256/ecdsa is (4, 3). Any other tuple rejects.
        let issuer = fresh_sct_issuer();
        let leaf_kp = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let issuer_spki = issuer_spki_from_cert(&issuer.cert);
        let (_, ct_log_key) = synth_ct_log_key(2025);
        let dummy_sig: Signature = SigningKey::random(&mut rand::thread_rng()).sign(&[0u8; 32]);
        let serialized = encode_serialized_sct(
            &ct_log_key.log_id,
            1_700_000_000_000,
            &[],
            5, // sha384 — wrong for Sigstore profile
            3,
            dummy_sig.to_der().as_bytes(),
        );
        let sct_list = encode_sct_list(&[&serialized]);
        let leaf_der = build_leaf_with_optional_sct(&leaf_kp, &issuer, Some(&sct_list));
        let err = verify_embedded_sct(
            &leaf_der,
            &issuer_spki,
            std::slice::from_ref(&ct_log_key),
            ts_year(2025),
        )
        .expect_err("non-sha256/ecdsa SCT must reject");
        match err {
            VerifyError::Sct(msg) => assert!(
                msg.contains("no SCT in the leaf cert's extension verified"),
                "got: {msg}"
            ),
            other => panic!("expected VerifyError::Sct, got: {other:?}"),
        }
    }

    #[test]
    fn rejects_sct_extension_with_malformed_tls_list() {
        // SCT extension is present but its TLS bytes declare a length
        // larger than the actual content (truncated).
        let issuer = fresh_sct_issuer();
        let leaf_kp = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        // Bytes: u16 outer length = 0xFFFF (huge), followed by only 2
        // actual content bytes — parse_sct_list_tls rejects.
        let garbage_list_bytes = vec![0xFF, 0xFF, 0xAA, 0xBB];
        let leaf_der = build_leaf_with_optional_sct(&leaf_kp, &issuer, Some(&garbage_list_bytes));

        let issuer_spki = issuer_spki_from_cert(&issuer.cert);
        let (_, ct_log_key) = synth_ct_log_key(2025);
        let err = verify_embedded_sct(
            &leaf_der,
            &issuer_spki,
            std::slice::from_ref(&ct_log_key),
            ts_year(2025),
        )
        .expect_err("malformed SCT list must reject");
        match err {
            VerifyError::Sct(msg) => assert!(
                msg.contains("SCT list TLS encoding is malformed"),
                "got: {msg}"
            ),
            other => panic!("expected VerifyError::Sct, got: {other:?}"),
        }
    }

    #[test]
    fn vendored_ct_log_keys_parse_as_p256_spki() {
        // Sanity: every CT log key in the vendored trust root has a
        // 32-byte logId (sha256 invariant) and an SPKI DER that
        // decodes as ECDSA P-256. A future rotation that ships a
        // non-P-256 CT log trips this loudly before any real install
        // breaks.
        use p256::pkcs8::DecodePublicKey;
        let root = TrustRoot::parse(EMBEDDED_TRUST_ROOT_JSON).unwrap();
        for (i, key) in root.ctlog_keys.iter().enumerate() {
            assert_eq!(
                key.log_id.len(),
                32,
                "ctlog_keys[{i}].log_id must be 32 bytes (sha256)"
            );
            VerifyingKey::from_public_key_der(&key.spki_der).unwrap_or_else(|e| {
                panic!("ctlog_keys[{i}].spki_der did not decode as P-256: {e}");
            });
        }
    }

    #[test]
    fn der_encode_decode_length_roundtrip() {
        // Cover the short-form / long-form boundary and a few
        // representative larger values.
        for &len in &[0usize, 1, 127, 128, 255, 256, 65535, 65536, 1_000_000] {
            let encoded = der_encode_length(len);
            let (decoded, consumed) = der_decode_length(&encoded).unwrap();
            assert_eq!(decoded, len, "len={len} round-trip");
            assert_eq!(consumed, encoded.len(), "len={len} consumed");
        }
    }

    #[test]
    fn vendored_fulcio_roots_satisfy_issuer_constraint_profile() {
        // Sanity: every Fulcio root in the vendored trust root has
        // BasicConstraints critical+cA=TRUE and (if present)
        // KeyUsage.keyCertSign — i.e. each one passes
        // enforce_issuer_constraints. A future rotation that vendors
        // a non-conformant root trips this test loudly before any
        // real install breaks.
        let root = TrustRoot::parse(EMBEDDED_TRUST_ROOT_JSON).unwrap();
        for (i, fulcio) in root.fulcio_roots.iter().enumerate() {
            for (j, der) in fulcio.cert_chain_der.iter().enumerate() {
                let (_, cert) = X509Certificate::from_der(der).unwrap();
                // 0 = the cert is a root or topmost intermediate;
                // no intermediates follow.
                enforce_issuer_constraints(&cert, 0, &format!("fulcio[{i}].cert[{j}]"))
                    .unwrap_or_else(|e| {
                        panic!("vendored Fulcio cert[{j}] in CA[{i}] failed issuer profile: {e}")
                    });
            }
        }
    }

    #[test]
    fn vendored_fulcio_roots_parse_as_x509_with_expected_algorithms() {
        // Sanity: every Fulcio root in the vendored trust root parses
        // as X.509 DER and uses the algorithms our verify_cert_chain
        // dispatch supports. A future rotation that introduces a
        // non-supported algorithm would fail this test loudly before
        // breaking real installs.
        let root = TrustRoot::parse(EMBEDDED_TRUST_ROOT_JSON).unwrap();
        for (i, fulcio) in root.fulcio_roots.iter().enumerate() {
            for (j, der) in fulcio.cert_chain_der.iter().enumerate() {
                let (_, cert) = X509Certificate::from_der(der)
                    .unwrap_or_else(|e| panic!("Fulcio root[{i}].cert[{j}] failed to parse: {e}"));
                let sig_alg = &cert.signature_algorithm.algorithm;
                assert!(
                    oid_components_match(sig_alg, &OID_ECDSA_WITH_SHA256)
                        || oid_components_match(sig_alg, &OID_ECDSA_WITH_SHA384),
                    "Fulcio root[{i}].cert[{j}] uses unsupported sig algorithm {sig_alg}"
                );
            }
        }
    }

    #[test]
    fn rejects_set_with_non_hex_log_id() {
        // A bundle whose logId.keyId is not valid hex must reject —
        // verify_rekor_set hex-decodes it to look up the trust root.
        let (signing_key, _spki_der, _log_id_bytes) = p256_rekor_signing_key();
        let mut tlog =
            synth_tlog_entry_with_set(&signing_key, "not!hex!", 42, 1700000000, "Zm9vYmFy");
        // Re-encode signed_entry_timestamp because the synth helper
        // already used the (invalid) hex in the SET input.
        tlog.log_id.key_id = "not!hex!".into();
        let err = verify_rekor_set(&tlog, &[], RekorInclusionProofPolicy::RequireSet)
            .expect_err("non-hex logId must reject");
        match err {
            VerifyError::RekorSet(msg) => assert!(msg.contains("not valid hex"), "got: {msg}"),
            other => panic!("expected VerifyError::RekorSet, got: {other:?}"),
        }
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

    // ── Phase 1.8 — bundle parser ─────────────────────────────────

    /// Build a minimal v0.2 bundle JSON (chain shape) with one leaf
    /// cert + the supplied DSSE envelope + tlog entry.
    fn synth_bundle_v02(
        leaf_cert_der: &[u8],
        chain_extras_der: &[Vec<u8>],
        dsse: &serde_json::Value,
        tlog: &serde_json::Value,
    ) -> serde_json::Value {
        let mut certs = vec![serde_json::json!({"rawBytes": BASE64.encode(leaf_cert_der)})];
        for d in chain_extras_der {
            certs.push(serde_json::json!({"rawBytes": BASE64.encode(d)}));
        }
        serde_json::json!({
            "mediaType": "application/vnd.dev.sigstore.bundle+json;version=0.2",
            "dsseEnvelope": dsse,
            "verificationMaterial": {
                "x509CertificateChain": { "certificates": certs },
                "tlogEntries": [tlog],
            }
        })
    }

    /// Build a minimal v0.3 bundle JSON (single-cert shape).
    fn synth_bundle_v03(
        leaf_cert_der: &[u8],
        dsse: &serde_json::Value,
        tlog: &serde_json::Value,
    ) -> serde_json::Value {
        serde_json::json!({
            "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
            "dsseEnvelope": dsse,
            "verificationMaterial": {
                "certificate": { "rawBytes": BASE64.encode(leaf_cert_der) },
                "tlogEntries": [tlog],
            }
        })
    }

    /// Wrap an inner bundle as an npm `{ attestations: [{ bundle }] }`
    /// response.
    fn synth_bundle_npm_wrapper(inner: &serde_json::Value) -> serde_json::Value {
        serde_json::json!({
            "attestations": [
                { "predicateType": "https://slsa.dev/provenance/v1", "bundle": inner }
            ]
        })
    }

    fn dummy_dsse_envelope() -> serde_json::Value {
        serde_json::json!({
            "payloadType": "application/vnd.in-toto+json",
            "payload": BASE64.encode(b"{}"),
            "signatures": [{"keyid": "", "sig": BASE64.encode([0u8; 64])}],
        })
    }

    fn dummy_tlog_entry() -> serde_json::Value {
        serde_json::json!({
            "logIndex": "42",
            "logId": {"keyId": "deadbeef"},
            "integratedTime": "1700000000",
            "canonicalizedBody": "Zm9v",
        })
    }

    #[test]
    fn parses_v0_2_chain_bundle() {
        let leaf = b"leaf-der-stand-in";
        let intermediate = b"intermediate-der";
        let bundle = synth_bundle_v02(
            leaf,
            &[intermediate.to_vec()],
            &dummy_dsse_envelope(),
            &dummy_tlog_entry(),
        );
        let body = serde_json::to_vec(&bundle).unwrap();
        let parsed = parse_bundle_components(&body).expect("v0.2 chain bundle must parse");
        assert_eq!(parsed.leaf_cert_der, leaf);
        assert_eq!(parsed.chain_der.len(), 2);
        assert_eq!(parsed.chain_der[1], intermediate);
        assert_eq!(parsed.tlog_entry.log_index, "42");
    }

    #[test]
    fn parses_v0_3_single_cert_bundle() {
        let leaf = b"leaf-der-only";
        let bundle = synth_bundle_v03(leaf, &dummy_dsse_envelope(), &dummy_tlog_entry());
        let body = serde_json::to_vec(&bundle).unwrap();
        let parsed = parse_bundle_components(&body).expect("v0.3 single-cert bundle must parse");
        assert_eq!(parsed.leaf_cert_der, leaf);
        assert_eq!(parsed.chain_der.len(), 1);
    }

    #[test]
    fn parses_npm_attestations_wrapper() {
        let leaf = b"leaf-from-npm";
        let inner = synth_bundle_v03(leaf, &dummy_dsse_envelope(), &dummy_tlog_entry());
        let wrapped = synth_bundle_npm_wrapper(&inner);
        let body = serde_json::to_vec(&wrapped).unwrap();
        let parsed = parse_bundle_components(&body).expect("npm wrapper must parse");
        assert_eq!(parsed.leaf_cert_der, leaf);
    }

    #[test]
    fn parser_rejects_bundle_without_verification_material() {
        let bundle = serde_json::json!({"dsseEnvelope": dummy_dsse_envelope()});
        let err = parse_bundle_components(&serde_json::to_vec(&bundle).unwrap())
            .expect_err("missing verificationMaterial must reject");
        match err {
            VerifyError::BundleParse(msg) => assert!(msg.contains("verificationMaterial")),
            other => panic!("expected BundleParse, got: {other:?}"),
        }
    }

    #[test]
    fn parser_rejects_bundle_without_dsse_envelope() {
        let leaf = b"leaf-der";
        let bundle = serde_json::json!({
            "verificationMaterial": {
                "certificate": { "rawBytes": BASE64.encode(leaf) },
                "tlogEntries": [dummy_tlog_entry()],
            }
        });
        let err = parse_bundle_components(&serde_json::to_vec(&bundle).unwrap())
            .expect_err("missing dsseEnvelope must reject");
        match err {
            VerifyError::BundleParse(msg) => assert!(msg.contains("dsseEnvelope")),
            other => panic!("expected BundleParse, got: {other:?}"),
        }
    }

    #[test]
    fn parser_rejects_bundle_with_empty_tlog_entries() {
        let leaf = b"leaf";
        let bundle = serde_json::json!({
            "dsseEnvelope": dummy_dsse_envelope(),
            "verificationMaterial": {
                "certificate": { "rawBytes": BASE64.encode(leaf) },
                "tlogEntries": [],
            }
        });
        let err = parse_bundle_components(&serde_json::to_vec(&bundle).unwrap())
            .expect_err("empty tlogEntries must reject");
        match err {
            VerifyError::BundleParse(msg) => assert!(msg.contains("tlogEntries")),
            other => panic!("expected BundleParse, got: {other:?}"),
        }
    }

    #[test]
    fn parser_rejects_malformed_json() {
        let err =
            parse_bundle_components(b"not-valid-json").expect_err("malformed JSON must reject");
        match err {
            VerifyError::BundleParse(msg) => assert!(msg.contains("not valid JSON")),
            other => panic!("expected BundleParse, got: {other:?}"),
        }
    }

    // ── Phase 1.8 — identity expectations ─────────────────────────

    /// Build a leaf cert with a SAN URI + optional Fulcio OIDC
    /// issuer extension. Used to test check_identity_expectations.
    fn leaf_with_san_and_issuer(san_uri: &str, fulcio_issuer: Option<&str>) -> Vec<u8> {
        let issuer = fresh_sct_issuer();
        let leaf_kp = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let mut params = cert_params_validity(2025);
        params.subject_alt_names = vec![rcgen::SanType::URI(
            rcgen::Ia5String::try_from(san_uri.to_string()).unwrap(),
        )];
        if let Some(iss) = fulcio_issuer {
            // Encode as plain UTF-8 (v1 extension shape).
            params.custom_extensions = vec![rcgen::CustomExtension::from_oid_content(
                &FULCIO_OIDC_ISSUER_OID_V1,
                iss.as_bytes().to_vec(),
            )];
        }
        let leaf = params
            .signed_by(&leaf_kp, &issuer.cert, &issuer.kp)
            .unwrap();
        leaf.der().to_vec()
    }

    #[test]
    fn identity_check_passes_when_expectations_match() {
        let san =
            "https://github.com/lpm-dev/rust-client/.github/workflows/release.yml@refs/tags/v1";
        let der =
            leaf_with_san_and_issuer(san, Some("https://token.actions.githubusercontent.com"));
        let (_, parsed) = X509Certificate::from_der(&der).unwrap();
        let expectations = IdentityExpectations {
            expected_issuer: Some("https://token.actions.githubusercontent.com".into()),
            expected_san_uri_prefix: Some("https://github.com/lpm-dev/rust-client/".into()),
            expected_workflow_path: Some(".github/workflows/release.yml".into()),
        };
        check_identity_expectations(&parsed, &expectations).expect("matching identity must pass");
    }

    #[test]
    fn identity_check_rejects_san_uri_prefix_mismatch() {
        let san =
            "https://github.com/other-org/other-repo/.github/workflows/release.yml@refs/tags/v1";
        let der =
            leaf_with_san_and_issuer(san, Some("https://token.actions.githubusercontent.com"));
        let (_, parsed) = X509Certificate::from_der(&der).unwrap();
        let expectations = IdentityExpectations {
            expected_san_uri_prefix: Some("https://github.com/lpm-dev/rust-client/".into()),
            ..IdentityExpectations::none()
        };
        let err = check_identity_expectations(&parsed, &expectations)
            .expect_err("wrong org/repo SAN must reject");
        match err {
            VerifyError::IdentityMismatch { field, .. } => {
                assert_eq!(field, "san_uri_prefix")
            }
            other => panic!("expected IdentityMismatch, got: {other:?}"),
        }
    }

    #[test]
    fn identity_check_rejects_workflow_path_mismatch() {
        let san = "https://github.com/lpm-dev/rust-client/.github/workflows/build.yml@refs/tags/v1";
        let der = leaf_with_san_and_issuer(san, None);
        let (_, parsed) = X509Certificate::from_der(&der).unwrap();
        let expectations = IdentityExpectations {
            expected_workflow_path: Some(".github/workflows/release.yml".into()),
            ..IdentityExpectations::none()
        };
        let err = check_identity_expectations(&parsed, &expectations)
            .expect_err("wrong workflow path must reject");
        match err {
            VerifyError::IdentityMismatch { field, .. } => {
                assert_eq!(field, "workflow_path")
            }
            other => panic!("expected IdentityMismatch, got: {other:?}"),
        }
    }

    #[test]
    fn identity_check_rejects_fulcio_oidc_issuer_mismatch() {
        let san =
            "https://github.com/lpm-dev/rust-client/.github/workflows/release.yml@refs/tags/v1";
        let der = leaf_with_san_and_issuer(san, Some("https://malicious-issuer.example.com"));
        let (_, parsed) = X509Certificate::from_der(&der).unwrap();
        let expectations = IdentityExpectations {
            expected_issuer: Some("https://token.actions.githubusercontent.com".into()),
            ..IdentityExpectations::none()
        };
        let err = check_identity_expectations(&parsed, &expectations)
            .expect_err("wrong OIDC issuer must reject");
        match err {
            VerifyError::IdentityMismatch { field, .. } => assert_eq!(field, "issuer"),
            other => panic!("expected IdentityMismatch, got: {other:?}"),
        }
    }

    #[test]
    fn identity_check_rejects_missing_oidc_issuer_when_required() {
        let san =
            "https://github.com/lpm-dev/rust-client/.github/workflows/release.yml@refs/tags/v1";
        let der = leaf_with_san_and_issuer(san, None);
        let (_, parsed) = X509Certificate::from_der(&der).unwrap();
        let expectations = IdentityExpectations {
            expected_issuer: Some("https://token.actions.githubusercontent.com".into()),
            ..IdentityExpectations::none()
        };
        let err = check_identity_expectations(&parsed, &expectations)
            .expect_err("missing OIDC issuer must reject when expected");
        match err {
            VerifyError::IdentityMismatch { field, .. } => assert_eq!(field, "issuer"),
            other => panic!("expected IdentityMismatch, got: {other:?}"),
        }
    }

    #[test]
    fn identity_check_passes_with_none_expectations() {
        let san = "https://github.com/anyone/anywhere/.github/workflows/whatever.yml@anything";
        let der = leaf_with_san_and_issuer(san, None);
        let (_, parsed) = X509Certificate::from_der(&der).unwrap();
        check_identity_expectations(&parsed, &IdentityExpectations::none())
            .expect("none() must skip all checks");
    }

    // ── Phase 1.8 — VerifyOptions presets ─────────────────────────

    #[test]
    fn verify_options_strict_requires_both_set_and_inclusion_proof() {
        let opts = VerifyOptions::strict();
        assert_eq!(
            opts.rekor_inclusion_policy,
            RekorInclusionProofPolicy::RequireBoth
        );
    }

    #[test]
    fn verify_options_npm_attestation_allows_either() {
        let opts = VerifyOptions::npm_attestation();
        assert_eq!(
            opts.rekor_inclusion_policy,
            RekorInclusionProofPolicy::Either
        );
    }

    // ── Phase 1.8 — find_leaf_issuer_spki ─────────────────────────

    #[test]
    fn find_leaf_issuer_spki_picks_intermediate_when_chain_provides_it() {
        let issuer = fresh_sct_issuer();
        let leaf_kp = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let leaf_der = cert_params_validity(2025)
            .signed_by(&leaf_kp, &issuer.cert, &issuer.kp)
            .unwrap()
            .der()
            .to_vec();
        let intermediate_der = issuer.cert.der().to_vec();

        let (_, leaf_parsed) = X509Certificate::from_der(&leaf_der).unwrap();
        let chain = vec![leaf_der.clone(), intermediate_der.clone()];
        let trust = TrustRoot::parse(EMBEDDED_TRUST_ROOT_JSON).unwrap();
        let spki = find_leaf_issuer_spki(&leaf_parsed, &chain, &trust, ts_year(2025))
            .expect("chain-provided intermediate must resolve");
        // Sanity: returned SPKI must be the intermediate's, not the leaf's.
        let (_, intermediate_parsed) = X509Certificate::from_der(&intermediate_der).unwrap();
        assert_eq!(spki, intermediate_parsed.tbs_certificate.subject_pki.raw);
    }
}
