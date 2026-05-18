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
        let VerifyError::DsseSignature(msg) = err;
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
        let VerifyError::DsseSignature(msg) = err;
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
        let VerifyError::DsseSignature(msg) = err;
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
        let VerifyError::DsseSignature(msg) = err;
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
        let VerifyError::DsseSignature(msg) = err;
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
        let VerifyError::DsseSignature(msg) = err;
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
        let VerifyError::DsseSignature(msg) = err;
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
        let VerifyError::DsseSignature(msg) = err;
        assert!(
            msg.contains("P-256"),
            "expected curve-mismatch diagnostic, got: {msg}"
        );
    }
}
