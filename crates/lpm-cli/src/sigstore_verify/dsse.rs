use crate::sigstore::DsseEnvelope;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use x509_parser::oid_registry::{OID_EC_P256, OID_KEY_TYPE_EC_PUBLIC_KEY};
use x509_parser::prelude::*;

use super::VerifyError;

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
#[allow(dead_code)] // wired into provenance_bundle
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
#[allow(dead_code)] // consumer (`verify_dsse`) is allow-dead; transitively dead
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
