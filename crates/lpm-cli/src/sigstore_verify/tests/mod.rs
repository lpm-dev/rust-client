use super::*;
use crate::sigstore::{DsseEnvelope, DsseSignature};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use chrono::{DateTime, Utc};
use ecdsa::signature::Signer;
use ecdsa::signature::hazmat::PrehashSigner;
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use p256::pkcs8::DecodePrivateKey;
use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::SystemTime;
use x509_parser::prelude::{FromDer, X509Certificate};

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
    let err = verify_dsse(&envelope, &cert).expect_err("tampered payload must fail verification");
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
    // attempt diagnostic; the "tried DER and raw" wording is the
    // contract.
    let (cert_der, signing_key) = p256_cert_and_signing_key();
    let mut envelope = dsse_envelope_signed_with(&signing_key, PAYLOAD);
    envelope.signatures[0].sig = BASE64.encode(b"garbage");
    let (_, cert) = X509Certificate::from_der(&cert_der).unwrap();
    let err = verify_dsse(&envelope, &cert).expect_err("unparseable signature must fail");
    let msg = expect_dsse_sig_msg(err);
    assert!(
        msg.contains("DER and raw"),
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

// ── verify_rekor_body — ───────────────────────────

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
        other => {
            panic!("expected VerifyError::RekorBodyMismatch on `{expected_field}`, got: {other:?}")
        }
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
    // reason" invariant.
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
    let err =
        verify_rekor_body(&tlog, &envelope, &cert_der).expect_err("unknown apiVersion must reject");
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
    let err =
        verify_rekor_body(&tlog, &envelope, &cert_der).expect_err("non-intoto kind must reject");
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
    let err =
        verify_rekor_body(&tlog, &envelope, &cert_der).expect_err("malformed base64 must reject");
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
        msg.contains("not valid JSON"),
        "expected JSON-parse diagnostic, got: {msg}"
    );
}

// ── TrustRoot — ─────────────────────────────────────

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
    // Sanity: the vendored artifact has at least one active key per
    // role at wall-clock now. If a future rotation lets one role go
    // retired-only, this test fails loudly so release work refreshes
    // the embedded root.
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

// ── verify_rekor_set — ──────────────────────────────

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
    // produces for a fixed input catches key-reorder, whitespace,
    // or casing regressions before they break SET verification.
    let s = build_set_input_canonical_json("Zm9vYmFy", 1700000000, 42, "wNI9atQGlz");
    let expected =
        r#"{"body":"Zm9vYmFy","integratedTime":1700000000,"logID":"wNI9atQGlz","logIndex":42}"#;
    assert_eq!(s, expected, "SET canonical-JSON layout drift");
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
    let expected = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(integrated_time as u64);
    assert_eq!(
        returned_time, expected,
        "verify_rekor_set must return the parsed integratedTime as the at_time anchor"
    );
}

#[test]
fn rejects_bundle_with_forged_rekor_set() {
    let (signing_key, spki_der, log_id_bytes) = p256_rekor_signing_key();
    let log_id_hex = hex::encode(&log_id_bytes);
    let mut tlog = synth_tlog_entry_with_set(&signing_key, &log_id_hex, 42, 1700000000, "Zm9vYmFy");

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
    // The caller is responsible for ensuring the inclusion
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
    // Names the policy explicitly so the contract is pinned for
    // callers that require inclusion-proof presence without also
    // requiring a SET.
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
    // claim. The current verifier is embedded-SCT-only and rejects
    // fail-closed when no embedded SCT is present.
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
    // `verification.inclusionPromise` (the schema's
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

// ── verify_inclusion_proof — ────────────────────────

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
    // Pin the algorithm against a hand-derivable test vector. For
    // leaf 0 in a 4-leaf tree, the inclusion proof is [h(b), h(cd)].
    let ([h0, h1, _h2, _h3], (_h01, h23), root, _) = four_leaf_tree();
    let proof = vec![h1, h23];
    let computed = rfc6962_verify_inclusion(0, 4, &h0, &proof)
        .expect("known-good inclusion proof must walk to the root");
    assert_eq!(computed, root, "RFC 6962 walker drifted");
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
    let mut tampered = h1;
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
    tlog.inclusion_proof.as_mut().unwrap().checkpoint = serde_json::json!({"not-envelope": "oops"});
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

// ── verify_cert_chain — ─────────────────────────────

/// Build a (rcgen::Certificate, DER bytes, KeyPair) triple for a
/// P-384 self-signed root — matches the real Sigstore Fulcio root
/// profile.
fn p384_root_cert(not_before: rcgen::CertificateParams) -> (rcgen::Certificate, Vec<u8>, KeyPair) {
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
    let (real_root_cert, real_root_der, real_root_kp) = p384_root_cert(cert_params_validity(2025));
    let leaf_der = p256_leaf_signed_by(cert_params_validity(2025), &real_root_cert, &real_root_kp);
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

// ── verify_cert_chain — issuer BasicConstraints enforcement ───

/// Helper: build a P-256 cert that is NOT a CA (Sigstore leaf
/// shape), but used as an "issuer" — i.e. its keypair signs
/// another cert beneath it. This is the building block for proving
/// issuer BasicConstraints are enforced.
fn p256_leaf_shaped_cert(params: rcgen::CertificateParams) -> (rcgen::Certificate, KeyPair) {
    let kp = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    // is_ca defaults to NoCa, which is what we want
    let cert = params.self_signed(&kp).unwrap();
    (cert, kp)
}

#[test]
fn rejects_forged_leaf_signed_by_real_leaf_used_as_intermediate() {
    // A legitimate Sigstore leaf cert is not a CA. If its ephemeral
    // key signs a forged child cert, chain validation must reject the
    // real leaf when it appears in issuer position.
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
    let err =
        verify_cert_chain(&chain, &roots, ts_year(2025)).expect_err("CA-flagged leaf must reject");
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
    let root_der_bytes = root_der.clone();
    let chain: Vec<&[u8]> = vec![&leaf_der, &leaf_der, &leaf_der, &root_der_bytes];
    let root = fulcio_root_active_at(2025, root_der);
    let roots: Vec<&FulcioRoot> = vec![&root];
    let err =
        verify_cert_chain(&chain, &roots, ts_year(2025)).expect_err("length-4 chain must reject");
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
    let root_der_bytes = root_der.clone();
    let chain: Vec<&[u8]> = vec![&leaf_der, &intermediate_der, &root_der_bytes];
    let root = fulcio_root_active_at(2025, root_der);
    let roots: Vec<&FulcioRoot> = vec![&root];
    let err =
        verify_cert_chain(&chain, &roots, ts_year(2025)).expect_err("pathLen exceeded must reject");
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
    let err =
        verify_cert_chain(&chain, &roots, ts_year(2025)).expect_err("non-CA anchor must reject");
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

// ── verify_embedded_sct — ───────────────────────────

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
    let leaf_with_sct_der = build_leaf_with_optional_sct(&leaf_kp, &issuer, Some(&sct_list_bytes));

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
            enforce_issuer_constraints(&cert, 0, &format!("fulcio[{i}].cert[{j}]")).unwrap_or_else(
                |e| panic!("vendored Fulcio cert[{j}] in CA[{i}] failed issuer profile: {e}"),
            );
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
fn rejects_set_with_log_id_that_is_neither_hex_nor_base64() {
    // A bundle whose logId.keyId is neither valid hex (Rekor's
    // canonical encoding) nor valid base64 (Sigstore Bundle v0.3
    // protobuf JSON's bytes encoding) must reject — the verifier
    // can't decode it to look up the trust root.
    let (signing_key, _spki_der, _log_id_bytes) = p256_rekor_signing_key();
    let mut tlog = synth_tlog_entry_with_set(&signing_key, "not!hex!", 42, 1700000000, "Zm9vYmFy");
    // Re-encode signed_entry_timestamp because the synth helper
    // already used the (invalid) hex in the SET input.
    tlog.log_id.key_id = "not!hex!".into();
    let err = verify_rekor_set(&tlog, &[], RekorInclusionProofPolicy::RequireSet)
        .expect_err("logId that is neither hex nor base64 must reject");
    match err {
        VerifyError::RekorSet(msg) => assert!(
            msg.contains("neither valid hex") && msg.contains("nor valid base64"),
            "got: {msg}"
        ),
        other => panic!("expected VerifyError::RekorSet, got: {other:?}"),
    }
}

#[test]
fn rejects_bundle_with_missing_payload_hash_field() {
    // Without payloadHash the verifier cannot bind the entry to the
    // envelope payload, so the body is structurally malformed.
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

// ── bundle parser ─────────────────────────────────

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
    let err = parse_bundle_components(b"not-valid-json").expect_err("malformed JSON must reject");
    match err {
        VerifyError::BundleParse(msg) => assert!(msg.contains("not valid JSON")),
        other => panic!("expected BundleParse, got: {other:?}"),
    }
}

// ── identity expectations ─────────────────────────

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
    let san = "https://github.com/lpm-dev/rust-client/.github/workflows/release.yml@refs/tags/v1";
    let der = leaf_with_san_and_issuer(san, Some("https://token.actions.githubusercontent.com"));
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
    let san = "https://github.com/other-org/other-repo/.github/workflows/release.yml@refs/tags/v1";
    let der = leaf_with_san_and_issuer(san, Some("https://token.actions.githubusercontent.com"));
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
    let san = "https://github.com/lpm-dev/rust-client/.github/workflows/release.yml@refs/tags/v1";
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
    let san = "https://github.com/lpm-dev/rust-client/.github/workflows/release.yml@refs/tags/v1";
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

// ── VerifyOptions presets ─────────────────────────

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

// ── find_leaf_issuer_spki ─────────────────────────────────────

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

// ── Placeholder-fixture rejection (defense in depth) ─────────
//
// The committed fixtures at `tests/fixtures/sigstore_bundles/`
// are wire-shape representative but cryptographically fake
// (zero SPKI points, zero signatures, all-zero log_id). The
// contract test asserts they parse cleanly; this complement
// asserts they CANNOT verify against the embedded trust root.
// Closes the observational-only fixture-safety gap: a future
// edit that accidentally turned a placeholder into a real
// signed bundle would break here.

fn load_fixture_bundle(name: &str) -> Vec<u8> {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("sigstore_bundles")
        .join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("read fixture {}: {e}", path.display()))
}

/// Walk every placeholder fixture (positive, non-`invalid`,
/// non-`real-`) and assert the composed verifier rejects with a
/// NON-`BundleParse` error variant. `BundleParse` would mean the
/// parser stopped before reaching crypto — that's the contract-
/// test's territory, not this test's. Reaching the chain / SCT /
/// DSSE / Rekor primitives and being rejected there is the proof
/// that the fixture is inert against the real trust root.
///
/// `real-` named fixtures are captured production bundles that
/// MUST verify; they're covered by `verifies_real_npm_attestation_*`
/// positive tests below and explicitly skipped here.
#[test]
fn placeholder_fixtures_never_verify_against_embedded_trust_root() {
    let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("sigstore_bundles");
    let mut checked = 0;
    for entry in std::fs::read_dir(&dir).expect("fixtures dir") {
        let entry = entry.expect("dirent");
        let name = entry.file_name().to_string_lossy().into_owned();
        if !name.ends_with(".json") || name.contains("invalid") || name.contains("real") {
            continue;
        }
        let body = load_fixture_bundle(&name);
        for opts in [VerifyOptions::npm_attestation(), VerifyOptions::strict()] {
            match verify_sigstore_bundle(&body, &IdentityExpectations::none(), opts) {
                Ok(_) => panic!(
                    "placeholder fixture `{name}` accidentally verified against the real \
                         Sigstore trust root — the fixture is no longer inert. If a real \
                         captured bundle was added, name it without `invalid` and pair it with \
                         a positive test."
                ),
                Err(VerifyError::BundleParse(msg)) => panic!(
                    "placeholder fixture `{name}` rejected at the parser ({msg}) instead of \
                         reaching cryptographic primitives. The contract test's job is to pin \
                         parser behaviour; this test must reach chain/SCT/DSSE/Rekor and be \
                         rejected there. Fix: ensure the fixture has enough structure to parse \
                         (valid base64 rawBytes, well-formed DSSE envelope, non-empty \
                         tlogEntries)."
                ),
                Err(_other) => {
                    checked += 1;
                }
            }
        }
    }
    assert!(
        checked >= 6,
        "expected at least 3 positive fixtures × 2 policies = 6 rejection checks; ran {checked}",
    );
}

// ── Real npm attestation positive path ───────────────────────
//
// Captured-from-production bundle pinned end-to-end against the
// embedded Sigstore trust root. Without this, a `flate2` /
// `x509-parser` / `webpki` upgrade that subtly breaks real-cert
// parsing or chain validation wouldn't fail until production.
//
// Refresh procedure (if axios@1.14.0 is yanked or the trust root
// rotates past its active window):
//
//   curl -fsS \
//     https://registry.npmjs.org/-/npm/v1/attestations/<name>@<version> \
//     -o crates/lpm-cli/tests/fixtures/sigstore_bundles/20-real-npm-<name>-<version>.json
//
// then rename the constants below and re-run the suite.

const REAL_NPM_FIXTURE: &str = "20-real-npm-axios-1.14.0.json";

/// End-to-end positive: a real, production npm attestation
/// verifies against the embedded Sigstore trust root under the
/// npm policy (Either: SET or inclusion proof is enough). This
/// is the load-bearing positive pin against silent breakage of
/// any verifier primitive.
#[test]
fn verifies_real_npm_attestation_for_axios_1_14_0() {
    let body = load_fixture_bundle(REAL_NPM_FIXTURE);
    let result = verify_sigstore_bundle(
        &body,
        &IdentityExpectations::none(),
        VerifyOptions::npm_attestation(),
    );
    let verified = result.unwrap_or_else(|e| {
        panic!(
            "real npm attestation for axios@1.14.0 must verify against the embedded \
                 Sigstore trust root; got error: {e:?}\n\n\
                 If the trust root has rotated past the bundle's integratedTime, refresh \
                 the fixture per the procedure documented above REAL_NPM_FIXTURE."
        )
    });
    assert!(
        verified.log_index > 0,
        "verified bundle must carry a Rekor log_index"
    );
    assert!(
        !verified.log_id.is_empty(),
        "verified bundle must carry a Rekor log_id"
    );
    assert!(
        verified.leaf_cert_sha256.starts_with("sha256-"),
        "leaf_cert_sha256 must be in the `sha256-<hex>` audit form; got: {}",
        verified.leaf_cert_sha256,
    );
}

#[test]
fn rejects_proof_only_bundle_with_malformed_outer_log_index() {
    let body = load_fixture_bundle(REAL_NPM_FIXTURE);
    let mut root: serde_json::Value =
        serde_json::from_slice(&body).expect("fixture must be valid JSON");
    let mut changed_entries = 0;
    for attestation in root["attestations"]
        .as_array_mut()
        .expect("npm wrapper must contain attestations")
    {
        let Some(entries) =
            attestation["bundle"]["verificationMaterial"]["tlogEntries"].as_array_mut()
        else {
            continue;
        };
        for entry in entries {
            entry
                .as_object_mut()
                .expect("tlog entry must be an object")
                .remove("inclusionPromise");
            entry["logIndex"] = serde_json::json!("not-an-index");
            changed_entries += 1;
        }
    }
    assert!(changed_entries > 0, "fixture must contain tlog entries");
    let body = serde_json::to_vec(&root).expect("serialize modified fixture");

    let error = verify_sigstore_bundle(
        &body,
        &IdentityExpectations::none(),
        VerifyOptions::npm_attestation(),
    )
    .expect_err("a verified proof still requires a valid outer Rekor log index");
    match error {
        VerifyError::RekorSet(message) => {
            assert!(message.contains("logIndex"), "unexpected error: {message}");
        }
        other => panic!("expected a Rekor log-index error, got {other:?}"),
    }
}

/// Same fixture, but assert the bundle exercises the v0.3
/// single-cert wire shape inside the npm wrapper. npm currently
/// ships its SLSA provenance attestation in this shape; if it
/// ever migrates to v0.2 chain, the parser must still extract
/// the leaf, and this test will tell us so by failing on the
/// shape pin (the verifier-success assertion guards the path).
#[test]
fn verifies_real_npm_attestation_v0_3_shape() {
    let body = load_fixture_bundle(REAL_NPM_FIXTURE);
    let root: serde_json::Value = serde_json::from_slice(&body).expect("fixture is JSON");
    let inner_v03 = root["attestations"]
        .as_array()
        .expect("npm wrapper")
        .iter()
        .find_map(|a| {
            let b = a.get("bundle")?;
            let media = b.get("mediaType")?.as_str()?;
            if media.contains("v0.3") || media.contains("version=0.3") {
                Some(b)
            } else {
                None
            }
        });
    assert!(
        inner_v03.is_some(),
        "axios attestation must ship at least one v0.3-shaped inner bundle; if npm \
             migrated away from v0.3, refresh the fixture and update this test",
    );
    let inner = inner_v03.unwrap();
    assert!(
        inner["verificationMaterial"]["certificate"]["rawBytes"]
            .as_str()
            .is_some(),
        "v0.3 shape requires `verificationMaterial.certificate.rawBytes`",
    );
    // The composed verifier picks the first parseable inner
    // bundle. With the v0.3 SLSA-provenance shape present, the
    // path exercised here is the v0.3 cert extraction — so a
    // successful verify also proves the v0.3 parser arm works.
    verify_sigstore_bundle(
        &body,
        &IdentityExpectations::none(),
        VerifyOptions::npm_attestation(),
    )
    .expect("v0.3 path inside npm wrapper must verify");
}

/// Exercises the npm `{ attestations: [{ bundle: <inner> }] }`
/// wrapper unwrap path. The verifier scans attestations[*].bundle
/// for the first parseable inner; the axios fixture has two
/// (publish-time publicKey-only + SLSA provenance Fulcio).
#[test]
fn verifies_real_npm_attestation_list_wrapper() {
    let body = load_fixture_bundle(REAL_NPM_FIXTURE);
    let root: serde_json::Value = serde_json::from_slice(&body).expect("fixture is JSON");
    let attestations = root["attestations"]
        .as_array()
        .expect("npm-wrapper fixture must carry top-level `attestations` array");
    assert!(
        !attestations.is_empty(),
        "wrapper must have at least one attestation entry; got {}",
        attestations.len()
    );
    assert!(
        attestations.iter().any(|a| a.get("bundle").is_some()),
        "at least one attestation entry must carry an inner `bundle`",
    );
    verify_sigstore_bundle(
        &body,
        &IdentityExpectations::none(),
        VerifyOptions::npm_attestation(),
    )
    .expect("npm wrapper unwrap must reach a verifiable inner bundle");
}

// ─── Per-primitive microbench ────────────────────────────────
//
// `#[ignore]`-gated; `lpm-cli` is `[[bin]]`-only so a Criterion
// `[[bench]]` harness would have no library API to reach.
//
// Invocation:
//
//   cargo test --release -p lpm-cli --bin lpm-rs \
//     sigstore_verify::tests::microbench_per_step_primitive_timings \
//     -- --ignored --nocapture
//
// Reports mean / p50 / p95 / p99 per primitive over a 50-warmup
// + 200-measure sample. No assertions — measurement only.

#[test]
#[ignore = "perf microbench — run via `cargo test --release ... -- --ignored --nocapture`"]
fn microbench_per_step_primitive_timings() {
    use std::time::{Duration, Instant};

    const WARMUP_ITERS: usize = 50;
    const MEASURE_ITERS: usize = 200;

    fn measure<F: FnMut()>(label: &str, mut f: F) {
        for _ in 0..WARMUP_ITERS {
            f();
        }
        let mut samples = Vec::with_capacity(MEASURE_ITERS);
        for _ in 0..MEASURE_ITERS {
            let t0 = Instant::now();
            f();
            samples.push(t0.elapsed());
        }
        samples.sort();
        let mean: Duration = samples.iter().sum::<Duration>() / (samples.len() as u32);
        let p50 = samples[samples.len() / 2];
        let p95 = samples[(samples.len() * 95) / 100];
        let p99 = samples[(samples.len() * 99) / 100];
        println!(
            "  {label:<32} mean={:>8.2}µs  p50={:>8.2}µs  p95={:>8.2}µs  p99={:>8.2}µs",
            mean.as_secs_f64() * 1_000_000.0,
            p50.as_secs_f64() * 1_000_000.0,
            p95.as_secs_f64() * 1_000_000.0,
            p99.as_secs_f64() * 1_000_000.0,
        );
    }

    println!();
    println!("sigstore_verify per-primitive microbench:");
    println!("  warmup={WARMUP_ITERS}  measure={MEASURE_ITERS}  build=release");

    // ── verify_dsse — DSSE envelope signature ────────────────
    {
        let (envelope, leaf_der) = build_signed_dsse_envelope_with_self_signed_leaf();
        let (_, leaf_parsed) = X509Certificate::from_der(&leaf_der).unwrap();
        measure("verify_dsse", || {
            verify_dsse(&envelope, &leaf_parsed).expect("dsse must verify under bench setup");
        });
    }

    // ── verify_rekor_set — SET signature + canonicalization ──
    {
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
            inclusion_promise: Some(crate::sigstore::RekorInclusionPromise {
                signed_entry_timestamp: set_b64,
            }),
            inclusion_proof: None,
            verification: None,
            canonicalized_body: canonicalized_body.into(),
        };
        let key = rekor_key_active_around(log_id_bytes, spki_der, integrated_time);
        let keys = std::slice::from_ref(&key);
        measure("verify_rekor_set", || {
            verify_rekor_set(&tlog, keys, RekorInclusionProofPolicy::RequireSet)
                .expect("rekor set must verify under bench setup");
        });
    }

    // ── verify_embedded_sct — precert reconstruction + ECDSA ──
    {
        let bundle = build_signed_sct_bundle_for_bench();
        let (_, leaf_parsed) = X509Certificate::from_der(&bundle.leaf_with_sct_der).unwrap();
        let _ = leaf_parsed; // shape sanity
        let keys = std::slice::from_ref(&bundle.ct_log_key);
        measure("verify_embedded_sct", || {
            verify_embedded_sct(
                &bundle.leaf_with_sct_der,
                &bundle.issuer_spki,
                keys,
                ts_year(2025),
            )
            .expect("embedded SCT must verify under bench setup");
        });
    }

    // ── verify_inclusion_proof — Merkle walk + checkpoint ECDSA ──
    {
        let (signing_key, spki_der, log_id_bytes) = p256_rekor_signing_key();
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
        let key = rekor_key_active_around(log_id_bytes, spki_der, integrated_time);
        let keys = std::slice::from_ref(&key);
        measure("verify_inclusion_proof", || {
            verify_inclusion_proof(&tlog, keys)
                .expect("inclusion proof must verify under bench setup");
        });
    }

    // ── parse_bundle_components — JSON parse + base64 + serde ──
    {
        let leaf = b"leaf-der-stand-in";
        let bundle = synth_bundle_v03(leaf, &dummy_dsse_envelope(), &dummy_tlog_entry());
        let body = serde_json::to_vec(&bundle).unwrap();
        measure("parse_bundle_components", || {
            parse_bundle_components(&body).expect("parse must succeed under bench setup");
        });
    }

    println!();
    println!("  baseline (microbench only — wall-clock from `lpm install` is the");
    println!("  authoritative perf gate).");
    println!();
}

/// Build a DSSE envelope signed by a freshly-generated leaf
/// cert's P-256 key. Returns `(envelope, leaf_der)` so the
/// bench can hold both. Mirrors what
/// `verifies_raw_r_s_signature_against_matching_leaf_cert`
/// constructs inline.
fn build_signed_dsse_envelope_with_self_signed_leaf() -> (DsseEnvelope, Vec<u8>) {
    let leaf_kp = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let mut params = cert_params_validity(2025);
    params.subject_alt_names = vec![rcgen::SanType::URI(
        rcgen::Ia5String::try_from("https://example.invalid/bench".to_string()).unwrap(),
    )];
    let cert = params.self_signed(&leaf_kp).unwrap();
    let leaf_der = cert.der().to_vec();

    let payload_bytes = b"{\"_type\":\"https://in-toto.io/Statement/v1\"}".to_vec();
    let payload_type = "application/vnd.in-toto+json";
    let pae_bytes = pae(payload_type, &payload_bytes);

    let pkcs8 = leaf_kp.serialize_der();
    let signing = p256::ecdsa::SigningKey::from_pkcs8_der(&pkcs8).unwrap();
    let signature: Signature = signing.sign(&pae_bytes);
    let sig_b64 = BASE64.encode(signature.to_bytes().as_slice());

    let envelope = DsseEnvelope {
        payload_type: payload_type.to_string(),
        payload: BASE64.encode(&payload_bytes),
        signatures: vec![DsseSignature {
            keyid: String::new(),
            sig: sig_b64,
        }],
    };
    (envelope, leaf_der)
}

/// Bench-time SCT setup: build a leaf with one valid embedded
/// SCT signed by a synthetic CT-log key. Returns the leaf DER,
/// the issuer's SPKI, and the CT log key to pin. Mirrors
/// `verifies_valid_embedded_sct_against_pinned_ct_log_key`.
struct BenchSctBundle {
    leaf_with_sct_der: Vec<u8>,
    issuer_spki: Vec<u8>,
    ct_log_key: CtLogKey,
}

fn build_signed_sct_bundle_for_bench() -> BenchSctBundle {
    let issuer = fresh_sct_issuer();
    let leaf_kp = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let issuer_spki = issuer_spki_from_cert(&issuer.cert);
    let issuer_key_hash = Sha256::digest(&issuer_spki).to_vec();
    let (ct_signing_key, ct_log_key) = synth_ct_log_key(2025);
    let timestamp_ms = 1_700_000_000_000u64;
    let sct_extensions: &[u8] = &[];

    let leaf_without_sct_der = build_leaf_with_optional_sct(&leaf_kp, &issuer, None);
    let (_, parsed_without_sct) = X509Certificate::from_der(&leaf_without_sct_der).unwrap();
    let precert_tbs = parsed_without_sct.tbs_certificate.as_ref().to_vec();

    let mut signed_input = Vec::new();
    signed_input.push(0u8);
    signed_input.push(0u8);
    signed_input.extend_from_slice(&timestamp_ms.to_be_bytes());
    signed_input.extend_from_slice(&1u16.to_be_bytes());
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
        4,
        3,
        &sig_der,
    );
    let sct_list = encode_sct_list(&[&serialized_sct]);
    let leaf_with_sct_der = build_leaf_with_optional_sct(&leaf_kp, &issuer, Some(&sct_list));

    BenchSctBundle {
        leaf_with_sct_der,
        issuer_spki,
        ct_log_key,
    }
}
