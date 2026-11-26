//! Rekor v2 bundles: a `hashedrekord` 0.0.2 entry over the DSSE
//! pre-authentication encoding, a C2SP signed-note checkpoint, and an RFC
//! 3161 timestamp in place of an integrated time.

use super::super::checkpoint::{LogStyle, log_name, verify_checkpoint};
use super::super::inclusion::verify_rekor_v2_inclusion_proof;
use super::super::rekor_set::decode_log_id;
use super::super::trust_root::ValidityWindow;
use super::super::{
    IdentityExpectations, RekorKey, TrustRoot, VerifiedProvenance, VerifyError, VerifyOptions,
    bundle::verify_sigstore_bundle_with,
};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use ed25519_dalek::Signer as _;
use lpm_common::Timestamp;
use sha2::{Digest, Sha256};
use std::path::PathBuf;

const DSSE_CASE: &str = "rekor2-dsse-happy-path";

fn conformance_file(case: &str, file: &str) -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/sigstore_conformance")
        .join(case)
        .join(file);
    std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

fn conformance_bundle(case: &str) -> serde_json::Value {
    serde_json::from_slice(&conformance_file(case, "bundle.sigstore.json")).unwrap()
}

fn conformance_trust(case: &str) -> TrustRoot {
    TrustRoot::parse(&conformance_file(case, "trusted_root.json")).unwrap()
}

fn verify(
    bundle: &serde_json::Value,
    trust: &TrustRoot,
    options: VerifyOptions,
) -> Result<VerifiedProvenance, VerifyError> {
    verify_sigstore_bundle_with(
        &serde_json::to_vec(bundle).unwrap(),
        &IdentityExpectations::none(),
        options,
        trust,
    )
}

fn verify_case(case: &str) -> Result<VerifiedProvenance, VerifyError> {
    verify(
        &conformance_bundle(case),
        &conformance_trust(case),
        VerifyOptions::npm_attestation(),
    )
}

fn tlog_entry(bundle: &serde_json::Value) -> crate::sigstore::TlogEntry {
    serde_json::from_value(bundle["verificationMaterial"]["tlogEntries"][0].clone()).unwrap()
}

/// The trust root's log for a conformance bundle's entry.
fn entry_log<'a>(trust: &'a TrustRoot, entry: &crate::sigstore::TlogEntry) -> &'a RekorKey {
    let log_id = decode_log_id(&entry.log_id.key_id).unwrap();
    trust
        .rekor_keys
        .iter()
        .find(|log| log.log_id == log_id)
        .expect("the case's trust root holds its log")
}

#[test]
fn a_rekor_v2_dsse_bundle_verifies_under_every_policy() {
    let bundle = conformance_bundle(DSSE_CASE);
    let trust = conformance_trust(DSSE_CASE);
    for options in [VerifyOptions::npm_attestation(), VerifyOptions::strict()] {
        let verified = verify(&bundle, &trust, options).unwrap();
        assert_eq!(
            Timestamp::from(verified.signed_at).to_rfc3339_seconds(),
            "2026-05-13T19:23:33Z",
            "the signing time is the RFC 3161 timestamp's"
        );
        assert_eq!(verified.log_index, 4_026_478);
        assert_eq!(
            verified.log_id,
            "09OnDKEw7/hpZiYVPoTRzRbglHk0sylsUovegnRUlJY="
        );
        assert_eq!(
            verified.statement["subject"][0]["name"],
            serde_json::json!("a.txt")
        );
    }
}

#[test]
fn a_rekor_v2_bundle_whose_envelope_signature_is_not_the_certificates_is_refused() {
    let refused = verify_case("rekor2-dsse-invalid-sig_fail").unwrap_err();
    assert!(
        matches!(refused, VerifyError::DsseSignature(_)),
        "{refused:?}"
    );
}

#[test]
fn a_rekor_v2_bundle_whose_envelope_is_not_the_logged_one_is_refused() {
    let refused = verify_case("rekor2-dsse-mismatch-envelope_fail").unwrap_err();
    assert!(
        matches!(
            refused,
            VerifyError::RekorBodyMismatch {
                field: "digest",
                ..
            }
        ),
        "{refused:?}"
    );
}

#[test]
fn a_rekor_v2_bundle_whose_signature_is_not_the_logged_one_is_refused() {
    let refused = verify_case("rekor2-dsse-mismatch-sig_fail").unwrap_err();
    assert!(
        matches!(
            refused,
            VerifyError::RekorBodyMismatch {
                field: "signature",
                ..
            }
        ),
        "{refused:?}"
    );
}

#[test]
fn a_rekor_v2_bundle_needs_a_timestamp() {
    let mut bundle = conformance_bundle(DSSE_CASE);
    bundle["verificationMaterial"]
        .as_object_mut()
        .unwrap()
        .remove("timestampVerificationData");
    let refused = verify(
        &bundle,
        &conformance_trust(DSSE_CASE),
        VerifyOptions::npm_attestation(),
    )
    .unwrap_err();
    assert!(
        matches!(&refused, VerifyError::Timestamp(why) if why.contains("no RFC 3161 timestamp")),
        "{refused:?}"
    );
}

#[test]
fn a_rekor_v2_bundle_timestamped_only_by_an_unknown_authority_needs_newer_trust_material() {
    let mut trust = conformance_trust(DSSE_CASE);
    trust.timestamp_authorities.clear();
    let refused = verify(
        &conformance_bundle(DSSE_CASE),
        &trust,
        VerifyOptions::npm_attestation(),
    )
    .unwrap_err();
    assert!(refused.is_missing_trust_material(), "{refused:?}");
}

#[test]
fn a_rekor_v2_bundle_needs_an_inclusion_proof_under_every_policy() {
    let mut bundle = conformance_bundle(DSSE_CASE);
    bundle["verificationMaterial"]["tlogEntries"][0]
        .as_object_mut()
        .unwrap()
        .remove("inclusionProof");
    let trust = conformance_trust(DSSE_CASE);
    for options in [VerifyOptions::npm_attestation(), VerifyOptions::strict()] {
        let refused = verify(&bundle, &trust, options).unwrap_err();
        assert!(
            matches!(refused, VerifyError::InclusionProofMissing),
            "{refused:?}"
        );
    }

    let case = "rekor2-no-inclusion-proof_fail";
    let entry = tlog_entry(&conformance_bundle(case));
    let trust = conformance_trust(case);
    let refused = verify_rekor_v2_inclusion_proof(&entry, entry_log(&trust, &entry)).unwrap_err();
    assert!(
        matches!(refused, VerifyError::InclusionProofMissing),
        "{refused:?}"
    );
}

#[test]
fn a_rekor_v2_entry_from_a_log_outside_the_trust_root_needs_newer_trust_material() {
    let bundle = conformance_bundle(DSSE_CASE);
    let entry = tlog_entry(&bundle);
    let mut trust = conformance_trust(DSSE_CASE);
    let log_id = decode_log_id(&entry.log_id.key_id).unwrap();
    trust.rekor_keys.retain(|log| log.log_id != log_id);
    let refused = verify(&bundle, &trust, VerifyOptions::npm_attestation()).unwrap_err();
    assert!(
        matches!(
            refused,
            VerifyError::MissingTrustMaterial {
                check: "Rekor inclusion proof",
                ..
            }
        ),
        "{refused:?}"
    );
}

#[test]
fn a_rekor_v2_entry_signed_outside_its_logs_validity_window_is_refused() {
    let bundle = conformance_bundle(DSSE_CASE);
    let entry = tlog_entry(&bundle);
    let mut trust = conformance_trust(DSSE_CASE);
    let log_id = decode_log_id(&entry.log_id.key_id).unwrap();
    for log in trust
        .rekor_keys
        .iter_mut()
        .filter(|log| log.log_id == log_id)
    {
        log.valid_for = ValidityWindow {
            start: Timestamp::parse_rfc3339("2025-01-01T00:00:00Z").unwrap(),
            end: Some(Timestamp::parse_rfc3339("2026-01-01T00:00:00Z").unwrap()),
        };
    }
    let refused = verify(&bundle, &trust, VerifyOptions::npm_attestation()).unwrap_err();
    assert!(refused.is_missing_trust_material(), "{refused:?}");
}

#[test]
fn a_rekor_v2_entry_is_hashed_as_logged_not_as_reserialized() {
    // The same values with different whitespace are a different leaf.
    let mut bundle = conformance_bundle(DSSE_CASE);
    let entry = &mut bundle["verificationMaterial"]["tlogEntries"][0];
    let body: serde_json::Value = serde_json::from_slice(
        &BASE64
            .decode(entry["canonicalizedBody"].as_str().unwrap())
            .unwrap(),
    )
    .unwrap();
    entry["canonicalizedBody"] =
        serde_json::json!(BASE64.encode(serde_json::to_vec_pretty(&body).unwrap()));
    let refused = verify(
        &bundle,
        &conformance_trust(DSSE_CASE),
        VerifyOptions::npm_attestation(),
    )
    .unwrap_err();
    assert!(
        matches!(&refused, VerifyError::InclusionProof(why) if why.contains("Merkle walk root")),
        "{refused:?}"
    );
}

#[test]
fn a_bundle_whose_named_kind_disagrees_with_its_entry_is_refused() {
    let mut bundle = conformance_bundle(DSSE_CASE);
    bundle["verificationMaterial"]["tlogEntries"][0]["kindVersion"] =
        serde_json::json!({"kind": "dsse", "version": "0.0.1"});
    let refused = verify(
        &bundle,
        &conformance_trust(DSSE_CASE),
        VerifyOptions::npm_attestation(),
    )
    .unwrap_err();
    assert!(
        matches!(&refused, VerifyError::RekorBodyMalformed(why) if why.contains("names the entry")),
        "{refused:?}"
    );
}

#[test]
fn checkpoints_from_sigstores_conformance_cases() {
    let verifies = [
        "rekor2-dsse-happy-path",
        "rekor2-checkpoint-cosigned",
        "rekor2-checkpoint-multiple-cosigs",
        "rekor2-checkpoint-origin-not-first",
        "rekor2-checkpoint-two-sigs-cosigned",
        "rekor2-checkpoint-two-sigs-from-origin",
    ];
    for case in verifies {
        let entry = tlog_entry(&conformance_bundle(case));
        let trust = conformance_trust(case);
        verify_rekor_v2_inclusion_proof(&entry, entry_log(&trust, &entry))
            .unwrap_or_else(|e| panic!("{case}: {e}"));
    }

    let refused = [
        (
            "rekor2-checkpoint-missing-log-signature_fail",
            "signature lines",
        ),
        ("rekor2-checkpoint-missing-origin_fail", "did not verify"),
        ("rekor2-checkpoint-missing-root-hash_fail", "did not verify"),
        ("rekor2-checkpoint-missing-size_fail", "did not verify"),
        (
            "rekor2-checkpoint-no-matching-signature_fail",
            "no signature from the log",
        ),
    ];
    for (case, expected) in refused {
        let entry = tlog_entry(&conformance_bundle(case));
        let trust = conformance_trust(case);
        let why = match verify_rekor_v2_inclusion_proof(&entry, entry_log(&trust, &entry)) {
            Err(VerifyError::InclusionProof(why)) => why,
            other => panic!("{case}: expected a refused inclusion proof, got {other:?}"),
        };
        assert!(why.contains(expected), "{case}: {why}");
    }
}

// ─── Synthesized checkpoints ─────────────────────────────────────

const LOG_URL: &str = "https://log.test.example";
const LOG_NAME: &str = "log.test.example";
const ROOT_HASH: [u8; 32] = [0x11; 32];

struct TestLog {
    key: ed25519_dalek::SigningKey,
    trusted: RekorKey,
}

fn test_log(seed: u8) -> TestLog {
    let key = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
    let mut spki = vec![
        0x30, 0x2A, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];
    spki.extend_from_slice(key.verifying_key().as_bytes());
    let trusted = RekorKey {
        log_id: Sha256::digest(&spki).to_vec(),
        spki_der: spki,
        valid_for: ValidityWindow {
            start: Timestamp::parse_rfc3339("2020-01-01T00:00:00Z").unwrap(),
            end: None,
        },
        base_url: LOG_URL.into(),
        checkpoint_key_id: None,
    };
    TestLog { key, trusted }
}

impl TestLog {
    fn key_id(&self, name: &str) -> [u8; 4] {
        let mut hasher = Sha256::new();
        hasher.update(name.as_bytes());
        hasher.update([b'\n', 0x01]);
        hasher.update(self.key.verifying_key().as_bytes());
        let digest = hasher.finalize();
        [digest[0], digest[1], digest[2], digest[3]]
    }

    fn signature_line(&self, name: &str, text: &str) -> String {
        let mut signed = self.key_id(name).to_vec();
        signed.extend_from_slice(&self.key.sign(text.as_bytes()).to_bytes());
        format!("\u{2014} {name} {}\n", BASE64.encode(signed))
    }
}

fn checkpoint_text(origin: &str, size: &str) -> String {
    format!("{origin}\n{size}\n{}\n", BASE64.encode(ROOT_HASH))
}

fn witness_line(name: &str) -> String {
    format!(
        "\u{2014} {name} {}\n",
        BASE64.encode([0x42; 4 + 8 + 64].as_slice())
    )
}

#[test]
fn a_checkpoint_signed_by_the_log_verifies_among_witness_signatures() {
    let log = test_log(1);
    let text = checkpoint_text(LOG_NAME, "736");
    let envelope = format!(
        "{text}\n{}{}{}",
        witness_line("witness.example/one"),
        log.signature_line(LOG_NAME, &text),
        witness_line("witness.example/two"),
    );
    let checkpoint = verify_checkpoint(&envelope, &log.trusted, LogStyle::RekorV2).unwrap();
    assert_eq!(checkpoint.size, 736);
    assert_eq!(checkpoint.root_hash, ROOT_HASH);
}

#[test]
fn a_bad_signature_under_the_logs_name_and_key_id_refuses_the_checkpoint() {
    let log = test_log(1);
    let text = checkpoint_text(LOG_NAME, "736");
    let forged = test_log(2);
    let mut signed = log.key_id(LOG_NAME).to_vec();
    signed.extend_from_slice(&forged.key.sign(text.as_bytes()).to_bytes());
    let envelope = format!(
        "{text}\n\u{2014} {LOG_NAME} {}\n{}",
        BASE64.encode(signed),
        log.signature_line(LOG_NAME, &text),
    );
    let why = verify_checkpoint(&envelope, &log.trusted, LogStyle::RekorV2).unwrap_err();
    assert!(why.contains("did not verify"), "{why}");
}

#[test]
fn signatures_under_another_name_or_key_id_do_not_count() {
    let log = test_log(1);
    let text = checkpoint_text(LOG_NAME, "736");
    let other_name = log.signature_line("other.test.example", &text);
    let other_key = test_log(2).signature_line(LOG_NAME, &text);
    let envelope = format!("{text}\n{other_name}{other_key}");
    let why = verify_checkpoint(&envelope, &log.trusted, LogStyle::RekorV2).unwrap_err();
    assert!(why.contains("no signature from the log"), "{why}");
}

#[test]
fn a_rekor_v2_checkpoint_for_another_origin_is_refused() {
    let log = test_log(1);
    for origin in [
        "another.test.example".to_string(),
        format!("{LOG_NAME} - 1193050959916656506"),
    ] {
        let text = checkpoint_text(&origin, "736");
        let envelope = format!("{text}\n{}", log.signature_line(LOG_NAME, &text));
        let why = verify_checkpoint(&envelope, &log.trusted, LogStyle::RekorV2).unwrap_err();
        assert!(why.contains("is not the log"), "{origin}: {why}");
    }
}

#[test]
fn a_rekor_v1_checkpoint_counts_the_signature_with_the_logs_key_id_under_any_name() {
    // Rekor v1 names itself as it likes, here with a port, over an origin
    // naming its shard; its own verifier finds its signature by key ID.
    use p256::pkcs8::EncodePublicKey;
    let key = p256::ecdsa::SigningKey::from_slice(&[3; 32]).unwrap();
    let spki = p256::ecdsa::VerifyingKey::from(&key)
        .to_public_key_der()
        .unwrap()
        .as_bytes()
        .to_vec();
    let log = RekorKey {
        log_id: Sha256::digest(&spki).to_vec(),
        spki_der: spki,
        valid_for: ValidityWindow {
            start: Timestamp::parse_rfc3339("2020-01-01T00:00:00Z").unwrap(),
            end: None,
        },
        base_url: "http://localhost:8000".into(),
        checkpoint_key_id: None,
    };
    let text = checkpoint_text("localhost:8000 - 124190645164477", "736");
    let signature: p256::ecdsa::Signature =
        ecdsa::signature::hazmat::PrehashSigner::sign_prehash(&key, &Sha256::digest(&text))
            .unwrap();
    let mut signed = log.log_id[..4].to_vec();
    signed.extend_from_slice(signature.to_der().as_bytes());
    let envelope = format!(
        "{text}\n{}\u{2014} localhost:8000 {}\n",
        witness_line("witness.example"),
        BASE64.encode(signed)
    );

    let checkpoint = verify_checkpoint(&envelope, &log, LogStyle::RekorV1).unwrap();
    assert_eq!(checkpoint.size, 736);
    let why = verify_checkpoint(&envelope, &log, LogStyle::RekorV2).unwrap_err();
    assert!(why.contains("no signature from the log"), "{why}");
}

#[test]
fn malformed_checkpoints_are_refused() {
    let log = test_log(1);
    let signed = |text: &str| format!("{text}\n{}", log.signature_line(LOG_NAME, text));
    let cases = [
        (signed(&checkpoint_text(LOG_NAME, "0736")), "tree size"),
        (signed(&checkpoint_text(LOG_NAME, "-1")), "tree size"),
        (
            signed(&format!("{LOG_NAME}\n736\n{}\n", BASE64.encode([1u8; 20]))),
            "root hash",
        ),
        (signed(&format!("{LOG_NAME}\r\n736\n")), "control character"),
        (
            format!(
                "{}\n{}",
                checkpoint_text(LOG_NAME, "736"),
                "- log.test.example AAAA\n"
            ),
            "doesn't start with",
        ),
        (checkpoint_text(LOG_NAME, "736"), "no blank line"),
    ];
    for (envelope, expected) in cases {
        let why = verify_checkpoint(&envelope, &log.trusted, LogStyle::RekorV2).unwrap_err();
        assert!(why.contains(expected), "{expected}: {why}");
    }

    let text = checkpoint_text(LOG_NAME, "736");
    let many = format!(
        "{text}\n{}{}",
        witness_line("witness.example").repeat(100),
        log.signature_line(LOG_NAME, &text)
    );
    let why = verify_checkpoint(&many, &log.trusted, LogStyle::RekorV2).unwrap_err();
    assert!(why.contains("more than 100 signatures"), "{why}");
}

#[test]
fn a_log_is_named_by_the_host_of_its_base_url() {
    assert_eq!(
        log_name("https://log2025-1.rekor.sigstore.dev").as_deref(),
        Some("log2025-1.rekor.sigstore.dev")
    );
    assert_eq!(
        log_name("https://rekor.sigstore.dev/").as_deref(),
        Some("rekor.sigstore.dev")
    );
    assert_eq!(
        log_name("log.test.example/path").as_deref(),
        Some("log.test.example")
    );
    assert_eq!(log_name(""), None);
}
