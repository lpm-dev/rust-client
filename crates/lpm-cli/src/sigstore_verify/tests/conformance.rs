//! Every DSSE case vendored from the Sigstore conformance suite, through
//! the composed verifier as the suite runs it: a case whose name ends in
//! `_fail` must be refused and every other must verify, under both of
//! LPM's policies.

use super::super::trust_root::EMBEDDED_TRUST_ROOT_JSON;
use super::super::{
    IdentityExpectations, TrustRoot, VerifyError, VerifyOptions,
    bundle::verify_sigstore_bundle_with, verify_inclusion_proof,
};
use std::path::PathBuf;

/// The identity the suite verifies its bundles against.
fn conformance_identity() -> IdentityExpectations {
    IdentityExpectations {
        expected_issuer: Some("https://token.actions.githubusercontent.com".into()),
        expected_san_uri_prefix: Some(
            "https://github.com/sigstore-conformance/extremely-dangerous-public-oidc-beacon/"
                .into(),
        ),
        expected_workflow_path: Some(
            ".github/workflows/extremely-dangerous-oidc-beacon.yml".into(),
        ),
    }
}

#[test]
fn vendored_dsse_conformance_cases_verify_or_fail_as_the_suite_expects() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sigstore_conformance");
    let mut cases: Vec<PathBuf> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.is_dir())
        .collect();
    cases.sort();

    let mut checked = 0;
    for case in cases {
        let name = case.file_name().unwrap().to_string_lossy().into_owned();
        let bundle = std::fs::read(case.join("bundle.sigstore.json")).unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&bundle).unwrap();
        if parsed.get("dsseEnvelope").is_none() {
            continue;
        }
        // A case without its own trust root was signed against production.
        let trust = match std::fs::read(case.join("trusted_root.json")) {
            Ok(bytes) => TrustRoot::parse(&bytes).unwrap(),
            Err(_) => TrustRoot::parse(EMBEDDED_TRUST_ROOT_JSON).unwrap(),
        };
        for options in [VerifyOptions::npm_attestation(), VerifyOptions::strict()] {
            let outcome =
                verify_sigstore_bundle_with(&bundle, &conformance_identity(), options, &trust);
            if name.ends_with("_fail") {
                assert!(outcome.is_err(), "{name} must be refused under {options:?}");
            } else if let Err(error) = outcome {
                panic!("{name} must verify under {options:?}: {error}");
            }
        }
        checked += 1;
    }
    assert!(checked >= 10, "only {checked} DSSE cases were found");
}

#[test]
fn rekor_v1_checkpoints_from_sigstores_conformance_cases() {
    let trust = TrustRoot::parse(EMBEDDED_TRUST_ROOT_JSON).unwrap();
    let entry = |case: &str| -> crate::sigstore::TlogEntry {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/sigstore_conformance")
            .join(case)
            .join("bundle.sigstore.json");
        let bundle: serde_json::Value =
            serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        serde_json::from_value(bundle["verificationMaterial"]["tlogEntries"][0].clone()).unwrap()
    };

    verify_inclusion_proof(&entry("happy-path-v0.3"), &trust.rekor_keys).unwrap();
    for (case, expected) in [
        ("checkpoint-bad-keyhint_fail", "no signature from the log"),
        (
            "checkpoint-wrong-roothash_fail",
            "disagrees with signed checkpoint",
        ),
        ("invalid-checkpoint-signature_fail", "did not verify"),
    ] {
        match verify_inclusion_proof(&entry(case), &trust.rekor_keys) {
            Err(VerifyError::InclusionProof(why)) => {
                assert!(why.contains(expected), "{case}: {why}");
            }
            other => panic!("{case}: expected a refused inclusion proof, got {other:?}"),
        }
    }
}
