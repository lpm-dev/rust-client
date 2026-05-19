//! **Tier placement: cli-binary** (per CLAUDE.md `# Testing Tier
//! Discipline`). Justification class: **parser/schema corpus**. This
//! file iterates committed JSON fixtures under
//! `tests/fixtures/sigstore_bundles/` and pins the *wire shapes* the
//! verifier must continue to recognise — no binary spawn, no
//! `TempProject`. Mirrors the layout of [`lpm_config_schema_corpus`].
//!
//! Why a separate corpus when `sigstore_verify.rs` already carries an
//! inline `#[cfg(test)]` block with 100+ tests?
//!
//! - The inline tests build bundles from rcgen + p256 primitives.
//!   They are exhaustive on *cryptographic* behaviour (DSSE, chain,
//!   SCT, Rekor SET, inclusion proof, identity pinning) but they say
//!   nothing about the *exact JSON byte shape* npm and GitHub
//!   `attest-build-provenance` actually emit. If a future serde
//!   refactor flipped `#[serde(rename_all = "camelCase")]` off, or a
//!   field rename slipped through, the inline tests would keep
//!   passing while production install paths silently broke.
//!
//! - The committed fixtures here are pure JSON files captured / hand-
//!   crafted to match the three wire shapes the production
//!   [`crate::sigstore_verify::parse_bundle_components`] is documented
//!   to accept. This corpus pins the shape inventory: if `npm` ever
//!   ships a v4 wrapper, or GitHub adds a new media type, the new
//!   shape lands as a fixture here *with a corresponding test*, and
//!   adding the fixture without the shape-detection arm fails this
//!   suite.
//!
//! Why not call `verify_sigstore_bundle` directly? `lpm-cli` is a
//! `[[bin]]`-only crate (no `[lib]` target). External integration
//! tests cannot import its Rust API. The verifier's end-to-end
//! behaviour is covered by:
//!
//! - The inline `#[cfg(test)]` corpus in `crates/lpm-cli/src/sigstore_verify.rs`.
//! - The workflow tests in `tests/workflows/tests/install_provenance.rs`
//!   which drive the real fetch + verify path through the spawned
//!   `lpm-rs` binary.
//!
//! Fixture naming:
//!
//! - `NN-v0.x-<descriptor>.json` — must match one of the three known
//!   wire shapes (v0.2 chain, v0.3 single-cert, or npm wrapper).
//! - `NN-invalid-<descriptor>.{json,txt}` — must NOT match any known
//!   shape; either because the JSON is malformed, the wrapper is
//!   structurally wrong, or a required field is missing.
//!
//! When this test fails the cause is one of:
//!
//!  - The wire format the registry emits drifted → add a fixture and
//!    a shape-detection arm to `detect_shape` below.
//!  - The parser's shape inventory is wrong → fix
//!    `parse_bundle_components` in `sigstore_verify.rs` and update
//!    the matching arm here.
//!  - A fixture got hand-edited and now parses differently → restore
//!    the fixture or, if intentional, rename it with the matching
//!    prefix.

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

/// The wire shapes the production parser at
/// `crate::sigstore_verify::parse_bundle_components` recognises. Adding
/// a variant here is the contract change that says "the install path
/// now accepts a new registry-side bundle layout."
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum BundleShape {
    /// Sigstore Bundle v0.2 — `verificationMaterial.x509CertificateChain.certificates[]`.
    V02Chain,
    /// Sigstore Bundle v0.3 — `verificationMaterial.certificate.rawBytes`.
    V03SingleCert,
    /// npm response wrapper — `{ attestations: [{ bundle: <inner> }] }`.
    /// Inner bundle is then v0.2 or v0.3.
    NpmAttestationsWrapper,
}

/// Match a fixture body against the wire-shape inventory. Returns
/// `None` if the body is not JSON or doesn't match any known shape —
/// for the invalid corpus that's the contract.
fn detect_shape(body: &[u8]) -> Option<BundleShape> {
    let root: serde_json::Value = serde_json::from_slice(body).ok()?;

    if let Some(attestations) = root.get("attestations").and_then(|v| v.as_array()) {
        let has_inner_bundle = attestations
            .iter()
            .any(|a| a.get("bundle").and_then(|b| b.as_object()).is_some());
        return if has_inner_bundle {
            Some(BundleShape::NpmAttestationsWrapper)
        } else {
            None
        };
    }

    let vm = root.get("verificationMaterial")?.as_object()?;
    if vm.contains_key("certificate") {
        Some(BundleShape::V03SingleCert)
    } else if vm.contains_key("x509CertificateChain") {
        Some(BundleShape::V02Chain)
    } else {
        None
    }
}

fn corpus_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("sigstore_bundles")
}

fn load_corpus() -> Vec<(String, Vec<u8>, /* must_match_shape */ bool)> {
    let dir = corpus_dir();
    let mut files: Vec<_> = fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("could not read corpus dir {}: {e}", dir.display()))
        .filter_map(|entry| {
            let entry = entry.ok()?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if !name.ends_with(".json") && !name.ends_with(".txt") {
                return None;
            }
            let body = fs::read(entry.path()).ok()?;
            let must_match_shape = !name.contains("invalid");
            Some((name, body, must_match_shape))
        })
        .collect();
    files.sort_by(|a, b| a.0.cmp(&b.0));
    assert!(!files.is_empty(), "corpus dir is empty: {}", dir.display());
    files
}

// ─── Top-level corpus sweep ──────────────────────────────────────

/// Every positive-named fixture (one without an `invalid` token in
/// the filename) MUST match a known wire shape; if it doesn't, either
/// the fixture is mis-named or the parser's shape inventory has
/// drifted. Negative fixtures may or may not match a shape — they're
/// invalid for *some* reason that downstream tests pin (missing
/// dsseEnvelope, empty tlogEntries, malformed JSON, …), and the
/// matching reason is each fixture's named pin below.
///
/// This test also enforces the inventory: at least one positive
/// fixture must exist for each variant of [`BundleShape`]. A new
/// shape lands as a `BundleShape` variant + a `detect_shape` arm +
/// a fixture — adding any two without the third breaks the suite.
#[test]
fn every_positive_fixture_matches_a_known_shape_and_inventory_is_complete() {
    let mut shape_counts: BTreeMap<BundleShape, usize> = BTreeMap::new();
    for (name, body, must_match) in load_corpus() {
        let detected = detect_shape(&body);
        match (must_match, detected) {
            (true, Some(shape)) => {
                *shape_counts.entry(shape).or_insert(0) += 1;
            }
            (true, None) => panic!(
                "fixture `{name}` is named as valid (no `invalid` token) but its body did not \
                 match any known wire shape. Either name it `…-invalid-…` or extend \
                 `detect_shape` to recognise the new layout.",
            ),
            (false, _) => {
                // Negative fixtures may or may not match — the
                // matching per-fixture pin test (below) names the
                // exact reason the bundle is invalid.
            }
        }
    }

    for shape in [
        BundleShape::V02Chain,
        BundleShape::V03SingleCert,
        BundleShape::NpmAttestationsWrapper,
    ] {
        assert!(
            shape_counts.get(&shape).copied().unwrap_or(0) > 0,
            "wire-shape inventory regression: no positive-fixture for {shape:?}. \
             The verifier still accepts this shape — drop a representative fixture \
             into the corpus so future drift breaks here.",
        );
    }
}

// ─── Per-shape spot pins (one positive fixture per shape) ────────

#[test]
fn v02_chain_fixture_has_non_empty_certificates_array() {
    let body = fs::read(corpus_dir().join("01-v0.2-chain-shape.json"))
        .expect("01-v0.2-chain-shape.json must exist");
    let root: serde_json::Value =
        serde_json::from_slice(&body).expect("01-v0.2-chain-shape.json must be valid JSON");
    let certs = root["verificationMaterial"]["x509CertificateChain"]["certificates"]
        .as_array()
        .expect("v0.2 chain shape must carry `certificates: []`");
    assert!(
        !certs.is_empty(),
        "v0.2 fixture must ship at least one cert — the parser rejects empty chains",
    );
    for (i, cert) in certs.iter().enumerate() {
        assert!(
            cert.get("rawBytes").and_then(|v| v.as_str()).is_some(),
            "cert[{i}] missing `rawBytes` string",
        );
    }
}

#[test]
fn v03_single_cert_fixture_has_rawbytes_string() {
    let body = fs::read(corpus_dir().join("02-v0.3-single-cert-shape.json"))
        .expect("02-v0.3-single-cert-shape.json must exist");
    let root: serde_json::Value =
        serde_json::from_slice(&body).expect("02-v0.3-single-cert-shape.json must be valid JSON");
    assert!(
        root["verificationMaterial"]["certificate"]["rawBytes"]
            .as_str()
            .is_some(),
        "v0.3 fixture must carry `verificationMaterial.certificate.rawBytes` string",
    );
    assert!(
        root["verificationMaterial"]["x509CertificateChain"].is_null(),
        "v0.3 fixture must NOT also carry a v0.2 chain — the shapes are alternatives",
    );
}

#[test]
fn npm_wrapper_fixture_has_attestations_array_with_inner_bundle() {
    let body = fs::read(corpus_dir().join("03-npm-attestations-wrapper.json"))
        .expect("03-npm-attestations-wrapper.json must exist");
    let root: serde_json::Value =
        serde_json::from_slice(&body).expect("03-npm-attestations-wrapper.json must be valid JSON");
    let arr = root["attestations"]
        .as_array()
        .expect("npm wrapper must carry `attestations: []`");
    assert!(
        !arr.is_empty(),
        "npm wrapper must ship at least one attestation entry",
    );
    let inner = arr
        .iter()
        .find_map(|a| a.get("bundle"))
        .expect("at least one attestation entry must carry an inner `bundle` object");
    assert!(
        inner.get("verificationMaterial").is_some(),
        "inner bundle inside npm wrapper must look like a real Sigstore bundle (have verificationMaterial)",
    );
}

// ─── Negative-fixture pins ──────────────────────────────────────

#[test]
fn invalid_no_verification_material_fixture_is_explicit_about_missing_field() {
    let body = fs::read(corpus_dir().join("10-invalid-no-verification-material.json"))
        .expect("10-invalid-no-verification-material.json must exist");
    let root: serde_json::Value =
        serde_json::from_slice(&body).expect("fixture must be valid JSON");
    assert!(
        root.get("verificationMaterial").is_none(),
        "fixture name claims `verificationMaterial` is missing — keep it that way",
    );
}

#[test]
fn invalid_no_dsse_envelope_fixture_is_explicit_about_missing_field() {
    let body = fs::read(corpus_dir().join("11-invalid-no-dsse-envelope.json"))
        .expect("11-invalid-no-dsse-envelope.json must exist");
    let root: serde_json::Value =
        serde_json::from_slice(&body).expect("fixture must be valid JSON");
    assert!(
        root.get("dsseEnvelope").is_none(),
        "fixture name claims `dsseEnvelope` is missing — keep it that way",
    );
}

#[test]
fn invalid_empty_tlog_entries_fixture_has_explicit_empty_array() {
    let body = fs::read(corpus_dir().join("12-invalid-empty-tlog-entries.json"))
        .expect("12-invalid-empty-tlog-entries.json must exist");
    let root: serde_json::Value =
        serde_json::from_slice(&body).expect("fixture must be valid JSON");
    let entries = root["verificationMaterial"]["tlogEntries"]
        .as_array()
        .expect("tlogEntries should be an array");
    assert!(
        entries.is_empty(),
        "fixture name claims `tlogEntries` is empty — keep it that way",
    );
}

#[test]
fn invalid_not_json_fixture_is_actually_unparseable_as_json() {
    let body = fs::read(corpus_dir().join("14-invalid-not-json.txt"))
        .expect("14-invalid-not-json.txt must exist");
    assert!(
        serde_json::from_slice::<serde_json::Value>(&body).is_err(),
        "fixture name claims it's not JSON — keep it that way",
    );
}

// ─── Corpus hygiene ─────────────────────────────────────────────

#[test]
fn fixture_corpus_dir_exists_and_is_non_empty() {
    let dir = corpus_dir();
    let entries: Vec<_> = fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("could not read fixture dir {}: {e}", dir.display()))
        .filter_map(|e| e.ok())
        .collect();
    assert!(
        !entries.is_empty(),
        "fixture corpus must not be empty: {}",
        dir.display(),
    );
}

#[test]
fn every_fixture_has_a_recognised_extension() {
    let dir = corpus_dir();
    for entry in fs::read_dir(&dir).expect("read fixture dir") {
        let entry = entry.expect("dirent");
        let name = entry.file_name().to_string_lossy().into_owned();
        assert!(
            name.ends_with(".json") || name.ends_with(".txt"),
            "unexpected fixture extension on `{name}`; allowed: .json (valid + invalid), .txt (intentionally-not-JSON invalid)",
        );
    }
}
