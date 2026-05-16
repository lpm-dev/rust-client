//! Curated corpus mode end-to-end smoke test.
//!
//! Runs `lpm-audit-corpus --corpus=curated` against the 523-entry
//! static-gate fixture (the same fixture
//! `lpm-security::tests::static_gate_corpus` exercises) and asserts
//! the audit pipeline produces the expected shape: exit 0, a JSON
//! records file with one entry per fixture row, sidecar metadata
//! stamped `corpus = "curated"`, and a Markdown report. Used to
//! catch a regression where:
//!
//! - The curated path stops resolving the sibling-crate fixture
//!   directory (workspace layout / `CARGO_MANIFEST_DIR`-relative
//!   path breakage on a future re-organisation).
//! - The fixture's `expectations.json` schema drifts from the
//!   curated loader's expectations.
//! - The Markdown report-writer chokes on the curated metadata
//!   path (e.g. forgetting to switch the corpus arm in a future
//!   re-write of one of the report sections).
//!
//! Deliberately tolerant of count drift: the fixture grows over
//! time as new amber / red shapes are added. We assert the count
//! is in a reasonable range rather than pinning a specific number.
//! Per-entry correctness is covered by
//! `lpm-security::tests::static_gate_corpus`'s 523-entry assertion
//! matrix.

use std::fs;

use assert_cmd::Command;

/// Lower bound on the curated fixture size. The corpus has 523
/// entries today; this floor catches a regression that drops the
/// fixture (e.g. a broken file glob) without forcing every
/// addition to bump the assertion.
const CURATED_MIN_ENTRIES: usize = 400;

#[test]
fn curated_corpus_runs_offline_and_produces_well_formed_outputs() {
    let workdir = tempfile::tempdir().expect("create tempdir");
    let results = workdir.path().join("results.json");
    let report = workdir.path().join("report.md");

    Command::cargo_bin("lpm-audit-corpus")
        .expect("audit-corpus binary built")
        .arg("--corpus=curated")
        .arg("--results")
        .arg(&results)
        .arg("--report")
        .arg(&report)
        // Defensive: curated mode is offline (reads sibling-crate
        // fixture files only). Sentinel proxy guards against a
        // future refactor that accidentally reintroduces a network
        // call into this path.
        .env("HTTP_PROXY", "http://127.0.0.1:1")
        .env("HTTPS_PROXY", "http://127.0.0.1:1")
        .env("NO_PROXY", "")
        .assert()
        .success();

    // Records file: one record per fixture entry, with required
    // post-finalize fields populated.
    let records_raw = fs::read_to_string(&results).expect("results.json readable");
    let records: serde_json::Value =
        serde_json::from_str(&records_raw).expect("results.json valid JSON");
    let arr = records.as_array().expect("records is a JSON array");
    assert!(
        arr.len() >= CURATED_MIN_ENTRIES,
        "curated record count must be ≥ {CURATED_MIN_ENTRIES} (got {}); the static-gate fixture \
         shouldn't shrink in normal development",
        arr.len(),
    );

    // Every record must carry the post-finalize portable_outcome
    // (no `null`). This pins the contract that `finalize_outcomes`
    // ran on the curated path.
    for (i, rec) in arr.iter().enumerate() {
        let name = rec
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("<missing>");
        let outcome = rec
            .get("portable_outcome")
            .unwrap_or(&serde_json::Value::Null);
        assert!(
            !outcome.is_null(),
            "record[{i}] ({name}): portable_outcome missing — finalize_outcomes did not run",
        );
    }

    // Sidecar metadata: corpus must be stamped `"curated"` so the
    // report-writer's corpus-aware switches can route correctly.
    let meta_path = format!("{}.meta.json", results.display());
    let meta_raw = fs::read_to_string(&meta_path).expect("sidecar metadata readable");
    let meta: serde_json::Value =
        serde_json::from_str(&meta_raw).expect("sidecar metadata valid JSON");
    assert_eq!(
        meta.get("corpus").and_then(|v| v.as_str()),
        Some("curated"),
        "sidecar metadata must stamp corpus='curated' so report-writer corpus arms fire correctly",
    );
    assert_eq!(
        meta.get("audit_size")
            .and_then(|v| v.as_u64())
            .map(|n| n as usize),
        Some(arr.len()),
        "audit_size in curated mode reflects fixture row count",
    );

    // Markdown report: standing-benchmark table present.
    let report_md = fs::read_to_string(&report).expect("report.md readable");
    assert!(
        report_md.contains("## Standing benchmark table"),
        "report must include the canonical standing-benchmark table",
    );
}
