//! Phase 69 — hermetic offline corpus mode end-to-end smoke test.
//!
//! Runs `lpm-audit-corpus --corpus=hermetic` against the bundled
//! frozen fixture and asserts the audit pipeline produces the
//! expected shape: exit 0, a JSON records file with one entry per
//! fixture row, and a Markdown report containing the standing-
//! benchmark table. Used to catch a regression where:
//!
//! - The hermetic path stops resolving the fixture file (path /
//!   `CARGO_MANIFEST_DIR` macro breakage on a future packaging
//!   change).
//! - The fixture's JSON schema drifts from the loader's expectations.
//! - The standing-benchmark Markdown writer chokes on the hermetic
//!   metadata path (e.g. forgetting to switch the corpus arm in a
//!   future re-write of one of the report sections).
//!
//! Deliberately narrow: tier-distribution and per-package
//! correctness are covered by `lpm-security`'s
//! `static_gate_corpus.rs` (523-entry fixture, full assertion
//! matrix). This test only locks the "binary runs end-to-end
//! without the network and emits a well-formed report."

use std::fs;

use assert_cmd::Command;
use predicates::str::contains;

const FIXTURE_PACKAGE_COUNT: usize = 16;

#[test]
fn hermetic_corpus_runs_offline_and_produces_well_formed_outputs() {
    let workdir = tempfile::tempdir().expect("create tempdir");
    let results = workdir.path().join("results.json");
    let report = workdir.path().join("report.md");

    Command::cargo_bin("lpm-audit-corpus")
        .expect("audit-corpus binary built")
        .arg("--corpus=hermetic")
        .arg("--results")
        .arg(&results)
        .arg("--report")
        .arg(&report)
        // Defensive: with `--corpus=hermetic` the loader takes the
        // offline path and never builds a reqwest client, but
        // setting these to clearly-invalid sentinels keeps a future
        // refactor that accidentally reintroduces a network call
        // from silently succeeding because the developer happens to
        // have a working npm registry.
        .env("HTTP_PROXY", "http://127.0.0.1:1")
        .env("HTTPS_PROXY", "http://127.0.0.1:1")
        .env("NO_PROXY", "")
        .assert()
        .success()
        .stdout(contains("hermetic: loaded 16 synthetic packages from"))
        .stdout(contains("wrote 16 audit records"))
        // Phase 46b Lever #4 + Option B — the hermetic fixture
        // includes 4 delegate-to-local-file entries with matching
        // `repository` URLs (Lever #4 territory). Of those, 3 have
        // `publish_age_hours: 8760` (1 year, well past 24h cooldown)
        // → Lever #4 fires, Amber → Green. 1 has
        // `publish_age_hours: 1` (`hermetic-amber-binary-fetcher-recent`)
        // → Option B's cooldown defense-in-depth refuses to widen,
        // entry stays Amber and is hard-blocked by L3 cooldown. The
        // distribution thus moves from pre-Lever-#4 baseline
        // (green=4, amber=8, hard-block=4 = 3 reds + 1 cooldown) to
        // post-Lever-#4-with-Option-B (green=6, amber=6, hard-block=4 =
        // still 3 reds + 1 cooldown). The cooldown-blocked entry's
        // count is preserved — Option B's load-bearing invariant.
        .stdout(contains("L1: green=6 amber=6 red=3 no-scripts=1"))
        .stdout(contains(
            "Portable (L1-3): auto-run=6 prompt=5 hard-block=4 no-scripts=1",
        ));

    // Records file: one record per fixture entry, with required
    // post-finalize fields populated.
    let records_raw = fs::read_to_string(&results).expect("results.json readable");
    let records: serde_json::Value =
        serde_json::from_str(&records_raw).expect("results.json valid JSON");
    let arr = records.as_array().expect("records is a JSON array");
    assert_eq!(
        arr.len(),
        FIXTURE_PACKAGE_COUNT,
        "record count must match fixture row count exactly"
    );

    // Every record must carry the post-finalize portable_outcome
    // (no `null`). This pins the contract that `finalize_outcomes`
    // ran on the hermetic path.
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

    // Sidecar metadata: corpus must be stamped `"hermetic"` so the
    // report-writer's corpus-aware switches can route correctly.
    let meta_path = format!("{}.meta.json", results.display());
    let meta_raw = fs::read_to_string(&meta_path).expect("sidecar metadata readable");
    let meta: serde_json::Value =
        serde_json::from_str(&meta_raw).expect("sidecar metadata valid JSON");
    assert_eq!(
        meta.get("corpus").and_then(|v| v.as_str()),
        Some("hermetic"),
        "sidecar metadata must stamp corpus='hermetic' so report-writer corpus arms fire correctly",
    );
    assert_eq!(
        meta.get("audit_size").and_then(|v| v.as_u64()),
        Some(FIXTURE_PACKAGE_COUNT as u64),
        "audit_size in hermetic mode reflects fixture row count, not the ignored --size flag",
    );

    // Markdown report: standing-benchmark table present + hermetic-
    // specific zero-FP-red wording in place (NOT the live "MUST stay
    // 0" framing, which is wrong for the fixture's intentional red
    // shape coverage).
    let report_md = fs::read_to_string(&report).expect("report.md readable");
    assert!(
        report_md.contains("## Standing benchmark table"),
        "report must include the canonical standing-benchmark table",
    );
    assert!(
        report_md.contains("Hermetic fixture: count reflects intentional red shape coverage"),
        "zero-FP-red Notes column must use hermetic framing, not the live '§4.1 ship gate' wording",
    );
    assert!(
        !report_md.contains("**§4.1 ship gate — MUST stay 0**"),
        "live-corpus 'MUST stay 0' wording must NOT appear in a hermetic report",
    );
    assert!(
        report_md.contains("## Red-classified packages (hermetic fixture coverage)"),
        "red-packages section header must reflect hermetic framing",
    );
}
