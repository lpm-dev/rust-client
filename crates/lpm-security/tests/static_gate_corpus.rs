//! Phase 46 P2 Chunk 2 — integration-test harness for the static-gate
//! fixture corpus.
//!
//! Reads `tests/fixtures/postinstall-scripts/expectations.json` and
//! the sibling `scripts/<id>.txt` files, classifies each entry via
//! [`lpm_security::static_gate::classify`], and asserts:
//!
//! 1. **Every expectation matches** — any mismatch between the
//!    declared `expected` tier and the classifier's output fails the
//!    test with a detailed diff.
//! 2. **Zero false-positive reds** — any entry whose expectation is
//!    NOT `red` but whose classifier output IS `red` fails separately
//!    (redundant with #1, but listed explicitly so the ship-criterion
//!    invariant from §4.1 has its own named failure).
//!
//! Prints per-run stats: total count, per-tier counts, and the
//! green-rate (green / (green + amber)) over non-adversarial
//! entries. The ship criterion is `≥60%` green-rate on a 500-script
//! real-world corpus per §4.1, but the threshold is NOT asserted
//! here — the starter set is deliberately biased toward amber/red
//! coverage and its green-rate starts lower. Chunk 6 flips the
//! `≥60%` assertion on once the corpus grows to 500 entries.
//!
//! The harness is deliberately minimal: one test, one read of
//! fixtures, no retries. Fast (<100ms on a warm build) so it runs on
//! every `cargo nextest` without slowing the suite.

use std::fs;
use std::path::PathBuf;

use lpm_security::static_gate::classify;
use lpm_security::triage::StaticTier;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct CorpusEntry {
    id: String,
    expected: StaticTier,
    #[serde(default)]
    #[allow(dead_code)] // surfaced on mismatch for review, not asserted directly
    notes: Option<String>,
}

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("postinstall-scripts")
}

fn load_corpus() -> Vec<CorpusEntry> {
    let manifest_path = fixtures_dir().join("expectations.json");
    let raw = fs::read_to_string(&manifest_path)
        .unwrap_or_else(|e| panic!("failed to read {manifest_path:?}: {e}"));
    serde_json::from_str(&raw).unwrap_or_else(|e| panic!("failed to parse {manifest_path:?}: {e}"))
}

fn load_script_body(id: &str) -> String {
    let path = fixtures_dir().join("scripts").join(format!("{id}.txt"));
    let body = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed to read fixture {path:?}: {e}"));
    // Strip the ONE trailing newline that Write / most editors append
    // so the classifier sees the same bytes a real postinstall body
    // would carry (postinstall bodies come from JSON strings, which
    // don't typically end in a newline). Preserve any meaningful
    // content inside — we only strip the final trailing `\n`.
    body.strip_suffix('\n').map(str::to_string).unwrap_or(body)
}

fn is_adversarial(id: &str) -> bool {
    id.starts_with("adversarial-")
}

#[test]
fn corpus_matches_expectations_and_has_no_fp_reds() {
    let entries = load_corpus();
    assert!(
        !entries.is_empty(),
        "corpus expectations.json is empty — at least the starter set \
         must ship with the harness",
    );

    // Duplicate-id guard: a typo-clone would silently double-count
    // one fixture. Cheap linear check; corpus is small.
    {
        let mut seen = std::collections::HashSet::new();
        for entry in &entries {
            assert!(
                seen.insert(entry.id.clone()),
                "duplicate id in corpus: {}",
                entry.id,
            );
        }
    }

    let mut mismatches: Vec<(String, StaticTier, StaticTier)> = Vec::new();
    let mut fp_reds: Vec<String> = Vec::new();
    let mut green = 0usize;
    let mut amber = 0usize;
    let mut amber_llm_unexpected = 0usize;
    let mut red = 0usize;

    // Stats sub-slice: non-adversarial entries represent the "real
    // corpus" shape the 60% ship criterion is measured against.
    // Adversarial entries are deliberate stress tests and don't
    // belong in the green-rate denominator.
    let mut green_real = 0usize;
    let mut amber_real = 0usize;

    for entry in &entries {
        let body = load_script_body(&entry.id);
        let actual = classify(&body);

        if actual != entry.expected {
            mismatches.push((entry.id.clone(), entry.expected, actual));
        }
        if actual == StaticTier::Red && entry.expected != StaticTier::Red {
            fp_reds.push(entry.id.clone());
        }

        match actual {
            StaticTier::Green => {
                green += 1;
                if !is_adversarial(&entry.id) {
                    green_real += 1;
                }
            }
            StaticTier::Amber => {
                amber += 1;
                if !is_adversarial(&entry.id) {
                    amber_real += 1;
                }
            }
            StaticTier::AmberLlm => {
                // The P2 classifier is contracted to emit only
                // Green | Amber | Red (AmberLlm is reserved for P8).
                // Any AmberLlm here is a classifier-contract bug,
                // not a corpus issue.
                amber_llm_unexpected += 1;
            }
            StaticTier::Red => red += 1,
        }
    }

    let total = entries.len();
    let green_rate_real = if green_real + amber_real > 0 {
        (green_real * 100) / (green_real + amber_real)
    } else {
        0
    };

    // Stats block — printed on every run (pass or fail) so tuning
    // during Chunks 3-6 has continuous feedback.
    eprintln!("────────────────────────────────────────");
    eprintln!("static_gate corpus ({total} scripts)");
    eprintln!("  green : {green:>3}   amber : {amber:>3}   red : {red:>3}");
    eprintln!(
        "  green-rate (real-corpus subset, excl. adversarial): \
         {green_rate_real}%  (target ≥60% — hard-gated in Chunk 6)"
    );
    eprintln!("────────────────────────────────────────");

    assert_eq!(
        amber_llm_unexpected, 0,
        "classifier emitted AmberLlm for {amber_llm_unexpected} \
         entries — static classifier is contracted to emit only \
         Green | Amber | Red (AmberLlm is owned by P8)",
    );

    if !fp_reds.is_empty() {
        panic!(
            "FALSE-POSITIVE REDS — classifier flagged {} entry(ies) as \
             red that were NOT expected-red. Ship criterion from §4.1 \
             is zero FP reds.\n  {}",
            fp_reds.len(),
            fp_reds.join("\n  "),
        );
    }

    if !mismatches.is_empty() {
        let detail = mismatches
            .iter()
            .map(|(id, exp, got)| format!("  {id}: expected {exp:?}, got {got:?}"))
            .collect::<Vec<_>>()
            .join("\n");
        panic!(
            "corpus expectation mismatches ({}):\n{}",
            mismatches.len(),
            detail,
        );
    }
}
