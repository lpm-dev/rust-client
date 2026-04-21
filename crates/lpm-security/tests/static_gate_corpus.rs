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
//! entries.
//!
//! **Chunk 6 hard gate (2026-04-21):** the corpus has grown past
//! 250 entries and the `≥60%` green-rate threshold is now asserted
//! — a regression below 60% hard-fails the test. The ship-criterion
//! denominator is pinned in the plan doc §4.1 (`green / (green +
//! amber)` over non-adversarial entries, reds excluded, AmberLlm
//! collapses into amber). Keep these two numbers in lockstep: the
//! plan is the contract, the harness enforces it.
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

/// Enforce that every `scripts/*.txt` file has a manifest entry and
/// every manifest entry has a `scripts/*.txt` file. Both directions
/// must match; an orphan in either direction is a hard-fail.
///
/// Added in Chunk 6 after an audit found the earlier harness only
/// loaded the manifest (silently ignoring orphan script files) and
/// only opened `scripts/<id>.txt` for manifest-listed ids (silently
/// ignoring stale manifest entries whose script file was deleted).
/// The current harness must make both classes visible.
fn assert_manifest_matches_filesystem(entries: &[CorpusEntry]) {
    let scripts_dir = fixtures_dir().join("scripts");
    let mut fs_ids: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let read = fs::read_dir(&scripts_dir)
        .unwrap_or_else(|e| panic!("failed to enumerate {scripts_dir:?}: {e}"));
    for entry in read {
        let entry = entry.unwrap_or_else(|e| panic!("dir entry error: {e}"));
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let Some(id) = name.strip_suffix(".txt") else {
            continue;
        };
        fs_ids.insert(id.to_string());
    }

    let manifest_ids: std::collections::BTreeSet<String> =
        entries.iter().map(|e| e.id.clone()).collect();

    let missing_on_disk: Vec<&String> = manifest_ids.difference(&fs_ids).collect();
    let orphan_on_disk: Vec<&String> = fs_ids.difference(&manifest_ids).collect();

    if !missing_on_disk.is_empty() || !orphan_on_disk.is_empty() {
        let mut msg = String::from(
            "corpus manifest/filesystem drifted out of lockstep. Every \
             script in scripts/ MUST have a manifest entry and every \
             manifest entry MUST have a script on disk.\n",
        );
        if !missing_on_disk.is_empty() {
            msg.push_str(&format!(
                "  manifest references missing scripts ({}):\n",
                missing_on_disk.len()
            ));
            for id in &missing_on_disk {
                msg.push_str(&format!("    {id}\n"));
            }
        }
        if !orphan_on_disk.is_empty() {
            msg.push_str(&format!(
                "  orphan scripts with no manifest entry ({}):\n",
                orphan_on_disk.len()
            ));
            for id in &orphan_on_disk {
                msg.push_str(&format!("    {id}\n"));
            }
        }
        panic!("{msg}");
    }
}

/// Phase 46 P2 §18 ship contract — the locked fixture corpus must
/// carry at least this many entries. Introduced in Chunk 6 to
/// mechanically enforce what the plan doc has been claiming: that
/// "the top-500 postinstall fixture corpus is locked." A regression
/// below this floor (fixture accidentally deleted, manifest reset,
/// etc.) MUST fail CI, not silently pass with smaller coverage.
///
/// This floor grows with the corpus. Raising it is expected; lowering
/// it without a plan-doc update is a ship-contract regression.
const CORPUS_MIN_ENTRIES: usize = 500;

#[test]
fn corpus_matches_expectations_and_has_no_fp_reds() {
    let entries = load_corpus();

    // Ship contract floor. See `CORPUS_MIN_ENTRIES`.
    assert!(
        entries.len() >= CORPUS_MIN_ENTRIES,
        "corpus shrank below the §18 ship contract: got {} entries, \
         expected ≥{CORPUS_MIN_ENTRIES}. Either restore the missing \
         fixtures or, if this is intentional, update the plan doc and \
         `CORPUS_MIN_ENTRIES` in lockstep.",
        entries.len(),
    );

    // Manifest/filesystem bijection. Keeps the earlier orphan-file
    // drift bug from recurring: every script file MUST have a manifest
    // entry, and every manifest entry MUST have a script file on disk.
    // Orphans in either direction hard-fail so the test can't pass
    // while the corpus drifts out of lockstep with the manifest.
    assert_manifest_matches_filesystem(&entries);

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

    /// Phase 46 P2 §4.1 ship criterion — green-rate floor over the
    /// non-adversarial subset. Flipped from printed telemetry to a
    /// hard assertion in Chunk 6 once the corpus grew past 250
    /// entries and real-world distribution stabilized above the
    /// plan's 60% target.
    const MIN_GREEN_RATE_PERCENT: usize = 60;

    // Stats block — printed on every run (pass or fail) so tuning
    // during future corpus growth keeps continuous feedback.
    eprintln!("────────────────────────────────────────");
    eprintln!("static_gate corpus ({total} scripts)");
    eprintln!("  green : {green:>3}   amber : {amber:>3}   red : {red:>3}");
    eprintln!(
        "  green-rate (real-corpus subset, excl. adversarial): \
         {green_rate_real}%  (hard-gated ≥{MIN_GREEN_RATE_PERCENT}% per §4.1)"
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

    // Hard gate — flipped from telemetry to assertion in Chunk 6.
    // Regressions below 60% must surface before they reach CI.
    assert!(
        green_rate_real >= MIN_GREEN_RATE_PERCENT,
        "green-rate {green_rate_real}% fell below the §4.1 ship criterion of \
         ≥{MIN_GREEN_RATE_PERCENT}% over the non-adversarial subset \
         ({green_real} green / {amber_real} amber). Do not chase this threshold \
         by weakening red rules — see plan §4.1 tuning order.",
    );
}
