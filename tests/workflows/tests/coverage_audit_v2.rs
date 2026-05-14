//! Coverage matrix **v2** — depth + scenario metrics.
//!
//! Why v2 exists:
//!
//! v1 ([coverage_audit.rs](tests/workflows/tests/coverage_audit.rs)) tracks
//! a binary "does any test exist for this surface" flag per row. That
//! metric saturated at 97.8% workflow / 70% JSON contract during the
//! 2026-05-14 coverage push without reflecting:
//!
//! - **Scenario depth.** A surface with 1 trivial test and one with 50
//!   thorough tests get the same v1 flag.
//! - **Failure-mode coverage.** Which of the known failure modes for a
//!   surface are actually exercised by tests, and which are gaps?
//! - **JSON contract depth.** "Locked via insta snapshot" vs "checked
//!   one field semantically" all flip the same v1 `json_contract: true`.
//! - **Cross-command flow membership.** Single-command tests don't
//!   catch state-consistency bugs between commands.
//!
//! See [`support/coverage_audit_v2_baseline.rs`](support/coverage_audit_v2_baseline.rs)
//! for the schema and the populated rows.
//!
//! See [`private/test-gaps-strategic-audit.md`](private/test-gaps-strategic-audit.md)
//! for the strategic gap inventory that informed the failure-mode lists.
//!
//! ## How these tests behave today
//!
//! - **Reminder mode (current default).** The progress / gap reports
//!   print to stderr via `eprintln!` so they show up in `cargo nextest
//!   run -p lpm-workflows --test coverage_audit_v2` output, but the
//!   tests themselves PASS so CI is not blocked during the v2 backfill
//!   period.
//! - **Once v2 is fully populated** (every workflow-covered or
//!   cli-binary-covered surface has a row, every flow is either
//!   `tested: true` or has an open ticket reference), flip the
//!   `EXPECT_FULL_V2_BACKFILL` constant in this file to `true`. The
//!   tests will then fail-loud on regressions.

// Re-import the v1 baseline via `#[path]`. v2 only consumes
// `SURFACES` + `SurfaceBaseline::{id, name, workflow, cli_binary}`;
// the other v1 helpers (count constants, variant enums) are dead in
// this test binary but live in `coverage_audit.rs`. Suppress here.
#[path = "support/coverage_audit_baseline.rs"]
#[allow(dead_code)]
mod v1;

#[path = "support/coverage_audit_v2_baseline.rs"]
mod v2;

use std::collections::HashSet;
use v2::{CROSS_COMMAND_FLOWS, JsonContractDepth, SURFACES_V2};

/// When the v2 backfill is complete, flip this to `true` and the
/// reminder tests below tighten to hard asserts. Stays `false` while
/// surfaces are being populated session-by-session.
const EXPECT_FULL_V2_BACKFILL: bool = false;

// ─── Schema integrity ─────────────────────────────────────────────────

#[test]
fn v2_rows_have_no_duplicate_ids() {
    let mut seen: HashSet<u16> = HashSet::new();
    for surface in SURFACES_V2 {
        assert!(
            seen.insert(surface.id),
            "v2 baseline has duplicate id {} ({}); each surface gets exactly one row",
            surface.id,
            v1_name_for(surface.id).unwrap_or("<unknown id>"),
        );
    }
}

#[test]
fn v2_ids_reference_real_v1_surfaces() {
    for surface in SURFACES_V2 {
        assert!(
            v1::SURFACES.iter().any(|s| s.id == surface.id),
            "v2 row id {} does not match any v1 surface — fix the id in v2 baseline",
            surface.id,
        );
    }
}

#[test]
fn v2_failure_modes_have_no_overlap_between_tested_and_known() {
    // A failure mode should appear in `failure_modes_tested` XOR
    // `failure_modes_known`. The same string in both means "tested
    // AND a gap" — a contradiction that signals a stale annotation.
    for surface in SURFACES_V2 {
        let tested: HashSet<&str> = surface.failure_modes_tested.iter().copied().collect();
        let known: HashSet<&str> = surface.failure_modes_known.iter().copied().collect();
        let overlap: Vec<&&str> = tested.intersection(&known).collect();
        assert!(
            overlap.is_empty(),
            "v2 row id {} ({}) has failure modes in both `tested` and `known`: {:?}\n\
             A mode is either tested (move out of `known`) or a gap (remove from `tested`).",
            surface.id,
            v1_name_for(surface.id).unwrap_or("?"),
            overlap,
        );
    }
}

#[test]
fn v2_scenarios_count_is_positive_when_workflow_or_cli_binary_covered() {
    // If a surface has any workflow or cli-binary test (v1) AND has a
    // v2 row, the scenario count must be > 0.
    for surface in SURFACES_V2 {
        let v1_row = v1::SURFACES
            .iter()
            .find(|s| s.id == surface.id)
            .expect("validated by `v2_ids_reference_real_v1_surfaces`");
        if v1_row.workflow || v1_row.cli_binary {
            assert!(
                surface.scenarios > 0,
                "v2 row id {} ({}) claims v1 coverage but reports scenarios = 0",
                surface.id,
                v1_row.name,
            );
        }
    }
}

// ─── Backfill progress (reminder mode) ────────────────────────────────

#[test]
fn v2_backfill_progress_report_for_workflow_and_cli_binary_surfaces() {
    let v1_covered_ids: HashSet<u16> = v1::SURFACES
        .iter()
        .filter(|s| s.workflow || s.cli_binary)
        .map(|s| s.id)
        .collect();

    let v2_populated_ids: HashSet<u16> = SURFACES_V2.iter().map(|s| s.id).collect();

    let backlog: Vec<u16> = {
        let mut ids: Vec<u16> = v1_covered_ids
            .difference(&v2_populated_ids)
            .copied()
            .collect();
        ids.sort();
        ids
    };

    let total = v1_covered_ids.len();
    let done = v2_populated_ids.intersection(&v1_covered_ids).count();
    let pct = if total == 0 {
        0.0
    } else {
        100.0 * done as f64 / total as f64
    };

    eprintln!();
    eprintln!("┌─────────────────────────────────────────────────────────────");
    eprintln!("│ coverage matrix v2 — backfill progress");
    eprintln!("├─────────────────────────────────────────────────────────────");
    eprintln!(
        "│ {} / {} v1-covered surfaces have v2 annotations  ({:.1}%)",
        done, total, pct,
    );
    eprintln!(
        "│ backlog: {} surfaces awaiting failure-mode + scenario annotation",
        backlog.len(),
    );
    eprintln!("├─────────────────────────────────────────────────────────────");
    for id in &backlog {
        let name = v1_name_for(*id).unwrap_or("?");
        eprintln!("│   id {:>3}  {}", id, name);
    }
    eprintln!("└─────────────────────────────────────────────────────────────");
    eprintln!();

    if EXPECT_FULL_V2_BACKFILL {
        assert!(
            backlog.is_empty(),
            "v2 backfill incomplete — flip EXPECT_FULL_V2_BACKFILL back to false until {} \
             surfaces have v2 rows",
            backlog.len(),
        );
    }
}

#[test]
fn v2_json_contract_depth_distribution_report() {
    use JsonContractDepth::*;

    let mut none = 0u32;
    let mut semantic = 0u32;
    let mut snapshot = 0u32;
    for surface in SURFACES_V2 {
        match surface.json_contract_depth {
            None => none += 1,
            SemanticAsserts => semantic += 1,
            InstaSnapshot => snapshot += 1,
        }
    }

    eprintln!();
    eprintln!("┌─────────────────────────────────────────────────────────────");
    eprintln!(
        "│ JSON contract depth (across {} populated v2 rows)",
        SURFACES_V2.len()
    );
    eprintln!("├─────────────────────────────────────────────────────────────");
    eprintln!("│   InstaSnapshot     — {} surface(s)", snapshot);
    eprintln!("│   SemanticAsserts   — {} surface(s)", semantic);
    eprintln!("│   None              — {} surface(s)", none);
    eprintln!("└─────────────────────────────────────────────────────────────");
    eprintln!();
}

#[test]
fn v2_failure_mode_gap_report() {
    let mut total_tested = 0usize;
    let mut total_known_gaps = 0usize;
    let mut by_surface: Vec<(u16, &'static str, usize, usize)> = Vec::new();

    for surface in SURFACES_V2 {
        let tested = surface.failure_modes_tested.len();
        let gaps = surface.failure_modes_known.len();
        total_tested += tested;
        total_known_gaps += gaps;
        let name = v1_name_for(surface.id).unwrap_or("?");
        by_surface.push((surface.id, name, tested, gaps));
    }
    by_surface.sort_by_key(|(_, _, _, gaps)| std::cmp::Reverse(*gaps));

    eprintln!();
    eprintln!("┌─────────────────────────────────────────────────────────────");
    eprintln!("│ failure-mode coverage (populated v2 rows only)");
    eprintln!("├─────────────────────────────────────────────────────────────");
    eprintln!(
        "│ tested: {}    known gaps: {}    ratio tested: {:.0}%",
        total_tested,
        total_known_gaps,
        if total_tested + total_known_gaps == 0 {
            0.0
        } else {
            100.0 * total_tested as f64 / (total_tested + total_known_gaps) as f64
        },
    );
    eprintln!("├─────────────────────────────────────────────────────────────");
    eprintln!("│ by surface (sorted by gap count, descending):");
    for (id, name, tested, gaps) in &by_surface {
        eprintln!(
            "│   id {:>3}  tested: {:>2}  gaps: {:>2}  — {}",
            id, tested, gaps, name,
        );
    }
    eprintln!("└─────────────────────────────────────────────────────────────");
    eprintln!();
}

// ─── Cross-command flow inventory ─────────────────────────────────────

#[test]
fn cross_command_flows_have_unique_names() {
    let mut seen: HashSet<&str> = HashSet::new();
    for flow in CROSS_COMMAND_FLOWS {
        assert!(
            seen.insert(flow.name),
            "cross-command flow name collision: {:?}",
            flow.name,
        );
    }
}

#[test]
fn cross_command_flows_tested_flag_implies_test_file_set() {
    for flow in CROSS_COMMAND_FLOWS {
        if flow.tested {
            assert!(
                flow.test_file.is_some(),
                "flow {:?} is tested: true but test_file is None — set the path",
                flow.name,
            );
        }
    }
}

#[test]
fn cross_command_flows_inventory_report() {
    let untested: Vec<&FlowAlias> = CROSS_COMMAND_FLOWS
        .iter()
        .filter(|f| !f.tested)
        .map(|f| f as &FlowAlias)
        .collect();

    eprintln!();
    eprintln!("┌─────────────────────────────────────────────────────────────");
    eprintln!(
        "│ cross-command flow inventory ({} flows enumerated)",
        CROSS_COMMAND_FLOWS.len()
    );
    eprintln!("├─────────────────────────────────────────────────────────────");
    eprintln!(
        "│ tested: {}    untested: {}",
        CROSS_COMMAND_FLOWS.len() - untested.len(),
        untested.len(),
    );
    eprintln!("├─────────────────────────────────────────────────────────────");
    for flow in CROSS_COMMAND_FLOWS {
        let marker = if flow.tested { "✓" } else { " " };
        eprintln!("│  [{}] {}", marker, flow.name);
        eprintln!("│        commands: {}", flow.commands.join(" → "));
        eprintln!("│        catches:  {}", flow.catches);
    }
    eprintln!("└─────────────────────────────────────────────────────────────");
    eprintln!();

    if EXPECT_FULL_V2_BACKFILL {
        assert!(
            untested.is_empty(),
            "{} cross-command flows are still untested — flip EXPECT_FULL_V2_BACKFILL back to \
             false until they're either implemented or removed",
            untested.len(),
        );
    }
}

// Local alias so the iterator binding in `cross_command_flows_inventory_report`
// has a spellable name without importing through the `#[path]` mod chain.
type FlowAlias = v2::CrossCommandFlow;

// ─── Helpers ───────────────────────────────────────────────────────────

fn v1_name_for(id: u16) -> Option<&'static str> {
    v1::SURFACES.iter().find(|s| s.id == id).map(|s| s.name)
}
