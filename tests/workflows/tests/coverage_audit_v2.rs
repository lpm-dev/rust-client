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
//! Two independent locking flags govern strictness:
//!
//! - `EXPECT_FULL_V2_SURFACES_BACKFILL` — true once every
//!   workflow-covered or cli-binary-covered surface has a v2 row.
//!   When true, the backfill-progress test hard-fails if any surface
//!   loses its v2 row. **Locked in 2026-05-14 after the 133/133
//!   backfill landed.** Drop a new surface? You owe it a v2 row.
//! - `EXPECT_FULL_V2_FLOWS_BACKFILL` — true once every cross-command
//!   flow has been implemented as an integration test and its row
//!   marked `tested: true` with a `test_file` path. **Locked in
//!   2026-05-14** after all 10 flows landed as
//!   `tests/workflows/tests/cross_command_flows.rs`.
//!
//! Both flags are independent on purpose. Surface backfill and
//! cross-command-flow implementation move at different speeds and
//! gating them on the same flag would couple unrelated work items.

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

/// Locks in the surface backfill. When `true`, the
/// `v2_backfill_progress_report_for_workflow_and_cli_binary_surfaces`
/// test hard-fails if any v1-covered surface is missing its v2 row.
/// Flipped to `true` on 2026-05-14 after every workflow-covered and
/// cli-binary-covered surface gained a v2 entry.
const EXPECT_FULL_V2_SURFACES_BACKFILL: bool = true;

/// Locks in the cross-command flow backfill. When `true`, the
/// `cross_command_flows_inventory_report` test hard-fails if any
/// enumerated flow still has `tested: false`. Flipped to `true` on
/// 2026-05-14 after all 10 flows shipped as
/// `tests/workflows/tests/cross_command_flows.rs`.
const EXPECT_FULL_V2_FLOWS_BACKFILL: bool = true;

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
fn login_v2_json_contract_depth_matches_v1_json_contract_bit() {
    let mut mismatches = Vec::new();
    let login_surface_ids = [34, 35, 36, 37];

    for surface in SURFACES_V2
        .iter()
        .filter(|surface| login_surface_ids.contains(&surface.id))
    {
        let v1_row = v1::SURFACES
            .iter()
            .find(|s| s.id == surface.id)
            .expect("validated by `v2_ids_reference_real_v1_surfaces`");
        let v2_has_json_contract = !matches!(surface.json_contract_depth, JsonContractDepth::None);
        if v1_row.json_contract != v2_has_json_contract {
            mismatches.push(format!(
                "#{} {}: v1 json_contract={} but v2 json_contract_depth={:?}",
                surface.id, v1_row.name, v1_row.json_contract, surface.json_contract_depth,
            ));
        }
    }

    assert!(
        mismatches.is_empty(),
        "v1/v2 login JSON contract coverage drifted:\n{}",
        mismatches.join("\n"),
    );
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

    if EXPECT_FULL_V2_SURFACES_BACKFILL {
        assert!(
            backlog.is_empty(),
            "v2 surface backfill regressed — {} v1-covered surface(s) no longer carry a v2 row. \
             Either restore the missing row(s) or flip EXPECT_FULL_V2_SURFACES_BACKFILL back to \
             false (and explain why in the commit).",
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

    if EXPECT_FULL_V2_FLOWS_BACKFILL {
        assert!(
            untested.is_empty(),
            "{} cross-command flows are still untested — flip EXPECT_FULL_V2_FLOWS_BACKFILL back \
             to false until they're either implemented or removed",
            untested.len(),
        );
    }
}

// Local alias so the iterator binding in `cross_command_flows_inventory_report`
// has a spellable name without importing through the `#[path]` mod chain.
type FlowAlias = v2::CrossCommandFlow;

// ─── Scenario-by-file partition (sum invariant + reminder) ────────────

/// When a v2 row populates `scenarios_by_file`, the per-file counts
/// must sum to `scenarios`. Catches drift where new tests get added
/// to a shared file but the row's count isn't bumped.
#[test]
fn v2_scenarios_by_file_sum_matches_scenarios_when_populated() {
    for surface in SURFACES_V2 {
        if surface.scenarios_by_file.is_empty() {
            continue; // unpartitioned — not subject to the sum invariant
        }
        let sum: u32 = surface
            .scenarios_by_file
            .iter()
            .map(|(_, count)| *count)
            .sum();
        assert_eq!(
            sum,
            surface.scenarios,
            "v2 row id {} ({}): scenarios_by_file sums to {} but scenarios = {}. \
             Either fix the per-file count or update `scenarios` after auditing the test files.",
            surface.id,
            v1_name_for(surface.id).unwrap_or("?"),
            sum,
            surface.scenarios,
        );
    }
}

/// Surfaces that share a workflow test file with at least one other
/// surface SHOULD populate `scenarios_by_file` so the sum invariant
/// catches drift. Reminder mode only — prints the unpartitioned set
/// so the next session knows what to attribute.
#[test]
fn v2_scenarios_by_file_partition_reminder() {
    use std::collections::HashMap;

    // Build the inverse map: which surfaces would share each test
    // file IF every row were partitioned? We can't know the file
    // membership of unpartitioned rows, so this only catches rows
    // where someone HAS started partitioning but others on the same
    // file haven't.
    let mut file_to_surfaces: HashMap<&'static str, Vec<u16>> = HashMap::new();
    for surface in SURFACES_V2 {
        for (file, _) in surface.scenarios_by_file {
            file_to_surfaces.entry(file).or_default().push(surface.id);
        }
    }

    let shared_files: Vec<(&&'static str, &Vec<u16>)> = file_to_surfaces
        .iter()
        .filter(|(_, ids)| ids.len() > 1)
        .collect();

    let unpartitioned: Vec<&v2::SurfaceV2> = SURFACES_V2
        .iter()
        .filter(|s| s.scenarios_by_file.is_empty())
        .collect();

    eprintln!();
    eprintln!("┌─────────────────────────────────────────────────────────────");
    eprintln!("│ scenarios_by_file partition status");
    eprintln!("├─────────────────────────────────────────────────────────────");
    eprintln!(
        "│ partitioned: {} / {} rows",
        SURFACES_V2.len() - unpartitioned.len(),
        SURFACES_V2.len(),
    );
    eprintln!(
        "│ shared files with partitioned data ({}):",
        shared_files.len()
    );
    for (file, ids) in &shared_files {
        eprintln!("│   {} → ids {:?}", file, ids);
    }
    eprintln!(
        "│ unpartitioned: {} rows (silent until populated)",
        unpartitioned.len(),
    );
    eprintln!("└─────────────────────────────────────────────────────────────");
    eprintln!();
}

// ─── Audit freshness (last_audited_at) ─────────────────────────────────

/// `last_audited_at` must be a 10-character ISO date `YYYY-MM-DD`.
/// Loose parser — full RFC 3339 conformance isn't needed; the field
/// just has to sort lexicographically for the freshness report.
#[test]
fn v2_last_audited_at_is_iso_date() {
    for surface in SURFACES_V2 {
        let d = surface.last_audited_at;
        assert!(
            d.len() == 10
                && d.as_bytes()[4] == b'-'
                && d.as_bytes()[7] == b'-'
                && d[0..4].chars().all(|c| c.is_ascii_digit())
                && d[5..7].chars().all(|c| c.is_ascii_digit())
                && d[8..10].chars().all(|c| c.is_ascii_digit()),
            "v2 row id {} ({}): last_audited_at = {:?} is not in YYYY-MM-DD format",
            surface.id,
            v1_name_for(surface.id).unwrap_or("?"),
            d,
        );
    }
}

/// Print the rows sorted by oldest audit date so the next session
/// knows what to re-check. Reminder mode only — bit-rot is a
/// soft signal, not a CI gate.
#[test]
fn v2_audit_freshness_report() {
    let mut by_date: Vec<(&'static str, u16, &'static str)> = SURFACES_V2
        .iter()
        .map(|s| (s.last_audited_at, s.id, v1_name_for(s.id).unwrap_or("?")))
        .collect();
    by_date.sort();

    eprintln!();
    eprintln!("┌─────────────────────────────────────────────────────────────");
    eprintln!("│ v2 audit freshness (oldest 10 rows)");
    eprintln!("├─────────────────────────────────────────────────────────────");
    for (date, id, name) in by_date.iter().take(10) {
        eprintln!("│   {}  id {:>3}  {}", date, id, name);
    }
    eprintln!("└─────────────────────────────────────────────────────────────");
    eprintln!();
}

// ─── Markdown summary artifact ─────────────────────────────────────────

/// Render the v2 reports as a single Markdown document and write it
/// to `target/coverage_audit_v2.md` (CARGO_TARGET_DIR-aware). CI can
/// upload this as an artifact so PR descriptions, dashboards, or
/// Slack summaries don't have to re-run nextest just to pull the
/// reminder reports. Never fails — best-effort write; if the target
/// dir isn't writable, the test still passes.
#[test]
fn v2_emit_markdown_summary_artifact() {
    use std::fmt::Write as _;

    let v1_covered: usize = v1::SURFACES
        .iter()
        .filter(|s| s.workflow || s.cli_binary)
        .count();
    let v2_populated = SURFACES_V2.len();

    let mut none = 0u32;
    let mut semantic = 0u32;
    let mut snapshot = 0u32;
    for surface in SURFACES_V2 {
        match surface.json_contract_depth {
            JsonContractDepth::None => none += 1,
            JsonContractDepth::SemanticAsserts => semantic += 1,
            JsonContractDepth::InstaSnapshot => snapshot += 1,
        }
    }

    let total_tested_modes: usize = SURFACES_V2
        .iter()
        .map(|s| s.failure_modes_tested.len())
        .sum();
    let total_known_modes: usize = SURFACES_V2
        .iter()
        .map(|s| s.failure_modes_known.len())
        .sum();

    let flows_tested = CROSS_COMMAND_FLOWS.iter().filter(|f| f.tested).count();
    let flows_total = CROSS_COMMAND_FLOWS.len();

    let mut md = String::new();
    let _ = writeln!(md, "# Coverage Matrix v2 — Summary");
    let _ = writeln!(
        md,
        "_Generated by `coverage_audit_v2::v2_emit_markdown_summary_artifact`._"
    );
    let _ = writeln!(md);
    let _ = writeln!(md, "## Surface backfill");
    let _ = writeln!(
        md,
        "- **{} / {}** v1-covered surfaces have v2 annotations ({:.1}%)",
        v2_populated,
        v1_covered,
        100.0 * v2_populated as f64 / v1_covered.max(1) as f64,
    );
    let _ = writeln!(md);
    let _ = writeln!(md, "## JSON contract depth");
    let _ = writeln!(md, "| Depth | Count |");
    let _ = writeln!(md, "|-------|-------|");
    let _ = writeln!(md, "| InstaSnapshot   | {} |", snapshot);
    let _ = writeln!(md, "| SemanticAsserts | {} |", semantic);
    let _ = writeln!(md, "| None            | {} |", none);
    let _ = writeln!(md);
    let _ = writeln!(md, "## Failure-mode coverage");
    let _ = writeln!(
        md,
        "- Tested: **{}**  Known gaps: **{}**  Ratio tested: **{:.0}%**",
        total_tested_modes,
        total_known_modes,
        if total_tested_modes + total_known_modes == 0 {
            0.0
        } else {
            100.0 * total_tested_modes as f64 / (total_tested_modes + total_known_modes) as f64
        },
    );
    let _ = writeln!(md);
    let _ = writeln!(md, "## Top 10 surfaces by failure-mode gaps");
    let mut by_gap: Vec<(u16, &'static str, usize, usize)> = SURFACES_V2
        .iter()
        .map(|s| {
            (
                s.id,
                v1_name_for(s.id).unwrap_or("?"),
                s.failure_modes_tested.len(),
                s.failure_modes_known.len(),
            )
        })
        .collect();
    by_gap.sort_by_key(|(_, _, _, gaps)| std::cmp::Reverse(*gaps));
    let _ = writeln!(md, "| id | surface | tested | gaps |");
    let _ = writeln!(md, "|---:|---------|-------:|-----:|");
    for (id, name, tested, gaps) in by_gap.iter().take(10) {
        let _ = writeln!(md, "| {} | {} | {} | {} |", id, name, tested, gaps);
    }
    let _ = writeln!(md);
    let _ = writeln!(md, "## Cross-command flows");
    let _ = writeln!(
        md,
        "- **{} / {}** flows implemented",
        flows_tested, flows_total
    );
    let _ = writeln!(md, "| status | flow |");
    let _ = writeln!(md, "|--------|------|");
    for flow in CROSS_COMMAND_FLOWS {
        let marker = if flow.tested { "✓" } else { "·" };
        let _ = writeln!(md, "| {} | {} |", marker, flow.name);
    }

    // Write to <cargo-target-dir>/coverage_audit_v2.md. The
    // workflow tier's MANIFEST_DIR is `tests/workflows/`; cargo
    // typically places the target dir as a sibling at the workspace
    // root. Best-effort: try a few candidates and fall back to the
    // OS temp dir.
    let manifest_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let candidates = [
        manifest_dir.join("../../target/coverage_audit_v2.md"),
        manifest_dir.join("target/coverage_audit_v2.md"),
        std::env::temp_dir().join("coverage_audit_v2.md"),
    ];
    let mut written_to: Option<std::path::PathBuf> = None;
    for path in candidates {
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if std::fs::write(&path, &md).is_ok() {
            written_to = Some(path);
            break;
        }
    }

    eprintln!();
    eprintln!("┌─────────────────────────────────────────────────────────────");
    match written_to {
        Some(p) => eprintln!("│ v2 markdown summary written to {}", p.display()),
        None => eprintln!("│ v2 markdown summary could not be written (best-effort)"),
    }
    eprintln!("└─────────────────────────────────────────────────────────────");
    eprintln!();
}

// ─── Helpers ───────────────────────────────────────────────────────────

fn v1_name_for(id: u16) -> Option<&'static str> {
    v1::SURFACES.iter().find(|s| s.id == id).map(|s| s.name)
}
