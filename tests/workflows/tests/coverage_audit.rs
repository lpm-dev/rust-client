//! Coverage audit guard for the Phase 65 command-surface matrix.
//!
//! This is the lightweight 65.1 enforcement pass:
//! - the corrected 136-row surface inventory is checked into the repo
//! - every top-level `Commands` variant is pinned against `main.rs`
//! - every surface marked as covered must still point at live evidence files
//!
//! It intentionally does NOT require the currently-uncovered rows to gain
//! tests before CI can pass. The goal is to stop silent drift in the audited
//! baseline, not to broaden coverage in the same step.

#[path = "support/coverage_audit_baseline.rs"]
mod coverage_audit_baseline;

use coverage_audit_baseline::{
    EXPECTED_COMMAND_VARIANTS, EXPECTED_SURFACE_COUNT, SURFACES, SurfaceBaseline,
};
use std::collections::BTreeSet;
use std::path::PathBuf;

#[test]
fn coverage_audit_baseline_shape_matches_phase65_matrix() {
    assert_eq!(
        SURFACES.len(),
        EXPECTED_SURFACE_COUNT,
        "baseline surface count drifted; regenerate the audit baseline after updating the Phase 65 matrix"
    );

    let ids: Vec<u16> = SURFACES.iter().map(|surface| surface.id).collect();
    let expected_ids: Vec<u16> = (1..=EXPECTED_SURFACE_COUNT as u16).collect();
    assert_eq!(
        ids, expected_ids,
        "surface ids must stay contiguous so matrix rows and baseline rows refer to the same inventory"
    );

    let names: BTreeSet<&str> = SURFACES.iter().map(|surface| surface.name).collect();
    assert_eq!(
        names.len(),
        SURFACES.len(),
        "duplicate surface names in the audit baseline would make drift reports ambiguous"
    );

    let covered = SURFACES
        .iter()
        .filter(|surface| surface.has_any_coverage())
        .count();
    let uncovered = SURFACES
        .iter()
        .filter(|surface| !surface.has_any_coverage())
        .count();
    assert_eq!(
        covered, 135,
        "Phase 65 baseline should have 135 covered rows"
    );
    assert_eq!(
        uncovered, 1,
        "Phase 65 baseline should have 1 uncovered row"
    );
}

#[test]
fn covered_surfaces_still_have_live_evidence_paths() {
    let root = workspace_root();
    let mut covered_without_refs = Vec::new();
    let mut uncovered_with_refs = Vec::new();
    let mut missing_paths = Vec::new();

    for surface in SURFACES {
        let references = combined_references(surface);
        if surface.has_any_coverage() {
            if references.is_empty() {
                covered_without_refs.push(render_surface(surface));
                continue;
            }
            for reference in references {
                let path = root.join(reference);
                if !path.exists() {
                    missing_paths.push(format!(
                        "{} -> {}",
                        render_surface(surface),
                        path.display()
                    ));
                }
            }
        } else if !references.is_empty() {
            uncovered_with_refs.push(format!(
                "{} unexpectedly carries evidence refs: {}",
                render_surface(surface),
                references.join(", ")
            ));
        }
    }

    assert!(
        covered_without_refs.is_empty(),
        "covered surfaces missing audit refs:\n{}",
        covered_without_refs.join("\n")
    );
    assert!(
        uncovered_with_refs.is_empty(),
        "uncovered surfaces should not carry audit refs:\n{}",
        uncovered_with_refs.join("\n")
    );
    assert!(
        missing_paths.is_empty(),
        "coverage evidence paths disappeared; update the coverage audit baseline or restore the referenced tests/files:\n{}",
        missing_paths.join("\n")
    );
}

#[test]
fn commands_enum_variants_match_audit_baseline() {
    let main_rs = std::fs::read_to_string(workspace_root().join("crates/lpm-cli/src/main.rs"))
        .expect("failed to read crates/lpm-cli/src/main.rs");

    let actual = extract_command_variants(&main_rs);
    let expected: BTreeSet<&str> = EXPECTED_COMMAND_VARIANTS.iter().copied().collect();

    assert_eq!(
        actual, expected,
        "top-level Commands variants drifted; update the Phase 65 matrix and regenerate coverage_audit_baseline.rs"
    );
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
}

fn combined_references(surface: &SurfaceBaseline) -> Vec<&'static str> {
    let mut refs = surface.references.to_vec();
    refs.extend_from_slice(supplemental_references(surface.id));
    refs.sort_unstable();
    refs.dedup();
    refs
}

fn supplemental_references(surface_id: u16) -> &'static [&'static str] {
    match surface_id {
        10 => &["crates/lpm-cli/src/commands/doctor.rs"],
        17 => &["crates/lpm-cli/src/commands/install.rs"],
        21 => &["crates/lpm-cli/src/commands/uninstall.rs"],
        48 => &["crates/lpm-cli/src/commands/cache.rs"],
        51 | 53 => &["crates/lpm-cli/src/commands/store.rs"],
        56 | 57 => &["crates/lpm-cli/src/commands/global.rs"],
        61 => &["crates/lpm-cli/src/commands/trust.rs"],
        65 => &["crates/lpm-cli/src/commands/audit/mod.rs"],
        67 => &["crates/lpm-cli/src/commands/query.rs"],
        85 => &["crates/lpm-cli/src/commands/run.rs"],
        89 | 90 => &["crates/lpm-cli/src/commands/tools.rs"],
        98 | 99 | 100 | 101 | 103 | 106 => &["crates/lpm-cli/src/commands/env.rs"],
        111 => &["crates/lpm-cli/src/commands/dev.rs"],
        118 => &["tests/workflows/tests/ports.rs"],
        120 | 121 => &["crates/lpm-cli/src/commands/tunnel.rs"],
        125 => &[
            "crates/lpm-cli/src/commands/migrate_overrides.rs",
            "crates/lpm-cli/src/commands/migrate_patches.rs",
        ],
        128 => &["crates/lpm-cli/src/update_check.rs"],
        132 => &["crates/lpm-cli/src/commands/use.rs"],
        _ => &[],
    }
}

fn render_surface(surface: &SurfaceBaseline) -> String {
    format!("#{} {}", surface.id, surface.name)
}

fn extract_command_variants(main_rs: &str) -> BTreeSet<&str> {
    let mut in_commands_enum = false;
    let mut variants = BTreeSet::new();

    for line in main_rs.lines() {
        if !in_commands_enum {
            if line.contains("enum Commands {") {
                in_commands_enum = true;
            }
            continue;
        }

        if line == "}" {
            break;
        }

        if !line.starts_with("    ") || line.starts_with("        ") {
            continue;
        }

        let trimmed = line.trim_start();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('/') {
            continue;
        }

        let end = trimmed
            .find(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_'))
            .unwrap_or(trimmed.len());
        if end == 0 {
            continue;
        }

        let name = &trimmed[..end];
        let rest = trimmed[end..].trim_start();
        if matches!(rest.chars().next(), Some('{') | Some('(') | Some(',')) {
            variants.insert(name);
        }
    }

    variants
}
