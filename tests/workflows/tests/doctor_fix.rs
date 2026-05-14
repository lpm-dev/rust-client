//! Workflow tests for `lpm doctor --fix`.
//!
//! Phase 65's `doctor_list.rs` covers `lpm doctor list` (the catalog
//! dump). This file covers the auto-fix dispatch path for issues that
//! don't require network access:
//!
//! - `gitattributes_missing` → creates `.gitattributes` with `lpm.lockb binary`
//! - `lockfile_binary_missing` → regenerates `lpm.lockb` from `lpm.lock`
//!
//! Tests point the registry at a deliberately broken URL so the
//! `registry_unreachable` / `auth_missing` checks fail fast (no fix
//! branch fires for them) while the local-only auto-fix branches still
//! run on the seeded project state.

mod support;

use support::{TempProject, lpm};

/// Run `lpm doctor` with a deliberately-broken registry URL so the
/// network-dependent checks fail fast without hanging on a real TCP
/// connection. Port 1 reliably refuses connections cross-platform.
fn lpm_doctor_offline(project: &TempProject) -> assert_cmd::Command {
    let mut cmd = lpm(project);
    cmd.args(["--registry", "http://127.0.0.1:1", "--insecure"]);
    cmd
}

/// Seed a "healthy hoisted" install marker so the
/// `node_modules_missing` check doesn't fire (which would trigger an
/// auto-fix attempt to run `lpm install`, requiring a real registry).
fn seed_healthy_hoisted_install(project: &TempProject) {
    std::fs::create_dir_all(project.path().join("node_modules"))
        .expect("failed to create node_modules");
    std::fs::create_dir_all(project.path().join(".lpm/hoisted"))
        .expect("failed to create .lpm/hoisted");
    std::fs::write(
        project.path().join(".lpm/hoisted/metadata.json"),
        r#"{"version":1,"members":{},"packages":{}}"#,
    )
    .expect("failed to seed hoisted metadata");
}

/// Seed a minimal `lpm.lock` so the `lockfile_missing` check doesn't
/// fire (the auto-fix branch for that one would invoke `lpm install`).
fn seed_minimal_lockfile(project: &TempProject) {
    project.write_file("lpm.lock", "[metadata]\nlockfile-version = 1\n");
}

// ─── gitattributes_missing fix ────────────────────────────────────────

#[test]
fn doctor_fix_creates_gitattributes_when_lockfile_exists_without_it() {
    let project = TempProject::empty(r#"{"name":"doctor-gitattr","version":"1.0.0"}"#);
    seed_healthy_hoisted_install(&project);
    seed_minimal_lockfile(&project);
    // Crucially: NO .gitattributes file. lpm.lock exists, so the
    // GITATTRIBUTES_MISSING warn fires.
    assert!(
        !project.file_exists(".gitattributes"),
        "preconditions: .gitattributes must not exist before --fix"
    );

    let output = lpm_doctor_offline(&project)
        .arg("doctor")
        .arg("--fix")
        .arg("--yes")
        .output()
        .expect("failed to run lpm doctor --fix");

    // Doctor's exit code reflects whether any failing checks remain.
    // Registry/auth always fail in this offline harness, so non-zero
    // exit is expected; we only assert the fix-branch side effect.
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    assert!(
        project.file_exists(".gitattributes"),
        "doctor --fix must create .gitattributes when lpm.lock is present and the file is missing\noutput:\n{combined}"
    );

    let content = project.read_file(".gitattributes");
    assert!(
        content.contains("lpm.lockb binary"),
        ".gitattributes must mark lpm.lockb as binary, got:\n{content}"
    );
}

// ─── lockfile_binary_missing fix ──────────────────────────────────────

#[test]
fn doctor_fix_regenerates_binary_lockfile_when_toml_present() {
    let project = TempProject::empty(r#"{"name":"doctor-lockb","version":"1.0.0"}"#);
    seed_healthy_hoisted_install(&project);
    seed_minimal_lockfile(&project);
    // No lpm.lockb on disk yet.
    assert!(
        !project.file_exists("lpm.lockb"),
        "preconditions: lpm.lockb must not exist before --fix"
    );

    let output = lpm_doctor_offline(&project)
        .arg("doctor")
        .arg("--fix")
        .arg("--yes")
        .output()
        .expect("failed to run lpm doctor --fix");

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    assert!(
        project.file_exists("lpm.lockb"),
        "doctor --fix must regenerate lpm.lockb when lpm.lock is present and the binary is missing\noutput:\n{combined}"
    );
}

// ─── doctor (no --fix) is read-only ──────────────────────────────────

#[test]
fn doctor_without_fix_does_not_create_gitattributes_or_lockb() {
    let project = TempProject::empty(r#"{"name":"doctor-readonly","version":"1.0.0"}"#);
    seed_healthy_hoisted_install(&project);
    seed_minimal_lockfile(&project);

    // No --fix: doctor must be read-only. Both files must remain
    // absent regardless of which checks doctor reports.
    let _ = lpm_doctor_offline(&project)
        .arg("doctor")
        .output()
        .expect("failed to run lpm doctor");

    assert!(
        !project.file_exists(".gitattributes"),
        "doctor without --fix must not create .gitattributes"
    );
    assert!(
        !project.file_exists("lpm.lockb"),
        "doctor without --fix must not create lpm.lockb"
    );
}

// ─── --fix JSON envelope surfaces fixes_applied ──────────────────────

#[test]
fn doctor_fix_json_envelope_carries_fixes_applied_array() {
    let project = TempProject::empty(r#"{"name":"doctor-json","version":"1.0.0"}"#);
    seed_healthy_hoisted_install(&project);
    seed_minimal_lockfile(&project);

    let output = lpm_doctor_offline(&project)
        .arg("--json")
        .arg("doctor")
        .arg("--fix")
        .arg("--yes")
        .output()
        .expect("failed to run lpm doctor --fix --json");

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let envelope: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("doctor --json must be valid JSON: {e}\n---\n{stdout}"));

    // Stable schema: fixes_applied must be present (possibly empty)
    let fixes = envelope["fixes_applied"]
        .as_array()
        .expect("fixes_applied must be an array even when no fixes ran");

    // Sanity: at least one fix should have run (gitattributes,
    // lpm.lockb, or both, depending on doctor's check order).
    assert!(
        !fixes.is_empty(),
        "doctor --fix --json on the seeded project must report at least one fix, got: {envelope}",
    );
}
