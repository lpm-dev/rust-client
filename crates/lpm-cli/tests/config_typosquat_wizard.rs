//! Cli-binary tier — machine-readable contract for
//! `lpm config typosquat`.
//!
//! Inline tests in `commands/config.rs` pin the parser, force-floor
//! guard, and persistence helpers. This file covers the public binary
//! surface automation reads: the `--json` success envelope, non-TTY
//! wizard guard, and isolated user config mutation.

mod common;

use common::{parse_json_stdout, run_lpm};
use tempfile::TempDir;

fn isolated_project() -> (TempDir, TempDir) {
    let project = TempDir::new().expect("create temp project");
    let lpm_home = TempDir::new().expect("create temp LPM_HOME");

    std::fs::write(
        project.path().join("package.json"),
        r#"{"name":"typosquat-wizard-test","version":"1.0.0"}"#,
    )
    .expect("seed package.json");

    (project, lpm_home)
}

fn lpm_config_path(lpm_home: &TempDir) -> std::path::PathBuf {
    lpm_home.path().join("config.toml")
}

fn read_lpm_config(lpm_home: &TempDir) -> String {
    let path = lpm_config_path(lpm_home);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("config.toml at {} not readable: {e}", path.display()))
}

#[test]
fn typosquat_wizard_set_off_with_json_requires_security_approval_and_does_not_persist() {
    let (project, lpm_home) = isolated_project();

    let (status, stdout, stderr) = run_lpm(
        project.path(),
        lpm_home.path(),
        None,
        &["config", "--json", "typosquat", "--set", "off"],
    );

    assert!(
        !status.success(),
        "lpm config --json typosquat --set off must require approval;\nstdout:\n{stdout}\nstderr:\n{stderr}",
    );

    let envelope = parse_json_stdout(&stdout);
    assert_eq!(envelope["success"], serde_json::json!(false));
    assert_eq!(
        envelope["error_code"],
        serde_json::json!("security_approval_required"),
        "guarded weakening must use the security approval envelope; got: {envelope}",
    );

    assert!(
        !lpm_config_path(&lpm_home).exists(),
        "refused --set off must not create config.toml",
    );
}

#[test]
fn typosquat_wizard_set_on_with_json_announces_success_and_persists_override() {
    let (project, lpm_home) = isolated_project();

    let (status, stdout, stderr) = run_lpm(
        project.path(),
        lpm_home.path(),
        None,
        &["config", "--json", "typosquat", "--set", "on"],
    );

    assert!(
        status.success(),
        "lpm config --json typosquat --set on must succeed;\nstdout:\n{stdout}\nstderr:\n{stderr}",
    );

    let envelope = parse_json_stdout(&stdout);
    assert_eq!(envelope["success"], serde_json::json!(true));
    assert_eq!(envelope["typosquat-guard"], serde_json::json!("on"));

    let cfg = read_lpm_config(&lpm_home);
    assert!(
        cfg.contains("typosquat-guard = \"on\""),
        "config.toml must persist typosquat-guard = on; got:\n{cfg}",
    );
}

#[test]
fn typosquat_wizard_set_default_with_json_removes_existing_override() {
    let (project, lpm_home) = isolated_project();
    std::fs::write(lpm_config_path(&lpm_home), "typosquat-guard = \"on\"\n")
        .expect("seed typosquat override");

    let (status, stdout, stderr) = run_lpm(
        project.path(),
        lpm_home.path(),
        None,
        &["config", "--json", "typosquat", "--set", "default"],
    );

    assert!(
        status.success(),
        "lpm config --json typosquat --set default must succeed;\nstdout:\n{stdout}\nstderr:\n{stderr}",
    );

    let envelope = parse_json_stdout(&stdout);
    assert_eq!(envelope["success"], serde_json::json!(true));
    assert_eq!(envelope["typosquat-guard"], serde_json::json!("default"));

    let cfg = read_lpm_config(&lpm_home);
    assert!(
        !cfg.contains("typosquat-guard"),
        "default must remove the explicit typosquat-guard override; got:\n{cfg}",
    );
}

#[test]
fn typosquat_wizard_without_set_and_without_tty_errors_with_actionable_diagnostic() {
    let (project, lpm_home) = isolated_project();

    let (status, stdout, stderr) = run_lpm(
        project.path(),
        lpm_home.path(),
        None,
        &["config", "typosquat"],
    );

    assert!(
        !status.success(),
        "lpm config typosquat without --set and without TTY must fail;\nstdout:\n{stdout}\nstderr:\n{stderr}",
    );
    let combined = format!("{stdout}{stderr}");
    assert!(
        combined.contains("TTY") && combined.contains("--set default|on|off"),
        "error must name the TTY requirement and --set escape hatch; got:\n{combined}",
    );
}

#[test]
fn typosquat_wizard_set_rejects_unknown_value_without_persisting() {
    let (project, lpm_home) = isolated_project();

    let (status, stdout, stderr) = run_lpm(
        project.path(),
        lpm_home.path(),
        None,
        &["config", "typosquat", "--set", "maybe"],
    );

    assert!(
        !status.success(),
        "lpm config typosquat --set maybe must fail;\nstdout:\n{stdout}\nstderr:\n{stderr}",
    );
    let combined = format!("{stdout}{stderr}");
    assert!(
        combined.contains("default") && combined.contains("on") && combined.contains("off"),
        "invalid-value diagnostic must list valid values; got:\n{combined}",
    );
    assert!(
        !lpm_config_path(&lpm_home).exists(),
        "invalid --set value must not create config.toml",
    );
}

#[test]
fn generic_config_set_typosquat_guard_off_with_json_requires_security_approval() {
    let (project, lpm_home) = isolated_project();

    let (status, stdout, stderr) = run_lpm(
        project.path(),
        lpm_home.path(),
        None,
        &["config", "--json", "set", "typosquat-guard", "off"],
    );

    assert!(
        !status.success(),
        "lpm config set typosquat-guard off must require approval;\nstdout:\n{stdout}\nstderr:\n{stderr}",
    );

    let envelope = parse_json_stdout(&stdout);
    assert_eq!(
        envelope["error_code"],
        serde_json::json!("security_approval_required"),
        "generic setter must use the same approval boundary as the wizard; got: {envelope}",
    );
    assert!(
        !lpm_config_path(&lpm_home).exists(),
        "refused generic set must not create config.toml",
    );
}
