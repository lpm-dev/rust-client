//! Cli-binary tier — machine-readable contract for
//! `lpm config release-age`.
//!
//! Inline tests in `commands/config.rs` already pin the parser,
//! canonical-seconds persistence, and preset-selection helpers. This
//! file covers the public binary surface that automation actually
//! reads: the `--json` success envelope plus the user-home
//! `config.toml` mutation.

mod common;

use common::{parse_json_stdout, run_lpm};
use tempfile::TempDir;

fn isolated_project() -> (TempDir, TempDir) {
    let project = TempDir::new().expect("create temp project");
    let lpm_home = TempDir::new().expect("create temp LPM_HOME");

    std::fs::write(
        project.path().join("package.json"),
        r#"{"name":"release-age-wizard-test","version":"1.0.0"}"#,
    )
    .expect("seed package.json");

    (project, lpm_home)
}

fn project_config_path(project: &TempDir) -> std::path::PathBuf {
    project.path().join(".lpm").join("config.toml")
}

fn read_project_config(project: &TempDir) -> String {
    let path = project_config_path(project);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("config.toml at {} not readable: {e}", path.display()))
}

/// The public machine-readable contract for the wizard is the
/// canonical-seconds envelope, not the human duration the operator
/// typed. This keeps CLI UX human-friendly while preserving a stable
/// config/storage API for downstream automation.
#[test]
fn release_age_wizard_set_duration_with_json_announces_canonical_seconds() {
    let (project, lpm_home) = isolated_project();

    let (status, stdout, stderr) = run_lpm(
        project.path(),
        lpm_home.path(),
        None,
        &["config", "--json", "release-age", "--set", "3d"],
    );

    assert!(
        status.success(),
        "lpm config --json release-age --set 3d must succeed;\nstdout:\n{stdout}\nstderr:\n{stderr}",
    );

    let envelope = parse_json_stdout(&stdout);
    assert_eq!(
        envelope["success"],
        serde_json::json!(true),
        "envelope must report success; got: {envelope}",
    );
    assert_eq!(
        envelope["minimum-release-age-secs"],
        serde_json::json!(259200),
        "envelope must announce canonical seconds, not the raw duration; got: {envelope}",
    );

    let cfg = read_project_config(&project);
    assert!(
        cfg.contains("minimum-release-age-secs = \"259200\""),
        "config.toml must persist canonical seconds after --set 3d; got:\n{cfg}",
    );
}

/// `default` is not a synonym for writing the current built-in value.
/// It means "remove the operator override entirely" so a future
/// product-default change can flow through without another CLI write.
#[test]
fn release_age_wizard_set_default_with_json_deletes_override_and_announces_null() {
    let (project, lpm_home) = isolated_project();
    let config_path = project_config_path(&project);
    std::fs::create_dir_all(config_path.parent().expect("config dir")).expect("create .lpm dir");
    std::fs::write(&config_path, "minimum-release-age-secs = \"259200\"\n")
        .expect("seed release-age override");

    let (status, stdout, stderr) = run_lpm(
        project.path(),
        lpm_home.path(),
        None,
        &["config", "--json", "release-age", "--set", "default"],
    );

    assert!(
        status.success(),
        "lpm config --json release-age --set default must succeed;\nstdout:\n{stdout}\nstderr:\n{stderr}",
    );

    let envelope = parse_json_stdout(&stdout);
    assert_eq!(
        envelope["success"],
        serde_json::json!(true),
        "envelope must report success; got: {envelope}",
    );
    assert_eq!(
        envelope["minimum-release-age-secs"],
        serde_json::Value::Null,
        "default must announce that the override is absent; got: {envelope}",
    );

    let cfg = read_project_config(&project);
    assert!(
        !cfg.contains("minimum-release-age-secs"),
        "default must delete the explicit override from config.toml; got:\n{cfg}",
    );
}
