//! Cli-binary tier — startup hard-fail for unknown
//! `LPM_PROVENANCE_ENFORCE` values. Pins the
//! `EnforceMode::validate_from_env` gate end-to-end against the
//! real `lpm-rs` binary.

use assert_cmd::Command;
use tempfile::TempDir;

fn lpm_isolated() -> (Command, TempDir, TempDir) {
    let project = TempDir::new().expect("create temp project");
    let home = TempDir::new().expect("create temp home");
    std::fs::write(
        project.path().join("package.json"),
        r#"{"name":"enforce-env-gate","version":"1.0.0"}"#,
    )
    .expect("seed package.json");
    let mut cmd = Command::cargo_bin("lpm-rs").expect("lpm-rs binary");
    cmd.current_dir(project.path());
    cmd.env("HOME", home.path());
    cmd.env("LPM_HOME", home.path().join(".lpm"));
    cmd.env("NO_COLOR", "1");
    cmd.env("LPM_NO_UPDATE_CHECK", "1");
    cmd.env("LPM_DISABLE_TELEMETRY", "1");
    cmd.env("LPM_FORCE_FILE_AUTH", "1");
    cmd.env("LPM_TEST_FAST_SCRYPT", "1");
    cmd.env("LPM_FORCE_FILE_VAULT", "1");
    cmd.env("LPM_DISABLE_HOST_CLI_AUTH", "1");
    cmd.env(
        "LPM_SECURITY_POLICY_PATH",
        home.path().join(".lpm/security-policy.toml"),
    );
    cmd.env_remove("RUST_LOG");
    cmd.env_remove("LPM_PROVENANCE_ENFORCE");
    (cmd, project, home)
}

/// A typo'd `LPM_PROVENANCE_ENFORCE` must hard-fail at startup with
/// an error naming the offending value and the three valid options.
/// Pre-fix, the internal parser silently downgraded unknown values
/// to `Deny` — security-conservative, but the operator who set
/// `LPM_PROVENANCE_ENFORCE=warm` thinking they meant `warn` got
/// fail-closed verification with no signal that their intent didn't
/// take effect. The startup gate surfaces the misconfiguration so
/// they can fix it.
#[test]
fn unknown_provenance_enforce_env_value_hard_fails_at_startup() {
    let (mut cmd, _project, _home) = lpm_isolated();

    let output = cmd
        .env("LPM_PROVENANCE_ENFORCE", "warm")
        .args(["doctor"])
        .output()
        .expect("spawn lpm doctor with bad env value");

    assert!(
        !output.status.success(),
        "bad LPM_PROVENANCE_ENFORCE value MUST fail the command at startup;\n\
         stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let combined = format!("{stdout}{stderr}");
    assert!(
        combined.contains("LPM_PROVENANCE_ENFORCE"),
        "error must name the env var so the operator knows what to fix;\n got:\n{combined}",
    );
    assert!(
        combined.contains("warm"),
        "error must quote the offending value so the operator can spot the typo;\n got:\n{combined}",
    );
    assert!(
        combined.contains("deny") && combined.contains("warn") && combined.contains("off"),
        "error must name all three valid values;\n got:\n{combined}",
    );
}

/// All three valid values pass the startup gate. Smoke test that
/// the gate doesn't false-fire on legitimate operator configs.
#[test]
fn valid_provenance_enforce_env_values_pass_the_startup_gate() {
    for value in ["deny", "warn", "off"] {
        let (mut cmd, _project, _home) = lpm_isolated();
        let output = cmd
            .env("LPM_PROVENANCE_ENFORCE", value)
            .args(["--version"])
            .output()
            .unwrap_or_else(|e| panic!("spawn lpm --version with `{value}`: {e}"));
        assert!(
            output.status.success(),
            "valid LPM_PROVENANCE_ENFORCE=`{value}` MUST pass the startup gate;\n\
             stdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }
}

/// Absent env var passes (the default code path).
#[test]
fn absent_provenance_enforce_env_passes_the_startup_gate() {
    let (mut cmd, _project, _home) = lpm_isolated();
    let output = cmd
        .args(["--version"])
        .output()
        .expect("spawn lpm --version with no env");
    assert!(
        output.status.success(),
        "absent LPM_PROVENANCE_ENFORCE (default Deny) MUST pass the startup gate",
    );
}
