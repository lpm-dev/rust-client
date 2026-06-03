mod support;

use support::{TempProject, lpm};

fn assert_failed(output: &std::process::Output, command_name: &str) {
    assert!(
        !output.status.success(),
        "{command_name} should fail\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn assert_no_miette_frame(output: &std::process::Output, command_name: &str) {
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    for marker in ["Error:", "×", "│", "help:", "lpm::"] {
        assert!(
            !combined.contains(marker),
            "{command_name} leaked miette marker {marker:?}\n{combined}"
        );
    }
}

#[test]
fn run_workspace_concurrency_validation_error_renders_as_slim_error() {
    let project = TempProject::empty(
        r#"{"name":"slim-error-run","version":"1.0.0","scripts":{"build":"node -e \"\" "}}"#,
    );

    let output = lpm(&project)
        .args([
            "--color=never",
            "run",
            "--workspace-concurrency",
            "2",
            "build",
        ])
        .output()
        .expect("failed to run lpm run validation repro");

    assert_failed(&output, "lpm run --workspace-concurrency");
    assert_no_miette_frame(&output, "lpm run --workspace-concurrency");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("✗ Script error"),
        "stderr should carry slim failure headline:\n{stderr}"
    );
    assert!(
        stderr.contains(
            "reason --workspace-concurrency requires --all, --filter, --filter-prod, or --affected"
        ),
        "stderr should carry validation reason:\n{stderr}"
    );
}

#[test]
fn startup_env_validation_error_renders_as_slim_error() {
    let project = TempProject::empty(r#"{"name":"slim-error-startup","version":"1.0.0"}"#);

    let output = lpm(&project)
        .env("LPM_PROVENANCE_ENFORCE", "maybe")
        .args(["--color=never", "whoami"])
        .output()
        .expect("failed to run lpm startup validation repro");

    assert_failed(&output, "LPM_PROVENANCE_ENFORCE=maybe lpm whoami");
    assert_no_miette_frame(&output, "LPM_PROVENANCE_ENFORCE=maybe lpm whoami");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("✗ Registry error"),
        "stderr should carry slim registry failure headline:\n{stderr}"
    );
    assert!(
        stderr.contains("reason LPM_PROVENANCE_ENFORCE has unknown value `maybe`; must be one of: deny | warn | off"),
        "stderr should carry startup validation reason:\n{stderr}"
    );
}

#[test]
fn startup_env_validation_error_under_json_emits_single_envelope() {
    let project = TempProject::empty(r#"{"name":"slim-error-json","version":"1.0.0"}"#);

    let output = lpm(&project)
        .env("LPM_PROVENANCE_ENFORCE", "maybe")
        .args(["--color=never", "--json", "whoami"])
        .output()
        .expect("failed to run lpm startup json validation repro");

    assert_failed(&output, "LPM_PROVENANCE_ENFORCE=maybe lpm --json whoami");
    assert_no_miette_frame(&output, "LPM_PROVENANCE_ENFORCE=maybe lpm --json whoami");

    let envelope: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("stdout should be one JSON envelope");
    assert_eq!(envelope["success"], serde_json::json!(false));
    assert_eq!(envelope["error_code"], serde_json::json!("registry"));
    assert!(
        envelope["error"]
            .as_str()
            .is_some_and(|error| error.contains("LPM_PROVENANCE_ENFORCE")),
        "JSON error should carry startup validation message: {envelope:#}"
    );
}
