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

fn assert_no_clap_error_frame(stderr: &str, command_name: &str) {
    for marker in ["error:", "For more information, try"] {
        assert!(
            !stderr.contains(marker),
            "{command_name} leaked clap's normal error frame marker {marker:?}\n{stderr}"
        );
    }
}

#[test]
fn install_linker_invalid_value_renders_as_slim_parse_error() {
    let project = TempProject::empty(r#"{"name":"slim-clap-linker","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["--color=never", "install", "--linker", "symlink"])
        .output()
        .expect("failed to run lpm install --linker symlink");

    assert_failed(&output, "lpm install --linker symlink");
    assert_eq!(output.status.code(), Some(2));
    assert!(
        output.stdout.is_empty(),
        "human parse errors must keep stdout empty; got:\n{}",
        String::from_utf8_lossy(&output.stdout)
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_no_clap_error_frame(&stderr, "lpm install --linker symlink");
    assert!(
        stderr.contains("✗ Invalid command line"),
        "stderr should carry slim parse headline:\n{stderr}"
    );
    assert!(
        stderr.contains("reason invalid value") && stderr.contains("symlink"),
        "stderr should carry invalid value reason:\n{stderr}"
    );
    assert!(
        stderr.contains("argument --linker <LINKER>"),
        "stderr should name the rejected argument:\n{stderr}"
    );
    assert!(
        stderr.contains("values isolated, hoisted"),
        "stderr should list accepted values:\n{stderr}"
    );
    assert!(
        stderr.contains("hint Run `lpm install --help`"),
        "stderr should point to command help:\n{stderr}"
    );
}

#[test]
fn install_conflicting_flags_render_as_slim_parse_error() {
    let project = TempProject::empty(r#"{"name":"slim-clap-conflict","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args([
            "--color=never",
            "install",
            "--audit-after-install",
            "--no-audit-after-install",
        ])
        .output()
        .expect("failed to run lpm install with conflicting audit flags");

    assert_failed(
        &output,
        "lpm install --audit-after-install --no-audit-after-install",
    );
    assert_eq!(output.status.code(), Some(2));

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_no_clap_error_frame(
        &stderr,
        "lpm install --audit-after-install --no-audit-after-install",
    );
    assert!(
        stderr.contains("✗ Invalid command line"),
        "stderr should carry slim parse headline:\n{stderr}"
    );
    assert!(
        stderr.contains("--audit-after-install") && stderr.contains("--no-audit-after-install"),
        "stderr should name both conflicting flags:\n{stderr}"
    );
    assert!(
        stderr.contains("usage "),
        "stderr should keep usage as a slim detail row:\n{stderr}"
    );
}

#[test]
fn json_parse_error_emits_single_usage_envelope() {
    let project = TempProject::empty(r#"{"name":"slim-clap-json","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["--color=never", "--json", "install", "--linker", "symlink"])
        .output()
        .expect("failed to run lpm --json install --linker symlink");

    assert_failed(&output, "lpm --json install --linker symlink");
    assert_eq!(output.status.code(), Some(2));
    assert!(
        output.stderr.is_empty(),
        "JSON parse errors must not emit human stderr; got:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let envelope: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("stdout should be one JSON envelope");
    assert_eq!(envelope["success"], serde_json::json!(false));
    assert_eq!(envelope["error_code"], serde_json::json!("usage"));
    assert_eq!(envelope["kind"], serde_json::json!("invalid_value"));
    assert!(
        envelope["error"]
            .as_str()
            .is_some_and(|error| error.contains("invalid value") && error.contains("symlink")),
        "JSON error should carry parse reason: {envelope:#}"
    );
    assert_eq!(envelope["argument"], serde_json::json!("--linker <LINKER>"));
    assert_eq!(
        envelope["valid_values"],
        serde_json::json!(["isolated", "hoisted"])
    );
}

#[test]
fn requested_help_keeps_clap_help_output() {
    let project = TempProject::empty(r#"{"name":"slim-clap-help","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["--color=never", "install", "--help"])
        .output()
        .expect("failed to run lpm install --help");

    assert!(
        output.status.success(),
        "requested help should succeed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.stderr.is_empty(),
        "requested help should not emit stderr; got:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Usage:") && stdout.contains("Options:"),
        "requested help should keep clap help layout:\n{stdout}"
    );
    assert!(
        !stdout.contains("✗ Invalid command line"),
        "requested help must not be rendered as a slim error:\n{stdout}"
    );
}
