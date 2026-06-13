mod support;

use support::mock_registry::{MockRegistry, make_tarball};
use support::{TempProject, lpm_with_registry};

fn assert_no_terminal_controls(context: &str, text: &str) {
    assert!(
        !text.bytes().any(|b| matches!(b, 0x07 | 0x1b | 0x7f)),
        "{context} must not contain terminal control bytes, got:\n{text}"
    );
}

#[tokio::test]
async fn info_human_output_uses_slim_completion_and_stdout_report() {
    let project = TempProject::empty(r#"{"name":"info-test","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    let tarball = make_tarball("@lpm.dev/owner.react", "1.0.0");
    mock.with_package_and_deps(
        "@lpm.dev/owner.react",
        "1.0.0",
        &tarball,
        serde_json::json!({
            "react": "^19.0.0",
            "@radix-ui/react-dialog": "^1.1.6"
        }),
    )
    .await;

    let output = lpm_with_registry(&project, &mock.url())
        .args(["info", "owner.react", "--version", "1.0.0"])
        .output()
        .expect("failed to run lpm info");

    assert!(
        output.status.success(),
        "lpm info failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("@lpm.dev/owner.react")
            && stdout.contains("version      1.0.0")
            && stdout.contains("integrity    sha512-")
            && stdout.contains('…')
            && stdout.contains("dependencies")
            && stdout.contains("@radix-ui/react-dialog")
            && stdout.contains("react"),
        "info report must stay on stdout, got:\n{stdout}",
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("✓ Loaded package metadata"),
        "info must finish with a slim completion line, got:\n{stderr}",
    );
    assert!(
        !stderr.contains('●') && !stderr.contains('│') && !stderr.contains('◇'),
        "info must not use cliclack gutter output, got:\n{stderr}",
    );
}

#[tokio::test]
async fn info_human_output_sanitizes_registry_control_sequences() {
    let project = TempProject::empty(r#"{"name":"info-controls","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    let tarball = make_tarball("ansi-info-pkg", "1.0.0");
    let mut metadata = mock.package_metadata("ansi-info-pkg", "1.0.0", &tarball);
    metadata["name"] = serde_json::json!("ansi-info-pkg\u{1b}[2J");
    metadata["description"] = serde_json::json!("safe description\u{1b}]52;c;AAAA\u{7}");
    metadata["versions"]["1.0.0"]["version"] = serde_json::json!("1.0.0\u{1b}[31m");
    metadata["versions"]["1.0.0"]["dependencies"] = serde_json::json!({
        "dep\u{1b}[2J": "^1.0.0\u{7}"
    });
    mock.with_package_metadata("ansi-info-pkg", "1.0.0", &tarball, metadata)
        .await;

    let output = lpm_with_registry(&project, &mock.url())
        .args(["info", "ansi-info-pkg", "--version", "1.0.0"])
        .output()
        .expect("failed to run lpm info ansi-info-pkg");

    assert!(
        output.status.success(),
        "lpm info failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_no_terminal_controls("info stdout", &stdout);
    assert!(
        stdout.contains("safe description") && stdout.contains("dependencies"),
        "sanitized info output should preserve readable registry text, got:\n{stdout}",
    );
}

#[tokio::test]
async fn info_positional_npm_version_spec_resolves_requested_version() {
    let project = TempProject::empty(r#"{"name":"info-inline-version","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    let requested_tarball = make_tarball("react", "0.14.3");
    let latest_tarball = make_tarball("react", "0.14.4");
    mock.with_full_package_metadata(
        "react",
        "0.14.4",
        &[
            ("0.14.3", serde_json::json!({}), Some(requested_tarball)),
            ("0.14.4", serde_json::json!({}), Some(latest_tarball)),
        ],
    )
    .await;

    let output = lpm_with_registry(&project, &mock.url())
        .args(["info", "react@0.14.3"])
        .output()
        .expect("failed to run lpm info react@0.14.3");

    assert!(
        output.status.success(),
        "info must accept an npm-style positional version spec:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("react") && stdout.contains("version      0.14.3"),
        "info must show the requested inline version, got:\n{stdout}",
    );
    assert!(
        !stdout.contains("version      0.14.4"),
        "info must not show latest as the selected version when inline version is requested:\n{stdout}",
    );
}
