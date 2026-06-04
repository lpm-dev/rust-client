mod support;

use support::assertions::{JsonType, assert_json_field, parse_json_output};
use support::mock_registry::{MockRegistry, make_tarball};
use support::{TempProject, lpm_with_registry};

/// `lpm download` must accept its subcommand-local `--version` flag
/// without colliding with the global `--version` bool, and the JSON
/// envelope must report the canonicalized absolute extraction path.
#[tokio::test]
async fn download_json_accepts_version_flag_and_canonicalizes_output_dir() {
    let project = TempProject::empty(r#"{"name": "test", "version": "1.0.0"}"#);
    let mock = MockRegistry::start().await;
    let tarball = make_tarball("@lpm.dev/owner.react", "1.0.0");
    mock.with_package("@lpm.dev/owner.react", "1.0.0", &tarball)
        .await;

    let output_dir_arg = "nested/../download-out";
    let output = lpm_with_registry(&project, &mock.url())
        .args([
            "download",
            "owner.react",
            "--version",
            "1.0.0",
            "--json",
            "--output",
            output_dir_arg,
        ])
        .output()
        .expect("failed to run lpm download --json");

    assert!(
        output.status.success(),
        "lpm download --json failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let json = parse_json_output(&output.stdout);
    assert_json_field(&json, "success", JsonType::Bool);
    assert_json_field(&json, "package", JsonType::String);
    assert_json_field(&json, "version", JsonType::String);
    assert_json_field(&json, "tarball_url", JsonType::String);
    assert_json_field(&json, "output_dir", JsonType::String);
    assert_json_field(&json, "files_extracted", JsonType::Number);

    assert_eq!(json["success"], true);
    assert_eq!(json["package"], "@lpm.dev/owner.react");
    assert_eq!(json["version"], "1.0.0");

    let expected_output_dir = project
        .path()
        .join("download-out")
        .canonicalize()
        .expect("download output dir should exist")
        .display()
        .to_string();
    assert_eq!(json["output_dir"], expected_output_dir);
    assert!(
        project
            .path()
            .join("download-out")
            .join("package.json")
            .is_file(),
        "download must extract files into the canonicalized output directory"
    );
}

#[tokio::test]
async fn download_version_flag_resolves_dist_tags_instead_of_exact_versions_only() {
    let project = TempProject::empty(r#"{"name": "test", "version": "1.0.0"}"#);
    let mock = MockRegistry::start().await;
    let v1_tarball = make_tarball("tagged-download", "1.0.0");
    let v2_tarball = make_tarball("tagged-download", "2.0.0");
    mock.with_full_package_metadata(
        "tagged-download",
        "2.0.0",
        &[
            ("1.0.0", serde_json::json!({}), Some(v1_tarball)),
            ("2.0.0", serde_json::json!({}), Some(v2_tarball)),
        ],
    )
    .await;

    let output = lpm_with_registry(&project, &mock.url())
        .args([
            "download",
            "tagged-download",
            "--version",
            "latest",
            "--json",
            "--output",
            "tagged-out",
        ])
        .output()
        .expect("failed to run lpm download --version latest --json");

    assert!(
        output.status.success(),
        "download --version latest must resolve the registry dist-tag:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let json = parse_json_output(&output.stdout);
    assert_eq!(json["success"], true);
    assert_eq!(json["package"], "tagged-download");
    assert_eq!(json["version"], "2.0.0");
    assert!(
        project
            .path()
            .join("tagged-out")
            .join("package.json")
            .is_file(),
        "download must extract the dist-tag resolved tarball"
    );
}

#[tokio::test]
async fn download_human_output_uses_slim_progress_and_completion() {
    let project = TempProject::empty(r#"{"name": "test", "version": "1.0.0"}"#);
    let mock = MockRegistry::start().await;
    let tarball = make_tarball("@lpm.dev/owner.react", "1.0.0");
    mock.with_package("@lpm.dev/owner.react", "1.0.0", &tarball)
        .await;

    let output = lpm_with_registry(&project, &mock.url())
        .args([
            "download",
            "owner.react",
            "--version",
            "1.0.0",
            "--output",
            "download-human",
        ])
        .output()
        .expect("failed to run lpm download");

    assert!(
        output.status.success(),
        "lpm download failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.is_empty(),
        "human download must keep the extracted file list on stderr, got stdout:\n{stdout}"
    );
    assert!(
        stderr.contains("› Resolving owner.react"),
        "download must use a slim resolve phase, got:\n{stderr}"
    );
    assert!(
        stderr.contains("› Downloading @lpm.dev/owner.react@1.0.0"),
        "download must use a slim download phase, got:\n{stderr}"
    );
    assert!(
        stderr.contains("✓ Verified integrity"),
        "download must report slim integrity verification, got:\n{stderr}"
    );
    assert!(
        stderr.contains('…') && !stderr.contains("..."),
        "download must abbreviate integrity and overflow rows with a unicode ellipsis, got:\n{stderr}"
    );
    assert!(
        stderr.contains("output:") && stderr.contains("files extracted:"),
        "download must report extraction details on stderr, got:\n{stderr}"
    );
    assert!(
        stderr.contains("✓ Done · tarball extracted in "),
        "download must report slim timed completion, got:\n{stderr}"
    );
    assert!(
        !stderr.contains('●') && !stderr.contains('│') && !stderr.contains('◇'),
        "download output must not use cliclack spinner/gutter output, got:\n{stderr}"
    );

    assert!(
        project
            .path()
            .join("download-human")
            .join("package.json")
            .is_file(),
        "download must extract files into the output directory"
    );
}
