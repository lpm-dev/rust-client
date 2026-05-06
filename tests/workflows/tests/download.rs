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
