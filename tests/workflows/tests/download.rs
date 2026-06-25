mod support;

use support::assertions::{JsonType, assert_json_field, parse_json_output};
use support::mock_registry::{MockRegistry, compute_integrity, make_tarball};
use support::{
    TempProject, lpm_with_registry, write_lpm_proxy_npmrc, write_npm_firewall_global_config,
};

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
async fn download_accepts_single_string_platform_fields_from_npm_packument() {
    let project = TempProject::empty(r#"{"name": "test", "version": "1.0.0"}"#);
    let mock = MockRegistry::start().await;
    mock.with_manifest_package(
        serde_json::json!({
            "name": "@utoo/utoo-darwin-x64",
            "version": "1.0.32",
            "os": "darwin",
            "cpu": "x64",
            "libc": null,
        }),
        &[],
    )
    .await;

    let output = lpm_with_registry(&project, &mock.url())
        .args([
            "download",
            "@utoo/utoo-darwin-x64",
            "--version",
            "1.0.32",
            "--json",
            "--output",
            "utoo-out",
        ])
        .output()
        .expect("failed to run lpm download for package with string platform fields");

    assert!(
        output.status.success(),
        "download must parse npm packuments that use strings for platform fields:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let json = parse_json_output(&output.stdout);
    assert_eq!(json["success"], true);
    assert_eq!(json["package"], "@utoo/utoo-darwin-x64");
    assert_eq!(json["version"], "1.0.32");
    assert!(
        project
            .path()
            .join("utoo-out")
            .join("package.json")
            .is_file(),
        "download must extract the package after parsing the string platform fields"
    );
}

#[tokio::test]
async fn download_ignores_legacy_boolean_fields_in_other_lightdash_versions() {
    let project = TempProject::empty(r#"{"name": "test", "version": "1.0.0"}"#);
    let mock = MockRegistry::start().await;
    let package = "@lightdash/cli";
    let requested_version = "0.3168.0";
    let tarball = make_tarball(package, requested_version);
    let metadata = serde_json::json!({
        "name": package,
        "dist-tags": { "latest": requested_version },
        "versions": {
            "0.103.0-alpha.9": {
                "name": package,
                "version": "0.103.0-alpha.9",
                "bundleDependencies": [true]
            },
            "0.273.0-rc1": {
                "name": package,
                "version": "0.273.0-rc1",
                "config": {
                    "unsafe-perm": true
                }
            },
            requested_version: {
                "name": package,
                "version": requested_version,
                "dist": {
                    "tarball": mock.tarball_url(package, requested_version),
                    "integrity": compute_integrity(&tarball),
                }
            }
        }
    });
    mock.with_package_metadata_and_tarballs(package, metadata, &[(requested_version, tarball)])
        .await;

    let output = lpm_with_registry(&project, &mock.url())
        .args([
            "download",
            package,
            "--version",
            requested_version,
            "--json",
            "--output",
            "lightdash-out",
        ])
        .output()
        .expect("failed to run lpm download for @lightdash/cli");

    assert!(
        output.status.success(),
        "download must ignore legacy fields from unrelated historical versions:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let json = parse_json_output(&output.stdout);
    assert_eq!(json["success"], true);
    assert_eq!(json["package"], package);
    assert_eq!(json["version"], requested_version);
    assert!(
        project
            .path()
            .join("lightdash-out")
            .join("package.json")
            .is_file(),
        "download must extract the requested @lightdash/cli version"
    );
}

#[tokio::test]
async fn download_positional_npm_version_spec_resolves_requested_version() {
    let project = TempProject::empty(r#"{"name": "test", "version": "1.0.0"}"#);
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
        .args([
            "download",
            "react@0.14.3",
            "--json",
            "--output",
            "inline-version-out",
        ])
        .output()
        .expect("failed to run lpm download react@0.14.3 --json");

    assert!(
        output.status.success(),
        "download must accept an npm-style positional version spec:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let json = parse_json_output(&output.stdout);
    assert_eq!(json["success"], true);
    assert_eq!(json["package"], "react");
    assert_eq!(json["version"], "0.14.3");

    let package_json: serde_json::Value =
        serde_json::from_str(&project.read_file("inline-version-out/package.json"))
            .expect("download must extract a valid package.json");
    assert_eq!(package_json["version"], "0.14.3");
}

#[tokio::test]
async fn download_firewall_enforce_blocks_public_npm_package_before_tarball_fetch() {
    let project = TempProject::empty(r#"{"name": "test", "version": "1.0.0"}"#);
    write_npm_firewall_global_config(&project, "enforce");
    let mock = MockRegistry::start().await;
    write_lpm_proxy_npmrc(&project, &mock.url());
    let tarball = make_tarball("blocked-download", "1.0.0");
    mock.with_package("blocked-download", "1.0.0", &tarball)
        .await;
    mock.with_npm_firewall_block("blocked-download", "1.0.0")
        .await;

    let output = lpm_with_registry(&project, &mock.url())
        .args([
            "download",
            "blocked-download",
            "--version",
            "1.0.0",
            "--output",
            "blocked-out",
        ])
        .output()
        .expect("failed to run lpm download with firewall enforce");

    assert!(
        !output.status.success(),
        "firewall enforce must block download:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("Downloading blocked-download@1.0.0 - 🔥 LPM Firewall active"),
        "firewall-active download must show the badge; got:\n{combined}"
    );
    assert!(
        combined.contains("blocked by LPM npm firewall"),
        "error must name the firewall block; got:\n{combined}"
    );
    assert_eq!(
        mock.tarball_request_count("blocked-download", "1.0.0")
            .await,
        0,
        "firewall block must happen before tarball download"
    );
    assert!(
        !project.file_exists("blocked-out/package.json"),
        "blocked download must not extract package files"
    );
}

#[tokio::test]
async fn download_firewall_report_json_includes_verdict_summary_and_decisions() {
    let project = TempProject::empty(r#"{"name": "test", "version": "1.0.0"}"#);
    write_npm_firewall_global_config(&project, "report");
    let mock = MockRegistry::start().await;
    let tarball = make_tarball("reported-download", "1.0.0");
    mock.with_package("reported-download", "1.0.0", &tarball)
        .await;
    mock.with_npm_firewall_block("reported-download", "1.0.0")
        .await;
    write_lpm_proxy_npmrc(&project, &mock.url());

    let output = lpm_with_registry(&project, &mock.url())
        .args([
            "download",
            "reported-download",
            "--version",
            "1.0.0",
            "--json",
            "--output",
            "reported-out",
        ])
        .output()
        .expect("failed to run lpm download with firewall report");

    assert!(
        output.status.success(),
        "firewall report mode must continue:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let json = parse_json_output(&output.stdout);
    assert_eq!(json["success"], true);
    assert_eq!(json["firewall"]["enabled"], true, "{json:#}");
    assert_eq!(json["firewall"]["mode"], "report");
    assert_eq!(json["firewall"]["checked_count"], 1);
    assert_eq!(json["firewall"]["block_count"], 1);
    assert_eq!(
        json["firewall"]["decisions"][0]["name"],
        "reported-download"
    );
    assert_eq!(json["firewall"]["decisions"][0]["action"], "block");
    assert!(
        project.file_exists("reported-out/package.json"),
        "report mode must still extract package files"
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
