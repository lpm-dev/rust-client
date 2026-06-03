//! Workflow tests for `lpm publish`.
//!
//! Tests dry-run, quality check, error cases, and mock registry publish.

mod support;

use support::mock_registry::MockRegistry;
use support::{TempProject, lpm, lpm_with_registry};

// ─── Dry Run ─────────────────────────────────────────────────────

#[test]
fn publish_dry_run_validates_package() {
    let project = TempProject::empty(
        r#"{
        "name": "@lpm.dev/testuser.test-pkg",
        "version": "1.0.0",
        "description": "A test package for workflow tests",
        "main": "index.js",
        "license": "MIT"
    }"#,
    );

    // Create a minimal source file
    project.write_file("index.js", "module.exports = {}");

    let output = lpm(&project)
        .args(["publish", "--dry-run", "--yes"])
        .output()
        .expect("failed to run lpm publish --dry-run");

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    // Dry run may succeed or fail (no auth), but should show package info
    assert!(
        combined.contains("test-pkg") || combined.contains("dry") || combined.contains("preview"),
        "expected package info or dry-run indicator in output, got:\n{combined}"
    );
}

// ─── Missing package.json ────────────────────────────────────────

#[test]
fn publish_without_package_json_fails() {
    let dir = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();

    let mut cmd = assert_cmd::Command::cargo_bin("lpm-rs").unwrap();
    cmd.current_dir(dir.path());
    cmd.env("HOME", home.path());
    cmd.env("NO_COLOR", "1");
    cmd.env("LPM_NO_UPDATE_CHECK", "1");
    cmd.env_remove("LPM_TOKEN");

    let output = cmd
        .args(["publish", "--dry-run", "--yes"])
        .output()
        .expect("failed to run lpm publish");

    assert!(!output.status.success());

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("package.json") || stderr.contains("not found"),
        "expected error about missing package.json, got:\n{stderr}"
    );
}

#[test]
fn publish_secret_scan_human_failure_uses_stderr_only() {
    let project = TempProject::empty(
        r#"{
        "name": "@lpm.dev/testuser.secret-pkg",
        "version": "1.0.0",
        "description": "Contains a secret fixture",
        "main": "index.js",
        "license": "MIT"
    }"#,
    );
    project.write_file(
        "index.js",
        r#"const password = "not-a-real-secret-fixture";"#,
    );

    let output = lpm(&project)
        .args(["publish", "--dry-run", "--yes", "--lpm"])
        .output()
        .expect("failed to run lpm publish");

    assert!(!output.status.success(), "secret scan must block publish");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        stdout.trim().is_empty(),
        "human secret-scan failure must not write to stdout, got:\n{stdout}"
    );
    assert!(
        stderr.contains("! Secret scan found")
            && stderr.contains("✗ Publish blocked. Remove secrets before publishing.")
            && stderr.contains("hint If these are false positives, use --allow-secrets."),
        "expected slim stderr secret-scan failure, got:\n{stderr}"
    );
    assert!(
        !stderr.contains("Registry error") && !stderr.contains("Error:"),
        "command-owned failure should not be followed by framework diagnostics:\n{stderr}"
    );
}

#[test]
fn publish_secret_scan_json_failure_emits_single_envelope() {
    let project = TempProject::empty(
        r#"{
        "name": "@lpm.dev/testuser.secret-json-pkg",
        "version": "1.0.0",
        "description": "Contains a secret fixture",
        "main": "index.js",
        "license": "MIT"
    }"#,
    );
    project.write_file(
        "index.js",
        r#"const password = "not-a-real-json-secret-fixture";"#,
    );

    let output = lpm(&project)
        .args(["--json", "publish", "--dry-run", "--yes", "--lpm"])
        .output()
        .expect("failed to run lpm publish --json");

    assert!(!output.status.success(), "secret scan must block publish");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let json: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("stdout should be one JSON object");

    assert_eq!(json["error"], "secret_scan_failed");
    assert_eq!(json["matches"][0]["pattern"], "generic_password");
    assert!(
        stderr.trim().is_empty(),
        "JSON secret-scan failure must not add human diagnostics, got:\n{stderr}"
    );
}

// ─── Missing Required Fields ─────────────────────────────────────

#[test]
fn publish_without_name_fails() {
    let project = TempProject::empty(
        r#"{
        "version": "1.0.0",
        "description": "No name field"
    }"#,
    );

    project.write_file("index.js", "module.exports = {}");

    let output = lpm(&project)
        .args(["publish", "--dry-run", "--yes"])
        .output()
        .expect("failed to run lpm publish");

    assert!(
        !output.status.success(),
        "publish should fail without a name field"
    );
}

// ─── Publish Target Flags ────────────────────────────────────────

#[test]
fn publish_accepts_target_flags() {
    let project = TempProject::empty(
        r#"{
        "name": "@lpm.dev/testuser.flag-test",
        "version": "1.0.0",
        "description": "Testing target flags",
        "main": "index.js",
        "license": "MIT"
    }"#,
    );

    project.write_file("index.js", "module.exports = {}");

    // --lpm flag should be accepted (even if it fails for auth reasons)
    let output = lpm(&project)
        .args(["publish", "--dry-run", "--yes", "--lpm"])
        .output()
        .expect("failed to run lpm publish with --lpm");

    // We just verify the flag is accepted (not an "unknown argument" error)
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("unexpected argument") && !stderr.contains("unrecognized"),
        "--lpm flag should be recognized, got:\n{stderr}"
    );
}

// ─── Quality Check Only ──────────────────────────────────────────

#[test]
fn publish_check_mode_shows_quality() {
    let project = TempProject::empty(
        r#"{
        "name": "@lpm.dev/testuser.quality-test",
        "version": "1.0.0",
        "description": "Testing --check mode",
        "main": "index.js",
        "license": "MIT",
        "repository": {
            "type": "git",
            "url": "https://github.com/test/test"
        }
    }"#,
    );

    project.write_file("index.js", "module.exports = {}");
    project.write_file("README.md", "# Quality Test\n\nA test package.");

    let output = lpm(&project)
        .args(["publish", "--check"])
        .output()
        .expect("failed to run lpm publish --check");

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    // --check should show quality report
    assert!(
        combined.contains("quality") || combined.contains("score") || combined.contains("Quality"),
        "expected quality report in --check output, got:\n{combined}"
    );
}

// ─── Mock Registry Publish ───────────────────────────────────────

#[tokio::test]
async fn publish_to_mock_registry_succeeds() {
    let mock = MockRegistry::start().await;
    mock.with_publish_endpoint().await;
    // The publish flow also calls whoami to verify auth
    mock.with_whoami("testuser", "test@example.com").await;

    let project = TempProject::empty(
        r#"{
        "name": "@lpm.dev/testuser.mock-publish",
        "version": "1.0.0",
        "description": "A test package for mock publish",
        "main": "index.js",
        "license": "MIT"
    }"#,
    );

    project.write_file("index.js", "module.exports = { hello: 'world' }");
    project.write_file("README.md", "# Mock Publish Test\n\nA package.");

    let output = lpm_with_registry(&project, &mock.url())
        .args(["publish", "--yes", "--token", "test-token-123", "--lpm"])
        .output()
        .expect("failed to run lpm publish");

    assert!(
        output.status.success(),
        "mock publish should succeed when the registry accepts the upload\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    let combined = format!("{stdout}{stderr}");
    assert!(
        combined.contains("Done · published @lpm.dev/testuser.mock-publish@1.0.0"),
        "expected publish success output, got:\n{combined}"
    );
    assert!(
        combined.contains("✓ Secret scan passed")
            && combined.contains("✓ Quality score:")
            && combined.contains("› Uploading tarball to lpm.dev")
            && combined.contains("target     @lpm.dev/testuser.mock-publish@1.0.0"),
        "publish human output should use the slim contract, got:\n{combined}"
    );
    assert!(
        !combined.contains("Packing tarball")
            && !combined.contains("Publishing as")
            && !combined.contains("Uploading..."),
        "publish human output should not include old chatter, got:\n{combined}"
    );
}

#[tokio::test]
async fn publish_rewrites_catalog_dependency_in_uploaded_tarball() {
    use base64::Engine;

    let mock = MockRegistry::start().await;
    mock.with_publish_endpoint().await;
    mock.with_whoami("testuser", "test@example.com").await;

    let project = TempProject::empty(
        r#"{
        "name": "catalog-publish-workspace",
        "version": "1.0.0",
        "private": true
    }"#,
    );

    project.write_file(
        "pnpm-workspace.yaml",
        r#"packages:
  - "packages/*"
catalog:
  ms: ^2.1.3
"#,
    );
    project.write_file(
        "packages/lib/package.json",
        r#"{
        "name": "@lpm.dev/testuser.catalog-publish",
        "version": "1.0.0",
        "description": "Catalog publish rewrite test",
        "main": "index.js",
        "license": "MIT",
        "dependencies": {
            "ms": "catalog:"
        }
    }"#,
    );
    project.write_file("packages/lib/index.js", "module.exports = require(\"ms\")");

    let mut cmd = lpm_with_registry(&project, &mock.url());
    cmd.current_dir(project.path().join("packages/lib"));
    let output = cmd
        .args(["publish", "--yes", "--token", "test-token-123", "--lpm"])
        .output()
        .expect("failed to run lpm publish for catalog workspace member");

    assert!(
        output.status.success(),
        "catalog-backed publish must succeed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let requests = mock
        .server()
        .received_requests()
        .await
        .expect("wiremock request log must be available");
    let publish_request = requests
        .iter()
        .find(|request| request.method.as_str() == "PUT")
        .unwrap_or_else(|| {
            panic!(
                "expected a publish PUT request, got {} request(s)",
                requests.len()
            )
        });

    let payload: serde_json::Value = serde_json::from_slice(&publish_request.body)
        .expect("publish request body must be valid JSON");
    let attachment = payload["_attachments"]
        .as_object()
        .and_then(|attachments| attachments.values().next())
        .unwrap_or_else(|| panic!("publish payload must contain one tarball attachment"));
    let tarball_data = base64::engine::general_purpose::STANDARD
        .decode(
            attachment["data"]
                .as_str()
                .expect("tarball attachment must be base64 text"),
        )
        .expect("tarball attachment must decode from base64");

    let published_package_json = extract_uploaded_package_json(&tarball_data);
    assert_eq!(
        published_package_json["dependencies"]["ms"],
        serde_json::json!("^2.1.3"),
        "published tarball must rewrite catalog: to the workspace catalog range"
    );
    assert!(
        !published_package_json.to_string().contains("catalog:"),
        "published tarball manifest must not leak catalog: references\n{}",
        serde_json::to_string_pretty(&published_package_json)
            .expect("published manifest must serialize")
    );
}

// ─── Multi-target flags ──────────────────────────────────────────

#[test]
fn publish_multi_target_flags_accepted() {
    let project = TempProject::empty(
        r#"{
        "name": "@lpm.dev/testuser.multi-target",
        "version": "1.0.0",
        "description": "Multi-target test",
        "main": "index.js",
        "license": "MIT"
    }"#,
    );

    project.write_file("index.js", "module.exports = {}");

    // --lpm --npm should both be accepted
    let output = lpm(&project)
        .args(["publish", "--dry-run", "--yes", "--lpm", "--npm"])
        .output()
        .expect("failed to run lpm publish with multi-target");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("unexpected argument") && !stderr.contains("unrecognized"),
        "--lpm --npm flags should be recognized, got:\n{stderr}"
    );
}

#[test]
fn publish_custom_registry_dry_run_json_surfaces_registry_url_and_resolved_name() {
    let project = TempProject::empty(
        r#"{
        "name": "custom-publish-pkg",
        "version": "1.2.3",
        "description": "Custom registry dry-run test",
        "main": "index.js",
        "license": "MIT"
    }"#,
    );

    project.write_file("index.js", "module.exports = {}");

    let registry_url = "https://packages.example.test/npm";
    let output = lpm(&project)
        .args([
            "publish",
            "--publish-registry",
            registry_url,
            "--dry-run",
            "--yes",
            "--json",
        ])
        .output()
        .expect("failed to run lpm publish --publish-registry --dry-run --json");

    assert!(
        output.status.success(),
        "custom registry dry-run must succeed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let envelope: serde_json::Value = serde_json::from_str(&stdout).unwrap_or_else(|e| {
        panic!("publish --publish-registry --json must be valid JSON: {e}\n---\n{stdout}")
    });

    assert_eq!(envelope["success"], serde_json::json!(true));
    assert_eq!(envelope["dry_run"], serde_json::json!(true));
    assert_eq!(envelope["name"], serde_json::json!("custom-publish-pkg"));
    assert_eq!(envelope["version"], serde_json::json!("1.2.3"));

    let targets = envelope["targets"]
        .as_array()
        .expect("targets must be an array");
    assert_eq!(targets.len(), 1, "custom dry-run should resolve one target");
    assert_eq!(targets[0]["registry"], serde_json::json!(registry_url));
    assert_eq!(targets[0]["name"], serde_json::json!("custom-publish-pkg"));
}

// ─── --github / --gitlab provider flags ───────────────────────────────
//
// The github/gitlab targets eventually hit GitHub Packages and GitLab
// Packages. Workflow tests cover the dry-run plan envelope only (the
// target enum is resolved without doing any network).

#[test]
fn publish_github_dry_run_resolves_github_target_in_json_envelope() {
    let project = TempProject::empty(
        r#"{
        "name": "@my-org/gh-pkg",
        "version": "1.0.0",
        "description": "GitHub Packages dry-run target",
        "main": "index.js",
        "license": "MIT"
    }"#,
    );
    project.write_file("index.js", "module.exports = {}");

    let output = lpm(&project)
        .args(["--json", "publish", "--dry-run", "--yes", "--github"])
        .output()
        .expect("failed to run lpm publish --github --dry-run");

    assert!(
        output.status.success(),
        "publish --github --dry-run --json must succeed\nstderr: {}",
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let envelope: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("publish --json must be valid JSON: {e}\n---\n{stdout}"));

    assert_eq!(envelope["dry_run"], serde_json::json!(true));
    let targets = envelope["targets"]
        .as_array()
        .expect("targets must be an array");
    assert!(
        targets
            .iter()
            .any(|t| t["registry"] == serde_json::json!("github")),
        "--github must surface a target with registry=github, got: {targets:?}",
    );
}

#[test]
fn publish_gitlab_dry_run_resolves_gitlab_target_in_json_envelope() {
    let project = TempProject::empty(
        r#"{
        "name": "@my-org/gl-pkg",
        "version": "1.0.0",
        "description": "GitLab Packages dry-run target",
        "main": "index.js",
        "license": "MIT"
    }"#,
    );
    project.write_file("index.js", "module.exports = {}");
    // GitLab Packages requires a numeric project ID in lpm.json so the
    // upload URL can be constructed; without it, dry-run fails-fast with
    // a clear configuration error.
    project.write_file(
        "lpm.json",
        r#"{ "publish": { "gitlab": { "projectId": "12345" } } }"#,
    );

    let output = lpm(&project)
        .args(["--json", "publish", "--dry-run", "--yes", "--gitlab"])
        .output()
        .expect("failed to run lpm publish --gitlab --dry-run");

    assert!(
        output.status.success(),
        "publish --gitlab --dry-run --json must succeed\nstderr: {}",
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let envelope: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("publish --json must be valid JSON: {e}\n---\n{stdout}"));

    let targets = envelope["targets"]
        .as_array()
        .expect("targets must be an array");
    assert!(
        targets
            .iter()
            .any(|t| t["registry"] == serde_json::json!("gitlab")),
        "--gitlab must surface a target with registry=gitlab, got: {targets:?}",
    );
}

#[test]
fn publish_npm_dry_run_resolves_npm_target_in_json_envelope() {
    let project = TempProject::empty(
        r#"{
        "name": "@my-org/npm-pkg",
        "version": "1.0.0",
        "description": "npm Packages dry-run target",
        "main": "index.js",
        "license": "MIT"
    }"#,
    );
    project.write_file("index.js", "module.exports = {}");

    let output = lpm(&project)
        .args(["--json", "publish", "--dry-run", "--yes", "--npm"])
        .output()
        .expect("failed to run lpm publish --npm --dry-run");

    assert!(
        output.status.success(),
        "publish --npm --dry-run --json must succeed\nstderr: {}",
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let envelope: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("publish --json must be valid JSON: {e}\n---\n{stdout}"));

    assert_eq!(envelope["dry_run"], serde_json::json!(true));
    let targets = envelope["targets"]
        .as_array()
        .expect("targets must be an array");
    assert!(
        targets
            .iter()
            .any(|t| t["registry"] == serde_json::json!("npm")),
        "--npm must surface a target with registry=npm, got: {targets:?}",
    );
}

#[test]
fn publish_github_and_gitlab_together_yields_two_targets() {
    let project = TempProject::empty(
        r#"{
        "name": "@my-org/multi-pkg",
        "version": "1.0.0",
        "description": "Multi-provider dry-run",
        "main": "index.js",
        "license": "MIT"
    }"#,
    );
    project.write_file("index.js", "module.exports = {}");
    project.write_file(
        "lpm.json",
        r#"{ "publish": { "gitlab": { "projectId": "12345" } } }"#,
    );

    let output = lpm(&project)
        .args([
            "--json",
            "publish",
            "--dry-run",
            "--yes",
            "--github",
            "--gitlab",
        ])
        .output()
        .expect("failed to run lpm publish --github --gitlab --dry-run");

    assert!(
        output.status.success(),
        "multi-provider dry-run must succeed"
    );

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let envelope: serde_json::Value = serde_json::from_str(&stdout).unwrap();

    let target_registries: Vec<&str> = envelope["targets"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|t| t["registry"].as_str())
        .collect();
    assert!(
        target_registries.contains(&"github") && target_registries.contains(&"gitlab"),
        "both providers must appear in the targets array, got: {target_registries:?}",
    );
}

fn extract_uploaded_package_json(tarball_data: &[u8]) -> serde_json::Value {
    use std::io::Read;

    let mut decoder = flate2::read::GzDecoder::new(tarball_data);
    let mut tar_data = Vec::new();
    decoder
        .read_to_end(&mut tar_data)
        .expect("published tarball must decompress");

    let mut archive = tar::Archive::new(tar_data.as_slice());
    for entry in archive
        .entries()
        .expect("published tarball must list entries")
    {
        let mut entry = entry.expect("published tarball entry must read");
        if entry
            .path()
            .expect("published tarball entry path must read")
            .to_string_lossy()
            == "package/package.json"
        {
            let mut content = String::new();
            entry
                .read_to_string(&mut content)
                .expect("published package.json must read");
            return serde_json::from_str(&content).expect("published package.json must parse");
        }
    }

    panic!("published tarball missing package/package.json");
}
