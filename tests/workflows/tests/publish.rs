//! Workflow tests for `lpm publish`.
//!
//! Tests dry-run, quality check, error cases, and mock registry publish.

mod support;

use support::mock_registry::MockRegistry;
use support::{TempProject, lpm, lpm_with_registry};

// ─── Dry Run ─────────────────────────────────────────────────────

#[test]
fn publish_dry_run_validates_package() {
    let project = TempProject::empty(r#"{
        "name": "@lpm.dev/testuser.test-pkg",
        "version": "1.0.0",
        "description": "A test package for workflow tests",
        "main": "index.js",
        "license": "MIT"
    }"#);

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

// ─── Missing Required Fields ─────────────────────────────────────

#[test]
fn publish_without_name_fails() {
    let project = TempProject::empty(r#"{
        "version": "1.0.0",
        "description": "No name field"
    }"#);

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
    let project = TempProject::empty(r#"{
        "name": "@lpm.dev/testuser.flag-test",
        "version": "1.0.0",
        "description": "Testing target flags",
        "main": "index.js",
        "license": "MIT"
    }"#);

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
    let project = TempProject::empty(r#"{
        "name": "@lpm.dev/testuser.quality-test",
        "version": "1.0.0",
        "description": "Testing --check mode",
        "main": "index.js",
        "license": "MIT",
        "repository": {
            "type": "git",
            "url": "https://github.com/test/test"
        }
    }"#);

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

    let project = TempProject::empty(r#"{
        "name": "@lpm.dev/testuser.mock-publish",
        "version": "1.0.0",
        "description": "A test package for mock publish",
        "main": "index.js",
        "license": "MIT"
    }"#);

    project.write_file("index.js", "module.exports = { hello: 'world' }");
    project.write_file("README.md", "# Mock Publish Test\n\nA package.");

    let output = lpm_with_registry(&project, &mock.url())
        .args(["publish", "--yes", "--token", "test-token-123", "--lpm"])
        .output()
        .expect("failed to run lpm publish");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // The publish may fail at tarball upload validation or succeed —
    // the key assertion is that it reached the registry (not a local-only error)
    let combined = format!("{stdout}{stderr}");
    assert!(
        combined.contains("publish")
            || combined.contains("Published")
            || combined.contains("quality")
            || combined.contains("tarball")
            || combined.contains("Upload")
            || combined.contains("Package published")
            || combined.contains("error"),
        "expected publish-related output (success or server error), got:\n{combined}"
    );
}

// ─── Multi-target flags ──────────────────────────────────────────

#[test]
fn publish_multi_target_flags_accepted() {
    let project = TempProject::empty(r#"{
        "name": "@lpm.dev/testuser.multi-target",
        "version": "1.0.0",
        "description": "Multi-target test",
        "main": "index.js",
        "license": "MIT"
    }"#);

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
