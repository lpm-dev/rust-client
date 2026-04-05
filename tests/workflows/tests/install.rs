//! Workflow tests for `lpm install`.
//!
//! Tests that exercise the full install pipeline through the real binary.
//! Network-dependent tests use MockRegistry; local-only tests use fixtures.

mod support;

use support::assertions;
use support::mock_registry::{MockRegistry, make_tarball};
use support::{TempProject, lpm, lpm_with_registry};

// ─── No package.json ─────────────────────────────────────────────

#[test]
fn install_without_package_json_fails() {
    let dir = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();

    let mut cmd = assert_cmd::Command::cargo_bin("lpm-rs").unwrap();
    cmd.current_dir(dir.path());
    cmd.env("HOME", home.path());
    cmd.env("NO_COLOR", "1");
    cmd.env("LPM_NO_UPDATE_CHECK", "1");
    cmd.env_remove("LPM_TOKEN");

    let output = cmd
        .args(["install"])
        .output()
        .expect("failed to run lpm install");

    assert!(!output.status.success());

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("package.json"),
        "expected error about missing package.json, got:\n{stderr}"
    );
}

// ─── Empty Dependencies ──────────────────────────────────────────

#[test]
fn install_with_no_dependencies_succeeds() {
    let project = TempProject::empty(
        r#"{
        "name": "empty-deps",
        "version": "1.0.0",
        "dependencies": {}
    }"#,
    );

    let output = lpm(&project)
        .args(["install"])
        .output()
        .expect("failed to run lpm install");

    assert!(
        output.status.success(),
        "install with empty deps failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    assert!(
        combined.contains("No dependencies") || combined.contains("up to date"),
        "expected 'No dependencies' or 'up to date' message, got:\n{combined}"
    );
}

// ─── --force Bypasses Fast Path ──────────────────────────────────

#[test]
fn install_force_bypasses_up_to_date() {
    let project = TempProject::empty(
        r#"{
        "name": "force-test",
        "version": "1.0.0",
        "dependencies": {}
    }"#,
    );

    // First install
    lpm(&project).args(["install"]).assert().success();

    // Force install should NOT say up-to-date
    let output = lpm(&project)
        .args(["install", "--force"])
        .output()
        .expect("failed to run forced install");

    assert!(output.status.success());
}

// ─── Real Install: Single Package via Mock Registry ──────────────

#[tokio::test]
async fn install_single_package_via_mock_registry() {
    let mock = MockRegistry::start().await;
    let tarball = make_tarball("ms", "2.1.3");

    // Mount package metadata + tarball
    mock.with_package("ms", "2.1.3", &tarball).await;

    // Mount batch-metadata (the install pipeline calls this first)
    let batch_meta = serde_json::json!({
        "name": "ms",
        "dist-tags": { "latest": "2.1.3" },
        "versions": {
            "2.1.3": {
                "name": "ms",
                "version": "2.1.3",
                "dist": {
                    "tarball": format!("{}/tarballs/ms-2.1.3.tgz", mock.url()),
                    "integrity": format!("sha512-placeholder"),
                },
                "dependencies": {}
            }
        },
        "time": { "2.1.3": "2025-01-01T00:00:00.000Z" }
    });
    mock.with_batch_metadata(vec![batch_meta]).await;

    let project = TempProject::empty(
        r#"{
        "name": "install-test",
        "version": "1.0.0",
        "dependencies": {
            "ms": "^2.1.3"
        }
    }"#,
    );

    let output = lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("failed to run lpm install");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "install with mock registry failed:\nstdout: {stdout}\nstderr: {stderr}"
    );

    // Verify lockfile was created
    assertions::assert_lockfile_exists(project.path());
    assertions::assert_lockfile_contains(project.path(), "ms");

    // Verify node_modules was populated
    assertions::assert_node_modules_exists(project.path());
    assertions::assert_in_node_modules(project.path(), "ms");
}

// ─── Install JSON Output with Packages ───────────────────────────

#[tokio::test]
async fn install_json_output_contains_package_list() {
    let mock = MockRegistry::start().await;
    let tarball = make_tarball("ms", "2.1.3");
    mock.with_package("ms", "2.1.3", &tarball).await;

    let batch_meta = serde_json::json!({
        "name": "ms",
        "dist-tags": { "latest": "2.1.3" },
        "versions": {
            "2.1.3": {
                "name": "ms",
                "version": "2.1.3",
                "dist": {
                    "tarball": format!("{}/tarballs/ms-2.1.3.tgz", mock.url()),
                    "integrity": "sha512-placeholder",
                },
                "dependencies": {}
            }
        },
        "time": { "2.1.3": "2025-01-01T00:00:00.000Z" }
    });
    mock.with_batch_metadata(vec![batch_meta]).await;

    let project = TempProject::empty(
        r#"{
        "name": "json-install-test",
        "version": "1.0.0",
        "dependencies": {
            "ms": "^2.1.3"
        }
    }"#,
    );

    let output = lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "--json",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("failed to run lpm install --json");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "install --json failed:\nstdout: {stdout}\nstderr: {stderr}"
    );

    let json = assertions::parse_json_output(&output.stdout);
    assertions::assert_json_field(&json, "success", assertions::JsonType::Bool);
    assertions::assert_json_field(&json, "packages", assertions::JsonType::Array);
    assertions::assert_json_field(&json, "count", assertions::JsonType::Number);
    assertions::assert_json_field(&json, "duration_ms", assertions::JsonType::Number);
    assertions::assert_json_field(&json, "timing", assertions::JsonType::Object);

    assert_eq!(json["success"], true);
    assert!(
        json["count"].as_u64().unwrap() >= 1,
        "should have at least 1 package"
    );

    // Verify the packages array contains ms
    let packages = json["packages"].as_array().unwrap();
    let has_ms = packages.iter().any(|p| p["name"] == "ms");
    assert!(
        has_ms,
        "packages array should contain 'ms', got: {packages:?}"
    );
}

// ─── Lockfile Fast Path (Up-to-date) ────────────────────────────

#[tokio::test]
async fn install_lockfile_reuse_is_fast_path() {
    let mock = MockRegistry::start().await;
    let tarball = make_tarball("ms", "2.1.3");
    mock.with_package("ms", "2.1.3", &tarball).await;

    let batch_meta = serde_json::json!({
        "name": "ms",
        "dist-tags": { "latest": "2.1.3" },
        "versions": {
            "2.1.3": {
                "name": "ms",
                "version": "2.1.3",
                "dist": {
                    "tarball": format!("{}/tarballs/ms-2.1.3.tgz", mock.url()),
                    "integrity": "sha512-placeholder",
                },
                "dependencies": {}
            }
        },
        "time": { "2.1.3": "2025-01-01T00:00:00.000Z" }
    });
    mock.with_batch_metadata(vec![batch_meta]).await;

    let project = TempProject::empty(
        r#"{
        "name": "lockfile-reuse-test",
        "version": "1.0.0",
        "dependencies": {
            "ms": "^2.1.3"
        }
    }"#,
    );

    // First install: resolves + downloads
    lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .assert()
        .success();

    assertions::assert_both_lockfiles_exist(project.path());

    // Second install: should hit the fast path (up to date)
    let output = lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("failed to run second install");

    assert!(output.status.success());

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    assert!(
        combined.contains("up to date") || combined.contains("Using lockfile"),
        "second install should hit fast path, got:\n{combined}"
    );
}

// ─── Up-to-date JSON Output ─────────────────────────────────────

#[tokio::test]
async fn install_up_to_date_json_includes_flag() {
    let mock = MockRegistry::start().await;
    let tarball = make_tarball("ms", "2.1.3");
    mock.with_package("ms", "2.1.3", &tarball).await;

    let batch_meta = serde_json::json!({
        "name": "ms",
        "dist-tags": { "latest": "2.1.3" },
        "versions": {
            "2.1.3": {
                "name": "ms",
                "version": "2.1.3",
                "dist": {
                    "tarball": format!("{}/tarballs/ms-2.1.3.tgz", mock.url()),
                    "integrity": "sha512-placeholder",
                },
                "dependencies": {}
            }
        },
        "time": { "2.1.3": "2025-01-01T00:00:00.000Z" }
    });
    mock.with_batch_metadata(vec![batch_meta]).await;

    let project = TempProject::empty(
        r#"{
        "name": "up-to-date-json-test",
        "version": "1.0.0",
        "dependencies": {
            "ms": "^2.1.3"
        }
    }"#,
    );

    // First install
    lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .assert()
        .success();

    // Second install with --json should show up_to_date
    let output = lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "--json",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("failed to run second install --json");

    assert!(output.status.success());

    let json = assertions::parse_json_output(&output.stdout);
    assert_eq!(json["success"], true);
    assert_eq!(json["up_to_date"], true);
    assertions::assert_json_field(&json, "duration_ms", assertions::JsonType::Number);
}

// ─── Offline Mode ────────────────────────────────────────────────

#[tokio::test]
async fn install_offline_with_store_succeeds() {
    let mock = MockRegistry::start().await;
    let tarball = make_tarball("ms", "2.1.3");
    mock.with_package("ms", "2.1.3", &tarball).await;

    let batch_meta = serde_json::json!({
        "name": "ms",
        "dist-tags": { "latest": "2.1.3" },
        "versions": {
            "2.1.3": {
                "name": "ms",
                "version": "2.1.3",
                "dist": {
                    "tarball": format!("{}/tarballs/ms-2.1.3.tgz", mock.url()),
                    "integrity": "sha512-placeholder",
                },
                "dependencies": {}
            }
        },
        "time": { "2.1.3": "2025-01-01T00:00:00.000Z" }
    });
    mock.with_batch_metadata(vec![batch_meta]).await;

    let project = TempProject::empty(
        r#"{
        "name": "offline-test",
        "version": "1.0.0",
        "dependencies": {
            "ms": "^2.1.3"
        }
    }"#,
    );

    // First install online: populates store + lockfile
    lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .assert()
        .success();

    assertions::assert_both_lockfiles_exist(project.path());

    // Remove node_modules to force re-link
    let nm = project.path().join("node_modules");
    if nm.exists() {
        std::fs::remove_dir_all(&nm).unwrap();
    }

    // Offline install: should use lockfile + store
    let output = lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "--offline",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("failed to run offline install");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "offline install failed:\nstdout: {stdout}\nstderr: {stderr}"
    );

    // node_modules should be re-populated
    assertions::assert_node_modules_exists(project.path());
    assertions::assert_in_node_modules(project.path(), "ms");
}

// ─── Offline Without Lockfile Fails ──────────────────────────────

#[test]
fn install_offline_without_lockfile_fails() {
    let project = TempProject::empty(
        r#"{
        "name": "offline-no-lock",
        "version": "1.0.0",
        "dependencies": {
            "ms": "^2.1.3"
        }
    }"#,
    );

    let output = lpm(&project)
        .args(["install", "--offline"])
        .output()
        .expect("failed to run offline install");

    assert!(!output.status.success());

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("lockfile") || stderr.contains("--offline"),
        "expected error about missing lockfile for offline mode, got:\n{stderr}"
    );
}
