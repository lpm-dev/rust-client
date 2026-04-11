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

// ─── Phase 33: dependency save semantics ─────────────────────────
//
// These tests validate the manifest-write contract documented in
// `DOCS/new-features/37-rust-client-RUNNER-VISION-phase33.md`. They are
// load-bearing for the "no `*` default" rule and the
// "placeholder-never-survives-failure" invariant added during plan review.
//
// All four are red until the Phase 33 implementation lands; bare installs
// currently write `"*"` to the manifest, so row 1 fails immediately, and the
// failure-restore test fails because there is no transaction guard yet.

/// Helper to fetch the `dependencies` map from a project's package.json.
fn read_dependencies(project: &TempProject) -> serde_json::Map<String, serde_json::Value> {
    let raw = project.read_file("package.json");
    let doc: serde_json::Value =
        serde_json::from_str(&raw).expect("package.json must be valid JSON");
    doc.get("dependencies")
        .and_then(|v| v.as_object())
        .cloned()
        .unwrap_or_default()
}

/// Mount the canonical `ms@2.1.3` package + batch metadata on the mock.
async fn mount_ms_2_1_3(mock: &MockRegistry) {
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
}

/// Phase 33 row 1 (smoke): a bare `lpm install ms` must write
/// `"ms": "^2.1.3"` into `package.json`, NOT `"ms": "*"`.
///
/// This is the load-bearing test for the entire phase.
#[tokio::test]
async fn install_bare_writes_caret_resolved_not_wildcard() {
    let mock = MockRegistry::start().await;
    mount_ms_2_1_3(&mock).await;

    let project = TempProject::empty(
        r#"{
        "name": "phase33-row1",
        "version": "1.0.0",
        "dependencies": {}
    }"#,
    );

    let output = lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "ms",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("failed to run lpm install ms");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "install failed:\nstdout: {stdout}\nstderr: {stderr}"
    );

    let deps = read_dependencies(&project);
    let ms_spec = deps
        .get("ms")
        .and_then(|v| v.as_str())
        .expect("dependencies.ms must be present after install");

    assert_eq!(
        ms_spec, "^2.1.3",
        "Phase 33 default: bare `lpm install ms` must save `^<resolved>`, got `{ms_spec}`. \
         If this is `\"*\"`, the placeholder is leaking into the final manifest."
    );
}

/// Phase 33 row 12: re-running `lpm install <pkg>` on a dep that already
/// exists in the manifest must NOT rewrite the existing range, even if the
/// resolved version differs from what would be the new default.
///
/// Setup: manifest has `"ms": "~2.1.3"` (a tilde range the user authored).
/// Action: `lpm install ms` (bare — no spec).
/// Expected: manifest still has `"ms": "~2.1.3"`. The bare reinstall is
/// just a refresh of lockfile/store state, not a save-spec change.
#[tokio::test]
async fn install_existing_dep_bare_reinstall_no_churn() {
    let mock = MockRegistry::start().await;
    mount_ms_2_1_3(&mock).await;

    let project = TempProject::empty(
        r#"{
        "name": "phase33-row12",
        "version": "1.0.0",
        "dependencies": {
            "ms": "~2.1.3"
        }
    }"#,
    );

    let output = lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "ms",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("failed to run lpm install ms");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "reinstall failed:\nstdout: {stdout}\nstderr: {stderr}"
    );

    let deps = read_dependencies(&project);
    let ms_spec = deps.get("ms").and_then(|v| v.as_str()).unwrap();
    assert_eq!(
        ms_spec, "~2.1.3",
        "bare reinstall must not churn an existing range; got `{ms_spec}`"
    );
}

/// **Audit Finding B regression (Medium).** When the user runs `lpm
/// install ms --filter app` from inside `packages/app/` of a workspace,
/// the project-tier `lpm.toml` MUST be read from the WORKSPACE ROOT, not
/// from `cwd` (which is `packages/app/`). Save policy is a workspace-wide
/// preference; per-member overrides would create incoherent multi-member
/// installs where the same `--filter` produces different prefixes per
/// member.
///
/// Pre-fix: `run_install_filtered_add` called
/// `SaveConfigLoader::load_for_project(cwd)`. From the workspace root the
/// root `lpm.toml` was found correctly; from `packages/app` it was not,
/// because `packages/app/lpm.toml` does not exist. The user observed
/// `lpm install ms --filter app` from the workspace root saving
/// `"~2.1.3"` while the same command from `packages/app/` saved
/// `"^2.1.3"` — save policy depending on where the user stood.
///
/// Post-fix: the loader resolves the workspace root via
/// `lpm_workspace::discover_workspace(cwd)` and reads from there.
#[tokio::test]
async fn install_filtered_from_member_dir_reads_workspace_root_lpm_toml() {
    let mock = MockRegistry::start().await;
    mount_ms_2_1_3(&mock).await;

    // Build a workspace with one member at packages/app/.
    let project = TempProject::empty(
        r#"{
        "name": "phase33-finding-b-workspace",
        "version": "1.0.0",
        "private": true,
        "workspaces": ["packages/*"]
    }"#,
    );
    project.write_file(
        "packages/app/package.json",
        r#"{
        "name": "app",
        "version": "0.0.1",
        "dependencies": {}
    }"#,
    );
    // Drop a project-tier lpm.toml ONLY at the workspace root.
    project.write_file("lpm.toml", "save-prefix = \"~\"\n");

    // Run `lpm install ms --filter app` from packages/app — this is the
    // exact scenario the audit reproduced.
    let member_dir = project.path().join("packages").join("app");
    let mut cmd = lpm_with_registry(&project, &mock.url());
    cmd.current_dir(&member_dir);
    let output = cmd
        .args([
            "install",
            "ms",
            "--filter",
            "app",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("failed to run filtered install from member dir");

    assert!(
        output.status.success(),
        "filtered install failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    // The member's manifest must reflect the workspace-root save policy.
    let app_pkg: serde_json::Value =
        serde_json::from_str(&project.read_file("packages/app/package.json")).unwrap();
    let ms_spec = app_pkg["dependencies"]["ms"]
        .as_str()
        .expect("packages/app/package.json must have a ms entry after install");

    assert_eq!(
        ms_spec, "~2.1.3",
        "Finding B: filtered install from a member dir must honor the \
         workspace-root lpm.toml. Got `{ms_spec}` (probably `^2.1.3` if \
         the loader is still reading from cwd)"
    );
}

/// **Phase 33 Step 6 end-to-end:** project-tier `./lpm.toml` with
/// `save-prefix = "~"` must affect a bare `lpm install ms` so the
/// manifest gets `"ms": "~2.1.3"`. Validates that the loader is
/// actually read by the install entry point and the resolved
/// `SaveConfig` flows into `decide_saved_dependency_spec`.
#[tokio::test]
async fn install_honors_project_lpm_toml_save_prefix_tilde() {
    let mock = MockRegistry::start().await;
    mount_ms_2_1_3(&mock).await;

    let project = TempProject::empty(
        r#"{
        "name": "phase33-project-config",
        "version": "1.0.0",
        "dependencies": {}
    }"#,
    );

    // Drop a project-tier lpm.toml asking for `~` prefixes.
    project.write_file("lpm.toml", "save-prefix = \"~\"\n");

    let output = lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "ms",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("failed to run lpm install ms");

    assert!(
        output.status.success(),
        "stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let deps = read_dependencies(&project);
    assert_eq!(
        deps.get("ms").and_then(|v| v.as_str()),
        Some("~2.1.3"),
        "project lpm.toml save-prefix='~' must override the default ^"
    );
}

/// **Phase 33 Step 6:** invalid `lpm.toml` (e.g. `save-prefix = "*"`)
/// surfaces a clear error before the install pipeline runs. The
/// transaction guard never opens because we error out at config-load
/// time.
#[tokio::test]
async fn install_rejects_lpm_toml_with_wildcard_save_prefix() {
    let mock = MockRegistry::start().await;
    mount_ms_2_1_3(&mock).await;

    let project = TempProject::empty(
        r#"{
        "name": "phase33-project-config-invalid",
        "version": "1.0.0",
        "dependencies": {}
    }"#,
    );

    project.write_file("lpm.toml", "save-prefix = \"*\"\n");

    let output = lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "ms",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("failed to run lpm install ms");

    assert!(
        !output.status.success(),
        "lpm.toml with `save-prefix = '*'` must be rejected"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("lpm.toml") && stderr.contains("save-prefix"),
        "stderr should name the file and the offending key, got:\n{stderr}"
    );

    // The manifest must be untouched (no placeholder leak — config
    // failure happens before the transaction is even constructed).
    let deps = read_dependencies(&project);
    assert!(
        !deps.contains_key("ms"),
        "rejected config must not stage anything: {deps:?}"
    );
}

/// **Phase 33 Step 6:** explicit user input still beats project config.
/// `lpm install zod@^4.3.0` with `save-prefix = "~"` in lpm.toml saves
/// `^4.3.0` (preserved verbatim), not `~4.3.6`.
#[tokio::test]
async fn install_explicit_range_beats_project_config_save_prefix() {
    let mock = MockRegistry::start().await;
    mount_ms_2_1_3(&mock).await;

    let project = TempProject::empty(
        r#"{
        "name": "phase33-explicit-beats-config",
        "version": "1.0.0",
        "dependencies": {}
    }"#,
    );
    project.write_file("lpm.toml", "save-prefix = \"~\"\n");

    let output = lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "ms@^2.0.0",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("failed to run lpm install ms@^2.0.0");

    assert!(
        output.status.success(),
        "stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let deps = read_dependencies(&project);
    assert_eq!(
        deps.get("ms").and_then(|v| v.as_str()),
        Some("^2.0.0"),
        "explicit user range must beat project lpm.toml save-prefix"
    );
}

/// **Phase 33 row 7 / Step 5 end-to-end:** `lpm install ms --exact`
/// against the mock registry must save `"ms": "2.1.3"` (no prefix).
#[tokio::test]
async fn install_with_exact_flag_saves_pinned_version() {
    let mock = MockRegistry::start().await;
    mount_ms_2_1_3(&mock).await;

    let project = TempProject::empty(
        r#"{
        "name": "phase33-flag-exact",
        "version": "1.0.0",
        "dependencies": {}
    }"#,
    );

    let output = lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "ms",
            "--exact",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("failed to run lpm install ms --exact");

    assert!(
        output.status.success(),
        "stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let deps = read_dependencies(&project);
    assert_eq!(
        deps.get("ms").and_then(|v| v.as_str()),
        Some("2.1.3"),
        "--exact must save the bare resolved version, no caret prefix"
    );
}

/// **Phase 33 row 8 / Step 5 end-to-end:** `lpm install ms --tilde`
/// must save `"ms": "~2.1.3"`.
#[tokio::test]
async fn install_with_tilde_flag_saves_tilde_resolved() {
    let mock = MockRegistry::start().await;
    mount_ms_2_1_3(&mock).await;

    let project = TempProject::empty(
        r#"{
        "name": "phase33-flag-tilde",
        "version": "1.0.0",
        "dependencies": {}
    }"#,
    );

    let output = lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "ms",
            "--tilde",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("failed to run lpm install ms --tilde");

    assert!(
        output.status.success(),
        "stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let deps = read_dependencies(&project);
    assert_eq!(
        deps.get("ms").and_then(|v| v.as_str()),
        Some("~2.1.3"),
        "--tilde must save `~<resolved>`"
    );
}

/// **Phase 33 / Step 5 end-to-end:** `lpm install ms --save-prefix '~'`
/// must save `"ms": "~2.1.3"` (same effect as `--tilde`, alternate syntax).
#[tokio::test]
async fn install_with_save_prefix_tilde_saves_tilde_resolved() {
    let mock = MockRegistry::start().await;
    mount_ms_2_1_3(&mock).await;

    let project = TempProject::empty(
        r#"{
        "name": "phase33-flag-save-prefix",
        "version": "1.0.0",
        "dependencies": {}
    }"#,
    );

    let output = lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "ms",
            "--save-prefix",
            "~",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("failed to run lpm install ms --save-prefix '~'");

    assert!(
        output.status.success(),
        "stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let deps = read_dependencies(&project);
    assert_eq!(
        deps.get("ms").and_then(|v| v.as_str()),
        Some("~2.1.3"),
        "--save-prefix '~' must save `~<resolved>`"
    );
}

/// **Phase 33 / Step 5:** `--save-prefix '*'` is rejected with a clear
/// error before the install pipeline runs. Wildcards must be requested
/// per-package via `pkg@*`, never as a save policy.
#[test]
fn install_save_prefix_wildcard_rejected() {
    let project = TempProject::empty(
        r#"{
        "name": "phase33-flag-save-prefix-wildcard",
        "version": "1.0.0",
        "dependencies": {}
    }"#,
    );

    let output = lpm(&project)
        .args(["install", "ms", "--save-prefix", "*"])
        .output()
        .expect("failed to spawn lpm install");

    assert!(
        !output.status.success(),
        "--save-prefix '*' must be rejected"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("save-prefix")
            && (stderr.contains("'*'") || stderr.contains("not allowed")),
        "stderr should explain the wildcard rejection, got:\n{stderr}"
    );
}

/// Phase 33 row 15: contradictory save-flag combinations are rejected at
/// the CLI layer with a clear error.
#[test]
fn install_contradictory_save_flags_fail() {
    let project = TempProject::empty(
        r#"{
        "name": "phase33-row15",
        "version": "1.0.0",
        "dependencies": {}
    }"#,
    );

    let output = lpm(&project)
        .args(["install", "ms", "--exact", "--tilde"])
        .output()
        .expect("failed to run lpm install");

    assert!(
        !output.status.success(),
        "contradictory --exact + --tilde must exit non-zero"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("--exact") && stderr.contains("--tilde"),
        "stderr should name the conflicting flags, got:\n{stderr}"
    );
}

// **Phase 33 audit Finding 1 regression coverage lives in unit tests.**
//
// The audit flagged a defensive-correctness issue in
// `collect_resolved_versions_from_lockfile`: a flat name-scan over
// `lockfile.packages` would pick the wrong version if the lockfile ever
// contained two entries for the same package name (one direct, one
// transitive at a different version).
//
// We attempted a workflow test that staged `legacy-pkg → ms@~1.5.0` as a
// transitive and then ran `lpm install ms` to add a new direct edge — but
// LPM's pubgrub resolver fundamentally MERGES range constraints per
// package name. Bare `lpm install ms` stages a `*` placeholder, pubgrub
// intersects `*` with the existing transitive `~1.5.0`, and resolves to a
// SINGLE version. The lockfile never grows a duplicate via this path.
//
// The Finding 1 fix is therefore a defensive correctness change with no
// reachable workflow-level reproduction in the current resolver. The
// regression coverage is the unit test
// `commands::install::tests::collect_direct_versions_*` in install.rs,
// which calls the helper directly with hand-built `Vec<InstallPackage>`
// fixtures that include both a direct and a transitive entry for the
// same name.

/// **Phase 33 audit Finding 2 regression.** When an `lpm install` against
/// an already-installed project fails partway through, the rollback MUST
/// cover the lockfile and the install-hash, not just the manifest. The
/// pre-fix transaction guard only snapshotted `package.json`, so a failed
/// finalize (or a failed multi-member install) left:
///
///   - `package.json` rolled back to its pre-stage bytes
///   - `lpm.lock` mutated by the install pipeline
///   - `.lpm/install-hash` cached for the new state
///
/// → split-brain: the manifest claims the old dep set while the lockfile
/// and the up-to-date cache reflect the new one.
///
/// The fix is two-part:
///   1. Snapshot `lpm.lock` (and `lpm.lockb`) alongside the manifest and
///      restore them on rollback.
///   2. Delete `.lpm/install-hash` on rollback (the lockfile bytes match
///      after restore, so the fast-exit check would fire even though
///      `node_modules/` is out-of-sync; deleting the hash forces the next
///      install to re-resolve and re-link).
///
/// Setup: install `ms@2.1.3` successfully, then run a failing install that
/// adds a package the mock registry doesn't know about. Assert all three
/// state files are coherent with the pre-failure project.
#[tokio::test]
async fn install_failure_rolls_back_lockfile_and_invalidates_install_hash() {
    let mock = MockRegistry::start().await;
    mount_ms_2_1_3(&mock).await;

    let project = TempProject::empty(
        r#"{
        "name": "phase33-rollback-boundary",
        "version": "1.0.0",
        "dependencies": {
            "ms": "^2.1.3"
        }
    }"#,
    );

    // 1. Successful install populates lpm.lock + .lpm/install-hash.
    lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .assert()
        .success();

    let manifest_path = project.path().join("package.json");
    let lockfile_path = project.path().join("lpm.lock");
    let lockfile_bin_path = project.path().join("lpm.lockb");
    let install_hash_path = project.path().join(".lpm").join("install-hash");

    assert!(
        lockfile_path.exists(),
        "lockfile must exist after first install"
    );
    assert!(
        install_hash_path.exists(),
        "install-hash must exist after first install"
    );

    // Capture the post-install bytes — the rollback target.
    let pre_manifest = std::fs::read(&manifest_path).unwrap();
    let pre_lockfile = std::fs::read(&lockfile_path).unwrap();
    let pre_lockfile_bin = if lockfile_bin_path.exists() {
        Some(std::fs::read(&lockfile_bin_path).unwrap())
    } else {
        None
    };

    // 2. Run a failing install: add a package the mock has never heard of.
    let output = lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "definitely-not-in-mock-registry",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("failed to spawn lpm install");

    assert!(
        !output.status.success(),
        "install of unknown package should fail; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    // 3. Assert manifest is byte-identical (Phase 33 placeholder invariant).
    let post_manifest = std::fs::read(&manifest_path).unwrap();
    assert_eq!(
        post_manifest, pre_manifest,
        "manifest must roll back; the placeholder for `definitely-not-in-mock-registry` \
         must NOT survive a failed install"
    );

    // 4. Assert lockfile is byte-identical.
    let post_lockfile = std::fs::read(&lockfile_path).unwrap();
    assert_eq!(
        post_lockfile, pre_lockfile,
        "lockfile must roll back to its pre-failure bytes; rolling back the \
         manifest alone leaves the project in a split-brain state"
    );

    // 5. Assert lpm.lockb is byte-identical (or absent if it was absent).
    if let Some(pre_bin) = pre_lockfile_bin {
        let post_bin = std::fs::read(&lockfile_bin_path).unwrap();
        assert_eq!(
            post_bin, pre_bin,
            "lpm.lockb (binary lockfile) must roll back alongside lpm.lock"
        );
    }

    // 6. Assert .lpm/install-hash was invalidated. The fast-exit check
    //    in `is_install_up_to_date` requires this file; without it, the
    //    next install re-runs the full pipeline and converges any drift
    //    between the rolled-back lockfile and the still-mutated
    //    node_modules/ tree (which the transaction guard does not snapshot).
    assert!(
        !install_hash_path.exists(),
        "rollback must delete .lpm/install-hash so the next install \
         re-resolves; otherwise the fast-exit check would fire on a \
         project whose node_modules/ no longer matches its lockfile"
    );

    // 7. Defensive: re-parse the post-rollback manifest and confirm the
    //    failed install's package name is nowhere in dependencies.
    let deps = read_dependencies(&project);
    assert!(
        !deps.contains_key("definitely-not-in-mock-registry"),
        "failed install left the unknown package in dependencies: {deps:?}"
    );
}

/// Phase 33 placeholder-never-survives invariant (added during plan review).
///
/// When `lpm install <pkg>` stages a placeholder spec into `package.json`
/// and the install pipeline subsequently fails, the manifest MUST be
/// restored to its pre-staging state byte-for-byte. The temporary `"*"`
/// placeholder must never be observable to any caller after a failed run.
///
/// Setup: project has an existing dep `"existing": "1.0.0"`. Mock registry
/// has NO packages mounted, so any metadata fetch returns 404 → install
/// fails. We run `lpm install ms` and assert:
///
/// 1. The install command exits non-zero.
/// 2. `package.json` is byte-identical to its pre-install snapshot.
/// 3. Specifically: `dependencies.ms` does NOT exist (it must not have
///    leaked through as `"*"` or anything else).
#[tokio::test]
async fn install_failure_restores_original_manifest_bytes() {
    // Empty mock — every metadata fetch will 404.
    let mock = MockRegistry::start().await;

    let original_manifest = r#"{
    "name": "phase33-failure-restore",
    "version": "1.0.0",
    "dependencies": {
        "existing": "1.0.0"
    }
}
"#;

    let project = TempProject::empty(original_manifest);

    // Capture the exact bytes before invoking install — this is what we'll
    // assert against. Includes whitespace, trailing newline, key order.
    let pre_bytes = std::fs::read(project.path().join("package.json"))
        .expect("must be able to read package.json before install");

    let output = lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "ms",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("failed to run lpm install ms");

    // Install MUST fail (mock has no `ms` package).
    assert!(
        !output.status.success(),
        "install should have failed against empty mock; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    // Manifest MUST be byte-identical to the pre-install snapshot.
    let post_bytes = std::fs::read(project.path().join("package.json"))
        .expect("package.json must still exist after failed install");

    assert_eq!(
        post_bytes,
        pre_bytes,
        "Phase 33 invariant violated: failed install left the manifest \
         in a modified state. The transaction guard must restore the \
         pre-staging bytes exactly. Post-install content:\n{}",
        String::from_utf8_lossy(&post_bytes)
    );

    // Defensive: even parsing the post manifest, `ms` must not appear
    // anywhere in dependencies. Catches the case where the bytes happen
    // to differ in whitespace but the placeholder still leaked.
    let deps = read_dependencies(&project);
    assert!(
        !deps.contains_key("ms"),
        "failed install left `ms` in dependencies map: {deps:?}"
    );
    assert_eq!(
        deps.get("existing").and_then(|v| v.as_str()),
        Some("1.0.0"),
        "pre-existing dep `existing` must be untouched after rollback"
    );
}
