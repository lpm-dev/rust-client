//! CLI-level end-to-end coverage for the global install state surface.
//!
//! **Tier placement: cli-binary.** Justification class:
//! **global-install state mutation**. These tests touch `~/.lpm/global/` (manifest WAL,
//! install-root commits, persistent shim state, startup recovery
//! roll-forward) — surfaces the workflow tier's per-project
//! `TempProject` model can't isolate cleanly. The `LpmRoot` env in
//! these tests must point at a shared `~/.lpm/global/` that survives
//! across multiple binary invocations within a single test, with the
//! WAL replay path observing real cross-invocation state. A workflow
//! harness that resets state between commands would defeat the whole
//! contract.
//!
//! These tests spawn the real `lpm-rs` binary and exercise three
//! load-bearing flows that were under-covered at the subprocess level:
//!
//! - install exact -> `global update <pkg>@<range>` upgrades in place
//!   and preserves the user-typed saved spec
//! - `--replace-bin` transfers command ownership and `uninstall -g`
//!   removes the transferred shim without corrupting the surviving row
//! - startup recovery rolls forward a ready pending install on the
//!   next `lpm global *` invocation

use lpm_common::LpmRoot;
use lpm_global::{
    InstallReadyMarker, IntentPayload, PackageEntry, PackageSource, PendingEntry, Shim, TxKind,
    WalRecord, WalWriter, artifacts_complete, emit_shim, read_for, write_for, write_marker,
};
use std::path::Path;
use tempfile::TempDir;
use wiremock::matchers::{method, path as match_path};
use wiremock::{Mock, MockServer, ResponseTemplate};

mod common;

use common::{MockPackage, MockPackageVersion};

fn read_package_row(root: &LpmRoot, package: &str) -> lpm_global::PackageEntry {
    read_for(root)
        .unwrap()
        .packages
        .get(package)
        .cloned()
        .unwrap_or_else(|| panic!("missing package row for {package}"))
}

fn make_complete_install_root(install_root: &Path, commands: &[&str]) {
    let bin_dir = install_root.join("node_modules").join(".bin");
    std::fs::create_dir_all(&bin_dir).unwrap();
    for command in commands {
        let target = bin_dir.join(command);
        std::fs::write(&target, b"#!/bin/sh\necho ok\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
    }
    std::fs::write(
        install_root.join("lpm.lock"),
        lpm_global::MINIMAL_VALID_LOCKFILE_TOML,
    )
    .unwrap();
    write_marker(
        install_root,
        &InstallReadyMarker::new(commands.iter().map(|command| command.to_string()).collect()),
    )
    .unwrap();
}

fn pending_install(root_relative: &str) -> PendingEntry {
    PendingEntry {
        saved_spec: "^1".into(),
        resolved: "1.0.0".into(),
        integrity: "sha512-recover".into(),
        source: PackageSource::UpstreamNpm,
        started_at: chrono::Utc::now(),
        root: root_relative.into(),
        commands: Vec::new(),
        replaces_version: None,
    }
}

fn install_intent(tx_id: &str, package: &str, new_root: &Path, root_relative: &str) -> WalRecord {
    WalRecord::Intent(Box::new(IntentPayload {
        tx_id: tx_id.into(),
        kind: TxKind::Install,
        package: package.into(),
        new_root_path: new_root.to_path_buf(),
        new_row_json: serde_json::json!({
            "saved_spec": "^1",
            "resolved": "1.0.0",
            "integrity": "sha512-recover",
            "source": "upstream-npm",
            "started_at": "2026-04-15T00:00:00Z",
            "root": root_relative,
            "commands": [],
        }),
        prior_active_row_json: None,
        prior_command_ownership_json: serde_json::json!({}),
        new_aliases_json: serde_json::json!({}),
        ownership_delta: Vec::new(),
        uninstall_trust_prune: Vec::new(),
    }))
}

fn seed_active_global_package(
    root: &LpmRoot,
    package: &str,
    version: &str,
    saved_spec: &str,
    commands: &[&str],
    emit_owned_shims: bool,
) -> std::path::PathBuf {
    let install_root = root.install_root_for(package, version);
    make_complete_install_root(&install_root, commands);

    let mut manifest = read_for(root).unwrap_or_default();
    manifest.packages.insert(
        package.into(),
        PackageEntry {
            saved_spec: saved_spec.into(),
            resolved: version.into(),
            integrity: format!("sha512-{package}-{version}"),
            source: PackageSource::UpstreamNpm,
            installed_at: chrono::Utc::now(),
            root: format!("installs/{package}@{version}"),
            commands: commands
                .iter()
                .map(|command| (*command).to_string())
                .collect(),
        },
    );
    write_for(root, &manifest).unwrap();

    if emit_owned_shims {
        let install_bin = install_root.join("node_modules").join(".bin");
        for command in commands {
            emit_shim(
                &root.bin_dir(),
                &Shim {
                    command_name: (*command).to_string(),
                    target: install_bin.join(command),
                },
            )
            .unwrap();
        }
    }

    install_root
}

fn write_fake_node(bin_dir: &Path) {
    std::fs::create_dir_all(bin_dir).unwrap();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let node_path = bin_dir.join("node");
        std::fs::write(&node_path, b"#!/bin/sh\necho v22.0.0\n").unwrap();
        std::fs::set_permissions(&node_path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    #[cfg(windows)]
    {
        let node_path = bin_dir.join("node.cmd");
        std::fs::write(&node_path, b"@echo v22.0.0\r\n").unwrap();
    }
}

fn assert_shim_points_to(root: &LpmRoot, command_name: &str, expected_fragment: &str) {
    #[cfg(unix)]
    {
        let target = std::fs::read_link(root.bin_dir().join(command_name)).unwrap();
        let rendered = target.to_string_lossy();
        assert!(
            rendered.contains(expected_fragment),
            "expected shim {command_name} to point at {expected_fragment}, got {rendered}"
        );
    }

    #[cfg(windows)]
    {
        let contents =
            std::fs::read_to_string(root.bin_dir().join(format!("{command_name}.cmd"))).unwrap();
        assert!(
            contents.contains(expected_fragment),
            "expected shim {command_name} to contain {expected_fragment}, got {contents}"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn cli_global_update_upgrades_exact_install_and_preserves_user_range() {
    let server = MockServer::start().await;
    common::mount_mock_registry(
        &server,
        &[MockPackage {
            name: "tool",
            versions: vec![
                MockPackageVersion {
                    version: "1.0.0",
                    dependencies: Vec::new(),
                    bins: vec![("tool", "bin/tool.js")],
                },
                MockPackageVersion {
                    version: "1.1.0",
                    dependencies: Vec::new(),
                    bins: vec![("tool", "bin/tool.js")],
                },
            ],
        }],
    )
    .await;

    let sandbox = TempDir::new().unwrap();
    let cwd = sandbox.path().join("workspace");
    let lpm_home = sandbox.path().join("lpm-home");
    std::fs::create_dir_all(&cwd).unwrap();
    std::fs::create_dir_all(&lpm_home).unwrap();
    let root = LpmRoot::from_dir(&lpm_home);

    let (status, stdout, stderr) = common::run_lpm(
        &cwd,
        &lpm_home,
        Some(&server.uri()),
        &["install", "-g", "tool@1.0.0"],
    );
    assert!(
        status.success(),
        "install -g failed. stdout={stdout} stderr={stderr}"
    );

    let initial = read_package_row(&root, "tool");
    assert_eq!(initial.resolved, "1.0.0");
    assert_eq!(initial.saved_spec, "1.0.0");
    assert_eq!(initial.commands, vec!["tool"]);
    assert!(artifacts_complete(&root.bin_dir(), "tool"));

    let (status, stdout, stderr) = common::run_lpm(
        &cwd,
        &lpm_home,
        Some(&server.uri()),
        &["global", "update", "tool@^1.0.0", "--dry-run"],
    );
    assert!(
        status.success(),
        "global update --dry-run failed. stdout={stdout} stderr={stderr}"
    );
    assert!(
        stdout.trim().is_empty(),
        "global update --dry-run human output must stay off stdout. stdout={stdout:?} stderr={stderr:?}"
    );
    assert!(
        stderr.contains("tool 1.0.0 → 1.1.0"),
        "global update --dry-run should print the plan on stderr. stderr={stderr:?}"
    );

    let metadata_requests_before_execution = server
        .received_requests()
        .await
        .expect("mock registry request log")
        .into_iter()
        .filter(|request| {
            matches!(
                request.url.path(),
                "/tool" | "/api/registry/tool" | "/api/registry/batch-metadata"
            )
        })
        .count();

    let (status, stdout, stderr) = common::run_lpm(
        &cwd,
        &lpm_home,
        Some(&server.uri()),
        &["global", "update", "tool@^1.0.0"],
    );
    assert!(
        status.success(),
        "global update failed. stdout={stdout} stderr={stderr}"
    );
    assert!(
        stdout.trim().is_empty(),
        "global update human output must stay off stdout. stdout={stdout:?} stderr={stderr:?}"
    );

    let metadata_requests_after_execution = server
        .received_requests()
        .await
        .expect("mock registry request log");
    let execution_metadata_requests = metadata_requests_after_execution
        .iter()
        .filter(|request| {
            matches!(
                request.url.path(),
                "/tool" | "/api/registry/tool" | "/api/registry/batch-metadata"
            )
        })
        .skip(metadata_requests_before_execution)
        .map(|request| {
            format!(
                "{} {} {}",
                request.method,
                request.url.path(),
                String::from_utf8_lossy(&request.body)
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        execution_metadata_requests.len(),
        1,
        "global update planning and installation must share one root packument: {execution_metadata_requests:?}"
    );

    let updated = read_package_row(&root, "tool");
    assert_eq!(updated.resolved, "1.1.0");
    assert_eq!(updated.saved_spec, "^1.0.0");
    assert_eq!(updated.commands, vec!["tool"]);
    assert!(
        root.install_root_for("tool", "1.1.0").exists(),
        "new install root should exist after update"
    );
    let expected_integrity = common::sri_for(&common::make_mock_tarball(
        "tool",
        "1.1.0",
        &[("tool", "bin/tool.js")],
    ));
    assert_eq!(updated.integrity, expected_integrity);
    let staged_lockfile = lpm_lockfile::Lockfile::read_from_file(
        &root.install_root_for("tool", "1.1.0").join("lpm.lock"),
    )
    .expect("read staged global lockfile");
    let staged = staged_lockfile
        .packages
        .iter()
        .find(|entry| entry.name == "tool")
        .expect("staged global package lock entry");
    assert_eq!(staged.version, updated.resolved);
    assert_eq!(
        staged.integrity.as_deref(),
        Some(updated.integrity.as_str())
    );
    assert!(artifacts_complete(&root.bin_dir(), "tool"));
    assert_shim_points_to(&root, "tool", "tool@1.1.0");
}

#[tokio::test(flavor = "multi_thread")]
async fn cli_install_global_json_emits_single_result_document() {
    let server = MockServer::start().await;
    common::mount_mock_registry(
        &server,
        &[MockPackage {
            name: "alpha",
            versions: vec![MockPackageVersion {
                version: "1.0.0",
                dependencies: Vec::new(),
                bins: vec![("alpha", "bin/alpha.js")],
            }],
        }],
    )
    .await;

    let sandbox = TempDir::new().unwrap();
    let cwd = sandbox.path().join("workspace");
    let lpm_home = sandbox.path().join("lpm-home");
    std::fs::create_dir_all(&cwd).unwrap();
    std::fs::create_dir_all(&lpm_home).unwrap();

    let (status, stdout, stderr) = common::run_lpm(
        &cwd,
        &lpm_home,
        Some(&server.uri()),
        &["--json", "install", "-g", "alpha@1.0.0"],
    );
    assert!(
        status.success(),
        "install -g --json should succeed. stdout={stdout} stderr={stderr}"
    );

    let json = common::parse_json_stdout(&stdout);
    assert_eq!(json["success"].as_bool(), Some(true));
    assert_eq!(json["package"], "alpha");
    assert_eq!(json["version"], "1.0.0");
    assert_eq!(json["saved_spec"], "1.0.0");
    assert_eq!(json["commands"], serde_json::json!(["alpha"]));
    assert_eq!(json["path_hint"]["on_path"].as_bool(), Some(true));
}

#[tokio::test(flavor = "multi_thread")]
async fn cli_install_global_rejects_invalid_declared_bin_without_pending_state() {
    let server = MockServer::start().await;
    common::mount_mock_registry(
        &server,
        &[MockPackage {
            name: "bad-bin",
            versions: vec![MockPackageVersion {
                version: "1.0.0",
                dependencies: Vec::new(),
                bins: vec![("../escape", "bin/escape.js")],
            }],
        }],
    )
    .await;

    let sandbox = TempDir::new().unwrap();
    let cwd = sandbox.path().join("workspace");
    let lpm_home = sandbox.path().join("lpm-home");
    std::fs::create_dir_all(&cwd).unwrap();
    std::fs::create_dir_all(&lpm_home).unwrap();
    let root = LpmRoot::from_dir(&lpm_home);

    let (status, stdout, stderr) = common::run_lpm(
        &cwd,
        &lpm_home,
        Some(&server.uri()),
        &["install", "-g", "bad-bin@1.0.0"],
    );

    assert_eq!(
        status.code(),
        Some(1),
        "install -g should reject a package with no materialized safe bin entries. stdout={stdout} stderr={stderr}"
    );

    let manifest = read_for(&root).unwrap();
    assert!(
        !manifest.packages.contains_key("bad-bin"),
        "failed install must not create an active global package row"
    );
    assert!(
        !manifest.pending.contains_key("bad-bin"),
        "failed install must roll back the pending global transaction immediately"
    );
    assert!(
        !root.install_root_for("bad-bin", "1.0.0").exists(),
        "failed install must remove the unusable install root"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn cli_replace_bin_then_uninstall_removes_transferred_shim_cleanly() {
    let server = MockServer::start().await;
    common::mount_mock_registry(
        &server,
        &[
            MockPackage {
                name: "foo",
                versions: vec![MockPackageVersion {
                    version: "1.0.0",
                    dependencies: Vec::new(),
                    bins: vec![("serve", "bin/serve.js")],
                }],
            },
            MockPackage {
                name: "bar",
                versions: vec![MockPackageVersion {
                    version: "1.0.0",
                    dependencies: Vec::new(),
                    bins: vec![("serve", "bin/serve.js")],
                }],
            },
        ],
    )
    .await;

    let sandbox = TempDir::new().unwrap();
    let cwd = sandbox.path().join("workspace");
    let lpm_home = sandbox.path().join("lpm-home");
    std::fs::create_dir_all(&cwd).unwrap();
    std::fs::create_dir_all(&lpm_home).unwrap();
    let root = LpmRoot::from_dir(&lpm_home);

    let (status, stdout, stderr) = common::run_lpm(
        &cwd,
        &lpm_home,
        Some(&server.uri()),
        &["install", "-g", "foo@1.0.0"],
    );
    assert!(
        status.success(),
        "install foo failed. stdout={stdout} stderr={stderr}"
    );
    assert_shim_points_to(&root, "serve", "foo@1.0.0");

    let (status, stdout, stderr) = common::run_lpm(
        &cwd,
        &lpm_home,
        Some(&server.uri()),
        &["install", "-g", "bar@1.0.0", "--replace-bin", "serve"],
    );
    assert!(
        status.success(),
        "install bar --replace-bin failed. stdout={stdout} stderr={stderr}"
    );

    let manifest = read_for(&root).unwrap();
    assert_eq!(
        manifest.packages.get("foo").unwrap().commands,
        Vec::<String>::new(),
        "foo should lose serve ownership after direct transfer"
    );
    assert_eq!(
        manifest.packages.get("bar").unwrap().commands,
        vec!["serve"]
    );
    assert_shim_points_to(&root, "serve", "bar@1.0.0");

    let (status, stdout, stderr) = common::run_lpm(
        &cwd,
        &lpm_home,
        Some(&server.uri()),
        &["uninstall", "-g", "bar"],
    );
    assert!(
        status.success(),
        "uninstall -g bar failed. stdout={stdout} stderr={stderr}"
    );

    let final_manifest = read_for(&root).unwrap();
    assert!(!final_manifest.packages.contains_key("bar"));
    assert_eq!(
        final_manifest.packages.get("foo").unwrap().commands,
        Vec::<String>::new(),
        "direct transfer should not resurrect serve ownership onto foo during uninstall"
    );
    assert!(
        std::fs::symlink_metadata(root.bin_dir().join("serve")).is_err(),
        "transferred serve shim should be removed when bar is uninstalled"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn cli_bulk_global_update_reports_mixed_success_skip_and_failure_in_single_json() {
    let server = MockServer::start().await;
    common::mount_mock_registry(
        &server,
        &[
            MockPackage {
                name: "alpha",
                versions: vec![
                    MockPackageVersion {
                        version: "1.0.0",
                        dependencies: Vec::new(),
                        bins: vec![("alpha", "bin/alpha.js")],
                    },
                    MockPackageVersion {
                        version: "1.1.0",
                        dependencies: Vec::new(),
                        bins: vec![("alpha", "bin/alpha.js")],
                    },
                ],
            },
            MockPackage {
                name: "beta",
                versions: vec![MockPackageVersion {
                    version: "1.0.0",
                    dependencies: Vec::new(),
                    bins: vec![("beta", "bin/beta.js")],
                }],
            },
        ],
    )
    .await;

    let sandbox = TempDir::new().unwrap();
    let cwd = sandbox.path().join("workspace");
    let lpm_home = sandbox.path().join("lpm-home");
    std::fs::create_dir_all(&cwd).unwrap();
    std::fs::create_dir_all(&lpm_home).unwrap();
    let root = LpmRoot::from_dir(&lpm_home);

    for package in ["alpha@1.0.0", "beta@1.0.0"] {
        let (status, stdout, stderr) = common::run_lpm(
            &cwd,
            &lpm_home,
            Some(&server.uri()),
            &["install", "-g", package],
        );
        assert!(
            status.success(),
            "install {package} failed. stdout={stdout} stderr={stderr}"
        );
    }

    let mut manifest = read_for(&root).unwrap();
    manifest.packages.get_mut("alpha").unwrap().saved_spec = "^1.0.0".into();
    manifest.packages.insert(
        "missing-tool".into(),
        PackageEntry {
            saved_spec: "^1.0.0".into(),
            resolved: "1.0.0".into(),
            integrity: "sha512-missing-tool".into(),
            source: PackageSource::UpstreamNpm,
            installed_at: chrono::Utc::now(),
            root: "installs/missing-tool@1.0.0".into(),
            commands: vec!["missing-tool".into()],
        },
    );
    write_for(&root, &manifest).unwrap();

    let (status, stdout, stderr) = common::run_lpm(
        &cwd,
        &lpm_home,
        Some(&server.uri()),
        &["--json", "global", "update"],
    );
    assert_eq!(
        status.code(),
        Some(1),
        "mixed bulk update should exit non-zero. stdout={stdout} stderr={stderr}"
    );

    let json = common::parse_json_stdout(&stdout);
    assert_eq!(json["success"].as_bool(), Some(false));
    let results = json["results"]
        .as_array()
        .expect("results should be an array");
    assert_eq!(results.len(), 3);

    let alpha = results
        .iter()
        .find(|entry| entry["package"] == "alpha")
        .expect("alpha result must be present");
    assert_eq!(alpha["action"], "upgraded");
    assert_eq!(alpha["from"], "1.0.0");
    assert_eq!(alpha["to"], "1.1.0");
    assert_eq!(alpha["saved_spec"], "^1.0.0");

    let beta = results
        .iter()
        .find(|entry| entry["package"] == "beta")
        .expect("beta result must be present");
    assert_eq!(beta["action"], "skip");
    assert_eq!(beta["current"], "1.0.0");

    let missing = results
        .iter()
        .find(|entry| entry["package"] == "missing-tool")
        .expect("missing-tool result must be present");
    assert_eq!(missing["action"], "failed");
    assert!(
        missing["reason"]
            .as_str()
            .unwrap_or_default()
            .contains("Not found"),
        "failure reason should preserve the registry not-found response: {missing:?}"
    );

    let final_manifest = read_for(&root).unwrap();
    assert_eq!(
        final_manifest.packages.get("alpha").unwrap().resolved,
        "1.1.0"
    );
    assert_eq!(
        final_manifest.packages.get("beta").unwrap().resolved,
        "1.0.0"
    );
    assert!(final_manifest.packages.contains_key("missing-tool"));
}

#[tokio::test(flavor = "multi_thread")]
async fn cli_global_update_exact_saved_spec_missing_from_registry_fails_instead_of_skipping() {
    let server = MockServer::start().await;
    common::mount_mock_registry(
        &server,
        &[MockPackage {
            name: "tool",
            versions: vec![MockPackageVersion {
                version: "1.1.0",
                dependencies: Vec::new(),
                bins: vec![("tool", "bin/tool.js")],
            }],
        }],
    )
    .await;

    let sandbox = TempDir::new().unwrap();
    let cwd = sandbox.path().join("workspace");
    let lpm_home = sandbox.path().join("lpm-home");
    std::fs::create_dir_all(&cwd).unwrap();
    std::fs::create_dir_all(&lpm_home).unwrap();
    let root = LpmRoot::from_dir(&lpm_home);

    seed_active_global_package(&root, "tool", "1.0.0", "1.0.0", &["tool"], true);

    let (status, stdout, stderr) = common::run_lpm(
        &cwd,
        &lpm_home,
        Some(&server.uri()),
        &["--json", "global", "update"],
    );
    assert_eq!(
        status.code(),
        Some(1),
        "exact-pinned version missing from registry must fail instead of skipping. stdout={stdout} stderr={stderr}"
    );

    let json = common::parse_json_stdout(&stdout);
    assert_eq!(json["success"].as_bool(), Some(false));
    let results = json["results"]
        .as_array()
        .expect("results should be an array");
    assert_eq!(results.len(), 1);
    assert_eq!(results[0]["package"], "tool");
    assert_eq!(results[0]["action"], "failed");
    assert!(
        results[0]["reason"]
            .as_str()
            .unwrap_or_default()
            .contains("registry no longer serves version '1.0.0'"),
        "failure reason should explain the yanked exact version: {json:?}"
    );

    let final_manifest = read_for(&root).unwrap();
    let tool = final_manifest
        .packages
        .get("tool")
        .expect("failed update must preserve active row");
    assert_eq!(tool.resolved, "1.0.0");
    assert_eq!(tool.saved_spec, "1.0.0");
    assert_shim_points_to(&root, "tool", "tool@1.0.0");
}

#[cfg(unix)]
#[test]
fn cli_uninstall_failure_emits_json_error_and_preserves_manifest_state() {
    use std::os::unix::fs::PermissionsExt;

    let sandbox = TempDir::new().unwrap();
    let cwd = sandbox.path().join("workspace");
    let lpm_home = sandbox.path().join("lpm-home");
    std::fs::create_dir_all(&cwd).unwrap();
    std::fs::create_dir_all(&lpm_home).unwrap();
    let root = LpmRoot::from_dir(&lpm_home);

    seed_active_global_package(&root, "fragile", "1.0.0", "^1.0.0", &["fragile"], true);

    let original_permissions = std::fs::metadata(root.bin_dir()).unwrap().permissions();
    std::fs::set_permissions(root.bin_dir(), std::fs::Permissions::from_mode(0o555)).unwrap();

    let (status, stdout, stderr) = common::run_lpm(
        &cwd,
        &lpm_home,
        None,
        &["--json", "uninstall", "-g", "fragile"],
    );

    std::fs::set_permissions(root.bin_dir(), original_permissions).unwrap();

    assert_eq!(
        status.code(),
        Some(1),
        "uninstall failure should exit non-zero. stdout={stdout} stderr={stderr}"
    );

    let json = common::parse_json_stdout(&stdout);
    assert_eq!(json["success"].as_bool(), Some(false));
    assert!(
        json["error"]
            .as_str()
            .unwrap_or_default()
            .contains("uninstall of 'fragile' failed"),
        "top-level json error should describe the uninstall failure: {json:?}"
    );

    let manifest = read_for(&root).unwrap();
    assert!(
        manifest.packages.contains_key("fragile"),
        "manifest entry must be preserved after uninstall abort"
    );
    assert!(
        std::fs::symlink_metadata(root.bin_dir().join("fragile")).is_ok(),
        "the existing shim should still be present after uninstall abort"
    );

    // L50 contract: when shim removal AND restoration both fail (the
    // 0o555 perm blocks emit_shim too), the transaction is left
    // unresolved so recovery retries on next invocation. The WAL
    // Intent stays on disk as the recovery handle; the WAL Abort is
    // NOT written. Pre-fix the Abort was written regardless, leaving
    // PATH and manifest divergent with no recovery path.
    let scan = lpm_global::WalReader::at(root.global_wal()).scan().unwrap();
    assert!(
        !scan
            .records
            .iter()
            .any(|record| matches!(record, WalRecord::Abort { .. })),
        "L50: when restoration also fails, WAL Abort must be skipped \
         so recovery retries — Intent remains the recovery handle"
    );
    assert!(
        scan.records
            .iter()
            .any(|record| matches!(record, WalRecord::Intent(_))),
        "Intent must still be present so recovery has the cleanup handle"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn cli_doctor_json_flags_broken_global_state_with_machine_readable_checks() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(match_path("/api/registry/health"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(match_path("/api/registry/-/whoami"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "username": "tester",
            "plan_tier": "pro",
            "available_scopes": [],
            "organizations": [],
        })))
        .mount(&server)
        .await;

    let sandbox = TempDir::new().unwrap();
    let cwd = sandbox.path().join("workspace");
    let lpm_home = sandbox.path().join("lpm-home");
    std::fs::create_dir_all(&cwd).unwrap();
    std::fs::create_dir_all(&lpm_home).unwrap();
    std::fs::create_dir_all(cwd.join("node_modules").join(".lpm")).unwrap();
    std::fs::write(
        cwd.join("package.json"),
        r#"{"name":"doctor-fixture","version":"1.0.0"}"#,
    )
    .unwrap();
    std::fs::write(
        cwd.join("lpm.lock"),
        "[metadata]\nlockfile-version = 1\nresolved-with = \"pubgrub\"\n",
    )
    .unwrap();
    write_fake_node(&lpm_home.join("bin"));

    let root = LpmRoot::from_dir(&lpm_home);
    let install_root = seed_active_global_package(
        &root,
        "broken-tool",
        "1.0.0",
        "^1.0.0",
        &["broken-tool"],
        true,
    );
    std::fs::remove_file(
        install_root
            .join("node_modules")
            .join(".bin")
            .join("broken-tool"),
    )
    .unwrap();
    std::fs::write(root.bin_dir().join("ghost"), b"#!/bin/sh\necho ghost\n").unwrap();

    let (status, stdout, stderr) = common::run_lpm_with_env(
        &cwd,
        &lpm_home,
        Some(&server.uri()),
        &[("LPM_TOKEN", "test-token")],
        // Globals diagnostics are Extended-tier; the default fast
        // preset doesn't probe `~/.lpm/global/`. Pass `--all` so the
        // crafted broken install root surfaces in the check set.
        &["--json", "doctor", "--all"],
    );
    assert_eq!(
        status.code(),
        Some(1),
        "doctor should exit non-zero when hard failures are present. stdout={stdout} stderr={stderr}"
    );

    let json = common::parse_json_stdout(&stdout);
    assert_eq!(json["success"].as_bool(), Some(true));
    assert_eq!(json["no_failures"].as_bool(), Some(false));
    assert_eq!(json["clean"].as_bool(), Some(false));

    let checks = json["checks"]
        .as_array()
        .expect("checks should be an array");
    let global_manifest = checks
        .iter()
        .find(|entry| entry["check"] == "Global manifest")
        .expect("Global manifest check should be present");
    assert_eq!(global_manifest["passed"].as_bool(), Some(true));

    let orphaned = checks
        .iter()
        .find(|entry| entry["check"] == "Orphaned shims")
        .expect("Orphaned shims check should be present");
    assert_eq!(orphaned["severity"], "warn");
    assert!(
        orphaned["detail"]
            .as_str()
            .unwrap_or_default()
            .contains("ghost"),
        "orphaned shim warning should mention the crafted ghost shim: {orphaned:?}"
    );

    let roots = checks
        .iter()
        .find(|entry| entry["check"] == "Global install roots")
        .expect("Global install roots check should be present");
    assert_eq!(roots["passed"].as_bool(), Some(false));
    assert!(
        roots["detail"]
            .as_str()
            .unwrap_or_default()
            .contains("broken-tool [MissingBinTarget"),
        "broken install root should be surfaced in doctor output: {roots:?}"
    );
}

#[test]
fn cli_startup_recovery_rolls_forward_ready_pending_install() {
    let sandbox = TempDir::new().unwrap();
    let cwd = sandbox.path().join("workspace");
    let lpm_home = sandbox.path().join("lpm-home");
    std::fs::create_dir_all(&cwd).unwrap();
    std::fs::create_dir_all(&lpm_home).unwrap();
    let root = LpmRoot::from_dir(&lpm_home);

    let install_root = root.install_root_for("recover-tool", "1.0.0");
    make_complete_install_root(&install_root, &["recover-tool"]);

    let mut manifest = lpm_global::GlobalManifest::default();
    manifest.pending.insert(
        "recover-tool".into(),
        pending_install("installs/recover-tool@1.0.0"),
    );
    write_for(&root, &manifest).unwrap();

    let mut wal = WalWriter::open(root.global_wal()).unwrap();
    wal.append(&install_intent(
        "tx-recover-tool",
        "recover-tool",
        &install_root,
        "installs/recover-tool@1.0.0",
    ))
    .unwrap();

    let (status, stdout, stderr) =
        common::run_lpm(&cwd, &lpm_home, None, &["--json", "global", "list"]);
    assert!(
        status.success(),
        "global list should trigger recovery. stdout={stdout} stderr={stderr}"
    );
    let parsed: serde_json::Value = serde_json::from_str(&common::strip_ansi(&stdout)).unwrap();
    let rendered = parsed.to_string();
    assert!(
        rendered.contains("recover-tool"),
        "recovered package should appear in global list output: {rendered}"
    );

    let recovered_manifest = read_for(&root).unwrap();
    let recovered = recovered_manifest
        .packages
        .get("recover-tool")
        .unwrap_or_else(|| panic!("recover-tool should be committed after recovery"));
    assert_eq!(recovered.resolved, "1.0.0");
    assert_eq!(recovered.saved_spec, "^1");
    assert_eq!(recovered.commands, vec!["recover-tool"]);
    assert!(
        !recovered_manifest.pending.contains_key("recover-tool"),
        "pending row must be cleared after roll-forward"
    );
    assert!(artifacts_complete(&root.bin_dir(), "recover-tool"));
    assert_shim_points_to(&root, "recover-tool", "recover-tool@1.0.0");
}
