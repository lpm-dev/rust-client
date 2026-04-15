//! Phase 37 CLI-level regressions for the global install surface.
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

use base64::Engine;
use lpm_common::LpmRoot;
use lpm_global::{
    InstallReadyMarker, IntentPayload, PackageEntry, PackageSource, PendingEntry, Shim, TxKind,
    WalRecord, WalWriter, artifacts_complete, emit_shim, read_for, write_for, write_marker,
};
use lpm_registry::{DistInfo, PackageMetadata, VersionMetadata};
use sha2::Digest;
use std::collections::HashMap;
use std::path::Path;
use std::process::Command;
use tempfile::TempDir;
use wiremock::matchers::{method, path as match_path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[derive(Clone)]
struct MockPackageVersion {
    version: &'static str,
    dependencies: Vec<(&'static str, &'static str)>,
    bins: Vec<(&'static str, &'static str)>,
}

#[derive(Clone)]
struct MockPackage {
    name: &'static str,
    versions: Vec<MockPackageVersion>,
}

fn run_lpm(
    cwd: &Path,
    lpm_home: &Path,
    registry_url: Option<&str>,
    args: &[&str],
) -> (std::process::ExitStatus, String, String) {
    run_lpm_with_env(cwd, lpm_home, registry_url, &[], args)
}

fn run_lpm_with_env(
    cwd: &Path,
    lpm_home: &Path,
    registry_url: Option<&str>,
    extra_env: &[(&str, &str)],
    args: &[&str],
) -> (std::process::ExitStatus, String, String) {
    let exe = env!("CARGO_BIN_EXE_lpm-rs");
    let mut path_entries = vec![lpm_home.join("bin")];
    path_entries.extend(std::env::split_paths(
        &std::env::var_os("PATH").unwrap_or_default(),
    ));
    let joined_path = std::env::join_paths(path_entries).unwrap();

    let mut command = Command::new(exe);
    command
        .args(args)
        .current_dir(cwd)
        .env("HOME", cwd)
        .env("LPM_HOME", lpm_home)
        .env("PATH", joined_path)
        .env("NO_COLOR", "1")
        .env("LPM_NO_UPDATE_CHECK", "1")
        .env("LPM_DISABLE_TELEMETRY", "1")
        .env_remove("RUST_LOG");
    match registry_url {
        Some(url) => {
            command.env("LPM_REGISTRY_URL", url);
        }
        None => {
            command.env_remove("LPM_REGISTRY_URL");
        }
    }
    for (key, value) in extra_env {
        command.env(key, value);
    }

    let output = command.output().expect("failed to spawn lpm-rs");
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    (output.status, stdout, stderr)
}

fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == 0x1b && index + 1 < bytes.len() && bytes[index + 1] == b'[' {
            index += 2;
            while index < bytes.len() {
                let byte = bytes[index];
                index += 1;
                if (0x40..=0x7e).contains(&byte) {
                    break;
                }
            }
        } else {
            out.push(bytes[index] as char);
            index += 1;
        }
    }
    out
}

fn tarball_route(name: &str, version: &str) -> String {
    let sanitized = name.trim_start_matches('@').replace('/', "-");
    format!("/tarballs/{sanitized}-{version}.tgz")
}

fn append_tar_entry(
    builder: &mut tar::Builder<flate2::write::GzEncoder<Vec<u8>>>,
    path: &str,
    bytes: &[u8],
    mode: u32,
) {
    let mut header = tar::Header::new_gnu();
    header.set_size(bytes.len() as u64);
    header.set_mode(mode);
    header.set_cksum();
    builder.append_data(&mut header, path, bytes).unwrap();
}

fn make_mock_tarball(package_name: &str, version: &str, bin_entries: &[(&str, &str)]) -> Vec<u8> {
    use flate2::Compression;
    use flate2::write::GzEncoder;

    let mut builder = tar::Builder::new(GzEncoder::new(Vec::new(), Compression::default()));
    let mut package_json = serde_json::json!({
        "name": package_name,
        "version": version,
    });
    if !bin_entries.is_empty() {
        let bin_map = bin_entries
            .iter()
            .map(|(command, path)| {
                (
                    (*command).to_string(),
                    serde_json::Value::String((*path).to_string()),
                )
            })
            .collect::<serde_json::Map<String, serde_json::Value>>();
        package_json
            .as_object_mut()
            .unwrap()
            .insert("bin".into(), serde_json::Value::Object(bin_map));
    }

    let package_json_bytes = serde_json::to_vec(&package_json).unwrap();
    append_tar_entry(
        &mut builder,
        "package/package.json",
        &package_json_bytes,
        0o644,
    );

    for (_, path) in bin_entries {
        append_tar_entry(
            &mut builder,
            &format!("package/{path}"),
            b"#!/usr/bin/env node\nconsole.log('ok')\n",
            0o755,
        );
    }

    let encoder = builder.into_inner().unwrap();
    encoder.finish().unwrap()
}

fn sri_for(bytes: &[u8]) -> String {
    let digest = sha2::Sha512::digest(bytes);
    format!(
        "sha512-{}",
        base64::engine::general_purpose::STANDARD.encode(digest)
    )
}

fn make_version_metadata(
    name: &str,
    version: &str,
    dependencies: &[(&str, &str)],
    tarball_url: String,
    integrity: String,
) -> VersionMetadata {
    VersionMetadata {
        name: name.to_string(),
        version: version.to_string(),
        dependencies: dependencies
            .iter()
            .map(|(dep_name, dep_range)| (dep_name.to_string(), dep_range.to_string()))
            .collect(),
        dist: Some(DistInfo {
            tarball: Some(tarball_url),
            integrity: Some(integrity),
            shasum: None,
        }),
        ..VersionMetadata::default()
    }
}

fn make_package_metadata(name: &str, versions: Vec<VersionMetadata>) -> PackageMetadata {
    let latest = versions
        .last()
        .map(|version| version.version.clone())
        .expect("mock package metadata must include at least one version");

    PackageMetadata {
        name: name.to_string(),
        description: None,
        dist_tags: HashMap::from([("latest".to_string(), latest.clone())]),
        versions: versions
            .into_iter()
            .map(|version| (version.version.clone(), version))
            .collect(),
        time: Default::default(),
        downloads: None,
        distribution_mode: None,
        package_type: None,
        latest_version: Some(latest),
        ecosystem: None,
    }
}

async fn mount_mock_registry(server: &MockServer, packages: &[MockPackage]) {
    let mut tarballs: HashMap<(String, String), Vec<u8>> = HashMap::new();
    let mut metadata_map: HashMap<String, PackageMetadata> = HashMap::new();

    for package in packages {
        let mut versions = Vec::new();
        for version in &package.versions {
            let tarball = make_mock_tarball(package.name, version.version, &version.bins);
            let tarball_key = (package.name.to_string(), version.version.to_string());
            let tarball_url = format!(
                "{}{}",
                server.uri(),
                tarball_route(package.name, version.version)
            );
            let integrity = sri_for(&tarball);
            tarballs.insert(tarball_key, tarball);
            versions.push(make_version_metadata(
                package.name,
                version.version,
                &version.dependencies,
                tarball_url,
                integrity,
            ));
        }
        metadata_map.insert(
            package.name.to_string(),
            make_package_metadata(package.name, versions),
        );
    }

    for ((name, version), tarball) in &tarballs {
        Mock::given(method("GET"))
            .and(match_path(tarball_route(name, version)))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(tarball.clone()))
            .mount(server)
            .await;
    }

    for (name, metadata) in &metadata_map {
        Mock::given(method("GET"))
            .and(match_path(format!("/api/registry/{name}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(metadata))
            .mount(server)
            .await;
    }

    Mock::given(method("POST"))
        .and(match_path("/api/registry/batch-metadata"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "packages": metadata_map,
        })))
        .mount(server)
        .await;
}

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
    std::fs::write(install_root.join("lpm.lock"), b"# valid").unwrap();
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
    }))
}

fn parse_json_stdout(stdout: &str) -> serde_json::Value {
    let stripped = strip_ansi(stdout);
    let trimmed = stripped.trim();
    serde_json::from_str(trimmed).unwrap_or_else(|error| {
        panic!("failed to parse JSON stdout: {error}; raw stdout={trimmed:?}")
    })
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
            commands: commands.iter().map(|command| (*command).to_string()).collect(),
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
    mount_mock_registry(
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

    let (status, stdout, stderr) = run_lpm(
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

    let (status, stdout, stderr) = run_lpm(
        &cwd,
        &lpm_home,
        Some(&server.uri()),
        &["global", "update", "tool@^1.0.0"],
    );
    assert!(
        status.success(),
        "global update failed. stdout={stdout} stderr={stderr}"
    );

    let updated = read_package_row(&root, "tool");
    assert_eq!(updated.resolved, "1.1.0");
    assert_eq!(updated.saved_spec, "^1.0.0");
    assert_eq!(updated.commands, vec!["tool"]);
    assert!(
        root.install_root_for("tool", "1.1.0").exists(),
        "new install root should exist after update"
    );
    assert!(artifacts_complete(&root.bin_dir(), "tool"));
    assert_shim_points_to(&root, "tool", "tool@1.1.0");
}

#[tokio::test(flavor = "multi_thread")]
async fn cli_install_global_json_emits_single_result_document() {
    let server = MockServer::start().await;
    mount_mock_registry(
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

    let (status, stdout, stderr) = run_lpm(
        &cwd,
        &lpm_home,
        Some(&server.uri()),
        &["--json", "install", "-g", "alpha@1.0.0"],
    );
    assert!(
        status.success(),
        "install -g --json should succeed. stdout={stdout} stderr={stderr}"
    );

    let json = parse_json_stdout(&stdout);
    assert_eq!(json["success"].as_bool(), Some(true));
    assert_eq!(json["package"], "alpha");
    assert_eq!(json["version"], "1.0.0");
    assert_eq!(json["saved_spec"], "1.0.0");
    assert_eq!(json["commands"], serde_json::json!(["alpha"]));
    assert_eq!(json["path_hint"]["on_path"].as_bool(), Some(true));
}

#[tokio::test(flavor = "multi_thread")]
async fn cli_replace_bin_then_uninstall_removes_transferred_shim_cleanly() {
    let server = MockServer::start().await;
    mount_mock_registry(
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

    let (status, stdout, stderr) = run_lpm(
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

    let (status, stdout, stderr) = run_lpm(
        &cwd,
        &lpm_home,
        Some(&server.uri()),
        &[
            "install",
            "-g",
            "bar@1.0.0",
            "--replace-bin",
            "serve",
        ],
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
    assert_eq!(manifest.packages.get("bar").unwrap().commands, vec!["serve"]);
    assert_shim_points_to(&root, "serve", "bar@1.0.0");

    let (status, stdout, stderr) = run_lpm(
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
    mount_mock_registry(
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
        let (status, stdout, stderr) = run_lpm(
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

    let (status, stdout, stderr) = run_lpm(
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

    let json = parse_json_stdout(&stdout);
    assert_eq!(json["success"].as_bool(), Some(false));
    let results = json["results"].as_array().expect("results should be an array");
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
        missing["reason"].as_str().unwrap_or_default().contains("Not found"),
        "failure reason should preserve the registry not-found response: {missing:?}"
    );

    let final_manifest = read_for(&root).unwrap();
    assert_eq!(final_manifest.packages.get("alpha").unwrap().resolved, "1.1.0");
    assert_eq!(final_manifest.packages.get("beta").unwrap().resolved, "1.0.0");
    assert!(final_manifest.packages.contains_key("missing-tool"));
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
    std::fs::set_permissions(&root.bin_dir(), std::fs::Permissions::from_mode(0o555)).unwrap();

    let (status, stdout, stderr) = run_lpm(&cwd, &lpm_home, None, &["--json", "uninstall", "-g", "fragile"]);

    std::fs::set_permissions(&root.bin_dir(), original_permissions).unwrap();

    assert_eq!(
        status.code(),
        Some(1),
        "uninstall failure should exit non-zero. stdout={stdout} stderr={stderr}"
    );

    let json = parse_json_stdout(&stdout);
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

    let scan = lpm_global::WalReader::at(root.global_wal()).scan().unwrap();
    assert!(
        scan.records
            .iter()
            .any(|record| matches!(record, WalRecord::Abort { .. })),
        "aborting uninstall must append a WAL abort record"
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

    let (status, stdout, stderr) = run_lpm_with_env(
        &cwd,
        &lpm_home,
        Some(&server.uri()),
        &[("LPM_TOKEN", "test-token")],
        &["--json", "doctor"],
    );
    assert_eq!(
        status.code(),
        Some(1),
        "doctor should exit non-zero when hard failures are present. stdout={stdout} stderr={stderr}"
    );

    let json = parse_json_stdout(&stdout);
    assert_eq!(json["success"].as_bool(), Some(true));
    assert_eq!(json["no_failures"].as_bool(), Some(false));
    assert_eq!(json["clean"].as_bool(), Some(false));

    let checks = json["checks"].as_array().expect("checks should be an array");
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
        orphaned["detail"].as_str().unwrap_or_default().contains("ghost"),
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

    let (status, stdout, stderr) = run_lpm(&cwd, &lpm_home, None, &["--json", "global", "list"]);
    assert!(
        status.success(),
        "global list should trigger recovery. stdout={stdout} stderr={stderr}"
    );
    let parsed: serde_json::Value = serde_json::from_str(&strip_ansi(&stdout)).unwrap();
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
