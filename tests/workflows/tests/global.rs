//! Workflow tests for `lpm global *` and the `lpm install -g` / `lpm uninstall -g`
//! aliases.
//!
//! [`crates/lpm-cli/tests/global_install_state_mutation.rs`] is the
//! authoritative cli-binary survivor: it exercises the full WAL +
//! manifest + shim machinery against an isolated `~/.lpm/global/` dir.
//! This workflow-tier file covers the lighter-weight contracts that
//! don't depend on the WAL / shim repair internals:
//!
//! - `lpm global list` on an empty manifest (human + --json envelope)
//! - `lpm global list --outdated` on an empty manifest
//! - `lpm global bin` prints the isolated bin path
//! - `lpm global path <pkg>` error path (no such global)
//! - `lpm global link [path]` / `unlink <pkg>` local package shims
//! - `lpm global remove <pkg>` error path (no such global)
//! - `lpm uninstall -g <pkg>` error path (alias parity)
//! - `lpm global update --dry-run` on an empty manifest (idempotent)

mod support;

use chrono::{SecondsFormat, Utc};
use lpm_global::{GlobalManifest, PackageEntry, PackageSource, WalReader, WalRecord};
use support::mock_registry::{MockRegistry, compute_integrity, make_tarball};
use support::{TempProject, lpm, lpm_with_registry_and_npm};
use wiremock::matchers::{header, method, path as wm_path};
use wiremock::{Mock, Request, Respond, ResponseTemplate};

#[derive(Clone)]
struct RecordDelayedGlobalUpdateMetadataStart {
    starts: std::sync::Arc<std::sync::Mutex<Vec<std::time::Instant>>>,
    delay: std::time::Duration,
}

impl Respond for RecordDelayedGlobalUpdateMetadataStart {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        self.starts
            .lock()
            .expect("record global-update metadata request start")
            .push(std::time::Instant::now());
        let name = request
            .url
            .path()
            .strip_prefix("/api/registry/")
            .unwrap_or_default();
        ResponseTemplate::new(200)
            .set_delay(self.delay)
            .set_body_json(serde_json::json!({
                "name": name,
                "dist-tags": { "latest": "1.1.0" },
                "versions": {
                    "1.0.0": { "name": name, "version": "1.0.0" },
                    "1.1.0": {
                        "name": name,
                        "version": "1.1.0",
                        "dist": {
                            "tarball": "https://example.invalid/package.tgz",
                            "integrity": "sha512-test"
                        }
                    }
                },
                "time": {
                    "1.0.0": "2025-01-01T00:00:00.000Z",
                    "1.1.0": "2025-01-01T00:00:00.000Z"
                }
            }))
    }
}

#[derive(Clone)]
struct GlobalOutdatedMetadata;

impl Respond for GlobalOutdatedMetadata {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let name = request.url.path().trim_start_matches('/');
        ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "name": name,
            "dist-tags": { "latest": "1.1.0" },
            "versions": {
                "1.0.0": { "name": name, "version": "1.0.0" },
                "1.1.0": { "name": name, "version": "1.1.0" }
            }
        }))
    }
}

#[derive(Clone)]
struct RecordDelayedGlobalOutdatedReleaseTimes {
    starts: std::sync::Arc<std::sync::Mutex<Vec<std::time::Instant>>>,
    delay: std::time::Duration,
}

#[derive(Clone)]
struct RecordDelayedGlobalUpdateTarballStart {
    starts: std::sync::Arc<std::sync::Mutex<Vec<std::time::Instant>>>,
    delay: std::time::Duration,
    body: Vec<u8>,
}

impl Respond for RecordDelayedGlobalUpdateTarballStart {
    fn respond(&self, _request: &Request) -> ResponseTemplate {
        self.starts
            .lock()
            .expect("record global-update tarball request start")
            .push(std::time::Instant::now());
        ResponseTemplate::new(200)
            .set_delay(self.delay)
            .set_body_bytes(self.body.clone())
    }
}

impl Respond for RecordDelayedGlobalOutdatedReleaseTimes {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        self.starts
            .lock()
            .expect("record global-outdated release-time request start")
            .push(std::time::Instant::now());
        let name = request.url.path().trim_start_matches('/');
        ResponseTemplate::new(200)
            .set_delay(self.delay)
            .set_body_json(serde_json::json!({
                "name": name,
                "dist-tags": { "latest": "1.1.0" },
                "versions": {
                    "1.0.0": { "name": name, "version": "1.0.0" },
                    "1.1.0": { "name": name, "version": "1.1.0" }
                },
                "time": {
                    "1.0.0": "2025-01-01T00:00:00.000Z",
                    "1.1.0": "2025-01-01T00:00:00.000Z"
                }
            }))
    }
}

#[cfg(unix)]
fn chmod_executable(path: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;

    let mut permissions = std::fs::metadata(path)
        .unwrap_or_else(|e| panic!("stat {}: {e}", path.display()))
        .permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(path, permissions)
        .unwrap_or_else(|e| panic!("chmod {}: {e}", path.display()));
}

fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' && chars.peek() == Some(&'[') {
            chars.next();
            for cc in chars.by_ref() {
                let cb = cc as u32;
                if (0x40..=0x7e).contains(&cb) {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

fn iso8601_n_secs_ago(n_secs: i64) -> String {
    let dt = Utc::now() - chrono::Duration::seconds(n_secs);
    dt.to_rfc3339_opts(SecondsFormat::Millis, true)
}

fn seed_global_package_with_source(
    project: &TempProject,
    package: &str,
    source: PackageSource,
    commands: Vec<String>,
) {
    let root = lpm_common::LpmRoot::from_dir(project.home().join(".lpm"));
    let mut manifest = GlobalManifest::default();
    manifest.packages.insert(
        package.to_string(),
        PackageEntry {
            saved_spec: "^1".to_string(),
            resolved: "1.0.0".to_string(),
            integrity: "sha512-test".to_string(),
            source,
            installed_at: Utc::now(),
            root: format!("installs/{package}@1.0.0"),
            commands,
        },
    );
    lpm_global::write_for(&root, &manifest).expect("write global manifest fixture");
}

fn seed_global_package(project: &TempProject, package: &str, commands: Vec<String>) {
    seed_global_package_with_source(project, package, PackageSource::UpstreamNpm, commands);
}

fn isolated_lpm_root(project: &TempProject) -> lpm_common::LpmRoot {
    lpm_common::LpmRoot::from_dir(project.home().join(".lpm"))
}

fn write_local_cli_package(project: &TempProject) -> std::path::PathBuf {
    let package_dir = project.path().join("linked-tool");
    std::fs::create_dir_all(package_dir.join("bin")).expect("create linked package dirs");
    std::fs::write(
        package_dir.join("package.json"),
        r#"{
  "name": "linked-tool",
  "version": "1.2.3",
  "bin": {
    "linked-tool": "bin/linked-tool"
  }
}"#,
    )
    .expect("write linked package manifest");
    let bin_path = package_dir.join("bin").join("linked-tool");
    std::fs::write(&bin_path, "#!/bin/sh\necho linked-tool:$1\n")
        .expect("write linked package bin");
    #[cfg(unix)]
    chmod_executable(&bin_path);
    package_dir
}

// ─── list (empty) ─────────────────────────────────────────────────────

#[test]
fn global_list_on_empty_manifest_succeeds_with_no_packages_message() {
    let project = TempProject::empty(r#"{"name":"global","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["global", "list"])
        .output()
        .expect("failed to run lpm global list");

    assert!(
        output.status.success(),
        "global list on empty HOME must succeed\nstderr: {}",
        String::from_utf8_lossy(&output.stderr),
    );

    let combined = strip_ansi(&format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    ));
    assert!(
        combined.contains("No globally-installed")
            || combined.contains("no packages")
            || combined.contains("0 package"),
        "human output must indicate empty state, got:\n{combined}",
    );
    assert!(
        combined.contains("! No globally-installed packages"),
        "global list should use a slim warning for the empty state, got:\n{combined}"
    );
    assert!(
        !combined.contains('│') && !combined.contains('◇'),
        "global list output should not use bordered/cliclack glyphs, got:\n{combined}"
    );
}

#[test]
fn global_list_json_envelope_on_empty_manifest_carries_empty_packages_array() {
    let project = TempProject::empty(r#"{"name":"global","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["--json", "global", "list"])
        .output()
        .expect("failed to run lpm global list --json");

    assert!(output.status.success(), "global list --json must succeed");

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let envelope: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("global list --json must be valid JSON: {e}\n---\n{stdout}"));

    // Schema: `packages` array — must be present and empty on fresh HOME.
    let packages = envelope["packages"]
        .as_array()
        .expect("envelope must carry packages array");
    assert!(
        packages.is_empty(),
        "fresh HOME must report zero packages, got: {envelope}",
    );
}

#[test]
fn global_list_outdated_on_empty_manifest_succeeds_with_empty_set() {
    let project = TempProject::empty(r#"{"name":"global","version":"1.0.0"}"#);

    let output = lpm(&project)
        // Use --registry pointing at port 1 so the batch-metadata probe
        // fails fast if the empty-manifest short-circuit doesn't catch.
        .args([
            "--registry",
            "http://127.0.0.1:1",
            "--insecure",
            "--json",
            "global",
            "list",
            "--outdated",
        ])
        .output()
        .expect("failed to run lpm global list --outdated --json");

    assert!(
        output.status.success(),
        "global list --outdated on empty manifest must succeed (no registry call needed)\nstderr: {}",
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let envelope: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("envelope must be valid JSON: {e}\n---\n{stdout}"));

    // Stable shape — packages array (may be empty), no outdated entries.
    if let Some(packages) = envelope["packages"].as_array() {
        assert!(packages.is_empty(), "empty manifest expected: {envelope}");
    }
}

#[tokio::test]
async fn global_list_outdated_human_output_uses_current_wanted_latest_bins_table() {
    let project = TempProject::empty(r#"{"name":"global","version":"1.0.0"}"#);
    seed_global_package_with_source(
        &project,
        "@lpm.dev/acme.demo-cli",
        PackageSource::LpmDev,
        vec!["demo".to_string()],
    );

    let mock = MockRegistry::start().await;
    mock.with_batch_metadata(vec![serde_json::json!({
        "name": "@lpm.dev/acme.demo-cli",
        "dist-tags": { "latest": "2.0.0" },
        "modified": iso8601_n_secs_ago(86_400),
        "versions": {
            "1.0.0": { "name": "@lpm.dev/acme.demo-cli", "version": "1.0.0" },
            "1.5.0": { "name": "@lpm.dev/acme.demo-cli", "version": "1.5.0" },
            "2.0.0": { "name": "@lpm.dev/acme.demo-cli", "version": "2.0.0" }
        },
        "time": {
            "1.0.0": iso8601_n_secs_ago(3 * 86_400),
            "1.5.0": iso8601_n_secs_ago(2 * 86_400),
            "2.0.0": iso8601_n_secs_ago(86_400)
        }
    })])
    .await;

    let output = lpm_with_registry_and_npm(&project, &mock.url())
        .args(["global", "list", "--outdated"])
        .output()
        .expect("failed to run lpm global list --outdated");

    assert!(
        output.status.success(),
        "global list --outdated must succeed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let combined = strip_ansi(&format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    ));
    assert!(
        combined.contains("Package")
            && combined.contains("Current")
            && combined.contains("Wanted")
            && combined.contains("Latest")
            && combined.contains("Bins"),
        "outdated output must render the table header, got:\n{combined}"
    );
    assert!(
        combined.contains("demo-cli")
            && combined.contains("1.0.0")
            && combined.contains("1.5.0")
            && combined.contains("2.0.0")
            && combined.contains("demo"),
        "outdated table must include current, wanted, absolute latest, and bins, got:\n{combined}"
    );
    assert!(
        !combined.contains("outdated:")
            && !combined.contains("Run `lpm global update")
            && combined.contains("✓ 1 global package installed"),
        "outdated output must match the slim table-only shape, got:\n{combined}"
    );
}

#[tokio::test]
async fn global_list_outdated_json_distinguishes_wanted_from_absolute_latest() {
    let project = TempProject::empty(r#"{"name":"global","version":"1.0.0"}"#);
    seed_global_package(&project, "demo-cli", vec!["demo".to_string()]);

    let mock = MockRegistry::start().await;
    Mock::given(method("GET"))
        .and(wm_path("/demo-cli"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "name": "demo-cli",
            "dist-tags": { "latest": "2.0.0" },
            "modified": iso8601_n_secs_ago(86_400),
            "versions": {
                "1.0.0": { "name": "demo-cli", "version": "1.0.0" },
                "1.5.0": { "name": "demo-cli", "version": "1.5.0" },
                "2.0.0": { "name": "demo-cli", "version": "2.0.0" }
            },
            "time": {
                "1.0.0": iso8601_n_secs_ago(3 * 86_400),
                "1.5.0": iso8601_n_secs_ago(2 * 86_400),
                "2.0.0": iso8601_n_secs_ago(86_400)
            }
        })))
        .mount(mock.server())
        .await;

    let output = lpm_with_registry_and_npm(&project, &mock.url())
        .args(["--json", "global", "list", "--outdated"])
        .output()
        .expect("run global list --outdated --json");
    assert!(
        output.status.success(),
        "global list --outdated --json must succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let envelope: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("valid JSON envelope");
    assert_eq!(envelope["outdated"][0]["wanted"], "1.5.0");
    assert_eq!(envelope["outdated"][0]["latest"], "2.0.0");
}

#[tokio::test]
async fn global_list_outdated_reports_a_malformed_installed_version_as_unresolved() {
    let project = TempProject::empty(r#"{"name":"global","version":"1.0.0"}"#);
    seed_global_package(&project, "demo-cli", vec!["demo".to_string()]);
    let root = isolated_lpm_root(&project);
    let mut manifest = lpm_global::read_for(&root).expect("read global manifest");
    manifest
        .packages
        .get_mut("demo-cli")
        .expect("seeded package")
        .resolved = "not-semver".to_string();
    lpm_global::write_for(&root, &manifest).expect("write malformed version fixture");

    let mock = MockRegistry::start().await;
    Mock::given(method("GET"))
        .and(wm_path("/demo-cli"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "name": "demo-cli",
            "dist-tags": { "latest": "1.1.0" },
            "versions": {
                "1.0.0": { "name": "demo-cli", "version": "1.0.0" },
                "1.1.0": { "name": "demo-cli", "version": "1.1.0" }
            },
            "time": {
                "1.0.0": iso8601_n_secs_ago(2 * 86_400),
                "1.1.0": iso8601_n_secs_ago(86_400)
            }
        })))
        .mount(mock.server())
        .await;

    let output = lpm_with_registry_and_npm(&project, &mock.url())
        .args(["--json", "global", "list", "--outdated"])
        .output()
        .expect("run global list --outdated --json");
    assert!(
        !output.status.success(),
        "malformed installed versions must not be reported as up to date"
    );
    let envelope: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("valid JSON envelope");
    assert_eq!(envelope["up_to_date"], serde_json::json!([]));
    assert_eq!(envelope["unresolved"][0]["package"], "demo-cli");
    assert!(
        envelope["unresolved"][0]["reason"]
            .as_str()
            .is_some_and(
                |reason| reason.contains("installed version") && reason.contains("not-semver")
            ),
        "unresolved reason must identify the malformed installed version: {envelope}"
    );
}

#[tokio::test]
async fn global_list_outdated_treats_fresh_latest_as_up_to_date() {
    let project = TempProject::empty(r#"{"name":"global","version":"1.0.0"}"#);
    let package = "@lpm.dev/acme.cooldown-cli";
    seed_global_package_with_source(
        &project,
        package,
        PackageSource::LpmDev,
        vec!["cooldown".to_string()],
    );

    let mock = MockRegistry::start().await;
    mock.with_batch_metadata(vec![serde_json::json!({
        "name": package,
        "dist-tags": { "latest": "1.1.0" },
        "modified": iso8601_n_secs_ago(3_600),
        "versions": {
            "1.0.0": { "name": package, "version": "1.0.0" },
            "1.1.0": { "name": package, "version": "1.1.0" }
        },
        "time": {
            "1.0.0": iso8601_n_secs_ago(3 * 86_400),
            "1.1.0": iso8601_n_secs_ago(3_600)
        }
    })])
    .await;

    let output = lpm_with_registry_and_npm(&project, &mock.url())
        .args(["--json", "global", "list", "--outdated"])
        .output()
        .expect("failed to run lpm global list --outdated --json");
    assert!(
        output.status.success(),
        "global list --outdated should not report a fresh latest as installable\nstderr: {}",
        String::from_utf8_lossy(&output.stderr),
    );

    let envelope: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("valid JSON envelope");
    assert_eq!(envelope["count_outdated"], serde_json::json!(0));
    assert_eq!(envelope["up_to_date"], serde_json::json!([package]));
}

#[tokio::test]
async fn global_list_outdated_routes_upstream_npm_packages_directly_to_npm() {
    let project = TempProject::empty(r#"{"name":"global","version":"1.0.0"}"#);
    seed_global_package(&project, "demo-cli", vec!["demo".to_string()]);

    let mock = MockRegistry::start().await;
    let metadata = serde_json::json!({
        "name": "demo-cli",
        "dist-tags": { "latest": "2.0.0" },
        "modified": iso8601_n_secs_ago(86_400),
        "versions": {
            "1.0.0": { "name": "demo-cli", "version": "1.0.0" },
            "1.5.0": { "name": "demo-cli", "version": "1.5.0" },
            "2.0.0": { "name": "demo-cli", "version": "2.0.0" }
        },
        "time": {
            "1.0.0": iso8601_n_secs_ago(3 * 86_400),
            "1.5.0": iso8601_n_secs_ago(2 * 86_400),
            "2.0.0": iso8601_n_secs_ago(86_400)
        }
    });
    Mock::given(method("GET"))
        .and(wm_path("/demo-cli"))
        .respond_with(ResponseTemplate::new(200).set_body_json(metadata))
        .mount(mock.server())
        .await;

    let output = lpm_with_registry_and_npm(&project, &mock.url())
        .args(["global", "list", "--outdated"])
        .output()
        .expect("failed to run lpm global list --outdated");

    assert!(
        output.status.success(),
        "global list --outdated must route npm globals directly\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let received_paths: Vec<String> = mock
        .server()
        .received_requests()
        .await
        .expect("wiremock recorded requests")
        .into_iter()
        .map(|request| request.url.path().to_string())
        .collect();
    assert!(
        received_paths.iter().any(|path| path == "/demo-cli"),
        "npm global must use the direct npm metadata path, got {received_paths:?}"
    );
    assert!(
        !received_paths
            .iter()
            .any(|path| path.starts_with("/api/registry")),
        "npm global must not be disclosed to the LPM Worker, got {received_paths:?}"
    );

    let combined = strip_ansi(&format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    ));
    assert!(
        combined.contains("demo-cli") && combined.contains("1.5.0") && combined.contains("2.0.0"),
        "outdated table must include routed npm metadata, got:\n{combined}"
    );
}

#[tokio::test]
async fn global_list_outdated_hydrates_release_times_in_bounded_parallel_waves() {
    const PACKAGE_COUNT: usize = 8;
    let project = TempProject::empty(r#"{"name":"global","version":"1.0.0"}"#);
    let root = isolated_lpm_root(&project);
    let mut manifest = GlobalManifest::default();
    for index in 0..PACKAGE_COUNT {
        let package = format!("parallel-outdated-{index}");
        manifest.packages.insert(
            package.clone(),
            PackageEntry {
                saved_spec: "^1".to_string(),
                resolved: "1.0.0".to_string(),
                integrity: "sha512-test".to_string(),
                source: PackageSource::UpstreamNpm,
                installed_at: Utc::now(),
                root: format!("installs/{package}@1.0.0"),
                commands: vec![package],
            },
        );
    }
    lpm_global::write_for(&root, &manifest).expect("write parallel outdated manifest fixture");

    let mock = MockRegistry::start().await;
    Mock::given(method("GET"))
        .and(wiremock::matchers::path_regex(
            r"^/parallel-outdated-[0-9]+$",
        ))
        .and(header("accept", "application/vnd.npm.install-v1+json"))
        .respond_with(GlobalOutdatedMetadata)
        .mount(mock.server())
        .await;
    let starts = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    Mock::given(method("GET"))
        .and(wiremock::matchers::path_regex(
            r"^/parallel-outdated-[0-9]+$",
        ))
        .and(header("accept", "application/json"))
        .respond_with(RecordDelayedGlobalOutdatedReleaseTimes {
            starts: std::sync::Arc::clone(&starts),
            delay: std::time::Duration::from_millis(250),
        })
        .mount(mock.server())
        .await;

    let output = lpm_with_registry_and_npm(&project, &mock.url())
        .args(["--json", "global", "list", "--outdated"])
        .output()
        .expect("run global outdated with delayed release times");
    assert!(
        output.status.success(),
        "parallel outdated check should succeed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let starts = starts.lock().expect("read global-outdated request starts");
    assert_eq!(starts.len(), PACKAGE_COUNT);
    let first = *starts.iter().min().unwrap();
    let mut offsets = starts
        .iter()
        .map(|start| start.duration_since(first))
        .collect::<Vec<_>>();
    offsets.sort();
    assert!(offsets[3] < std::time::Duration::from_millis(150));
    assert!(
        offsets[4] >= std::time::Duration::from_millis(200),
        "more than four release-time requests ran in the first wave: {offsets:?}"
    );
    assert!(
        offsets[7] < std::time::Duration::from_millis(450),
        "release-time hydration did not refill promptly: {offsets:?}"
    );
}

#[tokio::test]
async fn global_list_outdated_json_with_unresolved_metadata_exits_nonzero() {
    let project = TempProject::empty(r#"{"name":"global","version":"1.0.0"}"#);
    seed_global_package_with_source(
        &project,
        "@lpm.dev/acme.missing-cli",
        PackageSource::LpmDev,
        vec!["missing".to_string()],
    );

    let mock = MockRegistry::start().await;
    mock.with_batch_metadata(vec![]).await;

    let output = lpm_with_registry_and_npm(&project, &mock.url())
        .args(["--json", "global", "list", "--outdated"])
        .output()
        .expect("failed to run lpm global list --outdated --json");

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let envelope: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("envelope must be valid JSON: {e}\n---\n{stdout}"));

    assert!(
        !output.status.success(),
        "unresolved registry metadata must make global list --outdated fail\nstdout: {}\nstderr: {}",
        stdout,
        String::from_utf8_lossy(&output.stderr),
    );
    assert_eq!(envelope["success"], serde_json::json!(false));
    assert_eq!(envelope["count_outdated"], serde_json::json!(0));
    assert_eq!(envelope["count_unresolved"], serde_json::json!(1));
    let unresolved = envelope["unresolved"]
        .as_array()
        .expect("envelope must carry unresolved rows");
    assert_eq!(
        unresolved.len(),
        1,
        "expected one unresolved row: {envelope}"
    );
    assert_eq!(
        unresolved[0]["package"],
        serde_json::json!("@lpm.dev/acme.missing-cli")
    );
    assert!(
        unresolved[0]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("no registry metadata")),
        "unresolved reason must explain missing metadata: {envelope}",
    );
}

#[tokio::test]
async fn global_list_outdated_human_with_unresolved_metadata_exits_nonzero() {
    let project = TempProject::empty(r#"{"name":"global","version":"1.0.0"}"#);
    seed_global_package_with_source(
        &project,
        "@lpm.dev/acme.missing-cli",
        PackageSource::LpmDev,
        vec!["missing".to_string()],
    );

    let mock = MockRegistry::start().await;
    mock.with_batch_metadata(vec![]).await;

    let output = lpm_with_registry_and_npm(&project, &mock.url())
        .args(["global", "list", "--outdated"])
        .output()
        .expect("failed to run lpm global list --outdated");

    let combined = strip_ansi(&format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    ));

    assert!(
        !output.status.success(),
        "unresolved registry metadata must make global list --outdated fail\n{combined}",
    );
    assert!(
        combined.contains("could not be compared")
            && combined.contains("@lpm.dev/acme.missing-cli"),
        "human output must surface unresolved package details, got:\n{combined}",
    );
}

// ─── bin ──────────────────────────────────────────────────────────────

#[test]
fn global_bin_prints_isolated_global_bin_directory() {
    let project = TempProject::empty(r#"{"name":"global","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["global", "bin"])
        .output()
        .expect("failed to run lpm global bin");

    assert!(
        output.status.success(),
        "global bin must succeed\nstderr: {}",
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let expected = project
        .home()
        .join(".lpm")
        .join("bin")
        .display()
        .to_string();
    assert_eq!(
        stdout.trim(),
        expected,
        "global bin must print the isolated bin dir, got: {stdout}",
    );
}

#[test]
fn global_bin_json_envelope_carries_path() {
    let project = TempProject::empty(r#"{"name":"global","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["--json", "global", "bin"])
        .output()
        .expect("failed to run lpm global bin --json");

    assert!(output.status.success(), "global bin --json must succeed");

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let envelope: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("envelope must be valid JSON: {e}\n---\n{stdout}"));

    let bin_path = envelope["bin"]
        .as_str()
        .or_else(|| envelope["path"].as_str())
        .expect("envelope must carry the bin path");
    let expected = project
        .home()
        .join(".lpm")
        .join("bin")
        .display()
        .to_string();
    assert_eq!(
        bin_path, expected,
        "envelope bin path must point at the isolated bin dir: {envelope}",
    );
}

#[test]
fn global_bin_does_not_read_an_unrelated_corrupt_manifest() {
    let project = TempProject::empty(r#"{"name":"global","version":"1.0.0"}"#);
    let root = isolated_lpm_root(&project);
    std::fs::create_dir_all(root.global_root()).expect("create global state directory");
    std::fs::write(root.global_manifest(), b"this is not valid toml")
        .expect("write corrupt global manifest");

    let output = lpm(&project)
        .args(["global", "bin"])
        .output()
        .expect("run global bin");

    assert!(
        output.status.success(),
        "global bin must not depend on the manifest: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        root.bin_dir().display().to_string()
    );
}

#[test]
fn global_install_rejects_flags_that_the_global_pipeline_cannot_honor() {
    let project = TempProject::empty(r#"{"name":"global","version":"1.0.0"}"#);
    let cases: &[(&[&str], &str)] = &[
        (&["--offline"], "--offline"),
        (&["--force"], "--force"),
        (&["--skills"], "--skills"),
        (&["--timing"], "--timing"),
        (&["--audit-after-install"], "--audit-after-install"),
        (&["--no-audit-after-install"], "--no-audit-after-install"),
        (&["--workspace-concurrency", "2"], "--workspace-concurrency"),
    ];

    for &(flags, expected_flag) in cases {
        let mut args = vec![
            "--registry",
            "http://127.0.0.1:1",
            "--insecure",
            "install",
            "-g",
            "demo-cli",
        ];
        args.extend_from_slice(flags);
        let output = lpm(&project)
            .args(args)
            .output()
            .unwrap_or_else(|error| panic!("run install -g {flags:?}: {error}"));
        let combined = strip_ansi(&format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        ));
        assert!(
            !output.status.success()
                && combined.contains(expected_flag)
                && combined.contains("not supported"),
            "install -g must reject {expected_flag} before registry access, got:\n{combined}"
        );
    }
}

// ─── path <pkg> (error path) ──────────────────────────────────────────

#[test]
fn global_path_for_unknown_package_fails_with_helpful_message() {
    let project = TempProject::empty(r#"{"name":"global","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["global", "path", "not-installed-pkg"])
        .output()
        .expect("failed to run lpm global path <unknown>");

    assert!(
        !output.status.success(),
        "global path on unknown package must exit non-zero"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("not-installed-pkg") || stderr.contains("not installed"),
        "stderr must mention the missing package, got:\n{stderr}",
    );
}

#[test]
fn global_path_for_unknown_package_under_json_emits_error_envelope_on_stdout() {
    let project = TempProject::empty(r#"{"name":"global","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["--json", "global", "path", "not-installed-pkg"])
        .output()
        .expect("failed to run lpm global path <unknown> --json");

    // Whether the process exits zero or non-zero is a separate contract.
    // The load-bearing claim here is that the failure surfaces on stdout as a
    // parsable envelope with `success: false`, not as a free-form stderr
    // message.
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let envelope: serde_json::Value = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("--json error path must emit JSON: {e}\n---\n{stdout}"));
    assert_eq!(envelope["success"], serde_json::json!(false));
    let combined = format!("{envelope}{}", String::from_utf8_lossy(&output.stderr));
    assert!(
        combined.contains("not-installed-pkg") || combined.contains("not installed"),
        "envelope or stderr must mention the missing package, got:\n{combined}",
    );
}

// ─── link / unlink ────────────────────────────────────────────────────

#[test]
fn global_link_creates_manifest_entry_and_global_shim_for_local_package() {
    let project = TempProject::empty(r#"{"name":"global","version":"1.0.0"}"#);
    let package_dir = write_local_cli_package(&project);

    let output = lpm(&project)
        .args(["--json", "global", "link", "linked-tool"])
        .output()
        .expect("failed to run lpm global link");

    assert!(
        output.status.success(),
        "global link must succeed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let envelope: serde_json::Value = serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|e| panic!("global link --json must emit JSON: {e}"));
    assert_eq!(envelope["package"], serde_json::json!("linked-tool"));
    assert_eq!(envelope["version"], serde_json::json!("1.2.3"));
    assert_eq!(envelope["commands"], serde_json::json!(["linked-tool"]));

    let root = isolated_lpm_root(&project);
    let manifest = lpm_global::read_for(&root).expect("read global manifest");
    let entry = manifest
        .packages
        .get("linked-tool")
        .expect("linked package must be recorded");
    assert_eq!(entry.source, PackageSource::LocalLink);
    let canonical_package_dir = package_dir
        .canonicalize()
        .expect("canonicalize linked package dir");
    assert_eq!(
        entry.saved_spec,
        format!("link:{}", canonical_package_dir.display())
    );
    assert_eq!(entry.root, "links/linked-tool");

    let install_bin = root
        .global_root()
        .join(&entry.root)
        .join("node_modules")
        .join(".bin");
    for artifact in lpm_global::expected_artifacts(&install_bin, "linked-tool") {
        assert!(
            artifact.exists(),
            "inner local-link shim artifact must exist: {}",
            artifact.display(),
        );
    }
    for artifact in lpm_global::expected_artifacts(&root.bin_dir(), "linked-tool") {
        assert!(
            artifact.exists(),
            "global shim artifact must exist: {}",
            artifact.display(),
        );
    }

    let path_output = lpm(&project)
        .args(["global", "path", "linked-tool"])
        .output()
        .expect("failed to run lpm global path linked-tool");
    assert!(path_output.status.success());
    assert_eq!(
        String::from_utf8_lossy(&path_output.stdout).trim(),
        canonical_package_dir.display().to_string(),
    );

    #[cfg(unix)]
    {
        let run_output = std::process::Command::new(root.bin_dir().join("linked-tool"))
            .arg("ok")
            .output()
            .expect("run linked global shim");
        assert!(
            run_output.status.success(),
            "linked global shim must execute\nstderr: {}",
            String::from_utf8_lossy(&run_output.stderr),
        );
        assert_eq!(
            String::from_utf8_lossy(&run_output.stdout).trim(),
            "linked-tool:ok",
        );
    }
}

#[test]
fn global_unlink_removes_local_link_manifest_entry_and_shims() {
    let project = TempProject::empty(r#"{"name":"global","version":"1.0.0"}"#);
    write_local_cli_package(&project);

    let link_output = lpm(&project)
        .args(["global", "link", "linked-tool"])
        .output()
        .expect("failed to run lpm global link");
    assert!(
        link_output.status.success(),
        "setup link failed\nstderr: {}",
        String::from_utf8_lossy(&link_output.stderr),
    );

    let root = isolated_lpm_root(&project);
    let manifest = lpm_global::read_for(&root).expect("read manifest after link");
    let entry_root = manifest
        .packages
        .get("linked-tool")
        .expect("linked package must exist before unlink")
        .root
        .clone();

    let unlink_output = lpm(&project)
        .args(["--json", "global", "unlink", "linked-tool"])
        .output()
        .expect("failed to run lpm global unlink");
    assert!(
        unlink_output.status.success(),
        "global unlink must succeed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&unlink_output.stdout),
        String::from_utf8_lossy(&unlink_output.stderr),
    );

    let envelope: serde_json::Value = serde_json::from_slice(&unlink_output.stdout)
        .unwrap_or_else(|e| panic!("global unlink --json must emit JSON: {e}"));
    assert_eq!(envelope["package"], serde_json::json!("linked-tool"));
    assert_eq!(envelope["commands"], serde_json::json!(["linked-tool"]));

    let manifest = lpm_global::read_for(&root).expect("read manifest after unlink");
    assert!(
        !manifest.packages.contains_key("linked-tool"),
        "unlink must remove the local-link manifest row",
    );
    assert!(
        !root.global_root().join(entry_root).exists(),
        "unlink must remove the local-link root",
    );
    for artifact in lpm_global::expected_artifacts(&root.bin_dir(), "linked-tool") {
        assert!(
            !artifact.exists(),
            "global shim artifact must be removed: {}",
            artifact.display(),
        );
    }
}

#[cfg(unix)]
#[test]
fn global_unlink_restores_shims_when_any_shim_removal_fails() {
    let project = TempProject::empty(r#"{"name":"global","version":"1.0.0"}"#);
    let package_dir = project.path().join("multi-bin-tool");
    std::fs::create_dir_all(package_dir.join("bin")).expect("create linked package dirs");
    std::fs::write(
        package_dir.join("package.json"),
        r#"{
  "name": "multi-bin-tool",
  "version": "1.0.0",
  "bin": {
    "a-tool": "bin/a-tool",
    "b-tool": "bin/b-tool"
  }
}"#,
    )
    .expect("write linked package manifest");
    for command in ["a-tool", "b-tool"] {
        let target = package_dir.join("bin").join(command);
        std::fs::write(&target, "#!/bin/sh\nexit 0\n").expect("write bin target");
        chmod_executable(&target);
    }

    let link = lpm(&project)
        .args([
            "global",
            "link",
            package_dir.to_str().expect("utf-8 temp path"),
        ])
        .output()
        .expect("link local package");
    assert!(
        link.status.success(),
        "global link must succeed: {}",
        String::from_utf8_lossy(&link.stderr)
    );

    let root = isolated_lpm_root(&project);
    let blocked_shim = root.bin_dir().join("b-tool");
    lpm_common::remove_path_entry(&blocked_shim).expect("remove b-tool shim");
    std::fs::create_dir(&blocked_shim).expect("replace b-tool shim with a directory");

    let unlink = lpm(&project)
        .args(["global", "unlink", "multi-bin-tool"])
        .output()
        .expect("run global unlink");
    assert!(!unlink.status.success(), "sabotaged unlink must fail");
    assert!(
        std::fs::symlink_metadata(root.bin_dir().join("a-tool")).is_ok(),
        "a shim removed before the failure must be restored"
    );
    let manifest = lpm_global::read_for(&root).expect("read global manifest after failed unlink");
    assert!(
        manifest.packages.contains_key("multi-bin-tool"),
        "failed unlink must preserve the active manifest row"
    );
}

#[test]
fn global_unlink_invalid_local_link_root_preserves_manifest_entry_and_shims() {
    let project = TempProject::empty(r#"{"name":"global","version":"1.0.0"}"#);
    write_local_cli_package(&project);

    let link_output = lpm(&project)
        .args(["global", "link", "linked-tool"])
        .output()
        .expect("failed to run lpm global link");
    assert!(
        link_output.status.success(),
        "setup link failed\nstderr: {}",
        String::from_utf8_lossy(&link_output.stderr),
    );

    let root = isolated_lpm_root(&project);
    let mut manifest = lpm_global::read_for(&root).expect("read manifest after link");
    manifest
        .packages
        .get_mut("linked-tool")
        .expect("linked package row")
        .root = "../outside-global-root".to_string();
    lpm_global::write_for(&root, &manifest).expect("write corrupt local-link root fixture");

    let unlink_output = lpm(&project)
        .args(["global", "unlink", "linked-tool"])
        .output()
        .expect("failed to run lpm global unlink");
    assert!(
        !unlink_output.status.success(),
        "unlink with invalid local-link root must fail"
    );

    let manifest = lpm_global::read_for(&root).expect("read manifest after failed unlink");
    assert!(
        manifest.packages.contains_key("linked-tool"),
        "failed unlink must preserve the manifest row",
    );
    for artifact in lpm_global::expected_artifacts(&root.bin_dir(), "linked-tool") {
        assert!(
            artifact.exists(),
            "failed unlink must preserve global shim artifact: {}",
            artifact.display(),
        );
    }
}

#[test]
fn global_link_refuses_command_owned_by_existing_global_package() {
    let project = TempProject::empty(r#"{"name":"global","version":"1.0.0"}"#);
    write_local_cli_package(&project);
    seed_global_package(&project, "registry-owner", vec!["linked-tool".to_string()]);

    let output = lpm(&project)
        .args(["global", "link", "linked-tool"])
        .output()
        .expect("failed to run lpm global link");

    assert!(
        !output.status.success(),
        "global link must reject command ownership collisions"
    );
    let combined = strip_ansi(&format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    ));
    assert!(
        combined.contains("linked-tool") && combined.contains("registry-owner"),
        "collision error must name the command and owner, got:\n{combined}",
    );
}

#[test]
fn global_unlink_refuses_registry_backed_global_package() {
    let project = TempProject::empty(r#"{"name":"global","version":"1.0.0"}"#);
    seed_global_package(
        &project,
        "registry-owner",
        vec!["registry-owner".to_string()],
    );

    let output = lpm(&project)
        .args(["global", "unlink", "registry-owner"])
        .output()
        .expect("failed to run lpm global unlink");

    assert!(
        !output.status.success(),
        "global unlink must refuse registry-backed packages"
    );
    let combined = strip_ansi(&format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    ));
    assert!(
        combined.contains("global remove") && combined.contains("registry-owner"),
        "unlink error must point to global remove, got:\n{combined}",
    );
}

// ─── remove / uninstall -g (error path) ───────────────────────────────

#[test]
fn global_remove_unknown_package_fails_with_helpful_message() {
    let project = TempProject::empty(r#"{"name":"global","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["global", "remove", "not-installed-pkg"])
        .output()
        .expect("failed to run lpm global remove <unknown>");

    assert!(
        !output.status.success(),
        "global remove on unknown package must exit non-zero"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("not-installed-pkg")
            || stderr.contains("not installed")
            || stderr.contains("not found"),
        "stderr must mention the missing package, got:\n{stderr}",
    );
}

#[test]
fn uninstall_g_unknown_package_matches_global_remove_error_path() {
    // `lpm uninstall -g <pkg>` and `lpm global remove <pkg>` route
    // through the same implementation. Pin parity so a future
    // divergence between the two aliases fails this test.
    let project = TempProject::empty(r#"{"name":"global","version":"1.0.0"}"#);

    let out_uninstall = lpm(&project)
        .args(["uninstall", "-g", "not-installed-pkg"])
        .output()
        .expect("failed to run lpm uninstall -g <unknown>");

    let out_remove = lpm(&project)
        .args(["global", "remove", "not-installed-pkg"])
        .output()
        .expect("failed to run lpm global remove <unknown>");

    assert!(
        !out_uninstall.status.success(),
        "uninstall -g on unknown package must exit non-zero"
    );
    assert!(
        !out_remove.status.success(),
        "global remove on unknown package must exit non-zero"
    );

    // Both paths must produce an error mentioning the missing package.
    let stderr_uninstall = String::from_utf8_lossy(&out_uninstall.stderr);
    let stderr_remove = String::from_utf8_lossy(&out_remove.stderr);
    assert!(
        stderr_uninstall.contains("not-installed-pkg")
            || stderr_uninstall.contains("not installed")
            || stderr_uninstall.contains("not found"),
        "uninstall -g stderr: {stderr_uninstall}"
    );
    assert!(
        stderr_remove.contains("not-installed-pkg")
            || stderr_remove.contains("not installed")
            || stderr_remove.contains("not found"),
        "global remove stderr: {stderr_remove}"
    );
}

// ─── update (empty + dry-run) ─────────────────────────────────────────

#[test]
fn global_update_dry_run_on_empty_manifest_succeeds_without_writing_manifest() {
    let project = TempProject::empty(r#"{"name":"global","version":"1.0.0"}"#);

    let manifest_path = isolated_lpm_root(&project).global_manifest();

    let output = lpm(&project)
        .args([
            "--registry",
            "http://127.0.0.1:1",
            "--insecure",
            "--json",
            "global",
            "update",
            "--dry-run",
        ])
        .output()
        .expect("failed to run lpm global update --dry-run --json");

    assert!(
        output.status.success(),
        "global update --dry-run on empty manifest must succeed\nstderr: {}",
        String::from_utf8_lossy(&output.stderr),
    );

    // The global directory may be created as a side effect of
    // `LpmRoot::from_env()` (it ensures the home tree exists), but
    // dry-run MUST NOT write a populated manifest.
    assert!(
        !manifest_path.exists(),
        "dry-run must not create the global manifest, but it exists at {}",
        manifest_path.display(),
    );
}

#[tokio::test]
async fn global_update_dry_run_selects_latest_mature_candidate_when_latest_is_fresh() {
    let project = TempProject::empty(r#"{"name":"global","version":"1.0.0"}"#);
    let package = "@lpm.dev/acme.cooldown-update";
    seed_global_package_with_source(
        &project,
        package,
        PackageSource::LpmDev,
        vec!["cooldown-update".to_string()],
    );

    let mock = MockRegistry::start().await;
    let v1_0_0 = make_tarball(package, "1.0.0");
    let v1_1_0 = make_tarball(package, "1.1.0");
    let v1_2_0 = make_tarball(package, "1.2.0");
    let metadata = serde_json::json!({
        "name": package,
        "dist-tags": { "latest": "1.2.0" },
        "modified": iso8601_n_secs_ago(3_600),
        "versions": {
            "1.0.0": {
                "name": package,
                "version": "1.0.0",
                "dist": {
                    "tarball": mock.tarball_url(package, "1.0.0"),
                    "integrity": compute_integrity(&v1_0_0),
                },
                "dependencies": {}
            },
            "1.1.0": {
                "name": package,
                "version": "1.1.0",
                "dist": {
                    "tarball": mock.tarball_url(package, "1.1.0"),
                    "integrity": compute_integrity(&v1_1_0),
                },
                "dependencies": {}
            },
            "1.2.0": {
                "name": package,
                "version": "1.2.0",
                "dist": {
                    "tarball": mock.tarball_url(package, "1.2.0"),
                    "integrity": compute_integrity(&v1_2_0),
                },
                "dependencies": {}
            }
        },
        "time": {
            "1.0.0": iso8601_n_secs_ago(3 * 86_400),
            "1.1.0": iso8601_n_secs_ago(2 * 86_400),
            "1.2.0": iso8601_n_secs_ago(3_600)
        }
    });
    mock.with_package_metadata_and_tarballs(
        package,
        metadata,
        &[("1.0.0", v1_0_0), ("1.1.0", v1_1_0), ("1.2.0", v1_2_0)],
    )
    .await;

    let output = lpm_with_registry_and_npm(&project, &mock.url())
        .args(["--json", "global", "update", package, "--dry-run"])
        .output()
        .expect("failed to run lpm global update --dry-run --json");
    assert!(
        output.status.success(),
        "global update dry-run should plan the mature candidate\nstderr: {}",
        String::from_utf8_lossy(&output.stderr),
    );

    let envelope: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("valid JSON envelope");
    assert_eq!(envelope["plans"][0]["action"], serde_json::json!("upgrade"));
    assert_eq!(envelope["plans"][0]["to"], serde_json::json!("1.1.0"));
}

#[tokio::test]
async fn global_update_plans_upstream_npm_packages_without_contacting_the_worker() {
    let project = TempProject::empty(r#"{"name":"global","version":"1.0.0"}"#);
    let package = "direct-update-tool";
    seed_global_package(&project, package, vec![package.to_string()]);

    let mock = MockRegistry::start().await;
    let tarball = make_tarball(package, "1.1.0");
    Mock::given(method("GET"))
        .and(wm_path(format!("/{package}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "name": package,
            "dist-tags": { "latest": "1.1.0" },
            "versions": {
                "1.0.0": { "name": package, "version": "1.0.0" },
                "1.1.0": {
                    "name": package,
                    "version": "1.1.0",
                    "dist": {
                        "tarball": mock.tarball_url(package, "1.1.0"),
                        "integrity": compute_integrity(&tarball)
                    }
                }
            },
            "time": {
                "1.0.0": "2025-01-01T00:00:00.000Z",
                "1.1.0": "2025-01-01T00:00:00.000Z"
            }
        })))
        .expect(1)
        .mount(mock.server())
        .await;

    let output = lpm_with_registry_and_npm(&project, &mock.url())
        .args(["--json", "global", "update", "--dry-run"])
        .output()
        .expect("run direct npm global update plan");
    assert!(
        output.status.success(),
        "direct npm update planning should succeed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let envelope: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("valid global update envelope");
    assert_eq!(envelope["plans"][0]["action"], serde_json::json!("upgrade"));
    assert_eq!(envelope["plans"][0]["to"], serde_json::json!("1.1.0"));
    let paths = mock
        .server()
        .received_requests()
        .await
        .expect("wiremock recorded requests")
        .into_iter()
        .map(|request| request.url.path().to_string())
        .collect::<Vec<_>>();
    assert!(
        !paths.iter().any(|path| path.starts_with("/api/registry")),
        "upstream npm package names must not be disclosed to the Worker: {paths:?}"
    );
}

#[tokio::test]
async fn global_update_dry_run_rejects_exact_fresh_target() {
    let project = TempProject::empty(r#"{"name":"global","version":"1.0.0"}"#);
    let package = "@lpm.dev/acme.cooldown-update-exact";
    seed_global_package_with_source(
        &project,
        package,
        PackageSource::LpmDev,
        vec!["cooldown-update-exact".to_string()],
    );

    let mock = MockRegistry::start().await;
    let v1_0_0 = make_tarball(package, "1.0.0");
    let v1_1_0 = make_tarball(package, "1.1.0");
    let metadata = serde_json::json!({
        "name": package,
        "dist-tags": { "latest": "1.1.0" },
        "modified": iso8601_n_secs_ago(3_600),
        "versions": {
            "1.0.0": {
                "name": package,
                "version": "1.0.0",
                "dist": {
                    "tarball": mock.tarball_url(package, "1.0.0"),
                    "integrity": compute_integrity(&v1_0_0),
                },
                "dependencies": {}
            },
            "1.1.0": {
                "name": package,
                "version": "1.1.0",
                "dist": {
                    "tarball": mock.tarball_url(package, "1.1.0"),
                    "integrity": compute_integrity(&v1_1_0),
                },
                "dependencies": {}
            }
        },
        "time": {
            "1.0.0": iso8601_n_secs_ago(3 * 86_400),
            "1.1.0": iso8601_n_secs_ago(3_600)
        }
    });
    mock.with_package_metadata_and_tarballs(
        package,
        metadata,
        &[("1.0.0", v1_0_0), ("1.1.0", v1_1_0)],
    )
    .await;

    let output = lpm_with_registry_and_npm(&project, &mock.url())
        .args([
            "--json",
            "global",
            "update",
            &format!("{package}@1.1.0"),
            "--dry-run",
        ])
        .output()
        .expect("failed to run lpm global update <pkg>@<exact> --dry-run --json");
    assert!(
        !output.status.success(),
        "global update dry-run must reject exact fresh targets instead of planning a version install would reject\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let envelope: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("valid JSON envelope");
    assert_eq!(envelope["success"], serde_json::json!(false));
    assert_eq!(
        envelope["plans"][0]["action"],
        serde_json::json!("plan_error")
    );
    assert!(
        envelope["plans"][0]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("minimumReleaseAge")),
        "plan error should explain the cooldown block: {envelope:#}",
    );
}

#[tokio::test]
async fn global_update_dry_run_does_not_plan_an_implicit_registry_rollback() {
    let project = TempProject::empty(r#"{"name":"global","version":"1.0.0"}"#);
    let package = "@lpm.dev/acme.rollback-update";
    seed_global_package_with_source(
        &project,
        package,
        PackageSource::LpmDev,
        vec!["rollback-update".to_string()],
    );
    let root = isolated_lpm_root(&project);
    let mut manifest = lpm_global::read_for(&root).expect("read global manifest fixture");
    let active = manifest
        .packages
        .get_mut(package)
        .expect("seeded package row");
    active.saved_spec = "*".to_string();
    active.resolved = "2.0.0".to_string();
    active.root = format!("installs/{package}@2.0.0");
    lpm_global::write_for(&root, &manifest).expect("write rollback manifest fixture");

    let mock = MockRegistry::start().await;
    let tarball = make_tarball(package, "1.9.0");
    mock.with_package(package, "1.9.0", &tarball).await;

    let output = lpm_with_registry_and_npm(&project, &mock.url())
        .args(["--json", "global", "update", "--dry-run"])
        .output()
        .expect("run global update against registry rollback");
    assert!(
        output.status.success(),
        "implicit rollback should be a successful no-op\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let envelope: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("valid global update envelope");
    assert_eq!(envelope["plans"][0]["action"], serde_json::json!("skip"));
    assert_eq!(envelope["plans"][0]["current"], serde_json::json!("2.0.0"));
}

#[tokio::test]
async fn bulk_global_update_plans_metadata_in_bounded_parallel_waves() {
    const PACKAGE_COUNT: usize = 8;
    let project = TempProject::empty(r#"{"name":"global","version":"1.0.0"}"#);
    let root = isolated_lpm_root(&project);
    let mut manifest = GlobalManifest::default();
    for index in 0..PACKAGE_COUNT {
        let package = format!("@lpm.dev/acme.parallel-update-{index}");
        manifest.packages.insert(
            package.clone(),
            PackageEntry {
                saved_spec: "^1".to_string(),
                resolved: "1.0.0".to_string(),
                integrity: "sha512-test".to_string(),
                source: PackageSource::LpmDev,
                installed_at: Utc::now(),
                root: format!("installs/{package}@1.0.0"),
                commands: vec![format!("parallel-update-{index}")],
            },
        );
    }
    lpm_global::write_for(&root, &manifest).expect("write bulk global manifest fixture");

    let mock = MockRegistry::start().await;
    let starts = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    Mock::given(method("GET"))
        .and(wiremock::matchers::path_regex(
            r"^/api/registry/@lpm\.dev/acme\.parallel-update-[0-9]+$",
        ))
        .respond_with(RecordDelayedGlobalUpdateMetadataStart {
            starts: std::sync::Arc::clone(&starts),
            delay: std::time::Duration::from_millis(250),
        })
        .mount(mock.server())
        .await;

    let output = lpm_with_registry_and_npm(&project, &mock.url())
        .args(["--json", "global", "update", "--dry-run"])
        .output()
        .expect("run bounded bulk global update plan");
    assert!(
        output.status.success(),
        "bounded bulk plan should succeed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let starts = starts.lock().expect("read global-update request starts");
    assert_eq!(starts.len(), PACKAGE_COUNT);
    let first = *starts.iter().min().unwrap();
    let mut offsets = starts
        .iter()
        .map(|start| start.duration_since(first))
        .collect::<Vec<_>>();
    offsets.sort();
    assert!(offsets[3] < std::time::Duration::from_millis(150));
    assert!(
        offsets[4] >= std::time::Duration::from_millis(200),
        "more than four metadata requests ran in the first wave: {offsets:?}"
    );
    assert!(
        offsets[7] < std::time::Duration::from_millis(450),
        "the planner did not refill promptly for the second wave: {offsets:?}"
    );
}

#[tokio::test]
async fn bulk_global_update_installs_and_commits_in_bounded_parallel_batches() {
    const PACKAGE_COUNT: usize = 8;
    let project = TempProject::empty(r#"{"name":"global","version":"1.0.0"}"#);
    let root = isolated_lpm_root(&project);
    let mut manifest = GlobalManifest::default();
    let mock = MockRegistry::start().await;
    let starts = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));

    for index in 0..PACKAGE_COUNT {
        let package = format!("parallel-install-update-{index}");
        manifest.packages.insert(
            package.clone(),
            PackageEntry {
                saved_spec: "^1".to_string(),
                resolved: "1.0.0".to_string(),
                integrity: "sha512-old".to_string(),
                source: PackageSource::UpstreamNpm,
                installed_at: Utc::now(),
                root: format!("installs/{package}@1.0.0"),
                commands: vec![package.clone()],
            },
        );

        let bin_path = format!("bin/{package}.js");
        let tarball = support::mock_registry::make_tarball_from_pkg_json(
            serde_json::json!({
                "name": package,
                "version": "1.1.0",
                "bin": { package.clone(): bin_path.clone() }
            }),
            &[(bin_path.as_str(), b"#!/usr/bin/env node\n" as &[u8])],
        );
        let integrity = compute_integrity(&tarball);
        let tarball_path = format!("/tarballs/{package}/-/{package}-1.1.0.tgz");
        Mock::given(method("GET"))
            .and(wm_path(format!("/{package}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "name": package,
                "dist-tags": { "latest": "1.1.0" },
                "versions": {
                    "1.0.0": { "name": package, "version": "1.0.0" },
                    "1.1.0": {
                        "name": package,
                        "version": "1.1.0",
                        "bin": { package.clone(): bin_path },
                        "dist": {
                            "tarball": format!("{}{}", mock.url(), tarball_path),
                            "integrity": integrity
                        }
                    }
                },
                "time": {
                    "1.0.0": "2025-01-01T00:00:00.000Z",
                    "1.1.0": "2025-01-01T00:00:00.000Z"
                }
            })))
            .mount(mock.server())
            .await;
        Mock::given(method("GET"))
            .and(wm_path(tarball_path))
            .respond_with(RecordDelayedGlobalUpdateTarballStart {
                starts: std::sync::Arc::clone(&starts),
                delay: std::time::Duration::from_millis(250),
                body: tarball,
            })
            .mount(mock.server())
            .await;
    }
    lpm_global::write_for(&root, &manifest).expect("write bulk update fixture");

    let output = lpm_with_registry_and_npm(&project, &mock.url())
        .args(["--json", "global", "update"])
        .output()
        .expect("run concurrent bulk global update");
    assert!(
        output.status.success(),
        "bulk global update should succeed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let starts = starts.lock().expect("read global-update tarball starts");
    assert_eq!(starts.len(), PACKAGE_COUNT);
    let first = *starts.iter().min().unwrap();
    let mut offsets = starts
        .iter()
        .map(|start| start.duration_since(first))
        .collect::<Vec<_>>();
    offsets.sort();
    assert!(offsets[3] < std::time::Duration::from_millis(150));
    assert!(offsets[4] >= std::time::Duration::from_millis(200));
    assert!(offsets[7] < std::time::Duration::from_millis(450));
    drop(starts);

    let manifest = lpm_global::read_for(&root).expect("read committed bulk manifest");
    assert!(manifest.pending.is_empty());
    assert!(
        manifest
            .packages
            .values()
            .all(|entry| entry.resolved == "1.1.0")
    );
    let wal = WalReader::at(root.global_wal())
        .scan()
        .expect("scan bulk global-update WAL");
    assert!(wal.is_clean());
    assert_eq!(wal.records.len(), PACKAGE_COUNT * 2);
    assert!(
        wal.records[..PACKAGE_COUNT]
            .iter()
            .all(|record| matches!(record, WalRecord::Intent(_)))
    );
    assert!(
        wal.records[PACKAGE_COUNT..]
            .iter()
            .all(|record| matches!(record, WalRecord::Commit { .. }))
    );
}

#[test]
fn global_update_unknown_package_fails_with_helpful_message() {
    let project = TempProject::empty(r#"{"name":"global","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args([
            "--registry",
            "http://127.0.0.1:1",
            "--insecure",
            "global",
            "update",
            "not-installed-pkg",
        ])
        .output()
        .expect("failed to run lpm global update <unknown>");

    assert!(
        !output.status.success(),
        "global update on unknown package must exit non-zero"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("not-installed-pkg")
            || stderr.contains("not installed")
            || stderr.contains("not found"),
        "stderr must mention the missing package, got:\n{stderr}",
    );
}

// ─── install -g (clap-level arg validation) ───────────────────────────

#[test]
fn install_g_without_package_args_fails_or_no_ops() {
    let project = TempProject::empty(r#"{"name":"global","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args([
            "--registry",
            "http://127.0.0.1:1",
            "--insecure",
            "install",
            "-g",
        ])
        .output()
        .expect("failed to run lpm install -g (no args)");

    // Either exits non-zero (no spec given) OR exits 0 with a clear
    // "nothing to do" message — both are acceptable contracts for
    // empty-args. Crashing or hanging on network is NOT.
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    if output.status.success() {
        assert!(
            combined.contains("nothing")
                || combined.contains("no packages")
                || combined.contains("0 packages"),
            "if install -g succeeds with no args, output must explain why, got:\n{combined}",
        );
    } else {
        assert!(
            combined.contains("package") || combined.contains("spec"),
            "install -g without args error must mention packages/spec, got:\n{combined}",
        );
    }
}
