mod support;

use base64::Engine as _;
use support::assertions::parse_json_output;
use support::{
    LOCK_CONTENTION_MARKER_ENV, TempProject, lpm, lpm_spawnable, lpm_with_registry,
    wait_for_lock_contention,
};
use wiremock::matchers::{body_string_contains, header, method, path, path_regex, query_param};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

struct RewriteManifestOnMetadataRead {
    manifest_path: std::path::PathBuf,
    replacement: String,
}

struct RewriteManifestOnExistingPreflight {
    manifest_path: std::path::PathBuf,
    replacement: String,
}

#[derive(Clone)]
struct RewriteManifestAfterFirstPublish {
    attempts: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    manifest_path: std::path::PathBuf,
    replacement: String,
}

#[derive(Clone, Copy)]
struct AvailableLpmPublishPreflight;

#[derive(Clone)]
struct RecordDelayedPreflightStart {
    starts: std::sync::Arc<std::sync::Mutex<Vec<std::time::Instant>>>,
    delay: std::time::Duration,
}

#[derive(Clone)]
struct RecordSkewedPreflightStart {
    starts: std::sync::Arc<std::sync::Mutex<Vec<(String, std::time::Instant)>>>,
}

#[derive(Clone)]
struct RecordDelayedNpmPackumentStart {
    starts: std::sync::Arc<std::sync::Mutex<Vec<std::time::Instant>>>,
    delay: std::time::Duration,
}

#[derive(Clone)]
struct FailFirstPreflightAndDelayOthers {
    starts: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    delay: std::time::Duration,
}

#[derive(Clone)]
struct RecordDelayedLpmMetadataStart {
    starts: std::sync::Arc<std::sync::Mutex<Vec<std::time::Instant>>>,
    delay: std::time::Duration,
}

#[derive(Clone, Default)]
struct FailSecondPublish {
    attempts: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

impl Respond for FailSecondPublish {
    fn respond(&self, _request: &Request) -> ResponseTemplate {
        let attempt = self
            .attempts
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if attempt == 0 {
            ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": true,
                "message": "Package published"
            }))
        } else {
            ResponseTemplate::new(500).set_body_json(serde_json::json!({
                "error": "simulated registry failure"
            }))
        }
    }
}

fn available_lpm_publish_preflight_response(request: &Request) -> ResponseTemplate {
    let query: std::collections::HashMap<_, _> = request.url.query_pairs().into_owned().collect();
    ResponseTemplate::new(200).set_body_json(serde_json::json!({
        "success": true,
        "name": query.get("name").cloned().unwrap_or_default(),
        "version": query.get("version").cloned().unwrap_or_default(),
        "packageExists": false,
    }))
}

impl Respond for AvailableLpmPublishPreflight {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        available_lpm_publish_preflight_response(request)
    }
}

impl Respond for RewriteManifestOnMetadataRead {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        std::fs::write(&self.manifest_path, &self.replacement)
            .expect("rewrite manifest after release preflight intent capture");
        available_lpm_publish_preflight_response(request)
    }
}

impl Respond for RewriteManifestOnExistingPreflight {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        std::fs::write(&self.manifest_path, &self.replacement)
            .expect("rewrite manifest after release preflight intent capture");
        let query: std::collections::HashMap<_, _> =
            request.url.query_pairs().into_owned().collect();
        ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "success": true,
            "name": query.get("name").cloned().unwrap_or_default(),
            "version": query.get("version").cloned().unwrap_or_default(),
            "packageExists": true,
        }))
    }
}

impl Respond for RewriteManifestAfterFirstPublish {
    fn respond(&self, _request: &Request) -> ResponseTemplate {
        let attempt = self
            .attempts
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if attempt == 0 {
            std::fs::write(&self.manifest_path, &self.replacement)
                .expect("rewrite manifest after the first member upload");
        }
        ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "success": true,
            "message": "Package published"
        }))
    }
}

impl Respond for RecordDelayedPreflightStart {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        self.starts
            .lock()
            .expect("record metadata request start")
            .push(std::time::Instant::now());
        let query: std::collections::HashMap<_, _> =
            request.url.query_pairs().into_owned().collect();
        let name = query.get("name").cloned().unwrap_or_default();
        let version = query.get("version").cloned().unwrap_or_default();
        ResponseTemplate::new(200)
            .set_delay(self.delay)
            .set_body_json(serde_json::json!({
                "success": true,
                "name": name,
                "version": version,
                "packageExists": false,
            }))
    }
}

impl Respond for RecordSkewedPreflightStart {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let query: std::collections::HashMap<_, _> =
            request.url.query_pairs().into_owned().collect();
        let name = query.get("name").cloned().unwrap_or_default();
        let version = query.get("version").cloned().unwrap_or_default();
        self.starts
            .lock()
            .expect("record skewed metadata request start")
            .push((name.clone(), std::time::Instant::now()));
        let delay = if name.ends_with("package-0") {
            std::time::Duration::from_millis(600)
        } else {
            std::time::Duration::from_millis(20)
        };
        ResponseTemplate::new(200)
            .set_delay(delay)
            .set_body_json(serde_json::json!({
                "success": true,
                "name": name,
                "version": version,
                "packageExists": false,
            }))
    }
}

impl Respond for RecordDelayedNpmPackumentStart {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        self.starts
            .lock()
            .expect("record npm packument request start")
            .push(std::time::Instant::now());
        let name = request.url.path().trim_start_matches('/');
        ResponseTemplate::new(200)
            .set_delay(self.delay)
            .set_body_json(serde_json::json!({
                "name": name,
                "versions": {},
            }))
    }
}

impl Respond for FailFirstPreflightAndDelayOthers {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        self.starts
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let query: std::collections::HashMap<_, _> =
            request.url.query_pairs().into_owned().collect();
        let name = query.get("name").cloned().unwrap_or_default();
        if name.ends_with("package-0") {
            return ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": true,
                "name": name,
                "version": "1.0.0"
            }));
        }
        let version = query.get("version").cloned().unwrap_or_default();
        ResponseTemplate::new(200)
            .set_delay(self.delay)
            .set_body_json(serde_json::json!({
                "success": true,
                "name": name,
                "version": version,
                "packageExists": false,
            }))
    }
}

impl Respond for RecordDelayedLpmMetadataStart {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        self.starts
            .lock()
            .expect("record LPM metadata request start")
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
                "description": "existing package",
                "latestVersion": "0.9.0",
                "dist-tags": {"latest": "0.9.0"},
                "versions": {
                    "0.9.0": {
                        "name": name,
                        "version": "0.9.0",
                        "dist": {
                            "tarball": "https://example.com/package-0.9.0.tgz",
                            "integrity": "sha512-test"
                        },
                        "dependencies": {}
                    }
                }
            }))
    }
}

fn workspace_project() -> TempProject {
    let project = TempProject::empty(
        r#"{"name":"root","private":true,"version":"0.0.0","workspaces":["packages/*"]}"#,
    );
    project.write_file(
        "packages/core/package.json",
        r#"{"name":"core","version":"1.2.3"}"#,
    );
    project.write_file(
        "packages/app/package.json",
        r#"{"name":"app","version":"1.0.0","dependencies":{"core":"^1.2.3"}}"#,
    );
    project
}

fn stale_workspace_project() -> TempProject {
    let project = TempProject::empty(
        r#"{"name":"root","private":true,"version":"0.0.0","workspaces":["packages/*"]}"#,
    );
    project.write_file(
        "packages/core/package.json",
        r#"{"name":"core","version":"2.0.0"}"#,
    );
    project.write_file(
        "packages/app/package.json",
        r#"{"name":"app","version":"1.0.0","dependencies":{"core":"^1.2.3"}}"#,
    );
    project
}

fn read_package_json(project: &TempProject, rel: &str) -> serde_json::Value {
    serde_json::from_str(&project.read_file(rel)).expect("package.json must be valid JSON")
}

fn interrupt_release_apply_after_first_manifest(project: &TempProject) {
    let interrupted = lpm(project)
        .env("LPM_INTERNAL_TEST_RELEASE_ABORT_AFTER_MANIFEST_WRITES", "1")
        .args([
            "release", "apply", "--filter", "core", "--bump", "major", "--json",
        ])
        .output()
        .expect("run release apply with crash injection");
    assert!(!interrupted.status.success());
}

fn redact_release_paths(json: &mut serde_json::Value) {
    if let Some(packages) = json["packages"].as_array_mut() {
        for package in packages {
            let name = package["name"].as_str().unwrap_or("pkg").to_string();
            package["path"] = serde_json::json!(format!("[{name}]"));
            package["manifest_path"] = serde_json::json!(format!("[{name}/package.json]"));
        }
    }
    if let Some(updates) = json["dependency_updates"].as_array_mut() {
        for update in updates {
            let dependent = update["dependent"].as_str().unwrap_or("pkg").to_string();
            update["manifest_path"] = serde_json::json!(format!("[{dependent}/package.json]"));
        }
    }
    if let Some(files) = json["files"].as_array_mut() {
        for file in files {
            let path = file["path"].as_str().unwrap_or_default();
            let placeholder = if path.contains("/packages/core/") {
                "[core/package.json]"
            } else if path.contains("/packages/app/") {
                "[app/package.json]"
            } else {
                "[package.json]"
            };
            file["path"] = serde_json::json!(placeholder);
        }
    }
}

fn redact_publish_paths(json: &mut serde_json::Value) {
    if let Some(results) = json["results"].as_array_mut() {
        for result in results {
            let name = result["name"].as_str().unwrap_or("pkg").to_string();
            result["path"] = serde_json::json!(format!("[{name}]"));
            if let Some(targets) = result
                .get_mut("targets")
                .and_then(serde_json::Value::as_array_mut)
            {
                for target in targets {
                    if target.get("duration_ms").is_some() {
                        target["duration_ms"] = serde_json::json!("[duration]");
                    }
                }
            }
        }
    }
}

async fn mount_successful_lpm_publish_preflight(
    server: &MockServer,
    name: &str,
    version: &str,
    package_exists: bool,
) {
    Mock::given(method("GET"))
        .and(path("/api/registry/-/package/publish-preflight"))
        .and(query_param("name", name))
        .and(query_param("version", version))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "success": true,
            "name": name,
            "version": version,
            "packageExists": package_exists,
        })))
        .expect(1)
        .mount(server)
        .await;
}

async fn mount_lpm_metadata_versions(server: &MockServer, name: &str, versions: &[&str]) {
    let mut version_documents = serde_json::Map::with_capacity(versions.len());
    for version in versions {
        version_documents.insert(
            (*version).to_string(),
            serde_json::json!({
                "name": name,
                "version": version,
                "dist": {
                    "tarball": format!("https://example.com/{version}.tgz"),
                    "integrity": "sha512-test"
                },
                "dependencies": {}
            }),
        );
    }
    let latest = versions.first().copied().unwrap_or("0.0.0");
    Mock::given(method("GET"))
        .and(path(format!("/api/registry/{name}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "name": name,
            "description": "test package",
            "latestVersion": latest,
            "dist-tags": { "latest": latest },
            "versions": version_documents,
        })))
        .expect(1)
        .mount(server)
        .await;
}

fn extract_release_upload_tarball(request: &wiremock::Request) -> Vec<u8> {
    let payload: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
    let attachment = payload["_attachments"]
        .as_object()
        .and_then(|attachments| attachments.values().next())
        .expect("release publish payload must contain a tarball attachment");
    base64::engine::general_purpose::STANDARD
        .decode(
            attachment["data"]
                .as_str()
                .expect("release tarball attachment must be base64 text"),
        )
        .expect("release tarball attachment must decode")
}

fn release_uploaded_file_paths(tarball_data: &[u8]) -> Vec<String> {
    let decoder = flate2::read::GzDecoder::new(tarball_data);
    let mut archive = tar::Archive::new(decoder);
    archive
        .entries()
        .expect("release tarball must list entries")
        .map(|entry| {
            entry
                .expect("release tarball entry must read")
                .path()
                .expect("release tarball entry path must read")
                .to_string_lossy()
                .into_owned()
        })
        .collect()
}

#[test]
fn release_plan_json_reports_bumps_and_internal_dependent_updates() {
    let project = workspace_project();

    let output = lpm(&project)
        .args([
            "release", "plan", "--filter", "core", "--bump", "major", "--json",
        ])
        .output()
        .expect("failed to run lpm release plan");

    assert!(
        output.status.success(),
        "lpm release plan failed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let mut json = parse_json_output(&output.stdout);
    redact_release_paths(&mut json);
    insta::assert_json_snapshot!(json, @r###"
    {
      "success": true,
      "dry_run": true,
      "packages": [
        {
          "name": "core",
          "path": "[core]",
          "manifest_path": "[core/package.json]",
          "old_version": "1.2.3",
          "new_version": "2.0.0",
          "bump": "major"
        }
      ],
      "dependency_updates": [
        {
          "dependent": "app",
          "dependency": "core",
          "section": "dependencies",
          "manifest_path": "[app/package.json]",
          "old_spec": "^1.2.3",
          "new_spec": "^2.0.0"
        }
      ],
      "files": [
        {
          "path": "[app/package.json]",
          "changes": 1
        },
        {
          "path": "[core/package.json]",
          "changes": 1
        }
      ]
    }
    "###);
    assert_eq!(
        read_package_json(&project, "packages/core/package.json")["version"],
        "1.2.3"
    );
}

#[test]
fn release_plan_reads_one_locked_workspace_generation() {
    let project = workspace_project();
    let lock_path = lpm_common::project_install_lock(project.path());
    let transaction_lock = lpm_common::acquire_exclusive_lock(&lock_path)
        .expect("hold the workspace transaction lock");
    let marker_path = project.home().join("release-plan-lock-contention");
    let mut command = lpm_spawnable(&project);
    command.env(LOCK_CONTENTION_MARKER_ENV, &marker_path).args([
        "release", "plan", "--filter", "core", "--bump", "minor", "--json",
    ]);
    let mut child = command.spawn().expect("spawn contending release plan");

    wait_for_lock_contention(&mut child, &marker_path, &lock_path);
    project.write_file(
        "packages/core/package.json",
        r#"{"name":"core","version":"2.0.0"}"#,
    );
    project.write_file(
        "packages/app/package.json",
        r#"{"name":"app","version":"1.0.0","dependencies":{"core":"^2.0.0"}}"#,
    );
    drop(transaction_lock);

    let output = child.wait_with_output().expect("finish release plan");
    assert!(
        output.status.success(),
        "release plan failed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let json = parse_json_output(&output.stdout);
    assert_eq!(json["packages"][0]["old_version"], "2.0.0");
    assert_eq!(json["packages"][0]["new_version"], "2.1.0");
}

#[test]
fn release_apply_updates_selected_package_and_internal_dependents() {
    let project = workspace_project();

    let output = lpm(&project)
        .args([
            "release", "apply", "--filter", "core", "--bump", "major", "--json",
        ])
        .output()
        .expect("failed to run lpm release apply");

    assert!(
        output.status.success(),
        "lpm release apply failed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let mut json = parse_json_output(&output.stdout);
    redact_release_paths(&mut json);
    insta::assert_json_snapshot!(json, @r###"
    {
      "success": true,
      "dry_run": false,
      "packages": [
        {
          "name": "core",
          "path": "[core]",
          "manifest_path": "[core/package.json]",
          "old_version": "1.2.3",
          "new_version": "2.0.0",
          "bump": "major"
        }
      ],
      "dependency_updates": [
        {
          "dependent": "app",
          "dependency": "core",
          "section": "dependencies",
          "manifest_path": "[app/package.json]",
          "old_spec": "^1.2.3",
          "new_spec": "^2.0.0"
        }
      ],
      "files": [
        {
          "path": "[app/package.json]",
          "changes": 1
        },
        {
          "path": "[core/package.json]",
          "changes": 1
        }
      ]
    }
    "###);
    assert_eq!(
        read_package_json(&project, "packages/core/package.json")["version"],
        "2.0.0"
    );
    assert_eq!(
        read_package_json(&project, "packages/app/package.json")["dependencies"]["core"],
        "^2.0.0"
    );
}

#[test]
fn release_apply_plans_after_acquiring_the_workspace_transaction_lock() {
    let project = workspace_project();
    let lock_path = lpm_common::project_install_lock(project.path());
    let transaction_lock = lpm_common::acquire_exclusive_lock(&lock_path)
        .expect("hold the workspace transaction lock");
    let marker_path = project.home().join("release-apply-lock-contention");
    let mut command = lpm_spawnable(&project);
    command
        .current_dir(project.path().join("packages/core"))
        .env(LOCK_CONTENTION_MARKER_ENV, &marker_path)
        .args([
            "release", "apply", "--filter", "core", "--bump", "major", "--json",
        ]);
    let mut child = command.spawn().expect("spawn contending release apply");

    wait_for_lock_contention(&mut child, &marker_path, &lock_path);
    project.write_file(
        "packages/core/package.json",
        r#"{"name":"core","version":"1.2.3","description":"edit made while waiting"}"#,
    );
    drop(transaction_lock);

    let output = child.wait_with_output().expect("finish release apply");
    assert!(
        output.status.success(),
        "release apply failed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let core = read_package_json(&project, "packages/core/package.json");
    assert_eq!(core["version"], "2.0.0");
    assert_eq!(core["description"], "edit made while waiting");
}

#[test]
fn release_apply_recovers_an_interrupted_manifest_transaction_before_replanning() {
    let project = workspace_project();
    interrupt_release_apply_after_first_manifest(&project);

    let recovered = lpm(&project)
        .args([
            "release", "apply", "--filter", "core", "--bump", "patch", "--json",
        ])
        .output()
        .expect("run release apply after interrupted transaction");

    assert!(
        recovered.status.success(),
        "release apply did not recover before replanning\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&recovered.stdout),
        String::from_utf8_lossy(&recovered.stderr)
    );
    assert_eq!(
        read_package_json(&project, "packages/core/package.json")["version"],
        "1.2.4"
    );
    assert_eq!(
        read_package_json(&project, "packages/app/package.json")["dependencies"]["core"],
        "^1.2.3"
    );
}

#[test]
fn release_apply_retry_after_durable_commit_does_not_bump_twice() {
    let project = workspace_project();
    let interrupted = lpm(&project)
        .env("LPM_INTERNAL_TEST_RELEASE_ABORT_AFTER_COMMIT", "1")
        .args([
            "release", "apply", "--filter", "core", "--bump", "major", "--json",
        ])
        .output()
        .expect("interrupt release apply after durable commit");
    assert!(!interrupted.status.success());

    let recovered = lpm(&project)
        .args([
            "release", "apply", "--filter", "core", "--bump", "major", "--json",
        ])
        .output()
        .expect("retry release apply after durable commit");

    assert!(
        recovered.status.success(),
        "release apply did not recover durable completion\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&recovered.stdout),
        String::from_utf8_lossy(&recovered.stderr)
    );
    assert_eq!(
        read_package_json(&project, "packages/core/package.json")["version"],
        "2.0.0"
    );
    assert_eq!(
        read_package_json(&project, "packages/app/package.json")["dependencies"]["core"],
        "^2.0.0"
    );
}

#[test]
fn release_apply_runs_after_recovering_a_different_completed_operation() {
    let project = workspace_project();
    let interrupted = lpm(&project)
        .env("LPM_INTERNAL_TEST_RELEASE_ABORT_AFTER_COMMIT", "1")
        .args(["version", "patch", "--no-git-tag-version"])
        .output()
        .expect("interrupt version after durable commit");
    assert!(!interrupted.status.success());

    let release = lpm(&project)
        .args([
            "release", "apply", "--filter", "core", "--bump", "patch", "--json",
        ])
        .output()
        .expect("run a different release operation after recovery");

    assert!(
        release.status.success(),
        "release apply did not continue after cross-command recovery\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&release.stdout),
        String::from_utf8_lossy(&release.stderr)
    );
    assert_eq!(
        read_package_json(&project, "package.json")["version"],
        "0.0.1"
    );
    assert_eq!(
        read_package_json(&project, "packages/core/package.json")["version"],
        "1.2.4"
    );
}

#[test]
fn install_package_from_a_workspace_member_uses_the_workspace_transaction_lock() {
    let project = workspace_project();
    let root_lock_path = lpm_common::project_install_lock(project.path());
    let root_lock = lpm_common::acquire_exclusive_lock(&root_lock_path)
        .expect("hold the workspace transaction lock");
    let marker_path = project.home().join("member-install-lock-contention");
    let mut command = lpm_spawnable(&project);
    command
        .current_dir(project.path().join("packages/core"))
        .env(LOCK_CONTENTION_MARKER_ENV, &marker_path)
        .args(["install", "left-pad", "--offline", "--json"]);
    let mut child = command.spawn().expect("spawn member package install");

    wait_for_lock_contention(&mut child, &marker_path, &root_lock_path);
    drop(root_lock);
    let _ = child
        .wait_with_output()
        .expect("finish member package install");
}

#[test]
fn install_refuses_an_applying_release_manifest_transaction() {
    let project = workspace_project();
    interrupt_release_apply_after_first_manifest(&project);

    let output = lpm(&project)
        .args(["install", "--offline", "--json"])
        .output()
        .expect("run install with an applying release transaction");

    assert!(
        !output.status.success(),
        "install must not observe or extend a partially applied release"
    );
    let envelope = parse_json_output(&output.stdout);
    assert!(
        envelope["error"]
            .as_str()
            .is_some_and(|error| error.contains("interrupted release manifest transaction")),
        "install returned the wrong failure: {envelope:#}"
    );
}

#[test]
fn release_apply_recovers_an_interrupted_root_package_version() {
    let project = workspace_project();
    let interrupted = lpm(&project)
        .env("LPM_INTERNAL_TEST_RELEASE_ABORT_AFTER_MANIFEST_WRITES", "1")
        .args(["version", "major", "--no-git-tag-version"])
        .output()
        .expect("interrupt root package version");
    assert!(!interrupted.status.success());

    let recovered = lpm(&project)
        .args([
            "release", "apply", "--filter", "core", "--bump", "patch", "--json",
        ])
        .output()
        .expect("recover root package version with release apply");

    assert!(
        recovered.status.success(),
        "release apply did not recover root package journal\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&recovered.stdout),
        String::from_utf8_lossy(&recovered.stderr)
    );
    assert_eq!(
        read_package_json(&project, "package.json")["version"],
        "0.0.0"
    );
    assert_eq!(
        read_package_json(&project, "packages/core/package.json")["version"],
        "1.2.4"
    );
}

#[test]
fn release_plan_refuses_to_read_an_interrupted_manifest_transaction() {
    let project = workspace_project();
    interrupt_release_apply_after_first_manifest(&project);

    let output = lpm(&project)
        .args([
            "release", "plan", "--filter", "core", "--bump", "patch", "--json",
        ])
        .output()
        .expect("run release plan with interrupted transaction");

    assert!(!output.status.success());
    let envelope = parse_json_output(&output.stdout);
    assert!(
        envelope["error"]
            .as_str()
            .is_some_and(|error| error.contains("interrupted release manifest transaction"))
    );
    assert_eq!(
        read_package_json(&project, "packages/core/package.json")["version"],
        "1.2.3"
    );
    assert_eq!(
        read_package_json(&project, "packages/app/package.json")["dependencies"]["core"],
        "^2.0.0"
    );
}

#[test]
fn release_publish_dry_run_refuses_to_read_an_interrupted_manifest_transaction() {
    let project = workspace_project();
    interrupt_release_apply_after_first_manifest(&project);

    let output = lpm(&project)
        .args([
            "release",
            "publish",
            "--all",
            "--dry-run",
            "--npm",
            "--json",
        ])
        .output()
        .expect("run release publish dry-run with interrupted transaction");

    assert!(!output.status.success());
    let envelope = parse_json_output(&output.stdout);
    assert!(
        envelope["error"]
            .as_str()
            .is_some_and(|error| error.contains("interrupted release manifest transaction"))
    );
    assert_eq!(
        read_package_json(&project, "packages/app/package.json")["dependencies"]["core"],
        "^2.0.0"
    );
}

#[test]
fn release_publish_recovers_an_interrupted_transaction_before_auth_preflight() {
    let project = workspace_project();
    interrupt_release_apply_after_first_manifest(&project);

    let output = lpm(&project)
        .args(["release", "publish", "--all", "--npm", "--yes", "--json"])
        .output()
        .expect("run release publish with interrupted transaction");

    assert!(!output.status.success(), "missing npm auth must still fail");
    assert_eq!(
        read_package_json(&project, "packages/core/package.json")["version"],
        "1.2.3"
    );
    assert_eq!(
        read_package_json(&project, "packages/app/package.json")["dependencies"]["core"],
        "^1.2.3"
    );
    assert!(
        !project
            .path()
            .join(".lpm/release-apply/journal.json")
            .exists()
    );
}

#[test]
fn release_publish_recovers_an_interrupted_root_package_version_before_auth() {
    let project = workspace_project();
    let interrupted = lpm(&project)
        .env("LPM_INTERNAL_TEST_RELEASE_ABORT_AFTER_MANIFEST_WRITES", "1")
        .args(["version", "major", "--no-git-tag-version"])
        .output()
        .expect("interrupt root package version");
    assert!(!interrupted.status.success());

    let output = lpm(&project)
        .args(["release", "publish", "--all", "--npm", "--yes", "--json"])
        .output()
        .expect("recover root package version with release publish");

    assert!(!output.status.success(), "missing npm auth must still fail");
    assert_eq!(
        read_package_json(&project, "package.json")["version"],
        "0.0.0"
    );
    assert!(
        !String::from_utf8_lossy(&output.stdout).contains("not a release manifest"),
        "release publish rejected the root recovery allow-list"
    );
}

#[test]
fn standalone_publish_dry_run_refuses_a_pending_workspace_release_transaction() {
    let project = workspace_project();
    interrupt_release_apply_after_first_manifest(&project);
    let mut command = lpm(&project);
    command.current_dir(project.path().join("packages/app"));

    let output = command
        .args(["publish", "--dry-run", "--npm", "--json"])
        .output()
        .expect("run standalone publish dry-run from a partially updated member");

    assert!(!output.status.success());
    let envelope = parse_json_output(&output.stdout);
    assert!(
        envelope["error"]
            .as_str()
            .is_some_and(|error| error.contains("interrupted release manifest transaction"))
    );
    assert_eq!(
        read_package_json(&project, "packages/app/package.json")["dependencies"]["core"],
        "^2.0.0"
    );
}

#[test]
fn standalone_publish_recovers_a_pending_workspace_release_before_auth() {
    let project = workspace_project();
    interrupt_release_apply_after_first_manifest(&project);
    let mut command = lpm(&project);
    command.current_dir(project.path().join("packages/app"));

    let output = command
        .args(["publish", "--npm", "--yes", "--json"])
        .output()
        .expect("run standalone publish from a partially updated member");

    assert!(!output.status.success(), "missing npm auth must still fail");
    assert_eq!(
        read_package_json(&project, "packages/core/package.json")["version"],
        "1.2.3"
    );
    assert_eq!(
        read_package_json(&project, "packages/app/package.json")["dependencies"]["core"],
        "^1.2.3"
    );
}

#[test]
fn standalone_publish_without_recovery_does_not_parse_unrelated_workspace_members() {
    let project = workspace_project();
    project.write_file("packages/core/package.json", "{ invalid sibling manifest");
    let mut command = lpm(&project);
    command.current_dir(project.path().join("packages/app"));

    let output = command
        .args(["publish", "--npm", "--yes", "--json"])
        .output()
        .expect("publish member with unrelated malformed sibling");

    assert!(!output.status.success(), "missing npm auth must still fail");
    let envelope = parse_json_output(&output.stdout);
    let error = envelope["error"].as_str().unwrap_or_default();
    assert!(
        !error.contains("core/package.json") && !error.contains("workspace"),
        "standalone publish parsed an unrelated workspace member: {error}"
    );
}

#[test]
fn standalone_publish_refuses_workspace_scope_drift_while_waiting_for_the_transaction_lock() {
    let project = workspace_project();
    let lock_path = lpm_common::project_install_lock(project.path());
    let transaction_lock =
        lpm_common::acquire_exclusive_lock(&lock_path).expect("hold workspace transaction lock");
    let marker_path = project.home().join("publish-scope-drift-lock-contention");
    let mut command = lpm_spawnable(&project);
    command
        .current_dir(project.path().join("packages/core"))
        .env(LOCK_CONTENTION_MARKER_ENV, &marker_path)
        .args(["publish", "--check", "--npm", "--json"]);
    let mut child = command.spawn().expect("spawn contending member publish");

    wait_for_lock_contention(&mut child, &marker_path, &lock_path);
    project.write_file(
        "package.json",
        r#"{"name":"root","private":true,"version":"0.0.0"}"#,
    );
    drop(transaction_lock);

    let output = child.wait_with_output().expect("finish member publish");
    assert!(
        !output.status.success(),
        "publish accepted a project that left its locked workspace"
    );
}

#[tokio::test]
async fn release_publish_dry_run_reports_dependency_order() {
    let project = workspace_project();
    project.write_file(
        "packages/core/lpm.json",
        r#"{"publish":{"lpm":{"name":"@lpm.dev/acme.core"}}}"#,
    );
    project.write_file(
        "packages/app/lpm.json",
        r#"{"publish":{"lpm":{"name":"@lpm.dev/acme.app"}}}"#,
    );
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/registry/-/package/publish-preflight"))
        .respond_with(AvailableLpmPublishPreflight)
        .expect(2)
        .mount(&server)
        .await;

    let output = lpm_with_registry(&project, &server.uri())
        .args([
            "release",
            "publish",
            "--all",
            "--dry-run",
            "--json",
            "--lpm",
        ])
        .output()
        .expect("failed to run lpm release publish");

    assert!(
        output.status.success(),
        "lpm release publish failed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let mut json = parse_json_output(&output.stdout);
    redact_publish_paths(&mut json);
    insta::assert_json_snapshot!(json, @r###"
    {
      "success": true,
      "dry_run": true,
      "packages": 2,
      "results": [
        {
          "name": "core",
          "version": "1.2.3",
          "path": "[core]",
          "status": "planned"
        },
        {
          "name": "app",
          "version": "1.0.0",
          "path": "[app]",
          "status": "planned"
        }
      ]
    }
    "###);
}

#[tokio::test]
async fn release_publish_preflights_independent_members_concurrently() {
    let project = TempProject::empty(
        r#"{"name":"root","private":true,"version":"0.0.0","workspaces":["packages/*"]}"#,
    );
    let packages = [
        ("@lpm.dev/acme.alpha", "packages/alpha"),
        ("@lpm.dev/acme.beta", "packages/beta"),
        ("@lpm.dev/acme.gamma", "packages/gamma"),
    ];
    let server = MockServer::start().await;
    let starts = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    for (name, path) in packages {
        project.write_file(
            &format!("{path}/package.json"),
            &format!(r#"{{"name":"{name}","version":"1.0.0"}}"#),
        );
    }
    Mock::given(method("GET"))
        .and(path("/api/registry/-/package/publish-preflight"))
        .respond_with(RecordDelayedPreflightStart {
            starts: std::sync::Arc::clone(&starts),
            delay: std::time::Duration::from_millis(600),
        })
        .expect(3)
        .mount(&server)
        .await;

    let output = lpm_with_registry(&project, &server.uri())
        .args([
            "release",
            "publish",
            "--all",
            "--lpm",
            "--dry-run",
            "--json",
        ])
        .output()
        .expect("run release publish with delayed preflights");
    assert!(
        output.status.success(),
        "release publish failed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let starts = starts.lock().expect("read metadata request starts");
    assert_eq!(starts.len(), 3);
    let first = starts.iter().min().expect("first preflight start");
    let last = starts.iter().max().expect("last preflight start");
    assert!(
        last.duration_since(*first) < std::time::Duration::from_millis(300),
        "delayed preflights started {:?} apart; they ran serially",
        last.duration_since(*first),
    );
}

#[tokio::test]
async fn release_publish_preflight_starts_at_most_four_requests_before_one_completes() {
    let project = TempProject::empty(
        r#"{"name":"root","private":true,"version":"0.0.0","workspaces":["packages/*"]}"#,
    );
    for index in 0..8 {
        project.write_file(
            &format!("packages/package-{index}/package.json"),
            &format!(r#"{{"name":"@lpm.dev/acme.package-{index}","version":"1.0.0"}}"#),
        );
    }
    let server = MockServer::start().await;
    let starts = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    Mock::given(method("GET"))
        .and(path("/api/registry/-/package/publish-preflight"))
        .respond_with(RecordDelayedPreflightStart {
            starts: std::sync::Arc::clone(&starts),
            delay: std::time::Duration::from_millis(500),
        })
        .expect(8)
        .mount(&server)
        .await;

    let output = lpm_with_registry(&project, &server.uri())
        .args([
            "release",
            "publish",
            "--all",
            "--lpm",
            "--dry-run",
            "--json",
        ])
        .output()
        .expect("run bounded release preflight");
    assert!(output.status.success());
    let mut starts = starts.lock().expect("read preflight starts").clone();
    starts.sort_unstable();
    assert_eq!(starts.len(), 8);
    assert!(
        starts[3].duration_since(starts[0]) < std::time::Duration::from_millis(250),
        "the first four requests did not start concurrently"
    );
    assert!(
        starts[4].duration_since(starts[0]) >= std::time::Duration::from_millis(400),
        "more than four preflight requests started before a slot completed"
    );
}

#[tokio::test]
async fn release_publish_preflight_refills_slots_behind_a_slow_first_request() {
    let project = TempProject::empty(
        r#"{"name":"root","private":true,"version":"0.0.0","workspaces":["packages/*"]}"#,
    );
    for index in 0..8 {
        project.write_file(
            &format!("packages/package-{index}/package.json"),
            &format!(r#"{{"name":"@lpm.dev/acme.package-{index}","version":"1.0.0"}}"#),
        );
    }
    let server = MockServer::start().await;
    let starts = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    Mock::given(method("GET"))
        .and(path("/api/registry/-/package/publish-preflight"))
        .respond_with(RecordSkewedPreflightStart {
            starts: std::sync::Arc::clone(&starts),
        })
        .expect(8)
        .mount(&server)
        .await;

    let output = lpm_with_registry(&project, &server.uri())
        .args([
            "release",
            "publish",
            "--all",
            "--lpm",
            "--dry-run",
            "--json",
        ])
        .output()
        .expect("run skewed release preflight");

    assert!(output.status.success());
    let starts = starts.lock().expect("read skewed preflight starts");
    let first = starts
        .iter()
        .find(|(name, _)| name.ends_with("package-0"))
        .expect("package-0 preflight start")
        .1;
    let refill = starts
        .iter()
        .filter(|(name, _)| {
            name.rsplit('-')
                .next()
                .and_then(|index| index.parse::<usize>().ok())
                .is_some_and(|index| index >= 4)
        })
        .map(|(_, start)| *start)
        .min()
        .expect("a refill preflight start");
    assert!(
        refill.duration_since(first) < std::time::Duration::from_millis(300),
        "bounded preflight left slots idle behind the slow first request"
    );
}

#[tokio::test]
async fn release_publish_preflight_stops_the_delayed_tail_after_the_first_error() {
    let project = TempProject::empty(
        r#"{"name":"root","private":true,"version":"0.0.0","workspaces":["packages/*"]}"#,
    );
    for index in 0..12 {
        project.write_file(
            &format!("packages/package-{index}/package.json"),
            &format!(r#"{{"name":"@lpm.dev/acme.package-{index}","version":"1.0.0"}}"#),
        );
    }
    let server = MockServer::start().await;
    let starts = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    Mock::given(method("GET"))
        .and(path("/api/registry/-/package/publish-preflight"))
        .respond_with(FailFirstPreflightAndDelayOthers {
            starts: std::sync::Arc::clone(&starts),
            delay: std::time::Duration::from_millis(700),
        })
        .mount(&server)
        .await;

    let started = std::time::Instant::now();
    let output = lpm_with_registry(&project, &server.uri())
        .args([
            "release",
            "publish",
            "--all",
            "--lpm",
            "--dry-run",
            "--json",
        ])
        .output()
        .expect("run fail-fast release preflight");

    assert!(!output.status.success());
    assert!(
        started.elapsed() < std::time::Duration::from_millis(650),
        "release preflight waited for delayed work after the first error"
    );
    assert!(
        starts.load(std::sync::atomic::Ordering::SeqCst) <= 4,
        "release preflight started work beyond its initial bounded window"
    );
}

#[tokio::test]
async fn release_publish_limits_full_npm_packument_preflights_to_one_in_flight() {
    let project = TempProject::empty(
        r#"{"name":"root","private":true,"version":"0.0.0","workspaces":["packages/*"]}"#,
    );
    let server = MockServer::start().await;
    for index in 0..4 {
        project.write_file(
            &format!("packages/package-{index}/package.json"),
            &format!(r#"{{"name":"package-{index}","version":"1.0.0"}}"#),
        );
        project.write_file(
            &format!("packages/package-{index}/lpm.json"),
            &format!(
                r#"{{"publish":{{"npm":{{"registry":"{}"}}}}}}"#,
                server.uri()
            ),
        );
    }
    let login = lpm(&project)
        .args([
            "--json",
            "login",
            "--login-registry",
            &server.uri(),
            "--token",
            "packument-memory-token",
        ])
        .output()
        .expect("store registry-scoped token");
    assert!(login.status.success());
    let starts = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    Mock::given(method("GET"))
        .and(path_regex("/package-[0-9]+"))
        .respond_with(RecordDelayedNpmPackumentStart {
            starts: std::sync::Arc::clone(&starts),
            delay: std::time::Duration::from_millis(250),
        })
        .expect(4)
        .mount(&server)
        .await;

    let output = lpm_with_registry(&project, &server.uri())
        .args([
            "release",
            "publish",
            "--all",
            "--npm",
            "--dry-run",
            "--json",
        ])
        .output()
        .expect("run memory-bounded npm preflight");

    assert!(
        output.status.success(),
        "npm preflight failed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let starts = starts.lock().expect("read npm packument starts").clone();
    assert_eq!(starts.len(), 4);
    assert!(
        starts.windows(2).all(|pair| {
            pair[1].duration_since(pair[0]) >= std::time::Duration::from_millis(150)
        })
    );
}

#[tokio::test]
async fn release_publish_limits_lpm_metadata_fallbacks_to_one_in_flight() {
    let project = TempProject::empty(
        r#"{"name":"root","private":true,"version":"0.0.0","workspaces":["packages/*"]}"#,
    );
    for index in 0..4 {
        project.write_file(
            &format!("packages/package-{index}/package.json"),
            &format!(r#"{{"name":"@lpm.dev/acme.package-{index}","version":"1.0.0"}}"#),
        );
    }
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/registry/-/package/publish-preflight"))
        .respond_with(|request: &Request| {
            let query: std::collections::HashMap<_, _> =
                request.url.query_pairs().into_owned().collect();
            ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": true,
                "name": query.get("name").cloned().unwrap_or_default(),
                "version": query.get("version").cloned().unwrap_or_default(),
                "packageExists": true,
            }))
        })
        .expect(4)
        .mount(&server)
        .await;
    let starts = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    Mock::given(method("GET"))
        .and(path_regex("/api/registry/@lpm[.]dev/acme[.]package-[0-9]+"))
        .respond_with(RecordDelayedLpmMetadataStart {
            starts: std::sync::Arc::clone(&starts),
            delay: std::time::Duration::from_millis(250),
        })
        .expect(4)
        .mount(&server)
        .await;

    let output = lpm_with_registry(&project, &server.uri())
        .args([
            "release",
            "publish",
            "--all",
            "--lpm",
            "--dry-run",
            "--json",
        ])
        .output()
        .expect("run memory-bounded LPM metadata fallback");

    assert!(
        output.status.success(),
        "LPM preflight failed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let starts = starts.lock().expect("read LPM metadata starts").clone();
    assert_eq!(starts.len(), 4);
    assert!(
        starts.windows(2).all(|pair| {
            pair[1].duration_since(pair[0]) >= std::time::Duration::from_millis(150)
        })
    );
}

#[tokio::test]
async fn release_publish_refreshes_workspace_once_after_remote_preflight() {
    let project = TempProject::empty(
        r#"{"name":"root","private":true,"version":"0.0.0","workspaces":["packages/*"]}"#,
    );
    for index in 0..3 {
        project.write_file(
            &format!("packages/package-{index}/package.json"),
            &format!(r#"{{"name":"@lpm.dev/acme.package-{index}","version":"1.0.0"}}"#),
        );
    }
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/registry/-/package/publish-preflight"))
        .respond_with(AvailableLpmPublishPreflight)
        .expect(3)
        .mount(&server)
        .await;
    let marker = project.home().join("release-workspace-discoveries");

    let output = lpm_with_registry(&project, &server.uri())
        .env(
            "LPM_INTERNAL_TEST_RELEASE_WORKSPACE_DISCOVERY_MARKER",
            &marker,
        )
        .args([
            "release",
            "publish",
            "--all",
            "--lpm",
            "--dry-run",
            "--json",
        ])
        .output()
        .expect("run release publish with discovery instrumentation");

    assert!(
        output.status.success(),
        "release publish failed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let discoveries = std::fs::read_to_string(marker).expect("read workspace discovery marker");
    assert_eq!(discoveries.lines().count(), 3);
}

#[tokio::test]
async fn release_publish_preflight_reports_the_earliest_ordered_error() {
    let project = TempProject::empty(
        r#"{"name":"root","private":true,"version":"0.0.0","workspaces":["packages/*"]}"#,
    );
    for name in ["alpha", "beta"] {
        project.write_file(
            &format!("packages/{name}/package.json"),
            &format!(r#"{{"name":"@lpm.dev/acme.{name}","version":"1.0.0"}}"#),
        );
    }
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/registry/-/package/publish-preflight"))
        .and(query_param("name", "@lpm.dev/acme.alpha"))
        .respond_with(
            ResponseTemplate::new(500)
                .set_delay(std::time::Duration::from_millis(400))
                .set_body_string("ordered-alpha-error"),
        )
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/registry/-/package/publish-preflight"))
        .and(query_param("name", "@lpm.dev/acme.beta"))
        .respond_with(ResponseTemplate::new(500).set_body_string("later-beta-error"))
        .mount(&server)
        .await;

    let output = lpm_with_registry(&project, &server.uri())
        .args([
            "release",
            "publish",
            "--all",
            "--lpm",
            "--dry-run",
            "--json",
        ])
        .output()
        .expect("run ordered-error release preflight");
    assert!(!output.status.success());
    let envelope = parse_json_output(&output.stdout);
    assert!(
        envelope["error"]
            .as_str()
            .is_some_and(|error| error.contains("ordered-alpha-error")),
        "release preflight returned a later error: {envelope:#}"
    );
}

#[tokio::test]
async fn release_publish_lpm_oidc_preflights_each_package_with_its_scoped_token() {
    let project = TempProject::empty(
        r#"{"name":"root","private":true,"version":"0.0.0","workspaces":["packages/*"]}"#,
    );
    let server = MockServer::start().await;
    for package in ["@lpm.dev/acme.alpha", "@lpm.dev/acme.beta"] {
        let member = package.rsplit('.').next().expect("member name");
        let scoped_token = format!("scoped-{member}-token");
        project.write_file(
            &format!("packages/{member}/package.json"),
            &format!(r#"{{"name":"{package}","version":"1.0.0"}}"#),
        );
        Mock::given(method("POST"))
            .and(path("/api/registry/-/token/oidc"))
            .and(query_param("scope", "publish"))
            .and(body_string_contains(format!(r#""package":"{package}""#)))
            .and(body_string_contains(r#""token":"release-oidc-jwt""#))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "token": &scoped_token,
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/registry/-/package/publish-preflight"))
            .and(query_param("name", package))
            .and(header("authorization", format!("Bearer {scoped_token}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": true,
                "name": package,
                "version": "1.0.0",
                "packageExists": false,
            })))
            .expect(1)
            .mount(&server)
            .await;
    }

    let output = lpm_with_registry(&project, &server.uri())
        .env("LPM_OIDC_TOKEN", "release-oidc-jwt")
        .args([
            "release",
            "publish",
            "--all",
            "--lpm",
            "--dry-run",
            "--json",
        ])
        .output()
        .expect("run OIDC-only release preflight");
    assert!(
        output.status.success(),
        "OIDC preflight failed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    server.verify().await;
}

#[tokio::test]
async fn release_publish_fetches_the_lpm_provider_jwt_once_per_command() {
    let project = TempProject::empty(
        r#"{"name":"root","private":true,"version":"0.0.0","workspaces":["packages/*"]}"#,
    );
    let server = MockServer::start().await;
    for package in ["@lpm.dev/acme.alpha", "@lpm.dev/acme.beta"] {
        let member = package.rsplit('.').next().expect("member name");
        project.write_file(
            &format!("packages/{member}/package.json"),
            &format!(r#"{{"name":"{package}","version":"1.0.0"}}"#),
        );
    }
    Mock::given(method("GET"))
        .and(path("/runtime-oidc"))
        .and(query_param("audience", "https://lpm.dev"))
        .and(header("authorization", "Bearer runtime-request-token"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({"value": "provider-lpm-jwt"})),
        )
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/registry/-/token/oidc"))
        .and(body_string_contains(r#""token":"provider-lpm-jwt""#))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({"token": "scoped-lpm-token"})),
        )
        .expect(2)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/registry/-/package/publish-preflight"))
        .and(header("authorization", "Bearer scoped-lpm-token"))
        .respond_with(AvailableLpmPublishPreflight)
        .expect(2)
        .mount(&server)
        .await;
    let output = lpm_with_registry(&project, &server.uri())
        .env(
            "ACTIONS_ID_TOKEN_REQUEST_URL",
            format!("{}/runtime-oidc?seed=1", server.uri()),
        )
        .env("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "runtime-request-token")
        .args([
            "release",
            "publish",
            "--all",
            "--lpm",
            "--dry-run",
            "--json",
        ])
        .output()
        .expect("run release with GitHub runtime LPM OIDC");

    assert!(
        output.status.success(),
        "LPM OIDC release failed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    server.verify().await;
}

#[tokio::test]
async fn release_publish_checks_the_requested_version_when_the_lpm_package_exists() {
    let project = TempProject::empty(
        r#"{"name":"root","private":true,"version":"0.0.0","workspaces":["packages/*"]}"#,
    );
    let name = "@lpm.dev/acme.existing";
    project.write_file(
        "packages/existing/package.json",
        &format!(r#"{{"name":"{name}","version":"2.0.0"}}"#),
    );
    let server = MockServer::start().await;
    mount_successful_lpm_publish_preflight(&server, name, "2.0.0", true).await;
    Mock::given(method("GET"))
        .and(path("/api/registry/@lpm.dev/acme.existing"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "name": name,
            "description": "existing package",
            "latestVersion": "1.0.0",
            "dist-tags": { "latest": "1.0.0" },
            "versions": {
                "1.0.0": {
                    "name": name,
                    "version": "1.0.0",
                    "dist": {
                        "tarball": "https://example.com/existing-1.0.0.tgz",
                        "integrity": "sha512-test"
                    },
                    "dependencies": {}
                }
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let output = lpm_with_registry(&project, &server.uri())
        .args([
            "release",
            "publish",
            "--all",
            "--lpm",
            "--dry-run",
            "--json",
        ])
        .output()
        .expect("check an unpublished version of an existing LPM package");

    assert!(
        output.status.success(),
        "release publish failed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    assert_eq!(
        parse_json_output(&output.stdout)["results"][0]["status"],
        "planned"
    );
    server.verify().await;
}

#[tokio::test]
async fn release_publish_revalidates_fresh_metadata_before_deciding_version_absence() {
    let project = TempProject::empty(
        r#"{"name":"root","private":true,"version":"0.0.0","workspaces":["packages/*"]}"#,
    );
    let name = "@lpm.dev/acme.cached";
    project.write_file(
        "packages/cached/package.json",
        &format!(r#"{{"name":"{name}","version":"1.0.0"}}"#),
    );
    let server = MockServer::start().await;
    mount_successful_lpm_publish_preflight(&server, name, "1.0.0", false).await;

    let initial = lpm_with_registry(&project, &server.uri())
        .args([
            "release",
            "publish",
            "--all",
            "--lpm",
            "--dry-run",
            "--json",
        ])
        .output()
        .expect("seed a fresh absent-version metadata cache");
    assert!(initial.status.success());

    server.reset().await;
    mount_successful_lpm_publish_preflight(&server, name, "1.0.0", true).await;
    mount_lpm_metadata_versions(&server, name, &["1.0.0"]).await;
    let output = lpm_with_registry(&project, &server.uri())
        .args([
            "release",
            "publish",
            "--all",
            "--lpm",
            "--dry-run",
            "--json",
        ])
        .output()
        .expect("revalidate release publish metadata");

    assert!(output.status.success());
    let envelope = parse_json_output(&output.stdout);
    assert_eq!(envelope["results"][0]["status"], "skipped");
    assert_eq!(envelope["results"][0]["reason"], "already_published");
}

#[tokio::test]
async fn release_publish_revalidates_fresh_metadata_before_deciding_version_presence() {
    let project = TempProject::empty(
        r#"{"name":"root","private":true,"version":"0.0.0","workspaces":["packages/*"]}"#,
    );
    let name = "@lpm.dev/acme.unpublished";
    project.write_file(
        "packages/unpublished/package.json",
        &format!(r#"{{"name":"{name}","version":"1.0.0"}}"#),
    );
    let server = MockServer::start().await;
    mount_successful_lpm_publish_preflight(&server, name, "1.0.0", true).await;
    mount_lpm_metadata_versions(&server, name, &["1.0.0"]).await;

    let initial = lpm_with_registry(&project, &server.uri())
        .args([
            "release",
            "publish",
            "--all",
            "--lpm",
            "--dry-run",
            "--json",
        ])
        .output()
        .expect("seed a fresh present-version metadata cache");
    assert!(initial.status.success());
    assert_eq!(
        parse_json_output(&initial.stdout)["results"][0]["status"],
        "skipped"
    );

    server.reset().await;
    mount_successful_lpm_publish_preflight(&server, name, "1.0.0", true).await;
    mount_lpm_metadata_versions(&server, name, &["0.9.0"]).await;
    let output = lpm_with_registry(&project, &server.uri())
        .args([
            "release",
            "publish",
            "--all",
            "--lpm",
            "--dry-run",
            "--json",
        ])
        .output()
        .expect("revalidate unpublished release metadata");

    assert!(output.status.success());
    let envelope = parse_json_output(&output.stdout);
    assert_eq!(envelope["results"][0]["status"], "planned");
}

#[tokio::test]
async fn release_publish_does_not_treat_server_error_text_as_version_absence() {
    let project = TempProject::empty(
        r#"{"name":"root","private":true,"version":"0.0.0","workspaces":["packages/*"]}"#,
    );
    let name = "@lpm.dev/acme.unavailable";
    project.write_file(
        "packages/unavailable/package.json",
        &format!(r#"{{"name":"{name}","version":"1.0.0"}}"#),
    );
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/registry/-/package/publish-preflight"))
        .and(query_param("name", name))
        .and(query_param("version", "1.0.0"))
        .respond_with(ResponseTemplate::new(500).set_body_string("upstream returned not found 404"))
        .mount(&server)
        .await;

    let output = lpm_with_registry(&project, &server.uri())
        .args([
            "release",
            "publish",
            "--all",
            "--lpm",
            "--dry-run",
            "--json",
        ])
        .output()
        .expect("run release publish across a server error");

    assert!(
        !output.status.success(),
        "release publish treated HTTP 500 text as version absence"
    );
    let envelope = parse_json_output(&output.stdout);
    assert_eq!(envelope["error_code"], "http");
}

#[tokio::test]
async fn release_publish_rejects_mismatched_lpm_metadata_identity() {
    let project = TempProject::empty(
        r#"{"name":"root","private":true,"version":"0.0.0","workspaces":["packages/*"]}"#,
    );
    let name = "@lpm.dev/acme.expected";
    project.write_file(
        "packages/expected/package.json",
        &format!(r#"{{"name":"{name}","version":"1.0.0"}}"#),
    );
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/registry/-/package/publish-preflight"))
        .and(query_param("name", name))
        .and(query_param("version", "1.0.0"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "success": true,
            "name": "@lpm.dev/acme.attacker",
            "version": "1.0.0",
            "packageExists": true,
        })))
        .mount(&server)
        .await;

    let output = lpm_with_registry(&project, &server.uri())
        .args([
            "release",
            "publish",
            "--all",
            "--lpm",
            "--dry-run",
            "--json",
        ])
        .output()
        .expect("run release publish with mismatched metadata identity");

    assert!(!output.status.success());
    let envelope = parse_json_output(&output.stdout);
    assert!(
        envelope["error"]
            .as_str()
            .is_some_and(|error| error.contains("mismatched package identity")),
        "mismatched identity returned the wrong error: {envelope:#}",
    );
}

#[tokio::test]
async fn release_publish_checks_the_configured_npm_registry_with_its_scoped_token() {
    let project = TempProject::empty(
        r#"{"name":"root","private":true,"version":"0.0.0","workspaces":["packages/*"]}"#,
    );
    let name = "configured-release-package";
    project.write_file(
        "packages/configured/package.json",
        &format!(r#"{{"name":"{name}","version":"1.0.0"}}"#),
    );
    let lpm_server = MockServer::start().await;
    let npm_server = MockServer::start().await;
    project.write_file(
        "packages/configured/lpm.json",
        &format!(
            r#"{{"publish":{{"npm":{{"registry":"{}"}}}}}}"#,
            npm_server.uri()
        ),
    );
    let token = "release-configured-registry-token";
    let login = lpm(&project)
        .args([
            "--json",
            "login",
            "--login-registry",
            &npm_server.uri(),
            "--token",
            token,
        ])
        .output()
        .expect("store configured registry token");
    assert!(login.status.success());

    Mock::given(method("GET"))
        .and(path(format!("/{name}")))
        .and(header("authorization", format!("Bearer {token}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "name": name,
            "versions": {
                "1.0.0": {"name": name, "version": "1.0.0"}
            }
        })))
        .expect(1)
        .mount(&npm_server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/api/registry/{name}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "name": name,
            "dist-tags": {},
            "versions": {},
            "time": {},
        })))
        .expect(0)
        .mount(&lpm_server)
        .await;

    let output = lpm_with_registry(&project, &lpm_server.uri())
        .args([
            "release",
            "publish",
            "--all",
            "--npm",
            "--dry-run",
            "--json",
        ])
        .output()
        .expect("run configured npm registry release preflight");

    assert!(
        output.status.success(),
        "configured npm preflight failed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let envelope = parse_json_output(&output.stdout);
    assert_eq!(envelope["results"][0]["status"], "skipped");
    assert_eq!(envelope["results"][0]["reason"], "already_published");
    npm_server.verify().await;
    lpm_server.verify().await;
}

#[tokio::test]
async fn release_publish_fetches_the_npm_provider_jwt_once_per_command() {
    let project = TempProject::empty(
        r#"{"name":"root","private":true,"version":"0.0.0","workspaces":["packages/*"]}"#,
    );
    let server = MockServer::start().await;
    for package in ["npm-provider-alpha", "npm-provider-beta"] {
        project.write_file(
            &format!("packages/{package}/package.json"),
            &format!(r#"{{"name":"{package}","version":"1.0.0"}}"#),
        );
        project.write_file(
            &format!("packages/{package}/lpm.json"),
            &format!(
                r#"{{"publish":{{"npm":{{"registry":"{}"}}}}}}"#,
                server.uri()
            ),
        );
    }
    Mock::given(method("GET"))
        .and(path("/runtime-oidc"))
        .and(query_param("audience", "npm:registry.npmjs.org"))
        .and(header("authorization", "Bearer runtime-request-token"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({"value": "provider-npm-jwt"})),
        )
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path_regex("/-/npm/v1/oidc/token/exchange/package/.*"))
        .and(header("authorization", "Bearer provider-npm-jwt"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({"token": "scoped-npm-token"})),
        )
        .expect(4)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path_regex("/npm-provider-(alpha|beta)"))
        .and(header("authorization", "Bearer scoped-npm-token"))
        .respond_with(|request: &Request| {
            ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "name": request.url.path().trim_start_matches('/'),
                "versions": {},
            }))
        })
        .expect(2)
        .mount(&server)
        .await;
    Mock::given(method("PUT"))
        .and(path_regex("/npm-provider-(alpha|beta)"))
        .and(header("authorization", "Bearer scoped-npm-token"))
        .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({})))
        .expect(2)
        .mount(&server)
        .await;
    let client_build_marker = project.home().join("npm-publish-client-builds");

    let output = lpm_with_registry(&project, &server.uri())
        .env(
            "ACTIONS_ID_TOKEN_REQUEST_URL",
            format!("{}/runtime-oidc?seed=1", server.uri()),
        )
        .env("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "runtime-request-token")
        .env(
            "LPM_INTERNAL_TEST_NPM_PUBLISH_CLIENT_BUILD_MARKER",
            &client_build_marker,
        )
        .args(["release", "publish", "--all", "--npm", "--yes", "--json"])
        .output()
        .expect("run release with GitHub runtime npm OIDC");

    assert!(
        output.status.success(),
        "npm OIDC release failed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    server.verify().await;
    assert_eq!(
        std::fs::read_to_string(client_build_marker)
            .expect("read npm publish client build marker")
            .lines()
            .count(),
        1,
        "release publish rebuilt npm upload clients per package"
    );
}

#[tokio::test]
async fn release_publish_with_an_explicit_npm_tag_fetches_only_the_exact_version_document() {
    let project = TempProject::empty(
        r#"{"name":"root","private":true,"version":"0.0.0","workspaces":["packages/*"]}"#,
    );
    let package = "explicit-tag-release-package";
    project.write_file(
        "packages/package/package.json",
        &format!(r#"{{"name":"{package}","version":"1.0.0"}}"#),
    );
    let server = MockServer::start().await;
    project.write_file(
        "packages/package/lpm.json",
        &format!(
            r#"{{"publish":{{"npm":{{"registry":"{}","tag":"next"}}}}}}"#,
            server.uri()
        ),
    );
    let token = "explicit-tag-release-token";
    let login = lpm(&project)
        .args([
            "--json",
            "login",
            "--login-registry",
            &server.uri(),
            "--token",
            token,
        ])
        .output()
        .expect("store release registry token");
    assert!(login.status.success());
    Mock::given(method("GET"))
        .and(path(format!("/{package}/1.0.0")))
        .and(header("authorization", format!("Bearer {token}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "name": package,
            "version": "1.0.0"
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/{package}")))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&server)
        .await;

    let output = lpm_with_registry(&project, &server.uri())
        .args([
            "release",
            "publish",
            "--all",
            "--npm",
            "--dry-run",
            "--json",
        ])
        .output()
        .expect("run explicit-tag npm release preflight");

    assert!(
        output.status.success(),
        "explicit-tag npm preflight failed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    assert_eq!(
        parse_json_output(&output.stdout)["results"][0]["status"],
        "skipped"
    );
    server.verify().await;
}

#[tokio::test]
async fn release_publish_rejects_an_oversized_exact_npm_version_document() {
    let project = TempProject::empty(
        r#"{"name":"root","private":true,"version":"0.0.0","workspaces":["packages/*"]}"#,
    );
    let package = "oversized-exact-version";
    project.write_file(
        "packages/package/package.json",
        &format!(r#"{{"name":"{package}","version":"1.0.0"}}"#),
    );
    let server = MockServer::start().await;
    project.write_file(
        "packages/package/lpm.json",
        &format!(
            r#"{{"publish":{{"npm":{{"registry":"{}","tag":"next"}}}}}}"#,
            server.uri()
        ),
    );
    let token = "oversized-version-token";
    let login = lpm(&project)
        .args([
            "--json",
            "login",
            "--login-registry",
            &server.uri(),
            "--token",
            token,
        ])
        .output()
        .expect("store oversized-version registry token");
    assert!(login.status.success());
    Mock::given(method("GET"))
        .and(path(format!("/{package}/1.0.0")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "name": package,
            "version": "1.0.0",
            "padding": "x".repeat(2 * 1024 * 1024),
        })))
        .expect(1)
        .mount(&server)
        .await;

    let output = lpm_with_registry(&project, &server.uri())
        .args([
            "release",
            "publish",
            "--all",
            "--npm",
            "--dry-run",
            "--json",
        ])
        .output()
        .expect("run oversized exact-version preflight");

    assert!(!output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let error = parse_json_output(&output.stdout)["error"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    assert!(
        (error.contains("cap") && error.contains("1048576"))
            || (stderr.contains("cap") && stderr.contains("1048576")),
        "oversized exact-version response returned the wrong error\nstdout: {}\nstderr: {}",
        stdout,
        stderr,
    );
}

#[tokio::test]
async fn release_publish_fetches_one_npm_packument_before_uploading() {
    let project = TempProject::empty(
        r#"{"name":"root","private":true,"version":"0.0.0","workspaces":["packages/*"]}"#,
    );
    let package = "single-preflight-release-package";
    project.write_file(
        "packages/package/package.json",
        &format!(r#"{{"name":"{package}","version":"1.0.0"}}"#),
    );
    let server = MockServer::start().await;
    project.write_file(
        "packages/package/lpm.json",
        &format!(
            r#"{{"publish":{{"npm":{{"registry":"{}"}}}}}}"#,
            server.uri()
        ),
    );
    let token = "single-preflight-release-token";
    let login = lpm(&project)
        .args([
            "--json",
            "login",
            "--login-registry",
            &server.uri(),
            "--token",
            token,
        ])
        .output()
        .expect("store release registry token");
    assert!(login.status.success());
    Mock::given(method("GET"))
        .and(path(format!("/{package}")))
        .and(header("authorization", format!("Bearer {token}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "name": package,
            "versions": {}
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("PUT"))
        .and(path(format!("/{package}")))
        .and(header("authorization", format!("Bearer {token}")))
        .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({})))
        .expect(1)
        .mount(&server)
        .await;

    let output = lpm_with_registry(&project, &server.uri())
        .args(["release", "publish", "--all", "--npm", "--yes", "--json"])
        .output()
        .expect("publish after one npm preflight");
    assert!(
        output.status.success(),
        "release publish failed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        parse_json_output(&output.stdout)["results"][0]["status"],
        "published"
    );
    server.verify().await;
}

#[tokio::test]
async fn release_publish_rejects_mismatched_configured_npm_metadata_identity() {
    let project = TempProject::empty(
        r#"{"name":"root","private":true,"version":"0.0.0","workspaces":["packages/*"]}"#,
    );
    let name = "configured-release-identity";
    project.write_file(
        "packages/configured/package.json",
        &format!(r#"{{"name":"{name}","version":"1.0.0"}}"#),
    );
    let lpm_server = MockServer::start().await;
    let npm_server = MockServer::start().await;
    project.write_file(
        "packages/configured/lpm.json",
        &format!(
            r#"{{"publish":{{"npm":{{"registry":"{}"}}}}}}"#,
            npm_server.uri()
        ),
    );
    let token = "release-identity-registry-token";
    let login = lpm(&project)
        .args([
            "--json",
            "login",
            "--login-registry",
            &npm_server.uri(),
            "--token",
            token,
        ])
        .output()
        .expect("store configured registry token");
    assert!(login.status.success());
    Mock::given(method("GET"))
        .and(path(format!("/{name}")))
        .and(header("authorization", format!("Bearer {token}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "name": "different-package",
            "versions": {
                "1.0.0": {"name": "different-package", "version": "1.0.0"}
            }
        })))
        .expect(1)
        .mount(&npm_server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/api/registry/{name}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "name": name,
            "dist-tags": {},
            "versions": {},
            "time": {},
        })))
        .mount(&lpm_server)
        .await;

    let output = lpm_with_registry(&project, &lpm_server.uri())
        .args([
            "release",
            "publish",
            "--all",
            "--npm",
            "--dry-run",
            "--json",
        ])
        .output()
        .expect("run mismatched configured npm preflight");

    assert!(!output.status.success());
    let envelope = parse_json_output(&output.stdout);
    assert!(
        envelope["error"]
            .as_str()
            .is_some_and(|error| error.contains("unexpected package")),
        "mismatched npm identity returned the wrong error: {envelope:#}",
    );
}

#[tokio::test]
async fn release_publish_checks_gitlab_package_registry_before_skipping_a_version() {
    let project = TempProject::empty(
        r#"{"name":"root","private":true,"version":"0.0.0","workspaces":["packages/*"]}"#,
    );
    let package = "gitlab-release-package";
    project.write_file(
        "packages/gitlab/package.json",
        &format!(r#"{{"name":"{package}","version":"1.0.0"}}"#),
    );
    let server = MockServer::start().await;
    project.write_file(
        "packages/gitlab/lpm.json",
        &format!(
            r#"{{"publish":{{"registries":["gitlab"],"gitlab":{{"projectId":"42","registry":"{}"}}}}}}"#,
            server.uri()
        ),
    );
    let endpoint = format!("{}/api/v4/projects/42/packages/npm", server.uri());
    let token = "gitlab-release-registry-token";
    let login = lpm(&project)
        .args([
            "--json",
            "login",
            "--login-registry",
            &endpoint,
            "--token",
            token,
        ])
        .output()
        .expect("store GitLab registry token");
    assert!(login.status.success());
    Mock::given(method("GET"))
        .and(path(format!("/api/v4/projects/42/packages/npm/{package}")))
        .and(header("authorization", format!("Bearer {token}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "name": package,
            "versions": {
                "1.0.0": {"name": package, "version": "1.0.0"}
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let output = lpm_with_registry(&project, &server.uri())
        .args(["release", "publish", "--all", "--dry-run", "--json"])
        .output()
        .expect("run GitLab release preflight");
    assert!(
        output.status.success(),
        "GitLab preflight failed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let envelope = parse_json_output(&output.stdout);
    assert_eq!(envelope["results"][0]["status"], "skipped");
    server.verify().await;
}

#[tokio::test]
async fn release_publish_treats_an_exact_npm_404_as_version_availability() {
    let project = TempProject::empty(
        r#"{"name":"root","private":true,"version":"0.0.0","workspaces":["packages/*"]}"#,
    );
    let package = "npm-404-release-package";
    project.write_file(
        "packages/npm/package.json",
        &format!(r#"{{"name":"{package}","version":"1.0.0"}}"#),
    );
    let server = MockServer::start().await;
    project.write_file(
        "packages/npm/lpm.json",
        &format!(
            r#"{{"publish":{{"npm":{{"registry":"{}"}}}}}}"#,
            server.uri()
        ),
    );
    let token = "npm-404-release-token";
    let login = lpm(&project)
        .args([
            "--json",
            "login",
            "--login-registry",
            &server.uri(),
            "--token",
            token,
        ])
        .output()
        .expect("store npm registry token");
    assert!(login.status.success());
    Mock::given(method("GET"))
        .and(path(format!("/{package}")))
        .and(header("authorization", format!("Bearer {token}")))
        .respond_with(ResponseTemplate::new(404).set_body_string("package does not exist"))
        .expect(1)
        .mount(&server)
        .await;

    let output = lpm_with_registry(&project, &server.uri())
        .args([
            "release",
            "publish",
            "--all",
            "--npm",
            "--dry-run",
            "--json",
        ])
        .output()
        .expect("run npm 404 release preflight");
    assert!(output.status.success());
    assert_eq!(
        parse_json_output(&output.stdout)["results"][0]["status"],
        "planned"
    );
}

#[tokio::test]
async fn release_publish_rejects_duplicate_effective_destinations_before_network_access() {
    let project = TempProject::empty(
        r#"{"name":"root","private":true,"version":"0.0.0","workspaces":["packages/*"]}"#,
    );
    for member in ["alpha", "beta"] {
        project.write_file(
            &format!("packages/{member}/package.json"),
            &format!(r#"{{"name":"{member}","version":"1.0.0"}}"#),
        );
        project.write_file(
            &format!("packages/{member}/lpm.json"),
            r#"{"publish":{"lpm":{"name":"@lpm.dev/acme.shared"}}}"#,
        );
    }
    let server = MockServer::start().await;

    let output = lpm_with_registry(&project, &server.uri())
        .args([
            "release",
            "publish",
            "--all",
            "--lpm",
            "--dry-run",
            "--json",
        ])
        .output()
        .expect("run release publish with duplicate destinations");

    assert!(!output.status.success());
    let envelope = parse_json_output(&output.stdout);
    assert!(
        envelope["error"]
            .as_str()
            .is_some_and(|error| error.contains("same publication destination")),
        "duplicate destination returned the wrong error: {envelope:#}",
    );
    assert!(
        server
            .received_requests()
            .await
            .expect("read registry requests")
            .is_empty(),
        "duplicate destinations reached the registry",
    );
}

#[tokio::test]
async fn release_publish_rejects_different_versions_for_one_remote_package_before_network_access() {
    let project = TempProject::empty(
        r#"{"name":"root","private":true,"version":"0.0.0","workspaces":["packages/*"]}"#,
    );
    let server = MockServer::start().await;
    for (member, version) in [("alpha", "1.0.0"), ("beta", "2.0.0")] {
        project.write_file(
            &format!("packages/{member}/package.json"),
            &format!(r#"{{"name":"{member}","version":"{version}"}}"#),
        );
        project.write_file(
            &format!("packages/{member}/lpm.json"),
            &format!(
                r#"{{"publish":{{"npm":{{"name":"shared-package","registry":"{}"}}}}}}"#,
                server.uri()
            ),
        );
    }
    let login = lpm(&project)
        .args([
            "--json",
            "login",
            "--login-registry",
            &server.uri(),
            "--token",
            "shared-package-token",
        ])
        .output()
        .expect("store registry-scoped token");
    assert!(login.status.success());

    let output = lpm_with_registry(&project, &server.uri())
        .args([
            "release",
            "publish",
            "--all",
            "--npm",
            "--dry-run",
            "--json",
        ])
        .output()
        .expect("run release publish with remote package aliases");

    assert!(!output.status.success());
    let envelope = parse_json_output(&output.stdout);
    assert!(
        envelope["error"]
            .as_str()
            .is_some_and(|error| error.contains("same remote package")),
        "remote package aliases returned the wrong error: {envelope:#}",
    );
    assert!(
        server
            .received_requests()
            .await
            .expect("read registry requests")
            .is_empty(),
        "remote package aliases reached the registry",
    );
}

#[tokio::test]
async fn release_publish_rejects_equivalent_npm_and_custom_registry_destinations() {
    let project = TempProject::empty(
        r#"{"name":"root","private":true,"version":"0.0.0","workspaces":["packages/*"]}"#,
    );
    project.write_file(
        "packages/alpha/package.json",
        r#"{"name":"alpha","version":"1.0.0"}"#,
    );
    project.write_file(
        "packages/alpha/lpm.json",
        r#"{"publish":{"registries":["npm"],"npm":{"name":"shared-package","registry":"https://REGISTRY.example.com:443/npm/"}}}"#,
    );
    project.write_file(
        "packages/beta/package.json",
        r#"{"name":"beta","version":"1.0.0"}"#,
    );
    project.write_file(
        "packages/beta/lpm.json",
        r#"{"publish":{"registries":["https://registry.example.com/npm"],"npm":{"name":"shared-package"}}}"#,
    );
    let server = MockServer::start().await;

    let output = lpm_with_registry(&project, &server.uri())
        .args(["release", "publish", "--all", "--dry-run", "--json"])
        .output()
        .expect("run release publish with endpoint aliases");
    assert!(!output.status.success());
    let envelope = parse_json_output(&output.stdout);
    assert!(
        envelope["error"]
            .as_str()
            .is_some_and(|error| error.contains("same publication destination")),
        "equivalent endpoints were not rejected: {envelope:#}"
    );
    assert!(
        server
            .received_requests()
            .await
            .expect("read registry requests")
            .is_empty()
    );
}

#[test]
fn release_publish_dry_run_reuses_publish_preflight_validation() {
    let project = workspace_project();
    project.write_file(
        "packages/core/package.json",
        r#"{"name":"core","version":"v1.2.3"}"#,
    );

    let output = lpm(&project)
        .args([
            "release",
            "publish",
            "--filter",
            "core",
            "--dry-run",
            "--json",
            "--publish-registry",
            "https://registry.example.com",
        ])
        .output()
        .expect("run release publish dry-run with invalid publish metadata");

    assert!(!output.status.success());
    let envelope = parse_json_output(&output.stdout);
    assert!(
        envelope["error"]
            .as_str()
            .is_some_and(|error| error.contains("semantic version")),
        "release publish must share publish preflight validation: {envelope:#}",
    );
}

#[test]
fn release_publish_refuses_stale_internal_ranges_before_publish_starts() {
    let project = stale_workspace_project();

    let output = lpm(&project)
        .args([
            "release",
            "publish",
            "--all",
            "--dry-run",
            "--json",
            "--publish-registry",
            "https://registry.example.com",
        ])
        .output()
        .expect("failed to run lpm release publish");

    assert!(!output.status.success(), "stale internal range must fail");
    let json = parse_json_output(&output.stdout);
    assert_eq!(json["success"], false);
    assert_eq!(json["error_code"], "script");
    assert!(
        json["error"]
            .as_str()
            .unwrap_or_default()
            .contains("does not accept current workspace version 2.0.0")
    );
}

#[tokio::test]
async fn release_publish_refuses_manifest_drift_after_remote_preflight() {
    let project = TempProject::empty(
        r#"{"name":"root","private":true,"version":"0.0.0","workspaces":["packages/*"]}"#,
    );
    project.write_file(
        "packages/core/package.json",
        r#"{"name":"@lpm.dev/acme.core","version":"1.2.3"}"#,
    );
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/registry/-/package/publish-preflight"))
        .and(query_param("name", "@lpm.dev/acme.core"))
        .and(query_param("version", "1.2.3"))
        .respond_with(RewriteManifestOnMetadataRead {
            manifest_path: project.path().join("packages/core/package.json"),
            replacement: r#"{"name":"@lpm.dev/acme.core","version":"1.2.4"}"#.to_string(),
        })
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/registry/-/whoami"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "username": "test@example.com",
            "profile_username": "acme",
            "email": "test@example.com",
            "plan_tier": "pro",
            "mfa_enabled": false,
            "has_pool_access": true,
            "usage": { "storage_bytes": 0, "private_packages": 0 },
            "limits": { "storageBytes": 1_000_000, "privatePackages": 100 },
            "organizations": []
        })))
        .mount(&server)
        .await;
    Mock::given(method("PUT"))
        .and(path_regex("/api/registry/.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "success": true,
            "message": "Package published"
        })))
        .mount(&server)
        .await;

    let output = lpm_with_registry(&project, &server.uri())
        .args(["release", "publish", "--all", "--lpm", "--yes", "--json"])
        .output()
        .expect("run release publish across a preflight manifest change");

    assert!(
        !output.status.success(),
        "release publish accepted manifest drift\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let envelope = parse_json_output(&output.stdout);
    assert!(
        envelope["results"][0]["error"]
            .as_str()
            .is_some_and(|error| error.contains("changed after release publish preflight")),
        "release publish used stale prepared state: {envelope:#}"
    );
}

#[tokio::test]
async fn release_publish_revalidates_manifest_before_skipping_an_existing_version() {
    let project = TempProject::empty(
        r#"{"name":"root","private":true,"version":"0.0.0","workspaces":["packages/*"]}"#,
    );
    let name = "@lpm.dev/acme.core";
    project.write_file(
        "packages/core/package.json",
        &format!(r#"{{"name":"{name}","version":"1.0.0"}}"#),
    );
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/registry/-/package/publish-preflight"))
        .and(query_param("name", name))
        .and(query_param("version", "1.0.0"))
        .respond_with(RewriteManifestOnExistingPreflight {
            manifest_path: project.path().join("packages/core/package.json"),
            replacement: format!(r#"{{"name":"{name}","version":"2.0.0"}}"#),
        })
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/registry/@lpm.dev/acme.core"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "name": name,
            "description": "existing package",
            "latestVersion": "1.0.0",
            "dist-tags": { "latest": "1.0.0" },
            "versions": {
                "1.0.0": {
                    "name": name,
                    "version": "1.0.0",
                    "dist": {
                        "tarball": "https://example.com/core-1.0.0.tgz",
                        "integrity": "sha512-test"
                    },
                    "dependencies": {}
                }
            }
        })))
        .mount(&server)
        .await;

    let output = lpm_with_registry(&project, &server.uri())
        .args([
            "release",
            "publish",
            "--all",
            "--lpm",
            "--dry-run",
            "--json",
        ])
        .output()
        .expect("revalidate a skipped release member");

    assert!(
        !output.status.success(),
        "release publish skipped stale local intent\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let envelope = parse_json_output(&output.stdout);
    assert!(
        envelope["results"][0]["error"]
            .as_str()
            .is_some_and(|error| error.contains("changed after release publish preflight")),
        "release publish returned the wrong skipped-intent error: {envelope:#}"
    );
}

#[tokio::test]
async fn release_publish_human_failure_reports_the_package_and_manifest_drift() {
    let project = TempProject::empty(
        r#"{"name":"root","private":true,"version":"0.0.0","workspaces":["packages/*"]}"#,
    );
    project.write_file(
        "packages/core/package.json",
        r#"{"name":"@lpm.dev/acme.core","version":"1.2.3"}"#,
    );
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/registry/-/package/publish-preflight"))
        .and(query_param("name", "@lpm.dev/acme.core"))
        .and(query_param("version", "1.2.3"))
        .respond_with(RewriteManifestOnMetadataRead {
            manifest_path: project.path().join("packages/core/package.json"),
            replacement: r#"{"name":"@lpm.dev/acme.core","version":"1.2.4"}"#.to_string(),
        })
        .expect(1)
        .mount(&server)
        .await;

    let output = lpm_with_registry(&project, &server.uri())
        .args(["release", "publish", "--all", "--lpm", "--yes"])
        .output()
        .expect("run human release publish across a preflight manifest change");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("@lpm.dev/acme.core")
            && stderr.contains("changed after release publish preflight"),
        "human release publish hid the concrete package failure: {stderr}"
    );
}

#[tokio::test]
async fn release_publish_refuses_workspace_dependency_drift_after_remote_preflight() {
    let project = TempProject::empty(
        r#"{"name":"root","private":true,"version":"0.0.0","workspaces":["packages/*"]}"#,
    );
    project.write_file(
        "packages/core/package.json",
        r#"{"name":"@lpm.dev/acme.core","version":"1.0.0"}"#,
    );
    project.write_file(
        "packages/app/package.json",
        r#"{"name":"@lpm.dev/acme.app","version":"1.0.0","dependencies":{"@lpm.dev/acme.core":"workspace:*"}}"#,
    );
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/registry/-/package/publish-preflight"))
        .and(query_param("name", "@lpm.dev/acme.app"))
        .and(query_param("version", "1.0.0"))
        .respond_with(RewriteManifestOnMetadataRead {
            manifest_path: project.path().join("packages/core/package.json"),
            replacement: r#"{"name":"@lpm.dev/acme.core","version":"2.0.0"}"#.to_string(),
        })
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/registry/-/whoami"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "username": "test@example.com",
            "profile_username": "acme",
            "email": "test@example.com",
            "plan_tier": "pro",
            "mfa_enabled": false,
            "has_pool_access": true,
            "usage": { "storage_bytes": 0, "private_packages": 0 },
            "limits": { "storageBytes": 1_000_000, "privatePackages": 100 },
            "organizations": []
        })))
        .mount(&server)
        .await;
    Mock::given(method("PUT"))
        .and(path_regex("/api/registry/.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "success": true,
            "message": "Package published"
        })))
        .expect(0)
        .mount(&server)
        .await;

    let output = lpm_with_registry(&project, &server.uri())
        .args([
            "release",
            "publish",
            "--filter",
            "@lpm.dev/acme.app",
            "--lpm",
            "--yes",
            "--json",
        ])
        .output()
        .expect("run release publish across workspace dependency drift");

    assert!(
        !output.status.success(),
        "release publish accepted derived workspace drift\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let envelope = parse_json_output(&output.stdout);
    assert!(
        envelope["results"][0]["error"]
            .as_str()
            .is_some_and(|error| error.contains("workspace") && error.contains("changed")),
        "release publish returned the wrong drift error: {envelope:#}"
    );
}

#[tokio::test]
async fn release_publish_refuses_workspace_dependency_drift_between_member_uploads() {
    let project = TempProject::empty(
        r#"{"name":"root","private":true,"version":"0.0.0","workspaces":["packages/*"]}"#,
    );
    project.write_file(
        "packages/core/package.json",
        r#"{"name":"@lpm.dev/acme.core","version":"1.0.0"}"#,
    );
    project.write_file(
        "packages/app/package.json",
        r#"{"name":"@lpm.dev/acme.app","version":"1.0.0","dependencies":{"@lpm.dev/acme.core":"workspace:^"}}"#,
    );
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/registry/-/package/publish-preflight"))
        .respond_with(AvailableLpmPublishPreflight)
        .expect(2)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/registry/-/whoami"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "username": "test@example.com",
            "profile_username": "acme",
            "email": "test@example.com",
            "plan_tier": "pro",
            "mfa_enabled": false,
            "has_pool_access": true,
            "usage": { "storage_bytes": 0, "private_packages": 0 },
            "limits": { "storageBytes": 1_000_000, "privatePackages": 100 },
            "organizations": []
        })))
        .mount(&server)
        .await;
    let attempts = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    Mock::given(method("PUT"))
        .and(path_regex("/api/registry/.*"))
        .respond_with(RewriteManifestAfterFirstPublish {
            attempts: std::sync::Arc::clone(&attempts),
            manifest_path: project.path().join("packages/core/package.json"),
            replacement: r#"{"name":"@lpm.dev/acme.core","version":"2.0.0"}"#.to_string(),
        })
        .mount(&server)
        .await;

    let output = lpm_with_registry(&project, &server.uri())
        .args(["release", "publish", "--all", "--lpm", "--yes", "--json"])
        .output()
        .expect("run release publish across member upload drift");

    assert!(
        !output.status.success(),
        "release publish accepted derived workspace drift\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let envelope = parse_json_output(&output.stdout);
    assert_eq!(envelope["results"][0]["status"], "published");
    assert_eq!(envelope["results"][1]["status"], "failed");
    assert!(
        envelope["results"][1]["error"]
            .as_str()
            .is_some_and(|error| error.contains("workspace") && error.contains("changed")),
        "release publish returned the wrong drift error: {envelope:#}"
    );
    assert_eq!(attempts.load(std::sync::atomic::Ordering::SeqCst), 1);
}

#[tokio::test]
async fn release_publish_refuses_static_internal_range_drift_between_member_uploads() {
    let project = TempProject::empty(
        r#"{"name":"root","private":true,"version":"0.0.0","workspaces":["packages/*"]}"#,
    );
    project.write_file(
        "packages/core/package.json",
        r#"{"name":"@lpm.dev/acme.core","version":"1.0.0"}"#,
    );
    project.write_file(
        "packages/app/package.json",
        r#"{"name":"@lpm.dev/acme.app","version":"1.0.0","dependencies":{"@lpm.dev/acme.core":"^1.0.0"}}"#,
    );
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/registry/-/package/publish-preflight"))
        .respond_with(AvailableLpmPublishPreflight)
        .expect(2)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/registry/-/whoami"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "username": "test@example.com",
            "profile_username": "acme",
            "email": "test@example.com",
            "plan_tier": "pro",
            "mfa_enabled": false,
            "has_pool_access": true,
            "usage": { "storage_bytes": 0, "private_packages": 0 },
            "limits": { "storageBytes": 1_000_000, "privatePackages": 100 },
            "organizations": []
        })))
        .mount(&server)
        .await;
    let attempts = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    Mock::given(method("PUT"))
        .and(path_regex("/api/registry/.*"))
        .respond_with(RewriteManifestAfterFirstPublish {
            attempts: std::sync::Arc::clone(&attempts),
            manifest_path: project.path().join("packages/core/package.json"),
            replacement: r#"{"name":"@lpm.dev/acme.core","version":"2.0.0"}"#.to_string(),
        })
        .mount(&server)
        .await;

    let output = lpm_with_registry(&project, &server.uri())
        .args(["release", "publish", "--all", "--lpm", "--yes", "--json"])
        .output()
        .expect("run release publish across static internal range drift");

    assert!(
        !output.status.success(),
        "release publish accepted static internal range drift\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let envelope = parse_json_output(&output.stdout);
    assert_eq!(envelope["results"][0]["status"], "published");
    assert_eq!(envelope["results"][1]["status"], "failed");
    assert!(
        envelope["results"][1]["error"]
            .as_str()
            .is_some_and(|error| error.contains("does not accept current workspace version 2.0.0")),
        "release publish returned the wrong internal-range drift error: {envelope:#}"
    );
    assert_eq!(attempts.load(std::sync::atomic::Ordering::SeqCst), 1);
}

#[tokio::test]
async fn release_publish_refuses_duplicate_member_name_drift_between_uploads() {
    let project = TempProject::empty(
        r#"{"name":"root","private":true,"version":"0.0.0","workspaces":["packages/*"]}"#,
    );
    project.write_file(
        "packages/core/package.json",
        r#"{"name":"@lpm.dev/acme.core","version":"1.0.0"}"#,
    );
    project.write_file(
        "packages/app/package.json",
        r#"{"name":"@lpm.dev/acme.app","version":"1.0.0","dependencies":{"@lpm.dev/acme.core":"workspace:^"}}"#,
    );
    project.write_file(
        "packages/other/package.json",
        r#"{"name":"@lpm.dev/acme.other","version":"1.0.0"}"#,
    );
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/registry/-/package/publish-preflight"))
        .respond_with(AvailableLpmPublishPreflight)
        .expect(2)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/registry/-/whoami"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "username": "test@example.com",
            "profile_username": "acme",
            "email": "test@example.com",
            "plan_tier": "pro",
            "mfa_enabled": false,
            "has_pool_access": true,
            "usage": { "storage_bytes": 0, "private_packages": 0 },
            "limits": { "storageBytes": 1_000_000, "privatePackages": 100 },
            "organizations": []
        })))
        .mount(&server)
        .await;
    let attempts = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    Mock::given(method("PUT"))
        .and(path_regex("/api/registry/.*"))
        .respond_with(RewriteManifestAfterFirstPublish {
            attempts: std::sync::Arc::clone(&attempts),
            manifest_path: project.path().join("packages/other/package.json"),
            replacement: r#"{"name":"@lpm.dev/acme.core","version":"1.0.0"}"#.to_string(),
        })
        .mount(&server)
        .await;

    let output = lpm_with_registry(&project, &server.uri())
        .args([
            "release",
            "publish",
            "--filter",
            "@lpm.dev/acme.core",
            "--filter",
            "@lpm.dev/acme.app",
            "--lpm",
            "--yes",
            "--json",
        ])
        .output()
        .expect("run release publish across duplicate member-name drift");

    assert!(
        !output.status.success(),
        "release publish accepted duplicate member-name drift\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let envelope = parse_json_output(&output.stdout);
    assert_eq!(envelope["results"][0]["status"], "published");
    assert_eq!(envelope["results"][1]["status"], "failed");
    assert!(
        envelope["results"][1]["error"]
            .as_str()
            .is_some_and(|error| error.contains("duplicate workspace package names")),
        "release publish returned the wrong duplicate-name drift error: {envelope:#}"
    );
    assert_eq!(attempts.load(std::sync::atomic::Ordering::SeqCst), 1);
}

#[tokio::test]
async fn release_publish_refuses_a_new_workspace_member_between_uploads() {
    let project = TempProject::empty(
        r#"{"name":"root","private":true,"version":"0.0.0","workspaces":["packages/*"]}"#,
    );
    project.write_file(
        "packages/core/package.json",
        r#"{"name":"@lpm.dev/acme.core","version":"1.0.0"}"#,
    );
    project.write_file(
        "packages/app/package.json",
        r#"{"name":"@lpm.dev/acme.app","version":"1.0.0","dependencies":{"@lpm.dev/acme.core":"workspace:^"}}"#,
    );
    project.write_file("packages/future/placeholder", "reserved directory");
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/registry/-/package/publish-preflight"))
        .respond_with(AvailableLpmPublishPreflight)
        .expect(2)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/registry/-/whoami"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "username": "test@example.com",
            "profile_username": "acme",
            "email": "test@example.com",
            "plan_tier": "pro",
            "mfa_enabled": false,
            "has_pool_access": true,
            "usage": { "storage_bytes": 0, "private_packages": 0 },
            "limits": { "storageBytes": 1_000_000, "privatePackages": 100 },
            "organizations": []
        })))
        .mount(&server)
        .await;
    let attempts = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    Mock::given(method("PUT"))
        .and(path_regex("/api/registry/.*"))
        .respond_with(RewriteManifestAfterFirstPublish {
            attempts: std::sync::Arc::clone(&attempts),
            manifest_path: project.path().join("packages/future/package.json"),
            replacement: r#"{"name":"@lpm.dev/acme.future","version":"1.0.0"}"#.to_string(),
        })
        .mount(&server)
        .await;

    let output = lpm_with_registry(&project, &server.uri())
        .args([
            "release",
            "publish",
            "--filter",
            "@lpm.dev/acme.core",
            "--filter",
            "@lpm.dev/acme.app",
            "--lpm",
            "--yes",
            "--json",
        ])
        .output()
        .expect("run release publish across workspace member addition");

    assert!(!output.status.success());
    let envelope = parse_json_output(&output.stdout);
    assert_eq!(envelope["results"][0]["status"], "published");
    assert_eq!(envelope["results"][1]["status"], "failed");
    assert!(
        envelope["results"][1]["error"]
            .as_str()
            .is_some_and(|error| error.contains("workspace member set changed")),
        "release publish returned the wrong member-set drift error: {envelope:#}"
    );
    assert_eq!(attempts.load(std::sync::atomic::Ordering::SeqCst), 1);
}

#[tokio::test]
async fn release_publish_refuses_catalog_drift_between_member_uploads() {
    let project = TempProject::empty(
        r#"{"name":"root","private":true,"version":"0.0.0","workspaces":["packages/*"],"catalogs":{"default":{"react":"^18.0.0"}}}"#,
    );
    project.write_file(
        "packages/core/package.json",
        r#"{"name":"@lpm.dev/acme.core","version":"1.0.0"}"#,
    );
    project.write_file(
        "packages/app/package.json",
        r#"{"name":"@lpm.dev/acme.app","version":"1.0.0","dependencies":{"@lpm.dev/acme.core":"workspace:^","react":"catalog:"}}"#,
    );
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/registry/-/package/publish-preflight"))
        .respond_with(AvailableLpmPublishPreflight)
        .expect(2)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/registry/-/whoami"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "username": "test@example.com",
            "profile_username": "acme",
            "email": "test@example.com",
            "plan_tier": "pro",
            "mfa_enabled": false,
            "has_pool_access": true,
            "usage": { "storage_bytes": 0, "private_packages": 0 },
            "limits": { "storageBytes": 1_000_000, "privatePackages": 100 },
            "organizations": []
        })))
        .mount(&server)
        .await;
    let attempts = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    Mock::given(method("PUT"))
        .and(path_regex("/api/registry/.*"))
        .respond_with(RewriteManifestAfterFirstPublish {
            attempts: std::sync::Arc::clone(&attempts),
            manifest_path: project.path().join("package.json"),
            replacement: r#"{"name":"root","private":true,"version":"0.0.0","workspaces":["packages/*"],"catalogs":{"default":{"react":"^19.0.0"}}}"#.to_string(),
        })
        .mount(&server)
        .await;

    let output = lpm_with_registry(&project, &server.uri())
        .args(["release", "publish", "--all", "--lpm", "--yes", "--json"])
        .output()
        .expect("run release publish across catalog drift");

    assert!(
        !output.status.success(),
        "release publish accepted catalog drift\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let envelope = parse_json_output(&output.stdout);
    assert_eq!(envelope["results"][0]["status"], "published");
    assert_eq!(envelope["results"][1]["status"], "failed");
    assert!(
        envelope["results"][1]["error"]
            .as_str()
            .is_some_and(|error| error.contains("catalog") && error.contains("changed")),
        "release publish returned the wrong catalog drift error: {envelope:#}"
    );
    assert_eq!(attempts.load(std::sync::atomic::Ordering::SeqCst), 1);
}

#[tokio::test]
async fn release_publish_reuses_one_lpm_whoami_for_shared_auth_members() {
    let project = TempProject::empty(
        r#"{"name":"root","private":true,"version":"0.0.0","workspaces":["packages/*"]}"#,
    );
    for package in ["@lpm.dev/acme.alpha", "@lpm.dev/acme.beta"] {
        let member = package.rsplit('.').next().expect("member name");
        project.write_file(
            &format!("packages/{member}/package.json"),
            &format!(r#"{{"name":"{package}","version":"1.0.0"}}"#),
        );
    }
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/registry/-/package/publish-preflight"))
        .respond_with(AvailableLpmPublishPreflight)
        .expect(2)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/registry/-/whoami"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "username": "test@example.com",
            "profile_username": "acme",
            "email": "test@example.com",
            "plan_tier": "pro",
            "mfa_enabled": false,
            "has_pool_access": true,
            "usage": { "storage_bytes": 0, "private_packages": 0 },
            "limits": { "storageBytes": 1_000_000, "privatePackages": 100 },
            "organizations": []
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("PUT"))
        .and(path_regex("/api/registry/.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "success": true,
            "message": "Package published"
        })))
        .expect(2)
        .mount(&server)
        .await;

    let output = lpm_with_registry(&project, &server.uri())
        .args(["release", "publish", "--all", "--lpm", "--yes", "--json"])
        .output()
        .expect("publish two release members with shared registry authentication");

    assert!(
        output.status.success(),
        "release publish failed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    server.verify().await;
}

#[tokio::test]
async fn release_publish_reports_completed_and_unattempted_packages_after_failure() {
    let project = TempProject::empty(
        r#"{"name":"root","private":true,"version":"0.0.0","workspaces":["packages/*"]}"#,
    );
    project.write_file(
        "packages/core/package.json",
        r#"{"name":"@lpm.dev/acme.core","version":"1.0.0"}"#,
    );
    project.write_file(
        "packages/app/package.json",
        r#"{"name":"@lpm.dev/acme.app","version":"1.0.0","dependencies":{"@lpm.dev/acme.core":"workspace:*"}}"#,
    );
    project.write_file(
        "packages/docs/package.json",
        r#"{"name":"@lpm.dev/acme.docs","version":"1.0.0","dependencies":{"@lpm.dev/acme.app":"workspace:*"}}"#,
    );
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/registry/-/package/publish-preflight"))
        .respond_with(AvailableLpmPublishPreflight)
        .expect(3)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/registry/-/whoami"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "username": "test@example.com",
            "profile_username": "acme",
            "email": "test@example.com",
            "plan_tier": "pro",
            "mfa_enabled": false,
            "has_pool_access": true,
            "usage": { "storage_bytes": 0, "private_packages": 0 },
            "limits": { "storageBytes": 1_000_000, "privatePackages": 100 },
            "organizations": []
        })))
        .mount(&server)
        .await;
    Mock::given(method("PUT"))
        .and(path_regex("/api/registry/.*"))
        .respond_with(FailSecondPublish::default())
        .expect(2)
        .mount(&server)
        .await;

    let output = lpm_with_registry(&project, &server.uri())
        .args(["release", "publish", "--all", "--lpm", "--yes", "--json"])
        .output()
        .expect("publish a workspace with a later package failure");

    assert!(!output.status.success());
    let mut json = parse_json_output(&output.stdout);
    redact_publish_paths(&mut json);
    insta::assert_json_snapshot!(json, @r###"
    {
      "success": false,
      "dry_run": false,
      "packages": 3,
      "results": [
        {
          "name": "@lpm.dev/acme.core",
          "version": "1.0.0",
          "path": "[@lpm.dev/acme.core]",
          "status": "published"
        },
        {
          "name": "@lpm.dev/acme.app",
          "version": "1.0.0",
          "path": "[@lpm.dev/acme.app]",
          "status": "failed",
          "error": "one or more publish targets failed",
          "targets": [
            {
              "registry": "lpm",
              "success": false,
              "error": "HTTP 500: {\"error\":\"simulated registry failure\"}",
              "duration_ms": "[duration]"
            }
          ]
        },
        {
          "name": "@lpm.dev/acme.docs",
          "version": "1.0.0",
          "path": "[@lpm.dev/acme.docs]",
          "status": "not_attempted",
          "reason": "a previous package failed"
        }
      ],
      "warning": "Publishing is not transactional. Successful uploads were not rolled back; retry only failed and not-attempted packages."
    }
    "###);
}

#[tokio::test]
async fn release_publish_uses_each_members_publish_config_directory() {
    let project = TempProject::empty(
        r#"{"name":"root","private":true,"version":"0.0.0","workspaces":["packages/*"]}"#,
    );
    project.write_file(
        "packages/projected/package.json",
        r#"{
          "name":"@lpm.dev/acme.projected",
          "version":"1.0.0",
          "publishConfig":{"directory":"dist"},
          "files":["root-only.js"]
        }"#,
    );
    project.write_file(
        "packages/projected/root-only.js",
        "module.exports = 'root';\n",
    );
    project.write_file(
        "packages/projected/dist/package.json",
        r#"{
          "name":"@lpm.dev/acme.projected",
          "version":"1.0.0",
          "description":"release projection",
          "files":["projected.js"]
        }"#,
    );
    project.write_file(
        "packages/projected/dist/projected.js",
        "module.exports = 'projected';\n",
    );
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/registry/-/package/publish-preflight"))
        .respond_with(AvailableLpmPublishPreflight)
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/registry/-/whoami"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "username": "test@example.com",
            "profile_username": "acme",
            "email": "test@example.com",
            "plan_tier": "pro",
            "mfa_enabled": false,
            "has_pool_access": true,
            "usage": { "storage_bytes": 0, "private_packages": 0 },
            "limits": { "storageBytes": 1_000_000, "privatePackages": 100 },
            "organizations": []
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("PUT"))
        .and(path_regex("/api/registry/.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "success": true,
            "message": "Package published"
        })))
        .expect(1)
        .mount(&server)
        .await;

    let output = lpm_with_registry(&project, &server.uri())
        .args(["release", "publish", "--all", "--lpm", "--yes", "--json"])
        .output()
        .expect("publish a projected release member");

    assert!(
        output.status.success(),
        "release publish failed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let requests = server.received_requests().await.unwrap();
    let upload = requests
        .iter()
        .find(|request| request.method.as_str() == "PUT")
        .expect("release publish must upload the member");
    let paths = release_uploaded_file_paths(&extract_release_upload_tarball(upload));
    assert!(paths.iter().any(|path| path == "package/projected.js"));
    assert!(
        !paths.iter().any(|path| path == "package/root-only.js"),
        "release publish leaked the source package into the projected artifact: {paths:?}"
    );
}

#[tokio::test]
async fn release_publish_runs_each_lifecycle_phase_once_in_npm_order() {
    let project = TempProject::empty(
        r#"{"name":"root","private":true,"version":"0.0.0","workspaces":["packages/*"]}"#,
    );
    project.write_file(
        "packages/member/package.json",
        r#"{
          "name":"@lpm.dev/acme.lifecycle",
          "version":"1.0.0",
          "scripts":{
            "prepublishOnly":"node record-lifecycle.js prepublishOnly",
            "prepack":"node record-lifecycle.js prepack",
            "prepare":"node record-lifecycle.js prepare",
            "postpack":"node record-lifecycle.js postpack",
            "publish":"node record-lifecycle.js publish",
            "postpublish":"node record-lifecycle.js postpublish"
          }
        }"#,
    );
    project.write_file(
        "packages/member/record-lifecycle.js",
        "require('fs').appendFileSync('lifecycle.log', process.argv[2] + '\\n')\n",
    );
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/registry/-/package/publish-preflight"))
        .respond_with(AvailableLpmPublishPreflight)
        .expect(1)
        .mount(&server)
        .await;

    let output = lpm_with_registry(&project, &server.uri())
        .args([
            "release",
            "publish",
            "--all",
            "--lpm",
            "--dry-run",
            "--yes",
            "--json",
        ])
        .output()
        .expect("run release publish lifecycle");

    assert!(
        output.status.success(),
        "release lifecycle failed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    assert_eq!(
        project.read_file("packages/member/lifecycle.log"),
        "prepublishOnly\nprepack\nprepare\npostpack\npublish\npostpublish\n"
    );
}

#[tokio::test]
async fn release_publish_ignore_scripts_skips_every_lifecycle_phase() {
    let project = TempProject::empty(
        r#"{"name":"root","private":true,"version":"0.0.0","workspaces":["packages/*"]}"#,
    );
    project.write_file(
        "packages/member/package.json",
        r#"{
          "name":"@lpm.dev/acme.ignore-lifecycle",
          "version":"1.0.0",
          "scripts":{"prepack":"node write-marker.js","postpublish":"node write-marker.js"}
        }"#,
    );
    project.write_file(
        "packages/member/write-marker.js",
        "require('fs').writeFileSync('lifecycle-ran', 'yes')\n",
    );
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/registry/-/package/publish-preflight"))
        .respond_with(AvailableLpmPublishPreflight)
        .expect(1)
        .mount(&server)
        .await;

    let output = lpm_with_registry(&project, &server.uri())
        .args([
            "release",
            "publish",
            "--all",
            "--lpm",
            "--dry-run",
            "--ignore-scripts",
            "--json",
        ])
        .output()
        .expect("run release publish with lifecycle scripts disabled");

    assert!(output.status.success(), "{output:?}");
    assert!(
        !project
            .path()
            .join("packages/member/lifecycle-ran")
            .exists()
    );
}

#[tokio::test]
async fn release_publish_preserves_successful_upload_when_postpublish_fails() {
    let project = TempProject::empty(
        r#"{"name":"root","private":true,"version":"0.0.0","workspaces":["packages/*"]}"#,
    );
    project.write_file(
        "packages/member/package.json",
        r#"{
          "name":"@lpm.dev/acme.postpublish-failure",
          "version":"1.0.0",
          "scripts":{"postpublish":"node -e \"process.exit(17)\""}
        }"#,
    );
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/registry/-/package/publish-preflight"))
        .respond_with(AvailableLpmPublishPreflight)
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/registry/-/whoami"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "username": "test@example.com",
            "profile_username": "acme",
            "email": "test@example.com",
            "plan_tier": "pro",
            "mfa_enabled": false,
            "has_pool_access": true,
            "usage": { "storage_bytes": 0, "private_packages": 0 },
            "limits": { "storageBytes": 1_000_000, "privatePackages": 100 },
            "organizations": []
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("PUT"))
        .and(path_regex("/api/registry/.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "success": true,
            "message": "Package published"
        })))
        .expect(1)
        .mount(&server)
        .await;

    let output = lpm_with_registry(&project, &server.uri())
        .args(["release", "publish", "--all", "--lpm", "--yes", "--json"])
        .output()
        .expect("publish before a failing release postpublish lifecycle");

    assert!(
        !output.status.success(),
        "postpublish failure must fail the command"
    );
    let json = parse_json_output(&output.stdout);
    assert_eq!(json["results"][0]["status"], "failed");
    assert_eq!(json["results"][0]["targets"][0]["success"], true);
    assert!(
        json["results"][0]["error"]
            .as_str()
            .is_some_and(|error| error.contains("postpublish")),
        "the lifecycle failure must remain separate from the successful upload: {json}"
    );
    assert!(
        json["warning"]
            .as_str()
            .is_some_and(|warning| warning.contains("Successful uploads were not rolled back")),
        "the retry warning must acknowledge the completed upload: {json}"
    );
}

#[tokio::test]
async fn release_publish_holds_the_exclusive_install_lock_through_upload() {
    let project = TempProject::empty(
        r#"{"name":"root","private":true,"version":"0.0.0","workspaces":["packages/*"]}"#,
    );
    project.write_file(
        "packages/member/package.json",
        r#"{"name":"@lpm.dev/acme.release-lock","version":"1.0.0"}"#,
    );
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/registry/-/package/publish-preflight"))
        .respond_with(AvailableLpmPublishPreflight)
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/registry/-/whoami"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "username": "test@example.com",
            "profile_username": "acme",
            "email": "test@example.com",
            "plan_tier": "pro",
            "mfa_enabled": false,
            "has_pool_access": true,
            "usage": { "storage_bytes": 0, "private_packages": 0 },
            "limits": { "storageBytes": 1_000_000, "privatePackages": 100 },
            "organizations": []
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("PUT"))
        .and(path_regex("/api/registry/.*"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(std::time::Duration::from_secs(3))
                .set_body_json(serde_json::json!({
                    "success": true,
                    "message": "Package published"
                })),
        )
        .expect(1)
        .mount(&server)
        .await;

    let mut command = lpm_spawnable(&project);
    command
        .env("LPM_REGISTRY_URL", server.uri())
        .args(["release", "publish", "--all", "--lpm", "--yes", "--json"]);
    let mut child = command.spawn().expect("spawn delayed release publish");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        let upload_started = server
            .received_requests()
            .await
            .expect("read mock requests")
            .iter()
            .any(|request| request.method.as_str() == "PUT");
        if upload_started {
            break;
        }
        if let Some(status) = child.try_wait().expect("inspect delayed release publish") {
            panic!("release publish exited with {status} before uploading");
        }
        if std::time::Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("release publish did not begin uploading within 10 seconds");
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }

    let install_lock = lpm_common::project_install_lock(project.path());
    let available_during_upload = lpm_common::try_acquire_exclusive_lock(&install_lock)
        .expect("probe release install lock")
        .is_some();
    let output = child
        .wait_with_output()
        .expect("finish delayed release publish");

    assert!(
        output.status.success(),
        "release publish failed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    assert!(
        !available_during_upload,
        "release publish must keep the install lock while holding the publication lock"
    );
}
