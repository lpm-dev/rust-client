mod support;

use support::assertions::parse_json_output;
use support::{
    LOCK_CONTENTION_MARKER_ENV, TempProject, lpm, lpm_spawnable, lpm_with_registry,
    wait_for_lock_contention,
};
use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

struct RewriteManifestOnMetadataRead {
    manifest_path: std::path::PathBuf,
    metadata: serde_json::Value,
    replacement: String,
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

impl Respond for RewriteManifestOnMetadataRead {
    fn respond(&self, _request: &Request) -> ResponseTemplate {
        std::fs::write(&self.manifest_path, &self.replacement)
            .expect("rewrite manifest after release preflight intent capture");
        ResponseTemplate::new(200).set_body_json(&self.metadata)
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

#[test]
fn release_publish_dry_run_reports_dependency_order() {
    let project = workspace_project();

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
        .and(path("/api/registry/@lpm.dev/acme.core"))
        .respond_with(RewriteManifestOnMetadataRead {
            manifest_path: project.path().join("packages/core/package.json"),
            metadata: serde_json::json!({
                "name": "@lpm.dev/acme.core",
                "dist-tags": {},
                "versions": {},
                "time": {},
            }),
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
        .and(path("/api/registry/@lpm.dev/acme.core"))
        .respond_with(RewriteManifestOnMetadataRead {
            manifest_path: project.path().join("packages/core/package.json"),
            metadata: serde_json::json!({
                "name": "@lpm.dev/acme.core",
                "dist-tags": {},
                "versions": {},
                "time": {},
            }),
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
        .and(path("/api/registry/@lpm.dev/acme.app"))
        .respond_with(RewriteManifestOnMetadataRead {
            manifest_path: project.path().join("packages/core/package.json"),
            metadata: serde_json::json!({
                "name": "@lpm.dev/acme.app",
                "dist-tags": {},
                "versions": {},
                "time": {},
            }),
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
        .and(path_regex("/api/registry/@lpm.dev/acme.(core|app|docs)"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "name": "workspace-package",
            "dist-tags": {},
            "versions": {},
            "time": {},
        })))
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
