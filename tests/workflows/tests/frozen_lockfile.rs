//! Workflow tests for frozen lockfile install semantics.

mod support;

use support::mock_registry::{MockRegistry, make_tarball};
use support::{TempProject, assertions, lpm, lpm_with_registry};

async fn mount_ms(mock: &MockRegistry) {
    let tarball = make_tarball("ms", "2.1.3");
    mock.with_package("ms", "2.1.3", &tarball).await;
}

async fn install_once(project: &TempProject, mock: &MockRegistry) {
    let output = lpm_with_registry(project, &mock.url())
        .args(["install", "--no-security-summary", "--no-skills"])
        .output()
        .expect("failed to run initial lpm install");

    assert!(
        output.status.success(),
        "initial install failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn install_workspace_once(project: &TempProject) {
    let output = lpm(project)
        .args(["install", "--no-security-summary", "--no-skills"])
        .output()
        .expect("failed to run initial workspace lpm install");

    assert!(
        output.status.success(),
        "initial workspace install failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[tokio::test]
async fn mutable_install_refreshes_legacy_lockfile_for_future_frozen_installs() {
    let mock = MockRegistry::start().await;
    mount_ms(&mock).await;

    let project = TempProject::empty(
        r#"{
            "name": "frozen-upgrade",
            "version": "1.0.0",
            "dependencies": { "ms": "^2.1.3" }
        }"#,
    );
    install_once(&project, &mock).await;

    let lockfile_path = project.path().join("lpm.lock");
    let mut legacy_lockfile =
        lpm_lockfile::Lockfile::read_from_file(&lockfile_path).expect("initial lockfile parses");
    legacy_lockfile.metadata.lockfile_version = 4;
    legacy_lockfile.importers.clear();
    legacy_lockfile.root_resolutions.clear();
    for package in &mut legacy_lockfile.packages {
        package.instance_id = None;
        package.dependency_targets.clear();
        package.peer_targets.clear();
        package.peer_edges.clear();
        package.manifest_fingerprint = None;
    }
    legacy_lockfile
        .write_to_file(&lockfile_path)
        .expect("failed to write simulated legacy lockfile");

    let output = lpm_with_registry(&project, &mock.url())
        .args(["install", "--no-security-summary", "--no-skills"])
        .output()
        .expect("failed to run mutable lpm install");

    assert!(
        output.status.success(),
        "mutable install must refresh a legacy lockfile:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let upgraded =
        lpm_lockfile::Lockfile::read_from_file(&lockfile_path).expect("upgraded lockfile parses");
    assert_eq!(
        upgraded.metadata.lockfile_version,
        lpm_lockfile::LOCKFILE_VERSION,
        "mutable install must upgrade the lockfile schema for frozen installs"
    );
    assert!(
        upgraded.importers.contains_key("."),
        "mutable install must record the root importer snapshot"
    );
    assert!(
        !project.path().join("lpm.lockb").exists(),
        "importer snapshots are TOML-only and must remove stale binary lockfiles"
    );

    let ci_output = lpm_with_registry(&project, &mock.url())
        .args(["ci", "--no-skills", "--no-security-summary"])
        .output()
        .expect("failed to run lpm ci after lockfile refresh");

    assert!(
        ci_output.status.success(),
        "refreshed lockfile must be accepted by lpm ci:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&ci_output.stdout),
        String::from_utf8_lossy(&ci_output.stderr)
    );
}

#[tokio::test]
async fn frozen_install_rejects_manifest_specifier_drift_without_rewriting_lockfile() {
    let mock = MockRegistry::start().await;
    mount_ms(&mock).await;

    let project = TempProject::empty(
        r#"{
            "name": "frozen-drift",
            "version": "1.0.0",
            "dependencies": { "ms": "^2.1.3" }
        }"#,
    );
    install_once(&project, &mock).await;
    let before = project.read_file("lpm.lock");

    project.write_file(
        "package.json",
        r#"{
            "name": "frozen-drift",
            "version": "1.0.0",
            "dependencies": { "ms": "^2.0.0" }
        }"#,
    );

    let output = lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "--frozen-lockfile",
            "--no-security-summary",
            "--no-skills",
        ])
        .output()
        .expect("failed to run lpm install --frozen-lockfile");

    assert!(
        !output.status.success(),
        "frozen install must reject package.json/lpm.lock drift"
    );
    assert_eq!(
        project.read_file("lpm.lock"),
        before,
        "frozen install must not rewrite lpm.lock on mismatch"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Frozen lockfile mismatch")
            && stderr.contains("ms")
            && stderr.contains("^2.0.0")
            && stderr.contains("^2.1.3"),
        "stderr must name the drifting dependency and both specifiers, got:\n{stderr}"
    );
}

#[tokio::test]
async fn lpm_ci_rejects_manifest_specifier_drift_without_rewriting_lockfile() {
    let mock = MockRegistry::start().await;
    mount_ms(&mock).await;
    let project = TempProject::empty(
        r#"{
            "name": "ci-drift",
            "version": "1.0.0",
            "dependencies": { "ms": "^2.1.3" }
        }"#,
    );
    install_once(&project, &mock).await;
    let before = project.read_file("lpm.lock");
    project.write_file(
        "package.json",
        r#"{
            "name": "ci-drift",
            "version": "1.0.0",
            "dependencies": { "ms": "^3.0.0" }
        }"#,
    );

    let output = lpm_with_registry(&project, &mock.url())
        .args(["ci", "--no-security-summary", "--no-skills"])
        .output()
        .expect("run lpm ci with manifest drift");

    assert!(!output.status.success());
    assert_eq!(project.read_file("lpm.lock"), before);
    assert!(String::from_utf8_lossy(&output.stderr).contains("Frozen lockfile mismatch"));
}

#[tokio::test]
async fn ci_env_enables_frozen_install_when_lockfile_exists() {
    let mock = MockRegistry::start().await;
    mount_ms(&mock).await;

    let project = TempProject::empty(
        r#"{
            "name": "ci-auto-freeze",
            "version": "1.0.0",
            "dependencies": { "ms": "^2.1.3" }
        }"#,
    );
    install_once(&project, &mock).await;
    let before = project.read_file("lpm.lock");

    project.write_file(
        "package.json",
        r#"{
            "name": "ci-auto-freeze",
            "version": "1.0.0",
            "dependencies": { "ms": "^2.0.0" }
        }"#,
    );

    let output = lpm_with_registry(&project, &mock.url())
        .env("CI", "true")
        .args(["install", "--no-security-summary", "--no-skills"])
        .output()
        .expect("failed to run CI=true lpm install");

    assert!(
        !output.status.success(),
        "CI=true lpm install must auto-enable frozen mode when lpm.lock exists"
    );
    assert_eq!(
        project.read_file("lpm.lock"),
        before,
        "CI auto-frozen install must not rewrite lpm.lock on mismatch"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Frozen lockfile mismatch") && stderr.contains("--no-frozen-lockfile"),
        "stderr must explain CI frozen mode and the escape hatch, got:\n{stderr}"
    );
}

#[tokio::test]
async fn ci_auto_frozen_repeat_install_uses_up_to_date_fast_path() {
    let mock = MockRegistry::start().await;
    mount_ms(&mock).await;

    let project = TempProject::empty(
        r#"{
            "name": "ci-auto-frozen-fast-path",
            "version": "1.0.0",
            "dependencies": { "ms": "^2.1.3" }
        }"#,
    );
    install_once(&project, &mock).await;

    let output = lpm_with_registry(&project, &mock.url())
        .env("CI", "true")
        .args([
            "install",
            "--json",
            "--timing",
            "--no-security-summary",
            "--no-skills",
        ])
        .output()
        .expect("failed to run repeated CI=true lpm install");

    assert!(
        output.status.success(),
        "matching CI auto-frozen install must fast-exit successfully:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let json = assertions::parse_json_output(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        json["success"],
        serde_json::json!(true),
        "{json:#}\n{stderr}"
    );
    assert_eq!(
        json["up_to_date"],
        serde_json::json!(true),
        "{json:#}\n{stderr}"
    );
    assert_eq!(
        json["timing"]["resolve_ms"],
        serde_json::json!(0),
        "{json:#}\n{stderr}"
    );
    assert_eq!(
        json["timing"]["fetch_ms"],
        serde_json::json!(0),
        "{json:#}\n{stderr}"
    );
    assert_eq!(
        json["timing"]["link_ms"],
        serde_json::json!(0),
        "{json:#}\n{stderr}"
    );
}

#[tokio::test]
async fn frozen_replay_accepts_unchanged_peer_dependency_rules_across_processes() {
    let mock = MockRegistry::start().await;
    mount_ms(&mock).await;

    let project = TempProject::empty(
        r#"{
            "name": "frozen-peer-rules",
            "version": "1.0.0",
            "dependencies": { "ms": "^2.1.3" },
            "lpm": {
                "peerDependencyRules": {
                    "allowedVersions": {
                        "consumer-a>peer-a": "^1.0.0",
                        "consumer-b>peer-b": "^2.0.0",
                        "consumer-c>peer-c": "^3.0.0",
                        "consumer-d>peer-d": "^4.0.0",
                        "consumer-e>peer-e": "^5.0.0",
                        "consumer-f>peer-f": "^6.0.0",
                        "consumer-g>peer-g": "^7.0.0",
                        "consumer-h>peer-h": "^8.0.0"
                    }
                }
            }
        }"#,
    );
    install_once(&project, &mock).await;

    let output = lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "--frozen-lockfile",
            "--no-security-summary",
            "--no-skills",
        ])
        .output()
        .expect("failed to run frozen replay with unchanged peer rules");

    assert!(
        output.status.success(),
        "unchanged peer rules must have a process-stable lockfile fingerprint:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[tokio::test]
async fn lpm_ci_replays_frozen_lockfile_without_rewriting_lockfiles() {
    let mock = MockRegistry::start().await;
    mount_ms(&mock).await;

    let project = TempProject::empty(
        r#"{
            "name": "ci-frozen-success",
            "version": "1.0.0",
            "dependencies": { "ms": "^2.1.3" }
        }"#,
    );
    install_once(&project, &mock).await;
    let lock_before = project.read_file("lpm.lock");
    let lockb_before = std::fs::read(project.path().join("lpm.lockb")).ok();

    let output = lpm_with_registry(&project, &mock.url())
        .args(["ci", "--no-skills", "--no-security-summary"])
        .output()
        .expect("failed to run lpm ci");

    assert!(
        output.status.success(),
        "lpm ci must replay a matching frozen lockfile:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        project.read_file("lpm.lock"),
        lock_before,
        "lpm ci must not rewrite lpm.lock"
    );
    assert_eq!(
        std::fs::read(project.path().join("lpm.lockb")).ok(),
        lockb_before,
        "lpm ci must not rewrite lpm.lockb"
    );
}

#[tokio::test]
async fn lpm_ci_json_reports_success_envelope_without_rewriting_lockfile() {
    let mock = MockRegistry::start().await;
    mount_ms(&mock).await;

    let project = TempProject::empty(
        r#"{
            "name": "ci-frozen-json",
            "version": "1.0.0",
            "dependencies": { "ms": "^2.1.3" }
        }"#,
    );
    install_once(&project, &mock).await;
    let lock_before = project.read_file("lpm.lock");

    let output = lpm_with_registry(&project, &mock.url())
        .args(["--json", "ci", "--no-skills", "--no-security-summary"])
        .output()
        .expect("failed to run lpm --json ci");

    assert!(
        output.status.success(),
        "lpm --json ci must replay a matching frozen lockfile:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        project.read_file("lpm.lock"),
        lock_before,
        "lpm --json ci must not rewrite lpm.lock"
    );

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let envelope: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("lpm --json ci must emit valid JSON: {e}\n---\n{stdout}"));
    assert_eq!(envelope["schema_version"], serde_json::json!(2));
    assert_eq!(envelope["success"], serde_json::json!(true));
    assert!(
        envelope.get("timing").is_none(),
        "lpm --json ci success envelope must omit opt-in timing by default, got: {envelope}"
    );
}

#[test]
fn lpm_ci_accepts_workspace_member_trusted_dependencies_without_rewriting_lockfiles() {
    let project = TempProject::empty(
        r#"{
  "name": "workspace-frozen-trust-root",
  "version": "1.0.0",
  "private": true,
  "workspaces": ["packages/*"],
  "dependencies": { "foo": "workspace:*" }
}"#,
    );
    project.write_file(
        "packages/foo/package.json",
        r#"{
  "name": "foo",
  "version": "1.0.0",
  "lpm": {
    "trustedDependencies": ["esbuild"]
  }
}"#,
    );
    support::write_signed_unlock_for(
        &project,
        &project.path().join("packages/foo"),
        &["trust-bulk-approve"],
    );

    install_workspace_once(&project);
    let lock_before = project.read_file("lpm.lock");
    let lockb_before = std::fs::read(project.path().join("lpm.lockb")).ok();

    let output = lpm(&project)
        .args(["ci", "--no-skills", "--no-security-summary"])
        .output()
        .expect("failed to run lpm ci for workspace trust regression");

    assert!(
        output.status.success(),
        "lpm ci must accept member-level trust config after a clean install:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        project.read_file("lpm.lock"),
        lock_before,
        "workspace trust-only frozen replay must not rewrite lpm.lock"
    );
    assert_eq!(
        std::fs::read(project.path().join("lpm.lockb")).ok(),
        lockb_before,
        "workspace trust-only frozen replay must not rewrite lpm.lockb"
    );
}

#[test]
fn lpm_ci_rejects_workspace_member_dependency_edge_absent_from_lockfile() {
    let project = TempProject::empty(
        r#"{
  "name": "workspace-frozen-member-drift-root",
  "version": "1.0.0",
  "private": true,
  "workspaces": ["packages/*"],
  "dependencies": { "foo": "workspace:*" }
}"#,
    );
    project.write_file(
        "packages/foo/package.json",
        r#"{ "name": "foo", "version": "1.0.0" }"#,
    );
    project.write_file(
        "packages/bar/package.json",
        r#"{ "name": "bar", "version": "1.0.0" }"#,
    );

    install_workspace_once(&project);
    assert!(
        project.path().join("node_modules/foo").exists(),
        "initial install must link the direct workspace dependency"
    );
    assert!(
        !project.path().join("node_modules/bar").exists(),
        "bar is not reachable before foo declares it"
    );
    let lock_before = project.read_file("lpm.lock");

    project.write_file(
        "packages/foo/package.json",
        r#"{
  "name": "foo",
  "version": "1.0.0",
  "dependencies": { "bar": "workspace:*" }
}"#,
    );
    std::fs::remove_dir_all(project.path().join("node_modules"))
        .expect("remove node_modules before frozen replay");

    let output = lpm(&project)
        .args(["ci", "--no-skills", "--no-security-summary"])
        .output()
        .expect("failed to run lpm ci after member manifest edit");

    assert!(
        !output.status.success(),
        "lpm ci must reject a workspace dependency edge absent from the committed lockfile:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("Frozen lockfile mismatch"),
        "lpm ci must explain that the workspace dependency graph drifted:\n{}",
        String::from_utf8_lossy(&output.stderr),
    );
    assert!(
        !project.path().join("node_modules/bar").exists(),
        "frozen replay must not invent a workspace edge absent from the lockfile"
    );
    assert_eq!(
        project.read_file("lpm.lock"),
        lock_before,
        "rejected frozen replay must not rewrite lpm.lock"
    );

    install_workspace_once(&project);
    assert!(
        project.path().join("node_modules/bar").exists(),
        "a mutable install must reconcile the changed workspace dependency graph"
    );
    assert_ne!(
        project.read_file("lpm.lock"),
        lock_before,
        "a mutable install must record the new workspace dependency edge"
    );
}

#[test]
fn ci_default_auto_frozen_workspace_install_preserves_lockfile_and_rejects_removed_importer() {
    let project = TempProject::empty(
        r#"{
  "name": "workspace-ci-auto-frozen-root",
  "version": "1.0.0",
  "private": true,
  "workspaces": ["packages/*"]
}"#,
    );
    project.write_file(
        "packages/foo/package.json",
        r#"{ "name": "foo", "version": "1.0.0" }"#,
    );
    project.write_file(
        "packages/removed/package.json",
        r#"{ "name": "removed", "version": "1.0.0" }"#,
    );

    install_workspace_once(&project);
    let lock_before = project.read_file("lpm.lock");
    std::fs::remove_dir_all(project.path().join("packages/removed"))
        .expect("remove workspace member directory");

    let output = lpm(&project)
        .env("CI", "true")
        .args(["install", "--no-skills", "--no-security-summary"])
        .output()
        .expect("failed to run CI-default lpm install");

    assert!(
        !output.status.success(),
        "CI=true default install must refuse a workspace lockfile with a removed importer:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        project.read_file("lpm.lock"),
        lock_before,
        "CI=true auto-frozen install must preserve lpm.lock byte-for-byte"
    );
}

#[test]
fn filtered_frozen_workspace_install_rejects_removed_importer_before_running_member_hooks() {
    let project = TempProject::empty(
        r#"{
  "name": "workspace-filtered-frozen-preflight-root",
  "version": "1.0.0",
  "private": true,
  "workspaces": ["packages/*"]
}"#,
    );
    let marker = project.path().join("hook-ran.marker");
    project.write_file(
        "packages/foo/package.json",
        &serde_json::json!({
            "name": "foo",
            "version": "1.0.0",
            "scripts": {
                "postinstall": "node -e \"require('fs').writeFileSync('../../hook-ran.marker', 'ran')\""
            }
        })
        .to_string(),
    );
    project.write_file(
        "packages/removed/package.json",
        r#"{ "name": "removed", "version": "1.0.0" }"#,
    );

    install_workspace_once(&project);
    let _ = std::fs::remove_file(&marker);
    let lock_before = project.read_file("lpm.lock");
    std::fs::remove_dir_all(project.path().join("packages/removed"))
        .expect("remove workspace member directory");

    let output = lpm(&project)
        .args([
            "install",
            "--frozen-lockfile",
            "--filter",
            "foo",
            "--no-skills",
            "--no-security-summary",
        ])
        .output()
        .expect("failed to run filtered frozen workspace install");

    assert!(
        !output.status.success(),
        "filtered frozen install must fail on a removed workspace importer:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !marker.exists(),
        "filtered frozen preflight must reject before running selected member lifecycle hooks"
    );
    assert_eq!(
        project.read_file("lpm.lock"),
        lock_before,
        "rejected filtered frozen install must preserve lpm.lock byte-for-byte"
    );
}

#[test]
fn ci_default_install_succeeds_in_fresh_workspace_without_any_lockfile() {
    let project = TempProject::empty(
        r#"{
  "name": "workspace-ci-fresh-no-lock-root",
  "version": "1.0.0",
  "private": true,
  "workspaces": ["packages/*"]
}"#,
    );
    project.write_file(
        "packages/foo/package.json",
        r#"{ "name": "foo", "version": "1.0.0" }"#,
    );

    let output = lpm(&project)
        .env("CI", "true")
        .args(["install", "--no-skills", "--no-security-summary"])
        .output()
        .expect("failed to run CI-default lpm install on fresh workspace");

    assert!(
        output.status.success(),
        "CI=true default install must succeed in a fresh workspace with no lockfile:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        project.path().join("lpm.lock").is_file(),
        "fresh workspace install under CI=true should create lpm.lock"
    );
}

#[test]
fn ci_default_filtered_workspace_install_rejects_before_running_deferred_root_and_new_member_hooks()
{
    let project = TempProject::empty(
        &serde_json::json!({
            "name": "workspace-ci-filtered-hooks-root",
            "version": "1.0.0",
            "private": true,
            "workspaces": ["packages/*"],
            "scripts": {
                "postinstall": "node -e \"require('fs').writeFileSync('root-hook.marker', 'ran')\""
            }
        })
        .to_string(),
    );
    project.write_file(
        "packages/foo/package.json",
        r#"{ "name": "foo", "version": "1.0.0" }"#,
    );
    project.write_file(
        "packages/removed/package.json",
        r#"{ "name": "removed", "version": "1.0.0" }"#,
    );

    install_workspace_once(&project);
    let root_marker = project.path().join("root-hook.marker");
    let _ = std::fs::remove_file(&root_marker);

    // Case 1: adding a brand-new unlocked member `newpkg` + unfiltered CI=true install
    // must reject before running the deferred root postinstall hook.
    let new_marker = project.path().join("new-hook.marker");
    project.write_file(
        "packages/newpkg/package.json",
        &serde_json::json!({
            "name": "newpkg",
            "version": "1.0.0",
            "scripts": {
                "postinstall": "node -e \"require('fs').writeFileSync('../../new-hook.marker', 'ran')\""
            }
        })
        .to_string(),
    );
    let root_output = lpm(&project)
        .env("CI", "true")
        .args(["install", "--no-skills", "--no-security-summary"])
        .output()
        .expect("failed to run CI-default workspace install with new member");
    assert!(
        !root_output.status.success(),
        "CI=true install must fail on newly added unlocked importer:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&root_output.stdout),
        String::from_utf8_lossy(&root_output.stderr)
    );
    assert!(
        !root_marker.exists(),
        "CI=true install must not run deferred root postinstall hook before frozen rejection"
    );
    assert!(
        !new_marker.exists(),
        "CI=true install must not run postinstall hook of a newly added unlocked member"
    );

    // Case 2: filtered CI=true --filter newpkg must also reject before running `newpkg`'s hook.
    let new_output = lpm(&project)
        .env("CI", "true")
        .args([
            "install",
            "--filter",
            "newpkg",
            "--no-skills",
            "--no-security-summary",
        ])
        .output()
        .expect("failed to run CI-default filtered new-member install");
    assert!(
        !new_output.status.success(),
        "CI=true filtered install must reject a new unlocked importer:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&new_output.stdout),
        String::from_utf8_lossy(&new_output.stderr)
    );
    assert!(
        !new_marker.exists(),
        "CI=true filtered install must not run postinstall hook of a newly added unlocked member"
    );
}

#[test]
fn frozen_workspace_preflight_rejects_missing_importer_before_running_locked_sibling_hooks() {
    let project = TempProject::empty(
        r#"{
            "name": "workspace-frozen-sibling-preflight",
            "version": "1.0.0",
            "private": true,
            "workspaces": ["packages/*"]
        }"#,
    );
    project.write_file(
        "packages/aaa-locked/package.json",
        &serde_json::json!({
            "name": "aaa-locked",
            "version": "1.0.0",
            "scripts": {
                "postinstall": "node -e \"require('fs').writeFileSync('../../locked-sibling.marker', 'ran')\""
            }
        })
        .to_string(),
    );

    install_workspace_once(&project);
    let sibling_marker = project.path().join("locked-sibling.marker");
    let _ = std::fs::remove_file(&sibling_marker);
    // Remove node_modules so `aaa-locked` is not skipped as already up-to-date.
    let _ = std::fs::remove_dir_all(project.path().join("packages/aaa-locked/node_modules"));
    let _ = std::fs::remove_dir_all(project.path().join("packages/aaa-locked/.lpm"));

    // Add a second member scheduled after `aaa-locked` that is missing from `lpm.lock`.
    project.write_file(
        "packages/zzz-unlocked/package.json",
        r#"{ "name": "zzz-unlocked", "version": "1.0.0" }"#,
    );

    let output = lpm(&project)
        .args([
            "install",
            "--frozen-lockfile",
            "--no-skills",
            "--no-security-summary",
        ])
        .output()
        .expect("failed to run frozen workspace install");

    assert!(
        !output.status.success(),
        "frozen workspace install must fail when a selected member is missing from lpm.lock:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !sibling_marker.exists(),
        "frozen preflight must reject before running hooks on an already-locked sibling member"
    );
}

#[test]
fn frozen_workspace_preflight_rejects_drifted_member_before_running_root_dev_preinstall() {
    let project = TempProject::empty(
        r#"{
            "name": "workspace-frozen-drift-preflight",
            "version": "1.0.0",
            "private": true,
            "workspaces": ["packages/*"],
            "scripts": {
                "pnpm:devPreinstall": "node -e \"require('fs').writeFileSync('root-dev-preinstall.marker', 'ran')\""
            }
        }"#,
    );
    project.write_file(
        "packages/aaa-hooked/package.json",
        &serde_json::json!({
            "name": "aaa-hooked",
            "version": "1.0.0",
            "scripts": {
                "pnpm:devPreinstall": "node -e \"require('fs').writeFileSync('../../sibling-dev-preinstall.marker', 'ran')\"",
                "postinstall": "node -e \"require('fs').writeFileSync('../../sibling-postinstall.marker', 'ran')\""
            }
        })
        .to_string(),
    );
    project.write_file(
        "packages/zzz-drifted/package.json",
        r#"{ "name": "zzz-drifted", "version": "1.0.0" }"#,
    );

    install_workspace_once(&project);
    let root_marker = project.path().join("root-dev-preinstall.marker");
    let sibling_pre_marker = project.path().join("sibling-dev-preinstall.marker");
    let sibling_post_marker = project.path().join("sibling-postinstall.marker");
    for marker in [&root_marker, &sibling_pre_marker, &sibling_post_marker] {
        let _ = std::fs::remove_file(marker);
    }
    let _ = std::fs::remove_dir_all(project.path().join("packages/aaa-hooked/node_modules"));
    let _ = std::fs::remove_dir_all(project.path().join("packages/aaa-hooked/.lpm"));

    // Mutate zzz-drifted's declared dependency so its locked importer is stale.
    project.write_file(
        "packages/zzz-drifted/package.json",
        r#"{ "name": "zzz-drifted", "version": "1.0.0", "dependencies": { "left-pad": "^1.3.0" } }"#,
    );

    let output = lpm(&project)
        .args([
            "install",
            "--frozen-lockfile",
            "--no-skills",
            "--no-security-summary",
        ])
        .output()
        .expect("failed to run frozen workspace install");

    assert!(
        !output.status.success(),
        "frozen workspace install must fail when a member's declared dependencies drifted:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !root_marker.exists(),
        "frozen preflight must reject manifest drift before running root pnpm:devPreinstall"
    );
    assert!(
        !sibling_pre_marker.exists(),
        "frozen preflight must reject manifest drift before running sibling pnpm:devPreinstall"
    );
    assert!(
        !sibling_post_marker.exists(),
        "frozen preflight must reject manifest drift before running sibling postinstall"
    );
}
