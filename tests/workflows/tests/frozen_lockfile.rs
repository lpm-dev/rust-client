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
        .args([
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
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
        .args([
            "install",
            "--no-recursive",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
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
    legacy_lockfile
        .write_to_file(&lockfile_path)
        .expect("failed to write simulated legacy lockfile");

    let output = lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
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
        .args([
            "ci",
            "--no-skills",
            "--no-editor-setup",
            "--no-security-summary",
        ])
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
            "--no-editor-setup",
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
        .args([
            "ci",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
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
        .args([
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
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
            "--no-editor-setup",
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
            "--no-editor-setup",
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
        .args([
            "ci",
            "--no-skills",
            "--no-editor-setup",
            "--no-security-summary",
        ])
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
        .args([
            "--json",
            "ci",
            "--no-skills",
            "--no-editor-setup",
            "--no-security-summary",
        ])
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

    install_workspace_once(&project);
    let lock_before = project.read_file("lpm.lock");
    let lockb_before = std::fs::read(project.path().join("lpm.lockb")).ok();

    let output = lpm(&project)
        .args([
            "ci",
            "--no-skills",
            "--no-editor-setup",
            "--no-security-summary",
        ])
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
fn lpm_ci_replays_workspace_member_manifest_change_when_lockfile_can_satisfy_link() {
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
        .args([
            "ci",
            "--no-skills",
            "--no-editor-setup",
            "--no-security-summary",
        ])
        .output()
        .expect("failed to run lpm ci after member manifest edit");

    assert!(
        output.status.success(),
        "lpm ci must replay a workspace-member-only manifest edit when all links are locally satisfiable:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        project.path().join("node_modules/bar").exists(),
        "frozen replay must materialize the newly reachable workspace sibling"
    );
    assert_eq!(
        project.read_file("lpm.lock"),
        lock_before,
        "locally satisfiable workspace link replay must not rewrite lpm.lock"
    );
}
