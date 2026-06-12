//! Workflow tests for frozen lockfile install semantics.

mod support;

use support::mock_registry::{MockRegistry, make_tarball};
use support::{TempProject, lpm_with_registry};

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
    assert_eq!(envelope["success"], serde_json::json!(true));
    assert!(
        envelope.get("timing").is_some(),
        "lpm --json ci success envelope must include timing, got: {envelope}"
    );
}
