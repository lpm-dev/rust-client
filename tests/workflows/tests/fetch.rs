//! Workflow tests for lockfile-only `lpm fetch`.

mod support;

use support::mock_registry::{MockRegistry, compute_integrity, make_tarball};
use support::{TempProject, lpm_with_registry};

const PACKAGE_JSON: &str = r#"{
  "name": "fetch-app",
  "version": "1.0.0",
  "dependencies": { "ms": "^2.1.3" }
}"#;

async fn mount_ms(mock: &MockRegistry) {
    let tarball = make_tarball("ms", "2.1.3");
    mock.with_package("ms", "2.1.3", &tarball).await;
}

async fn seed_lockfile(mock: &MockRegistry) -> String {
    let project = TempProject::empty(PACKAGE_JSON);
    let output = lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("failed to run seed install");

    assert!(
        output.status.success(),
        "seed install failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    project.read_file("lpm.lock")
}

fn project_with_lockfile(lockfile: &str) -> TempProject {
    let project = TempProject::empty(PACKAGE_JSON);
    std::fs::remove_file(project.path().join("package.json")).expect("remove package.json");
    project.write_file("lpm.lock", lockfile);
    project
}

fn package_store_dir(project: &TempProject, name: &str, version: &str) -> std::path::PathBuf {
    project
        .store_dir()
        .join("v1")
        .join(format!("{name}@{version}"))
}

async fn tarball_request_count(mock: &MockRegistry, name: &str, version: &str) -> usize {
    let path = MockRegistry::tarball_path(name, version);
    mock.server()
        .received_requests()
        .await
        .expect("request log must be available")
        .into_iter()
        .filter(|request| request.url.path() == path)
        .count()
}

#[tokio::test]
async fn fetch_reads_lockfile_without_manifest_and_enables_offline_frozen_install() {
    let mock = MockRegistry::start().await;
    mount_ms(&mock).await;
    let lockfile = seed_lockfile(&mock).await;
    let project = project_with_lockfile(&lockfile);

    let output = lpm_with_registry(&project, &mock.url())
        .args(["fetch"])
        .output()
        .expect("failed to run lpm fetch");

    assert!(
        output.status.success(),
        "lpm fetch failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !project.file_exists("package.json"),
        "lpm fetch must not require or recreate package.json"
    );
    assert!(
        !project.file_exists("node_modules"),
        "lpm fetch must not link node_modules"
    );
    assert_eq!(
        project.read_file("lpm.lock"),
        lockfile,
        "lpm fetch must not rewrite lpm.lock"
    );
    assert!(
        package_store_dir(&project, "ms", "2.1.3")
            .join("package.json")
            .is_file(),
        "lpm fetch must populate the package store"
    );

    project.write_file("package.json", PACKAGE_JSON);
    let offline = lpm_with_registry(&project, "http://127.0.0.1:1")
        .args([
            "install",
            "--offline",
            "--frozen-lockfile",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("failed to run offline frozen install");

    assert!(
        offline.status.success(),
        "offline frozen install should consume fetch-warmed store:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&offline.stdout),
        String::from_utf8_lossy(&offline.stderr)
    );
}

#[tokio::test]
async fn fetch_uses_store_cache_without_downloading_again() {
    let mock = MockRegistry::start().await;
    mount_ms(&mock).await;
    let lockfile = seed_lockfile(&mock).await;
    let project = project_with_lockfile(&lockfile);

    let first = lpm_with_registry(&project, &mock.url())
        .args(["fetch"])
        .output()
        .expect("failed to run first lpm fetch");
    assert!(
        first.status.success(),
        "first fetch failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&first.stdout),
        String::from_utf8_lossy(&first.stderr)
    );
    let after_first = tarball_request_count(&mock, "ms", "2.1.3").await;

    let second = lpm_with_registry(&project, &mock.url())
        .args(["fetch"])
        .output()
        .expect("failed to run cached lpm fetch");
    assert!(
        second.status.success(),
        "cached fetch failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&second.stdout),
        String::from_utf8_lossy(&second.stderr)
    );
    let after_second = tarball_request_count(&mock, "ms", "2.1.3").await;

    assert_eq!(
        after_second, after_first,
        "cached lpm fetch must not issue another tarball request"
    );
}

#[tokio::test]
async fn fetch_hard_errors_when_locked_integrity_is_missing() {
    let mock = MockRegistry::start().await;
    mount_ms(&mock).await;
    let lockfile = seed_lockfile(&mock).await;
    let project = project_with_lockfile(&lockfile);

    let lockfile_path = project.path().join("lpm.lock");
    let mut parsed =
        lpm_lockfile::Lockfile::read_from_file(&lockfile_path).expect("lockfile parses");
    parsed.packages[0].integrity = None;
    parsed
        .write_to_file(&lockfile_path)
        .expect("write lockfile without integrity");

    let output = lpm_with_registry(&project, &mock.url())
        .args(["fetch"])
        .output()
        .expect("failed to run lpm fetch");

    assert!(
        !output.status.success(),
        "fetch must reject remote packages without integrity"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("missing integrity"),
        "error must name missing integrity, got:\n{stderr}"
    );
    assert!(
        !package_store_dir(&project, "ms", "2.1.3").exists(),
        "failed fetch must not populate the store"
    );
}

#[tokio::test]
async fn fetch_rejects_integrity_mismatch_before_storing_bytes() {
    let mock = MockRegistry::start().await;
    mount_ms(&mock).await;
    let lockfile = seed_lockfile(&mock).await;
    let project = project_with_lockfile(&lockfile);

    let lockfile_path = project.path().join("lpm.lock");
    let mut parsed =
        lpm_lockfile::Lockfile::read_from_file(&lockfile_path).expect("lockfile parses");
    parsed.packages[0].integrity = Some(compute_integrity(b"different bytes"));
    parsed
        .write_to_file(&lockfile_path)
        .expect("write lockfile with mismatched integrity");

    let output = lpm_with_registry(&project, &mock.url())
        .args(["fetch"])
        .output()
        .expect("failed to run lpm fetch");

    assert!(
        !output.status.success(),
        "fetch must reject integrity mismatches"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.to_ascii_lowercase().contains("integrity mismatch"),
        "error must name the integrity mismatch, got:\n{stderr}"
    );
    assert!(
        !package_store_dir(&project, "ms", "2.1.3").exists(),
        "integrity mismatch must not populate the store"
    );
}

#[tokio::test]
async fn fetch_platform_option_skips_incompatible_lockfile_entries() {
    let mock = MockRegistry::start().await;
    mount_ms(&mock).await;
    let lockfile = seed_lockfile(&mock).await;
    let project = project_with_lockfile(&lockfile);

    let native_tarball = make_tarball("native-musl", "1.0.0");
    let lockfile_path = project.path().join("lpm.lock");
    let mut parsed =
        lpm_lockfile::Lockfile::read_from_file(&lockfile_path).expect("lockfile parses");
    let mut native = parsed.packages[0].clone();
    native.name = "native-musl".to_string();
    native.version = "1.0.0".to_string();
    native.integrity = Some(compute_integrity(&native_tarball));
    native.tarball = Some(mock.tarball_url("native-musl", "1.0.0"));
    native.os = vec!["linux".to_string()];
    native.cpu = vec!["x64".to_string()];
    native.libc = vec!["musl".to_string()];
    parsed.add_package(native);
    parsed
        .write_to_file(&lockfile_path)
        .expect("write lockfile with platform package");

    let output = lpm_with_registry(&project, &mock.url())
        .args(["fetch", "--platform", "darwin/arm64", "--json"])
        .output()
        .expect("failed to run lpm fetch --platform");

    assert!(
        output.status.success(),
        "platform fetch failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("fetch JSON parses");
    assert_eq!(json["counts"]["fetched"], serde_json::json!(1));
    assert_eq!(json["counts"]["skipped"], serde_json::json!(1));
    assert!(
        !package_store_dir(&project, "native-musl", "1.0.0").exists(),
        "incompatible platform package must not be fetched"
    );
}

#[tokio::test]
async fn fetch_json_envelope_reports_lockfile_counts() {
    let mock = MockRegistry::start().await;
    mount_ms(&mock).await;
    let lockfile = seed_lockfile(&mock).await;
    let project = project_with_lockfile(&lockfile);

    let output = lpm_with_registry(&project, &mock.url())
        .args(["fetch", "--platform", "linux/x64/glibc", "--json"])
        .output()
        .expect("failed to run lpm fetch --json");
    assert!(
        output.status.success(),
        "fetch --json failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let envelope: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("fetch --json must be valid JSON");
    assert_eq!(envelope["success"], serde_json::json!(true));
    assert_eq!(envelope["counts"]["fetched"], serde_json::json!(1));
    assert_eq!(envelope["packages"][0]["name"], serde_json::json!("ms"));

    insta::with_settings!({
        filters => vec![
            (r#""elapsed_ms": \d+"#, r#""elapsed_ms": "[ELAPSED]""#),
        ],
    }, {
        insta::assert_json_snapshot!("fetch_json_envelope_reports_lockfile_counts", envelope);
    });
}
