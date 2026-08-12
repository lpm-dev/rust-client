//! Workflow tests for lockfile-only `lpm fetch`.

mod support;

use support::mock_registry::{
    MockRegistry, compute_integrity, make_tarball, make_tarball_with_files,
};
use support::{TempProject, lpm, lpm_with_registry, write_npm_firewall_global_config};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

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

fn package_object_dir(project: &TempProject, name: &str, version: &str) -> std::path::PathBuf {
    let integrity = compute_integrity(&make_tarball(name, version));
    lpm_store::v2::StoreV2Paths::at(project.store_dir().join("v2"))
        .object_dir(&integrity)
        .expect("fixture integrity must address a valid v2 object path")
}

fn rewrite_lockfile_registry_sources_to_public_npm(project: &TempProject) {
    let lockfile_path = project.path().join(lpm_lockfile::LOCKFILE_NAME);
    let mut lockfile =
        lpm_lockfile::Lockfile::read_from_file(&lockfile_path).expect("lockfile should parse");
    for package in &mut lockfile.packages {
        if package
            .source
            .as_deref()
            .is_some_and(|source| source.starts_with("registry+"))
        {
            package.source = Some(format!("registry+{}", lpm_common::NPM_REGISTRY_URL));
        }
    }
    lockfile
        .write_to_file(&lockfile_path)
        .expect("rewrite lockfile registry source");
    let _ = std::fs::remove_file(lockfile_path.with_extension("lockb"));
}

fn rewrite_lockfile_registry_source_to_legacy_public_npm_tarball(project: &TempProject) {
    let lockfile_path = project.path().join(lpm_lockfile::LOCKFILE_NAME);
    let mut lockfile =
        lpm_lockfile::Lockfile::read_from_file(&lockfile_path).expect("lockfile should parse");
    let package = lockfile
        .packages
        .iter_mut()
        .find(|package| package.name == "ms" && package.version == "2.1.3")
        .expect("seed lockfile should contain ms@2.1.3");
    package.source = None;
    package.tarball = Some(format!(
        "{}/ms/-/ms-2.1.3.tgz",
        lpm_common::NPM_REGISTRY_URL.trim_end_matches('/')
    ));
    let instance_id = package.instance_id.expect("seed instance id");
    if let Some(root) = lockfile
        .root_resolutions
        .values_mut()
        .find(|root| root.instance_id == Some(instance_id))
    {
        root.source = None;
    }
    lockfile
        .write_to_file(&lockfile_path)
        .expect("rewrite lockfile as legacy public npm tarball row");
    let _ = std::fs::remove_file(lockfile_path.with_extension("lockb"));
}

fn rewrite_lockfile_registry_source_to_canonical_public_npm_tarball(project: &TempProject) {
    let lockfile_path = project.path().join(lpm_lockfile::LOCKFILE_NAME);
    let mut lockfile =
        lpm_lockfile::Lockfile::read_from_file(&lockfile_path).expect("lockfile should parse");
    let package = lockfile
        .packages
        .iter_mut()
        .find(|package| package.name == "ms" && package.version == "2.1.3")
        .expect("seed lockfile should contain ms@2.1.3");
    package.source = Some(format!(
        "tarball+{}/ms/-/ms-2.1.3.tgz",
        lpm_common::NPM_REGISTRY_URL.trim_end_matches('/')
    ));
    package.tarball = None;
    let instance_id = package.instance_id.expect("seed instance id");
    if let Some(root) = lockfile
        .root_resolutions
        .values_mut()
        .find(|root| root.instance_id == Some(instance_id))
    {
        root.source = package.source.clone();
    }
    lockfile
        .write_to_file(&lockfile_path)
        .expect("rewrite lockfile as canonical public npm tarball row");
    let _ = std::fs::remove_file(lockfile_path.with_extension("lockb"));
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
        package_object_dir(&project, "ms", "2.1.3")
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
async fn fetch_materializes_commit_pinned_github_source_with_security_analysis() {
    const COMMIT: &str = "779219540f66cecaa159da32b3b8936697ba10a7";

    let archive = make_tarball_with_files(
        "wa-sqlite",
        "1.0.9",
        &[("index.js", b"module.exports = 'fetch-ok';\n")],
    );
    let integrity = compute_integrity(&archive);
    let github = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/rhashimoto/wa-sqlite/tar.gz/{COMMIT}")))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(archive))
        .expect(1)
        .mount(&github)
        .await;

    let mut lockfile = lpm_lockfile::Lockfile::new_with_resolver("greedy-fusion");
    lockfile.add_package(lpm_lockfile::LockedPackage {
        instance_id: Some(lpm_common::PackageInstanceId::derive(
            "wa-sqlite",
            "1.0.9",
            &format!("git+https://github.com/rhashimoto/wa-sqlite.git#{COMMIT}"),
            "fixture/fetch-github",
        )),
        dependency_targets: std::collections::BTreeMap::new(),
        peer_targets: std::collections::BTreeMap::new(),
        name: "wa-sqlite".to_string(),
        version: "1.0.9".to_string(),
        source: Some(format!(
            "git+https://github.com/rhashimoto/wa-sqlite.git#{COMMIT}"
        )),
        integrity: Some(integrity.clone()),
        ..Default::default()
    });
    support::finalize_exact_lockfile_fixture(&mut lockfile, &[("wa-sqlite", "wa-sqlite", "1.0.9")]);
    let project = TempProject::empty(r#"{"name":"fetch-github-fixture","version":"1.0.0"}"#);
    std::fs::remove_file(project.path().join("package.json")).expect("remove package manifest");
    project.write_file(
        "lpm.lock",
        &lockfile
            .to_toml()
            .expect("serialize GitHub lockfile fixture"),
    );

    let output = lpm(&project)
        .env("LPM_GITHUB_CODELOAD_BASE_URL", github.uri())
        .args(["fetch"])
        .output()
        .expect("run lpm fetch for GitHub source");

    assert!(
        output.status.success(),
        "GitHub fetch must succeed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let object_dir = lpm_store::v2::StoreV2Paths::at(project.store_dir().join("v2"))
        .object_dir(&integrity)
        .expect("GitHub archive integrity should address the v2 object");
    assert!(object_dir.join("package.json").is_file());
    assert!(object_dir.join(".lpm-security.json").is_file());
}

#[tokio::test]
async fn fetch_rejects_github_archive_that_does_not_match_lockfile_integrity() {
    const COMMIT: &str = "779219540f66cecaa159da32b3b8936697ba10a7";

    let archive = make_tarball("wa-sqlite", "1.0.9");
    let archive_integrity = compute_integrity(&archive);
    let github = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/rhashimoto/wa-sqlite/tar.gz/{COMMIT}")))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(archive))
        .expect(1)
        .mount(&github)
        .await;

    let mut lockfile = lpm_lockfile::Lockfile::new_with_resolver("greedy-fusion");
    lockfile.add_package(lpm_lockfile::LockedPackage {
        instance_id: Some(lpm_common::PackageInstanceId::derive(
            "wa-sqlite",
            "1.0.9",
            &format!("git+https://github.com/rhashimoto/wa-sqlite.git#{COMMIT}"),
            "fixture/fetch-github-mismatch",
        )),
        dependency_targets: std::collections::BTreeMap::new(),
        peer_targets: std::collections::BTreeMap::new(),
        name: "wa-sqlite".to_string(),
        version: "1.0.9".to_string(),
        source: Some(format!(
            "git+https://github.com/rhashimoto/wa-sqlite.git#{COMMIT}"
        )),
        integrity: Some(compute_integrity(b"different archive bytes")),
        ..Default::default()
    });
    support::finalize_exact_lockfile_fixture(&mut lockfile, &[("wa-sqlite", "wa-sqlite", "1.0.9")]);
    let project = TempProject::empty(r#"{"name":"fetch-github-mismatch","version":"1.0.0"}"#);
    std::fs::remove_file(project.path().join("package.json")).expect("remove package manifest");
    project.write_file(
        "lpm.lock",
        &lockfile
            .to_toml()
            .expect("serialize mismatched GitHub lockfile fixture"),
    );

    let output = lpm(&project)
        .env("LPM_GITHUB_CODELOAD_BASE_URL", github.uri())
        .args(["fetch"])
        .output()
        .expect("run lpm fetch with mismatched GitHub integrity");

    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .to_ascii_lowercase()
            .contains("integrity"),
        "GitHub integrity rejection must identify the mismatch; stderr: {}",
        String::from_utf8_lossy(&output.stderr),
    );
    let object_dir = lpm_store::v2::StoreV2Paths::at(project.store_dir().join("v2"))
        .object_dir(&archive_integrity)
        .expect("actual GitHub archive integrity should address a potential v2 object");
    assert!(!object_dir.exists());
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
async fn fetch_firewall_enforce_blocks_public_npm_lockfile_package_before_tarball_fetch() {
    let mock = MockRegistry::start().await;
    mount_ms(&mock).await;
    let lockfile = seed_lockfile(&mock).await;
    let project = project_with_lockfile(&lockfile);
    rewrite_lockfile_registry_sources_to_public_npm(&project);
    write_npm_firewall_global_config(&project, "enforce");
    mock.with_npm_firewall_block("ms", "2.1.3").await;
    let tarball_requests_before = mock.tarball_request_count("ms", "2.1.3").await;

    let output = lpm_with_registry(&project, &mock.url())
        .args(["fetch"])
        .output()
        .expect("failed to run lpm fetch with firewall enforce");

    assert!(
        !output.status.success(),
        "firewall enforce must block fetch:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("Fetching 1 package(s) from lpm.lock - 🔥 LPM Firewall active"),
        "firewall-active fetch must show the badge; got:\n{combined}"
    );
    assert!(
        combined.contains("blocked by LPM npm firewall"),
        "error must name the firewall block; got:\n{combined}"
    );
    assert_eq!(
        mock.tarball_request_count("ms", "2.1.3").await,
        tarball_requests_before,
        "firewall block must happen before fetch downloads tarballs"
    );
    assert!(
        !package_object_dir(&project, "ms", "2.1.3").exists(),
        "blocked fetch must not populate the package store"
    );
}

#[tokio::test]
async fn fetch_firewall_enforce_blocks_legacy_public_npm_tarball_before_download() {
    let mock = MockRegistry::start().await;
    mount_ms(&mock).await;
    let lockfile = seed_lockfile(&mock).await;
    let project = project_with_lockfile(&lockfile);
    rewrite_lockfile_registry_source_to_legacy_public_npm_tarball(&project);
    write_npm_firewall_global_config(&project, "enforce");
    mock.with_npm_firewall_block("ms", "2.1.3").await;

    let output = lpm_with_registry(&project, &mock.url())
        .args(["fetch"])
        .output()
        .expect("failed to run lpm fetch with legacy public npm tarball");

    assert!(
        !output.status.success(),
        "firewall enforce must block legacy fetch:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("blocked by LPM npm firewall"),
        "error must name the firewall block; got:\n{combined}"
    );
    assert!(
        !package_object_dir(&project, "ms", "2.1.3").exists(),
        "blocked legacy fetch must not populate the package store"
    );
}

#[tokio::test]
async fn fetch_firewall_enforce_blocks_canonical_public_npm_tarball_before_download() {
    let mock = MockRegistry::start().await;
    mount_ms(&mock).await;
    let lockfile = seed_lockfile(&mock).await;
    let project = project_with_lockfile(&lockfile);
    rewrite_lockfile_registry_source_to_canonical_public_npm_tarball(&project);
    write_npm_firewall_global_config(&project, "enforce");
    mock.with_npm_firewall_block("ms", "2.1.3").await;

    let output = lpm_with_registry(&project, &mock.url())
        .args(["fetch"])
        .output()
        .expect("failed to run lpm fetch with canonical public npm tarball");

    assert!(
        !output.status.success(),
        "firewall enforce must block canonical npm tarball fetch:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("blocked by LPM npm firewall"),
        "error must name the firewall block; got:\n{combined}"
    );
    assert!(
        !package_object_dir(&project, "ms", "2.1.3").exists(),
        "blocked canonical npm tarball fetch must not populate the package store"
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
        !package_object_dir(&project, "ms", "2.1.3").exists(),
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
        !package_object_dir(&project, "ms", "2.1.3").exists(),
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
    native.instance_id = Some(lpm_common::PackageInstanceId::derive(
        &native.name,
        &native.version,
        native.source.as_deref().expect("registry source"),
        "fixture/native-musl",
    ));
    native.integrity = Some(compute_integrity(&native_tarball));
    native.tarball = Some(mock.tarball_url("native-musl", "1.0.0"));
    native.os = vec!["linux".to_string()];
    native.cpu = vec!["x64".to_string()];
    native.libc = vec!["musl".to_string()];
    parsed.add_package(native);
    for package in &mut parsed.packages {
        package.instance_id = None;
        package.dependency_targets.clear();
        package.peer_targets.clear();
    }
    for root in parsed.root_resolutions.values_mut() {
        root.instance_id = None;
    }
    parsed.metadata.lockfile_version = 12;
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
        !package_object_dir(&project, "native-musl", "1.0.0").exists(),
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

#[tokio::test]
async fn fetch_downloads_shared_contextual_artifact_once_and_reports_each_instance() {
    let mock = MockRegistry::start().await;
    let tarball = make_tarball("shared-artifact", "1.0.0");
    mock.with_package("shared-artifact", "1.0.0", &tarball)
        .await;
    let integrity = compute_integrity(&tarball);
    let source = format!("registry+{}", mock.url());
    let tarball_url = mock.tarball_url("shared-artifact", "1.0.0");
    let first_id = lpm_common::PackageInstanceId::derive(
        "shared-artifact",
        "1.0.0",
        &source,
        "root/first/shared-artifact",
    );
    let second_id = lpm_common::PackageInstanceId::derive(
        "shared-artifact",
        "1.0.0",
        &source,
        "root/second/shared-artifact",
    );
    let mut lockfile = lpm_lockfile::Lockfile::new();
    for instance_id in [first_id, second_id] {
        lockfile.add_package(lpm_lockfile::LockedPackage {
            instance_id: Some(instance_id),
            name: "shared-artifact".to_string(),
            version: "1.0.0".to_string(),
            source: Some(source.clone()),
            integrity: Some(integrity.clone()),
            tarball: Some(tarball_url.clone()),
            ..Default::default()
        });
    }
    for (local_name, instance_id) in [("first", first_id), ("second", second_id)] {
        lockfile.root_resolutions.insert(
            local_name.to_string(),
            lpm_lockfile::LockedRootResolution {
                instance_id: Some(instance_id),
                package: "shared-artifact".to_string(),
                version: "1.0.0".to_string(),
                source: Some(source.clone()),
            },
        );
    }
    let project = TempProject::empty(r#"{"name":"fetch-shared","version":"1.0.0"}"#);
    std::fs::remove_file(project.path().join("package.json")).expect("remove package manifest");
    project.write_file(
        "lpm.lock",
        &lockfile.to_toml().expect("serialize exact lockfile"),
    );

    let output = lpm_with_registry(&project, &mock.url())
        .args(["fetch", "--json"])
        .output()
        .expect("run lpm fetch");

    assert!(
        output.status.success(),
        "fetch failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        mock.tarball_request_count("shared-artifact", "1.0.0").await,
        1,
        "contextual rows for one artifact must share one download"
    );
    let envelope: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("fetch JSON parses");
    assert_eq!(envelope["counts"]["total"], serde_json::json!(2));
    assert_eq!(envelope["counts"]["fetched"], serde_json::json!(2));
    assert_eq!(
        envelope["packages"].as_array().map(Vec::len),
        Some(2),
        "reporting remains per lockfile instance"
    );
}
