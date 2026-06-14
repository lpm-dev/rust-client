//! Workflow tests for deterministic registry fault handling.

mod support;

use std::path::PathBuf;

use support::fault_registry::{
    FaultRegistry, MetadataReply, TarballReply, integrity_for, missing_tarball_reply,
};
use support::mock_registry::make_tarball;
use support::{TempProject, lpm_spawnable_with_registry, lpm_with_registry};

const INSTALL_ARGS: &[&str] = &[
    "install",
    "--no-security-summary",
    "--no-skills",
    "--no-editor-setup",
];

fn project_with_dep(project_name: &str, dep_name: &str, dep_spec: &str) -> TempProject {
    TempProject::empty(&format!(
        r#"{{
            "name": "{project_name}",
            "version": "1.0.0",
            "dependencies": {{
                "{dep_name}": "{dep_spec}"
            }}
        }}"#
    ))
}

fn install(project: &TempProject, registry: &FaultRegistry) -> std::process::Output {
    lpm_with_registry(project, &registry.url())
        .env("LPM_GREEDY_FUSION", "0")
        .args(INSTALL_ARGS)
        .output()
        .expect("failed to run lpm install")
}

fn install_with_store_version(
    project: &TempProject,
    registry_url: &str,
    store_version: &str,
    extra_args: &[&str],
) -> std::process::Output {
    let mut cmd = lpm_with_registry(project, registry_url);
    cmd.env("LPM_GREEDY_FUSION", "0")
        .env("LPM_STORE_VERSION", store_version)
        .args(INSTALL_ARGS)
        .args(extra_args)
        .output()
        .expect("failed to run lpm install")
}

fn package_install_path(project: &TempProject, package_name: &str) -> PathBuf {
    package_name
        .split('/')
        .fold(project.path().join("node_modules"), |path, segment| {
            path.join(segment)
        })
}

fn assert_failed_cleanly(output: &std::process::Output, project: &TempProject, package_name: &str) {
    assert!(
        !output.status.success(),
        "install must fail under the injected registry fault\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    assert!(
        !project.file_exists("lpm.lock"),
        "failed install must not leave a text lockfile"
    );
    assert!(
        !project.file_exists("lpm.lockb"),
        "failed install must not leave a binary lockfile"
    );
    assert!(
        !package_install_path(project, package_name).exists(),
        "failed install must not materialize node_modules/{package_name}"
    );
}

fn locked_package(project: &TempProject, package_name: &str) -> lpm_lockfile::LockedPackage {
    let lockfile = lpm_lockfile::Lockfile::read_from_file(&project.path().join("lpm.lock"))
        .expect("read lpm.lock");
    lockfile
        .packages
        .into_iter()
        .find(|package| package.name == package_name)
        .unwrap_or_else(|| panic!("lockfile must contain {package_name}"))
}

#[tokio::test]
async fn install_fails_without_lockfile_when_metadata_advertises_yanked_tarball() {
    let registry = FaultRegistry::start().await;
    let package_name = "fault-yanked-mid-resolution";
    let version = "1.0.0";
    let tarball = make_tarball(package_name, version);
    let metadata = registry.package_metadata(package_name, version, &tarball);
    let tarball_path = FaultRegistry::tarball_path(package_name, version);

    registry.with_batch_metadata(vec![metadata.clone()]).await;
    registry
        .with_package_metadata_reply(package_name, MetadataReply::Ok(metadata))
        .await;
    let tarball_hits = registry
        .with_tarball_reply(&tarball_path, missing_tarball_reply())
        .await;

    let project = project_with_dep("fault-yanked-mid-resolution-app", package_name, version);
    let output = install(&project, &registry);

    assert_failed_cleanly(&output, &project, package_name);
    assert!(
        tarball_hits.get() >= 1,
        "install must attempt the tarball URL that resolution selected"
    );
    let stderr = String::from_utf8_lossy(&output.stderr).to_ascii_lowercase();
    assert!(
        stderr.contains("tarball") || stderr.contains("unpublished"),
        "error should explain the missing tarball, got:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[tokio::test]
async fn install_fails_without_fetching_tarball_when_tarball_exists_without_metadata() {
    let registry = FaultRegistry::start().await;
    let package_name = "fault-tarball-only-publish";
    let version = "1.0.0";
    let tarball = make_tarball(package_name, version);
    let tarball_path = FaultRegistry::tarball_path(package_name, version);

    registry.with_batch_metadata(Vec::new()).await;
    registry
        .with_package_metadata_reply(
            package_name,
            MetadataReply::NotFound(r#"{"error":"package metadata not visible"}"#.to_string()),
        )
        .await;
    let tarball_hits = registry
        .with_tarball_reply(&tarball_path, TarballReply::Bytes(tarball))
        .await;

    let project = project_with_dep("fault-tarball-only-publish-app", package_name, version);
    let output = install(&project, &registry);

    assert_failed_cleanly(&output, &project, package_name);
    assert_eq!(
        tarball_hits.get(),
        0,
        "resolver must not fetch an unreferenced tarball when metadata is absent"
    );
}

#[tokio::test]
async fn lockfile_install_fails_cleanly_when_cached_version_tarball_is_yanked() {
    let registry = FaultRegistry::start().await;
    let package_name = "fault-lockfile-yanked";
    let version = "1.0.0";
    let tarball = make_tarball(package_name, version);
    let metadata = registry.package_metadata(package_name, version, &tarball);
    let tarball_path = FaultRegistry::tarball_path(package_name, version);

    registry.with_batch_metadata(vec![metadata.clone()]).await;
    registry
        .with_package_metadata_reply(package_name, MetadataReply::Ok(metadata))
        .await;
    registry
        .with_tarball_sequence(
            &tarball_path,
            vec![TarballReply::Bytes(tarball), missing_tarball_reply()],
        )
        .await;

    let project = project_with_dep("fault-lockfile-yanked-app", package_name, version);
    let first = install(&project, &registry);
    assert!(
        first.status.success(),
        "initial install must establish the lockfile\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&first.stdout),
        String::from_utf8_lossy(&first.stderr),
    );

    std::fs::remove_dir_all(project.path().join("node_modules"))
        .expect("remove node_modules before lockfile reinstall");
    std::fs::remove_dir_all(project.store_dir()).expect("remove store before lockfile reinstall");

    let second = install(&project, &registry);
    assert_failed_cleanly(&second, &project, package_name);
}

#[tokio::test]
async fn install_recovers_when_stale_metadata_points_to_moved_tarball_with_same_integrity() {
    let registry = FaultRegistry::start().await;
    let package_name = "fault-stale-moved-tarball";
    let version = "1.0.0";
    let tarball = make_tarball(package_name, version);
    let integrity = integrity_for(&tarball);
    let old_url = registry.tarball_url(package_name, version);
    let old_path = FaultRegistry::tarball_path(package_name, version);
    let fresh_path = format!("/tarballs/{package_name}/-/{package_name}-{version}-fresh.tgz");
    let fresh_url = format!("{}{}", registry.url(), fresh_path);
    let stale_metadata =
        registry.package_metadata_with_tarball_url(package_name, version, &old_url, &integrity);
    let fresh_metadata =
        registry.package_metadata_with_tarball_url(package_name, version, &fresh_url, &integrity);

    registry.with_batch_metadata(vec![stale_metadata]).await;
    registry
        .with_package_metadata_reply(package_name, MetadataReply::Ok(fresh_metadata))
        .await;
    registry
        .with_tarball_reply(&old_path, missing_tarball_reply())
        .await;
    registry
        .with_tarball_reply(&fresh_path, TarballReply::Bytes(tarball))
        .await;

    let project = project_with_dep("fault-stale-moved-tarball-app", package_name, "^1.0.0");
    let output = install(&project, &registry);
    assert!(
        output.status.success(),
        "install should recover from stale metadata when fresh metadata points to the same bytes\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let locked = locked_package(&project, package_name);
    assert_eq!(locked.version, version);
    assert_eq!(
        locked.tarball.as_deref(),
        Some(fresh_url.as_str()),
        "lockfile must persist the verified fresh tarball URL"
    );
}

#[tokio::test]
async fn install_rejects_tarball_bytes_that_change_after_resolution() {
    let registry = FaultRegistry::start().await;
    let package_name = "fault-toctou-tarball";
    let version = "1.0.0";
    let resolved_tarball = make_tarball(package_name, version);
    let changed_tarball = make_tarball("fault-toctou-other-bytes", version);
    let metadata = registry.package_metadata(package_name, version, &resolved_tarball);
    let tarball_path = FaultRegistry::tarball_path(package_name, version);

    registry.with_batch_metadata(vec![metadata.clone()]).await;
    registry
        .with_package_metadata_reply(package_name, MetadataReply::Ok(metadata))
        .await;
    registry
        .with_tarball_reply(&tarball_path, TarballReply::Bytes(changed_tarball))
        .await;

    let project = project_with_dep("fault-toctou-tarball-app", package_name, version);
    let output = install(&project, &registry);

    assert_failed_cleanly(&output, &project, package_name);
    let stderr = String::from_utf8_lossy(&output.stderr).to_ascii_lowercase();
    assert!(
        stderr.contains("integrity") || stderr.contains("checksum"),
        "error should explain the integrity failure, got:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[tokio::test]
async fn offline_v2_install_fails_cleanly_when_cached_object_is_corrupted() {
    let registry = FaultRegistry::start().await;
    let package_name = "fault-corrupted-cache";
    let version = "1.0.0";
    let tarball = make_tarball(package_name, version);
    let integrity = integrity_for(&tarball);
    let metadata = registry.package_metadata(package_name, version, &tarball);
    let tarball_path = FaultRegistry::tarball_path(package_name, version);

    registry.with_batch_metadata(vec![metadata.clone()]).await;
    registry
        .with_package_metadata_reply(package_name, MetadataReply::Ok(metadata))
        .await;
    registry
        .with_tarball_reply(&tarball_path, TarballReply::Bytes(tarball))
        .await;

    let project = project_with_dep("fault-corrupted-cache-app", package_name, version);
    let online = install_with_store_version(&project, &registry.url(), "v2", &[]);
    assert!(
        online.status.success(),
        "online v2 install must warm the cache\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&online.stdout),
        String::from_utf8_lossy(&online.stderr),
    );

    let v2_store = lpm_store::v2::Store::at(project.home().join(".lpm/store/v2"));
    let object_dir = v2_store
        .paths()
        .object_dir(&integrity)
        .expect("test integrity should map to a v2 object dir");
    std::fs::write(
        object_dir.join("index.js"),
        b"module.exports = 'corrupted';",
    )
    .expect("tamper cached object");
    std::fs::remove_dir_all(project.path().join("node_modules"))
        .expect("remove node_modules before offline reinstall");

    let offline = install_with_store_version(&project, "http://127.0.0.1:1", "v2", &["--offline"]);
    assert!(
        !offline.status.success(),
        "offline reinstall must fail when the only cached object is corrupted\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&offline.stdout),
        String::from_utf8_lossy(&offline.stderr),
    );
    assert!(
        project.file_exists("lpm.lock"),
        "offline cache failure may preserve the existing lockfile graph"
    );
    assert!(
        !package_install_path(&project, package_name).exists(),
        "offline cache failure must not link corrupted bytes into node_modules/{package_name}"
    );
    let stderr = String::from_utf8_lossy(&offline.stderr).to_ascii_lowercase();
    assert!(
        stderr.contains("integrity") || stderr.contains("corrupt") || stderr.contains("offline"),
        "offline cache-corruption error should be explicit, got:\n{}",
        String::from_utf8_lossy(&offline.stderr)
    );
}

#[tokio::test]
async fn concurrent_publish_allows_one_winner_for_the_same_package_version() {
    let registry = FaultRegistry::start().await;
    registry.with_whoami("testuser", "test@example.com").await;
    let publish_counter = registry.with_single_winner_publish().await;

    let package_json = r#"{
        "name": "@lpm.dev/testuser.concurrent-fault-publish",
        "version": "1.0.0",
        "description": "publish race fixture",
        "main": "index.js",
        "license": "MIT"
    }"#;
    let project_a = TempProject::empty(package_json);
    let project_b = TempProject::empty(package_json);
    project_a.write_file("index.js", "module.exports = 'a';\n");
    project_b.write_file("index.js", "module.exports = 'b';\n");

    let child_a = lpm_spawnable_with_registry(&project_a, &registry.url())
        .args(["publish", "--yes", "--token", "test-token-123", "--lpm"])
        .spawn()
        .expect("spawn first publish");
    let child_b = lpm_spawnable_with_registry(&project_b, &registry.url())
        .args(["publish", "--yes", "--token", "test-token-123", "--lpm"])
        .spawn()
        .expect("spawn second publish");

    let output_a = child_a.wait_with_output().expect("wait for first publish");
    let output_b = child_b.wait_with_output().expect("wait for second publish");
    let success_count =
        usize::from(output_a.status.success()) + usize::from(output_b.status.success());

    assert_eq!(
        success_count,
        1,
        "exactly one concurrent publish should win\nA stdout:\n{}\nA stderr:\n{}\nB stdout:\n{}\nB stderr:\n{}",
        String::from_utf8_lossy(&output_a.stdout),
        String::from_utf8_lossy(&output_a.stderr),
        String::from_utf8_lossy(&output_b.stdout),
        String::from_utf8_lossy(&output_b.stderr),
    );
    assert_eq!(
        publish_counter.get(),
        2,
        "both publish clients must reach the registry publish endpoint"
    );

    let requests = registry
        .server()
        .received_requests()
        .await
        .expect("wiremock request log must be available");
    let put_count = requests
        .iter()
        .filter(|request| request.method.as_str() == "PUT")
        .count();
    assert_eq!(put_count, 2, "registry must observe both publish attempts");
}
