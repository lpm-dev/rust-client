use super::*;

fn artifact_lockfile(mock: &MockRegistry, name: &str, tarball: &[u8]) -> lpm_lockfile::Lockfile {
    let mut lockfile = lpm_lockfile::Lockfile::new();
    lockfile.add_package(lpm_lockfile::LockedPackage {
        name: name.into(),
        version: "1.0.0".into(),
        source: Some(format!("registry+{}", mock.url())),
        integrity: Some(compute_integrity(tarball)),
        tarball: Some(mock.tarball_url(name, "1.0.0")),
        ..Default::default()
    });
    support::finalize_exact_lockfile_fixture(&mut lockfile, &[(name, name, "1.0.0")]);
    lockfile
}

async fn workspace_fetch(from_member: bool) {
    let mock = MockRegistry::start().await;
    let project =
        TempProject::empty(r#"{"name":"root","private":true,"workspaces":["packages/*"]}"#);
    let mut union = lpm_lockfile::Lockfile::new();
    for name in ["alpha", "beta"] {
        let bytes = make_tarball(name, "1.0.0");
        mock.with_package(name, "1.0.0", &bytes).await;
        let mut member = artifact_lockfile(&mock, name, &bytes);
        member.importers.insert(
            ".".into(),
            lpm_lockfile::ImporterSnapshot {
                dependencies: std::collections::BTreeMap::from([(name.into(), "1.0.0".into())]),
                ..Default::default()
            },
        );
        union
            .absorb_importer(&format!("packages/{name}"), member)
            .unwrap();
        project.write_file(
            &format!("packages/{name}/package.json"),
            &format!(r#"{{"name":"{name}","version":"1.0.0"}}"#),
        );
    }
    let toml = union.to_toml().unwrap();
    project.write_file("lpm.lock", &toml);
    // A stale member file must not supersede the authoritative workspace union.
    project.write_file(
        "packages/alpha/lpm.lock",
        &artifact_lockfile(&mock, "alpha", &make_tarball("alpha", "1.0.0"))
            .to_toml()
            .unwrap(),
    );
    let cwd = if from_member {
        project.path().join("packages/alpha")
    } else {
        project.path().to_path_buf()
    };
    let output = lpm_with_registry(&project, &mock.url())
        .current_dir(cwd)
        .args(["fetch", "--json"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["counts"]["fetched"], 2, "{json}");
    for name in ["alpha", "beta"] {
        assert_eq!(mock.tarball_request_count(name, "1.0.0").await, 1);
    }
    assert_eq!(project.read_file("lpm.lock"), toml);
    assert!(!project.file_exists("node_modules"));
}

#[tokio::test]
async fn fetch_from_workspace_root_fetches_all_importers_without_root_importer() {
    workspace_fetch(false).await;
}
#[tokio::test]
async fn fetch_from_workspace_member_fetches_all_importers_despite_stale_local_lockfile() {
    workspace_fetch(true).await;
}

#[tokio::test]
async fn fetch_prefers_local_lockfile_only_directory_over_unrelated_ancestor_manifest() {
    let mock = MockRegistry::start().await;
    let bytes = make_tarball("alpha", "1.0.0");
    mock.with_package("alpha", "1.0.0", &bytes).await;
    let project = TempProject::empty(r#"{"name":"unrelated","version":"1.0.0"}"#);
    project.write_file(
        "cache/lpm.lock",
        &artifact_lockfile(&mock, "alpha", &bytes).to_toml().unwrap(),
    );
    let output = lpm_with_registry(&project, &mock.url())
        .current_dir(project.path().join("cache"))
        .args(["fetch", "--json"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(mock.tarball_request_count("alpha", "1.0.0").await, 1);
}

async fn platform_fetch(os: &[&str], cpu: &[&str], libc: &[&str], target: &str, expected: usize) {
    let mock = MockRegistry::start().await;
    let bytes = make_tarball("platform-pkg", "1.0.0");
    mock.with_package("platform-pkg", "1.0.0", &bytes).await;
    let mut lockfile = artifact_lockfile(&mock, "platform-pkg", &bytes);
    let package = &mut lockfile.packages[0];
    package.os = os.iter().map(|s| s.to_string()).collect();
    package.cpu = cpu.iter().map(|s| s.to_string()).collect();
    package.libc = libc.iter().map(|s| s.to_string()).collect();
    let project = project_with_lockfile(&lockfile.to_toml().unwrap());
    let output = lpm_with_registry(&project, &mock.url())
        .args(["fetch", "--platform", target, "--json"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        json["counts"]["fetched"], expected,
        "{os:?}/{cpu:?}/{libc:?} for {target}: {json}"
    );
    assert_eq!(
        mock.tarball_request_count("platform-pkg", "1.0.0").await,
        expected
    );
}

#[tokio::test]
async fn fetch_accepts_sole_any_platform_filters() {
    platform_fetch(&["any"], &["any"], &["any"], "linux/x64/musl", 1).await;
}
#[tokio::test]
async fn fetch_mixed_platform_filters_still_require_positive_match() {
    platform_fetch(&["linux", "!win32"], &[], &[], "darwin/arm64", 0).await;
    platform_fetch(&[], &["x64", "!arm"], &[], "linux/arm64", 0).await;
    platform_fetch(&[], &[], &["musl", "!other"], "linux/x64/glibc", 0).await;
}
#[tokio::test]
async fn fetch_platform_exclusions_win_and_explicit_target_does_not_inherit_libc() {
    platform_fetch(&["linux", "!linux"], &[], &[], "linux/x64", 0).await;
    platform_fetch(&["any", "!darwin"], &[], &[], "linux/x64", 0).await;
    platform_fetch(&[], &[], &["any"], "linux/x64", 0).await;
    platform_fetch(&["!win32"], &[], &[], "linux/x64", 1).await;
}

#[tokio::test]
async fn fetch_v1_rejects_different_artifact_at_an_existing_coordinate() {
    let mock = MockRegistry::start().await;
    let first = make_tarball_with_files("same", "1.0.0", &[("marker.txt", b"original")]);
    let second = make_tarball_with_files("same", "1.0.0", &[("marker.txt", b"replacement")]);
    mock.with_package("same", "1.0.0", &second).await;
    let project =
        project_with_lockfile(&artifact_lockfile(&mock, "same", &first).to_toml().unwrap());
    let store = lpm_store::PackageStore::at(project.store_dir());
    let dir = store.store_package("same", "1.0.0", &first).unwrap();
    let cached = lpm_with_registry(&project, &mock.url())
        .env("LPM_STORE_VERSION", "1")
        .args(["fetch", "--json"])
        .output()
        .unwrap();
    assert!(
        cached.status.success(),
        "{}",
        String::from_utf8_lossy(&cached.stderr)
    );
    let json: serde_json::Value = serde_json::from_slice(&cached.stdout).unwrap();
    assert_eq!(json["counts"]["cached"], 1);
    assert_eq!(mock.tarball_request_count("same", "1.0.0").await, 0);
    project.write_file(
        "lpm.lock",
        &artifact_lockfile(&mock, "same", &second).to_toml().unwrap(),
    );
    let changed = lpm_with_registry(&project, &mock.url())
        .env("LPM_STORE_VERSION", "1")
        .args(["fetch", "--json"])
        .output()
        .unwrap();
    assert!(
        !changed.status.success(),
        "a different pinned artifact must not be reported as cached: {}",
        String::from_utf8_lossy(&changed.stdout)
    );
    let message = format!(
        "{}{}",
        String::from_utf8_lossy(&changed.stdout),
        String::from_utf8_lossy(&changed.stderr)
    );
    assert!(
        message.contains("integrity") && message.contains("conflict"),
        "{message}"
    );
    assert_eq!(
        std::fs::read_to_string(dir.join("marker.txt")).unwrap(),
        "original"
    );
    assert_eq!(
        lpm_store::read_stored_integrity(&dir).unwrap(),
        compute_integrity(&first)
    );
}

#[tokio::test]
async fn fetch_v1_verifies_equivalent_pins_with_different_hash_algorithms() {
    let mock = MockRegistry::start().await;
    let bytes = make_tarball_with_files(
        "same",
        "1.0.0",
        &[
            (".integrity.sha256", b"package data"),
            (".integrity.sha1/payload", b"directory data"),
        ],
    );
    mock.with_package("same", "1.0.0", &bytes).await;
    let mut lockfile = artifact_lockfile(&mock, "same", &bytes);
    lockfile.packages[0].integrity = Some(lpm_store::compute_sri_hash_sha256(&bytes));
    let project = project_with_lockfile(&lockfile.to_toml().unwrap());
    let store = lpm_store::PackageStore::at(project.store_dir());
    let dir = store.store_package("same", "1.0.0", &bytes).unwrap();
    let output = lpm_with_registry(&project, &mock.url())
        .env("LPM_STORE_VERSION", "1")
        .args(["fetch", "--json"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        mock.tarball_request_count("same", "1.0.0").await,
        1,
        "algorithm equivalence needs archive verification"
    );
    assert_eq!(
        lpm_store::read_stored_integrity(&dir).unwrap(),
        compute_integrity(&bytes)
    );
    assert_eq!(
        std::fs::read(dir.join(".integrity.sha256")).unwrap(),
        b"package data",
        "integrity receipts must not replace package contents"
    );
    let warm = lpm_with_registry(&project, &mock.url())
        .env("LPM_STORE_VERSION", "1")
        .args(["fetch", "--json"])
        .output()
        .unwrap();
    assert!(
        warm.status.success(),
        "{}",
        String::from_utf8_lossy(&warm.stderr)
    );
    let json: serde_json::Value = serde_json::from_slice(&warm.stdout).unwrap();
    assert_eq!(
        json["counts"]["cached"], 1,
        "verified equivalent pins must remain reusable: {json}"
    );
    assert_eq!(mock.tarball_request_count("same", "1.0.0").await, 1);
    lockfile.packages[0].integrity = Some(lpm_store::compute_sri_hash_sha1(&bytes));
    project.write_file("lpm.lock", &lockfile.to_toml().unwrap());
    for _ in 0..2 {
        let output = lpm_with_registry(&project, &mock.url())
            .env("LPM_STORE_VERSION", "1")
            .args(["fetch", "--json"])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    assert_eq!(mock.tarball_request_count("same", "1.0.0").await, 2);
    assert_eq!(
        std::fs::read(dir.join(".integrity.sha1/payload")).unwrap(),
        b"directory data"
    );
}
