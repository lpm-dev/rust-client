//! Workflow coverage for reinstalling mixed cached and local package entries.

mod support;

use support::mock_registry::{MockRegistry, compute_integrity, make_tarball_with_files};
use support::{TempProject, lpm_v1_with_registry, lpm_with_registry};

const INSTALL: [&str; 3] = ["install", "--no-skills", "--no-security-summary"];

fn marked_archive(marker: &[u8]) -> Vec<u8> {
    make_tarball_with_files("same", "1.0.0", &[("marker.txt", marker)])
}

fn consumer_of_same() -> TempProject {
    TempProject::empty(
        r#"{"name":"cached-consumer","version":"1.0.0","dependencies":{"same":"1.0.0"}}"#,
    )
}

fn installed_marker(project: &TempProject) -> Option<Vec<u8>> {
    std::fs::read(project.path().join("node_modules/same/marker.txt")).ok()
}

fn remove_install_output(project: &TempProject) {
    std::fs::remove_dir_all(project.path().join("node_modules")).unwrap();
    std::fs::remove_dir_all(project.path().join(".lpm")).unwrap();
}

/// Where the lockfile's pin comes from in the scenario below.
#[derive(Clone, Copy, PartialEq)]
enum Pin {
    /// No lockfile: the install resolves the registry's current metadata.
    Registry,
    /// A lockfile an earlier install of the registry's archive wrote.
    Lockfile,
}

/// The v1 store holds `original` at `same@1.0.0`, and the install selects
/// `replacement` for that coordinate. It must not link `original`.
async fn v1_install_rejects_another_archive_at_the_coordinate(
    env: &[(&str, &str)],
    extra_args: &[&str],
    pin: Pin,
) {
    let mock = MockRegistry::start().await;
    let original = marked_archive(b"original");
    let replacement = marked_archive(b"replacement");
    mock.with_package("same", "1.0.0", &replacement).await;
    let project = consumer_of_same();
    let store = lpm_store::PackageStore::at(project.store_dir());
    if pin == Pin::Lockfile {
        lpm_v1_with_registry(&project, &mock.url())
            .args(INSTALL)
            .assert()
            .success();
        assert_eq!(installed_marker(&project).unwrap(), b"replacement");
        assert!(
            project
                .read_file("lpm.lock")
                .contains(&compute_integrity(&replacement))
        );
        remove_install_output(&project);
        std::fs::remove_dir_all(store.package_dir("same", "1.0.0")).unwrap();
    }
    let entry = store.store_package("same", "1.0.0", &original).unwrap();

    let output = lpm_v1_with_registry(&project, &mock.url())
        .envs(env.iter().copied())
        .args(INSTALL)
        .args(extra_args)
        .output()
        .unwrap();

    // An offline install has no archive to compare, so it reports the entry
    // as absent under the pinned integrity.
    let expected_error = if extra_args.contains(&"--offline") {
        "not in the global store under the integrity"
    } else {
        "conflict"
    };
    let message = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !output.status.success(),
        "the cached archive must not be installed as the selected one: {message}"
    );
    assert!(
        message.contains("integrity") && message.contains(expected_error),
        "{message}"
    );
    assert_ne!(
        installed_marker(&project),
        Some(b"original".to_vec()),
        "{message}"
    );
    assert_eq!(
        std::fs::read(entry.join("marker.txt")).unwrap(),
        b"original"
    );
    assert_eq!(
        lpm_store::read_stored_integrity(&entry).unwrap(),
        compute_integrity(&original)
    );
}

#[tokio::test]
async fn v1_install_does_not_reuse_a_coordinate_that_holds_another_archive() {
    v1_install_rejects_another_archive_at_the_coordinate(&[], &[], Pin::Registry).await;
}

#[tokio::test]
async fn v1_install_from_a_lockfile_does_not_reuse_a_coordinate_that_holds_another_archive() {
    v1_install_rejects_another_archive_at_the_coordinate(&[], &[], Pin::Lockfile).await;
}

#[tokio::test]
async fn v1_offline_install_does_not_reuse_a_coordinate_that_holds_another_archive() {
    v1_install_rejects_another_archive_at_the_coordinate(&[], &["--offline"], Pin::Lockfile).await;
}

#[tokio::test]
async fn v1_forced_install_does_not_keep_another_archive_at_the_coordinate() {
    v1_install_rejects_another_archive_at_the_coordinate(&[], &["--force"], Pin::Registry).await;
}

#[tokio::test]
async fn v1_file_backed_install_does_not_reuse_a_coordinate_that_holds_another_archive() {
    v1_install_rejects_another_archive_at_the_coordinate(
        &[("LPM_STREAM_FETCH", "0")],
        &[],
        Pin::Registry,
    )
    .await;
}

#[tokio::test]
async fn v1_forced_file_backed_install_does_not_keep_another_archive_at_the_coordinate() {
    v1_install_rejects_another_archive_at_the_coordinate(
        &[("LPM_STREAM_FETCH", "0")],
        &["--force"],
        Pin::Lockfile,
    )
    .await;
}

/// A lockfile that pins the stored archive under another hash algorithm
/// downloads it once to prove the pin, and is a cache hit from then on.
async fn v1_install_proves_an_alternate_pin_once(env: &[(&str, &str)]) {
    let mock = MockRegistry::start().await;
    let archive = marked_archive(b"original");
    mock.with_package("same", "1.0.0", &archive).await;
    let project = consumer_of_same();
    lpm_v1_with_registry(&project, &mock.url())
        .args(INSTALL)
        .assert()
        .success();
    assert_eq!(mock.tarball_request_count("same", "1.0.0").await, 1);
    let sha512 = compute_integrity(&archive);
    let sha256 = lpm_store::compute_sri_hash_sha256(&archive);
    let locked = project.read_file("lpm.lock");
    assert!(locked.contains(&sha512), "{locked}");
    let pinned = locked.replace(&sha512, &sha256);

    for _ in 0..2 {
        remove_install_output(&project);
        project.write_file("lpm.lock", &pinned);
        lpm_v1_with_registry(&project, &mock.url())
            .envs(env.iter().copied())
            .args(INSTALL)
            .assert()
            .success();
        assert_eq!(installed_marker(&project).unwrap(), b"original");
        assert!(
            project.read_file("lpm.lock").contains(&sha256),
            "the install replays the lockfile's pin"
        );
    }

    assert_eq!(
        mock.tarball_request_count("same", "1.0.0").await,
        2,
        "the pin is proven against the archive once, then recorded"
    );
}

#[tokio::test]
async fn v1_install_downloads_once_to_prove_a_pin_in_another_hash_algorithm() {
    v1_install_proves_an_alternate_pin_once(&[]).await;
}

#[tokio::test]
async fn v1_file_backed_install_downloads_once_to_prove_a_pin_in_another_hash_algorithm() {
    v1_install_proves_an_alternate_pin_once(&[("LPM_STREAM_FETCH", "0")]).await;
}

#[tokio::test]
async fn missing_install_artifacts_do_not_bypass_frozen_lockfile_validation() {
    let mock = MockRegistry::start().await;
    let tarball = make_tarball_with_files("cached-dep", "1.0.0", &[]);
    mock.with_package("cached-dep", "1.0.0", &tarball).await;
    for missing in ["node_modules", ".lpm/install-hash"] {
        let project = TempProject::empty(
            r#"{"name":"cached-consumer","version":"1.0.0","dependencies":{"cached-dep":"1.0.0"}}"#,
        );
        lpm_with_registry(&project, &mock.url())
            .args(["install", "--no-skills", "--no-security-summary"])
            .assert()
            .success();
        let path = project.path().join(missing);
        if path.is_dir() {
            std::fs::remove_dir_all(path).unwrap();
        } else {
            std::fs::remove_file(path).unwrap();
        }
        project.write_file("lpm.lock", "invalid = [");
        lpm_with_registry(&project, &mock.url())
            .args([
                "install",
                "--frozen-lockfile",
                "--no-skills",
                "--no-security-summary",
            ])
            .assert()
            .failure();
    }
}

#[tokio::test]
async fn cached_reinstall_keeps_package_bytes_and_force_refetches_each_registry_package() {
    let mock = MockRegistry::start().await;
    for (name, size) in [("a-small", 32), ("z-large", 65536), ("m-new", 128)] {
        let payload = vec![name.as_bytes()[0]; size];
        let tarball = make_tarball_with_files(name, "1.0.0", &[("payload.bin", &payload)]);
        let metadata = serde_json::json!({
            "name": name,
            "dist-tags": {"latest": "1.0.0"},
            "versions": {"1.0.0": {
                "name": name,
                "version": "1.0.0",
                "dist": {
                    "tarball": mock.tarball_url(name, "1.0.0"),
                    "integrity": compute_integrity(&tarball),
                    "unpackedSize": size + 256
                }
            }},
            "time": {"1.0.0": "2025-01-01T00:00:00.000Z"}
        });
        mock.with_package_metadata(name, "1.0.0", &tarball, metadata)
            .await;
    }
    let project = TempProject::empty(
        r#"{"name":"cached-consumer","version":"1.0.0","dependencies":{"a-small":"1.0.0","z-large":"1.0.0"}}"#,
    );
    project.write_file(".npmrc", &format!("registry={}/\n", mock.url()));
    let args = [
        "--json",
        "install",
        "--no-frozen-lockfile",
        "--no-skills",
        "--no-security-summary",
    ];
    lpm_with_registry(&project, &mock.url())
        .args(args)
        .assert()
        .success();
    let saved_lock = std::fs::read(project.path().join("lpm.lock")).unwrap();
    std::fs::remove_dir_all(project.path().join("node_modules")).unwrap();
    lpm_with_registry(&project, &mock.url())
        .args(args)
        .assert()
        .success();
    assert_eq!(
        std::fs::read(project.path().join("lpm.lock")).unwrap(),
        saved_lock
    );
    for name in ["a-small", "z-large"] {
        assert_eq!(mock.tarball_request_count(name, "1.0.0").await, 1);
    }

    project.write_file(
        "local/package.json",
        r#"{"name":"n-local","version":"1.0.0"}"#,
    );
    project.write_file("local/marker.txt", "local entry");
    project.write_file("package.json", r#"{"name":"cached-consumer","version":"1.0.0","dependencies":{"a-small":"1.0.0","m-new":"1.0.0","n-local":"file:./local","z-large":"1.0.0"}}"#);
    std::fs::remove_dir_all(project.path().join("node_modules")).unwrap();
    lpm_with_registry(&project, &mock.url())
        .args(args)
        .assert()
        .success();
    for (name, size) in [("a-small", 32), ("z-large", 65536), ("m-new", 128)] {
        assert_eq!(
            std::fs::read(
                project
                    .path()
                    .join("node_modules")
                    .join(name)
                    .join("payload.bin")
            )
            .unwrap(),
            vec![name.as_bytes()[0]; size],
        );
        assert_eq!(mock.tarball_request_count(name, "1.0.0").await, 1);
    }
    assert_eq!(
        std::fs::read_to_string(project.path().join("node_modules/n-local/marker.txt")).unwrap(),
        "local entry"
    );

    lpm_with_registry(&project, &mock.url())
        .args(args)
        .arg("--force")
        .assert()
        .success();
    for name in ["a-small", "z-large", "m-new"] {
        assert_eq!(mock.tarball_request_count(name, "1.0.0").await, 2);
    }
}
