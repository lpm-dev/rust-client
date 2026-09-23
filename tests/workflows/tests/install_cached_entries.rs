//! Workflow coverage for reinstalling mixed cached and local package entries.

mod support;

use support::mock_registry::{MockRegistry, compute_integrity, make_tarball_with_files};
use support::{TempProject, lpm_with_registry};

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
            .args([
                "install",
                "--no-skills",
                "--no-editor-setup",
                "--no-security-summary",
            ])
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
                "--no-editor-setup",
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
        "--no-editor-setup",
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
