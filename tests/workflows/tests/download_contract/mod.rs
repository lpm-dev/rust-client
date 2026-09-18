use super::*;

#[tokio::test]
async fn download_refuses_existing_files_without_changing_any_output() {
    let project = TempProject::empty(r#"{"name":"owner","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    mock.with_package("pkg", "1.0.0", &make_tarball("pkg", "1.0.0"))
        .await;
    project.write_file("out/index.js", "keep this file");
    project.write_file("out/unrelated.txt", "keep unrelated");
    let output = lpm_with_registry(&project, &mock.url())
        .args(["download", "pkg", "--output", "out", "--json"])
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "existing payload leaf must be rejected"
    );
    assert_eq!(project.read_file("out/index.js"), "keep this file");
    assert_eq!(project.read_file("out/unrelated.txt"), "keep unrelated");
    assert!(
        !project.file_exists("out/package.json"),
        "preflight must precede all payload writes"
    );
}

#[tokio::test]
async fn download_invalid_archive_does_not_remove_or_overwrite_existing_files() {
    let project = TempProject::empty(r#"{"name":"owner","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    let bytes = make_tarball_with_files(
        "pkg",
        "1.0.0",
        &[("context.md", b"one"), ("CONTEXT.md", b"two")],
    );
    mock.with_package("pkg", "1.0.0", &bytes).await;
    project.write_file("out/package.json", "original manifest");
    project.write_file("out/index.js", "original source");
    let output = lpm_with_registry(&project, &mock.url())
        .args(["download", "pkg", "--output", "out", "--json"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert_eq!(
        std::fs::read(project.path().join("out/package.json")).ok(),
        Some(b"original manifest".to_vec())
    );
    assert_eq!(project.read_file("out/index.js"), "original source");
    assert!(!project.file_exists("out/context.md"));
}

#[tokio::test]
async fn download_refuses_existing_hardlink_without_modifying_its_other_name() {
    let project = TempProject::empty(r#"{"name":"owner","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    mock.with_package("pkg", "1.0.0", &make_tarball("pkg", "1.0.0"))
        .await;
    project.write_file("outside.txt", "original outside content");
    std::fs::create_dir(project.path().join("out")).unwrap();
    std::fs::hard_link(
        project.path().join("outside.txt"),
        project.path().join("out/index.js"),
    )
    .unwrap();
    let output = lpm_with_registry(&project, &mock.url())
        .args(["download", "pkg", "--output", "out"])
        .output()
        .unwrap();
    assert!(!output.status.success(), "hardlink collision must fail");
    assert_eq!(project.read_file("outside.txt"), "original outside content");
}

async fn registry_without_integrity(mock: &MockRegistry, bytes: &[u8]) {
    mock.with_package_metadata_and_tarballs("pkg", serde_json::json!({
        "name":"pkg", "dist-tags":{"latest":"1.0.0"},
        "versions":{"1.0.0":{"name":"pkg","version":"1.0.0","dist":{"tarball":mock.tarball_url("pkg","1.0.0")}}}
    }), &[("1.0.0",bytes.to_vec())]).await;
}

#[tokio::test]
async fn download_missing_integrity_fails_before_any_tarball_request() {
    let project = TempProject::empty(r#"{"name":"owner","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    registry_without_integrity(&mock, &make_tarball("pkg", "1.0.0")).await;
    let output = lpm_with_registry(&project, &mock.url())
        .args(["download", "pkg", "--output", "out", "--json"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert_eq!(
        mock.tarball_request_count("pkg", "1.0.0").await,
        0,
        "missing integrity is known before download"
    );
    assert!(!project.file_exists("out"));
}

#[tokio::test]
async fn download_unverified_opt_in_allows_missing_hash_and_preserves_unrelated_files() {
    let project = TempProject::empty(r#"{"name":"owner","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    let bytes =
        make_tarball_with_files("pkg", "1.0.0", &[("lib/module.js", b"module.exports = 1")]);
    registry_without_integrity(&mock, &bytes).await;
    project.write_file("out/lib/keep.txt", "unrelated");
    let output = lpm_with_registry(&project, &mock.url())
        .args([
            "download",
            "pkg",
            "--output",
            "out",
            "--allow-unverified",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["integrity_verified"], false);
    assert_eq!(json["size_bytes"], bytes.len());
    assert_eq!(project.read_file("out/lib/keep.txt"), "unrelated");
    assert_eq!(project.read_file("out/lib/module.js"), "module.exports = 1");
    assert_eq!(mock.tarball_request_count("pkg", "1.0.0").await, 1);
}

async fn registry_with_dist(mock: &MockRegistry, bytes: &[u8], mut dist: serde_json::Value) {
    dist["tarball"] = mock.tarball_url("pkg", "1.0.0").into();
    mock.with_package_metadata_and_tarballs(
        "pkg",
        serde_json::json!({
            "name":"pkg", "dist-tags":{"latest":"1.0.0"},
            "versions":{"1.0.0":{"name":"pkg","version":"1.0.0","dist":dist}}
        }),
        &[("1.0.0", bytes.to_vec())],
    )
    .await;
}

#[tokio::test]
async fn download_verifies_legacy_shasum_without_sri() {
    use lpm_common::integrity::{HashAlgorithm, Integrity};
    let project = TempProject::empty(r#"{"name":"owner","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    let bytes = make_tarball("pkg", "1.0.0");
    let integrity = Integrity::from_bytes(HashAlgorithm::Sha1, &bytes);
    registry_with_dist(
        &mock,
        &bytes,
        serde_json::json!({"shasum":hex::encode(&integrity.hash)}),
    )
    .await;
    let output = lpm_with_registry(&project, &mock.url())
        .args(["download", "pkg", "--output", "out", "--json"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["integrity_verified"], true);
    assert_eq!(json["integrity"], integrity.to_string());
}

#[tokio::test]
async fn download_unverified_flag_never_waives_an_advertised_hash_mismatch() {
    for allow in [false, true] {
        let project = TempProject::empty(r#"{"name":"owner","version":"1.0.0"}"#);
        let mock = MockRegistry::start().await;
        let bytes = make_tarball("pkg", "1.0.0");
        registry_with_dist(
            &mock,
            &bytes,
            serde_json::json!({"integrity":compute_integrity(b"different bytes")}),
        )
        .await;
        let mut command = lpm_with_registry(&project, &mock.url());
        command.args(["download", "pkg", "--output", "out", "--json"]);
        if allow {
            command.arg("--allow-unverified");
        }
        let output = command.output().unwrap();
        assert!(!output.status.success());
        let rendered = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(rendered.to_lowercase().contains("integrity"), "{rendered}");
        assert!(!project.file_exists("out"));
    }
}

#[tokio::test]
async fn download_rejects_a_directory_at_a_payload_file_without_publishing() {
    let project = TempProject::empty(r#"{"name":"owner","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    mock.with_package("pkg", "1.0.0", &make_tarball("pkg", "1.0.0"))
        .await;
    project.write_file("out/index.js/keep", "original");
    let output = lpm_with_registry(&project, &mock.url())
        .args(["download", "pkg", "--output", "out", "--json"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert_eq!(project.read_file("out/index.js/keep"), "original");
    assert!(!project.file_exists("out/package.json"));
}

#[cfg(unix)]
#[tokio::test]
async fn download_rejects_symlink_leaves_and_ancestors_without_writing_outside_output() {
    for ancestor in [false, true] {
        let project = TempProject::empty(r#"{"name":"owner","version":"1.0.0"}"#);
        let mock = MockRegistry::start().await;
        let bytes = make_tarball_with_files("pkg", "1.0.0", &[("lib/module.js", b"new")]);
        mock.with_package("pkg", "1.0.0", &bytes).await;
        project.write_file("outside/keep", "original");
        std::fs::create_dir(project.path().join("out")).unwrap();
        let (source, target) = if ancestor {
            ("outside", "out/lib")
        } else {
            ("outside/keep", "out/index.js")
        };
        std::os::unix::fs::symlink(project.path().join(source), project.path().join(target))
            .unwrap();
        let output = lpm_with_registry(&project, &mock.url())
            .args(["download", "pkg", "--output", "out", "--json"])
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert_eq!(project.read_file("outside/keep"), "original");
        assert!(!project.file_exists("outside/module.js"));
        assert!(!project.file_exists("out/package.json"));
    }
}

#[cfg(unix)]
#[tokio::test]
async fn download_rejects_fifo_payload_collision_without_opening_it() {
    let project = TempProject::empty(r#"{"name":"owner","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    mock.with_package("pkg", "1.0.0", &make_tarball("pkg", "1.0.0"))
        .await;
    std::fs::create_dir(project.path().join("out")).unwrap();
    assert!(
        std::process::Command::new("mkfifo")
            .arg(project.path().join("out/index.js"))
            .status()
            .unwrap()
            .success()
    );
    let output = lpm_with_registry(&project, &mock.url())
        .timeout(std::time::Duration::from_secs(10))
        .args(["download", "pkg", "--output", "out", "--json"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(!project.file_exists("out/package.json"));
    use std::os::unix::fs::FileTypeExt as _;
    assert!(
        std::fs::symlink_metadata(project.path().join("out/index.js"))
            .unwrap()
            .file_type()
            .is_fifo()
    );
}

#[cfg(unix)]
#[tokio::test]
async fn download_preserves_executable_permissions() {
    use std::os::unix::fs::PermissionsExt as _;
    let project = TempProject::empty(r#"{"name":"owner","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    let bytes = support::mock_registry::make_tarball_from_pkg_json(
        serde_json::json!({"name":"pkg","version":"1.0.0"}),
        &[("bin/tool", b"#!/bin/sh\nexit 0\n")],
    );
    mock.with_package("pkg", "1.0.0", &bytes).await;
    let output = lpm_with_registry(&project, &mock.url())
        .args(["download", "pkg", "--output", "out", "--json"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        std::fs::metadata(project.path().join("out/bin/tool"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o755
    );
}

#[tokio::test]
async fn download_malformed_advertised_integrity_fails_before_tarball_even_with_opt_in() {
    let project = TempProject::empty(r#"{"name":"owner","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    registry_with_dist(
        &mock,
        &make_tarball("pkg", "1.0.0"),
        serde_json::json!({"integrity":"sha512-invalid"}),
    )
    .await;
    let output = lpm_with_registry(&project, &mock.url())
        .args([
            "download",
            "pkg",
            "--output",
            "out",
            "--allow-unverified",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert_eq!(mock.tarball_request_count("pkg", "1.0.0").await, 0);
    assert!(!project.file_exists("out"));
}
