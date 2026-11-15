//! Workflow coverage for the integrity a lockfile keeps after it is replayed.

mod support;

use lpm_common::integrity::{HashAlgorithm, Integrity};
use support::mock_registry::{MockRegistry, compute_integrity, make_tarball};
use support::{TempProject, lpm_with_registry};

const INSTALL: [&str; 3] = ["install", "--no-skills", "--no-security-summary"];

/// A project whose lockfile pins `pinned@1.0.0` by SHA-1 alone, as one
/// migrated from an old `package-lock.json` does, with nothing installed.
async fn project_pinned_by_sha1(registry: &MockRegistry) -> (TempProject, String) {
    let tarball = make_tarball("pinned", "1.0.0");
    registry.with_package("pinned", "1.0.0", &tarball).await;
    let project = TempProject::empty(
        r#"{"name":"consumer","version":"1.0.0","dependencies":{"pinned":"1.0.0"}}"#,
    );
    lpm_with_registry(&project, &registry.url())
        .args(INSTALL)
        .assert()
        .success();

    let sha512 = compute_integrity(&tarball);
    let sha1 = Integrity::from_bytes(HashAlgorithm::Sha1, &tarball).to_string();
    let lockfile = project.read_file("lpm.lock");
    assert!(lockfile.contains(&sha512), "{lockfile}");
    project.write_file("lpm.lock", &lockfile.replace(&sha512, &sha1));
    forget_install(&project);
    std::fs::remove_dir_all(project.store_dir()).unwrap();
    (project, sha512)
}

fn forget_install(project: &TempProject) {
    for path in ["node_modules", ".lpm"] {
        match std::fs::remove_dir_all(project.path().join(path)) {
            Err(error) if error.kind() != std::io::ErrorKind::NotFound => panic!("{error}"),
            _ => {}
        }
    }
}

#[tokio::test]
async fn a_replayed_lockfile_keeps_the_sha512_of_the_bytes_it_fetched() {
    let registry = MockRegistry::start().await;
    let (project, sha512) = project_pinned_by_sha1(&registry).await;
    let fetched_before = registry.tarball_request_count("pinned", "1.0.0").await;

    lpm_with_registry(&project, &registry.url())
        .args(INSTALL)
        .assert()
        .success();

    assert_eq!(
        registry.tarball_request_count("pinned", "1.0.0").await,
        fetched_before + 1
    );
    let lockfile = project.read_file("lpm.lock");
    assert!(lockfile.contains(&sha512), "{lockfile}");
    assert!(!lockfile.contains("sha1-"), "{lockfile}");

    forget_install(&project);
    lpm_with_registry(&project, &registry.url())
        .args(INSTALL)
        .assert()
        .success();

    assert_eq!(
        registry.tarball_request_count("pinned", "1.0.0").await,
        fetched_before + 1,
        "the next install finds the package in the store"
    );
    assert!(project.file_exists("node_modules/pinned/package.json"));
}

#[tokio::test]
async fn a_frozen_lockfile_keeps_the_integrity_it_was_written_with() {
    let registry = MockRegistry::start().await;
    let (project, _) = project_pinned_by_sha1(&registry).await;
    let pinned = project.read_file("lpm.lock");

    lpm_with_registry(&project, &registry.url())
        .args(INSTALL)
        .arg("--frozen-lockfile")
        .assert()
        .success();

    assert_eq!(project.read_file("lpm.lock"), pinned);
    assert!(project.file_exists("node_modules/pinned/package.json"));
}
