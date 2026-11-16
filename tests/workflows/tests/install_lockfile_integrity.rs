//! Workflow coverage for what an install writes back to the lockfile it
//! replays: a package's integrity and the URL that serves it.

mod support;

use lpm_common::integrity::{HashAlgorithm, Integrity};
use support::mock_registry::{
    MockRegistry, RegistrySigningFixture, compute_integrity, make_tarball,
};
use support::{TempProject, lpm_with_registry};

const INSTALL: [&str; 3] = ["install", "--no-skills", "--no-security-summary"];

fn single_project() -> TempProject {
    TempProject::empty(r#"{"name":"consumer","version":"1.0.0","dependencies":{"pinned":"1.0.0"}}"#)
}

fn workspace() -> TempProject {
    let project = TempProject::empty(
        r#"{"name":"root","version":"1.0.0","private":true,"workspaces":["packages/*"]}"#,
    );
    project.write_file(
        "packages/app/package.json",
        r#"{"name":"app","version":"1.0.0","private":true,"dependencies":{"pinned":"1.0.0"}}"#,
    );
    project
}

/// Installs `project`, then leaves it as a checkout whose lockfile pins
/// `pinned@1.0.0` by `pin_of` its archive alone, as one migrated from an
/// old `package-lock.json` pins by SHA-1: nothing installed, nothing in
/// the store. Returns the archive's sha512.
async fn pinned_by(
    project: &TempProject,
    registry: &MockRegistry,
    pin_of: impl FnOnce(&[u8]) -> String,
) -> String {
    let tarball = make_tarball("pinned", "1.0.0");
    registry.with_package("pinned", "1.0.0", &tarball).await;
    lpm_with_registry(project, &registry.url())
        .args(INSTALL)
        .assert()
        .success();

    let sha512 = compute_integrity(&tarball);
    let lockfile = project.read_file("lpm.lock");
    assert!(lockfile.contains(&sha512), "{lockfile}");
    let pin = pin_of(&tarball);
    if project.file_exists("packages/app/package.json") {
        pin_workspace_packages(project, &pin);
    } else {
        project.write_file("lpm.lock", &lockfile.replace(&sha512, &pin));
    }
    let lockfile = project.read_file("lpm.lock");
    assert!(
        lockfile.contains(&pin) && !lockfile.contains(&sha512),
        "{lockfile}"
    );
    forget_install(project);
    std::fs::remove_dir_all(project.store_dir()).unwrap();
    sha512
}

/// A workspace lockfile names each package by a digest of its row, so the
/// row is replaced through the lockfile's own writer.
fn pin_workspace_packages(project: &TempProject, pin: &str) {
    let path = project.path().join("lpm.lock");
    let mut lockfile = lpm_lockfile::Lockfile::read_fast(&path).unwrap();
    let mut app = lockfile.project_importer("packages/app").unwrap();
    for package in &mut app.packages {
        package.integrity = Some(pin.to_owned());
    }
    lockfile.replace_importer("packages/app", app).unwrap();
    lockfile.write_all(&path).unwrap();
}

fn sha1_of(bytes: &[u8]) -> String {
    Integrity::from_bytes(HashAlgorithm::Sha1, bytes).to_string()
}

fn forget_install(project: &TempProject) {
    for path in [
        "node_modules",
        ".lpm",
        "packages/app/node_modules",
        "packages/app/.lpm",
    ] {
        match std::fs::remove_dir_all(project.path().join(path)) {
            Err(error) if error.kind() != std::io::ErrorKind::NotFound => panic!("{error}"),
            _ => {}
        }
    }
}

/// An install that replays a SHA-1 pin and downloads the package writes the
/// sha512 of those bytes to the lockfile, so the install after it finds the
/// package in the store.
async fn replay_records_the_sha512(project: TempProject, installed: &str, env: &[(&str, &str)]) {
    let registry = MockRegistry::start().await;
    let sha512 = pinned_by(&project, &registry, sha1_of).await;
    let fetched_before = registry.tarball_request_count("pinned", "1.0.0").await;

    lpm_with_registry(&project, &registry.url())
        .envs(env.iter().copied())
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
        .envs(env.iter().copied())
        .args(INSTALL)
        .assert()
        .success();

    assert_eq!(
        registry.tarball_request_count("pinned", "1.0.0").await,
        fetched_before + 1,
        "the next install finds the package in the store"
    );
    assert!(project.file_exists(installed));
}

#[tokio::test]
async fn a_replayed_lockfile_keeps_the_sha512_of_the_bytes_it_fetched() {
    replay_records_the_sha512(single_project(), "node_modules/pinned/package.json", &[]).await;
}

#[tokio::test]
async fn a_replayed_lockfile_keeps_the_sha512_of_a_file_backed_fetch() {
    replay_records_the_sha512(
        single_project(),
        "node_modules/pinned/package.json",
        &[("LPM_STREAM_FETCH", "0")],
    )
    .await;
}

#[tokio::test]
async fn a_replayed_workspace_lockfile_keeps_the_sha512_of_the_bytes_it_fetched() {
    replay_records_the_sha512(
        workspace(),
        "packages/app/node_modules/pinned/package.json",
        &[],
    )
    .await;
}

#[tokio::test]
async fn a_frozen_lockfile_keeps_the_integrity_it_was_written_with() {
    let registry = MockRegistry::start().await;
    let project = single_project();
    pinned_by(&project, &registry, sha1_of).await;
    let pinned = project.read_file("lpm.lock");

    lpm_with_registry(&project, &registry.url())
        .args(INSTALL)
        .arg("--frozen-lockfile")
        .assert()
        .success();

    assert_eq!(project.read_file("lpm.lock"), pinned);
    assert!(project.file_exists("node_modules/pinned/package.json"));
}

/// A lockfile that can't be rewritten keeps its SHA-1 pin, and the store
/// keeps the package under the sha512 of its bytes. The store remembers
/// which bytes a fetch checked against the pin, so only the first install
/// downloads them.
async fn a_pin_that_stays_is_downloaded_once(project: TempProject, installed: &str) {
    let registry = MockRegistry::start().await;
    pinned_by(&project, &registry, sha1_of).await;
    let pinned = project.read_file("lpm.lock");
    let fetched_before = registry.tarball_request_count("pinned", "1.0.0").await;
    let frozen_install = || {
        let mut install = lpm_with_registry(&project, &registry.url());
        install.args(INSTALL).arg("--frozen-lockfile");
        install
    };

    frozen_install().assert().success();
    assert_eq!(
        registry.tarball_request_count("pinned", "1.0.0").await,
        fetched_before + 1
    );

    forget_install(&project);
    frozen_install().assert().success();

    assert_eq!(
        registry.tarball_request_count("pinned", "1.0.0").await,
        fetched_before + 1,
        "the store names the package its pin was checked against"
    );
    assert_eq!(project.read_file("lpm.lock"), pinned);
    assert!(project.file_exists(installed));

    forget_install(&project);
    frozen_install().arg("--offline").assert().success();
    assert!(project.file_exists(installed));

    // A lockfile that could take the sha512 keeps its pin too: only a
    // download of the install itself changes it.
    forget_install(&project);
    lpm_with_registry(&project, &registry.url())
        .args(INSTALL)
        .assert()
        .success();
    assert_eq!(
        registry.tarball_request_count("pinned", "1.0.0").await,
        fetched_before + 1
    );
    assert_eq!(project.read_file("lpm.lock"), pinned);
    assert!(project.file_exists(installed));
}

/// A registry that publishes only a SHA-1 signs over it. The lockfile row
/// keeps that integrity beside the signature, which a replay then
/// verifies, and the store finds the package by its record.
#[tokio::test]
async fn a_signed_package_published_by_a_weaker_hash_keeps_it_and_is_downloaded_once() {
    let registry = MockRegistry::start().await;
    let signer = RegistrySigningFixture::new();
    registry.with_registry_signing_keys(&signer).await;
    let tarball = make_tarball("pinned", "1.0.0");
    let published = sha1_of(&tarball);
    let mut metadata = registry.package_metadata("pinned", "1.0.0", &tarball);
    metadata["versions"]["1.0.0"]["dist"]["integrity"] = serde_json::json!(published);
    metadata["versions"]["1.0.0"]["dist"]["signatures"] =
        serde_json::json!([signer.signature_json("pinned", "1.0.0", &published)]);
    registry
        .with_package_metadata("pinned", "1.0.0", &tarball, metadata.clone())
        .await;
    registry.with_batch_metadata(vec![metadata]).await;
    let project = single_project();
    let lpm_dir = project.home().join(".lpm");
    std::fs::create_dir_all(&lpm_dir).unwrap();
    std::fs::write(lpm_dir.join("config.toml"), "signatures = true\n").unwrap();

    lpm_with_registry(&project, &registry.url())
        .args(INSTALL)
        .assert()
        .success();

    let lockfile = project.read_file("lpm.lock");
    assert!(lockfile.contains(&published), "{lockfile}");
    assert!(
        !lockfile.contains(&compute_integrity(&tarball)),
        "{lockfile}"
    );
    let fetched = registry.tarball_request_count("pinned", "1.0.0").await;

    forget_install(&project);
    lpm_with_registry(&project, &registry.url())
        .args(INSTALL)
        .arg("--frozen-lockfile")
        .assert()
        .success();

    assert_eq!(
        registry.tarball_request_count("pinned", "1.0.0").await,
        fetched
    );
    assert!(project.file_exists("node_modules/pinned/package.json"));
}

/// What the store remembers is the pin a fetch checked. A lockfile that
/// pins the same package by another integrity is checked against the
/// registry's bytes like any other.
#[tokio::test]
async fn the_store_answers_only_for_the_pin_a_fetch_checked() {
    let registry = MockRegistry::start().await;
    let project = single_project();
    pinned_by(&project, &registry, sha1_of).await;
    let checked = sha1_of(&make_tarball("pinned", "1.0.0"));
    let frozen_install = || {
        let mut install = lpm_with_registry(&project, &registry.url());
        install.args(INSTALL).arg("--frozen-lockfile");
        install
    };
    frozen_install().assert().success();
    let fetched = registry.tarball_request_count("pinned", "1.0.0").await;

    forget_install(&project);
    let another = sha1_of(b"another archive");
    project.write_file(
        "lpm.lock",
        &project.read_file("lpm.lock").replace(&checked, &another),
    );
    frozen_install().assert().failure();

    assert_eq!(
        registry.tarball_request_count("pinned", "1.0.0").await,
        fetched + 1
    );
    assert!(!project.file_exists("node_modules/pinned/package.json"));
}

#[tokio::test]
async fn a_frozen_lockfile_pinned_by_a_weaker_hash_downloads_its_package_once() {
    a_pin_that_stays_is_downloaded_once(single_project(), "node_modules/pinned/package.json").await;
}

#[tokio::test]
async fn a_frozen_workspace_lockfile_pinned_by_a_weaker_hash_downloads_its_package_once() {
    a_pin_that_stays_is_downloaded_once(
        workspace(),
        "packages/app/node_modules/pinned/package.json",
    )
    .await;
}

#[tokio::test]
async fn a_pin_the_fetched_bytes_do_not_match_fails_the_install_and_stays() {
    let registry = MockRegistry::start().await;
    let project = single_project();
    pinned_by(&project, &registry, |_| sha1_of(b"another archive")).await;
    let pinned = project.read_file("lpm.lock");

    lpm_with_registry(&project, &registry.url())
        .args(INSTALL)
        .assert()
        .failure();

    assert_eq!(project.read_file("lpm.lock"), pinned);
    assert!(!project.file_exists("node_modules/pinned/package.json"));
}

const REFRESHED_URL_NOTICE: &str = "stale tarball URL";

/// Installs the single project, then leaves it as a fresh checkout: the
/// lockfile, nothing installed, nothing in the store.
async fn fresh_checkout(registry: &MockRegistry) -> TempProject {
    let project = single_project();
    registry
        .with_package("pinned", "1.0.0", &make_tarball("pinned", "1.0.0"))
        .await;
    lpm_with_registry(&project, &registry.url())
        .args(INSTALL)
        .assert()
        .success();
    forget_install(&project);
    std::fs::remove_dir_all(project.store_dir()).unwrap();
    project
}

fn output_of(install: &std::process::Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&install.stdout),
        String::from_utf8_lossy(&install.stderr)
    )
}

#[tokio::test]
async fn a_download_from_the_locked_url_is_not_reported_as_a_refreshed_url() {
    let registry = MockRegistry::start().await;
    let project = fresh_checkout(&registry).await;
    let locked = project.read_file("lpm.lock");

    let install = lpm_with_registry(&project, &registry.url())
        .args(INSTALL)
        .assert()
        .success();

    let output = output_of(install.get_output());
    assert!(!output.contains(REFRESHED_URL_NOTICE), "{output}");
    assert_eq!(project.read_file("lpm.lock"), locked);
    assert!(project.file_exists("node_modules/pinned/package.json"));
}

#[tokio::test]
async fn a_download_from_a_registry_an_npmrc_names_is_not_reported_as_a_refreshed_url() {
    let registry = MockRegistry::start().await;
    let scoped = MockRegistry::start().await;
    scoped
        .with_package(
            "@acme/pinned",
            "1.0.0",
            &make_tarball("@acme/pinned", "1.0.0"),
        )
        .await;
    let project = TempProject::empty(
        r#"{"name":"consumer","version":"1.0.0","dependencies":{"@acme/pinned":"1.0.0"}}"#,
    );
    project.write_file(".npmrc", &format!("@acme:registry={}/\n", scoped.url()));
    lpm_with_registry(&project, &registry.url())
        .args(INSTALL)
        .assert()
        .success();
    forget_install(&project);
    std::fs::remove_dir_all(project.store_dir()).unwrap();
    let locked = project.read_file("lpm.lock");
    assert!(locked.contains(&scoped.url()), "{locked}");

    let install = lpm_with_registry(&project, &registry.url())
        .args(INSTALL)
        .assert()
        .success();

    let output = output_of(install.get_output());
    assert!(!output.contains(REFRESHED_URL_NOTICE), "{output}");
    assert_eq!(project.read_file("lpm.lock"), locked);
    assert!(project.file_exists("node_modules/@acme/pinned/package.json"));
}

#[tokio::test]
async fn a_download_from_another_url_than_the_locked_one_is_recorded_and_reported() {
    let registry = MockRegistry::start().await;
    let project = fresh_checkout(&registry).await;
    let locked = project.read_file("lpm.lock");
    let served = registry.tarball_url("pinned", "1.0.0");
    assert!(locked.contains(&served), "{locked}");
    project.write_file(
        "lpm.lock",
        &locked.replace(&served, &format!("{served}.moved")),
    );

    let install = lpm_with_registry(&project, &registry.url())
        .args(INSTALL)
        .assert()
        .success();

    let output = output_of(install.get_output());
    assert!(output.contains(REFRESHED_URL_NOTICE), "{output}");
    assert_eq!(project.read_file("lpm.lock"), locked);
}
