//! The registries a migrated lockfile came from, and the integrity it locked.
//!
//! A foreign lockfile records where each package came from. A package that
//! came from a private registry must still come from it, or a same-named
//! package on the public registry would take its place; and a package
//! installed at the version the lockfile locked must have the bytes it
//! recorded.

use crate::support::mock_registry::{MockRegistry, compute_integrity, make_tarball_with_files};
use crate::support::{TempProject, lpm_with_registry};
use std::process::Output;

const PROJECT: &str =
    r#"{"name":"migration-host","version":"1.0.0","dependencies":{"corp-utils":"1.0.0"}}"#;

struct Registries {
    public: MockRegistry,
    private: MockRegistry,
    private_integrity: String,
    public_integrity: String,
}

/// npm's registry and a private one, both serving a `corp-utils@1.0.0`
/// whose `origin.txt` names the registry it came from.
async fn registries() -> Registries {
    let public = MockRegistry::start().await;
    let private = MockRegistry::start().await;
    let private_tarball =
        make_tarball_with_files("corp-utils", "1.0.0", &[("origin.txt", b"private")]);
    let public_tarball =
        make_tarball_with_files("corp-utils", "1.0.0", &[("origin.txt", b"public")]);
    private
        .with_package("corp-utils", "1.0.0", &private_tarball)
        .await;
    public
        .with_package("corp-utils", "1.0.0", &public_tarball)
        .await;
    Registries {
        public,
        private,
        private_integrity: compute_integrity(&private_tarball),
        public_integrity: compute_integrity(&public_tarball),
    }
}

fn package_lock(resolved: &str, integrity: &str) -> String {
    serde_json::json!({
        "name": "migration-host",
        "version": "1.0.0",
        "lockfileVersion": 3,
        "packages": {
            "": {
                "name": "migration-host",
                "version": "1.0.0",
                "dependencies": { "corp-utils": "1.0.0" }
            },
            "node_modules/corp-utils": {
                "version": "1.0.0",
                "resolved": resolved,
                "integrity": integrity
            }
        }
    })
    .to_string()
}

fn migrate(project: &TempProject, npm: &MockRegistry, extra: &[&str]) -> Output {
    lpm_with_registry(project, &npm.url())
        .args([
            "migrate",
            "--skip-verify",
            "--no-npmrc",
            "--no-ci",
            "--json",
        ])
        .args(extra)
        .output()
        .unwrap()
}

fn report(output: &Output) -> String {
    format!(
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

async fn requests_for(registry: &MockRegistry, name: &str) -> usize {
    registry
        .server()
        .received_requests()
        .await
        .expect("wiremock request log must be available")
        .iter()
        .filter(|request| request.url.path().contains(name))
        .count()
}

#[tokio::test]
async fn migrate_refuses_a_package_locked_to_a_registry_lpm_would_not_fetch_it_from() {
    let registries = registries().await;
    let project = TempProject::empty(PROJECT);
    project.write_file(
        "package-lock.json",
        &package_lock(
            &registries.private.tarball_url("corp-utils", "1.0.0"),
            &registries.private_integrity,
        ),
    );

    let output = migrate(&project, &registries.public, &[]);

    assert!(!output.status.success(), "{}", report(&output));
    let text = report(&output);
    assert!(text.contains("corp-utils@1.0.0"), "{text}");
    assert!(text.contains(&registries.private.url()), "{text}");
    assert_eq!(
        requests_for(&registries.public, "corp-utils").await,
        0,
        "the public registry was asked for the private package"
    );
    assert!(
        !project.file_exists("lpm.lock"),
        "a refused migration wrote the lockfile"
    );
    assert!(!project.file_exists("node_modules/corp-utils"));
}

#[tokio::test]
async fn migrate_installs_a_package_from_the_registry_its_lockfile_names_when_npmrc_routes_it() {
    let registries = registries().await;
    let project = TempProject::empty(PROJECT);
    project.write_file(
        "package-lock.json",
        &package_lock(
            &registries.private.tarball_url("corp-utils", "1.0.0"),
            &registries.private_integrity,
        ),
    );
    project.write_file(
        ".npmrc",
        &format!("registry={}/\n", registries.private.url()),
    );

    let output = migrate(&project, &registries.public, &[]);

    assert!(output.status.success(), "{}", report(&output));
    assert_eq!(
        project.read_file("node_modules/corp-utils/origin.txt"),
        "private"
    );
    assert_eq!(requests_for(&registries.public, "corp-utils").await, 0);
}

#[tokio::test]
async fn migrate_with_registry_change_allowed_still_refuses_other_bytes_at_the_locked_version() {
    let registries = registries().await;
    let project = TempProject::empty(PROJECT);
    project.write_file(
        "package-lock.json",
        &package_lock(
            &registries.private.tarball_url("corp-utils", "1.0.0"),
            &registries.private_integrity,
        ),
    );

    let output = migrate(&project, &registries.public, &["--allow-registry-change"]);

    assert!(!output.status.success(), "{}", report(&output));
    let text = report(&output);
    assert!(text.contains("corp-utils@1.0.0"), "{text}");
    assert!(text.contains("integrity"), "{text}");
    assert!(!project.file_exists("node_modules/corp-utils"));
}

#[tokio::test]
async fn migrate_refuses_other_bytes_at_the_locked_version_from_the_registry_it_names() {
    let registries = registries().await;
    let project = TempProject::empty(PROJECT);
    project.write_file(
        "package-lock.json",
        &package_lock(
            &registries.private.tarball_url("corp-utils", "1.0.0"),
            &registries.public_integrity,
        ),
    );
    project.write_file(
        ".npmrc",
        &format!("registry={}/\n", registries.private.url()),
    );

    let output = migrate(&project, &registries.public, &[]);

    assert!(!output.status.success(), "{}", report(&output));
    assert!(report(&output).contains("integrity"), "{}", report(&output));
    assert!(!project.file_exists("node_modules/corp-utils"));
}

#[tokio::test]
async fn migrate_with_registry_change_allowed_moves_a_mirrored_package_to_npm() {
    let public = MockRegistry::start().await;
    let mirror = MockRegistry::start().await;
    let tarball = make_tarball_with_files("corp-utils", "1.0.0", &[("origin.txt", b"same")]);
    public.with_package("corp-utils", "1.0.0", &tarball).await;
    mirror.with_package("corp-utils", "1.0.0", &tarball).await;
    let project = TempProject::empty(PROJECT);
    project.write_file(
        "package-lock.json",
        &package_lock(
            &mirror.tarball_url("corp-utils", "1.0.0"),
            &compute_integrity(&tarball),
        ),
    );

    let output = migrate(&project, &public, &["--allow-registry-change"]);

    assert!(output.status.success(), "{}", report(&output));
    assert_eq!(
        project.read_file("node_modules/corp-utils/origin.txt"),
        "same"
    );
    let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        envelope["registry_changes"],
        serde_json::json!([{
            "name": "corp-utils",
            "version": "1.0.0",
            "from": mirror.tarball_url("corp-utils", "1.0.0"),
        }])
    );
}

#[tokio::test]
async fn migrate_refuses_a_yarn_scope_lpm_does_not_route() {
    let public = MockRegistry::start().await;
    let private = MockRegistry::start().await;
    let project = TempProject::empty(
        r#"{"name":"migration-host","version":"1.0.0","dependencies":{"@corp/utils":"1.0.0"}}"#,
    );
    project.write_file(
        "yarn.lock",
        "__metadata:\n  version: 8\n  cacheKey: 10\n\n\"@corp/utils@npm:1.0.0\":\n  version: 1.0.0\n  resolution: \"@corp/utils@npm:1.0.0\"\n  languageName: node\n  linkType: hard\n",
    );
    project.write_file(
        ".yarnrc.yml",
        &format!(
            "npmScopes:\n  corp:\n    npmRegistryServer: \"{}\"\n",
            private.url()
        ),
    );

    let output = migrate(&project, &public, &[]);

    assert!(!output.status.success(), "{}", report(&output));
    let text = report(&output);
    assert!(text.contains("@corp/utils@1.0.0"), "{text}");
    assert!(text.contains(&private.url()), "{text}");
    assert_eq!(requests_for(&public, "utils").await, 0);
    assert!(!project.file_exists("lpm.lock"));
}
