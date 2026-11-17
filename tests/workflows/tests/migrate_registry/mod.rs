//! The registries a migrated lockfile came from, and the integrity it locked.
//!
//! A foreign lockfile records where each package came from. A package that
//! came from a private registry must still come from it, or a same-named
//! package on the public registry would take its place; and a package
//! installed at the version the lockfile locked must have the bytes it
//! recorded.

use crate::support::mock_registry::{
    MockRegistry, RegistrySigningFixture, compute_integrity, make_tarball_with_files,
};
use crate::support::{TempProject, lpm_with_registry};
use std::process::Output;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

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
    assert!(
        !project.file_exists(".lpm/migrate-backup")
            && !project.file_exists(".lpm-migrate-manifest.json"),
        "a refused migration left a backup behind"
    );
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
    let changes = envelope["registry_changes"].as_array().unwrap();
    assert_eq!(changes.len(), 1, "{changes:?}");
    assert_eq!(changes[0]["name"], "corp-utils");
    assert_eq!(changes[0]["version"], "1.0.0");
    assert_eq!(
        changes[0]["from"],
        mirror.tarball_url("corp-utils", "1.0.0")
    );
    assert_eq!(
        changes[0]["to"], "https://registry.npmjs.org",
        "the registry is named by what LPM routes to, not by the transport a test redirects"
    );
    assert!(
        requests_for(&public, "corp-utils").await > 0,
        "the package wasn't fetched from npm"
    );
    assert_eq!(requests_for(&mirror, "corp-utils").await, 0);
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

fn workspace_package_lock(resolved: &str, integrity: &str) -> String {
    serde_json::json!({
        "name": "migration-host",
        "version": "1.0.0",
        "lockfileVersion": 3,
        "packages": {
            "": {
                "name": "migration-host",
                "version": "1.0.0",
                "workspaces": ["packages/*"]
            },
            "packages/app": {
                "name": "app",
                "version": "1.0.0",
                "dependencies": { "corp-utils": "1.0.0" }
            },
            "node_modules/app": { "resolved": "packages/app", "link": true },
            "node_modules/corp-utils": {
                "version": "1.0.0",
                "resolved": resolved,
                "integrity": integrity
            }
        }
    })
    .to_string()
}

#[tokio::test]
async fn migrate_refuses_a_workspace_members_package_with_other_bytes_at_the_locked_version() {
    let registries = registries().await;
    let project = TempProject::empty(
        r#"{"name":"migration-host","version":"1.0.0","private":true,"workspaces":["packages/*"]}"#,
    );
    project.write_file(
        "packages/app/package.json",
        r#"{"name":"app","version":"1.0.0","dependencies":{"corp-utils":"1.0.0"}}"#,
    );
    project.write_file(
        "package-lock.json",
        &workspace_package_lock(
            &registries.private.tarball_url("corp-utils", "1.0.0"),
            &registries.private_integrity,
        ),
    );

    let output = migrate(&project, &registries.public, &["--allow-registry-change"]);

    assert!(!output.status.success(), "{}", report(&output));
    let text = report(&output);
    assert!(
        text.contains("corp-utils@1.0.0") && text.contains("integrity"),
        "{text}"
    );
    assert!(!project.file_exists("node_modules/corp-utils"));
    assert!(!project.file_exists("packages/app/node_modules/corp-utils"));
}

#[tokio::test]
async fn an_install_after_migrating_without_installing_still_refuses_other_bytes_at_the_locked_version()
 {
    let registries = registries().await;
    let project = TempProject::empty(PROJECT);
    project.write_file(
        "package-lock.json",
        &package_lock(
            &registries.private.tarball_url("corp-utils", "1.0.0"),
            &registries.private_integrity,
        ),
    );
    let migrated = migrate(
        &project,
        &registries.public,
        &["--allow-registry-change", "--no-install"],
    );
    assert!(migrated.status.success(), "{}", report(&migrated));

    let installed = lpm_with_registry(&project, &registries.public.url())
        .args(["install", "--json"])
        .output()
        .unwrap();

    assert!(!installed.status.success(), "{}", report(&installed));
    let text = report(&installed);
    assert!(
        text.contains("corp-utils@1.0.0") && text.contains("integrity"),
        "{text}"
    );
    assert!(!project.file_exists("node_modules/corp-utils"));
    assert!(
        project
            .read_file("lpm.lock")
            .contains("resolved-with = \"migrate\""),
        "a refused install replaced the migrated lockfile and its integrities"
    );
}

#[tokio::test]
async fn migrate_refuses_a_bun_scope_lpm_does_not_route() {
    let public = MockRegistry::start().await;
    let private = MockRegistry::start().await;
    let tarball = make_tarball_with_files("@corp/utils", "1.0.0", &[("origin.txt", b"private")]);
    let project = TempProject::empty(
        r#"{"name":"migration-host","version":"1.0.0","dependencies":{"@corp/utils":"1.0.0"}}"#,
    );
    project.write_file(
        "bun.lock",
        &serde_json::json!({
            "lockfileVersion": 1,
            "workspaces": {
                "": {
                    "name": "migration-host",
                    "dependencies": { "@corp/utils": "1.0.0" }
                }
            },
            "packages": {
                "@corp/utils": ["@corp/utils@1.0.0", "", {}, compute_integrity(&tarball)]
            }
        })
        .to_string(),
    );
    project.write_file(
        "bunfig.toml",
        &format!("[install.scopes]\ncorp = \"{}/\"\n", private.url()),
    );

    let output = migrate(&project, &public, &[]);

    assert!(!output.status.success(), "{}", report(&output));
    let text = report(&output);
    assert!(text.contains("@corp/utils@1.0.0"), "{text}");
    assert!(text.contains(&private.url()), "{text}");
    assert_eq!(requests_for(&public, "utils").await, 0);
    assert!(!project.file_exists("lpm.lock"));
}

#[tokio::test]
async fn migrate_installs_a_tarball_url_dependency_from_its_url() {
    let public = MockRegistry::start().await;
    let cdn = MockServer::start().await;
    let tarball = make_tarball_with_files("xlsx", "0.20.3", &[("origin.txt", b"cdn")]);
    Mock::given(method("GET"))
        .and(path("/xlsx-0.20.3/xlsx-0.20.3.tgz"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(tarball.clone()))
        .mount(&cdn)
        .await;
    let url = format!("{}/xlsx-0.20.3/xlsx-0.20.3.tgz", cdn.uri());
    let project = TempProject::empty(
        &serde_json::json!({
            "name": "migration-host",
            "version": "1.0.0",
            "dependencies": { "xlsx": url }
        })
        .to_string(),
    );
    project.write_file(
        "package-lock.json",
        &serde_json::json!({
            "name": "migration-host",
            "version": "1.0.0",
            "lockfileVersion": 3,
            "packages": {
                "": {
                    "name": "migration-host",
                    "version": "1.0.0",
                    "dependencies": { "xlsx": url }
                },
                "node_modules/xlsx": {
                    "version": "0.20.3",
                    "resolved": url,
                    "integrity": compute_integrity(&tarball)
                }
            }
        })
        .to_string(),
    );

    let output = migrate(&project, &public, &[]);

    assert!(output.status.success(), "{}", report(&output));
    assert_eq!(project.read_file("node_modules/xlsx/origin.txt"), "cdn");
}

#[tokio::test]
async fn migrate_installs_an_aliased_package_from_the_registry_its_scope_routes_to() {
    let public = MockRegistry::start().await;
    let private = MockRegistry::start().await;
    let tarball = make_tarball_with_files("@corp/utils", "1.0.0", &[("origin.txt", b"private")]);
    private.with_package("@corp/utils", "1.0.0", &tarball).await;
    let project = TempProject::empty(
        r#"{"name":"migration-host","version":"1.0.0","dependencies":{"utils":"npm:@corp/utils@1.0.0"}}"#,
    );
    project.write_file(
        "package-lock.json",
        &serde_json::json!({
            "name": "migration-host",
            "version": "1.0.0",
            "lockfileVersion": 3,
            "packages": {
                "": {
                    "name": "migration-host",
                    "version": "1.0.0",
                    "dependencies": { "utils": "npm:@corp/utils@1.0.0" }
                },
                "node_modules/utils": {
                    "name": "@corp/utils",
                    "version": "1.0.0",
                    "resolved": private.tarball_url("@corp/utils", "1.0.0"),
                    "integrity": compute_integrity(&tarball)
                }
            }
        })
        .to_string(),
    );
    project.write_file(".npmrc", &format!("@corp:registry={}/\n", private.url()));

    let output = migrate(&project, &public, &[]);

    assert!(output.status.success(), "{}", report(&output));
    assert_eq!(
        project.read_file("node_modules/utils/origin.txt"),
        "private"
    );
    assert_eq!(requests_for(&public, "utils").await, 0);
}

fn files_containing(root: &std::path::Path, name: &str, content: &[u8]) -> Vec<std::path::PathBuf> {
    let mut found = Vec::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        let Ok(entries) = std::fs::read_dir(&directory) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            match entry.file_type() {
                Ok(kind) if kind.is_dir() => pending.push(path),
                Ok(kind)
                    if kind.is_file()
                        && entry.file_name() == name
                        && std::fs::read(&path).is_ok_and(|bytes| bytes == content) =>
                {
                    found.push(path);
                }
                _ => {}
            }
        }
    }
    found
}

#[tokio::test]
async fn migrate_refuses_a_tarball_dependency_whose_url_now_serves_other_bytes_before_storing_them()
{
    let public = MockRegistry::start().await;
    let cdn = MockServer::start().await;
    let original = make_tarball_with_files("actual", "1.0.0", &[("origin.txt", b"original")]);
    let swapped = make_tarball_with_files("actual", "1.0.0", &[("origin.txt", b"swapped")]);
    Mock::given(method("GET"))
        .and(path("/actual-1.0.0.tgz"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(swapped))
        .mount(&cdn)
        .await;
    let url = format!("{}/actual-1.0.0.tgz", cdn.uri());
    let project = TempProject::empty(
        &serde_json::json!({
            "name": "migration-host",
            "version": "1.0.0",
            "dependencies": { "shim": url }
        })
        .to_string(),
    );
    project.write_file(
        "package-lock.json",
        &serde_json::json!({
            "name": "migration-host",
            "version": "1.0.0",
            "lockfileVersion": 3,
            "packages": {
                "": {
                    "name": "migration-host",
                    "version": "1.0.0",
                    "dependencies": { "shim": url }
                },
                "node_modules/shim": {
                    "name": "actual",
                    "version": "1.0.0",
                    "resolved": url,
                    "integrity": compute_integrity(&original)
                }
            }
        })
        .to_string(),
    );

    let output = migrate(&project, &public, &[]);

    assert!(!output.status.success(), "{}", report(&output));
    let text = report(&output);
    assert!(
        text.contains("integrity") && text.contains("lpm migrate --rollback"),
        "{text}"
    );
    assert!(!project.file_exists("node_modules/shim"));
    assert_eq!(
        files_containing(project.home(), "origin.txt", b"swapped"),
        Vec::<std::path::PathBuf>::new(),
        "the other bytes were extracted before the check refused them"
    );
}

#[tokio::test]
async fn migrate_names_a_registry_built_from_environment_variables_without_printing_their_values() {
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
            "npmScopes:\n  corp:\n    npmRegistryServer: \"{}/${{REG_TOKEN}}/npm/\"\n",
            private.url()
        ),
    );

    let output = lpm_with_registry(&project, &public.url())
        .env("REG_TOKEN", "tok_4f9a2c")
        .args([
            "migrate",
            "--skip-verify",
            "--no-npmrc",
            "--no-ci",
            "--json",
        ])
        .output()
        .unwrap();

    assert!(!output.status.success(), "{}", report(&output));
    let text = report(&output);
    assert!(text.contains("@corp/utils@1.0.0"), "{text}");
    assert!(text.contains("npmScopes.corp.npmRegistryServer"), "{text}");
    assert!(
        !text.contains("tok_4f9a2c"),
        "a value from the environment was printed:\n{text}"
    );
    assert!(!project.file_exists("lpm.lock"));
}

async fn tarball_requests_for(registry: &MockRegistry, name: &str) -> usize {
    registry
        .server()
        .received_requests()
        .await
        .expect("wiremock request log must be available")
        .iter()
        .filter(|request| request.url.path().contains(name) && request.url.path().ends_with(".tgz"))
        .count()
}

#[tokio::test]
async fn a_package_refused_at_its_locked_version_is_never_downloaded() {
    let registries = registries().await;
    let project = TempProject::empty(PROJECT);
    project.write_file(
        "package-lock.json",
        &package_lock(
            &registries.private.tarball_url("corp-utils", "1.0.0"),
            &registries.private_integrity,
        ),
    );

    // Downloads would otherwise start from the first selected package.
    let output = lpm_with_registry(&project, &registries.public.url())
        .env("LPM_FETCH_OVERLAP", "1")
        .env("LPM_FETCH_OVERLAP_MIN_SELECTED", "1")
        .args([
            "migrate",
            "--skip-verify",
            "--no-npmrc",
            "--no-ci",
            "--json",
            "--allow-registry-change",
        ])
        .output()
        .unwrap();

    assert!(!output.status.success(), "{}", report(&output));
    assert_eq!(
        tarball_requests_for(&registries.public, "corp-utils").await,
        0,
        "the tarball was downloaded before its integrity was checked"
    );
}

#[tokio::test]
async fn an_install_with_the_experimental_resolver_requested_still_holds_the_locked_integrity() {
    let registries = registries().await;
    let project = TempProject::empty(PROJECT);
    project.write_file(
        "package-lock.json",
        &package_lock(
            &registries.private.tarball_url("corp-utils", "1.0.0"),
            &registries.private_integrity,
        ),
    );
    let migrated = migrate(
        &project,
        &registries.public,
        &["--allow-registry-change", "--no-install"],
    );
    assert!(migrated.status.success(), "{}", report(&migrated));

    let installed = lpm_with_registry(&project, &registries.public.url())
        .env("LPM_EXPERIMENTAL_INSTALLER_SPIKE", "1")
        .env("LPM_INSTALLER_SPIKE_GRAPH", "resolve-worklist")
        .args(["install", "--json", "--no-security-summary", "--no-skills"])
        .output()
        .unwrap();

    assert!(!installed.status.success(), "{}", report(&installed));
    let text = report(&installed);
    assert!(
        text.contains("corp-utils@1.0.0") && text.contains("integrity"),
        "{text}"
    );
    assert!(!project.file_exists("node_modules/corp-utils"));
}

fn workspace_project(registry: &MockRegistry, integrity: &str) -> TempProject {
    let project = TempProject::empty(
        r#"{"name":"migration-host","version":"1.0.0","private":true,"workspaces":["packages/*"]}"#,
    );
    for member in ["app", "lib"] {
        project.write_file(
            &format!("packages/{member}/package.json"),
            &format!(
                r#"{{"name":"{member}","version":"1.0.0","dependencies":{{"corp-utils":"1.0.0"}}}}"#
            ),
        );
    }
    project.write_file(
        "package-lock.json",
        &serde_json::json!({
            "name": "migration-host",
            "version": "1.0.0",
            "lockfileVersion": 3,
            "packages": {
                "": { "name": "migration-host", "version": "1.0.0", "workspaces": ["packages/*"] },
                "packages/app": { "name": "app", "version": "1.0.0", "dependencies": { "corp-utils": "1.0.0" } },
                "packages/lib": { "name": "lib", "version": "1.0.0", "dependencies": { "corp-utils": "1.0.0" } },
                "node_modules/app": { "resolved": "packages/app", "link": true },
                "node_modules/lib": { "resolved": "packages/lib", "link": true },
                "node_modules/corp-utils": {
                    "version": "1.0.0",
                    "resolved": registry.tarball_url("corp-utils", "1.0.0"),
                    "integrity": integrity
                }
            }
        })
        .to_string(),
    );
    project.write_file(".npmrc", &format!("registry={}/\n", registry.url()));
    project
}

#[tokio::test]
async fn migrating_a_workspace_installs_every_member_held_to_its_locked_integrity() {
    let registries = registries().await;
    let project = workspace_project(&registries.private, &registries.private_integrity);

    let output = migrate(&project, &registries.public, &[]);

    assert!(output.status.success(), "{}", report(&output));
    assert!(
        !project
            .read_file("lpm.lock")
            .contains("resolved-with = \"migrate\"")
    );
}

#[tokio::test]
async fn installing_one_workspace_member_over_a_migrated_lockfile_is_refused_until_all_are_checked()
{
    let registries = registries().await;
    let project = workspace_project(&registries.private, &registries.private_integrity);
    let migrated = migrate(&project, &registries.public, &["--no-install"]);
    assert!(migrated.status.success(), "{}", report(&migrated));

    let installed = lpm_with_registry(&project, &registries.public.url())
        .current_dir(project.path().join("packages/app"))
        .args(["install", "--json"])
        .output()
        .unwrap();

    assert!(!installed.status.success(), "{}", report(&installed));
    assert!(
        report(&installed).contains("from the workspace root"),
        "{}",
        report(&installed)
    );
    assert!(
        !project.file_exists("packages/app/node_modules/corp-utils")
            && !project.file_exists("node_modules/corp-utils"),
        "the member's install ran before it was refused"
    );
    assert!(
        project
            .read_file("lpm.lock")
            .contains("resolved-with = \"migrate\""),
        "a partial install replaced the migrated lockfile"
    );
}

#[tokio::test]
async fn registry_signatures_are_checked_against_the_published_integrity_when_the_recorded_one_is_stronger()
 {
    let public = MockRegistry::start().await;
    let signer = RegistrySigningFixture::new();
    public.with_registry_signing_keys(&signer).await;
    let tarball = make_tarball_with_files("corp-utils", "1.0.0", &[("origin.txt", b"signed")]);
    let published =
        lpm_common::Integrity::from_bytes(lpm_common::integrity::HashAlgorithm::Sha1, &tarball)
            .to_string();
    let mut metadata = public.package_metadata("corp-utils", "1.0.0", &tarball);
    metadata["versions"]["1.0.0"]["dist"]["integrity"] = serde_json::json!(published);
    metadata["versions"]["1.0.0"]["dist"]["signatures"] =
        serde_json::json!([signer.signature_json("corp-utils", "1.0.0", &published)]);
    public
        .with_package_metadata("corp-utils", "1.0.0", &tarball, metadata.clone())
        .await;
    public.with_batch_metadata(vec![metadata]).await;
    let project = TempProject::empty(PROJECT);
    project.write_file(
        "package-lock.json",
        &package_lock(
            &public.tarball_url("corp-utils", "1.0.0"),
            &compute_integrity(&tarball),
        ),
    );
    project.write_file(".npmrc", &format!("registry={}/\n", public.url()));
    let lpm_dir = project.home().join(".lpm");
    std::fs::create_dir_all(&lpm_dir).unwrap();
    std::fs::write(lpm_dir.join("config.toml"), "signatures = true\n").unwrap();

    let output = migrate(&project, &public, &[]);

    assert!(output.status.success(), "{}", report(&output));
    assert_eq!(
        project.read_file("node_modules/corp-utils/origin.txt"),
        "signed"
    );
    let replay = lpm_with_registry(&project, &public.url())
        .args(["install", "--frozen-lockfile", "--json"])
        .output()
        .unwrap();
    assert!(
        replay.status.success(),
        "a replay of the migrated install must verify the same signatures:\n{}",
        report(&replay)
    );
}

/// The install held the download to the hash the lockfile recorded. The
/// registry's own, weaker hash was never checked against those bytes, so
/// the store must not remember it as naming them.
#[tokio::test]
async fn the_store_records_no_check_of_a_published_integrity_the_download_was_not_held_to() {
    let public = MockRegistry::start().await;
    let tarball = make_tarball_with_files("corp-utils", "1.0.0", &[("origin.txt", b"recorded")]);
    let published = lpm_common::Integrity::from_bytes(
        lpm_common::integrity::HashAlgorithm::Sha1,
        b"another archive",
    )
    .to_string();
    let mut metadata = public.package_metadata("corp-utils", "1.0.0", &tarball);
    metadata["versions"]["1.0.0"]["dist"]["integrity"] = serde_json::json!(published);
    if let Some(dist) = metadata["versions"]["1.0.0"]["dist"].as_object_mut() {
        dist.remove("shasum");
    }
    public
        .with_package_metadata("corp-utils", "1.0.0", &tarball, metadata.clone())
        .await;
    public.with_batch_metadata(vec![metadata]).await;
    let project = TempProject::empty(PROJECT);
    project.write_file(
        "package-lock.json",
        &package_lock(
            &public.tarball_url("corp-utils", "1.0.0"),
            &compute_integrity(&tarball),
        ),
    );
    project.write_file(".npmrc", &format!("registry={}/\n", public.url()));

    let output = migrate(&project, &public, &[]);

    assert!(output.status.success(), "{}", report(&output));
    assert_eq!(
        project.read_file("node_modules/corp-utils/origin.txt"),
        "recorded"
    );
    let records = project.store_dir().join("v2").join("checked-pins");
    let recorded: Vec<_> = std::fs::read_dir(&records)
        .map(|entries| entries.map(|entry| entry.unwrap().file_name()).collect())
        .unwrap_or_default();
    assert!(recorded.is_empty(), "{recorded:?}");
}

#[tokio::test]
async fn migrate_names_the_destination_registry_without_values_npmrc_expanded_into_it() {
    let registries = registries().await;
    let project = TempProject::empty(PROJECT);
    project.write_file(
        "package-lock.json",
        &package_lock(
            &registries.private.tarball_url("corp-utils", "1.0.0"),
            &registries.private_integrity,
        ),
    );
    std::fs::write(
        project.home().join(".npmrc"),
        format!("registry={}/${{REG_TOKEN}}/npm/\n", registries.public.url()),
    )
    .unwrap();

    let output = lpm_with_registry(&project, &registries.public.url())
        .env("REG_TOKEN", "tok_8c1e5d")
        .args([
            "migrate",
            "--skip-verify",
            "--no-npmrc",
            "--no-ci",
            "--json",
        ])
        .output()
        .unwrap();

    assert!(!output.status.success(), "{}", report(&output));
    let text = report(&output);
    assert!(text.contains("corp-utils@1.0.0"), "{text}");
    assert!(
        !text.contains("tok_8c1e5d"),
        "a value .npmrc expanded was printed:\n{text}"
    );
}

#[tokio::test]
async fn a_migrated_lockfile_records_only_the_origin_of_a_registry_built_from_environment_variables()
 {
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
            "npmScopes:\n  corp:\n    npmRegistryServer: \"{}/${{REG_TOKEN}}/npm/\"\n",
            private.url()
        ),
    );
    std::fs::write(
        project.home().join(".npmrc"),
        format!("@corp:registry={}/${{REG_TOKEN}}/npm/\n", private.url()),
    )
    .unwrap();

    let output = lpm_with_registry(&project, &public.url())
        .env("REG_TOKEN", "tok_3b7f90")
        .args([
            "migrate",
            "--skip-verify",
            "--no-npmrc",
            "--no-ci",
            "--json",
            "--no-install",
        ])
        .output()
        .unwrap();

    assert!(output.status.success(), "{}", report(&output));
    assert!(
        !report(&output).contains("tok_3b7f90"),
        "{}",
        report(&output)
    );
    let lockfile = project.read_file("lpm.lock");
    assert!(!lockfile.contains("tok_3b7f90"), "{lockfile}");
    assert!(
        lockfile.contains(&format!("source = \"registry+{}/\"", private.url())),
        "{lockfile}"
    );
}

#[tokio::test]
async fn deploying_a_member_of_a_migrated_workspace_waits_for_a_workspace_install() {
    let registries = registries().await;
    let project = workspace_project(&registries.private, &registries.private_integrity);
    let migrated = migrate(&project, &registries.public, &["--no-install"]);
    assert!(migrated.status.success(), "{}", report(&migrated));
    let out = tempfile::tempdir().unwrap();

    let deployed = lpm_with_registry(&project, &registries.public.url())
        .args(["deploy", out.path().to_str().unwrap(), "--filter", "app"])
        .output()
        .unwrap();

    assert!(!deployed.status.success(), "{}", report(&deployed));
    assert!(
        report(&deployed).contains("lpm install"),
        "{}",
        report(&deployed)
    );
    assert_eq!(std::fs::read_dir(out.path()).unwrap().count(), 0);
}
