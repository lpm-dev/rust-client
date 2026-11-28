//! Workflow coverage for what two projects share in one package store.

mod support;

use std::path::{Path, PathBuf};

use lpm_common::integrity::{HashAlgorithm, Integrity};
use support::mock_registry::{MockRegistry, make_tarball_from_pkg_json};
use support::{TempProject, lpm_with_registry, write_signed_unlock_for};
use wiremock::matchers::{method, path};
use wiremock::{Mock, ResponseTemplate};

/// Project folders under one home, so they install into one package store.
struct Neighbours {
    holder: TempProject,
}

impl Neighbours {
    fn new() -> Self {
        let holder = TempProject::empty("{}");
        std::fs::remove_file(holder.path().join("package.json")).unwrap();
        Self { holder }
    }

    fn dir(&self, project: &str) -> PathBuf {
        self.holder.path().join(project)
    }

    fn write(&self, project: &str, rel_path: &str, content: &str) {
        self.holder
            .write_file(&format!("{project}/{rel_path}"), content);
    }

    fn install(&self, project: &str, registry: &MockRegistry) {
        self.install_with(project, registry, &[]);
    }

    fn install_with(&self, project: &str, registry: &MockRegistry, options: &[&str]) {
        lpm_with_registry(&self.holder, &registry.url())
            .current_dir(self.dir(project))
            .args(["install", "--no-skills", "--no-security-summary"])
            .args(options)
            .assert()
            .success();
    }

    fn forget_registry_answers(&self) {
        match std::fs::remove_dir_all(self.holder.cache_dir()) {
            Err(error) if error.kind() != std::io::ErrorKind::NotFound => panic!("{error}"),
            _ => {}
        }
    }

    /// The file a project's own code would load from one of its packages.
    fn installed(&self, project: &str, rel_path: &str) -> String {
        let path = self.dir(project).join("node_modules").join(rel_path);
        std::fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("read {}: {error}", path.display()))
    }

    /// Where a project's `node_modules/<package>` leads once links are followed.
    fn store_entry(&self, project: &str, package: &str) -> PathBuf {
        self.dir(project)
            .join("node_modules")
            .join(package)
            .canonicalize()
            .unwrap()
    }

    /// Where a package's own code would find `dependency`.
    fn dependency_of(&self, project: &str, package: &str, dependency: &str) -> PathBuf {
        self.store_entry(project, package)
            .parent()
            .map(Path::to_path_buf)
            .unwrap()
            .join(dependency)
    }

    /// The file a package's own code would load from its dependency.
    fn seen_by(&self, project: &str, package: &str, dependency_file: &str) -> String {
        let path = self.dependency_of(project, package, dependency_file);
        std::fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("read {}: {error}", path.display()))
    }
}

async fn serve_family(registry: &MockRegistry, parent: &[u8], child_owner: &str) {
    registry
        .with_package_and_deps(
            "parent",
            "1.0.0",
            parent,
            serde_json::json!({ "child": "1.0.0" }),
        )
        .await;
    registry
        .with_package("child", "1.0.0", &owned_package("child", child_owner))
        .await;
}

/// Serves a version as registries did before `dist.integrity`: with a SHA-1
/// `shasum` only.
async fn serve_by_shasum(registry: &MockRegistry, name: &str, tarball: &[u8]) {
    let metadata = serde_json::json!({
        "name": name,
        "dist-tags": { "latest": "1.0.0" },
        "versions": {
            "1.0.0": {
                "name": name,
                "version": "1.0.0",
                "dist": {
                    "tarball": registry.tarball_url(name, "1.0.0"),
                    "shasum": hex::encode(Integrity::from_bytes(HashAlgorithm::Sha1, tarball).hash),
                },
            }
        },
        "time": { "1.0.0": "2025-01-01T00:00:00.000Z" },
    });
    for metadata_path in [format!("/api/registry/{name}"), format!("/{name}")] {
        Mock::given(method("GET"))
            .and(path(metadata_path))
            .respond_with(ResponseTemplate::new(200).set_body_json(metadata.clone()))
            .mount(registry.server())
            .await;
    }
    Mock::given(method("GET"))
        .and(path(MockRegistry::tarball_path(name, "1.0.0")))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_bytes(tarball.to_vec())
                .insert_header("content-type", "application/octet-stream"),
        )
        .mount(registry.server())
        .await;
}

fn owned_package(name: &str, owner: &str) -> Vec<u8> {
    make_tarball_from_pkg_json(
        serde_json::json!({ "name": name, "version": "1.0.0" }),
        &[("owner.txt", owner.as_bytes())],
    )
}

#[tokio::test]
async fn projects_with_a_local_package_at_the_same_relative_path_keep_their_own_files() {
    let registry = MockRegistry::start().await;
    let neighbours = Neighbours::new();
    for project in ["first", "second"] {
        neighbours.write(
            project,
            "package.json",
            r#"{"name":"consumer","version":"1.0.0","dependencies":{"local-lib":"file:./local-lib"}}"#,
        );
        neighbours.write(
            project,
            "local-lib/package.json",
            r#"{"name":"local-lib","version":"1.0.0"}"#,
        );
        neighbours.write(project, "local-lib/owner.txt", project);
    }

    neighbours.install("first", &registry);
    neighbours.install("second", &registry);

    assert_eq!(
        neighbours.installed("first", "local-lib/owner.txt"),
        "first"
    );
    assert_eq!(
        neighbours.installed("second", "local-lib/owner.txt"),
        "second"
    );

    std::fs::remove_dir_all(neighbours.dir("first").join("node_modules")).unwrap();
    neighbours.install("first", &registry);

    assert_eq!(
        neighbours.installed("first", "local-lib/owner.txt"),
        "first"
    );
    assert_eq!(
        neighbours.installed("second", "local-lib/owner.txt"),
        "second"
    );
}

#[tokio::test]
async fn projects_installing_one_version_from_two_registries_keep_their_own_bytes() {
    let neighbours = Neighbours::new();
    let mut registries = Vec::new();
    for project in ["first", "second"] {
        let registry = MockRegistry::start().await;
        registry
            .with_package("same-name", "1.0.0", &owned_package("same-name", project))
            .await;
        neighbours.write(
            project,
            "package.json",
            r#"{"name":"consumer","version":"1.0.0","dependencies":{"same-name":"1.0.0"}}"#,
        );
        registries.push(registry);
    }

    neighbours.install("first", &registries[0]);
    neighbours.forget_registry_answers();
    neighbours.install("second", &registries[1]);

    assert_eq!(
        neighbours.installed("first", "same-name/owner.txt"),
        "first"
    );
    assert_eq!(
        neighbours.installed("second", "same-name/owner.txt"),
        "second"
    );
}

#[tokio::test]
async fn a_package_keeps_the_dependency_bytes_its_project_installed() {
    let registry = MockRegistry::start().await;
    let neighbours = Neighbours::new();
    let parent = make_tarball_from_pkg_json(
        serde_json::json!({
            "name": "parent",
            "version": "1.0.0",
            "dependencies": { "child": "1.0.0" },
        }),
        &[],
    );
    for project in ["first", "second"] {
        neighbours.write(
            project,
            "package.json",
            r#"{"name":"consumer","version":"1.0.0","dependencies":{"parent":"1.0.0"}}"#,
        );
    }

    serve_family(&registry, &parent, "first").await;
    neighbours.install("first", &registry);

    // The registry now serves other bytes for the dependency's version, as a
    // lockfile written elsewhere can name them too.
    registry.server().reset().await;
    serve_family(&registry, &parent, "second").await;
    neighbours.forget_registry_answers();
    neighbours.install("second", &registry);

    assert_eq!(
        neighbours.seen_by("first", "parent", "child/owner.txt"),
        "first"
    );
    assert_eq!(
        neighbours.seen_by("second", "parent", "child/owner.txt"),
        "second"
    );
}

#[tokio::test]
async fn projects_installing_the_same_bytes_share_one_store_entry() {
    let registry = MockRegistry::start().await;
    registry
        .with_package("same-bytes", "1.0.0", &owned_package("same-bytes", "both"))
        .await;
    let neighbours = Neighbours::new();
    for project in ["first", "second"] {
        neighbours.write(
            project,
            "package.json",
            r#"{"name":"consumer","version":"1.0.0","dependencies":{"same-bytes":"1.0.0"}}"#,
        );
        neighbours.install(project, &registry);
    }

    assert_eq!(
        neighbours.store_entry("first", "same-bytes"),
        neighbours.store_entry("second", "same-bytes")
    );
}

#[tokio::test]
async fn a_package_declared_by_shasum_keeps_its_entry_through_a_build_and_the_next_install() {
    let registry = MockRegistry::start().await;
    serve_by_shasum(&registry, "legacy", &owned_package("legacy", "legacy")).await;
    registry
        .with_manifest_package(
            serde_json::json!({
                "name": "built",
                "version": "1.0.0",
                "dependencies": { "legacy": "1.0.0" },
                "scripts": { "postinstall": "node build.js" },
            }),
            &[(
                "build.js",
                b"require('fs').writeFileSync('built.txt', 'ok');\n",
            )],
        )
        .await;
    let neighbours = Neighbours::new();
    neighbours.write(
        "first",
        "package.json",
        r#"{"name":"consumer","version":"1.0.0","dependencies":{"built":"1.0.0"},"lpm":{"trustedDependencies":["built"]}}"#,
    );
    let install_and_build = || {
        write_signed_unlock_for(
            &neighbours.holder,
            &neighbours.dir("first"),
            &["sandbox-none", "trust-bulk-approve"],
        );
        neighbours.install_with("first", &registry, &["--no-sandbox", "--auto-build"]);
        assert_eq!(neighbours.installed("first", "built/built.txt"), "ok");
        [
            neighbours.store_entry("first", "built"),
            neighbours
                .dependency_of("first", "built", "legacy")
                .canonicalize()
                .unwrap(),
        ]
    };

    let entries = install_and_build();
    assert_eq!(
        neighbours.seen_by("first", "built", "legacy/owner.txt"),
        "legacy"
    );

    std::fs::remove_dir_all(neighbours.dir("first").join("node_modules")).unwrap();
    assert_eq!(install_and_build(), entries);
}

#[tokio::test]
async fn isolated_and_hoisted_installs_share_the_same_store_link_entry() {
    let registry = MockRegistry::start().await;
    registry
        .with_package("shared-mod", "1.0.0", &owned_package("shared-mod", "both"))
        .await;
    let neighbours = Neighbours::new();
    for project in ["isolated-proj", "hoisted-proj"] {
        neighbours.write(
            project,
            "package.json",
            r#"{"name":"consumer","version":"1.0.0","dependencies":{"shared-mod":"1.0.0"}}"#,
        );
    }

    neighbours.install_with("isolated-proj", &registry, &["--linker=isolated"]);
    neighbours.install_with("hoisted-proj", &registry, &["--linker=hoisted"]);

    assert_eq!(
        neighbours.store_entry("isolated-proj", "shared-mod"),
        neighbours.store_entry("hoisted-proj", "shared-mod"),
        "isolated and hoisted linkers should reuse the same v2 store link entry"
    );
}
