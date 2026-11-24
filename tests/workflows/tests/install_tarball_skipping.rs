//! Workflow tests for bundled-dependency tarball skipping, cross-platform
//! optional graph pruning, and strict integrity enforcement on non-materialized
//! lockfile rows.

mod support;

use support::mock_registry::{MockRegistry, make_tarball, make_tarball_from_pkg_json};
use support::{TempProject, lpm_with_registry};
use wiremock::matchers::{method, path};
use wiremock::{Mock, ResponseTemplate};

const INSTALL: [&str; 3] = ["install", "--no-skills", "--no-security-summary"];

fn foreign_os() -> &'static str {
    if cfg!(target_os = "macos") {
        "linux"
    } else {
        "darwin"
    }
}

#[tokio::test]
async fn install_bundled_dependencies_skip_registry_fetches_for_array_and_boolean_true() {
    let mock = MockRegistry::start().await;

    let array_parent = serde_json::json!({
        "name": "array-bundler",
        "version": "1.0.0",
        "dependencies": {
            "vendored-a": "^1.0.0",
            "external-dep": "1.0.0"
        },
        "bundleDependencies": ["vendored-a"]
    });
    mock.with_manifest_package(
        array_parent,
        &[(
            "node_modules/vendored-a/package.json",
            br#"{"name":"vendored-a","version":"1.0.0"}"#,
        )],
    )
    .await;

    let bool_parent = serde_json::json!({
        "name": "bool-bundler",
        "version": "1.0.0",
        "dependencies": {
            "vendored-b": "^1.0.0"
        },
        "optionalDependencies": {
            "non-bundled-opt": "1.0.0"
        },
        "bundleDependencies": true
    });
    mock.with_manifest_package(
        bool_parent,
        &[(
            "node_modules/vendored-b/package.json",
            br#"{"name":"vendored-b","version":"1.0.0"}"#,
        )],
    )
    .await;

    mock.with_package(
        "external-dep",
        "1.0.0",
        &make_tarball("external-dep", "1.0.0"),
    )
    .await;
    mock.with_package(
        "non-bundled-opt",
        "1.0.0",
        &make_tarball("non-bundled-opt", "1.0.0"),
    )
    .await;

    // Neither vendored-a nor vendored-b is registered on the mock server; any
    // packument or tarball request would fail resolution or assert below.
    let project = TempProject::empty(
        r#"{
            "name": "bundled-consumer",
            "version": "1.0.0",
            "dependencies": {
                "array-bundler": "1.0.0",
                "bool-bundler": "1.0.0"
            }
        }"#,
    );

    let output = lpm_with_registry(&project, &mock.url())
        .args(INSTALL)
        .output()
        .expect("run lpm install");
    assert!(
        output.status.success(),
        "install failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let requests = mock.server().received_requests().await.unwrap();
    for forbidden in ["vendored-a", "vendored-b"] {
        assert!(
            !requests
                .iter()
                .any(|req| req.url.path().contains(forbidden)),
            "bundled dependency `{forbidden}` must never hit the registry; requests: {:?}",
            requests.iter().map(|r| r.url.path()).collect::<Vec<_>>()
        );
    }
    assert_eq!(
        mock.tarball_request_count("array-bundler", "1.0.0").await,
        1
    );
    assert_eq!(mock.tarball_request_count("bool-bundler", "1.0.0").await, 1);
    assert_eq!(mock.tarball_request_count("external-dep", "1.0.0").await, 1);
    assert_eq!(
        mock.tarball_request_count("non-bundled-opt", "1.0.0").await,
        1
    );

    let lockfile = project.read_file("lpm.lock");
    assert!(!lockfile.contains("name = \"vendored-a\""), "{lockfile}");
    assert!(!lockfile.contains("name = \"vendored-b\""), "{lockfile}");
    assert!(lockfile.contains("name = \"external-dep\""), "{lockfile}");
    assert!(
        lockfile.contains("name = \"non-bundled-opt\""),
        "bundleDependencies: true must only bundle regular dependencies, not optionalDependencies: {lockfile}"
    );
    assert!(project.file_exists("node_modules/array-bundler/node_modules/vendored-a/package.json"));
    assert!(project.file_exists("node_modules/bool-bundler/node_modules/vendored-b/package.json"));
}

#[tokio::test]
async fn install_local_tgz_archive_skips_bundled_dependencies_and_respects_optional_platform() {
    let mock = MockRegistry::start().await;
    mock.with_package("real-dep", "1.0.0", &make_tarball("real-dep", "1.0.0"))
        .await;

    let bundled_archive = make_tarball_from_pkg_json(
        serde_json::json!({
            "name": "local-bundle",
            "version": "1.0.0",
            "dependencies": {
                "private-vendored": "^1.0.0",
                "real-dep": "1.0.0"
            },
            "bundleDependencies": ["private-vendored"]
        }),
        &[(
            "node_modules/private-vendored/package.json",
            br#"{"name":"private-vendored","version":"1.0.0"}"#,
        )],
    );
    let foreign_archive = make_tarball_from_pkg_json(
        serde_json::json!({
            "name": "local-foreign-opt",
            "version": "1.0.0",
            "os": [foreign_os()],
            "peerDependencies": {
                "foreign-peer": "1.0.0"
            }
        }),
        &[],
    );

    let project = TempProject::empty(
        r#"{
            "name": "archive-consumer",
            "version": "1.0.0",
            "dependencies": {
                "local-bundle": "file:./vendor/local-bundle.tgz"
            },
            "optionalDependencies": {
                "local-foreign-opt": "file:./vendor/local-foreign-opt.tgz"
            }
        }"#,
    );
    std::fs::create_dir_all(project.path().join("vendor")).unwrap();
    std::fs::write(
        project.path().join("vendor/local-bundle.tgz"),
        &bundled_archive,
    )
    .unwrap();
    std::fs::write(
        project.path().join("vendor/local-foreign-opt.tgz"),
        &foreign_archive,
    )
    .unwrap();

    let output = lpm_with_registry(&project, &mock.url())
        .args(INSTALL)
        .output()
        .expect("run lpm install");
    assert!(
        output.status.success(),
        "install failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let requests = mock.server().received_requests().await.unwrap();
    for forbidden in ["private-vendored", "foreign-peer"] {
        assert!(
            !requests
                .iter()
                .any(|req| req.url.path().contains(forbidden)),
            "`{forbidden}` must never be fetched from registry; requests: {:?}",
            requests.iter().map(|r| r.url.path()).collect::<Vec<_>>()
        );
    }
    assert_eq!(mock.tarball_request_count("real-dep", "1.0.0").await, 1);
    assert!(project.file_exists("node_modules/local-bundle/package.json"));
    assert!(
        !project.file_exists("node_modules/local-foreign-opt/package.json"),
        "platform-incompatible optional local tarball must not be linked"
    );
}

#[tokio::test]
async fn install_skips_tarballs_for_descendants_and_ambient_peers_of_foreign_platform_optionals() {
    let mock = MockRegistry::start().await;

    mock.with_manifest_package(
        serde_json::json!({
            "name": "native-wrapper",
            "version": "1.0.0",
            "dependencies": {
                "compat-sibling": "1.0.0"
            },
            "optionalDependencies": {
                "foreign-native": "1.0.0"
            }
        }),
        &[],
    )
    .await;
    mock.with_manifest_package(
        serde_json::json!({
            "name": "compat-sibling",
            "version": "1.0.0",
            "dependencies": {
                "diamond-shared": "1.0.0"
            }
        }),
        &[],
    )
    .await;
    mock.with_manifest_package(
        serde_json::json!({
            "name": "foreign-native",
            "version": "1.0.0",
            "os": [foreign_os()],
            "dependencies": {
                "orphan-child": "1.0.0",
                "diamond-shared": "1.0.0"
            },
            "peerDependencies": {
                "orphan-peer": "1.0.0"
            }
        }),
        &[],
    )
    .await;
    for name in ["orphan-child", "orphan-peer", "diamond-shared"] {
        mock.with_package(name, "1.0.0", &make_tarball(name, "1.0.0"))
            .await;
    }

    let project = TempProject::empty(
        r#"{
            "name": "platform-pruning-app",
            "version": "1.0.0",
            "dependencies": {
                "native-wrapper": "1.0.0"
            }
        }"#,
    );

    let output = lpm_with_registry(&project, &mock.url())
        .args(INSTALL)
        .output()
        .expect("run lpm install");
    assert!(
        output.status.success(),
        "install failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    assert_eq!(
        mock.tarball_request_count("native-wrapper", "1.0.0").await,
        1
    );
    assert_eq!(
        mock.tarball_request_count("compat-sibling", "1.0.0").await,
        1
    );
    assert_eq!(
        mock.tarball_request_count("diamond-shared", "1.0.0").await,
        1,
        "shared diamond dependency needed by a compatible branch must still be downloaded"
    );
    assert_eq!(
        mock.tarball_request_count("foreign-native", "1.0.0").await,
        0,
        "foreign-platform optional package tarball must not be downloaded"
    );
    assert_eq!(
        mock.tarball_request_count("orphan-child", "1.0.0").await,
        0,
        "descendant reachable only through a foreign-platform optional must not be downloaded"
    );
    assert_eq!(
        mock.tarball_request_count("orphan-peer", "1.0.0").await,
        0,
        "ambient peer required only by a foreign-platform optional must not be downloaded"
    );
    assert!(!project.file_exists("node_modules/orphan-peer/package.json"));
    assert!(
        project
            .read_file("lpm.lock")
            .contains("name = \"foreign-native\"")
    );
}

#[tokio::test]
async fn install_strict_integrity_rejects_other_platform_optional_without_integrity() {
    let mock = MockRegistry::start().await;
    mock.with_manifest_package(
        serde_json::json!({
            "name": "host-pkg",
            "version": "1.0.0",
            "optionalDependencies": {
                "unsigned-foreign": "1.0.0"
            }
        }),
        &[],
    )
    .await;

    // Mount unsigned-foreign without dist.integrity or dist.shasum.
    let unsigned_meta = serde_json::json!({
        "name": "unsigned-foreign",
        "dist-tags": { "latest": "1.0.0" },
        "versions": {
            "1.0.0": {
                "name": "unsigned-foreign",
                "version": "1.0.0",
                "os": [foreign_os()],
                "dist": {
                    "tarball": mock.tarball_url("unsigned-foreign", "1.0.0")
                }
            }
        }
    });
    Mock::given(method("GET"))
        .and(path("/unsigned-foreign"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&unsigned_meta))
        .mount(mock.server())
        .await;

    let project = TempProject::empty(
        r#"{
            "name": "strict-integrity-app",
            "version": "1.0.0",
            "dependencies": {
                "host-pkg": "1.0.0"
            }
        }"#,
    );

    let output = lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "--strict-integrity",
            "--no-skills",
            "--no-security-summary",
        ])
        .output()
        .expect("run lpm install --strict-integrity");
    assert!(
        !output.status.success(),
        "--strict-integrity must reject non-materialized optional lockfile rows without integrity:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("--strict-integrity") && stderr.contains("unsigned-foreign@1.0.0"),
        "expected strict integrity error naming unsigned-foreign@1.0.0; got:\n{stderr}"
    );
    assert_eq!(
        mock.tarball_request_count("unsigned-foreign", "1.0.0")
            .await,
        0,
        "foreign-platform optional package tarball must not be downloaded"
    );
    assert!(
        !project.file_exists("lpm.lock"),
        "failed --strict-integrity install must not write lpm.lock"
    );

    // Install without --strict-integrity so lpm.lock is written with the
    // unsigned foreign optional row, then verify both --offline and freshness
    // re-installs reject it when --strict-integrity is enabled.
    let permissive = lpm_with_registry(&project, &mock.url())
        .args(INSTALL)
        .output()
        .expect("run permissive install");
    assert!(
        permissive.status.success(),
        "permissive install failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&permissive.stdout),
        String::from_utf8_lossy(&permissive.stderr)
    );
    assert!(project.file_exists("lpm.lock"));

    for extra_args in [
        vec![
            "install",
            "--offline",
            "--strict-integrity",
            "--no-skills",
            "--no-security-summary",
        ],
        vec![
            "install",
            "--strict-integrity",
            "--no-skills",
            "--no-security-summary",
        ],
    ] {
        let strict_replay = lpm_with_registry(&project, &mock.url())
            .args(&extra_args)
            .output()
            .expect("run strict integrity replay");
        assert!(
            !strict_replay.status.success(),
            "replay `{extra_args:?}` must reject unsigned foreign optional lockfile row:\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&strict_replay.stdout),
            String::from_utf8_lossy(&strict_replay.stderr)
        );
        let replay_stderr = String::from_utf8_lossy(&strict_replay.stderr);
        assert!(
            replay_stderr.contains("--strict-integrity")
                && replay_stderr.contains("unsigned-foreign@1.0.0"),
            "expected strict integrity error for `{extra_args:?}`; got:\n{replay_stderr}"
        );
    }
}

#[tokio::test]
async fn install_local_tgz_skips_vendored_file_bundled_dep_and_foreign_optional_children() {
    let mock = MockRegistry::start().await;
    mock.with_package("real-dep", "1.0.0", &make_tarball("real-dep", "1.0.0"))
        .await;

    let bundled_archive = make_tarball_from_pkg_json(
        serde_json::json!({
            "name": "local-vendored-file",
            "version": "1.0.0",
            "dependencies": {
                "vendored-local": "file:../nonexistent-vendored-pkg",
                "real-dep": "1.0.0"
            },
            "bundleDependencies": ["vendored-local"]
        }),
        &[(
            "node_modules/vendored-local/package.json",
            br#"{"name":"vendored-local","version":"1.0.0"}"#,
        )],
    );
    let foreign_archive = make_tarball_from_pkg_json(
        serde_json::json!({
            "name": "local-foreign-with-child",
            "version": "1.0.0",
            "os": [foreign_os()],
            "dependencies": {
                "foreign-archive-child": "1.0.0"
            }
        }),
        &[],
    );

    let project = TempProject::empty(
        r#"{
            "name": "archive-vendored-consumer",
            "version": "1.0.0",
            "dependencies": {
                "local-vendored-file": "file:./vendor/local-vendored-file.tgz"
            },
            "optionalDependencies": {
                "local-foreign-with-child": "file:./vendor/local-foreign-with-child.tgz"
            }
        }"#,
    );
    std::fs::create_dir_all(project.path().join("vendor")).unwrap();
    std::fs::write(
        project.path().join("vendor/local-vendored-file.tgz"),
        &bundled_archive,
    )
    .unwrap();
    std::fs::write(
        project.path().join("vendor/local-foreign-with-child.tgz"),
        &foreign_archive,
    )
    .unwrap();

    let output = lpm_with_registry(&project, &mock.url())
        .args(INSTALL)
        .output()
        .expect("run lpm install");
    assert!(
        output.status.success(),
        "install failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let requests = mock.server().received_requests().await.unwrap();
    assert!(
        !requests
            .iter()
            .any(|req| req.url.path().contains("foreign-archive-child")),
        "foreign optional archive's unbundled child must never hit the registry; requests: {:?}",
        requests.iter().map(|r| r.url.path()).collect::<Vec<_>>()
    );
    assert!(project.file_exists("node_modules/local-vendored-file/package.json"));
    assert!(!project.file_exists("node_modules/local-foreign-with-child/package.json"));
    assert!(!project.file_exists("node_modules/foreign-archive-child/package.json"));
    assert!(
        !project.file_exists("node_modules/real-dep/package.json"),
        "archive's unbundled dependency must not leak as a direct project root link"
    );
}
