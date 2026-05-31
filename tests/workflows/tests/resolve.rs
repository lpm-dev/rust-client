mod support;

use support::mock_registry::{MockRegistry, compute_integrity, make_tarball};
use support::{TempProject, lpm, lpm_with_registry};

async fn mount_lpm_package(mock: &MockRegistry, package: &str, version: &str) {
    mount_lpm_package_with_deps(mock, package, version, serde_json::json!({})).await;
}

async fn mount_lpm_package_with_deps(
    mock: &MockRegistry,
    package: &str,
    version: &str,
    dependencies: serde_json::Value,
) {
    let tarball = make_tarball(package, version);
    mock.with_package(package, version, &tarball).await;
    mock.with_batch_metadata(vec![lpm_package_metadata(
        mock,
        package,
        version,
        dependencies,
    )])
    .await;
}

fn lpm_package_metadata(
    mock: &MockRegistry,
    package: &str,
    version: &str,
    dependencies: serde_json::Value,
) -> serde_json::Value {
    let tarball = make_tarball(package, version);
    serde_json::json!({
        "name": package,
        "dist-tags": { "latest": version },
        "versions": {
            version: {
                "name": package,
                "version": version,
                "dist": {
                    "tarball": format!("{}/tarballs/{package}/-/{package}-{version}.tgz", mock.url()),
                    "integrity": compute_integrity(&tarball),
                },
                "dependencies": dependencies
            }
        },
        "time": { version: "2025-01-01T00:00:00.000Z" }
    })
}

#[test]
fn resolve_without_packages_fails_before_registry_lookup() {
    let project = TempProject::empty(r#"{"name":"resolve-test","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["resolve"])
        .output()
        .expect("failed to run lpm resolve");

    assert!(
        !output.status.success(),
        "resolve without packages must exit non-zero"
    );

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("no packages specified"),
        "expected empty-input error, got:\n{combined}"
    );
}

#[tokio::test]
async fn resolve_bare_scoped_package_defaults_to_latest_version_in_human_output() {
    let package = "@lpm.dev/owner.latest";
    let version = "2.3.4";
    let project = TempProject::empty(r#"{"name":"resolve-test","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    mount_lpm_package(&mock, package, version).await;

    let output = lpm_with_registry(&project, &mock.url())
        .args(["resolve", package])
        .output()
        .expect("failed to run lpm resolve");

    assert!(
        output.status.success(),
        "lpm resolve failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("Resolved 1 package in"),
        "expected success summary, got:\n{combined}"
    );
    assert!(
        combined.contains("› Resolving 1 package"),
        "resolve must use a slim phase line, got:\n{combined}"
    );
    assert!(
        combined.contains(package),
        "resolved package name must be shown, got:\n{combined}"
    );
    assert!(
        combined.contains(&format!("{package}@{version}")),
        "resolved package must be rendered in name@version form, got:\n{combined}"
    );
    assert!(
        !combined.contains(&format!("v{version}")) && !combined.contains(" lpm"),
        "resolve output must drop the v prefix and registry-kind label, got:\n{combined}"
    );
    assert!(
        !combined.contains('●') && !combined.contains('│'),
        "resolve output must not use cliclack gutter output, got:\n{combined}"
    );
}

#[tokio::test]
async fn resolve_human_output_nests_transitive_dependencies_as_tree() {
    let project = TempProject::empty(r#"{"name":"resolve-tree-test","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    let root = "@lpm.dev/owner.react";
    let child = "@lpm.dev/owner.scheduler";
    mock.with_full_package_metadata(
        root,
        "19.0.0",
        &[(
            "19.0.0",
            serde_json::json!({ child: "^0.25.0" }),
            Some(make_tarball(root, "19.0.0")),
        )],
    )
    .await;
    mock.with_full_package_metadata(
        child,
        "0.25.0",
        &[(
            "0.25.0",
            serde_json::json!({}),
            Some(make_tarball(child, "0.25.0")),
        )],
    )
    .await;
    mock.with_batch_metadata(vec![
        lpm_package_metadata(
            &mock,
            root,
            "19.0.0",
            serde_json::json!({ child: "^0.25.0" }),
        ),
        lpm_package_metadata(&mock, child, "0.25.0", serde_json::json!({})),
    ])
    .await;

    let output = lpm_with_registry(&project, &mock.url())
        .args(["resolve", root])
        .output()
        .expect("failed to run lpm resolve");

    assert!(
        output.status.success(),
        "lpm resolve failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("@lpm.dev/owner.react@19.0.0"),
        "root package must render in the resolve tree, got:\n{stdout}"
    );
    assert!(
        stdout.contains("└─ @lpm.dev/owner.scheduler@0.25.0")
            || stdout.contains("├─ @lpm.dev/owner.scheduler@0.25.0"),
        "transitive dependency must render under the root as a tree edge, got:\n{stdout}"
    );

    let scheduler_pos = stdout
        .find("@lpm.dev/owner.scheduler@0.25.0")
        .expect("scheduler line should be present");
    let react_pos = stdout
        .find("@lpm.dev/owner.react@19.0.0")
        .expect("react line should be present");
    assert!(
        react_pos < scheduler_pos,
        "transitive dependency must appear after its parent, got:\n{stdout}"
    );
}

#[tokio::test]
async fn resolve_json_scoped_version_uses_last_at_as_version_separator() {
    let package = "@lpm.dev/owner.react";
    let version = "1.0.0";
    let project = TempProject::empty(r#"{"name":"resolve-test","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    mount_lpm_package(&mock, package, version).await;

    let output = lpm_with_registry(&project, &mock.url())
        .args(["resolve", &format!("{package}@{version}"), "--json"])
        .output()
        .expect("failed to run lpm resolve --json");

    assert!(
        output.status.success(),
        "lpm resolve --json failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let mut envelope: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("resolve --json must be valid JSON: {e}\n---\n{stdout}"));

    assert_eq!(envelope["success"], serde_json::json!(true));
    assert_eq!(envelope["count"], serde_json::json!(1));
    assert!(
        envelope["elapsed_secs"].is_number(),
        "elapsed_secs must be numeric"
    );

    let packages = envelope["packages"]
        .as_array()
        .expect("packages must be an array");
    assert_eq!(packages.len(), 1);
    assert_eq!(packages[0]["package"], serde_json::json!(package));
    assert_eq!(packages[0]["version"], serde_json::json!(version));

    envelope["elapsed_secs"] = serde_json::json!("[elapsed]");
    insta::assert_json_snapshot!("resolve_json_envelope_one_scoped_package", envelope);
}
