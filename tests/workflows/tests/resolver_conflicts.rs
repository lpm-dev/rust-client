mod support;

use support::mock_registry::{MockRegistry, make_tarball};
use support::{TempProject, lpm_with_registry};

const INSTALL_ARGS: &[&str] = &[
    "install",
    "--no-security-summary",
    "--no-skills",
    "--no-editor-setup",
];

#[tokio::test]
async fn install_explains_transitive_range_that_has_no_matching_version() {
    let mock = MockRegistry::start().await;
    mount_transitive_no_match_graph(&mock).await;
    let project = transitive_no_match_project();

    let output = lpm_with_registry(&project, &mock.url())
        .args(INSTALL_ARGS)
        .output()
        .expect("failed to run lpm install");

    assert!(
        !output.status.success(),
        "unresolvable transitive range must fail"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Could not resolve dependencies")
            && stderr.contains("package missing-leaf@^2.0.0")
            && stderr.contains("required by parent-pkg@1.0.0")
            && stderr.contains("reason no published version satisfies ^2.0.0")
            && stderr.contains("available 1 version, newest 1.0.0"),
        "stderr must explain the failed package, requester, reason, and available versions:\n{stderr}"
    );
    assert!(
        !stderr.contains("Registry error")
            && !stderr.contains("resolution failed: failed to fetch dependencies"),
        "resolution failures must not be flattened into generic registry errors:\n{stderr}"
    );
}

#[tokio::test]
async fn install_json_reports_structured_transitive_resolution_failure() {
    let mock = MockRegistry::start().await;
    mount_transitive_no_match_graph(&mock).await;
    let project = transitive_no_match_project();

    let output = lpm_with_registry(&project, &mock.url())
        .arg("--json")
        .args(INSTALL_ARGS)
        .output()
        .expect("failed to run lpm install --json");

    assert!(
        !output.status.success(),
        "unresolvable transitive range must fail under --json"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("failure stdout must be valid JSON");
    assert_eq!(json["success"], serde_json::json!(false));
    assert_eq!(json["error_code"], serde_json::json!("resolution_failed"));
    assert_eq!(json["error"]["package"], serde_json::json!("missing-leaf"));
    assert_eq!(json["error"]["requested"], serde_json::json!("^2.0.0"));
    assert_eq!(
        json["error"]["required_by"],
        serde_json::json!("parent-pkg@1.0.0")
    );
    assert_eq!(
        json["error"]["kind"],
        serde_json::json!("no_matching_version")
    );
    assert_eq!(json["error"]["available_versions"], serde_json::json!(1));
    assert_eq!(json["error"]["newest_version"], serde_json::json!("1.0.0"));
}

#[tokio::test]
async fn resolve_json_reports_structured_transitive_resolution_failure() {
    let mock = MockRegistry::start().await;
    mount_transitive_no_match_graph(&mock).await;
    let project = transitive_no_match_project();

    let output = lpm_with_registry(&project, &mock.url())
        .args(["resolve", "parent-pkg", "--json"])
        .output()
        .expect("failed to run lpm resolve --json");

    assert!(
        !output.status.success(),
        "unresolvable transitive range must fail under lpm resolve --json"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("failure stdout must be valid JSON");
    assert_eq!(json["success"], serde_json::json!(false));
    assert_eq!(json["error_code"], serde_json::json!("resolution_failed"));
    assert_eq!(json["error"]["package"], serde_json::json!("missing-leaf"));
    assert_eq!(json["error"]["requested"], serde_json::json!("^2.0.0"));
    assert_eq!(
        json["error"]["required_by"],
        serde_json::json!("parent-pkg@1.0.0")
    );
    assert_eq!(
        json["error"]["kind"],
        serde_json::json!("no_matching_version")
    );
}

#[tokio::test]
async fn install_json_reports_structured_required_peer_resolution_failure() {
    let mock = MockRegistry::start().await;
    mount_required_peer_no_match_graph(&mock).await;
    let project = TempProject::empty(
        r#"{
            "name": "resolver-peer-conflict-workflow",
            "version": "1.0.0",
            "dependencies": {
                "future-pkg": "^1.0.0"
            }
        }"#,
    );

    let output = lpm_with_registry(&project, &mock.url())
        .arg("--json")
        .args(INSTALL_ARGS)
        .output()
        .expect("failed to run lpm install --json");

    assert!(
        !output.status.success(),
        "required peer range with no satisfiable published version must fail"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("failure stdout must be valid JSON");
    assert_eq!(json["success"], serde_json::json!(false));
    assert_eq!(json["error_code"], serde_json::json!("resolution_failed"));
    assert_eq!(json["error"]["package"], serde_json::json!("react"));
    assert_eq!(json["error"]["requested"], serde_json::json!("^99.0.0"));
    assert_eq!(
        json["error"]["required_by"],
        serde_json::json!("future-pkg")
    );
    assert_eq!(json["error"]["kind"], serde_json::json!("peer_conflict"));
    assert_eq!(
        json["error"]["reason"],
        serde_json::json!("no published peer version satisfies the required range")
    );
    assert_eq!(
        json["error"]["derivation"],
        serde_json::json!("future-pkg wants ^99.0.0")
    );
}

async fn mount_transitive_no_match_graph(mock: &MockRegistry) {
    mock.with_manifest_package(
        serde_json::json!({
            "name": "parent-pkg",
            "version": "1.0.0",
            "dependencies": {
                "missing-leaf": "^2.0.0"
            }
        }),
        &[],
    )
    .await;
    mock.with_manifest_package(
        serde_json::json!({
            "name": "missing-leaf",
            "version": "1.0.0"
        }),
        &[],
    )
    .await;
}

async fn mount_required_peer_no_match_graph(mock: &MockRegistry) {
    mock.with_manifest_package(
        serde_json::json!({
            "name": "future-pkg",
            "version": "1.0.0",
            "peerDependencies": {
                "react": "^99.0.0"
            }
        }),
        &[],
    )
    .await;
    mock.with_full_package_metadata(
        "react",
        "18.2.0",
        &[
            (
                "18.2.0",
                serde_json::json!({}),
                Some(make_tarball("react", "18.2.0")),
            ),
            (
                "17.0.2",
                serde_json::json!({}),
                Some(make_tarball("react", "17.0.2")),
            ),
        ],
    )
    .await;
}

fn transitive_no_match_project() -> TempProject {
    TempProject::empty(
        r#"{
            "name": "resolver-conflict-workflow",
            "version": "1.0.0",
            "dependencies": {
                "parent-pkg": "^1.0.0"
            }
        }"#,
    )
}
