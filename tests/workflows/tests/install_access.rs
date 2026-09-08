//! Cached registry installs must recheck access and version state before linking.
mod support;

use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use support::mock_registry::{MockRegistry, make_tarball};
use support::{TempProject, lpm_with_registry};
use wiremock::matchers::{method, path};
use wiremock::{Mock, ResponseTemplate};

const ROOT: &str = "@lpm.dev/test.access-root";
const LEAF: &str = "@lpm.dev/test.paid-leaf";

async fn registry_with_access_check(denied: Arc<AtomicBool>, reason: &'static str) -> MockRegistry {
    let registry = MockRegistry::start().await;
    registry
        .with_package_and_deps(
            ROOT,
            "1.0.0",
            &make_tarball(ROOT, "1.0.0"),
            serde_json::json!({ LEAF: "1.0.0" }),
        )
        .await;
    registry
        .with_package(LEAF, "1.0.0", &make_tarball(LEAF, "1.0.0"))
        .await;
    Mock::given(method("POST")).and(path("/api/registry/install-check"))
        .respond_with(move |request: &wiremock::Request| {
            let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
            let packages: Vec<_> = body["packages"].as_array().unwrap().iter().map(|package| {
                let allowed = package["name"] != LEAF || !denied.load(Ordering::SeqCst);
                serde_json::json!({ "name": package["name"], "version": package["version"], "allowed": allowed, "reason": if allowed { "" } else { reason }, "deprecated": "Use the maintained replacement" })
            }).collect();
            ResponseTemplate::new(200).set_body_json(serde_json::json!({"packages": packages}))
        }).mount(registry.server()).await;
    registry
}

async fn cached_install_rechecks(reason: &'static str, relink: bool) {
    let denied = Arc::new(AtomicBool::new(false));
    let registry = registry_with_access_check(denied.clone(), reason).await;
    let project = TempProject::empty(&serde_json::json!({ "name": "access-check", "version": "1.0.0", "dependencies": {ROOT: "1.0.0"} }).to_string());
    let args = ["install", "--json", "--no-skills", "--no-editor-setup"];
    lpm_with_registry(&project, &registry.url())
        .args(args)
        .assert()
        .success();
    let manifest = project.read_file("package.json");
    let lock = project.read_file("lpm.lock");
    if relink {
        std::fs::remove_dir_all(project.path().join("node_modules")).unwrap();
    }
    denied.store(true, Ordering::SeqCst);
    let output = lpm_with_registry(&project, &registry.url())
        .args(args)
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "cached {reason} install must fail: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["error_code"], "package_install_denied");
    assert!(result["error"].as_str().unwrap().contains(LEAF));
    assert_ne!(result["installed"], true);
    assert_eq!(project.read_file("package.json"), manifest);
    assert_eq!(project.read_file("lpm.lock"), lock);
    if relink {
        assert!(!project.path().join("node_modules").exists());
    }
}

#[tokio::test]
async fn cached_quarantined_version_is_denied_before_relink() {
    cached_install_rechecks("Version is quarantined", true).await;
}
#[tokio::test]
async fn cached_unpublished_version_is_denied_before_relink() {
    cached_install_rechecks("Version is unpublished", true).await;
}
#[tokio::test]
async fn cached_revoked_version_does_not_suggest_pool_attribution_retry() {
    cached_install_rechecks("Version is unavailable", true).await;
}
#[tokio::test]
async fn cached_transitive_license_revocation_is_denied_before_relink() {
    cached_install_rechecks("Package access denied", true).await;
}
#[tokio::test]
async fn up_to_date_install_rechecks_transitive_access() {
    cached_install_rechecks("Package access denied", false).await;
}

#[tokio::test]
async fn fresh_and_up_to_date_installs_show_deprecation_in_json_and_human_output() {
    let registry = registry_with_access_check(Arc::new(AtomicBool::new(false)), "").await;
    let project = TempProject::empty(
        &serde_json::json!({ "name": "deprecation", "dependencies": {ROOT: "1.0.0"} }).to_string(),
    );
    for json in [true, true, false] {
        let mut command = lpm_with_registry(&project, &registry.url());
        command.args(["install", "--no-skills", "--no-editor-setup"]);
        if json {
            command.arg("--json");
        }
        let output = command.output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        if json {
            let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
            assert!(
                result["warnings"]
                    .as_array()
                    .is_some_and(|warnings| warnings.iter().any(|warning| warning
                        .to_string()
                        .contains("Use the maintained replacement"))),
                "{result}"
            );
        } else {
            let text = format!(
                "{}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(text.contains("Use the maintained replacement"), "{text}");
        }
    }
}
