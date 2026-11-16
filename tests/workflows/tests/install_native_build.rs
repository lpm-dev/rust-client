//! Workflow coverage for the native build a package gets without naming it.

mod support;

use support::mock_registry::MockRegistry;
use support::{TempProject, lpm, lpm_with_registry};

const INSTALL: [&str; 3] = ["install", "--no-skills", "--no-security-summary"];

fn consumer_of(dependency: &str) -> TempProject {
    TempProject::empty(&format!(
        r#"{{"name":"consumer","version":"1.0.0","dependencies":{{"{dependency}":"1.0.0"}}}}"#
    ))
}

/// What `approve-scripts --list` reports as waiting for review.
fn waiting_for_review(project: &TempProject) -> serde_json::Value {
    let listed = lpm(project)
        .args(["--json", "approve-scripts", "--list"])
        .output()
        .expect("spawn lpm approve-scripts --list");
    assert!(listed.status.success(), "{listed:?}");
    serde_json::from_slice(&listed.stdout).expect("approve-scripts --list --json prints JSON")
}

#[tokio::test]
async fn a_package_with_a_binding_gyp_and_no_install_script_waits_for_review_of_its_build() {
    let registry = MockRegistry::start().await;
    registry
        .with_manifest_package(
            serde_json::json!({ "name": "native", "version": "1.0.0" }),
            &[("binding.gyp", br#"{"targets":[{"target_name":"native"}]}"#)],
        )
        .await;
    let project = consumer_of("native");

    lpm_with_registry(&project, &registry.url())
        .args(INSTALL)
        .assert()
        .success();

    let waiting = waiting_for_review(&project);
    assert_eq!(waiting["blocked_count"], 1, "{waiting:#}");
    let native = &waiting["blocked"][0];
    assert_eq!(native["name"], "native", "{waiting:#}");
    assert_eq!(
        native["phases_present"],
        serde_json::json!(["install"]),
        "{waiting:#}"
    );
    assert_eq!(native["static_tier"], "green", "{waiting:#}");
}

#[tokio::test]
async fn a_package_that_opts_out_of_the_implied_build_has_nothing_to_review() {
    let registry = MockRegistry::start().await;
    registry
        .with_manifest_package(
            serde_json::json!({ "name": "prebuilt", "version": "1.0.0", "gypfile": false }),
            &[(
                "binding.gyp",
                br#"{"targets":[{"target_name":"prebuilt"}]}"#,
            )],
        )
        .await;
    let project = consumer_of("prebuilt");

    lpm_with_registry(&project, &registry.url())
        .args(INSTALL)
        .assert()
        .success();

    let waiting = waiting_for_review(&project);
    assert_eq!(waiting["blocked_count"], 0, "{waiting:#}");
}
