mod support;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use support::mock_registry::{MockRegistry, compute_integrity, make_tarball};
use support::{TempProject, lpm_with_registry};
use wiremock::matchers::{method, path};
use wiremock::{Mock, Request, ResponseTemplate};

#[tokio::test]
async fn install_fetches_optional_tarball_while_other_metadata_is_pending() {
    let registry = MockRegistry::start().await;
    registry
        .with_manifest_package(
            serde_json::json!({
                "name": "a-parent", "version": "1.0.0",
                "optionalDependencies": {"native": "1.0.0"}
            }),
            &[],
        )
        .await;
    let native_tarball = make_tarball("native", "1.0.0");
    registry
        .with_package("native", "1.0.0", &native_tarball)
        .await;
    let gate_tarball = make_tarball("z-gate", "1.0.0");
    registry
        .with_package("z-gate", "1.0.0", &gate_tarball)
        .await;

    let native_fetched = Arc::new(AtomicBool::new(false));
    let fetched = Arc::clone(&native_fetched);
    Mock::given(method("GET"))
        .and(path(MockRegistry::tarball_path("native", "1.0.0")))
        .respond_with(move |_: &Request| {
            fetched.store(true, Ordering::SeqCst);
            ResponseTemplate::new(200).set_body_bytes(native_tarball.clone())
        })
        .with_priority(1)
        .mount(registry.server())
        .await;

    let gate_metadata = serde_json::json!({
        "name": "z-gate", "dist-tags": {"latest": "1.0.0"},
        "versions": {"1.0.0": {
            "name": "z-gate", "version": "1.0.0",
            "dist": {
                "tarball": registry.tarball_url("z-gate", "1.0.0"),
                "integrity": compute_integrity(&gate_tarball)
            }
        }}
    });
    let fetched = Arc::clone(&native_fetched);
    Mock::given(method("GET"))
        .and(path("/z-gate"))
        .respond_with(move |_: &Request| {
            if fetched.load(Ordering::SeqCst) {
                ResponseTemplate::new(200).set_body_json(&gate_metadata)
            } else {
                ResponseTemplate::new(503)
            }
        })
        .with_priority(1)
        .mount(registry.server())
        .await;

    let project = TempProject::empty(
        r#"{
        "name": "optional-overlap", "version": "1.0.0",
        "dependencies": {"a-parent": "^1.0.0", "z-gate": "^1.0.0"}
    }"#,
    );
    project.write_file(".npmrc", &format!("registry={}/\n", registry.url()));
    let output = lpm_with_registry(&project, &registry.url())
        .env("LPM_GREEDY_FUSION", "1")
        .env("LPM_RETRY_BACKOFF_MS_OVERRIDE", "500")
        .args([
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("run optional speculation install");

    assert!(
        output.status.success(),
        "optional tarball must arrive before resolution can complete:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(native_fetched.load(Ordering::SeqCst));
    support::assertions::assert_in_node_modules(project.path(), "a-parent");
    assert!(project.read_file("lpm.lock").contains("name = \"native\""));
    let requests = registry.server().received_requests().await.unwrap();
    assert_eq!(
        requests
            .iter()
            .filter(|request| request.url.path() == MockRegistry::tarball_path("native", "1.0.0"))
            .count(),
        1,
        "the authoritative fetch must reuse the speculative tarball"
    );
}
