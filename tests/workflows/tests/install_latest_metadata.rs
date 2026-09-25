mod support;

use support::mock_registry::{MockRegistry, make_tarball_from_pkg_json};
use support::{TempProject, lpm_with_registry_and_npm};
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, ResponseTemplate};

#[tokio::test]
async fn ranged_install_answers_from_latest_document_without_waiting_for_history() {
    install_latest(false).await;
}

#[tokio::test]
async fn ranged_install_keeps_publication_metadata_for_blocked_scripts() {
    install_latest(true).await;
}

async fn install_latest(scripted: bool) {
    let registry = MockRegistry::start().await;
    let mut manifest = serde_json::json!({"name":"latest-package","version":"1.1.0"});
    if scripted {
        manifest["scripts"] = serde_json::json!({"install":"node -e \"process.exit(37)\""});
    }
    let tarball = make_tarball_from_pkg_json(manifest.clone(), &[]);
    let mut metadata = registry.package_metadata("latest-package", "1.1.0", &tarball);
    if scripted {
        metadata["versions"]["1.1.0"]["scripts"] = manifest["scripts"].clone();
        metadata["time"]["1.1.0"] = serde_json::json!("2025-01-01T00:00:00Z");
    } else {
        let newer = make_tarball_from_pkg_json(
            serde_json::json!({"name":"latest-package","version":"1.2.0"}),
            &[],
        );
        metadata["versions"]["1.2.0"] =
            registry.package_metadata("latest-package", "1.2.0", &newer)["versions"]["1.2.0"]
                .clone();
    }
    Mock::given(method("GET"))
        .and(path("/latest-package/latest"))
        .and(header("Accept", "application/json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&metadata["versions"]["1.1.0"]))
        .mount(registry.server())
        .await;
    // The history raced against the latest document trails it; later
    // history reads, such as publication times, are answered immediately.
    Mock::given(method("GET"))
        .and(path("/latest-package"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(&metadata)
                .set_delay(std::time::Duration::from_secs(2)),
        )
        .up_to_n_times(1)
        .with_priority(1)
        .mount(registry.server())
        .await;
    registry
        .with_package_metadata("latest-package", "1.1.0", &tarball, metadata)
        .await;
    let project = TempProject::empty(
        r#"{"name":"latest-install","version":"1.0.0","dependencies":{"latest-package":"^1.0.0"}}"#,
    );
    let output = lpm_with_registry_and_npm(&project, &registry.url())
        .env("LPM_NPM_ROUTE", "direct")
        .args([
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .assert()
        .success();
    let installed: serde_json::Value =
        serde_json::from_str(&project.read_file("node_modules/latest-package/package.json"))
            .unwrap();
    assert_eq!(installed["version"], "1.1.0");
    let lock = project.read_file("lpm.lock");
    assert!(lock.contains("name = \"latest-package\""));
    assert!(lock.contains("version = \"1.1.0\""));
    let requests = registry.server().received_requests().await.unwrap();
    let count = |endpoint: &str| {
        requests
            .iter()
            .filter(|request| request.url.path() == endpoint)
            .count()
    };
    let (latest_requests, history_requests) =
        (count("/latest-package/latest"), count("/latest-package"));
    assert_eq!(latest_requests, 1);
    if scripted {
        assert!((1..=2).contains(&history_requests), "{history_requests}");
        let state: serde_json::Value =
            serde_json::from_str(&project.read_file(".lpm/build-state.json")).unwrap();
        let blocked = state["blocked_packages"].as_array().unwrap();
        assert_eq!(blocked.len(), 1);
        assert_eq!(blocked[0]["name"], "latest-package");
        assert_eq!(blocked[0]["published_at"], "2025-01-01T00:00:00Z");
    } else {
        assert!(history_requests <= 1, "{history_requests}");
        let rendered = format!(
            "{}{}",
            String::from_utf8_lossy(&output.get_output().stdout),
            String::from_utf8_lossy(&output.get_output().stderr)
        );
        assert!(!rendered.contains("v1.2.0 available"));
    }
}

#[tokio::test]
async fn optional_latest_keeps_portable_platform_metadata_without_fetching_payload() {
    let registry = MockRegistry::start().await;
    let tarball = make_tarball_from_pkg_json(
        serde_json::json!({"name":"optional-latest","version":"1.1.0","cpu":["wasm32"]}),
        &[],
    );
    let mut metadata = registry.package_metadata("optional-latest", "1.1.0", &tarball);
    metadata["versions"]["1.1.0"]["cpu"] = serde_json::json!(["wasm32"]);
    Mock::given(method("GET"))
        .and(path("/optional-latest/latest"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&metadata["versions"]["1.1.0"]))
        .expect(1)
        .mount(registry.server())
        .await;
    let project = TempProject::empty(
        r#"{"name":"optional-latest-install","version":"1.0.0","optionalDependencies":{"optional-latest":"^1.0.0"}}"#,
    );
    lpm_with_registry_and_npm(&project, &registry.url())
        .env("LPM_NPM_ROUTE", "direct")
        .args([
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .assert()
        .success();
    let lock = project.read_file("lpm.lock");
    assert!(lock.contains("name = \"optional-latest\""));
    assert!(lock.contains("version = \"1.1.0\""));
    assert!(lock.contains("wasm32"));
    assert!(!project.path().join("node_modules/optional-latest").exists());
    let requests = registry.server().received_requests().await.unwrap();
    assert!(
        !requests
            .iter()
            .any(|request| request.url.path().contains("/-/"))
    );
    assert!(
        requests
            .iter()
            .filter(|request| request.url.path() == "/optional-latest")
            .count()
            <= 1
    );
    registry.server().verify().await;
}
