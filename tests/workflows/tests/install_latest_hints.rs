mod support;

use support::mock_registry::{MockRegistry, make_tarball_from_pkg_json};
use support::{TempProject, lpm_with_registry_and_npm};
use wiremock::matchers::{method, path};
use wiremock::{Mock, ResponseTemplate};

#[tokio::test]
async fn install_hint_uses_latest_tag_instead_of_a_higher_stable_version() {
    install_latest_hint(Some("2.0.0"), Some("(v2.0.0 available)")).await;
}

#[tokio::test]
async fn install_hint_preserves_a_prerelease_latest_tag() {
    install_latest_hint(Some("2.0.0-beta.1"), Some("(v2.0.0-beta.1 available)")).await;
}

#[tokio::test]
async fn install_hint_does_not_invent_latest_when_the_tag_is_missing() {
    install_latest_hint(None, None).await;
}

#[tokio::test]
async fn install_hint_does_not_invent_latest_when_the_tag_is_invalid() {
    install_latest_hint(Some("not-a-version"), None).await;
}

#[tokio::test]
async fn cached_history_retains_latest_tag_hints_without_another_metadata_request() {
    install_latest_hint_rounds(Some("2.0.0"), Some("(v2.0.0 available)"), 2).await;
}

#[tokio::test]
async fn install_hint_preserves_native_latest_version_without_an_npm_tag() {
    install_latest_hint_authority(None, Some("2.0.0"), Some("(v2.0.0 available)"), 1).await;
}

#[tokio::test]
async fn install_hint_omits_a_latest_tag_older_than_the_installed_version() {
    install_latest_hint(Some("0.9.0"), None).await;
}

#[tokio::test]
async fn install_hint_prefers_the_npm_tag_over_a_conflicting_native_latest_version() {
    install_latest_hint_authority(Some("2.0.0"), Some("3.0.0"), Some("(v2.0.0 available)"), 1)
        .await;
}

async fn install_latest_hint(tag: Option<&str>, expected_hint: Option<&str>) {
    install_latest_hint_rounds(tag, expected_hint, 1).await;
}

async fn install_latest_hint_rounds(tag: Option<&str>, expected_hint: Option<&str>, rounds: usize) {
    install_latest_hint_authority(tag, None, expected_hint, rounds).await;
}

async fn install_latest_hint_authority(
    tag: Option<&str>,
    native_latest: Option<&str>,
    expected_hint: Option<&str>,
    rounds: usize,
) {
    let registry = MockRegistry::start().await;
    let name = "latest-hint-package";
    let selected_tarball =
        make_tarball_from_pkg_json(serde_json::json!({"name":name,"version":"1.0.0"}), &[]);
    let mut metadata = registry.package_metadata(name, "1.0.0", &selected_tarball);
    for version in ["2.0.0", "2.0.0-beta.1", "3.0.0"] {
        let body =
            make_tarball_from_pkg_json(serde_json::json!({"name":name,"version":version}), &[]);
        metadata["versions"][version] =
            registry.package_metadata(name, version, &body)["versions"][version].clone();
    }
    metadata["dist-tags"] = tag.map_or_else(
        || serde_json::json!({}),
        |tag| serde_json::json!({"latest":tag}),
    );
    metadata["latestVersion"] = serde_json::json!(native_latest);
    // Resolution may race the latest document against history once; hints
    // add no request of their own, and later rounds reuse the cached history.
    Mock::given(method("GET"))
        .and(path(format!("/{name}/latest")))
        .respond_with(ResponseTemplate::new(404))
        .expect(..=1)
        .mount(registry.server())
        .await;
    registry
        .with_package_metadata(name, "1.0.0", &selected_tarball, metadata)
        .await;
    let project = TempProject::empty(&serde_json::json!({"name":"hint-install","version":"1.0.0","dependencies":{name:"^1.0.0"}}).to_string());
    for round in 0..rounds {
        if round > 0 {
            std::fs::remove_dir_all(project.path().join("node_modules")).unwrap();
            std::fs::remove_file(project.path().join("lpm.lock")).unwrap();
        }
        let output = lpm_with_registry_and_npm(&project, &registry.url())
            .env("LPM_NPM_ROUTE", "direct")
            .args([
                "install",
                "--no-security-summary",
                "--no-skills",
                "--no-editor-setup",
            ])
            .assert();
        let rendered = format!(
            "{}{}",
            String::from_utf8_lossy(&output.get_output().stdout),
            String::from_utf8_lossy(&output.get_output().stderr)
        );
        let paths: Vec<_> = registry
            .server()
            .received_requests()
            .await
            .unwrap()
            .into_iter()
            .map(|request| request.url.path().to_owned())
            .collect();
        assert!(
            output.get_output().status.success(),
            "{rendered}; requests: {paths:?}"
        );
        assert!(rendered.contains("latest-hint-package@1.0.0"), "{rendered}");
        assert!(!rendered.contains("(v3.0.0 available)"), "{rendered}");
        if let Some(hint) = expected_hint {
            assert!(rendered.contains(hint), "{rendered}");
        } else {
            assert!(!rendered.contains(" available)"), "{rendered}");
        }
    }
    let requests = registry.server().received_requests().await.unwrap();
    assert_eq!(
        requests
            .iter()
            .filter(|request| request.url.path() == format!("/{name}"))
            .count(),
        1
    );
    registry.server().verify().await;
}

#[tokio::test]
async fn exact_fallback_and_lock_replay_do_not_retry_history_for_hints() {
    let registry = MockRegistry::start().await;
    let name = "exact-hint-package";
    let tarball =
        make_tarball_from_pkg_json(serde_json::json!({"name":name,"version":"1.0.0"}), &[]);
    let metadata = registry.package_metadata(name, "1.0.0", &tarball);
    Mock::given(method("GET"))
        .and(path(format!("/{name}/1.0.0")))
        .respond_with(ResponseTemplate::new(200).set_body_json(&metadata["versions"]["1.0.0"]))
        .expect(1)
        .mount(registry.server())
        .await;
    registry
        .with_package_metadata(name, "1.0.0", &tarball, metadata)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/{name}")))
        .respond_with(ResponseTemplate::new(404))
        .with_priority(1)
        .expect(1)
        .mount(registry.server())
        .await;
    let project = TempProject::empty(
        &serde_json::json!({
            "name":"exact-hint-install","version":"1.0.0","dependencies":{name:"1.0.0"}
        })
        .to_string(),
    );
    for round in 0..2 {
        if round > 0 {
            std::fs::remove_dir_all(project.path().join("node_modules")).unwrap();
        }
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
        let rendered = format!(
            "{}{}",
            String::from_utf8_lossy(&output.get_output().stdout),
            String::from_utf8_lossy(&output.get_output().stderr)
        );
        assert!(!rendered.contains(" available)"), "{rendered}");
        assert!(
            project
                .path()
                .join("node_modules/exact-hint-package/package.json")
                .is_file()
        );
    }
    let requests = registry.server().received_requests().await.unwrap();
    assert!(
        !requests
            .iter()
            .any(|request| request.url.path() == format!("/{name}/latest"))
    );
    registry.server().verify().await;
}

#[tokio::test]
async fn worker_batch_hint_does_not_treat_an_untagged_version_as_latest() {
    worker_batch_hint(None, None).await;
}

#[tokio::test]
async fn worker_batch_hint_preserves_the_advertised_tag_below_an_untagged_version() {
    worker_batch_hint(Some("2.0.0"), Some("(v2.0.0 available)")).await;
}

async fn worker_batch_hint(tag: Option<&str>, expected_hint: Option<&str>) {
    let registry = MockRegistry::start().await;
    let name = "worker-hint-package";
    let tarball =
        make_tarball_from_pkg_json(serde_json::json!({"name":name,"version":"1.0.0"}), &[]);
    let mut first = registry.package_metadata(name, "1.0.0", &tarball);
    first["dist-tags"] = tag.map_or_else(
        || serde_json::json!({}),
        |tag| serde_json::json!({"latest":tag}),
    );
    if let Some(tag) = tag {
        first["versions"][tag] = serde_json::json!({"name":name,"version":tag});
    }
    let second =
        serde_json::json!({"name":name,"versions":{"3.0.0":{"name":name,"version":"3.0.0"}}});
    registry
        .with_package_metadata(name, "1.0.0", &tarball, first.clone())
        .await;
    let body = format!(
        "{}\n{}\n",
        serde_json::json!({"name":name,"metadata":first}),
        serde_json::json!({"name":name,"metadata":second})
    );
    Mock::given(method("POST"))
        .and(path("/api/registry/batch-metadata"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(body, "application/x-ndjson"))
        .expect(1)
        .mount(registry.server())
        .await;
    let project = TempProject::empty(&serde_json::json!({"name":"worker-hint-install","version":"1.0.0","dependencies":{name:"^1.0.0"}}).to_string());
    let output = support::lpm_with_registry(&project, &registry.url())
        .env("LPM_WORKER_RANGE_AWARE_BATCH", "1")
        .env("LPM_WORKER_STREAMING_BATCH", "0")
        .args([
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .assert()
        .success();
    let rendered = format!(
        "{}{}",
        String::from_utf8_lossy(&output.get_output().stdout),
        String::from_utf8_lossy(&output.get_output().stderr)
    );
    assert!(!rendered.contains("(v3.0.0 available)"), "{rendered}");
    if let Some(hint) = expected_hint {
        assert!(rendered.contains(hint), "{rendered}");
    } else {
        assert!(!rendered.contains(" available)"), "{rendered}");
    }
    registry.server().verify().await;
}
