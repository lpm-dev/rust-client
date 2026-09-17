use super::support::mock_registry::MockRegistry;
use super::support::{TempProject, lpm_with_registry};
use serde_json::{Value, json};
use wiremock::{
    Mock, ResponseTemplate,
    matchers::{method, path},
};

fn metadata() -> Value {
    json!({
        "name":"info-fixture", "description":"Package description",
        "dist-tags":{"latest":"1.10.0","next":"1.2.0","broken":"9.0.0"},
        "versions":{
            "1.0.0":{"name":"info-fixture","version":"1.0.0","dependencies":{"runtime-dep":"^1"},"peerDependencies":{"peer-dep":"^1"}},
            "1.2.0":{"name":"info-fixture","version":"1.2.0"},
            "1.10.0":{"name":"info-fixture","version":"1.10.0"}
        },
        "time":{"1.0.0":"2025-01-01T00:00:00Z","1.10.0":"2026-01-01T00:00:00Z"}
    })
}

async fn fixture(body: Value) -> (TempProject, MockRegistry) {
    let project = TempProject::empty(r#"{"name":"info-contract","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    project.write_file(".npmrc", &format!("registry={}\n", mock.url()));
    Mock::given(method("GET"))
        .and(path("/info-fixture"))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .mount(mock.server())
        .await;
    (project, mock)
}

#[tokio::test]
async fn info_rejects_unresolvable_selectors_in_both_output_modes() {
    for selector in ["9.0.0", "broken", "^9", "unknown-tag", ""] {
        for json_output in [false, true] {
            let (project, mock) = fixture(metadata()).await;
            let mut command = lpm_with_registry(&project, &mock.url());
            command.args(["info", "info-fixture", "--version", selector]);
            if json_output {
                command.arg("--json");
            }
            let output = command.output().unwrap();
            assert!(
                !output.status.success(),
                "invalid selector {selector:?} succeeded (json={json_output}): {}",
                String::from_utf8_lossy(&output.stdout)
            );
            if json_output {
                let envelope: Value = serde_json::from_slice(&output.stdout).unwrap();
                assert_eq!(envelope["success"], false);
            }
        }
    }
}

#[tokio::test]
async fn info_resolves_tags_ranges_and_exact_versions_in_both_output_modes() {
    for (selector, expected) in [("next", "1.2.0"), ("^1", "1.10.0"), ("1.0.0", "1.0.0")] {
        for json_output in [false, true] {
            let (project, mock) = fixture(metadata()).await;
            let mut command = lpm_with_registry(&project, &mock.url());
            command.args(["info", &format!("info-fixture@{selector}")]);
            if json_output {
                command.arg("--json");
            }
            let output = command.output().unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stdout)
            );
            if json_output {
                let envelope: Value = serde_json::from_slice(&output.stdout).unwrap();
                assert_eq!(envelope["selected_version"], expected);
                assert_eq!(envelope["versions"].as_object().unwrap().len(), 3);
                assert_eq!(envelope["dist-tags"]["latest"], "1.10.0");
            } else {
                assert!(
                    String::from_utf8_lossy(&output.stdout)
                        .contains(&format!("version      {expected}")),
                    "selector {selector} did not select {expected}"
                );
            }
        }
    }
}

#[tokio::test]
async fn info_shows_the_selected_versions_publication_date() {
    let (project, mock) = fixture(metadata()).await;
    let output = lpm_with_registry(&project, &mock.url())
        .args(["info", "info-fixture@1.0.0"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("published    2025-01-01T00:00:00Z"),
        "{stdout}"
    );
    assert!(!stdout.contains("2026-01-01"));
}

#[tokio::test]
async fn info_rejects_version_identity_mismatches_before_success_output() {
    for json_output in [false, true] {
        let mut body = metadata();
        body["versions"]["1.0.0"]["version"] = json!("2.0.0\u{1b}[2J");
        let (project, mock) = fixture(body).await;
        let mut command = lpm_with_registry(&project, &mock.url());
        command.args(["info", "info-fixture@1.0.0"]);
        if json_output {
            command.arg("--json");
        }
        let output = command.output().unwrap();
        assert!(
            !output.status.success(),
            "mismatched version identity must fail"
        );
        assert!(!output.stdout.contains(&0x1b) && !output.stderr.contains(&0x1b));
    }
}

#[tokio::test]
async fn info_without_a_default_version_returns_an_explicit_package_overview() {
    for empty in [false, true] {
        for json_output in [false, true] {
            let mut body = metadata();
            body["dist-tags"] = json!({});
            if empty {
                body["versions"] = json!({});
            }
            let (project, mock) = fixture(body).await;
            let mut command = lpm_with_registry(&project, &mock.url());
            command.args(["info", "info-fixture"]);
            if json_output {
                command.arg("--json");
            }
            let output = command.output().unwrap();
            assert!(output.status.success());
            if json_output {
                let envelope: Value = serde_json::from_slice(&output.stdout).unwrap();
                assert_eq!(envelope.get("selected_version"), Some(&Value::Null));
                assert_eq!(envelope["description"], "Package description");
            } else {
                let stdout = String::from_utf8_lossy(&output.stdout);
                assert!(
                    stdout.contains("No default version") && stdout.contains("Package description"),
                    "{stdout}"
                );
            }
        }
    }
}

#[tokio::test]
async fn info_uses_latest_tag_then_legacy_default_without_selecting_the_highest() {
    for use_tag in [false, true] {
        let mut body = metadata();
        body["latestVersion"] = json!("1.0.0");
        body["dist-tags"] = if use_tag {
            json!({"latest":"1.2.0"})
        } else {
            json!({})
        };
        let (project, mock) = fixture(body).await;
        let output = lpm_with_registry(&project, &mock.url())
            .args(["info", "info-fixture", "--json"])
            .output()
            .unwrap();
        assert!(output.status.success());
        let envelope: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(
            envelope["selected_version"],
            if use_tag { "1.2.0" } else { "1.0.0" }
        );
    }
}

#[tokio::test]
async fn info_rejects_dangling_default_pointers_in_both_output_modes() {
    for legacy in [false, true] {
        for json_output in [false, true] {
            let mut body = metadata();
            body["dist-tags"] = if legacy {
                json!({})
            } else {
                json!({"latest":"9.0.0"})
            };
            if legacy {
                body["latestVersion"] = json!("9.0.0");
            }
            let (project, mock) = fixture(body).await;
            let mut command = lpm_with_registry(&project, &mock.url());
            command.args(["info", "info-fixture"]);
            if json_output {
                command.arg("--json");
            }
            assert!(!command.output().unwrap().status.success());
        }
    }
}

#[tokio::test]
async fn info_json_preserves_all_versions_and_identifies_the_selected_version() {
    let (project, mock) = fixture(metadata()).await;
    let output = lpm_with_registry(&project, &mock.url())
        .args(["info", "info-fixture@1.0.0", "--json"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let envelope: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(envelope["selected_version"], "1.0.0");
    assert_eq!(envelope["versions"].as_object().unwrap().len(), 3);
    insta::with_settings!({sort_maps => true}, {
        insta::assert_json_snapshot!("info_selected_version_envelope", envelope);
    });
}

#[tokio::test]
async fn info_npm_authentication_errors_explain_npmrc_credentials() {
    for json_output in [false, true] {
        let (project, mock) = fixture(metadata()).await;
        mock.server().reset().await;
        Mock::given(method("GET"))
            .and(path("/info-fixture"))
            .respond_with(ResponseTemplate::new(401))
            .mount(mock.server())
            .await;
        let mut command = lpm_with_registry(&project, &mock.url());
        command.args(["info", "info-fixture"]);
        if json_output {
            command.arg("--json");
        }
        let output = command.output().unwrap();
        assert!(!output.status.success());
        let combined = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            combined.contains(".npmrc"),
            "wrong authentication advice: {combined}"
        );
        assert!(!combined.contains("lpm login") && !combined.contains("LPM_TOKEN"));
    }
}

#[tokio::test]
async fn info_rejects_registry_query_and_fragment_before_network() {
    for suffix in ["/base?mirror=1", "/base#fragment"] {
        let (project, mock) = fixture(metadata()).await;
        mock.server().reset().await;
        project.write_file(".npmrc", &format!("registry=\"{}{suffix}\"\n", mock.url()));
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_json(metadata()))
            .mount(mock.server())
            .await;
        let output = lpm_with_registry(&project, &mock.url())
            .args(["info", "info-fixture", "--json"])
            .output()
            .unwrap();
        assert!(
            !output.status.success(),
            "ambiguous registry URL must fail: {suffix}"
        );
        assert!(mock.server().received_requests().await.unwrap().is_empty());
    }
}

#[tokio::test]
async fn info_ignores_unrelated_lpm_tls_identity_in_proxy_mode() {
    let project = TempProject::empty(r#"{"name":"info-tls","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    project.write_private_file("user.npmrc", "//lpm-info.example.invalid/:certfile=missing-cert.pem\n//lpm-info.example.invalid/:keyfile=missing-key.pem\n");
    Mock::given(method("GET"))
        .and(path("/info-fixture"))
        .respond_with(ResponseTemplate::new(200).set_body_json(metadata()))
        .expect(1)
        .mount(mock.server())
        .await;
    let output = lpm_with_registry(&project, "https://lpm-info.example.invalid")
        .env("NPM_CONFIG_USERCONFIG", project.path().join("user.npmrc"))
        .env("LPM_INTERNAL_TEST_NPM_REGISTRY_URL", mock.url())
        .env("LPM_NPM_ROUTE", "proxy")
        .args(["info", "info-fixture", "--json"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "unrelated LPM identity blocked npm metadata: {}",
        String::from_utf8_lossy(&output.stdout)
    );
}

#[tokio::test]
async fn info_can_select_an_explicit_version_without_a_default() {
    let mut body = metadata();
    body["dist-tags"] = json!({});
    let (project, mock) = fixture(body).await;
    let output = lpm_with_registry(&project, &mock.url())
        .args(["info", "info-fixture@1.2.0", "--json"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let envelope: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(envelope["selected_version"], "1.2.0");
}

#[tokio::test]
async fn info_resolves_the_requested_version_after_conditional_revalidation() {
    use wiremock::matchers::header;
    let (project, mock) = fixture(metadata()).await;
    mock.server().reset().await;
    Mock::given(method("GET"))
        .and(path("/info-fixture"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("etag", "\"info-version\"")
                .set_body_json(metadata()),
        )
        .expect(1)
        .mount(mock.server())
        .await;
    let initial = lpm_with_registry(&project, &mock.url())
        .args(["info", "info-fixture", "--json"])
        .output()
        .unwrap();
    assert!(initial.status.success());
    mock.server().reset().await;
    Mock::given(method("GET"))
        .and(path("/info-fixture"))
        .and(header("if-none-match", "\"info-version\""))
        .respond_with(ResponseTemplate::new(304))
        .expect(1)
        .mount(mock.server())
        .await;
    let output = lpm_with_registry(&project, &mock.url())
        .args(["info", "info-fixture@next", "--json"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    let envelope: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(envelope["selected_version"], "1.2.0");
    assert_eq!(envelope["_cache"]["status"], "revalidated");
    assert_eq!(envelope["versions"].as_object().unwrap().len(), 3);
}
