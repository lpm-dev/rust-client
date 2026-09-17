mod support;

use support::mock_registry::MockRegistry;
use support::{TempProject, lpm_with_registry};

fn assert_no_terminal_controls(context: &str, text: &str) {
    assert!(
        !text.bytes().any(|b| matches!(b, 0x07 | 0x1b | 0x7f)),
        "{context} must not contain terminal control bytes, got:\n{text}"
    );
}

fn sample_search_package(description: &str, download_count: u64) -> serde_json::Value {
    serde_json::json!({
        "name": "react",
        "owner": "neo",
        "description": description,
        "distributionMode": "pool",
        "downloadCount": download_count,
        "latestVersion": "1.2.3",
        "qualityScore": 91,
        "ecosystem": "js"
    })
}

#[tokio::test]
async fn search_human_output_sanitizes_registry_control_sequences() {
    let project = TempProject::empty(r#"{"name":"search-controls","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    let mut package =
        sample_search_package("safe description\u{1b}]8;;file:///etc/passwd\u{7}", 12_345);
    package["name"] = serde_json::json!("react\u{1b}[2J");
    package["owner"] = serde_json::json!("neo\u{7}");
    package["latestVersion"] = serde_json::json!("1.2.3\u{1b}[31m");
    package["ecosystem"] = serde_json::json!("js\u{1b}[0m");
    mock.with_search_results("@lpm.dev/react", 20, vec![package])
        .await;

    let output = lpm_with_registry(&project, &mock.url())
        .args(["search", "@lpm.dev/react"])
        .output()
        .expect("failed to run lpm search");

    assert!(
        output.status.success(),
        "lpm search failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_no_terminal_controls("search output", &combined);
    assert!(
        combined.contains("safe description") && combined.contains("latest 1.2.3"),
        "sanitized search output should preserve readable registry text, got:\n{combined}",
    );
}

#[tokio::test]
async fn search_without_matches_warns_and_exits_zero() {
    let project = TempProject::empty(r#"{"name":"search-test","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    mock.with_search_results("@lpm.dev/nothing-here", 20, vec![])
        .await;

    let output = lpm_with_registry(&project, &mock.url())
        .args(["search", "@lpm.dev/nothing-here"])
        .output()
        .expect("failed to run lpm search");

    assert!(
        output.status.success(),
        "search with zero results must exit 0"
    );

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("No packages found for \"@lpm.dev/nothing-here\""),
        "expected empty-result warning, got:\n{combined}"
    );
    assert!(
        combined.contains(&format!(
            "› Searching {} for \"@lpm.dev/nothing-here\"",
            mock.url().trim_start_matches("http://")
        )),
        "search must use a slim phase line, got:\n{combined}"
    );
    assert!(
        !combined.contains('●') && !combined.contains('│'),
        "search empty-result output must not use cliclack gutter output, got:\n{combined}"
    );
}

#[tokio::test]
async fn search_human_output_truncates_long_description_and_prints_metadata_line() {
    let project = TempProject::empty(r#"{"name":"search-test","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    let long_description = "This description is intentionally long so the human output path must truncate it before rendering to the terminal.";
    mock.with_search_results(
        "@lpm.dev/react",
        20,
        vec![sample_search_package(long_description, 12_345)],
    )
    .await;

    let output = lpm_with_registry(&project, &mock.url())
        .args(["search", "@lpm.dev/react"])
        .output()
        .expect("failed to run lpm search");

    assert!(
        output.status.success(),
        "lpm search failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("@lpm.dev/neo.react"),
        "package name must be rendered, got:\n{combined}"
    );
    assert!(
        combined.contains("latest 1.2.3 · quality 91 · ecosystem js"),
        "metadata line must include latest version, quality, and ecosystem, got:\n{combined}"
    );
    assert!(
        !combined.contains("↓") && !combined.contains("12K") && !combined.contains(" pool"),
        "search results should drop mode badges and download rows, got:\n{combined}"
    );
    assert!(
        combined.contains(
            "This description is intentionally long so the human output path must truncate..."
        ),
        "long descriptions must be truncated with an ellipsis, got:\n{combined}"
    );
    assert!(
        combined.contains("✓ Found 1 package"),
        "search must report a slim result count, got:\n{combined}"
    );
    assert!(
        !combined.contains('●') && !combined.contains('│'),
        "search output must not use cliclack gutter output, got:\n{combined}"
    );
}

#[tokio::test]
async fn search_json_envelope_one_result_matches_snapshot() {
    let project = TempProject::empty(r#"{"name":"search-test","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    mock.with_search_results(
        "@lpm.dev/react",
        20,
        vec![sample_search_package("Fast UI package", 12_345)],
    )
    .await;

    let output = lpm_with_registry(&project, &mock.url())
        .args(["search", "@lpm.dev/react", "--json"])
        .output()
        .expect("failed to run lpm search --json");

    assert!(
        output.status.success(),
        "lpm search --json failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let envelope: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("search --json must be valid JSON: {e}\n---\n{stdout}"));

    assert_eq!(envelope["success"], serde_json::json!(true));
    assert_eq!(envelope["count"], serde_json::json!(1));
    assert_eq!(envelope["packages"][0]["name"], serde_json::json!("react"));
    assert_eq!(
        envelope["packages"][0]["latestVersion"],
        serde_json::json!("1.2.3")
    );

    insta::assert_json_snapshot!("search_json_envelope_one_result", envelope);
}

#[tokio::test]
async fn search_rejects_out_of_range_limits_before_network() {
    for limit in ["0", "21", "4294967295"] {
        let project = TempProject::empty(r#"{"name":"search-limits","version":"1.0.0"}"#);
        let mock = MockRegistry::start().await;
        mock.with_search_results(
            "@lpm.dev/query",
            limit.parse::<u32>().unwrap().min(20),
            vec![],
        )
        .await;
        let output = lpm_with_registry(&project, &mock.url())
            .args(["search", "@lpm.dev/query", "--limit", limit])
            .output()
            .unwrap();
        assert!(
            !output.status.success(),
            "limit {limit} must fail before the request"
        );
        assert!(mock.server().received_requests().await.unwrap().is_empty());
    }
}

#[tokio::test]
async fn search_accepts_both_limit_boundaries() {
    for limit in ["1", "20"] {
        let project = TempProject::empty(r#"{"name":"search-limits","version":"1.0.0"}"#);
        let mock = MockRegistry::start().await;
        mock.with_search_results("@lpm.dev/query", limit.parse().unwrap(), vec![])
            .await;
        let output = lpm_with_registry(&project, &mock.url())
            .args(["search", "@lpm.dev/query", "--limit", limit, "--json"])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(json["count"], 0);
    }
}

#[tokio::test]
async fn search_rejects_malformed_npm_success_envelopes() {
    use wiremock::{
        Mock, ResponseTemplate,
        matchers::{method, path},
    };
    for body in [
        serde_json::json!({}),
        serde_json::json!({"error":"access denied"}),
        serde_json::json!({"objects":{}}),
    ] {
        let project = TempProject::empty(r#"{"name":"search-envelope","version":"1.0.0"}"#);
        let mock = MockRegistry::start().await;
        project.write_file(".npmrc", &format!("registry={}\n", mock.url()));
        Mock::given(method("GET"))
            .and(path("/-/v1/search"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&body))
            .mount(mock.server())
            .await;
        let output = lpm_with_registry(&project, &mock.url())
            .args(["search", "react", "--json"])
            .output()
            .unwrap();
        assert!(
            !output.status.success(),
            "invalid response must fail: {body}; stdout={}",
            String::from_utf8_lossy(&output.stdout)
        );
    }
}

#[tokio::test]
async fn search_accepts_valid_empty_and_populated_npm_envelopes() {
    use wiremock::{
        Mock, ResponseTemplate,
        matchers::{method, path},
    };
    for objects in [
        serde_json::json!([]),
        serde_json::json!([{"package":{"name":"react","version":"1.2.3"}}]),
    ] {
        let project = TempProject::empty(r#"{"name":"search-envelope","version":"1.0.0"}"#);
        let mock = MockRegistry::start().await;
        project.write_file(".npmrc", &format!("registry={}\n", mock.url()));
        Mock::given(method("GET"))
            .and(path("/-/v1/search"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"objects":objects})),
            )
            .mount(mock.server())
            .await;
        let output = lpm_with_registry(&project, &mock.url())
            .args(["search", "react", "--json"])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(json["count"], objects.as_array().unwrap().len());
    }
}

#[tokio::test]
async fn search_npm_authentication_errors_explain_npmrc_credentials() {
    use wiremock::{
        Mock, ResponseTemplate,
        matchers::{method, path},
    };
    for json in [false, true] {
        let project = TempProject::empty(r#"{"name":"search-auth","version":"1.0.0"}"#);
        let mock = MockRegistry::start().await;
        project.write_file(".npmrc", &format!("registry={}\n", mock.url()));
        Mock::given(method("GET"))
            .and(path("/-/v1/search"))
            .respond_with(ResponseTemplate::new(401))
            .mount(mock.server())
            .await;
        let mut command = lpm_with_registry(&project, &mock.url());
        command.args(["search", "react"]);
        if json {
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
async fn search_rejects_registry_query_and_fragment_before_network() {
    use wiremock::{Mock, ResponseTemplate, matchers::method};
    for suffix in ["/base?mirror=1", "/base#fragment"] {
        let project = TempProject::empty(r#"{"name":"search-url","version":"1.0.0"}"#);
        let mock = MockRegistry::start().await;
        project.write_file(".npmrc", &format!("registry=\"{}{suffix}\"\n", mock.url()));
        Mock::given(method("GET"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"objects":[]})),
            )
            .mount(mock.server())
            .await;
        let output = lpm_with_registry(&project, &mock.url())
            .args(["search", "react", "--json"])
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
async fn search_ignores_unrelated_lpm_tls_identity_in_proxy_mode() {
    use wiremock::{
        Mock, ResponseTemplate,
        matchers::{method, path},
    };
    let project = TempProject::empty(r#"{"name":"search-tls","version":"1.0.0"}"#);
    let lpm_mock = MockRegistry::start().await;
    let npm_mock = MockRegistry::start().await;
    let origin = "lpm-search.example.invalid";
    project.write_file(
        ".npmrc",
        &format!("//{origin}/:certfile=missing-cert.pem\n//{origin}/:keyfile=missing-key.pem\n"),
    );
    Mock::given(method("GET"))
        .and(path("/-/v1/search"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"objects":[]})))
        .mount(npm_mock.server())
        .await;
    let output = lpm_with_registry(&project, "https://lpm-search.example.invalid")
        .env("NPM_CONFIG_USERCONFIG", project.path().join(".npmrc"))
        .env("LPM_INTERNAL_TEST_NPM_REGISTRY_URL", npm_mock.url())
        .env("LPM_NPM_ROUTE", "proxy")
        .args(["search", "react", "--json"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "unrelated LPM identity blocked npm search: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(
        lpm_mock
            .server()
            .received_requests()
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        npm_mock.server().received_requests().await.unwrap().len(),
        1
    );
}

#[tokio::test]
async fn search_preserves_registry_path_prefix_and_scoped_credentials() {
    use wiremock::{
        Mock, ResponseTemplate,
        matchers::{header, method, path, query_param},
    };
    let project = TempProject::empty(r#"{"name":"search-path","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    project.write_private_file(
        ".npmrc",
        &format!(
            "@company:registry={}/npm/\n//{}/npm/:_authToken=search-secret\n",
            mock.url(),
            mock.url().trim_start_matches("http://")
        ),
    );
    Mock::given(method("GET"))
        .and(path("/npm/-/v1/search"))
        .and(query_param("text", "@company/tool"))
        .and(header("authorization", "Bearer search-secret"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"objects":[]})))
        .expect(1)
        .mount(mock.server())
        .await;
    let output = lpm_with_registry(&project, &mock.url())
        .args(["search", "@company/tool", "--json"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
}

#[tokio::test]
async fn search_lpm_catalogue_remains_anonymous_with_available_credentials() {
    let project = TempProject::empty(r#"{"name":"search-anonymous","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    let unused = MockRegistry::start().await;
    project.write_private_file(
        ".npmrc",
        &format!(
            "@lpm.dev:registry={}\n//{}/:_authToken=npm-secret\n",
            unused.url(),
            mock.url().trim_start_matches("http://")
        ),
    );
    mock.with_search_results("@lpm.dev/alice", 20, vec![]).await;
    let output = lpm_with_registry(&project, &mock.url())
        .env("LPM_TOKEN", "ambient-secret")
        .args([
            "--token",
            "explicit-secret",
            "search",
            "@lpm.dev/alice",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    let requests = mock.server().received_requests().await.unwrap();
    assert_eq!(requests.len(), 1);
    assert!(requests[0].headers.get("authorization").is_none());
    assert!(
        unused
            .server()
            .received_requests()
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn search_enforces_limit_when_registry_returns_extra_results() {
    use wiremock::{
        Mock, ResponseTemplate,
        matchers::{method, path},
    };
    for lpm_route in [true, false] {
        let project = TempProject::empty(r#"{"name":"search-cap","version":"1.0.0"}"#);
        let mock = MockRegistry::start().await;
        let query = if lpm_route { "@lpm.dev/alice" } else { "react" };
        if lpm_route {
            mock.with_search_results(
                query,
                1,
                vec![
                    sample_search_package("first", 0),
                    sample_search_package("second", 0),
                ],
            )
            .await;
        } else {
            project.write_file(".npmrc", &format!("registry={}\n", mock.url()));
            Mock::given(method("GET")).and(path("/-/v1/search"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"objects":[{"package":{"name":"first","version":"1.0.0"}},{"package":{"name":"second","version":"1.0.0"}}]})))
                .mount(mock.server()).await;
        }
        let output = lpm_with_registry(&project, &mock.url())
            .args(["search", query, "--limit", "1", "--json"])
            .output()
            .unwrap();
        assert!(output.status.success());
        let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(json["count"], 1, "search must enforce its requested limit");
        assert_eq!(json["packages"].as_array().unwrap().len(), 1);
    }
}
