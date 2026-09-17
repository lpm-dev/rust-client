use super::*;

#[test]
fn publish_check_accepts_a_utf8_bom_manifest() {
    let project = TempProject::empty("\u{feff}{\"name\":\"bom-package\",\"version\":\"1.0.0\"}");
    let before = std::fs::read(project.path().join("package.json")).unwrap();
    let output = lpm(&project)
        .args(["publish", "--npm", "--check", "--ignore-scripts", "--json"])
        .output()
        .unwrap();
    assert!(output.status.success(), "BOM manifest rejected: {output:?}");
    assert_eq!(
        std::fs::read(project.path().join("package.json")).unwrap(),
        before
    );
}

#[tokio::test]
async fn publish_rejects_duplicate_resolved_destinations_before_network() {
    let server = MockServer::start().await;
    let project = TempProject::empty(r#"{"name":"duplicate-package","version":"1.0.0"}"#);
    project.write_file(
        "lpm.json",
        &serde_json::json!({
            "publish": {"npm": {"registry": server.uri()}}
        })
        .to_string(),
    );
    let output = lpm(&project)
        .args([
            "publish",
            "--npm",
            "--publish-registry",
            &format!("{}/", server.uri()),
            "--check",
            "--ignore-scripts",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "duplicate destination accepted: {output:?}"
    );
    let body: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(
        body["error"]
            .as_str()
            .unwrap()
            .contains("same publication destination"),
        "{body}"
    );
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn publish_custom_npm_success_does_not_link_to_npmjs() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;
    Mock::given(method("PUT"))
        .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({"ok": true})))
        .expect(1)
        .mount(&server)
        .await;
    let project = TempProject::empty(r#"{"name":"custom-output-package","version":"1.0.0"}"#);
    project.write_file(
        "lpm.json",
        &serde_json::json!({
            "publish": {"npm": {"registry": server.uri()}}
        })
        .to_string(),
    );
    let login = lpm(&project)
        .args([
            "login",
            "--login-registry",
            &server.uri(),
            "--token",
            CUSTOM_REGISTRY_TOKEN,
            "--json",
        ])
        .output()
        .unwrap();
    assert!(login.status.success(), "{login:?}");
    let output = lpm(&project)
        .args([
            "publish",
            "--npm",
            "--yes",
            "--ignore-scripts",
            "--no-provenance",
        ])
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !text.contains("https://www.npmjs.com/package/"),
        "wrong registry link: {text}"
    );
}

#[test]
fn publish_check_accepts_a_bom_projected_manifest() {
    let project = TempProject::empty(
        r#"{"name":"source-package","version":"1.0.0","publishConfig":{"directory":"dist"}}"#,
    );
    project.write_file(
        "dist/package.json",
        "\u{feff}{\"name\":\"projected-package\",\"version\":\"1.0.0\"}",
    );
    let output = lpm(&project)
        .args(["publish", "--npm", "--check", "--ignore-scripts", "--json"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "BOM projection rejected: {output:?}"
    );
}

#[tokio::test]
async fn publish_gitlab_missing_token_requires_the_full_registry_login_endpoint() {
    let server = MockServer::start().await;
    let project = TempProject::empty(r#"{"name":"gitlab-token-package","version":"1.0.0"}"#);
    project.write_file(
        "lpm.json",
        &serde_json::json!({
            "publish": {"gitlab": {"registry": server.uri(), "projectId": "42"}}
        })
        .to_string(),
    );
    let output = lpm(&project)
        .args([
            "publish",
            "--gitlab",
            "--dry-run",
            "--ignore-scripts",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success(), "{output:?}");
    let body: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let expected = "lpm login --login-registry <gitlab-package-registry-url> --token";
    assert!(
        body["error"].as_str().unwrap().contains(expected),
        "login hint cannot satisfy the scoped credential lookup: {body}"
    );
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn publish_bom_manifest_survives_target_rename_and_source_stays_unchanged() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;
    Mock::given(method("PUT"))
        .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({"ok": true})))
        .expect(1)
        .mount(&server)
        .await;
    let manifest = "\u{feff}{\"name\":\"source-package\",\"version\":\"1.0.0\"}";
    let project = TempProject::empty(manifest);
    project.write_file(
        "lpm.json",
        &serde_json::json!({
            "publish": {"npm": {"registry": server.uri(), "name": "renamed-package"}}
        })
        .to_string(),
    );
    let login = lpm(&project)
        .args([
            "login",
            "--login-registry",
            &server.uri(),
            "--token",
            CUSTOM_REGISTRY_TOKEN,
            "--json",
        ])
        .output()
        .unwrap();
    assert!(login.status.success(), "{login:?}");
    let output = lpm(&project)
        .args([
            "publish",
            "--npm",
            "--yes",
            "--ignore-scripts",
            "--no-provenance",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "BOM target rename failed: {output:?}"
    );
    assert_eq!(
        std::fs::read_to_string(project.path().join("package.json")).unwrap(),
        manifest
    );
    let requests = server.received_requests().await.unwrap();
    let request = requests
        .iter()
        .find(|request| request.method.as_str() == "PUT")
        .unwrap();
    let tarball = extract_lpm_upload_tarball(request);
    assert_eq!(
        extract_uploaded_package_json(&tarball)["name"],
        "renamed-package"
    );
}

#[test]
fn publish_allows_distinct_names_on_the_same_registry() {
    let project = TempProject::empty(r#"{"name":"@acme/source","version":"1.0.0"}"#);
    project.write_file(
        "lpm.json",
        r#"{"publish":{"github":{"name":"@acme/github"},"npm":{"name":"@acme/custom"}}}"#,
    );
    let output = lpm(&project)
        .args([
            "publish",
            "--github",
            "--publish-registry",
            "https://npm.pkg.github.com",
            "--check",
            "--ignore-scripts",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "distinct names rejected: {output:?}"
    );
    let body: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(body["targets"].as_array().unwrap().len(), 2);
}
