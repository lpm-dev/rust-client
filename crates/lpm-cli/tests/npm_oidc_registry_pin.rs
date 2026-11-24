//! Intentionally minimal binary-surface repro verifying that the compiled
//! `lpm-rs` debug binary never sends an npm OIDC JWT to an arbitrary loopback
//! registry configured in `lpm.json` without an explicit test-harness opt-in.

mod common;

use std::fs;
use wiremock::matchers::any;
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn debug_cli_never_sends_npm_oidc_jwt_to_loopback_registry() {
    let server = MockServer::start().await;
    Mock::given(any())
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&server)
        .await;

    let project = tempfile::tempdir().expect("create temp project");
    let home = tempfile::tempdir().expect("create temp home");
    fs::write(
        project.path().join("package.json"),
        r#"{
  "name": "oidc-loopback-pin-pkg",
  "version": "1.0.0",
  "description": "Verifies debug CLI refuses npm OIDC exchange on loopback",
  "main": "index.js",
  "license": "MIT"
}"#,
    )
    .expect("write package.json");
    fs::write(project.path().join("index.js"), "module.exports = {};\n").expect("write index.js");
    fs::write(
        project.path().join("lpm.json"),
        format!(
            r#"{{"publish":{{"npm":{{"registry":"{}","access":"public"}}}}}}"#,
            server.uri()
        ),
    )
    .expect("write lpm.json");

    let (status, stdout, stderr) = common::run_lpm_with_env(
        project.path(),
        home.path(),
        None,
        &[("NPM_ID_TOKEN", "secret-npm-oidc-jwt")],
        &["publish", "--npm", "--yes"],
    );

    assert!(
        !status.success(),
        "debug binary must refuse loopback npm OIDC exchange without explicit opt-in\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    let requests = server
        .received_requests()
        .await
        .expect("wiremock request log");
    assert!(
        requests.is_empty(),
        "loopback registry must receive zero requests when OIDC override is unset; got {} request(s)",
        requests.len()
    );
    server.verify().await;
}
