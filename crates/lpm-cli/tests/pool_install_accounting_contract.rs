mod common;

use common::{MockPackage, MockPackageVersion};
use std::collections::HashMap;
use tempfile::TempDir;
use wiremock::matchers::{body_json, method, path as match_path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const TOKEN_ENV: &[(&str, &str)] = &[("LPM_TOKEN", "pool-accounting-test-token")];

fn isolated_project() -> (TempDir, TempDir) {
    let project = TempDir::new().expect("create temp project");
    let lpm_home = TempDir::new().expect("create temp LPM home");
    std::fs::write(
        project.path().join("package.json"),
        r#"{"name":"pool-accounting-fixture","version":"1.0.0"}"#,
    )
    .expect("seed package.json");
    (project, lpm_home)
}

async fn mount_lpm_install_auxiliary_routes(server: &MockServer) {
    Mock::given(method("GET"))
        .and(match_path("/api/registry/quality"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "name": "@lpm.dev/test.fixture",
            "score": 100,
            "maxScore": 100,
            "checks": [],
        })))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(match_path("/api/registry/skills"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "name": "@lpm.dev/test.fixture",
            "available": false,
            "skills": [],
        })))
        .mount(server)
        .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn managed_install_reports_topmost_pool_roots_after_cold_and_freshness_cache_hit_runs() {
    let server = MockServer::start().await;
    common::mount_mock_registry(
        &server,
        &[
            MockPackage {
                name: "@lpm.dev/alice.alpha",
                versions: vec![MockPackageVersion {
                    version: "1.0.0",
                    dependencies: vec![("npm-x", "1.0.0")],
                    bins: Vec::new(),
                }],
            },
            MockPackage {
                name: "npm-x",
                versions: vec![MockPackageVersion {
                    version: "1.0.0",
                    dependencies: vec![("@lpm.dev/bob.beta", "2.0.0")],
                    bins: Vec::new(),
                }],
            },
            MockPackage {
                name: "@lpm.dev/bob.beta",
                versions: vec![MockPackageVersion {
                    version: "2.0.0",
                    dependencies: Vec::new(),
                    bins: Vec::new(),
                }],
            },
        ],
    )
    .await;
    mount_lpm_install_auxiliary_routes(&server).await;
    let expected_report = serde_json::json!({
        "roots": [
            {
                "name": "@lpm.dev/alice.alpha",
                "version": "1.0.0",
            },
        ],
    });
    Mock::given(method("POST"))
        .and(match_path("/api/registry/pool/install-report"))
        .and(body_json(&expected_report))
        .respond_with(ResponseTemplate::new(200))
        .expect(2)
        .mount(&server)
        .await;

    let (project, lpm_home) = isolated_project();
    let (first_status, first_stdout, first_stderr) = common::run_lpm_with_env(
        project.path(),
        lpm_home.path(),
        Some(&server.uri()),
        TOKEN_ENV,
        &["install", "@lpm.dev/alice.alpha@1.0.0"],
    );
    let first_requests = server.received_requests().await.expect("received requests");
    assert!(
        first_status.success(),
        "cold install failed. stdout={first_stdout} stderr={first_stderr} requests={:?}",
        first_requests
            .iter()
            .map(|request| request.url.path().to_string())
            .collect::<Vec<_>>()
    );

    let (second_status, second_stdout, second_stderr) = common::run_lpm_with_env(
        project.path(),
        lpm_home.path(),
        Some(&server.uri()),
        TOKEN_ENV,
        &["install"],
    );
    assert!(
        second_status.success(),
        "freshness cache-hit install failed. stdout={second_stdout} stderr={second_stderr}"
    );

    let requests = server.received_requests().await.expect("received requests");
    let reports: Vec<_> = requests
        .iter()
        .filter(|request| request.url.path() == "/api/registry/pool/install-report")
        .collect();
    assert_eq!(
        reports.len(),
        2,
        "both cold and freshness runs must report. second stdout={second_stdout} stderr={second_stderr} package.json={} lockfile_exists={}",
        std::fs::read_to_string(project.path().join("package.json"))
            .unwrap_or_else(|error| format!("<read failed: {error}>")),
        project.path().join("lpm.lock").exists(),
    );
    assert_eq!(reports[0].body, reports[1].body);

    let managed_tarball_paths: Vec<_> = requests
        .iter()
        .filter(|request| {
            request
                .headers
                .get(lpm_registry::MANAGED_INSTALL_ACCOUNTING_HEADER)
                .is_some()
        })
        .map(|request| request.url.path().to_string())
        .collect();
    assert!(
        managed_tarball_paths
            .iter()
            .any(|path| path.contains("lpm.dev-alice.alpha-1.0.0.tgz"))
    );
    assert!(
        managed_tarball_paths
            .iter()
            .any(|path| path.contains("lpm.dev-bob.beta-2.0.0.tgz"))
    );
    assert!(
        managed_tarball_paths
            .iter()
            .all(|path| !path.contains("npm-x-1.0.0.tgz"))
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn exhausted_reporting_returns_truthful_json_and_human_partial_success_with_exit_one() {
    let server = MockServer::start().await;
    common::mount_mock_registry(
        &server,
        &[MockPackage {
            name: "@lpm.dev/alice.alpha",
            versions: vec![MockPackageVersion {
                version: "1.0.0",
                dependencies: Vec::new(),
                bins: Vec::new(),
            }],
        }],
    )
    .await;
    mount_lpm_install_auxiliary_routes(&server).await;
    Mock::given(method("POST"))
        .and(match_path("/api/registry/pool/install-report"))
        .respond_with(ResponseTemplate::new(422).set_body_string("report rejected"))
        .expect(2)
        .mount(&server)
        .await;

    let (project, lpm_home) = isolated_project();
    let (json_status, json_stdout, json_stderr) = common::run_lpm_with_env(
        project.path(),
        lpm_home.path(),
        Some(&server.uri()),
        TOKEN_ENV,
        &["--json", "install", "@lpm.dev/alice.alpha@1.0.0"],
    );
    assert_eq!(
        json_status.code(),
        Some(1),
        "JSON partial success must exit 1. stdout={json_stdout} stderr={json_stderr}"
    );
    let envelope = common::parse_json_stdout(&json_stdout);
    assert_eq!(envelope["success"], serde_json::json!(false));
    assert_eq!(envelope["installed"], serde_json::json!(true));
    assert_eq!(
        envelope["pool_attribution_confirmed"],
        serde_json::json!(false)
    );
    assert_eq!(
        envelope["error_code"],
        serde_json::json!("pool_attribution_unconfirmed")
    );
    assert_eq!(envelope["error"]["retry_safe"], serde_json::json!(true));
    assert!(
        project
            .path()
            .join("node_modules/@lpm.dev/alice.alpha")
            .exists(),
        "the partial-success envelope must only be emitted after linking completed"
    );

    let (human_status, human_stdout, human_stderr) = common::run_lpm_with_env(
        project.path(),
        lpm_home.path(),
        Some(&server.uri()),
        TOKEN_ENV,
        &["install", "@lpm.dev/alice.alpha@1.0.0"],
    );
    assert_eq!(
        human_status.code(),
        Some(1),
        "human partial success must exit 1. stdout={human_stdout} stderr={human_stderr}"
    );
    let human = common::strip_ansi(&format!("{human_stdout}\n{human_stderr}"));
    assert!(human.contains("Installed, but Pool attribution is unconfirmed"));
    assert!(human.contains("run the same lpm install command again"));
}

#[tokio::test(flavor = "multi_thread")]
async fn failed_install_never_sends_a_pool_accounting_report() {
    let server = MockServer::start().await;
    let package_name = "@lpm.dev/alice.alpha";
    let tarball_url = format!("{}/broken.tgz", server.uri());
    let integrity = common::sri_for(b"tarball response is never accepted");
    let metadata = lpm_registry::PackageMetadata {
        name: package_name.to_string(),
        description: None,
        dist_tags: HashMap::from([("latest".to_string(), "1.0.0".to_string())]),
        versions: HashMap::from([(
            "1.0.0".to_string(),
            lpm_registry::VersionMetadata {
                name: package_name.to_string(),
                version: "1.0.0".to_string(),
                dist: Some(lpm_registry::DistInfo {
                    tarball: Some(tarball_url),
                    integrity: Some(integrity),
                    ..Default::default()
                }),
                ..Default::default()
            },
        )]),
        time: HashMap::from([("1.0.0".to_string(), "2020-01-01T00:00:00.000Z".to_string())]),
        modified: None,
        downloads: None,
        distribution_mode: None,
        package_type: None,
        latest_version: Some("1.0.0".to_string()),
        ecosystem: None,
    };
    Mock::given(method("POST"))
        .and(match_path("/api/registry/batch-metadata"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "packages": {
                package_name: metadata,
            },
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(match_path("/api/registry/@lpm.dev/alice.alpha"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&metadata))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(match_path("/broken.tgz"))
        .respond_with(ResponseTemplate::new(422).set_body_string("broken tarball"))
        .expect(2)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(match_path("/api/registry/pool/install-report"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&server)
        .await;

    let (project, lpm_home) = isolated_project();
    let (status, stdout, stderr) = common::run_lpm_with_env(
        project.path(),
        lpm_home.path(),
        Some(&server.uri()),
        TOKEN_ENV,
        &["install", "@lpm.dev/alice.alpha@1.0.0"],
    );

    assert!(
        !status.success(),
        "broken tarball install unexpectedly succeeded. stdout={stdout} stderr={stderr}"
    );
    assert!(
        common::strip_ansi(&format!("{stdout}\n{stderr}")).contains("broken tarball"),
        "fixture must fail because the tarball request was rejected. stdout={stdout} stderr={stderr}"
    );
    assert!(
        server
            .received_requests()
            .await
            .expect("received requests")
            .iter()
            .all(|request| request.url.path() != "/api/registry/pool/install-report")
    );
}
