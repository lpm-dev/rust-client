mod support;

use support::assertions::parse_json_output;
use support::mock_registry::{MockRegistry, make_tarball};
use support::{TempProject, lpm_with_registry};
use wiremock::matchers::{header, method, path, query_param};
use wiremock::{Mock, ResponseTemplate};

const TOKEN: &str = "ITEM8-READ-ONLY-TOKEN";
const PACKAGE_NAME: &str = "lodash.merge";
const VERSION: &str = "4.6.2";

fn write_project_npmrc(project: &TempProject, registry_url: &str) {
    let host_no_scheme = registry_url
        .strip_prefix("http://")
        .or_else(|| registry_url.strip_prefix("https://"))
        .unwrap_or(registry_url);
    project.write_file(
        ".npmrc",
        &format!("registry={registry_url}/\n//{host_no_scheme}/:_authToken={TOKEN}\n"),
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            project.path().join(".npmrc"),
            std::fs::Permissions::from_mode(0o600),
        )
        .expect("restrict project npmrc permissions");
    }
}

async fn mount_auth_required_npm_package(mock: &MockRegistry) {
    let auth_value = format!("Bearer {TOKEN}");
    let server_url = mock.url();
    let tarball = make_tarball(PACKAGE_NAME, VERSION);
    let tarball_path = MockRegistry::tarball_path(PACKAGE_NAME, VERSION);
    let tarball_url = format!("{server_url}{tarball_path}");
    let metadata = serde_json::json!({
        "name": PACKAGE_NAME,
        "dist-tags": { "latest": VERSION },
        "versions": {
            VERSION: {
                "name": PACKAGE_NAME,
                "version": VERSION,
                "dist": {
                    "tarball": tarball_url,
                    "integrity": support::mock_registry::compute_integrity(&tarball),
                },
                "dependencies": {}
            }
        },
        "time": { VERSION: "2025-01-01T00:00:00.000Z" }
    });

    Mock::given(method("GET"))
        .and(path(format!("/{PACKAGE_NAME}")))
        .and(header("Authorization", auth_value.as_str()))
        .respond_with(ResponseTemplate::new(200).set_body_json(metadata))
        .mount(mock.server())
        .await;

    Mock::given(method("GET"))
        .and(path(tarball_path))
        .and(header("Authorization", auth_value.as_str()))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_bytes(tarball)
                .insert_header("content-type", "application/octet-stream"),
        )
        .mount(mock.server())
        .await;
}

async fn mount_auth_required_npm_search(mock: &MockRegistry, query: &str, limit: u32) {
    let auth_value = format!("Bearer {TOKEN}");
    Mock::given(method("GET"))
        .and(path("/-/v1/search"))
        .and(query_param("text", query))
        .and(query_param("size", limit.to_string()))
        .and(header("Authorization", auth_value.as_str()))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "objects": [
                {
                    "package": {
                        "name": PACKAGE_NAME,
                        "version": VERSION,
                        "description": "Deep object merge helper"
                    }
                }
            ]
        })))
        .mount(mock.server())
        .await;
}

async fn received_auth_headers(mock: &MockRegistry) -> Vec<Option<String>> {
    mock.server()
        .received_requests()
        .await
        .expect("wiremock recorded request log")
        .into_iter()
        .map(|request| {
            request
                .headers
                .get("Authorization")
                .and_then(|value| value.to_str().ok())
                .map(ToOwned::to_owned)
        })
        .collect()
}

#[cfg(unix)]
#[tokio::test]
async fn json_routing_warns_when_permissive_npmrc_credentials_are_refused() {
    use std::os::unix::fs::PermissionsExt;

    let project = TempProject::empty(r#"{"name":"read-only-routing","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    write_project_npmrc(&project, &mock.url());
    std::fs::set_permissions(
        project.path().join(".npmrc"),
        std::fs::Permissions::from_mode(0o644),
    )
    .expect("make project npmrc permissive");

    let metadata = serde_json::json!({
        "name": PACKAGE_NAME,
        "dist-tags": { "latest": VERSION },
        "versions": {
            VERSION: {
                "name": PACKAGE_NAME,
                "version": VERSION,
                "dist": {
                    "tarball": format!("{}/{PACKAGE_NAME}-{VERSION}.tgz", mock.url()),
                    "integrity": "sha512-unused"
                }
            }
        },
        "time": { VERSION: "2025-01-01T00:00:00.000Z" }
    });
    Mock::given(method("GET"))
        .and(path(format!("/{PACKAGE_NAME}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(metadata))
        .mount(mock.server())
        .await;

    let output = lpm_with_registry(&project, &mock.url())
        .env_remove("LPM_NPM_ROUTE")
        .env_remove("LPM_TOKEN")
        .args(["info", PACKAGE_NAME, "--json"])
        .output()
        .expect("run lpm info --json");

    assert!(
        output.status.success(),
        "routing must remain usable after credential refusal; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    assert_eq!(parse_json_output(&output.stdout)["success"], true);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("refus") && stderr.contains("chmod 600"),
        "JSON mode must surface actionable credential refusal, got:\n{stderr}"
    );
    assert_eq!(received_auth_headers(&mock).await, vec![None]);
}

#[tokio::test]
async fn info_json_routes_bare_package_through_project_npmrc_registry() {
    let project = TempProject::empty(r#"{"name":"read-only-routing","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    write_project_npmrc(&project, &mock.url());
    mount_auth_required_npm_package(&mock).await;

    let output = lpm_with_registry(&project, &mock.url())
        .env_remove("LPM_NPM_ROUTE")
        .env_remove("LPM_TOKEN")
        .args(["info", PACKAGE_NAME, "--json"])
        .output()
        .expect("failed to run lpm info --json");

    assert!(
        output.status.success(),
        "lpm info --json must honor project .npmrc routing; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let json = parse_json_output(&output.stdout);
    assert_eq!(json["success"], true);
    assert_eq!(json["name"], PACKAGE_NAME);
    assert_eq!(json["dist-tags"]["latest"], VERSION);

    assert_eq!(
        received_auth_headers(&mock).await,
        vec![Some(format!("Bearer {TOKEN}"))]
    );
}

#[tokio::test]
async fn info_does_not_fallback_from_missing_npm_package_to_lpm() {
    let project = TempProject::empty(r#"{"name":"read-only-routing","version":"1.0.0"}"#);
    let lpm_registry = MockRegistry::start().await;
    let npm_registry = MockRegistry::start().await;
    write_project_npmrc(&project, &npm_registry.url());

    let output = lpm_with_registry(&project, &lpm_registry.url())
        .env_remove("LPM_NPM_ROUTE")
        .env_remove("LPM_TOKEN")
        .args(["info", "never.found", "--json"])
        .output()
        .expect("run lpm info for a missing npm package");

    assert!(
        !output.status.success(),
        "a missing npm package must fail; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    assert_eq!(
        npm_registry
            .server()
            .received_requests()
            .await
            .expect("npm registry request log")
            .len(),
        1,
        "the configured npm registry must receive the metadata request",
    );
    let lpm_request_paths = lpm_registry
        .server()
        .received_requests()
        .await
        .expect("LPM registry request log")
        .into_iter()
        .map(|request| request.url.path().to_string())
        .collect::<Vec<_>>();
    assert!(
        !lpm_request_paths
            .iter()
            .any(|path| path == "/api/registry/@lpm.dev/never.found"),
        "an npm 404 must not trigger an LPM metadata fallback; requests: {lpm_request_paths:?}",
    );
}

#[tokio::test]
async fn download_json_routes_bare_package_through_project_npmrc_registry() {
    let project = TempProject::empty(r#"{"name":"read-only-routing","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    write_project_npmrc(&project, &mock.url());
    mount_auth_required_npm_package(&mock).await;

    let output = lpm_with_registry(&project, &mock.url())
        .env_remove("LPM_NPM_ROUTE")
        .env_remove("LPM_TOKEN")
        .args([
            "download",
            PACKAGE_NAME,
            "--json",
            "--output",
            "downloaded-package",
        ])
        .output()
        .expect("failed to run lpm download --json");

    assert!(
        output.status.success(),
        "lpm download --json must honor project .npmrc routing; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let json = parse_json_output(&output.stdout);
    assert_eq!(json["success"], true);
    assert_eq!(json["package"], PACKAGE_NAME);
    assert_eq!(json["version"], VERSION);
    assert!(project.file_exists("downloaded-package/package.json"));

    assert_eq!(
        received_auth_headers(&mock).await,
        vec![
            Some(format!("Bearer {TOKEN}")),
            Some(format!("Bearer {TOKEN}"))
        ]
    );
}

#[tokio::test]
async fn resolve_json_routes_bare_package_through_project_npmrc_registry() {
    let project = TempProject::empty(r#"{"name":"read-only-routing","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    write_project_npmrc(&project, &mock.url());
    mount_auth_required_npm_package(&mock).await;

    let output = lpm_with_registry(&project, &mock.url())
        .env_remove("LPM_NPM_ROUTE")
        .env_remove("LPM_TOKEN")
        .args(["resolve", PACKAGE_NAME, "--json"])
        .output()
        .expect("failed to run lpm resolve --json");

    assert!(
        output.status.success(),
        "lpm resolve --json must honor project .npmrc routing; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let json = parse_json_output(&output.stdout);
    assert_eq!(json["success"], true);
    assert_eq!(json["count"], 1);
    assert_eq!(json["packages"][0]["package"], PACKAGE_NAME);
    assert_eq!(json["packages"][0]["version"], VERSION);

    assert_eq!(
        received_auth_headers(&mock).await,
        vec![Some(format!("Bearer {TOKEN}"))]
    );
}

#[tokio::test]
async fn search_json_routes_query_through_project_npmrc_registry() {
    let project = TempProject::empty(r#"{"name":"read-only-routing","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    write_project_npmrc(&project, &mock.url());
    mount_auth_required_npm_search(&mock, PACKAGE_NAME, 20).await;

    let output = lpm_with_registry(&project, &mock.url())
        .env_remove("LPM_NPM_ROUTE")
        .env_remove("LPM_TOKEN")
        .args(["search", PACKAGE_NAME, "--json"])
        .output()
        .expect("failed to run lpm search --json");

    assert!(
        output.status.success(),
        "lpm search --json must honor project .npmrc routing; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let json = parse_json_output(&output.stdout);
    assert_eq!(json["success"], true);
    assert_eq!(json["count"], 1);
    assert_eq!(json["packages"][0]["name"], PACKAGE_NAME);
    assert_eq!(json["packages"][0]["latestVersion"], VERSION);

    assert_eq!(
        received_auth_headers(&mock).await,
        vec![Some(format!("Bearer {TOKEN}"))]
    );
}

#[tokio::test]
async fn search_human_banner_names_project_npmrc_registry() {
    let project = TempProject::empty(r#"{"name":"read-only-routing","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    write_project_npmrc(&project, &mock.url());
    mount_auth_required_npm_search(&mock, PACKAGE_NAME, 20).await;

    let output = lpm_with_registry(&project, &mock.url())
        .env_remove("LPM_NPM_ROUTE")
        .env_remove("LPM_TOKEN")
        .args(["search", PACKAGE_NAME])
        .output()
        .expect("failed to run lpm search");

    assert!(
        output.status.success(),
        "lpm search must honor project .npmrc routing; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("› Searching 127.0.0.1 for \"lodash.merge\""),
        "search banner must name the routed custom registry, got:\n{combined}"
    );
    assert!(
        !combined.contains("Searching lpm.dev for \"lodash.merge\""),
        "npm/custom search banner must not claim lpm.dev, got:\n{combined}"
    );

    assert_eq!(
        received_auth_headers(&mock).await,
        vec![Some(format!("Bearer {TOKEN}"))]
    );
}
