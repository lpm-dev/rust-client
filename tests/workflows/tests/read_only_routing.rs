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
    )
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
