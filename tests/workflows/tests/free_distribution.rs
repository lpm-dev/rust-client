mod support;

use support::auth_state::{SessionSeed, read_credentials, seed_sessions};
use support::mock_registry::{MockRegistry, make_tarball};
use support::{TempProject, lpm_with_registry};
use wiremock::matchers::{method, path};
use wiremock::{Mock, ResponseTemplate};

const PACKAGE: &str = "@lpm.dev/author.free-package";

async fn install_public_package(access_token: Option<&str>, refresh_token: Option<&str>) {
    let project = TempProject::empty(r#"{"name":"consumer","version":"1.0.0"}"#);
    let registry = MockRegistry::start().await;
    registry
        .with_package(PACKAGE, "1.0.0", &make_tarball(PACKAGE, "1.0.0"))
        .await;
    registry
        .with_package_skills("author.free-package", vec![])
        .await;
    Mock::given(method("POST"))
        .and(path("/api/cli/refresh"))
        .respond_with(ResponseTemplate::new(401))
        .expect(0)
        .mount(registry.server())
        .await;
    seed_sessions(
        project.home(),
        &[SessionSeed {
            registry_url: &registry.url(),
            access_token,
            refresh_token,
            session_access_expires_at: access_token.map(|_| "2020-01-01T00:00:00Z"),
        }],
    );
    let initial = (access_token.is_some() || refresh_token.is_some())
        .then(|| read_credentials(project.home()));
    for args in [
        vec!["install", PACKAGE, "--no-editor-setup"],
        vec!["install", "--no-editor-setup"],
    ] {
        let output = lpm_with_registry(&project, &registry.url())
            .args(args)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "stdout: {}\nstderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    assert!(
        project
            .path()
            .join("node_modules/@lpm.dev/author.free-package/package.json")
            .is_file()
    );
    let requests = registry.server().received_requests().await.unwrap();
    assert!(
        requests
            .iter()
            .any(|request| request.url.path() == "/api/registry/install-check")
    );
    assert!(
        requests
            .iter()
            .any(|request| request.url.path() == "/api/registry/pool/install-report")
    );
    assert!(
        !requests
            .iter()
            .any(|request| request.url.path().contains("refresh")),
        "public installation must not refresh a session: {:?}",
        requests.iter().map(|r| r.url.path()).collect::<Vec<_>>()
    );
    if let Some(initial) = initial {
        assert_eq!(read_credentials(project.home()), initial);
    }
}

#[tokio::test]
async fn anonymous_free_install_and_cached_reinstall_succeed() {
    install_public_package(None, None).await;
}

#[tokio::test]
async fn stale_token_does_not_block_free_install() {
    install_public_package(Some("stale-token"), None).await;
}

#[tokio::test]
async fn expired_session_does_not_refresh_before_free_install() {
    install_public_package(Some("expired-access"), Some("expired-refresh")).await;
}

#[tokio::test]
async fn refresh_only_session_does_not_block_free_install() {
    install_public_package(None, Some("expired-refresh")).await;
}

#[tokio::test]
async fn protected_install_still_refreshes_after_an_authentication_challenge() {
    let project = TempProject::empty(r#"{"name":"consumer","version":"1.0.0"}"#);
    let registry = MockRegistry::start().await;
    registry
        .with_package(PACKAGE, "1.0.0", &make_tarball(PACKAGE, "1.0.0"))
        .await;
    registry
        .with_package_skills("author.free-package", vec![])
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/api/registry/{PACKAGE}")))
        .and(wiremock::matchers::header(
            "authorization",
            "Bearer expired-access",
        ))
        .respond_with(ResponseTemplate::new(401))
        .with_priority(1)
        .expect(1)
        .mount(registry.server())
        .await;
    registry
        .with_refresh_expected(
            "valid-refresh",
            "rotated-access",
            "rotated-refresh",
            "2099-01-01T00:00:00Z",
            1,
        )
        .await;
    seed_sessions(
        project.home(),
        &[SessionSeed {
            registry_url: &registry.url(),
            access_token: Some("expired-access"),
            refresh_token: Some("valid-refresh"),
            session_access_expires_at: Some("2020-01-01T00:00:00Z"),
        }],
    );
    lpm_with_registry(&project, &registry.url())
        .args(["install", PACKAGE, "--no-editor-setup"])
        .assert()
        .success();
    assert_eq!(
        read_credentials(project.home())[registry.url()],
        "rotated-access"
    );
}

async fn install_private_history_with_expired_session(
    prime: Option<&str>,
    explicit: bool,
    public_available: bool,
) {
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };
    let project = TempProject::empty(r#"{"name":"consumer","version":"1.0.0"}"#);
    let registry = MockRegistry::start().await;
    let owner_metadata = registry
        .mount_full_package_metadata_routes(
            PACKAGE,
            "2.0.0",
            &[
                (
                    "1.0.0",
                    serde_json::json!({}),
                    Some(make_tarball(PACKAGE, "1.0.0")),
                ),
                (
                    "2.0.0",
                    serde_json::json!({}),
                    Some(make_tarball(PACKAGE, "2.0.0")),
                ),
            ],
        )
        .await;
    let mut public_metadata = owner_metadata.clone();
    public_metadata["versions"]
        .as_object_mut()
        .unwrap()
        .remove("1.0.0");
    let expired = Arc::new(AtomicBool::new(prime != Some("1.0.0")));
    for (verb, endpoint, batch) in [
        ("GET", format!("/api/registry/{PACKAGE}"), false),
        ("POST", "/api/registry/batch-metadata".to_string(), true),
    ] {
        let expired = Arc::clone(&expired);
        let owner_metadata = owner_metadata.clone();
        let public_metadata = public_metadata.clone();
        Mock::given(method(verb))
            .and(path(endpoint))
            .respond_with(move |request: &wiremock::Request| {
                let is_owner = !expired.load(Ordering::SeqCst)
                    || request
                        .headers
                        .get("authorization")
                        .is_some_and(|header| header == "Bearer rotated-access");
                let metadata = if is_owner {
                    owner_metadata.clone()
                } else {
                    public_metadata.clone()
                };
                if !is_owner && !public_available {
                    return ResponseTemplate::new(404)
                        .set_body_json(serde_json::json!({ "error": "Version not found" }));
                }
                ResponseTemplate::new(200).set_body_json(if batch {
                    serde_json::json!({ "packages": { PACKAGE: metadata } })
                } else {
                    metadata
                })
            })
            .with_priority(1)
            .mount(registry.server())
            .await;
    }
    let access_expired = Arc::clone(&expired);
    Mock::given(method("POST")).and(path("/api/registry/install-check")).respond_with(move |request: &wiremock::Request| {
        let is_owner = !access_expired.load(Ordering::SeqCst) || request.headers.get("authorization").is_some_and(|header| header == "Bearer rotated-access");
        let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
        let decisions: Vec<_> = body["packages"].as_array().unwrap().iter().map(|package| serde_json::json!({ "name": package["name"], "version": package["version"], "allowed": is_owner || package["version"] == "2.0.0" })).collect();
        ResponseTemplate::new(200).set_body_json(serde_json::json!({ "packages": decisions }))
    }).with_priority(1).mount(registry.server()).await;
    registry
        .with_package_skills_for_version("author.free-package", "1.0.0", vec![])
        .await;
    registry
        .with_refresh_expected(
            "valid-refresh",
            "rotated-access",
            "rotated-refresh",
            "2099-01-01T00:00:00Z",
            1,
        )
        .await;
    if prime == Some("2.0.0") {
        registry
            .with_package_skills_for_version("author.free-package", "2.0.0", vec![])
            .await;
    }
    let seed = |expires| {
        seed_sessions(
            project.home(),
            &[SessionSeed {
                registry_url: &registry.url(),
                access_token: Some("expired-access"),
                refresh_token: Some("valid-refresh"),
                session_access_expires_at: Some(expires),
            }],
        )
    };
    if let Some(version) = prime {
        seed(if version == "1.0.0" {
            "2099-01-01T00:00:00Z"
        } else {
            "2020-01-01T00:00:00Z"
        });
        lpm_with_registry(&project, &registry.url())
            .args([
                "install",
                &format!("{PACKAGE}@{version}"),
                "--no-editor-setup",
            ])
            .assert()
            .success();
    }
    expired.store(true, Ordering::SeqCst);
    seed("2020-01-01T00:00:00Z");
    let mut command = lpm_with_registry(&project, &registry.url());
    command.arg("install");
    if explicit {
        command.arg(format!("{PACKAGE}@^1.0.0"));
    }
    command.arg("--no-editor-setup").assert().success();
    let installed: serde_json::Value = serde_json::from_slice(
        &std::fs::read(
            project
                .path()
                .join("node_modules")
                .join(PACKAGE)
                .join("package.json"),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(installed["version"], "1.0.0");
    assert_eq!(
        read_credentials(project.home())[registry.url()],
        "rotated-access"
    );
}

#[tokio::test]
async fn expired_owner_session_recovers_private_history_from_cold_metadata() {
    install_private_history_with_expired_session(None, true, true).await;
}

#[tokio::test]
async fn expired_owner_session_recovers_private_history_from_cached_public_metadata() {
    install_private_history_with_expired_session(Some("2.0.0"), true, true).await;
}

#[tokio::test]
async fn expired_owner_session_recovers_cached_private_history_install_check() {
    install_private_history_with_expired_session(Some("1.0.0"), false, true).await;
}

#[tokio::test]
async fn expired_owner_session_recovers_history_when_public_releases_are_unavailable() {
    install_private_history_with_expired_session(None, true, false).await;
}

#[tokio::test]
async fn missing_versions_share_one_failed_session_refresh() {
    let project = TempProject::empty(r#"{"name":"consumer","version":"1.0.0"}"#);
    let registry = MockRegistry::start().await;
    registry
        .with_package(PACKAGE, "2.0.0", &make_tarball(PACKAGE, "2.0.0"))
        .await;
    let other_package = "@lpm.dev/author.other-free-package";
    registry
        .with_package(
            other_package,
            "2.0.0",
            &make_tarball(other_package, "2.0.0"),
        )
        .await;
    Mock::given(method("POST"))
        .and(path("/api/cli/refresh"))
        .respond_with(ResponseTemplate::new(503).set_delay(std::time::Duration::from_millis(50)))
        .expect(1)
        .mount(registry.server())
        .await;
    seed_sessions(
        project.home(),
        &[SessionSeed {
            registry_url: &registry.url(),
            access_token: Some("expired-access"),
            refresh_token: Some("valid-refresh"),
            session_access_expires_at: Some("2020-01-01T00:00:00Z"),
        }],
    );
    lpm_with_registry(&project, &registry.url())
        .args([
            "install",
            &format!("{PACKAGE}@1.0.0"),
            &format!("{other_package}@0.9.0"),
            "--no-editor-setup",
        ])
        .assert()
        .failure();
    assert_eq!(
        read_credentials(project.home())[registry.url()],
        "expired-access"
    );
    assert!(!project.path().join("node_modules").exists());
}
