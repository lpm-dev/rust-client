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
