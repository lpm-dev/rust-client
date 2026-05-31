mod support;

use support::auth_state::{SessionSeed, seed_sessions};
use support::mock_registry::MockRegistry;
use support::{TempProject, lpm_with_registry};
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, ResponseTemplate};

#[tokio::test]
async fn whoami_human_output_uses_slim_logged_out_guidance() {
    let project = TempProject::empty(r#"{"name":"whoami","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;

    let output = lpm_with_registry(&project, &mock.url())
        .arg("whoami")
        .output()
        .expect("failed to run lpm whoami");

    assert!(
        output.status.success(),
        "logged-out whoami must exit 0, stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.trim().is_empty(),
        "human whoami should not write to stdout when logged out, got:\n{stdout}"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(&format!("› Not logged in to {}.", mock.url())),
        "logged-out whoami should use the slim guidance line, got:\n{stderr}"
    );
    assert!(
        stderr.contains(&format!(
            "› Run `lpm login --registry {}` to authenticate.",
            mock.url()
        )),
        "logged-out whoami should keep the registry-specific login hint, got:\n{stderr}"
    );
    assert!(
        !stderr.contains("●") && !stderr.contains("◆") && !stderr.contains("│"),
        "legacy cliclack glyphs must be gone from whoami stderr, got:\n{stderr}"
    );

    let requests = mock
        .server()
        .received_requests()
        .await
        .expect("wiremock request log must be available");
    assert!(
        requests.is_empty(),
        "logged-out human whoami should not hit the network, got {} request(s)",
        requests.len()
    );
}

#[tokio::test]
async fn whoami_human_output_uses_slim_account_summary() {
    let project = TempProject::empty(r#"{"name":"whoami","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    Mock::given(method("GET"))
        .and(path("/api/registry/-/whoami"))
        .and(header("authorization", "Bearer access-primary"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "username": "test@example.com",
            "profile_username": "testuser",
            "email": "test@example.com",
            "plan_tier": "pro",
            "mfa_enabled": false,
            "has_pool_access": true,
            "usage": {
                "storage_bytes": 1024 * 1024 * 50,
                "private_packages": 3
            },
            "limits": {
                "storageBytes": 1024 * 1024 * 500,
                "privatePackages": 100
            },
            "organizations": [
                {
                    "slug": "acme",
                    "name": "Acme",
                    "role": "admin"
                }
            ]
        })))
        .mount(mock.server())
        .await;

    seed_sessions(
        project.home(),
        &[SessionSeed {
            registry_url: &mock.url(),
            access_token: Some("access-primary"),
            refresh_token: None,
            session_access_expires_at: None,
        }],
    );

    let output = lpm_with_registry(&project, &mock.url())
        .arg("whoami")
        .output()
        .expect("failed to run authenticated lpm whoami");

    assert!(
        output.status.success(),
        "authenticated whoami must exit 0, stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.trim().is_empty(),
        "human whoami should not write to stdout when authenticated, got:\n{stdout}"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("testuser")
            && stderr.contains("email          test@example.com")
            && !stderr.contains("Logged in as"),
        "authenticated whoami should render the bare identity header and email detail, got:\n{stderr}"
    );
    assert!(
        stderr.contains("plan           Pro"),
        "authenticated whoami should show the plan as an aligned detail row, got:\n{stderr}"
    );
    assert!(
        stderr.contains("pool access    yes"),
        "authenticated whoami should show pool access as an aligned detail row, got:\n{stderr}"
    );
    assert!(
        stderr.contains("mfa            no"),
        "authenticated whoami should show MFA status as an aligned detail row, got:\n{stderr}"
    );
    assert!(
        stderr.contains("usage") && stderr.contains("storage        50.00MB / 500MB  █░░░░░░░░░"),
        "authenticated whoami should show storage usage with a quota bar, got:\n{stderr}"
    );
    assert!(
        stderr.contains("private pkgs   3 / 100  █░░░░░░░░░"),
        "authenticated whoami should show package usage with a quota bar, got:\n{stderr}"
    );
    assert!(
        stderr.contains("scopes"),
        "authenticated whoami should show the scopes section, got:\n{stderr}"
    );
    assert!(
        stderr.contains("@lpm.dev/testuser.*"),
        "authenticated whoami should list the personal scope, got:\n{stderr}"
    );
    assert!(
        stderr.contains("@lpm.dev/acme.*  admin "),
        "authenticated whoami should render admin as a padded badge label, got:\n{stderr}"
    );
    assert!(
        stderr.contains("registries") && stderr.contains("● lpm.dev authenticated"),
        "authenticated whoami should include lpm.dev in the human registries list, got:\n{stderr}"
    );
    assert!(
        stderr.contains("✓ Identity loaded"),
        "authenticated whoami should finish with the identity-loaded terminus, got:\n{stderr}"
    );
    assert!(
        !stderr.contains("(admin)"),
        "authenticated whoami should not render the admin role as the old parenthesized label, got:\n{stderr}"
    );
    assert!(
        !stderr.contains("◆") && !stderr.contains("│"),
        "legacy cliclack glyphs must be gone from whoami stderr, got:\n{stderr}"
    );

    let colored_output = lpm_with_registry(&project, &mock.url())
        .arg("whoami")
        .env_remove("NO_COLOR")
        .env("FORCE_COLOR", "1")
        .output()
        .expect("failed to run color-forced lpm whoami");
    assert!(
        colored_output.status.success(),
        "color-forced whoami must exit 0, stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&colored_output.stdout),
        String::from_utf8_lossy(&colored_output.stderr),
    );
    let colored_stderr = String::from_utf8_lossy(&colored_output.stderr);
    assert!(
        colored_stderr.contains("\u{1b}[1;33;48;5;236m admin \u{1b}[0m"),
        "color-forced whoami should render admin with a badge background, got:\n{colored_stderr:?}"
    );
}
