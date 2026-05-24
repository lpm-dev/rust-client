mod support;

use support::auth_state::{SessionSeed, seed_sessions};
use support::mock_registry::MockRegistry;
use support::{TempProject, lpm_with_registry};

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
    mock.with_authenticated_whoami("access-primary", "testuser", "test@example.com")
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
        stderr.contains("✓ Logged in as testuser") && stderr.contains("test@example.com"),
        "authenticated whoami should use the slim summary line, got:\n{stderr}"
    );
    assert!(
        stderr.contains("› Plan PRO"),
        "authenticated whoami should show the plan on a slim line, got:\n{stderr}"
    );
    assert!(
        stderr.contains("› Pool Active"),
        "authenticated whoami should show pool access on a slim line, got:\n{stderr}"
    );
    assert!(
        stderr.contains("› 2FA disabled"),
        "authenticated whoami should show 2FA status on a slim line, got:\n{stderr}"
    );
    assert!(
        stderr.contains("› Storage 50.00MB / 500MB"),
        "authenticated whoami should show storage usage on a slim line, got:\n{stderr}"
    );
    assert!(
        stderr.contains("› Private Packages 3 / 100"),
        "authenticated whoami should show package usage on a slim line, got:\n{stderr}"
    );
    assert!(
        stderr.contains("› Available Scopes"),
        "authenticated whoami should show the scopes header on a slim line, got:\n{stderr}"
    );
    assert!(
        stderr.contains("@lpm.dev/testuser.*"),
        "authenticated whoami should list the personal scope, got:\n{stderr}"
    );
    assert!(
        !stderr.contains("●") && !stderr.contains("◆") && !stderr.contains("│"),
        "legacy cliclack glyphs must be gone from whoami stderr, got:\n{stderr}"
    );
}
