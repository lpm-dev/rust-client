mod support;

use support::mock_registry::MockRegistry;
use support::{TempProject, lpm_with_registry};

#[tokio::test]
async fn setup_npmrc_json_writes_scoped_config_gitignore_and_read_only_token() {
    let project = TempProject::empty(r#"{"name":"web app","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    mock.with_npmrc_token_create(14, "lpm_read_only_token", "2030-01-02T03:04:05Z")
        .await;

    let output = lpm_with_registry(&project, &mock.url())
        .args(["setup-npmrc", "--days", "14", "--json"])
        .output()
        .expect("failed to run lpm setup-npmrc --json");

    assert!(
        output.status.success(),
        "lpm setup-npmrc --json failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let envelope: serde_json::Value = serde_json::from_str(&stdout).unwrap_or_else(|e| {
        panic!("setup-npmrc --json must be valid JSON: {e}\n---\n{stdout}")
    });

    assert_eq!(envelope["success"], serde_json::json!(true));
    assert_eq!(envelope["proxy"], serde_json::json!(false));
    assert_eq!(envelope["expiry_days"], serde_json::json!(14));
    assert_eq!(
        envelope["expires_at"],
        serde_json::json!("2030-01-02T03:04:05Z")
    );
    assert_eq!(envelope["gitignore_updated"], serde_json::json!(true));

    insta::with_settings!({
        filters => vec![
            (r#""/[^"]+/\.npmrc""#, r#""[NPMRC_PATH]""#),
        ],
    }, {
        insta::assert_json_snapshot!("setup_npmrc_json_envelope_writes_scoped_config", envelope);
    });

    let npmrc = project.read_file(".npmrc");
    assert!(
        npmrc.contains(&format!("@lpm.dev:registry={}/api/registry", mock.url())),
        ".npmrc must use scoped routing by default, got:\n{npmrc}"
    );
    assert!(
        npmrc.contains("lpm_read_only_token"),
        ".npmrc must contain the issued read-only token, got:\n{npmrc}"
    );
    assert_eq!(project.read_file(".gitignore"), ".npmrc\n");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let mode = std::fs::metadata(project.path().join(".npmrc"))
            .expect(".npmrc must exist")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, ".npmrc must be owner-only on unix");
    }

    let requests = mock
        .server()
        .received_requests()
        .await
        .expect("wiremock request log must be available");
    assert_eq!(requests.len(), 1, "expected exactly one token-create request");

    let body: serde_json::Value =
        serde_json::from_slice(&requests[0].body).expect("token-create body must be JSON");
    assert_eq!(body["scope"], serde_json::json!("read"));
    assert_eq!(body["expiryDays"], serde_json::json!(14));
    assert!(
        body["name"]
            .as_str()
            .expect("token-create name must be a string")
            .starts_with("npmrc-web-app-"),
        "token name must derive from the package name, got body:\n{}",
        serde_json::to_string_pretty(&body).unwrap()
    );
}
