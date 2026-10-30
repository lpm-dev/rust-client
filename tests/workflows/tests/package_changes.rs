mod support;

use support::auth_state::{SessionSeed, seed_sessions};
use support::mock_registry::MockRegistry;
use support::{TempProject, lpm_with_registry};
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, Request, ResponseTemplate};

const UNPUBLISH_PATH: &str = "/api/registry/-/package/unpublish";
const DEPRECATE_PATH: &str = "/api/registry/-/package/deprecate";
const ACCESS_TOKEN: &str = "stored-session-token";

fn signed_in_project(registry_url: &str) -> TempProject {
    let project = TempProject::empty(r#"{"name":"package-changes","version":"1.0.0"}"#);
    seed_sessions(
        project.home(),
        &[SessionSeed {
            registry_url,
            access_token: Some(ACCESS_TOKEN),
            ..Default::default()
        }],
    );
    project
}

async fn mount_change(mock: &MockRegistry, route: &str, response: serde_json::Value) {
    Mock::given(method("POST"))
        .and(path(route))
        .and(header("authorization", format!("Bearer {ACCESS_TOKEN}")))
        .and(header("x-lpm-browser-approval", "1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(response))
        .mount(mock.server())
        .await;
}

/// Asks for a browser approval until the change carries one, as the
/// registry does for an account with a passkey.
async fn mount_approval_challenge(
    mock: &MockRegistry,
    route: &str,
    accepts_code: bool,
    approved: serde_json::Value,
) {
    let base = mock.url();
    Mock::given(method("POST"))
        .and(path(route))
        .respond_with(move |request: &Request| {
            if request.headers.get("x-lpm-approval").is_some() {
                return ResponseTemplate::new(200).set_body_json(approved.clone());
            }
            ResponseTemplate::new(401).set_body_json(serde_json::json!({
                "error": "Approve this change in your browser with your passkey.",
                "code": "OTP_REQUIRED",
                "otp": accepts_code,
                "passkey": true,
                "authUrl": format!("{base}/cli/approve/approval-1"),
                "doneUrl": format!("{base}/api/auth/cli-approvals/approval-1/poll-secret"),
            }))
        })
        .mount(mock.server())
        .await;
    Mock::given(method("GET"))
        .and(path("/api/auth/cli-approvals/approval-1/poll-secret"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({ "token": "approval-token" })),
        )
        .mount(mock.server())
        .await;
}

async fn requests_to(mock: &MockRegistry, route: &str) -> Vec<Request> {
    mock.server()
        .received_requests()
        .await
        .expect("record requests")
        .into_iter()
        .filter(|request| request.url.path() == route)
        .collect()
}

fn body(request: &Request) -> serde_json::Value {
    serde_json::from_slice(&request.body).expect("change requests carry JSON")
}

fn json_output(output: &std::process::Output) -> serde_json::Value {
    let stdout = String::from_utf8_lossy(&output.stdout);
    serde_json::from_str(&stdout).unwrap_or_else(|error| {
        panic!(
            "--json must print JSON: {error}\nstdout: {stdout}\nstderr: {}",
            String::from_utf8_lossy(&output.stderr)
        )
    })
}

fn unpublished() -> serde_json::Value {
    serde_json::json!({ "ok": true, "package": "@lpm.dev/acme.kit", "version": "1.2.3" })
}

fn deprecation(action: &str, version: &str, changed: u64) -> serde_json::Value {
    serde_json::json!({
        "ok": true,
        "action": action,
        "package": "@lpm.dev/acme.kit",
        "version": version,
        "changed": changed,
    })
}

#[tokio::test]
async fn unpublish_sends_the_version_and_reports_it() {
    let mock = MockRegistry::start().await;
    let project = signed_in_project(&mock.url());
    mount_change(&mock, UNPUBLISH_PATH, unpublished()).await;

    let output = lpm_with_registry(&project, &mock.url())
        .args(["unpublish", "acme.kit@v1.2.3", "--yes", "--json"])
        .output()
        .expect("run lpm unpublish");

    assert!(output.status.success(), "{output:?}");
    assert_eq!(
        json_output(&output),
        serde_json::json!({
            "success": true,
            "unpublished": true,
            "package": "@lpm.dev/acme.kit",
            "version": "1.2.3",
        })
    );
    let requests = requests_to(&mock, UNPUBLISH_PATH).await;
    assert_eq!(requests.len(), 1);
    assert_eq!(
        body(&requests[0]),
        serde_json::json!({ "package": "@lpm.dev/acme.kit", "version": "1.2.3" })
    );
}

#[tokio::test]
async fn unpublish_says_what_it_did() {
    let mock = MockRegistry::start().await;
    let project = signed_in_project(&mock.url());
    mount_change(&mock, UNPUBLISH_PATH, unpublished()).await;

    let output = lpm_with_registry(&project, &mock.url())
        .args(["unpublish", "@lpm.dev/acme.kit@1.2.3", "--yes"])
        .output()
        .expect("run lpm unpublish");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{stderr}");
    assert!(
        stderr.contains("Unpublishing @lpm.dev/acme.kit@1.2.3"),
        "{stderr}"
    );
    assert!(
        stderr.contains("Done · unpublished @lpm.dev/acme.kit@1.2.3"),
        "{stderr}"
    );
}

#[tokio::test]
async fn unpublish_without_yes_and_without_a_terminal_changes_nothing() {
    let mock = MockRegistry::start().await;
    let project = signed_in_project(&mock.url());
    mount_change(&mock, UNPUBLISH_PATH, unpublished()).await;

    for json in [false, true] {
        let mut command = lpm_with_registry(&project, &mock.url());
        command.args(["unpublish", "@lpm.dev/acme.kit@1.2.3"]);
        if json {
            command.arg("--json");
        }
        let output = command.output().expect("run lpm unpublish");

        assert!(!output.status.success());
        if json {
            let envelope = json_output(&output);
            assert_eq!(envelope["error_code"], "confirmation_required");
            assert_eq!(envelope["error"]["command"], "lpm unpublish");
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(stderr.contains("--yes"), "{stderr}");
        }
    }
    assert!(requests_to(&mock, UNPUBLISH_PATH).await.is_empty());
}

#[tokio::test]
async fn unpublish_needs_one_exact_version() {
    let mock = MockRegistry::start().await;
    let project = signed_in_project(&mock.url());
    mount_change(&mock, UNPUBLISH_PATH, unpublished()).await;

    for target in [
        "@lpm.dev/acme.kit",
        "@lpm.dev/acme.kit@^1.2.0",
        "@lpm.dev/acme.kit@latest",
    ] {
        let output = lpm_with_registry(&project, &mock.url())
            .args(["unpublish", target, "--yes", "--json"])
            .output()
            .expect("run lpm unpublish");

        assert!(!output.status.success(), "{target}");
        assert_eq!(
            json_output(&output)["error_code"],
            "invalid_version",
            "{target}"
        );
    }
    assert!(requests_to(&mock, UNPUBLISH_PATH).await.is_empty());
}

#[tokio::test]
async fn unpublish_approves_a_passkey_account_in_the_browser_and_sends_the_approval() {
    let mock = MockRegistry::start().await;
    let project = signed_in_project(&mock.url());
    mount_approval_challenge(&mock, UNPUBLISH_PATH, false, unpublished()).await;

    let output = lpm_with_registry(&project, &mock.url())
        .args(["unpublish", "@lpm.dev/acme.kit@1.2.3", "--yes"])
        .output()
        .expect("run lpm unpublish");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{stderr}");
    assert!(
        stderr.contains("Approve in your browser to unpublish @lpm.dev/acme.kit@1.2.3"),
        "{stderr}"
    );
    let requests = requests_to(&mock, UNPUBLISH_PATH).await;
    assert_eq!(requests.len(), 2, "the approval is sent once, on a retry");
    assert!(requests[0].headers.get("x-lpm-approval").is_none());
    assert_eq!(
        requests[1]
            .headers
            .get("x-lpm-approval")
            .and_then(|value| value.to_str().ok()),
        Some("approval-token")
    );
    assert_eq!(body(&requests[1]), body(&requests[0]));
}

#[tokio::test]
async fn unpublish_json_reports_an_approval_it_cant_wait_for() {
    let mock = MockRegistry::start().await;
    let project = signed_in_project(&mock.url());
    mount_approval_challenge(&mock, UNPUBLISH_PATH, true, unpublished()).await;

    let output = lpm_with_registry(&project, &mock.url())
        .args(["unpublish", "@lpm.dev/acme.kit@1.2.3", "--yes", "--json"])
        .output()
        .expect("run lpm unpublish");

    assert!(!output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.contains("cli/approve"), "{stdout}");
    let envelope = json_output(&output);
    assert_eq!(envelope["error_code"], "browser_approval_required");
    assert_eq!(envelope["error"]["action"], "unpublish");
    assert_eq!(requests_to(&mock, UNPUBLISH_PATH).await.len(), 1);
}

#[tokio::test]
async fn unpublish_sends_a_code_it_was_given_on_the_first_request() {
    let mock = MockRegistry::start().await;
    let project = signed_in_project(&mock.url());
    mount_change(&mock, UNPUBLISH_PATH, unpublished()).await;

    let output = lpm_with_registry(&project, &mock.url())
        .args([
            "unpublish",
            "@lpm.dev/acme.kit@1.2.3",
            "--otp",
            "123456",
            "--yes",
            "--json",
        ])
        .output()
        .expect("run lpm unpublish");

    assert!(output.status.success(), "{output:?}");
    let requests = requests_to(&mock, UNPUBLISH_PATH).await;
    assert_eq!(requests.len(), 1);
    assert_eq!(
        requests[0]
            .headers
            .get("x-otp")
            .and_then(|value| value.to_str().ok()),
        Some("123456")
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.contains("123456"), "{stdout}");
}

#[tokio::test]
async fn unpublish_refuses_a_code_from_an_account_with_only_a_passkey() {
    let mock = MockRegistry::start().await;
    let project = signed_in_project(&mock.url());
    mount_approval_challenge(&mock, UNPUBLISH_PATH, false, unpublished()).await;

    let output = lpm_with_registry(&project, &mock.url())
        .args([
            "unpublish",
            "@lpm.dev/acme.kit@1.2.3",
            "--otp",
            "123456",
            "--yes",
        ])
        .output()
        .expect("run lpm unpublish");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("--otp needs an authenticator app"),
        "{stderr}"
    );
    assert_eq!(requests_to(&mock, UNPUBLISH_PATH).await.len(), 1);
}

#[tokio::test]
async fn unpublish_reports_what_the_registry_refuses() {
    let mock = MockRegistry::start().await;
    let project = signed_in_project(&mock.url());
    Mock::given(method("POST"))
        .and(path(UNPUBLISH_PATH))
        .respond_with(ResponseTemplate::new(403).set_body_json(serde_json::json!({
            "error": "Cannot unpublish: Pool versions older than 72 hours can't be unpublished.",
        })))
        .expect(1)
        .mount(mock.server())
        .await;

    let output = lpm_with_registry(&project, &mock.url())
        .args(["unpublish", "@lpm.dev/acme.kit@1.2.3", "--yes", "--json"])
        .output()
        .expect("run lpm unpublish");

    assert!(!output.status.success());
    let envelope = json_output(&output);
    assert_eq!(envelope["error_code"], "registry");
    assert!(
        envelope.to_string().contains("older than 72 hours"),
        "{envelope}"
    );
}

#[tokio::test]
async fn deprecate_one_version_sends_its_trimmed_message() {
    let mock = MockRegistry::start().await;
    let project = signed_in_project(&mock.url());
    mount_change(&mock, DEPRECATE_PATH, deprecation("deprecated", "1.2.3", 1)).await;

    let output = lpm_with_registry(&project, &mock.url())
        .args([
            "deprecate",
            "@lpm.dev/acme.kit@1.2.3",
            "  Use 2.0.0, which fixes the leak  ",
            "--json",
        ])
        .output()
        .expect("run lpm deprecate");

    assert!(output.status.success(), "{output:?}");
    assert_eq!(
        json_output(&output),
        serde_json::json!({
            "success": true,
            "deprecated": true,
            "package": "@lpm.dev/acme.kit",
            "version": "1.2.3",
            "changed": 1,
            "message": "Use 2.0.0, which fixes the leak",
        })
    );
    let requests = requests_to(&mock, DEPRECATE_PATH).await;
    assert_eq!(
        body(&requests[0]),
        serde_json::json!({
            "package": "@lpm.dev/acme.kit",
            "version": "1.2.3",
            "message": "Use 2.0.0, which fixes the leak",
        })
    );
}

#[tokio::test]
async fn deprecate_every_version_names_no_version_and_counts_what_changed() {
    let mock = MockRegistry::start().await;
    let project = signed_in_project(&mock.url());
    mount_change(&mock, DEPRECATE_PATH, deprecation("deprecated", "all", 3)).await;

    let output = lpm_with_registry(&project, &mock.url())
        .args([
            "deprecate",
            "@lpm.dev/acme.kit",
            "Moved to @lpm.dev/acme.kit2",
        ])
        .output()
        .expect("run lpm deprecate");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{stderr}");
    assert!(
        stderr.contains("Deprecating every version of @lpm.dev/acme.kit"),
        "{stderr}"
    );
    assert!(
        stderr.contains("Done · deprecated 3 versions of @lpm.dev/acme.kit"),
        "{stderr}"
    );
    assert!(stderr.contains("Moved to @lpm.dev/acme.kit2"), "{stderr}");
    let requests = requests_to(&mock, DEPRECATE_PATH).await;
    assert_eq!(
        body(&requests[0]),
        serde_json::json!({
            "package": "@lpm.dev/acme.kit",
            "message": "Moved to @lpm.dev/acme.kit2",
        }),
        "the registry takes no `version` for every version"
    );
}

#[tokio::test]
async fn undeprecate_sends_no_message() {
    let mock = MockRegistry::start().await;
    let project = signed_in_project(&mock.url());
    mount_change(
        &mock,
        DEPRECATE_PATH,
        deprecation("undeprecated", "1.2.3", 1),
    )
    .await;

    let output = lpm_with_registry(&project, &mock.url())
        .args(["undeprecate", "@lpm.dev/acme.kit@1.2.3", "--json"])
        .output()
        .expect("run lpm undeprecate");

    assert!(output.status.success(), "{output:?}");
    assert_eq!(
        json_output(&output),
        serde_json::json!({
            "success": true,
            "deprecated": false,
            "package": "@lpm.dev/acme.kit",
            "version": "1.2.3",
            "changed": 1,
        })
    );
    let requests = requests_to(&mock, DEPRECATE_PATH).await;
    assert_eq!(
        body(&requests[0]),
        serde_json::json!({
            "package": "@lpm.dev/acme.kit",
            "version": "1.2.3",
            "message": null,
        })
    );
}

#[tokio::test]
async fn undeprecate_every_version_says_when_none_was_deprecated() {
    let mock = MockRegistry::start().await;
    let project = signed_in_project(&mock.url());
    mount_change(&mock, DEPRECATE_PATH, deprecation("undeprecated", "all", 0)).await;

    let output = lpm_with_registry(&project, &mock.url())
        .args(["undeprecate", "acme.kit"])
        .output()
        .expect("run lpm undeprecate");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{stderr}");
    assert!(
        stderr.contains("Removing the deprecation of every version of @lpm.dev/acme.kit"),
        "{stderr}"
    );
    assert!(
        stderr.contains("No version of @lpm.dev/acme.kit was deprecated"),
        "{stderr}"
    );
    let requests = requests_to(&mock, DEPRECATE_PATH).await;
    assert_eq!(
        body(&requests[0]),
        serde_json::json!({ "package": "@lpm.dev/acme.kit", "message": null })
    );
}

#[tokio::test]
async fn deprecate_refuses_a_message_the_registry_would_before_any_request() {
    let mock = MockRegistry::start().await;
    let project = signed_in_project(&mock.url());
    mount_change(&mock, DEPRECATE_PATH, deprecation("deprecated", "1.2.3", 1)).await;

    for (message, expected) in [
        ("   ".to_owned(), "lpm undeprecate"),
        ("x".repeat(501), "at most 500"),
    ] {
        let output = lpm_with_registry(&project, &mock.url())
            .args(["deprecate", "@lpm.dev/acme.kit@1.2.3", &message])
            .output()
            .expect("run lpm deprecate");

        assert_eq!(output.status.code(), Some(2), "{output:?}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains(expected), "{stderr}");
    }
    assert!(requests_to(&mock, DEPRECATE_PATH).await.is_empty());
}

#[tokio::test]
async fn deprecate_approves_a_passkey_account_in_the_browser() {
    let mock = MockRegistry::start().await;
    let project = signed_in_project(&mock.url());
    mount_approval_challenge(
        &mock,
        DEPRECATE_PATH,
        false,
        deprecation("deprecated", "all", 2),
    )
    .await;

    let output = lpm_with_registry(&project, &mock.url())
        .args(["deprecate", "@lpm.dev/acme.kit", "Use acme.kit2"])
        .output()
        .expect("run lpm deprecate");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{stderr}");
    assert!(
        stderr.contains("Approve in your browser to deprecate every version of @lpm.dev/acme.kit"),
        "{stderr}"
    );
    let requests = requests_to(&mock, DEPRECATE_PATH).await;
    assert_eq!(requests.len(), 2);
    assert!(requests[1].headers.get("x-lpm-approval").is_some());
}

#[tokio::test]
async fn deprecate_refuses_a_response_for_another_change() {
    let mock = MockRegistry::start().await;
    let project = signed_in_project(&mock.url());
    mount_change(
        &mock,
        DEPRECATE_PATH,
        deprecation("undeprecated", "1.2.3", 1),
    )
    .await;

    let output = lpm_with_registry(&project, &mock.url())
        .args(["deprecate", "@lpm.dev/acme.kit@1.2.3", "Use 2", "--json"])
        .output()
        .expect("run lpm deprecate");

    assert!(!output.status.success());
    let envelope = json_output(&output);
    assert_eq!(envelope["error_code"], "registry");
    assert!(
        envelope
            .to_string()
            .contains("invalid deprecation response"),
        "{envelope}"
    );
}

#[tokio::test]
async fn unpublish_stops_when_the_approval_is_denied() {
    let mock = MockRegistry::start().await;
    let project = signed_in_project(&mock.url());
    let base = mock.url();
    Mock::given(method("POST"))
        .and(path(UNPUBLISH_PATH))
        .respond_with(ResponseTemplate::new(401).set_body_json(serde_json::json!({
            "error": "Approve this unpublish in your browser with your passkey.",
            "code": "OTP_REQUIRED",
            "otp": false,
            "passkey": true,
            "authUrl": format!("{base}/cli/approve/approval-1"),
            "doneUrl": format!("{base}/api/auth/cli-approvals/approval-1/poll-secret"),
        })))
        .mount(mock.server())
        .await;
    Mock::given(method("GET"))
        .and(path("/api/auth/cli-approvals/approval-1/poll-secret"))
        .respond_with(ResponseTemplate::new(410))
        .mount(mock.server())
        .await;

    let output = lpm_with_registry(&project, &mock.url())
        .args(["unpublish", "@lpm.dev/acme.kit@1.2.3", "--yes"])
        .output()
        .expect("run lpm unpublish");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("denied or expired"), "{stderr}");
    assert!(!stderr.contains("Done ·"), "{stderr}");
    assert_eq!(
        requests_to(&mock, UNPUBLISH_PATH).await.len(),
        1,
        "nothing is sent again once the approval is denied"
    );
}

#[tokio::test]
async fn deprecate_reports_the_registrys_rate_limit() {
    let mock = MockRegistry::start().await;
    let project = signed_in_project(&mock.url());
    Mock::given(method("POST"))
        .and(path(DEPRECATE_PATH))
        .respond_with(
            ResponseTemplate::new(429)
                .insert_header("retry-after", "42")
                .set_body_json(serde_json::json!({
                    "error": "Rate limit exceeded. Try again later.",
                })),
        )
        .expect(1)
        .mount(mock.server())
        .await;

    let output = lpm_with_registry(&project, &mock.url())
        .args(["deprecate", "@lpm.dev/acme.kit@1.2.3", "Use 2", "--json"])
        .output()
        .expect("run lpm deprecate");

    assert!(!output.status.success());
    let envelope = json_output(&output);
    assert_eq!(envelope["error_code"], "registry");
    assert!(
        envelope.to_string().contains("Rate limit exceeded"),
        "{envelope}"
    );
}
