//! Approval for `[firewall.npm.policies]` settings that handle LPM Firewall
//! verdicts more leniently than the approved machine posture.

mod support;

use support::mock_registry::{MockRegistry, make_tarball};
use support::{
    TempProject, lpm_with_registry, write_npm_firewall_global_config_with_policies,
    write_signed_firewall_posture,
};
use wiremock::matchers::{body_string_contains, method, path};
use wiremock::{Mock, ResponseTemplate};

const VERDICTS_PATH: &str = "/api/registry/-/npm-firewall/verdicts";

fn allow_response(name: &str) -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_json(serde_json::json!({
        "requestId": "policy-guard",
        "policyMode": "enforce",
        "summary": { "total": 1, "allow": 1, "warn": 0, "block": 0, "unknown": 0, "matched": 0 },
        "decisions": [{
            "decisionId": name,
            "name": name,
            "version": "1.0.0",
            "action": "allow",
            "verdict": "clean",
            "reason": "clean",
            "matchSource": "none",
            "policyMode": "enforce",
            "enqueueScan": false
        }]
    }))
}

async fn registry_with_package(name: &str) -> MockRegistry {
    let mock = MockRegistry::start().await;
    mock.with_package(name, "1.0.0", &make_tarball(name, "1.0.0"))
        .await;
    mock
}

fn install(project: &TempProject, mock: &MockRegistry, name: &str) -> std::process::Output {
    lpm_with_registry(project, &mock.url())
        .args(["install", "--json", "--no-skills", &format!("{name}@1.0.0")])
        .output()
        .unwrap()
}

#[tokio::test]
async fn install_refuses_config_firewall_policy_looser_than_the_approved_policy() {
    let mock = registry_with_package("guarded-policy").await;
    Mock::given(method("POST"))
        .and(path(VERDICTS_PATH))
        .respond_with(allow_response("guarded-policy"))
        .expect(0)
        .mount(mock.server())
        .await;
    let project = TempProject::empty(r#"{"name":"consumer","version":"1.0.0"}"#);
    write_signed_firewall_posture(&project, "enforce", &[]);
    write_npm_firewall_global_config_with_policies(
        &project,
        "enforce",
        &[("lpm_ai_confirmed_malware", "allow")],
    );

    let output = install(&project, &mock, "guarded-policy");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!output.status.success(), "{stdout}");
    let envelope: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(envelope["error_code"], "security_approval_required");
    assert!(
        envelope["error"]["message"]
            .as_str()
            .unwrap()
            .contains("lpm_ai_confirmed_malware = allow (approved: block)"),
        "{envelope}"
    );
    assert_eq!(envelope["error"]["requested_scopes"][0], "firewall-disable");
    assert_eq!(
        envelope["error"]["suggested_command"],
        "lpm config firewall"
    );
    assert_eq!(envelope["next_steps"][0]["command"], "lpm config firewall");
    assert!(!project.file_exists("node_modules/guarded-policy/package.json"));
}

async fn install_sending_policy(
    name: &str,
    approved: &[(&str, &str)],
    config: &[(&str, &str)],
    expected_body: &str,
) {
    let mock = registry_with_package(name).await;
    Mock::given(method("POST"))
        .and(path(VERDICTS_PATH))
        .and(body_string_contains(expected_body))
        .respond_with(allow_response(name))
        .expect(1)
        .mount(mock.server())
        .await;
    let project = TempProject::empty(r#"{"name":"consumer","version":"1.0.0"}"#);
    write_signed_firewall_posture(&project, "enforce", approved);
    write_npm_firewall_global_config_with_policies(&project, "enforce", config);

    let output = install(&project, &mock, name);

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(project.file_exists(&format!("node_modules/{name}/package.json")));
}

#[tokio::test]
async fn install_runs_the_default_policy_when_config_has_no_table_and_the_approved_one_is_looser() {
    install_sending_policy(
        "approved-policy",
        &[("lpm_ai_confirmed_malware", "allow")],
        &[],
        r#""lpmAiConfirmedMalware":"block""#,
    )
    .await;
}

#[tokio::test]
async fn install_keeps_a_stricter_approved_policy_when_config_has_no_table() {
    install_sending_policy(
        "strict-policy",
        &[("lpm_ai_agent_control_surface", "block")],
        &[],
        r#""lpmAiAgentControlSurface":"block""#,
    )
    .await;
}

#[tokio::test]
async fn install_sends_an_approved_looser_policy_the_config_asks_for() {
    install_sending_policy(
        "requested-policy",
        &[("lpm_ai_confirmed_malware", "allow")],
        &[("lpm_ai_confirmed_malware", "allow")],
        r#""lpmAiConfirmedMalware":"allow""#,
    )
    .await;
}

#[tokio::test]
async fn install_needs_no_policy_approval_where_the_approved_firewall_is_off() {
    let mock = registry_with_package("fresh-runner").await;
    Mock::given(method("POST"))
        .and(path(VERDICTS_PATH))
        .and(body_string_contains(r#""lpmAiConfirmedMalware":"allow""#))
        .respond_with(allow_response("fresh-runner"))
        .expect(1)
        .mount(mock.server())
        .await;
    let project = TempProject::empty(r#"{"name":"consumer","version":"1.0.0"}"#);
    write_npm_firewall_global_config_with_policies(
        &project,
        "enforce",
        &[("lpm_ai_confirmed_malware", "allow")],
    );

    let output = install(&project, &mock, "fresh-runner");

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
}

#[tokio::test]
async fn install_keeps_a_stricter_approved_policy_a_partial_table_leaves_out() {
    install_sending_policy(
        "partial-policy",
        &[("lpm_ai_agent_control_surface", "block")],
        &[("lpm_ai_telemetry", "block")],
        r#""lpmAiAgentControlSurface":"block""#,
    )
    .await;
}
