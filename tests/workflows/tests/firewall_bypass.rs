//! `lpm firewall bypass`: rules that let specific package versions past LPM
//! Firewall blocks, how installs apply and report them, and the hint a block
//! gives.

mod support;

#[cfg(unix)]
use support::lpm_spawnable_with_registry;
use support::mock_registry::{MockRegistry, compute_integrity, make_tarball};
use support::{
    TempProject, lpm, lpm_with_registry, write_npm_firewall_global_config,
    write_signed_firewall_bypass,
};
use wiremock::matchers::{body_string_contains, method, path};
use wiremock::{Mock, ResponseTemplate};

const VERDICTS_PATH: &str = "/api/registry/-/npm-firewall/verdicts";

async fn registry_blocking(name: &str, verdict: &str, group: &str) -> MockRegistry {
    let mock = MockRegistry::start().await;
    mock.with_package(name, "1.0.0", &make_tarball(name, "1.0.0"))
        .await;
    mount_block_verdict(&mock, name, verdict, group).await;
    mock
}

/// LPM Firewall blocks `name@1.0.0` with `verdict`, under the policy `group`.
async fn mount_block_verdict(mock: &MockRegistry, name: &str, verdict: &str, group: &str) {
    mount_block_verdicts(mock, &[name], verdict, group).await;
}

/// LPM Firewall blocks every one of `names` at 1.0.0 in a request that asks
/// about them all.
async fn mount_block_verdicts(mock: &MockRegistry, names: &[&str], verdict: &str, group: &str) {
    mount_block_verdicts_after(mock, names, verdict, group, std::time::Duration::ZERO).await;
}

/// As [`mount_block_verdicts`], answering only after `delay`.
async fn mount_block_verdicts_after(
    mock: &MockRegistry,
    names: &[&str],
    verdict: &str,
    group: &str,
    delay: std::time::Duration,
) {
    let decisions: Vec<serde_json::Value> = names
        .iter()
        .map(|name| {
            serde_json::json!({
                "decisionId": format!("bypass-test:{name}"),
                "name": name,
                "version": "1.0.0",
                "action": "block",
                "verdict": verdict,
                "reason": format!("client policy maps {group} to block"),
                "matchSource": "package",
                "policyMode": "enforce",
                "enqueueScan": false,
                "policy": { "group": group },
                "display": {
                    "summary": "The package can send a credential to a gateway.",
                    "reportUrl": format!("https://firewall.lpm.dev/npm/{name}/v/1.0.0")
                }
            })
        })
        .collect();
    let mut request = Mock::given(method("POST")).and(path(VERDICTS_PATH));
    for name in names {
        request = request.and(body_string_contains(format!("\"name\":\"{name}\"")));
    }
    request
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({
                    "requestId": "bypass-test",
                    "policyMode": "enforce",
                    "summary": {
                        "total": names.len(),
                        "allow": 0,
                        "warn": 0,
                        "block": names.len(),
                        "unknown": 0,
                        "matched": names.len()
                    },
                    "decisions": decisions
                }))
                .set_delay(delay),
        )
        .mount(mock.server())
        .await;
}

fn stored_rule(spec: &str, extra: serde_json::Value) -> serde_json::Value {
    let mut rule = serde_json::json!({
        "id": format!("fwb_{}", spec.len()),
        "spec": spec,
        "scope": "global",
        "added_at": "2026-11-25T10:00:00Z",
    });
    rule.as_object_mut()
        .unwrap()
        .extend(extra.as_object().cloned().unwrap_or_default());
    rule
}

/// A project root as the CLI keys rules on it: canonical, and on Windows a
/// drive path without the `\\?\` prefix canonical paths carry there. Other
/// verbatim paths, such as `\\?\UNC\...`, keep it, as the CLI does.
fn cli_project_root(dir: &std::path::Path) -> String {
    let root = std::fs::canonicalize(dir).unwrap().display().to_string();
    match root.strip_prefix(r"\\?\") {
        Some(plain)
            if cfg!(windows)
                && matches!(
                    plain.as_bytes(),
                    [drive, b':', b'\\', ..] if drive.is_ascii_alphabetic()
                ) =>
        {
            plain.to_string()
        }
        _ => root,
    }
}

fn enforcing_project() -> TempProject {
    let project = TempProject::empty(r#"{"name":"consumer","version":"1.0.0"}"#);
    write_npm_firewall_global_config(&project, "enforce");
    project
}

fn install(
    project: &TempProject,
    mock: &MockRegistry,
    name: &str,
    json: bool,
) -> std::process::Output {
    let mut command = lpm_with_registry(project, &mock.url());
    command.args(["--color", "never", "install", "--no-skills"]);
    if json {
        command.arg("--json");
    }
    command.arg(format!("{name}@1.0.0")).output().unwrap()
}

const AGENT_TOOL_HINT: &str = "  allow lpm firewall bypass add \"agent-tool@1.0.0\"\n";

#[tokio::test]
async fn blocked_install_names_the_command_that_allows_the_exact_version() {
    let mock = registry_blocking("agent-tool", "suspicious", "lpm_ai_agent_control_surface").await;
    let project = enforcing_project();

    let output = install(&project, &mock, "agent-tool", false);

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "{stderr}");
    assert!(
        stderr.contains(
            &format!(
                "✗ Blocked by LPM Firewall\n  reason 1 package blocked by LPM Firewall\n{AGENT_TOOL_HINT}"
            )
        ),
        "{stderr}"
    );
}

#[tokio::test]
async fn blocked_install_json_offers_the_bypass_command_as_a_next_step() {
    let mock = registry_blocking("agent-tool", "suspicious", "lpm_ai_agent_control_surface").await;
    let project = enforcing_project();

    let output = install(&project, &mock, "agent-tool", true);

    let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(envelope["error_code"], "npm_firewall_blocked");
    assert_eq!(envelope["error"]["packages"][0]["bypassable"], true);
    assert_eq!(envelope["error"]["packages"][0]["block_class"], "policy");
    assert_eq!(
        envelope["next_steps"][0]["command"],
        "lpm firewall bypass add \"agent-tool@1.0.0\""
    );
}

#[tokio::test]
async fn bypass_rule_lets_a_blocked_version_install_and_the_install_says_so() {
    let mock = registry_blocking("agent-tool", "suspicious", "lpm_ai_agent_control_surface").await;
    let project = enforcing_project();
    write_signed_firewall_bypass(
        &project,
        &[stored_rule("agent-tool", serde_json::json!({}))],
    );

    let output = install(&project, &mock, "agent-tool", false);

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{stderr}");
    assert!(
        stderr.contains("! LPM Firewall allowed 1 blocked package because of your bypass rules:\n"),
        "{stderr}"
    );
    assert!(
        stderr.contains("    rule: agent-tool (every project)\n"),
        "{stderr}"
    );
    assert!(project.file_exists("node_modules/agent-tool/package.json"));
}

#[tokio::test]
async fn bypassed_version_is_listed_in_the_install_json_security_report() {
    let mock = registry_blocking("agent-tool", "suspicious", "lpm_ai_agent_control_surface").await;
    let project = enforcing_project();
    write_signed_firewall_bypass(
        &project,
        &[stored_rule("agent-tool", serde_json::json!({}))],
    );

    let output = lpm_with_registry(&project, &mock.url())
        .env("LPM_TIMING_DETAIL", "1")
        .args(["install", "--no-skills", "--json", "agent-tool@1.0.0"])
        .output()
        .unwrap();

    assert!(output.status.success());
    let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let firewall = &envelope["security"]["firewall"];
    assert_eq!(firewall["bypassed_count"], 1);
    assert_eq!(firewall["bypassed"][0]["name"], "agent-tool");
    assert_eq!(firewall["bypassed"][0]["rule"]["spec"], "agent-tool");
    assert_eq!(firewall["bypassed"][0]["rule"]["source"], "local");
    assert_eq!(firewall["bypassed"][0]["rule"]["scope"], "global");
    assert_eq!(
        firewall["bypassed"][0]["rule"].get("project_root"),
        Some(&serde_json::Value::Null)
    );
    for timing in [
        &envelope["timing"]["firewall"],
        &envelope["timing"]["detail"]["security"]["firewall"],
    ] {
        assert_eq!(timing["bypassed_count"], 1, "{envelope:#}");
        assert!(timing.get("bypassed").is_none(), "{envelope:#}");
    }
}

/// More packages than one verdict request carries, so monitor mode asks in
/// two batches: the first, which holds `aaa-agent-tool` (packages are asked
/// in name order), answers and the second fails.
#[tokio::test]
async fn monitor_reports_what_a_rule_would_allow_when_a_later_verdict_batch_fails() {
    let mock = MockRegistry::start().await;
    let names: Vec<String> = std::iter::once("aaa-agent-tool".to_string())
        .chain((0..512).map(|index| format!("filler-{index:03}")))
        .collect();
    for name in &names {
        mock.with_package(name, "1.0.0", &make_tarball(name, "1.0.0"))
            .await;
    }
    Mock::given(method("POST"))
        .and(path(VERDICTS_PATH))
        .and(body_string_contains("\"name\":\"aaa-agent-tool\""))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "requestId": "bypass-test",
            "policyMode": "monitor",
            "summary": { "total": 1, "allow": 0, "warn": 0, "block": 1, "unknown": 0, "matched": 1 },
            "decisions": [{
                "decisionId": "bypass-test:aaa-agent-tool",
                "name": "aaa-agent-tool",
                "version": "1.0.0",
                "action": "block",
                "verdict": "suspicious",
                "reason": "client policy maps lpm_ai_agent_control_surface to block",
                "matchSource": "package",
                "policyMode": "monitor",
                "enqueueScan": false,
                "policy": { "group": "lpm_ai_agent_control_surface" }
            }]
        })))
        .with_priority(1)
        .expect(1)
        .mount(mock.server())
        .await;
    Mock::given(method("POST"))
        .and(path(VERDICTS_PATH))
        .respond_with(ResponseTemplate::new(500))
        .mount(mock.server())
        .await;
    let dependencies: serde_json::Map<String, serde_json::Value> = names
        .iter()
        .map(|name| (name.clone(), serde_json::json!("1.0.0")))
        .collect();
    let project = TempProject::empty(
        &serde_json::json!({ "name": "consumer", "version": "1.0.0", "dependencies": dependencies })
            .to_string(),
    );
    write_npm_firewall_global_config(&project, "monitor");
    write_signed_firewall_bypass(
        &project,
        &[stored_rule("aaa-agent-tool", serde_json::json!({}))],
    );

    let output = lpm_with_registry(&project, &mock.url())
        .args(["--color", "never", "install", "--no-skills"])
        .output()
        .unwrap();

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{stderr}");
    assert!(
        stderr.contains("! npm firewall verdict preflight failed in monitor mode:"),
        "{stderr}"
    );
    assert!(
        stderr
            .contains("! LPM Firewall monitor: your bypass rules would allow 1 blocked package:\n"),
        "{stderr}"
    );
    assert!(
        stderr.contains("    rule: aaa-agent-tool (every project)\n"),
        "{stderr}"
    );
}

/// An enforce-mode install of `agent-tool`, which a rule lifts, and
/// `unchecked-tool`, whose verdict request fails, each answered after its
/// delay, so the test controls which arrives first.
async fn install_with_a_failing_verdict_request(
    lifted_after: std::time::Duration,
    failure_after: std::time::Duration,
) -> (MockRegistry, std::process::Output) {
    install_with_a_failing_verdict_request_in(lifted_after, failure_after, false).await
}

/// As [`install_with_a_failing_verdict_request`], in JSON when `json` is set.
async fn install_with_a_failing_verdict_request_in(
    lifted_after: std::time::Duration,
    failure_after: std::time::Duration,
    json: bool,
) -> (MockRegistry, std::process::Output) {
    let mock = MockRegistry::start().await;
    mock.with_package("agent-tool", "1.0.0", &make_tarball("agent-tool", "1.0.0"))
        .await;
    mount_block_verdicts_after(
        &mock,
        &["agent-tool"],
        "suspicious",
        "lpm_ai_agent_control_surface",
        lifted_after,
    )
    .await;
    mock.with_package(
        "unchecked-tool",
        "1.0.0",
        &make_tarball("unchecked-tool", "1.0.0"),
    )
    .await;
    Mock::given(method("POST"))
        .and(path(VERDICTS_PATH))
        .and(body_string_contains("\"name\":\"unchecked-tool\""))
        .respond_with(ResponseTemplate::new(400).set_delay(failure_after))
        .mount(mock.server())
        .await;
    let project = enforcing_project();
    write_signed_firewall_bypass(
        &project,
        &[stored_rule("agent-tool", serde_json::json!({}))],
    );

    let mut command = lpm_with_registry(&project, &mock.url());
    command.env("LPM_EXPERIMENT_NPM_FIREWALL_CHUNK_SIZE", "1");
    if json {
        command.arg("--json");
    }
    let output = command
        .args([
            "--color",
            "never",
            "install",
            "--no-skills",
            "agent-tool@1.0.0",
            "unchecked-tool@1.0.0",
        ])
        .output()
        .unwrap();
    (mock, output)
}

const AGENT_TOOL_ALLOWED: &str =
    "! LPM Firewall allowed 1 blocked package because of your bypass rules:\n";

#[tokio::test]
async fn an_install_prints_a_lifted_version_it_downloaded_before_a_verdict_request_failed() {
    let (mock, output) = install_with_a_failing_verdict_request(
        std::time::Duration::ZERO,
        std::time::Duration::from_millis(1500),
    )
    .await;

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "{stderr}");
    let notice = stderr.find(AGENT_TOOL_ALLOWED).expect(&stderr);
    assert!(
        stderr[notice..].contains("    rule: agent-tool (every project)\n"),
        "{stderr}"
    );
    let error = stderr.find("npm firewall").expect(&stderr);
    assert!(
        notice < error,
        "the notice must come before the error: {stderr}"
    );
    assert_eq!(mock.tarball_request_count("agent-tool", "1.0.0").await, 1);
}

#[tokio::test]
async fn an_install_reports_no_lifted_version_held_back_after_a_verdict_request_failed() {
    let (mock, output) = install_with_a_failing_verdict_request(
        std::time::Duration::from_millis(1500),
        std::time::Duration::ZERO,
    )
    .await;

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "{stderr}");
    assert!(
        stderr.contains("npm firewall verdict preflight failed"),
        "{stderr}"
    );
    assert_eq!(verdict_requests_naming(&mock, "agent-tool").await, 1);
    assert_eq!(verdict_requests_naming(&mock, "unchecked-tool").await, 1);
    assert!(!stderr.contains("LPM Firewall allowed"), "{stderr}");
    assert_eq!(mock.tarball_request_count("agent-tool", "1.0.0").await, 0);
}

/// How many verdict requests the registry received that ask about `name`.
async fn verdict_requests_naming(mock: &MockRegistry, name: &str) -> usize {
    let needle = format!("\"name\":\"{name}\"");
    mock.server()
        .received_requests()
        .await
        .expect("wiremock request log must be available")
        .iter()
        .filter(|request| {
            request.url.path() == VERDICTS_PATH
                && String::from_utf8_lossy(&request.body).contains(&needle)
        })
        .count()
}

#[tokio::test]
async fn name_rule_never_lets_a_malware_version_through() {
    let mock = registry_blocking("hijacked", "malicious", "lpm_ai_confirmed_malware").await;
    let project = enforcing_project();
    write_signed_firewall_bypass(&project, &[stored_rule("hijacked", serde_json::json!({}))]);

    let output = install(&project, &mock, "hijacked", false);

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "{stderr}");
    assert!(
        stderr.contains("  malware hijacked@1.0.0 is flagged as malware;"),
        "{stderr}"
    );
    assert!(
        !stderr.contains("allow lpm firewall bypass add"),
        "{stderr}"
    );
    assert!(!project.file_exists("node_modules/hijacked/package.json"));
}

#[tokio::test]
async fn exact_rule_approved_for_malware_lets_that_version_through() {
    let mock = registry_blocking("hijacked", "malicious", "lpm_ai_confirmed_malware").await;
    let project = enforcing_project();
    write_signed_firewall_bypass(
        &project,
        &[stored_rule(
            "hijacked@1.0.0",
            serde_json::json!({ "covers_malware": true }),
        )],
    );

    let output = install(&project, &mock, "hijacked", false);

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[tokio::test]
async fn expired_bypass_rule_no_longer_applies() {
    let mock = registry_blocking("agent-tool", "suspicious", "lpm_ai_agent_control_surface").await;
    let project = enforcing_project();
    write_signed_firewall_bypass(
        &project,
        &[stored_rule(
            "agent-tool",
            serde_json::json!({ "expires_at": "2026-01-01T00:00:00Z" }),
        )],
    );

    let output = install(&project, &mock, "agent-tool", false);

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "{stderr}");
    assert!(stderr.contains(AGENT_TOOL_HINT), "{stderr}");
    assert!(!stderr.contains("couldn't be read"), "{stderr}");
    assert!(!project.file_exists("node_modules/agent-tool/package.json"));
}

#[tokio::test]
async fn tampered_bypass_store_keeps_the_block_and_says_why() {
    let mock = registry_blocking("agent-tool", "suspicious", "lpm_ai_agent_control_surface").await;
    let project = enforcing_project();
    write_signed_firewall_bypass(
        &project,
        &[stored_rule(
            "agent-tool",
            serde_json::json!({ "reason": "reviewed the report" }),
        )],
    );
    let store = project.home().join(".lpm/security/firewall-bypass.json");
    let original = std::fs::read_to_string(&store).unwrap();
    let tampered = original.replace("reviewed the report", "reviewed the reportX");
    assert_ne!(original, tampered);
    std::fs::write(&store, tampered).unwrap();

    let output = install(&project, &mock, "agent-tool", false);

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "{stderr}");
    assert!(
        stderr.contains("note your bypass rules couldn't be read"),
        "{stderr}"
    );
    assert_eq!(stderr.matches("lpm security repair").count(), 1, "{stderr}");
    assert!(
        !stderr.contains("allow lpm firewall bypass add"),
        "{stderr}"
    );
    assert!(!project.file_exists("node_modules/agent-tool/package.json"));
}

#[tokio::test]
async fn project_bypass_rule_applies_only_in_its_project() {
    let mock = registry_blocking("agent-tool", "suspicious", "lpm_ai_agent_control_surface").await;
    let project = enforcing_project();
    let root = cli_project_root(project.path());
    write_signed_firewall_bypass(
        &project,
        &[stored_rule(
            "agent-tool",
            serde_json::json!({ "scope": "project", "project_root": root }),
        )],
    );

    let output = install(&project, &mock, "agent-tool", true);
    assert!(output.status.success());
    let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let rule = &envelope["security"]["firewall"]["bypassed"][0]["rule"];
    assert_eq!(rule["scope"], "project");
    assert_eq!(rule["project_root"], root.as_str());

    let other = enforcing_project();
    write_signed_firewall_bypass(
        &other,
        &[stored_rule(
            "agent-tool",
            serde_json::json!({ "scope": "project", "project_root": root }),
        )],
    );
    let output = install(&other, &mock, "agent-tool", false);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "{stderr}");
    assert!(stderr.contains(AGENT_TOOL_HINT), "{stderr}");
}

#[tokio::test]
async fn managed_policy_turns_off_local_bypass_rules_and_applies_its_own_list() {
    let mock = registry_blocking("agent-tool", "suspicious", "lpm_ai_agent_control_surface").await;
    let project = enforcing_project();
    write_signed_firewall_bypass(
        &project,
        &[stored_rule("agent-tool", serde_json::json!({}))],
    );
    let policy = project.home().join(".lpm/security-policy.toml");
    std::fs::write(&policy, "[firewall]\nmode = \"enforce\"\n").unwrap();

    let output = install(&project, &mock, "agent-tool", false);

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "{stderr}");
    assert!(stderr.contains("[firewall].bypass"), "{stderr}");
    assert!(
        !stderr.contains("allow lpm firewall bypass add"),
        "{stderr}"
    );

    std::fs::write(
        &policy,
        "[firewall]\nmode = \"enforce\"\nbypass = [\"agent-tool@1.0.0\"]\n",
    )
    .unwrap();
    let output = install(&project, &mock, "agent-tool", false);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{stderr}");
    assert!(
        stderr.contains("rule: agent-tool@1.0.0 (every project from the managed policy)"),
        "{stderr}"
    );
}

#[test]
fn bypass_add_in_json_mode_asks_a_person_to_approve_it() {
    let project = TempProject::empty(r#"{"name":"consumer","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["firewall", "bypass", "add", "agent-tool@1.0.0", "--json"])
        .output()
        .unwrap();

    assert!(!output.status.success());
    let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(envelope["error_code"], "security_approval_required");
    assert_eq!(envelope["error"]["requested_scopes"][0], "firewall-bypass");
    assert_eq!(
        envelope["next_steps"][0]["command"],
        "lpm firewall bypass add \"agent-tool@1.0.0\""
    );
    assert!(
        !project
            .home()
            .join(".lpm/security/firewall-bypass.json")
            .exists()
    );
}

#[test]
fn bypass_add_rejects_a_dist_tag() {
    let project = TempProject::empty(r#"{"name":"consumer","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["firewall", "bypass", "add", "agent-tool@latest", "--json"])
        .output()
        .unwrap();

    let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(envelope["error_code"], "invalid_package_name");
    assert!(
        envelope["error"].as_str().unwrap().contains("dist-tag"),
        "{envelope}"
    );
}

#[test]
fn bypass_list_json_reports_saved_and_managed_rules() {
    let project = TempProject::empty(r#"{"name":"consumer","version":"1.0.0"}"#);
    write_signed_firewall_bypass(
        &project,
        &[
            stored_rule(
                "agent-tool",
                serde_json::json!({ "reason": "reviewed the report" }),
            ),
            stored_rule(
                "hijacked@1.0.0",
                serde_json::json!({ "covers_malware": true, "expires_at": "2026-01-01T00:00:00Z" }),
            ),
        ],
    );
    std::fs::write(
        project.home().join(".lpm/security-policy.toml"),
        "[firewall]\nbypass = [\"left-pad@^1.0.0\"]\n",
    )
    .unwrap();

    let output = lpm(&project)
        .args(["firewall", "bypass", "list", "--json"])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    insta::assert_json_snapshot!("firewall_bypass_list_json", envelope);
}

#[test]
fn bypass_remove_and_clear_need_no_approval() {
    let project = TempProject::empty(r#"{"name":"consumer","version":"1.0.0"}"#);
    write_signed_firewall_bypass(
        &project,
        &[
            stored_rule("agent-tool", serde_json::json!({})),
            stored_rule("left-pad@1.0.0", serde_json::json!({})),
        ],
    );

    let removed = lpm(&project)
        .args([
            "firewall",
            "bypass",
            "remove",
            "agent-tool",
            "missing-tool",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(removed.status.success());
    let removed: serde_json::Value = serde_json::from_slice(&removed.stdout).unwrap();
    assert_eq!(removed["count"], 1);
    assert_eq!(removed["removed"][0]["spec"], "agent-tool");
    assert_eq!(removed["not_found"][0], "missing-tool");
    assert_eq!(removed["rules_total"], 1);

    let cleared = lpm(&project)
        .args(["firewall", "bypass", "clear", "--json"])
        .output()
        .unwrap();
    assert!(cleared.status.success());
    let cleared: serde_json::Value = serde_json::from_slice(&cleared.stdout).unwrap();
    assert_eq!(cleared["count"], 1);
    assert_eq!(cleared["rules_total"], 0);
    assert!(
        !project
            .home()
            .join(".lpm/security/firewall-bypass.json")
            .exists()
    );
}

#[tokio::test]
async fn global_install_block_names_a_rule_for_every_project() {
    let mock = registry_blocking("agent-tool", "suspicious", "lpm_ai_agent_control_surface").await;
    let project = enforcing_project();
    let root = cli_project_root(project.path());
    write_signed_firewall_bypass(
        &project,
        &[stored_rule(
            "agent-tool",
            serde_json::json!({ "scope": "project", "project_root": root }),
        )],
    );

    let output = lpm_with_registry(&project, &mock.url())
        .args(["--color", "never", "install", "-g", "agent-tool@1.0.0"])
        .output()
        .unwrap();

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "{stderr}");
    assert!(stderr.contains(AGENT_TOOL_HINT), "{stderr}");
}

#[tokio::test]
async fn global_install_ignores_a_project_rule_for_a_workspace_that_holds_lpm_home() {
    let mock = registry_blocking("agent-tool", "suspicious", "lpm_ai_agent_control_surface").await;
    let project = enforcing_project();
    // The workspace claims every directory under `LPM_HOME`'s global tree,
    // so the global install root resolves to this project.
    std::fs::write(
        project.home().join("package.json"),
        r#"{"name":"home-workspace","private":true,"workspaces":[".lpm/global/**"]}"#,
    )
    .unwrap();
    let root = cli_project_root(project.home());
    write_signed_firewall_bypass(
        &project,
        &[stored_rule(
            "agent-tool",
            serde_json::json!({ "scope": "project", "project_root": root }),
        )],
    );

    let output = lpm_with_registry(&project, &mock.url())
        .args(["--color", "never", "install", "-g", "agent-tool@1.0.0"])
        .output()
        .unwrap();

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "{stderr}");
    assert!(stderr.contains(AGENT_TOOL_HINT), "{stderr}");
}

/// A project whose dependency LPM Firewall blocks, with no rule for it.
fn project_depending_on_a_blocked_tool() -> TempProject {
    let project = TempProject::empty(
        r#"{"name":"consumer","version":"1.0.0","scripts":{"dev":"node index.js"},"dependencies":{"agent-tool":"1.0.0"}}"#,
    );
    project.write_file("index.js", "console.log('dev-ran');\n");
    write_npm_firewall_global_config(&project, "enforce");
    project
}

#[tokio::test]
async fn dev_auto_install_names_what_a_block_stopped_and_the_command_that_allows_it() {
    let mock = registry_blocking("agent-tool", "suspicious", "lpm_ai_agent_control_surface").await;
    let project = project_depending_on_a_blocked_tool();

    let output = lpm_with_registry(&project, &mock.url())
        .args(["--color", "never", "dev", "--no-open", "--no-dashboard"])
        .output()
        .unwrap();

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "{stderr}");
    assert!(!String::from_utf8_lossy(&output.stdout).contains("dev-ran"));
    assert!(
        stderr
            .contains("blocked agent-tool@1.0.0 - The package can send a credential to a gateway."),
        "{stderr}"
    );
    assert!(stderr.contains("✗ Blocked by LPM Firewall"), "{stderr}");
    assert!(stderr.contains(AGENT_TOOL_HINT), "{stderr}");
}

#[tokio::test]
async fn doctor_fix_names_what_a_block_stopped_in_its_failed_install() {
    let mock = MockRegistry::start().await;
    for name in ["agent-tool", "helper-tool"] {
        mock.with_package(name, "1.0.0", &make_tarball(name, "1.0.0"))
            .await;
    }
    mount_block_verdicts(
        &mock,
        &["agent-tool", "helper-tool"],
        "suspicious",
        "lpm_ai_agent_control_surface",
    )
    .await;
    let project = TempProject::empty(
        r#"{"name":"consumer","version":"1.0.0","dependencies":{"agent-tool":"1.0.0","helper-tool":"1.0.0"}}"#,
    );
    write_npm_firewall_global_config(&project, "enforce");
    write_signed_firewall_bypass(
        &project,
        &[stored_rule("helper-tool", serde_json::json!({}))],
    );

    let terminal = lpm_with_registry(&project, &mock.url())
        .args(["--color", "never", "doctor", "--fix", "--yes"])
        .output()
        .unwrap();
    let json = lpm_with_registry(&project, &mock.url())
        .args(["--json", "doctor", "--fix", "--yes"])
        .output()
        .unwrap();

    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&terminal.stdout),
        String::from_utf8_lossy(&terminal.stderr)
    );
    assert!(text.contains("lpm install failed"), "{text}");
    assert!(
        text.contains("blocked agent-tool@1.0.0 - The package can send a credential to a gateway."),
        "{text}"
    );
    assert!(
        text.contains("allowed helper-tool@1.0.0 by your bypass rule helper-tool"),
        "{text}"
    );
    assert!(text.contains(AGENT_TOOL_HINT), "{text}");
    let json_stderr = String::from_utf8_lossy(&json.stderr);
    assert!(!json_stderr.contains("lpm install failed"), "{json_stderr}");
    assert!(!json_stderr.contains("blocked agent-tool"), "{json_stderr}");
    let envelope: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
    let failed = &envelope["fixes_failed"][0];
    assert_eq!(failed["action"], "lpm install", "{envelope:#}");
    assert_eq!(failed["error_code"], "npm_firewall_blocked", "{envelope:#}");
    assert_eq!(
        failed["block"]["packages"][0]["name"], "agent-tool",
        "{envelope:#}"
    );
    assert_eq!(
        failed["block"]["bypassed"][0]["name"], "helper-tool",
        "{envelope:#}"
    );
}

/// A registry where a rule lets `agent-tool@1.0.0` past its block and its
/// download then fails the integrity check, so the install fails after LPM
/// Firewall let the version through.
async fn registry_lifting_a_tarball_that_fails_its_check() -> MockRegistry {
    let mock = registry_blocking("agent-tool", "suspicious", "lpm_ai_agent_control_surface").await;
    let tarball_url = mock.tarball_url("agent-tool", "1.0.0");
    let tarball_path = tarball_url.strip_prefix(&mock.url()).unwrap().to_string();
    Mock::given(method("GET"))
        .and(path(tarball_path))
        .respond_with(
            ResponseTemplate::new(200).set_body_bytes(make_tarball("other-tool", "9.9.9")),
        )
        .with_priority(1)
        .mount(mock.server())
        .await;
    mock
}

/// Runs a quiet install's command where the install fails after a rule let a
/// blocked version through.
async fn run_through_a_failing_lifted_install(args: &[&str]) -> std::process::Output {
    let mock = registry_lifting_a_tarball_that_fails_its_check().await;
    let project = project_depending_on_a_blocked_tool();
    write_signed_firewall_bypass(
        &project,
        &[stored_rule("agent-tool", serde_json::json!({}))],
    );
    lpm_with_registry(&project, &mock.url())
        .args(["--color", "never"])
        .args(args)
        .output()
        .unwrap()
}

#[tokio::test]
async fn quiet_installs_that_fail_after_a_rule_lifted_a_block_still_print_it() {
    for args in [
        &["doctor", "--fix", "--yes"][..],
        &["dev", "--no-open", "--no-dashboard"][..],
        &["--json", "dlx", "agent-tool@1.0.0"][..],
    ] {
        let output = run_through_a_failing_lifted_install(args).await;

        let stderr = String::from_utf8_lossy(&output.stderr);
        let text = format!("{}{stderr}", String::from_utf8_lossy(&output.stdout));
        assert!(!output.status.success(), "{args:?}: {text}");
        assert!(text.contains("integrity"), "{args:?}: {text}");
        assert!(
            stderr.contains(
                "! LPM Firewall allowed 1 blocked package because of your bypass rules:\n"
            ),
            "{args:?}: {text}"
        );
        assert!(
            stderr.contains("    rule: agent-tool (every project)\n"),
            "{args:?}: {text}"
        );
    }
}

async fn mount_blocked_global_update(mock: &MockRegistry, name: &str) {
    mount_global_update(mock, name, "block").await;
}

/// `name` 1.1.0 is published with a binary, and LPM Firewall answers
/// `action` for it.
async fn mount_global_update(mock: &MockRegistry, name: &str, action: &str) {
    let blocked = action == "block";
    let bin_path = format!("bin/{name}.js");
    let tarball = support::mock_registry::make_tarball_from_pkg_json(
        serde_json::json!({ "name": name, "version": "1.1.0", "bin": { name: bin_path } }),
        &[(bin_path.as_str(), b"#!/usr/bin/env node\n" as &[u8])],
    );
    let tarball_path = format!("/tarballs/{name}/-/{name}-1.1.0.tgz");
    Mock::given(method("GET"))
        .and(path(format!("/{name}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "name": name,
            "dist-tags": { "latest": "1.1.0" },
            "versions": {
                "1.0.0": { "name": name, "version": "1.0.0" },
                "1.1.0": {
                    "name": name,
                    "version": "1.1.0",
                    "bin": { name: bin_path },
                    "dist": {
                        "tarball": format!("{}{tarball_path}", mock.url()),
                        "integrity": support::mock_registry::compute_integrity(&tarball)
                    }
                }
            },
            "time": {
                "1.0.0": "2025-01-01T00:00:00.000Z",
                "1.1.0": "2025-01-01T00:00:00.000Z"
            }
        })))
        .mount(mock.server())
        .await;
    Mock::given(method("GET"))
        .and(path(tarball_path))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(tarball))
        .mount(mock.server())
        .await;
    Mock::given(method("POST"))
        .and(path(VERDICTS_PATH))
        .and(body_string_contains(format!("\"name\":\"{name}\"")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "requestId": "global-update",
            "policyMode": "enforce",
            "summary": {
                "total": 1,
                "allow": u8::from(!blocked),
                "warn": 0,
                "block": u8::from(blocked),
                "unknown": 0,
                "matched": 1
            },
            "decisions": [{
                "decisionId": format!("global-update:{name}"),
                "name": name,
                "version": "1.1.0",
                "action": action,
                "verdict": if blocked { "suspicious" } else { "clean" },
                "reason": "client policy maps lpm_ai_agent_control_surface to block",
                "matchSource": "package",
                "policyMode": "enforce",
                "enqueueScan": false,
                "policy": { "group": "lpm_ai_agent_control_surface" },
                "display": {
                    "summary": "The package can send a credential to a gateway.",
                    "reportUrl": format!("https://firewall.lpm.dev/npm/{name}/v/1.1.0")
                }
            }]
        })))
        .mount(mock.server())
        .await;
}

fn installed_globally(project: &TempProject, names: &[&str]) {
    let mut manifest = lpm_global::GlobalManifest::default();
    for name in names {
        manifest.packages.insert(
            (*name).to_string(),
            lpm_global::PackageEntry {
                saved_spec: "^1".to_string(),
                resolved: "1.0.0".to_string(),
                integrity: "sha512-old".to_string(),
                source: lpm_global::PackageSource::UpstreamNpm,
                installed_at: lpm_common::Timestamp::now(),
                root: format!("installs/{name}@1.0.0"),
                commands: vec![(*name).to_string()],
            },
        );
    }
    lpm_global::write_for(
        &lpm_common::LpmRoot::from_dir(project.home().join(".lpm")),
        &manifest,
    )
    .unwrap();
}

#[tokio::test]
async fn global_update_block_names_the_bypass_command() {
    let mock = MockRegistry::start().await;
    mount_blocked_global_update(&mock, "update-tool").await;
    let project = enforcing_project();
    installed_globally(&project, &["update-tool"]);

    let output = lpm_with_registry(&project, &mock.url())
        .args(["--color", "never", "global", "update"])
        .output()
        .unwrap();

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "{stderr}");
    assert!(
        stderr.contains("  allow lpm firewall bypass add \"update-tool@1.1.0\"\n"),
        "{stderr}"
    );
}

#[tokio::test]
async fn global_update_json_offers_one_bypass_command_for_every_blocked_package() {
    let mock = MockRegistry::start().await;
    mount_blocked_global_update(&mock, "update-tool").await;
    mount_blocked_global_update(&mock, "other-tool").await;
    let project = enforcing_project();
    installed_globally(&project, &["update-tool", "other-tool"]);

    let output = lpm_with_registry(&project, &mock.url())
        .args(["--json", "global", "update"])
        .output()
        .unwrap();

    assert!(!output.status.success());
    let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let results = envelope["results"].as_array().unwrap();
    assert_eq!(results.len(), 2, "{envelope:#}");
    for result in results {
        let package = result["package"].as_str().unwrap();
        assert_eq!(result["action"], "failed");
        assert_eq!(result["error_code"], "npm_firewall_blocked");
        assert_eq!(result["error"]["packages"][0]["name"], package);
        assert_eq!(
            result["error"]["packages"][0]["display"]["report_url"],
            format!("https://firewall.lpm.dev/npm/{package}/v/1.1.0")
        );
        assert_eq!(
            result["error"]["bypass_command"],
            format!("lpm firewall bypass add \"{package}@1.1.0\"")
        );
    }
    assert_eq!(
        envelope["next_steps"][0]["command"],
        "lpm firewall bypass add \"other-tool@1.1.0\" \"update-tool@1.1.0\""
    );
}

#[tokio::test]
async fn batch_global_update_names_each_blocked_version_under_its_tool() {
    let mock = MockRegistry::start().await;
    mount_blocked_global_update(&mock, "update-tool").await;
    mount_blocked_global_update(&mock, "other-tool").await;
    let project = enforcing_project();
    installed_globally(&project, &["update-tool", "other-tool"]);

    let output = lpm_with_registry(&project, &mock.url())
        .args(["--color", "never", "global", "update"])
        .output()
        .unwrap();

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "{stderr}");
    for name in ["update-tool", "other-tool"] {
        assert!(
            stderr.contains(&format!(
                "  blocked {name}@1.1.0 - The package can send a credential to a gateway.\n  report https://firewall.lpm.dev/npm/{name}/v/1.1.0\n"
            )),
            "{stderr}"
        );
    }
    assert!(
        stderr.contains(
            "  allow lpm firewall bypass add \"other-tool@1.1.0\" \"update-tool@1.1.0\"\n"
        ),
        "{stderr}"
    );
}

#[tokio::test]
async fn managed_bypass_entries_still_apply_when_local_rules_fail_verification() {
    let mock = registry_blocking("agent-tool", "suspicious", "lpm_ai_agent_control_surface").await;
    let project = enforcing_project();
    write_signed_firewall_bypass(
        &project,
        &[stored_rule(
            "other-tool",
            serde_json::json!({ "reason": "reviewed the report" }),
        )],
    );
    let store = project.home().join(".lpm/security/firewall-bypass.json");
    let tampered = std::fs::read_to_string(&store)
        .unwrap()
        .replace("reviewed the report", "reviewed the reportX");
    std::fs::write(&store, tampered).unwrap();
    std::fs::write(
        project.home().join(".lpm/security-policy.toml"),
        "[firewall]\nbypass = [\"agent-tool@1.0.0\"]\n",
    )
    .unwrap();

    let output = install(&project, &mock, "agent-tool", false);

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{stderr}");
    assert!(
        stderr.contains("rule: agent-tool@1.0.0 (every project from the managed policy)"),
        "{stderr}"
    );
}

/// The id the CLI gives a global rule for `spec`, so a fixture can stand in
/// for a rule `add` saved.
fn global_rule_id(spec: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"global");
    hasher.update([0]);
    hasher.update([0]);
    hasher.update(spec.as_bytes());
    hasher.update([0, 0]);
    format!("fwb_{}", hex::encode(&hasher.finalize()[..6]))
}

fn saved_rules(project: &TempProject) -> Vec<serde_json::Value> {
    let store = project.home().join(".lpm/security/firewall-bypass.json");
    let file: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(store).unwrap()).unwrap();
    file["payload"]["rules"].as_array().unwrap().clone()
}

#[test]
fn bypass_add_json_shortens_a_saved_rule_without_approval() {
    let project = enforcing_project();
    write_signed_firewall_bypass(
        &project,
        &[stored_rule(
            "agent-tool",
            serde_json::json!({ "id": global_rule_id("agent-tool") }),
        )],
    );

    let output = lpm(&project)
        .args([
            "--json",
            "firewall",
            "bypass",
            "add",
            "agent-tool",
            "--ttl",
            "30m",
        ])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(envelope["narrowed"][0]["spec"], "agent-tool");
    assert!(saved_rules(&project)[0]["expires_at"].is_string());
}

#[test]
fn bypass_add_json_that_needs_approval_changes_nothing() {
    let project = enforcing_project();
    write_signed_firewall_bypass(
        &project,
        &[stored_rule(
            "agent-tool",
            serde_json::json!({ "id": global_rule_id("agent-tool") }),
        )],
    );

    let output = lpm(&project)
        .args([
            "--json",
            "firewall",
            "bypass",
            "add",
            "agent-tool",
            "other-tool",
            "--ttl",
            "30m",
        ])
        .output()
        .unwrap();

    assert!(!output.status.success());
    let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(envelope["error_code"], "security_approval_required");
    assert_eq!(
        envelope["next_steps"][0]["command"],
        "lpm firewall bypass add --ttl 30m \"agent-tool\" \"other-tool\""
    );
    let rules = saved_rules(&project);
    assert_eq!(rules.len(), 1);
    assert!(rules[0].get("expires_at").is_none());
}

#[test]
fn bypass_add_that_only_shortens_a_rule_reads_no_preview_settings() {
    let project = enforcing_project();
    write_signed_firewall_bypass(
        &project,
        &[stored_rule(
            "agent-tool",
            serde_json::json!({ "id": global_rule_id("agent-tool") }),
        )],
    );

    let output = lpm(&project)
        .env("LPM_NPM_FIREWALL", "not-a-mode")
        .args(["firewall", "bypass", "add", "agent-tool", "--ttl", "30m"])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(saved_rules(&project)[0]["expires_at"].is_string());
}

#[tokio::test]
async fn global_update_names_a_version_refused_while_planning_once() {
    let mock = MockRegistry::start().await;
    // Only lpm.dev can answer with LPM Firewall's refusal, and global update
    // plans an @lpm.dev package through it.
    Mock::given(method("GET"))
        .and(wiremock::matchers::path_regex(r"plan-tool$"))
        .respond_with(ResponseTemplate::new(403).set_body_json(serde_json::json!({
            "error": "blocked_by_lpm_firewall",
            "package": "@lpm.dev/acme.plan-tool@1.1.0",
            "verdict": "malicious",
            "reason": "the registry policy refused this download",
            "display": { "reportUrl": "https://firewall.lpm.dev/npm/plan-tool/v/1.1.0" }
        })))
        .mount(mock.server())
        .await;
    let project = enforcing_project();
    installed_globally(&project, &["@lpm.dev/acme.plan-tool"]);

    let output = lpm_with_registry(&project, &mock.url())
        .args(["--color", "never", "global", "update"])
        .output()
        .unwrap();

    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!output.status.success(), "{text}");
    assert_eq!(
        text.matches("blocked @lpm.dev/acme.plan-tool@1.1.0")
            .count(),
        1,
        "{text}"
    );
    assert!(text.contains("verdict: malicious"), "{text}");
    assert!(
        text.contains("https://firewall.lpm.dev/npm/plan-tool/v/1.1.0"),
        "{text}"
    );
}

#[tokio::test]
async fn global_install_json_reports_the_version_a_bypass_rule_let_through() {
    for mode in ["enforce", "monitor"] {
        assert_global_install_json_reports_the_bypass(mode).await;
    }
}

/// In `monitor` mode nothing is blocked, so the entry is what the rule would
/// have let through, with `mode` saying so.
async fn assert_global_install_json_reports_the_bypass(mode: &str) {
    let mock = MockRegistry::start().await;
    mount_blocked_global_update(&mock, "update-tool").await;
    let project = TempProject::empty(r#"{"name":"consumer","version":"1.0.0"}"#);
    write_npm_firewall_global_config(&project, mode);
    write_signed_firewall_bypass(
        &project,
        &[stored_rule("update-tool", serde_json::json!({}))],
    );

    let output = lpm_with_registry(&project, &mock.url())
        .args(["--json", "install", "-g", "update-tool"])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{mode}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let firewall = &envelope["security"]["firewall"];
    assert_eq!(firewall["mode"], mode, "{envelope:#}");
    assert_eq!(
        firewall["bypassed"][0]["name"], "update-tool",
        "{envelope:#}"
    );
    assert_eq!(firewall["bypassed"][0]["version"], "1.1.0", "{envelope:#}");
    assert_eq!(
        firewall["bypassed"][0]["rule"]["spec"], "update-tool",
        "{envelope:#}"
    );
}

/// A bulk `lpm global update` of `update-tool`, which a rule lets past a
/// block, and `other-tool`, which LPM Firewall answers `other_tool_action`
/// for.
async fn batch_update_with_one_tool_allowed(
    json: bool,
    other_tool_action: &str,
) -> (std::process::Output, TempProject) {
    let mock = MockRegistry::start().await;
    mount_blocked_global_update(&mock, "update-tool").await;
    mount_global_update(&mock, "other-tool", other_tool_action).await;
    let project = enforcing_project();
    installed_globally(&project, &["update-tool", "other-tool"]);
    write_signed_firewall_bypass(
        &project,
        &[stored_rule("update-tool", serde_json::json!({}))],
    );

    let mut command = lpm_with_registry(&project, &mock.url());
    command.args(["--color", "never"]);
    if json {
        command.arg("--json");
    }
    let output = command.args(["global", "update"]).output().unwrap();
    (output, project)
}

#[tokio::test]
async fn global_update_reports_what_a_rule_let_through_for_a_tool_whose_update_then_failed() {
    for json in [true, false] {
        let mock = MockRegistry::start().await;
        mount_blocked_global_update(&mock, "update-tool").await;
        mount_global_update(&mock, "other-tool", "allow").await;
        Mock::given(method("GET"))
            .and(path("/tarballs/update-tool/-/update-tool-1.1.0.tgz"))
            .respond_with(
                ResponseTemplate::new(200).set_body_bytes(make_tarball("other-tool", "9.9.9")),
            )
            .with_priority(1)
            .mount(mock.server())
            .await;
        let project = enforcing_project();
        installed_globally(&project, &["update-tool", "other-tool"]);
        write_signed_firewall_bypass(
            &project,
            &[stored_rule("update-tool", serde_json::json!({}))],
        );

        let mut command = lpm_with_registry(&project, &mock.url());
        command.args(["--color", "never"]);
        if json {
            command.arg("--json");
        }
        let output = command.args(["global", "update"]).output().unwrap();

        assert!(!output.status.success());
        if json {
            let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
            let failed = envelope["results"]
                .as_array()
                .unwrap()
                .iter()
                .find(|result| result["package"] == "update-tool")
                .unwrap();
            assert_eq!(failed["action"], "failed", "{envelope:#}");
            assert_eq!(
                failed["security"]["firewall"]["bypassed"][0]["name"], "update-tool",
                "{envelope:#}"
            );
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let failure = stderr.find("update-tool:").expect(&stderr);
            let notice = stderr
                .find("LPM Firewall allowed 1 blocked package because of your bypass rules")
                .expect(&stderr);
            assert!(failure < notice, "{stderr}");
            assert!(stderr.contains("rule: update-tool"), "{stderr}");
        }
    }
}

#[tokio::test]
async fn batch_global_update_prints_what_a_bypass_rule_let_through_under_its_tool() {
    let (output, _project) = batch_update_with_one_tool_allowed(false, "block").await;

    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        text.matches("LPM Firewall allowed 1 blocked package because of your bypass rules")
            .count(),
        1,
        "{text}"
    );
    assert!(
        text.contains(
            "✓ Upgraded update-tool 1.0.0 → 1.1.0\n! LPM Firewall allowed 1 blocked package because of your bypass rules:\n"
        ),
        "{text}"
    );
    assert!(text.contains("rule: update-tool"), "{text}");
}

#[tokio::test]
async fn batch_global_update_json_reports_what_a_bypass_rule_let_through_per_tool() {
    let (output, _project) = batch_update_with_one_tool_allowed(true, "allow").await;

    let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let results = envelope["results"].as_array().unwrap();
    let updated = results
        .iter()
        .find(|result| result["package"] == "update-tool")
        .unwrap();
    assert_eq!(updated["action"], "upgraded", "{envelope:#}");
    let firewall = &updated["security"]["firewall"];
    assert_eq!(
        firewall["bypassed"][0]["name"], "update-tool",
        "{envelope:#}"
    );
    assert_eq!(
        firewall["bypassed"][0]["rule"]["spec"], "update-tool",
        "{envelope:#}"
    );
    assert_eq!(
        firewall["bypassed"].as_array().map(Vec::len),
        Some(1),
        "{envelope:#}"
    );
    let other = results
        .iter()
        .find(|result| result["package"] == "other-tool")
        .unwrap();
    assert_eq!(other["action"], "upgraded", "{envelope:#}");
    assert!(other.get("security").is_none(), "{envelope:#}");
}

#[tokio::test]
async fn deploy_json_reports_the_version_a_bypass_rule_let_through() {
    let mock = registry_blocking("agent-tool", "suspicious", "lpm_ai_agent_control_surface").await;
    let project =
        TempProject::empty(r#"{"name":"root","private":true,"workspaces":["packages/*"]}"#);
    write_npm_firewall_global_config(&project, "enforce");
    project.write_file(
        "packages/app/package.json",
        r#"{"name":"app","version":"1.0.0","dependencies":{"agent-tool":"1.0.0"}}"#,
    );
    project.write_file("packages/app/index.js", "module.exports = 1;\n");
    write_signed_firewall_bypass(
        &project,
        &[stored_rule("agent-tool", serde_json::json!({}))],
    );
    let out = tempfile::tempdir().unwrap();
    let out_dir = out.path().join("deployed");

    let output = lpm_with_registry(&project, &mock.url())
        .args([
            "deploy",
            out_dir.to_str().unwrap(),
            "--filter",
            "app",
            "--json",
        ])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stderr),
        String::from_utf8_lossy(&output.stdout)
    );
    let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let firewall = &envelope["security"]["firewall"];
    assert_eq!(firewall["mode"], "enforce", "{envelope:#}");
    assert_eq!(
        firewall["bypassed"][0]["name"], "agent-tool",
        "{envelope:#}"
    );
    assert_eq!(
        firewall["bypassed"][0]["rule"]["spec"], "agent-tool",
        "{envelope:#}"
    );
}

/// Runs `lpm doctor --fix` on a project whose dependency isn't installed, so
/// its install fix installs a version a rule lets past a block.
async fn doctor_fix_through_a_bypass_rule(json: bool) -> std::process::Output {
    let mock = registry_blocking("agent-tool", "suspicious", "lpm_ai_agent_control_surface").await;
    let project = TempProject::empty(
        r#"{"name":"consumer","version":"1.0.0","dependencies":{"agent-tool":"1.0.0"}}"#,
    );
    write_npm_firewall_global_config(&project, "enforce");
    write_signed_firewall_bypass(
        &project,
        &[stored_rule("agent-tool", serde_json::json!({}))],
    );
    let mut command = lpm_with_registry(&project, &mock.url());
    if json {
        command.arg("--json");
    } else {
        command.args(["--color", "never"]);
    }
    command.args(["doctor", "--fix", "--yes"]).output().unwrap()
}

#[tokio::test]
async fn doctor_fix_json_reports_the_version_a_bypass_rule_let_through() {
    let output = doctor_fix_through_a_bypass_rule(true).await;

    let envelope: serde_json::Value =
        serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
            panic!(
                "{error}\nstdout: {}\nstderr: {}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            )
        });
    assert!(
        envelope["fixes_applied"]
            .as_array()
            .is_some_and(|fixes| fixes.iter().any(|fix| fix == "lpm install")),
        "{envelope:#}"
    );
    let firewall = &envelope["security"]["firewall"];
    assert_eq!(firewall["mode"], "enforce", "{envelope:#}");
    assert_eq!(
        firewall["bypassed"][0]["name"], "agent-tool",
        "{envelope:#}"
    );
}

#[tokio::test]
async fn doctor_fix_prints_the_version_a_bypass_rule_let_through() {
    let output = doctor_fix_through_a_bypass_rule(false).await;

    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        text.contains("! LPM Firewall allowed 1 blocked package because of your bypass rules:\n"),
        "{text}"
    );
    assert!(
        text.contains("    rule: agent-tool (every project)\n"),
        "{text}"
    );
}

#[tokio::test]
async fn migrate_json_reports_the_version_a_bypass_rule_let_through() {
    let mock = registry_blocking("agent-tool", "suspicious", "lpm_ai_agent_control_surface").await;
    let project = TempProject::empty(
        r#"{"name":"consumer","version":"1.0.0","dependencies":{"agent-tool":"1.0.0"}}"#,
    );
    project.write_file(
        "package-lock.json",
        &serde_json::json!({
            "name": "consumer",
            "version": "1.0.0",
            "lockfileVersion": 3,
            "requires": true,
            "packages": {
                "": { "name": "consumer", "version": "1.0.0", "dependencies": { "agent-tool": "1.0.0" } },
                "node_modules/agent-tool": {
                    "version": "1.0.0",
                    "resolved": "https://registry.npmjs.org/agent-tool/-/agent-tool-1.0.0.tgz",
                    "integrity": compute_integrity(&make_tarball("agent-tool", "1.0.0")),
                },
            },
        })
        .to_string(),
    );
    write_npm_firewall_global_config(&project, "enforce");
    write_signed_firewall_bypass(
        &project,
        &[stored_rule("agent-tool", serde_json::json!({}))],
    );

    let output = lpm_with_registry(&project, &mock.url())
        .args([
            "--json",
            "migrate",
            "--skip-verify",
            "--no-ci",
            "--no-npmrc",
        ])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stderr),
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(project.file_exists("node_modules/agent-tool/package.json"));
    let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let firewall = &envelope["security"]["firewall"];
    assert_eq!(firewall["mode"], "enforce", "{envelope:#}");
    assert_eq!(
        firewall["bypassed"][0]["name"], "agent-tool",
        "{envelope:#}"
    );
}

#[tokio::test]
async fn a_command_that_fails_after_its_install_still_reports_what_a_rule_let_through() {
    let mock = registry_blocking("agent-tool", "suspicious", "lpm_ai_agent_control_surface").await;
    let project = TempProject::empty(
        r#"{"name":"consumer","version":"1.0.0","scripts":{"test":"exit 1"},"dependencies":{"agent-tool":"1.0.0"}}"#,
    );
    project.write_file(
        "package-lock.json",
        &serde_json::json!({
            "name": "consumer",
            "version": "1.0.0",
            "lockfileVersion": 3,
            "requires": true,
            "packages": {
                "": { "name": "consumer", "version": "1.0.0", "dependencies": { "agent-tool": "1.0.0" } },
                "node_modules/agent-tool": {
                    "version": "1.0.0",
                    "resolved": "https://registry.npmjs.org/agent-tool/-/agent-tool-1.0.0.tgz",
                    "integrity": compute_integrity(&make_tarball("agent-tool", "1.0.0")),
                },
            },
        })
        .to_string(),
    );
    write_npm_firewall_global_config(&project, "enforce");
    write_signed_firewall_bypass(
        &project,
        &[stored_rule("agent-tool", serde_json::json!({}))],
    );

    let output = lpm_with_registry(&project, &mock.url())
        .args(["--json", "migrate", "--no-ci", "--no-npmrc"])
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(project.file_exists("node_modules/agent-tool/package.json"));
    let envelope: serde_json::Value =
        serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
            panic!(
                "{error}\nstdout: {}\nstderr: {}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            )
        });
    assert_eq!(envelope["success"], false, "{envelope:#}");
    let firewall = &envelope["security"]["firewall"];
    assert_eq!(firewall["mode"], "enforce", "{envelope:#}");
    assert_eq!(
        firewall["bypassed"][0]["name"], "agent-tool",
        "{envelope:#}"
    );
}

fn json_envelope(output: &std::process::Output) -> serde_json::Value {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "{error}\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    })
}

#[tokio::test]
async fn an_install_whose_later_verdict_request_fails_still_reports_what_a_rule_let_through() {
    let (_mock, output) = install_with_a_failing_verdict_request_in(
        std::time::Duration::ZERO,
        std::time::Duration::from_millis(1500),
        true,
    )
    .await;

    assert!(!output.status.success());
    let envelope = json_envelope(&output);
    assert_eq!(envelope["success"], false, "{envelope:#}");
    assert_eq!(
        envelope["security"]["firewall"]["bypassed"][0]["name"], "agent-tool",
        "{envelope:#}"
    );
}

#[tokio::test]
async fn an_install_whose_verdict_request_fails_first_reports_no_held_back_version() {
    let (mock, output) = install_with_a_failing_verdict_request_in(
        std::time::Duration::from_millis(1500),
        std::time::Duration::ZERO,
        true,
    )
    .await;

    assert!(!output.status.success());
    let envelope = json_envelope(&output);
    assert_eq!(envelope["success"], false, "{envelope:#}");
    assert!(
        envelope
            .to_string()
            .contains("npm firewall verdict preflight failed"),
        "{envelope:#}"
    );
    assert_eq!(verdict_requests_naming(&mock, "agent-tool").await, 1);
    assert_eq!(verdict_requests_naming(&mock, "unchecked-tool").await, 1);
    assert!(envelope.get("security").is_none(), "{envelope:#}");
}

#[tokio::test]
async fn a_blocked_install_lists_what_it_downloaded_in_the_block_alone() {
    let mock = MockRegistry::start().await;
    mock.with_package("agent-tool", "1.0.0", &make_tarball("agent-tool", "1.0.0"))
        .await;
    mount_block_verdict(
        &mock,
        "agent-tool",
        "suspicious",
        "lpm_ai_agent_control_surface",
    )
    .await;
    mock.with_package("evil-tool", "1.0.0", &make_tarball("evil-tool", "1.0.0"))
        .await;
    mount_block_verdicts_after(
        &mock,
        &["evil-tool"],
        "suspicious",
        "lpm_ai_agent_control_surface",
        std::time::Duration::from_millis(1500),
    )
    .await;
    let project = enforcing_project();
    write_signed_firewall_bypass(
        &project,
        &[stored_rule("agent-tool", serde_json::json!({}))],
    );

    let output = lpm_with_registry(&project, &mock.url())
        .env("LPM_EXPERIMENT_NPM_FIREWALL_CHUNK_SIZE", "1")
        .args([
            "--json",
            "install",
            "--no-skills",
            "agent-tool@1.0.0",
            "evil-tool@1.0.0",
        ])
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert_eq!(mock.tarball_request_count("agent-tool", "1.0.0").await, 1);
    let envelope = json_envelope(&output);
    assert_eq!(
        envelope["error_code"], "npm_firewall_blocked",
        "{envelope:#}"
    );
    assert_eq!(
        envelope["error"]["packages"][0]["name"], "evil-tool",
        "{envelope:#}"
    );
    assert_eq!(
        envelope["error"]["bypassed"][0]["name"], "agent-tool",
        "{envelope:#}"
    );
    assert!(envelope.get("security").is_none(), "{envelope:#}");
}

/// A registry where `helper-tool`, which a rule lifts, is answered at once
/// and `agent-tool` is blocked a moment later, so an install of both
/// downloads `helper-tool` before its check blocks.
async fn registry_blocking_after_a_lifted_download() -> MockRegistry {
    let mock = MockRegistry::start().await;
    mock.with_package(
        "helper-tool",
        "1.0.0",
        &make_tarball("helper-tool", "1.0.0"),
    )
    .await;
    mount_block_verdict(
        &mock,
        "helper-tool",
        "suspicious",
        "lpm_ai_agent_control_surface",
    )
    .await;
    mock.with_package("agent-tool", "1.0.0", &make_tarball("agent-tool", "1.0.0"))
        .await;
    mount_block_verdicts_after(
        &mock,
        &["agent-tool"],
        "suspicious",
        "lpm_ai_agent_control_surface",
        std::time::Duration::from_millis(1500),
    )
    .await;
    mock
}

#[tokio::test]
async fn doctor_lists_a_version_its_blocked_install_downloaded_once() {
    let mock = registry_blocking_after_a_lifted_download().await;
    let project = TempProject::empty(
        r#"{"name":"consumer","version":"1.0.0","dependencies":{"helper-tool":"1.0.0","agent-tool":"1.0.0"}}"#,
    );
    write_npm_firewall_global_config(&project, "enforce");
    write_signed_firewall_bypass(
        &project,
        &[stored_rule("helper-tool", serde_json::json!({}))],
    );

    let output = lpm_with_registry(&project, &mock.url())
        .env("LPM_EXPERIMENT_NPM_FIREWALL_CHUNK_SIZE", "1")
        .args(["--color", "never", "doctor", "--fix", "--yes"])
        .output()
        .unwrap();

    assert_eq!(mock.tarball_request_count("helper-tool", "1.0.0").await, 1);
    let printed = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        printed.contains("allowed helper-tool@1.0.0 by your bypass rule helper-tool"),
        "{printed}"
    );
    assert_eq!(printed.matches("helper-tool@1.0.0").count(), 1, "{printed}");
}

#[tokio::test]
async fn a_workspace_error_names_what_a_blocked_member_downloaded() {
    let mock = registry_blocking_after_a_lifted_download().await;
    let project =
        TempProject::empty(r#"{"name":"root","private":true,"workspaces":["packages/*"]}"#);
    project.write_file(
        "packages/blocked/package.json",
        r#"{"name":"blocked","version":"1.0.0","dependencies":{"helper-tool":"1.0.0","agent-tool":"1.0.0"}}"#,
    );
    // Filtering out the root and a lifecycle script here keep the members out
    // of a shared resolution, so each runs on its own, the blocked one
    // streaming its check, and the first error doesn't stop the other.
    project.write_file(
        "packages/broken/package.json",
        r#"{"name":"broken","version":"1.0.0","scripts":{"postinstall":"node -e 0"},"dependencies":{"missing-tool":"1.0.0"}}"#,
    );
    write_npm_firewall_global_config(&project, "enforce");
    write_signed_firewall_bypass(
        &project,
        &[stored_rule("helper-tool", serde_json::json!({}))],
    );

    let output = lpm_with_registry(&project, &mock.url())
        .env("LPM_EXPERIMENT_NPM_FIREWALL_CHUNK_SIZE", "1")
        .env("LPM_WORKSPACE_CONCURRENCY", "2")
        .args([
            "--json",
            "install",
            "--no-skills",
            "--filter",
            "blocked",
            "--filter",
            "broken",
        ])
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert_eq!(mock.tarball_request_count("helper-tool", "1.0.0").await, 1);
    let envelope = json_envelope(&output);
    assert_ne!(
        envelope["error_code"], "npm_firewall_blocked",
        "{envelope:#}"
    );
    assert_eq!(
        envelope["security"]["firewall"]["bypassed"][0]["name"], "helper-tool",
        "{envelope:#}"
    );
}

/// `lpm doctor --fix` in JSON and then in a terminal, over a project whose
/// install checks `agent-tool`, which a rule lifts, and `unchecked-tool`,
/// whose verdict request fails, each answered after its delay.
async fn doctor_with_a_failing_verdict_request(
    lifted_after: std::time::Duration,
    failure_after: std::time::Duration,
) -> (
    std::process::Output,
    [usize; 2],
    std::process::Output,
    [usize; 2],
) {
    let mock = MockRegistry::start().await;
    mock.with_package("agent-tool", "1.0.0", &make_tarball("agent-tool", "1.0.0"))
        .await;
    mount_block_verdicts_after(
        &mock,
        &["agent-tool"],
        "suspicious",
        "lpm_ai_agent_control_surface",
        lifted_after,
    )
    .await;
    mock.with_package(
        "unchecked-tool",
        "1.0.0",
        &make_tarball("unchecked-tool", "1.0.0"),
    )
    .await;
    Mock::given(method("POST"))
        .and(path(VERDICTS_PATH))
        .and(body_string_contains("\"name\":\"unchecked-tool\""))
        .respond_with(ResponseTemplate::new(400).set_delay(failure_after))
        .mount(mock.server())
        .await;
    let project = TempProject::empty(
        r#"{"name":"consumer","version":"1.0.0","dependencies":{"agent-tool":"1.0.0","unchecked-tool":"1.0.0"}}"#,
    );
    write_npm_firewall_global_config(&project, "enforce");
    write_signed_firewall_bypass(
        &project,
        &[stored_rule("agent-tool", serde_json::json!({}))],
    );
    let doctor = |json: bool| {
        let mut command = lpm_with_registry(&project, &mock.url());
        command.env("LPM_EXPERIMENT_NPM_FIREWALL_CHUNK_SIZE", "1");
        if json {
            command.arg("--json");
        } else {
            command.args(["--color", "never"]);
        }
        command.args(["doctor", "--fix", "--yes"]).output().unwrap()
    };
    let json = doctor(true);
    let json_requests = [
        verdict_requests_naming(&mock, "agent-tool").await,
        verdict_requests_naming(&mock, "unchecked-tool").await,
    ];
    let terminal = doctor(false);
    let terminal_requests = [
        verdict_requests_naming(&mock, "agent-tool").await - json_requests[0],
        verdict_requests_naming(&mock, "unchecked-tool").await - json_requests[1],
    ];
    (json, json_requests, terminal, terminal_requests)
}

#[tokio::test]
async fn a_wrapper_reports_what_a_rule_let_through_before_a_verdict_request_failed() {
    let (json, _, terminal, _) = doctor_with_a_failing_verdict_request(
        std::time::Duration::ZERO,
        std::time::Duration::from_millis(1500),
    )
    .await;

    let envelope: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
    assert_eq!(
        envelope["fixes_failed"][0]["action"], "lpm install",
        "{envelope:#}"
    );
    assert_eq!(
        envelope["security"]["firewall"]["bypassed"][0]["name"], "agent-tool",
        "{envelope:#}"
    );
    let stderr = String::from_utf8_lossy(&terminal.stderr);
    assert!(stderr.contains(AGENT_TOOL_ALLOWED), "{stderr}");
}

#[tokio::test]
async fn a_wrapper_reports_no_lifted_version_held_back_after_a_verdict_request_failed() {
    let (json, json_requests, terminal, terminal_requests) = doctor_with_a_failing_verdict_request(
        std::time::Duration::from_millis(1500),
        std::time::Duration::ZERO,
    )
    .await;

    let envelope: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
    assert_eq!(
        envelope["fixes_failed"][0]["action"], "lpm install",
        "{envelope:#}"
    );
    assert!(
        envelope["fixes_failed"][0]["error"]
            .as_str()
            .is_some_and(|error| error.contains("npm firewall verdict preflight failed")),
        "{envelope:#}"
    );
    assert_eq!(
        json_requests,
        [1, 1],
        "the JSON run asks about each version once"
    );
    assert!(envelope.get("security").is_none(), "{envelope:#}");
    let stderr = String::from_utf8_lossy(&terminal.stderr);
    assert!(
        stderr.contains("npm firewall verdict preflight failed"),
        "{stderr}"
    );
    assert_eq!(
        terminal_requests,
        [1, 1],
        "the terminal run asks about each version once"
    );
    assert!(!stderr.contains("LPM Firewall allowed"), "{stderr}");
}

/// A registry where `agent-tool`, which a rule lifts, resolves at once and
/// `missing-tool` is reported missing only after `delay`, so an install of
/// both is still resolving, or fails resolving, after `agent-tool` was
/// released to download.
async fn registry_failing_resolution_after_a_lifted_release(
    delay: std::time::Duration,
) -> MockRegistry {
    let mock = registry_blocking("agent-tool", "suspicious", "lpm_ai_agent_control_surface").await;
    for metadata_path in ["/missing-tool", "/api/registry/missing-tool"] {
        Mock::given(method("GET"))
            .and(path(metadata_path))
            .respond_with(ResponseTemplate::new(404).set_delay(delay))
            .mount(mock.server())
            .await;
    }
    mock
}

#[tokio::test]
async fn an_install_that_fails_after_releasing_a_lifted_version_still_reports_it() {
    let mock =
        registry_failing_resolution_after_a_lifted_release(std::time::Duration::from_millis(1500))
            .await;
    let project = enforcing_project();
    write_signed_firewall_bypass(
        &project,
        &[stored_rule("agent-tool", serde_json::json!({}))],
    );
    let install = |json: bool| {
        let mut command = lpm_with_registry(&project, &mock.url());
        command.env("LPM_EXPERIMENT_NPM_FIREWALL_CHUNK_SIZE", "1");
        if json {
            command.arg("--json");
        } else {
            command.args(["--color", "never"]);
        }
        command
            .args([
                "install",
                "--no-skills",
                "agent-tool@1.0.0",
                "missing-tool@1.0.0",
            ])
            .output()
            .unwrap()
    };

    let terminal = install(false);
    let json = install(true);

    let stderr = String::from_utf8_lossy(&terminal.stderr);
    assert!(!terminal.status.success(), "{stderr}");
    let notice = stderr.find(AGENT_TOOL_ALLOWED).expect(&stderr);
    let error = stderr.find("missing-tool").expect(&stderr);
    assert!(
        notice < error,
        "the notice must come before the error: {stderr}"
    );
    assert!(!json.status.success());
    let envelope: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
    assert_eq!(envelope["success"], false, "{envelope:#}");
    assert_eq!(
        envelope["security"]["firewall"]["bypassed"][0]["name"], "agent-tool",
        "{envelope:#}"
    );
}

#[tokio::test]
async fn a_wrapper_reports_a_lifted_version_its_failed_install_released() {
    let mock =
        registry_failing_resolution_after_a_lifted_release(std::time::Duration::from_millis(1500))
            .await;
    let project = TempProject::empty(
        r#"{"name":"consumer","version":"1.0.0","dependencies":{"agent-tool":"1.0.0","missing-tool":"1.0.0"}}"#,
    );
    write_npm_firewall_global_config(&project, "enforce");
    write_signed_firewall_bypass(
        &project,
        &[stored_rule("agent-tool", serde_json::json!({}))],
    );

    let output = lpm_with_registry(&project, &mock.url())
        .env("LPM_EXPERIMENT_NPM_FIREWALL_CHUNK_SIZE", "1")
        .args(["--json", "doctor", "--fix", "--yes"])
        .output()
        .unwrap();

    let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        envelope["fixes_failed"][0]["action"], "lpm install",
        "{envelope:#}"
    );
    assert_eq!(
        envelope["security"]["firewall"]["bypassed"][0]["name"], "agent-tool",
        "{envelope:#}"
    );
}

#[tokio::test]
async fn workspace_migrate_json_reports_the_version_a_bypass_rule_let_through() {
    let mock = registry_blocking("agent-tool", "suspicious", "lpm_ai_agent_control_surface").await;
    mock.with_package("lib-tool", "1.0.0", &make_tarball("lib-tool", "1.0.0"))
        .await;
    mount_block_verdict(
        &mock,
        "lib-tool",
        "suspicious",
        "lpm_ai_agent_control_surface",
    )
    .await;
    let project =
        TempProject::empty(r#"{"name":"root","private":true,"workspaces":["packages/*"]}"#);
    project.write_file(
        "packages/app/package.json",
        r#"{"name":"app","version":"1.0.0","dependencies":{"agent-tool":"1.0.0"}}"#,
    );
    project.write_file(
        "packages/lib/package.json",
        r#"{"name":"lib","version":"1.0.0","dependencies":{"lib-tool":"1.0.0"}}"#,
    );
    project.write_file(
        "package-lock.json",
        &serde_json::json!({
            "name": "root",
            "lockfileVersion": 3,
            "requires": true,
            "packages": {
                "": { "name": "root", "workspaces": ["packages/*"] },
                "node_modules/app": { "resolved": "packages/app", "link": true },
                "packages/app": { "name": "app", "version": "1.0.0", "dependencies": { "agent-tool": "1.0.0" } },
                "node_modules/lib": { "resolved": "packages/lib", "link": true },
                "packages/lib": { "name": "lib", "version": "1.0.0", "dependencies": { "lib-tool": "1.0.0" } },
                "node_modules/lib-tool": {
                    "version": "1.0.0",
                    "resolved": "https://registry.npmjs.org/lib-tool/-/lib-tool-1.0.0.tgz",
                    "integrity": compute_integrity(&make_tarball("lib-tool", "1.0.0")),
                },
                "node_modules/agent-tool": {
                    "version": "1.0.0",
                    "resolved": "https://registry.npmjs.org/agent-tool/-/agent-tool-1.0.0.tgz",
                    "integrity": compute_integrity(&make_tarball("agent-tool", "1.0.0")),
                },
            },
        })
        .to_string(),
    );
    write_npm_firewall_global_config(&project, "enforce");
    write_signed_firewall_bypass(
        &project,
        &[
            stored_rule("agent-tool", serde_json::json!({})),
            stored_rule("lib-tool", serde_json::json!({ "id": "fwb_lib" })),
        ],
    );

    let output = lpm_with_registry(&project, &mock.url())
        .args([
            "--json",
            "migrate",
            "--skip-verify",
            "--no-ci",
            "--no-npmrc",
        ])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stderr),
        String::from_utf8_lossy(&output.stdout)
    );
    let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let firewall = &envelope["security"]["firewall"];
    assert_eq!(firewall["mode"], "enforce", "{envelope:#}");
    let mut names: Vec<&str> = firewall["bypassed"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|entry| entry["name"].as_str())
        .collect();
    names.sort_unstable();
    assert_eq!(names, ["agent-tool", "lib-tool"], "{envelope:#}");
}

#[tokio::test]
async fn tidy_fix_json_reports_the_version_a_bypass_rule_let_through() {
    let mock = registry_blocking("agent-tool", "suspicious", "lpm_ai_agent_control_surface").await;
    let project = TempProject::empty(
        r#"{"name":"consumer","version":"1.0.0","dependencies":{"agent-tool":"1.0.0","unused-dep":"1.0.0"}}"#,
    );
    project.write_file("src/index.js", r#"import "agent-tool";"#);
    write_npm_firewall_global_config(&project, "enforce");
    write_signed_firewall_bypass(
        &project,
        &[stored_rule("agent-tool", serde_json::json!({}))],
    );

    let output = lpm_with_registry(&project, &mock.url())
        .args(["--json", "tidy", "--fix"])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stderr),
        String::from_utf8_lossy(&output.stdout)
    );
    let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(envelope["counts"]["removed"], 1, "{envelope:#}");
    let firewall = &envelope["security"]["firewall"];
    assert_eq!(firewall["mode"], "enforce", "{envelope:#}");
    assert_eq!(
        firewall["bypassed"][0]["name"], "agent-tool",
        "{envelope:#}"
    );
}

#[tokio::test]
async fn dev_auto_install_prints_the_version_a_bypass_rule_let_through() {
    let mock = registry_blocking("agent-tool", "suspicious", "lpm_ai_agent_control_surface").await;
    let project = TempProject::empty(
        r#"{"name":"consumer","version":"1.0.0","scripts":{"dev":"node index.js"},"dependencies":{"agent-tool":"1.0.0"}}"#,
    );
    project.write_file("index.js", "console.log('dev-ran');\n");
    write_npm_firewall_global_config(&project, "enforce");
    write_signed_firewall_bypass(
        &project,
        &[stored_rule("agent-tool", serde_json::json!({}))],
    );

    let output = lpm_with_registry(&project, &mock.url())
        .args(["--color", "never", "dev", "--no-open", "--no-dashboard"])
        .output()
        .unwrap();

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{stderr}");
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("dev-ran"),
        "{stderr}"
    );
    assert!(
        stderr.contains("! LPM Firewall allowed 1 blocked package because of your bypass rules:\n"),
        "{stderr}"
    );
    assert!(
        stderr.contains("    rule: agent-tool (every project)\n"),
        "{stderr}"
    );
}

#[tokio::test]
async fn dlx_with_stdout_reserved_prints_the_version_a_bypass_rule_let_through_on_stderr() {
    let mock = MockRegistry::start().await;
    mock.with_manifest_package(
        serde_json::json!({"name":"dlx-bypass-tool","version":"1.0.0","bin":{"dlx-bypass-tool":"tool.js"}}),
        &[("tool.js", b"#!/usr/bin/env node\nconsole.log(JSON.stringify({child:true}));")],
    )
    .await;
    mount_block_verdict(
        &mock,
        "dlx-bypass-tool",
        "suspicious",
        "lpm_ai_agent_control_surface",
    )
    .await;
    let project = enforcing_project();
    write_signed_firewall_bypass(
        &project,
        &[stored_rule("dlx-bypass-tool", serde_json::json!({}))],
    );

    let output = lpm_with_registry(&project, &mock.url())
        .args(["--json", "dlx", "dlx-bypass-tool@1.0.0"])
        .output()
        .unwrap();

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{stderr}");
    let child: serde_json::Value = serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|error| panic!("{error}: {}", String::from_utf8_lossy(&output.stdout)));
    assert_eq!(child, serde_json::json!({ "child": true }));
    assert!(
        stderr.contains("LPM Firewall allowed 1 blocked package because of your bypass rules:"),
        "{stderr}"
    );
    assert!(
        stderr.contains("rule: dlx-bypass-tool (every project)"),
        "{stderr}"
    );
}

#[tokio::test]
async fn upgrade_json_reports_the_version_a_bypass_rule_let_through() {
    let project = TempProject::empty(
        r#"{"name":"upgrade-bypass","version":"1.0.0","dependencies":{"agent-tool":"^1.0.0"}}"#,
    );
    write_npm_firewall_global_config(&project, "enforce");
    project.write_file(
        "lpm.lock",
        "[metadata]\nlockfile-version = 2\nresolved-with = \"greedy-fusion\"\n\n\
         [[packages]]\nname = \"agent-tool\"\nversion = \"1.0.0\"\n\
         source = \"registry+https://registry.npmjs.org\"\n",
    );
    let mock = MockRegistry::start().await;
    mock.with_full_package_metadata(
        "agent-tool",
        "1.1.0",
        &[
            (
                "1.0.0",
                serde_json::json!({}),
                Some(make_tarball("agent-tool", "1.0.0")),
            ),
            (
                "1.1.0",
                serde_json::json!({}),
                Some(make_tarball("agent-tool", "1.1.0")),
            ),
        ],
    )
    .await;
    Mock::given(method("POST"))
        .and(path(VERDICTS_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "requestId": "upgrade-bypass",
            "policyMode": "enforce",
            "summary": { "total": 1, "allow": 0, "warn": 0, "block": 1, "unknown": 0, "matched": 1 },
            "decisions": [{
                "decisionId": "upgrade-bypass:agent-tool",
                "name": "agent-tool",
                "version": "1.1.0",
                "action": "block",
                "verdict": "suspicious",
                "reason": "client policy maps lpm_ai_agent_control_surface to block",
                "matchSource": "package",
                "policyMode": "enforce",
                "enqueueScan": false,
                "policy": { "group": "lpm_ai_agent_control_surface" }
            }]
        })))
        .mount(mock.server())
        .await;
    write_signed_firewall_bypass(
        &project,
        &[stored_rule("agent-tool", serde_json::json!({}))],
    );

    let output = lpm_with_registry(&project, &mock.url())
        .args(["upgrade", "-y", "--json"])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let firewall = &envelope["security"]["firewall"];
    assert_eq!(firewall["mode"], "enforce", "{envelope:#}");
    assert_eq!(
        firewall["bypassed"][0]["name"], "agent-tool",
        "{envelope:#}"
    );
    assert_eq!(firewall["bypassed"][0]["version"], "1.1.0", "{envelope:#}");
}

#[tokio::test]
async fn lone_global_update_prints_what_a_bypass_rule_let_through_once() {
    let mock = MockRegistry::start().await;
    mount_blocked_global_update(&mock, "update-tool").await;
    let project = enforcing_project();
    installed_globally(&project, &["update-tool"]);
    write_signed_firewall_bypass(
        &project,
        &[stored_rule("update-tool", serde_json::json!({}))],
    );

    let output = lpm_with_registry(&project, &mock.url())
        .args(["--color", "never", "global", "update"])
        .output()
        .unwrap();

    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.status.success(), "{text}");
    assert_eq!(
        text.matches("LPM Firewall allowed 1 blocked package because of your bypass rules")
            .count(),
        1,
        "{text}"
    );
}

/// Runs `command` until the registry has served the `name@version` tarball,
/// then sends it Ctrl-C and returns what it printed.
#[cfg(unix)]
async fn interrupt_after_download(
    mut command: std::process::Command,
    mock: &MockRegistry,
    name: &str,
    version: &str,
) -> std::process::Output {
    let mut child = command.spawn().unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
    while mock.tarball_request_count(name, version).await == 0 {
        if std::time::Instant::now() >= deadline || child.try_wait().unwrap().is_some() {
            let _ = child.kill();
            let output = child.wait_with_output().unwrap();
            panic!(
                "the command never downloaded {name}@{version}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert!(
        std::process::Command::new("kill")
            .args(["-INT", &child.id().to_string()])
            .status()
            .unwrap()
            .success()
    );
    child.wait_with_output().unwrap()
}

/// Checks an interrupted install's output for the `agent-tool` notice: in
/// JSON its error's `security`, in a terminal a notice before the error.
#[cfg(unix)]
fn assert_interrupted_after_reporting_agent_tool(output: &std::process::Output, json: bool) {
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    if json {
        let envelope = json_envelope(output);
        assert!(
            envelope.to_string().contains("Install interrupted"),
            "{envelope:#}"
        );
        assert_eq!(
            envelope["security"]["firewall"]["bypassed"][0]["name"], "agent-tool",
            "{envelope:#}"
        );
    } else {
        let notice = stderr.find(AGENT_TOOL_ALLOWED).expect(&stderr);
        let error = stderr.find("Install interrupted").expect(&stderr);
        assert!(
            notice < error,
            "the notice must come before the error: {stderr}"
        );
        assert!(
            stderr[notice..error].contains("› agent-tool@1.0.0 - "),
            "the notice names the version before the error: {stderr}"
        );
        assert_eq!(stderr.matches(AGENT_TOOL_ALLOWED).count(), 1, "{stderr}");
    }
}

#[cfg(unix)]
#[tokio::test]
async fn an_interrupted_install_reports_a_lifted_version_it_released() {
    for json in [false, true] {
        let mock =
            registry_failing_resolution_after_a_lifted_release(std::time::Duration::from_secs(30))
                .await;
        let project = enforcing_project();
        write_signed_firewall_bypass(
            &project,
            &[stored_rule("agent-tool", serde_json::json!({}))],
        );
        let mut command = lpm_spawnable_with_registry(&project, &mock.url());
        command.env("LPM_EXPERIMENT_NPM_FIREWALL_CHUNK_SIZE", "1");
        if json {
            command.arg("--json");
        }
        command.args([
            "--color",
            "never",
            "install",
            "--no-skills",
            "agent-tool@1.0.0",
            "missing-tool@1.0.0",
        ]);

        let output = interrupt_after_download(command, &mock, "agent-tool", "1.0.0").await;

        assert_interrupted_after_reporting_agent_tool(&output, json);
    }
}

#[cfg(unix)]
#[tokio::test]
async fn an_interrupted_workspace_install_reports_what_a_member_released() {
    for json in [false, true] {
        let mock =
            registry_failing_resolution_after_a_lifted_release(std::time::Duration::from_secs(30))
                .await;
        let project =
            TempProject::empty(r#"{"name":"root","private":true,"workspaces":["packages/*"]}"#);
        project.write_file(
            "packages/app/package.json",
            r#"{"name":"app","version":"1.0.0","dependencies":{"agent-tool":"1.0.0","missing-tool":"1.0.0"}}"#,
        );
        write_npm_firewall_global_config(&project, "enforce");
        write_signed_firewall_bypass(
            &project,
            &[stored_rule("agent-tool", serde_json::json!({}))],
        );
        let mut command = lpm_spawnable_with_registry(&project, &mock.url());
        command.env("LPM_EXPERIMENT_NPM_FIREWALL_CHUNK_SIZE", "1");
        if json {
            command.arg("--json");
        }
        command.args([
            "--color",
            "never",
            "install",
            "--no-skills",
            "--filter",
            "app",
        ]);

        let output = interrupt_after_download(command, &mock, "agent-tool", "1.0.0").await;

        assert_interrupted_after_reporting_agent_tool(&output, json);
    }
}
