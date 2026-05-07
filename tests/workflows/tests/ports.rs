mod support;

use lpm_runner::dlx::deterministic_hash;
use std::net::TcpListener;
use std::path::Path;
use support::{TempProject, lpm};

fn bind_ephemeral_port() -> (u16, TcpListener) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("failed to bind an ephemeral test port");
    let port = listener
        .local_addr()
        .expect("listener must expose its local address")
        .port();
    (port, listener)
}

fn reserve_then_release_port() -> u16 {
    let (port, listener) = bind_ephemeral_port();
    drop(listener);
    port
}

fn project_key(project_dir: &Path) -> String {
    format!(
        "project_{}",
        deterministic_hash(&project_dir.to_string_lossy())
    )
}

#[test]
fn ports_list_json_reports_free_and_in_use_services() {
    let project = TempProject::empty(r#"{"name":"ports-test","version":"1.0.0"}"#);
    let (busy_port, _busy_listener) = bind_ephemeral_port();
    let free_port = reserve_then_release_port();
    project.write_file(
        "lpm.json",
        &format!(
            "{{\n  \"services\": {{\n    \"web\": {{ \"command\": \"node web.js\", \"port\": {busy_port} }},\n    \"api\": {{ \"command\": \"node api.js\", \"port\": {free_port} }}\n  }}\n}}\n"
        ),
    );

    let output = lpm(&project)
        .args(["ports", "list", "--json"])
        .output()
        .expect("failed to run lpm ports list --json");

    assert!(
        output.status.success(),
        "lpm ports list --json failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let mut envelope: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("ports list --json must be valid JSON: {e}\n---\n{stdout}"));

    assert_eq!(envelope["success"], serde_json::json!(true));

    let ports = envelope["ports"]
        .as_array_mut()
        .expect("ports must be an array");
    ports.sort_by(|left, right| left["service"].as_str().cmp(&right["service"].as_str()));

    assert_eq!(ports.len(), 2);
    assert_eq!(
        ports[0],
        serde_json::json!({
            "service": "api",
            "port": free_port,
            "status": "free"
        })
    );
    assert_eq!(
        ports[1],
        serde_json::json!({
            "service": "web",
            "port": busy_port,
            "status": "in_use"
        })
    );

    insta::assert_json_snapshot!("ports_list_json_envelope_mixed_statuses", envelope, {
        ".ports[].port" => "[PORT]",
    });
}

#[test]
fn ports_kill_json_reports_already_free_for_unused_port() {
    let project = TempProject::empty(r#"{"name":"ports-test","version":"1.0.0"}"#);
    let free_port = reserve_then_release_port();

    let output = lpm(&project)
        .args(["ports", "kill", &free_port.to_string(), "--json"])
        .output()
        .expect("failed to run lpm ports kill --json");

    assert!(
        output.status.success(),
        "lpm ports kill --json failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let envelope: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("ports kill --json must be valid JSON: {e}\n---\n{stdout}"));

    assert_eq!(
        envelope,
        serde_json::json!({
            "success": true,
            "port": free_port,
            "status": "already_free"
        })
    );
}

#[test]
fn ports_reset_json_clears_only_current_project_overrides() {
    let project = TempProject::empty(r#"{"name":"ports-test","version":"1.0.0"}"#);
    let canonical_project_dir = project
        .path()
        .canonicalize()
        .expect("project path must canonicalize");
    let current_key = project_key(&canonical_project_dir);
    let other_key = "project_other_fixture";
    let ports_toml = project.home().join(".lpm").join("ports.toml");
    std::fs::create_dir_all(
        ports_toml
            .parent()
            .expect("ports.toml parent directory must exist"),
    )
    .expect("failed to create .lpm directory");
    std::fs::write(
        &ports_toml,
        format!("[{current_key}]\nweb = 3100\n\n[{other_key}]\napi = 4100\n"),
    )
    .expect("failed to seed ports.toml");

    let output = lpm(&project)
        .env("LPM_HOME", project.home().join(".lpm"))
        .current_dir(&canonical_project_dir)
        .args(["ports", "reset", "--json"])
        .output()
        .expect("failed to run lpm ports reset --json");

    assert!(
        output.status.success(),
        "lpm ports reset --json failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let envelope: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("ports reset --json must be valid JSON: {e}\n---\n{stdout}"));

    assert_eq!(
        envelope,
        serde_json::json!({
            "success": true,
            "reset": true
        })
    );

    let persisted = std::fs::read_to_string(&ports_toml).expect("failed to read ports.toml");
    assert!(
        !persisted.contains(&current_key),
        "ports reset must remove only the current project's override entry, got:\n{persisted}"
    );
    assert!(
        persisted.contains(other_key) && persisted.contains("api = 4100"),
        "ports reset must preserve unrelated project overrides, got:\n{persisted}"
    );
}
