mod support;

use lpm_runner::dlx::deterministic_hash;
use std::net::{TcpListener, TcpStream};
use std::path::Path;
#[cfg(any(unix, windows))]
use std::process::{Child, Command, Stdio};
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

#[cfg(all(unix, not(target_os = "linux")))]
fn lsof_available() -> bool {
    Command::new("lsof").arg("-v").output().is_ok()
}

#[cfg(any(unix, windows))]
fn node_available() -> bool {
    Command::new("node").arg("--version").output().is_ok()
}

#[cfg(any(target_os = "linux", windows))]
fn ports_discovery_available() -> bool {
    true
}

#[cfg(all(unix, not(target_os = "linux")))]
fn ports_discovery_available() -> bool {
    lsof_available()
}

#[cfg(not(any(unix, windows)))]
fn ports_discovery_available() -> bool {
    false
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
fn ports_list_human_renders_table_and_slim_completion() {
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
        .args(["ports", "list"])
        .output()
        .expect("failed to run lpm ports list");

    assert!(
        output.status.success(),
        "lpm ports list failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Service") && stdout.contains("Port") && stdout.contains("Status"),
        "ports list must render a table header, got:\n{stdout}"
    );
    assert!(
        stdout.contains("web") && stdout.contains("api"),
        "ports list must render service rows, got:\n{stdout}"
    );
    assert!(
        stdout.contains("● ready") && stdout.contains("● listening"),
        "ports list must render slim status dots for ready and listening services, got:\n{stdout}"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("✓ 2 declared service ports"),
        "ports list must report a slim service-port count, got:\n{stderr}"
    );
    assert!(
        !stderr.contains('●') && !stderr.contains('│'),
        "ports list status output must not use cliclack gutter output, got:\n{stderr}"
    );
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
fn ports_kill_human_reports_free_port_with_slim_completion() {
    let project = TempProject::empty(r#"{"name":"ports-test","version":"1.0.0"}"#);
    let free_port = reserve_then_release_port();

    let output = lpm(&project)
        .args(["ports", "kill", &free_port.to_string()])
        .output()
        .expect("failed to run lpm ports kill");

    assert!(
        output.status.success(),
        "lpm ports kill failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(&format!("✓ Port {free_port} is not in use")),
        "ports kill must report already-free ports with slim UI, got:\n{stderr}"
    );
    assert!(
        !stderr.contains('●') && !stderr.contains('│'),
        "ports kill output must not use cliclack gutter output, got:\n{stderr}"
    );
}

#[test]
fn ports_all_json_includes_visible_listening_processes() {
    if !ports_discovery_available() {
        return;
    }

    let project = TempProject::empty(r#"{"name":"ports-test","version":"1.0.0"}"#);
    let (busy_port, _busy_listener) = bind_ephemeral_port();

    let output = lpm(&project)
        .args(["ports", "all", "--json"])
        .output()
        .expect("failed to run lpm ports all --json");

    assert!(
        output.status.success(),
        "lpm ports all --json failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    assert_eq!(String::from_utf8_lossy(&output.stderr), "");

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let envelope: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("ports all --json must be valid JSON: {e}\n---\n{stdout}"));

    assert_eq!(envelope["success"], serde_json::json!(true));
    assert_eq!(envelope["scope"], serde_json::json!("all"));
    let ports = envelope["ports"]
        .as_array()
        .expect("ports all must return an array");
    assert!(
        ports.iter().any(|row| row["port"] == busy_port),
        "ports all must include the listener opened by this test, got:\n{stdout}"
    );
}

#[test]
fn ports_all_json_accepts_all_flag_alias() {
    let project = TempProject::empty(r#"{"name":"ports-test","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["ports", "--all", "--json"])
        .output()
        .expect("failed to run lpm ports --all --json");

    assert!(
        output.status.success(),
        "lpm ports --all --json failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    assert_eq!(String::from_utf8_lossy(&output.stderr), "");

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let envelope: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("ports --all --json must be valid JSON: {e}\n---\n{stdout}"));

    assert_eq!(envelope["success"], serde_json::json!(true));
    assert_eq!(envelope["scope"], serde_json::json!("all"));
    assert!(envelope["ports"].is_array());
}

#[cfg(unix)]
#[test]
fn ports_default_json_falls_back_to_project_listeners_without_services() {
    if !ports_discovery_available() || !node_available() {
        return;
    }

    let project = TempProject::empty(r#"{"name":"ports-test","version":"1.0.0"}"#);
    project.write_file(
        "listener.js",
        r#"
const fs = require('fs');
const net = require('net');

const server = net.createServer((socket) => socket.end());
server.listen(0, '127.0.0.1', () => {
  fs.writeFileSync('listener-port.txt', String(server.address().port));
});
process.on('SIGTERM', () => server.close(() => process.exit(0)));
setInterval(() => {}, 1000);
"#,
    );
    let mut child = Command::new("node")
        .arg("listener.js")
        .current_dir(project.path())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn project listener");
    let busy_port = wait_for_listener_port(&project, &mut child);

    let output = lpm(&project)
        .args(["ports", "--json"])
        .output()
        .expect("failed to run lpm ports --json");
    let _ = child.kill();
    let _ = child.wait();

    assert!(
        output.status.success(),
        "lpm ports --json fallback failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let envelope: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("ports fallback --json must be valid JSON: {e}\n---\n{stdout}"));

    assert_eq!(envelope["success"], serde_json::json!(true));
    assert_eq!(envelope["scope"], serde_json::json!("project"));
    let ports = envelope["ports"]
        .as_array()
        .expect("ports fallback must return an array");
    assert!(
        ports.iter().any(|row| row["port"] == busy_port),
        "project fallback must include the listener rooted in the project cwd, got:\n{stdout}"
    );
}

#[test]
fn ports_list_json_reports_host_only_persisted_assignments() {
    let project = TempProject::empty(r#"{"name":"ports-test","version":"1.0.0"}"#);
    project.write_file(
        "lpm.json",
        r#"{
            "services": {
                "web": {
                    "command": "node server.js",
                    "host": "web.localhost"
                }
            }
        }"#,
    );
    let canonical_project_dir = project
        .path()
        .canonicalize()
        .expect("project path must canonicalize");
    let assigned_port = reserve_then_release_port();
    let current_key = project_key(&canonical_project_dir);
    let ports_toml = project.home().join(".lpm").join("ports.toml");
    std::fs::create_dir_all(
        ports_toml
            .parent()
            .expect("ports.toml parent directory must exist"),
    )
    .expect("failed to create .lpm directory");
    std::fs::write(
        &ports_toml,
        format!("[{current_key}]\nweb = {assigned_port}\n"),
    )
    .expect("failed to seed ports.toml");

    let output = lpm(&project)
        .current_dir(&canonical_project_dir)
        .args(["ports", "list", "--json"])
        .output()
        .expect("failed to run lpm ports list --json");

    assert!(
        output.status.success(),
        "lpm ports list --json failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    assert_eq!(String::from_utf8_lossy(&output.stderr), "");

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let envelope: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("ports list --json must be valid JSON: {e}\n---\n{stdout}"));

    assert_eq!(envelope["success"], serde_json::json!(true));
    assert_eq!(
        envelope["ports"],
        serde_json::json!([{
            "service": "web",
            "port": assigned_port,
            "status": "free"
        }])
    );
}

#[test]
fn ports_inspect_json_accepts_bare_port_argument() {
    if !ports_discovery_available() {
        return;
    }

    let project = TempProject::empty(r#"{"name":"ports-test","version":"1.0.0"}"#);
    let (busy_port, _busy_listener) = bind_ephemeral_port();

    let output = lpm(&project)
        .args(["ports", &busy_port.to_string(), "--json"])
        .output()
        .expect("failed to run lpm ports <port> --json");

    assert!(
        output.status.success(),
        "lpm ports <port> --json failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let envelope: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("ports inspect --json must be valid JSON: {e}\n---\n{stdout}"));

    assert_eq!(envelope["success"], serde_json::json!(true));
    assert_eq!(envelope["port"], serde_json::json!(busy_port));
    assert_eq!(envelope["status"], serde_json::json!("listening"));
    assert!(
        envelope["listeners"]
            .as_array()
            .is_some_and(|listeners| !listeners.is_empty()),
        "ports inspect must report at least one listener, got:\n{stdout}"
    );
}

#[test]
fn ports_inspect_json_accepts_explicit_action() {
    if !ports_discovery_available() {
        return;
    }

    let project = TempProject::empty(r#"{"name":"ports-test","version":"1.0.0"}"#);
    let (busy_port, _busy_listener) = bind_ephemeral_port();

    let output = lpm(&project)
        .args(["ports", "inspect", &busy_port.to_string(), "--json"])
        .output()
        .expect("failed to run lpm ports inspect <port> --json");

    assert!(
        output.status.success(),
        "lpm ports inspect <port> --json failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    assert_eq!(String::from_utf8_lossy(&output.stderr), "");

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let envelope: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("ports inspect --json must be valid JSON: {e}\n---\n{stdout}"));

    assert_eq!(envelope["success"], serde_json::json!(true));
    assert_eq!(envelope["port"], serde_json::json!(busy_port));
    assert_eq!(envelope["status"], serde_json::json!("listening"));
}

#[cfg(any(unix, windows))]
fn wait_for_listener_port(project: &TempProject, child: &mut Child) -> u16 {
    let path = project.path().join("listener-port.txt");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while std::time::Instant::now() < deadline {
        if let Some(status) = child.try_wait().expect("poll project listener") {
            panic!("project listener exited before writing port file: {status}");
        }
        if let Ok(content) = std::fs::read_to_string(&path)
            && let Ok(port) = content.trim().parse::<u16>()
        {
            return port;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    let _ = child.kill();
    panic!("project listener did not write {}", path.display());
}

#[cfg(any(unix, windows))]
fn wait_for_child_exit(child: &mut Child) -> bool {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while std::time::Instant::now() < deadline {
        if child.try_wait().expect("poll listener process").is_some() {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    false
}

#[test]
fn ports_kill_range_json_with_yes_reports_empty_free_range() {
    let project = TempProject::empty(r#"{"name":"ports-test","version":"1.0.0"}"#);
    let free_port = reserve_then_release_port();
    let range = format!("{free_port}-{free_port}");

    let output = lpm(&project)
        .args(["ports", "kill", &range, "--yes", "--json"])
        .output()
        .expect("failed to run lpm ports kill <range> --yes --json");

    assert!(
        output.status.success(),
        "lpm ports kill <range> --yes --json failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let envelope: serde_json::Value = serde_json::from_str(&stdout).unwrap_or_else(|e| {
        panic!("ports range kill --json must be valid JSON: {e}\n---\n{stdout}")
    });

    assert_eq!(envelope["success"], serde_json::json!(true));
    assert_eq!(envelope["range"]["start"], serde_json::json!(free_port));
    assert_eq!(envelope["range"]["end"], serde_json::json!(free_port));
    assert_eq!(envelope["killed"], serde_json::json!([]));
}

#[test]
fn ports_kill_range_json_without_yes_requires_confirmation_before_killing() {
    if !ports_discovery_available() {
        return;
    }

    let project = TempProject::empty(r#"{"name":"ports-test","version":"1.0.0"}"#);
    let (busy_port, _busy_listener) = bind_ephemeral_port();
    let range = format!("{busy_port}-{busy_port}");

    let output = lpm(&project)
        .args(["ports", "kill", &range, "--json"])
        .output()
        .expect("failed to run lpm ports kill <range> --json");

    assert!(
        !output.status.success(),
        "range kill without --yes should fail before killing:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("pass --yes to confirm"),
        "got:\n{combined}"
    );
    assert!(
        TcpStream::connect(("127.0.0.1", busy_port)).is_ok(),
        "listener on {busy_port} should still be alive after confirmation failure"
    );
}

#[cfg(any(unix, windows))]
#[test]
fn ports_kill_range_json_with_yes_terminates_live_listener_process() {
    if !ports_discovery_available() || !node_available() {
        return;
    }

    let project = TempProject::empty(r#"{"name":"ports-test","version":"1.0.0"}"#);
    project.write_file(
        "listener.js",
        r#"
const fs = require('fs');
const net = require('net');

const server = net.createServer((socket) => socket.end());
server.listen(0, '127.0.0.1', () => {
  fs.writeFileSync('listener-port.txt', String(server.address().port));
});
process.on('SIGTERM', () => server.close(() => process.exit(0)));
setInterval(() => {}, 1000);
"#,
    );
    let mut child = Command::new("node")
        .arg("listener.js")
        .current_dir(project.path())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn range-kill listener");
    let child_pid = child.id();
    let busy_port = wait_for_listener_port(&project, &mut child);
    let range = format!("{busy_port}-{busy_port}");

    let output = lpm(&project)
        .args(["ports", "kill", &range, "--yes", "--json"])
        .output()
        .expect("failed to run lpm ports kill <range> --yes --json");
    let child_exited = wait_for_child_exit(&mut child);
    if !child_exited {
        let _ = child.kill();
        let _ = child.wait();
    }

    assert!(
        output.status.success(),
        "lpm ports kill live range failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    assert!(
        child_exited,
        "range kill should terminate the listener process with PID {child_pid}"
    );

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let envelope: serde_json::Value = serde_json::from_str(&stdout).unwrap_or_else(|e| {
        panic!("ports live range kill --json must be valid JSON: {e}\n---\n{stdout}")
    });

    assert_eq!(envelope["success"], serde_json::json!(true));
    assert_eq!(envelope["range"]["start"], serde_json::json!(busy_port));
    assert_eq!(envelope["range"]["end"], serde_json::json!(busy_port));
    let killed = envelope["killed"]
        .as_array()
        .expect("live range kill must return a killed array");
    assert!(
        killed.iter().any(|row| {
            row["pid"] == serde_json::json!(child_pid)
                && row["ports"]
                    .as_array()
                    .is_some_and(|ports| ports.contains(&serde_json::json!(busy_port)))
        }),
        "live range kill must report the child PID and port, got:\n{stdout}"
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
