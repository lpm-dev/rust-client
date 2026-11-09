//! Workflow tests for `lpm mcp setup / remove / status / serve`.
//!
//! MCP setup writes server entries into existing well-known editor config
//! files (Claude Code: `~/.claude.json`, Cursor: `~/.cursor/mcp.json`,
//! etc.). Tests run under an isolated HOME so they don't touch the
//! developer's real editor config. `lpm mcp serve` is driven over its stdio
//! as an editor drives it, with the mock registry as the hosted MCP server.

mod support;

use serde_json::{Value, json};
use std::io::{BufRead, BufReader, Write};
use std::sync::mpsc;
use std::time::Duration;
use support::auth_state::{SessionSeed, seed_sessions};
use support::mock_registry::{MockRegistry, make_tarball};
use support::{TempProject, lpm, lpm_spawnable_with_registry};
use wiremock::matchers::{any, body_partial_json, header, method, path};
use wiremock::{Mock, Request, ResponseTemplate};

#[test]
fn mcp_invalid_syntax_reports_usage_errors() {
    let project = TempProject::empty(r#"{"name":"mcp-usage"}"#);
    for args in [
        vec!["mcp", "remove"],
        vec!["mcp", "status", "unexpected"],
        vec!["mcp", "invalid"],
        vec!["mcp", "serve", "unexpected"],
    ] {
        for json in [false, true] {
            let mut command = lpm(&project);
            command.args(&args);
            if json {
                command.arg("--json");
            }
            let output = command.output().unwrap();
            assert_eq!(output.status.code(), Some(2), "{args:?}: {output:?}");
            if json {
                let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
                assert_eq!(result["error_code"], "usage");
            }
        }
    }
}

#[cfg(unix)]
#[test]
fn mcp_setup_pins_the_launcher_before_project_path_lookup() {
    use std::os::unix::fs::PermissionsExt;
    let project = TempProject::empty(r#"{"name":"mcp-launcher"}"#);
    std::fs::write(project.home().join(".claude.json"), "{}").unwrap();
    project.write_file("lpm", "#!/bin/sh\nprintf hijacked > intercepted\nexit 91\n");
    std::fs::set_permissions(
        project.path().join("lpm"),
        std::fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    let setup = lpm(&project).args(["mcp", "setup"]).output().unwrap();
    assert!(setup.status.success(), "{setup:?}");
    let config: serde_json::Value =
        serde_json::from_slice(&std::fs::read(project.home().join(".claude.json")).unwrap())
            .unwrap();
    let server = &config["mcpServers"]["lpm-registry"];
    let mut paths = vec![project.path().to_path_buf()];
    paths.extend(std::env::split_paths(
        &std::env::var_os("PATH").unwrap_or_default(),
    ));
    let result = std::process::Command::new(server["command"].as_str().unwrap())
        .args(["mcp", "serve", "--help"])
        .current_dir(project.path())
        .env("PATH", std::env::join_paths(paths).unwrap())
        .output()
        .unwrap();
    assert!(
        !project.path().join("intercepted").exists(),
        "configured launcher resolved a project executable"
    );
    assert!(result.status.success(), "{result:?}");
    assert!(std::path::Path::new(server["command"].as_str().unwrap()).is_absolute());
    assert!(server.get("env").is_none(), "{server}");
}

#[cfg(unix)]
#[test]
fn mcp_mutations_preserve_linked_editor_configs() {
    for action in ["setup", "remove"] {
        let project = TempProject::empty(r#"{"name":"mcp-linked"}"#);
        let original = r#"{"mcpServers":{"lpm-registry":{"command":"old"}}}"#;
        let target = project.path().join("shared.json");
        std::fs::write(&target, original).unwrap();
        let config = project.home().join(".claude.json");
        std::os::unix::fs::symlink(&target, &config).unwrap();
        let output = lpm(&project)
            .args(["mcp", action, "lpm-registry", "--json"])
            .output()
            .unwrap();
        assert!(
            !output.status.success(),
            "linked config must be rejected: {output:?}"
        );
        assert!(
            std::fs::symlink_metadata(&config)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(std::fs::read_to_string(target).unwrap(), original);
    }
}

#[cfg(unix)]
#[test]
fn mcp_rejects_relative_home_without_editing_project_configs() {
    let project = TempProject::empty(r#"{"name":"mcp-home"}"#);
    project.write_file(".claude.json", "{}");
    let output = lpm(&project)
        .env("HOME", ".")
        .args(["mcp", "setup", "--json"])
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "relative HOME must be rejected: {output:?}"
    );
    assert_eq!(
        std::fs::read_to_string(project.path().join(".claude.json")).unwrap(),
        "{}"
    );
}
const HOSTILE_SERVER_NAME: &str =
    "safe\nFORGED\rrewritten\u{8}\u{1b}]52;c;AAAA\u{7}\u{0090}hidden\u{009c}end";

fn assert_hostile_server_name_is_inline_safe(context: &str, rendered: &str) {
    assert!(
        rendered.contains("safe?FORGED?rewritten?end"),
        "{context} must preserve readable server text without forged rows, got:\n{rendered}"
    );
    for attacker_fragment in [
        "\u{1b}", "\u{7}", "\u{8}", "\r", "\u{007f}", "\u{0090}", "\u{009c}", "hidden",
    ] {
        assert!(
            !rendered.contains(attacker_fragment),
            "{context} retained attacker fragment {attacker_fragment:?}:\n{rendered}"
        );
    }
}

// ─── status (read-only) ───────────────────────────────────────────────

#[test]
fn mcp_status_on_fresh_home_succeeds() {
    let project = TempProject::empty(r#"{"name":"mcp","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["mcp", "status"])
        .output()
        .expect("failed to run lpm mcp status");

    assert!(
        output.status.success(),
        "mcp status on fresh HOME must succeed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("✓ MCP status loaded"),
        "mcp status must finish with a slim completion line, got:\n{stderr}",
    );
    assert!(
        !stderr.contains('●') && !stderr.contains('│') && !stderr.contains('◇'),
        "mcp status must not use cliclack gutter output, got:\n{stderr}",
    );
}

#[test]
fn mcp_status_json_envelope_is_valid_json() {
    let project = TempProject::empty(r#"{"name":"mcp","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["--json", "mcp", "status"])
        .output()
        .expect("failed to run lpm mcp status --json");

    assert!(output.status.success(), "mcp status --json must succeed");

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let _envelope: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("mcp status --json must be valid JSON: {e}\n---\n{stdout}"));
}

// ─── remove without name ──────────────────────────────────────────────

#[test]
fn mcp_remove_without_name_fails_with_helpful_message() {
    let project = TempProject::empty(r#"{"name":"mcp","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["mcp", "remove"])
        .output()
        .expect("failed to run lpm mcp remove (no name)");

    assert!(
        !output.status.success(),
        "mcp remove without name must exit non-zero"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("<NAME>"),
        "stderr must guide the user, got:\n{stderr}",
    );
}

#[test]
fn mcp_remove_server_argument_cannot_inject_terminal_rows() {
    let project = TempProject::empty(r#"{"name":"mcp","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["mcp", "remove", HOSTILE_SERVER_NAME])
        .output()
        .expect("failed to run lpm mcp remove with terminal controls in the server name");

    assert!(
        output.status.success(),
        "mcp remove of an unknown server succeeds"
    );
    let rendered = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_hostile_server_name_is_inline_safe("mcp remove output", &rendered);
}

#[test]
fn mcp_status_configured_server_name_cannot_inject_terminal_rows() {
    let project = TempProject::empty(r#"{"name":"mcp","version":"1.0.0"}"#);
    let config = serde_json::json!({
        "mcpServers": {
            HOSTILE_SERVER_NAME: {
                "command": "node"
            }
        }
    });
    std::fs::write(
        project.home().join(".claude.json"),
        serde_json::to_vec(&config).expect("serialize hostile MCP config"),
    )
    .expect("write hostile MCP config");

    let output = lpm(&project)
        .args(["mcp", "status"])
        .output()
        .expect("failed to run lpm mcp status with a hostile configured server name");

    assert!(output.status.success(), "mcp status must succeed");
    let rendered = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_hostile_server_name_is_inline_safe("mcp status output", &rendered);
}

#[test]
fn mcp_setup_and_remove_use_slim_human_status() {
    let project = TempProject::empty(r#"{"name":"mcp","version":"1.0.0"}"#);
    std::fs::write(project.home().join(".claude.json"), "{}")
        .expect("failed to seed Claude Code MCP config");

    let setup = lpm(&project)
        .args(["mcp", "setup", "test-server"])
        .output()
        .expect("failed to run lpm mcp setup");

    assert!(
        setup.status.success(),
        "mcp setup must succeed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&setup.stdout),
        String::from_utf8_lossy(&setup.stderr),
    );

    let setup_stderr = String::from_utf8_lossy(&setup.stderr);
    assert!(
        setup_stderr.contains("› Configuring MCP servers for supported editors"),
        "mcp setup must start with a slim phase line, got:\n{setup_stderr}",
    );
    assert!(
        setup_stderr.contains("✓ Claude Code") && setup_stderr.contains("configured"),
        "mcp setup must report configured editors, got:\n{setup_stderr}",
    );
    assert!(
        setup_stderr.contains("○") && setup_stderr.contains("skipped (config not found)"),
        "mcp setup must report skipped editor configs, got:\n{setup_stderr}",
    );
    assert!(
        setup_stderr.contains("✓ Server name: test-server"),
        "mcp setup must report the configured server name, got:\n{setup_stderr}",
    );
    assert!(
        setup_stderr.contains("✓ Done · restart your editor to pick up the new MCP server"),
        "mcp setup must finish with a slim completion line, got:\n{setup_stderr}",
    );
    assert!(
        !setup_stderr.contains('●') && !setup_stderr.contains('│') && !setup_stderr.contains('◇'),
        "mcp setup must not use cliclack gutter output, got:\n{setup_stderr}",
    );
    assert!(
        setup_stderr.contains("Registry tools come from https://lpm.dev/mcp"),
        "mcp setup must say where registry tools come from, got:\n{setup_stderr}"
    );

    let remove = lpm(&project)
        .args(["mcp", "remove", "test-server"])
        .output()
        .expect("failed to run lpm mcp remove");

    assert!(
        remove.status.success(),
        "mcp remove must succeed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&remove.stdout),
        String::from_utf8_lossy(&remove.stderr),
    );

    let remove_stderr = String::from_utf8_lossy(&remove.stderr);
    assert!(
        remove_stderr.contains("✓ Removed \"test-server\" from"),
        "mcp remove must report slim removal lines, got:\n{remove_stderr}",
    );
    assert!(
        !remove_stderr.contains('●')
            && !remove_stderr.contains('│')
            && !remove_stderr.contains('◇'),
        "mcp remove must not use cliclack gutter output, got:\n{remove_stderr}",
    );
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
fn mcp_setup_writes_the_lpm_launcher_to_both_container_shapes_idempotently() {
    let project = TempProject::empty(r#"{"name":"mcp","version":"1.0.0"}"#);
    let claude_path = project.home().join(".claude.json");
    #[cfg(target_os = "macos")]
    let vscode_path = project
        .home()
        .join("Library/Application Support/Code/User/mcp.json");
    #[cfg(target_os = "linux")]
    let vscode_path = project.home().join(".config/Code/User/mcp.json");

    std::fs::create_dir_all(vscode_path.parent().unwrap()).unwrap();
    std::fs::write(
        &claude_path,
        r#"{"theme":"dark","mcpServers":{"keep":{"command":"node"}}}"#,
    )
    .unwrap();
    std::fs::write(
        &vscode_path,
        r#"{"inputs":[{"type":"promptString"}],"servers":{"keep":{"command":"node"}}}"#,
    )
    .unwrap();

    for _ in 0..2 {
        let output = lpm(&project)
            .args(["mcp", "setup"])
            .output()
            .expect("failed to run lpm mcp setup");
        assert!(
            output.status.success(),
            "repeated mcp setup must succeed\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let claude: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&claude_path).unwrap()).unwrap();
    let vscode: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&vscode_path).unwrap()).unwrap();
    let executable = assert_cmd::cargo::cargo_bin("lpm-rs")
        .canonicalize()
        .unwrap();
    for server in [
        &claude["mcpServers"]["lpm-registry"],
        &vscode["servers"]["lpm-registry"],
    ] {
        let command = server["command"].as_str().expect("launcher command path");
        // The launcher is the running binary as the OS reports it, which may
        // reach it through a symlinked directory such as macOS `/tmp`.
        assert_eq!(
            std::path::Path::new(command).canonicalize().unwrap(),
            executable
        );
        assert_eq!(server["args"], serde_json::json!(["mcp", "serve"]));
        assert!(server.get("env").is_none(), "{server}");
    }
    assert_eq!(claude["mcpServers"].as_object().unwrap().len(), 2);
    assert_eq!(vscode["servers"].as_object().unwrap().len(), 2);
    assert_eq!(claude["theme"], "dark");
    assert!(vscode["inputs"].is_array());
}

#[test]
fn mcp_setup_json_reports_the_launcher_it_wrote_and_the_registry_server() {
    let project = TempProject::empty(r#"{"name":"mcp","version":"1.0.0"}"#);
    let claude_path = project.home().join(".claude.json");
    std::fs::write(&claude_path, "{}").unwrap();

    let output = lpm(&project)
        .args(["--json", "mcp", "setup"])
        .output()
        .expect("failed to run lpm mcp setup --json");
    assert!(
        output.status.success(),
        "mcp setup --json must succeed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let envelope: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|error| panic!("stdout must be one JSON document: {error}\n{stdout}"));
    insta::assert_json_snapshot!(envelope, {
        ".command" => "[LPM_PATH]",
    }, @r###"
    {
      "success": true,
      "server": "lpm-registry",
      "configured": [
        "Claude Code"
      ],
      "command": "[LPM_PATH]",
      "args": [
        "mcp",
        "serve"
      ],
      "registry_server": "https://lpm.dev/mcp"
    }
    "###);

    let config: serde_json::Value =
        serde_json::from_slice(&std::fs::read(claude_path).unwrap()).unwrap();
    assert_eq!(
        config["mcpServers"]["lpm-registry"]["args"],
        envelope["args"]
    );
}

// ─── unknown action ───────────────────────────────────────────────────

#[test]
fn mcp_unknown_action_reports_usage_and_points_to_help() {
    let project = TempProject::empty(r#"{"name":"mcp","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["mcp", "not-a-real-action"])
        .output()
        .expect("failed to run lpm mcp bogus");

    assert!(
        !output.status.success(),
        "unknown mcp action must exit non-zero"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("usage lpm mcp") && stderr.contains("--help"),
        "stderr must show usage and the help option, got:\n{stderr}",
    );
}

// ─── serve ────────────────────────────────────────────────────────────

/// How long a test waits for one answer from the server.
const ANSWER_TIMEOUT: Duration = Duration::from_secs(120);

/// A running `lpm mcp serve`, driven over its stdio as an editor drives it.
struct McpServer {
    child: std::process::Child,
    stdin: Option<std::process::ChildStdin>,
    lines: mpsc::Receiver<String>,
    next_id: u64,
    /// Whether each request carries the 2026-07-28 `_meta` in place of an
    /// `initialize` handshake.
    stateless: bool,
    /// Notifications read while waiting for a response.
    notifications: Vec<Value>,
}

const STATELESS_META: &str = r#"{
    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
    "io.modelcontextprotocol/clientCapabilities": {},
    "io.modelcontextprotocol/clientInfo": { "name": "workflow-test", "version": "1.0.0" }
}"#;

impl McpServer {
    fn start(project: &TempProject, registry_url: &str) -> Self {
        let mut server = Self::spawn(project, registry_url, false);
        let initialized = server.request(
            "initialize",
            json!({
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": { "name": "workflow-test", "version": "1.0.0" },
            }),
        );
        assert_eq!(initialized["result"]["serverInfo"]["name"], "lpm");
        server.send(&json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }));
        server
    }

    /// A server driven as a 2026-07-28 client drives it, without `initialize`.
    fn start_stateless(project: &TempProject, registry_url: &str) -> Self {
        Self::spawn(project, registry_url, true)
    }

    fn spawn(project: &TempProject, registry_url: &str, stateless: bool) -> Self {
        let mut command = lpm_spawnable_with_registry(project, registry_url);
        command
            .args(["mcp", "serve"])
            .stdin(std::process::Stdio::piped());
        let mut child = command.spawn().expect("start lpm mcp serve");
        let stdin = child.stdin.take();
        let stdout = child.stdout.take().expect("server stdout");
        let (sender, lines) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let Ok(line) = line else { break };
                if sender.send(line).is_err() {
                    break;
                }
            }
        });
        Self {
            child,
            stdin,
            lines,
            next_id: 1,
            stateless,
            notifications: Vec::new(),
        }
    }

    fn send(&mut self, message: &Value) {
        let stdin = self.stdin.as_mut().expect("server stdin is open");
        writeln!(stdin, "{message}").expect("write to the server");
        stdin.flush().expect("flush to the server");
    }

    fn request(&mut self, method: &str, mut params: Value) -> Value {
        let id = self.send_request(method, &mut params);
        loop {
            let message = self.next_message(method);
            if message["id"] == json!(id) && message.get("method").is_none() {
                return message;
            }
            if message.get("id").is_none() {
                self.notifications.push(message);
            }
        }
    }

    fn send_request(&mut self, method: &str, params: &mut Value) -> u64 {
        if self.stateless {
            params["_meta"] = serde_json::from_str(STATELESS_META).unwrap();
        }
        let id = self.next_id;
        self.next_id += 1;
        self.send(&json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params }));
        id
    }

    fn next_message(&mut self, waiting_for: &str) -> Value {
        let line = self
            .lines
            .recv_timeout(ANSWER_TIMEOUT)
            .unwrap_or_else(|_| panic!("nothing arrived while waiting for {waiting_for}"));
        serde_json::from_str(&line)
            .unwrap_or_else(|error| panic!("stdout must carry only JSON-RPC: {error}: {line}"))
    }

    /// The next notification with `method`, including one already read
    /// while waiting for a response.
    fn notification(&mut self, method: &str) -> Value {
        if let Some(index) = self
            .notifications
            .iter()
            .position(|message| message["method"] == method)
        {
            return self.notifications.remove(index);
        }
        loop {
            let message = self.next_message(method);
            if message["method"] == method {
                return message;
            }
        }
    }

    fn tool_names(&mut self) -> Vec<String> {
        self.request("tools/list", json!({}))["result"]["tools"]
            .as_array()
            .expect("a tool list")
            .iter()
            .map(|tool| tool["name"].as_str().unwrap().to_owned())
            .collect()
    }

    /// The result of a tool call, and its text.
    fn call(&mut self, name: &str, arguments: Value) -> (Value, String) {
        let answer = self.request(
            "tools/call",
            json!({ "name": name, "arguments": arguments }),
        );
        let result = answer["result"].clone();
        assert!(
            !result.is_null(),
            "{name} must answer with a result: {answer}"
        );
        let text = result["content"][0]["text"]
            .as_str()
            .unwrap_or_default()
            .to_owned();
        (result, text)
    }

    /// Close stdin, as an editor does when it stops the server, and return
    /// how it exited and what it wrote to stderr.
    fn stop(mut self) -> (std::process::ExitStatus, String) {
        drop(self.stdin.take());
        let deadline = std::time::Instant::now() + ANSWER_TIMEOUT;
        let status = loop {
            if let Some(status) = self.child.try_wait().expect("poll the server") {
                break status;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "the server must exit when its stdin closes"
            );
            std::thread::sleep(Duration::from_millis(20));
        };
        let mut stderr = String::new();
        if let Some(mut pipe) = self.child.stderr.take() {
            std::io::Read::read_to_string(&mut pipe, &mut stderr).expect("read stderr");
        }
        (status, stderr)
    }
}

impl Drop for McpServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Answers a JSON-RPC request to the hosted MCP server with `result`, under
/// the request's own id.
fn rpc_result(result: Value) -> impl Fn(&Request) -> ResponseTemplate {
    move |request: &Request| {
        let body: Value = serde_json::from_slice(&request.body).expect("a JSON-RPC request");
        ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc": "2.0",
            "id": body["id"],
            "result": result,
        }))
    }
}

/// Refuses a JSON-RPC request to the hosted MCP server with `status` and a
/// JSON-RPC error saying `message`.
fn rpc_refusal(status: u16, message: &'static str) -> impl Fn(&Request) -> ResponseTemplate {
    move |request: &Request| {
        let body: Value = serde_json::from_slice(&request.body).expect("a JSON-RPC request");
        ResponseTemplate::new(status)
            .insert_header("www-authenticate", "Bearer scope=\"read\"")
            .set_body_json(json!({
                "jsonrpc": "2.0",
                "id": body["id"],
                "error": { "code": -32000, "message": message },
            }))
    }
}

fn registry_tool(name: &str) -> Value {
    json!({
        "name": name,
        "description": format!("The registry's {name}."),
        "inputSchema": { "type": "object", "properties": {} },
    })
}

async fn mount_tool_listing(registry: &MockRegistry, tools: Value) {
    Mock::given(method("POST"))
        .and(path("/mcp"))
        .and(header("mcp-method", "tools/list"))
        .and(header("mcp-protocol-version", "2026-07-28"))
        .respond_with(rpc_result(json!({ "tools": tools, "ttlMs": 3_600_000 })))
        .mount(registry.server())
        .await;
}

fn seed_login(project: &TempProject, registry: &MockRegistry, access: &str) {
    seed_sessions(
        project.home(),
        &[SessionSeed {
            registry_url: &registry.url(),
            access_token: Some(access),
            refresh_token: Some("stored-refresh"),
            session_access_expires_at: Some("2099-01-01T00:00:00Z"),
        }],
    );
}

#[tokio::test]
async fn mcp_serve_lists_the_registry_tools_and_its_own_without_reading_a_login() {
    let project = TempProject::empty(r#"{"name":"mcp-serve","version":"1.0.0"}"#);
    let registry = MockRegistry::start().await;
    mount_tool_listing(
        &registry,
        json!([registry_tool("lpm_search"), registry_tool("lpm_install")]),
    )
    .await;
    seed_login(&project, &registry, "stored-access");
    let mut server = McpServer::start(&project, &registry.url());

    let tools = server.tool_names();
    let listed_again = server.tool_names();

    assert_eq!(
        tools,
        ["lpm_search", "lpm_install", "lpm_add", "lpm_audit"],
        "registry tools come first, and a local tool keeps its name"
    );
    assert_eq!(listed_again, tools);
    let listings: Vec<_> = registry
        .server()
        .received_requests()
        .await
        .unwrap()
        .into_iter()
        .filter(|request| request.url.path() == "/mcp")
        .collect();
    assert_eq!(listings.len(), 1, "a fresh listing is reused");
    assert!(
        listings[0].headers.get("authorization").is_none(),
        "a listing is the same for everyone and must not carry the login"
    );
    let (status, stderr) = server.stop();
    assert!(status.success(), "{stderr}");
}

#[tokio::test]
async fn mcp_serve_calls_a_registry_tool_with_the_stored_login() {
    let project = TempProject::empty(r#"{"name":"mcp-serve","version":"1.0.0"}"#);
    let registry = MockRegistry::start().await;
    Mock::given(method("POST"))
        .and(path("/mcp"))
        .and(header("mcp-method", "tools/call"))
        .and(header("mcp-name", "lpm_account"))
        .and(header("authorization", "Bearer stored-access"))
        .and(body_partial_json(json!({
            "params": { "name": "lpm_account", "arguments": { "pool": true } }
        })))
        .respond_with(rpc_result(json!({
            "content": [{ "type": "text", "text": "Signed in as alice." }],
        })))
        .expect(1)
        .mount(registry.server())
        .await;
    seed_login(&project, &registry, "stored-access");
    let mut server = McpServer::start(&project, &registry.url());

    let (result, text) = server.call("lpm_account", json!({ "pool": true }));

    assert_eq!(text, "Signed in as alice.");
    assert!(result.get("isError").is_none_or(|error| error == false));
}

#[tokio::test]
async fn mcp_serve_refreshes_a_rejected_login_once_and_retries_the_call() {
    let project = TempProject::empty(r#"{"name":"mcp-serve","version":"1.0.0"}"#);
    let registry = MockRegistry::start().await;
    Mock::given(method("POST"))
        .and(path("/mcp"))
        .and(header("authorization", "Bearer stale-access"))
        .respond_with(rpc_refusal(401, "This token has expired."))
        .expect(1)
        .mount(registry.server())
        .await;
    registry
        .with_refresh_expected(
            "stored-refresh",
            "rotated-access",
            "rotated-refresh",
            "2099-01-01T00:00:00Z",
            1,
        )
        .await;
    Mock::given(method("POST"))
        .and(path("/mcp"))
        .and(header("authorization", "Bearer rotated-access"))
        .respond_with(rpc_result(json!({
            "content": [{ "type": "text", "text": "Signed in as alice." }],
        })))
        .expect(1)
        .mount(registry.server())
        .await;
    seed_login(&project, &registry, "stale-access");
    let mut server = McpServer::start(&project, &registry.url());

    let (_, text) = server.call("lpm_account", json!({}));

    assert_eq!(text, "Signed in as alice.");
}

#[tokio::test]
async fn mcp_serve_asks_for_lpm_login_when_the_registry_wants_an_account() {
    let project = TempProject::empty(r#"{"name":"mcp-serve","version":"1.0.0"}"#);
    let registry = MockRegistry::start().await;
    Mock::given(method("POST"))
        .and(path("/mcp"))
        .respond_with(rpc_refusal(
            401,
            "Reading an account needs you to sign in to LPM.dev.",
        ))
        .mount(registry.server())
        .await;
    let mut server = McpServer::start(&project, &registry.url());

    let (result, text) = server.call("lpm_account", json!({}));

    assert_eq!(result["isError"], true);
    assert_eq!(
        text,
        "Reading an account needs you to sign in to LPM.dev. Run `lpm login` in a terminal to sign in to LPM.dev, then call the tool again."
    );
}

#[tokio::test]
async fn mcp_serve_uses_a_login_made_after_it_started() {
    let project = TempProject::empty(r#"{"name":"mcp-serve","version":"1.0.0"}"#);
    let registry = MockRegistry::start().await;
    Mock::given(method("POST"))
        .and(path("/mcp"))
        .and(header("authorization", "Bearer later-access"))
        .respond_with(rpc_result(json!({
            "content": [{ "type": "text", "text": "Signed in as alice." }],
        })))
        .with_priority(1)
        .mount(registry.server())
        .await;
    Mock::given(method("POST"))
        .and(path("/mcp"))
        .respond_with(rpc_refusal(401, "Reading an account needs you to sign in."))
        .mount(registry.server())
        .await;
    let mut server = McpServer::start(&project, &registry.url());
    let (signed_out, _) = server.call("lpm_account", json!({}));
    assert_eq!(signed_out["isError"], true);

    seed_login(&project, &registry, "later-access");
    let (_, text) = server.call("lpm_account", json!({}));

    assert_eq!(text, "Signed in as alice.");
}

#[tokio::test]
async fn mcp_serve_keeps_its_own_tools_when_the_registry_is_unreachable() {
    let project = TempProject::empty(r#"{"name":"mcp-serve","version":"1.0.0"}"#);
    let mut server = McpServer::start(&project, "http://127.0.0.1:9");

    let tools = server.tool_names();
    let (result, text) = server.call("lpm_search", json!({ "query": "forms" }));

    assert_eq!(tools, ["lpm_install", "lpm_add", "lpm_audit"]);
    assert_eq!(result["isError"], true);
    assert!(
        text.starts_with("lpm couldn't reach the registry's MCP server at http://127.0.0.1:9/mcp"),
        "{text}"
    );
}

#[tokio::test]
async fn mcp_serve_installs_an_lpm_dev_package_into_the_named_project() {
    let editor = TempProject::empty(r#"{"name":"editor-workspace","version":"1.0.0"}"#);
    let project = TempProject::empty(r#"{"name":"mcp-install","version":"1.0.0"}"#);
    let registry = MockRegistry::start().await;
    registry
        .with_package(
            "@lpm.dev/acme.forms",
            "1.0.0",
            &make_tarball("@lpm.dev/acme.forms", "1.0.0"),
        )
        .await;
    let mut server = McpServer::start(&editor, &registry.url());

    let (result, text) = server.call(
        "lpm_install",
        json!({
            "projectPath": project.path().to_str().unwrap(),
            "name": "acme.forms",
            "version": "1.0.0",
        }),
    );

    assert!(
        result.get("isError").is_none_or(|error| error == false),
        "{text}"
    );
    let report: Value = serde_json::from_str(&text).expect("the tool returns the JSON result");
    assert_eq!(report["success"], true, "{report}");
    assert!(
        project
            .path()
            .join("node_modules/@lpm.dev/acme.forms/package.json")
            .is_file(),
        "the package must be installed in the named project"
    );
    assert!(
        !editor.path().join("node_modules").exists(),
        "nothing may be installed in the editor's own directory"
    );
}

#[tokio::test]
async fn mcp_serve_refuses_a_relative_project_without_running_anything() {
    let project = TempProject::empty(r#"{"name":"mcp-serve","version":"1.0.0"}"#);
    let mut server = McpServer::start(&project, "http://127.0.0.1:9");

    let (result, text) = server.call(
        "lpm_install",
        json!({ "projectPath": ".", "name": "acme.forms" }),
    );

    assert_eq!(result["isError"], true);
    assert_eq!(
        text,
        "projectPath must be an absolute path to the project's directory, not .."
    );
    assert!(!project.path().join("node_modules").exists());
}

#[tokio::test]
async fn mcp_serve_and_setup_remove_the_retired_npm_runtime() {
    for action in ["serve", "setup"] {
        let project = TempProject::empty(r#"{"name":"mcp-retired","version":"1.0.0"}"#);
        let root = lpm_common::LpmRoot::from_dir(project.home().join(".lpm"));
        let runtime = root.retired_mcp_runtime();
        std::fs::create_dir_all(runtime.join("runtime")).unwrap();
        std::fs::write(runtime.join("runtime/package.json"), "{}").unwrap();

        if action == "serve" {
            let server = McpServer::start(&project, "http://127.0.0.1:9");
            let (status, stderr) = server.stop();
            assert!(status.success(), "{stderr}");
        } else {
            let output = lpm(&project).args(["mcp", "setup"]).output().unwrap();
            assert!(output.status.success(), "{output:?}");
        }

        assert!(
            !runtime.exists(),
            "`lpm mcp {action}` must remove the retired runtime"
        );
    }
}

#[tokio::test]
async fn mcp_serve_keeps_the_retired_runtime_while_an_older_lpm_runs_it() {
    let project = TempProject::empty(r#"{"name":"mcp-retired","version":"1.0.0"}"#);
    let root = lpm_common::LpmRoot::from_dir(project.home().join(".lpm"));
    let runtime = root.retired_mcp_runtime();
    std::fs::create_dir_all(runtime.join("runtime")).unwrap();
    std::fs::write(runtime.join("runtime/package.json"), "{}").unwrap();
    let lock_path = root.retired_mcp_runtime_lock();
    let (held_tx, held_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel::<()>();
    let holder = std::thread::spawn(move || {
        lpm_common::with_shared_lock(lock_path, || {
            held_tx.send(()).unwrap();
            release_rx.recv().unwrap();
            Ok::<_, lpm_common::LpmError>(())
        })
    });
    held_rx.recv().unwrap();

    let server = McpServer::start(&project, "http://127.0.0.1:9");
    let (status, stderr) = server.stop();
    release_tx.send(()).unwrap();
    holder.join().unwrap().unwrap();

    assert!(status.success(), "{stderr}");
    assert!(
        runtime.join("runtime/package.json").is_file(),
        "a runtime an older lpm still runs must stay"
    );
}

/// A tool listing that answers only after `delay`, the first time.
async fn mount_slow_then_prompt_listing(registry: &MockRegistry, delay: Duration) {
    Mock::given(method("POST"))
        .and(path("/mcp"))
        .and(header("mcp-method", "tools/list"))
        .respond_with(move |request: &Request| {
            rpc_result(json!({ "tools": [registry_tool("lpm_search")] }))(request).set_delay(delay)
        })
        .up_to_n_times(1)
        .with_priority(1)
        .mount(registry.server())
        .await;
    mount_tool_listing(registry, json!([registry_tool("lpm_search")])).await;
}

#[tokio::test]
async fn mcp_serve_lists_its_own_tools_while_the_registry_is_slow_and_announces_the_rest() {
    let project = TempProject::empty(r#"{"name":"mcp-serve","version":"1.0.0"}"#);
    let registry = MockRegistry::start().await;
    mount_slow_then_prompt_listing(&registry, Duration::from_secs(60)).await;
    let mut server = McpServer::start(&project, &registry.url());

    let started = std::time::Instant::now();
    let first = server.tool_names();
    assert!(
        started.elapsed() < Duration::from_secs(30),
        "a slow registry must not hold the listing: {:?}",
        started.elapsed()
    );
    assert_eq!(first, ["lpm_install", "lpm_add", "lpm_audit"]);

    server.notification("notifications/tools/list_changed");
    let second = server.tool_names();

    assert_eq!(
        second,
        ["lpm_search", "lpm_install", "lpm_add", "lpm_audit"]
    );
}

#[tokio::test]
async fn mcp_serve_announces_late_registry_tools_on_a_listen_stream() {
    let project = TempProject::empty(r#"{"name":"mcp-serve","version":"1.0.0"}"#);
    let registry = MockRegistry::start().await;
    mount_slow_then_prompt_listing(&registry, Duration::from_secs(60)).await;
    let mut server = McpServer::start_stateless(&project, &registry.url());
    let listen = server.send_request(
        "subscriptions/listen",
        &mut json!({ "notifications": { "toolsListChanged": true } }),
    );
    let acknowledged = server.notification("notifications/subscriptions/acknowledged");
    assert_eq!(
        acknowledged["params"]["notifications"]["toolsListChanged"],
        true
    );

    let first = server.tool_names();
    let changed = server.notification("notifications/tools/list_changed");
    let second = server.tool_names();

    assert_eq!(first, ["lpm_install", "lpm_add", "lpm_audit"]);
    assert_eq!(
        changed["params"]["_meta"]["io.modelcontextprotocol/subscriptionId"],
        json!(listen),
        "the notice belongs to the listen stream: {changed}"
    );
    assert_eq!(
        second,
        ["lpm_search", "lpm_install", "lpm_add", "lpm_audit"]
    );
}

#[tokio::test]
async fn mcp_serve_reads_public_data_again_after_lpm_logout() {
    let project = TempProject::empty(r#"{"name":"mcp-serve","version":"1.0.0"}"#);
    let registry = MockRegistry::start().await;
    Mock::given(method("POST"))
        .and(path("/mcp"))
        .and(header("authorization", "Bearer stored-access"))
        .respond_with(rpc_result(json!({
            "content": [{ "type": "text", "text": "Results for alice." }],
        })))
        .up_to_n_times(1)
        .with_priority(1)
        .mount(registry.server())
        .await;
    Mock::given(method("POST"))
        .and(path("/mcp"))
        .and(header("authorization", "Bearer stored-access"))
        .respond_with(rpc_refusal(401, "This token was revoked."))
        .with_priority(2)
        .mount(registry.server())
        .await;
    Mock::given(method("POST"))
        .and(path("/mcp"))
        .respond_with(rpc_result(json!({
            "content": [{ "type": "text", "text": "Public results." }],
        })))
        .mount(registry.server())
        .await;
    seed_login(&project, &registry, "stored-access");
    let mut server = McpServer::start(&project, &registry.url());
    let (_, signed_in) = server.call("lpm_search", json!({ "query": "forms" }));
    assert_eq!(signed_in, "Results for alice.");

    support::auth_state::write_credentials_store(project.home(), &json!({}));
    let (result, text) = server.call("lpm_search", json!({ "query": "forms" }));

    assert_eq!(text, "Public results.");
    assert!(result.get("isError").is_none_or(|error| error == false));
}

#[tokio::test]
async fn mcp_serve_stops_a_running_command_when_the_editor_disconnects() {
    let editor = TempProject::empty(r#"{"name":"editor-workspace","version":"1.0.0"}"#);
    let project = TempProject::empty(r#"{"name":"mcp-install","version":"1.0.0"}"#);
    let registry = MockRegistry::start().await;
    Mock::given(any())
        .respond_with(ResponseTemplate::new(503).set_delay(Duration::from_secs(120)))
        .with_priority(1)
        .mount(registry.server())
        .await;
    let mut server = McpServer::start(&editor, &registry.url());
    server.send_request(
        "tools/call",
        &mut json!({
            "name": "lpm_install",
            "arguments": {
                "projectPath": project.path().to_str().unwrap(),
                "name": "acme.forms",
            },
        }),
    );
    let deadline = std::time::Instant::now() + ANSWER_TIMEOUT;
    while registry
        .server()
        .received_requests()
        .await
        .unwrap()
        .is_empty()
    {
        assert!(
            std::time::Instant::now() < deadline,
            "the install never reached the registry"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    let disconnected = std::time::Instant::now();
    let (status, stderr) = server.stop();

    assert!(
        disconnected.elapsed() < Duration::from_secs(60),
        "the server must stop the install instead of waiting for it: {:?}\n{stderr}",
        disconnected.elapsed()
    );
    assert!(status.success(), "{stderr}");
}
