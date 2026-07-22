//! Workflow tests for `lpm mcp setup / remove / status`.
//!
//! MCP setup writes server entries into existing well-known editor config
//! files (Claude Code: `~/.claude.json`, Cursor: `~/.cursor/mcp.json`,
//! etc.). Tests run under an isolated HOME so they don't touch the
//! developer's real editor config.

mod support;

use support::{TempProject, lpm};

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
        stderr.contains("specify server name") || stderr.contains("name"),
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

// ─── unknown action ───────────────────────────────────────────────────

#[test]
fn mcp_unknown_action_lists_valid_subcommands() {
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
        stderr.contains("setup") && stderr.contains("remove") && stderr.contains("status"),
        "stderr must enumerate valid actions, got:\n{stderr}",
    );
}
