//! Workflow tests for `lpm mcp setup / remove / status`.
//!
//! MCP setup writes server entries into well-known editor config files
//! (Claude Code: `~/.claude.json`, Cursor: `~/.cursor/mcp.json`, etc.).
//! Tests run under an isolated HOME so they don't touch the developer's
//! real editor config.

mod support;

use support::{TempProject, lpm};

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
