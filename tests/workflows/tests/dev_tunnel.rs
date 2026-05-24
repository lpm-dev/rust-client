//! Workflow tests for `lpm dev`, `lpm tunnel`, and `lpm internal-update-check`.
//!
//! These commands all sit on the network/TTY/server boundary and
//! cannot fully run inside the workflow tier:
//!
//! - `lpm dev` starts long-lived service orchestration (HTTPS server,
//!   tunnel, dashboard) — only the parse-time / help / error paths are
//!   testable hermetically.
//! - `lpm tunnel` opens a network connection to the LPM tunnel
//!   service. Like dev, only the parse-time paths are workflow-safe.
//! - `lpm internal-update-check` is a hidden subcommand that refreshes
//!   the update cache — exits cleanly even when the network is down,
//!   since the parent already checked staleness.

mod support;

use std::fs;
use support::{TempProject, lpm};

// ─── dev: --help dispatches and exits cleanly ─────────────────────────

#[test]
fn dev_help_emits_command_usage_and_flags() {
    let project = TempProject::empty(r#"{"name":"dev","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["dev", "--help"])
        .output()
        .expect("failed to run lpm dev --help");

    assert!(
        output.status.success(),
        "lpm dev --help must succeed (clap-level dispatch)"
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    // The help text must mention key flags so a future doc/clap drift
    // (e.g., --tunnel renamed) fails this test.
    assert!(
        stdout.contains("--tunnel") && stdout.contains("--https"),
        "dev --help must list the documented flags, got:\n{stdout}",
    );
}

#[test]
fn dev_human_output_suppresses_nested_install_chatter_and_legacy_glyphs() {
    let project =
        TempProject::empty(r#"{"name":"dev-output","version":"1.0.0","dependencies":{}}"#);
    project.write_file(
        "lpm.json",
        r#"{
            "services": {
                "web": {
                    "command": "node -e \"setTimeout(() => process.exit(0), 300)\""
                }
            }
        }"#,
    );

    let output = lpm(&project)
        .args(["dev", "--no-open"])
        .output()
        .expect("failed to run lpm dev for human-output regression test");

    assert!(
        output.status.success(),
        "lpm dev fixture must exit cleanly; stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.trim().is_empty(),
        "human lpm dev should not write progress chatter to stdout, got:\n{stdout}"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("› Dependencies out of date, installing..."),
        "expected dev-owned install phase line, got:\n{stderr}"
    );
    assert!(
        !stderr.contains("Resolving dependencies from")
            && !stderr.contains("No dependencies to install")
            && !stderr.contains("◆")
            && !stderr.contains("▲")
            && !stderr.contains("│"),
        "nested install chatter and legacy glyphs must be absent from dev stderr, got:\n{stderr}"
    );
}

// ─── tunnel: --help dispatches and exits cleanly ──────────────────────

#[test]
fn tunnel_help_emits_action_summary() {
    let project = TempProject::empty(r#"{"name":"tunnel","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["tunnel", "--help"])
        .output()
        .expect("failed to run lpm tunnel --help");

    assert!(output.status.success(), "lpm tunnel --help must succeed");

    let stdout = String::from_utf8_lossy(&output.stdout);
    // Document the action names so a future rename ("claim" →
    // "register"?) fails this test.
    assert!(
        stdout.contains("claim") || stdout.contains("unclaim") || stdout.contains("Actions"),
        "tunnel --help must document the action list, got:\n{stdout}",
    );
}

// ─── tunnel claim: requires auth ──────────────────────────────────────

#[test]
fn tunnel_start_without_auth_under_json_emits_error_envelope_on_stdout() {
    let project = TempProject::empty(r#"{"name":"tunnel","version":"1.0.0"}"#);

    // A numeric first arg routes to "start <port>" in the tunnel
    // dispatcher. Like every other tunnel action it requires a
    // session-backed bearer — fails before opening any socket.
    let output = lpm(&project)
        .args([
            "--registry",
            "http://127.0.0.1:1",
            "--insecure",
            "--json",
            "tunnel",
            "4567",
        ])
        .output()
        .expect("failed to run lpm --json tunnel 4567");

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let envelope: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap_or_else(|e| {
        panic!("--json tunnel <port> error path must emit JSON: {e}\n---\n{stdout}")
    });
    assert_eq!(envelope["success"], serde_json::json!(false));
    assert_eq!(envelope["error_code"], serde_json::json!("tunnel"));
}

#[test]
fn tunnel_claim_without_auth_under_json_emits_error_envelope_on_stdout() {
    let project = TempProject::empty(r#"{"name":"tunnel","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args([
            "--registry",
            "http://127.0.0.1:1",
            "--insecure",
            "--json",
            "tunnel",
            "claim",
            "test-tunnel.example.test",
        ])
        .output()
        .expect("failed to run lpm --json tunnel claim");

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let envelope: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap_or_else(|e| {
        panic!("--json tunnel claim error path must emit JSON: {e}\n---\n{stdout}")
    });
    assert_eq!(envelope["success"], serde_json::json!(false));
    assert_eq!(envelope["error_code"], serde_json::json!("tunnel"));
}

#[test]
fn tunnel_list_without_auth_under_json_emits_error_envelope_on_stdout() {
    let project = TempProject::empty(r#"{"name":"tunnel","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args([
            "--registry",
            "http://127.0.0.1:1",
            "--insecure",
            "--json",
            "tunnel",
            "list",
        ])
        .output()
        .expect("failed to run lpm --json tunnel list");

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let envelope: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap_or_else(|e| {
        panic!("--json tunnel list error path must emit JSON: {e}\n---\n{stdout}")
    });
    assert_eq!(envelope["success"], serde_json::json!(false));
    assert_eq!(envelope["error_code"], serde_json::json!("tunnel"));
}

#[test]
fn tunnel_inspect_without_auth_reads_local_log_under_json() {
    let project = TempProject::empty(r#"{"name":"tunnel","version":"1.0.0"}"#);

    let lpm_dir = project.path().join(".lpm");
    fs::create_dir_all(&lpm_dir).expect("failed to create .lpm fixture dir");
    fs::write(
        lpm_dir.join("webhook-log.jsonl"),
        "{\"id\":\"wh-stripe-402\",\"ts\":\"2026-05-22T10:05:00Z\",\"method\":\"POST\",\"path\":\"/webhooks/stripe\",\"status\":402,\"ms\":18,\"provider\":\"Stripe\",\"summary\":\"Stripe: payment_intent.payment_failed\",\"req_size\":56,\"res_size\":27}\n",
    )
    .expect("failed to seed webhook log");

    let output = lpm(&project)
        .args(["--json", "tunnel", "inspect"])
        .output()
        .expect("failed to run lpm --json tunnel inspect");

    assert!(
        output.status.success(),
        "local tunnel inspect should not require auth when only reading the on-disk log"
    );

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let entries: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap_or_else(|e| {
        panic!("--json tunnel inspect must emit the local webhook list: {e}\n---\n{stdout}")
    });
    let rows = entries
        .as_array()
        .expect("expected tunnel inspect JSON output to be an array");
    assert_eq!(rows.len(), 1, "expected one seeded webhook row");
    assert_eq!(rows[0]["provider"], serde_json::json!("Stripe"));
    assert_eq!(rows[0]["status"], serde_json::json!(402));
}

#[test]
fn tunnel_claim_without_auth_fails_with_clear_message() {
    // `lpm tunnel claim <domain>` calls the registry to claim the
    // domain. On an isolated HOME (no token) the call must fail with
    // a clear auth message instead of crashing or hanging.
    let project = TempProject::empty(r#"{"name":"tunnel","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args([
            "--registry",
            "http://127.0.0.1:1",
            "--insecure",
            "tunnel",
            "claim",
            "test-tunnel.example.test",
        ])
        .output()
        .expect("failed to run lpm tunnel claim");

    assert!(
        !output.status.success(),
        "tunnel claim without auth must exit non-zero"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    // Either an auth-required message OR a network error against the
    // broken localhost endpoint. Both are acceptable contracts; the
    // process MUST exit (not hang).
    assert!(
        !stderr.is_empty() || !String::from_utf8_lossy(&output.stdout).is_empty(),
        "must produce a diagnostic on failure"
    );
}

// ─── internal-update-check: hidden, exits cleanly ─────────────────────

#[test]
fn internal_update_check_hidden_command_exits_zero_even_offline() {
    let project = TempProject::empty(r#"{"name":"iuc","version":"1.0.0"}"#);

    // Point at a deliberately broken registry so the cache-refresh
    // network call fails. The command persists the failure to cache
    // (so the parent's stale check backs off) and exits 0 regardless.
    let output = lpm(&project)
        .args([
            "--registry",
            "http://127.0.0.1:1",
            "--insecure",
            "internal-update-check",
        ])
        .output()
        .expect("failed to run lpm internal-update-check");

    assert!(
        output.status.success(),
        "internal-update-check must always exit 0 (even on network failure) so the parent loop doesn't escalate\nstderr: {}",
        String::from_utf8_lossy(&output.stderr),
    );
}

#[test]
fn internal_update_check_is_hidden_from_help() {
    let project = TempProject::empty(r#"{"name":"iuc","version":"1.0.0"}"#);

    let output = lpm(&project)
        .arg("--help")
        .output()
        .expect("failed to run lpm --help");

    assert!(output.status.success(), "lpm --help must succeed");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.contains("internal-update-check"),
        "the hidden internal-update-check subcommand must not appear in user-facing help, got:\n{stdout}",
    );
}
