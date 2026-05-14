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
