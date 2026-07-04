//! Cli-binary survivor — `lpm approve-scripts` TTY/interactive contract.
//!
//! **Tier-placement justification (survivor class):**
//! intentionally minimal binary-surface repro for the TTY-interactive
//! contract. The interactive walk path (no `--yes`, no `--list`, no
//! `<pkg>`) cannot be exercised from the workflow tier without a real
//! PTY; the assertions below confirm the *guards* that protect the
//! interactive walk fire correctly when stdin is not a TTY. The
//! companion non-interactive paths (`--yes`, `--list`, `<pkg>`,
//! `--global`, `--dry-run`) are exhaustively covered in
//! [`tests/workflows/tests/approve_scripts.rs`].

use assert_cmd::Command;
use tempfile::TempDir;

/// Build a `lpm-rs` Command in an isolated HOME with a seeded
/// build-state.json containing one blocked package — so
/// `approve-scripts` reaches the interactive walk guard instead of
/// short-circuiting on the missing-state-file branch.
fn lpm_isolated() -> (Command, TempDir, TempDir) {
    let project = TempDir::new().expect("create temp project");
    let home = TempDir::new().expect("create temp home");

    std::fs::write(
        project.path().join("package.json"),
        r#"{"name":"approve-tty","version":"1.0.0"}"#,
    )
    .expect("seed package.json");

    // Seed a minimal build-state.json so approve-scripts has a non-empty
    // blocked set to walk; the TTY/JSON guards below the discovery
    // branch can only fire when there's something to approve.
    let lpm_dir = project.path().join(".lpm");
    std::fs::create_dir_all(&lpm_dir).expect("mkdir .lpm");
    let build_state = serde_json::json!({
        "state_version": 1,
        "blocked_set_fingerprint": "sha256-fixture",
        "captured_at": "2026-05-01T00:00:00Z",
        "blocked_packages": [
            {
                "name": "scripted-pkg",
                "version": "1.0.0",
                "integrity": null,
                "script_hash": null,
                "phases_present": ["postinstall"],
                "binding_drift": false
            }
        ]
    });
    std::fs::write(
        lpm_dir.join("build-state.json"),
        serde_json::to_string_pretty(&build_state).unwrap(),
    )
    .expect("seed build-state.json");

    let mut cmd = Command::cargo_bin("lpm-rs").expect("lpm-rs binary");
    cmd.current_dir(project.path());
    cmd.env("HOME", home.path());
    cmd.env("LPM_HOME", home.path().join(".lpm"));
    cmd.env("NO_COLOR", "1");
    cmd.env("LPM_NO_UPDATE_CHECK", "1");
    cmd.env("LPM_FORCE_FILE_AUTH", "1");
    cmd.env("LPM_TEST_FAST_SCRYPT", "1");
    cmd.env("LPM_FORCE_FILE_VAULT", "1");
    cmd.env("LPM_DISABLE_HOST_CLI_AUTH", "1");
    cmd.env(
        "LPM_SECURITY_POLICY_PATH",
        home.path().join(".lpm/security-policy.toml"),
    );
    cmd.env_remove("LPM_TOKEN");
    cmd.env_remove("LPM_LINKER");
    cmd.env("LPM_STORE_VERSION", "v1");
    (cmd, project, home)
}

/// Without `--yes` / `--list` / `<pkg>`, `lpm approve-scripts` enters
/// the interactive walk — which requires a TTY. assert_cmd inherits a
/// non-TTY stdin from the test runner, so the walk-time TTY guard must
/// fire with a helpful error pointing at the three non-interactive
/// alternatives.
#[test]
fn approve_scripts_interactive_walk_without_tty_fails_with_helpful_alternatives() {
    let (mut cmd, _project, _home) = lpm_isolated();

    let output = cmd
        .arg("approve-scripts")
        .output()
        .expect("failed to run lpm approve-scripts");

    assert!(
        !output.status.success(),
        "interactive walk without TTY must exit non-zero, got stdout: {}",
        String::from_utf8_lossy(&output.stdout),
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("TTY") || stderr.contains("tty") || stderr.contains("requires"),
        "stderr must surface the TTY requirement, got:\n{stderr}",
    );
    assert!(
        stderr.contains("--yes") && stderr.contains("--list"),
        "stderr must guide the user to non-interactive alternatives, got:\n{stderr}",
    );
}

/// `lpm --json approve-scripts` in a non-TTY shell emits an error
/// envelope on stdout. Per finding #74, the `--json`-specific guard
/// fires BEFORE the TTY gate (since every `--json` caller is
/// non-interactive by definition, the TTY message was always
/// unhelpful for the CI/agent case). The contract pinned here:
///
/// 1. stdout contains a valid JSON envelope, with `success: false`
///    and a populated `error` field.
/// 2. Exit code is `1` — the envelope's `success` field and the
///    process exit code must agree (finding #73 contract).
/// 3. The error message explicitly names the `--json`-compatible
///    flag pairs (`--list --json`, `--yes --json`, `<pkg> --json`)
///    so the user knows EXACTLY which fix to apply, instead of the
///    pre-fix generic "requires a TTY" hint.
#[test]
fn approve_scripts_interactive_with_json_emits_failure_envelope_on_stdout() {
    let (mut cmd, _project, _home) = lpm_isolated();

    let output = cmd
        .args(["--json", "approve-scripts"])
        .output()
        .expect("failed to run lpm --json approve-scripts");

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let envelope: serde_json::Value = serde_json::from_str(&stdout).unwrap_or_else(|e| {
        panic!(
            "--json approve-scripts must emit a valid JSON envelope on stdout: {e}\n---\n{stdout}"
        )
    });

    assert_eq!(
        envelope["success"],
        serde_json::json!(false),
        "envelope must report success=false in this error path: {envelope}"
    );

    assert_eq!(
        output.status.code(),
        Some(1),
        "exit code must mirror envelope success=false → 1 \
         (got code={:?}, envelope={envelope})",
        output.status.code(),
    );

    let error_msg = envelope["error"]
        .as_str()
        .expect("envelope must carry an error string");
    assert!(
        error_msg.contains("cannot be combined with `--json`"),
        "error must surface the --json-specific guard message, not the \
         generic TTY one (finding #74): got {error_msg:?}",
    );
    assert!(
        error_msg.contains("--list --json")
            && error_msg.contains("--yes --json")
            && error_msg.contains("<pkg> --json"),
        "error must name every `--json`-compatible flag pair so the \
         user knows the exact fix, got: {error_msg:?}",
    );
}
