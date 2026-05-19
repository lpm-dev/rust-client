//! Cli-binary tier — `lpm config sigstore` wizard contract.
//!
//! **Tier-placement justification (per CLAUDE.md `# Testing Tier
//! Discipline`):** intentionally minimal binary-surface repro for the
//! TTY-interactive contract. The interactive `cliclack::select` /
//! `cliclack::confirm` walk path (no `--set`, no piped stdin)
//! cannot be exercised from the workflow tier without a real PTY;
//! the assertions below confirm the guards that protect the
//! interactive walk fire correctly when stdin is not a TTY. The
//! non-interactive `--set` paths plus the `read_/persist_/announce_`
//! seams are exhaustively covered by inline `#[cfg(test)]` tests in
//! [`crates/lpm-cli/src/commands/config.rs`].
//!
//! What this file pins specifically:
//!
//! 1. `lpm config sigstore --set off` succeeds without a TTY and
//!    writes `[sigstore] verify = "off"` to the isolated HOME's
//!    `.lpm/config.toml`.
//! 2. `lpm config sigstore` (no `--set`) outside a TTY fails with the
//!    "requires a TTY" message naming the valid `--set` values, so a
//!    user who accidentally runs the wizard in CI gets actionable
//!    diagnostics instead of a hang.
//! 3. `lpm config --json sigstore --set warn` emits the
//!    `{"success": true, "sigstore": {"verify": "warn"}}` shape the
//!    rest of the wizard family uses (matches `announce_*_set`).

use assert_cmd::Command;
use tempfile::TempDir;

/// Build a `lpm-rs` Command in an isolated HOME. Returns the
/// `(command, project_dir, home_dir)` so the caller can hold the
/// TempDir guards for the duration of the test and inspect the
/// resulting config file. Pattern mirrors
/// `approve_scripts_interactive_tty::lpm_isolated`.
fn lpm_isolated() -> (Command, TempDir, TempDir) {
    let project = TempDir::new().expect("create temp project");
    let home = TempDir::new().expect("create temp home");

    std::fs::write(
        project.path().join("package.json"),
        r#"{"name":"sigstore-wizard-test","version":"1.0.0"}"#,
    )
    .expect("seed package.json");

    let mut cmd = Command::cargo_bin("lpm-rs").expect("lpm-rs binary");
    cmd.current_dir(project.path());
    cmd.env("HOME", home.path());
    cmd.env("LPM_HOME", home.path().join(".lpm"));
    cmd.env("NO_COLOR", "1");
    cmd.env("LPM_NO_UPDATE_CHECK", "1");
    cmd.env("LPM_DISABLE_TELEMETRY", "1");
    cmd.env_remove("RUST_LOG");
    cmd.env_remove("LPM_PROVENANCE_ENFORCE");
    (cmd, project, home)
}

fn read_config_toml(home: &TempDir) -> String {
    let path = home.path().join(".lpm").join("config.toml");
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("config.toml at {} not readable: {e}", path.display(),))
}

/// `--set off` is the persistent fleet-wide opt-out path. It must
/// succeed without a TTY (CI pipelines, automation, ansible-style
/// provisioning) and write the `[sigstore].verify` table key. If this
/// regresses, an operator-machine deploy script that flipped the knob
/// to `off` would silently fail and leave the operator in the default
/// `deny` posture — possibly the right thing, but not what they asked
/// for, and silent.
#[test]
fn sigstore_wizard_set_off_succeeds_without_tty_and_persists_to_config_toml() {
    let (mut cmd, _project, home) = lpm_isolated();

    let output = cmd
        .args(["config", "sigstore", "--set", "off"])
        .output()
        .expect("failed to run lpm config sigstore --set off");

    assert!(
        output.status.success(),
        "lpm config sigstore --set off must succeed without a TTY;\n\
         stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let cfg = read_config_toml(&home);
    assert!(
        cfg.contains("[sigstore]"),
        "[sigstore] table must be present after --set off; got config.toml:\n{cfg}",
    );
    assert!(
        cfg.contains("verify = \"off\""),
        "verify = \"off\" must be persisted under [sigstore]; got config.toml:\n{cfg}",
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{stdout}{stderr}");
    assert!(
        !combined.contains("Are you sure"),
        "--set off path MUST NOT prompt — the wizard's stern confirm \
         is the interactive-only guard. Presence of the prompt here \
         means the --set form leaked into the interactive branch.\n\
         got:\n{combined}",
    );
}

/// Without `--set` and without a TTY (stdin is piped from
/// `assert_cmd`), `lpm config sigstore` must fail loudly rather than
/// hang on the `cliclack::select` blocking read. The error must name
/// the three valid `--set` values so the user has actionable
/// diagnostics.
#[test]
fn sigstore_wizard_without_set_and_without_tty_errors_with_actionable_diagnostic() {
    let (mut cmd, _project, _home) = lpm_isolated();

    let output = cmd
        .args(["config", "sigstore"])
        .output()
        .expect("failed to run lpm config sigstore");

    assert!(
        !output.status.success(),
        "lpm config sigstore (no --set, no TTY) MUST fail — otherwise \
         the wizard would block on cliclack waiting for input that \
         will never arrive;\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let combined = format!("{stdout}{stderr}");
    assert!(
        combined.contains("TTY") || combined.contains("--set"),
        "error message must name the TTY requirement or the --set \
         escape hatch so the user knows what to do next;\n\
         got:\n{combined}",
    );
}

/// `--json` is the machine-readable announce path. Wizards in the
/// security-posture family (`scripts`, `triage`, `sandbox`, and now
/// `sigstore`) all emit `{"success": true, "<topic>": {...}}` after a
/// successful `--set`. Pin the sigstore wizard's announce shape so a
/// future refactor doesn't accidentally break the
/// `{"success": true, "sigstore": {"verify": "<v>"}}` contract that
/// downstream automation reads.
#[test]
fn sigstore_wizard_set_warn_with_json_announces_success_envelope() {
    let (mut cmd, _project, _home) = lpm_isolated();

    let output = cmd
        .args(["config", "--json", "sigstore", "--set", "warn"])
        .output()
        .expect("failed to run lpm config --json sigstore --set warn");

    assert!(
        output.status.success(),
        "lpm config --json sigstore --set warn must succeed;\n\
         stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let envelope: serde_json::Value = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("--json stdout must parse as JSON: {e}\nraw stdout: {stdout}"));

    assert_eq!(
        envelope["success"],
        serde_json::json!(true),
        "envelope `success` must be true; got: {envelope}",
    );
    assert_eq!(
        envelope["sigstore"]["verify"],
        serde_json::json!("warn"),
        "envelope must carry the persisted verify value under `sigstore.verify`; \
         got: {envelope}",
    );
}

/// `--set` rejects values outside the documented set
/// `deny | warn | off`. The error must name the valid values so the
/// operator can fix the call without diving into `lpm config --help`.
/// Run inline at the binary tier (not just the unit-test tier) so a
/// future refactor that changes the clap dispatch — e.g., adds
/// validation at the clap layer — still surfaces the right
/// diagnostic to actual `lpm-rs` users.
#[test]
fn sigstore_wizard_set_rejects_unknown_value_with_actionable_diagnostic() {
    let (mut cmd, _project, _home) = lpm_isolated();

    let output = cmd
        .args(["config", "sigstore", "--set", "nuke-it"])
        .output()
        .expect("failed to run lpm config sigstore --set nuke-it");

    assert!(
        !output.status.success(),
        "lpm config sigstore --set <invalid> MUST fail;\n\
         stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let combined = format!("{stdout}{stderr}");
    assert!(
        combined.contains("deny") && combined.contains("warn") && combined.contains("off"),
        "rejection diagnostic must name all three valid values \
         (deny, warn, off);\ngot:\n{combined}",
    );
}
