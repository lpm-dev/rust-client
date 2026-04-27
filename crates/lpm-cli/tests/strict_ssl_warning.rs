//! Phase 58.1 day-3 — `strict-ssl=false` install-start warning surface.
//!
//! Subprocess test (per `feedback_cli_subprocess_tests_for_stream_separation`):
//! unit tests can't observe fd 1 vs fd 2 separation, so the only way to
//! pin the contract "warning fires on stderr at install start, citing
//! the contributing source/line" is from a real process invocation.
//!
//! ## What's asserted
//!
//! 1. Install with an empty-deps `package.json` and `.npmrc strict-ssl=false`
//!    completes (exit 0) — `strict-ssl=false` is advisory; it does NOT
//!    block install.
//! 2. **stderr** contains the loud warning text mentioning `DISABLED`.
//! 3. The warning cites the source file and line number where the
//!    setting came from (e.g., `<dir>/.npmrc:1`). This is the
//!    diagnostic-tool property — a user with multiple `.npmrc` layers
//!    (system / user / project) can see exactly which file flipped the
//!    flag.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};

struct CommandOutput {
    status: ExitStatus,
    stdout: String,
    stderr: String,
}

fn project_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir()
        .join("lpm-phase58.1-strict-ssl-warning")
        .join(format!("{name}.{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn write_empty_manifest(dir: &Path) {
    let manifest = serde_json::json!({
        "name": "phase58.1-strict-ssl-warning",
        "version": "1.0.0",
        "dependencies": {},
    });
    fs::write(
        dir.join("package.json"),
        serde_json::to_string_pretty(&manifest).unwrap(),
    )
    .unwrap();
}

fn run_lpm(cwd: &Path, args: &[&str]) -> CommandOutput {
    let exe = env!("CARGO_BIN_EXE_lpm-rs");
    let home = cwd.join(".home");
    fs::create_dir_all(&home).unwrap();

    let mut command = Command::new(exe);
    command
        .args(args)
        .current_dir(cwd)
        .env("HOME", &home)
        .env("NO_COLOR", "1")
        .env("LPM_NO_UPDATE_CHECK", "1")
        .env("LPM_DISABLE_TELEMETRY", "1")
        .env("LPM_FORCE_FILE_VAULT", "1")
        .env_remove("LPM_TOKEN")
        .env_remove("RUST_LOG")
        // Pin LPM Worker to an unreachable port so any incidental
        // network call refuses-connect rather than silently hitting prod.
        .env("LPM_REGISTRY_URL", "http://127.0.0.1:1");

    let output = command.output().expect("failed to spawn lpm-rs");
    CommandOutput {
        status: output.status,
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
    }
}

#[test]
fn strict_ssl_false_emits_loud_warning_with_source_citation() {
    let dir = project_dir("strict_ssl_false");
    write_empty_manifest(&dir);
    let npmrc_path = dir.join(".npmrc");
    fs::write(&npmrc_path, "strict-ssl=false\n").unwrap();

    let out = run_lpm(&dir, &["install"]);

    // Install with empty deps must succeed — strict-ssl is advisory,
    // never a blocker.
    if !out.status.success() {
        panic!(
            "install with empty deps must succeed even with strict-ssl=false\n\
             exit: {:?}\nstdout:\n{}\nstderr:\n{}",
            out.status.code(),
            out.stdout,
            out.stderr,
        );
    }

    // Loud warning must be on stderr, mentioning DISABLED and citing
    // the contributing source/line. This is the user's diagnostic
    // signal: when they see it in a CI log, they can find the .npmrc
    // line that flipped the flag.
    assert!(
        out.stderr.contains("DISABLED"),
        "stderr must contain DISABLED warning marker\nstderr:\n{}",
        out.stderr,
    );
    let cite = format!("{}:1", npmrc_path.display());
    assert!(
        out.stderr.contains(&cite),
        "stderr must cite the contributing source:line ({})\nstderr:\n{}",
        cite,
        out.stderr,
    );
}

#[test]
fn no_strict_ssl_setting_emits_no_warning() {
    // Negative case: an empty `.npmrc` (or none at all) must NOT emit
    // the disabled-verification warning. Guards against a future change
    // that fires the warning on `Some(true)` or `None` by accident.
    let dir = project_dir("no_strict_ssl");
    write_empty_manifest(&dir);
    fs::write(dir.join(".npmrc"), "registry=https://example.com/\n").unwrap();

    let out = run_lpm(&dir, &["install"]);
    if !out.status.success() {
        panic!(
            "install must succeed with bland .npmrc\n\
             exit: {:?}\nstdout:\n{}\nstderr:\n{}",
            out.status.code(),
            out.stdout,
            out.stderr,
        );
    }
    assert!(
        !out.stderr
            .contains("TLS certificate verification is DISABLED"),
        "stderr must NOT contain the strict-ssl warning when not set\nstderr:\n{}",
        out.stderr,
    );
}
