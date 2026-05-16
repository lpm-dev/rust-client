//! Workflow tests for the process-wide color policy.
//!
//! Pins the GPT-audit-2026-05-15 fixes:
//! - `--color` / `NO_COLOR` / `FORCE_COLOR` are honored on the
//!   pre-`Cli::parse` fast paths (top-of-`main()` `--version` notice
//!   and bare-install fast lane), not just inside `async_main`.
//! - `FORCE_COLOR=0` explicitly disables (was previously treated as
//!   truthy, breaking CI workflows that opted out via `FORCE_COLOR=0`).
//!
//! Bare `lpm install` fast-lane testing belongs in the install workflow
//! tests (which already exercise a fresh `TempProject`); the smoke-level
//! version-notice path below is the regression guard that proves the
//! policy initializes before *any* styled output.

mod support;

use support::{TempProject, lpm};

/// Seed `<home>/.lpm/update-check.json` so `lpm --version` actually prints
/// the colored "Update available" notice. Without the cache file the
/// banner short-circuits and the test exercises only the plain "lpm
/// {version}" line, which never had ANSI in the first place — i.e.
/// would be a false-pass.
fn seed_update_notice(project: &TempProject, latest_version: &str) {
    let lpm_dir = project.home().join(".lpm");
    std::fs::create_dir_all(&lpm_dir).expect("create ~/.lpm");
    let payload = format!(r#"{{"latest":"{latest_version}","lastCheck":99999999999}}"#);
    std::fs::write(lpm_dir.join("update-check.json"), payload).expect("write update-check.json");
}

#[test]
fn version_fast_path_emits_no_ansi_under_no_color() {
    let project = TempProject::empty(r#"{"name":"colortest","version":"1.0.0"}"#);
    // Stage a fake newer version so the banner code path runs.
    seed_update_notice(&project, "99999.0.0");

    let output = lpm(&project)
        .args(["--version"])
        .output()
        .expect("failed to run lpm --version");

    assert!(output.status.success(), "--version must succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stdout.contains("lpm "),
        "--version must print the version line, got stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    // Harness sets `NO_COLOR=1` (see `support/mod.rs`). The notice path
    // styles its banner via [`Painted`]; init must fire before the
    // top-of-`main()` `--version` fast path or this leaks ANSI.
    let combined = format!("{stdout}{stderr}");
    assert!(
        !combined.contains('\x1b'),
        "--version + update notice must contain no ANSI escape under NO_COLOR=1, got:\n{combined:?}"
    );
}

#[test]
fn version_emits_ansi_under_force_color() {
    let project = TempProject::empty(r#"{"name":"colortest","version":"1.0.0"}"#);
    seed_update_notice(&project, "99999.0.0");

    let output = lpm(&project)
        .args(["--version"])
        .env_remove("NO_COLOR")
        .env("FORCE_COLOR", "1")
        .output()
        .expect("failed to run lpm --version under FORCE_COLOR=1");

    assert!(output.status.success(), "--version must succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    // `FORCE_COLOR=1` must force-on the notice's styling even when stdout
    // is not a TTY (assert_cmd captures stdout, so it never is).
    assert!(
        stdout.contains('\x1b'),
        "FORCE_COLOR=1 must force ANSI in the update notice, got:\n{stdout:?}"
    );
}

#[test]
fn force_color_zero_disables_even_without_no_color() {
    let project = TempProject::empty(r#"{"name":"colortest","version":"1.0.0"}"#);
    seed_update_notice(&project, "99999.0.0");

    let output = lpm(&project)
        .args(["--version"])
        // Drop NO_COLOR so the only disable signal is FORCE_COLOR=0.
        // Pre-fix this was parsed as truthy and the notice still leaked.
        .env_remove("NO_COLOR")
        .env("FORCE_COLOR", "0")
        .output()
        .expect("failed to run lpm --version under FORCE_COLOR=0");

    assert!(output.status.success(), "--version must succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{stdout}{stderr}");
    assert!(
        !combined.contains('\x1b'),
        "FORCE_COLOR=0 must disable ANSI (per supports-color convention), got:\n{combined:?}"
    );
}

#[test]
fn color_flag_never_disables_under_force_color_one() {
    let project = TempProject::empty(r#"{"name":"colortest","version":"1.0.0"}"#);
    seed_update_notice(&project, "99999.0.0");

    // `-V` (clap-parsed short version flag) is used here instead of
    // `--version` (the top-of-`main()` argv pre-check that demands the
    // flag be the SOLE argument). The clap-parsed path enters
    // `async_main` and re-runs `color_policy::init` after `Cli::parse`,
    // which honors `--color`. The top-of-`main()` early init has also
    // already honored it via `peek_color_choice_from_argv`, so this test
    // pins the precedence regardless of which init path won.
    let output = lpm(&project)
        .args(["--color=never", "-V"])
        .env_remove("NO_COLOR")
        .env("FORCE_COLOR", "1")
        .output()
        .expect("failed to run lpm --color=never -V");

    assert!(
        output.status.success(),
        "-V must succeed; stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{stdout}{stderr}");
    // `--color=never` is the canonical override — must beat FORCE_COLOR.
    // Honored via the argv pre-scan in `color_policy::peek_color_choice_from_argv`,
    // because clap hasn't run yet at the top of `fn main()`.
    assert!(
        !combined.contains('\x1b'),
        "--color=never must override FORCE_COLOR=1, got:\n{combined:?}"
    );
}
