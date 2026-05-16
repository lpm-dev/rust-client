//! Argv-contract integration tests for
//! `lpm-sandbox-helper.exe`.
//!
//! Tier: cli-binary (integration) — covers the argv → exit-code
//! contract that the lib-tier unit tests can't exercise on its own
//! (those tests pin the parser via `parse_argv`; this file pins the
//! same shape via the real `cargo build`-produced binary). Locates
//! the binary through `assert_cmd::Command::cargo_bin`, which
//! consults `CARGO_BIN_EXE_lpm-sandbox-helper` — plain
//! `Command::new("lpm-sandbox-helper")` would not find it in the
//! cargo test environment.
//!
//! Each test corresponds to one named branch in
//! [`crates/lpm-sandbox/src/bin/lpm-sandbox-helper.rs`]'s
//! `windows_main::run` dispatch so a failure here names a specific
//! contract regression.

#![cfg(target_os = "windows")]

use assert_cmd::Command;

const EXIT_ARGV_PARSE: i32 = 64;
const EXIT_PROTOCOL_MISMATCH: i32 = 65;

const TEST_APPCONTAINER_NAME: &str = "LpmSandboxHelperIntegrationTest";

/// Returns the standard minimal argv slice with the bin path,
/// missing only the program tail. Tests append `--` + program +
/// program args.
fn minimal_argv<'a>() -> Vec<&'a str> {
    vec![
        "--protocol-version",
        "1",
        "--appcontainer-name",
        TEST_APPCONTAINER_NAME,
        "--stdio-stdin",
        "null",
        "--stdio-stdout",
        "null",
        "--stdio-stderr",
        "null",
    ]
}

#[test]
fn helper_rejects_protocol_version_mismatch_naming_remediation() {
    let mut argv = minimal_argv();
    // Bump the version value.
    argv[1] = "999";
    argv.extend(["--", r"C:\Windows\System32\whoami.exe"]);
    let assert = Command::cargo_bin("lpm-sandbox-helper")
        .expect("locate built helper via CARGO_BIN_EXE")
        .args(&argv)
        .assert()
        .failure();
    let out = assert.get_output();
    assert_eq!(
        out.status.code(),
        Some(EXIT_PROTOCOL_MISMATCH),
        "protocol-version mismatch must exit {EXIT_PROTOCOL_MISMATCH}; got stderr:\n{}",
        String::from_utf8_lossy(&out.stderr),
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("protocol version") && stderr.contains("Reinstall lpm"),
        "stderr must name the remediation; got: {stderr}",
    );
}

#[test]
fn helper_rejects_argv_without_separator() {
    // Drop the `--` (and program tail). Helper parser refuses with
    // a clear `MissingSeparator` error and exits with the
    // argv-parse code.
    let argv = minimal_argv();
    let assert = Command::cargo_bin("lpm-sandbox-helper")
        .expect("locate built helper")
        .args(&argv)
        .assert()
        .failure();
    let out = assert.get_output();
    assert_eq!(
        out.status.code(),
        Some(EXIT_ARGV_PARSE),
        "missing-separator must exit {EXIT_ARGV_PARSE}; got: {}",
        String::from_utf8_lossy(&out.stderr),
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("`--` separator"),
        "stderr must name the missing separator; got: {stderr}",
    );
}

#[test]
fn helper_rejects_missing_appcontainer_name() {
    // Build a valid argv but omit `--appcontainer-name` to pin the
    // MissingFlag branch end-to-end.
    let argv = vec![
        "--protocol-version",
        "1",
        "--stdio-stdin",
        "null",
        "--stdio-stdout",
        "null",
        "--stdio-stderr",
        "null",
        "--",
        r"C:\Windows\System32\whoami.exe",
    ];
    let assert = Command::cargo_bin("lpm-sandbox-helper")
        .expect("locate built helper")
        .args(&argv)
        .assert()
        .failure();
    let out = assert.get_output();
    assert_eq!(out.status.code(), Some(EXIT_ARGV_PARSE));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("appcontainer-name"),
        "stderr must name the missing flag; got: {stderr}",
    );
}

#[test]
fn helper_rejects_unknown_flag_naming_offender_with_reinstall_remediation() {
    // Unknown flags catch the case where the parent's wire-version
    // is ahead of the helper. The helper's error names the offender
    // and the named remediation ("reinstall lpm").
    let mut argv = minimal_argv();
    argv.insert(0, "--brand-new-flag-from-the-future");
    argv.extend(["--", r"C:\Windows\System32\whoami.exe"]);
    let assert = Command::cargo_bin("lpm-sandbox-helper")
        .expect("locate built helper")
        .args(&argv)
        .assert()
        .failure();
    let out = assert.get_output();
    assert_eq!(out.status.code(), Some(EXIT_ARGV_PARSE));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("--brand-new-flag-from-the-future"),
        "stderr must name the offending flag; got: {stderr}",
    );
    assert!(
        stderr.contains("reinstall lpm"),
        "stderr must name the reinstall remediation; got: {stderr}",
    );
}

#[test]
fn helper_runs_trivial_command_under_appcontainer_and_propagates_exit_zero() {
    // The headline forward-path: spawn `whoami.exe`, which the
    // AppContainer permits via ALL_APPLICATION_PACKAGES on System32.
    // Exit code 0 propagates back through the helper without any
    // setup failure on the DACL / Job Object / STARTUPINFOEXW
    // path.
    let mut argv = minimal_argv();
    argv.extend(["--", r"C:\Windows\System32\whoami.exe"]);
    Command::cargo_bin("lpm-sandbox-helper")
        .expect("locate built helper")
        .args(&argv)
        .assert()
        .success();
}

#[test]
fn helper_propagates_nonzero_exit_code_from_lifecycle_child() {
    // cmd /c exit 7 — verifies that GetExitCodeProcess + the
    // u32→i32 cast in run_appcontainer_spawn surface the lifecycle
    // child's exit code untouched.
    let mut argv = minimal_argv();
    argv.extend(["--", r"C:\Windows\System32\cmd.exe", "/c", "exit", "7"]);
    let assert = Command::cargo_bin("lpm-sandbox-helper")
        .expect("locate built helper")
        .args(&argv)
        .assert()
        .failure();
    let out = assert.get_output();
    assert_eq!(
        out.status.code(),
        Some(7),
        "lifecycle exit code 7 must propagate verbatim through the helper",
    );
}
