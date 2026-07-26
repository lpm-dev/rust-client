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

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;

use assert_cmd::Command;
use windows_sys::Win32::Security::Isolation::DeleteAppContainerProfile;

const EXIT_ARGV_PARSE: i32 = 64;
const EXIT_PROTOCOL_MISMATCH: i32 = 65;

const TEST_APPCONTAINER_NAME: &str = "LpmSandboxHelperIntegrationTest";

struct TemporaryAppContainerProfile {
    wide_name: Vec<u16>,
    cleanup_required: bool,
}

impl TemporaryAppContainerProfile {
    fn new(name: &str) -> Self {
        Self {
            wide_name: OsStr::new(name).encode_wide().chain(Some(0)).collect(),
            cleanup_required: true,
        }
    }

    fn delete(&mut self) -> i32 {
        // SAFETY: `wide_name` is null-terminated and remains alive for the call.
        let hresult = unsafe { DeleteAppContainerProfile(self.wide_name.as_ptr()) };
        if hresult == 0 {
            self.cleanup_required = false;
        }
        hresult
    }

    fn assert_deleted(mut self) {
        let hresult = self.delete();
        assert_eq!(
            hresult, 0,
            "temporary AppContainer profile cleanup failed with HRESULT 0x{hresult:08X}"
        );
    }
}

impl Drop for TemporaryAppContainerProfile {
    fn drop(&mut self) {
        if self.cleanup_required {
            let hresult = self.delete();
            if hresult != 0 {
                eprintln!(
                    "temporary AppContainer profile cleanup failed with HRESULT 0x{hresult:08X}"
                );
            }
        }
    }
}

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
fn helper_supports_concurrent_first_use_and_deletes_temporary_appcontainer_profile() {
    const HELPER_COUNT: usize = 16;

    let unique_suffix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock must be after the Unix epoch")
        .as_nanos();
    let appcontainer_name = format!(
        "LpmConcurrentHelperTest{:x}{unique_suffix:x}",
        std::process::id()
    );
    let temporary_profile = TemporaryAppContainerProfile::new(&appcontainer_name);
    let appcontainer_name = std::sync::Arc::new(appcontainer_name);
    let start = std::sync::Arc::new(std::sync::Barrier::new(HELPER_COUNT));

    let mut helpers = Vec::with_capacity(HELPER_COUNT);
    for _ in 0..HELPER_COUNT {
        let appcontainer_name = std::sync::Arc::clone(&appcontainer_name);
        let start = std::sync::Arc::clone(&start);
        helpers.push(std::thread::spawn(move || {
            let mut command = Command::cargo_bin("lpm-sandbox-helper")
                .map_err(|error| format!("locate built helper: {error}"))?;
            command.args([
                "--protocol-version",
                "1",
                "--appcontainer-name",
                appcontainer_name.as_str(),
                "--stdio-stdin",
                "null",
                "--stdio-stdout",
                "null",
                "--stdio-stderr",
                "null",
                "--",
                r"C:\Windows\System32\whoami.exe",
            ]);
            start.wait();
            command
                .output()
                .map_err(|error| format!("run concurrent helper: {error}"))
        }));
    }

    let failures = helpers
        .into_iter()
        .enumerate()
        .filter_map(|(index, helper)| match helper.join() {
            Ok(Ok(output)) if output.status.success() => None,
            Ok(Ok(output)) => Some(format!(
                "helper {index}: status {:?}\nstderr: {}",
                output.status.code(),
                String::from_utf8_lossy(&output.stderr)
            )),
            Ok(Err(error)) => Some(format!("helper {index}: {error}")),
            Err(_) => Some(format!(
                "helper {index}: concurrent helper thread panicked before returning its output"
            )),
        })
        .collect::<Vec<_>>();

    temporary_profile.assert_deleted();

    assert!(
        failures.is_empty(),
        "all helpers sharing a freshly created AppContainer profile must succeed:\n{}",
        failures.join("\n")
    );
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
        "lifecycle exit code 7 must propagate verbatim through the helper; stderr:\n{}",
        String::from_utf8_lossy(&out.stderr),
    );
}
