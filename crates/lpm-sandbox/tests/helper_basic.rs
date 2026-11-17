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
use std::sync::LazyLock;

use assert_cmd::Command;
use windows_sys::Win32::Security::Isolation::DeleteAppContainerProfile;

static PROTOCOL_VERSION: LazyLock<String> =
    LazyLock::new(|| lpm_sandbox::helper_protocol::PROTOCOL_VERSION.to_string());

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
        PROTOCOL_VERSION.as_str(),
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

/// lpm asks the helper beside it which release it comes from, to tell one
/// an earlier release left there.
#[test]
fn helper_reports_the_release_it_comes_from() {
    let assert = Command::cargo_bin("lpm-sandbox-helper")
        .expect("locate built helper via CARGO_BIN_EXE")
        .arg(lpm_sandbox::helper_protocol::RELEASE_FLAG)
        .assert()
        .success();
    assert_eq!(
        String::from_utf8_lossy(&assert.get_output().stdout).trim(),
        lpm_sandbox::helper_protocol::HELPER_RELEASE
    );
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

/// The helper's exit code says how its run went even when the process
/// that would read why is gone, as after its caller has ended.
#[test]
fn helper_keeps_its_exit_code_when_nothing_reads_its_stderr() {
    use std::process::Stdio;

    let (reader, stderr) = std::io::pipe().expect("make a pipe");
    drop(reader);

    let status = std::process::Command::new(assert_cmd::cargo::cargo_bin("lpm-sandbox-helper"))
        .args(minimal_argv())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(stderr)
        .status()
        .expect("start the helper");

    assert_eq!(status.code(), Some(EXIT_ARGV_PARSE));
}

#[test]
fn helper_rejects_missing_appcontainer_name() {
    // Build a valid argv but omit `--appcontainer-name` to pin the
    // MissingFlag branch end-to-end.
    let argv = vec![
        "--protocol-version",
        PROTOCOL_VERSION.as_str(),
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
fn helpers_started_together_for_one_new_profile_all_run_and_leave_it_to_be_deleted() {
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
                PROTOCOL_VERSION.as_str(),
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

/// The helper goes on after a sweep record it can't read, which it only
/// logs. Its log goes to stderr, the one place its caller reads.
#[test]
fn helper_writes_what_it_warns_of_to_stderr() {
    let unique_suffix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock must be after the Unix epoch")
        .as_nanos();
    let name = format!("LpmWarningTest{:x}{unique_suffix:x}", std::process::id());
    let _profile = TemporaryAppContainerProfile::new(&name);
    let folder = tempfile::tempdir().expect("make a folder");
    let sweep_record = folder.path().join("swept-trees.json");
    std::fs::write(&sweep_record, "not a record").expect("write the record");
    let sweep_record = sweep_record.to_str().expect("a UTF-8 path");
    let mut argv = minimal_argv();
    argv[3] = &name;
    argv.extend([
        "--sweep-record",
        sweep_record,
        "--",
        r"C:\Windows\System32\whoami.exe",
    ]);

    let assert = Command::cargo_bin("lpm-sandbox-helper")
        .expect("locate built helper")
        .args(&argv)
        .timeout(std::time::Duration::from_secs(60))
        .assert()
        .success();

    let stderr = String::from_utf8_lossy(&assert.get_output().stderr);
    assert!(
        stderr.contains("lpm-sandbox-helper: warning: ignoring unreadable")
            && stderr.contains("swept-trees.json"),
        "the helper should say that it ignored the record; got: {stderr}",
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

/// Windows ends no process with the one that started it, so the helper
/// ends its script when its own caller goes. The caller here is a
/// `cmd.exe` the test can end; the script is another that waits for input
/// nobody sends.
#[test]
fn a_script_ends_when_the_process_that_started_its_helper_does() {
    use std::io::Read;
    use std::os::windows::process::CommandExt;
    use std::process::Stdio;
    use std::time::{Duration, Instant};

    let unique_suffix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock must be after the Unix epoch")
        .as_nanos();
    let name = format!("LpmCallerEndsTest{:x}{unique_suffix:x}", std::process::id());
    let _profile = TemporaryAppContainerProfile::new(&name);
    let helper = assert_cmd::cargo::cargo_bin("lpm-sandbox-helper");
    let mut caller = std::process::Command::new(r"C:\Windows\System32\cmd.exe");
    caller
        .raw_arg(format!(
            "/d /s /c \"\"{}\" --protocol-version {} --appcontainer-name {name} \
             --stdio-stdin inherit --stdio-stdout inherit --stdio-stderr null \
             -- C:\\Windows\\System32\\cmd.exe /d /k\"",
            helper.display(),
            PROTOCOL_VERSION.as_str(),
        ))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let mut caller = caller.spawn().expect("start the helper's caller");
    let input_nobody_sends = caller.stdin.take().expect("the caller's stdin");
    let mut output = caller.stdout.take().expect("the caller's stdout");
    let (said, heard) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut buffer = [0u8; 256];
        loop {
            let read = output.read(&mut buffer).unwrap_or(0);
            if said.send(read).is_err() || read == 0 {
                return;
            }
        }
    });
    // Neither the caller nor the helper writes anything, so the first
    // bytes are the script's prompt.
    let started = heard.recv_timeout(Duration::from_secs(60));
    assert!(
        matches!(started, Ok(read) if read > 0),
        "the script never started: {started:?}"
    );

    caller.kill().expect("end the helper's caller");
    caller.wait().expect("reap the helper's caller");

    // The pipe closes once the helper and the script have both let go of it.
    let deadline = Instant::now() + Duration::from_secs(20);
    let closed = loop {
        match heard.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
            Ok(0) => break true,
            Ok(_) => {}
            Err(_) => break false,
        }
    };
    // The end of its input stops the script too, so a failure here leaves
    // nothing running.
    drop(input_nobody_sends);
    assert!(
        closed,
        "the script outlived the process that started its helper"
    );
}
