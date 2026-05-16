//! Filesystem-grant integration tests for
//! `lpm-sandbox-helper.exe`.
//!
//! Tier: cli-binary (integration). Pins the contract that:
//!
//! - `--writable-dir <path>` grants the AppContainer SID R+W+X on
//!   `<path>` and its descendants (so the lifecycle child can write
//!   inside it).
//! - `--readable-dir <path>` grants R+X only (the child can read
//!   but not write).
//! - Paths NOT listed in either argv set are denied — AppContainer's
//!   default-deny posture covers everything outside the allow-set
//!   union (other than the `ALL_APPLICATION_PACKAGES`-grant'd
//!   system paths like `C:\Windows\System32`).
//!
//! The mechanism under test is
//! [`crate::helper_appcontainer::grant_dacl_ace_to_tree`] driven
//! from real argv, which the lib-tier unit tests can't observe
//! (they pin the DACL grant function in isolation but don't pin
//! the lifecycle child's access pattern through the full spawn).

#![cfg(target_os = "windows")]

use assert_cmd::Command;
use std::fs;

const TEST_APPCONTAINER_NAME: &str = "LpmSandboxHelperIntegrationTest";

fn helper_argv_base() -> Vec<String> {
    vec![
        "--protocol-version".into(),
        "1".into(),
        "--appcontainer-name".into(),
        TEST_APPCONTAINER_NAME.into(),
        "--stdio-stdin".into(),
        "null".into(),
        "--stdio-stdout".into(),
        "piped".into(),
        "--stdio-stderr".into(),
        "piped".into(),
    ]
}

/// PowerShell one-liner that writes one line to a target file +
/// echoes "OK" on success. Used by the writable-dir test to prove
/// the lifecycle child can actually write where the helper granted
/// access.
fn ps_write_file(target: &str) -> String {
    format!(
        r#"
$ErrorActionPreference = 'Stop'
try {{
    [System.IO.File]::WriteAllText('{}', 'lpm-sandbox-helper-write-test')
    Write-Output 'OK'
}} catch {{
    Write-Error $_
    exit 1
}}
"#,
        target.replace('\\', "\\\\")
    )
}

/// PowerShell one-liner that reads a target file + echoes its
/// contents. Returns exit 0 with the contents on stdout if the
/// read succeeds; exits 1 with stderr error otherwise.
fn ps_read_file(target: &str) -> String {
    format!(
        r#"
$ErrorActionPreference = 'Stop'
try {{
    $content = Get-Content -Raw '{}'
    Write-Output $content
}} catch {{
    Write-Error $_
    exit 1
}}
"#,
        target.replace('\\', "\\\\")
    )
}

#[test]
fn helper_writable_dir_grant_lets_lifecycle_child_create_file() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let target = tmp.path().join("created-by-child.txt");

    let mut argv = helper_argv_base();
    argv.extend([
        "--writable-dir".into(),
        tmp.path().to_string_lossy().into_owned(),
        "--".into(),
        r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe".into(),
        "-NoProfile".into(),
        "-NonInteractive".into(),
        "-Command".into(),
        ps_write_file(&target.to_string_lossy()),
    ]);

    let out = Command::cargo_bin("lpm-sandbox-helper")
        .expect("locate helper")
        .args(&argv)
        .output()
        .expect("spawn helper");

    assert!(
        out.status.success(),
        "writable-dir grant should allow PowerShell to write; status: {:?}\nstdout: {}\nstderr: {}",
        out.status,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    assert!(
        target.exists(),
        "lifecycle child must have created the file under the writable-dir grant",
    );
    let body = fs::read_to_string(&target).expect("read back");
    assert_eq!(body, "lpm-sandbox-helper-write-test");
}

#[test]
fn helper_readable_dir_grant_lets_lifecycle_child_read_preexisting_file() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let target = tmp.path().join("preexisting.txt");
    fs::write(&target, "secret-content").expect("seed file");

    let mut argv = helper_argv_base();
    argv.extend([
        "--readable-dir".into(),
        tmp.path().to_string_lossy().into_owned(),
        "--".into(),
        r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe".into(),
        "-NoProfile".into(),
        "-NonInteractive".into(),
        "-Command".into(),
        ps_read_file(&target.to_string_lossy()),
    ]);

    let out = Command::cargo_bin("lpm-sandbox-helper")
        .expect("locate helper")
        .args(&argv)
        .output()
        .expect("spawn helper");

    assert!(
        out.status.success(),
        "readable-dir grant should allow PowerShell to read; status: {:?}\nstdout: {}\nstderr: {}",
        out.status,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("secret-content"),
        "lifecycle child must have read the seeded content under the readable-dir grant; got: {stdout}",
    );
}

#[test]
fn helper_denies_read_to_path_outside_any_allow_set() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let target = tmp.path().join("forbidden.txt");
    fs::write(&target, "should-not-be-readable").expect("seed file");

    // Argv supplies NO `--readable-dir` for the target. The
    // AppContainer SID gets no grant on this path → AppContainer's
    // default-deny posture rejects the read.
    let mut argv = helper_argv_base();
    argv.extend([
        "--".into(),
        r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe".into(),
        "-NoProfile".into(),
        "-NonInteractive".into(),
        "-Command".into(),
        ps_read_file(&target.to_string_lossy()),
    ]);

    let out = Command::cargo_bin("lpm-sandbox-helper")
        .expect("locate helper")
        .args(&argv)
        .output()
        .expect("spawn helper");

    assert!(
        !out.status.success(),
        "AppContainer must deny reads outside the allow-set; got success with stdout: {}",
        String::from_utf8_lossy(&out.stdout),
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    let combined = format!("{}\n{}", String::from_utf8_lossy(&out.stdout), stderr,);
    // Windows access denial surface — PowerShell wraps the Win32
    // ERROR_ACCESS_DENIED (5) as "Access to the path ... is denied"
    // / "UnauthorizedAccessException" depending on the API path.
    let denial_signal = combined.contains("Access to the path")
        || combined.contains("UnauthorizedAccessException")
        || combined.contains("access is denied")
        || combined.contains("Access is denied")
        || combined.contains("PermissionDenied");
    assert!(
        denial_signal,
        "expected an access-denied signal in the lifecycle child's output; got:\n{combined}",
    );
}

#[test]
fn helper_refuses_reparse_point_root_with_named_error() {
    // PR-1 contract: refuse a reparse-point root as a writable-dir
    // / readable-dir grant target. Same shape as the SACL refusal
    // pinned at `windows::tests::apply_low_il_label_refuses_reparse_point_root_*`
    // but for the AppContainer DACL path.
    //
    // Build a junction inside a tmpdir pointing at the parent
    // tmpdir, then ask the helper to grant on the junction. The
    // walker must refuse rather than follow.
    let tmp = tempfile::tempdir().expect("tempdir");
    let real_dir = tmp.path().join("real");
    let junction = tmp.path().join("junction");
    fs::create_dir(&real_dir).expect("create real dir");

    // `mklink /J <link> <target>` creates an NTFS directory
    // junction without admin (unlike symlinks).
    let status = std::process::Command::new("cmd")
        .args([
            "/c",
            "mklink",
            "/J",
            &junction.to_string_lossy(),
            &real_dir.to_string_lossy(),
        ])
        .status();
    let Ok(s) = status else {
        eprintln!("skipping: mklink /J not available in this environment");
        return;
    };
    if !s.success() {
        eprintln!("skipping: mklink /J failed (junction creation unsupported here)");
        return;
    }

    let mut argv = helper_argv_base();
    argv.extend([
        "--writable-dir".into(),
        junction.to_string_lossy().into_owned(),
        "--".into(),
        r"C:\Windows\System32\whoami.exe".into(),
    ]);
    let out = Command::cargo_bin("lpm-sandbox-helper")
        .expect("locate helper")
        .args(&argv)
        .output()
        .expect("spawn helper");
    assert!(
        !out.status.success(),
        "reparse-point root must be refused; got success with stdout: {}",
        String::from_utf8_lossy(&out.stdout),
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("reparse point"),
        "stderr must name the reparse-point refusal; got: {stderr}",
    );
}
