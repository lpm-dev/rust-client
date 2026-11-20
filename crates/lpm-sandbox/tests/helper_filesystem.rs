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

static NEXT_PROFILE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

#[test]
fn node_can_resolve_project_paths_without_listing_or_reading_ancestors() {
    let temporary = tempfile::tempdir().unwrap();
    let project = temporary.path().join("project");
    fs::create_dir(&project).unwrap();
    fs::write(temporary.path().join("unrelated.txt"), "outside content").unwrap();
    fs::write(
        project.join("hook.cjs"),
        r#"
const fs = require('node:fs');
const path = require('node:path');
const assert = require('node:assert/strict');
assert.equal(fs.realpathSync(__filename), __filename);
const parent = path.dirname(__dirname);
for (const operation of [
    () => fs.readdirSync(parent),
    () => fs.readFileSync(path.join(parent, 'unrelated.txt')),
]) {
    assert.throws(operation, error => ['EACCES', 'EPERM'].includes(error.code));
}
console.log('ancestor boundaries verified');
"#,
    )
    .unwrap();
    let node = std::process::Command::new("node")
        .args(["-p", "process.execPath"])
        .output()
        .expect("Node must be installed for the native filesystem gate");
    assert!(node.status.success(), "{node:?}");
    let node = std::path::PathBuf::from(String::from_utf8(node.stdout).unwrap().trim());
    let mut argv = helper_argv_base();
    argv.extend([
        "--env-clear".into(),
        "--env".into(),
        format!("SystemRoot={}", std::env::var("SystemRoot").unwrap()),
        "--env".into(),
        format!("LOCALAPPDATA={}", project.display()),
        "--working-dir".into(),
        project.display().to_string(),
        "--writable-dir".into(),
        project.display().to_string(),
        "--readable-dir".into(),
        node.parent().unwrap().display().to_string(),
        "--".into(),
        node.display().to_string(),
        "hook.cjs".into(),
    ]);
    let output = Command::cargo_bin("lpm-sandbox-helper")
        .unwrap()
        .args(&argv)
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    assert!(String::from_utf8_lossy(&output.stdout).contains("ancestor boundaries verified"));
}

#[test]
fn helper_preserves_an_extended_drive_working_directory() {
    let temporary = tempfile::tempdir().unwrap();
    let directory = temporary.path().canonicalize().unwrap();
    let system = std::env::var("SystemRoot").unwrap();
    let mut argv = helper_argv_base();
    argv.extend([
        "--env-clear".into(),
        "--env".into(),
        format!("SystemRoot={system}"),
        "--env".into(),
        format!("LOCALAPPDATA={}", directory.display()),
        "--working-dir".into(),
        directory.display().to_string(),
        "--writable-dir".into(),
        directory.display().to_string(),
        "--".into(),
        format!(r"{system}\System32\cmd.exe"),
        "/d".into(),
        "/c".into(),
        "echo working-directory>created.txt".into(),
    ]);
    let output = Command::cargo_bin("lpm-sandbox-helper")
        .unwrap()
        .args(&argv)
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    assert_eq!(
        fs::read_to_string(directory.join("created.txt"))
            .unwrap()
            .trim(),
        "working-directory"
    );
}

/// A script that fails because a program on PATH was out of the sandbox's
/// reach shows only the shell's "not recognized", so the helper names the
/// PATH directories it couldn't grant, and only when the script fails.
#[test]
fn a_failed_script_is_told_which_path_directories_it_could_not_read() {
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        DELETE, FILE_DISPOSITION_INFO, FILE_FLAG_BACKUP_SEMANTICS, FileDispositionInfo,
        SetFileInformationByHandle,
    };

    // Nothing opens a directory pending deletion, whatever the runner's
    // privileges, though its name still lists, so the helper can neither
    // resolve nor grant this one.
    let temporary = tempfile::tempdir().unwrap();
    let removed = temporary
        .path()
        .canonicalize()
        .unwrap()
        .join("removed-tools");
    fs::create_dir(&removed).unwrap();
    let pending = fs::OpenOptions::new()
        .access_mode(DELETE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(&removed)
        .unwrap();
    let disposition = FILE_DISPOSITION_INFO { DeleteFile: true };
    // SAFETY: the handle stays open for the call, and the buffer is the
    // class's record.
    let marked = unsafe {
        SetFileInformationByHandle(
            pending.as_raw_handle(),
            FileDispositionInfo,
            std::ptr::from_ref(&disposition).cast(),
            std::mem::size_of::<FILE_DISPOSITION_INFO>() as u32,
        )
    };
    assert_ne!(marked, 0, "mark the directory for deletion");
    let system = std::env::var("SystemRoot").unwrap();
    for (exit_code, reported) in [(3, true), (0, false)] {
        let mut argv = helper_argv_base();
        argv.extend([
            "--delete-appcontainer-profile".into(),
            "--working-dir".into(),
            format!(r"{system}\System32"),
            "--readable-dir-best-effort".into(),
            removed.display().to_string(),
            "--".into(),
            format!(r"{system}\System32\cmd.exe"),
            "/d".into(),
            "/c".into(),
            format!("exit {exit_code}"),
        ]);
        let output = Command::cargo_bin("lpm-sandbox-helper")
            .unwrap()
            .args(&argv)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(exit_code), "{output:?}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(
            stderr.contains(&format!("  {}: ", removed.display())),
            reported,
            "{stderr}"
        );
        assert_eq!(
            stderr.contains("lpm doctor sandbox-setup --tool-dir"),
            reported,
            "{stderr}"
        );
    }
}

/// A PATH directory inside a writable root is opened from that root, never
/// through a link a script could have made there, so one reached through a
/// junction gets no grant of its own. It isn't reported, though: the script
/// still reaches what the junction leads to wherever another grant covers
/// it, here the writable root itself.
#[test]
fn a_path_directory_through_a_link_in_a_writable_root_is_not_reported() {
    let temporary = tempfile::tempdir().unwrap();
    let writable = temporary.path().canonicalize().unwrap().join("project");
    let target = writable.join("real-tools");
    fs::create_dir_all(target.join("bin")).unwrap();
    fs::write(target.join("bin").join("probe.cmd"), "@echo REACHED\r\n").unwrap();
    let link = writable.join("tools");
    let output = std::process::Command::new("cmd")
        .args(["/d", "/c", "mklink", "/J"])
        .arg(&link)
        .arg(&target)
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    let tools = link.join("bin");
    let system = std::env::var("SystemRoot").unwrap();
    let mut argv = helper_argv_base();
    argv.extend([
        "--delete-appcontainer-profile".into(),
        "--working-dir".into(),
        format!(r"{system}\System32"),
        "--writable-dir".into(),
        writable.display().to_string(),
        "--readable-dir-best-effort".into(),
        tools.display().to_string(),
        "--env".into(),
        format!(r"PATH={};{system}\System32", tools.display()),
        "--".into(),
        format!(r"{system}\System32\cmd.exe"),
        "/d".into(),
        "/c".into(),
        "probe & exit 3".into(),
    ]);
    let output = Command::cargo_bin("lpm-sandbox-helper")
        .unwrap()
        .args(&argv)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(3), "{output:?}");
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("REACHED"),
        "{output:?}"
    );
    assert!(
        !String::from_utf8_lossy(&output.stderr).contains("couldn't give the script access"),
        "{output:?}"
    );
}

/// The arguments of a run under an identity of the test's own. Dropping
/// them revokes what the identity was granted and deletes its profile, so
/// a test leaves neither on the machine it ran on.
struct OwnIdentityArgv {
    argv: Vec<String>,
    _identity: RunIdentity,
    _records: tempfile::TempDir,
}

impl std::ops::Deref for OwnIdentityArgv {
    type Target = Vec<String>;

    fn deref(&self) -> &Vec<String> {
        &self.argv
    }
}

impl std::ops::DerefMut for OwnIdentityArgv {
    fn deref_mut(&mut self) -> &mut Vec<String> {
        &mut self.argv
    }
}

impl<'a> IntoIterator for &'a OwnIdentityArgv {
    type Item = &'a String;
    type IntoIter = std::slice::Iter<'a, String>;

    fn into_iter(self) -> Self::IntoIter {
        self.argv.iter()
    }
}

fn helper_argv_base() -> OwnIdentityArgv {
    let records = tempfile::tempdir().expect("record tempdir");
    let identity = vec![
        "--protocol-version".to_string(),
        lpm_sandbox::helper_protocol::PROTOCOL_VERSION.to_string(),
        "--appcontainer-name".into(),
        format!(
            "LpmFilesystemTest-{}-{}",
            std::process::id(),
            NEXT_PROFILE.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ),
        "--grant-record".into(),
        records
            .path()
            .join("grants.json")
            .to_string_lossy()
            .into_owned(),
    ];
    let mut argv = identity.clone();
    argv.extend([
        "--identity-record".to_string(),
        identity_record_of(&identity).to_string_lossy().into_owned(),
        "--identity-project".into(),
        records.path().to_string_lossy().into_owned(),
        "--identity-package".into(),
        RECORDED_PACKAGE.into(),
    ]);
    argv.extend(
        [
            "--stdio-stdin",
            "null",
            "--stdio-stdout",
            "piped",
            "--stdio-stderr",
            "piped",
        ]
        .map(String::from),
    );
    OwnIdentityArgv {
        argv,
        _identity: RunIdentity(identity),
        _records: records,
    }
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
    [Console]::WriteLine('OK')
}} catch {{
    [Console]::Error.WriteLine($_)
    exit 1
}}
"#,
        target.replace('\'', "''")
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
    $content = [System.IO.File]::ReadAllText('{}')
    [Console]::WriteLine($content)
}} catch {{
    [Console]::Error.WriteLine($_)
    exit 1
}}
"#,
        target.replace('\'', "''")
    )
}

const POWERSHELL: &str = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe";

/// PowerShell that writes a line through the handle with value `handle`,
/// which only exists in its process if it was inherited. In a child that
/// didn't inherit it the value can still name a handle of its own, such as
/// a file it opened to read: then the stream holds the bytes it couldn't
/// write, and its finalizer, trying again, would crash PowerShell after
/// `NO-HANDLE`.
fn ps_write_through_handle(handle: usize) -> String {
    format!(
        r#"
$ErrorActionPreference = 'Stop'
try {{
    $handle = [Microsoft.Win32.SafeHandles.SafeFileHandle]::new([IntPtr]{handle}, $false)
    $stream = [System.IO.FileStream]::new($handle, [System.IO.FileAccess]::Write)
    $bytes = [System.Text.Encoding]::ASCII.GetBytes('written by the child')
    $stream.Write($bytes, 0, $bytes.Length)
    $stream.Flush()
    [Console]::WriteLine('WROTE')
}} catch {{
    if ($stream) {{ [GC]::SuppressFinalize($stream) }}
    [Console]::WriteLine('NO-HANDLE')
}}
"#
    )
}

/// The helper runs with the user's full token, so any handle it passes to
/// its AppContainer child is access the child's grants don't give.
#[test]
fn the_lifecycle_child_inherits_none_of_the_helper_s_other_handles() {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::{HANDLE_FLAG_INHERIT, SetHandleInformation};

    let tmp = tempfile::tempdir().expect("tempdir");
    let target = tmp.path().join("helper-only.txt");
    fs::write(&target, "untouched").expect("seed file");
    let file = fs::OpenOptions::new()
        .write(true)
        .open(&target)
        .expect("open the target");
    // SAFETY: the handle stays open for the call.
    let marked = unsafe {
        SetHandleInformation(
            file.as_raw_handle(),
            HANDLE_FLAG_INHERIT,
            HANDLE_FLAG_INHERIT,
        )
    };
    assert_ne!(marked, 0, "mark the handle inheritable");
    let script = ps_write_through_handle(file.as_raw_handle() as usize);

    // Positive control: an unsandboxed child, started as the helper is,
    // inherits the handle and can write through it.
    let control = std::process::Command::new(POWERSHELL)
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .output()
        .expect("spawn the control child");
    assert_eq!(
        fs::read_to_string(&target).expect("read the target"),
        "written by the child",
        "the probe can't write through an inherited handle; stdout: {}",
        String::from_utf8_lossy(&control.stdout),
    );
    fs::write(&target, "untouched").expect("reset the target");

    let mut argv = helper_argv_base();
    argv.extend([
        "--".into(),
        POWERSHELL.into(),
        "-NoProfile".into(),
        "-NonInteractive".into(),
        "-Command".into(),
        script,
    ]);
    let out = Command::cargo_bin("lpm-sandbox-helper")
        .expect("locate helper")
        .args(&argv)
        .output()
        .expect("spawn helper");
    drop(file);

    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success() && (stdout.contains("WROTE") || stdout.contains("NO-HANDLE")),
        "the probe did not run; status: {:?}\nstdout: {stdout}\nstderr: {}",
        out.status,
        String::from_utf8_lossy(&out.stderr),
    );
    assert_eq!(
        fs::read_to_string(&target).expect("read the target"),
        "untouched",
        "the AppContainer child wrote through a handle the helper inherited"
    );
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
fn helper_secret_read_deny_overrides_broad_read_and_does_not_leave_a_stale_deny() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let target = tmp.path().join(".env");
    fs::write(&target, "protected-content").expect("seed protected file");

    let mut denied_argv = helper_argv_base();
    denied_argv.extend([
        "--readable-dir".into(),
        tmp.path().to_string_lossy().into_owned(),
        "--secret-read-deny".into(),
        target.to_string_lossy().into_owned(),
        "--".into(),
        r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe".into(),
        "-NoProfile".into(),
        "-NonInteractive".into(),
        "-Command".into(),
        ps_read_file(&target.to_string_lossy()),
    ]);
    let denied = Command::cargo_bin("lpm-sandbox-helper")
        .expect("locate helper")
        .args(&denied_argv)
        .output()
        .expect("spawn helper with secret denial");
    let denied_output = format!(
        "{}\n{}",
        String::from_utf8_lossy(&denied.stdout),
        String::from_utf8_lossy(&denied.stderr)
    );
    assert!(
        !denied.status.success(),
        "secret ACL protection must override the broad project read grant; status: {:?}\noutput: {}",
        denied.status,
        denied_output
    );
    assert!(
        !denied_output.contains("protected-content"),
        "the lifecycle child exposed the protected secret: {denied_output}"
    );
    assert!(
        denied_output.contains("Access to the path")
            || denied_output.contains("UnauthorizedAccessException")
            || denied_output.contains("access is denied")
            || denied_output.contains("Access is denied")
            || denied_output.contains("PermissionDenied"),
        "expected an access-denied signal from the lifecycle child: {denied_output}"
    );
    assert_eq!(
        fs::read_to_string(&target).expect("the host user must retain access to the secret"),
        "protected-content"
    );

    let mut allowed_argv = helper_argv_base();
    allowed_argv.extend([
        "--readable-dir".into(),
        tmp.path().to_string_lossy().into_owned(),
        "--".into(),
        r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe".into(),
        "-NoProfile".into(),
        "-NonInteractive".into(),
        "-Command".into(),
        ps_read_file(&target.to_string_lossy()),
    ]);
    let allowed = Command::cargo_bin("lpm-sandbox-helper")
        .expect("locate helper")
        .args(&allowed_argv)
        .output()
        .expect("spawn helper after removing secret denial");
    assert!(
        allowed.status.success(),
        "a later broad grant must replace the stable AppContainer SID's stale explicit deny; stderr: {}",
        String::from_utf8_lossy(&allowed.stderr)
    );
    assert!(
        String::from_utf8_lossy(&allowed.stdout).contains("protected-content"),
        "the later allow must restore reads after the denial is no longer requested"
    );
}

/// The entries of `path`'s permissions as `icacls` saves them: one string
/// per entry, such as `D;;FRFX;;;S-1-15-2-1-2` for a denial. The saved
/// form names every trustee by SID and doesn't depend on the language
/// Windows runs in.
fn saved_entries(path: &std::path::Path) -> Vec<String> {
    saved_permissions(path)
        .split('(')
        .skip(1)
        .filter_map(|entry| entry.split(')').next())
        .map(str::to_owned)
        .collect()
}

/// How `path`'s permissions inherit, as `icacls` saves it ahead of the
/// entries: `AI` when Windows keeps the inherited ones in step with the
/// parent's, `P` when the parent's don't apply, both, or neither.
fn saved_inheritance(path: &std::path::Path) -> String {
    let saved = saved_permissions(path);
    let descriptor = saved
        .lines()
        .rev()
        .find_map(|line| line.trim().strip_prefix("D:"))
        .unwrap_or_else(|| panic!("no permissions were saved for {}", path.display()));
    dacl_inheritance(descriptor).to_owned()
}

/// The flags that open the DACL part of saved permissions, given what
/// follows `D:`. They end at the first entry, or at the `S:` part when
/// the DACL has no entries.
fn dacl_inheritance(descriptor: &str) -> &str {
    let flags = descriptor.split('(').next().unwrap_or_default();
    flags.split("S:").next().unwrap_or_default()
}

#[test]
fn the_saved_inheritance_is_read_from_the_dacl_part_alone() {
    assert_eq!(dacl_inheritance("AI(A;ID;FA;;;SY)(A;;FA;;;BA)"), "AI");
    assert_eq!(dacl_inheritance("PAI(A;;FA;;;BA)S:AI(ML;;NW;;;LW)"), "PAI");
    assert_eq!(dacl_inheritance("(A;;FA;;;BA)"), "");
    assert_eq!(dacl_inheritance("AIS:(AU;SA;FA;;;WD)"), "AI");
    assert_eq!(dacl_inheritance("S:(AU;SA;FA;;;WD)"), "");
}

/// What `icacls /save` writes for `path`: its name, then its permissions.
fn saved_permissions(path: &std::path::Path) -> String {
    let directory = tempfile::tempdir().expect("directory for the saved permissions");
    let saved = directory.path().join("permissions");
    let listing = std::process::Command::new("icacls")
        .arg(path)
        .arg("/save")
        .arg(&saved)
        .output()
        .expect("icacls saves the permissions");
    assert!(listing.status.success(), "{listing:?}");
    let bytes = fs::read(&saved).expect("read the saved permissions");
    let units: Vec<u16> = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u16::from_le_bytes(*pair))
        .collect();
    String::from_utf16_lossy(&units)
}

/// The AppContainer SIDs `path`'s permissions deny access.
fn denied_app_containers(path: &std::path::Path) -> Vec<String> {
    saved_entries(path)
        .iter()
        .filter(|entry| entry.starts_with("D;"))
        .filter_map(|entry| entry.rsplit(';').next())
        .filter(|trustee| trustee.starts_with("S-1-15-2-"))
        .map(str::to_owned)
        .collect()
}

fn names_trustee(path: &std::path::Path, sid: &str) -> bool {
    saved_entries(path)
        .iter()
        .any(|entry| entry.rsplit(';').next() == Some(sid))
}

/// Takes back what the runs of one identity set, and deletes its profile,
/// when dropped.
struct RunIdentity(Vec<String>);

/// The package the runs [`helper_argv_base`] starts record their identity
/// for.
const RECORDED_PACKAGE: &str = "lpm-filesystem-test";

/// Where the runs of `identity` record it: beside its grant record.
fn identity_record_of(identity: &[String]) -> std::path::PathBuf {
    let grants = identity
        .iter()
        .skip_while(|argument| *argument != "--grant-record")
        .nth(1)
        .expect("the identity names its grant record");
    std::path::Path::new(grants).with_extension("identity.json")
}

/// The helper run that revokes what `identity` was granted, deletes its
/// profile and removes its identity record.
fn cleanup_of(identity: &[String]) -> std::process::Command {
    let mut cleanup = std::process::Command::new(env!("CARGO_BIN_EXE_lpm-sandbox-helper"));
    cleanup
        .args(identity)
        .arg("--identity-record")
        .arg(identity_record_of(identity))
        .args(["--revoke-only", "--delete-appcontainer-profile"]);
    cleanup
}

impl RunIdentity {
    fn clean_up(&self) -> std::process::Output {
        cleanup_of(&self.0).output().expect("spawn cleanup")
    }
}

impl Drop for RunIdentity {
    fn drop(&mut self) {
        // A test that failed is unwinding here, and a second panic would
        // end the whole test process.
        let _ = cleanup_of(&self.0).output();
    }
}

#[test]
fn a_run_and_its_cleanup_leave_how_each_folder_and_file_inherits() {
    let project = tempfile::tempdir().expect("project tempdir");
    // Where no folder above inherits, a new one doesn't either and the run
    // would have nothing to keep. icacls writes the folder as Windows' own
    // tools do, and what is made inside it then inherits as it does.
    let marked = std::process::Command::new("icacls.exe")
        .arg(project.path())
        .arg("/inheritance:e")
        .output()
        .expect("run icacls");
    assert!(marked.status.success(), "{marked:?}");
    let records = tempfile::tempdir().expect("record tempdir");
    let secret = project.path().join(".env");
    fs::write(&secret, "protected-content").expect("seed protected file");
    let kept = project.path().join("kept.txt");
    fs::write(&kept, "kept").expect("seed a file the grant reaches");
    let created = project.path().join("created-by-child.txt");
    let watched: Vec<std::path::PathBuf> = project
        .path()
        .ancestors()
        .filter(|ancestor| ancestor.parent().is_some())
        .map(std::path::Path::to_path_buf)
        .chain([secret.clone(), kept])
        .collect();
    let inheritance = || -> Vec<(&std::path::Path, String)> {
        watched
            .iter()
            .map(|path| (path.as_path(), saved_inheritance(path)))
            .collect()
    };
    let before = inheritance();
    assert!(
        before
            .iter()
            .filter(|(path, _)| path.starts_with(project.path()))
            .all(|(_, flags)| flags.contains("AI")),
        "the project doesn't inherit its permissions, so the run has nothing to keep: {before:?}"
    );
    let identity = RunIdentity(vec![
        "--protocol-version".to_string(),
        lpm_sandbox::helper_protocol::PROTOCOL_VERSION.to_string(),
        "--appcontainer-name".into(),
        format!("LpmFilesystemInheritance-{}", std::process::id()),
        "--grant-record".into(),
        records
            .path()
            .join("grants.json")
            .to_string_lossy()
            .into_owned(),
    ]);

    let run = std::process::Command::new(env!("CARGO_BIN_EXE_lpm-sandbox-helper"))
        .args(&identity.0)
        .args(["--stdio-stdin", "null"])
        .args(["--stdio-stdout", "piped"])
        .args(["--stdio-stderr", "piped"])
        .arg("--writable-dir")
        .arg(project.path())
        .arg("--secret-read-deny")
        .arg(&secret)
        .args([
            "--",
            POWERSHELL,
            "-NoProfile",
            "-NonInteractive",
            "-Command",
        ])
        .arg(ps_write_file(&created.to_string_lossy()))
        .output()
        .expect("spawn helper");

    assert!(run.status.success(), "{run:?}");
    assert!(created.exists());
    assert_eq!(inheritance(), before, "after the run");

    let cleanup = identity.clean_up();

    assert!(cleanup.status.success(), "{cleanup:?}");
    assert_eq!(inheritance(), before, "after the cleanup");
    assert!(saved_inheritance(&created).contains("AI"));
    // A file the script made inherited the run's entry from the project
    // folder. The cleanup's write to it carries the file's inheritance,
    // which must not bring that entry back.
    let left: Vec<String> = saved_entries(&created)
        .into_iter()
        .filter(|entry| {
            entry
                .rsplit(';')
                .next()
                .is_some_and(|trustee| trustee.starts_with("S-1-15-2-") && trustee.len() > 12)
        })
        .collect();
    assert!(left.is_empty(), "{left:?}");
}

/// A sandboxed run that is stopped rather than left to end. Whatever the
/// test goes on to find, dropping this stops the helper and cleans up
/// after its identity, while the record that says what to clean still
/// exists.
struct StoppedRun {
    helper: std::process::Child,
    identity: Vec<String>,
    /// The run's Job, where the test holds it as `lpm` does.
    job: Option<HeldJob>,
    /// The folder a script in a held Job writes to once it has read the
    /// secret.
    outside: Option<tempfile::TempDir>,
}

impl StoppedRun {
    /// As a script over its time limit is stopped: the helper gets no
    /// chance to take back what it set.
    fn stop(&mut self) {
        let _ = self.helper.kill();
        let _ = self.helper.wait();
    }

    fn clean_up(&self) -> std::process::Output {
        cleanup_of(&self.identity).output().expect("spawn cleanup")
    }

    /// Whether the script of a run in a held Job got to read the secret.
    /// It tries without pause for as long as it runs.
    fn script_read_the_secret(&self) -> bool {
        let outside = self.outside.as_ref().expect("a run in a held Job");
        outside.path().join(SECRET_WAS_READ).exists()
    }
}

const SECRET_WAS_READ: &str = "secret-was-read";

impl Drop for StoppedRun {
    fn drop(&mut self) {
        self.stop();
        // Closing a held Job ends the script, which the cleanup waits for.
        self.job = None;
        let _ = cleanup_of(&self.identity).output();
    }
}

/// A Job the test made and holds, as `lpm` holds the Job of a run it
/// started: the script in it outlives the helper until the Job is closed.
struct HeldJob {
    name: String,
    handle: std::os::windows::io::OwnedHandle,
}

impl HeldJob {
    fn create(name: String) -> Self {
        use std::os::windows::io::{AsRawHandle as _, FromRawHandle as _};
        use windows_sys::Win32::System::JobObjects::{
            CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
            SetInformationJobObject,
        };

        let wide_name: Vec<u16> = name.encode_utf16().chain([0]).collect();
        // SAFETY: the name is null-terminated and lives through the call.
        let job = unsafe { CreateJobObjectW(std::ptr::null(), wide_name.as_ptr()) };
        assert!(!job.is_null(), "create the Job");
        // SAFETY: the call returned a handle nothing else owns.
        let handle = unsafe { std::os::windows::io::OwnedHandle::from_raw_handle(job.cast()) };
        // SAFETY: the structure accepts the all-zero state.
        let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        // SAFETY: `limits` is a stack-local of the size passed.
        let configured = unsafe {
            SetInformationJobObject(
                handle.as_raw_handle().cast(),
                JobObjectExtendedLimitInformation,
                (&raw const limits).cast(),
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        };
        assert_ne!(
            configured, 0,
            "end the Job's processes with its last handle"
        );
        Self { name, handle }
    }

    fn active_processes(&self) -> u32 {
        use std::os::windows::io::AsRawHandle as _;
        use windows_sys::Win32::System::JobObjects::{
            JOBOBJECT_BASIC_ACCOUNTING_INFORMATION, JobObjectBasicAccountingInformation,
            QueryInformationJobObject,
        };

        // SAFETY: the structure accepts the all-zero state.
        let mut counted: JOBOBJECT_BASIC_ACCOUNTING_INFORMATION = unsafe { std::mem::zeroed() };
        // SAFETY: `counted` is a stack-local of the size passed.
        let asked = unsafe {
            QueryInformationJobObject(
                self.handle.as_raw_handle().cast(),
                JobObjectBasicAccountingInformation,
                (&raw mut counted).cast(),
                std::mem::size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as u32,
                std::ptr::null_mut(),
            )
        };
        assert_ne!(asked, 0, "ask the Job how many processes it holds");
        counted.ActiveProcesses
    }
}

/// Starts a run of the identity `profile` that reads `project`, is denied
/// `secret` and sleeps, and returns it with the identity's SID once the
/// denial is set.
fn start_a_run_that_sleeps(
    profile: &str,
    project: &std::path::Path,
    record: &std::path::Path,
    secret: &std::path::Path,
) -> (StoppedRun, String) {
    start_a_run_that_sleeps_in(profile, project, record, secret, None)
}

/// As [`start_a_run_that_sleeps`]. Where a `job` is given the script is in
/// it, and instead of sleeping it tries to read `secret` without pause,
/// and says so in a folder of its own once it could.
fn start_a_run_that_sleeps_in(
    profile: &str,
    project: &std::path::Path,
    record: &std::path::Path,
    secret: &std::path::Path,
    job: Option<HeldJob>,
) -> (StoppedRun, String) {
    let identity = vec![
        "--protocol-version".to_string(),
        lpm_sandbox::helper_protocol::PROTOCOL_VERSION.to_string(),
        "--appcontainer-name".into(),
        format!("{profile}-{}", std::process::id()),
        "--grant-record".into(),
        record.to_string_lossy().into_owned(),
    ];
    let outside = job
        .is_some()
        .then(|| tempfile::tempdir().expect("folder for the script's own file"));
    let quoted = |path: &std::path::Path| path.to_string_lossy().replace('\'', "''");
    let script = match &outside {
        Some(outside) => format!(
            "while ($true) {{ try {{ [System.IO.File]::ReadAllText('{}') | Out-Null; [System.IO.File]::WriteAllText('{}', 'read') }} catch {{ }} }}",
            quoted(secret),
            quoted(&outside.path().join(SECRET_WAS_READ)),
        ),
        None => "Start-Sleep -Seconds 300".to_owned(),
    };
    let mut helper = std::process::Command::new(env!("CARGO_BIN_EXE_lpm-sandbox-helper"));
    helper
        .args(&identity)
        .args(job.iter().flat_map(|job| ["--job", job.name.as_str()]))
        .args(["--stdio-stdin", "null"])
        .args(["--stdio-stdout", "null"])
        .args(["--stdio-stderr", "null"])
        .arg("--readable-dir")
        .arg(project)
        .arg("--secret-read-deny")
        .arg(secret);
    if let Some(outside) = &outside {
        helper.arg("--writable-dir").arg(outside.path());
    }
    let helper = helper
        .args([
            "--",
            POWERSHELL,
            "-NoProfile",
            "-NonInteractive",
            "-Command",
        ])
        .arg(script)
        .spawn()
        .expect("spawn helper");
    let mut run = StoppedRun {
        helper,
        identity,
        job,
        outside,
    };
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(120);
    let sid = loop {
        if let Some(sid) = denied_app_containers(secret).pop() {
            break sid;
        }
        assert!(
            run.helper.try_wait().expect("poll helper").is_none(),
            "the run ended before it denied its identity the secret"
        );
        assert!(
            std::time::Instant::now() < deadline,
            "the run never denied its identity the secret"
        );
        std::thread::sleep(std::time::Duration::from_millis(100));
    };
    (run, sid)
}

/// The directories `record` says a run passes through until it ends.
fn recorded_traversal(record: &std::path::Path) -> Vec<std::path::PathBuf> {
    recorded_run_paths(record, "traversed")
}

/// The secrets `record` says a run denies its identity until it ends.
fn recorded_denials(record: &std::path::Path) -> Vec<std::path::PathBuf> {
    recorded_run_paths(record, "denied")
}

fn recorded_run_paths(record: &std::path::Path, part: &str) -> Vec<std::path::PathBuf> {
    let recorded: serde_json::Value =
        serde_json::from_slice(&fs::read(record).expect("the run recorded what it set"))
            .expect("the record is JSON");
    recorded["run"][part]
        .as_array()
        .map(|paths| {
            paths
                .iter()
                .filter_map(|path| path.as_str())
                .map(std::path::PathBuf::from)
                .collect()
        })
        .unwrap_or_default()
}

#[test]
fn a_cleanup_takes_back_what_a_run_that_was_stopped_left_set() {
    let project = tempfile::tempdir().expect("project tempdir");
    let records = tempfile::tempdir().expect("record tempdir");
    let secret = project.path().join(".env");
    fs::write(&secret, "protected-content").expect("seed protected file");
    let record = records.path().join("grants.json");
    let (mut run, sid) =
        start_a_run_that_sleeps("LpmFilesystemStopped", project.path(), &record, &secret);

    run.stop();
    assert_eq!(
        denied_app_containers(&secret),
        std::slice::from_ref(&sid),
        "a stopped run can't take its denial back itself"
    );
    let traversed = recorded_traversal(&record);
    for directory in &traversed {
        assert!(
            names_trustee(directory, &sid),
            "the stopped run still passes through {}",
            directory.display()
        );
    }

    let cleanup = run.clean_up();

    assert!(cleanup.status.success(), "{cleanup:?}");
    assert!(
        denied_app_containers(&secret).is_empty(),
        "the cleanup takes back the denial the stopped run left"
    );
    for directory in &traversed {
        assert!(
            !names_trustee(directory, &sid),
            "the cleanup takes back the run's way through {}",
            directory.display()
        );
    }
    assert!(!record.exists());
    assert_eq!(
        fs::read_to_string(&secret).expect("the host user keeps access to the secret"),
        "protected-content"
    );
}

#[test]
fn taking_back_a_stopped_run_leaves_the_identity_its_trees_and_its_record() {
    let project = tempfile::tempdir().expect("project tempdir");
    let records = tempfile::tempdir().expect("record tempdir");
    let secret = project.path().join(".env");
    fs::write(&secret, "protected-content").expect("seed protected file");
    let record = records.path().join("grants.json");
    let (mut run, sid) =
        start_a_run_that_sleeps("LpmFilesystemTakenBack", project.path(), &record, &secret);
    run.stop();
    let traversed = recorded_traversal(&record);

    let taken_back = std::process::Command::new(env!("CARGO_BIN_EXE_lpm-sandbox-helper"))
        .args(&run.identity)
        .arg("--take-back-run")
        .output()
        .expect("spawn the take-back");

    assert!(taken_back.status.success(), "{taken_back:?}");
    assert!(
        denied_app_containers(&secret).is_empty(),
        "the denial the stopped run left is taken back"
    );
    for directory in &traversed {
        assert!(
            !names_trustee(directory, &sid),
            "the run's way through {} is taken back",
            directory.display()
        );
    }
    assert!(
        recorded_traversal(&record).is_empty(),
        "the record names nothing the run still holds"
    );
    assert!(
        names_trustee(project.path(), &sid),
        "the identity keeps the tree it was granted, for its next run"
    );
}

/// Starts a run whose script is in a Job the test holds, stops its
/// helper once the script runs, and returns the run with its identity's
/// SID. The script is then still running, denied `secret`.
fn stop_the_helper_of_a_run_in_a_held_job(
    profile: &str,
    project: &std::path::Path,
    record: &std::path::Path,
    secret: &std::path::Path,
) -> (StoppedRun, String) {
    let job = HeldJob::create(format!(r"Global\{profile}-{}", std::process::id()));
    let (mut run, sid) = start_a_run_that_sleeps_in(profile, project, record, secret, Some(job));
    let job = run.job.as_ref().expect("the run's Job");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(120);
    while job.active_processes() == 0 {
        assert!(
            run.helper.try_wait().expect("poll helper").is_none(),
            "the run ended before its script started"
        );
        assert!(
            std::time::Instant::now() < deadline,
            "the run never started its script"
        );
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    run.stop();
    let job = run.job.as_ref().expect("the run's Job");
    assert!(
        job.active_processes() >= 1,
        "the script outlives its helper while the Job is held"
    );
    assert_eq!(
        denied_app_containers(secret),
        std::slice::from_ref(&sid),
        "a stopped run can't take its denial back itself"
    );
    assert!(!run.script_read_the_secret());
    (run, sid)
}

#[test]
fn a_take_back_ends_what_is_left_of_the_script_in_the_run_s_job_first() {
    let project = tempfile::tempdir().expect("project tempdir");
    let records = tempfile::tempdir().expect("record tempdir");
    let secret = project.path().join(".env");
    fs::write(&secret, "protected-content").expect("seed protected file");
    let record = records.path().join("grants.json");
    let (run, _) = stop_the_helper_of_a_run_in_a_held_job(
        "LpmFilesystemHeldJob",
        project.path(),
        &record,
        &secret,
    );
    let job = run.job.as_ref().expect("the run's Job");

    let taken_back = std::process::Command::new(env!("CARGO_BIN_EXE_lpm-sandbox-helper"))
        .args(&run.identity)
        .arg("--take-back-run")
        .output()
        .expect("spawn the take-back");

    assert!(taken_back.status.success(), "{taken_back:?}");
    assert_eq!(job.active_processes(), 0, "the script is ended");
    assert!(
        !run.script_read_the_secret(),
        "and it was ended before the denial came off"
    );
    assert!(
        denied_app_containers(&secret).is_empty(),
        "the denial comes off once the script is gone"
    );
    assert!(recorded_denials(&record).is_empty());
}

#[test]
fn the_identity_s_next_run_ends_what_a_stopped_run_left_in_its_job_first() {
    let project = tempfile::tempdir().expect("project tempdir");
    let records = tempfile::tempdir().expect("record tempdir");
    let secret = project.path().join(".env");
    fs::write(&secret, "protected-content").expect("seed protected file");
    let record = records.path().join("grants.json");
    let created = project.path().join("created-by-child.txt");
    let (run, _) = stop_the_helper_of_a_run_in_a_held_job(
        "LpmFilesystemNextRun",
        project.path(),
        &record,
        &secret,
    );
    let job = run.job.as_ref().expect("the run's Job");

    let next = std::process::Command::new(env!("CARGO_BIN_EXE_lpm-sandbox-helper"))
        .args(&run.identity)
        .args(["--stdio-stdin", "null"])
        .args(["--stdio-stdout", "piped"])
        .args(["--stdio-stderr", "piped"])
        .arg("--writable-dir")
        .arg(project.path())
        .args([
            "--",
            POWERSHELL,
            "-NoProfile",
            "-NonInteractive",
            "-Command",
        ])
        .arg(ps_write_file(&created.to_string_lossy()))
        .output()
        .expect("spawn the next run");

    assert!(next.status.success(), "{next:?}");
    assert_eq!(
        job.active_processes(),
        0,
        "the stopped run's script is ended"
    );
    assert!(
        !run.script_read_the_secret(),
        "and it was ended before its denial came off"
    );
    assert!(created.exists());
    assert!(
        denied_app_containers(&secret).is_empty(),
        "the next run listed no secret, and took the stopped run's denial back"
    );
}

#[test]
fn a_run_whose_job_can_t_be_opened_starts_no_script() {
    let project = tempfile::tempdir().expect("project tempdir");
    let created = project.path().join("created-by-child.txt");
    let mut argv = helper_argv_base();
    argv.extend(
        [
            "--job",
            r"Local\LpmFilesystemNoSuchJob",
            "--writable-dir",
            &project.path().to_string_lossy(),
            "--",
            POWERSHELL,
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            &ps_write_file(&created.to_string_lossy()),
        ]
        .map(String::from),
    );

    let output = Command::cargo_bin("lpm-sandbox-helper")
        .expect("cargo bin")
        .args(&argv)
        .output()
        .expect("spawn helper");

    assert!(!output.status.success(), "{output:?}");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("OpenJobObjectW"),
        "{output:?}"
    );
    assert!(!created.exists());
}

/// A script that runs as an identity while no run holds the identity, and
/// which the record of the run under test doesn't name. It belongs to a
/// run of the identity that keeps a record of its own, as one started from
/// another LPM home does, in a Job the test holds, and that run's helper
/// was stopped. It stands in for processes that outlasted their run: the
/// script the helper started, and one that script started in turn.
struct OutlastingScript {
    /// Held until both scripts are gone, then closed.
    job: Option<HeldJob>,
    /// The identity with the stand-in run's own record.
    identity: Vec<String>,
    folder: tempfile::TempDir,
}

impl OutlastingScript {
    /// Starts the script as the identity `identity` names, stops its
    /// helper once the script it starts in turn runs, and returns with
    /// both scripts still running.
    fn start(identity: &[String]) -> Self {
        let folder = tempfile::tempdir().expect("folder for the outlasting script");
        let scripts_own = folder.path().join("script");
        fs::create_dir(&scripts_own).expect("folder the outlasting script writes to");
        let started = scripts_own.join("second-script-started");
        let quoted = |path: &std::path::Path| path.to_string_lossy().replace('\'', "''");
        let name = identity
            .iter()
            .skip_while(|argument| *argument != "--appcontainer-name")
            .nth(1)
            .expect("the identity names its profile");
        let identity = vec![
            "--protocol-version".to_string(),
            lpm_sandbox::helper_protocol::PROTOCOL_VERSION.to_string(),
            "--appcontainer-name".into(),
            name.clone(),
            "--grant-record".into(),
            folder
                .path()
                .join("grants.json")
                .to_string_lossy()
                .into_owned(),
        ];
        let job = HeldJob::create(format!(
            r"Global\LpmFilesystemOutlasting-{}-{}",
            std::process::id(),
            NEXT_PROFILE.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let script = format!(
            "$env:LPM_TEST_STARTED = '{}'\n$env:LPM_TEST_TOLD_TO_END = '{}'\n& '{POWERSHELL}' -NoProfile -NonInteractive -Command 'New-Item -ItemType File -Path $env:LPM_TEST_STARTED | Out-Null; while (-not (Test-Path -LiteralPath $env:LPM_TEST_TOLD_TO_END)) {{ Start-Sleep -Milliseconds 100 }}'",
            quoted(&started),
            quoted(&scripts_own.join("told-to-end")),
        );
        let mut helper = std::process::Command::new(env!("CARGO_BIN_EXE_lpm-sandbox-helper"))
            .args(&identity)
            .args(["--job", job.name.as_str()])
            .args(["--stdio-stdin", "null"])
            .args(["--stdio-stdout", "null"])
            .args(["--stdio-stderr", "null"])
            .arg("--writable-dir")
            .arg(&scripts_own)
            .args([
                "--",
                POWERSHELL,
                "-NoProfile",
                "-NonInteractive",
                "-Command",
            ])
            .arg(script)
            .spawn()
            .expect("spawn helper");
        // From here on dropping this ends the scripts and cleans up.
        let outlasting = Self {
            job: Some(job),
            identity,
            folder,
        };
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(120);
        let running = loop {
            if started.exists() {
                break true;
            }
            if helper.try_wait().expect("poll helper").is_some()
                || std::time::Instant::now() >= deadline
            {
                break false;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        };
        let _ = helper.kill();
        let _ = helper.wait();
        assert!(running, "the outlasting script never started");
        let left = outlasting.job.as_ref().map(HeldJob::active_processes);
        assert!(
            left >= Some(2),
            "both scripts outlive their helper while the Job is held: {left:?}"
        );
        outlasting
    }

    /// Tells both scripts to end, waits until the Job counts none, and
    /// has the stand-in run's own record cleaned up. Scripts that don't
    /// end are ended with the Job.
    fn end(&mut self) {
        let Some(job) = self.job.take() else {
            return;
        };
        let _ = fs::write(self.folder.path().join("script").join("told-to-end"), "");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
        while job.active_processes() > 0 && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        // The profile is left for the identity's own cleanup. This may run
        // while a failed test unwinds, so a cleanup that failed is only
        // shown.
        let revoked = std::process::Command::new(env!("CARGO_BIN_EXE_lpm-sandbox-helper"))
            .args(&self.identity)
            .arg("--revoke-only")
            .output();
        if !matches!(&revoked, Ok(output) if output.status.success()) {
            eprintln!("the outlasting script's own run wasn't cleaned up: {revoked:?}");
        }
    }
}

impl Drop for OutlastingScript {
    fn drop(&mut self) {
        self.end();
    }
}

/// The ids of the processes `output` says an earlier run left running.
fn processes_left_running(output: &std::process::Output) -> Vec<u32> {
    let stderr = String::from_utf8_lossy(&output.stderr);
    stderr
        .split_once("left processes running (")
        .and_then(|(_, rest)| rest.split_once(')'))
        .map(|(ids, _)| {
            ids.split(", ")
                .map(|id| id.parse().expect("a process id"))
                .collect()
        })
        .unwrap_or_default()
}

#[test]
fn a_stopped_run_s_denial_stays_set_while_a_process_still_runs_as_its_identity() {
    let project = tempfile::tempdir().expect("project tempdir");
    let records = tempfile::tempdir().expect("record tempdir");
    let secret = project.path().join(".env");
    fs::write(&secret, "protected-content").expect("seed protected file");
    let record = records.path().join("grants.json");
    let (mut run, sid) =
        start_a_run_that_sleeps("LpmFilesystemOutlasted", project.path(), &record, &secret);
    run.stop();
    let take_back = || {
        std::process::Command::new(env!("CARGO_BIN_EXE_lpm-sandbox-helper"))
            .args(&run.identity)
            .arg("--take-back-run")
            .output()
            .expect("spawn the take-back")
    };
    let mut outlasting = OutlastingScript::start(&run.identity);

    let refused = take_back();

    assert!(!refused.status.success(), "{refused:?}");
    assert!(
        processes_left_running(&refused).len() >= 2,
        "the script and the one it started both run as the identity: {refused:?}"
    );
    assert_eq!(
        denied_app_containers(&secret),
        std::slice::from_ref(&sid),
        "the identity stays denied the secret while a process runs as it"
    );
    assert_eq!(
        recorded_denials(&record),
        std::slice::from_ref(&secret),
        "the record still names the denial, for whoever takes it back later"
    );

    outlasting.end();
    let taken_back = take_back();

    assert!(taken_back.status.success(), "{taken_back:?}");
    assert!(
        denied_app_containers(&secret).is_empty(),
        "the denial is taken back once no process runs as the identity"
    );
    assert!(recorded_denials(&record).is_empty());
}

#[test]
fn no_run_or_cleanup_of_an_identity_starts_while_a_process_still_runs_as_it() {
    let project = tempfile::tempdir().expect("project tempdir");
    let records = tempfile::tempdir().expect("record tempdir");
    let created = project.path().join("created-by-child.txt");
    let identity = RunIdentity(vec![
        "--protocol-version".to_string(),
        lpm_sandbox::helper_protocol::PROTOCOL_VERSION.to_string(),
        "--appcontainer-name".into(),
        format!("LpmFilesystemInUse-{}", std::process::id()),
        "--grant-record".into(),
        records
            .path()
            .join("grants.json")
            .to_string_lossy()
            .into_owned(),
    ]);
    let run = || {
        std::process::Command::new(env!("CARGO_BIN_EXE_lpm-sandbox-helper"))
            .args(&identity.0)
            .args(["--stdio-stdin", "null"])
            .args(["--stdio-stdout", "piped"])
            .args(["--stdio-stderr", "piped"])
            .arg("--writable-dir")
            .arg(project.path())
            .args([
                "--",
                POWERSHELL,
                "-NoProfile",
                "-NonInteractive",
                "-Command",
            ])
            .arg(ps_write_file(&created.to_string_lossy()))
            .output()
            .expect("spawn helper")
    };
    let mut outlasting = OutlastingScript::start(&identity.0);

    let refused_run = run();
    let refused_cleanup = identity.clean_up();

    assert!(!refused_run.status.success(), "{refused_run:?}");
    assert!(
        !processes_left_running(&refused_run).is_empty(),
        "{refused_run:?}"
    );
    assert!(!created.exists(), "the refused run started no script");
    assert!(!refused_cleanup.status.success(), "{refused_cleanup:?}");
    assert!(
        !processes_left_running(&refused_cleanup).is_empty(),
        "{refused_cleanup:?}"
    );

    outlasting.end();
    let ran = run();

    assert!(ran.status.success(), "{ran:?}");
    assert!(created.exists());
    let cleanup = identity.clean_up();
    assert!(cleanup.status.success(), "{cleanup:?}");
}

/// A helper that is stopped, if it still runs, when the test is done with
/// it: a cleanup of its identity gets nowhere while it holds the identity.
struct StoppedWithTheTest(std::process::Child);

impl Drop for StoppedWithTheTest {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn ends_within(helper: &mut std::process::Child, limit: std::time::Duration) -> bool {
    let deadline = std::time::Instant::now() + limit;
    loop {
        if helper.try_wait().expect("poll helper").is_some() {
            return true;
        }
        if std::time::Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

/// A run without a grant record still denies its identity the project's
/// secrets and takes the denials back when it ends. A second such run
/// that didn't wait for the first would take them back under a script
/// that still runs.
#[test]
fn a_run_without_a_grant_record_waits_for_the_run_of_its_identity_before_it() {
    let project = tempfile::tempdir().expect("project tempdir");
    let records = tempfile::tempdir().expect("record tempdir");
    let scripts_own = tempfile::tempdir().expect("folder the first script writes to");
    let secret = project.path().join(".env");
    fs::write(&secret, "protected-content").expect("seed protected file");
    let started = scripts_own.path().join("started");
    let told_to_end = scripts_own.path().join("told-to-end");
    let secret_was_read = scripts_own.path().join(SECRET_WAS_READ);
    let name = format!("LpmFilesystemNoRecord-{}", std::process::id());
    // Neither run keeps a record, so one that has to be stopped leaves what
    // it set. This record names everything the two may set, for the
    // cleanup to take back.
    let record = records.path().join("grants.json");
    let above = |folder: &std::path::Path| -> Vec<std::path::PathBuf> {
        folder
            .ancestors()
            .skip(1)
            .map(std::path::Path::to_path_buf)
            .collect()
    };
    let traversed = [above(project.path()), above(scripts_own.path())].concat();
    fs::write(
        &record,
        serde_json::to_vec(&serde_json::json!({
            "version": 1,
            "trees": [project.path(), scripts_own.path()],
            "run": {
                "traversed": traversed,
                "denied": [&secret],
            },
        }))
        .unwrap(),
    )
    .expect("write the cleanup's record");
    let _profile = RunIdentity(vec![
        "--protocol-version".to_string(),
        lpm_sandbox::helper_protocol::PROTOCOL_VERSION.to_string(),
        "--appcontainer-name".into(),
        name.clone(),
        "--grant-record".into(),
        record.to_string_lossy().into_owned(),
    ]);
    // `says` is the file the helper's own stderr goes to.
    let run_without_a_record =
        |script: String, writable: Option<&std::path::Path>, says: Option<&std::path::Path>| {
            let mut helper = std::process::Command::new(env!("CARGO_BIN_EXE_lpm-sandbox-helper"));
            helper
                .arg("--protocol-version")
                .arg(lpm_sandbox::helper_protocol::PROTOCOL_VERSION.to_string())
                .arg("--appcontainer-name")
                .arg(&name)
                .args(["--stdio-stdin", "null"])
                .args(["--stdio-stdout", "null"])
                .args(["--stdio-stderr", "null"])
                .arg("--readable-dir")
                .arg(project.path())
                .arg("--secret-read-deny")
                .arg(&secret);
            if let Some(writable) = writable {
                helper.arg("--writable-dir").arg(writable);
            }
            if let Some(says) = says {
                helper.stderr(fs::File::create(says).expect("file for the helper's stderr"));
            }
            helper
                .args([
                    "--",
                    POWERSHELL,
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                ])
                .arg(script)
                .spawn()
                .map(StoppedWithTheTest)
                .expect("spawn helper")
        };
    let quoted = |path: &std::path::Path| path.to_string_lossy().replace('\'', "''");
    let mut first = run_without_a_record(
        format!(
            "New-Item -ItemType File -Path '{}' | Out-Null; while (-not (Test-Path -LiteralPath '{}')) {{ try {{ [System.IO.File]::ReadAllText('{}') | Out-Null; [System.IO.File]::WriteAllText('{}', 'read') }} catch {{ }} }}",
            quoted(&started),
            quoted(&told_to_end),
            quoted(&secret),
            quoted(&secret_was_read),
        ),
        Some(scripts_own.path()),
        None,
    );
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(120);
    while !started.exists() {
        assert!(
            first.0.try_wait().expect("poll helper").is_none()
                && std::time::Instant::now() < deadline,
            "the first run's script never started"
        );
        std::thread::sleep(std::time::Duration::from_millis(100));
    }

    // A run says that it waits once it has waited for the identity, so a
    // second run that is only slow to start isn't taken for one that waits.
    let second_says = records.path().join("second-run-says.txt");
    let mut second = run_without_a_record("exit 0".to_owned(), None, Some(&second_says));
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    let second_waited = loop {
        if fs::read_to_string(&second_says)
            .is_ok_and(|said| said.contains("waiting for the process that holds"))
        {
            break true;
        }
        if second.0.try_wait().expect("poll helper").is_some()
            || std::time::Instant::now() >= deadline
        {
            break false;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    };
    fs::write(&told_to_end, "").expect("tell the first script to end");
    let first_ended = ends_within(&mut first.0, std::time::Duration::from_secs(60));
    let second_ended = ends_within(&mut second.0, std::time::Duration::from_secs(120));

    assert!(second_waited, "the second run didn't wait for the first");
    assert!(first_ended && second_ended);
    let second_run = second.0.wait().expect("the second run's exit status");
    assert!(second_run.success(), "{second_run:?}");
    assert!(
        !secret_was_read.exists(),
        "the first run's script read the secret once the second run took the denial back"
    );
    assert!(
        denied_app_containers(&secret).is_empty(),
        "each run takes its denial back once its own script is gone"
    );
}

/// The lock of a sandbox identity, held by name until dropped, as a
/// process of any account can hold it without running the package.
struct HeldIdentity {
    release: Option<std::sync::mpsc::Sender<()>>,
    holder: Option<std::thread::JoinHandle<()>>,
}

impl HeldIdentity {
    fn hold(profile: &str) -> Self {
        use windows_sys::Win32::Foundation::{CloseHandle, WAIT_ABANDONED, WAIT_OBJECT_0};
        use windows_sys::Win32::System::Threading::{
            CreateMutexExW, ReleaseMutex, WaitForSingleObject,
        };

        let name: Vec<u16> = format!(r"Global\LpmSandboxIdentity-{profile}")
            .encode_utf16()
            .chain([0])
            .collect();
        let (says_held, is_held) = std::sync::mpsc::channel();
        let (release, released) = std::sync::mpsc::channel::<()>();
        // A mutex is let go by the thread that took it.
        let holder = std::thread::spawn(move || {
            // SAFETY: the name is null-terminated and lives through the
            // call. The rights are the two a holder needs: to wait for the
            // mutex and to release it.
            let mutex = unsafe { CreateMutexExW(std::ptr::null(), name.as_ptr(), 0, 0x0010_0001) };
            if mutex.is_null() {
                let _ = says_held.send(false);
                return;
            }
            // SAFETY: `mutex` is a handle this thread owns.
            let taken = unsafe { WaitForSingleObject(mutex, 60_000) };
            let held = taken == WAIT_OBJECT_0 || taken == WAIT_ABANDONED;
            let _ = says_held.send(held);
            if held {
                // Ends when the test releases the lock or drops its end.
                let _ = released.recv();
                // SAFETY: this thread took the mutex above.
                unsafe { ReleaseMutex(mutex) };
            }
            // SAFETY: the handle is closed once, here.
            unsafe { CloseHandle(mutex) };
        });
        let held = is_held.recv().unwrap_or(false);
        let mut identity = Self {
            release: Some(release),
            holder: Some(holder),
        };
        if !held {
            identity.release();
            panic!("couldn't hold the identity's lock");
        }
        identity
    }

    fn release(&mut self) {
        self.release = None;
        if let Some(holder) = self.holder.take() {
            let _ = holder.join();
        }
    }
}

impl Drop for HeldIdentity {
    fn drop(&mut self) {
        self.release();
    }
}

/// What `helper` printed and how it ended. One that hasn't ended by then is
/// stopped and fails the test: it waited for a held identity without
/// limit.
fn output_within_half_a_minute(mut helper: std::process::Command) -> std::process::Output {
    let mut helper = helper
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn helper");
    let ended = ends_within(&mut helper, std::time::Duration::from_secs(30));
    let _ = helper.kill();
    let output = helper.wait_with_output().expect("the helper's output");
    assert!(ended, "the helper had to be stopped: {output:?}");
    output
}

fn profile_of(identity: &[String]) -> &str {
    identity
        .iter()
        .skip_while(|argument| *argument != "--appcontainer-name")
        .nth(1)
        .expect("the identity names its profile")
}

#[test]
fn a_take_back_fails_while_a_process_that_takes_nothing_back_holds_the_identity() {
    let project = tempfile::tempdir().expect("project tempdir");
    let records = tempfile::tempdir().expect("record tempdir");
    let secret = project.path().join(".env");
    fs::write(&secret, "protected-content").expect("seed protected file");
    let record = records.path().join("grants.json");
    let (mut run, sid) =
        start_a_run_that_sleeps("LpmFilesystemHeldLock", project.path(), &record, &secret);
    run.stop();
    let take_back = || {
        let mut take_back = std::process::Command::new(env!("CARGO_BIN_EXE_lpm-sandbox-helper"));
        take_back.args(&run.identity).arg("--take-back-run");
        output_within_half_a_minute(take_back)
    };
    let mut held = HeldIdentity::hold(profile_of(&run.identity));

    let refused = take_back();

    assert!(
        !refused.status.success(),
        "nothing was taken back, and the take-back said it had been: {refused:?}"
    );
    assert!(
        String::from_utf8_lossy(&refused.stderr).contains("holds this package's sandbox identity"),
        "{refused:?}"
    );
    assert_eq!(
        denied_app_containers(&secret),
        std::slice::from_ref(&sid),
        "the denial stays set"
    );
    assert_eq!(
        recorded_denials(&record),
        std::slice::from_ref(&secret),
        "and the record still names it, for whoever takes it back later"
    );

    held.release();
    let taken_back = take_back();

    assert!(taken_back.status.success(), "{taken_back:?}");
    assert!(denied_app_containers(&secret).is_empty());
    assert!(recorded_denials(&record).is_empty());
}

#[test]
fn a_take_back_ends_once_the_identity_s_holder_has_taken_the_stopped_run_back() {
    let project = tempfile::tempdir().expect("project tempdir");
    let records = tempfile::tempdir().expect("record tempdir");
    let secret = project.path().join(".env");
    fs::write(&secret, "protected-content").expect("seed protected file");
    let record = records.path().join("grants.json");
    let (run, sid) = stop_the_helper_of_a_run_in_a_held_job(
        "LpmFilesystemHolderTakesBack",
        project.path(),
        &record,
        &secret,
    );
    let job = run.job.as_ref().expect("the run's Job");
    let _held = HeldIdentity::hold(profile_of(&run.identity));
    let mut take_back = std::process::Command::new(env!("CARGO_BIN_EXE_lpm-sandbox-helper"))
        .args(&run.identity)
        .args(["--job", job.name.as_str()])
        .arg("--take-back-run")
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn the take-back");
    let waits = !ends_within(&mut take_back, std::time::Duration::from_secs(1));

    // The part of the identity's next run, which holds the identity: once
    // it has taken the stopped run back, the record no longer names that
    // run's Job. The run's entries stay recorded here, so that the test's
    // cleanup takes them back.
    let mut recorded: serde_json::Value =
        serde_json::from_slice(&fs::read(&record).expect("the run recorded what it set"))
            .expect("the record is JSON");
    recorded["run"]["jobs"] = serde_json::json!([]);
    fs::write(&record, serde_json::to_vec(&recorded).unwrap()).expect("rewrite the record");
    let ended = ends_within(&mut take_back, std::time::Duration::from_secs(10));
    let _ = take_back.kill();
    let taken_back = take_back
        .wait_with_output()
        .expect("the take-back's output");

    assert!(waits, "the record still named the run: {taken_back:?}");
    assert!(ended && taken_back.status.success(), "{taken_back:?}");
    assert_eq!(
        denied_app_containers(&secret),
        std::slice::from_ref(&sid),
        "a take-back that doesn't hold the identity changes nothing itself"
    );
    assert!(!run.script_read_the_secret());
}

#[test]
fn a_run_says_that_it_waits_for_the_process_that_holds_its_identity() {
    let project = tempfile::tempdir().expect("project tempdir");
    let created = project.path().join("created-by-child.txt");
    let mut argv = helper_argv_base();
    argv.extend(
        [
            "--writable-dir",
            &project.path().to_string_lossy(),
            "--",
            POWERSHELL,
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            &ps_write_file(&created.to_string_lossy()),
        ]
        .map(String::from),
    );
    let mut held = HeldIdentity::hold(profile_of(&argv));
    let mut run = std::process::Command::new(env!("CARGO_BIN_EXE_lpm-sandbox-helper"))
        .args(&argv)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn helper");

    let ended_while_held = ends_within(&mut run, std::time::Duration::from_secs(8));
    let started_its_script = created.exists();
    held.release();
    let ended = ends_within(&mut run, std::time::Duration::from_secs(120));
    let _ = run.kill();
    let output = run.wait_with_output().expect("the run's output");

    assert!(
        !ended_while_held && !started_its_script,
        "the run didn't wait for the identity: {output:?}"
    );
    assert!(ended && output.status.success(), "{output:?}");
    assert!(created.exists());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("waiting for the process that holds"),
        "{output:?}"
    );
}

/// A release of the identity removes its record while it holds the
/// identity, so the record a run writes must wait for the identity too.
/// Otherwise a run that recorded it before a release ended would go on
/// to grant access that nothing names.
#[test]
fn a_run_records_its_identity_only_once_it_holds_it() {
    use std::io::Read as _;

    const WAITING: &[u8] = b"waiting for the process that holds";
    let project = tempfile::tempdir().expect("project tempdir");
    let mut argv = helper_argv_base();
    argv.extend(
        [
            "--writable-dir",
            &project.path().to_string_lossy(),
            "--",
            r"C:\Windows\System32\cmd.exe",
            "/d",
            "/c",
            "exit 0",
        ]
        .map(String::from),
    );
    let record = identity_record_of(&argv);
    let mut held = HeldIdentity::hold(profile_of(&argv));
    let mut run = std::process::Command::new(env!("CARGO_BIN_EXE_lpm-sandbox-helper"))
        .args(&argv)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn helper");
    let mut stderr = run.stderr.take().expect("the run's stderr");
    let (says_it_waits, waits) = std::sync::mpsc::channel();
    let reader = std::thread::spawn(move || {
        let mut printed = Vec::new();
        let mut buffer = [0u8; 1024];
        loop {
            let read = stderr.read(&mut buffer).unwrap_or(0);
            if read == 0 {
                return printed;
            }
            printed.extend_from_slice(&buffer[..read]);
            if printed.windows(WAITING.len()).any(|said| said == WAITING) {
                let _ = says_it_waits.send(());
            }
        }
    });

    let waited = waits
        .recv_timeout(std::time::Duration::from_secs(60))
        .is_ok();
    let recorded_while_held = record.exists();
    held.release();
    let ended = ends_within(&mut run, std::time::Duration::from_secs(120));
    let _ = run.kill();
    let status = run.wait().expect("the run's exit status");
    let printed = String::from_utf8_lossy(&reader.join().unwrap_or_default()).into_owned();

    assert!(
        waited,
        "the run never said that it waits for its identity: {printed}"
    );
    assert!(
        !recorded_while_held,
        "the run recorded an identity it didn't hold"
    );
    assert!(ended && status.success(), "{status:?}: {printed}");
    let recorded: serde_json::Value =
        serde_json::from_slice(&fs::read(&record).expect("the run recorded its identity"))
            .expect("an identity record");
    assert_eq!(recorded["package"], RECORDED_PACKAGE);
    assert_eq!(
        recorded["project"].as_str().map(std::path::PathBuf::from),
        record.parent().map(std::path::Path::to_path_buf)
    );
}

#[test]
fn a_cleanup_fails_rather_than_wait_without_limit_for_the_process_that_holds_its_identity() {
    let records = tempfile::tempdir().expect("record tempdir");
    let identity = RunIdentity(vec![
        "--protocol-version".to_string(),
        lpm_sandbox::helper_protocol::PROTOCOL_VERSION.to_string(),
        "--appcontainer-name".into(),
        format!("LpmFilesystemBusy-{}", std::process::id()),
        "--grant-record".into(),
        records
            .path()
            .join("grants.json")
            .to_string_lossy()
            .into_owned(),
    ]);
    let record = identity_record_of(&identity.0);
    fs::write(&record, "{}").expect("record the identity");
    let mut held = HeldIdentity::hold(profile_of(&identity.0));

    let refused = output_within_half_a_minute(cleanup_of(&identity.0));

    assert!(!refused.status.success(), "{refused:?}");
    assert!(
        String::from_utf8_lossy(&refused.stderr).contains("nothing of it was cleaned up"),
        "{refused:?}"
    );
    assert!(
        record.exists(),
        "a cleanup that didn't hold the identity keeps its record"
    );

    held.release();
    let cleaned_up = output_within_half_a_minute(cleanup_of(&identity.0));

    assert!(cleaned_up.status.success(), "{cleaned_up:?}");
    assert!(!record.exists(), "the identity's record goes with it");
}

/// The run's helper is started by a `cmd.exe` the test can end, and what
/// it writes to stderr comes back through that process's pipe, which
/// closes once the helper has ended too.
#[test]
fn a_run_stops_waiting_for_its_identity_once_the_process_that_started_it_ends() {
    use std::io::Read as _;
    use std::os::windows::process::CommandExt as _;

    let project = tempfile::tempdir().expect("project tempdir");
    let created = project.path().join("created-by-child.txt");
    let mut argv = helper_argv_base();
    argv.extend(["--writable-dir", &project.path().to_string_lossy()].map(String::from));
    let quoted: Vec<String> = argv
        .iter()
        .map(|argument| format!("\"{argument}\""))
        .collect();
    let mut held = HeldIdentity::hold(profile_of(&argv));
    let mut caller = std::process::Command::new(r"C:\Windows\System32\cmd.exe");
    caller
        .raw_arg(format!(
            "/d /s /c \"\"{}\" {} -- C:\\Windows\\System32\\cmd.exe /d /c mkdir \"{}\"\"",
            env!("CARGO_BIN_EXE_lpm-sandbox-helper"),
            quoted.join(" "),
            created.display(),
        ))
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped());
    let mut caller = caller.spawn().expect("start the helper's caller");
    let mut stderr = caller.stderr.take().expect("the caller's stderr");
    let (said, heard) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut buffer = [0u8; 1024];
        loop {
            let read = stderr.read(&mut buffer).unwrap_or(0);
            if said.send(buffer[..read].to_vec()).is_err() || read == 0 {
                return;
            }
        }
    });
    let mut printed = String::new();
    let mut closed_before = |wanted: Option<&str>, limit: std::time::Duration| {
        let deadline = std::time::Instant::now() + limit;
        loop {
            if wanted.is_some_and(|wanted| printed.contains(wanted)) {
                return false;
            }
            match heard.recv_timeout(deadline.saturating_duration_since(std::time::Instant::now()))
            {
                Ok(bytes) if bytes.is_empty() => return true,
                Ok(bytes) => printed.push_str(&String::from_utf8_lossy(&bytes)),
                Err(_) => return false,
            }
        }
    };

    let ended_before_it_waited = closed_before(
        Some("waiting for the process that holds"),
        std::time::Duration::from_secs(60),
    );
    let _ = caller.kill();
    let _ = caller.wait();
    let helper_ended = closed_before(None, std::time::Duration::from_secs(20));
    held.release();

    assert!(
        !ended_before_it_waited && printed.contains("waiting for the process that holds"),
        "the run never said that it waits: {printed}"
    );
    assert!(
        helper_ended,
        "the run went on waiting for its identity after the process that started it ended: {printed}"
    );
    assert!(!created.exists(), "and it started no script");
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

/// A junction in `folder` to a folder beside it, or `None` where none can
/// be made. `mklink /J` makes one without administrator rights, unlike a
/// symbolic link.
fn junction_in(folder: &std::path::Path) -> Option<std::path::PathBuf> {
    let real_dir = folder.join("real");
    let junction = folder.join("junction");
    fs::create_dir(&real_dir).expect("create real dir");
    let status = std::process::Command::new("cmd")
        .args([
            "/c",
            "mklink",
            "/J",
            &junction.to_string_lossy(),
            &real_dir.to_string_lossy(),
        ])
        .status();
    match status {
        Ok(status) if status.success() => Some(junction),
        Ok(_) => {
            eprintln!("skipping: mklink /J failed (junction creation unsupported here)");
            None
        }
        Err(_) => {
            eprintln!("skipping: mklink /J not available in this environment");
            None
        }
    }
}

/// A run records its identity before it sets anything, so one refused
/// partway still leaves the record its release starts from.
#[test]
fn a_run_refused_after_it_holds_its_identity_leaves_it_recorded() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let Some(junction) = junction_in(tmp.path()) else {
        return;
    };
    let mut argv = helper_argv_base();
    argv.extend([
        "--writable-dir".into(),
        junction.to_string_lossy().into_owned(),
        "--".into(),
        r"C:\Windows\System32\whoami.exe".into(),
    ]);
    let record = identity_record_of(&argv);

    let out = Command::cargo_bin("lpm-sandbox-helper")
        .expect("locate helper")
        .args(&argv)
        .output()
        .expect("spawn helper");

    assert!(
        !out.status.success(),
        "the run should be refused at the junction: {out:?}"
    );
    assert!(record.exists(), "the refused run left no record: {out:?}");
}

#[test]
fn helper_refuses_reparse_point_root_with_named_error() {
    // Refuse a reparse-point root as a writable-dir / readable-dir
    // grant target: granting on it would grant its target. The walker
    // must refuse rather than follow the junction.
    let tmp = tempfile::tempdir().expect("tempdir");
    let Some(junction) = junction_in(tmp.path()) else {
        return;
    };

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
