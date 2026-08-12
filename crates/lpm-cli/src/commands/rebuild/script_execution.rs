use super::process_tree::wait_with_timeout;
use lpm_common::sanitize_terminal_multiline;
use lpm_sandbox::SandboxMode;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::Child;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::Duration;

#[allow(clippy::too_many_arguments)]
pub(super) fn execute_script(
    cmd: &str,
    pkg_name: &str,
    pkg_version: &str,
    package_dir: &Path,
    project_dir: &Path,
    env: &HashMap<String, String>,
    timeout: &Duration,
    sandbox_mode: SandboxMode,
    sandbox_options: &lpm_sandbox::SandboxOptions,
    extra_write_dirs: &[PathBuf],
    extra_secret_read_allow: &[PathBuf],
    store_root: &Path,
    home_dir: &Path,
    tmpdir: &Path,
) -> Result<(), String> {
    // Build the environment the same way the legacy path did: start
    // from the sanitized set, strip INIT_CWD + PATH if the caller
    // pre-set them, then append our own INIT_CWD and PATH-with-
    // node_modules/.bin-prepended.
    //
    // : the path string is platform-aware
    // now. Pre-46.2 the helper hardcoded the POSIX `:` separator and
    // the POSIX `/usr/bin:/bin` fallback, which produced a malformed
    // PATH on Windows: the local `node_modules\.bin` shim got fused
    // into the same entry as the inherited system PATH and neither
    // resolved, so commands like `tsc`, `webpack`, or any sibling-
    // package binary were invisible to lifecycle scripts even though
    // the sandbox itself succeeded.
    //
    // round-5 : PATH lookup + filter are now
    // case-insensitive. Windows env vars are case-insensitive at the
    // OS level — `std::env::vars()` yields the key with its original
    // case (typically `"Path"` on Windows, `"PATH"` on POSIX). A
    // case-sensitive `env.get("PATH")` returned `None` on Windows
    // even when PATH was populated, so the child got the System32-
    // only fallback and lifecycle scripts couldn't find `node`,
    // `npm`, or any sibling-package binary on the inherited PATH.
    // Same hazard for the filter — letting "Path" through unfiltered
    // worked accidentally because `std::process::Command::env` on
    // Windows does case-insensitive deduplication and our explicit
    // `"PATH"` overrides won, but the LOOKUP path was still broken.
    let envs = build_lifecycle_environment(env, project_dir, tmpdir);

    let start = std::time::Instant::now();

    let mut child = spawn_lifecycle_child(
        cmd,
        pkg_name,
        pkg_version,
        package_dir,
        project_dir,
        &envs,
        sandbox_mode,
        sandbox_options,
        extra_write_dirs,
        extra_secret_read_allow,
        store_root,
        home_dir,
        tmpdir,
    )?;
    let output_readers = spawn_sanitized_output_readers(&mut child);

    let output = wait_with_timeout(child, timeout);
    output_readers.finish_and_join();

    match output {
        Ok(status) => {
            if status.success() {
                let elapsed = start.elapsed();
                tracing::debug!("script completed in {:.1}s", elapsed.as_secs_f64());
                Ok(())
            } else {
                Err(format!("exit code {}", status.code().unwrap_or(-1)))
            }
        }
        Err(e) => Err(e),
    }
}

pub(super) fn build_lifecycle_environment(
    env: &HashMap<String, String>,
    project_dir: &Path,
    tmpdir: &Path,
) -> Vec<(String, String)> {
    let parent_path = find_env_case_insensitive(env, "PATH");
    let path_value = build_lifecycle_path(project_dir, parent_path);
    let mut envs: Vec<(String, String)> = env
        .iter()
        .filter(|(k, _)| {
            !k.eq_ignore_ascii_case("PATH")
                && !k.eq_ignore_ascii_case("INIT_CWD")
                && !k.eq_ignore_ascii_case("TMPDIR")
                && !k.eq_ignore_ascii_case("TMP")
                && !k.eq_ignore_ascii_case("TEMP")
        })
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    envs.push(("INIT_CWD".to_string(), project_dir.display().to_string()));
    envs.push(("PATH".to_string(), path_value));
    let tmp = tmpdir.display().to_string();
    envs.push(("TMPDIR".to_string(), tmp.clone()));
    envs.push(("TMP".to_string(), tmp.clone()));
    envs.push(("TEMP".to_string(), tmp));
    envs
}

/// — resolve the live per-package directory where lifecycle
/// scripts should `current_dir` to.
///
/// **Why this matters.** Previously, `execute_script` passed
/// `pkg.store_path` (the global `~/.lpm/store/v1/<pkg>@<ver>/` location)
/// as the script's working directory. Scripts that resolve sibling
/// dependencies via `require.resolve()` failed because the global store
/// has no `node_modules/` upstream — Node's module resolution walks
/// from `__dirname` upward looking for `node_modules/` directories, and
/// in the global store there are none until you reach `~/.lpm/store/`
/// (and even then, no sibling deps for the package). esbuild's
/// `install.js` is the canonical reproducer: it does
/// `require.resolve('@esbuild/<platform>/bin/esbuild')` which fails
/// with "Failed to find package @esbuild/<platform> on the file
/// system" before falling through to a network-install fallback.
///
/// **Two layouts to handle.** The default isolated linker places each
/// package at `<project>/.lpm/wrappers/<safe_name>@<version>/node_modules/<name>/`
/// with sibling deps symlinked into the same wrapper's
/// `node_modules/`. The opt-in hoisted linker (`LPM_LINKER=hoisted`)
/// places packages at `<project>/node_modules/<name>/` with all deps
/// hoisted to the root `node_modules/`; its incremental state lives
/// at `<project>/.lpm/hoisted/metadata.json` (post-symmetry), but the
/// per-package directory probe in this function only cares about the
/// hoisted *package* location, which is unchanged. We probe both
/// Spawn a lifecycle script through the sandbox backend. The caller
/// must pass an already-resolved live package directory; this helper
/// only prepares the command and delegates containment to `lpm_sandbox`.
#[allow(clippy::too_many_arguments)]
pub(super) fn spawn_lifecycle_child(
    cmd: &str,
    pkg_name: &str,
    pkg_version: &str,
    package_dir: &Path,
    project_dir: &Path,
    envs: &[(String, String)],
    sandbox_mode: SandboxMode,
    sandbox_options: &lpm_sandbox::SandboxOptions,
    extra_write_dirs: &[PathBuf],
    extra_secret_read_allow: &[PathBuf],
    store_root: &Path,
    home_dir: &Path,
    tmpdir: &Path,
) -> Result<std::process::Child, String> {
    use lpm_sandbox::{SandboxSpec, SandboxStdio, SandboxedCommand, new_for_platform_with_options};

    let spec = SandboxSpec {
        package_dir: package_dir.to_path_buf(),
        project_dir: project_dir.to_path_buf(),
        package_name: pkg_name.to_string(),
        package_version: pkg_version.to_string(),
        store_root: store_root.to_path_buf(),
        home_dir: home_dir.to_path_buf(),
        tmpdir: tmpdir.to_path_buf(),
        secret_read_allow: extra_secret_read_allow.to_vec(),
        extra_write_dirs: extra_write_dirs.to_vec(),
    };
    // thread the resolved `[sandbox] allow-degraded`
    // opt-in through so per-package sandbox construction picks the
    // same posture the pre-probe used. Posture mismatches between
    // pre-probe and per-package construction would surface as a
    // visible behavior change midway through an install, which is
    // exactly the inconsistency the shared `sandbox_options` value
    // exists to prevent.
    let sandbox = new_for_platform_with_options(spec, sandbox_mode, sandbox_options.clone())
        .map_err(|e| format!("sandbox init failed: {e}"))?;

    let (shell_program, shell_args) = platform_shell_invocation(cmd);
    let mut sbcmd = SandboxedCommand::new(shell_program);
    for arg in shell_args {
        sbcmd = sbcmd.arg(arg);
    }
    sbcmd = sbcmd
        .current_dir(package_dir)
        .envs_cleared(envs.iter().map(|(k, v)| (k.clone(), v.clone())));
    sbcmd.stdout = SandboxStdio::Piped;
    sbcmd.stderr = SandboxStdio::Piped;
    sbcmd.stdin = SandboxStdio::Inherit;

    sandbox
        .spawn(sbcmd)
        .map_err(|e| format!("failed to spawn: {e}"))
}

struct OutputReaders {
    stdout: Option<JoinHandle<()>>,
    stderr: Option<JoinHandle<()>>,
    process_finished: Arc<AtomicBool>,
}

impl OutputReaders {
    fn finish_and_join(self) {
        self.process_finished.store(true, Ordering::Release);
        if let Some(handle) = self.stdout {
            let _ = handle.join();
        }
        if let Some(handle) = self.stderr {
            let _ = handle.join();
        }
    }
}

fn spawn_sanitized_output_readers(child: &mut Child) -> OutputReaders {
    let process_finished = Arc::new(AtomicBool::new(false));
    let stdout = child.stdout.take().map(|stdout| {
        let process_finished = Arc::clone(&process_finished);
        std::thread::spawn(move || {
            copy_sanitized_output(stdout, std::io::stdout(), &process_finished)
        })
    });
    let stderr = child.stderr.take().map(|stderr| {
        let process_finished = Arc::clone(&process_finished);
        std::thread::spawn(move || {
            copy_sanitized_output(stderr, std::io::stderr(), &process_finished)
        })
    });
    OutputReaders {
        stdout,
        stderr,
        process_finished,
    }
}

#[cfg(unix)]
fn copy_sanitized_output<R, W>(mut reader: R, mut writer: W, process_finished: &AtomicBool)
where
    R: Read + std::os::fd::AsRawFd,
    W: Write,
{
    let mut buf = [0_u8; 8192];
    let mut post_finish_bytes = 0_usize;
    loop {
        if !wait_for_output(reader.as_raw_fd(), process_finished) {
            break;
        }
        let read = match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(read) => read,
            Err(_) => break,
        };
        let lossy = String::from_utf8_lossy(&buf[..read]);
        let safe = sanitize_terminal_multiline(&lossy);
        if writer.write_all(safe.as_bytes()).is_err() {
            break;
        }
        if writer.flush().is_err() {
            break;
        }
        if process_finished.load(Ordering::Acquire) {
            post_finish_bytes = post_finish_bytes.saturating_add(read);
            if post_finish_bytes >= 1024 * 1024 {
                break;
            }
        }
    }
}

#[cfg(unix)]
fn wait_for_output(fd: std::os::fd::RawFd, process_finished: &AtomicBool) -> bool {
    let mut poll_fd = libc::pollfd {
        fd,
        events: libc::POLLIN | libc::POLLHUP,
        revents: 0,
    };
    loop {
        // SAFETY: poll_fd points to one initialized pollfd for the duration of
        // the call. The descriptor remains owned by the reader thread.
        let timeout_ms = if process_finished.load(Ordering::Acquire) {
            0
        } else {
            50
        };
        let result = unsafe { libc::poll(&mut poll_fd, 1, timeout_ms) };
        if result > 0 {
            return poll_fd.revents & (libc::POLLIN | libc::POLLHUP) != 0;
        }
        if result == 0 {
            if process_finished.load(Ordering::Acquire) {
                return false;
            }
            continue;
        }
        if std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
            return false;
        }
    }
}

#[cfg(windows)]
fn copy_sanitized_output<R, W>(mut reader: R, mut writer: W, process_finished: &AtomicBool)
where
    R: Read + std::os::windows::io::AsRawHandle,
    W: Write,
{
    let mut buf = [0_u8; 8192];
    let mut post_finish_bytes = 0_usize;
    loop {
        if !wait_for_windows_output(reader.as_raw_handle(), process_finished) {
            break;
        }
        let read = match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(read) => read,
            Err(_) => break,
        };
        let lossy = String::from_utf8_lossy(&buf[..read]);
        let safe = sanitize_terminal_multiline(&lossy);
        if writer.write_all(safe.as_bytes()).is_err() {
            break;
        }
        if writer.flush().is_err() {
            break;
        }
        if process_finished.load(Ordering::Acquire) {
            post_finish_bytes = post_finish_bytes.saturating_add(read);
            if post_finish_bytes >= 1024 * 1024 {
                break;
            }
        }
    }
}

#[cfg(windows)]
fn wait_for_windows_output(
    handle: std::os::windows::io::RawHandle,
    process_finished: &AtomicBool,
) -> bool {
    use windows_sys::Win32::System::Pipes::PeekNamedPipe;

    loop {
        let mut available = 0_u32;
        // SAFETY: handle belongs to the reader thread and remains valid for the
        // call. The null buffer requests only the available-byte count.
        let result = unsafe {
            PeekNamedPipe(
                handle as _,
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                &mut available,
                std::ptr::null_mut(),
            )
        };
        if result == 0 {
            return false;
        }
        if available > 0 {
            return true;
        }
        if process_finished.load(Ordering::Acquire) {
            return false;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[cfg(not(any(unix, windows)))]
fn copy_sanitized_output<R, W>(mut reader: R, mut writer: W, process_finished: &AtomicBool)
where
    R: Read,
    W: Write,
{
    let mut buf = [0_u8; 8192];
    loop {
        if process_finished.load(Ordering::Acquire) {
            break;
        }
        let read = match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(read) => read,
            Err(_) => break,
        };
        let lossy = String::from_utf8_lossy(&buf[..read]);
        let safe = sanitize_terminal_multiline(&lossy);
        if writer.write_all(safe.as_bytes()).is_err() {
            break;
        }
        if writer.flush().is_err() {
            break;
        }
    }
}

#[cfg(all(test, unix))]
mod timeout_output_tests {
    use super::{copy_sanitized_output, spawn_sanitized_output_readers};
    use crate::commands::rebuild::process_tree::wait_with_timeout;
    use std::io::Write;
    use std::os::unix::net::UnixStream;
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};
    use std::sync::atomic::AtomicBool;
    use std::time::{Duration, Instant};

    struct ProcessGuard(u32);

    impl Drop for ProcessGuard {
        fn drop(&mut self) {
            // SAFETY: the PID was written by the isolated fixture process. The
            // guard exists only to ensure a failed assertion cannot leak it.
            unsafe {
                libc::kill(self.0 as libc::pid_t, libc::SIGKILL);
            }
        }
    }

    fn write_detach_helper(path: &std::path::Path) {
        std::fs::write(
            path,
            r#"import os
import sys
import time

if os.fork() != 0:
    os._exit(0)
os.setsid()
if os.fork() != 0:
    os._exit(0)
with open(sys.argv[1], "w", encoding="utf-8") as pid_file:
    pid_file.write(str(os.getpid()))
    pid_file.flush()
time.sleep(4)
"#,
        )
        .unwrap();
    }

    fn wait_for_daemon_pid(pid_file: &std::path::Path) -> u32 {
        let pid_deadline = Instant::now() + Duration::from_secs(2);
        loop {
            if let Ok(text) = std::fs::read_to_string(pid_file)
                && let Ok(pid) = text.parse::<u32>()
            {
                return pid;
            }
            assert!(
                Instant::now() < pid_deadline,
                "detached fixture did not publish its PID"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn timed_out_output_readers_do_not_wait_for_reparented_pipe_holder() {
        let fixture = tempfile::tempdir().unwrap();
        let helper = fixture.path().join("detach.py");
        let pid_file = fixture.path().join("daemon.pid");
        write_detach_helper(&helper);

        let mut command = Command::new("/bin/sh");
        command
            .args([
                "-c",
                r#"python3 "$1" "$2" & while [ ! -s "$2" ]; do sleep 0.01; done; sleep 4"#,
                "lpm-timeout-fixture",
            ])
            .arg(&helper)
            .arg(&pid_file)
            .process_group(0)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command.spawn().unwrap();
        let output_readers = spawn_sanitized_output_readers(&mut child);

        let daemon_pid = wait_for_daemon_pid(&pid_file);
        let _daemon_guard = ProcessGuard(daemon_pid);

        let start = Instant::now();
        let error = wait_with_timeout(child, &Duration::from_millis(100)).unwrap_err();
        output_readers.finish_and_join();
        let elapsed = start.elapsed();

        assert!(error.starts_with("timeout after "));
        assert!(
            elapsed < Duration::from_secs(2),
            "output readers exceeded lifecycle timeout bound: {elapsed:?}"
        );
    }

    #[test]
    fn completed_output_readers_do_not_wait_for_reparented_pipe_holder() {
        let fixture = tempfile::tempdir().unwrap();
        let helper = fixture.path().join("detach.py");
        let pid_file = fixture.path().join("daemon.pid");
        write_detach_helper(&helper);

        let mut command = Command::new("/bin/sh");
        command
            .args([
                "-c",
                r#"python3 "$1" "$2" & while [ ! -s "$2" ]; do sleep 0.01; done; exit 0"#,
                "lpm-completed-fixture",
            ])
            .arg(&helper)
            .arg(&pid_file)
            .process_group(0)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command.spawn().unwrap();
        let output_readers = spawn_sanitized_output_readers(&mut child);
        let daemon_pid = wait_for_daemon_pid(&pid_file);
        let _daemon_guard = ProcessGuard(daemon_pid);

        let start = Instant::now();
        let status = wait_with_timeout(child, &Duration::from_secs(2)).unwrap();
        output_readers.finish_and_join();
        let elapsed = start.elapsed();

        assert!(status.success());
        assert!(
            elapsed < Duration::from_secs(2),
            "output readers waited for a completed script's detached pipe holder: {elapsed:?}"
        );
    }

    #[test]
    fn finished_output_reader_drains_bytes_already_in_pipe() {
        let (mut pipe_writer, pipe_reader) = UnixStream::pair().unwrap();
        pipe_writer.write_all(b"lifecycle tail\n").unwrap();
        let finished = AtomicBool::new(true);
        let mut output = Vec::new();

        copy_sanitized_output(pipe_reader, &mut output, &finished);

        assert_eq!(output, b"lifecycle tail\n");
    }
}

/// Case-insensitive env-var lookup against the sanitized env map.
/// Returns the first value whose key matches `target` ignoring ASCII
/// case. POSIX env keys are case-sensitive so this only ever changes
/// behavior on Windows, where `std::env::vars()` yields `"Path"`
/// (registry-preserved case) but the rest of the codebase looks up
/// `"PATH"`. Without this helper, lifecycle scripts on Windows ran
/// with the System32-only fallback PATH because the parent PATH
/// pass-through was silently missed.
fn find_env_case_insensitive<'a>(
    env: &'a HashMap<String, String>,
    target: &str,
) -> Option<&'a str> {
    env.iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(target))
        .map(|(_, v)| v.as_str())
}

/// Compose the `PATH` env var passed to a lifecycle script. Prepends
/// the project's `node_modules/.bin` so locally-installed binaries
/// shadow system ones (matches npm/yarn/pnpm), then appends either
/// the inherited PATH if the caller provided one or a minimal
/// platform-appropriate fallback.
///
/// Platform-aware on both axes:
/// - **Separator**: `:` on POSIX, `;` on Windows.
/// - **`.bin` shape**: `node_modules/.bin` resolves identically on
///   both platforms (Windows accepts forward slashes), but we render
///   via `Path::join` + `Path::display` so the produced string uses
///   the host's native separator.
/// - **Fallback**: `/usr/bin:/bin` on POSIX is the long-standing
///   minimum. Windows gets `C:\Windows\System32;C:\Windows;C:\Windows\System32\Wbem`
///   — System32 for `cmd.exe` / `where.exe` / OS DLLs, the bare
///   Windows dir for the small set of binaries that live one level
///   up, and `Wbem` for `wmic` (rarely used but harmless to keep).
///   Lifecycle scripts that need PowerShell or Git Bash should
///   declare them via the existing PATH passthrough, not rely on
///   this fallback.
///
/// Pre-this was inlined with hardcoded POSIX separators
/// and fallback. The Windows sandbox spawn would then succeed but
/// produce a malformed PATH (`node_modules\.bin:<parent-path>`),
/// rendering local shims invisible to scripts even though the
/// sandbox itself was working correctly.
pub(super) fn build_lifecycle_path(project_dir: &Path, parent_path: Option<&str>) -> String {
    let bin_dir = project_dir.join("node_modules").join(".bin");
    #[cfg(unix)]
    {
        format!(
            "{}:{}",
            bin_dir.display(),
            parent_path.unwrap_or("/usr/bin:/bin"),
        )
    }
    #[cfg(windows)]
    {
        format!(
            "{};{}",
            bin_dir.display(),
            parent_path.unwrap_or(r"C:\Windows\System32;C:\Windows;C:\Windows\System32\Wbem"),
        )
    }
    #[cfg(not(any(unix, windows)))]
    {
        format!(
            "{}:{}",
            bin_dir.display(),
            parent_path.unwrap_or("/usr/bin:/bin"),
        )
    }
}

/// Pick the right shell program + argv to run a lifecycle script's
/// shell-string verbatim. POSIX hosts get `sh -c <cmd>`, matching the
/// way npm/yarn/pnpm spawn lifecycle scripts. Windows gets
/// `cmd.exe /D /C <cmd>` — `/D` skips AutoRun (so the script doesn't
/// inherit shell hooks from `HKCU\Software\Microsoft\Command Processor`),
/// `/C` runs the command and terminates. Both shells are guaranteed
/// to be on PATH on their respective platforms.
///
/// This was hardcoded to `sh -c` before because the
/// previous sandbox returned `UnsupportedPlatform` on Windows, so the
/// lifecycle path never reached spawn there. With the real backend
/// landed, dispatch has to be platform-aware to make end-to-end
/// installs work on Windows.
pub(super) fn platform_shell_invocation(cmd: &str) -> (&'static str, Vec<String>) {
    #[cfg(unix)]
    {
        ("sh", vec!["-c".to_string(), cmd.to_string()])
    }
    #[cfg(windows)]
    {
        (
            "cmd.exe",
            vec!["/D".to_string(), "/C".to_string(), cmd.to_string()],
        )
    }
    #[cfg(not(any(unix, windows)))]
    {
        ("sh", vec!["-c".to_string(), cmd.to_string()])
    }
}
