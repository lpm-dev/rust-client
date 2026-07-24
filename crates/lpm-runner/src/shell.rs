//! Cross-platform shell abstraction for spawning commands.
//!
//! Handles `sh -c` on Unix and `cmd /C` on Windows, with proper
//! PATH injection, `.env` variable injection, and environment inheritance.
//!
//! ## Signal handling
//!
//! On Unix, `sh -c` creates a process group. When the user presses Ctrl+C,
//! the terminal sends SIGINT to the entire foreground process group, so both
//! the shell and the child process receive the signal. We don't need to
//! manually forward signals.
//!
//! However, if the child process is killed by a signal (e.g., SIGINT),
//! `ExitStatus::code()` returns `None` on Unix. We handle this by extracting
//! the signal number and translating it to a conventional exit code (128 + signal).

use lpm_common::{LpmError, sanitize_terminal_inline};
use std::collections::HashMap;
use std::path::Path;
use std::process::{Command, ExitStatus, Stdio};

use crate::dev_endpoint::{DevEndpoint, ListenerSnapshot};

/// Inherited-env names that MUST be stripped from any `lpm run` /
/// `lpm exec` child before spawn.
///
/// H21: the script runner spawns `sh -c <cmd>` (Unix) or
/// `cmd /C <cmd>` (Windows) with no `env_clear()` and no scrub of
/// the inherited process env. Pre-fix, every parent env variable
/// (credential bearers, dynamic-linker hijack hooks) flowed
/// verbatim into the user's `package.json > scripts` body.
///
/// We can't `env_clear` outright — legitimate scripts depend on
/// `HOME`, `USER`, `LANG`, `PATH`, etc. Instead we mirror the
/// lifecycle-script denylist (`STRIPPED_ENV_PATTERNS` in
/// `lpm-cli/src/commands/rebuild.rs`) and explicitly `env_remove`
/// each entry — same posture, applied at the script-runner boundary.
///
/// Credential carriers + dynamic-linker hijacks live in one list;
/// suffix-shaped patterns (`*_SECRET`, `*_PASSWORD`, etc.) get
/// stripped programmatically via `STRIPPED_INHERITED_ENV_SUFFIXES`.
const STRIPPED_INHERITED_ENV_PATTERNS: &[&str] = &[
    // Credential carriers
    "LPM_TOKEN",
    "NPM_TOKEN",
    "NODE_AUTH_TOKEN",
    "GITHUB_TOKEN",
    "GH_TOKEN",
    "GITLAB_TOKEN",
    "BITBUCKET_TOKEN",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "AZURE_CLIENT_SECRET",
    "LPM_KEY_PASSPHRASE",
    // Runtime-hijack carriers
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "LD_AUDIT",
    "DYLD_INSERT_LIBRARIES",
    "DYLD_LIBRARY_PATH",
    "DYLD_FRAMEWORK_PATH",
    "DYLD_FALLBACK_LIBRARY_PATH",
    "NODE_OPTIONS",
    "PYTHONPATH",
    "PYTHONSTARTUP",
    "GIT_SSH_COMMAND",
    "BASH_ENV",
    "ENV",
    "PERL5OPT",
    "PERL5LIB",
    "RUBYOPT",
    "RUBYLIB",
];

const STRIPPED_INHERITED_ENV_SUFFIXES: &[&str] = &["_SECRET", "_PASSWORD", "_KEY", "_PRIVATE_KEY"];

/// Strip credential + runtime-hijack inherited env vars from `cmd`
/// before spawn. Must run before any `command.envs(...)` that adds
/// project-resolved `.env` values, so a project that legitimately
/// overrides one of these names via its `.env` file (rare) still
/// takes effect.
///
/// Whitelisted: explicit project `envs` map values flowing through
/// `ShellCommand.envs`, since those are project-controlled and
/// already gated by the project's `.env` policy.
///
/// Crate-public so `dlx::build_dlx_command` (which spawns a
/// registry-distributed binary directly with no sandbox) can apply
/// the same scrub.
pub(crate) fn strip_inherited_env_hooks(cmd: &mut Command) {
    for &pattern in STRIPPED_INHERITED_ENV_PATTERNS {
        cmd.env_remove(pattern);
    }
    for (key, _value) in std::env::vars() {
        let upper = key.to_ascii_uppercase();
        if STRIPPED_INHERITED_ENV_SUFFIXES
            .iter()
            .any(|suffix| upper.ends_with(suffix))
        {
            cmd.env_remove(&key);
        }
    }
}

/// Max bytes accumulated per captured stream (stdout OR stderr).
///
/// Mirrors the post-execution truncation cap in `commands::run` so the
/// in-memory buffer never grows past it. Pre-fix, a chatty task could
/// produce gigabytes of stdout, fill up `String`, and only get
/// truncated AFTER the buffer was already in RAM (or written to a
/// `stdout.log` cache file). With this cap, accumulation halts at
/// 10 MiB while the reader keeps draining the pipe so the child
/// doesn't block — the truncation marker is appended once.
const MAX_CAPTURED_STREAM_BYTES: usize = 10 * 1024 * 1024;

/// Append `line` (plus a newline) to `buf` unless that would push
/// `buf.len()` past the cap; when the cap is first crossed, push a
/// one-shot truncation marker and silently drop subsequent lines.
///
/// The reader thread should KEEP READING after this returns so the
/// child's pipe doesn't fill up and stall the producer — we just
/// stop allocating into the buffer.
fn push_capped_line(buf: &mut String, line: &str) {
    if buf.len() >= MAX_CAPTURED_STREAM_BYTES {
        // Marker already written; silently drain.
        return;
    }
    let remaining = MAX_CAPTURED_STREAM_BYTES - buf.len();
    if line.len() < remaining {
        buf.push_str(line);
        buf.push('\n');
        return;
    }
    if remaining > 0 {
        let mut cut = remaining.saturating_sub(1);
        // Land on a UTF-8 boundary so we don't truncate mid-codepoint.
        while cut > 0 && !line.is_char_boundary(cut) {
            cut -= 1;
        }
        buf.push_str(&line[..cut]);
        buf.push('\n');
    }
    buf.push_str(&format!(
        "[output truncated at {} MiB]\n",
        MAX_CAPTURED_STREAM_BYTES / (1024 * 1024),
    ));
}

/// Configuration for spawning a shell command.
pub struct ShellCommand<'a> {
    /// The command string to execute (passed to `sh -c` / `cmd /C`).
    pub command: &'a str,
    /// Working directory for the command.
    pub cwd: &'a Path,
    /// The PATH environment variable to use (with .bin dirs prepended).
    pub path: &'a str,
    /// Additional environment variables to inject (e.g., from `.env` files).
    /// These are added to the inherited environment. PATH is set separately.
    pub envs: &'a HashMap<String, String>,
}

pub type EndpointResultCallback =
    Box<dyn FnOnce(Result<Option<DevEndpoint>, String>) + Send + 'static>;

/// Spawn a shell command and wait for it to complete.
///
/// Returns the exit status. Stdio is inherited so the child process
/// can interact with the terminal directly. This deliberately gives the child
/// ownership of the terminal; LPM cannot sanitize output on this raw path.
pub fn spawn_shell(cmd: &ShellCommand) -> Result<ExitStatus, LpmError> {
    let (shell, flag) = shell_and_flag();

    let mut command = Command::new(shell);
    command
        .arg(flag)
        .arg(cmd.command)
        .current_dir(cmd.cwd)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());

    // Scrub credential + runtime-hijack env hooks the parent process
    // inherited (H21). Runs BEFORE project envs so a legitimate
    // project-level override in `.env` can still take effect.
    strip_inherited_env_hooks(&mut command);

    // Inject .env vars, then set PATH AFTER to prevent .env from overriding it
    if !cmd.envs.is_empty() {
        command.envs(cmd.envs);
    }
    command.env("PATH", cmd.path);

    command
        .status()
        .map_err(|e| LpmError::Script(format!("failed to execute '{}': {e}", cmd.command)))
}

pub fn spawn_shell_with_endpoint(
    cmd: &ShellCommand,
    requested_port: Option<u16>,
    stop_requested: std::sync::Arc<std::sync::atomic::AtomicBool>,
    on_endpoint: EndpointResultCallback,
) -> Result<ExitStatus, LpmError> {
    let (shell, flag) = shell_and_flag();
    let baseline = ListenerSnapshot::capture();
    let mut command = Command::new(shell);
    command
        .arg(flag)
        .arg(cmd.command)
        .current_dir(cmd.cwd)
        .stdin(Stdio::inherit())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    strip_inherited_env_hooks(&mut command);
    if !cmd.envs.is_empty() {
        command.envs(cmd.envs);
    }
    command.env("PATH", cmd.path);

    let mut child = command.spawn().map_err(|error| {
        LpmError::Script(format!("failed to execute '{}': {error}", cmd.command))
    })?;
    let root_pid = child.id();
    let child_exited = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let (candidate_tx, candidate_rx) = std::sync::mpsc::channel();
    let stdout_handle =
        spawn_endpoint_output_reader(child.stdout.take(), false, candidate_tx.clone());
    let stderr_handle = spawn_endpoint_output_reader(child.stderr.take(), true, candidate_tx);

    let resolver_project_dir = cmd.cwd.to_path_buf();
    let resolver_child_exited = std::sync::Arc::clone(&child_exited);
    let resolution_failed = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let resolver_failed = std::sync::Arc::clone(&resolution_failed);
    // Script runners can reparent the listener process after discovery, so
    // cancellation retains the verified PID and port instead of relying only
    // on a fresh descendant walk from the original shell.
    let resolved_owner = std::sync::Arc::new(std::sync::Mutex::new(None::<(u32, u16)>));
    let resolver_owner = std::sync::Arc::clone(&resolved_owner);
    let resolver_handle = std::thread::spawn(move || {
        let result = crate::dev_endpoint::resolve_spawned_endpoint(
            &resolver_project_dir,
            root_pid,
            &baseline,
            requested_port,
            &candidate_rx,
            &resolver_child_exited,
            std::time::Duration::from_secs(30),
        );
        if result.is_err() {
            resolver_failed.store(true, std::sync::atomic::Ordering::Release);
        }
        if let Ok(Some(endpoint)) = &result
            && let Some(owner_pid) = endpoint.owner_pid
            && let Ok(mut owner) = resolver_owner.lock()
        {
            *owner = Some((owner_pid, endpoint.target.port));
        }
        on_endpoint(result);
    });

    let status = loop {
        if let Some(status) = child.try_wait().map_err(|error| {
            LpmError::Script(format!("failed to wait for '{}': {error}", cmd.command))
        })? {
            break status;
        }
        if resolution_failed.load(std::sync::atomic::Ordering::Acquire)
            || stop_requested.load(std::sync::atomic::Ordering::Acquire)
        {
            let owner = resolved_owner.lock().ok().and_then(|owner| *owner);
            if let Some((owner_pid, owner_port)) = owner
                && owner_pid != root_pid
            {
                let _ = crate::ports::kill_pid_if_owns_ports(owner_pid, &[owner_port]);
            }
            break crate::ports::terminate_child_process_tree(&mut child).map_err(|error| {
                LpmError::Script(format!("failed to stop '{}': {error}", cmd.command))
            })?;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    };
    child_exited.store(true, std::sync::atomic::Ordering::Release);
    let _ = stdout_handle.join();
    let _ = stderr_handle.join();
    let _ = resolver_handle.join();
    Ok(status)
}

fn spawn_endpoint_output_reader<R>(
    stream: Option<R>,
    is_stderr: bool,
    candidate_tx: std::sync::mpsc::Sender<lpm_common::LocalTarget>,
) -> std::thread::JoinHandle<()>
where
    R: std::io::Read + Send + 'static,
{
    std::thread::spawn(move || {
        let Some(stream) = stream else {
            return;
        };
        let reader = std::io::BufReader::new(stream);
        use std::io::BufRead;
        for line in reader.lines().map_while(Result::ok) {
            for target in crate::dev_endpoint::parse_local_targets(&line) {
                let _ = candidate_tx.send(target);
            }
            let safe = sanitize_terminal_inline(&line);
            if is_stderr {
                eprintln!("{safe}");
            } else {
                println!("{safe}");
            }
        }
    })
}

/// Extract the exit code from an ExitStatus.
///
/// On Unix, if the process was killed by a signal, the exit code is
/// `128 + signal_number` (convention used by bash/sh).
/// On Windows, just returns the exit code directly.
pub fn exit_code(status: &ExitStatus) -> i32 {
    if let Some(code) = status.code() {
        return code;
    }

    // On Unix, a None code means the process was killed by a signal
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(signal) = status.signal() {
            return 128 + signal;
        }
    }

    1 // fallback
}

/// Result of a tee-captured shell execution.
pub struct CapturedOutput {
    /// Exit status.
    pub status: ExitStatus,
    /// Captured stdout (also streamed to terminal).
    pub stdout: String,
    /// Captured stderr (also streamed to terminal).
    pub stderr: String,
}

/// Spawn a shell command with tee-captured stdout/stderr.
///
/// Output is sanitized line-by-line for the live terminal and captured verbatim
/// into strings so stored data keeps its original semantics. Cache replay must
/// sanitize the captured strings again at its terminal boundary.
pub fn spawn_shell_tee(cmd: &ShellCommand) -> Result<CapturedOutput, LpmError> {
    let (shell, flag) = shell_and_flag();

    let mut command = Command::new(shell);
    command
        .arg(flag)
        .arg(cmd.command)
        .current_dir(cmd.cwd)
        .stdin(Stdio::inherit())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    // Scrub credential + runtime-hijack env hooks the parent process
    // inherited (H21). Runs BEFORE project envs so a legitimate
    // project-level override in `.env` can still take effect.
    strip_inherited_env_hooks(&mut command);

    // Inject .env vars, then set PATH AFTER to prevent .env from overriding it
    if !cmd.envs.is_empty() {
        command.envs(cmd.envs);
    }
    command.env("PATH", cmd.path);

    let mut child = command
        .spawn()
        .map_err(|e| LpmError::Script(format!("failed to execute '{}': {e}", cmd.command)))?;

    // Take piped streams
    let child_stdout = child.stdout.take();
    let child_stderr = child.stderr.take();

    // Tee stdout: read from pipe, write to terminal + capped buffer
    let stdout_handle = std::thread::spawn(move || -> String {
        let mut buf = String::new();
        if let Some(stdout) = child_stdout {
            let reader = std::io::BufReader::new(stdout);
            use std::io::BufRead;
            for line in reader.lines().map_while(Result::ok) {
                println!("{}", sanitize_terminal_inline(&line));
                push_capped_line(&mut buf, &line);
            }
        }
        buf
    });

    // Tee stderr: read from pipe, write to terminal + capped buffer
    let stderr_handle = std::thread::spawn(move || -> String {
        let mut buf = String::new();
        if let Some(stderr) = child_stderr {
            let reader = std::io::BufReader::new(stderr);
            use std::io::BufRead;
            for line in reader.lines().map_while(Result::ok) {
                eprintln!("{}", sanitize_terminal_inline(&line));
                push_capped_line(&mut buf, &line);
            }
        }
        buf
    });

    let status = child
        .wait()
        .map_err(|e| LpmError::Script(format!("failed to wait for '{}': {e}", cmd.command)))?;

    let stdout = stdout_handle.join().unwrap_or_else(|_| {
        tracing::warn!("stdout reader thread panicked");
        String::new()
    });
    let stderr = stderr_handle.join().unwrap_or_else(|_| {
        tracing::warn!("stderr reader thread panicked");
        String::new()
    });

    Ok(CapturedOutput {
        status,
        stdout,
        stderr,
    })
}

/// Spawn a shell command with fully captured stdout/stderr (no terminal echo).
///
/// Unlike `spawn_shell_tee`, output is NOT displayed to the terminal.
/// Used by buffered parallel mode where output should only appear after
/// the task completes.
pub fn spawn_shell_capture(cmd: &ShellCommand) -> Result<CapturedOutput, LpmError> {
    let (shell, flag) = shell_and_flag();

    let mut command = Command::new(shell);
    command
        .arg(flag)
        .arg(cmd.command)
        .current_dir(cmd.cwd)
        .stdin(Stdio::inherit())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    strip_inherited_env_hooks(&mut command);

    if !cmd.envs.is_empty() {
        command.envs(cmd.envs);
    }
    command.env("PATH", cmd.path);

    let mut child = command
        .spawn()
        .map_err(|e| LpmError::Script(format!("failed to execute '{}': {e}", cmd.command)))?;

    // Manual piped reads (rather than `Command::output()`) so the
    // accumulator can apply MAX_CAPTURED_STREAM_BYTES during read —
    // `output()` would buffer the entire stream into a `Vec<u8>`
    // regardless of size.
    let child_stdout = child.stdout.take();
    let child_stderr = child.stderr.take();

    let stdout_handle = std::thread::spawn(move || -> String {
        let mut buf = String::new();
        if let Some(stdout) = child_stdout {
            let reader = std::io::BufReader::new(stdout);
            use std::io::BufRead;
            for line in reader.lines().map_while(Result::ok) {
                push_capped_line(&mut buf, &line);
            }
        }
        buf
    });

    let stderr_handle = std::thread::spawn(move || -> String {
        let mut buf = String::new();
        if let Some(stderr) = child_stderr {
            let reader = std::io::BufReader::new(stderr);
            use std::io::BufRead;
            for line in reader.lines().map_while(Result::ok) {
                push_capped_line(&mut buf, &line);
            }
        }
        buf
    });

    let status = child
        .wait()
        .map_err(|e| LpmError::Script(format!("failed to wait for '{}': {e}", cmd.command)))?;

    let stdout = stdout_handle.join().unwrap_or_default();
    let stderr = stderr_handle.join().unwrap_or_default();

    Ok(CapturedOutput {
        status,
        stdout,
        stderr,
    })
}

/// Spawn a shell command with prefixed output — each line gets a `[prefix]` tag.
///
/// Prefixes and child lines are sanitized before LPM-owned styling is added.
/// Captured strings remain verbatim and must be sanitized by any later renderer.
pub fn spawn_shell_prefixed(
    cmd: &ShellCommand,
    prefix: &str,
    color: &str,
) -> Result<CapturedOutput, LpmError> {
    let (shell, flag) = shell_and_flag();

    let mut command = Command::new(shell);
    command
        .arg(flag)
        .arg(cmd.command)
        .current_dir(cmd.cwd)
        .stdin(Stdio::inherit())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    strip_inherited_env_hooks(&mut command);

    if !cmd.envs.is_empty() {
        command.envs(cmd.envs);
    }
    command.env("PATH", cmd.path);

    let mut child = command
        .spawn()
        .map_err(|e| LpmError::Script(format!("failed to execute '{}': {e}", cmd.command)))?;

    let child_stdout = child.stdout.take();
    let child_stderr = child.stderr.take();

    let prefix_out = format!("[{}]", sanitize_terminal_inline(prefix));
    let prefix_err = prefix_out.clone();
    let color_out = color.to_string();
    let color_err = color_out.clone();

    // Prefixed stdout reader
    let stdout_handle = std::thread::spawn(move || -> String {
        let mut buf = String::new();
        if let Some(stdout) = child_stdout {
            let reader = std::io::BufReader::new(stdout);
            use std::io::BufRead;
            for line in reader.lines().map_while(Result::ok) {
                let safe_line = sanitize_terminal_inline(&line);
                eprintln!("\x1b[{}m{}\x1b[0m {}", color_out, prefix_out, safe_line);
                push_capped_line(&mut buf, &line);
            }
        }
        buf
    });

    // Prefixed stderr reader
    let stderr_handle = std::thread::spawn(move || -> String {
        let mut buf = String::new();
        if let Some(stderr) = child_stderr {
            let reader = std::io::BufReader::new(stderr);
            use std::io::BufRead;
            for line in reader.lines().map_while(Result::ok) {
                let safe_line = sanitize_terminal_inline(&line);
                eprintln!("\x1b[{}m{}\x1b[0m {}", color_err, prefix_err, safe_line);
                push_capped_line(&mut buf, &line);
            }
        }
        buf
    });

    let status = child
        .wait()
        .map_err(|e| LpmError::Script(format!("failed to wait for '{}': {e}", cmd.command)))?;

    let stdout = stdout_handle.join().unwrap_or_else(|_| String::new());
    let stderr = stderr_handle.join().unwrap_or_else(|_| String::new());

    Ok(CapturedOutput {
        status,
        stdout,
        stderr,
    })
}

/// Returns the shell binary and flag for the current platform.
fn shell_and_flag() -> (&'static str, &'static str) {
    if cfg!(windows) {
        ("cmd", "/C")
    } else {
        ("sh", "-c")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_envs() -> HashMap<String, String> {
        HashMap::new()
    }

    #[test]
    fn spawn_echo() {
        let dir = tempfile::tempdir().unwrap();
        let path = std::env::var("PATH").unwrap_or_default();
        let envs = empty_envs();

        let status = spawn_shell(&ShellCommand {
            command: "echo hello",
            cwd: dir.path(),
            path: &path,
            envs: &envs,
        })
        .unwrap();

        assert!(status.success());
        assert_eq!(exit_code(&status), 0);
    }

    #[test]
    fn spawn_failing_command() {
        let dir = tempfile::tempdir().unwrap();
        let path = std::env::var("PATH").unwrap_or_default();
        let envs = empty_envs();

        let status = spawn_shell(&ShellCommand {
            command: "exit 42",
            cwd: dir.path(),
            path: &path,
            envs: &envs,
        })
        .unwrap();

        assert!(!status.success());
        assert_eq!(exit_code(&status), 42);
    }

    #[test]
    fn spawn_with_injected_env() {
        let dir = tempfile::tempdir().unwrap();
        let path = std::env::var("PATH").unwrap_or_default();
        let mut envs = HashMap::new();
        envs.insert("LPM_TEST_VAR".into(), "injected_value".into());

        // The shell can see the injected env var
        let status = spawn_shell(&ShellCommand {
            command: "test \"$LPM_TEST_VAR\" = \"injected_value\"",
            cwd: dir.path(),
            path: &path,
            envs: &envs,
        })
        .unwrap();

        assert!(
            status.success(),
            "injected env var should be visible in child"
        );
    }

    #[test]
    fn path_cannot_be_overridden_by_envs() {
        let dir = tempfile::tempdir().unwrap();
        let real_path = std::env::var("PATH").unwrap_or_default();

        // envs contains a malicious PATH that would break command resolution
        let mut envs = HashMap::new();
        envs.insert("PATH".into(), "/nonexistent/malicious".into());

        // If PATH is overridden by envs, `echo` won't be found
        let status = spawn_shell(&ShellCommand {
            command: "echo path-safe",
            cwd: dir.path(),
            path: &real_path,
            envs: &envs,
        })
        .unwrap();

        assert!(
            status.success(),
            "PATH from envs should not override the injected PATH"
        );
    }

    #[test]
    fn spawn_shell_capture_captures_without_tee() {
        let dir = tempfile::tempdir().unwrap();
        let path = std::env::var("PATH").unwrap_or_default();
        let envs = empty_envs();

        let result = spawn_shell_capture(&ShellCommand {
            command: "echo captured-output",
            cwd: dir.path(),
            path: &path,
            envs: &envs,
        })
        .unwrap();

        assert!(result.status.success());
        assert!(
            result.stdout.contains("captured-output"),
            "stdout should contain the echoed text"
        );
    }

    #[test]
    fn spawn_shell_capture_captures_stderr() {
        let dir = tempfile::tempdir().unwrap();
        let path = std::env::var("PATH").unwrap_or_default();
        let envs = empty_envs();

        let result = spawn_shell_capture(&ShellCommand {
            command: "echo err-text >&2",
            cwd: dir.path(),
            path: &path,
            envs: &envs,
        })
        .unwrap();

        assert!(result.status.success());
        assert!(
            result.stderr.contains("err-text"),
            "stderr should contain the error text"
        );
    }

    #[test]
    fn spawn_shell_capture_preserves_exit_code() {
        let dir = tempfile::tempdir().unwrap();
        let path = std::env::var("PATH").unwrap_or_default();
        let envs = empty_envs();

        let result = spawn_shell_capture(&ShellCommand {
            command: "echo fail-output && exit 3",
            cwd: dir.path(),
            path: &path,
            envs: &envs,
        })
        .unwrap();

        assert!(!result.status.success());
        assert_eq!(exit_code(&result.status), 3);
        assert!(result.stdout.contains("fail-output"));
    }

    #[test]
    fn spawn_shell_prefixed_adds_prefix() {
        let dir = tempfile::tempdir().unwrap();
        let path = std::env::var("PATH").unwrap_or_default();
        let envs = empty_envs();

        let result = spawn_shell_prefixed(
            &ShellCommand {
                command: "echo prefixed-line",
                cwd: dir.path(),
                path: &path,
                envs: &envs,
            },
            "my-task",
            "36",
        )
        .unwrap();

        assert!(result.status.success());
        assert!(
            result.stdout.contains("prefixed-line"),
            "captured output should contain the original text"
        );
    }

    #[cfg(unix)]
    #[test]
    fn signal_produces_128_plus_code() {
        let dir = tempfile::tempdir().unwrap();
        let path = std::env::var("PATH").unwrap_or_default();
        let envs = empty_envs();

        let status = spawn_shell(&ShellCommand {
            command: "kill -TERM $$",
            cwd: dir.path(),
            path: &path,
            envs: &envs,
        })
        .unwrap();

        assert_eq!(exit_code(&status), 143);
    }

    #[test]
    fn spawn_empty_command_succeeds() {
        // An empty command string passed to `sh -c ""` exits with 0 on Unix
        let dir = tempfile::tempdir().unwrap();
        let path = std::env::var("PATH").unwrap_or_default();
        let envs = empty_envs();

        let status = spawn_shell(&ShellCommand {
            command: "",
            cwd: dir.path(),
            path: &path,
            envs: &envs,
        })
        .unwrap();

        // sh -c "" returns 0 on Unix, which is the correct behavior
        assert!(status.success(), "empty command should exit 0 via sh -c");
    }

    #[test]
    fn spawn_shell_tee_captures_both_streams() {
        let dir = tempfile::tempdir().unwrap();
        let path = std::env::var("PATH").unwrap_or_default();
        let envs = empty_envs();

        let result = spawn_shell_tee(&ShellCommand {
            command: "echo stdout-text && echo stderr-text >&2",
            cwd: dir.path(),
            path: &path,
            envs: &envs,
        })
        .unwrap();

        assert!(result.status.success());
        assert!(
            result.stdout.contains("stdout-text"),
            "tee should capture stdout"
        );
        assert!(
            result.stderr.contains("stderr-text"),
            "tee should capture stderr"
        );
    }

    #[test]
    fn spawn_shell_tee_preserves_exit_code() {
        let dir = tempfile::tempdir().unwrap();
        let path = std::env::var("PATH").unwrap_or_default();
        let envs = empty_envs();

        let result = spawn_shell_tee(&ShellCommand {
            command: "echo before-fail && exit 7",
            cwd: dir.path(),
            path: &path,
            envs: &envs,
        })
        .unwrap();

        assert!(!result.status.success());
        assert_eq!(exit_code(&result.status), 7);
        assert!(result.stdout.contains("before-fail"));
    }

    #[test]
    fn multiple_env_vars_all_visible() {
        let dir = tempfile::tempdir().unwrap();
        let path = std::env::var("PATH").unwrap_or_default();
        let mut envs = HashMap::new();
        envs.insert("LPM_A".into(), "alpha".into());
        envs.insert("LPM_B".into(), "beta".into());
        envs.insert("LPM_C".into(), "gamma".into());

        let status = spawn_shell(&ShellCommand {
            command: r#"test "$LPM_A" = "alpha" && test "$LPM_B" = "beta" && test "$LPM_C" = "gamma""#,
            cwd: dir.path(),
            path: &path,
            envs: &envs,
        })
        .unwrap();

        assert!(status.success(), "all env vars should be visible");
    }

    /// M52: per-line accumulation halts at the cap. Subsequent lines
    /// are silently dropped. The marker is emitted exactly once.
    #[test]
    fn push_capped_line_truncates_at_cap_with_marker() {
        let mut buf = String::new();
        // Fill the buffer just under the cap.
        let big_line = "x".repeat(MAX_CAPTURED_STREAM_BYTES - 100);
        push_capped_line(&mut buf, &big_line);
        // Next line crosses the cap.
        push_capped_line(&mut buf, &"y".repeat(200));
        // A third line lands entirely past the cap.
        push_capped_line(&mut buf, "z");

        assert!(
            buf.contains("[output truncated at 10 MiB]"),
            "marker must be present after cap is crossed"
        );
        let marker_occurrences = buf.matches("[output truncated").count();
        assert_eq!(
            marker_occurrences, 1,
            "marker must be appended exactly once"
        );
        // The buffer should not have grown materially past the cap +
        // the marker text (account for marker + UTF-8 boundary slack).
        assert!(
            buf.len() <= MAX_CAPTURED_STREAM_BYTES + 64,
            "buffer must not exceed cap: {}",
            buf.len()
        );
    }

    /// Below-cap lines are written verbatim. Round-trip preservation.
    #[test]
    fn push_capped_line_preserves_small_outputs() {
        let mut buf = String::new();
        push_capped_line(&mut buf, "line one");
        push_capped_line(&mut buf, "line two");
        assert_eq!(buf, "line one\nline two\n");
    }

    /// M52: when the last buffer byte lands inside a multibyte
    /// codepoint, the truncator must walk back to a `char_boundary`
    /// rather than panic on `&str` slicing.
    #[test]
    fn push_capped_line_handles_multibyte_at_cap_boundary() {
        let mut buf = "x".repeat(MAX_CAPTURED_STREAM_BYTES - 4);
        // Force the next line's content (3-byte CJK kana per char) to
        // straddle the remaining 4-byte budget mid-codepoint.
        let multibyte = "あ".repeat(100);
        push_capped_line(&mut buf, &multibyte);
        assert!(
            buf.is_char_boundary(buf.len()),
            "buf must end on a UTF-8 boundary"
        );
        assert!(buf.contains("[output truncated"));
    }

    /// H21: each `spawn_shell` invocation must NOT inherit a parent
    /// `LD_PRELOAD` / `NODE_OPTIONS` / `LPM_TOKEN` value into the
    /// `sh -c` child. Pre-fix the parent env flowed verbatim.
    ///
    /// Cross-platform shape: we set the env vars on the calling
    /// process, spawn a shell that prints them, and assert the
    /// child saw nothing. Uses Unix shell builtins because the
    /// `#[cfg(windows)]` shape would need a different printer; the
    /// scrub itself is platform-agnostic (`Command::env_remove`).
    #[cfg(unix)]
    #[test]
    fn spawn_shell_strips_inherited_credential_and_hijack_env() {
        let dir = tempfile::tempdir().unwrap();
        let path = std::env::var("PATH").unwrap_or_default();
        let envs = empty_envs();
        // A `_SECRET`-suffix sentinel proves the suffix-shape scrub
        // also runs (not just the named-list scrub).
        let suffix_secret_name = format!("TEST_{}_SECRET", std::process::id());
        unsafe {
            std::env::set_var("LD_PRELOAD", "/dev/null/evil.so");
            std::env::set_var("NODE_OPTIONS", "--require=/dev/null/evil");
            std::env::set_var("LPM_TOKEN", "secret-token-value");
            std::env::set_var(&suffix_secret_name, "exfil-secret");
            // Non-stripped sentinel: a generic var that should pass
            // through so we know the scrub is targeted, not blanket.
            std::env::set_var("LPM_NONSCRUB_SENTINEL", "kept");
        }

        let cmd = format!(
            r#"echo "LP=${{LD_PRELOAD-unset}} NO=${{NODE_OPTIONS-unset}} TK=${{LPM_TOKEN-unset}} SE=${{{suffix_secret_name}-unset}} S=${{LPM_NONSCRUB_SENTINEL-unset}}""#
        );
        let result = spawn_shell_capture(&ShellCommand {
            command: &cmd,
            cwd: dir.path(),
            path: &path,
            envs: &envs,
        });

        // Clean up our env mutations even if the assertion below fails.
        unsafe {
            std::env::remove_var("LD_PRELOAD");
            std::env::remove_var("NODE_OPTIONS");
            std::env::remove_var("LPM_TOKEN");
            std::env::remove_var(&suffix_secret_name);
            std::env::remove_var("LPM_NONSCRUB_SENTINEL");
        }

        let result = result.expect("spawn_shell_capture failed");
        assert!(result.status.success());
        assert!(
            result.stdout.contains("LP=unset"),
            "LD_PRELOAD must NOT reach the child: {}",
            result.stdout
        );
        assert!(
            result.stdout.contains("NO=unset"),
            "NODE_OPTIONS must NOT reach the child: {}",
            result.stdout
        );
        assert!(
            result.stdout.contains("TK=unset"),
            "LPM_TOKEN must NOT reach the child: {}",
            result.stdout
        );
        assert!(
            result.stdout.contains("SE=unset"),
            "*_SECRET suffix must NOT reach the child: {}",
            result.stdout
        );
        assert!(
            result.stdout.contains("S=kept"),
            "non-scrubbed sentinel must pass through: {}",
            result.stdout
        );
    }

    /// H21: a value passed via the explicit `envs` map MUST still
    /// reach the child even if its name overlaps with a stripped
    /// pattern — the strip targets *inherited* env, not project-
    /// supplied values.
    #[cfg(unix)]
    #[test]
    fn spawn_shell_honors_project_env_even_for_stripped_names() {
        let dir = tempfile::tempdir().unwrap();
        let path = std::env::var("PATH").unwrap_or_default();
        let mut envs = HashMap::new();
        envs.insert("NODE_OPTIONS".into(), "--require=./project-allowed".into());

        let result = spawn_shell_capture(&ShellCommand {
            command: r#"echo "NO=${NODE_OPTIONS-unset}""#,
            cwd: dir.path(),
            path: &path,
            envs: &envs,
        })
        .unwrap();

        assert!(result.status.success());
        assert!(
            result.stdout.contains("NO=--require=./project-allowed"),
            "project-supplied envs map must overwrite the scrub: {}",
            result.stdout
        );
    }
}
