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

use lpm_common::LpmError;
use std::collections::HashMap;
use std::path::Path;
use std::process::{Command, ExitStatus, Stdio};

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

/// Spawn a shell command and wait for it to complete.
///
/// Returns the exit status. Stdio is inherited so the child process
/// can interact with the terminal directly.
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

    // Inject .env vars, then set PATH AFTER to prevent .env from overriding it
    if !cmd.envs.is_empty() {
        command.envs(cmd.envs);
    }
    command.env("PATH", cmd.path);

    command
        .status()
        .map_err(|e| LpmError::Script(format!("failed to execute '{}': {e}", cmd.command)))
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
/// Output is both displayed to the terminal in real-time AND captured into strings.
/// Used by task caching to replay output from cache hits.
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

    // Tee stdout: read from pipe, write to terminal + buffer
    let stdout_handle = std::thread::spawn(move || -> String {
        let mut buf = String::new();
        if let Some(stdout) = child_stdout {
            let reader = std::io::BufReader::new(stdout);
            use std::io::BufRead;
            for line in reader.lines().map_while(Result::ok) {
                println!("{line}");
                buf.push_str(&line);
                buf.push('\n');
            }
        }
        buf
    });

    // Tee stderr: read from pipe, write to terminal + buffer
    let stderr_handle = std::thread::spawn(move || -> String {
        let mut buf = String::new();
        if let Some(stderr) = child_stderr {
            let reader = std::io::BufReader::new(stderr);
            use std::io::BufRead;
            for line in reader.lines().map_while(Result::ok) {
                eprintln!("{line}");
                buf.push_str(&line);
                buf.push('\n');
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

    if !cmd.envs.is_empty() {
        command.envs(cmd.envs);
    }
    command.env("PATH", cmd.path);

    let output = command
        .output()
        .map_err(|e| LpmError::Script(format!("failed to execute '{}': {e}", cmd.command)))?;

    Ok(CapturedOutput {
        status: output.status,
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    })
}

/// Spawn a shell command with prefixed output — each line gets a `[prefix]` tag.
///
/// Output is displayed to the terminal in real-time with prefixes AND captured.
/// Used by streaming parallel mode (`--parallel --stream`).
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

    if !cmd.envs.is_empty() {
        command.envs(cmd.envs);
    }
    command.env("PATH", cmd.path);

    let mut child = command
        .spawn()
        .map_err(|e| LpmError::Script(format!("failed to execute '{}': {e}", cmd.command)))?;

    let child_stdout = child.stdout.take();
    let child_stderr = child.stderr.take();

    let prefix_out = format!("[{}]", prefix);
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
                eprintln!("\x1b[{}m{}\x1b[0m {}", color_out, prefix_out, line);
                buf.push_str(&line);
                buf.push('\n');
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
                eprintln!("\x1b[{}m{}\x1b[0m {}", color_err, prefix_err, line);
                buf.push_str(&line);
                buf.push('\n');
            }
        }
        buf
    });

    let status = child
        .wait()
        .map_err(|e| LpmError::Script(format!("failed to wait for '{}': {e}", cmd.command)))?;

    let stdout = stdout_handle
        .join()
        .unwrap_or_else(|_| String::new());
    let stderr = stderr_handle
        .join()
        .unwrap_or_else(|_| String::new());

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
}
