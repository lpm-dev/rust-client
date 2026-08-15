//! Cross-platform shell abstraction for spawning commands.
//!
//! Handles `sh -c` on Unix and `cmd /C` on Windows, with proper
//! PATH injection, `.env` variable injection, and environment inheritance.
//!
//! ## Signal handling
//!
//! On Unix, terminal Ctrl+C reaches the foreground process group. A targeted
//! signal to the LPM PID does not, so endpoint-aware dev execution also maps
//! SIGINT and SIGTERM to its scoped process-tree shutdown flag.
//!
//! However, if the child process is killed by a signal (e.g., SIGINT),
//! `ExitStatus::code()` returns `None` on Unix. We handle this by extracting
//! the signal number and translating it to a conventional exit code (128 + signal).

use lpm_common::{LpmError, sanitize_terminal_inline};
use std::collections::HashMap;
use std::path::Path;
use std::process::{Command, ExitStatus, Stdio};

use crate::dev_endpoint::DevEndpoint;

/// Inherited-env names that MUST be stripped from any `lpm run` /
/// `lpm exec` child before spawn.
///
/// The script runner spawns a platform shell without clearing the inherited
/// process environment, so credentials and runtime-injection hooks must be
/// removed explicitly before project env values are added.
///
/// We can't `env_clear` outright — legitimate scripts depend on
/// `HOME`, `USER`, `LANG`, `PATH`, etc. Instead we mirror the
/// lifecycle-script denylist (`STRIPPED_ENV_PATTERNS` in
/// `lpm-cli/src/commands/rebuild.rs`) and explicitly `env_remove`
/// each entry — same posture, applied at the script-runner boundary.
///
/// Credential carriers + dynamic-linker hijacks live in one list;
/// suffix-shaped patterns (`*_SECRET`, `*_TOKEN`, etc.) get
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

const STRIPPED_INHERITED_ENV_SUFFIXES: &[&str] = &[
    "_SECRET",
    "_PASSWORD",
    "_KEY",
    "_PRIVATE_KEY",
    "_KEY_ID",
    "_TOKEN",
];

fn inherited_env_is_stripped(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    STRIPPED_INHERITED_ENV_PATTERNS.contains(&upper.as_str())
        || STRIPPED_INHERITED_ENV_SUFFIXES
            .iter()
            .any(|suffix| upper.ends_with(suffix))
}

/// Return inherited environment variables that a script child can observe.
///
/// Explicit project env values are handled separately because they override
/// inherited values after the scrub.
pub fn inherited_child_env() -> HashMap<String, String> {
    std::env::vars()
        .filter(|(key, _)| !inherited_env_is_stripped(key))
        .collect()
}

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
        if inherited_env_is_stripped(&key) {
            cmd.env_remove(&key);
        }
    }
}

/// Max bytes accumulated per captured stream (stdout OR stderr).
///
/// Mirrors the post-execution truncation cap in `commands::run` so the
/// in-memory buffer never grows past it. Without this cap, a chatty task can
/// fill the process with output before later truncation. Accumulation halts at
/// 10 MiB while the reader keeps draining the pipe so the child
/// doesn't block — the truncation marker is appended once.
const MAX_CAPTURED_STREAM_BYTES: usize = lpm_common::TASK_OUTPUT_CAPTURE_BYTES;
const OUTPUT_READ_CHUNK_BYTES: usize = 16 * 1024;
const MAX_ENDPOINT_OUTPUT_LINE_BYTES: usize = 64 * 1024;
const MAX_PENDING_ENDPOINT_CANDIDATES: usize = 64;

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

fn drain_captured_stream<R: std::io::Read>(mut reader: R, mut render: impl FnMut(&str)) -> String {
    let mut captured = String::with_capacity(OUTPUT_READ_CHUNK_BYTES);
    let mut pending = Vec::with_capacity(OUTPUT_READ_CHUNK_BYTES);
    let mut chunk = [0u8; OUTPUT_READ_CHUNK_BYTES];
    loop {
        let read = match reader.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(read) => read,
        };
        let mut remaining = &chunk[..read];
        while let Some(newline) = remaining.iter().position(|byte| *byte == b'\n') {
            pending.extend_from_slice(&remaining[..newline]);
            let line = String::from_utf8_lossy(&pending);
            render(&line);
            push_capped_line(&mut captured, &line);
            pending.clear();
            remaining = &remaining[newline + 1..];
        }
        if !remaining.is_empty() && pending.len() < MAX_CAPTURED_STREAM_BYTES {
            let keep = remaining
                .len()
                .min(MAX_CAPTURED_STREAM_BYTES - pending.len());
            pending.extend_from_slice(&remaining[..keep]);
        }
    }
    if !pending.is_empty() {
        let line = String::from_utf8_lossy(&pending);
        render(&line);
        push_capped_line(&mut captured, &line);
    }
    captured
}

fn drain_bounded_lines<R: std::io::Read>(
    mut reader: R,
    max_line_bytes: usize,
    mut on_line: impl FnMut(&str),
) {
    let mut line = Vec::with_capacity(OUTPUT_READ_CHUNK_BYTES.min(max_line_bytes));
    let mut chunk = [0u8; OUTPUT_READ_CHUNK_BYTES];
    let mut truncated = false;
    loop {
        let read = match reader.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(read) => read,
        };
        let mut remaining = &chunk[..read];
        while let Some(newline) = remaining.iter().position(|byte| *byte == b'\n') {
            if !truncated {
                let keep = newline.min(max_line_bytes.saturating_sub(line.len()));
                line.extend_from_slice(&remaining[..keep]);
            }
            on_line(&String::from_utf8_lossy(&line));
            line.clear();
            truncated = false;
            remaining = &remaining[newline + 1..];
        }
        if !remaining.is_empty() && !truncated {
            let keep = remaining
                .len()
                .min(max_line_bytes.saturating_sub(line.len()));
            line.extend_from_slice(&remaining[..keep]);
            truncated = keep < remaining.len() || line.len() == max_line_bytes;
        }
    }
    if !line.is_empty() {
        on_line(&String::from_utf8_lossy(&line));
    }
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

#[cfg(unix)]
struct StopSignalRegistrations(Vec<signal_hook::SigId>);

#[cfg(unix)]
impl Drop for StopSignalRegistrations {
    fn drop(&mut self) {
        for registration in self.0.drain(..) {
            signal_hook::low_level::unregister(registration);
        }
    }
}

#[cfg(unix)]
fn register_stop_signals(
    stop_requested: &std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> Result<StopSignalRegistrations, LpmError> {
    use signal_hook::consts::{SIGINT, SIGTERM};

    let mut registrations = StopSignalRegistrations(Vec::with_capacity(2));
    for signal in [SIGINT, SIGTERM] {
        let registration =
            signal_hook::flag::register(signal, std::sync::Arc::clone(stop_requested)).map_err(
                |error| LpmError::Script(format!("failed to install dev signal handlers: {error}")),
            )?;
        registrations.0.push(registration);
    }
    Ok(registrations)
}

/// Spawn a shell command and wait for it to complete.
///
/// Returns the exit status. Stdio is inherited so the child process
/// can interact with the terminal directly. This deliberately gives the child
/// ownership of the terminal; LPM cannot sanitize output on this raw path.
pub fn spawn_shell(cmd: &ShellCommand) -> Result<ExitStatus, LpmError> {
    let mut command = shell_process(cmd.command)?;
    command
        .current_dir(cmd.cwd)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());

    // Scrub credential + runtime-hijack env hooks the parent process
    // inherited. Runs BEFORE project envs so a legitimate
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
    on_shutdown_started: Option<crate::ShutdownStartedCallback>,
) -> Result<ExitStatus, LpmError> {
    spawn_shell_with_endpoint_using(
        cmd,
        requested_port,
        stop_requested,
        on_endpoint,
        on_shutdown_started,
        crate::ports::terminate_child_process_tree,
    )
}

fn spawn_shell_with_endpoint_using<T>(
    cmd: &ShellCommand,
    requested_port: Option<u16>,
    stop_requested: std::sync::Arc<std::sync::atomic::AtomicBool>,
    on_endpoint: EndpointResultCallback,
    mut on_shutdown_started: Option<crate::ShutdownStartedCallback>,
    mut terminate_child: T,
) -> Result<ExitStatus, LpmError>
where
    T: FnMut(&mut std::process::Child) -> std::io::Result<ExitStatus>,
{
    #[cfg(unix)]
    let _stop_signal_registrations = register_stop_signals(&stop_requested)?;
    let mut command = shell_process(cmd.command)?;
    command
        .current_dir(cmd.cwd)
        .stdin(Stdio::inherit())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    strip_inherited_env_hooks(&mut command);
    if !cmd.envs.is_empty() {
        command.envs(cmd.envs);
    }
    command.env("PATH", cmd.path);

    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }

    let mut child = command.spawn().map_err(|error| {
        LpmError::Script(format!("failed to execute '{}': {error}", cmd.command))
    })?;
    let root_pid = child.id();
    let child_exited = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let (candidate_tx, candidate_rx) =
        std::sync::mpsc::sync_channel(MAX_PENDING_ENDPOINT_CANDIDATES);
    let stdout_handle =
        spawn_endpoint_output_reader(child.stdout.take(), false, candidate_tx.clone());
    let stderr_handle = spawn_endpoint_output_reader(child.stderr.take(), true, candidate_tx);

    let resolver_project_dir = cmd.cwd.to_path_buf();
    let resolver_child_exited = std::sync::Arc::clone(&child_exited);
    let resolver_stop_requested = std::sync::Arc::clone(&stop_requested);
    let resolution_failed = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let resolver_failed = std::sync::Arc::clone(&resolution_failed);
    // Script runners can reparent the listener process after discovery, so
    // cancellation retains the verified PID and port instead of relying only
    // on a fresh descendant walk from the original shell.
    let resolved_owner = std::sync::Arc::new(std::sync::Mutex::new(None::<DevEndpoint>));
    let resolver_owner = std::sync::Arc::clone(&resolved_owner);
    let resolver_handle = std::thread::spawn(move || {
        let result = crate::dev_endpoint::resolve_spawned_endpoint_until(
            &resolver_project_dir,
            root_pid,
            None,
            requested_port,
            &candidate_rx,
            std::time::Instant::now() + std::time::Duration::from_secs(30),
            || {
                resolver_child_exited.load(std::sync::atomic::Ordering::Acquire)
                    || resolver_stop_requested.load(std::sync::atomic::Ordering::Acquire)
            },
        );
        let result = match result {
            Err(error) if error == crate::dev_endpoint::ENDPOINT_DISCOVERY_CANCELLED => Ok(None),
            result => result,
        };
        if result.is_err() {
            resolver_failed.store(true, std::sync::atomic::Ordering::Release);
        }
        if let Ok(Some(endpoint)) = &result
            && let Ok(mut owner) = resolver_owner.lock()
        {
            *owner = Some(endpoint.clone());
        }
        on_endpoint(result);
    });

    let mut shutdown_result = Ok(());
    let status_result = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Ok(status),
            Ok(None) => {}
            Err(error) => {
                break Err(LpmError::Script(format!(
                    "failed to wait for '{}': {error}",
                    cmd.command
                )));
            }
        }
        let resolution_failed = resolution_failed.load(std::sync::atomic::Ordering::Acquire);
        let stop_requested = stop_requested.load(std::sync::atomic::Ordering::Acquire);
        if resolution_failed || stop_requested {
            if stop_requested {
                shutdown_result = crate::invoke_shutdown_started(&mut on_shutdown_started);
            }
            break terminate_child(&mut child).map_err(|error| {
                LpmError::Script(format!("failed to stop '{}': {error}", cmd.command))
            });
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    };
    child_exited.store(true, std::sync::atomic::Ordering::Release);
    #[cfg(unix)]
    cleanup_endpoint_process_group(root_pid);
    let _ = resolver_handle.join();
    let owner = resolved_owner.lock().ok().and_then(|owner| owner.clone());
    if let Some(owner) = owner
        && let Some(owner_pid) = owner.owner_pid
        && owner_pid != root_pid
    {
        #[cfg(not(windows))]
        if let Some(owner_identity) = owner.owner_identity.as_ref() {
            let _ = crate::ports::kill_pid_if_identity_owns_ports(
                owner_pid,
                owner_identity,
                &[owner.target.port],
            );
        }
        #[cfg(windows)]
        let _ = crate::ports::kill_pid_if_owns_ports(owner_pid, &[owner.target.port]);
    }
    let _ = stdout_handle.join();
    let _ = stderr_handle.join();
    compose_shell_and_shutdown_result(status_result, shutdown_result)
}

fn compose_shell_and_shutdown_result(
    status_result: Result<ExitStatus, LpmError>,
    shutdown_result: Result<(), LpmError>,
) -> Result<ExitStatus, LpmError> {
    match (status_result, shutdown_result) {
        (Ok(status), Ok(())) => Ok(status),
        (Err(error), Ok(())) | (Ok(_), Err(error)) => Err(error),
        (Err(primary), Err(shutdown)) => Err(LpmError::Script(format!(
            "{primary}; shutdown boundary also failed: {shutdown}"
        ))),
    }
}

#[cfg(unix)]
fn cleanup_endpoint_process_group(root_pid: u32) {
    let Ok(process_group) = libc::pid_t::try_from(root_pid) else {
        return;
    };
    if process_group <= 1 {
        return;
    }
    // SAFETY: the negative PID addresses only the process group created for
    // this endpoint-aware child; SIGKILL does not dereference memory.
    unsafe {
        libc::kill(-process_group, libc::SIGKILL);
    }
}

fn spawn_endpoint_output_reader<R>(
    stream: Option<R>,
    is_stderr: bool,
    candidate_tx: std::sync::mpsc::SyncSender<lpm_common::LocalTarget>,
) -> std::thread::JoinHandle<()>
where
    R: std::io::Read + Send + 'static,
{
    std::thread::spawn(move || {
        let Some(stream) = stream else {
            return;
        };
        drain_bounded_lines(stream, MAX_ENDPOINT_OUTPUT_LINE_BYTES, |line| {
            publish_endpoint_candidates(line, &candidate_tx);
            let safe = sanitize_terminal_inline(line);
            if is_stderr {
                eprintln!("{safe}");
            } else {
                println!("{safe}");
            }
        });
    })
}

fn publish_endpoint_candidates(
    line: &str,
    candidate_tx: &std::sync::mpsc::SyncSender<lpm_common::LocalTarget>,
) {
    for target in crate::dev_endpoint::parse_local_targets(line) {
        let _ = candidate_tx.try_send(target);
    }
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
    let mut command = shell_process(cmd.command)?;
    command
        .current_dir(cmd.cwd)
        .stdin(Stdio::inherit())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    // Scrub credential + runtime-hijack env hooks the parent process
    // inherited. Runs BEFORE project envs so a legitimate
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
        child_stdout.map_or_else(String::new, |stdout| {
            drain_captured_stream(stdout, |line| {
                println!("{}", sanitize_terminal_inline(line));
            })
        })
    });

    // Tee stderr: read from pipe, write to terminal + capped buffer
    let stderr_handle = std::thread::spawn(move || -> String {
        child_stderr.map_or_else(String::new, |stderr| {
            drain_captured_stream(stderr, |line| {
                eprintln!("{}", sanitize_terminal_inline(line));
            })
        })
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
    let mut command = shell_process(cmd.command)?;
    command
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
        child_stdout.map_or_else(String::new, |stdout| drain_captured_stream(stdout, |_| {}))
    });

    let stderr_handle = std::thread::spawn(move || -> String {
        child_stderr.map_or_else(String::new, |stderr| drain_captured_stream(stderr, |_| {}))
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
    let mut command = shell_process(cmd.command)?;
    command
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
        child_stdout.map_or_else(String::new, |stdout| {
            drain_captured_stream(stdout, |line| {
                let safe_line = sanitize_terminal_inline(line);
                eprintln!("\x1b[{}m{}\x1b[0m {}", color_out, prefix_out, safe_line);
            })
        })
    });

    // Prefixed stderr reader
    let stderr_handle = std::thread::spawn(move || -> String {
        child_stderr.map_or_else(String::new, |stderr| {
            drain_captured_stream(stderr, |line| {
                let safe_line = sanitize_terminal_inline(line);
                eprintln!("\x1b[{}m{}\x1b[0m {}", color_err, prefix_err, safe_line);
            })
        })
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

#[cfg(not(windows))]
#[expect(
    clippy::unnecessary_wraps,
    reason = "the Windows implementation can fail while resolving the system shell"
)]
pub(crate) fn shell_process(command: &str) -> Result<Command, LpmError> {
    let mut process = Command::new("sh");
    process.arg("-c").arg(command);
    Ok(process)
}

#[cfg(windows)]
pub(crate) fn shell_process(command: &str) -> Result<Command, LpmError> {
    use std::os::windows::process::CommandExt;

    let mut process = Command::new(windows_system_directory()?.join("cmd.exe"));
    process
        .arg("/D")
        .arg("/V:OFF")
        .arg("/S")
        .arg("/C")
        .raw_arg(format!("\"{command}\""));
    Ok(process)
}

#[cfg(windows)]
fn windows_system_directory() -> Result<std::path::PathBuf, LpmError> {
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;
    use windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW;

    let mut buffer = vec![0_u16; 260];
    loop {
        let buffer_len = u32::try_from(buffer.len())
            .map_err(|_| LpmError::Script("Windows system directory path is too long".into()))?;
        // SAFETY: `buffer` is writable for `buffer_len` UTF-16 units, and the
        // pointer remains valid for the duration of this synchronous call.
        let written = unsafe { GetSystemDirectoryW(buffer.as_mut_ptr(), buffer_len) };
        if written == 0 {
            return Err(LpmError::Script(format!(
                "failed to resolve Windows system directory: {}",
                std::io::Error::last_os_error()
            )));
        }

        let written = written as usize;
        if written < buffer.len() {
            buffer.truncate(written);
            return Ok(std::path::PathBuf::from(OsString::from_wide(&buffer)));
        }
        buffer.resize(written.saturating_add(1), 0);
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

    /// Per-line accumulation halts at the cap. Subsequent lines
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

    /// When the last buffer byte lands inside a multibyte
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

    #[test]
    fn drain_captured_stream_bounds_newline_free_input() {
        let input = vec![b'x'; MAX_CAPTURED_STREAM_BYTES * 3];

        let captured = drain_captured_stream(input.as_slice(), |_| {});

        assert!(captured.contains("[output truncated at 10 MiB]"));
        assert!(captured.len() <= MAX_CAPTURED_STREAM_BYTES + 64);
    }

    #[test]
    fn drain_bounded_lines_caps_newline_free_endpoint_output() {
        let input = vec![b'x'; MAX_ENDPOINT_OUTPUT_LINE_BYTES * 4];
        let mut observed = Vec::new();

        drain_bounded_lines(input.as_slice(), MAX_ENDPOINT_OUTPUT_LINE_BYTES, |line| {
            observed.push(line.len());
        });

        assert_eq!(observed, vec![MAX_ENDPOINT_OUTPUT_LINE_BYTES]);
    }

    #[cfg(unix)]
    #[test]
    fn endpoint_aware_shell_cleans_background_pipe_holders_after_the_shell_exits() {
        let dir = tempfile::tempdir().unwrap();
        let path = std::env::var("PATH").unwrap_or_default();
        let envs = empty_envs();
        let started = std::time::Instant::now();

        let status = spawn_shell_with_endpoint(
            &ShellCommand {
                command: "sleep 2 & exit 0",
                cwd: dir.path(),
                path: &path,
                envs: &envs,
            },
            None,
            std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            Box::new(|_| {}),
            None,
        )
        .unwrap();
        let elapsed = started.elapsed();

        assert!(status.success());
        assert!(
            elapsed < std::time::Duration::from_millis(500),
            "background process retained endpoint output pipes for {elapsed:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn endpoint_aware_shell_invokes_the_shutdown_boundary_before_child_cleanup() {
        let dir = tempfile::tempdir().unwrap();
        let path = std::env::var("PATH").unwrap_or_default();
        let envs = empty_envs();
        let started_path = dir.path().join("started");
        let stop_requested = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let controller_stop = std::sync::Arc::clone(&stop_requested);
        let controller_started = started_path.clone();
        let controller = std::thread::spawn(move || {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
            while !controller_started.exists() && std::time::Instant::now() < deadline {
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            assert!(controller_started.exists(), "endpoint child did not start");
            controller_stop.store(true, std::sync::atomic::Ordering::Release);
        });
        let shutdown_boundary_ran = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let callback_state = std::sync::Arc::clone(&shutdown_boundary_ran);

        let result = spawn_shell_with_endpoint(
            &ShellCommand {
                command: &format!(
                    "touch '{}'; while :; do sleep 1; done",
                    started_path.display()
                ),
                cwd: dir.path(),
                path: &path,
                envs: &envs,
            },
            None,
            stop_requested,
            Box::new(|_| {}),
            Some(Box::new(move || {
                callback_state.store(true, std::sync::atomic::Ordering::Release);
                Ok(())
            })),
        );
        controller.join().unwrap();

        assert!(result.is_ok(), "endpoint runner failed: {result:?}");
        assert!(
            shutdown_boundary_ran.load(std::sync::atomic::Ordering::Acquire),
            "child cleanup started without acknowledging the shutdown boundary"
        );
    }

    #[cfg(unix)]
    #[test]
    fn endpoint_aware_shell_preserves_shutdown_and_process_tree_failures() {
        let dir = tempfile::tempdir().unwrap();
        let path = std::env::var("PATH").unwrap_or_default();
        let envs = empty_envs();
        let started_path = dir.path().join("started");
        let stop_requested = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let controller_stop = std::sync::Arc::clone(&stop_requested);
        let controller_started = started_path.clone();
        let controller = std::thread::spawn(move || {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
            while !controller_started.exists() && std::time::Instant::now() < deadline {
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            assert!(controller_started.exists(), "endpoint child did not start");
            controller_stop.store(true, std::sync::atomic::Ordering::Release);
        });

        let error = spawn_shell_with_endpoint_using(
            &ShellCommand {
                command: &format!(
                    "touch '{}'; while :; do sleep 1; done",
                    started_path.display()
                ),
                cwd: dir.path(),
                path: &path,
                envs: &envs,
            },
            None,
            stop_requested,
            Box::new(|_| {}),
            Some(Box::new(|| {
                Err(LpmError::Tunnel(
                    "injected shutdown boundary failure".to_string(),
                ))
            })),
            |child| {
                let _ = crate::ports::terminate_child_process_tree(child);
                Err(std::io::Error::other(
                    "injected endpoint process-tree termination failure",
                ))
            },
        )
        .unwrap_err();
        controller.join().unwrap();
        let message = error.to_string();

        assert!(message.contains("injected endpoint process-tree termination failure"));
        assert!(message.contains("injected shutdown boundary failure"));
    }

    #[test]
    fn endpoint_candidate_hints_are_dropped_when_the_queue_is_full() {
        let (sender, receiver) = std::sync::mpsc::sync_channel(1);
        publish_endpoint_candidates("http://localhost:3000", &sender);
        let started = std::time::Instant::now();

        publish_endpoint_candidates("http://localhost:3001", &sender);

        assert!(started.elapsed() < std::time::Duration::from_millis(50));
        assert_eq!(receiver.try_iter().count(), 1);
    }

    /// Each `spawn_shell` invocation must NOT inherit a parent
    /// `LD_PRELOAD` / `NODE_OPTIONS` / `LPM_TOKEN` value into the
    /// `sh -c` child.
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
            std::env::set_var("CI_JOB_TOKEN", "ci-secret-token-value");
            std::env::set_var(&suffix_secret_name, "exfil-secret");
            // Non-stripped sentinel: a generic var that should pass
            // through so we know the scrub is targeted, not blanket.
            std::env::set_var("LPM_NONSCRUB_SENTINEL", "kept");
        }

        let cmd = format!(
            r#"echo "LP=${{LD_PRELOAD-unset}} NO=${{NODE_OPTIONS-unset}} TK=${{LPM_TOKEN-unset}} CI=${{CI_JOB_TOKEN-unset}} SE=${{{suffix_secret_name}-unset}} S=${{LPM_NONSCRUB_SENTINEL-unset}}""#
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
            std::env::remove_var("CI_JOB_TOKEN");
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
            result.stdout.contains("CI=unset"),
            "*_TOKEN suffix must NOT reach the child: {}",
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

    /// A value passed via the explicit `envs` map MUST still
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
