//! Package.json script execution with PATH injection, .env loading, and pre/post hooks.
//!
//! The main entry point is `run_script()`, which:
//! 1. Reads scripts from package.json (via lpm-workspace)
//! 2. Loads `.env` files (with optional mode from `--env` flag or `lpm.json` mapping)
//! 3. Checks for and runs pre-hooks
//! 4. Injects `node_modules/.bin` into PATH + `.env` vars into environment
//! 5. Runs the script via shell
//! 6. Checks for and runs post-hooks

use crate::bin_path;
use crate::bin_path::ManagedRuntimeHint;
use crate::dotenv;
use crate::hooks;
use crate::lpm_json;
use crate::shell::{self, ShellCommand};
use lpm_common::color::Painted;
use lpm_common::{LpmError, sanitize_terminal_inline};
use lpm_workspace::read_package_json;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

/// Global flag to skip env schema validation (set by `--no-env-check`).
static SKIP_ENV_VALIDATION: AtomicBool = AtomicBool::new(false);

const LPM_SCRIPT_CHILD_ENV: &str = "LPM_SCRIPT_CHILD";

/// Set the global flag to skip env schema validation.
///
/// Called by the CLI layer when `--no-env-check` is passed.
pub fn set_skip_env_validation(skip: bool) {
    SKIP_ENV_VALIDATION.store(skip, Ordering::Relaxed);
}

pub(crate) fn should_skip_env_validation() -> bool {
    SKIP_ENV_VALIDATION.load(Ordering::Relaxed)
}

pub fn is_hidden_script_name(name: &str) -> bool {
    name.starts_with('.')
}

pub fn hidden_script_direct_invocation_allowed() -> bool {
    std::env::var_os(LPM_SCRIPT_CHILD_ENV).is_some()
}

fn mark_script_child_env(env_vars: &mut HashMap<String, String>) {
    env_vars.insert(LPM_SCRIPT_CHILD_ENV.to_string(), "1".to_string());
}

/// Escape a runtime argument so the platform shell treats it as data.
#[cfg(not(windows))]
#[expect(
    clippy::unnecessary_wraps,
    reason = "the Windows implementation can reject unsafe cmd.exe arguments"
)]
fn shell_quote_arg(
    arg: &str,
    _script_cmd: &str,
    _project_dir: &Path,
    _path: &str,
) -> Result<String, LpmError> {
    let escaped = arg.replace('\'', "'\\''");
    Ok(format!("'{escaped}'"))
}

#[cfg(windows)]
fn shell_quote_arg(
    arg: &str,
    script_cmd: &str,
    project_dir: &Path,
    path: &str,
) -> Result<String, LpmError> {
    windows_shell_quote_arg(
        arg,
        windows_command_uses_batch_shim(script_cmd, project_dir, path),
    )
}

#[cfg(any(test, windows))]
fn windows_shell_quote_arg(arg: &str, double_escape: bool) -> Result<String, LpmError> {
    if arg
        .bytes()
        .any(|byte| matches!(byte, b'\0' | b'\r' | b'\n'))
    {
        return Err(LpmError::Script(
            "runtime arguments containing line breaks cannot be passed safely through cmd.exe"
                .to_string(),
        ));
    }

    let mut quoted = String::with_capacity(arg.len().saturating_mul(2).saturating_add(2));
    quoted.push('"');
    let mut backslashes = 0usize;
    for character in arg.chars() {
        if character == '\\' {
            backslashes += 1;
            continue;
        }
        if character == '"' {
            for _ in 0..backslashes.saturating_mul(2).saturating_add(1) {
                quoted.push('\\');
            }
            quoted.push('"');
        } else {
            for _ in 0..backslashes {
                quoted.push('\\');
            }
            quoted.push(character);
        }
        backslashes = 0;
    }
    for _ in 0..backslashes.saturating_mul(2) {
        quoted.push('\\');
    }
    quoted.push('"');

    let escaped = windows_escape_cmd_metacharacters(&quoted);
    if double_escape {
        Ok(windows_escape_cmd_metacharacters(&escaped))
    } else {
        Ok(escaped)
    }
}

#[cfg(any(test, windows))]
fn windows_escape_cmd_metacharacters(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len().saturating_mul(2));
    for character in value.chars() {
        if matches!(
            character,
            '(' | ')'
                | '['
                | ']'
                | '%'
                | '!'
                | '^'
                | '"'
                | '`'
                | '<'
                | '>'
                | '&'
                | '|'
                | ';'
                | ','
                | ' '
                | '*'
                | '?'
        ) {
            escaped.push('^');
        }
        escaped.push(character);
    }
    escaped
}

#[cfg(windows)]
fn windows_command_uses_batch_shim(script_cmd: &str, project_dir: &Path, path: &str) -> bool {
    let Some(command_name) = windows_first_command_word(script_cmd) else {
        return false;
    };
    let command_path = Path::new(command_name);
    if command_path
        .extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| matches!(extension.to_ascii_lowercase().as_str(), "cmd" | "bat"))
    {
        return true;
    }
    if command_path.extension().is_some() {
        return false;
    }

    let mut search_dirs = Vec::new();
    if command_path.components().count() > 1 {
        search_dirs.push(project_dir.to_path_buf());
    } else {
        search_dirs.extend(std::env::split_paths(path));
    }
    for directory in search_dirs {
        let candidate = directory.join(command_path);
        for extension in ["com", "exe", "bat", "cmd"] {
            let candidate = candidate.with_extension(extension);
            if candidate.is_file() {
                return matches!(extension, "bat" | "cmd");
            }
        }
    }
    false
}

#[cfg(windows)]
fn windows_first_command_word(script_cmd: &str) -> Option<&str> {
    let trimmed = script_cmd.trim_start();
    if let Some(rest) = trimmed.strip_prefix('"') {
        return rest.split_once('"').map(|(command, _)| command);
    }
    let end = trimmed
        .find(|character: char| character.is_whitespace() || "&|<>()".contains(character))
        .unwrap_or(trimmed.len());
    (end > 0).then(|| &trimmed[..end])
}

/// Build the shell command for a script invocation by quoting every runtime
/// argument for the platform shell. The script body is owned by
/// `package.json` (developer-authored) and legitimately contains shell
/// metacharacters (pipes, redirects, `$VAR`), so it is concatenated
/// verbatim. Extra args, however, come from the CLI tail (already
/// split into argv by the user's shell) and must not re-introduce
/// metacharacter semantics — otherwise `lpm run x -- "; rm -rf ~"`
/// detonates inside `sh -c`.
pub fn assemble_shell_command(
    script_cmd: &str,
    extra_args: &[String],
    project_dir: &Path,
    path: &str,
) -> Result<String, LpmError> {
    if extra_args.is_empty() {
        return Ok(script_cmd.to_string());
    }
    let mut full_command = String::with_capacity(
        script_cmd.len() + extra_args.iter().map(|arg| arg.len() + 3).sum::<usize>(),
    );
    full_command.push_str(script_cmd);
    for arg in extra_args {
        full_command.push(' ');
        full_command.push_str(&shell_quote_arg(arg, script_cmd, project_dir, path)?);
    }
    Ok(full_command)
}

/// Run a package.json script by name, with PATH injection, .env loading, and hooks.
///
/// # Arguments
/// * `project_dir` — project root (where package.json lives)
/// * `script_name` — the script key (e.g., "build", "dev", "test")
/// * `extra_args` — additional arguments appended to the script command
/// * `env_mode` — optional env mode from `--env` flag (e.g., "staging")
/// * `bin_hint` — pre-resolved managed-runtime bin from `lpm_runtime::ensure_runtime`,
///   or `Unknown` to fall back to silent detect.
pub fn run_script(
    project_dir: &Path,
    script_name: &str,
    extra_args: &[String],
    env_mode: Option<&str>,
    bin_hint: &ManagedRuntimeHint,
) -> Result<(), LpmError> {
    run_script_with_envs(
        project_dir,
        script_name,
        extra_args,
        env_mode,
        &[],
        bin_hint,
    )
}

/// Run a package.json script with additional environment variables.
///
/// Like `run_script`, but accepts extra env vars to inject into the child process
/// without mutating global process state (safe alternative to `std::env::set_var`).
pub fn run_script_with_envs(
    project_dir: &Path,
    script_name: &str,
    extra_args: &[String],
    env_mode: Option<&str>,
    extra_envs: &[(String, String)],
    bin_hint: &ManagedRuntimeHint,
) -> Result<(), LpmError> {
    let (script_cmd, scripts) = resolve_script_command(project_dir, script_name)?;

    // Build PATH with .bin dirs prepended
    let path = bin_path::build_path_with_bins_pre_resolved(project_dir, bin_hint)?;

    // Load .env files + merge extra env vars (from HTTPS/tunnel/network setup)
    let loaded = resolve_and_load_env(project_dir, script_name, env_mode)?;
    print_env_context(&loaded);
    let mut env_vars = loaded.vars;
    for (key, value) in extra_envs {
        env_vars.insert(key.clone(), value.clone());
    }
    mark_script_child_env(&mut env_vars);

    // Run pre-hook if it exists
    if let Some(pre_cmd) = hooks::find_pre_hook(&scripts, script_name) {
        let pre_name = hooks::pre_hook_name(script_name);
        tracing::debug!("running pre-hook: {pre_name}");

        let status = shell::spawn_shell(&ShellCommand {
            command: pre_cmd,
            cwd: project_dir,
            path: &path,
            envs: &env_vars,
        })?;

        if !status.success() {
            let code = status.code().unwrap_or(1);
            return Err(LpmError::Script(format!(
                "pre-hook '{pre_name}' exited with code {code}"
            )));
        }
    }

    let full_cmd = assemble_shell_command(&script_cmd, extra_args, project_dir, &path)?;

    // Run the main script
    let status = shell::spawn_shell(&ShellCommand {
        command: &full_cmd,
        cwd: project_dir,
        path: &path,
        envs: &env_vars,
    })?;

    if !status.success() {
        return Err(LpmError::ExitCode(shell::exit_code(&status)));
    }

    // Run post-hook if it exists
    if let Some(post_cmd) = hooks::find_post_hook(&scripts, script_name) {
        let post_name = hooks::post_hook_name(script_name);
        tracing::debug!("running post-hook: {post_name}");

        let status = shell::spawn_shell(&ShellCommand {
            command: post_cmd,
            cwd: project_dir,
            path: &path,
            envs: &env_vars,
        })?;

        if !status.success() {
            let code = status.code().unwrap_or(1);
            return Err(LpmError::Script(format!(
                "post-hook '{post_name}' exited with code {code}"
            )));
        }
    }

    Ok(())
}

pub struct DevScriptEndpointOptions {
    pub requested_port: Option<u16>,
    pub stop_requested: Arc<AtomicBool>,
    pub on_endpoint: shell::EndpointResultCallback,
    pub on_shutdown_started: Option<crate::ShutdownStartedCallback>,
}

pub fn run_dev_script_with_envs(
    project_dir: &Path,
    extra_args: &[String],
    env_mode: Option<&str>,
    extra_envs: &[(String, String)],
    bin_hint: &ManagedRuntimeHint,
    endpoint_options: DevScriptEndpointOptions,
) -> Result<(), LpmError> {
    let config = lpm_json::read_lpm_json(project_dir).map_err(LpmError::Script)?;
    run_dev_script_with_envs_and_config(
        project_dir,
        extra_args,
        env_mode,
        extra_envs,
        bin_hint,
        config.as_ref(),
        endpoint_options,
    )
}

pub fn run_dev_script_with_envs_and_config(
    project_dir: &Path,
    extra_args: &[String],
    env_mode: Option<&str>,
    extra_envs: &[(String, String)],
    bin_hint: &ManagedRuntimeHint,
    config: Option<&lpm_json::LpmJsonConfig>,
    endpoint_options: DevScriptEndpointOptions,
) -> Result<(), LpmError> {
    let (script_cmd, scripts) = resolve_script_command_with_config(project_dir, "dev", config)?;
    let path = bin_path::build_path_with_bins_pre_resolved(project_dir, bin_hint)?;
    let loaded = resolve_and_load_env_with_config(project_dir, "dev", env_mode, config)?;
    print_env_context(&loaded);
    let mut env_vars = loaded.vars;
    for (key, value) in extra_envs {
        env_vars.insert(key.clone(), value.clone());
    }
    mark_script_child_env(&mut env_vars);

    if let Some(pre_cmd) = hooks::find_pre_hook(&scripts, "dev") {
        let status = shell::spawn_shell(&ShellCommand {
            command: pre_cmd,
            cwd: project_dir,
            path: &path,
            envs: &env_vars,
        })?;
        if !status.success() {
            let code = status.code().unwrap_or(1);
            return Err(LpmError::Script(format!(
                "pre-hook 'predev' exited with code {code}"
            )));
        }
    }

    let full_cmd = assemble_shell_command(&script_cmd, extra_args, project_dir, &path)?;
    let status = shell::spawn_shell_with_endpoint(
        &ShellCommand {
            command: &full_cmd,
            cwd: project_dir,
            path: &path,
            envs: &env_vars,
        },
        endpoint_options.requested_port,
        Arc::clone(&endpoint_options.stop_requested),
        endpoint_options.on_endpoint,
        endpoint_options.on_shutdown_started,
    )?;
    if endpoint_options
        .stop_requested
        .load(std::sync::atomic::Ordering::Acquire)
    {
        return Ok(());
    }
    if !status.success() {
        return Err(LpmError::ExitCode(shell::exit_code(&status)));
    }

    if let Some(post_cmd) = hooks::find_post_hook(&scripts, "dev") {
        let status = shell::spawn_shell(&ShellCommand {
            command: post_cmd,
            cwd: project_dir,
            path: &path,
            envs: &env_vars,
        })?;
        if !status.success() {
            let code = status.code().unwrap_or(1);
            return Err(LpmError::Script(format!(
                "post-hook 'postdev' exited with code {code}"
            )));
        }
    }
    Ok(())
}

/// Result of a captured script execution.
pub struct ScriptOutput {
    /// Captured stdout (also displayed to terminal in real-time).
    pub stdout: String,
    /// Captured stderr (also displayed to terminal in real-time).
    pub stderr: String,
}

/// Run a script with tee-captured stdout/stderr.
///
/// Like `run_script`, but captures output for caching while still streaming
/// to the terminal. Pre/post hooks run normally (not captured).
pub fn run_script_captured(
    project_dir: &Path,
    script_name: &str,
    extra_args: &[String],
    env_mode: Option<&str>,
    bin_hint: &ManagedRuntimeHint,
) -> Result<ScriptOutput, LpmError> {
    let (script_cmd, scripts) = resolve_script_command(project_dir, script_name)?;

    let path = bin_path::build_path_with_bins_pre_resolved(project_dir, bin_hint)?;
    let loaded = resolve_and_load_env(project_dir, script_name, env_mode)?;
    print_env_context(&loaded);
    let mut env_vars = loaded.vars;
    mark_script_child_env(&mut env_vars);

    // Run pre-hook (not captured — hooks output goes to terminal only)
    if let Some(pre_cmd) = hooks::find_pre_hook(&scripts, script_name) {
        let pre_name = hooks::pre_hook_name(script_name);
        tracing::debug!("running pre-hook: {pre_name}");

        let status = shell::spawn_shell(&ShellCommand {
            command: pre_cmd,
            cwd: project_dir,
            path: &path,
            envs: &env_vars,
        })?;

        if !status.success() {
            let code = status.code().unwrap_or(1);
            return Err(LpmError::Script(format!(
                "pre-hook '{pre_name}' exited with code {code}"
            )));
        }
    }

    let full_cmd = assemble_shell_command(&script_cmd, extra_args, project_dir, &path)?;

    // Run the main script with tee capture
    let captured = shell::spawn_shell_tee(&ShellCommand {
        command: &full_cmd,
        cwd: project_dir,
        path: &path,
        envs: &env_vars,
    })?;

    if !captured.status.success() {
        return Err(LpmError::ExitCode(shell::exit_code(&captured.status)));
    }

    // Run post-hook (not captured)
    if let Some(post_cmd) = hooks::find_post_hook(&scripts, script_name) {
        let post_name = hooks::post_hook_name(script_name);
        tracing::debug!("running post-hook: {post_name}");

        let status = shell::spawn_shell(&ShellCommand {
            command: post_cmd,
            cwd: project_dir,
            path: &path,
            envs: &env_vars,
        })?;

        if !status.success() {
            let code = status.code().unwrap_or(1);
            return Err(LpmError::Script(format!(
                "post-hook '{post_name}' exited with code {code}"
            )));
        }
    }

    Ok(ScriptOutput {
        stdout: captured.stdout,
        stderr: captured.stderr,
    })
}

/// Run a script with fully captured output (no terminal echo).
///
/// Used by buffered parallel mode. Output is captured but NOT displayed
/// to the terminal — the caller prints it after the task completes.
pub fn run_script_buffered(
    project_dir: &Path,
    script_name: &str,
    extra_args: &[String],
    env_mode: Option<&str>,
    bin_hint: &ManagedRuntimeHint,
) -> Result<ScriptOutput, LpmError> {
    let (script_cmd, scripts) = resolve_script_command(project_dir, script_name)?;

    let path = bin_path::build_path_with_bins_pre_resolved(project_dir, bin_hint)?;
    let mut env_vars = resolve_and_load_env(project_dir, script_name, env_mode)?.vars;
    mark_script_child_env(&mut env_vars);

    // Pre-hook (not captured)
    if let Some(pre_cmd) = hooks::find_pre_hook(&scripts, script_name) {
        let pre_name = hooks::pre_hook_name(script_name);
        let status = shell::spawn_shell(&ShellCommand {
            command: pre_cmd,
            cwd: project_dir,
            path: &path,
            envs: &env_vars,
        })?;
        if !status.success() {
            let code = status.code().unwrap_or(1);
            return Err(LpmError::Script(format!(
                "pre-hook '{pre_name}' exited with code {code}"
            )));
        }
    }

    let full_cmd = assemble_shell_command(&script_cmd, extra_args, project_dir, &path)?;

    // Capture without terminal echo
    let captured = shell::spawn_shell_capture(&ShellCommand {
        command: &full_cmd,
        cwd: project_dir,
        path: &path,
        envs: &env_vars,
    })?;

    if !captured.status.success() {
        return Err(LpmError::ScriptWithOutput {
            code: shell::exit_code(&captured.status),
            stdout: captured.stdout,
            stderr: captured.stderr,
        });
    }

    // Post-hook (not captured)
    if let Some(post_cmd) = hooks::find_post_hook(&scripts, script_name) {
        let post_name = hooks::post_hook_name(script_name);
        let status = shell::spawn_shell(&ShellCommand {
            command: post_cmd,
            cwd: project_dir,
            path: &path,
            envs: &env_vars,
        })?;
        if !status.success() {
            let code = status.code().unwrap_or(1);
            return Err(LpmError::Script(format!(
                "post-hook '{post_name}' exited with code {code}"
            )));
        }
    }

    Ok(ScriptOutput {
        stdout: captured.stdout,
        stderr: captured.stderr,
    })
}

/// Run an explicit command with fully captured output (no terminal echo).
pub fn run_command_buffered(
    project_dir: &Path,
    command: &str,
    extra_args: &[String],
    env_mode: Option<&str>,
    bin_hint: &ManagedRuntimeHint,
) -> Result<ScriptOutput, LpmError> {
    run_command_buffered_named(
        project_dir,
        "",
        command,
        extra_args,
        env_mode,
        &[],
        bin_hint,
    )
}

pub fn run_task_command_buffered(
    project_dir: &Path,
    task_name: &str,
    command: &str,
    extra_args: &[String],
    env_mode: Option<&str>,
    bin_hint: &ManagedRuntimeHint,
) -> Result<ScriptOutput, LpmError> {
    run_command_buffered_named(
        project_dir,
        task_name,
        command,
        extra_args,
        env_mode,
        &[],
        bin_hint,
    )
}

/// Run an explicit command with fully captured output and additional env vars.
pub fn run_command_buffered_with_envs(
    project_dir: &Path,
    command: &str,
    extra_args: &[String],
    env_mode: Option<&str>,
    extra_envs: &[(String, String)],
    bin_hint: &ManagedRuntimeHint,
) -> Result<ScriptOutput, LpmError> {
    run_command_buffered_named(
        project_dir,
        "",
        command,
        extra_args,
        env_mode,
        extra_envs,
        bin_hint,
    )
}

fn run_command_buffered_named(
    project_dir: &Path,
    task_name: &str,
    command: &str,
    extra_args: &[String],
    env_mode: Option<&str>,
    extra_envs: &[(String, String)],
    bin_hint: &ManagedRuntimeHint,
) -> Result<ScriptOutput, LpmError> {
    let path = bin_path::build_path_with_bins_pre_resolved(project_dir, bin_hint)?;
    let mut env_vars = resolve_and_load_env(project_dir, task_name, env_mode)?.vars;
    for (key, value) in extra_envs {
        env_vars.insert(key.clone(), value.clone());
    }
    mark_script_child_env(&mut env_vars);

    let full_cmd = assemble_shell_command(command, extra_args, project_dir, &path)?;

    let captured = shell::spawn_shell_capture(&ShellCommand {
        command: &full_cmd,
        cwd: project_dir,
        path: &path,
        envs: &env_vars,
    })?;

    if !captured.status.success() {
        return Err(LpmError::ScriptWithOutput {
            code: shell::exit_code(&captured.status),
            stdout: captured.stdout,
            stderr: captured.stderr,
        });
    }

    Ok(ScriptOutput {
        stdout: captured.stdout,
        stderr: captured.stderr,
    })
}

/// Run a script with prefixed live output (for streaming parallel mode).
pub fn run_script_prefixed(
    project_dir: &Path,
    script_name: &str,
    extra_args: &[String],
    env_mode: Option<&str>,
    prefix: &str,
    color: &str,
    bin_hint: &ManagedRuntimeHint,
) -> Result<ScriptOutput, LpmError> {
    let (script_cmd, _scripts) = resolve_script_command(project_dir, script_name)?;

    let path = bin_path::build_path_with_bins_pre_resolved(project_dir, bin_hint)?;
    let mut env_vars = resolve_and_load_env(project_dir, script_name, env_mode)?.vars;
    mark_script_child_env(&mut env_vars);

    let full_cmd = assemble_shell_command(&script_cmd, extra_args, project_dir, &path)?;

    let captured = shell::spawn_shell_prefixed(
        &ShellCommand {
            command: &full_cmd,
            cwd: project_dir,
            path: &path,
            envs: &env_vars,
        },
        prefix,
        color,
    )?;

    if !captured.status.success() {
        return Err(LpmError::ScriptWithOutput {
            code: shell::exit_code(&captured.status),
            stdout: captured.stdout,
            stderr: captured.stderr,
        });
    }

    Ok(ScriptOutput {
        stdout: captured.stdout,
        stderr: captured.stderr,
    })
}

/// Run an explicit command with prefixed live output.
pub fn run_command_prefixed(
    project_dir: &Path,
    command: &str,
    extra_args: &[String],
    env_mode: Option<&str>,
    prefix: &str,
    color: &str,
    bin_hint: &ManagedRuntimeHint,
) -> Result<ScriptOutput, LpmError> {
    run_command_prefixed_named(
        project_dir,
        "",
        command,
        extra_args,
        env_mode,
        prefix,
        color,
        bin_hint,
    )
}

#[expect(
    clippy::too_many_arguments,
    reason = "the runner boundary keeps the task, shell, environment, output, and runtime inputs explicit"
)]
pub fn run_task_command_prefixed(
    project_dir: &Path,
    task_name: &str,
    command: &str,
    extra_args: &[String],
    env_mode: Option<&str>,
    prefix: &str,
    color: &str,
    bin_hint: &ManagedRuntimeHint,
) -> Result<ScriptOutput, LpmError> {
    run_command_prefixed_named(
        project_dir,
        task_name,
        command,
        extra_args,
        env_mode,
        prefix,
        color,
        bin_hint,
    )
}

#[expect(
    clippy::too_many_arguments,
    reason = "the runner boundary keeps the task, shell, environment, output, and runtime inputs explicit"
)]
fn run_command_prefixed_named(
    project_dir: &Path,
    task_name: &str,
    command: &str,
    extra_args: &[String],
    env_mode: Option<&str>,
    prefix: &str,
    color: &str,
    bin_hint: &ManagedRuntimeHint,
) -> Result<ScriptOutput, LpmError> {
    let path = bin_path::build_path_with_bins_pre_resolved(project_dir, bin_hint)?;
    let mut env_vars = resolve_and_load_env(project_dir, task_name, env_mode)?.vars;
    mark_script_child_env(&mut env_vars);

    let full_cmd = assemble_shell_command(command, extra_args, project_dir, &path)?;

    let captured = shell::spawn_shell_prefixed(
        &ShellCommand {
            command: &full_cmd,
            cwd: project_dir,
            path: &path,
            envs: &env_vars,
        },
        prefix,
        color,
    )?;

    if !captured.status.success() {
        return Err(LpmError::ScriptWithOutput {
            code: shell::exit_code(&captured.status),
            stdout: captured.stdout,
            stderr: captured.stderr,
        });
    }

    Ok(ScriptOutput {
        stdout: captured.stdout,
        stderr: captured.stderr,
    })
}

/// Run an explicit command string (from lpm.json task config).
///
/// Unlike `run_script`, this does NOT look up package.json scripts —
/// it executes the given command directly with the same PATH, .env, and
/// vault environment as a normal script run. Pre/post hooks are not applied
/// since command tasks are not package.json scripts.
pub fn run_command(
    project_dir: &Path,
    command: &str,
    extra_args: &[String],
    env_mode: Option<&str>,
    bin_hint: &ManagedRuntimeHint,
) -> Result<(), LpmError> {
    run_command_named_with_envs(
        project_dir,
        "",
        command,
        extra_args,
        env_mode,
        &[],
        bin_hint,
    )
}

pub fn run_task_command(
    project_dir: &Path,
    task_name: &str,
    command: &str,
    extra_args: &[String],
    env_mode: Option<&str>,
    bin_hint: &ManagedRuntimeHint,
) -> Result<(), LpmError> {
    run_command_named_with_envs(
        project_dir,
        task_name,
        command,
        extra_args,
        env_mode,
        &[],
        bin_hint,
    )
}

/// Run an explicit command string with additional environment variables.
pub fn run_command_with_envs(
    project_dir: &Path,
    command: &str,
    extra_args: &[String],
    env_mode: Option<&str>,
    extra_envs: &[(String, String)],
    bin_hint: &ManagedRuntimeHint,
) -> Result<(), LpmError> {
    run_command_named_with_envs(
        project_dir,
        "",
        command,
        extra_args,
        env_mode,
        extra_envs,
        bin_hint,
    )
}

fn run_command_named_with_envs(
    project_dir: &Path,
    task_name: &str,
    command: &str,
    extra_args: &[String],
    env_mode: Option<&str>,
    extra_envs: &[(String, String)],
    bin_hint: &ManagedRuntimeHint,
) -> Result<(), LpmError> {
    let path = bin_path::build_path_with_bins_pre_resolved(project_dir, bin_hint)?;
    let mut env_vars = resolve_and_load_env(project_dir, task_name, env_mode)?.vars;
    for (key, value) in extra_envs {
        env_vars.insert(key.clone(), value.clone());
    }
    mark_script_child_env(&mut env_vars);

    let full_cmd = assemble_shell_command(command, extra_args, project_dir, &path)?;

    let status = shell::spawn_shell(&ShellCommand {
        command: &full_cmd,
        cwd: project_dir,
        path: &path,
        envs: &env_vars,
    })?;

    if !status.success() {
        return Err(LpmError::ExitCode(shell::exit_code(&status)));
    }

    Ok(())
}

/// Build a direct process command for a project-local binary.
///
/// Resolves `command_name` only from `node_modules/.bin` directories discovered
/// from `project_dir` upward. The caller gets npm/pnpm-style local-bin PATH
/// precedence without a fallback to arbitrary system PATH executables.
pub fn build_local_bin_command(
    project_dir: &Path,
    command_name: &str,
    extra_args: &[String],
    env_mode: Option<&str>,
    no_env_check: bool,
    bin_hint: &ManagedRuntimeHint,
) -> Result<Command, LpmError> {
    let bin_path = resolve_local_bin_path(project_dir, command_name)?;
    let path = bin_path::build_path_with_bins_pre_resolved(project_dir, bin_hint)?;
    build_configured_local_bin_command(
        project_dir,
        bin_path,
        extra_args,
        env_mode,
        no_env_check,
        path,
    )
}

/// Build a direct process command for a project-local binary without allowing
/// binary or PATH discovery above `boundary`.
pub fn build_local_bin_command_bounded(
    project_dir: &Path,
    boundary: &Path,
    command_name: &str,
    extra_args: &[String],
    env_mode: Option<&str>,
    no_env_check: bool,
    bin_hint: &ManagedRuntimeHint,
) -> Result<Command, LpmError> {
    let bin_dirs = bin_path::find_bin_dirs_bounded(project_dir, boundary)?;
    let bin_path = resolve_local_bin_path_from_dirs(command_name, &bin_dirs)?;
    let path = bin_path::build_path_from_bin_dirs(project_dir, &bin_dirs, bin_hint)?;
    build_configured_local_bin_command(
        project_dir,
        bin_path,
        extra_args,
        env_mode,
        no_env_check,
        path,
    )
}

fn build_configured_local_bin_command(
    project_dir: &Path,
    bin_path: PathBuf,
    extra_args: &[String],
    env_mode: Option<&str>,
    no_env_check: bool,
    path: String,
) -> Result<Command, LpmError> {
    let env_vars =
        dotenv::load_project_env_with_schema_validation(project_dir, env_mode, !no_env_check)?;

    let mut command = Command::new(&bin_path);
    shell::strip_inherited_env_hooks(&mut command);
    command
        .args(extra_args)
        .current_dir(project_dir)
        .env("PATH", &path)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    if !env_vars.is_empty() {
        command.envs(&env_vars);
    }

    Ok(command)
}

/// Execute a project-local binary directly, with LPM env and PATH handling.
pub fn run_local_bin(
    project_dir: &Path,
    command_name: &str,
    extra_args: &[String],
    env_mode: Option<&str>,
    no_env_check: bool,
    bin_hint: &ManagedRuntimeHint,
) -> Result<(), LpmError> {
    let mut command = build_local_bin_command(
        project_dir,
        command_name,
        extra_args,
        env_mode,
        no_env_check,
        bin_hint,
    )?;
    let status = command
        .status()
        .map_err(|e| LpmError::Script(format!("failed to execute '{command_name}': {e}")))?;

    if !status.success() {
        return Err(LpmError::ExitCode(shell::exit_code(&status)));
    }

    Ok(())
}

/// Return whether `command_name` resolves to a project-local binary.
///
/// The lookup is intentionally the same `node_modules/.bin`-only resolution
/// used by [`run_local_bin`]; it never consults the inherited system PATH.
pub fn local_bin_exists(project_dir: &Path, command_name: &str) -> bool {
    resolve_local_bin_path(project_dir, command_name).is_ok()
}

fn resolve_local_bin_path(project_dir: &Path, command_name: &str) -> Result<PathBuf, LpmError> {
    if command_name.trim().is_empty() {
        return Err(LpmError::Script(
            "`lpm exec` requires a project-local binary name".into(),
        ));
    }
    if is_path_like_command(command_name) {
        return Err(LpmError::Script(format!(
            "`lpm exec` runs project-local binaries, not file paths. Use `lpm {command_name}` to run a JS/TS source file directly."
        )));
    }

    let bin_dirs = bin_path::find_bin_dirs(project_dir);
    resolve_local_bin_path_from_dirs(command_name, &bin_dirs)
}

fn resolve_local_bin_path_from_dirs(
    command_name: &str,
    bin_dirs: &[PathBuf],
) -> Result<PathBuf, LpmError> {
    if command_name.trim().is_empty() {
        return Err(LpmError::Script(
            "`lpm exec` requires a project-local binary name".into(),
        ));
    }
    if is_path_like_command(command_name) {
        return Err(LpmError::Script(format!(
            "`lpm exec` runs project-local binaries, not file paths. Use `lpm {command_name}` to run a JS/TS source file directly."
        )));
    }

    let candidate_names = local_bin_candidate_names(command_name);
    for bin_dir in bin_dirs {
        for candidate_name in &candidate_names {
            let candidate = bin_dir.join(candidate_name);
            if is_executable_file(&candidate) {
                return Ok(candidate);
            }
        }
    }

    let searched = if bin_dirs.is_empty() {
        "no node_modules/.bin directories were found".to_string()
    } else {
        format!(
            "searched {}",
            bin_dirs
                .iter()
                .map(|dir| dir.display().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        )
    };
    Err(LpmError::Script(format!(
        "project-local binary '{command_name}' was not found ({searched}). Run `lpm install` to link dependencies, or use `lpm dlx <pkg>` to run a package without adding it to the project."
    )))
}

fn is_path_like_command(command_name: &str) -> bool {
    command_name.contains('/')
        || command_name.contains('\\')
        || Path::new(command_name).is_absolute()
}

fn local_bin_candidate_names(command_name: &str) -> Vec<String> {
    #[cfg(windows)]
    {
        let path = Path::new(command_name);
        if path.extension().is_some() {
            return vec![command_name.to_string()];
        }
        return ["cmd", "exe", "bat", ""]
            .iter()
            .map(|ext| {
                if ext.is_empty() {
                    command_name.to_string()
                } else {
                    format!("{command_name}.{ext}")
                }
            })
            .collect();
    }

    #[cfg(not(windows))]
    {
        vec![command_name.to_string()]
    }
}

#[cfg(unix)]
fn is_executable_file(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;

    std::fs::metadata(path)
        .map(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

#[cfg(not(unix))]
fn is_executable_file(path: &Path) -> bool {
    path.is_file()
}

/// Run an explicit command with tee-captured output (for caching).
pub fn run_command_captured(
    project_dir: &Path,
    command: &str,
    extra_args: &[String],
    env_mode: Option<&str>,
    bin_hint: &ManagedRuntimeHint,
) -> Result<ScriptOutput, LpmError> {
    run_command_captured_named(project_dir, "", command, extra_args, env_mode, bin_hint)
}

pub fn run_task_command_captured(
    project_dir: &Path,
    task_name: &str,
    command: &str,
    extra_args: &[String],
    env_mode: Option<&str>,
    bin_hint: &ManagedRuntimeHint,
) -> Result<ScriptOutput, LpmError> {
    run_command_captured_named(
        project_dir,
        task_name,
        command,
        extra_args,
        env_mode,
        bin_hint,
    )
}

fn run_command_captured_named(
    project_dir: &Path,
    task_name: &str,
    command: &str,
    extra_args: &[String],
    env_mode: Option<&str>,
    bin_hint: &ManagedRuntimeHint,
) -> Result<ScriptOutput, LpmError> {
    let path = bin_path::build_path_with_bins_pre_resolved(project_dir, bin_hint)?;
    let mut env_vars = resolve_and_load_env(project_dir, task_name, env_mode)?.vars;
    mark_script_child_env(&mut env_vars);

    let full_cmd = assemble_shell_command(command, extra_args, project_dir, &path)?;

    let captured = shell::spawn_shell_tee(&ShellCommand {
        command: &full_cmd,
        cwd: project_dir,
        path: &path,
        envs: &env_vars,
    })?;

    if !captured.status.success() {
        return Err(LpmError::ExitCode(shell::exit_code(&captured.status)));
    }

    Ok(ScriptOutput {
        stdout: captured.stdout,
        stderr: captured.stderr,
    })
}

/// Print a one-line environment context before script execution.
///
/// Example output:
///   Env: development (via lpm.json "dev") · 5 vault secrets
fn print_env_context(loaded: &LoadedEnv) {
    let env_label = sanitize_terminal_inline(loaded.env_name.as_deref().unwrap_or("default"));

    let via = match (loaded.source, &loaded.alias) {
        ("--env flag", _) => format!("via {}", "--env".dimmed()),
        ("lpm.json task", _) => "via lpm.json task".to_string(),
        ("lpm.json", Some(alias)) => {
            format!(
                "via lpm.json \"{}\"",
                sanitize_terminal_inline(alias).dimmed()
            )
        }
        _ => String::new(),
    };

    let vault_str = if loaded.vault_count > 0 {
        format!(
            "{} vault secret{}",
            loaded.vault_count,
            if loaded.vault_count == 1 { "" } else { "s" }
        )
    } else {
        String::new()
    };

    // Build parts and join with " · "
    let mut parts = Vec::new();
    if !via.is_empty() {
        parts.push(via);
    }
    if !vault_str.is_empty() {
        parts.push(vault_str);
    }

    if parts.is_empty() {
        eprintln!("  {} {}", "Env:".dimmed(), env_label.bold());
    } else {
        eprintln!(
            "  {} {} ({})",
            "Env:".dimmed(),
            env_label.bold(),
            parts.join(" · ").dimmed()
        );
    }
}

/// Result of environment resolution + loading, including display metadata.
struct LoadedEnv {
    /// The loaded environment variables to inject into the child process.
    vars: HashMap<String, String>,
    /// The canonical environment name (e.g., "development", "production").
    /// `None` if no env was resolved (just .env + .env.local).
    env_name: Option<String>,
    /// The alias that resolved to this env (e.g., "dev" → "development").
    alias: Option<String>,
    /// How the env was determined.
    source: &'static str,
    /// Number of vault secrets loaded for this env.
    vault_count: usize,
}

/// Resolve the env mode and load environment variables.
///
/// Loading order (later sources override earlier):
/// 1. `.env` → `.env.local` → `.env.{mode}` → `.env.{mode}.local`
/// 2. **LPM Vault** (Keychain-backed secrets) — highest priority
///
/// Priority for determining the mode:
/// 1. Explicit `--env=staging` flag (highest priority)
/// 2. `lpm.json` `env` mapping for this script name
/// 3. No mode (load just `.env` and `.env.local`)
fn resolve_and_load_env(
    project_dir: &Path,
    script_name: &str,
    explicit_mode: Option<&str>,
) -> Result<LoadedEnv, LpmError> {
    let config = lpm_json::read_lpm_json(project_dir).map_err(LpmError::EnvValidation)?;
    resolve_and_load_env_with_config(project_dir, script_name, explicit_mode, config.as_ref())
}

fn resolve_and_load_env_with_config(
    project_dir: &Path,
    script_name: &str,
    explicit_mode: Option<&str>,
    config: Option<&lpm_json::LpmJsonConfig>,
) -> Result<LoadedEnv, LpmError> {
    // Determine the canonical env name via the resolver.
    // Priority: 1. explicit --env flag  2. lpm.json script mapping  3. None
    let (resolved, source) = if let Some(m) = explicit_mode {
        let resolved = match config {
            Some(c) => lpm_env::resolver::resolve(m, &c.env, c.environments.as_ref()),
            None => lpm_env::resolver::resolve(m, &Default::default(), None),
        };
        (Some(resolved), "--env flag")
    } else if let Some(task_mode) = config
        .and_then(|config| config.tasks.get(script_name))
        .and_then(|task| task.env.as_deref())
    {
        let config = config.expect("task mode requires lpm.json");
        let resolved =
            lpm_env::resolver::resolve(task_mode, &config.env, config.environments.as_ref());
        (Some(resolved), "lpm.json task")
    } else {
        match config.and_then(|c| {
            lpm_env::resolver::resolve_from_script(script_name, &c.env, c.environments.as_ref())
        }) {
            Some(resolved) => (Some(resolved), "lpm.json"),
            None => (None, "default"),
        }
    };
    let env_name = resolved.as_ref().map(|env| env.canonical.as_str());
    let file_path = resolved.as_ref().and_then(|env| env.file_path.as_deref());
    let loaded =
        dotenv::load_project_env_details_with_config(project_dir, env_name, file_path, config)?;

    Ok(LoadedEnv {
        vars: loaded.vars,
        env_name: env_name.map(str::to_string),
        alias: resolved.and_then(|env| env.alias),
        source,
        vault_count: loaded.vault_count,
    })
}

/// Load the exact environment that a named script or task receives.
///
/// This applies the same precedence as script execution: an explicit mode,
/// then `tasks.<name>.env`, then the `lpm.json` script mapping, then the
/// default environment.
pub fn load_script_env(
    project_dir: &Path,
    script_name: &str,
    explicit_mode: Option<&str>,
) -> Result<HashMap<String, String>, LpmError> {
    Ok(resolve_and_load_env(project_dir, script_name, explicit_mode)?.vars)
}

/// Load a script environment using a configuration that the caller already parsed.
pub fn load_script_env_with_config(
    project_dir: &Path,
    script_name: &str,
    explicit_mode: Option<&str>,
    config: Option<&lpm_json::LpmJsonConfig>,
) -> Result<HashMap<String, String>, LpmError> {
    Ok(resolve_and_load_env_with_config(project_dir, script_name, explicit_mode, config)?.vars)
}

/// Resolve only a script command from package.json or lpm.json tasks.
pub fn script_command(project_dir: &Path, script_name: &str) -> Result<String, LpmError> {
    resolve_script_command(project_dir, script_name).map(|(command, _)| command)
}

pub fn script_command_with_config(
    project_dir: &Path,
    script_name: &str,
    config: Option<&lpm_json::LpmJsonConfig>,
) -> Result<String, LpmError> {
    resolve_script_command_with_config(project_dir, script_name, config).map(|(command, _)| command)
}

/// Resolve a script command from package.json or lpm.json tasks.
///
/// Lookup order:
/// 1. `package.json` scripts (standard npm convention)
/// 2. `lpm.json` tasks with a `command` field (pure lpm.json projects)
///
/// Returns `(script_command, all_scripts_map)` for hook resolution.
fn resolve_script_command(
    project_dir: &Path,
    script_name: &str,
) -> Result<(String, HashMap<String, String>), LpmError> {
    let config = lpm_json::read_lpm_json(project_dir).map_err(LpmError::Script)?;
    resolve_script_command_with_config(project_dir, script_name, config.as_ref())
}

fn resolve_script_command_with_config(
    project_dir: &Path,
    script_name: &str,
    lpm_config: Option<&lpm_json::LpmJsonConfig>,
) -> Result<(String, HashMap<String, String>), LpmError> {
    let pkg_json_path = project_dir.join("package.json");

    let package = match read_package_json(&pkg_json_path) {
        Ok(package) => Some(package),
        Err(lpm_workspace::WorkspaceError::NotFound(_)) => None,
        Err(error) => {
            return Err(LpmError::Script(format!(
                "failed to read package.json: {error}"
            )));
        }
    };

    if let Some(pkg) = &package
        && let Some(cmd) = pkg.scripts.get(script_name)
    {
        return Ok((cmd.clone(), pkg.scripts.clone()));
    }

    if let Some(config) = lpm_config {
        for (task_name, task_config) in &config.tasks {
            if task_name == script_name
                && let Some(cmd) = &task_config.command
            {
                // Build a scripts map from lpm.json tasks for hook resolution
                let scripts: HashMap<String, String> = config
                    .tasks
                    .iter()
                    .filter_map(|(k, v)| v.command.as_ref().map(|c| (k.clone(), c.clone())))
                    .collect();
                return Ok((cmd.clone(), scripts));
            }
        }
    }

    // Neither package.json nor lpm.json had the script
    if let Some(pkg) = package {
        Err(script_not_found_error(script_name, &pkg.scripts))
    } else {
        let lpm_tasks = lpm_config
            .map(|c| {
                c.tasks
                    .iter()
                    .filter_map(|(k, v)| v.command.as_ref().map(|c| (k.clone(), c.clone())))
                    .collect::<HashMap<String, String>>()
            })
            .unwrap_or_default();

        if lpm_tasks.is_empty() {
            Err(LpmError::Script(
                "no package.json or lpm.json with tasks found in current directory".into(),
            ))
        } else {
            Err(script_not_found_error(script_name, &lpm_tasks))
        }
    }
}

/// Validate that an env mode string is safe to use in path construction.
///
/// Rejects modes containing path separators, parent-directory traversal,
/// null bytes, or empty strings — preventing path injection via lpm.json.
///
/// Validation is now performed inside `dotenv::load_project_env`. This function
/// is retained for backward compatibility with existing tests.
#[cfg(test)]
fn validate_env_mode(mode: &str) -> bool {
    !mode.is_empty()
        && !mode.contains('/')
        && !mode.contains('\\')
        && !mode.contains("..")
        && !mode.contains('\0')
}

/// List available scripts from package.json and lpm.json tasks.
/// Returns (script_name, command) pairs, sorted alphabetically.
pub fn list_scripts(project_dir: &Path) -> Result<Vec<(String, String)>, LpmError> {
    let mut all_scripts: HashMap<String, String> = HashMap::new();

    // Load from package.json
    let pkg_json_path = project_dir.join("package.json");
    match read_package_json(&pkg_json_path) {
        Ok(pkg) => {
            all_scripts.extend(
                pkg.scripts
                    .into_iter()
                    .filter(|(name, _)| !is_hidden_script_name(name)),
            );
        }
        Err(lpm_workspace::WorkspaceError::NotFound(_)) => {}
        Err(error) => {
            return Err(LpmError::Script(format!(
                "failed to read package.json: {error}"
            )));
        }
    }

    if let Some(config) = lpm_json::read_lpm_json(project_dir).map_err(LpmError::Script)? {
        for (name, task) in &config.tasks {
            if let Some(cmd) = &task.command {
                all_scripts
                    .entry(name.clone())
                    .or_insert_with(|| cmd.clone());
            }
        }
    }

    if all_scripts.is_empty() {
        return Err(LpmError::Script(
            "no scripts found in package.json or lpm.json".into(),
        ));
    }

    let mut scripts: Vec<(String, String)> = all_scripts.into_iter().collect();
    scripts.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(scripts)
}

/// Build a descriptive "script not found" error with available scripts listed.
fn script_not_found_error(script_name: &str, scripts: &HashMap<String, String>) -> LpmError {
    if scripts.is_empty() {
        return LpmError::Script(format!(
            "script '{script_name}' not found — no scripts defined in package.json or lpm.json"
        ));
    }

    let mut available: Vec<&str> = scripts
        .keys()
        .map(|k| k.as_str())
        .filter(|name| !is_hidden_script_name(name))
        .collect();
    available.sort();
    if available.is_empty() {
        return LpmError::Script(format!(
            "script '{script_name}' not found — no visible scripts defined in package.json or lpm.json"
        ));
    }

    LpmError::Script(format!(
        "script '{script_name}' not found. Available: {}",
        available.join(", ")
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bin_path::ManagedRuntimeHint::Unknown;
    use std::fs;

    #[cfg(unix)]
    fn make_executable(path: &Path) {
        use std::os::unix::fs::PermissionsExt;

        let mut permissions = fs::metadata(path).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(path, permissions).unwrap();
    }

    #[cfg(not(unix))]
    fn make_executable(_path: &Path) {}

    fn write_local_bin(project_dir: &Path, name: &str) -> PathBuf {
        let bin_dir = project_dir.join("node_modules").join(".bin");
        fs::create_dir_all(&bin_dir).unwrap();
        let bin_path = if cfg!(windows) {
            bin_dir.join(format!("{name}.cmd"))
        } else {
            bin_dir.join(name)
        };
        let script = if cfg!(windows) {
            "@echo off\r\necho local-bin %*\r\n"
        } else {
            "#!/bin/sh\necho local-bin \"$@\"\n"
        };
        fs::write(&bin_path, script).unwrap();
        make_executable(&bin_path);
        bin_path
    }

    #[test]
    fn run_simple_script() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("package.json"),
            r#"{"scripts": {"hello": "echo hello-from-script"}}"#,
        )
        .unwrap();

        let result = run_script(dir.path(), "hello", &[], None, &Unknown);
        assert!(result.is_ok());
    }

    #[test]
    fn run_script_with_extra_args() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("package.json"),
            r#"{"scripts": {"greet": "echo"}}"#,
        )
        .unwrap();

        let result = run_script(dir.path(), "greet", &["world".into()], None, &Unknown);
        assert!(result.is_ok());
    }

    #[test]
    fn run_nonexistent_script_errors() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("package.json"),
            r#"{"scripts": {"build": "echo build"}}"#,
        )
        .unwrap();

        let result = run_script(dir.path(), "nonexistent", &[], None, &Unknown);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("nonexistent"));
        assert!(err.contains("build"));
    }

    #[test]
    fn build_local_bin_command_resolves_project_bin_without_shell() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("package.json"), "{}").unwrap();
        let bin_path = write_local_bin(dir.path(), "eslint");

        let command = build_local_bin_command(
            dir.path(),
            "eslint",
            &["--fix".into(), "src/index.ts".into()],
            None,
            false,
            &Unknown,
        )
        .unwrap();

        assert_eq!(command.get_program(), bin_path.as_os_str());
        let args = command
            .get_args()
            .map(|arg| arg.to_string_lossy().to_string())
            .collect::<Vec<_>>();
        assert_eq!(args, vec!["--fix", "src/index.ts"]);
    }

    #[test]
    fn build_local_bin_command_keeps_shell_metacharacters_as_args() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("package.json"), "{}").unwrap();
        write_local_bin(dir.path(), "tool");

        let command = build_local_bin_command(
            dir.path(),
            "tool",
            &["; touch pwned".into(), "$(whoami)".into()],
            None,
            false,
            &Unknown,
        )
        .unwrap();
        let args = command
            .get_args()
            .map(|arg| arg.to_string_lossy().to_string())
            .collect::<Vec<_>>();

        assert_eq!(args, vec!["; touch pwned", "$(whoami)"]);
    }

    #[test]
    fn build_local_bin_command_rejects_path_like_command_names() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("package.json"), "{}").unwrap();

        let err =
            build_local_bin_command(dir.path(), "scripts/seed.ts", &[], None, false, &Unknown)
                .unwrap_err();

        assert!(err.to_string().contains("Use `lpm scripts/seed.ts`"));
    }

    #[test]
    fn build_local_bin_command_errors_when_project_bin_is_missing() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("package.json"), "{}").unwrap();

        let err =
            build_local_bin_command(dir.path(), "eslint", &[], None, false, &Unknown).unwrap_err();

        assert!(err.to_string().contains("project-local binary 'eslint'"));
    }

    #[test]
    fn build_local_bin_command_strips_credential_and_hijack_env_carriers() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("package.json"), "{}").unwrap();
        write_local_bin(dir.path(), "tool");

        let command =
            build_local_bin_command(dir.path(), "tool", &[], None, false, &Unknown).unwrap();
        let stripped = command
            .get_envs()
            .filter_map(|(key, value)| if value.is_none() { key.to_str() } else { None })
            .collect::<Vec<_>>();

        for required in ["LPM_TOKEN", "NODE_OPTIONS", "BASH_ENV", "GIT_SSH_COMMAND"] {
            assert!(
                stripped.contains(&required),
                "local-bin exec must strip {required}"
            );
        }
    }

    #[test]
    fn run_pre_hook() {
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("pre-ran");

        fs::write(
            dir.path().join("package.json"),
            format!(
                r#"{{"scripts": {{"prebuild": "touch {}", "build": "echo building"}}}}"#,
                marker.display()
            ),
        )
        .unwrap();

        let result = run_script(dir.path(), "build", &[], None, &Unknown);
        assert!(result.is_ok());
        assert!(marker.exists(), "pre-hook should have created marker file");
    }

    #[test]
    fn run_post_hook() {
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("post-ran");

        fs::write(
            dir.path().join("package.json"),
            format!(
                r#"{{"scripts": {{"build": "echo building", "postbuild": "touch {}"}}}}"#,
                marker.display()
            ),
        )
        .unwrap();

        let result = run_script(dir.path(), "build", &[], None, &Unknown);
        assert!(result.is_ok());
        assert!(marker.exists(), "post-hook should have created marker file");
    }

    #[test]
    fn pre_hook_failure_aborts() {
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("build-ran");

        fs::write(
            dir.path().join("package.json"),
            format!(
                r#"{{"scripts": {{"prebuild": "exit 1", "build": "touch {}"}}}}"#,
                marker.display()
            ),
        )
        .unwrap();

        let result = run_script(dir.path(), "build", &[], None, &Unknown);
        assert!(result.is_err());
        assert!(
            !marker.exists(),
            "build should NOT have run after pre-hook failure"
        );
    }

    #[test]
    fn no_package_json_errors() {
        let dir = tempfile::tempdir().unwrap();
        let result = run_script(dir.path(), "build", &[], None, &Unknown);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("package.json"));
    }

    #[test]
    fn list_scripts_sorted() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("package.json"),
            r#"{"scripts": {"test": "vitest", "build": "tsup", "dev": "vite"}}"#,
        )
        .unwrap();

        let scripts = list_scripts(dir.path()).unwrap();
        assert_eq!(scripts.len(), 3);
        assert_eq!(scripts[0].0, "build");
        assert_eq!(scripts[1].0, "dev");
        assert_eq!(scripts[2].0, "test");
    }

    #[test]
    fn list_scripts_omits_hidden_package_json_scripts() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("package.json"),
            r#"{"scripts": {"build": "tsup", ".build": "node internal.js"}}"#,
        )
        .unwrap();

        let scripts = list_scripts(dir.path()).unwrap();
        assert_eq!(scripts, vec![("build".to_string(), "tsup".to_string())]);
    }

    #[test]
    fn missing_script_suggestions_omit_hidden_package_json_scripts() {
        let mut scripts = HashMap::new();
        scripts.insert("build".to_string(), "tsup".to_string());
        scripts.insert(".build".to_string(), "node internal.js".to_string());

        let err = script_not_found_error("missing", &scripts);
        let msg = err.to_string();
        assert!(msg.contains("build"));
        assert!(!msg.contains(".build"));
    }

    #[test]
    fn script_children_receive_hidden_script_marker() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("package.json"),
            r#"{"scripts": {"check": "test \"$LPM_SCRIPT_CHILD\" = \"1\" "}}"#,
        )
        .unwrap();

        let result = run_script(dir.path(), "check", &[], None, &Unknown);
        assert!(result.is_ok());
    }

    #[test]
    fn path_injection_makes_bin_available() {
        let dir = tempfile::tempdir().unwrap();
        let bin_dir = dir.path().join("node_modules/.bin");
        fs::create_dir_all(&bin_dir).unwrap();

        let fake_bin = bin_dir.join("my-tool");
        fs::write(&fake_bin, "#!/bin/sh\necho my-tool-ran").unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&fake_bin, fs::Permissions::from_mode(0o755)).unwrap();
        }

        fs::write(
            dir.path().join("package.json"),
            r#"{"scripts": {"check": "my-tool"}}"#,
        )
        .unwrap();

        let result = run_script(dir.path(), "check", &[], None, &Unknown);
        assert!(result.is_ok(), "should find my-tool via PATH injection");
    }

    #[test]
    fn dotenv_vars_injected_into_script() {
        let dir = tempfile::tempdir().unwrap();

        fs::write(dir.path().join(".env"), "MY_TEST_VAR=hello_from_env").unwrap();
        fs::write(
            dir.path().join("package.json"),
            r#"{"scripts": {"check-env": "test \"$MY_TEST_VAR\" = \"hello_from_env\""}}"#,
        )
        .unwrap();

        let result = run_script(dir.path(), "check-env", &[], None, &Unknown);
        assert!(result.is_ok(), ".env var should be available in script");
    }

    #[test]
    fn env_mode_flag_loads_extra_file() {
        let dir = tempfile::tempdir().unwrap();

        fs::write(dir.path().join(".env"), "VAR=default").unwrap();
        fs::write(dir.path().join(".env.staging"), "VAR=staging_value").unwrap();
        fs::write(
            dir.path().join("package.json"),
            r#"{"scripts": {"check-env": "test \"$VAR\" = \"staging_value\""}}"#,
        )
        .unwrap();

        let result = run_script(dir.path(), "check-env", &[], Some("staging"), &Unknown);
        assert!(result.is_ok(), "--env=staging should load .env.staging");
    }

    #[test]
    fn script_env_mapping_loads_the_exact_configured_file_path() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join("config")).unwrap();
        fs::write(
            dir.path().join("config/dev.env"),
            "LPM_EXACT_ENV_MAPPING_TEST=from-configured-path\n",
        )
        .unwrap();
        fs::write(
            dir.path().join(".env.dev"),
            "LPM_EXACT_ENV_MAPPING_TEST=from-derived-path\n",
        )
        .unwrap();
        let config = lpm_json::parse_lpm_json(r#"{"env":{"dev":"config/dev.env"}}"#).unwrap();

        let loaded = load_script_env_with_config(dir.path(), "dev", None, Some(&config)).unwrap();

        assert_eq!(
            loaded.get("LPM_EXACT_ENV_MAPPING_TEST").map(String::as_str),
            Some("from-configured-path")
        );
    }

    #[test]
    fn script_command_with_config_does_not_reread_lpm_json() {
        let dir = tempfile::tempdir().unwrap();
        let config =
            lpm_json::parse_lpm_json(r#"{"tasks":{"dev":{"command":"echo configured"}}}"#).unwrap();
        fs::write(dir.path().join("lpm.json"), "{").unwrap();

        let command = script_command_with_config(dir.path(), "dev", Some(&config)).unwrap();

        assert_eq!(command, "echo configured");
    }

    #[test]
    fn failing_script_returns_exit_code_error() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("package.json"),
            r#"{"scripts": {"fail": "exit 42"}}"#,
        )
        .unwrap();

        let result = run_script(dir.path(), "fail", &[], None, &Unknown);
        assert!(result.is_err());
        match result.unwrap_err() {
            LpmError::ExitCode(code) => assert_eq!(code, 42),
            other => panic!("expected ExitCode(42), got: {other}"),
        }
    }

    #[test]
    fn validate_env_mode_rejects_path_traversal() {
        assert!(validate_env_mode("staging"), "normal mode should be valid");
        assert!(validate_env_mode("dev"), "normal mode should be valid");
        assert!(
            validate_env_mode("production"),
            "normal mode should be valid"
        );
        assert!(
            !validate_env_mode("../../etc/passwd"),
            "path traversal should be rejected"
        );
        assert!(
            !validate_env_mode("foo/bar"),
            "forward slash should be rejected"
        );
        assert!(
            !validate_env_mode("foo\\bar"),
            "backslash should be rejected"
        );
        assert!(!validate_env_mode(""), "empty mode should be rejected");
        assert!(
            !validate_env_mode("foo\0bar"),
            "null byte should be rejected"
        );
    }

    #[test]
    fn lpm_json_env_mapping() {
        let dir = tempfile::tempdir().unwrap();

        fs::write(dir.path().join(".env"), "API=default").unwrap();
        fs::write(dir.path().join(".env.development"), "API=dev_api").unwrap();
        fs::write(
            dir.path().join("lpm.json"),
            r#"{"env": {"dev": ".env.development"}}"#,
        )
        .unwrap();
        fs::write(
            dir.path().join("package.json"),
            r#"{"scripts": {"dev": "test \"$API\" = \"dev_api\""}}"#,
        )
        .unwrap();

        let result = run_script(dir.path(), "dev", &[], None, &Unknown);
        assert!(
            result.is_ok(),
            "lpm.json env mapping should auto-load .env.development for 'dev' script"
        );
    }

    // --- run_command tests ---

    #[test]
    fn run_command_executes_arbitrary_command() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("package.json"), r#"{"scripts": {}}"#).unwrap();

        let result = run_command(dir.path(), "echo command-ran", &[], None, &Unknown);
        assert!(result.is_ok());
    }

    #[test]
    fn run_command_with_extra_args() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("package.json"), r#"{"scripts": {}}"#).unwrap();

        let result = run_command(
            dir.path(),
            "echo",
            &["hello".into(), "world".into()],
            None,
            &Unknown,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn run_command_failure_returns_exit_code() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("package.json"), r#"{"scripts": {}}"#).unwrap();

        let result = run_command(dir.path(), "exit 42", &[], None, &Unknown);
        assert!(result.is_err());
        if let Err(LpmError::ExitCode(code)) = result {
            assert_eq!(code, 42);
        }
    }

    // --- run_command_captured tests ---

    #[test]
    fn run_command_captured_captures_output() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("package.json"), r#"{"scripts": {}}"#).unwrap();

        let result = run_command_captured(dir.path(), "echo captured-cmd", &[], None, &Unknown);
        assert!(result.is_ok());
        let output = result.unwrap();
        assert!(output.stdout.contains("captured-cmd"));
    }

    // --- run_script_buffered tests ---

    #[test]
    fn run_script_buffered_captures_without_tee() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("package.json"),
            r#"{"scripts": {"hello": "echo buffered-hello"}}"#,
        )
        .unwrap();

        let result = run_script_buffered(dir.path(), "hello", &[], None, &Unknown);
        assert!(result.is_ok());
        let output = result.unwrap();
        assert!(output.stdout.contains("buffered-hello"));
    }

    #[test]
    fn run_script_buffered_failure_preserves_output() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("package.json"),
            r#"{"scripts": {"fail": "echo fail-output >&2 && exit 1"}}"#,
        )
        .unwrap();

        let result = run_script_buffered(dir.path(), "fail", &[], None, &Unknown);
        assert!(result.is_err());
        if let Err(LpmError::ScriptWithOutput { code, stderr, .. }) = result {
            assert_eq!(code, 1);
            assert!(stderr.contains("fail-output"));
        } else {
            panic!("expected ScriptWithOutput error");
        }
    }

    // --- run_script_prefixed tests ---

    #[test]
    fn run_script_prefixed_captures() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("package.json"),
            r#"{"scripts": {"hello": "echo prefixed-test"}}"#,
        )
        .unwrap();

        let result = run_script_prefixed(dir.path(), "hello", &[], None, "my-task", "36", &Unknown);
        assert!(result.is_ok());
        let output = result.unwrap();
        assert!(output.stdout.contains("prefixed-test"));
    }

    #[cfg(not(windows))]
    #[test]
    fn assemble_shell_command_quotes_extra_args_against_injection() {
        let project = Path::new(".");
        let path = "";
        // Each runtime arg becomes a single-quoted POSIX shell word so
        // a malicious tail like `; rm -rf ~` lands as one literal token.
        let cmd =
            assemble_shell_command("echo hello", &["; rm -rf ~".into()], project, path).unwrap();
        assert_eq!(cmd, "echo hello '; rm -rf ~'");

        // Embedded single quotes are escaped via the close-escape-reopen
        // dance — the resulting word reaches the script as the literal
        // string `it's fine`.
        let cmd = assemble_shell_command("echo", &["it's fine".into()], project, path).unwrap();
        assert_eq!(cmd, r#"echo 'it'\''s fine'"#);

        // Shell metacharacters in extra args are inert.
        let cmd = assemble_shell_command(
            "echo",
            &["$HOME".into(), "`pwd`".into(), "&& whoami".into()],
            project,
            path,
        )
        .unwrap();
        assert_eq!(cmd, "echo '$HOME' '`pwd`' '&& whoami'");

        // Empty extra-args list returns the script body verbatim — the
        // body itself is package.json-authored and may contain pipes,
        // redirects, env expansion that must work as written.
        let cmd = assemble_shell_command("cat file | grep foo", &[], project, path).unwrap();
        assert_eq!(cmd, "cat file | grep foo");
    }

    #[test]
    fn windows_shell_argument_escaping_preserves_words_and_metacharacters() {
        let cases = [
            ("", "^\"^\""),
            ("two words", "^\"two^ words^\""),
            ("a&b", "^\"a^&b^\""),
            ("c|d", "^\"c^|d^\""),
            ("e<f", "^\"e^<f^\""),
            ("g>h", "^\"g^>h^\""),
            ("%PATH%", "^\"^%PATH^%^\""),
            ("!delayed!", "^\"^!delayed^!^\""),
            ("quoted\"value", "^\"quoted\\^\"value^\""),
            ("trail\\", "^\"trail\\\\^\""),
            ("x^(y)", "^\"x^^^(y^)^\""),
        ];

        for (input, expected) in cases {
            assert_eq!(windows_shell_quote_arg(input, false).unwrap(), expected);
        }
    }

    #[test]
    fn windows_shell_argument_escaping_rejects_line_breaks() {
        for input in ["one\ntwo", "one\rtwo", "one\0two"] {
            assert!(windows_shell_quote_arg(input, false).is_err());
        }
    }

    #[test]
    fn windows_batch_shim_argument_escaping_adds_a_second_cmd_layer() {
        let once = windows_shell_quote_arg("a&b", false).unwrap();
        let twice = windows_shell_quote_arg("a&b", true).unwrap();

        assert_eq!(once, "^\"a^&b^\"");
        assert_eq!(twice, "^^^\"a^^^&b^^^\"");
    }

    #[test]
    fn extra_args_with_shell_metachars_do_not_detonate() {
        // End-to-end: a malicious extra arg must not chain a second
        // command. The script body is a no-op `:` that swallows all
        // positional args; if injection succeeded the marker file
        // would be created by the chained `touch`.
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("pwn");
        fs::write(
            dir.path().join("package.json"),
            r#"{"scripts": {"noop": ":"}}"#,
        )
        .unwrap();

        let payload = format!("; touch {}", marker.display());
        let result = run_script(dir.path(), "noop", &[payload], None, &Unknown);
        assert!(result.is_ok());
        assert!(
            !marker.exists(),
            "shell-injected extra arg created marker — escaping is broken"
        );
    }
}
