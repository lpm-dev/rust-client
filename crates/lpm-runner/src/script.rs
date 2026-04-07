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
use crate::dotenv;
use crate::hooks;
use crate::lpm_json;
use crate::shell::{self, ShellCommand};
use lpm_common::LpmError;
use lpm_workspace::read_package_json;
use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};

/// Global flag to skip env schema validation (set by `--no-env-check`).
static SKIP_ENV_VALIDATION: AtomicBool = AtomicBool::new(false);

/// Set the global flag to skip env schema validation.
///
/// Called by the CLI layer when `--no-env-check` is passed.
pub fn set_skip_env_validation(skip: bool) {
    SKIP_ENV_VALIDATION.store(skip, Ordering::Relaxed);
}

pub(crate) fn should_skip_env_validation() -> bool {
    SKIP_ENV_VALIDATION.load(Ordering::Relaxed)
}

/// Run a package.json script by name, with PATH injection, .env loading, and hooks.
///
/// # Arguments
/// * `project_dir` — project root (where package.json lives)
/// * `script_name` — the script key (e.g., "build", "dev", "test")
/// * `extra_args` — additional arguments appended to the script command
/// * `env_mode` — optional env mode from `--env` flag (e.g., "staging")
pub fn run_script(
    project_dir: &Path,
    script_name: &str,
    extra_args: &[String],
    env_mode: Option<&str>,
) -> Result<(), LpmError> {
    run_script_with_envs(project_dir, script_name, extra_args, env_mode, &[])
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
) -> Result<(), LpmError> {
    let (script_cmd, scripts) = resolve_script_command(project_dir, script_name)?;

    // Build PATH with .bin dirs prepended
    let path = bin_path::build_path_with_bins(project_dir);

    // Load .env files + merge extra env vars (from HTTPS/tunnel/network setup)
    let mut env_vars = resolve_and_load_env(project_dir, script_name, env_mode)?;
    for (key, value) in extra_envs {
        env_vars.insert(key.clone(), value.clone());
    }

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

    // Build the full command with extra args
    let full_cmd = if extra_args.is_empty() {
        script_cmd
    } else {
        format!("{} {}", script_cmd, extra_args.join(" "))
    };

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
) -> Result<ScriptOutput, LpmError> {
    let (script_cmd, scripts) = resolve_script_command(project_dir, script_name)?;

    let path = bin_path::build_path_with_bins(project_dir);
    let env_vars = resolve_and_load_env(project_dir, script_name, env_mode)?;

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

    // Build full command with extra args
    let full_cmd = if extra_args.is_empty() {
        script_cmd
    } else {
        format!("{} {}", script_cmd, extra_args.join(" "))
    };

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
) -> Result<ScriptOutput, LpmError> {
    let (script_cmd, scripts) = resolve_script_command(project_dir, script_name)?;

    let path = bin_path::build_path_with_bins(project_dir);
    let env_vars = resolve_and_load_env(project_dir, script_name, env_mode)?;

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

    let full_cmd = if extra_args.is_empty() {
        script_cmd
    } else {
        format!("{} {}", script_cmd, extra_args.join(" "))
    };

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
) -> Result<ScriptOutput, LpmError> {
    let path = bin_path::build_path_with_bins(project_dir);
    let env_vars = resolve_and_load_env(project_dir, "", env_mode)?;

    let full_cmd = if extra_args.is_empty() {
        command.to_string()
    } else {
        format!("{} {}", command, extra_args.join(" "))
    };

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
) -> Result<ScriptOutput, LpmError> {
    let (script_cmd, _scripts) = resolve_script_command(project_dir, script_name)?;

    let path = bin_path::build_path_with_bins(project_dir);
    let env_vars = resolve_and_load_env(project_dir, script_name, env_mode)?;

    let full_cmd = if extra_args.is_empty() {
        script_cmd
    } else {
        format!("{} {}", script_cmd, extra_args.join(" "))
    };

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
) -> Result<ScriptOutput, LpmError> {
    let path = bin_path::build_path_with_bins(project_dir);
    let env_vars = resolve_and_load_env(project_dir, "", env_mode)?;

    let full_cmd = if extra_args.is_empty() {
        command.to_string()
    } else {
        format!("{} {}", command, extra_args.join(" "))
    };

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
) -> Result<(), LpmError> {
    let path = bin_path::build_path_with_bins(project_dir);
    let env_vars = resolve_and_load_env(project_dir, "", env_mode)?;

    let full_cmd = if extra_args.is_empty() {
        command.to_string()
    } else {
        format!("{} {}", command, extra_args.join(" "))
    };

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

/// Run an explicit command with tee-captured output (for caching).
pub fn run_command_captured(
    project_dir: &Path,
    command: &str,
    extra_args: &[String],
    env_mode: Option<&str>,
) -> Result<ScriptOutput, LpmError> {
    let path = bin_path::build_path_with_bins(project_dir);
    let env_vars = resolve_and_load_env(project_dir, "", env_mode)?;

    let full_cmd = if extra_args.is_empty() {
        command.to_string()
    } else {
        format!("{} {}", command, extra_args.join(" "))
    };

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
) -> Result<HashMap<String, String>, LpmError> {
    // Determine the effective env name (from --env flag or lpm.json script mapping)
    let env_name = if let Some(m) = explicit_mode {
        Some(m.to_string())
    } else {
        match lpm_json::read_lpm_json(project_dir) {
            Ok(Some(config)) => {
                lpm_json::resolve_env_mode(&config, script_name).and_then(|env_path| {
                    lpm_json::extract_mode_from_env_path(&env_path).map(|s| s.to_string())
                })
            }
            _ => None,
        }
    };

    // Delegate to the unified loader (handles inheritance, vault, schema validation)
    dotenv::load_project_env(project_dir, env_name.as_deref())
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
    let pkg_json_path = project_dir.join("package.json");

    // Try package.json first
    if pkg_json_path.exists() {
        let pkg = read_package_json(&pkg_json_path)
            .map_err(|e| LpmError::Script(format!("failed to read package.json: {e}")))?;

        if let Some(cmd) = pkg.scripts.get(script_name) {
            return Ok((cmd.clone(), pkg.scripts.clone()));
        }

        // Script not in package.json — fall through to lpm.json
    }

    // Try lpm.json tasks
    if let Ok(Some(config)) = lpm_json::read_lpm_json(project_dir) {
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
    if pkg_json_path.exists() {
        let pkg = read_package_json(&pkg_json_path)
            .map_err(|e| LpmError::Script(format!("failed to read package.json: {e}")))?;
        Err(script_not_found_error(script_name, &pkg.scripts))
    } else {
        // No package.json at all
        let lpm_tasks = lpm_json::read_lpm_json(project_dir)
            .ok()
            .flatten()
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
    if pkg_json_path.exists()
        && let Ok(pkg) = read_package_json(&pkg_json_path)
    {
        all_scripts.extend(pkg.scripts);
    }

    // Load from lpm.json tasks (commands not already in package.json)
    if let Ok(Some(config)) = lpm_json::read_lpm_json(project_dir) {
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

    let mut available: Vec<&str> = scripts.keys().map(|k| k.as_str()).collect();
    available.sort();

    LpmError::Script(format!(
        "script '{script_name}' not found. Available: {}",
        available.join(", ")
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn run_simple_script() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("package.json"),
            r#"{"scripts": {"hello": "echo hello-from-script"}}"#,
        )
        .unwrap();

        let result = run_script(dir.path(), "hello", &[], None);
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

        let result = run_script(dir.path(), "greet", &["world".into()], None);
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

        let result = run_script(dir.path(), "nonexistent", &[], None);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("nonexistent"));
        assert!(err.contains("build"));
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

        let result = run_script(dir.path(), "build", &[], None);
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

        let result = run_script(dir.path(), "build", &[], None);
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

        let result = run_script(dir.path(), "build", &[], None);
        assert!(result.is_err());
        assert!(
            !marker.exists(),
            "build should NOT have run after pre-hook failure"
        );
    }

    #[test]
    fn no_package_json_errors() {
        let dir = tempfile::tempdir().unwrap();
        let result = run_script(dir.path(), "build", &[], None);
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

        let result = run_script(dir.path(), "check", &[], None);
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

        let result = run_script(dir.path(), "check-env", &[], None);
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

        let result = run_script(dir.path(), "check-env", &[], Some("staging"));
        assert!(result.is_ok(), "--env=staging should load .env.staging");
    }

    #[test]
    fn failing_script_returns_exit_code_error() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("package.json"),
            r#"{"scripts": {"fail": "exit 42"}}"#,
        )
        .unwrap();

        let result = run_script(dir.path(), "fail", &[], None);
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

        let result = run_script(dir.path(), "dev", &[], None);
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

        let result = run_command(dir.path(), "echo command-ran", &[], None);
        assert!(result.is_ok());
    }

    #[test]
    fn run_command_with_extra_args() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("package.json"), r#"{"scripts": {}}"#).unwrap();

        let result = run_command(dir.path(), "echo", &["hello".into(), "world".into()], None);
        assert!(result.is_ok());
    }

    #[test]
    fn run_command_failure_returns_exit_code() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("package.json"), r#"{"scripts": {}}"#).unwrap();

        let result = run_command(dir.path(), "exit 42", &[], None);
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

        let result = run_command_captured(dir.path(), "echo captured-cmd", &[], None);
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

        let result = run_script_buffered(dir.path(), "hello", &[], None);
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

        let result = run_script_buffered(dir.path(), "fail", &[], None);
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

        let result = run_script_prefixed(dir.path(), "hello", &[], None, "my-task", "36");
        assert!(result.is_ok());
        let output = result.unwrap();
        assert!(output.stdout.contains("prefixed-test"));
    }
}
