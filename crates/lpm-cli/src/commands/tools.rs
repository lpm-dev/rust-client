use crate::output;
use lpm_common::LpmError;
use owo_colors::OwoColorize;
use std::path::Path;
use std::process::{Command, Stdio};

/// Run `lpm lint` — delegates to oxlint via plugin system.
pub async fn lint(project_dir: &Path, args: &[String], json_output: bool) -> Result<(), LpmError> {
    let version = read_tool_version(project_dir, "oxlint");
    let bin = lpm_plugin::ensure_plugin("oxlint", version.as_deref(), false).await?;

    if !json_output {
        output::info(&format!(
            "lint (oxlint {})",
            version.as_deref().unwrap_or("latest")
        ));
    }

    run_tool_binary(&bin, args, project_dir)
}

/// Run `lpm fmt` — delegates to biome via plugin system.
///
/// `lpm fmt`         → `biome format . --write` (format and write)
/// `lpm fmt --check` → `biome format .`         (check only, exit 1 if unformatted)
/// `lpm fmt src/`    → `biome format src/ --write` (format specific dir)
pub async fn fmt(
    project_dir: &Path,
    args: &[String],
    check: bool,
    json_output: bool,
) -> Result<(), LpmError> {
    let version = read_tool_version(project_dir, "biome");
    let bin = lpm_plugin::ensure_plugin("biome", version.as_deref(), false).await?;

    if !json_output {
        let mode = if check { "check" } else { "write" };
        output::info(&format!(
            "fmt ({mode}, biome {})",
            version.as_deref().unwrap_or("latest")
        ));
    }

    let mut biome_args = vec!["format".to_string()];
    if args.is_empty() {
        biome_args.push(".".into());
    } else {
        biome_args.extend_from_slice(args);
    }

    // --check mode: biome format without --write exits non-zero if files aren't formatted
    // Default mode: add --write so files are actually formatted
    if !check {
        biome_args.push("--write".into());
    }

    run_tool_binary(&bin, &biome_args, project_dir)
}

/// Run `lpm check` — delegates to tsc --noEmit from node_modules/.bin.
pub async fn check(project_dir: &Path, args: &[String], json_output: bool) -> Result<(), LpmError> {
    if !json_output {
        output::info("check (tsc --noEmit)");
    }

    // tsc should be in node_modules/.bin via PATH injection
    let path = lpm_runner::bin_path::build_path_with_bins(project_dir);

    let mut cmd_args = vec!["--noEmit".to_string()];
    cmd_args.extend_from_slice(args);

    let status = Command::new("tsc")
        .args(&cmd_args)
        .current_dir(project_dir)
        .env("PATH", &path)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .map_err(|e| {
            LpmError::Script(format!(
                "failed to run tsc: {e}. Is typescript installed? Run: lpm install typescript"
            ))
        })?;

    if !status.success() {
        let code = status.code().unwrap_or(1);
        return Err(LpmError::ExitCode(code));
    }

    Ok(())
}

/// Run `lpm test` — auto-detects test runner and delegates.
pub async fn test(project_dir: &Path, args: &[String], json_output: bool) -> Result<(), LpmError> {
    let (runner_name, runner_cmd) = detect_test_runner(project_dir)?;

    if !json_output {
        output::info(&format!("test ({runner_name})"));
    }

    let path = lpm_runner::bin_path::build_path_with_bins(project_dir);
    let env_vars = lpm_runner::dotenv::load_env_files(project_dir, None);

    let full_cmd = if args.is_empty() {
        runner_cmd.clone()
    } else {
        build_safe_command(&runner_name, &runner_cmd, args)
    };

    let status = lpm_runner::shell::spawn_shell(&lpm_runner::shell::ShellCommand {
        command: &full_cmd,
        cwd: project_dir,
        path: &path,
        envs: &env_vars,
    })?;

    if !status.success() {
        return Err(LpmError::ExitCode(lpm_runner::shell::exit_code(&status)));
    }

    Ok(())
}

/// Run `lpm bench` — auto-detects benchmark runner and delegates.
pub async fn bench(project_dir: &Path, args: &[String], json_output: bool) -> Result<(), LpmError> {
    // Check for vitest bench first, then package.json scripts.bench
    let pkg_json_path = project_dir.join("package.json");
    let (runner_name, cmd) = if pkg_json_path.exists() {
        let pkg = lpm_workspace::read_package_json(&pkg_json_path)
            .map_err(|e| LpmError::Script(format!("{e}")))?;

        if pkg.dependencies.contains_key("vitest") || pkg.dev_dependencies.contains_key("vitest") {
            ("vitest".to_string(), "vitest bench".to_string())
        } else if let Some(bench_script) = pkg.scripts.get("bench") {
            ("scripts.bench".to_string(), bench_script.clone())
        } else {
            return Err(LpmError::Script(
                "no benchmark runner found. Install vitest or add a 'bench' script to package.json"
                    .into(),
            ));
        }
    } else {
        return Err(LpmError::Script("no package.json found".into()));
    };

    if !json_output {
        output::info(&format!(
            "bench ({})",
            cmd.split_whitespace().next().unwrap_or("unknown")
        ));
    }

    let path = lpm_runner::bin_path::build_path_with_bins(project_dir);
    let env_vars = lpm_runner::dotenv::load_env_files(project_dir, None);

    let full_cmd = if args.is_empty() {
        cmd.clone()
    } else {
        build_safe_command(&runner_name, &cmd, args)
    };

    let status = lpm_runner::shell::spawn_shell(&lpm_runner::shell::ShellCommand {
        command: &full_cmd,
        cwd: project_dir,
        path: &path,
        envs: &env_vars,
    })?;

    if !status.success() {
        return Err(LpmError::ExitCode(lpm_runner::shell::exit_code(&status)));
    }

    Ok(())
}

// --- Helpers ---

/// Read a tool version from lpm.json tools section.
fn read_tool_version(project_dir: &Path, tool_name: &str) -> Option<String> {
    let config = lpm_runner::lpm_json::read_lpm_json(project_dir).ok()??;
    config.tools.get(tool_name).cloned()
}

/// Run a plugin binary with args, inheriting stdio.
fn run_tool_binary(bin: &Path, args: &[String], cwd: &Path) -> Result<(), LpmError> {
    let status = Command::new(bin)
        .args(args)
        .current_dir(cwd)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .map_err(|e| LpmError::Script(format!("failed to run {}: {e}", bin.display())))?;

    if !status.success() {
        let code = status.code().unwrap_or(1);
        return Err(LpmError::ExitCode(code));
    }

    Ok(())
}

/// Shell-escape a single argument to prevent injection.
///
/// Wraps the argument in single quotes, escaping any embedded single quotes
/// using the `'\''` technique (end quote, escaped literal quote, start quote).
fn shell_escape(arg: &str) -> String {
    format!("'{}'", arg.replace('\'', "'\\''"))
}

/// Build a shell command string with safely escaped extra arguments.
///
/// For known runners (vitest, jest, mocha), the base command is trusted and
/// extra args are shell-escaped before appending. For user-defined scripts
/// (scripts.test, scripts.bench), the script itself runs via `sh -c` and
/// extra args are also escaped.
fn build_safe_command(_runner_name: &str, base_cmd: &str, args: &[String]) -> String {
    let escaped: Vec<String> = args.iter().map(|a| shell_escape(a)).collect();
    format!("{} {}", base_cmd, escaped.join(" "))
}

/// Auto-detect the test runner from package.json devDependencies.
fn detect_test_runner(project_dir: &Path) -> Result<(String, String), LpmError> {
    let pkg_json_path = project_dir.join("package.json");
    if !pkg_json_path.exists() {
        return Err(LpmError::Script("no package.json found".into()));
    }

    let pkg = lpm_workspace::read_package_json(&pkg_json_path)
        .map_err(|e| LpmError::Script(format!("{e}")))?;

    let all_deps: Vec<&String> = pkg
        .dependencies
        .keys()
        .chain(pkg.dev_dependencies.keys())
        .collect();

    // Priority order: vitest > jest > mocha > scripts.test
    if all_deps.iter().any(|d| d.as_str() == "vitest") {
        return Ok(("vitest".into(), "vitest run".into()));
    }
    if all_deps.iter().any(|d| d.as_str() == "jest") {
        return Ok(("jest".into(), "jest".into()));
    }
    if all_deps.iter().any(|d| d.as_str() == "mocha") {
        return Ok(("mocha".into(), "mocha".into()));
    }

    // Fallback to package.json scripts.test
    if let Some(test_script) = pkg.scripts.get("test") {
        return Ok(("scripts.test".into(), test_script.clone()));
    }

    Err(LpmError::Script(
        "no test runner found. Install vitest/jest/mocha or add a 'test' script to package.json"
            .into(),
    ))
}

/// Run a tool command across all workspace packages.
///
/// Discovers workspace, runs the tool in each member's directory sequentially.
/// Supports: "lint", "fmt", "check".
pub async fn tool_workspace(
    project_dir: &Path,
    tool: &str,
    args: &[String],
    check: bool,
    json_output: bool,
) -> Result<(), LpmError> {
    let workspace = lpm_workspace::discover_workspace(project_dir)
        .map_err(|e| LpmError::Script(format!("workspace error: {e}")))?
        .ok_or_else(|| LpmError::Script("no workspace found. --all requires a monorepo".into()))?;

    let mut succeeded = 0;
    let mut failed = 0;
    let total = workspace.members.len();

    for member in &workspace.members {
        let name = member.package.name.as_deref().unwrap_or("unnamed");
        let member_dir = &member.path;

        if !json_output {
            output::info(&format!("[{}] {tool}", name.bold()));
        }

        let result = match tool {
            "lint" => lint(member_dir, args, json_output).await,
            "fmt" => fmt(member_dir, args, check, json_output).await,
            "check" => check_fn(member_dir, args, json_output).await,
            _ => Err(LpmError::Script(format!("unknown tool: {tool}"))),
        };

        match result {
            Ok(()) => succeeded += 1,
            Err(LpmError::ExitCode(_)) => {
                failed += 1;
            }
            Err(e) => {
                failed += 1;
                if !json_output {
                    eprintln!("  \x1b[31m[{name}]\x1b[0m {e}");
                }
            }
        }
    }

    if !json_output {
        if failed == 0 {
            output::success(&format!("{tool} passed in all {total} packages"));
        } else {
            output::warn(&format!(
                "{tool}: {succeeded} passed, {failed} failed out of {total} packages"
            ));
        }
    }

    if failed > 0 {
        return Err(LpmError::ExitCode(1));
    }

    Ok(())
}

/// Wrapper to avoid name collision with the `check` function in match arms
/// where `check` is also used as a variable name.
async fn check_fn(project_dir: &Path, args: &[String], json_output: bool) -> Result<(), LpmError> {
    check(project_dir, args, json_output).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shell_escape_plain_arg() {
        assert_eq!(shell_escape("--verbose"), "'--verbose'");
    }

    #[test]
    fn shell_escape_prevents_injection_semicolon() {
        let escaped = shell_escape("; rm -rf /");
        // The semicolon must be inside single quotes, not interpreted
        assert_eq!(escaped, "'; rm -rf /'");
        assert!(escaped.starts_with('\''));
        assert!(escaped.ends_with('\''));
    }

    #[test]
    fn shell_escape_prevents_injection_subshell() {
        let escaped = shell_escape("$(whoami)");
        assert_eq!(escaped, "'$(whoami)'");
    }

    #[test]
    fn shell_escape_prevents_backtick_injection() {
        let escaped = shell_escape("`whoami`");
        assert_eq!(escaped, "'`whoami`'");
    }

    #[test]
    fn shell_escape_handles_embedded_single_quotes() {
        let escaped = shell_escape("it's");
        assert_eq!(escaped, "'it'\\''s'");
    }

    #[test]
    fn build_safe_command_escapes_all_args() {
        let cmd = build_safe_command(
            "vitest",
            "vitest run",
            &["--reporter".to_string(), "; echo pwned".to_string()],
        );
        assert_eq!(cmd, "vitest run '--reporter' '; echo pwned'");
    }

    #[test]
    fn build_safe_command_no_args() {
        let cmd = build_safe_command("jest", "jest", &[]);
        assert_eq!(cmd, "jest ");
    }

    #[test]
    fn run_tool_binary_returns_exit_code_error() {
        // Verify run_tool_binary returns ExitCode error, not process::exit
        let result = run_tool_binary(Path::new("/usr/bin/false"), &[], Path::new("/tmp"));
        match result {
            Err(LpmError::ExitCode(code)) => assert_ne!(code, 0),
            other => panic!("expected ExitCode error, got: {other:?}"),
        }
    }
}
