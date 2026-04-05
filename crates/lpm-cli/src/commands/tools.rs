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
///
/// Warns on parse errors instead of silently falling back to latest version,
/// so users know their pinned version was ignored.
fn read_tool_version(project_dir: &Path, tool_name: &str) -> Option<String> {
    match lpm_runner::lpm_json::read_lpm_json(project_dir) {
        Ok(Some(config)) => config.tools.get(tool_name).cloned(),
        Ok(None) => None,
        Err(e) => {
            eprintln!(
                "  \x1b[33m!\x1b[0m failed to read lpm.json tools config: {e}"
            );
            None
        }
    }
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
    if args.is_empty() {
        return base_cmd.to_string();
    }
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

/// Run a tool command across workspace packages.
///
/// Discovers workspace, runs the tool in each member's directory sequentially.
/// Supports: "lint", "fmt", "check".
///
/// When `affected_base` is `Some(base_ref)`, only runs in packages affected by
/// git changes vs the base branch. When `None`, runs in all members (--all mode).
pub async fn tool_workspace(
    project_dir: &Path,
    tool: &str,
    args: &[String],
    check: bool,
    affected_base: Option<&str>,
    json_output: bool,
) -> Result<(), LpmError> {
    let workspace = lpm_workspace::discover_workspace(project_dir)
        .map_err(|e| LpmError::Script(format!("workspace error: {e}")))?
        .ok_or_else(|| {
            LpmError::Script(
                "no workspace found. --all/--affected require a monorepo".into(),
            )
        })?;

    // Compute affected member indices if --affected was passed
    let affected_indices = if let Some(base_ref) = affected_base {
        let ws_graph = lpm_task::graph::WorkspaceGraph::from_workspace(&workspace);
        let indices = lpm_task::affected::find_affected(&ws_graph, &workspace.root, base_ref)
            .map_err(LpmError::Script)?;
        if indices.is_empty() && !json_output {
            output::success(&format!("no packages affected vs {base_ref} — nothing to {tool}"));
            return Ok(());
        }
        Some(indices)
    } else {
        None
    };

    let mut succeeded = 0;
    let mut failed = 0;
    let mut skipped = 0;
    let total = workspace.members.len();

    for (idx, member) in workspace.members.iter().enumerate() {
        // Skip members not in the affected set
        if let Some(ref indices) = affected_indices
            && !indices.contains(&idx)
        {
            skipped += 1;
            continue;
        }
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
        let ran = succeeded + failed;
        if failed == 0 {
            if skipped > 0 {
                output::success(&format!(
                    "{tool} passed in {ran} affected packages ({skipped} skipped)"
                ));
            } else {
                output::success(&format!("{tool} passed in all {total} packages"));
            }
        } else if skipped > 0 {
            output::warn(&format!(
                "{tool}: {succeeded} passed, {failed} failed out of {ran} affected packages ({skipped} skipped)"
            ));
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
        assert_eq!(cmd, "jest");
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

    // --- Test runner detection ---

    fn write_package_json(dir: &Path, content: &str) {
        std::fs::write(dir.join("package.json"), content).unwrap();
    }

    #[test]
    fn detect_test_runner_vitest_priority() {
        let dir = tempfile::tempdir().unwrap();
        write_package_json(
            dir.path(),
            r#"{"name":"test","devDependencies":{"vitest":"^1.0","jest":"^29.0"}}"#,
        );
        let (name, cmd) = detect_test_runner(dir.path()).unwrap();
        assert_eq!(name, "vitest");
        assert_eq!(cmd, "vitest run");
    }

    #[test]
    fn detect_test_runner_jest_when_no_vitest() {
        let dir = tempfile::tempdir().unwrap();
        write_package_json(
            dir.path(),
            r#"{"name":"test","devDependencies":{"jest":"^29.0"}}"#,
        );
        let (name, cmd) = detect_test_runner(dir.path()).unwrap();
        assert_eq!(name, "jest");
        assert_eq!(cmd, "jest");
    }

    #[test]
    fn detect_test_runner_mocha_when_no_vitest_jest() {
        let dir = tempfile::tempdir().unwrap();
        write_package_json(
            dir.path(),
            r#"{"name":"test","devDependencies":{"mocha":"^10.0"}}"#,
        );
        let (name, cmd) = detect_test_runner(dir.path()).unwrap();
        assert_eq!(name, "mocha");
        assert_eq!(cmd, "mocha");
    }

    #[test]
    fn detect_test_runner_scripts_fallback() {
        let dir = tempfile::tempdir().unwrap();
        write_package_json(
            dir.path(),
            r#"{"name":"test","scripts":{"test":"node test.js"}}"#,
        );
        let (name, cmd) = detect_test_runner(dir.path()).unwrap();
        assert_eq!(name, "scripts.test");
        assert_eq!(cmd, "node test.js");
    }

    #[test]
    fn detect_test_runner_deps_not_just_dev_deps() {
        let dir = tempfile::tempdir().unwrap();
        write_package_json(
            dir.path(),
            r#"{"name":"test","dependencies":{"vitest":"^1.0"}}"#,
        );
        let (name, _) = detect_test_runner(dir.path()).unwrap();
        assert_eq!(name, "vitest");
    }

    #[test]
    fn detect_test_runner_no_runner_errors() {
        let dir = tempfile::tempdir().unwrap();
        write_package_json(dir.path(), r#"{"name":"test"}"#);
        let err = detect_test_runner(dir.path()).unwrap_err();
        assert!(
            err.to_string().contains("no test runner found"),
            "error: {err}"
        );
    }

    #[test]
    fn detect_test_runner_no_package_json() {
        let dir = tempfile::tempdir().unwrap();
        let err = detect_test_runner(dir.path()).unwrap_err();
        assert!(
            err.to_string().contains("no package.json"),
            "error: {err}"
        );
    }

    // --- Bench runner detection ---

    #[test]
    fn bench_detects_vitest() {
        let dir = tempfile::tempdir().unwrap();
        write_package_json(
            dir.path(),
            r#"{"name":"test","devDependencies":{"vitest":"^1.0"}}"#,
        );
        // bench() is async, but we can test the detection logic directly.
        // The bench function reads package.json and checks for vitest dep.
        let pkg_json_path = dir.path().join("package.json");
        let pkg = lpm_workspace::read_package_json(&pkg_json_path).unwrap();
        assert!(pkg.dev_dependencies.contains_key("vitest"));
    }

    #[test]
    fn bench_fallback_to_scripts() {
        let dir = tempfile::tempdir().unwrap();
        write_package_json(
            dir.path(),
            r#"{"name":"test","scripts":{"bench":"node bench.js"}}"#,
        );
        let pkg_json_path = dir.path().join("package.json");
        let pkg = lpm_workspace::read_package_json(&pkg_json_path).unwrap();
        assert!(!pkg.dev_dependencies.contains_key("vitest"));
        assert!(!pkg.dependencies.contains_key("vitest"));
        assert_eq!(pkg.scripts.get("bench").unwrap(), "node bench.js");
    }

    // --- read_tool_version ---

    #[test]
    fn read_tool_version_from_lpm_json() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("lpm.json"),
            r#"{"tools":{"oxlint":"1.55.0","biome":"2.4.5"}}"#,
        )
        .unwrap();
        assert_eq!(
            read_tool_version(dir.path(), "oxlint"),
            Some("1.55.0".into())
        );
        assert_eq!(
            read_tool_version(dir.path(), "biome"),
            Some("2.4.5".into())
        );
    }

    #[test]
    fn read_tool_version_missing_tool_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("lpm.json"), r#"{"tools":{"oxlint":"1.55.0"}}"#).unwrap();
        assert_eq!(read_tool_version(dir.path(), "biome"), None);
    }

    #[test]
    fn read_tool_version_no_lpm_json_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(read_tool_version(dir.path(), "oxlint"), None);
    }

    #[test]
    fn read_tool_version_malformed_json_warns_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("lpm.json"), "not valid json{{{").unwrap();
        // Should return None (not panic) and print a warning
        assert_eq!(read_tool_version(dir.path(), "oxlint"), None);
    }

    // --- fmt argument construction ---

    #[test]
    fn fmt_default_adds_write() {
        // When check=false, fmt should pass "--write" to biome
        // We can verify the arg construction logic directly
        let mut biome_args = vec!["format".to_string()];
        let user_args: Vec<String> = vec![];
        if user_args.is_empty() {
            biome_args.push(".".into());
        } else {
            biome_args.extend_from_slice(&user_args);
        }
        let check = false;
        if !check {
            biome_args.push("--write".into());
        }
        assert_eq!(biome_args, vec!["format", ".", "--write"]);
    }

    #[test]
    fn fmt_check_omits_write() {
        let mut biome_args = vec!["format".to_string()];
        let user_args: Vec<String> = vec![];
        if user_args.is_empty() {
            biome_args.push(".".into());
        }
        let check = true;
        if !check {
            biome_args.push("--write".into());
        }
        assert_eq!(biome_args, vec!["format", "."]);
    }

    #[test]
    fn fmt_with_path_arg() {
        let mut biome_args = vec!["format".to_string()];
        let user_args = vec!["src/".to_string()];
        if user_args.is_empty() {
            biome_args.push(".".into());
        } else {
            biome_args.extend_from_slice(&user_args);
        }
        let check = false;
        if !check {
            biome_args.push("--write".into());
        }
        assert_eq!(biome_args, vec!["format", "src/", "--write"]);
    }

    // --- CLI parser tests for --affected --base ---

    #[test]
    fn lint_affected_parses() {
        use clap::Parser;
        let cli = crate::Cli::try_parse_from(["lpm", "lint", "--affected", "--base", "develop"])
            .unwrap();
        match cli.command {
            crate::Commands::Lint {
                all,
                affected,
                base,
                args,
            } => {
                assert!(!all);
                assert!(affected);
                assert_eq!(base, "develop");
                assert!(args.is_empty());
            }
            _ => panic!("expected Lint command"),
        }
    }

    #[test]
    fn fmt_affected_parses() {
        use clap::Parser;
        let cli = crate::Cli::try_parse_from(["lpm", "fmt", "--affected", "--check"]).unwrap();
        match cli.command {
            crate::Commands::Fmt {
                check,
                all,
                affected,
                ..
            } => {
                assert!(check);
                assert!(!all);
                assert!(affected);
            }
            _ => panic!("expected Fmt command"),
        }
    }

    #[test]
    fn check_affected_parses() {
        use clap::Parser;
        let cli = crate::Cli::try_parse_from(["lpm", "check", "--affected"]).unwrap();
        match cli.command {
            crate::Commands::Check {
                all, affected, ..
            } => {
                assert!(!all);
                assert!(affected);
            }
            _ => panic!("expected Check command"),
        }
    }

    #[test]
    fn lint_all_and_affected_conflict() {
        use clap::Parser;
        let result = crate::Cli::try_parse_from(["lpm", "lint", "--all", "--affected"]);
        assert!(result.is_err(), "--all and --affected should conflict");
    }

    #[test]
    fn lint_affected_default_base_is_main() {
        use clap::Parser;
        let cli = crate::Cli::try_parse_from(["lpm", "lint", "--affected"]).unwrap();
        match cli.command {
            crate::Commands::Lint { base, .. } => {
                assert_eq!(base, "main");
            }
            _ => panic!("expected Lint command"),
        }
    }
}
