use crate::output;
use lpm_common::LpmError;
use owo_colors::OwoColorize;
use std::path::Path;
use std::process::{Command, Stdio};

/// Run `lpm lint` — delegates to oxlint via plugin system.
pub async fn lint(
	project_dir: &Path,
	args: &[String],
	json_output: bool,
) -> Result<(), LpmError> {
	let version = read_tool_version(project_dir, "oxlint");
	let bin = lpm_plugin::ensure_plugin("oxlint", version.as_deref(), false).await?;

	if !json_output {
		output::info(&format!("lint (oxlint {})", version.as_deref().unwrap_or("latest")));
	}

	run_tool_binary(&bin, args, project_dir)
}

/// Run `lpm fmt` — delegates to biome via plugin system.
pub async fn fmt(
	project_dir: &Path,
	args: &[String],
	json_output: bool,
) -> Result<(), LpmError> {
	let version = read_tool_version(project_dir, "biome");
	let bin = lpm_plugin::ensure_plugin("biome", version.as_deref(), false).await?;

	if !json_output {
		output::info(&format!("fmt (biome {})", version.as_deref().unwrap_or("latest")));
	}

	// biome uses "format" subcommand, but also "check --write" for lint+format
	let mut biome_args = vec!["format".to_string()];
	if args.is_empty() {
		// Default: format current directory
		biome_args.push(".".into());
		biome_args.push("--write".into());
	} else {
		biome_args.extend_from_slice(args);
	}

	run_tool_binary(&bin, &biome_args, project_dir)
}

/// Run `lpm check` — delegates to tsc --noEmit from node_modules/.bin.
pub async fn check(
	project_dir: &Path,
	args: &[String],
	json_output: bool,
) -> Result<(), LpmError> {
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
		std::process::exit(code);
	}

	Ok(())
}

/// Run `lpm test` — auto-detects test runner and delegates.
pub async fn test(
	project_dir: &Path,
	args: &[String],
	json_output: bool,
) -> Result<(), LpmError> {
	let (runner_name, runner_cmd) = detect_test_runner(project_dir)?;

	if !json_output {
		output::info(&format!("test ({runner_name})"));
	}

	let path = lpm_runner::bin_path::build_path_with_bins(project_dir);
	let env_vars = lpm_runner::dotenv::load_env_files(project_dir, None);

	let full_cmd = if args.is_empty() {
		runner_cmd
	} else {
		format!("{} {}", runner_cmd, args.join(" "))
	};

	let status = lpm_runner::shell::spawn_shell(&lpm_runner::shell::ShellCommand {
		command: &full_cmd,
		cwd: project_dir,
		path: &path,
		envs: &env_vars,
	})?;

	if !status.success() {
		std::process::exit(lpm_runner::shell::exit_code(&status));
	}

	Ok(())
}

/// Run `lpm bench` — auto-detects benchmark runner and delegates.
pub async fn bench(
	project_dir: &Path,
	args: &[String],
	json_output: bool,
) -> Result<(), LpmError> {
	// Check for vitest bench first, then package.json scripts.bench
	let pkg_json_path = project_dir.join("package.json");
	let cmd = if pkg_json_path.exists() {
		let pkg = lpm_workspace::read_package_json(&pkg_json_path)
			.map_err(|e| LpmError::Script(format!("{e}")))?;

		if pkg.dependencies.contains_key("vitest") || pkg.dev_dependencies.contains_key("vitest") {
			"vitest bench".to_string()
		} else if let Some(bench_script) = pkg.scripts.get("bench") {
			bench_script.clone()
		} else {
			return Err(LpmError::Script(
				"no benchmark runner found. Install vitest or add a 'bench' script to package.json".into(),
			));
		}
	} else {
		return Err(LpmError::Script("no package.json found".into()));
	};

	if !json_output {
		output::info(&format!("bench ({})", cmd.split_whitespace().next().unwrap_or("unknown")));
	}

	let path = lpm_runner::bin_path::build_path_with_bins(project_dir);
	let env_vars = lpm_runner::dotenv::load_env_files(project_dir, None);

	let full_cmd = if args.is_empty() {
		cmd
	} else {
		format!("{} {}", cmd, args.join(" "))
	};

	let status = lpm_runner::shell::spawn_shell(&lpm_runner::shell::ShellCommand {
		command: &full_cmd,
		cwd: project_dir,
		path: &path,
		envs: &env_vars,
	})?;

	if !status.success() {
		std::process::exit(lpm_runner::shell::exit_code(&status));
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
fn run_tool_binary(
	bin: &Path,
	args: &[String],
	cwd: &Path,
) -> Result<(), LpmError> {
	let status = Command::new(bin)
		.args(args)
		.current_dir(cwd)
		.stdin(Stdio::inherit())
		.stdout(Stdio::inherit())
		.stderr(Stdio::inherit())
		.status()
		.map_err(|e| {
			LpmError::Script(format!(
				"failed to run {}: {e}",
				bin.display()
			))
		})?;

	if !status.success() {
		let code = status.code().unwrap_or(1);
		std::process::exit(code);
	}

	Ok(())
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
		"no test runner found. Install vitest/jest/mocha or add a 'test' script to package.json".into(),
	))
}
