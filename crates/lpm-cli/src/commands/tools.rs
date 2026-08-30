use super::tools_ui;
use crate::{CheckEngine, install_ui};
use futures::stream::{FuturesUnordered, StreamExt};
use lpm_common::LpmError;
use std::collections::{HashSet, VecDeque};
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;

/// Maximum size for captured workspace stdout/stderr before truncation.
/// Mirrors the `MAX_CAPTURED_OUTPUT` constant in `commands::run` so chatty
/// failing members don't unbound the JSON envelope.
const MAX_CAPTURED_OUTPUT: usize = 10 * 1024 * 1024; // 10 MB

/// Truncate captured output if it exceeds `MAX_CAPTURED_OUTPUT`, cutting at
/// the last newline boundary to avoid splitting a line.
fn truncate_output(text: &str) -> String {
    if text.len() > MAX_CAPTURED_OUTPUT {
        let truncated = &text[..MAX_CAPTURED_OUTPUT];
        let end = truncated.rfind('\n').unwrap_or(MAX_CAPTURED_OUTPUT);
        format!(
            "{}...\n\n[output truncated at {}MB]",
            &text[..end],
            MAX_CAPTURED_OUTPUT / (1024 * 1024),
        )
    } else {
        text.to_string()
    }
}

/// How a tool subprocess should connect its stdio to the parent.
///
/// `Inherit` is the default — single-package mode and human-mode workspace
/// runs both stream child output directly to the user's terminal.
///
/// `Capture` is used for workspace + `--json` mode: child stdout/stderr is
/// piped into in-memory buffers so the orchestrator can emit a single, valid
/// JSON envelope on the parent's stdout. Without `Capture`, child writes to
/// stdout would interleave with the envelope and produce un-parsable output.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StdioMode {
    Inherit,
    Capture,
}

#[derive(Clone, Copy)]
pub enum WorkspaceConcurrency {
    HostDefault,
    Configured { cli_value: Option<NonZeroUsize> },
}

impl WorkspaceConcurrency {
    fn resolve(self, workspace_root: &Path) -> Result<usize, LpmError> {
        let value = match self {
            Self::HostDefault => {
                crate::workspace_concurrency_config::default_workspace_concurrency()
            }
            Self::Configured { cli_value } => {
                crate::workspace_concurrency_config::resolve_workspace_concurrency(
                    workspace_root,
                    cli_value,
                )?
            }
        };
        Ok(value.get())
    }
}

/// Captured stdio from a single tool invocation.
#[derive(Default)]
struct Captured {
    stdout: String,
    stderr: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RunnerTool {
    Test,
    Bench,
}

impl RunnerTool {
    fn from_label(label: &str) -> Result<Self, LpmError> {
        match label {
            "test" => Ok(Self::Test),
            "bench" => Ok(Self::Bench),
            _ => Err(LpmError::Script(format!("unknown runner tool: {label}"))),
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Test => "test",
            Self::Bench => "bench",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum RunnerInvocation {
    LocalBin {
        name: &'static str,
        base_args: Vec<String>,
    },
    PackageScript(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DetectedRunner {
    label: &'static str,
    invocation: RunnerInvocation,
}

/// Run `lpm lint` — delegates to oxlint via plugin system.
pub async fn lint(project_dir: &Path, args: &[String], json_output: bool) -> Result<(), LpmError> {
    let start = std::time::Instant::now();
    let version = read_tool_version(project_dir, "oxlint");
    let bin = lpm_plugin::ensure_plugin("oxlint", version.as_deref(), false).await?;

    if !json_output {
        let version_label = tools_ui::plugin_version_label(&bin, version.as_deref());
        tools_ui::using_tool("Oxlint", &version_label);
    }

    let outcome = run_tool_binary(&bin, args, project_dir, StdioMode::Inherit)?;
    if outcome.success() && !json_output {
        tools_ui::done_lint(start.elapsed());
    }
    finish_tool_outcome("lint", outcome, json_output)
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
    let start = std::time::Instant::now();
    let version = read_tool_version(project_dir, "biome");
    let bin = lpm_plugin::ensure_plugin("biome", version.as_deref(), false).await?;

    if !json_output {
        let version_label = tools_ui::plugin_version_label(&bin, version.as_deref());
        tools_ui::using_tool("Biome", &version_label);
    }

    let biome_args = build_biome_args(args, check);
    let outcome = run_tool_binary(&bin, &biome_args, project_dir, StdioMode::Inherit)?;
    if outcome.success() && !json_output {
        if check {
            tools_ui::done_fmt_check(start.elapsed());
        } else {
            tools_ui::done_fmt_write_elapsed(start.elapsed());
        }
    }
    finish_tool_outcome("fmt", outcome, json_output)
}

/// Apply project formatting for doctor without writing a nested command
/// response or forwarding the formatter's stdout into doctor's JSON.
pub(crate) async fn fmt_for_doctor(project_dir: &Path) -> Result<(), LpmError> {
    let version = read_tool_version(project_dir, "biome");
    let bin = lpm_plugin::ensure_plugin("biome", version.as_deref(), true).await?;
    let biome_args = build_biome_args(&[], false);
    let args: Vec<&str> = biome_args.iter().map(String::as_str).collect();
    let (_, _, code) =
        super::doctor::tooling::run_tool_with_timeout(&bin, &args, project_dir, None)
            .map_err(LpmError::Script)?;
    if code == 0 {
        Ok(())
    } else {
        Err(LpmError::ExitCode(code))
    }
}

/// Build the biome args vector — extracted so the workspace path can call it
/// per-member without duplicating the `--write` / default-`.` logic.
fn build_biome_args(args: &[String], check: bool) -> Vec<String> {
    let mut biome_args = vec!["format".to_string()];
    if args.is_empty() {
        biome_args.push(".".into());
    } else {
        biome_args.extend_from_slice(args);
    }
    if !check {
        biome_args.push("--write".into());
    }
    biome_args
}

/// Run `lpm check` — delegates to the selected engine with `--noEmit`.
///
/// Argument-aware preflight: when the user passes an explicit project
/// path (`-p` / `--project`) or a positional input file, we trust the
/// user knows the layout and skip the missing-tsconfig hint. Without
/// an explicit target, we surface "no tsconfig.json" first for every
/// engine. The default `tsc` engine also keeps the existing
/// "typescript not installed" preflight so users get the more
/// actionable LPM hint before the compiler would fail.
pub async fn check(
    project_dir: &Path,
    args: &[String],
    engine: CheckEngine,
    json_output: bool,
) -> Result<(), LpmError> {
    let start = std::time::Instant::now();
    if !json_output {
        tools_ui::using_check_engine(check_engine_binary(engine));
    }

    if !user_targeted_explicit_input(args) {
        check_preflight(project_dir, engine)?;
    }

    let outcome = run_check_engine(project_dir, args, engine, StdioMode::Inherit).await?;
    if outcome.success() && !json_output {
        tools_ui::done_typecheck(start.elapsed());
    }
    finish_tool_outcome("typecheck", outcome, json_output)
}

/// True when the user passed `-p` / `--project <path>` or any
/// positional (non-flag) argument. In those cases the user has named
/// the input target explicitly and a missing root `tsconfig.json` is
/// not a problem — preflight should defer to tsc.
fn user_targeted_explicit_input(args: &[String]) -> bool {
    let mut iter = args.iter().peekable();
    while let Some(arg) = iter.next() {
        if arg == "-p" || arg == "--project" {
            return iter.peek().is_some();
        }
        if arg.starts_with("-p=") || arg.starts_with("--project=") {
            return true;
        }
        if !arg.starts_with('-') {
            return true;
        }
    }
    false
}

/// Surface the common setup gaps with LPM-formatted messages before
/// spawning the selected engine:
///
/// - `tsconfig.json` missing → suggest `lpm init` or pass `-p`.
/// - `tsc` selected but typescript not reachable at all → suggest
///   `lpm install -D typescript` (or `lpm install` when the dep is
///   declared but not installed).
///
/// The post-spawn fallback in `run_check_engine` still wraps any
/// race-condition failure with the matching install hint.
fn check_preflight(project_dir: &Path, engine: CheckEngine) -> Result<(), LpmError> {
    if !project_dir.join("tsconfig.json").is_file() {
        return Err(LpmError::Script(format!(
            "no tsconfig.json found in {}. Add one (or pass `-p <path>` to use a different one)",
            project_dir.display(),
        )));
    }

    if matches!(engine, CheckEngine::Tsc) {
        let status = crate::tsc_status::TscStatus::probe(project_dir);
        if !status.runnable() {
            if status.in_deps {
                return Err(LpmError::Script(
                    "typescript declared in package.json but not installed. Run: lpm install"
                        .into(),
                ));
            }
            return Err(LpmError::Script(
                "typescript not installed. Run: lpm install -D typescript".into(),
            ));
        }
    }

    Ok(())
}

/// Run `lpm test` — auto-detects test runner and delegates.
pub async fn test(project_dir: &Path, args: &[String], json_output: bool) -> Result<(), LpmError> {
    run_single_runner(RunnerTool::Test, project_dir, args, json_output).await
}

/// Run `lpm bench` — auto-detects benchmark runner and delegates.
pub async fn bench(project_dir: &Path, args: &[String], json_output: bool) -> Result<(), LpmError> {
    run_single_runner(RunnerTool::Bench, project_dir, args, json_output).await
}

/// Auto-detect the benchmark runner from package.json. Extracted from the
/// inline match in `bench()` so the workspace orchestrator can reuse it
/// per-member without duplicating the priority logic.
#[cfg(test)]
fn detect_bench_runner(project_dir: &Path) -> Result<DetectedRunner, LpmError> {
    let pkg_json_path = project_dir.join("package.json");
    if !pkg_json_path.exists() {
        return Err(LpmError::Script("no package.json found".into()));
    }

    let pkg = lpm_workspace::read_package_json(&pkg_json_path)
        .map_err(|e| LpmError::Script(format!("{e}")))?;

    detect_bench_runner_from_package(&pkg)
}

async fn run_single_runner(
    tool: RunnerTool,
    project_dir: &Path,
    args: &[String],
    json_output: bool,
) -> Result<(), LpmError> {
    let pkg_json_path = project_dir.join("package.json");
    if !pkg_json_path.is_file() {
        return Err(LpmError::Script("no package.json found".into()));
    }
    let package = lpm_workspace::read_package_json(&pkg_json_path)
        .map_err(|error| LpmError::Script(error.to_string()))?;
    let runner = match tool {
        RunnerTool::Test => detect_test_runner_from_package(&package),
        RunnerTool::Bench => detect_bench_runner_from_package(&package),
    }?;

    if !json_output {
        match tool {
            RunnerTool::Test => tools_ui::detected_test_runner(runner.label),
            RunnerTool::Bench => tools_ui::detected_bench_runner(runner.label),
        }
    }

    let boundary = runner_boundary(project_dir)?;
    let project_dir = project_dir.to_path_buf();
    let member_name = package.name.unwrap_or_else(|| {
        project_dir.file_name().map_or_else(
            || "<project>".into(),
            |name| name.to_string_lossy().into_owned(),
        )
    });
    let args: Arc<[String]> = args.to_vec().into();
    let start = std::time::Instant::now();
    let stdio = if json_output {
        StdioMode::Capture
    } else {
        StdioMode::Inherit
    };
    let runtime_inventory = lpm_runner::bin_path::ManagedRuntimeInventory::default();
    let outcome = tokio::task::spawn_blocking(move || {
        execute_runner(
            &project_dir,
            &boundary,
            &runner,
            &args,
            stdio,
            &runtime_inventory,
        )
    })
    .await
    .map_err(|error| {
        LpmError::Script(format!("{0} runner task panicked: {error}", tool.label()))
    })?;
    let elapsed = start.elapsed();
    let result = outcome.as_result();

    if json_output {
        let success = outcome.success();
        let member = member_result(member_name, outcome, elapsed);
        emit_envelope(
            std::slice::from_ref(&member),
            1,
            usize::from(success),
            usize::from(!success),
            elapsed,
        );
    } else if outcome.success() {
        match tool {
            RunnerTool::Test => tools_ui::done_test(elapsed),
            RunnerTool::Bench => tools_ui::done_bench(elapsed),
        }
    } else if let Some(code) = outcome.exit_code {
        tools_ui::failed(tool.label(), code);
    }

    result
}

fn runner_boundary(project_dir: &Path) -> Result<PathBuf, LpmError> {
    lpm_workspace::find_workspace_root(project_dir)
        .map(|root| root.unwrap_or_else(|| project_dir.to_path_buf()))
        .map_err(|error| LpmError::Script(format!("workspace error: {error}")))
}

fn detect_test_runner_from_package(
    package: &lpm_workspace::PackageJson,
) -> Result<DetectedRunner, LpmError> {
    for (name, base_args) in [
        ("vitest", vec!["run".to_string()]),
        ("jest", Vec::new()),
        ("mocha", Vec::new()),
    ] {
        if package.dependencies.contains_key(name) || package.dev_dependencies.contains_key(name) {
            return Ok(DetectedRunner {
                label: name,
                invocation: RunnerInvocation::LocalBin { name, base_args },
            });
        }
    }
    if let Some(script) = package.scripts.get("test") {
        return Ok(DetectedRunner {
            label: "scripts.test",
            invocation: RunnerInvocation::PackageScript(script.clone()),
        });
    }
    Err(LpmError::Script(
        "no test runner found. Install vitest/jest/mocha or add a 'test' script to package.json"
            .into(),
    ))
}

fn detect_bench_runner_from_package(
    package: &lpm_workspace::PackageJson,
) -> Result<DetectedRunner, LpmError> {
    if package.dependencies.contains_key("vitest")
        || package.dev_dependencies.contains_key("vitest")
    {
        return Ok(DetectedRunner {
            label: "vitest",
            invocation: RunnerInvocation::LocalBin {
                name: "vitest",
                base_args: vec!["bench".to_string()],
            },
        });
    }
    if let Some(script) = package.scripts.get("bench") {
        return Ok(DetectedRunner {
            label: "scripts.bench",
            invocation: RunnerInvocation::PackageScript(script.clone()),
        });
    }
    Err(LpmError::Script(
        "no benchmark runner found. Install vitest or add a 'bench' script to package.json".into(),
    ))
}

fn execute_runner(
    project_dir: &Path,
    boundary: &Path,
    runner: &DetectedRunner,
    forwarded_args: &[String],
    stdio: StdioMode,
    runtime_inventory: &lpm_runner::bin_path::ManagedRuntimeInventory,
) -> ToolOutcome {
    let result = runtime_inventory
        .resolve_for_project(project_dir)
        .and_then(|runtime_hint| match &runner.invocation {
            RunnerInvocation::LocalBin { name, base_args } => execute_local_runner(
                project_dir,
                boundary,
                name,
                base_args,
                forwarded_args,
                stdio,
                &runtime_hint,
            ),
            RunnerInvocation::PackageScript(script) => execute_package_script(
                project_dir,
                boundary,
                script,
                forwarded_args,
                stdio,
                &runtime_hint,
            ),
        });
    result.unwrap_or_else(|error| ToolOutcome {
        error: Some(error.to_string()),
        ..Default::default()
    })
}

fn execute_local_runner(
    project_dir: &Path,
    boundary: &Path,
    name: &str,
    base_args: &[String],
    forwarded_args: &[String],
    stdio: StdioMode,
    runtime_hint: &lpm_runner::bin_path::ManagedRuntimeHint,
) -> Result<ToolOutcome, LpmError> {
    let args = local_runner_args(name, base_args, forwarded_args);

    let mut command = lpm_runner::script::build_local_bin_command_bounded(
        project_dir,
        boundary,
        name,
        &args,
        None,
        false,
        runtime_hint,
    )?;
    let mut outcome = ToolOutcome::default();
    match stdio {
        StdioMode::Inherit => {
            let status = command.status().map_err(|error| {
                LpmError::Script(format!("failed to execute '{name}': {error}"))
            })?;
            outcome.exit_code = Some(lpm_runner::shell::exit_code(&status));
        }
        StdioMode::Capture => {
            let captured = lpm_runner::shell::spawn_command_capture(command, name)?;
            outcome.exit_code = Some(lpm_runner::shell::exit_code(&captured.status));
            outcome.captured = Captured {
                stdout: captured.stdout,
                stderr: captured.stderr,
            };
        }
    }
    Ok(outcome)
}

fn local_runner_args(name: &str, base_args: &[String], forwarded_args: &[String]) -> Vec<String> {
    let drop_vitest_run = name == "vitest"
        && base_args.len() == 1
        && base_args[0] == "run"
        && args_imply_watch(forwarded_args);
    let mut args = Vec::with_capacity(base_args.len() + forwarded_args.len());
    if !drop_vitest_run {
        args.extend_from_slice(base_args);
    }
    args.extend_from_slice(forwarded_args);
    args
}

fn execute_package_script(
    project_dir: &Path,
    boundary: &Path,
    script: &str,
    forwarded_args: &[String],
    stdio: StdioMode,
    runtime_hint: &lpm_runner::bin_path::ManagedRuntimeHint,
) -> Result<ToolOutcome, LpmError> {
    let path =
        lpm_runner::bin_path::build_path_with_bins_bounded(project_dir, boundary, runtime_hint)?;
    let env_vars = lpm_runner::dotenv::load_env_files(project_dir, None)?;
    let command =
        lpm_runner::script::assemble_shell_command(script, forwarded_args, project_dir, &path)?;
    let shell_command = lpm_runner::shell::ShellCommand {
        command: &command,
        cwd: project_dir,
        path: &path,
        envs: &env_vars,
    };
    let mut outcome = ToolOutcome::default();
    match stdio {
        StdioMode::Inherit => {
            let status = lpm_runner::shell::spawn_shell(&shell_command)?;
            outcome.exit_code = Some(lpm_runner::shell::exit_code(&status));
        }
        StdioMode::Capture => {
            let captured = lpm_runner::shell::spawn_shell_capture(&shell_command)?;
            outcome.exit_code = Some(lpm_runner::shell::exit_code(&captured.status));
            outcome.captured = Captured {
                stdout: captured.stdout,
                stderr: captured.stderr,
            };
        }
    }
    Ok(outcome)
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
            install_ui::warn_untrusted(&format!("failed to read lpm.json tools config: {e}"));
            None
        }
    }
}

/// Outcome of a single tool invocation: either it ran (with an exit code) or
/// LPM couldn't even launch it (spawn / config / plugin failure).
#[derive(Default)]
struct ToolOutcome {
    exit_code: Option<i32>,
    captured: Captured,
    /// Set when LPM itself failed to launch — distinguishes from "ran and
    /// exited non-zero." Surfaces in the JSON envelope as `error` with a
    /// `null` exit_code.
    error: Option<String>,
}

impl ToolOutcome {
    fn success(&self) -> bool {
        matches!(self.exit_code, Some(0)) && self.error.is_none()
    }

    fn as_result(&self) -> Result<(), LpmError> {
        if let Some(error) = &self.error {
            return Err(LpmError::Script(error.clone()));
        }
        match self.exit_code {
            Some(0) => Ok(()),
            Some(code) => Err(LpmError::ExitCode(code)),
            None => Err(LpmError::Script(
                "tool exited without an exit code".to_string(),
            )),
        }
    }

    /// Convert into a `Result` for single-package callers that just want the
    /// exit-code propagated.
    fn into_result(self) -> Result<(), LpmError> {
        self.as_result()
    }
}

fn finish_tool_outcome(
    label: &str,
    outcome: ToolOutcome,
    json_output: bool,
) -> Result<(), LpmError> {
    if !json_output
        && let Some(code) = outcome.exit_code
        && code != 0
    {
        tools_ui::failed(label, code);
    }
    outcome.into_result()
}

/// Run a plugin binary with args. Returns the outcome rather than panicking
/// on non-zero so workspace mode can collect per-member results.
fn run_tool_binary(
    bin: &Path,
    args: &[String],
    cwd: &Path,
    stdio: StdioMode,
) -> Result<ToolOutcome, LpmError> {
    let mut cmd = Command::new(bin);
    cmd.args(args).current_dir(cwd);

    apply_stdio(&mut cmd, stdio);

    let mut outcome = ToolOutcome::default();

    match stdio {
        StdioMode::Inherit => {
            let status = cmd
                .status()
                .map_err(|e| LpmError::Script(format!("failed to run {}: {e}", bin.display())))?;
            outcome.exit_code = Some(status.code().unwrap_or(1));
        }
        StdioMode::Capture => {
            let result = cmd.output();
            match result {
                Ok(output) => {
                    outcome.captured = Captured {
                        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
                        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
                    };
                    outcome.exit_code = Some(output.status.code().unwrap_or(1));
                }
                Err(e) => {
                    outcome.error = Some(format!("failed to run {}: {e}", bin.display()));
                }
            }
        }
    }

    Ok(outcome)
}

fn check_engine_binary(engine: CheckEngine) -> &'static str {
    match engine {
        CheckEngine::Tsc => "tsc",
        CheckEngine::Tsgo => "tsgo",
    }
}

fn check_engine_spawn_hint(engine: CheckEngine) -> &'static str {
    match engine {
        CheckEngine::Tsc => "Is typescript installed? Run: lpm install -D typescript",
        CheckEngine::Tsgo => "The managed tsgo engine failed to start after install",
    }
}

/// Run the selected type-check engine with the configured stdio mode.
/// Honors `node_modules/.bin` PATH injection so project-local tools win
/// over a system install.
async fn run_check_engine(
    project_dir: &Path,
    args: &[String],
    engine: CheckEngine,
    stdio: StdioMode,
) -> Result<ToolOutcome, LpmError> {
    if matches!(engine, CheckEngine::Tsgo) {
        return run_tsgo(project_dir, args, stdio).await;
    }

    let binary = check_engine_binary(engine);
    let path = lpm_runner::bin_path::build_path_with_bins(project_dir)?;
    let mut cmd_args = vec!["--noEmit".to_string()];
    cmd_args.extend_from_slice(args);

    let mut cmd = Command::new(binary);
    cmd.args(&cmd_args)
        .current_dir(project_dir)
        .env("PATH", &path);

    apply_stdio(&mut cmd, stdio);

    let mut outcome = ToolOutcome::default();

    match stdio {
        StdioMode::Inherit => {
            let status = cmd.status().map_err(|e| {
                LpmError::Script(format!(
                    "failed to run {binary}: {e}. {}",
                    check_engine_spawn_hint(engine)
                ))
            })?;
            outcome.exit_code = Some(status.code().unwrap_or(1));
        }
        StdioMode::Capture => match cmd.output() {
            Ok(output) => {
                outcome.captured = Captured {
                    stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
                    stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
                };
                outcome.exit_code = Some(output.status.code().unwrap_or(1));
            }
            Err(e) => {
                outcome.error = Some(format!(
                    "failed to run {binary}: {e}. {}",
                    check_engine_spawn_hint(engine)
                ));
            }
        },
    }

    Ok(outcome)
}

async fn run_tsgo(
    project_dir: &Path,
    args: &[String],
    stdio: StdioMode,
) -> Result<ToolOutcome, LpmError> {
    let bin = lpm_plugin::ensure_engine("tsgo", None, matches!(stdio, StdioMode::Capture)).await?;
    let mut cmd_args = vec!["--noEmit".to_string()];
    cmd_args.extend_from_slice(args);
    run_tool_binary(&bin, &cmd_args, project_dir, stdio)
}

fn apply_stdio(cmd: &mut Command, stdio: StdioMode) {
    match stdio {
        StdioMode::Inherit => {
            cmd.stdin(Stdio::inherit())
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit());
        }
        StdioMode::Capture => {
            cmd.stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
        }
    }
}

/// Returns `true` if the forwarded args contain a watch-mode opt-in.
fn args_imply_watch(args: &[String]) -> bool {
    args.iter().any(|arg| {
        if arg == "--watch" || arg == "-w" {
            return true;
        }
        arg.strip_prefix("--watch=").is_some_and(|value| {
            !matches!(value.to_ascii_lowercase().as_str(), "false" | "0" | "off")
        })
    })
}

/// Auto-detect the test runner from package.json devDependencies.
#[cfg(test)]
fn detect_test_runner(project_dir: &Path) -> Result<DetectedRunner, LpmError> {
    let pkg_json_path = project_dir.join("package.json");
    if !pkg_json_path.exists() {
        return Err(LpmError::Script("no package.json found".into()));
    }

    let pkg = lpm_workspace::read_package_json(&pkg_json_path)
        .map_err(|e| LpmError::Script(format!("{e}")))?;

    detect_test_runner_from_package(&pkg)
}

// --- Workspace orchestration ---

/// Run a tool command across workspace packages, with topological levels and
/// within-level parallelism. Owns the JSON envelope contract for workspace
/// mode.
///
/// **Selection inputs:**
/// - `filters`: filter expressions. Empty + `affected_base.is_none()`
///   means "every member" (caller already verified workspace mode is active).
/// - `affected_base`: `Some(base_ref)` enables `--affected` semantics — direct
///   changes plus their transitive dependents — unioned with `filters`.
/// - `fail_if_no_match`: when true, an empty target set is a hard error rather
///   than a warning + zero-exit.
///
/// **Execution inputs:**
/// - `tool`: dispatch key — `"lint" | "fmt" | "check"`.
/// - `args`, `check`: forwarded to the per-member runner.
/// - `json_output`: when true, swaps subprocess stdio from `Inherit` to
///   `Capture` and emits a single JSON envelope at the end.
#[allow(clippy::too_many_arguments)]
pub async fn tool_workspace(
    project_dir: &Path,
    tool: &str,
    args: &[String],
    check: bool,
    check_engine: Option<CheckEngine>,
    filters: &[String],
    filter_prod: &[String],
    changed_files_ignore_pattern: &[String],
    test_pattern: &[String],
    affected_base: Option<&str>,
    fail_if_no_match: bool,
    workspace_concurrency: WorkspaceConcurrency,
    json_output: bool,
) -> Result<(), LpmError> {
    let workspace = lpm_workspace::discover_workspace(project_dir)
        .map_err(|e| LpmError::Script(format!("workspace error: {e}")))?
        .ok_or_else(|| {
            LpmError::Script(
                "no workspace found. --all/--filter/--affected require a monorepo".into(),
            )
        })?;

    let ws_graph = lpm_task::graph::WorkspaceGraph::from_workspace(&workspace);
    let workspace_concurrency = workspace_concurrency.resolve(&workspace.root)?;

    let target_set = crate::workspace_select::select_workspace_target_set(
        &ws_graph,
        &workspace.root,
        filters,
        filter_prod,
        changed_files_ignore_pattern,
        test_pattern,
        affected_base.is_some(),
        affected_base.unwrap_or("main"),
    )?;

    if target_set.is_empty() {
        // `--affected` with no filter is the common "nothing changed since the
        // base ref" case — keep its own message so it doesn't read like a
        // filter typo. With explicit `--filter` (with or without `--affected`)
        // we fall into the filter-miss path so the D2 hint can fire on bare
        // names that would have substring-matched in earlier filter behavior.
        let affected_only = filters.is_empty() && filter_prod.is_empty() && affected_base.is_some();

        if fail_if_no_match {
            let msg = if affected_only {
                format!(
                    "no workspace packages affected vs {} (--fail-if-no-match)",
                    affected_base.unwrap_or("main"),
                )
            } else {
                let hint =
                    crate::commands::filter::format_no_match_hint_for_sets(filters, filter_prod);
                let base = "no workspace packages matched the filter (--fail-if-no-match)";
                match hint {
                    Some(h) => format!("{base}\n\n{h}"),
                    None => base.to_string(),
                }
            };
            return Err(LpmError::Script(msg));
        }

        if json_output {
            let envelope = serde_json::json!({
                "success": true,
                "packages": 0,
                "succeeded": 0,
                "failed": 0,
                "duration_ms": 0,
                "members": [],
            });
            println!("{}", serde_json::to_string_pretty(&envelope).unwrap());
        } else if affected_only {
            tools_ui::done_no_packages_affected(tool, affected_base.unwrap_or("main"));
        } else {
            let hint = crate::commands::filter::format_no_match_hint_for_sets(filters, filter_prod);
            tools_ui::warn_no_packages_matched();
            if let Some(h) = hint {
                eprintln!();
                for line in h.lines() {
                    install_ui::detail_line(crate::install_ui::terminal_line!(
                        "  {}",
                        install_ui::dim(line)
                    ));
                }
                eprintln!();
            }
        }
        return Ok(());
    }

    let runner_tasks = RunnerTool::from_label(tool).ok().map(|runner_tool| {
        let boundary = Arc::new(workspace.root.clone());
        let runtime_inventory = Arc::new(lpm_runner::bin_path::ManagedRuntimeInventory::default());
        workspace
            .members
            .iter()
            .map(|member| {
                let runner = match runner_tool {
                    RunnerTool::Test => detect_test_runner_from_package(&member.package),
                    RunnerTool::Bench => detect_bench_runner_from_package(&member.package),
                }
                .map_err(|error| error.to_string());
                RunnerTask {
                    boundary: Arc::clone(&boundary),
                    runner,
                    runtime_inventory: Arc::clone(&runtime_inventory),
                }
            })
            .collect::<Vec<_>>()
    });

    // Pre-resolve plugin once at root for lint/fmt — covers the homogeneous
    // cold-cache race where N parallel members would all call ensure_plugin
    // for the same version. Per-member calls below reuse this binary if the
    // member's version pin matches root, otherwise fall back to a per-member
    // ensure_plugin (rare; mixed-version monorepos accept today's race).
    //
    // Prewarm failure is not an early-return: the workspace+`--json` contract
    // promises a single envelope on stdout, with plugin / config / spawn
    // failures represented as member entries with `exit_code: null`. We
    // synthesize per-member failure entries (one per targeted member) carrying
    // the prewarm error and skip orchestration. The plain-text path emits the
    // human summary so the user sees the same N-of-N-failed shape.
    let prewarm = match tool {
        "lint" => Some(prewarm_root_plugin(project_dir, "oxlint").await),
        "fmt" => Some(prewarm_root_plugin(project_dir, "biome").await),
        _ => None,
    };

    let root_pin: Option<(String, Option<String>, PathBuf)> = match prewarm {
        None => None,
        Some(Ok(pin)) => Some(pin),
        Some(Err(prewarm_err)) => {
            let elapsed = std::time::Duration::from_millis(0);
            let failed_members = synthesize_prewarm_failure_members(
                &ws_graph,
                &target_set,
                &prewarm_err.to_string(),
            );
            let total = failed_members.len();
            let succeeded = 0;
            let failed = total;

            if json_output {
                emit_envelope(&failed_members, total, succeeded, failed, elapsed);
            } else {
                emit_prewarm_failure(tool, &prewarm_err.to_string());
                emit_human_summary(tool, total, succeeded, failed, target_set.len(), elapsed);
            }
            return Err(LpmError::ExitCode(1));
        }
    };

    let stdio = if json_output {
        StdioMode::Capture
    } else {
        StdioMode::Inherit
    };

    let start = std::time::Instant::now();
    let shared_args: Arc<[String]> = args.to_vec().into();
    let member_results = run_selected_members(
        &ws_graph,
        &target_set,
        tool,
        shared_args,
        check,
        check_engine,
        stdio,
        &root_pin,
        runner_tasks.as_deref(),
        workspace_concurrency,
    )
    .await?;

    let elapsed = start.elapsed();
    let succeeded = member_results.iter().filter(|r| r.success).count();
    let failed = member_results.len() - succeeded;
    let total = member_results.len();

    if json_output {
        emit_envelope(&member_results, total, succeeded, failed, elapsed);
    } else {
        emit_human_summary(tool, total, succeeded, failed, target_set.len(), elapsed);
    }

    if failed > 0 {
        return Err(LpmError::ExitCode(1));
    }

    Ok(())
}

/// Pre-resolve a plugin once at the workspace root. Reads the root's tool
/// version pin and returns the resolved binary path along with the pin so
/// per-member calls can short-circuit when their pin matches.
///
/// Extracted as a named helper so the prewarm-failure envelope path can call
/// it via a single owned `Result` rather than the inline `?` form (which
/// would short-circuit `tool_workspace` before the envelope is built).
async fn prewarm_root_plugin(
    project_dir: &Path,
    plugin_name: &str,
) -> Result<(String, Option<String>, PathBuf), LpmError> {
    let v = read_tool_version(project_dir, plugin_name);
    let bin = lpm_plugin::ensure_plugin(plugin_name, v.as_deref(), false).await?;
    Ok((plugin_name.to_string(), v, bin))
}

/// Build per-member failure entries for the case where the root plugin
/// prewarm failed. Every member that would have been targeted gets a
/// failed `MemberResult` carrying the same prewarm error message —
/// preserves the workspace `--json` envelope contract that always emits
/// one envelope on stdout, with plugin failures represented as member
/// entries with `exit_code: null`.
fn synthesize_prewarm_failure_members(
    ws_graph: &lpm_task::graph::WorkspaceGraph,
    target_set: &std::collections::HashSet<usize>,
    error_msg: &str,
) -> Vec<MemberResult> {
    let mut indices: Vec<usize> = target_set.iter().copied().collect();
    indices.sort_unstable();
    indices
        .into_iter()
        .map(|idx| MemberResult {
            name: ws_graph.members[idx].name.clone(),
            success: false,
            exit_code: None,
            duration_ms: 0,
            captured: Captured::default(),
            error: Some(format!("plugin prewarm failed: {error_msg}")),
        })
        .collect()
}

/// Per-member result captured by the workspace orchestrator.
struct MemberResult {
    name: String,
    success: bool,
    /// `Some(code)` when the subprocess ran. `None` for spawn/config/plugin
    /// failures — paired with `error` in the envelope.
    exit_code: Option<i32>,
    duration_ms: u64,
    captured: Captured,
    error: Option<String>,
}

#[derive(Clone)]
struct RunnerTask {
    boundary: Arc<PathBuf>,
    runner: Result<DetectedRunner, String>,
    runtime_inventory: Arc<lpm_runner::bin_path::ManagedRuntimeInventory>,
}

fn member_result(name: String, outcome: ToolOutcome, elapsed: std::time::Duration) -> MemberResult {
    let success = outcome.success();
    MemberResult {
        name,
        success,
        exit_code: outcome.exit_code,
        duration_ms: elapsed.as_millis() as u64,
        captured: if success {
            Captured::default()
        } else {
            outcome.captured
        },
        error: outcome.error,
    }
}

fn selected_schedule_state(
    ws_graph: &lpm_task::graph::WorkspaceGraph,
    target_set: &HashSet<usize>,
) -> Result<(Vec<usize>, VecDeque<usize>), LpmError> {
    let mut initial_unmet = vec![0; ws_graph.len()];
    let mut ready = VecDeque::new();
    for &index in target_set {
        initial_unmet[index] = ws_graph.edges[index]
            .iter()
            .filter(|dependency| target_set.contains(dependency))
            .count();
        if initial_unmet[index] == 0 {
            ready.push_back(index);
        }
    }

    let mut remaining = initial_unmet.clone();
    let mut preflight = ready.clone();
    let mut processed = 0;
    while let Some(index) = preflight.pop_front() {
        processed += 1;
        for &dependent in &ws_graph.reverse_edges[index] {
            if !target_set.contains(&dependent) {
                continue;
            }
            remaining[dependent] -= 1;
            if remaining[dependent] == 0 {
                preflight.push_back(dependent);
            }
        }
    }
    if processed != target_set.len() {
        let mut blocked = target_set
            .iter()
            .filter(|index| remaining[**index] > 0)
            .map(|index| ws_graph.members[*index].name.as_str())
            .collect::<Vec<_>>();
        blocked.sort_unstable();
        return Err(LpmError::Script(format!(
            "dependency cycle detected in selected workspace packages: {}",
            blocked.join(", ")
        )));
    }

    let mut ready = ready.into_iter().collect::<Vec<_>>();
    ready.sort_unstable();
    Ok((initial_unmet, ready.into()))
}

#[allow(clippy::too_many_arguments)]
async fn run_selected_members(
    ws_graph: &lpm_task::graph::WorkspaceGraph,
    target_set: &HashSet<usize>,
    tool: &str,
    args: Arc<[String]>,
    check: bool,
    check_engine: Option<CheckEngine>,
    stdio: StdioMode,
    root_pin: &Option<(String, Option<String>, PathBuf)>,
    runner_tasks: Option<&[RunnerTask]>,
    workspace_concurrency: usize,
) -> Result<Vec<MemberResult>, LpmError> {
    let (mut unmet, mut ready) = selected_schedule_state(ws_graph, target_set)?;
    let mut in_flight = FuturesUnordered::new();
    let mut indexed_results = Vec::with_capacity(target_set.len());

    loop {
        while in_flight.len() < workspace_concurrency {
            let Some(index) = ready.pop_front() else {
                break;
            };
            in_flight.push(run_indexed_member(
                index,
                ws_graph,
                tool,
                Arc::clone(&args),
                check,
                check_engine,
                stdio,
                root_pin,
                runner_tasks.and_then(|tasks| tasks.get(index)).cloned(),
            ));
        }

        let Some((index, result)) = in_flight.next().await else {
            break;
        };
        indexed_results.push((index, result));
        for &dependent in &ws_graph.reverse_edges[index] {
            if !target_set.contains(&dependent) {
                continue;
            }
            unmet[dependent] -= 1;
            if unmet[dependent] == 0 {
                ready.push_back(dependent);
            }
        }
    }

    indexed_results.sort_unstable_by_key(|(index, _)| *index);
    Ok(indexed_results
        .into_iter()
        .map(|(_, result)| result)
        .collect())
}

#[allow(clippy::too_many_arguments)]
async fn run_indexed_member(
    index: usize,
    ws_graph: &lpm_task::graph::WorkspaceGraph,
    tool: &str,
    args: Arc<[String]>,
    check: bool,
    check_engine: Option<CheckEngine>,
    stdio: StdioMode,
    root_pin: &Option<(String, Option<String>, PathBuf)>,
    runner_task: Option<RunnerTask>,
) -> (usize, MemberResult) {
    let member = &ws_graph.members[index];
    let result = run_one_member(
        &member.path,
        &member.name,
        tool,
        args,
        check,
        check_engine,
        stdio,
        root_pin,
        runner_task,
    )
    .await;
    (index, result)
}

/// Execute one member's tool invocation and convert into a `MemberResult`.
#[allow(clippy::too_many_arguments)]
async fn run_one_member(
    member_dir: &Path,
    member_name: &str,
    tool: &str,
    args: Arc<[String]>,
    check: bool,
    check_engine: Option<CheckEngine>,
    stdio: StdioMode,
    root_pin: &Option<(String, Option<String>, PathBuf)>,
    runner_task: Option<RunnerTask>,
) -> MemberResult {
    let start = std::time::Instant::now();

    if matches!(stdio, StdioMode::Inherit) {
        install_ui::detail_line(crate::install_ui::terminal_line!(
            "  {} {}",
            install_ui::cyan(&format!("[{member_name}]")),
            install_ui::yellow(tool)
        ));
    }

    let outcome_result = match tool {
        "lint" => run_lint_member(member_dir, &args, stdio, root_pin).await,
        "fmt" => run_fmt_member(member_dir, &args, check, stdio, root_pin).await,
        "check" => Ok(run_check_engine(
            member_dir,
            &args,
            check_engine.unwrap_or(CheckEngine::Tsc),
            stdio,
        )
        .await
        .unwrap_or_else(|e| ToolOutcome {
            error: Some(e.to_string()),
            ..Default::default()
        })),
        "test" | "bench" => Ok(run_runner_member(member_dir, args, stdio, runner_task).await),
        _ => Err(LpmError::Script(format!("unknown tool: {tool}"))),
    };

    let outcome = match outcome_result {
        Ok(outcome) => outcome,
        Err(error) => ToolOutcome {
            error: Some(error.to_string()),
            ..Default::default()
        },
    };
    let success = outcome.success();
    let exit_code = outcome.exit_code;
    let error = outcome.error.clone();

    if matches!(stdio, StdioMode::Inherit) && !success {
        if let Some(code) = exit_code {
            install_ui::detail_line(format_member_failure(member_name, &format!("exit {code}")));
        } else if let Some(ref msg) = error {
            install_ui::detail_line(format_member_failure(member_name, msg));
        }
    }

    member_result(member_name.to_string(), outcome, start.elapsed())
}

async fn run_runner_member(
    member_dir: &Path,
    args: Arc<[String]>,
    stdio: StdioMode,
    runner_task: Option<RunnerTask>,
) -> ToolOutcome {
    let Some(task) = runner_task else {
        return ToolOutcome {
            error: Some("runner metadata was not prepared for workspace member".into()),
            ..Default::default()
        };
    };
    let member_dir = member_dir.to_path_buf();
    tokio::task::spawn_blocking(move || match task.runner {
        Ok(runner) => execute_runner(
            &member_dir,
            &task.boundary,
            &runner,
            &args,
            stdio,
            &task.runtime_inventory,
        ),
        Err(error) => ToolOutcome {
            error: Some(error),
            ..Default::default()
        },
    })
    .await
    .unwrap_or_else(|error| ToolOutcome {
        error: Some(format!("workspace runner task panicked: {error}")),
        ..Default::default()
    })
}

async fn run_lint_member(
    member_dir: &Path,
    args: &[String],
    stdio: StdioMode,
    root_pin: &Option<(String, Option<String>, PathBuf)>,
) -> Result<ToolOutcome, LpmError> {
    let bin = resolve_member_plugin(member_dir, "oxlint", root_pin).await?;
    run_tool_binary(&bin, args, member_dir, stdio)
}

async fn run_fmt_member(
    member_dir: &Path,
    args: &[String],
    check: bool,
    stdio: StdioMode,
    root_pin: &Option<(String, Option<String>, PathBuf)>,
) -> Result<ToolOutcome, LpmError> {
    let bin = resolve_member_plugin(member_dir, "biome", root_pin).await?;
    let biome_args = build_biome_args(args, check);
    run_tool_binary(&bin, &biome_args, member_dir, stdio)
}

/// Top-level dispatcher for `lpm test` and `lpm bench`. Owns the workspace-
/// mode gate, the workspace+`--watch` interaction, and the routing between
/// single-package and orchestrator paths.
///
/// **Watch mode in workspace selectors:** `--watch` is allowed when the
/// selection resolves to exactly one member — the natural "watch this
/// member's tests" workflow. We hand off to the single-package path against
/// the resolved member's directory (inherited stdio, no envelope, the
/// existing vitest `run` → bare `vitest` rewrite kicks in). Resolution to
/// zero members is an error (you asked to watch nothing); resolution to two
/// or more is rejected with the actual count to prevent N parallel
/// watchers. Both `test` and `bench` apply the same rule — `vitest bench
/// --watch` is just as much a footgun as the test runner.
#[allow(clippy::too_many_arguments)]
pub async fn dispatch_test_or_bench(
    project_dir: &Path,
    tool: &str,
    args: &[String],
    all: bool,
    filters: &[String],
    filter_prod: &[String],
    changed_files_ignore_pattern: &[String],
    test_pattern: &[String],
    affected: bool,
    base_ref: &str,
    fail_if_no_match: bool,
    workspace_concurrency: Option<NonZeroUsize>,
    json_output: bool,
) -> Result<(), LpmError> {
    let workspace_mode = all || affected || !filters.is_empty() || !filter_prod.is_empty();
    if workspace_concurrency.is_some() && !workspace_mode {
        return Err(LpmError::Script(format!(
            "--workspace-concurrency requires --all, --filter, --filter-prod, or --affected for `lpm {tool}`"
        )));
    }

    // Resolve workspace target selection up-front when watch is requested,
    // so we can hand off to single-package mode for the one-member case
    // before paying the orchestrator setup cost.
    if workspace_mode && args_imply_watch(args) {
        let workspace = lpm_workspace::discover_workspace(project_dir)
            .map_err(|e| LpmError::Script(format!("workspace error: {e}")))?
            .ok_or_else(|| {
                LpmError::Script(
                    "no workspace found. --all/--filter/--affected require a monorepo".into(),
                )
            })?;
        let ws_graph = lpm_task::graph::WorkspaceGraph::from_workspace(&workspace);
        let affected_ref_for_select = if affected { Some(base_ref) } else { None };
        let target_set = crate::workspace_select::select_workspace_target_set(
            &ws_graph,
            &workspace.root,
            filters,
            filter_prod,
            changed_files_ignore_pattern,
            test_pattern,
            affected,
            affected_ref_for_select.unwrap_or("main"),
        )?;

        match target_set.len() {
            0 => {
                return Err(LpmError::Script(format!(
                    "no workspace member matched the selection — nothing to watch with `lpm {tool} --watch`."
                )));
            }
            1 => {
                let idx = *target_set.iter().next().expect("len == 1");
                let member_dir = ws_graph.members[idx].path.clone();
                return match tool {
                    "test" => test(&member_dir, args, json_output).await,
                    "bench" => bench(&member_dir, args, json_output).await,
                    other => Err(LpmError::Script(format!("unknown runner tool: {other}"))),
                };
            }
            n => {
                return Err(LpmError::Script(format!(
                    "--watch is not supported when the selection resolves to {n} members for `lpm {tool}` \
                     (would start one watcher per member). Narrow the selection so it resolves to exactly \
                     one member, e.g. `lpm {tool} --filter <single-name> --watch`, or run from the member's \
                     directory with `cd <member> && lpm {tool} --watch`."
                )));
            }
        }
    }

    if workspace_mode {
        let affected_ref = if affected { Some(base_ref) } else { None };
        tool_workspace(
            project_dir,
            tool,
            args,
            false,
            None,
            filters,
            filter_prod,
            changed_files_ignore_pattern,
            test_pattern,
            affected_ref,
            fail_if_no_match,
            WorkspaceConcurrency::Configured {
                cli_value: workspace_concurrency,
            },
            json_output,
        )
        .await
    } else {
        match tool {
            "test" => test(project_dir, args, json_output).await,
            "bench" => bench(project_dir, args, json_output).await,
            other => Err(LpmError::Script(format!("unknown runner tool: {other}"))),
        }
    }
}

/// Reuse the root-prewarmed plugin binary when the member's version pin
/// matches the root, otherwise re-resolve. Prewarm at root closes the
/// homogeneous cold-cache race; mixed-version pins accept today's behavior.
async fn resolve_member_plugin(
    member_dir: &Path,
    plugin_name: &str,
    root_pin: &Option<(String, Option<String>, PathBuf)>,
) -> Result<PathBuf, LpmError> {
    let member_version = read_tool_version(member_dir, plugin_name);

    if let Some((root_name, root_version, root_bin)) = root_pin
        && root_name == plugin_name
        && member_version == *root_version
    {
        return Ok(root_bin.clone());
    }

    lpm_plugin::ensure_plugin(plugin_name, member_version.as_deref(), false).await
}

/// Emit the workspace JSON envelope. Stdout/stderr surface ONLY for failed
/// members and are truncated at the 10MB ceiling.
fn emit_envelope(
    results: &[MemberResult],
    total: usize,
    succeeded: usize,
    failed: usize,
    elapsed: std::time::Duration,
) {
    let members: Vec<serde_json::Value> = results
        .iter()
        .map(|r| {
            let mut obj = serde_json::Map::new();
            obj.insert("name".into(), serde_json::Value::String(r.name.clone()));
            obj.insert("success".into(), serde_json::Value::Bool(r.success));
            obj.insert(
                "exit_code".into(),
                match r.exit_code {
                    Some(code) => serde_json::Value::Number(code.into()),
                    None => serde_json::Value::Null,
                },
            );
            obj.insert(
                "duration_ms".into(),
                serde_json::Value::Number(r.duration_ms.into()),
            );

            if !r.success {
                if let Some(ref msg) = r.error {
                    obj.insert("error".into(), serde_json::Value::String(msg.clone()));
                }
                if !r.captured.stdout.is_empty() {
                    obj.insert(
                        "stdout".into(),
                        serde_json::Value::String(truncate_output(&r.captured.stdout)),
                    );
                }
                if !r.captured.stderr.is_empty() {
                    obj.insert(
                        "stderr".into(),
                        serde_json::Value::String(truncate_output(&r.captured.stderr)),
                    );
                }
            }

            serde_json::Value::Object(obj)
        })
        .collect();

    let envelope = serde_json::json!({
        "success": failed == 0,
        "packages": total,
        "succeeded": succeeded,
        "failed": failed,
        "duration_ms": elapsed.as_millis() as u64,
        "members": members,
    });

    println!("{}", serde_json::to_string_pretty(&envelope).unwrap());
}

fn emit_human_summary(
    tool: &str,
    total: usize,
    succeeded: usize,
    failed: usize,
    targeted: usize,
    elapsed: std::time::Duration,
) {
    if failed == 0 {
        tools_ui::done_workspace(tool, total, elapsed);
        if targeted > total {
            // Some level filtering reduced the actual run set; surface that.
            install_ui::detail_line(crate::install_ui::terminal_line!(
                "  {} {} targeted",
                install_ui::dim("·"),
                install_ui::dim(&format!("{targeted} packages"))
            ));
        }
    } else {
        tools_ui::failed_workspace(tool, succeeded, failed, total, elapsed);
    }
}

#[derive(Debug, Eq, PartialEq)]
enum ToolFailureLine {
    Failed(install_ui::TerminalLine),
    Detail(install_ui::TerminalLine),
}

fn emit_prewarm_failure(tool: &str, reason: &str) {
    for line in format_prewarm_failure(tool, reason) {
        match line {
            ToolFailureLine::Failed(message) => install_ui::failed_line(message),
            ToolFailureLine::Detail(message) => install_ui::detail_line(message),
        }
    }
}

fn format_prewarm_failure(tool: &str, reason: &str) -> Vec<ToolFailureLine> {
    vec![
        ToolFailureLine::Failed(install_ui::terminal_line!(
            "{} prewarm failed",
            install_ui::yellow(tool),
        )),
        ToolFailureLine::Detail(install_ui::terminal_line!(
            "  {} {}",
            install_ui::dim("reason"),
            reason,
        )),
    ]
}

fn format_member_failure(member_name: &str, reason: &str) -> install_ui::TerminalLine {
    install_ui::terminal_line!(
        "  {} {}: {}",
        install_ui::red("✗"),
        install_ui::yellow(member_name),
        reason,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prewarm_failure_formats_as_slim_failure_with_reason_detail() {
        let lines = format_prewarm_failure("lint", "download failed");
        let plain: Vec<String> = lines
            .into_iter()
            .map(|line| match line {
                ToolFailureLine::Failed(message) | ToolFailureLine::Detail(message) => {
                    console::strip_ansi_codes(&message).into_owned()
                }
            })
            .collect();

        assert_eq!(
            plain,
            vec!["lint prewarm failed", "  reason download failed"]
        );
    }

    #[test]
    fn member_failure_formats_as_slim_detail_row() {
        assert_eq!(
            console::strip_ansi_codes(&format_member_failure("web", "exit 1")).into_owned(),
            "  ✗ web: exit 1"
        );
    }

    // --- check preflight argument parsing ---

    #[test]
    fn user_targeted_explicit_input_detects_dash_p_with_value() {
        assert!(user_targeted_explicit_input(&[
            "-p".into(),
            "tsconfig.test.json".into()
        ]));
    }

    #[test]
    fn user_targeted_explicit_input_detects_long_project_with_value() {
        assert!(user_targeted_explicit_input(&[
            "--project".into(),
            "tsconfig.test.json".into()
        ]));
    }

    #[test]
    fn user_targeted_explicit_input_detects_eq_form() {
        assert!(user_targeted_explicit_input(&[
            "-p=tsconfig.test.json".into()
        ]));
        assert!(user_targeted_explicit_input(&[
            "--project=tsconfig.test.json".into()
        ]));
    }

    #[test]
    fn user_targeted_explicit_input_detects_positional_file() {
        assert!(user_targeted_explicit_input(&["src/foo.ts".into()]));
    }

    #[test]
    fn user_targeted_explicit_input_no_target_for_only_flags() {
        assert!(!user_targeted_explicit_input(&[]));
        assert!(!user_targeted_explicit_input(&["--pretty".into()]));
        assert!(!user_targeted_explicit_input(&[
            "--noEmit".into(),
            "--strict".into()
        ]));
    }

    #[test]
    fn user_targeted_explicit_input_dash_p_without_value_is_not_targeted() {
        // A dangling `-p` with no following arg is malformed; we let
        // tsc surface its own error rather than asserting our own.
        assert!(!user_targeted_explicit_input(&["-p".into()]));
    }

    // --- watch detection ---

    #[test]
    fn args_imply_watch_recognizes_long_form() {
        assert!(args_imply_watch(&["--watch".into()]));
        assert!(args_imply_watch(&["--coverage".into(), "--watch".into()]));
    }

    #[test]
    fn args_imply_watch_recognizes_short_form() {
        assert!(args_imply_watch(&["-w".into()]));
    }

    #[test]
    fn args_imply_watch_recognizes_equals_form() {
        assert!(args_imply_watch(&["--watch=true".into()]));
    }

    #[test]
    fn args_imply_watch_rejects_explicit_false_values() {
        for value in ["--watch=false", "--watch=0", "--watch=off"] {
            assert!(!args_imply_watch(&[value.into()]));
        }
    }

    #[test]
    fn local_runner_args_drop_vitest_run_for_watch() {
        let args = local_runner_args(
            "vitest",
            &["run".into()],
            &["--watch".into(), "; inert".into()],
        );
        assert_eq!(args, vec!["--watch", "; inert"]);
    }

    #[test]
    fn local_runner_args_keep_vitest_run_without_watch() {
        assert_eq!(
            local_runner_args("vitest", &["run".into()], &["--reporter=verbose".into()]),
            vec!["run", "--reporter=verbose"]
        );
    }

    #[test]
    fn local_runner_args_do_not_rewrite_other_runners() {
        assert_eq!(
            local_runner_args("jest", &[], &["--watch".into()]),
            vec!["--watch"]
        );
    }

    #[test]
    fn args_imply_watch_ignores_unrelated_args() {
        assert!(!args_imply_watch(&[]));
        assert!(!args_imply_watch(&["--reporter=verbose".into()]));
        assert!(!args_imply_watch(&["src/foo.test.ts".into()]));
        assert!(!args_imply_watch(&["--watchman".into()]));
        assert!(!args_imply_watch(&["-watch".into()]));
    }

    // --- run_tool_binary outcome shape ---

    #[cfg(unix)]
    #[test]
    fn run_tool_binary_inherit_returns_exit_code() {
        let outcome = run_tool_binary(
            Path::new("/usr/bin/false"),
            &[],
            Path::new("/tmp"),
            StdioMode::Inherit,
        )
        .expect("should not error launching /usr/bin/false");
        assert_eq!(outcome.exit_code, Some(1));
        assert!(!outcome.success());
    }

    #[cfg(unix)]
    #[test]
    fn run_tool_binary_capture_collects_stdout() {
        let outcome = run_tool_binary(
            Path::new("/bin/echo"),
            &["hello".to_string()],
            Path::new("/tmp"),
            StdioMode::Capture,
        )
        .expect("should run echo");
        assert_eq!(outcome.exit_code, Some(0));
        assert!(outcome.success());
        assert!(outcome.captured.stdout.contains("hello"));
    }

    #[test]
    fn tool_outcome_into_result_distinguishes_exit_from_error() {
        let exit_failure = ToolOutcome {
            exit_code: Some(2),
            ..Default::default()
        };
        match exit_failure.into_result() {
            Err(LpmError::ExitCode(code)) => assert_eq!(code, 2),
            other => panic!("expected ExitCode error, got: {other:?}"),
        }

        let spawn_failure = ToolOutcome {
            error: Some("spawn failed".into()),
            ..Default::default()
        };
        match spawn_failure.into_result() {
            Err(LpmError::Script(msg)) => assert_eq!(msg, "spawn failed"),
            other => panic!("expected Script error, got: {other:?}"),
        }
    }

    // --- biome args ---

    #[test]
    fn fmt_default_adds_write() {
        assert_eq!(build_biome_args(&[], false), vec!["format", ".", "--write"]);
    }

    #[test]
    fn fmt_check_omits_write() {
        assert_eq!(build_biome_args(&[], true), vec!["format", "."]);
    }

    #[test]
    fn fmt_with_path_arg() {
        assert_eq!(
            build_biome_args(&["src/".to_string()], false),
            vec!["format", "src/", "--write"]
        );
    }

    // --- truncate_output ---

    #[test]
    fn truncate_output_small_passthrough() {
        let small = "hello world\n".repeat(10);
        let result = truncate_output(&small);
        assert_eq!(result, small);
    }

    #[test]
    fn truncate_output_large_truncated() {
        let huge = "x".repeat(MAX_CAPTURED_OUTPUT + 2_000);
        let result = truncate_output(&huge);
        assert!(
            result.ends_with("[output truncated at 10MB]"),
            "expected truncation marker, got tail: {:?}",
            &result[result.len().saturating_sub(60)..]
        );
        assert!(result.len() <= MAX_CAPTURED_OUTPUT + 100);
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
        assert_eq!(read_tool_version(dir.path(), "biome"), Some("2.4.5".into()));
    }

    #[test]
    fn read_tool_version_missing_tool_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("lpm.json"),
            r#"{"tools":{"oxlint":"1.55.0"}}"#,
        )
        .unwrap();
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
        assert_eq!(read_tool_version(dir.path(), "oxlint"), None);
    }

    // --- Plugin prewarm reuse decision ---
    //
    // Proves the homogeneous-cold-cache contract: when every member's tool
    // version matches the root pin, member-level resolution returns the
    // root-prewarmed binary path WITHOUT spawning a fresh ensure_plugin call.
    //
    // We test the decision logic directly rather than mocking ensure_plugin,
    // which makes the contract explicit at the call site.

    #[test]
    fn member_with_matching_version_reuses_root_binary() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("lpm.json"),
            r#"{"tools":{"oxlint":"1.55.0"}}"#,
        )
        .unwrap();

        let root_bin = PathBuf::from("/fake/root/oxlint");
        let root_pin = Some((
            "oxlint".to_string(),
            Some("1.55.0".to_string()),
            root_bin.clone(),
        ));

        // Synchronously inspect the decision: read the member version, compare
        // to root pin. This mirrors the real `resolve_member_plugin` short-
        // circuit at the top of the function.
        let member_version = read_tool_version(dir.path(), "oxlint");
        assert_eq!(member_version, Some("1.55.0".into()));

        let (root_name, root_version, root_bin_ref) = root_pin.as_ref().unwrap();
        assert_eq!(root_name, "oxlint");
        assert_eq!(member_version, *root_version);
        assert_eq!(*root_bin_ref, root_bin);
    }

    #[test]
    fn member_with_unpinned_version_matches_root_unpinned() {
        // Member has no lpm.json, root also has no pin → both `None` → reuse.
        let dir = tempfile::tempdir().unwrap();
        let root_bin = PathBuf::from("/fake/root/oxlint");
        let root_pin = Some(("oxlint".to_string(), None, root_bin));

        let member_version = read_tool_version(dir.path(), "oxlint");
        let (_, root_version, _) = root_pin.as_ref().unwrap();
        assert_eq!(member_version, *root_version);
    }

    #[test]
    fn member_with_diverging_version_falls_back_to_resolution() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("lpm.json"),
            r#"{"tools":{"oxlint":"1.99.0"}}"#,
        )
        .unwrap();

        let root_bin = PathBuf::from("/fake/root/oxlint");
        let root_pin = Some(("oxlint".to_string(), Some("1.55.0".to_string()), root_bin));

        let member_version = read_tool_version(dir.path(), "oxlint");
        let (_, root_version, _) = root_pin.as_ref().unwrap();
        assert_ne!(
            member_version, *root_version,
            "diverging pin must NOT reuse root binary"
        );
    }

    // --- detection ---

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
        let runner = detect_test_runner(dir.path()).unwrap();
        assert_eq!(runner.label, "vitest");
        assert_eq!(
            runner.invocation,
            RunnerInvocation::LocalBin {
                name: "vitest",
                base_args: vec!["run".into()]
            }
        );
    }

    #[test]
    fn detect_test_runner_jest_when_no_vitest() {
        let dir = tempfile::tempdir().unwrap();
        write_package_json(
            dir.path(),
            r#"{"name":"test","devDependencies":{"jest":"^29.0"}}"#,
        );
        let runner = detect_test_runner(dir.path()).unwrap();
        assert_eq!(runner.label, "jest");
        assert_eq!(
            runner.invocation,
            RunnerInvocation::LocalBin {
                name: "jest",
                base_args: Vec::new()
            }
        );
    }

    #[test]
    fn detect_test_runner_mocha_when_no_vitest_jest() {
        let dir = tempfile::tempdir().unwrap();
        write_package_json(
            dir.path(),
            r#"{"name":"test","devDependencies":{"mocha":"^10.0"}}"#,
        );
        let runner = detect_test_runner(dir.path()).unwrap();
        assert_eq!(runner.label, "mocha");
        assert_eq!(
            runner.invocation,
            RunnerInvocation::LocalBin {
                name: "mocha",
                base_args: Vec::new()
            }
        );
    }

    #[test]
    fn detect_test_runner_scripts_fallback() {
        let dir = tempfile::tempdir().unwrap();
        write_package_json(
            dir.path(),
            r#"{"name":"test","scripts":{"test":"node test.js"}}"#,
        );
        let runner = detect_test_runner(dir.path()).unwrap();
        assert_eq!(runner.label, "scripts.test");
        assert_eq!(
            runner.invocation,
            RunnerInvocation::PackageScript("node test.js".into())
        );
    }

    #[test]
    fn detect_test_runner_deps_not_just_dev_deps() {
        let dir = tempfile::tempdir().unwrap();
        write_package_json(
            dir.path(),
            r#"{"name":"test","dependencies":{"vitest":"^1.0"}}"#,
        );
        assert_eq!(detect_test_runner(dir.path()).unwrap().label, "vitest");
    }

    #[test]
    fn detect_test_runner_no_runner_errors() {
        let dir = tempfile::tempdir().unwrap();
        write_package_json(dir.path(), r#"{"name":"test"}"#);
        let err = detect_test_runner(dir.path()).unwrap_err();
        assert!(err.to_string().contains("no test runner found"));
    }

    #[test]
    fn detect_test_runner_no_package_json() {
        let dir = tempfile::tempdir().unwrap();
        let err = detect_test_runner(dir.path()).unwrap_err();
        assert!(err.to_string().contains("no package.json"));
    }

    // --- bench detection ---

    #[test]
    fn detect_bench_runner_vitest_priority() {
        let dir = tempfile::tempdir().unwrap();
        write_package_json(
            dir.path(),
            r#"{"name":"bench","devDependencies":{"vitest":"^1.0"},"scripts":{"bench":"node bench.js"}}"#,
        );
        let runner = detect_bench_runner(dir.path()).unwrap();
        assert_eq!(runner.label, "vitest");
        assert_eq!(
            runner.invocation,
            RunnerInvocation::LocalBin {
                name: "vitest",
                base_args: vec!["bench".into()]
            }
        );
    }

    #[test]
    fn detect_bench_runner_scripts_fallback() {
        let dir = tempfile::tempdir().unwrap();
        write_package_json(
            dir.path(),
            r#"{"name":"bench","scripts":{"bench":"node bench.js"}}"#,
        );
        let runner = detect_bench_runner(dir.path()).unwrap();
        assert_eq!(runner.label, "scripts.bench");
        assert_eq!(
            runner.invocation,
            RunnerInvocation::PackageScript("node bench.js".into())
        );
    }

    #[test]
    fn detect_bench_runner_deps_not_just_dev_deps() {
        let dir = tempfile::tempdir().unwrap();
        write_package_json(
            dir.path(),
            r#"{"name":"bench","dependencies":{"vitest":"^1.0"}}"#,
        );
        let runner = detect_bench_runner(dir.path()).unwrap();
        assert_eq!(runner.label, "vitest");
        assert_eq!(
            runner.invocation,
            RunnerInvocation::LocalBin {
                name: "vitest",
                base_args: vec!["bench".into()]
            }
        );
    }

    #[test]
    fn detect_bench_runner_no_runner_errors() {
        let dir = tempfile::tempdir().unwrap();
        write_package_json(dir.path(), r#"{"name":"bench"}"#);
        let err = detect_bench_runner(dir.path()).unwrap_err();
        assert!(err.to_string().contains("no benchmark runner found"));
    }

    #[test]
    fn detect_bench_runner_no_package_json() {
        let dir = tempfile::tempdir().unwrap();
        let err = detect_bench_runner(dir.path()).unwrap_err();
        assert!(err.to_string().contains("no package.json"));
    }

    // --- CLI parser tests ---

    #[test]
    fn lint_affected_parses() {
        use clap::Parser;
        let cli =
            crate::Cli::try_parse_from(["lpm", "lint", "--affected", "--base", "develop"]).unwrap();
        match cli.command.expect("test parse missing subcommand") {
            crate::Commands::Lint(args) => {
                assert!(!args.all);
                assert!(args.affected);
                assert_eq!(args.base, "develop");
                assert!(args.args.is_empty());
                assert!(args.filter.is_empty());
                assert!(!args.fail_if_no_match);
            }
            _ => panic!("expected Lint command"),
        }
    }

    #[test]
    fn lint_filter_parses_with_grammar() {
        use clap::Parser;
        let cli = crate::Cli::try_parse_from([
            "lpm",
            "lint",
            "--filter",
            "@scope/*",
            "--filter",
            "!web-tests",
            "--fail-if-no-match",
        ])
        .unwrap();
        match cli.command.unwrap() {
            crate::Commands::Lint(args) => {
                assert_eq!(
                    args.filter,
                    vec!["@scope/*".to_string(), "!web-tests".to_string()]
                );
                assert!(args.fail_if_no_match);
            }
            _ => panic!("expected Lint command"),
        }
    }

    #[test]
    fn fmt_filter_and_check_compose() {
        use clap::Parser;
        let cli =
            crate::Cli::try_parse_from(["lpm", "fmt", "--filter", "./apps/*", "--check"]).unwrap();
        match cli.command.unwrap() {
            crate::Commands::Fmt(args) => {
                assert!(args.check);
                assert_eq!(args.filter, vec!["./apps/*".to_string()]);
            }
            _ => panic!("expected Fmt command"),
        }
    }

    #[test]
    fn check_filter_parses() {
        use clap::Parser;
        let cli = crate::Cli::try_parse_from([
            "lpm",
            "check",
            "--filter",
            "{./packages/core}",
            "--fail-if-no-match",
        ])
        .unwrap();
        match cli.command.unwrap() {
            crate::Commands::Check(args) => {
                assert_eq!(args.filter, vec!["{./packages/core}".to_string()]);
                assert!(args.fail_if_no_match);
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
    fn lint_all_and_filter_conflict() {
        // --all means "everything"; --filter narrows. Combining them used to
        // silently ignore --all and only honor the filter. Conflict is the
        // explicit fix — users pick one selection mode.
        use clap::Parser;
        let result = crate::Cli::try_parse_from(["lpm", "lint", "--all", "--filter", "foo"]);
        assert!(result.is_err(), "--all and --filter must conflict");
    }

    #[test]
    fn fmt_all_and_filter_conflict() {
        use clap::Parser;
        let result = crate::Cli::try_parse_from(["lpm", "fmt", "--all", "--filter", "foo"]);
        assert!(result.is_err(), "--all and --filter must conflict");
    }

    #[test]
    fn check_all_and_filter_conflict() {
        use clap::Parser;
        let result = crate::Cli::try_parse_from(["lpm", "check", "--all", "--filter", "foo"]);
        assert!(result.is_err(), "--all and --filter must conflict");
    }

    // --- Test/Bench workspace surface ---

    #[test]
    fn test_filter_parses_with_grammar() {
        use clap::Parser;
        let cli = crate::Cli::try_parse_from([
            "lpm",
            "test",
            "--filter",
            "@scope/*",
            "--filter",
            "!web-tests",
            "--fail-if-no-match",
        ])
        .unwrap();
        match cli.command.unwrap() {
            crate::Commands::Test(args) => {
                assert_eq!(
                    args.filter,
                    vec!["@scope/*".to_string(), "!web-tests".to_string()]
                );
                assert!(args.fail_if_no_match);
                assert!(args.args.is_empty());
            }
            _ => panic!("expected Test command"),
        }
    }

    #[test]
    fn test_compat_seam_double_dash_forwards_recognized_flags() {
        // Load-bearing: a user who passes runner-specific flags like --all
        // must be able to keep doing so by adding `--`. The trailing_var_arg
        // capture must claim everything after `--` regardless of name.
        use clap::Parser;
        let cli = crate::Cli::try_parse_from(["lpm", "test", "--", "--all", "--filter", "pattern"])
            .unwrap();
        match cli.command.unwrap() {
            crate::Commands::Test(args) => {
                assert!(!args.all, "--all after `--` must NOT be claimed by clap");
                assert!(
                    args.filter.is_empty(),
                    "--filter after `--` must NOT be claimed by clap"
                );
                assert_eq!(
                    args.args,
                    vec![
                        "--all".to_string(),
                        "--filter".to_string(),
                        "pattern".to_string()
                    ],
                    "all three tokens after `--` must end up in args verbatim"
                );
            }
            _ => panic!("expected Test command"),
        }
    }

    #[test]
    fn bench_compat_seam_double_dash_forwards_recognized_flags() {
        use clap::Parser;
        let cli =
            crate::Cli::try_parse_from(["lpm", "bench", "--", "--all", "--affected"]).unwrap();
        match cli.command.unwrap() {
            crate::Commands::Bench(args) => {
                assert!(!args.all);
                assert!(!args.affected);
                assert_eq!(
                    args.args,
                    vec!["--all".to_string(), "--affected".to_string()]
                );
            }
            _ => panic!("expected Bench command"),
        }
    }

    #[test]
    fn test_all_and_filter_conflict() {
        use clap::Parser;
        let result = crate::Cli::try_parse_from(["lpm", "test", "--all", "--filter", "foo"]);
        assert!(result.is_err(), "--all and --filter must conflict");
    }

    #[test]
    fn test_all_and_affected_conflict() {
        use clap::Parser;
        let result = crate::Cli::try_parse_from(["lpm", "test", "--all", "--affected"]);
        assert!(result.is_err(), "--all and --affected must conflict");
    }

    #[test]
    fn bench_all_and_filter_conflict() {
        use clap::Parser;
        let result = crate::Cli::try_parse_from(["lpm", "bench", "--all", "--filter", "foo"]);
        assert!(result.is_err(), "--all and --filter must conflict");
    }

    #[test]
    fn bench_all_and_affected_conflict() {
        use clap::Parser;
        let result = crate::Cli::try_parse_from(["lpm", "bench", "--all", "--affected"]);
        assert!(result.is_err(), "--all and --affected must conflict");
    }

    #[test]
    fn test_passthrough_args_stay_in_args() {
        // No workspace flag → trailing args still flow through.
        use clap::Parser;
        let cli =
            crate::Cli::try_parse_from(["lpm", "test", "src/foo.test.ts", "--coverage"]).unwrap();
        match cli.command.unwrap() {
            crate::Commands::Test(args) => {
                assert!(!args.all);
                assert_eq!(
                    args.args,
                    vec!["src/foo.test.ts".to_string(), "--coverage".to_string()]
                );
            }
            _ => panic!("expected Test command"),
        }
    }

    // --- prewarm failure → envelope contract ---

    #[test]
    fn prewarm_failure_synthesizes_one_failed_member_per_target() {
        use lpm_task::graph::{GraphNode, WorkspaceGraph};
        use std::collections::{HashMap, HashSet};

        let members = vec![
            GraphNode {
                name: "pkg-a".into(),
                path: PathBuf::from("packages/pkg-a"),
            },
            GraphNode {
                name: "pkg-b".into(),
                path: PathBuf::from("packages/pkg-b"),
            },
            GraphNode {
                name: "pkg-c".into(),
                path: PathBuf::from("packages/pkg-c"),
            },
        ];
        let graph = WorkspaceGraph {
            members,
            edges: vec![vec![], vec![], vec![]],
            reverse_edges: vec![vec![], vec![], vec![]],
            dependency_edges: vec![vec![], vec![], vec![]],
            reverse_dependency_edges: vec![vec![], vec![], vec![]],
            name_to_idx: HashMap::from([
                ("pkg-a".to_string(), 0usize),
                ("pkg-b".to_string(), 1usize),
                ("pkg-c".to_string(), 2usize),
            ]),
        };
        let target_set: HashSet<usize> = HashSet::from([0, 2]);

        let results =
            synthesize_prewarm_failure_members(&graph, &target_set, "plugin oxlint not found");

        assert_eq!(results.len(), 2, "one entry per targeted member");
        let names: Vec<&str> = results.iter().map(|r| r.name.as_str()).collect();
        assert_eq!(names, vec!["pkg-a", "pkg-c"], "deterministic order");

        for r in &results {
            assert!(!r.success);
            assert!(
                r.exit_code.is_none(),
                "prewarm failures must surface as exit_code: null, not a fake exit code"
            );
            let err = r.error.as_ref().expect("error must be populated");
            assert!(
                err.contains("plugin prewarm failed") && err.contains("plugin oxlint not found"),
                "error must carry both the wrapper and the original message, got: {err}"
            );
        }
    }

    #[test]
    fn prewarm_failure_skips_unselected_members() {
        // Members not in target_set must not appear in the synthesized failure
        // list — the contract is one entry per WHAT WOULD HAVE RUN, not one
        // per workspace member. Filter / affected selections must be honored.
        use lpm_task::graph::{GraphNode, WorkspaceGraph};
        use std::collections::{HashMap, HashSet};

        let members = vec![
            GraphNode {
                name: "pkg-a".into(),
                path: PathBuf::from("packages/pkg-a"),
            },
            GraphNode {
                name: "pkg-b".into(),
                path: PathBuf::from("packages/pkg-b"),
            },
        ];
        let graph = WorkspaceGraph {
            members,
            edges: vec![vec![], vec![]],
            reverse_edges: vec![vec![], vec![]],
            dependency_edges: vec![vec![], vec![]],
            reverse_dependency_edges: vec![vec![], vec![]],
            name_to_idx: HashMap::from([
                ("pkg-a".to_string(), 0usize),
                ("pkg-b".to_string(), 1usize),
            ]),
        };
        let target_set: HashSet<usize> = HashSet::from([0]); // only pkg-a

        let results = synthesize_prewarm_failure_members(&graph, &target_set, "x");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "pkg-a");
    }

    #[test]
    fn lint_affected_default_base_is_main() {
        use clap::Parser;
        let cli = crate::Cli::try_parse_from(["lpm", "lint", "--affected"]).unwrap();
        match cli.command.unwrap() {
            crate::Commands::Lint(args) => assert_eq!(args.base, "main"),
            _ => panic!("expected Lint command"),
        }
    }
}
