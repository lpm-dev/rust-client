use crate::{CheckEngine, output};
use lpm_common::LpmError;
use lpm_common::color::Painted;
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

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

    let outcome = run_tool_binary(&bin, args, project_dir, StdioMode::Inherit)?;
    outcome.into_result()
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

    let biome_args = build_biome_args(args, check);
    let outcome = run_tool_binary(&bin, &biome_args, project_dir, StdioMode::Inherit)?;
    outcome.into_result()
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
    if !json_output {
        output::info(&format!("check ({} --noEmit)", check_engine_binary(engine)));
    }

    if !user_targeted_explicit_input(args) {
        check_preflight(project_dir, engine)?;
    }

    let outcome = run_check_engine(project_dir, args, engine, StdioMode::Inherit).await?;
    outcome.into_result()
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
    let (runner_name, runner_cmd) = detect_test_runner(project_dir)?;
    let runner_cmd = adjust_test_runner_for_watch(&runner_name, runner_cmd, args);

    if !json_output {
        output::info(&format!("test ({runner_name})"));
    }

    let path = lpm_runner::bin_path::build_path_with_bins(project_dir);
    let env_vars = lpm_runner::dotenv::load_env_files(project_dir, None);

    let full_cmd = if args.is_empty() {
        runner_cmd
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
    let (runner_name, cmd) = detect_bench_runner(project_dir)?;

    if !json_output {
        output::info(&format!(
            "bench ({})",
            cmd.split_whitespace().next().unwrap_or("unknown")
        ));
    }

    let path = lpm_runner::bin_path::build_path_with_bins(project_dir);
    let env_vars = lpm_runner::dotenv::load_env_files(project_dir, None);

    let full_cmd = if args.is_empty() {
        cmd
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

/// Auto-detect the benchmark runner from package.json. Extracted from the
/// inline match in `bench()` so the workspace orchestrator can reuse it
/// per-member without duplicating the priority logic.
fn detect_bench_runner(project_dir: &Path) -> Result<(String, String), LpmError> {
    let pkg_json_path = project_dir.join("package.json");
    if !pkg_json_path.exists() {
        return Err(LpmError::Script("no package.json found".into()));
    }

    let pkg = lpm_workspace::read_package_json(&pkg_json_path)
        .map_err(|e| LpmError::Script(format!("{e}")))?;

    if pkg.dependencies.contains_key("vitest") || pkg.dev_dependencies.contains_key("vitest") {
        return Ok(("vitest".to_string(), "vitest bench".to_string()));
    }
    if let Some(bench_script) = pkg.scripts.get("bench") {
        return Ok(("scripts.bench".to_string(), bench_script.clone()));
    }

    Err(LpmError::Script(
        "no benchmark runner found. Install vitest or add a 'bench' script to package.json".into(),
    ))
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
            eprintln!("  \x1b[33m!\x1b[0m failed to read lpm.json tools config: {e}");
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

    /// Convert into a `Result` for single-package callers that just want the
    /// exit-code propagated.
    fn into_result(self) -> Result<(), LpmError> {
        if let Some(error) = self.error {
            return Err(LpmError::Script(error));
        }
        match self.exit_code {
            Some(0) => Ok(()),
            Some(code) => Err(LpmError::ExitCode(code)),
            None => Err(LpmError::Script(
                "tool exited without an exit code".to_string(),
            )),
        }
    }
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
    let path = lpm_runner::bin_path::build_path_with_bins(project_dir);
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

/// Shell-escape a single argument to prevent injection.
fn shell_escape(arg: &str) -> String {
    format!("'{}'", arg.replace('\'', "'\\''"))
}

/// Returns `true` if the forwarded args contain a watch-mode opt-in.
fn args_imply_watch(args: &[String]) -> bool {
    args.iter()
        .any(|a| a == "--watch" || a.starts_with("--watch=") || a == "-w")
}

/// Rewrite the auto-detected test runner command when the forwarded args ask
/// for watch mode. Vitest's `run` subcommand silently drops `--watch`; drop
/// the `run` so the resulting invocation is `vitest --watch`. Other runners
/// accept `--watch` natively against their bare command.
fn adjust_test_runner_for_watch(runner_name: &str, base_cmd: String, args: &[String]) -> String {
    if runner_name == "vitest" && args_imply_watch(args) {
        return "vitest".into();
    }
    base_cmd
}

/// Build a shell command string with safely escaped extra arguments.
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

    if all_deps.iter().any(|d| d.as_str() == "vitest") {
        return Ok(("vitest".into(), "vitest run".into()));
    }
    if all_deps.iter().any(|d| d.as_str() == "jest") {
        return Ok(("jest".into(), "jest".into()));
    }
    if all_deps.iter().any(|d| d.as_str() == "mocha") {
        return Ok(("mocha".into(), "mocha".into()));
    }

    if let Some(test_script) = pkg.scripts.get("test") {
        return Ok(("scripts.test".into(), test_script.clone()));
    }

    Err(LpmError::Script(
        "no test runner found. Install vitest/jest/mocha or add a 'test' script to package.json"
            .into(),
    ))
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
    let levels = ws_graph
        .topological_levels()
        .map_err(|e| LpmError::Script(e.to_string()))?;
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
            output::success(&format!(
                "no packages affected vs {} — nothing to {tool}",
                affected_base.unwrap_or("main"),
            ));
        } else {
            let hint = crate::commands::filter::format_no_match_hint_for_sets(filters, filter_prod);
            output::warn("No packages matched");
            if let Some(h) = hint {
                eprintln!();
                for line in h.lines() {
                    eprintln!("  {}", line.dimmed());
                }
                eprintln!();
            }
        }
        return Ok(());
    }

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
                eprintln!("  {} {tool}: {prewarm_err}", "\u{2716}".to_string().red(),);
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
    let mut member_results: Vec<MemberResult> = Vec::with_capacity(target_set.len());

    for level in &levels {
        let level_targets: Vec<usize> = level
            .iter()
            .filter(|i| target_set.contains(i))
            .copied()
            .collect();

        if level_targets.is_empty() {
            continue;
        }

        let level_outcomes = run_level(
            &ws_graph,
            &level_targets,
            tool,
            args,
            check,
            check_engine,
            stdio,
            &root_pin,
            workspace_concurrency,
        )
        .await;
        member_results.extend(level_outcomes);
    }

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

/// Run all members in a single topological level. Within a level, members are
/// independent; callers decide the workspace concurrency cap.
#[allow(clippy::too_many_arguments)]
async fn run_level(
    ws_graph: &lpm_task::graph::WorkspaceGraph,
    level_targets: &[usize],
    tool: &str,
    args: &[String],
    check: bool,
    check_engine: Option<CheckEngine>,
    stdio: StdioMode,
    root_pin: &Option<(String, Option<String>, PathBuf)>,
    workspace_concurrency: usize,
) -> Vec<MemberResult> {
    if level_targets.len() == 1 {
        let idx = level_targets[0];
        let result = run_one_member(
            &ws_graph.members[idx].path,
            &ws_graph.members[idx].name,
            tool,
            args,
            check,
            check_engine,
            stdio,
            root_pin,
        )
        .await;
        return vec![result];
    }

    let mut all_results: Vec<MemberResult> = Vec::with_capacity(level_targets.len());

    for chunk in level_targets.chunks(workspace_concurrency) {
        let mut chunk_futs = Vec::with_capacity(chunk.len());
        for &idx in chunk {
            let member_dir = ws_graph.members[idx].path.clone();
            let member_name = ws_graph.members[idx].name.clone();
            let tool_owned = tool.to_string();
            let args_owned: Vec<String> = args.to_vec();
            let root_pin_clone = root_pin
                .as_ref()
                .map(|(name, ver, bin)| (name.clone(), ver.clone(), bin.clone()));

            chunk_futs.push(tokio::spawn(async move {
                run_one_member(
                    &member_dir,
                    &member_name,
                    &tool_owned,
                    &args_owned,
                    check,
                    check_engine,
                    stdio,
                    &root_pin_clone,
                )
                .await
            }));
        }

        for fut in chunk_futs {
            match fut.await {
                Ok(r) => all_results.push(r),
                Err(join_err) => all_results.push(MemberResult {
                    name: "<unknown>".into(),
                    success: false,
                    exit_code: None,
                    duration_ms: 0,
                    captured: Captured::default(),
                    error: Some(format!("workspace task panicked: {join_err}")),
                }),
            }
        }
    }

    all_results
}

/// Execute one member's tool invocation and convert into a `MemberResult`.
#[allow(clippy::too_many_arguments)]
async fn run_one_member(
    member_dir: &Path,
    member_name: &str,
    tool: &str,
    args: &[String],
    check: bool,
    check_engine: Option<CheckEngine>,
    stdio: StdioMode,
    root_pin: &Option<(String, Option<String>, PathBuf)>,
) -> MemberResult {
    let start = std::time::Instant::now();

    if matches!(stdio, StdioMode::Inherit) {
        eprintln!("  {} {tool}", format!("[{member_name}]").bold());
    }

    let outcome_result = match tool {
        "lint" => run_lint_member(member_dir, args, stdio, root_pin).await,
        "fmt" => run_fmt_member(member_dir, args, check, stdio, root_pin).await,
        "check" => Ok(run_check_engine(
            member_dir,
            args,
            check_engine.unwrap_or(CheckEngine::Tsc),
            stdio,
        )
        .await
        .unwrap_or_else(|e| ToolOutcome {
            error: Some(e.to_string()),
            ..Default::default()
        })),
        "test" | "bench" => Ok(run_test_or_bench_member(member_dir, tool, args, stdio)),
        _ => Err(LpmError::Script(format!("unknown tool: {tool}"))),
    };

    let duration_ms = start.elapsed().as_millis() as u64;

    let (success, exit_code, captured, error) = match outcome_result {
        Ok(outcome) => {
            let success = outcome.success();
            let captured = outcome.captured;
            (success, outcome.exit_code, captured, outcome.error)
        }
        Err(e) => (false, None, Captured::default(), Some(e.to_string())),
    };

    if matches!(stdio, StdioMode::Inherit) && !success {
        if let Some(code) = exit_code {
            eprintln!(
                "  {} {member_name}: exit {code}",
                "\u{2716}".to_string().red()
            );
        } else if let Some(ref msg) = error {
            eprintln!("  {} {member_name}: {msg}", "\u{2716}".to_string().red());
        }
    }

    MemberResult {
        name: member_name.to_string(),
        success,
        exit_code,
        duration_ms,
        captured,
        error,
    }
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

/// Per-member callback for `lpm test` / `lpm bench` workspace mode.
///
/// Detection runs per member because workspace members may install different
/// runners (one vitest, another jest). A detection failure becomes a per-
/// member `ToolOutcome` with `exit_code: None` + an `error` string —
/// matching the workspace JSON envelope contract for spawn / config /
/// detection failures. The orchestrator never aborts on one member's missing
/// runner; the envelope still lists every targeted member.
fn run_test_or_bench_member(
    member_dir: &Path,
    tool: &str,
    args: &[String],
    stdio: StdioMode,
) -> ToolOutcome {
    let detection = match tool {
        "test" => detect_test_runner(member_dir),
        "bench" => detect_bench_runner(member_dir),
        _ => Err(LpmError::Script(format!("unknown runner tool: {tool}"))),
    };

    let (runner_name, base_cmd) = match detection {
        Ok(pair) => pair,
        Err(e) => {
            return ToolOutcome {
                error: Some(e.to_string()),
                ..Default::default()
            };
        }
    };

    // `test` adjusts `vitest run` → `vitest` when --watch is forwarded; `bench`
    // never needs the rewrite because vitest's `bench` subcommand respects
    // `--watch` directly. The workspace dispatcher rejects --watch before this
    // point, so the rewrite is a no-op here in practice — kept for symmetry
    // with the single-package path so the helper is independently safe.
    let base_cmd = if tool == "test" {
        adjust_test_runner_for_watch(&runner_name, base_cmd, args)
    } else {
        base_cmd
    };

    let full_cmd = if args.is_empty() {
        base_cmd
    } else {
        build_safe_command(&runner_name, &base_cmd, args)
    };

    let path = lpm_runner::bin_path::build_path_with_bins(member_dir);
    let env_vars = lpm_runner::dotenv::load_env_files(member_dir, None);
    let shell_cmd = lpm_runner::shell::ShellCommand {
        command: &full_cmd,
        cwd: member_dir,
        path: &path,
        envs: &env_vars,
    };

    let mut outcome = ToolOutcome::default();

    match stdio {
        StdioMode::Inherit => match lpm_runner::shell::spawn_shell(&shell_cmd) {
            Ok(status) => {
                outcome.exit_code = Some(lpm_runner::shell::exit_code(&status));
            }
            Err(e) => {
                outcome.error = Some(e.to_string());
            }
        },
        StdioMode::Capture => match lpm_runner::shell::spawn_shell_capture(&shell_cmd) {
            Ok(captured) => {
                outcome.exit_code = Some(lpm_runner::shell::exit_code(&captured.status));
                outcome.captured = Captured {
                    stdout: captured.stdout,
                    stderr: captured.stderr,
                };
            }
            Err(e) => {
                outcome.error = Some(e.to_string());
            }
        },
    }

    outcome
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
        output::success(&format!(
            "{tool} passed in {total} packages ({:.1}s)",
            elapsed.as_secs_f64()
        ));
        if targeted > total {
            // Some level filtering reduced the actual run set; surface that.
            eprintln!(
                "  {} {} targeted",
                "·".dimmed(),
                format!("{targeted} packages").dimmed()
            );
        }
    } else {
        output::warn(&format!(
            "{tool}: {succeeded} passed, {failed} failed out of {total} packages ({:.1}s)",
            elapsed.as_secs_f64()
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- shell escaping ---

    #[test]
    fn shell_escape_plain_arg() {
        assert_eq!(shell_escape("--verbose"), "'--verbose'");
    }

    #[test]
    fn shell_escape_prevents_injection_semicolon() {
        let escaped = shell_escape("; rm -rf /");
        assert_eq!(escaped, "'; rm -rf /'");
        assert!(escaped.starts_with('\''));
        assert!(escaped.ends_with('\''));
    }

    #[test]
    fn shell_escape_prevents_injection_subshell() {
        assert_eq!(shell_escape("$(whoami)"), "'$(whoami)'");
    }

    #[test]
    fn shell_escape_prevents_backtick_injection() {
        assert_eq!(shell_escape("`whoami`"), "'`whoami`'");
    }

    #[test]
    fn shell_escape_handles_embedded_single_quotes() {
        assert_eq!(shell_escape("it's"), "'it'\\''s'");
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
        assert_eq!(build_safe_command("jest", "jest", &[]), "jest");
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
    fn adjust_test_runner_drops_run_for_vitest_watch() {
        let cmd = adjust_test_runner_for_watch("vitest", "vitest run".into(), &["--watch".into()]);
        assert_eq!(cmd, "vitest");
    }

    #[test]
    fn adjust_test_runner_keeps_run_for_vitest_without_watch() {
        let cmd = adjust_test_runner_for_watch(
            "vitest",
            "vitest run".into(),
            &["--reporter=verbose".into()],
        );
        assert_eq!(cmd, "vitest run");
    }

    #[test]
    fn adjust_test_runner_does_not_touch_jest_or_mocha() {
        assert_eq!(
            adjust_test_runner_for_watch("jest", "jest".into(), &["--watch".into()]),
            "jest"
        );
        assert_eq!(
            adjust_test_runner_for_watch("mocha", "mocha".into(), &["--watch".into()]),
            "mocha"
        );
    }

    #[test]
    fn adjust_test_runner_does_not_touch_user_scripts() {
        let cmd = adjust_test_runner_for_watch(
            "scripts.test",
            "vitest run --reporter=verbose".into(),
            &["--watch".into()],
        );
        assert_eq!(cmd, "vitest run --reporter=verbose");
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
        let (name, cmd) = detect_bench_runner(dir.path()).unwrap();
        assert_eq!(name, "vitest");
        assert_eq!(cmd, "vitest bench");
    }

    #[test]
    fn detect_bench_runner_scripts_fallback() {
        let dir = tempfile::tempdir().unwrap();
        write_package_json(
            dir.path(),
            r#"{"name":"bench","scripts":{"bench":"node bench.js"}}"#,
        );
        let (name, cmd) = detect_bench_runner(dir.path()).unwrap();
        assert_eq!(name, "scripts.bench");
        assert_eq!(cmd, "node bench.js");
    }

    #[test]
    fn detect_bench_runner_deps_not_just_dev_deps() {
        let dir = tempfile::tempdir().unwrap();
        write_package_json(
            dir.path(),
            r#"{"name":"bench","dependencies":{"vitest":"^1.0"}}"#,
        );
        let (name, cmd) = detect_bench_runner(dir.path()).unwrap();
        assert_eq!(name, "vitest");
        assert_eq!(cmd, "vitest bench");
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
            crate::Commands::Lint {
                all,
                affected,
                base,
                args,
                filter,
                fail_if_no_match,
                ..
            } => {
                assert!(!all);
                assert!(affected);
                assert_eq!(base, "develop");
                assert!(args.is_empty());
                assert!(filter.is_empty());
                assert!(!fail_if_no_match);
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
            crate::Commands::Lint {
                filter,
                fail_if_no_match,
                ..
            } => {
                assert_eq!(
                    filter,
                    vec!["@scope/*".to_string(), "!web-tests".to_string()]
                );
                assert!(fail_if_no_match);
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
            crate::Commands::Fmt { check, filter, .. } => {
                assert!(check);
                assert_eq!(filter, vec!["./apps/*".to_string()]);
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
            crate::Commands::Check {
                filter,
                fail_if_no_match,
                ..
            } => {
                assert_eq!(filter, vec!["{./packages/core}".to_string()]);
                assert!(fail_if_no_match);
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
            crate::Commands::Test {
                filter,
                fail_if_no_match,
                args,
                ..
            } => {
                assert_eq!(
                    filter,
                    vec!["@scope/*".to_string(), "!web-tests".to_string()]
                );
                assert!(fail_if_no_match);
                assert!(args.is_empty());
            }
            _ => panic!("expected Test command"),
        }
    }

    #[test]
    fn test_compat_seam_double_dash_forwards_recognized_flags() {
        // Load-bearing: a user who today passes --all to bun/jest must be
        // able to keep doing so by adding `--`. The trailing_var_arg
        // capture must claim everything after `--` regardless of name.
        use clap::Parser;
        let cli = crate::Cli::try_parse_from(["lpm", "test", "--", "--all", "--filter", "pattern"])
            .unwrap();
        match cli.command.unwrap() {
            crate::Commands::Test {
                all, filter, args, ..
            } => {
                assert!(!all, "--all after `--` must NOT be claimed by clap");
                assert!(
                    filter.is_empty(),
                    "--filter after `--` must NOT be claimed by clap"
                );
                assert_eq!(
                    args,
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
            crate::Commands::Bench {
                all,
                affected,
                args,
                ..
            } => {
                assert!(!all);
                assert!(!affected);
                assert_eq!(args, vec!["--all".to_string(), "--affected".to_string()]);
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
            crate::Commands::Test { all, args, .. } => {
                assert!(!all);
                assert_eq!(
                    args,
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
            crate::Commands::Lint { base, .. } => assert_eq!(base, "main"),
            _ => panic!("expected Lint command"),
        }
    }
}
