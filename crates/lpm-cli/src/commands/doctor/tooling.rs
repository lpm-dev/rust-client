use std::io::Read;
use std::path::Path;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::thread::JoinHandle;
use std::time::Duration;

use crate::doctor_catalog;

use super::check::{Check, FixTarget};

#[derive(Clone)]
pub(super) struct InstalledDoctorPlugin {
    definition: &'static lpm_plugin::registry::PluginDef,
    version: String,
    binary: PathBuf,
}

pub(super) fn discover_installed_plugins() -> Vec<InstalledDoctorPlugin> {
    lpm_plugin::registry::list_plugins()
        .iter()
        .filter_map(|definition| {
            lpm_plugin::find_installed_for_current_platform(definition.name, definition.binary_name)
                .map(|(version, binary)| InstalledDoctorPlugin {
                    definition,
                    version,
                    binary,
                })
        })
        .collect()
}

pub(in crate::commands) fn run_tool_with_timeout(
    cmd: &Path,
    args: &[&str],
    cwd: &Path,
    extra_path: Option<&str>,
) -> Result<(String, String, i32), String> {
    let output = run_tool_output_with_timeout(cmd, args, cwd, extra_path)?;
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    let code = output.status.code().unwrap_or(1);

    Ok((stdout, stderr, code))
}

fn run_tool_output_with_timeout(
    cmd: &Path,
    args: &[&str],
    cwd: &Path,
    extra_path: Option<&str>,
) -> Result<std::process::Output, String> {
    let mut command = Command::new(cmd);
    command
        .args(args)
        .current_dir(cwd)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env_clear()
        .envs(crate::commands::rebuild::sandbox_env::build_sanitized_env());

    if let Some(path) = extra_path {
        command.env("PATH", path);
    }

    let child = lpm_sandbox::spawn_tracked_command(&mut command)
        .map_err(|error| format!("failed to start {}: {error}", cmd.display()))?;

    wait_with_timeout(child, Duration::from_secs(30)).map_err(|error| match error {
        ChildWaitError::Timeout => format!("{} exceeded its 30-second deadline", cmd.display()),
        ChildWaitError::Wait(error) => format!("failed to wait for {}: {error}", cmd.display()),
    })
}

const TOOL_OUTPUT_TAIL_CAP_BYTES: usize = 1024 * 1024;

pub(super) fn wait_with_timeout(
    mut child: std::process::Child,
    timeout: Duration,
) -> Result<std::process::Output, ChildWaitError> {
    let stdout_reader = child.stdout.take().map(spawn_tail_reader);
    let stderr_reader = child.stderr.take().map(spawn_tail_reader);

    let status = match crate::commands::rebuild::process_tree::wait_with_timeout(child, &timeout) {
        Ok(status) => status,
        Err(error) if error.starts_with("timeout after ") => {
            join_tail_reader(stdout_reader);
            join_tail_reader(stderr_reader);
            return Err(ChildWaitError::Timeout);
        }
        Err(error) => {
            join_tail_reader(stdout_reader);
            join_tail_reader(stderr_reader);
            return Err(ChildWaitError::Wait(error));
        }
    };

    Ok(std::process::Output {
        status,
        stdout: join_tail_reader(stdout_reader),
        stderr: join_tail_reader(stderr_reader),
    })
}

#[derive(Debug)]
pub(super) enum ChildWaitError {
    Timeout,
    Wait(String),
}

fn spawn_tail_reader(mut reader: impl Read + Send + 'static) -> JoinHandle<Vec<u8>> {
    std::thread::spawn(move || {
        let mut tail = TailBuffer::new();
        let mut chunk = [0u8; 16 * 1024];
        loop {
            match reader.read(&mut chunk) {
                Ok(0) => return tail.into_vec(),
                Ok(read) => tail.push(&chunk[..read]),
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(_) => return tail.into_vec(),
            }
        }
    })
}

fn join_tail_reader(reader: Option<JoinHandle<Vec<u8>>>) -> Vec<u8> {
    reader
        .and_then(|reader| reader.join().ok())
        .unwrap_or_default()
}

struct TailBuffer {
    bytes: Vec<u8>,
    start: usize,
}

impl TailBuffer {
    fn new() -> Self {
        Self {
            bytes: Vec::new(),
            start: 0,
        }
    }

    fn push(&mut self, mut input: &[u8]) {
        if input.len() >= TOOL_OUTPUT_TAIL_CAP_BYTES {
            self.bytes.clear();
            self.bytes
                .extend_from_slice(&input[input.len() - TOOL_OUTPUT_TAIL_CAP_BYTES..]);
            self.start = 0;
            return;
        }

        let available = TOOL_OUTPUT_TAIL_CAP_BYTES - self.bytes.len();
        let appended = available.min(input.len());
        self.bytes.extend_from_slice(&input[..appended]);
        input = &input[appended..];
        if input.is_empty() {
            return;
        }

        let first = input.len().min(TOOL_OUTPUT_TAIL_CAP_BYTES - self.start);
        self.bytes[self.start..self.start + first].copy_from_slice(&input[..first]);
        self.start = (self.start + first) % TOOL_OUTPUT_TAIL_CAP_BYTES;

        let remaining = &input[first..];
        if !remaining.is_empty() {
            self.bytes[..remaining.len()].copy_from_slice(remaining);
            self.start = remaining.len();
        }
    }

    fn into_vec(self) -> Vec<u8> {
        if self.bytes.len() < TOOL_OUTPUT_TAIL_CAP_BYTES || self.start == 0 {
            return self.bytes;
        }

        let mut ordered = Vec::with_capacity(TOOL_OUTPUT_TAIL_CAP_BYTES);
        ordered.extend_from_slice(&self.bytes[self.start..]);
        ordered.extend_from_slice(&self.bytes[..self.start]);
        ordered
    }
}

/// Run oxlint silently and count errors/warnings (30s timeout).
pub(super) fn run_lint_check(
    project_dir: &Path,
    plugins: &[InstalledDoctorPlugin],
) -> Option<Check> {
    let plugin = plugins
        .iter()
        .find(|plugin| plugin.definition.name == "oxlint")?;
    Some(run_lint_check_with_binary(&plugin.binary, project_dir))
}

fn run_lint_check_with_binary(bin: &Path, project_dir: &Path) -> Check {
    let output = match run_tool_output_with_timeout(bin, &["."], project_dir, None) {
        Ok(output) => output,
        Err(error) => return Check::warn(&doctor_catalog::LINT_PROBE_FAILED, &error),
    };
    let code = output.status.code().unwrap_or(1);

    if code == 0 {
        return Check::pass(&doctor_catalog::LINT_CLEAN, "no issues");
    }

    // Try to parse oxlint summary line, fall back to exit code
    let stdout = String::from_utf8_lossy(&output.stdout);
    if let Some(summary) = stdout.lines().rev().find(|l| l.contains("Found")) {
        let has_errors = summary.contains("error");
        if has_errors {
            Check::fail(
                &doctor_catalog::LINT_ERRORS,
                &format!("{} — run: lpm lint --fix", summary.trim()),
            )
        } else {
            Check::warn(
                &doctor_catalog::LINT_WARNINGS,
                &format!("{} — run: lpm lint --fix", summary.trim()),
            )
        }
    } else {
        Check::warn(
            &doctor_catalog::LINT_UNPARSEABLE,
            &format!("exited with code {code} — run: lpm lint for details"),
        )
    }
}

/// Run biome format --check silently (30s timeout).
pub(super) fn run_fmt_check(
    project_dir: &Path,
    plugins: &[InstalledDoctorPlugin],
) -> Option<Check> {
    let plugin = plugins
        .iter()
        .find(|plugin| plugin.definition.name == "biome")?;
    Some(run_fmt_check_with_binary(&plugin.binary, project_dir))
}

fn run_fmt_check_with_binary(bin: &Path, project_dir: &Path) -> Check {
    let output =
        match run_tool_output_with_timeout(bin, &["format", "--check", "."], project_dir, None) {
            Ok(output) => output,
            Err(error) => return Check::warn(&doctor_catalog::FMT_PROBE_FAILED, &error),
        };
    let code = output.status.code().unwrap_or(1);

    if code == 0 {
        return Check::pass(&doctor_catalog::FMT_CLEAN, "all files formatted");
    }

    // Try to count unformatted files, fall back to exit code
    let stderr = String::from_utf8_lossy(&output.stderr);
    let count = stderr
        .lines()
        .filter(|l| l.contains("Formatter would have printed"))
        .count();
    if count > 0 {
        Check::warn(
            &doctor_catalog::FMT_UNFORMATTED,
            &format!("{count} file(s) need formatting — run: lpm fmt"),
        )
    } else {
        Check::warn(
            &doctor_catalog::FMT_OTHER_ISSUE,
            &format!("formatting issues found (exit {code}) — run: lpm fmt"),
        )
    }
}

/// TypeScript readiness checks — one per tsconfig-owning directory.
/// Workspace-aware: in a monorepo this emits a check for the root (if
/// it has a `tsconfig.json`) plus every member with a local
/// `tsconfig.json`.
///
/// Codes:
///
/// - `typescript_healthy` (pass) — `tsc` resolves through the local
///   `node_modules/.bin` chain. Editor (`tsserver` from
///   `node_modules/typescript`) and CI agree on the version.
/// - `typescript_missing_for_tsconfig` (warn) — `tsc` runs only via
///   the system `PATH`. The project lacks a local install, so editor
///   and CI may use a different version. Fix: `lpm install -D typescript`.
/// - `typescript_unavailable` (fail) — `tsc` cannot run at all. Fix
///   depends on whether `typescript` is already declared (run `lpm
///   install`) or needs to be added (run `lpm install -D typescript`).
pub(super) fn check_typescript_setup(
    project_dir: &Path,
    project_package: &lpm_workspace::PackageJson,
    workspace: Option<&lpm_workspace::Workspace>,
) -> Vec<Check> {
    let mut checks = Vec::new();

    let candidates = collect_tsconfig_candidates(project_dir, project_package, workspace);
    if candidates.is_empty() {
        return checks;
    }

    let root_declares_typescript = workspace.as_ref().is_some_and(|workspace| {
        crate::tsc_status::manifest_declares_typescript(&workspace.root_package)
    });
    let system_tsc = crate::tsc_status::find_system_tsc();
    let mut local_tsc = crate::tsc_status::LocalTscResolver::default();

    for (dir, package) in candidates {
        let in_deps =
            root_declares_typescript || crate::tsc_status::manifest_declares_typescript(package);
        let status = crate::tsc_status::TscStatus::probe_with_local_snapshot(
            local_tsc.find(&dir),
            system_tsc.as_deref(),
            in_deps,
        );
        let label = label_for_tsconfig(project_dir, &dir);

        if let Some(ref bin) = status.local_bin {
            checks.push(Check::pass(
                &doctor_catalog::TYPESCRIPT_HEALTHY,
                &format!("{label}local tsc resolves at {}", bin.display()),
            ));
        } else if status.system_bin.is_some() {
            checks.push(Check::warn(&doctor_catalog::TYPESCRIPT_MISSING_FOR_TSCONFIG, &format!(
                    "{label}using system tsc — editor + CI may diverge. Run: lpm install -D typescript"
                ),));
        } else if status.in_deps {
            checks.push(Check::fail(
                &doctor_catalog::TYPESCRIPT_UNAVAILABLE,
                &format!("{label}declared but not installed — run: lpm install"),
            ));
        } else {
            checks.push(Check::fail(
                &doctor_catalog::TYPESCRIPT_UNAVAILABLE,
                &format!("{label}not installed — run: lpm install -D typescript"),
            ));
        }
    }

    checks
}

/// Collect every directory in the workspace that owns a `tsconfig.json`.
/// Always includes `project_dir` if it has one. In a workspace, also
/// includes every member directory with a `tsconfig.json` — covers the
/// monorepo case where `run_typecheck` previously missed every member.
fn collect_tsconfig_candidates<'a>(
    project_dir: &Path,
    project_package: &'a lpm_workspace::PackageJson,
    workspace: Option<&'a lpm_workspace::Workspace>,
) -> Vec<(std::path::PathBuf, &'a lpm_workspace::PackageJson)> {
    let mut candidates = Vec::new();

    if project_dir.join("tsconfig.json").is_file() {
        candidates.push((project_dir.to_path_buf(), project_package));
    }

    if let Some(workspace) = workspace {
        for member in &workspace.members {
            if member.path == project_dir {
                continue;
            }
            if member.path.join("tsconfig.json").is_file() {
                candidates.push((member.path.clone(), &member.package));
            }
        }
    }

    candidates
}

/// Format a relative-path prefix for a tsconfig directory. Empty when
/// `dir` is the project root (the common single-package case).
fn label_for_tsconfig(project_dir: &Path, dir: &Path) -> String {
    if dir == project_dir {
        return String::new();
    }
    if let Ok(rel) = dir.strip_prefix(project_dir) {
        return format!("{}: ", rel.display());
    }
    format!("{}: ", dir.display())
}

/// Check installed plugins for available updates.
///
/// Fetches latest versions in parallel for all installed plugins.
pub(super) async fn check_plugins(plugins: &[InstalledDoctorPlugin]) -> Vec<Check> {
    let client = match lpm_plugin::versions::github_client() {
        Ok(client) => client,
        Err(error) => {
            return plugins
                .iter()
                .map(|plugin| {
                    Check::warn(
                        &doctor_catalog::PLUGIN_UPDATE_CHECK_FAILED,
                        &format!("{}: upstream check failed: {error}", plugin.definition.name),
                    )
                })
                .collect();
        }
    };
    let futures: Vec<_> = plugins
        .iter()
        .map(|plugin| {
            lpm_plugin::versions::peek_latest_from_github_with_client(plugin.definition, &client)
        })
        .collect();

    let latest_versions = futures::future::join_all(futures).await;

    let mut checks = Vec::new();
    for (plugin, latest) in plugins.iter().zip(latest_versions) {
        let def = plugin.definition;
        let current = &plugin.version;
        match latest {
            Ok(latest) if lpm_plugin::versions::is_newer_semver(&latest, current) => {
                checks.push(Check::warn_with_fix_target(
                    &doctor_catalog::PLUGIN_UPDATE_AVAILABLE,
                    &format!(
                        "{}: v{current} → v{latest} available — run: lpm plugin update {}",
                        def.name, def.name,
                    ),
                    FixTarget::PluginName(def.name.to_string()),
                ));
            }
            Ok(latest) => {
                let detail = if latest == *current {
                    format!("{}: v{current} (up to date)", def.name)
                } else {
                    format!("{}: v{current} (newer than upstream v{latest})", def.name)
                };
                checks.push(Check::pass(&doctor_catalog::PLUGIN_UP_TO_DATE, &detail));
            }
            Err(error) => checks.push(Check::warn(
                &doctor_catalog::PLUGIN_UPDATE_CHECK_FAILED,
                &format!("{}: upstream check failed: {error}", def.name),
            )),
        }
    }

    checks
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn wait_with_timeout_drains_full_stdout_and_stderr_pipes_before_child_exit() {
        let child = Command::new("sh")
            .args([
                "-c",
                "dd if=/dev/zero bs=1024 count=1024 2>/dev/null; \
                 printf '\\nstdout-complete\\n'; \
                 dd if=/dev/zero bs=1024 count=1024 1>&2 2>/dev/null; \
                 printf '\\nstderr-complete\\n' 1>&2",
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn pipe-filling child");

        let output = wait_with_timeout(child, Duration::from_secs(2))
            .expect("pipe-filling child must complete before the timeout");

        assert!(output.status.success(), "{output:?}");
        assert!(output.stdout.ends_with(b"stdout-complete\n"));
        assert!(output.stderr.ends_with(b"stderr-complete\n"));
    }

    #[test]
    fn wait_with_timeout_terminates_descendants_that_retain_output_pipes() {
        use std::os::unix::process::CommandExt as _;

        let mut command = Command::new("sh");
        command
            .args(["-c", "sleep 1 & exit 0"])
            .process_group(0)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let child = command.spawn().expect("spawn descendant-holding child");
        let started = Instant::now();

        let output = wait_with_timeout(child, Duration::from_millis(100))
            .expect("the direct child exits successfully");

        assert!(output.status.success());
        assert!(
            started.elapsed() < Duration::from_millis(500),
            "pipe readers must not wait for the one-second descendant: {:?}",
            started.elapsed()
        );
    }

    #[test]
    fn diagnostic_tools_do_not_inherit_ambient_secrets() {
        let secret_name = "LPM_DOCTOR_TOOL_UNIQUE_SECRET";
        let prior = std::env::var_os(secret_name);
        // SAFETY: this uniquely named variable is scoped to this test and restored below.
        unsafe { std::env::set_var(secret_name, "must-not-leak") };

        let output = run_tool_with_timeout(
            Path::new("/bin/sh"),
            &["-c", "printf '%s' \"$LPM_DOCTOR_TOOL_UNIQUE_SECRET\""],
            Path::new("/"),
            None,
        );

        match prior {
            Some(value) => unsafe { std::env::set_var(secret_name, value) },
            None => unsafe { std::env::remove_var(secret_name) },
        }
        let (stdout, _, _) = output.expect("run diagnostic environment probe");
        assert!(
            stdout.is_empty(),
            "diagnostic tool inherited a secret: {stdout:?}"
        );
    }

    #[test]
    fn lint_spawn_failure_emits_a_coded_probe_result() {
        let dir = tempfile::tempdir().unwrap();
        let check = run_lint_check_with_binary(&dir.path().join("missing-oxlint"), dir.path());

        assert_eq!(check.code(), "lint_probe_failed");
    }

    #[test]
    fn format_spawn_failure_emits_a_coded_probe_result() {
        let dir = tempfile::tempdir().unwrap();
        let check = run_fmt_check_with_binary(&dir.path().join("missing-biome"), dir.path());

        assert_eq!(check.code(), "fmt_probe_failed");
    }
}
