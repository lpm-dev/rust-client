use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;

use crate::doctor_catalog;

use super::check::Check;

/// Run a tool command with a 30-second timeout.
/// Returns (stdout, stderr, exit_code) or None on timeout/error.
fn run_tool_with_timeout(
    cmd: &Path,
    args: &[&str],
    cwd: &Path,
    extra_path: Option<&str>,
) -> Option<(String, String, i32)> {
    let mut command = Command::new(cmd);
    command
        .args(args)
        .current_dir(cwd)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    if let Some(path) = extra_path {
        command.env("PATH", path);
    }

    let child = command.spawn().ok()?;

    // Wait with timeout
    let output = wait_with_timeout(child, Duration::from_secs(30))?;
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let code = output.status.code().unwrap_or(1);

    Some((stdout, stderr, code))
}

/// Wait for a child process with timeout. Returns None if timed out.
///
/// Uses exponential backoff (10ms → 20ms → … → 200ms cap) to avoid busy-waiting
/// while still returning promptly for fast-completing tools.
fn wait_with_timeout(
    mut child: std::process::Child,
    timeout: Duration,
) -> Option<std::process::Output> {
    let start = std::time::Instant::now();
    let mut sleep_ms: u64 = 10;
    const MAX_SLEEP_MS: u64 = 200;

    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let stdout = child
                    .stdout
                    .map(|mut s| {
                        let mut buf = Vec::new();
                        std::io::Read::read_to_end(&mut s, &mut buf).ok();
                        buf
                    })
                    .unwrap_or_default();
                let stderr = child
                    .stderr
                    .map(|mut s| {
                        let mut buf = Vec::new();
                        std::io::Read::read_to_end(&mut s, &mut buf).ok();
                        buf
                    })
                    .unwrap_or_default();
                return Some(std::process::Output {
                    status,
                    stdout,
                    stderr,
                });
            }
            Ok(None) => {
                if start.elapsed() > timeout {
                    let _ = child.kill();
                    return None;
                }
                std::thread::sleep(Duration::from_millis(sleep_ms));
                sleep_ms = (sleep_ms * 2).min(MAX_SLEEP_MS);
            }
            Err(_) => return None,
        }
    }
}

/// Run oxlint silently and count errors/warnings (30s timeout).
pub(super) fn run_lint_check(project_dir: &Path) -> Option<Check> {
    let (_version, bin) = lpm_plugin::find_installed_for_current_platform("oxlint", "oxlint")?;

    let (stdout, _stderr, code) = run_tool_with_timeout(&bin, &["."], project_dir, None)?;

    if code == 0 {
        return Some(Check::pass(&doctor_catalog::LINT_CLEAN, "no issues"));
    }

    // Try to parse oxlint summary line, fall back to exit code
    if let Some(summary) = stdout.lines().rev().find(|l| l.contains("Found")) {
        let has_errors = summary.contains("error");
        if has_errors {
            Some(Check::fail(
                &doctor_catalog::LINT_ERRORS,
                &format!("{} — run: lpm lint --fix", summary.trim()),
            ))
        } else {
            Some(Check::warn(
                &doctor_catalog::LINT_WARNINGS,
                &format!("{} — run: lpm lint --fix", summary.trim()),
            ))
        }
    } else {
        // Fallback: couldn't parse output, use exit code
        Some(Check::warn(
            &doctor_catalog::LINT_UNPARSEABLE,
            &format!("exited with code {code} — run: lpm lint for details"),
        ))
    }
}

/// Run biome format --check silently (30s timeout).
pub(super) fn run_fmt_check(project_dir: &Path) -> Option<Check> {
    let (_version, bin) = lpm_plugin::find_installed_for_current_platform("biome", "biome")?;

    let (_stdout, stderr, code) =
        run_tool_with_timeout(&bin, &["format", "--check", "."], project_dir, None)?;

    if code == 0 {
        return Some(Check::pass(
            &doctor_catalog::FMT_CLEAN,
            "all files formatted",
        ));
    }

    // Try to count unformatted files, fall back to exit code
    let count = stderr
        .lines()
        .filter(|l| l.contains("Formatter would have printed"))
        .count();
    if count > 0 {
        Some(Check::warn(
            &doctor_catalog::FMT_UNFORMATTED,
            &format!("{count} file(s) need formatting — run: lpm fmt"),
        ))
    } else {
        Some(Check::warn(
            &doctor_catalog::FMT_OTHER_ISSUE,
            &format!("formatting issues found (exit {code}) — run: lpm fmt"),
        ))
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
pub(super) fn check_typescript_setup(project_dir: &Path) -> Vec<Check> {
    let mut checks = Vec::new();

    let dirs = collect_tsconfig_dirs(project_dir);
    if dirs.is_empty() {
        return checks;
    }

    for dir in dirs {
        let status = crate::tsc_status::TscStatus::probe(&dir);
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
fn collect_tsconfig_dirs(project_dir: &Path) -> Vec<std::path::PathBuf> {
    let mut dirs = Vec::new();

    if project_dir.join("tsconfig.json").is_file() {
        dirs.push(project_dir.to_path_buf());
    }

    if let Ok(Some(workspace)) = lpm_workspace::discover_workspace(project_dir) {
        for member in &workspace.members {
            if member.path == project_dir {
                continue;
            }
            if member.path.join("tsconfig.json").is_file() {
                dirs.push(member.path.clone());
            }
        }
    }

    dirs
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
pub(super) async fn check_plugins() -> Vec<Check> {
    let plugins: Vec<_> = lpm_plugin::registry::list_plugins()
        .iter()
        .filter_map(|def| {
            let installed =
                lpm_plugin::store::list_installed_versions(def.name).unwrap_or_default();
            if installed.is_empty() {
                return None;
            }
            Some((def, installed))
        })
        .collect();

    let futures: Vec<_> = plugins
        .iter()
        .map(|(def, _installed)| lpm_plugin::versions::get_latest_version(def))
        .collect();

    let latest_versions = futures::future::join_all(futures).await;

    let mut checks = Vec::new();
    for ((def, installed), latest) in plugins.iter().zip(latest_versions) {
        let Some(current) = installed.last() else {
            continue;
        };

        if *current == latest {
            checks.push(Check::pass(
                &doctor_catalog::PLUGIN_UP_TO_DATE,
                &format!("{}: v{current} (up to date)", def.name),
            ));
        } else {
            checks.push(Check::warn(
                &doctor_catalog::PLUGIN_UPDATE_AVAILABLE,
                &format!(
                    "{}: v{current} → v{latest} available — run: lpm plugin update {}",
                    def.name, def.name,
                ),
            ));
        }
    }

    checks
}
