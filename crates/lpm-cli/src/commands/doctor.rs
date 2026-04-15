use crate::{auth, output};
use lpm_common::LpmError;
use lpm_registry::RegistryClient;
use lpm_store::PackageStore;
use owo_colors::OwoColorize;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;

/// Check result with status icon.
struct Check {
    name: String,
    passed: bool,
    detail: String,
    severity: Severity,
}

#[derive(Clone, Copy)]
enum Severity {
    Pass,
    Fail,
    Warn,
}

impl Severity {
    fn as_str(&self) -> &'static str {
        match self {
            Severity::Pass => "pass",
            Severity::Fail => "fail",
            Severity::Warn => "warn",
        }
    }
}

impl Check {
    fn pass(name: &str, detail: &str) -> Self {
        Self {
            name: name.into(),
            passed: true,
            detail: detail.into(),
            severity: Severity::Pass,
        }
    }
    fn fail(name: &str, detail: &str) -> Self {
        Self {
            name: name.into(),
            passed: false,
            detail: detail.into(),
            severity: Severity::Fail,
        }
    }
    fn warn(name: &str, detail: &str) -> Self {
        Self {
            name: name.into(),
            passed: true,
            detail: detail.into(),
            severity: Severity::Warn,
        }
    }
}

/// Enhanced health check: verify auth, registry, store, project state, runtime, tools, lpm.json.
pub async fn run(
    client: &RegistryClient,
    registry_url: &str,
    project_dir: &Path,
    json_output: bool,
    fix: bool,
    _yes: bool,
) -> Result<(), LpmError> {
    if !json_output {
        output::print_header();
    }

    let mut checks: Vec<Check> = Vec::new();
    let mut fixes_applied: Vec<String> = Vec::new();

    // === Infrastructure (parallelized network calls) ===

    let token_exists = auth::get_token(registry_url).is_some();
    let (registry_result, auth_result) = tokio::join!(client.health_check(), async {
        if token_exists {
            client.whoami().await.is_ok()
        } else {
            false
        }
    });

    // 1. Registry reachable?
    let registry_ok = registry_result.unwrap_or(false);
    if registry_ok {
        checks.push(Check::pass("Registry", registry_url));
    } else {
        checks.push(Check::fail(
            "Registry",
            &format!("{registry_url} — unreachable. Check your network or try again later"),
        ));
    }

    // 2. Auth token valid?
    if auth_result {
        checks.push(Check::pass("Authentication", "valid token"));
    } else if token_exists {
        checks.push(Check::fail(
            "Authentication",
            "token exists but invalid — run: lpm login",
        ));
    } else {
        checks.push(Check::fail("Authentication", "no token — run: lpm login"));
    }

    // 3. Global store accessible?
    let store_result = PackageStore::default_location();
    let store_ok = store_result.is_ok();
    let store_detail = store_result
        .map(|s| s.root().display().to_string())
        .unwrap_or_else(|_| "inaccessible".into());
    if store_ok {
        checks.push(Check::pass("Global store", &store_detail));
    } else {
        checks.push(Check::fail("Global store", &store_detail));
    }

    // === Project State ===

    // 4. package.json exists?
    let pkg_json_path = project_dir.join("package.json");
    if pkg_json_path.exists() {
        checks.push(Check::pass("package.json", "found"));
    } else {
        checks.push(Check::fail(
            "package.json",
            "not found — run: lpm init (or cd to your project root)",
        ));
    }

    // 5. node_modules intact?
    let nm = project_dir.join("node_modules");
    if nm.exists() && nm.join(".lpm").exists() {
        checks.push(Check::pass("node_modules", "exists with .lpm store"));
    } else if nm.exists() {
        checks.push(Check::warn(
            "node_modules",
            "exists but no .lpm store — run: lpm install",
        ));
    } else {
        checks.push(Check::fail("node_modules", "not found — run: lpm install"));
    }

    // 6. Lockfile?
    let lockfile = project_dir.join("lpm.lock");
    checks.extend(check_lockfile_state(project_dir));

    // 6b. .gitattributes check
    checks.extend(check_gitattributes_state(project_dir));

    // 6c. Dependencies in sync? (lockfile vs package.json)
    if lockfile.exists()
        && pkg_json_path.exists()
        && let Some(sync_check) = check_deps_in_sync(project_dir)
    {
        checks.push(sync_check);
    }

    // === lpm.json Validation ===

    // 7. Validate lpm.json (if exists)
    if let Some(lpm_json_check) = validate_lpm_json(project_dir) {
        checks.push(lpm_json_check);
    }

    // === Runtime (Phase 2) ===

    // 8. Node.js version
    let detected = lpm_runtime::detect::detect_node_version(project_dir);
    if let Some(ref det) = detected {
        let system_node = get_system_node_version(project_dir);
        let managed_versions = lpm_runtime::node::list_installed().unwrap_or_default();

        let spec = &det.spec;
        let clean = spec
            .trim_start_matches(">=")
            .trim_start_matches('^')
            .trim_start_matches('~')
            .trim_start_matches('>');

        let matched_managed = lpm_runtime::node::find_matching_installed(clean, &managed_versions);

        if let Some(ver) = matched_managed {
            checks.push(Check::pass(
                "Node.js",
                &format!("v{ver} (managed, from {})", det.source),
            ));
        } else if let Some(sys) = &system_node {
            checks.push(Check::warn(
				"Node.js",
				&format!(
					"{sys} (system) — pinned {spec} from {} not installed. Run: lpm use node@{clean}",
					det.source
				),
			));
        } else {
            checks.push(Check::fail(
                "Node.js",
                &format!(
                    "not found — pinned {spec} from {}. Run: lpm use node@{clean}",
                    det.source
                ),
            ));
        }
    } else {
        let sys = get_system_node_version(project_dir);
        if let Some(v) = sys {
            checks.push(Check::pass(
                "Node.js",
                &format!("{v} (system, no version pinned)"),
            ));
        } else {
            checks.push(Check::fail("Node.js", "not found — run: lpm use node@22"));
        }
    }

    // === Tunnel (Phase 9) ===

    // 8b. Tunnel domain config — format validation + ownership check
    let tunnel_checks = check_tunnel_domain(project_dir, client, token_exists).await;
    checks.extend(tunnel_checks);

    // === Code Quality (Phase 4) ===

    // 9. Lint check (if oxlint installed)
    if let Some(lint_result) = run_lint_check(project_dir) {
        checks.push(lint_result);
    }

    // 10. Format check (if biome installed)
    if let Some(fmt_result) = run_fmt_check(project_dir) {
        checks.push(fmt_result);
    }

    // 11. TypeScript check (if tsc available)
    if let Some(ts_result) = run_typecheck(project_dir) {
        checks.push(ts_result);
    }

    // === Plugins (Phase 4) ===

    // 12. Plugin status
    let plugin_checks = check_plugins().await;
    checks.extend(plugin_checks);

    // === Workspace (Phase 3) ===

    // 13. Workspace health
    if let Some(ws_check) = check_workspace(project_dir) {
        checks.push(ws_check);
    }

    // === Global installs (Phase 37 M6.2) ===
    //
    // Four checks, all gated on the existence of `~/.lpm/global/`:
    //
    //   14. Manifest validity — reads + structurally validates it
    //   15. PATH presence — `~/.lpm/bin/` on $PATH
    //   16. Orphaned bin shims — files in bin_dir without a manifest owner
    //   17. Install-root consistency — every manifest entry's install root
    //                                  exists AND carries a ready marker
    for check in check_global_installs() {
        checks.push(check);
    }

    // === Auto-fix (runs before output so JSON includes fixes_applied) ===
    if fix {
        if !json_output {
            println!();
            output::info("Running auto-fix...");
            println!();
        }

        let mut install_ran = false;

        for check in &checks {
            match (check.severity.as_str(), check.name.as_str()) {
                ("fail", "node_modules") | ("warn", "node_modules") => {
                    if !install_ran {
                        if !json_output {
                            output::info("fixing: lpm install");
                        }
                        match run_doctor_install(client, project_dir).await {
                            Ok(()) => {
                                fixes_applied.push("lpm install".into());
                                install_ran = true;
                            }
                            Err(e) => eprintln!("  \x1b[31m✖\x1b[0m lpm install failed: {e}"),
                        }
                    }
                }
                ("fail", "Node.js") | ("warn", "Node.js") => {
                    if let Some(spec) = extract_node_spec_from_detail(&check.detail) {
                        if !json_output {
                            output::info(&format!("fixing: lpm use node@{spec}"));
                        }
                        let http_client = reqwest::Client::builder()
                            .timeout(std::time::Duration::from_secs(60))
                            .build()
                            .map_err(|e| LpmError::Network(format!("{e}")))?;
                        let platform = lpm_runtime::platform::Platform::current()?;
                        let releases = lpm_runtime::node::fetch_index(&http_client).await;
                        if let Ok(releases) = releases
                            && let Some(release) =
                                lpm_runtime::node::resolve_version(&releases, &spec)
                        {
                            match lpm_runtime::download::install_node(
                                &http_client,
                                &release,
                                &platform,
                            )
                            .await
                            {
                                Ok(ver) => fixes_applied.push(format!("installed node {ver}")),
                                Err(e) => eprintln!("  \x1b[31m✖\x1b[0m node install failed: {e}"),
                            }
                        }
                    }
                }
                ("warn", "Format (biome)") => {
                    if !json_output {
                        output::info("fixing: lpm fmt");
                    }
                    let result = crate::commands::tools::fmt(project_dir, &[], false, false).await;
                    match result {
                        Ok(()) => fixes_applied.push("lpm fmt".into()),
                        Err(e) => eprintln!("  \x1b[31m✖\x1b[0m lpm fmt failed: {e}"),
                    }
                }
                ("warn", "Lockfile") => {
                    if !install_ran {
                        if !json_output {
                            output::info("fixing: lpm install (generates lockfile)");
                        }
                        match run_doctor_install(client, project_dir).await {
                            Ok(()) => {
                                fixes_applied.push("lpm install (lockfile)".into());
                                install_ran = true;
                            }
                            Err(e) => eprintln!("  \x1b[31m✖\x1b[0m lpm install failed: {e}"),
                        }
                    }
                }
                ("warn", "Deps sync") => {
                    if !install_ran {
                        if !json_output {
                            output::info("fixing: lpm install (sync lockfile)");
                        }
                        match run_doctor_install(client, project_dir).await {
                            Ok(()) => {
                                fixes_applied.push("lpm install (deps sync)".into());
                                install_ran = true;
                            }
                            Err(e) => eprintln!("  \x1b[31m✖\x1b[0m lpm install failed: {e}"),
                        }
                    }
                }
                ("warn", "Binary lockfile") => {
                    if !json_output {
                        output::info("fixing: regenerating lpm.lockb from lpm.lock");
                    }
                    match fix_binary_lockfile(project_dir) {
                        Ok(()) => fixes_applied.push("regenerated lpm.lockb".into()),
                        Err(e) => eprintln!("  \x1b[31m✖\x1b[0m {e}"),
                    }
                }
                ("warn", ".gitattributes") => {
                    if !json_output {
                        output::info("fixing: ensuring .gitattributes marks lpm.lockb as binary");
                    }
                    match fix_gitattributes(project_dir) {
                        Ok(()) => fixes_applied.push("updated .gitattributes".into()),
                        Err(e) => eprintln!("  \x1b[31m✖\x1b[0m {e}"),
                    }
                }
                ("warn", "Tunnel") if check.detail.contains("not claimed") => {
                    // Extract domain from detail: "acme-api.lpm.llc — not claimed ..."
                    if let Some(domain) = check.detail.split(" —").next() {
                        let domain = domain.trim();
                        if !json_output {
                            output::info(&format!("fixing: lpm tunnel claim {domain}"));
                        }
                        match client.tunnel_claim(domain, None).await {
                            Ok(_) => {
                                fixes_applied.push(format!("claimed tunnel domain {domain}"));
                            }
                            Err(e) => {
                                eprintln!("  \x1b[31m✖\x1b[0m tunnel claim failed: {e}");
                            }
                        }
                    }
                }
                _ => {}
            }
        }

        if !json_output {
            if fixes_applied.is_empty() {
                output::info("no auto-fixable issues found");
            } else {
                println!();
                output::success(&format!(
                    "applied {} fix(es): {}",
                    fixes_applied.len(),
                    fixes_applied.join(", ")
                ));
                println!("\n  Run {} to verify fixes.", "lpm doctor".bold());
            }
        }
    }

    // === Output (after fixes so JSON includes fixes_applied) ===

    if json_output {
        let results: Vec<_> = checks
            .iter()
            .map(|c| {
                serde_json::json!({
                    "check": c.name,
                    "passed": c.passed,
                    "severity": c.severity.as_str(),
                    "detail": c.detail,
                })
            })
            .collect();
        let no_failures = checks.iter().all(|c| c.passed);
        let has_warnings = checks.iter().any(|c| matches!(c.severity, Severity::Warn));
        let clean = no_failures && !has_warnings;
        let warning_count = checks
            .iter()
            .filter(|c| matches!(c.severity, Severity::Warn))
            .count();
        let passed_count = checks.iter().filter(|c| c.passed).count();
        let failed_count = checks.iter().filter(|c| !c.passed).count();
        let output = serde_json::to_string_pretty(&serde_json::json!({
            "success": true,
            "no_failures": no_failures,
            "clean": clean,
            "has_warnings": has_warnings,
            "checks": results,
            "passed": passed_count,
            "failed": failed_count,
            "warnings": warning_count,
            "fixes_applied": fixes_applied,
        }))
        .map_err(|e| LpmError::Script(format!("failed to serialize doctor output: {e}")))?;
        println!("{output}");
    } else {
        println!();
        for check in &checks {
            let icon = match check.severity {
                Severity::Pass => "✔".green().to_string(),
                Severity::Fail => "✖".red().to_string(),
                Severity::Warn => "⚠".yellow().to_string(),
            };
            println!("  {icon} {} {}", check.name.bold(), check.detail.dimmed());
        }
        println!();

        let failed = checks.iter().filter(|c| !c.passed).count();
        let warned = checks
            .iter()
            .filter(|c| matches!(c.severity, Severity::Warn))
            .count();
        let total = checks.len();

        if failed == 0 && warned == 0 {
            output::success(&format!("All {total} checks passed"));
        } else if failed == 0 {
            output::success(&format!(
                "{} checks passed, {} warning(s)",
                total - warned,
                warned
            ));
        } else {
            output::warn(&format!("{failed} check(s) failed, {warned} warning(s)"));
        }
        println!();
    }

    // Exit code 1 when any check has hard failures (not warnings)
    let has_failures = checks.iter().any(|c| !c.passed);
    if has_failures {
        return Err(LpmError::ExitCode(1));
    }

    Ok(())
}

/// Extract node version spec from doctor detail message.
fn extract_node_spec_from_detail(detail: &str) -> Option<String> {
    // "... pinned >=22 from ... Run: lpm use node@22"
    if let Some(pos) = detail.find("node@") {
        let after = &detail[pos + 5..];
        let end = after
            .find(|c: char| c.is_whitespace() || c == '"')
            .unwrap_or(after.len());
        return Some(after[..end].to_string());
    }
    // Fallback: "not found — run: lpm use node@22"
    None
}

// --- Check helpers ---

/// Get system Node.js version by running `node --version`.
fn get_system_node_version(project_dir: &Path) -> Option<String> {
    let path = lpm_runner::bin_path::build_path_with_bins(project_dir);
    let output = Command::new("node")
        .arg("--version")
        .env("PATH", &path)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .ok()?;

    if output.status.success() {
        Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
    } else {
        None
    }
}

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
fn run_lint_check(project_dir: &Path) -> Option<Check> {
    let versions = lpm_plugin::store::list_installed_versions("oxlint").ok()?;
    let version = versions.first()?;
    let bin = lpm_plugin::store::plugin_binary_path("oxlint", version, "oxlint").ok()?;

    if !bin.exists() {
        return None;
    }

    let (stdout, _stderr, code) = run_tool_with_timeout(&bin, &["."], project_dir, None)?;

    if code == 0 {
        return Some(Check::pass("Lint (oxlint)", "no issues"));
    }

    // Try to parse oxlint summary line, fall back to exit code
    if let Some(summary) = stdout.lines().rev().find(|l| l.contains("Found")) {
        let has_errors = summary.contains("error");
        if has_errors {
            Some(Check::fail(
                "Lint (oxlint)",
                &format!("{} — run: lpm lint --fix", summary.trim()),
            ))
        } else {
            Some(Check::warn(
                "Lint (oxlint)",
                &format!("{} — run: lpm lint --fix", summary.trim()),
            ))
        }
    } else {
        // Fallback: couldn't parse output, use exit code
        Some(Check::warn(
            "Lint (oxlint)",
            &format!("exited with code {code} — run: lpm lint for details"),
        ))
    }
}

/// Run biome format --check silently (30s timeout).
fn run_fmt_check(project_dir: &Path) -> Option<Check> {
    let versions = lpm_plugin::store::list_installed_versions("biome").ok()?;
    let version = versions.first()?;
    let bin = lpm_plugin::store::plugin_binary_path("biome", version, "biome").ok()?;

    if !bin.exists() {
        return None;
    }

    let (_stdout, stderr, code) =
        run_tool_with_timeout(&bin, &["format", "--check", "."], project_dir, None)?;

    if code == 0 {
        return Some(Check::pass("Format (biome)", "all files formatted"));
    }

    // Try to count unformatted files, fall back to exit code
    let count = stderr
        .lines()
        .filter(|l| l.contains("Formatter would have printed"))
        .count();
    if count > 0 {
        Some(Check::warn(
            "Format (biome)",
            &format!("{count} file(s) need formatting — run: lpm fmt"),
        ))
    } else {
        Some(Check::warn(
            "Format (biome)",
            &format!("formatting issues found (exit {code}) — run: lpm fmt"),
        ))
    }
}

/// Run tsc --noEmit silently (30s timeout).
fn run_typecheck(project_dir: &Path) -> Option<Check> {
    if !project_dir.join("tsconfig.json").exists() {
        return None;
    }

    let path = lpm_runner::bin_path::build_path_with_bins(project_dir);
    let tsc_path = std::path::PathBuf::from("tsc");

    let (stdout, _stderr, code) =
        run_tool_with_timeout(&tsc_path, &["--noEmit"], project_dir, Some(&path))?;

    if code == 0 {
        return Some(Check::pass("TypeScript", "no type errors"));
    }

    // Try to count TS errors, fall back to exit code
    let error_count = stdout.lines().filter(|l| l.contains("error TS")).count();
    if error_count > 0 {
        Some(Check::fail(
            "TypeScript",
            &format!("{error_count} type error(s) — run: lpm check"),
        ))
    } else {
        Some(Check::fail(
            "TypeScript",
            &format!("type errors found (exit {code}) — run: lpm check"),
        ))
    }
}

/// Check installed plugins for available updates.
///
/// Fetches latest versions in parallel for all installed plugins.
async fn check_plugins() -> Vec<Check> {
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
        .map(|(def, _installed)| lpm_plugin::versions::get_latest_version(def, false))
        .collect();

    let latest_versions = futures::future::join_all(futures).await;

    let mut checks = Vec::new();
    for ((def, installed), latest) in plugins.iter().zip(latest_versions) {
        let Some(current) = installed.last() else {
            continue;
        };

        if *current == latest {
            checks.push(Check::pass(
                &format!("Plugin: {}", def.name),
                &format!("v{current} (up to date)"),
            ));
        } else {
            checks.push(Check::warn(
                &format!("Plugin: {}", def.name),
                &format!(
                    "v{current} → v{latest} available — run: lpm plugin update {}",
                    def.name
                ),
            ));
        }
    }

    checks
}

/// Check workspace graph for cycles.
fn check_workspace(project_dir: &Path) -> Option<Check> {
    let workspace = lpm_workspace::discover_workspace(project_dir).ok()??;
    let graph = lpm_task::graph::WorkspaceGraph::from_workspace(&workspace);

    match graph.topological_sort() {
        Ok(sorted) => Some(Check::pass(
            "Workspace",
            &format!("{} packages, no dependency cycles", sorted.len()),
        )),
        Err(e) => Some(Check::fail(
            "Workspace",
            &format!("{e} — resolve circular dependencies"),
        )),
    }
}

/// Check tunnel domain configuration from lpm.json.
///
/// Performs format validation (RFC 1035/1123 compliance, subdomain constraints,
/// known base domain whitelist), ownership check (via registry API when authenticated),
/// and HTTP reachability check for claimed domains.
async fn check_tunnel_domain(
    project_dir: &Path,
    client: &RegistryClient,
    is_authenticated: bool,
) -> Vec<Check> {
    let config = match lpm_runner::lpm_json::read_lpm_json(project_dir) {
        Ok(Some(c)) => c,
        _ => return vec![],
    };
    let tunnel = match config.tunnel {
        Some(t) => t,
        None => return vec![],
    };
    let domain = match tunnel.domain {
        Some(d) => d,
        None => return vec![],
    };

    let mut checks = Vec::new();

    // RFC-compliant domain length checks (RFC 1035 / RFC 1123)
    if domain.len() > 253 {
        checks.push(Check::warn(
            "Tunnel",
            &format!(
                "domain \"{}\" exceeds 253 character limit ({} chars)",
                domain,
                domain.len()
            ),
        ));
        return checks;
    }

    // Check each label: max 63 chars, no empty labels (consecutive dots)
    for label in domain.split('.') {
        if label.is_empty() {
            checks.push(Check::warn(
                "Tunnel",
                &format!("domain \"{domain}\" contains empty label (consecutive dots)"),
            ));
            return checks;
        }
        if label.len() > 63 {
            checks.push(Check::warn(
                "Tunnel",
                &format!(
                    "domain label \"{}\" exceeds 63 character limit ({} chars)",
                    label,
                    label.len()
                ),
            ));
            return checks;
        }
    }

    // Validate domain format: must have at least one dot
    if !domain.contains('.') {
        checks.push(Check::warn(
            "Tunnel",
            &format!(
                "\"{}\" is not a full domain — use: {}.lpm.fyi or {}.lpm.llc",
                domain, domain, domain
            ),
        ));
        return checks;
    }

    // Split into subdomain + base domain (guaranteed to have a dot from check above)
    let parts: Vec<&str> = domain.splitn(2, '.').collect();
    let subdomain = parts[0];
    let base_domain = parts[1];

    // Check subdomain format
    if subdomain.len() < 3 || subdomain.len() > 32 {
        checks.push(Check::warn(
            "Tunnel",
            &format!("subdomain \"{subdomain}\" must be 3-32 characters"),
        ));
        return checks;
    }
    if !subdomain
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        checks.push(Check::warn(
            "Tunnel",
            &format!("subdomain \"{subdomain}\" must be lowercase alphanumeric + hyphens"),
        ));
        return checks;
    }
    if subdomain.starts_with('-') || subdomain.ends_with('-') {
        checks.push(Check::warn(
            "Tunnel",
            &format!("subdomain \"{subdomain}\" must not start or end with a hyphen"),
        ));
        return checks;
    }

    // Check known base domains — only deployed domains
    let known_bases = ["lpm.fyi", "lpm.llc"];
    if !known_bases.contains(&base_domain) {
        checks.push(Check::warn(
            "Tunnel",
            &format!(
                "unknown base domain \"{base_domain}\" (available: {})",
                known_bases.join(", ")
            ),
        ));
        return checks;
    }

    // === Ownership check (requires auth) ===
    if !is_authenticated {
        checks.push(Check::pass(
            "Tunnel",
            &format!("{domain} (configured, login to verify ownership)"),
        ));
        return checks;
    }

    // Check if domain is claimed by this user via registry API
    match client.tunnel_domain_lookup(&domain).await {
        Ok(result) => {
            let found = result["found"].as_bool().unwrap_or(false);
            let owned = result["ownedByYou"].as_bool().unwrap_or(false);

            if !found {
                checks.push(Check::warn(
                    "Tunnel",
                    &format!("{domain} — not claimed. Run: lpm tunnel claim {domain}"),
                ));
                return checks;
            }

            if !owned {
                checks.push(Check::warn(
                    "Tunnel",
                    &format!("{domain} — claimed by another user or org"),
                ));
                return checks;
            }

            // Domain is claimed and owned — check reachability
            let reachability = check_tunnel_reachability(&domain).await;
            match reachability {
                TunnelReachability::Active => {
                    checks.push(Check::pass(
                        "Tunnel",
                        &format!("{domain} (claimed, active)"),
                    ));
                }
                TunnelReachability::Idle => {
                    checks.push(Check::pass("Tunnel", &format!("{domain} (claimed, idle)")));
                }
                TunnelReachability::Unreachable => {
                    checks.push(Check::warn(
                        "Tunnel",
                        &format!("{domain} (claimed) — unreachable, DNS may not be configured"),
                    ));
                }
            }
        }
        Err(_) => {
            // API call failed — fall back to format-only validation
            checks.push(Check::pass(
                "Tunnel",
                &format!("{domain} (configured, could not verify ownership)"),
            ));
        }
    }

    checks
}

enum TunnelReachability {
    Active,
    Idle,
    Unreachable,
}

/// Quick HTTP HEAD check to see if a tunnel domain is reachable.
async fn check_tunnel_reachability(domain: &str) -> TunnelReachability {
    let url = format!("https://{domain}");
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
    {
        Ok(c) => c,
        Err(_) => return TunnelReachability::Unreachable,
    };

    match client.head(&url).send().await {
        Ok(resp) => {
            let status = resp.status().as_u16();
            if status == 404 {
                // Worker returns 404 when tunnel is not active
                TunnelReachability::Idle
            } else {
                TunnelReachability::Active
            }
        }
        Err(_) => TunnelReachability::Unreachable,
    }
}

/// Check lockfile (lpm.lock + lpm.lockb) state: exists, in sync, valid.
fn check_lockfile_state(project_dir: &Path) -> Vec<Check> {
    let lockfile = project_dir.join("lpm.lock");
    let lockb_path = project_dir.join("lpm.lockb");
    let mut checks = Vec::new();

    if lockfile.exists() {
        checks.push(Check::pass("Lockfile", "lpm.lock"));

        if lockb_path.exists() {
            // Binary exists — check if in sync
            let toml_mtime = lockfile.metadata().and_then(|m| m.modified()).ok();
            let bin_mtime = lockb_path.metadata().and_then(|m| m.modified()).ok();

            let is_stale = match (toml_mtime, bin_mtime) {
                (Some(t), Some(b)) => b < t,
                _ => false,
            };

            if is_stale {
                checks.push(Check::warn(
                    "Binary lockfile",
                    "lpm.lockb is stale — run lpm install to regenerate",
                ));
            } else {
                // Validate header
                match lpm_lockfile::binary::BinaryLockfileReader::open(&lockb_path) {
                    Ok(Some(_)) => {
                        checks.push(Check::pass("Binary lockfile", "lpm.lockb (in sync, valid)"))
                    }
                    Ok(None) => {} // shouldn't happen since we checked exists
                    Err(_) => {
                        checks.push(Check::warn(
                            "Binary lockfile",
                            "lpm.lockb is corrupt — run lpm install to regenerate",
                        ));
                    }
                }
            }
        } else {
            checks.push(Check::warn(
                "Binary lockfile",
                "lpm.lockb missing — run lpm install to generate",
            ));
        }
    } else {
        checks.push(Check::warn(
            "Lockfile",
            "not found — run: lpm install to generate",
        ));
    }

    checks
}

/// Check .gitattributes state: exists and has lpm.lockb binary marker.
fn check_gitattributes_state(project_dir: &Path) -> Vec<Check> {
    let lockfile = project_dir.join("lpm.lock");
    let lockb_path = project_dir.join("lpm.lockb");
    let ga_path = project_dir.join(".gitattributes");
    let mut checks = Vec::new();

    if lockb_path.exists() || lockfile.exists() {
        if ga_path.exists() {
            let ga_content = std::fs::read_to_string(&ga_path).unwrap_or_default();
            if ga_content.lines().any(|l| l.trim() == "lpm.lockb binary") {
                checks.push(Check::pass(".gitattributes", "lpm.lockb marked as binary"));
            } else {
                checks.push(Check::warn(
                    ".gitattributes",
                    "lpm.lockb not marked as binary — run lpm install to fix",
                ));
            }
        } else {
            checks.push(Check::warn(
                ".gitattributes",
                "missing — run lpm install to create (marks lpm.lockb as binary)",
            ));
        }
    }

    checks
}

/// Run `lpm install` with doctor-appropriate defaults (no security summary, no JSON output).
async fn run_doctor_install(client: &RegistryClient, project_dir: &Path) -> Result<(), LpmError> {
    crate::commands::install::run_with_options(
        client,
        project_dir,
        false, // json_output
        false, // offline
        false, // force
        false, // allow_new
        None,  // linker_override
        false, // no_skills
        false, // no_editor_setup
        true,  // no_security_summary
        false, // auto_build
        None,  // target_set: doctor is single-project
        None,  // direct_versions_out: doctor does not finalize Phase 33 placeholders
    )
    .await
}

/// Fix: regenerate `lpm.lockb` from `lpm.lock`.
fn fix_binary_lockfile(project_dir: &Path) -> Result<(), String> {
    let lock_path = project_dir.join("lpm.lock");
    if !lock_path.exists() {
        return Err("lpm.lock not found — cannot regenerate lpm.lockb".into());
    }
    let lf = lpm_lockfile::Lockfile::read_from_file(&lock_path)
        .map_err(|e| format!("read lpm.lock failed: {e}"))?;
    let lockb = project_dir.join("lpm.lockb");
    lpm_lockfile::binary::write_binary(&lf, &lockb)
        .map_err(|e| format!("write lpm.lockb failed: {e}"))
}

/// Fix: ensure `.gitattributes` marks `lpm.lockb` as binary.
fn fix_gitattributes(project_dir: &Path) -> Result<(), String> {
    lpm_lockfile::ensure_gitattributes(project_dir)
        .map_err(|e| format!(".gitattributes update failed: {e}"))
}

/// Check if lockfile dependencies match package.json dependencies.
///
/// Reads dep names from package.json and checks if they all appear in lpm.lock.
/// Detects "lockfile out of date" drift.
fn check_deps_in_sync(project_dir: &Path) -> Option<Check> {
    let pkg_json_path = project_dir.join("package.json");
    let lockfile_path = project_dir.join("lpm.lock");

    let pkg_content = std::fs::read_to_string(&pkg_json_path).ok()?;
    let pkg: serde_json::Value = serde_json::from_str(&pkg_content).ok()?;

    let lockfile = lpm_lockfile::Lockfile::read_from_file(&lockfile_path).ok()?;

    // Collect all dep names from package.json
    let mut declared_deps: Vec<String> = Vec::new();
    if let Some(deps) = pkg.get("dependencies").and_then(|d| d.as_object()) {
        for key in deps.keys() {
            declared_deps.push(key.clone());
        }
    }
    if let Some(deps) = pkg.get("devDependencies").and_then(|d| d.as_object()) {
        for key in deps.keys() {
            declared_deps.push(key.clone());
        }
    }

    if declared_deps.is_empty() {
        return None; // No deps to check
    }

    // Check which deps are missing from lockfile using proper lockfile parsing
    let mut missing: Vec<&str> = Vec::new();
    for dep in &declared_deps {
        if lockfile.find_package(dep).is_none() {
            missing.push(dep);
        }
    }

    if missing.is_empty() {
        Some(Check::pass("Deps sync", "lockfile matches package.json"))
    } else if missing.len() <= 3 {
        Some(Check::warn(
            "Deps sync",
            &format!(
                "lockfile missing: {} — run: lpm install",
                missing.join(", ")
            ),
        ))
    } else {
        Some(Check::warn(
            "Deps sync",
            &format!(
                "{} deps not in lockfile ({}, ...) — run: lpm install",
                missing.len(),
                missing[..2].join(", ")
            ),
        ))
    }
}

/// Validate lpm.json structure and known fields.
///
/// Checks:
/// - Valid JSON syntax
/// - Known top-level fields (runtime, env, tasks, tools, services, tunnel, publish, https)
/// - runtime.node is a valid version spec
/// - tasks have valid structure (command, dependsOn, cache, outputs, inputs, env)
/// - tools reference known plugins
/// - services have required command field
/// - Falls back to serde deserialization for type-level validation
fn validate_lpm_json(project_dir: &Path) -> Option<Check> {
    let lpm_json_path = project_dir.join("lpm.json");
    if !lpm_json_path.exists() {
        return None; // No lpm.json is fine — it's optional
    }

    let content = match std::fs::read_to_string(&lpm_json_path) {
        Ok(c) => c,
        Err(e) => {
            return Some(Check::fail("lpm.json", &format!("cannot read: {e}")));
        }
    };

    // 1. Valid JSON?
    let doc: serde_json::Value = match serde_json::from_str(&content) {
        Ok(v) => v,
        Err(e) => {
            return Some(Check::fail(
                "lpm.json",
                &format!("invalid JSON at line {} — {}", e.line(), e),
            ));
        }
    };

    let obj = match doc.as_object() {
        Some(o) => o,
        None => {
            return Some(Check::fail(
                "lpm.json",
                "must be a JSON object, not an array or primitive",
            ));
        }
    };

    let mut warnings: Vec<String> = Vec::new();

    // 2. Check for unknown top-level fields
    let known_fields = [
        "runtime", "env", "tasks", "tools", "services", "tunnel", "publish", "https",
    ];
    for key in obj.keys() {
        if !known_fields.contains(&key.as_str()) {
            warnings.push(format!("unknown field \"{key}\""));
        }
    }

    // 3. Validate runtime section
    if let Some(runtime) = obj.get("runtime") {
        if let Some(runtime_obj) = runtime.as_object() {
            for (rt_name, rt_value) in runtime_obj {
                if rt_name != "node" {
                    warnings.push(format!(
                        "runtime \"{rt_name}\" not yet supported (only \"node\")"
                    ));
                }
                if !rt_value.is_string() {
                    warnings.push(format!("runtime.{rt_name} must be a string version spec"));
                }
            }
        } else {
            warnings.push("\"runtime\" must be an object".into());
        }
    }

    // 4. Validate tasks section
    if let Some(tasks) = obj.get("tasks") {
        if let Some(tasks_obj) = tasks.as_object() {
            let known_task_fields = ["command", "dependsOn", "cache", "outputs", "inputs", "env"];
            for (task_name, task_value) in tasks_obj {
                if let Some(task_obj) = task_value.as_object() {
                    for key in task_obj.keys() {
                        if !known_task_fields.contains(&key.as_str()) {
                            warnings.push(format!("tasks.{task_name}: unknown field \"{key}\""));
                        }
                    }
                    // cache must be bool
                    if let Some(cache) = task_obj.get("cache")
                        && !cache.is_boolean()
                    {
                        warnings.push(format!("tasks.{task_name}.cache must be a boolean"));
                    }
                    // outputs and inputs must be arrays of strings
                    for field in ["outputs", "inputs"] {
                        if let Some(arr) = task_obj.get(field)
                            && !arr.is_array()
                        {
                            warnings.push(format!("tasks.{task_name}.{field} must be an array"));
                        }
                    }
                    // dependsOn must be array of strings
                    if let Some(deps) = task_obj.get("dependsOn")
                        && !deps.is_array()
                    {
                        warnings.push(format!("tasks.{task_name}.dependsOn must be an array"));
                    }
                } else {
                    warnings.push(format!("tasks.{task_name} must be an object"));
                }
            }
        } else {
            warnings.push("\"tasks\" must be an object".into());
        }
    }

    // 5. Validate tools section
    if let Some(tools) = obj.get("tools") {
        if let Some(tools_obj) = tools.as_object() {
            let known_tools: Vec<&str> = lpm_plugin::registry::list_plugins()
                .iter()
                .map(|p| p.name)
                .collect();
            for (tool_name, tool_value) in tools_obj {
                if !known_tools.contains(&tool_name.as_str()) {
                    warnings.push(format!(
                        "tools.{tool_name}: unknown plugin (available: {})",
                        known_tools.join(", ")
                    ));
                }
                if !tool_value.is_string() {
                    warnings.push(format!("tools.{tool_name} must be a version string"));
                }
            }
        } else {
            warnings.push("\"tools\" must be an object".into());
        }
    }

    // 6. Validate services section
    if let Some(services) = obj.get("services") {
        if let Some(services_obj) = services.as_object() {
            for (svc_name, svc_value) in services_obj {
                if let Some(svc_obj) = svc_value.as_object() {
                    if !svc_obj.contains_key("command") {
                        warnings.push(format!(
                            "services.{svc_name}: missing required \"command\" field"
                        ));
                    }
                } else {
                    warnings.push(format!("services.{svc_name} must be an object"));
                }
            }
        } else {
            warnings.push("\"services\" must be an object".into());
        }
    }

    // Also try parsing with the actual struct to catch serde errors
    if let Err(e) = serde_json::from_str::<lpm_runner::lpm_json::LpmJsonConfig>(&content) {
        warnings.push(format!("schema error: {e}"));
    }

    if warnings.is_empty() {
        Some(Check::pass("lpm.json", "valid"))
    } else if warnings.len() == 1 {
        Some(Check::warn("lpm.json", &warnings[0]))
    } else {
        Some(Check::warn(
            "lpm.json",
            &format!("{} issues: {}", warnings.len(), warnings.join("; ")),
        ))
    }
}

// ─── Phase 37 M6.2: global-installs health checks ─────────────────────

/// Top-level entry for the global health checks. Returns an empty Vec
/// if `~/.lpm/global/` doesn't exist (fresh machine / project-only
/// user) — doctor shouldn't invent checks for features the user hasn't
/// touched.
///
/// Each check has its own function so individual checks can be
/// unit-tested against a synthetic `LpmRoot` without running the whole
/// `doctor::run` pipeline.
fn check_global_installs() -> Vec<Check> {
    let root = match lpm_common::LpmRoot::from_env() {
        Ok(r) => r,
        Err(_) => return Vec::new(),
    };
    // Nothing to check if the global tree was never created.
    if !root.global_root().exists() {
        return Vec::new();
    }

    let mut out = Vec::new();

    // 14. Manifest validity.
    out.push(check_global_manifest_validity(&root));

    // The rest only make sense if the manifest read cleanly; otherwise
    // skip to avoid cascading errors that reference a corrupt
    // manifest's rows. The `check_global_manifest_validity` check
    // already surfaces the read error.
    let Ok(manifest) = lpm_global::read_for(&root) else {
        return out;
    };

    // 15. PATH presence.
    out.push(check_bin_dir_on_path(&root));

    // 16. Orphaned bin shims.
    out.push(check_orphaned_bin_shims(&root, &manifest));

    // 17. Install-root consistency.
    out.push(check_install_root_consistency(&root, &manifest));

    out
}

fn check_global_manifest_validity(root: &lpm_common::LpmRoot) -> Check {
    let path = root.global_manifest();
    if !path.exists() {
        return Check::pass("Global manifest", "not present (no global installs yet)");
    }
    match lpm_global::read_for(root) {
        Ok(manifest) => Check::pass(
            "Global manifest",
            &format!(
                "{} package{}, {} alias{}, {} tombstone{}",
                manifest.packages.len(),
                if manifest.packages.len() == 1 {
                    ""
                } else {
                    "s"
                },
                manifest.aliases.len(),
                if manifest.aliases.len() == 1 {
                    ""
                } else {
                    "es"
                },
                manifest.tombstones.len(),
                if manifest.tombstones.len() == 1 {
                    ""
                } else {
                    "s"
                },
            ),
        ),
        Err(e) => Check::fail(
            "Global manifest",
            &format!(
                "{}: {e}. Fix hint: inspect the file or delete it to reset the global tree.",
                path.display(),
            ),
        ),
    }
}

fn check_bin_dir_on_path(root: &lpm_common::LpmRoot) -> Check {
    let bin_dir = root.bin_dir();
    let path_env = std::env::var("PATH").unwrap_or_default();
    if crate::path_onboarding::is_bin_dir_on_path_str(&bin_dir, &path_env) {
        Check::pass("Global bin on PATH", &bin_dir.display().to_string())
    } else {
        Check::warn(
            "Global bin on PATH",
            &format!(
                "{} not on PATH. Fix hint: add it to your shell init (see `lpm global bin`).",
                bin_dir.display(),
            ),
        )
    }
}

fn check_orphaned_bin_shims(
    root: &lpm_common::LpmRoot,
    manifest: &lpm_global::GlobalManifest,
) -> Check {
    let bin_dir = root.bin_dir();
    if !bin_dir.exists() {
        return Check::pass("Orphaned shims", "bin dir does not exist yet");
    }
    // A shim is a file whose stem matches a package command or alias
    // name. On Windows, any member of the triple (`.cmd`, `.ps1`, no
    // suffix) counts; on Unix just the bare name.
    let owned_names: std::collections::HashSet<String> = manifest
        .packages
        .values()
        .flat_map(|e| e.commands.iter().cloned())
        .chain(manifest.aliases.keys().cloned())
        .collect();

    let mut orphans: Vec<String> = Vec::new();
    let Ok(entries) = std::fs::read_dir(&bin_dir) else {
        return Check::warn(
            "Orphaned shims",
            &format!("could not read {}", bin_dir.display()),
        );
    };
    for entry in entries.flatten() {
        let name_os = entry.file_name();
        let Some(name_str) = name_os.to_str() else {
            continue;
        };
        // Derive stem: strip a single known extension if present.
        let stem = name_str
            .strip_suffix(".cmd")
            .or_else(|| name_str.strip_suffix(".ps1"))
            .unwrap_or(name_str);
        if !owned_names.contains(stem) {
            orphans.push(name_str.to_string());
        }
    }
    orphans.sort();
    orphans.dedup();

    if orphans.is_empty() {
        Check::pass(
            "Orphaned shims",
            &format!(
                "{} owned shim{} in {}",
                owned_names.len(),
                if owned_names.len() == 1 { "" } else { "s" },
                bin_dir.display(),
            ),
        )
    } else {
        let preview: Vec<String> = orphans.iter().take(5).cloned().collect();
        let more = if orphans.len() > preview.len() {
            format!(", +{} more", orphans.len() - preview.len())
        } else {
            String::new()
        };
        Check::warn(
            "Orphaned shims",
            &format!(
                "{} shim{} in {} not owned by any manifest entry ({}{}). Fix hint: \
                 `lpm store gc` sweeps tombstoned roots but does not rm orphaned shims; \
                 remove manually or re-run the owning install to reclaim.",
                orphans.len(),
                if orphans.len() == 1 { "" } else { "s" },
                bin_dir.display(),
                preview.join(", "),
                more,
            ),
        )
    }
}

fn check_install_root_consistency(
    root: &lpm_common::LpmRoot,
    manifest: &lpm_global::GlobalManifest,
) -> Check {
    if manifest.packages.is_empty() {
        return Check::pass("Global install roots", "no packages to check");
    }
    let mut missing: Vec<String> = Vec::new();
    let mut unready: Vec<String> = Vec::new();
    for (name, entry) in &manifest.packages {
        let install_root = root.global_root().join(&entry.root);
        if !install_root.exists() {
            missing.push(name.clone());
            continue;
        }
        // Marker presence: `.lpm-install-ready` under the install root.
        match lpm_global::read_marker(&install_root) {
            Ok(Some(_)) => {} // healthy
            Ok(None) | Err(_) => unready.push(name.clone()),
        }
    }
    missing.sort();
    unready.sort();

    if missing.is_empty() && unready.is_empty() {
        return Check::pass(
            "Global install roots",
            &format!(
                "{} root{} healthy",
                manifest.packages.len(),
                if manifest.packages.len() == 1 {
                    ""
                } else {
                    "s"
                },
            ),
        );
    }
    let mut issues: Vec<String> = Vec::new();
    if !missing.is_empty() {
        issues.push(format!("{} missing: {}", missing.len(), missing.join(", ")));
    }
    if !unready.is_empty() {
        issues.push(format!(
            "{} without `.lpm-install-ready` marker: {}",
            unready.len(),
            unready.join(", "),
        ));
    }
    Check::fail(
        "Global install roots",
        &format!(
            "{}. Fix hint: `lpm uninstall -g <pkg>` and re-install to rebuild the install root.",
            issues.join("; "),
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_pass_sets_passed_true() {
        let c = Check::pass("test", "ok");
        assert!(c.passed);
        assert!(matches!(c.severity, Severity::Pass));
    }

    #[test]
    fn check_fail_sets_passed_false() {
        let c = Check::fail("test", "bad");
        assert!(!c.passed);
        assert!(matches!(c.severity, Severity::Fail));
    }

    #[test]
    fn check_warn_sets_passed_true_but_severity_warn() {
        let c = Check::warn("test", "meh");
        assert!(c.passed);
        assert!(matches!(c.severity, Severity::Warn));
    }

    #[test]
    fn warning_count_with_mixed_checks() {
        let checks = [
            Check::pass("a", "ok"),
            Check::warn("b", "meh"),
            Check::fail("c", "bad"),
            Check::warn("d", "meh2"),
        ];

        let warning_count = checks
            .iter()
            .filter(|c| matches!(c.severity, Severity::Warn))
            .count();
        let failed_count = checks.iter().filter(|c| !c.passed).count();
        let no_failures = checks.iter().all(|c| c.passed);
        let has_warnings = checks.iter().any(|c| matches!(c.severity, Severity::Warn));
        let clean = no_failures && !has_warnings;

        assert_eq!(warning_count, 2);
        assert_eq!(failed_count, 1);
        assert!(!no_failures); // fail check makes no_failures false
        assert!(has_warnings);
        assert!(!clean);
    }

    #[test]
    fn no_failures_true_with_warnings_but_clean_false() {
        // Warnings don't count as failures, but the run is not "clean"
        let checks = [Check::pass("a", "ok"), Check::warn("b", "meh")];
        let no_failures = checks.iter().all(|c| c.passed);
        let has_warnings = checks.iter().any(|c| matches!(c.severity, Severity::Warn));
        let clean = no_failures && !has_warnings;

        assert!(no_failures);
        assert!(has_warnings);
        assert!(!clean);
    }

    #[test]
    fn clean_true_only_when_all_pass_no_warnings() {
        let checks = [Check::pass("a", "ok"), Check::pass("b", "fine")];
        let no_failures = checks.iter().all(|c| c.passed);
        let has_warnings = checks.iter().any(|c| matches!(c.severity, Severity::Warn));
        let clean = no_failures && !has_warnings;

        assert!(no_failures);
        assert!(!has_warnings);
        assert!(clean);
    }

    #[test]
    fn deps_sync_uses_exact_name_matching() {
        // Bug: naive string search with `contains("name = \"a\"")` would match
        // a package named "react" if we searched for "a" because "a" appears inside "react".
        // The old code used `lock_content.contains(...)` which is too loose.
        // With proper lockfile parsing via find_package(), only exact matches work.
        let dir = tempfile::tempdir().unwrap();

        // Create package.json with dep "a"
        let pkg_json = serde_json::json!({
            "dependencies": {
                "a": "^1.0.0"
            }
        });
        std::fs::write(
            dir.path().join("package.json"),
            serde_json::to_string_pretty(&pkg_json).unwrap(),
        )
        .unwrap();

        // Create lockfile with "react" but NOT "a"
        let mut lockfile = lpm_lockfile::Lockfile::new();
        lockfile.add_package(lpm_lockfile::LockedPackage {
            name: "react".to_string(),
            version: "18.0.0".to_string(),
            source: None,
            integrity: None,
            dependencies: vec![],
        });
        lockfile
            .write_to_file(&dir.path().join("lpm.lock"))
            .unwrap();

        let result = check_deps_in_sync(dir.path());
        let check = result.expect("should return a check");
        // "a" should be reported as missing — it is NOT in the lockfile
        assert!(
            matches!(check.severity, Severity::Warn),
            "dep 'a' should be missing from lockfile"
        );
        assert!(
            check.detail.contains("a"),
            "detail should mention missing dep 'a'"
        );
    }

    #[test]
    fn deps_sync_finds_exact_match() {
        let dir = tempfile::tempdir().unwrap();

        let pkg_json = serde_json::json!({
            "dependencies": {
                "react": "^18.0.0"
            }
        });
        std::fs::write(
            dir.path().join("package.json"),
            serde_json::to_string_pretty(&pkg_json).unwrap(),
        )
        .unwrap();

        let mut lockfile = lpm_lockfile::Lockfile::new();
        lockfile.add_package(lpm_lockfile::LockedPackage {
            name: "react".to_string(),
            version: "18.0.0".to_string(),
            source: None,
            integrity: None,
            dependencies: vec![],
        });
        lockfile
            .write_to_file(&dir.path().join("lpm.lock"))
            .unwrap();

        let result = check_deps_in_sync(dir.path());
        let check = result.expect("should return a check");
        assert!(
            matches!(check.severity, Severity::Pass),
            "react should be found in lockfile"
        );
    }

    #[test]
    fn extract_node_spec_works() {
        let detail = "not found — pinned >=22 from .nvmrc. Run: lpm use node@22";
        let spec = extract_node_spec_from_detail(detail);
        assert_eq!(spec, Some("22".to_string()));
    }

    #[test]
    fn extract_node_spec_none_when_missing() {
        let detail = "v20.0.0 (system, no version pinned)";
        let spec = extract_node_spec_from_detail(detail);
        assert!(spec.is_none());
    }

    // ── Lockfile state checks ───────────────────────────────────────────

    #[test]
    fn lockfile_check_no_lockfile_warns() {
        let dir = tempfile::tempdir().unwrap();
        let checks = check_lockfile_state(dir.path());
        assert_eq!(checks.len(), 1);
        assert_eq!(checks[0].name, "Lockfile");
        assert!(matches!(checks[0].severity, Severity::Warn));
        assert!(checks[0].detail.contains("not found"));
    }

    #[test]
    fn lockfile_check_toml_only_warns_missing_binary() {
        let dir = tempfile::tempdir().unwrap();
        let lf = lpm_lockfile::Lockfile::new();
        lf.write_to_file(&dir.path().join("lpm.lock")).unwrap();

        let checks = check_lockfile_state(dir.path());
        assert_eq!(checks.len(), 2);
        assert_eq!(checks[0].name, "Lockfile");
        assert!(matches!(checks[0].severity, Severity::Pass));
        assert_eq!(checks[1].name, "Binary lockfile");
        assert!(matches!(checks[1].severity, Severity::Warn));
        assert!(checks[1].detail.contains("missing"));
    }

    #[test]
    fn lockfile_check_both_in_sync_passes() {
        let dir = tempfile::tempdir().unwrap();
        let lf = lpm_lockfile::Lockfile::new();
        // Write TOML first, then binary (so binary is newer)
        lf.write_to_file(&dir.path().join("lpm.lock")).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(50));
        lpm_lockfile::binary::write_binary(&lf, &dir.path().join("lpm.lockb")).unwrap();

        let checks = check_lockfile_state(dir.path());
        assert_eq!(checks.len(), 2);
        assert!(matches!(checks[0].severity, Severity::Pass));
        assert_eq!(checks[1].name, "Binary lockfile");
        assert!(matches!(checks[1].severity, Severity::Pass));
        assert!(checks[1].detail.contains("in sync, valid"));
    }

    #[test]
    fn lockfile_check_stale_binary_warns() {
        let dir = tempfile::tempdir().unwrap();
        let lf = lpm_lockfile::Lockfile::new();
        // Write binary first (older), then TOML (newer)
        lpm_lockfile::binary::write_binary(&lf, &dir.path().join("lpm.lockb")).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(50));
        lf.write_to_file(&dir.path().join("lpm.lock")).unwrap();

        let checks = check_lockfile_state(dir.path());
        assert_eq!(checks.len(), 2);
        assert_eq!(checks[1].name, "Binary lockfile");
        assert!(matches!(checks[1].severity, Severity::Warn));
        assert!(checks[1].detail.contains("stale"));
    }

    #[test]
    fn lockfile_check_corrupt_binary_warns() {
        let dir = tempfile::tempdir().unwrap();
        let lf = lpm_lockfile::Lockfile::new();
        lf.write_to_file(&dir.path().join("lpm.lock")).unwrap();
        // Write corrupt binary (newer than TOML)
        std::thread::sleep(std::time::Duration::from_millis(50));
        std::fs::write(dir.path().join("lpm.lockb"), b"BADMxxxxxxxxxxxxxxxxx").unwrap();

        let checks = check_lockfile_state(dir.path());
        assert_eq!(checks.len(), 2);
        assert_eq!(checks[1].name, "Binary lockfile");
        assert!(matches!(checks[1].severity, Severity::Warn));
        assert!(checks[1].detail.contains("corrupt"));
    }

    // ── .gitattributes state checks ─────────────────────────────────────

    #[test]
    fn gitattributes_check_skipped_without_lockfiles() {
        let dir = tempfile::tempdir().unwrap();
        // No lpm.lock or lpm.lockb — should produce no checks
        let checks = check_gitattributes_state(dir.path());
        assert!(checks.is_empty());
    }

    #[test]
    fn gitattributes_check_missing_warns() {
        let dir = tempfile::tempdir().unwrap();
        let lf = lpm_lockfile::Lockfile::new();
        lf.write_to_file(&dir.path().join("lpm.lock")).unwrap();
        // No .gitattributes file

        let checks = check_gitattributes_state(dir.path());
        assert_eq!(checks.len(), 1);
        assert!(matches!(checks[0].severity, Severity::Warn));
        assert!(checks[0].detail.contains("missing"));
    }

    #[test]
    fn gitattributes_check_without_marker_warns() {
        let dir = tempfile::tempdir().unwrap();
        let lf = lpm_lockfile::Lockfile::new();
        lf.write_to_file(&dir.path().join("lpm.lock")).unwrap();
        std::fs::write(dir.path().join(".gitattributes"), "*.png binary\n").unwrap();

        let checks = check_gitattributes_state(dir.path());
        assert_eq!(checks.len(), 1);
        assert!(matches!(checks[0].severity, Severity::Warn));
        assert!(checks[0].detail.contains("not marked as binary"));
    }

    #[test]
    fn gitattributes_check_with_marker_passes() {
        let dir = tempfile::tempdir().unwrap();
        let lf = lpm_lockfile::Lockfile::new();
        lf.write_to_file(&dir.path().join("lpm.lock")).unwrap();
        std::fs::write(
            dir.path().join(".gitattributes"),
            "# lpm\nlpm.lockb binary\n",
        )
        .unwrap();

        let checks = check_gitattributes_state(dir.path());
        assert_eq!(checks.len(), 1);
        assert!(matches!(checks[0].severity, Severity::Pass));
        assert!(checks[0].detail.contains("marked as binary"));
    }

    // ── Fix execution tests ─────────────────────────────────────────────

    #[test]
    fn fix_binary_lockfile_regenerates_from_toml() {
        let dir = tempfile::tempdir().unwrap();
        let mut lf = lpm_lockfile::Lockfile::new();
        lf.add_package(lpm_lockfile::LockedPackage {
            name: "react".to_string(),
            version: "18.0.0".to_string(),
            source: Some("registry+https://registry.npmjs.org".to_string()),
            integrity: None,
            dependencies: vec![],
        });
        lf.write_to_file(&dir.path().join("lpm.lock")).unwrap();

        // No lpm.lockb exists yet
        assert!(!dir.path().join("lpm.lockb").exists());

        // Fix should create it
        fix_binary_lockfile(dir.path()).unwrap();
        assert!(dir.path().join("lpm.lockb").exists());

        // The regenerated binary should be valid and contain the same data
        let reader =
            lpm_lockfile::binary::BinaryLockfileReader::open(&dir.path().join("lpm.lockb"))
                .unwrap()
                .unwrap();
        assert_eq!(reader.package_count(), 1);
        let pkg = reader.find_package("react").unwrap();
        assert_eq!(pkg.version(), "18.0.0");
    }

    #[test]
    fn fix_binary_lockfile_overwrites_corrupt() {
        let dir = tempfile::tempdir().unwrap();
        let lf = lpm_lockfile::Lockfile::new();
        lf.write_to_file(&dir.path().join("lpm.lock")).unwrap();

        // Write corrupt binary
        std::fs::write(dir.path().join("lpm.lockb"), b"GARBAGE_DATA").unwrap();

        // Fix should overwrite with valid binary
        fix_binary_lockfile(dir.path()).unwrap();

        let reader =
            lpm_lockfile::binary::BinaryLockfileReader::open(&dir.path().join("lpm.lockb"))
                .unwrap()
                .unwrap();
        assert_eq!(reader.package_count(), 0);
    }

    #[test]
    fn fix_binary_lockfile_fails_without_toml() {
        let dir = tempfile::tempdir().unwrap();
        // No lpm.lock
        let result = fix_binary_lockfile(dir.path());
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not found"));
    }

    #[test]
    fn fix_gitattributes_creates_file() {
        let dir = tempfile::tempdir().unwrap();
        assert!(!dir.path().join(".gitattributes").exists());

        fix_gitattributes(dir.path()).unwrap();

        let content = std::fs::read_to_string(dir.path().join(".gitattributes")).unwrap();
        assert!(content.contains("lpm.lockb binary"));
    }

    #[test]
    fn fix_gitattributes_appends_to_existing() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(".gitattributes"), "*.png binary\n").unwrap();

        fix_gitattributes(dir.path()).unwrap();

        let content = std::fs::read_to_string(dir.path().join(".gitattributes")).unwrap();
        assert!(content.contains("*.png binary"));
        assert!(content.contains("lpm.lockb binary"));
    }

    // ── Tunnel domain checks (format validation, no auth) ──────────

    #[tokio::test]
    async fn tunnel_check_skipped_without_lpm_json() {
        let dir = tempfile::tempdir().unwrap();
        let client = RegistryClient::new();
        let checks = check_tunnel_domain(dir.path(), &client, false).await;
        assert!(checks.is_empty(), "no tunnel check when no lpm.json");
    }

    #[tokio::test]
    async fn tunnel_check_skipped_without_tunnel_config() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("lpm.json"),
            r#"{ "runtime": { "node": "22" } }"#,
        )
        .unwrap();
        let client = RegistryClient::new();
        let checks = check_tunnel_domain(dir.path(), &client, false).await;
        assert!(checks.is_empty(), "no tunnel check when no tunnel section");
    }

    #[tokio::test]
    async fn tunnel_check_warns_bare_domain() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("lpm.json"),
            r#"{ "tunnel": { "domain": "acme" } }"#,
        )
        .unwrap();
        let client = RegistryClient::new();
        let checks = check_tunnel_domain(dir.path(), &client, false).await;
        assert_eq!(checks.len(), 1);
        assert!(matches!(checks[0].severity, Severity::Warn));
        assert!(checks[0].detail.contains("not a full domain"));
    }

    #[tokio::test]
    async fn tunnel_check_warns_unknown_base_domain() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("lpm.json"),
            r#"{ "tunnel": { "domain": "acme.lpm.run" } }"#,
        )
        .unwrap();
        let client = RegistryClient::new();
        let checks = check_tunnel_domain(dir.path(), &client, false).await;
        assert_eq!(checks.len(), 1);
        assert!(matches!(checks[0].severity, Severity::Warn));
        assert!(
            checks[0].detail.contains("unknown base domain"),
            "should reject unannounced lpm.run: {}",
            checks[0].detail
        );
    }

    #[tokio::test]
    async fn tunnel_check_passes_valid_domain_unauthenticated() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("lpm.json"),
            r#"{ "tunnel": { "domain": "acme-api.lpm.llc" } }"#,
        )
        .unwrap();
        let client = RegistryClient::new();
        let checks = check_tunnel_domain(dir.path(), &client, false).await;
        assert_eq!(checks.len(), 1);
        assert!(matches!(checks[0].severity, Severity::Pass));
        assert!(checks[0].detail.contains("configured"));
        assert!(checks[0].detail.contains("login to verify"));
    }

    #[tokio::test]
    async fn tunnel_check_warns_short_subdomain() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("lpm.json"),
            r#"{ "tunnel": { "domain": "ab.lpm.fyi" } }"#,
        )
        .unwrap();
        let client = RegistryClient::new();
        let checks = check_tunnel_domain(dir.path(), &client, false).await;
        assert_eq!(checks.len(), 1);
        assert!(matches!(checks[0].severity, Severity::Warn));
        assert!(checks[0].detail.contains("3-32 characters"));
    }

    #[tokio::test]
    async fn tunnel_check_warns_uppercase_subdomain() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("lpm.json"),
            r#"{ "tunnel": { "domain": "ACME.lpm.fyi" } }"#,
        )
        .unwrap();
        let client = RegistryClient::new();
        let checks = check_tunnel_domain(dir.path(), &client, false).await;
        assert_eq!(checks.len(), 1);
        assert!(matches!(checks[0].severity, Severity::Warn));
        assert!(checks[0].detail.contains("lowercase"));
    }

    #[tokio::test]
    async fn tunnel_check_warns_leading_hyphen() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("lpm.json"),
            r#"{ "tunnel": { "domain": "-acme.lpm.fyi" } }"#,
        )
        .unwrap();
        let client = RegistryClient::new();
        let checks = check_tunnel_domain(dir.path(), &client, false).await;
        assert_eq!(checks.len(), 1);
        assert!(matches!(checks[0].severity, Severity::Warn));
        assert!(
            checks[0]
                .detail
                .contains("must not start or end with a hyphen"),
            "should reject leading hyphen: {}",
            checks[0].detail
        );
    }

    #[tokio::test]
    async fn tunnel_check_warns_trailing_hyphen() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("lpm.json"),
            r#"{ "tunnel": { "domain": "acme-.lpm.llc" } }"#,
        )
        .unwrap();
        let client = RegistryClient::new();
        let checks = check_tunnel_domain(dir.path(), &client, false).await;
        assert_eq!(checks.len(), 1);
        assert!(matches!(checks[0].severity, Severity::Warn));
        assert!(
            checks[0]
                .detail
                .contains("must not start or end with a hyphen"),
            "should reject trailing hyphen: {}",
            checks[0].detail
        );
    }

    // ── validate_lpm_json tests ────────────────────────────────────────

    #[test]
    fn validate_lpm_json_no_file_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        assert!(validate_lpm_json(dir.path()).is_none());
    }

    #[test]
    fn validate_lpm_json_empty_object_passes() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("lpm.json"), "{}").unwrap();
        let result = validate_lpm_json(dir.path());
        let check = result.expect("should return a check");
        assert!(
            matches!(check.severity, Severity::Pass),
            "empty object should pass: {}",
            check.detail
        );
    }

    #[test]
    fn validate_lpm_json_invalid_json_fails() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("lpm.json"), "{ not json").unwrap();
        let result = validate_lpm_json(dir.path()).unwrap();
        assert!(matches!(result.severity, Severity::Fail));
        assert!(result.detail.contains("invalid JSON"));
    }

    #[test]
    fn validate_lpm_json_array_root_fails() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("lpm.json"), "[1, 2, 3]").unwrap();
        let result = validate_lpm_json(dir.path()).unwrap();
        assert!(matches!(result.severity, Severity::Fail));
        assert!(result.detail.contains("must be a JSON object"));
    }

    #[test]
    fn validate_lpm_json_unknown_field_warns() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("lpm.json"), r#"{ "bogus_field": true }"#).unwrap();
        let result = validate_lpm_json(dir.path()).unwrap();
        assert!(matches!(result.severity, Severity::Warn));
        assert!(result.detail.contains("unknown field \"bogus_field\""));
    }

    #[test]
    fn validate_lpm_json_publish_field_accepted() {
        // Regression test for Finding #1: publish is a valid LpmJsonConfig field
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("lpm.json"),
            r#"{ "publish": { "registries": ["lpm"] } }"#,
        )
        .unwrap();
        let result = validate_lpm_json(dir.path());
        let check = result.expect("should return a check");
        assert!(
            matches!(check.severity, Severity::Pass),
            "publish should be accepted: {}",
            check.detail
        );
    }

    #[test]
    fn validate_lpm_json_https_field_accepted() {
        // Regression test for Finding #1: https is a valid LpmJsonConfig field
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("lpm.json"), r#"{ "https": true }"#).unwrap();
        let result = validate_lpm_json(dir.path());
        let check = result.expect("should return a check");
        assert!(
            matches!(check.severity, Severity::Pass),
            "https should be accepted: {}",
            check.detail
        );
    }

    #[test]
    fn validate_lpm_json_vault_field_rejected() {
        // vault is NOT in LpmJsonConfig — should be flagged as unknown
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("lpm.json"), r#"{ "vault": {} }"#).unwrap();
        let result = validate_lpm_json(dir.path()).unwrap();
        assert!(
            matches!(result.severity, Severity::Warn),
            "vault should be unknown: {}",
            result.detail
        );
        assert!(result.detail.contains("unknown field \"vault\""));
    }

    #[test]
    fn validate_lpm_json_all_known_fields_pass() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("lpm.json"),
            r#"{
                "runtime": { "node": ">=22" },
                "env": { "dev": ".env.development" },
                "tasks": { "build": { "command": "tsc" } },
                "tools": {},
                "services": { "web": { "command": "next dev" } },
                "tunnel": { "domain": "acme.lpm.fyi" },
                "publish": { "registries": ["lpm", "npm"] },
                "https": true
            }"#,
        )
        .unwrap();
        let result = validate_lpm_json(dir.path());
        let check = result.expect("should return a check");
        assert!(
            matches!(check.severity, Severity::Pass),
            "all known fields should pass: {}",
            check.detail
        );
    }

    #[test]
    fn validate_lpm_json_runtime_non_object_warns() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("lpm.json"), r#"{ "runtime": "node" }"#).unwrap();
        let result = validate_lpm_json(dir.path()).unwrap();
        assert!(matches!(result.severity, Severity::Warn));
        assert!(result.detail.contains("must be an object"));
    }

    #[test]
    fn validate_lpm_json_runtime_unsupported_warns() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("lpm.json"),
            r#"{ "runtime": { "deno": ">=2.0.0" } }"#,
        )
        .unwrap();
        let result = validate_lpm_json(dir.path()).unwrap();
        assert!(matches!(result.severity, Severity::Warn));
        assert!(result.detail.contains("not yet supported"));
    }

    #[test]
    fn validate_lpm_json_tasks_string_value_warns() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("lpm.json"),
            r#"{ "tasks": { "build": "tsc" } }"#,
        )
        .unwrap();
        let result = validate_lpm_json(dir.path()).unwrap();
        assert!(matches!(result.severity, Severity::Warn));
        assert!(result.detail.contains("must be an object"));
    }

    #[test]
    fn validate_lpm_json_task_unknown_field_warns() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("lpm.json"),
            r#"{ "tasks": { "build": { "command": "tsc", "bogus": true } } }"#,
        )
        .unwrap();
        let result = validate_lpm_json(dir.path()).unwrap();
        assert!(matches!(result.severity, Severity::Warn));
        assert!(result.detail.contains("unknown field \"bogus\""));
    }

    #[test]
    fn validate_lpm_json_task_cache_non_bool_warns() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("lpm.json"),
            r#"{ "tasks": { "build": { "command": "tsc", "cache": "yes" } } }"#,
        )
        .unwrap();
        let result = validate_lpm_json(dir.path()).unwrap();
        assert!(matches!(result.severity, Severity::Warn));
        assert!(result.detail.contains("cache must be a boolean"));
    }

    #[test]
    fn validate_lpm_json_task_outputs_non_array_warns() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("lpm.json"),
            r#"{ "tasks": { "build": { "command": "tsc", "outputs": "dist" } } }"#,
        )
        .unwrap();
        let result = validate_lpm_json(dir.path()).unwrap();
        assert!(matches!(result.severity, Severity::Warn));
        assert!(result.detail.contains("outputs must be an array"));
    }

    #[test]
    fn validate_lpm_json_task_depends_on_non_array_warns() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("lpm.json"),
            r#"{ "tasks": { "test": { "command": "vitest", "dependsOn": "build" } } }"#,
        )
        .unwrap();
        let result = validate_lpm_json(dir.path()).unwrap();
        assert!(matches!(result.severity, Severity::Warn));
        assert!(result.detail.contains("dependsOn must be an array"));
    }

    #[test]
    fn validate_lpm_json_tools_non_object_warns() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("lpm.json"), r#"{ "tools": "biome" }"#).unwrap();
        let result = validate_lpm_json(dir.path()).unwrap();
        assert!(matches!(result.severity, Severity::Warn));
        assert!(result.detail.contains("must be an object"));
    }

    #[test]
    fn validate_lpm_json_services_missing_command_warns() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("lpm.json"),
            r#"{ "services": { "api": { "port": 3000 } } }"#,
        )
        .unwrap();
        let result = validate_lpm_json(dir.path()).unwrap();
        assert!(matches!(result.severity, Severity::Warn));
        assert!(result.detail.contains("missing required \"command\""));
    }

    #[test]
    fn validate_lpm_json_services_non_object_warns() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("lpm.json"), r#"{ "services": "web" }"#).unwrap();
        let result = validate_lpm_json(dir.path()).unwrap();
        assert!(matches!(result.severity, Severity::Warn));
        assert!(result.detail.contains("must be an object"));
    }

    #[test]
    fn validate_lpm_json_multiple_issues_counted() {
        let dir = tempfile::tempdir().unwrap();
        // 2 unknown fields + runtime non-object + serde schema error = 4 issues
        std::fs::write(
            dir.path().join("lpm.json"),
            r#"{ "bogus1": 1, "bogus2": 2, "runtime": "bad" }"#,
        )
        .unwrap();
        let result = validate_lpm_json(dir.path()).unwrap();
        assert!(matches!(result.severity, Severity::Warn));
        assert!(
            result.detail.contains("issues"),
            "should report multiple issues: {}",
            result.detail
        );
        // Verify it's more than 1 issue (the exact count depends on serde fallback too)
        assert!(
            result.detail.starts_with("4 issues") || result.detail.starts_with("3 issues"),
            "should have 3-4 issues: {}",
            result.detail
        );
    }

    // ─── Phase 37 M6.2: global-installs health checks ─────────────────

    use chrono::Utc;
    use lpm_common::LpmRoot;
    use lpm_global::{
        GlobalManifest, InstallReadyMarker, PackageEntry, PackageSource, write_marker,
    };

    fn pkg_entry(rel_root: &str) -> PackageEntry {
        PackageEntry {
            saved_spec: "^1".into(),
            resolved: "1.0.0".into(),
            integrity: "sha512-z".into(),
            source: PackageSource::UpstreamNpm,
            installed_at: Utc::now(),
            root: rel_root.into(),
            commands: vec!["bin-a".into()],
        }
    }

    #[test]
    fn check_global_manifest_validity_passes_when_manifest_reads_cleanly() {
        let tmp = tempfile::tempdir().unwrap();
        let root = LpmRoot::from_dir(tmp.path());
        let mut manifest = GlobalManifest::default();
        manifest
            .packages
            .insert("eslint".into(), pkg_entry("installs/eslint@9.24.0"));
        lpm_global::write_for(&root, &manifest).unwrap();

        let check = check_global_manifest_validity(&root);
        assert!(matches!(check.severity, Severity::Pass));
        assert!(check.detail.contains("1 package"));
    }

    #[test]
    fn check_global_manifest_validity_passes_when_absent() {
        let tmp = tempfile::tempdir().unwrap();
        let root = LpmRoot::from_dir(tmp.path());
        let check = check_global_manifest_validity(&root);
        assert!(matches!(check.severity, Severity::Pass));
        assert!(check.detail.contains("not present"));
    }

    #[test]
    fn check_global_manifest_validity_fails_when_malformed() {
        let tmp = tempfile::tempdir().unwrap();
        let root = LpmRoot::from_dir(tmp.path());
        std::fs::create_dir_all(root.global_root()).unwrap();
        std::fs::write(root.global_manifest(), b"not = valid = toml ; ;").unwrap();
        let check = check_global_manifest_validity(&root);
        assert!(matches!(check.severity, Severity::Fail));
        assert!(
            check.detail.contains("Fix hint"),
            "fail check must include a fix hint: {}",
            check.detail
        );
    }

    #[test]
    fn check_bin_dir_on_path_passes_when_bin_dir_in_path_env() {
        let tmp = tempfile::tempdir().unwrap();
        let root = LpmRoot::from_dir(tmp.path());
        let bin = root.bin_dir().display().to_string();
        // Serialize PATH mutation the same way path_onboarding's tests do.
        static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let prev = std::env::var("PATH").ok();
        unsafe {
            std::env::set_var("PATH", bin);
        }
        let check = check_bin_dir_on_path(&root);
        unsafe {
            match prev {
                Some(v) => std::env::set_var("PATH", v),
                None => std::env::remove_var("PATH"),
            }
        }
        assert!(matches!(check.severity, Severity::Pass));
    }

    #[test]
    fn check_bin_dir_on_path_warns_when_bin_dir_missing_from_path() {
        let tmp = tempfile::tempdir().unwrap();
        let root = LpmRoot::from_dir(tmp.path());
        static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let prev = std::env::var("PATH").ok();
        unsafe {
            std::env::set_var("PATH", "/usr/bin:/bin");
        }
        let check = check_bin_dir_on_path(&root);
        unsafe {
            match prev {
                Some(v) => std::env::set_var("PATH", v),
                None => std::env::remove_var("PATH"),
            }
        }
        assert!(matches!(check.severity, Severity::Warn));
        assert!(check.detail.contains("Fix hint"));
    }

    #[test]
    fn check_orphaned_bin_shims_passes_when_bin_dir_contains_only_owned_names() {
        let tmp = tempfile::tempdir().unwrap();
        let root = LpmRoot::from_dir(tmp.path());
        let bin_dir = root.bin_dir();
        std::fs::create_dir_all(&bin_dir).unwrap();
        std::fs::write(bin_dir.join("bin-a"), b"").unwrap();

        let mut manifest = GlobalManifest::default();
        manifest
            .packages
            .insert("pkg".into(), pkg_entry("installs/pkg@1.0.0"));
        let check = check_orphaned_bin_shims(&root, &manifest);
        assert!(matches!(check.severity, Severity::Pass));
    }

    #[test]
    fn check_orphaned_bin_shims_warns_when_extra_files_present() {
        let tmp = tempfile::tempdir().unwrap();
        let root = LpmRoot::from_dir(tmp.path());
        let bin_dir = root.bin_dir();
        std::fs::create_dir_all(&bin_dir).unwrap();
        std::fs::write(bin_dir.join("bin-a"), b"").unwrap();
        std::fs::write(bin_dir.join("leftover-ghost"), b"").unwrap();

        let mut manifest = GlobalManifest::default();
        manifest
            .packages
            .insert("pkg".into(), pkg_entry("installs/pkg@1.0.0"));
        let check = check_orphaned_bin_shims(&root, &manifest);
        assert!(matches!(check.severity, Severity::Warn));
        assert!(check.detail.contains("leftover-ghost"));
        assert!(check.detail.contains("Fix hint"));
    }

    #[test]
    fn check_install_root_consistency_passes_when_all_roots_are_ready() {
        let tmp = tempfile::tempdir().unwrap();
        let root = LpmRoot::from_dir(tmp.path());
        let install_root = root.global_root().join("installs/pkg@1.0.0");
        std::fs::create_dir_all(&install_root).unwrap();
        write_marker(
            &install_root,
            &InstallReadyMarker::new(vec!["bin-a".into()]),
        )
        .unwrap();

        let mut manifest = GlobalManifest::default();
        manifest
            .packages
            .insert("pkg".into(), pkg_entry("installs/pkg@1.0.0"));
        let check = check_install_root_consistency(&root, &manifest);
        assert!(matches!(check.severity, Severity::Pass));
    }

    #[test]
    fn check_install_root_consistency_fails_when_root_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let root = LpmRoot::from_dir(tmp.path());
        let mut manifest = GlobalManifest::default();
        // Manifest claims the install but the dir doesn't exist.
        manifest
            .packages
            .insert("ghost".into(), pkg_entry("installs/ghost@1.0.0"));
        let check = check_install_root_consistency(&root, &manifest);
        assert!(matches!(check.severity, Severity::Fail));
        assert!(check.detail.contains("missing"));
        assert!(check.detail.contains("ghost"));
        assert!(check.detail.contains("Fix hint"));
    }

    #[test]
    fn check_install_root_consistency_fails_when_marker_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let root = LpmRoot::from_dir(tmp.path());
        let install_root = root.global_root().join("installs/unready@1.0.0");
        std::fs::create_dir_all(&install_root).unwrap();
        // Intentionally NO marker.

        let mut manifest = GlobalManifest::default();
        manifest
            .packages
            .insert("unready".into(), pkg_entry("installs/unready@1.0.0"));
        let check = check_install_root_consistency(&root, &manifest);
        assert!(matches!(check.severity, Severity::Fail));
        assert!(check.detail.contains("without `.lpm-install-ready` marker"));
    }
}
