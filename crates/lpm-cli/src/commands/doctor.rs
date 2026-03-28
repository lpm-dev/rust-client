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
		Self { name: name.into(), passed: true, detail: detail.into(), severity: Severity::Pass }
	}
	fn fail(name: &str, detail: &str) -> Self {
		Self { name: name.into(), passed: false, detail: detail.into(), severity: Severity::Fail }
	}
	fn warn(name: &str, detail: &str) -> Self {
		Self { name: name.into(), passed: true, detail: detail.into(), severity: Severity::Warn }
	}
}

/// Enhanced health check: verify auth, registry, store, project state, runtime, tools, lpm.json.
pub async fn run(
	client: &RegistryClient,
	registry_url: &str,
	project_dir: &Path,
	json_output: bool,
	fix: bool,
) -> Result<(), LpmError> {
	let mut checks: Vec<Check> = Vec::new();
	let mut fixes_applied: Vec<String> = Vec::new();

	// === Infrastructure (parallelized network calls) ===

	let token_exists = auth::get_token(registry_url).is_some();
	let (registry_result, auth_result) = tokio::join!(
		client.health_check(),
		async {
			if token_exists { client.whoami().await.is_ok() } else { false }
		}
	);

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
		checks.push(Check::fail("Authentication", "token exists but invalid — run: lpm login"));
	} else {
		checks.push(Check::fail("Authentication", "no token — run: lpm login"));
	}

	// 3. Global store accessible?
	let store_ok = PackageStore::default_location().is_ok();
	let store_detail = PackageStore::default_location()
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
		checks.push(Check::warn("node_modules", "exists but no .lpm store — run: lpm install"));
	} else {
		checks.push(Check::fail("node_modules", "not found — run: lpm install"));
	}

	// 6. Lockfile?
	let lockfile = project_dir.join("lpm.lock");
	if lockfile.exists() {
		checks.push(Check::pass("Lockfile", "lpm.lock exists"));
	} else {
		checks.push(Check::warn("Lockfile", "not found — run: lpm install to generate"));
	}

	// 6b. Dependencies in sync? (lockfile vs package.json)
	if lockfile.exists() && pkg_json_path.exists() {
		if let Some(sync_check) = check_deps_in_sync(project_dir) {
			checks.push(sync_check);
		}
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
			checks.push(Check::pass("Node.js", &format!("{v} (system, no version pinned)")));
		} else {
			checks.push(Check::fail("Node.js", "not found — run: lpm use node@22"));
		}
	}

	// === Tunnel (Phase 9) ===

	// 8b. Tunnel domain config
	if let Some(tunnel_check) = check_tunnel_domain(project_dir) {
		checks.push(tunnel_check);
	}

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

	// === Output ===

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
		let all_ok = checks.iter().all(|c| c.passed);
		let warnings = checks.iter().filter(|c| matches!(c.severity, Severity::Warn)).count();
		let output = serde_json::to_string_pretty(&serde_json::json!({
			"all_ok": all_ok,
			"warnings": warnings,
			"checks": results,
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
		let warned = checks.iter().filter(|c| matches!(c.severity, Severity::Warn)).count();
		let total = checks.len();

		if failed == 0 && warned == 0 {
			output::success(&format!("All {total} checks passed"));
		} else if failed == 0 {
			output::success(&format!("{} checks passed, {} warnings", total - warned, warned));
		} else {
			output::warn(&format!("{failed} check(s) failed, {warned} warning(s)"));
		}
		println!();
	}

	// === Auto-fix ===
	if fix {
		println!();
		output::info("Running auto-fix...");
		println!();

		for check in &checks {
			match (check.severity.as_str(), check.name.as_str()) {
				("fail", "node_modules") | ("warn", "node_modules") => {
					output::info("fixing: lpm install");
					let result = crate::commands::install::run_with_options(
						client, project_dir, false, false,
					).await;
					match result {
						Ok(()) => fixes_applied.push("lpm install".into()),
						Err(e) => eprintln!("  \x1b[31m✖\x1b[0m lpm install failed: {e}"),
					}
				}
				("fail", "Node.js") | ("warn", "Node.js") => {
					// Extract version spec from detail
					if let Some(spec) = extract_node_spec_from_detail(&check.detail) {
						output::info(&format!("fixing: lpm use node@{spec}"));
						let http_client = reqwest::Client::builder()
							.timeout(std::time::Duration::from_secs(60))
							.build()
							.map_err(|e| LpmError::Network(format!("{e}")))?;
						let platform = lpm_runtime::platform::Platform::current();
						let releases = lpm_runtime::node::fetch_index(&http_client).await;
						if let Ok(releases) = releases {
							if let Some(release) = lpm_runtime::node::resolve_version(&releases, &spec, &platform) {
								match lpm_runtime::download::install_node(&http_client, &release, &platform).await {
									Ok(ver) => fixes_applied.push(format!("installed node {ver}")),
									Err(e) => eprintln!("  \x1b[31m✖\x1b[0m node install failed: {e}"),
								}
							}
						}
					}
				}
				("warn", "Format (biome)") => {
					output::info("fixing: lpm fmt");
					let result = crate::commands::tools::fmt(project_dir, &[], false, false).await;
					match result {
						Ok(()) => fixes_applied.push("lpm fmt".into()),
						Err(e) => eprintln!("  \x1b[31m✖\x1b[0m lpm fmt failed: {e}"),
					}
				}
				("warn", "Lockfile") => {
					output::info("fixing: lpm install (generates lockfile)");
					let result = crate::commands::install::run_with_options(
						client, project_dir, false, false,
					).await;
					match result {
						Ok(()) => fixes_applied.push("lpm install (lockfile)".into()),
						Err(e) => eprintln!("  \x1b[31m✖\x1b[0m lpm install failed: {e}"),
					}
				}
				("warn", "Deps sync") => {
					output::info("fixing: lpm install (sync lockfile)");
					let result = crate::commands::install::run_with_options(
						client, project_dir, false, false,
					).await;
					match result {
						Ok(()) => fixes_applied.push("lpm install (deps sync)".into()),
						Err(e) => eprintln!("  \x1b[31m✖\x1b[0m lpm install failed: {e}"),
					}
				}
				_ => {}
			}
		}

		if fixes_applied.is_empty() {
			output::info("no auto-fixable issues found");
		} else {
			println!();
			output::success(&format!("applied {} fix(es): {}", fixes_applied.len(), fixes_applied.join(", ")));
		}
	}

	Ok(())
}

/// Extract node version spec from doctor detail message.
fn extract_node_spec_from_detail(detail: &str) -> Option<String> {
	// "... pinned >=22 from ... Run: lpm use node@22"
	if let Some(pos) = detail.find("node@") {
		let after = &detail[pos + 5..];
		let end = after.find(|c: char| c.is_whitespace() || c == '"').unwrap_or(after.len());
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
fn wait_with_timeout(
	mut child: std::process::Child,
	timeout: Duration,
) -> Option<std::process::Output> {
	let start = std::time::Instant::now();
	loop {
		match child.try_wait() {
			Ok(Some(status)) => {
				let stdout = child.stdout.map(|mut s| {
					let mut buf = Vec::new();
					std::io::Read::read_to_end(&mut s, &mut buf).ok();
					buf
				}).unwrap_or_default();
				let stderr = child.stderr.map(|mut s| {
					let mut buf = Vec::new();
					std::io::Read::read_to_end(&mut s, &mut buf).ok();
					buf
				}).unwrap_or_default();
				return Some(std::process::Output { status, stdout, stderr });
			}
			Ok(None) => {
				if start.elapsed() > timeout {
					let _ = child.kill();
					return None;
				}
				std::thread::sleep(Duration::from_millis(50));
			}
			Err(_) => return None,
		}
	}
}

/// Run oxlint silently and count errors/warnings (30s timeout).
fn run_lint_check(project_dir: &Path) -> Option<Check> {
	let versions = lpm_plugin::store::list_installed_versions("oxlint").ok()?;
	let version = versions.first()?;
	let bin = lpm_plugin::store::plugin_binary_path("oxlint", version, "oxlint");

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
			Some(Check::fail("Lint (oxlint)", &format!("{} — run: lpm lint --fix", summary.trim())))
		} else {
			Some(Check::warn("Lint (oxlint)", &format!("{} — run: lpm lint --fix", summary.trim())))
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
	let bin = lpm_plugin::store::plugin_binary_path("biome", version, "biome");

	if !bin.exists() {
		return None;
	}

	let (_stdout, stderr, code) = run_tool_with_timeout(
		&bin,
		&["format", "--check", "."],
		project_dir,
		None,
	)?;

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

	let (stdout, _stderr, code) = run_tool_with_timeout(
		&tsc_path,
		&["--noEmit"],
		project_dir,
		Some(&path),
	)?;

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
async fn check_plugins() -> Vec<Check> {
	let mut checks = Vec::new();

	for def in lpm_plugin::registry::list_plugins() {
		let installed = lpm_plugin::store::list_installed_versions(def.name).unwrap_or_default();
		if installed.is_empty() {
			continue;
		}

		let latest = lpm_plugin::versions::get_latest_version(def).await;
		let Some(current) = installed.last() else { continue };

		if *current == latest {
			checks.push(Check::pass(
				&format!("Plugin: {}", def.name),
				&format!("v{current} (up to date)"),
			));
		} else {
			checks.push(Check::warn(
				&format!("Plugin: {}", def.name),
				&format!("v{current} → v{latest} available — run: lpm plugin update {}", def.name),
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

/// Validate lpm.json structure and known fields.
///
/// Checks:
/// - Valid JSON syntax
/// - Known top-level fields (runtime, env, tasks, tools, services)
/// - runtime.node is a valid version spec
/// - tasks have valid structure (command, dependsOn, cache, outputs, inputs)
/// - tools reference known plugins
/// Check tunnel domain configuration from lpm.json.
fn check_tunnel_domain(project_dir: &Path) -> Option<Check> {
	let config = lpm_runner::lpm_json::read_lpm_json(project_dir).ok()??;
	let tunnel = config.tunnel?;
	let domain = tunnel.domain?;

	// RFC-compliant domain length checks (RFC 1035 / RFC 1123)
	if domain.len() > 253 {
		return Some(Check::warn(
			"Tunnel",
			&format!(
				"domain \"{}\" exceeds 253 character limit ({} chars)",
				domain,
				domain.len()
			),
		));
	}

	// Check each label: max 63 chars, no empty labels (consecutive dots)
	for label in domain.split('.') {
		if label.is_empty() {
			return Some(Check::warn(
				"Tunnel",
				&format!("domain \"{domain}\" contains empty label (consecutive dots)"),
			));
		}
		if label.len() > 63 {
			return Some(Check::warn(
				"Tunnel",
				&format!(
					"domain label \"{}\" exceeds 63 character limit ({} chars)",
					label,
					label.len()
				),
			));
		}
	}

	// Validate domain format: must have at least one dot
	if !domain.contains('.') {
		return Some(Check::warn(
			"Tunnel",
			&format!(
				"\"{}\" is not a full domain — use: {}.lpm.fyi or {}.lpm.llc",
				domain, domain, domain
			),
		));
	}

	// Validate subdomain part
	let parts: Vec<&str> = domain.splitn(2, '.').collect();
	if parts.len() != 2 {
		return Some(Check::warn("Tunnel", &format!("invalid domain format: {domain}")));
	}

	let subdomain = parts[0];
	let base_domain = parts[1];

	// Check subdomain format
	if subdomain.len() < 3 || subdomain.len() > 32 {
		return Some(Check::warn(
			"Tunnel",
			&format!("subdomain \"{subdomain}\" must be 3-32 characters"),
		));
	}
	if !subdomain.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-') {
		return Some(Check::warn(
			"Tunnel",
			&format!("subdomain \"{subdomain}\" must be lowercase alphanumeric + hyphens"),
		));
	}

	// Check known base domains
	let known_bases = ["lpm.fyi", "lpm.llc", "lpm.run"];
	if !known_bases.contains(&base_domain) {
		return Some(Check::warn(
			"Tunnel",
			&format!(
				"unknown base domain \"{base_domain}\" (available: {})",
				known_bases.join(", ")
			),
		));
	}

	Some(Check::pass("Tunnel", &format!("{domain} (configured)")))
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

	let lock_content = std::fs::read_to_string(&lockfile_path).ok()?;

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

	// Check which deps are missing from lockfile (simple string search)
	let mut missing: Vec<&str> = Vec::new();
	for dep in &declared_deps {
		// Lockfile uses `name = "dep-name"` format (TOML) — check if dep name appears
		if !lock_content.contains(&format!("name = \"{dep}\""))
			&& !lock_content.contains(&format!("\"{dep}\""))
		{
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

fn validate_lpm_json(project_dir: &Path) -> Option<Check> {
	let lpm_json_path = project_dir.join("lpm.json");
	if !lpm_json_path.exists() {
		return None; // No lpm.json is fine — it's optional
	}

	let content = match std::fs::read_to_string(&lpm_json_path) {
		Ok(c) => c,
		Err(e) => {
			return Some(Check::fail(
				"lpm.json",
				&format!("cannot read: {e}"),
			));
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
			return Some(Check::fail("lpm.json", "must be a JSON object, not an array or primitive"));
		}
	};

	let mut warnings: Vec<String> = Vec::new();

	// 2. Check for unknown top-level fields
	let known_fields = ["runtime", "env", "tasks", "tools", "services", "vault", "tunnel"];
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
					warnings.push(format!("runtime \"{rt_name}\" not yet supported (only \"node\")"));
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
					if let Some(cache) = task_obj.get("cache") {
						if !cache.is_boolean() {
							warnings.push(format!("tasks.{task_name}.cache must be a boolean"));
						}
					}
					// outputs and inputs must be arrays of strings
					for field in ["outputs", "inputs"] {
						if let Some(arr) = task_obj.get(field) {
							if !arr.is_array() {
								warnings.push(format!("tasks.{task_name}.{field} must be an array"));
							}
						}
					}
					// dependsOn must be array of strings
					if let Some(deps) = task_obj.get("dependsOn") {
						if !deps.is_array() {
							warnings.push(format!("tasks.{task_name}.dependsOn must be an array"));
						}
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
					warnings.push(format!("tools.{tool_name}: unknown plugin (available: {})", known_tools.join(", ")));
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
						warnings.push(format!("services.{svc_name}: missing required \"command\" field"));
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
