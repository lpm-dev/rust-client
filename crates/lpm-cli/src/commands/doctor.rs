use crate::{auth, output};
use lpm_common::LpmError;
use lpm_registry::RegistryClient;
use lpm_store::PackageStore;
use owo_colors::OwoColorize;
use std::path::Path;
use std::process::{Command, Stdio};

/// Check result with status icon.
struct Check {
	name: String,
	passed: bool,
	detail: String,
	/// Optional: "warn" for non-critical issues
	severity: Severity,
}

enum Severity {
	Pass,
	Fail,
	Warn,
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

/// Enhanced health check: verify auth, registry, store, project state, runtime, tools.
pub async fn run(
	client: &RegistryClient,
	registry_url: &str,
	project_dir: &Path,
	json_output: bool,
) -> Result<(), LpmError> {
	let mut checks: Vec<Check> = Vec::new();

	// === Infrastructure ===

	// 1. Registry reachable?
	let registry_ok = client.health_check().await.unwrap_or(false);
	if registry_ok {
		checks.push(Check::pass("Registry", registry_url));
	} else {
		checks.push(Check::fail("Registry", &format!("{registry_url} — unreachable")));
	}

	// 2. Auth token valid?
	let token_exists = auth::get_token(registry_url).is_some();
	let auth_ok = if token_exists { client.whoami().await.is_ok() } else { false };
	if auth_ok {
		checks.push(Check::pass("Authentication", "valid token"));
	} else if token_exists {
		checks.push(Check::fail("Authentication", "token exists but invalid"));
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
		checks.push(Check::pass("package.json", &pkg_json_path.display().to_string()));
	} else {
		checks.push(Check::fail("package.json", "not found in current directory"));
	}

	// 5. node_modules intact?
	let nm = project_dir.join("node_modules");
	if nm.exists() && nm.join(".lpm").exists() {
		checks.push(Check::pass("node_modules", "exists with .lpm store"));
	} else if nm.exists() {
		checks.push(Check::warn("node_modules", "exists but no .lpm store (run: lpm install)"));
	} else {
		checks.push(Check::fail("node_modules", "not found (run: lpm install)"));
	}

	// 6. Lockfile?
	let lockfile = project_dir.join("lpm.lock");
	if lockfile.exists() {
		checks.push(Check::pass("Lockfile", "lpm.lock exists"));
	} else {
		checks.push(Check::warn("Lockfile", "not found (run: lpm install)"));
	}

	// === Runtime (Phase 2) ===

	// 7. Node.js version
	let detected = lpm_runtime::detect::detect_node_version(project_dir);
	if let Some(ref det) = detected {
		let system_node = get_system_node_version(project_dir);
		let managed_versions = lpm_runtime::node::list_installed().unwrap_or_default();

		// Check if pinned version is installed
		let spec = &det.spec;
		let clean = spec.trim_start_matches(">=").trim_start_matches('^').trim_start_matches('~').trim_start_matches('>');
		let matched_managed = managed_versions.iter().find(|v| {
			*v == clean || v.starts_with(&format!("{clean}."))
		});

		if let Some(ver) = matched_managed {
			checks.push(Check::pass(
				"Node.js",
				&format!("v{ver} (managed, from {})", det.source),
			));
		} else if let Some(sys) = &system_node {
			checks.push(Check::warn(
				"Node.js",
				&format!("{sys} (system) — pinned {spec} from {} not installed. Run: lpm env install node@{clean}", det.source),
			));
		} else {
			checks.push(Check::fail(
				"Node.js",
				&format!("not found — pinned {spec} from {}. Run: lpm env install node@{clean}", det.source),
			));
		}
	} else {
		let sys = get_system_node_version(project_dir);
		if let Some(v) = sys {
			checks.push(Check::pass("Node.js", &format!("{v} (system, no version pinned)")));
		} else {
			checks.push(Check::fail("Node.js", "not found — run: lpm env install node@22"));
		}
	}

	// === Code Quality (Phase 4) ===

	// 8. Lint check (if oxlint installed)
	if let Some(lint_result) = run_lint_check(project_dir) {
		checks.push(lint_result);
	}

	// 9. Format check (if biome installed)
	if let Some(fmt_result) = run_fmt_check(project_dir) {
		checks.push(fmt_result);
	}

	// 10. TypeScript check (if tsc available)
	if let Some(ts_result) = run_typecheck(project_dir) {
		checks.push(ts_result);
	}

	// === Plugins (Phase 4) ===

	// 11. Plugin status
	let plugin_checks = check_plugins().await;
	checks.extend(plugin_checks);

	// === Workspace (Phase 3) ===

	// 12. Workspace health
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
					"detail": c.detail,
				})
			})
			.collect();
		let all_ok = checks.iter().all(|c| c.passed);
		println!(
			"{}",
			serde_json::to_string_pretty(&serde_json::json!({
				"all_ok": all_ok,
				"checks": results,
			}))
			.unwrap()
		);
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

	Ok(())
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

/// Run oxlint silently and count errors/warnings.
fn run_lint_check(project_dir: &Path) -> Option<Check> {
	let bin = lpm_plugin::store::plugin_binary_path("oxlint", "", "oxlint");
	// Find any installed version
	let versions = lpm_plugin::store::list_installed_versions("oxlint").ok()?;
	let version = versions.first()?;
	let bin = lpm_plugin::store::plugin_binary_path("oxlint", version, "oxlint");

	if !bin.exists() {
		return None;
	}

	let output = Command::new(&bin)
		.arg(".")
		.current_dir(project_dir)
		.stdout(Stdio::piped())
		.stderr(Stdio::piped())
		.output()
		.ok()?;

	let stdout = String::from_utf8_lossy(&output.stdout);

	// Parse the "Found X warnings and Y errors" line
	if output.status.success() {
		Some(Check::pass("Lint (oxlint)", "no issues"))
	} else if let Some(summary) = stdout.lines().rev().find(|l| l.contains("Found")) {
		if stdout.contains("error") || summary.contains("error") {
			Some(Check {
				name: "Lint (oxlint)".into(),
				passed: false,
				detail: summary.trim().to_string(),
				severity: Severity::Fail
			})
		} else {
			Some(Check::warn("Lint (oxlint)", summary.trim()))
		}
	} else {
		Some(Check::warn("Lint (oxlint)", "completed with warnings"))
	}
}

/// Run biome format --check silently and count unformatted files.
fn run_fmt_check(project_dir: &Path) -> Option<Check> {
	let versions = lpm_plugin::store::list_installed_versions("biome").ok()?;
	let version = versions.first()?;
	let bin = lpm_plugin::store::plugin_binary_path("biome", version, "biome");

	if !bin.exists() {
		return None;
	}

	let output = Command::new(&bin)
		.args(["format", "--check", "."])
		.current_dir(project_dir)
		.stdout(Stdio::piped())
		.stderr(Stdio::piped())
		.output()
		.ok()?;

	if output.status.success() {
		Some(Check::pass("Format (biome)", "all files formatted"))
	} else {
		let stderr = String::from_utf8_lossy(&output.stderr);
		let count = stderr.lines().filter(|l| l.contains("Formatter would have printed")).count();
		if count > 0 {
			Some(Check::warn(
				"Format (biome)",
				&format!("{count} file(s) need formatting — run: lpm fmt"),
			))
		} else {
			Some(Check::warn("Format (biome)", "some files need formatting — run: lpm fmt"))
		}
	}
}

/// Run tsc --noEmit silently and count errors.
fn run_typecheck(project_dir: &Path) -> Option<Check> {
	// Only check if tsconfig.json exists (it's a TypeScript project)
	if !project_dir.join("tsconfig.json").exists() {
		return None;
	}

	let path = lpm_runner::bin_path::build_path_with_bins(project_dir);
	let output = Command::new("tsc")
		.arg("--noEmit")
		.current_dir(project_dir)
		.env("PATH", &path)
		.stdout(Stdio::piped())
		.stderr(Stdio::piped())
		.output()
		.ok()?;

	if output.status.success() {
		Some(Check::pass("TypeScript", "no type errors"))
	} else {
		let stdout = String::from_utf8_lossy(&output.stdout);
		let error_count = stdout.lines().filter(|l| l.contains("error TS")).count();
		if error_count > 0 {
			Some(Check::fail(
				"TypeScript",
				&format!("{error_count} type error(s) — run: lpm check"),
			))
		} else {
			Some(Check::fail("TypeScript", "type errors found — run: lpm check"))
		}
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
		let current = installed.last().unwrap();

		if *current == latest {
			checks.push(Check::pass(
				&format!("Plugin: {}", def.name),
				&format!("v{current} (up to date)"),
			));
		} else {
			checks.push(Check::warn(
				&format!("Plugin: {}", def.name),
				&format!("v{current} → v{latest} available. Run: lpm plugin update {}", def.name),
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
		Err(_) => Some(Check::fail(
			"Workspace",
			"dependency cycle detected — resolve circular dependencies",
		)),
	}
}
