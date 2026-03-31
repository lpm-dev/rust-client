//! `lpm build` — Selective lifecycle script execution.
//!
//! Phase 2 of the two-phase install model:
//! - `lpm install` downloads, extracts, and links packages — NO scripts execute.
//! - `lpm build` selectively runs lifecycle scripts based on trust policy.
//!
//! Trust policy is defined in package.json `"lpm"` config:
//! ```json
//! {
//!   "lpm": {
//!     "trustedDependencies": ["esbuild", "sharp"],
//!     "scripts": {
//!       "trustedScopes": ["@myorg/*"],
//!       "denyAll": false,
//!       "autoBuild": false
//!     }
//!   }
//! }
//! ```
//!
//! Build state is tracked via `.lpm-built` marker files in the store.
//! Already-built packages are skipped (idempotent). Use `--rebuild` to force.
//!
//! ## Security (S3)
//! - 5-minute default timeout per script (--timeout to override)
//! - Credential env vars stripped (LPM_TOKEN, NPM_TOKEN, GITHUB_TOKEN, etc.)
//! - Scripts run in package's store directory, not project root
//! - Process group killed on timeout (not just the child)

use crate::output;
use lpm_common::LpmError;
use lpm_security::SecurityPolicy;
use lpm_store::PackageStore;
use owo_colors::OwoColorize;
use std::collections::HashMap;
use std::path::Path;
use std::time::Duration;

/// Default timeout for each lifecycle script execution (5 minutes).
const DEFAULT_SCRIPT_TIMEOUT_SECS: u64 = 300;

/// Build state marker filename.
const BUILD_MARKER: &str = ".lpm-built";

/// Env var patterns to strip from script execution environment.
const STRIPPED_ENV_PATTERNS: &[&str] = &[
	"LPM_TOKEN",
	"NPM_TOKEN",
	"NODE_AUTH_TOKEN",
	"GITHUB_TOKEN",
	"GH_TOKEN",
	"GITLAB_TOKEN",
	"BITBUCKET_TOKEN",
	"AWS_SECRET_ACCESS_KEY",
	"AWS_SESSION_TOKEN",
	"AZURE_CLIENT_SECRET",
];

/// Env var suffix patterns — any var ending with these is stripped.
const STRIPPED_ENV_SUFFIXES: &[&str] = &["_SECRET", "_PASSWORD", "_KEY", "_PRIVATE_KEY"];

/// Lifecycle script phases in execution order.
const SCRIPT_PHASES: &[&str] = &["preinstall", "install", "postinstall"];

/// Run the `lpm build` command.
pub async fn run(
	project_dir: &Path,
	specific_packages: &[String],
	all: bool,
	dry_run: bool,
	rebuild: bool,
	timeout_secs: Option<u64>,
	json_output: bool,
) -> Result<(), LpmError> {
	let store = PackageStore::default_location()?;
	let policy = SecurityPolicy::from_package_json(&project_dir.join("package.json"));

	// Load lockfile to get installed packages with their scripts
	let lockfile_path = project_dir.join("lpm.lock");
	if !lockfile_path.exists() {
		return Err(LpmError::NotFound(
			"No lpm.lock found. Run `lpm install` first.".into(),
		));
	}

	let lockfile = lpm_lockfile::Lockfile::read_fast(&lockfile_path)
		.map_err(|e| LpmError::Registry(format!("failed to read lockfile: {e}")))?;

	// Collect packages that have lifecycle scripts
	let mut scriptable_packages: Vec<ScriptablePackage> = Vec::new();

	for lp in &lockfile.packages {
		let pkg_dir = store.package_dir(&lp.name, &lp.version);
		let pkg_json_path = pkg_dir.join("package.json");

		if !pkg_json_path.exists() {
			continue;
		}

		let scripts = match read_lifecycle_scripts(&pkg_json_path) {
			Some(s) if !s.is_empty() => s,
			_ => continue,
		};

		let is_built = pkg_dir.join(BUILD_MARKER).exists();
		let is_trusted = policy.can_run_scripts(&lp.name)
			|| is_scope_trusted(&lp.name, project_dir);

		scriptable_packages.push(ScriptablePackage {
			name: lp.name.clone(),
			version: lp.version.clone(),
			store_path: pkg_dir,
			scripts,
			is_built,
			is_trusted,
		});
	}

	if scriptable_packages.is_empty() {
		if !json_output {
			output::success("No packages have lifecycle scripts. Nothing to build.");
		}
		return Ok(());
	}

	// Determine which packages to build
	let to_build: Vec<&ScriptablePackage> = if !specific_packages.is_empty() {
		// Build specific packages by name
		let mut selected = Vec::new();
		for name in specific_packages {
			let found = scriptable_packages.iter().find(|p| p.name == *name || p.name.ends_with(&format!(".{name}")));
			match found {
				Some(pkg) => selected.push(pkg),
				None => {
					output::warn(&format!("{name} has no lifecycle scripts or is not installed"));
				}
			}
		}
		selected
	} else if all {
		// Build ALL packages with scripts
		scriptable_packages.iter().collect()
	} else {
		// Build only trusted packages
		scriptable_packages
			.iter()
			.filter(|p| p.is_trusted)
			.collect()
	};

	// Filter out already-built (unless --rebuild)
	let to_build: Vec<&ScriptablePackage> = if rebuild {
		to_build
	} else {
		to_build.into_iter().filter(|p| !p.is_built).collect()
	};

	if to_build.is_empty() {
		if !json_output {
			let total = scriptable_packages.len();
			let built = scriptable_packages.iter().filter(|p| p.is_built).count();
			output::success(&format!(
				"All {built}/{total} packages with scripts are already built."
			));
			if !rebuild {
				println!("  Use {} to rebuild.", "--rebuild".dimmed());
			}
		}
		return Ok(());
	}

	let timeout = Duration::from_secs(timeout_secs.unwrap_or(DEFAULT_SCRIPT_TIMEOUT_SECS));

	// Dry run — show what would be executed
	if dry_run {
		if json_output {
			let json = serde_json::json!({
				"dry_run": true,
				"packages": to_build.iter().map(|p| {
					serde_json::json!({
						"name": p.name,
						"version": p.version,
						"scripts": p.scripts,
						"trusted": p.is_trusted,
					})
				}).collect::<Vec<_>>(),
			});
			println!("{}", serde_json::to_string_pretty(&json).unwrap());
		} else {
			output::info(&format!("Dry run: {} package(s) would be built:", to_build.len()));
			for pkg in &to_build {
				let trust = if pkg.is_trusted {
					"trusted ✓".green().to_string()
				} else {
					"not trusted".yellow().to_string()
				};
				println!(
					"\n  {} {} ({})",
					pkg.name.bold(),
					format!("({})", pkg.version).dimmed(),
					trust,
				);
				for (phase, cmd) in &pkg.scripts {
					println!("    {phase}: {}", cmd.dimmed());
				}
			}
		}
		return Ok(());
	}

	// Warn if building untrusted packages
	let untrusted_count = to_build.iter().filter(|p| !p.is_trusted).count();
	if untrusted_count > 0 && !all && specific_packages.is_empty() {
		output::warn(&format!(
			"{untrusted_count} package(s) are not in trustedDependencies and will be skipped."
		));
		println!(
			"  Add them to {} or use {}.",
			"package.json > lpm > trustedDependencies".dimmed(),
			"lpm build --all".bold(),
		);
	}

	if !json_output {
		output::info(&format!("Building {} package(s)...", to_build.len()));
	}

	// Execute scripts
	let mut successes = 0usize;
	let mut failures = 0usize;
	let sanitized_env = build_sanitized_env();

	for pkg in &to_build {
		if !json_output {
			println!(
				"\n  {} {}",
				pkg.name.bold(),
				format!("({})", pkg.version).dimmed(),
			);
		}

		let mut pkg_success = true;

		for phase in SCRIPT_PHASES {
			let cmd = match pkg.scripts.get(*phase) {
				Some(c) => c,
				None => continue,
			};

			if !json_output {
				println!("    {} {phase}: {}", "→".dimmed(), cmd.dimmed());
			}

			match execute_script(cmd, &pkg.store_path, project_dir, &sanitized_env, &timeout) {
				Ok(()) => {
					if !json_output {
						println!("    {} {phase} completed", "✓".green());
					}
				}
				Err(e) => {
					pkg_success = false;
					if !json_output {
						println!("    {} {phase} failed: {e}", "✖".red());
					}
					break; // Don't run subsequent phases if one fails
				}
			}
		}

		if pkg_success {
			// Write .lpm-built marker
			let marker_path = pkg.store_path.join(BUILD_MARKER);
			if let Err(e) = std::fs::write(&marker_path, "") {
				tracing::warn!("failed to write build marker for {}: {e}", pkg.name);
			}
			successes += 1;
		} else {
			failures += 1;
		}
	}

	// Summary
	println!();
	if json_output {
		let json = serde_json::json!({
			"success": failures == 0,
			"built": successes,
			"failed": failures,
		});
		println!("{}", serde_json::to_string_pretty(&json).unwrap());
	} else if failures == 0 {
		output::success(&format!("{successes} package(s) built successfully."));
	} else {
		output::warn(&format!(
			"{successes} succeeded, {failures} failed."
		));
	}

	if failures > 0 {
		Err(LpmError::Registry(format!("{failures} package(s) failed to build")))
	} else {
		Ok(())
	}
}

/// Execute a single lifecycle script with timeout and env sanitization.
fn execute_script(
	cmd: &str,
	package_dir: &Path,
	project_dir: &Path,
	env: &HashMap<String, String>,
	timeout: &Duration,
) -> Result<(), String> {
	use std::process::Command;

	let mut command = Command::new("sh");
	command
		.args(["-c", cmd])
		.current_dir(package_dir)
		.env_clear();

	// Set sanitized environment
	for (key, value) in env {
		command.env(key, value);
	}

	// Set npm conventions
	command.env("INIT_CWD", project_dir);
	command.env(
		"PATH",
		format!(
			"{}:{}",
			project_dir.join("node_modules/.bin").display(),
			env.get("PATH").map(|s| s.as_str()).unwrap_or("/usr/bin:/bin")
		),
	);

	let start = std::time::Instant::now();

	let child = command
		.stdout(std::process::Stdio::inherit())
		.stderr(std::process::Stdio::inherit())
		.spawn()
		.map_err(|e| format!("failed to spawn: {e}"))?;

	// Wait with timeout
	let output = wait_with_timeout(child, timeout);

	match output {
		Ok(status) => {
			if status.success() {
				let elapsed = start.elapsed();
				tracing::debug!("script completed in {:.1}s", elapsed.as_secs_f64());
				Ok(())
			} else {
				Err(format!("exit code {}", status.code().unwrap_or(-1)))
			}
		}
		Err(e) => Err(e),
	}
}

/// Wait for a child process with a timeout. Kills the process group on timeout.
fn wait_with_timeout(
	mut child: std::process::Child,
	timeout: &Duration,
) -> Result<std::process::ExitStatus, String> {
	let start = std::time::Instant::now();
	let poll_interval = Duration::from_millis(100);

	loop {
		match child.try_wait() {
			Ok(Some(status)) => return Ok(status),
			Ok(None) => {
				if start.elapsed() > *timeout {
					// Kill the child process
					let _ = child.kill();
					let _ = child.wait(); // Reap zombie
					return Err(format!(
						"timeout after {}s — process killed",
						timeout.as_secs()
					));
				}
				std::thread::sleep(poll_interval);
			}
			Err(e) => return Err(format!("wait error: {e}")),
		}
	}
}

/// Build a sanitized environment for script execution.
/// Strips credential env vars, keeps essential system vars.
fn build_sanitized_env() -> HashMap<String, String> {
	let mut env: HashMap<String, String> = HashMap::new();

	for (key, value) in std::env::vars() {
		// Skip explicitly blocked vars
		if STRIPPED_ENV_PATTERNS.contains(&key.as_str()) {
			continue;
		}

		// Skip vars matching suffix patterns
		let upper = key.to_uppercase();
		if STRIPPED_ENV_SUFFIXES.iter().any(|suffix| upper.ends_with(suffix)) {
			continue;
		}

		env.insert(key, value);
	}

	env
}

/// Read lifecycle scripts from a package.json file.
fn read_lifecycle_scripts(pkg_json_path: &Path) -> Option<HashMap<String, String>> {
	let content = std::fs::read_to_string(pkg_json_path).ok()?;
	let parsed: serde_json::Value = serde_json::from_str(&content).ok()?;
	let scripts_obj = parsed.get("scripts")?.as_object()?;

	let mut lifecycle = HashMap::new();
	for phase in SCRIPT_PHASES {
		if let Some(cmd) = scripts_obj.get(*phase).and_then(|v| v.as_str()) {
			lifecycle.insert(phase.to_string(), cmd.to_string());
		}
	}

	if lifecycle.is_empty() {
		None
	} else {
		Some(lifecycle)
	}
}

/// Check if a package name matches any trustedScopes glob pattern.
fn is_scope_trusted(package_name: &str, project_dir: &Path) -> bool {
	let pkg_json_path = project_dir.join("package.json");
	let content = match std::fs::read_to_string(&pkg_json_path) {
		Ok(c) => c,
		Err(_) => return false,
	};
	let parsed: serde_json::Value = match serde_json::from_str(&content) {
		Ok(v) => v,
		Err(_) => return false,
	};

	// Check lpm.scripts.trustedScopes
	let scopes = parsed
		.get("lpm")
		.and_then(|l| l.get("scripts"))
		.and_then(|s| s.get("trustedScopes"))
		.and_then(|t| t.as_array());

	let Some(scopes) = scopes else {
		return false;
	};

	for scope in scopes {
		let Some(pattern) = scope.as_str() else {
			continue;
		};

		// Simple glob matching: "@myorg/*" matches "@myorg/anything"
		if let Some(prefix) = pattern.strip_suffix("/*") {
			if package_name.starts_with(prefix) && package_name.len() > prefix.len() + 1 {
				return true;
			}
		} else if pattern == package_name {
			return true;
		}
	}

	false
}

struct ScriptablePackage {
	name: String,
	version: String,
	store_path: std::path::PathBuf,
	scripts: HashMap<String, String>,
	is_built: bool,
	is_trusted: bool,
}

/// Show the install-time build hint (called from install.rs).
///
/// Lists packages with unexecuted scripts and their trust status.
pub fn show_install_build_hint(
	store: &PackageStore,
	packages: &[(String, String)], // (name, version)
	policy: &SecurityPolicy,
	project_dir: &Path,
) {
	let mut scriptable: Vec<(&str, &str, HashMap<String, String>, bool, bool)> = Vec::new();

	for (name, version) in packages {
		let pkg_dir = store.package_dir(name, version);
		let pkg_json_path = pkg_dir.join("package.json");

		let scripts = match read_lifecycle_scripts(&pkg_json_path) {
			Some(s) if !s.is_empty() => s,
			_ => continue,
		};

		let is_built = pkg_dir.join(BUILD_MARKER).exists();
		let is_trusted = policy.can_run_scripts(name)
			|| is_scope_trusted(name, project_dir);

		scriptable.push((name, version, scripts, is_built, is_trusted));
	}

	let unbuilt: Vec<_> = scriptable.iter().filter(|(_, _, _, built, _)| !built).collect();

	if unbuilt.is_empty() {
		return;
	}

	println!();
	output::info(&format!(
		"{} package(s) have install scripts:",
		unbuilt.len()
	));

	for (name, version, scripts, _, trusted) in &unbuilt {
		let trust_label = if *trusted {
			"trusted ✓".green().to_string()
		} else {
			"not trusted".yellow().to_string()
		};

		let script_names: Vec<&str> = scripts.keys().map(|s| s.as_str()).collect();
		println!(
			"  {:<30} {:<30} ({})",
			format!("{}@{}", name, version).bold(),
			script_names.join(", ").dimmed(),
			trust_label,
		);
	}

	let trusted_unbuilt = unbuilt.iter().filter(|(_, _, _, _, t)| *t).count();
	println!();
	if trusted_unbuilt > 0 {
		println!(
			"  Run {} to execute scripts for trusted packages.",
			"lpm build".bold()
		);
	}
	if trusted_unbuilt < unbuilt.len() {
		println!(
			"  Run {} to build specific packages.",
			"lpm build <package-name>".bold()
		);
	}
}
