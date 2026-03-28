use crate::output;
use lpm_common::LpmError;
use owo_colors::OwoColorize;
use std::path::Path;

/// Ensure the required Node.js runtime is available before running scripts.
///
/// Detects version requirements from lpm.json/package.json/.nvmrc/.node-version,
/// auto-installs if needed, and prints a user-visible notice about which version
/// is being used.
///
/// This replaces the silent fallback behavior — developers always know which
/// Node version they're running on.
pub async fn ensure_runtime(project_dir: &Path) {
	match lpm_runtime::ensure_runtime(project_dir).await {
		lpm_runtime::RuntimeStatus::Ready { version, source } => {
			// Point 1: one-line notice when using managed runtime
			eprintln!(
				"  {} node {} (from {})",
				"Using".dimmed(),
				version.bold(),
				source.dimmed(),
			);
		}
		lpm_runtime::RuntimeStatus::Installed { version, source } => {
			// Point 3: auto-installed
			output::success(&format!(
				"Auto-installed node {} (from {})",
				version.bold(),
				source,
			));
		}
		lpm_runtime::RuntimeStatus::NotInstalled { spec, source } => {
			// Point 2: warn when required version isn't installed
			output::warn(&format!(
				"{} requires node {}, but it's not installed. Using system node.",
				source,
				spec.bold(),
			));
			eprintln!(
				"    Run: {}",
				format!("lpm use node@{spec}").cyan(),
			);
		}
		lpm_runtime::RuntimeStatus::NoRequirement => {
			// No version pinned — nothing to show
		}
	}
}

/// Run a script from package.json (single package).
///
/// Delegates to `lpm_runner::script::run_script()` which provides:
/// - PATH injection (`node_modules/.bin` prepended)
/// - `.env` file loading (auto + `--env` flag + `lpm.json` mapping)
/// - Pre/post script hooks (npm convention)
/// - Task caching (when enabled in `lpm.json`)
pub async fn run(
	project_dir: &Path,
	script_name: &str,
	extra_args: &[String],
	env_mode: Option<&str>,
	no_cache: bool,
) -> Result<(), LpmError> {
	// Ensure runtime is available (auto-install if needed)
	ensure_runtime(project_dir).await;

	// Check if caching is enabled for this task
	if !no_cache {
		if let Some(hit) = try_cache_hit(project_dir, script_name, env_mode)? {
			// Cache hit — replay output
			if !hit.stdout.is_empty() {
				print!("{}", hit.stdout);
			}
			if !hit.stderr.is_empty() {
				eprint!("{}", hit.stderr);
			}
			output::success(&format!(
				"{} restored from cache (originally {:.1}s)",
				script_name.bold(),
				hit.meta.duration_ms as f64 / 1000.0,
			));
			return Ok(());
		}
	}

	output::info(&format!("{}", script_name.bold()));

	// Check if caching is enabled — if so, use tee capture
	let caching_enabled = !no_cache && is_task_cached(project_dir, script_name);

	let start = std::time::Instant::now();

	if caching_enabled {
		// Run with tee capture (output streams to terminal + captured for cache)
		let output = lpm_runner::script::run_script_captured(
			project_dir, script_name, extra_args, env_mode,
		)?;
		let duration_ms = start.elapsed().as_millis() as u64;
		let _ = try_cache_store_with_output(
			project_dir, script_name, env_mode, duration_ms,
			&output.stdout, &output.stderr,
		);
	} else {
		// Run normally (inherited stdio, no capture)
		lpm_runner::script::run_script(project_dir, script_name, extra_args, env_mode)?;
	}

	Ok(())
}

/// Run a script across workspace packages.
pub async fn run_workspace(
	project_dir: &Path,
	script_name: &str,
	extra_args: &[String],
	env_mode: Option<&str>,
	all: bool,
	filter: Option<&str>,
	affected: bool,
	base_ref: &str,
	no_cache: bool,
	json_output: bool,
) -> Result<(), LpmError> {
	// Ensure runtime is available at workspace root
	ensure_runtime(project_dir).await;

	let workspace = lpm_workspace::discover_workspace(project_dir)
		.map_err(|e| LpmError::Script(format!("workspace error: {e}")))?
		.ok_or_else(|| LpmError::Script(
			"no workspace found. --all/--filter/--affected require a monorepo".into(),
		))?;

	let graph = lpm_task::graph::WorkspaceGraph::from_workspace(&workspace);
	let levels = graph.topological_levels().map_err(|e| LpmError::Script(e.to_string()))?;
	let sorted: Vec<usize> = levels.iter().flatten().copied().collect();

	// Determine which packages to run in
	let target_set: std::collections::HashSet<usize> = if affected {
		lpm_task::affected::find_affected(&graph, &workspace.root, base_ref)
			.map_err(|e| LpmError::Script(e))?
	} else if let Some(filter_pat) = filter {
		sorted.iter().filter(|&&i| {
			let member = &graph.members[i];
			member.name.contains(filter_pat)
				|| member.path.to_string_lossy().contains(filter_pat)
		}).copied().collect()
	} else {
		sorted.iter().copied().collect()
	};

	if target_set.is_empty() {
		output::info("No packages matched");
		return Ok(());
	}

	let total = target_set.len();
	let succeeded = std::sync::atomic::AtomicUsize::new(0);
	let cached_count = std::sync::atomic::AtomicUsize::new(0);
	let start = std::time::Instant::now();
	let failed = std::sync::atomic::AtomicBool::new(false);

	// Run levels sequentially, but packages within each level in parallel
	for level in &levels {
		// Filter to only target packages in this level
		let level_targets: Vec<usize> = level.iter()
			.filter(|i| target_set.contains(i))
			.copied()
			.collect();

		if level_targets.is_empty() {
			continue;
		}

		if failed.load(std::sync::atomic::Ordering::Relaxed) {
			break;
		}

		// If only 1 package in this level, run sequentially (no thread overhead)
		if level_targets.len() == 1 {
			let idx = level_targets[0];
			let member = &graph.members[idx];
			let member_dir = &member.path;

			let pkg_json_path = member_dir.join("package.json");
			if !pkg_json_path.exists() { continue; }
			let pkg = lpm_workspace::read_package_json(&pkg_json_path)
				.map_err(|e| LpmError::Script(format!("{}: {e}", member.name)))?;
			if !pkg.scripts.contains_key(script_name) { continue; }

			if !no_cache {
				if let Ok(Some(_hit)) = try_cache_hit(member_dir, script_name, env_mode) {
					println!("{} {} (cached)", format!("[{}]", member.name).dimmed(), script_name.green());
					cached_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
					succeeded.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
					continue;
				}
			}

			println!("{} {}", format!("[{}]", member.name).cyan(), script_name);
			let task_start = std::time::Instant::now();
			lpm_runner::script::run_script(member_dir, script_name, extra_args, env_mode)?;
			let task_ms = task_start.elapsed().as_millis() as u64;
			if !no_cache {
				let _ = try_cache_store(member_dir, script_name, env_mode, task_ms);
			}
			succeeded.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
			continue;
		}

		// Multiple packages in this level — run in parallel
		let handles: Vec<_> = level_targets.iter().map(|&idx| {
			let member_name = graph.members[idx].name.clone();
			let member_dir = graph.members[idx].path.clone();
			let script = script_name.to_string();
			let args: Vec<String> = extra_args.to_vec();
			let mode = env_mode.map(|s| s.to_string());
			let no_cache = no_cache;

			std::thread::spawn(move || -> Result<(String, bool), String> {
				let pkg_json_path = member_dir.join("package.json");
				if !pkg_json_path.exists() {
					return Ok((member_name, false)); // skip
				}
				let pkg = lpm_workspace::read_package_json(&pkg_json_path)
					.map_err(|e| format!("{member_name}: {e}"))?;
				if !pkg.scripts.contains_key(&script) {
					return Ok((member_name, false)); // skip
				}

				println!("{} {}", format!("[{member_name}]"), script);

				lpm_runner::script::run_script(
					&member_dir, &script, &args, mode.as_deref(),
				).map_err(|e| format!("{member_name}: {e}"))?;

				Ok((member_name, true))
			})
		}).collect();

		for handle in handles {
			match handle.join() {
				Ok(Ok((_name, ran))) => {
					if ran {
						succeeded.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
					}
				}
				Ok(Err(e)) => {
					failed.store(true, std::sync::atomic::Ordering::Relaxed);
					return Err(LpmError::Script(e));
				}
				Err(_) => {
					failed.store(true, std::sync::atomic::Ordering::Relaxed);
					return Err(LpmError::Script("workspace task panicked".into()));
				}
			}
		}
	}

	let elapsed = start.elapsed();
	let succeeded = succeeded.load(std::sync::atomic::Ordering::Relaxed);
	let cached = cached_count.load(std::sync::atomic::Ordering::Relaxed);
	if json_output {
		println!("{}", serde_json::json!({
			"packages": total,
			"succeeded": succeeded,
			"cached": cached,
			"duration_ms": elapsed.as_millis() as u64,
		}));
	} else {
		output::success(&format!(
			"{total} packages, {succeeded} succeeded, {cached} cached ({:.1}s)",
			elapsed.as_secs_f64()
		));
	}

	Ok(())
}

/// Run a script in watch mode — re-run on file changes.
pub fn run_watch(
	project_dir: &Path,
	script_name: &str,
	extra_args: &[String],
	env_mode: Option<&str>,
	no_cache: bool,
) -> Result<(), LpmError> {
	output::info(&format!("watching {} (Ctrl+C to stop)", script_name.bold()));

	let script = script_name.to_string();
	let args: Vec<String> = extra_args.to_vec();
	let mode = env_mode.map(|s| s.to_string());
	let dir = project_dir.to_path_buf();

	lpm_task::watch::watch_and_run(project_dir, Box::new(move || {
		// Clear screen between runs
		print!("\x1B[2J\x1B[1;1H");
		println!(
			"{} running {} ...",
			owo_colors::OwoColorize::dimmed(&"[watch]"),
			script,
		);

		let result = lpm_runner::script::run_script(
			&dir,
			&script,
			&args,
			mode.as_deref(),
		);

		match result {
			Ok(()) => {
				println!(
					"\n{} {} completed. Waiting for changes...",
					owo_colors::OwoColorize::green(&"✔"),
					script,
				);
			}
			Err(e) => {
				eprintln!(
					"\n{} {}: {}",
					owo_colors::OwoColorize::red(&"✖"),
					script,
					e,
				);
				eprintln!("Waiting for changes...");
			}
		}
	}))
	.map_err(|e| LpmError::Script(format!("watch error: {e}")))?;

	Ok(())
}

/// Execute a file directly, auto-detecting the runtime.
pub async fn exec(
	project_dir: &Path,
	file_path: &str,
	extra_args: &[String],
) -> Result<(), LpmError> {
	ensure_runtime(project_dir).await;
	output::info(&format!("exec {}", file_path.bold()));
	lpm_runner::exec::exec_file(project_dir, file_path, extra_args)
}

/// Run a package binary without installing it into the project.
///
/// Uses LPM's own install pipeline (self-hosted, no npm dependency).
/// Caches installations for 24 hours. Use `--refresh` to force reinstall.
pub async fn dlx(
	project_dir: &Path,
	package_spec: &str,
	extra_args: &[String],
	refresh: bool,
) -> Result<(), LpmError> {
	let cache_dir = lpm_runner::dlx::dlx_cache_dir(package_spec)?;

	let needs_install = if refresh {
		true
	} else if !cache_dir.join("node_modules/.bin").is_dir() {
		true
	} else if !lpm_runner::dlx::is_cache_fresh(&cache_dir, lpm_runner::dlx::CACHE_TTL_SECS) {
		output::info(&format!("cache expired for {}, reinstalling...", package_spec.bold()));
		true
	} else {
		false
	};

	if needs_install {
		std::fs::create_dir_all(&cache_dir).map_err(|e| {
			LpmError::Script(format!("failed to create dlx cache dir: {e}"))
		})?;

		let (pkg_name, version_spec) = lpm_runner::dlx::parse_package_spec(package_spec);

		// Write package.json with the target dependency
		let pkg_json = format!(
			r#"{{"private":true,"dependencies":{{"{pkg_name}":"{version_spec}"}}}}"#,
		);
		std::fs::write(cache_dir.join("package.json"), &pkg_json).map_err(|e| {
			LpmError::Script(format!("failed to write dlx package.json: {e}"))
		})?;

		output::info(&format!("installing {}...", package_spec.bold()));

		// Self-hosted install using LPM's own resolver/store/linker
		let registry_url = std::env::var("LPM_REGISTRY_URL")
			.unwrap_or_else(|_| lpm_common::DEFAULT_REGISTRY_URL.to_string());
		let client = lpm_registry::RegistryClient::new()
			.with_base_url(&registry_url);

		// Pass to install pipeline (same as `lpm install`)
		crate::commands::install::run_with_options(
			&client,
			&cache_dir,
			false, // json_output
			false, // offline
		)
		.await?;

		lpm_runner::dlx::touch_cache(&cache_dir);
	}

	// Execute the binary
	lpm_runner::dlx::exec_dlx_binary(project_dir, &cache_dir, package_spec, extra_args)
}

// --- Cache helpers ---

fn try_cache_hit(
	project_dir: &Path,
	script_name: &str,
	env_mode: Option<&str>,
) -> Result<Option<lpm_task::cache::CacheHit>, LpmError> {
	let config = lpm_runner::lpm_json::read_lpm_json(project_dir)
		.map_err(|e| LpmError::Script(e))?;

	let task_config = config
		.as_ref()
		.and_then(|c| c.tasks.get(script_name));

	let task_config = match task_config {
		Some(tc) if tc.cache => tc,
		_ => return Ok(None), // Caching not enabled for this task
	};

	let env_vars = lpm_runner::dotenv::load_env_files(project_dir, env_mode);

	// Read deps for cache key
	let pkg_json_path = project_dir.join("package.json");
	let deps_json = if pkg_json_path.exists() {
		let pkg = lpm_workspace::read_package_json(&pkg_json_path)
			.map_err(|e| LpmError::Script(format!("failed to read package.json: {e}")))?;
		serde_json::to_string(&pkg.dependencies).unwrap_or_default()
	} else {
		"{}".into()
	};

	// Resolve the command
	let command = if let Some(cmd) = &task_config.command {
		cmd.clone()
	} else if pkg_json_path.exists() {
		let pkg = lpm_workspace::read_package_json(&pkg_json_path)
			.map_err(|e| LpmError::Script(format!("{e}")))?;
		pkg.scripts.get(script_name).cloned().unwrap_or_default()
	} else {
		String::new()
	};

	let cache_key = lpm_task::hasher::compute_cache_key(
		project_dir,
		&command,
		&task_config.effective_inputs(),
		&env_vars,
		&deps_json,
	);

	if lpm_task::cache::has_cache_hit(&cache_key) {
		let hit = lpm_task::cache::restore_cache(&cache_key, project_dir)?;
		return Ok(Some(hit));
	}

	Ok(None)
}

/// Check if a task has caching enabled in lpm.json.
fn is_task_cached(project_dir: &Path, script_name: &str) -> bool {
	lpm_runner::lpm_json::read_lpm_json(project_dir)
		.ok()
		.flatten()
		.and_then(|c| c.tasks.get(script_name).cloned())
		.map(|tc| tc.cache && !tc.outputs.is_empty())
		.unwrap_or(false)
}

/// Store cache with captured stdout/stderr.
fn try_cache_store_with_output(
	project_dir: &Path,
	script_name: &str,
	env_mode: Option<&str>,
	duration_ms: u64,
	stdout: &str,
	stderr: &str,
) -> Result<(), LpmError> {
	let config = lpm_runner::lpm_json::read_lpm_json(project_dir)
		.map_err(|e| LpmError::Script(e))?;

	let task_config = config
		.as_ref()
		.and_then(|c| c.tasks.get(script_name));

	let task_config = match task_config {
		Some(tc) if tc.cache && !tc.outputs.is_empty() => tc,
		_ => return Ok(()),
	};

	let env_vars = lpm_runner::dotenv::load_env_files(project_dir, env_mode);

	let pkg_json_path = project_dir.join("package.json");
	let deps_json = if pkg_json_path.exists() {
		let pkg = lpm_workspace::read_package_json(&pkg_json_path)
			.map_err(|e| LpmError::Script(format!("{e}")))?;
		serde_json::to_string(&pkg.dependencies).unwrap_or_default()
	} else {
		"{}".into()
	};

	let command = if let Some(cmd) = &task_config.command {
		cmd.clone()
	} else if pkg_json_path.exists() {
		let pkg = lpm_workspace::read_package_json(&pkg_json_path)
			.map_err(|e| LpmError::Script(format!("{e}")))?;
		pkg.scripts.get(script_name).cloned().unwrap_or_default()
	} else {
		String::new()
	};

	let cache_key = lpm_task::hasher::compute_cache_key(
		project_dir,
		&command,
		&task_config.effective_inputs(),
		&env_vars,
		&deps_json,
	);

	lpm_task::cache::store_cache(
		&cache_key,
		project_dir,
		&command,
		&task_config.outputs,
		stdout,
		stderr,
		duration_ms,
	)?;

	tracing::debug!("stored cache for task '{script_name}' (key: {cache_key}, stdout: {} bytes)", stdout.len());
	Ok(())
}

fn try_cache_store(
	project_dir: &Path,
	script_name: &str,
	env_mode: Option<&str>,
	duration_ms: u64,
) -> Result<(), LpmError> {
	let config = lpm_runner::lpm_json::read_lpm_json(project_dir)
		.map_err(|e| LpmError::Script(e))?;

	let task_config = config
		.as_ref()
		.and_then(|c| c.tasks.get(script_name));

	let task_config = match task_config {
		Some(tc) if tc.cache && !tc.outputs.is_empty() => tc,
		_ => return Ok(()), // Caching not enabled or no outputs
	};

	let env_vars = lpm_runner::dotenv::load_env_files(project_dir, env_mode);

	let pkg_json_path = project_dir.join("package.json");
	let deps_json = if pkg_json_path.exists() {
		let pkg = lpm_workspace::read_package_json(&pkg_json_path)
			.map_err(|e| LpmError::Script(format!("{e}")))?;
		serde_json::to_string(&pkg.dependencies).unwrap_or_default()
	} else {
		"{}".into()
	};

	let command = if let Some(cmd) = &task_config.command {
		cmd.clone()
	} else if pkg_json_path.exists() {
		let pkg = lpm_workspace::read_package_json(&pkg_json_path)
			.map_err(|e| LpmError::Script(format!("{e}")))?;
		pkg.scripts.get(script_name).cloned().unwrap_or_default()
	} else {
		String::new()
	};

	let cache_key = lpm_task::hasher::compute_cache_key(
		project_dir,
		&command,
		&task_config.effective_inputs(),
		&env_vars,
		&deps_json,
	);

	// For now, store without stdout capture (full tee comes later)
	lpm_task::cache::store_cache(
		&cache_key,
		project_dir,
		&command,
		&task_config.outputs,
		"", // TODO: stdout capture via tee
		"",
		duration_ms,
	)?;

	tracing::debug!("stored cache for task '{script_name}' (key: {cache_key})");
	Ok(())
}
