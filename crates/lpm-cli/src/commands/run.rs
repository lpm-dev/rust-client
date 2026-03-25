use crate::output;
use lpm_common::LpmError;
use owo_colors::OwoColorize;
use std::path::Path;

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

	let start = std::time::Instant::now();
	lpm_runner::script::run_script(project_dir, script_name, extra_args, env_mode)?;
	let duration_ms = start.elapsed().as_millis() as u64;

	// Store to cache if enabled
	if !no_cache {
		let _ = try_cache_store(project_dir, script_name, env_mode, duration_ms);
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
	let workspace = lpm_workspace::discover_workspace(project_dir)
		.map_err(|e| LpmError::Script(format!("workspace error: {e}")))?
		.ok_or_else(|| LpmError::Script(
			"no workspace found. --all/--filter/--affected require a monorepo".into(),
		))?;

	let graph = lpm_task::graph::WorkspaceGraph::from_workspace(&workspace);
	let sorted = graph.topological_sort().map_err(|e| LpmError::Script(e.to_string()))?;

	// Determine which packages to run in
	let target_indices: Vec<usize> = if affected {
		let affected_set = lpm_task::affected::find_affected(&graph, &workspace.root, base_ref)
			.map_err(|e| LpmError::Script(e))?;
		sorted.iter().filter(|i| affected_set.contains(i)).copied().collect()
	} else if let Some(filter_pat) = filter {
		sorted.iter().filter(|&&i| {
			let member = &graph.members[i];
			member.name.contains(filter_pat)
				|| member.path.to_string_lossy().contains(filter_pat)
		}).copied().collect()
	} else {
		// --all: all packages in topological order
		sorted.clone()
	};

	if target_indices.is_empty() {
		output::info("No packages matched");
		return Ok(());
	}

	let total = target_indices.len();
	let mut succeeded = 0;
	let mut cached = 0;
	let start = std::time::Instant::now();

	for &idx in &target_indices {
		let member = &graph.members[idx];
		let member_dir = &member.path;
		let label = format!("[{}]", member.name);

		// Check if this member has the script
		let pkg_json_path = member_dir.join("package.json");
		if !pkg_json_path.exists() {
			continue;
		}
		let pkg = lpm_workspace::read_package_json(&pkg_json_path)
			.map_err(|e| LpmError::Script(format!("{}: {e}", member.name)))?;
		if !pkg.scripts.contains_key(script_name) {
			continue;
		}

		// Try cache
		if !no_cache {
			if let Some(hit) = try_cache_hit(member_dir, script_name, env_mode)? {
				println!("{} {} (cached)", label.dimmed(), script_name.green());
				cached += 1;
				succeeded += 1;
				continue;
			}
		}

		println!("{} {}", label.cyan(), script_name);
		let task_start = std::time::Instant::now();

		lpm_runner::script::run_script(member_dir, script_name, extra_args, env_mode)?;

		let task_ms = task_start.elapsed().as_millis() as u64;
		if !no_cache {
			let _ = try_cache_store(member_dir, script_name, env_mode, task_ms);
		}

		succeeded += 1;
	}

	let elapsed = start.elapsed();
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
	output::info(&format!("exec {}", file_path.bold()));
	lpm_runner::exec::exec_file(project_dir, file_path, extra_args)
}

/// Run a package binary without installing it into the project.
pub async fn dlx(
	project_dir: &Path,
	package_spec: &str,
	extra_args: &[String],
) -> Result<(), LpmError> {
	output::info(&format!("dlx {}", package_spec.bold()));
	lpm_runner::dlx::dlx(project_dir, package_spec, extra_args)
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
