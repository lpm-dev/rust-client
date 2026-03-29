use crate::output;
use lpm_common::{LpmError, PackageName};
use lpm_registry::RegistryClient;
use owo_colors::OwoColorize;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

/// Result of handling a file conflict.
enum ConflictAction {
	Skip,
	Overwrite,
}

/// Add source files from a package into your project (shadcn-style).
///
/// Always does source delivery: download, extract, copy files.
/// For managed dependency installation, use `lpm install` instead.
pub async fn run(
	client: &RegistryClient,
	project_dir: &Path,
	package_spec: &str,
	target_path: Option<&str>,
	yes: bool,
	json_output: bool,
	force: bool,
	dry_run: bool,
	no_install_deps: bool,
	no_skills: bool,
	no_editor_setup: bool,
	pm: &str,
) -> Result<(), LpmError> {
	let is_tty = std::io::IsTerminal::is_terminal(&std::io::stdin());

	// Step 1: Parse package reference
	let (pkg_ref, version_spec, mut inline_config) = parse_package_ref(package_spec);

	let name = PackageName::parse(&pkg_ref)?;

	// Typosquatting check: warn if the name looks like a popular package misspelling
	if !json_output {
		// Check the bare package name (without scope) for npm-ecosystem typosquats
		let bare_name = pkg_ref.strip_prefix("@lpm.dev/").unwrap_or(&pkg_ref);
		if let Some(similar) = lpm_security::typosquatting::check_typosquatting(bare_name) {
			output::warn(&format!(
				"'{}' is similar to popular package '{}'. Did you mean '{}'?",
				bare_name, similar, similar
			));
		}
	}

	if !json_output {
		output::info(&format!("Adding {}", name.scoped().bold()));
	}

	// Step 2: Fetch metadata
	let metadata = client.get_package_metadata(&name).await?;
	let version = if let Some(v) = &version_spec {
		v.clone()
	} else {
		metadata
			.latest_version_tag()
			.ok_or_else(|| LpmError::NotFound("no latest version".into()))?
			.to_string()
	};

	let ver_meta = metadata.version(&version).ok_or_else(|| {
		LpmError::NotFound(format!("version {version} not found"))
	})?;

	if !json_output {
		output::info(&format!("Downloading {}@{}", name.scoped(), version.bold()));
	}

	// Step 3: Download tarball
	let tarball_url = ver_meta.tarball_url().ok_or_else(|| {
		LpmError::NotFound("no tarball URL".into())
	})?;
	let tarball_data = client.download_tarball(tarball_url).await?;

	// Step 3.1: Verify tarball integrity
	if let Some(integrity) = ver_meta.integrity() {
		lpm_extractor::verify_integrity(&tarball_data, integrity)?;
		if !json_output {
			output::info("Integrity verified");
		}
	} else {
		tracing::debug!(
			"no integrity hash for {}@{}, skipping verification",
			name.scoped(),
			version
		);
	}

	// Step 3.2: Extract tarball
	let temp_dir = tempfile::tempdir()
		.map_err(|e| LpmError::Io(e.into()))?;
	let extracted_paths = lpm_extractor::extract_tarball(&tarball_data, temp_dir.path())?;

	// Step 3.3: Validate extracted paths for path traversal
	validate_extracted_paths(&extracted_paths, temp_dir.path())?;

	// Step 4: Read lpm.config.json
	let lpm_config = read_lpm_config(temp_dir.path());

	// Step 4.1: Config schema interactive prompts
	if let Some(config) = &lpm_config {
		if let Some(schema) = config.get("configSchema").and_then(|s| s.as_object()) {
			if !yes && !json_output && is_tty {
				for (key, field) in schema {
					// Skip if already provided via inline config
					if inline_config.contains_key(key) {
						continue;
					}

					let field_type = field
						.get("type")
						.and_then(|t| t.as_str())
						.unwrap_or("string");
					let label = field
						.get("label")
						.and_then(|l| l.as_str())
						.unwrap_or(key);
					let default_val = config
						.get("defaultConfig")
						.and_then(|dc| dc.get(key))
						.and_then(|d| d.as_str())
						.or_else(|| field.get("default").and_then(|d| d.as_str()))
						.unwrap_or("");

					match field_type {
						"boolean" => {
							let result = dialoguer::Confirm::new()
								.with_prompt(label)
								.default(default_val == "true")
								.interact()
								.map_err(|e| LpmError::Registry(e.to_string()))?;
							inline_config.insert(key.clone(), result.to_string());
						}
						"select" => {
							let multi = field
								.get("multiSelect")
								.and_then(|m| m.as_bool())
								.unwrap_or(false);
							let options: Vec<String> = field
								.get("options")
								.and_then(|o| o.as_array())
								.map(|arr| {
									arr.iter()
										.filter_map(|v| {
											if let Some(s) = v.as_str() {
												Some(s.to_string())
											} else {
												v.get("value")
													.and_then(|vv| vv.as_str())
													.map(|s| s.to_string())
											}
										})
										.collect()
								})
								.unwrap_or_default();

							if options.is_empty() {
								continue;
							}

							if multi {
								let defaults: Vec<bool> = options
									.iter()
									.map(|_| true) // default all selected
									.collect();
								let selections = dialoguer::MultiSelect::new()
									.with_prompt(label)
									.items(&options)
									.defaults(&defaults)
									.interact()
									.map_err(|e| LpmError::Registry(e.to_string()))?;
								let selected: Vec<&str> = selections
									.iter()
									.map(|&i| options[i].as_str())
									.collect();
								inline_config
									.insert(key.clone(), selected.join(","));
							} else {
								let default_idx = options
									.iter()
									.position(|o| o == default_val)
									.unwrap_or(0);
								let selection = dialoguer::Select::new()
									.with_prompt(label)
									.items(&options)
									.default(default_idx)
									.interact()
									.map_err(|e| LpmError::Registry(e.to_string()))?;
								inline_config
									.insert(key.clone(), options[selection].clone());
							}
						}
						_ => {
							// string / text input
							let value: String = dialoguer::Input::new()
								.with_prompt(label)
								.default(default_val.to_string())
								.interact_text()
								.map_err(|e| LpmError::Registry(e.to_string()))?;
							inline_config.insert(key.clone(), value);
						}
					}
				}
			} else if yes {
				// --yes: use defaults for required fields that aren't provided
				for (key, field) in schema {
					if inline_config.contains_key(key) {
						continue;
					}
					let is_required = field
						.get("required")
						.and_then(|r| r.as_bool())
						.unwrap_or(false);
					if is_required {
						let default_val = config
							.get("defaultConfig")
							.and_then(|dc| dc.get(key))
							.and_then(|d| d.as_str())
							.or_else(|| field.get("default").and_then(|d| d.as_str()))
							.unwrap_or("");
						inline_config.insert(key.clone(), default_val.to_string());
					}
				}
			}
		}
	}

	// Step 5: Detect ecosystem and determine target
	let ecosystem = lpm_config
		.as_ref()
		.and_then(|c| c.get("ecosystem").and_then(|v| v.as_str()))
		.unwrap_or("js");

	// Step 5.1: Interactive target directory selection
	let target_dir = if target_path.is_some() {
		resolve_target_dir(project_dir, target_path, ecosystem, yes)?
	} else if !yes && !json_output && is_tty && ecosystem != "swift" {
		let default_dir = detect_default_install_dir(project_dir, ecosystem);
		let default_str = default_dir
			.strip_prefix(project_dir)
			.unwrap_or(&default_dir)
			.display()
			.to_string();

		let target: String = dialoguer::Input::new()
			.with_prompt("Install directory")
			.default(default_str)
			.interact_text()
			.map_err(|e| LpmError::Registry(e.to_string()))?;

		project_dir.join(target)
	} else {
		resolve_target_dir(project_dir, target_path, ecosystem, yes)?
	};

	if !json_output {
		let rel = target_dir
			.strip_prefix(project_dir)
			.unwrap_or(&target_dir);
		output::info(&format!("Installing to {}", rel.display().to_string().bold()));
	}

	// Step 6: Build file list (config-based or all files)
	let files = if let Some(config) = &lpm_config {
		if let Some(files_arr) = config.get("files").and_then(|f| f.as_array()) {
			filter_config_files(
				temp_dir.path(),
				files_arr,
				&inline_config,
			)?
		} else {
			collect_all_source_files(temp_dir.path())?
		}
	} else {
		collect_all_source_files(temp_dir.path())?
	};

	if files.is_empty() {
		return Err(LpmError::Registry("no files to install".into()));
	}

	// Step 6.1: Dry-run mode — show what would happen and exit
	if dry_run {
		return handle_dry_run(
			project_dir,
			&target_dir,
			&files,
			force,
			&name,
			&version,
			&lpm_config,
			&inline_config,
			ecosystem,
			json_output,
		);
	}

	// Step 7: Prepare import rewriting
	let author_alias = lpm_config
		.as_ref()
		.and_then(|c| c.get("importAlias"))
		.and_then(|v| v.as_str())
		.map(|s| s.to_string());

	let buyer_alias = detect_buyer_alias(project_dir);

	// Build src->dest map and dest file set for import resolution
	let src_to_dest: HashMap<String, String> = files.iter().cloned().collect();
	let dest_files: HashSet<String> = files.iter().map(|(_, d)| d.clone()).collect();

	// Step 8: Copy files to target (with import rewriting and conflict resolution)
	let mut copied = 0;
	let mut skipped = 0;
	let mut file_actions: Vec<(String, String, String)> = Vec::new(); // (src, dest, action)
	std::fs::create_dir_all(&target_dir)?;

	for (src_rel, dest_rel) in &files {
		let src_path = temp_dir.path().join(src_rel);
		let dest_path = target_dir.join(dest_rel);

		if !src_path.exists() {
			continue;
		}

		// Create parent dirs
		if let Some(parent) = dest_path.parent() {
			std::fs::create_dir_all(parent)?;
		}

		// Try to read as text for import rewriting
		let content = std::fs::read_to_string(&src_path).ok();
		let rewritten = content.as_deref().and_then(|text| {
			// Only rewrite JS/TS files
			let ext = src_path.extension().and_then(|e| e.to_str()).unwrap_or("");
			if !matches!(ext, "js" | "jsx" | "ts" | "tsx" | "mjs" | "cjs") {
				return None;
			}
			crate::import_rewriter::rewrite_imports(
				text,
				author_alias.as_deref(),
				buyer_alias.as_deref(),
				&src_to_dest,
				&dest_files,
			)
		});

		let final_content = rewritten.as_deref().or(content.as_deref());

		let dest_existed = dest_path.exists();

		// Check for conflicts using diff-aware resolution
		if dest_existed {
			let action = handle_file_conflict(
				&src_path,
				&dest_path,
				final_content,
				force,
				yes,
				json_output,
			)?;
			match action {
				ConflictAction::Skip => {
					skipped += 1;
					file_actions.push((src_rel.clone(), dest_rel.clone(), "skip".to_string()));
					continue;
				}
				ConflictAction::Overwrite => {
					// Fall through to write
				}
			}
		}

		// Write (rewritten text or copy binary)
		if let Some(text) = final_content {
			std::fs::write(&dest_path, text)?;
		} else {
			std::fs::copy(&src_path, &dest_path)?;
		}
		copied += 1;
		file_actions.push((
			src_rel.clone(),
			dest_rel.clone(),
			if dest_existed { "overwrite" } else { "create" }.to_string(),
		));
	}

	// Step 9: Handle dependencies (respects --no-install-deps)
	let dep_count = if !no_install_deps {
		handle_dependencies(
			project_dir,
			&lpm_config,
			&inline_config,
			ecosystem,
			yes,
			json_output,
			pm,
		)
		.await?
	} else {
		let count = count_dependencies(&lpm_config, &inline_config);
		if count > 0 && !json_output {
			output::info(&format!(
				"Skipped {} dependencies (--no-install-deps)",
				count
			));
		}
		0
	};

	// Step 10: For Swift, handle recursive LPM dependencies
	if ecosystem == "swift" {
		handle_swift_lpm_deps(
			client,
			project_dir,
			ver_meta,
			yes,
			json_output,
			force,
			dry_run,
			no_install_deps,
			no_skills,
			no_editor_setup,
			pm,
		)
		.await?;
	}

	// Step 11: Output
	if json_output {
		let json = serde_json::json!({
			"success": true,
			"package": {
				"name": name.scoped(),
				"version": version,
				"ecosystem": ecosystem,
			},
			"files": file_actions.iter().map(|(src, dest, action)| {
				serde_json::json!({
					"src": src,
					"dest": dest,
					"action": action,
				})
			}).collect::<Vec<_>>(),
			"installPath": target_dir.strip_prefix(project_dir).unwrap_or(&target_dir).display().to_string(),
			"files_copied": copied,
			"files_skipped": skipped,
			"dependencies_installed": dep_count,
			"config": inline_config,
			"alias": buyer_alias,
			"warnings": [],
			"errors": [],
		});
		println!("{}", serde_json::to_string_pretty(&json).unwrap());
	} else {
		println!();
		output::success(&format!(
			"Added {}@{} ({} files)",
			name.scoped().bold(),
			version,
			copied,
		));
		if skipped > 0 {
			println!("  {} files unchanged (skipped)", skipped.to_string().dimmed());
		}
		if dep_count > 0 {
			println!("  {} dependencies installed", dep_count.to_string().dimmed());
		}

		// Security check for source delivery too
		if ver_meta.has_security_issues() {
			print_security_warnings(&name.scoped(), &version, ver_meta);
		}
		println!();
	}

	// Step 12: Install skills if this is an LPM package (respects --no-skills)
	if !no_skills {
		let package_name = name.scoped();
		if package_name.starts_with("@lpm.dev/") {
			let short_name = package_name
				.strip_prefix("@lpm.dev/")
				.unwrap_or(&package_name);
			match client.get_skills(short_name, None).await {
				Ok(response) if !response.skills.is_empty() => {
					let skills_dir = project_dir
						.join(".lpm")
						.join("skills")
						.join(short_name);
					let _ = std::fs::create_dir_all(&skills_dir);

					let mut installed = 0;
					for skill in &response.skills {
						let content = skill
							.raw_content
							.as_deref()
							.or(skill.content.as_deref())
							.unwrap_or("");
						if !content.is_empty() {
							let path = skills_dir.join(format!("{}.md", skill.name));
							let _ = std::fs::write(&path, content);
							installed += 1;
						}
					}

					if installed > 0 && !json_output {
						output::info(&format!(
							"Installed {installed} agent skill(s) for {short_name}"
						));

						// Ensure .gitignore includes .lpm/skills/
						crate::commands::install::ensure_skills_gitignore(project_dir);

						// Auto-integrate with editors (respects --no-editor-setup)
						if !no_editor_setup {
							let integrations =
								crate::editor_skills::auto_integrate_skills(project_dir);
							for msg in &integrations {
								output::info(msg);
							}
						}
					}
				}
				_ => {} // No skills or API error -- skip silently
			}
		}
	}

	Ok(())
}

// ---------------------------------------------------------------------------
// Path traversal validation
// ---------------------------------------------------------------------------

/// Validate that all extracted file paths stay within the target directory.
///
/// Prevents malicious tarballs from writing outside the extraction directory
/// using `../` or symlink tricks.
fn validate_extracted_paths(files: &[PathBuf], target_dir: &Path) -> Result<(), LpmError> {
	let target_canonical = target_dir
		.canonicalize()
		.unwrap_or_else(|_| target_dir.to_path_buf());

	for file in files {
		let resolved = target_dir.join(file);
		let canonical = resolved
			.canonicalize()
			.unwrap_or_else(|_| resolved.clone());
		if !canonical.starts_with(&target_canonical) {
			return Err(LpmError::Registry(format!(
				"path traversal detected: '{}' escapes target directory",
				file.display()
			)));
		}
	}
	Ok(())
}

// ---------------------------------------------------------------------------
// Interactive target directory detection
// ---------------------------------------------------------------------------

/// Detect a reasonable default install directory based on project structure.
fn detect_default_install_dir(project_dir: &Path, _ecosystem: &str) -> PathBuf {
	for dir in [
		"src/components",
		"components",
		"src/lib",
		"lib",
		"src",
		"app",
	] {
		if project_dir.join(dir).is_dir() {
			return project_dir.join(dir);
		}
	}
	project_dir.join("src")
}

// ---------------------------------------------------------------------------
// File conflict resolution with diff preview
// ---------------------------------------------------------------------------

/// Handle a file conflict when the destination already exists.
///
/// Compares content and prompts the user with diff preview when interactive.
fn handle_file_conflict(
	_source_path: &Path,
	target_path: &Path,
	new_content: Option<&str>,
	force: bool,
	yes: bool,
	json_output: bool,
) -> Result<ConflictAction, LpmError> {
	if force {
		return Ok(ConflictAction::Overwrite);
	}

	// Read existing content
	let existing_bytes = std::fs::read(target_path)?;

	// Compare: if new_content is Some, compare as text; otherwise compare bytes
	if let Some(new_text) = new_content {
		let existing_text = String::from_utf8_lossy(&existing_bytes);
		if existing_text.as_ref() == new_text {
			return Ok(ConflictAction::Skip); // Identical
		}
	}

	// Non-interactive: skip conflicts
	if yes || json_output || !std::io::IsTerminal::is_terminal(&std::io::stdin()) {
		return Ok(ConflictAction::Skip);
	}

	// Show diff preview
	let rel_display = target_path
		.file_name()
		.map(|n| n.to_string_lossy().to_string())
		.unwrap_or_else(|| target_path.display().to_string());

	eprintln!(
		"\n  {} File exists: {}",
		"\u{26a0}".yellow(),
		rel_display
	);

	// Show a brief line-count diff summary
	if let Some(new_text) = new_content {
		let existing_text = String::from_utf8_lossy(&existing_bytes);
		let old_lines: Vec<&str> = existing_text.lines().collect();
		let new_lines: Vec<&str> = new_text.lines().collect();

		let mut added = 0usize;
		let mut removed = 0usize;
		let max_compare = old_lines.len().max(new_lines.len());
		for i in 0..max_compare {
			let old_line = old_lines.get(i).copied();
			let new_line = new_lines.get(i).copied();
			if old_line != new_line {
				if old_line.is_some() {
					removed += 1;
				}
				if new_line.is_some() {
					added += 1;
				}
			}
		}
		eprintln!(
			"    {} lines added, {} lines removed",
			format!("+{added}").green(),
			format!("-{removed}").red()
		);
	}

	let items = ["Skip (keep existing)", "Overwrite", "View full diff"];
	let action = dialoguer::Select::new()
		.with_prompt("How to handle?")
		.items(&items)
		.default(0)
		.interact()
		.map_err(|e| LpmError::Registry(e.to_string()))?;

	match action {
		0 => Ok(ConflictAction::Skip),
		1 => Ok(ConflictAction::Overwrite),
		2 => {
			// Print full diff then re-prompt
			if let Some(new_text) = new_content {
				let existing_text = String::from_utf8_lossy(&existing_bytes);
				eprintln!("\n  --- existing");
				eprintln!("  +++ incoming\n");
				for (i, (old, new)) in existing_text
					.lines()
					.zip(new_text.lines())
					.enumerate()
				{
					if old != new {
						eprintln!("  {:>4} {} {}", i + 1, "-".red(), old.red());
						eprintln!("  {:>4} {} {}", i + 1, "+".green(), new.green());
					}
				}
				eprintln!();
			}

			// Re-prompt after showing diff
			let re_items = ["Skip (keep existing)", "Overwrite"];
			let re_action = dialoguer::Select::new()
				.with_prompt("How to handle?")
				.items(&re_items)
				.default(0)
				.interact()
				.map_err(|e| LpmError::Registry(e.to_string()))?;

			match re_action {
				1 => Ok(ConflictAction::Overwrite),
				_ => Ok(ConflictAction::Skip),
			}
		}
		_ => Ok(ConflictAction::Skip),
	}
}

// ---------------------------------------------------------------------------
// Dry-run mode
// ---------------------------------------------------------------------------

/// Show what would happen without writing any files.
fn handle_dry_run(
	project_dir: &Path,
	target_dir: &Path,
	files: &[(String, String)],
	force: bool,
	name: &PackageName,
	version: &str,
	lpm_config: &Option<serde_json::Value>,
	inline_config: &HashMap<String, String>,
	_ecosystem: &str,
	json_output: bool,
) -> Result<(), LpmError> {
	let mut file_actions = Vec::new();

	for (_src_rel, dest_rel) in files {
		let target = target_dir.join(dest_rel);
		let exists = target.exists();
		let action = if exists {
			if force { "overwrite" } else { "skip" }
		} else {
			"create"
		};
		file_actions.push((dest_rel.clone(), action));
	}

	// Count dependencies that would be installed
	let dep_count = count_dependencies(lpm_config, inline_config);

	if json_output {
		let files_json: Vec<serde_json::Value> = file_actions
			.iter()
			.map(|(path, action)| {
				serde_json::json!({
					"path": path,
					"action": action,
				})
			})
			.collect();

		let json = serde_json::json!({
			"dry_run": true,
			"package": name.scoped(),
			"version": version,
			"target": target_dir.strip_prefix(project_dir).unwrap_or(target_dir).display().to_string(),
			"files": files_json,
			"dependencies_count": dep_count,
		});
		println!("{}", serde_json::to_string_pretty(&json).unwrap());
	} else {
		eprintln!("\n  Dry run -- no files will be modified.\n");
		eprintln!(
			"  Would install to: {}",
			target_dir
				.strip_prefix(project_dir)
				.unwrap_or(target_dir)
				.display()
		);
		eprintln!("  Files:");
		for (path, action) in &file_actions {
			let icon = if *action == "create" {
				"+".green().to_string()
			} else if *action == "overwrite" {
				"~".yellow().to_string()
			} else {
				"-".dimmed().to_string()
			};
			eprintln!("    {} {} ({})", icon, path, action);
		}
		if dep_count > 0 {
			eprintln!("\n  Dependencies to install: {dep_count}");

			// Show individual dep names if available
			if let Some(config) = lpm_config {
				if let Some(dep_config) = config.get("dependencies").and_then(|d| d.as_object()) {
					for (config_key, dep_map) in dep_config {
						let config_value =
							inline_config.get(config_key).map(|s| s.as_str()).unwrap_or("");
						if config_value.is_empty() {
							continue;
						}
						if let Some(deps) = dep_map.get(config_value).and_then(|d| d.as_array()) {
							for dep in deps {
								if let Some(dep_name) = dep.as_str() {
									eprintln!("    {dep_name}");
								}
							}
						}
					}
				}
			}
		}
		eprintln!();
	}

	Ok(())
}

// ---------------------------------------------------------------------------
// Package manager detection (for --pm=auto)
// ---------------------------------------------------------------------------

/// Detect the package manager from lockfile presence in the project directory.
fn detect_package_manager(project_dir: &Path) -> String {
	if project_dir.join("pnpm-lock.yaml").exists() {
		"pnpm"
	} else if project_dir.join("yarn.lock").exists() {
		"yarn"
	} else if project_dir.join("bun.lockb").exists() || project_dir.join("bun.lock").exists() {
		"bun"
	} else if project_dir.join("package-lock.json").exists() {
		"npm"
	} else {
		"lpm"
	}
	.to_string()
}

// ---------------------------------------------------------------------------
// Dependency counting (for dry-run and --no-install-deps)
// ---------------------------------------------------------------------------

/// Count how many dependencies would be installed without actually installing them.
fn count_dependencies(
	lpm_config: &Option<serde_json::Value>,
	inline_config: &HashMap<String, String>,
) -> usize {
	let config = match lpm_config {
		Some(c) => c,
		None => return 0,
	};

	let dep_config = match config.get("dependencies").and_then(|d| d.as_object()) {
		Some(d) => d,
		None => return 0,
	};

	let mut count = 0;
	for (config_key, dep_map) in dep_config {
		let config_value = inline_config.get(config_key).map(|s| s.as_str()).unwrap_or("");
		if config_value.is_empty() {
			continue;
		}
		if let Some(deps) = dep_map.get(config_value).and_then(|d| d.as_array()) {
			count += deps
				.iter()
				.filter(|d| {
					d.as_str()
						.map(|s| !s.starts_with("@lpm.dev/"))
						.unwrap_or(false)
				})
				.count();
		}
	}
	count
}

/// Detect the buyer's import alias from tsconfig.json or jsconfig.json.
///
/// Reads `compilerOptions.paths` and returns the first alias ending with `/*`.
/// e.g., `{ "@/*": ["./src/*"] }` -> `"@/"`
fn detect_buyer_alias(project_dir: &Path) -> Option<String> {
	for config_name in ["tsconfig.json", "jsconfig.json"] {
		let path = project_dir.join(config_name);
		if !path.exists() {
			continue;
		}
		let content = std::fs::read_to_string(&path).ok()?;
		// Strip comments (// and /* */) for JSON parsing
		let stripped = strip_json_comments(&content);
		let config: serde_json::Value = serde_json::from_str(&stripped).ok()?;
		let paths = config
			.get("compilerOptions")
			.and_then(|co| co.get("paths"))
			.and_then(|p| p.as_object())?;

		for key in paths.keys() {
			if key.ends_with("/*") {
				// "@/*" -> "@/"
				return Some(key[..key.len() - 1].to_string());
			}
		}
	}
	None
}

/// Strip single-line (//) and block (/* */) comments from JSON-like content.
fn strip_json_comments(input: &str) -> String {
	let mut result = String::with_capacity(input.len());
	let mut chars = input.chars().peekable();
	let mut in_string = false;

	while let Some(c) = chars.next() {
		if in_string {
			result.push(c);
			if c == '\\' {
				if let Some(&next) = chars.peek() {
					result.push(next);
					chars.next();
				}
			} else if c == '"' {
				in_string = false;
			}
		} else if c == '"' {
			in_string = true;
			result.push(c);
		} else if c == '/' {
			match chars.peek() {
				Some('/') => {
					// Skip until end of line
					for ch in chars.by_ref() {
						if ch == '\n' {
							result.push('\n');
							break;
						}
					}
				}
				Some('*') => {
					chars.next(); // consume *
					while let Some(ch) = chars.next() {
						if ch == '*' && chars.peek() == Some(&'/') {
							chars.next();
							break;
						}
					}
				}
				_ => result.push(c),
			}
		} else {
			result.push(c);
		}
	}
	result
}

/// Parse a package reference: `@lpm.dev/owner.pkg@1.0.0?component=dialog`
fn parse_package_ref(spec: &str) -> (String, Option<String>, HashMap<String, String>) {
	let mut inline_config = HashMap::new();

	// Split on ? for query params
	let (rest, _query) = if let Some(pos) = spec.find('?') {
		let q = &spec[pos + 1..];
		for param in q.split('&') {
			if let Some(eq) = param.find('=') {
				inline_config.insert(param[..eq].to_string(), param[eq + 1..].to_string());
			}
		}
		(&spec[..pos], Some(q.to_string()))
	} else {
		(spec, None)
	};

	// Split on @ for version (handling scoped packages)
	let (name, version) = if rest.starts_with('@') {
		// @scope/name@version
		if let Some(at_pos) = rest[1..].find('@') {
			let at_pos = at_pos + 1;
			(rest[..at_pos].to_string(), Some(rest[at_pos + 1..].to_string()))
		} else {
			(rest.to_string(), None)
		}
	} else if let Some(at_pos) = rest.find('@') {
		(rest[..at_pos].to_string(), Some(rest[at_pos + 1..].to_string()))
	} else {
		(rest.to_string(), None)
	};

	// Normalize name: add @lpm.dev/ prefix if missing
	let full_name = if name.starts_with("@lpm.dev/") {
		name
	} else if name.contains('.') && !name.contains('/') {
		format!("@lpm.dev/{name}")
	} else {
		name
	};

	(full_name, version, inline_config)
}

/// Read lpm.config.json from extracted package.
fn read_lpm_config(extract_dir: &Path) -> Option<serde_json::Value> {
	let path = extract_dir.join("lpm.config.json");
	if !path.exists() {
		return None;
	}
	let content = std::fs::read_to_string(&path).ok()?;
	serde_json::from_str(&content).ok()
}

/// Determine target directory for file installation.
fn resolve_target_dir(
	project_dir: &Path,
	explicit_path: Option<&str>,
	ecosystem: &str,
	_yes: bool,
) -> Result<PathBuf, LpmError> {
	if let Some(path) = explicit_path {
		return Ok(project_dir.join(path));
	}

	match ecosystem {
		"swift" => {
			// Swift Xcode: Packages/LPMComponents/Sources/
			let xcode_exists = std::fs::read_dir(project_dir)
				.map(|entries| {
					entries
						.flatten()
						.any(|e| {
							e.path()
								.extension()
								.map(|ext| ext == "xcodeproj" || ext == "xcworkspace")
								.unwrap_or(false)
						})
				})
				.unwrap_or(false);

			if xcode_exists {
				Ok(project_dir
					.join("Packages")
					.join("LPMComponents")
					.join("Sources"))
			} else {
				// SPM project: Sources/
				Ok(project_dir.join("Sources"))
			}
		}
		_ => {
			// JS: detect framework
			if project_dir.join("src/components").is_dir() {
				Ok(project_dir.join("src/components"))
			} else if project_dir.join("components").is_dir() {
				Ok(project_dir.join("components"))
			} else if project_dir.join("src").is_dir() {
				Ok(project_dir.join("src/components"))
			} else {
				Ok(project_dir.join("components"))
			}
		}
	}
}

/// Filter files using lpm.config.json `files` array with condition evaluation.
fn filter_config_files(
	extract_dir: &Path,
	files_rules: &[serde_json::Value],
	config: &HashMap<String, String>,
) -> Result<Vec<(String, String)>, LpmError> {
	let provided_params: HashSet<&str> = config.keys().map(|k| k.as_str()).collect();
	let mut result = Vec::new();

	for rule in files_rules {
		let src_pattern = rule
			.get("src")
			.and_then(|v| v.as_str())
			.unwrap_or("");
		let dest = rule
			.get("dest")
			.and_then(|v| v.as_str())
			.map(|s| s.to_string());
		let include = rule
			.get("include")
			.and_then(|v| v.as_str())
			.unwrap_or("always");

		// Evaluate condition
		match include {
			"never" => continue,
			"when" => {
				if let Some(condition) = rule.get("condition").and_then(|c| c.as_object()) {
					let mut matches = true;
					for (key, expected) in condition {
						// If the key wasn't explicitly provided, include the file (all-by-default)
						if !provided_params.contains(key.as_str()) {
							continue;
						}
						let expected_str = expected.as_str().unwrap_or("");
						let actual = config.get(key).map(|s| s.as_str()).unwrap_or("");

						// Support comma-separated multi-select
						let actual_values: Vec<&str> = actual.split(',').collect();
						if !actual_values.contains(&expected_str) {
							matches = false;
							break;
						}
					}
					if !matches {
						continue;
					}
				}
			}
			_ => {} // "always" or missing -- include
		}

		// Expand glob pattern
		let glob_pattern = extract_dir.join(src_pattern);
		let glob_str = glob_pattern.to_string_lossy();

		let expanded = match glob::glob(&glob_str) {
			Ok(entries) => entries.flatten().collect::<Vec<_>>(),
			Err(_) => {
				// Treat as literal
				let path = extract_dir.join(src_pattern);
				if path.exists() {
					vec![path]
				} else {
					vec![]
				}
			}
		};

		let multi_file = expanded.len() > 1;
		for path in expanded {
			if !path.is_file() {
				continue;
			}
			if let Ok(rel) = path.strip_prefix(extract_dir) {
				let src_rel = rel.to_string_lossy().to_string();
				let dest_rel = if let Some(d) = &dest {
					if d.ends_with('/') {
						format!("{}{}", d, rel.file_name().unwrap_or_default().to_string_lossy())
					} else if multi_file {
						// Multiple files: maintain structure under dest
						format!("{}/{}", d.trim_end_matches('/'), src_rel)
					} else {
						d.clone()
					}
				} else {
					src_rel.clone()
				};
				result.push((src_rel, dest_rel));
			}
		}
	}

	Ok(result)
}

/// Collect all files from extracted package (fallback when no config).
fn collect_all_source_files(
	extract_dir: &Path,
) -> Result<Vec<(String, String)>, LpmError> {
	let mut files = Vec::new();
	collect_dir(extract_dir, extract_dir, &mut files)?;
	Ok(files)
}

fn collect_dir(
	dir: &Path,
	root: &Path,
	files: &mut Vec<(String, String)>,
) -> Result<(), LpmError> {
	static SKIP: &[&str] = &["node_modules", ".git", "__tests__", "test", "tests"];

	for entry in std::fs::read_dir(dir)? {
		let entry = entry?;
		let path = entry.path();
		let name = entry.file_name();
		let name_str = name.to_string_lossy();

		if path.is_dir() {
			if SKIP.contains(&name_str.as_ref()) {
				continue;
			}
			collect_dir(&path, root, files)?;
		} else if path.is_file() {
			if name_str == "package.json" || name_str == "lpm.config.json" {
				continue;
			}
			if let Ok(rel) = path.strip_prefix(root) {
				let rel_str = rel.to_string_lossy().to_string();
				files.push((rel_str.clone(), rel_str));
			}
		}
	}
	Ok(())
}

/// Handle npm/LPM dependencies from lpm.config.json.
async fn handle_dependencies(
	project_dir: &Path,
	lpm_config: &Option<serde_json::Value>,
	inline_config: &HashMap<String, String>,
	ecosystem: &str,
	_yes: bool,
	json_output: bool,
	pm: &str,
) -> Result<usize, LpmError> {
	let config = match lpm_config {
		Some(c) => c,
		None => return Ok(0),
	};

	let dep_config = match config.get("dependencies").and_then(|d| d.as_object()) {
		Some(d) => d,
		None => return Ok(0),
	};

	// Resolve conditional dependencies
	let mut npm_deps = Vec::new();

	for (config_key, dep_map) in dep_config {
		let config_value = inline_config.get(config_key).map(|s| s.as_str()).unwrap_or("");
		if config_value.is_empty() {
			continue;
		}

		if let Some(deps) = dep_map.get(config_value).and_then(|d| d.as_array()) {
			for dep in deps {
				if let Some(name) = dep.as_str() {
					if !name.starts_with("@lpm.dev/") {
						npm_deps.push(name.to_string());
					}
				}
			}
		}
	}

	if npm_deps.is_empty() {
		return Ok(0);
	}

	if !json_output {
		output::info(&format!(
			"Installing {} dependencies...",
			npm_deps.len()
		));
	}

	// Add deps to package.json and run lpm install (no npm dependency)
	let pkg_json_path = project_dir.join("package.json");
	if pkg_json_path.exists() {
		let content = std::fs::read_to_string(&pkg_json_path)
			.map_err(|e| LpmError::Registry(format!("failed to read package.json: {e}")))?;
		let mut doc: serde_json::Value = serde_json::from_str(&content)
			.map_err(|e| LpmError::Registry(format!("failed to parse package.json: {e}")))?;

		let deps = doc
			.as_object_mut()
			.and_then(|o| {
				o.entry("dependencies")
					.or_insert_with(|| serde_json::json!({}))
					.as_object_mut()
			});

		if let Some(deps) = deps {
			for dep in &npm_deps {
				// Add with "*" range -- lpm install will resolve to latest
				if !deps.contains_key(dep) {
					deps.insert(dep.clone(), serde_json::Value::String("*".into()));
				}
			}
		}

		let updated = serde_json::to_string_pretty(&doc)
			.map_err(|e| LpmError::Registry(format!("failed to serialize package.json: {e}")))?;
		std::fs::write(&pkg_json_path, format!("{updated}\n"))
			.map_err(|e| LpmError::Registry(format!("failed to write package.json: {e}")))?;

		// Run package manager install to resolve and link the new dependencies
		let effective_pm = if pm == "auto" {
			detect_package_manager(project_dir)
		} else {
			pm.to_string()
		};

		match effective_pm.as_str() {
			"lpm" => {
				let registry_url = std::env::var("LPM_REGISTRY_URL")
					.unwrap_or_else(|_| lpm_common::DEFAULT_REGISTRY_URL.to_string());
				let client = lpm_registry::RegistryClient::new()
					.with_base_url(&registry_url);

				if let Err(e) = crate::commands::install::run_with_options(
					&client, project_dir, json_output, false, false, None, false,
				).await {
					output::warn(&format!("install failed: {e} -- you may need to run `lpm install` manually"));
				}
			}
			pm_name @ ("npm" | "pnpm" | "yarn" | "bun") => {
				if !json_output {
					output::info(&format!("Running {pm_name} install..."));
				}
				let status = std::process::Command::new(pm_name)
					.arg("install")
					.current_dir(project_dir)
					.status();
				match status {
					Ok(s) if s.success() => {}
					Ok(_) => output::warn(&format!("{pm_name} install exited with non-zero status")),
					Err(e) => output::warn(&format!("{pm_name} install failed: {e}")),
				}
			}
			other => {
				return Err(LpmError::Script(format!(
					"unknown package manager: {other}. Use: lpm, npm, pnpm, yarn, bun, auto"
				)));
			}
		}
	} else {
		output::warn("no package.json found -- dependencies not installed. Run `lpm install` manually.");
	}

	let _ = ecosystem; // Ecosystem used for future per-ecosystem dep handling

	Ok(npm_deps.len())
}

/// For Swift packages: recursively install LPM dependencies.
async fn handle_swift_lpm_deps(
	client: &RegistryClient,
	project_dir: &Path,
	ver_meta: &lpm_registry::VersionMetadata,
	yes: bool,
	json_output: bool,
	force: bool,
	dry_run: bool,
	no_install_deps: bool,
	no_skills: bool,
	no_editor_setup: bool,
	pm: &str,
) -> Result<(), LpmError> {
	// Check versionMeta for swift manifest dependencies
	// These are in the version's metadata, not in lpm.config.json
	let deps = &ver_meta.dependencies;
	if deps.is_empty() {
		return Ok(());
	}

	// Filter to LPM deps only
	let lpm_deps: Vec<(&String, &String)> = deps
		.iter()
		.filter(|(name, _)| name.starts_with("@lpm.dev/"))
		.collect();

	if lpm_deps.is_empty() {
		return Ok(());
	}

	if !json_output {
		output::info(&format!(
			"This package has {} LPM dependencies -- installing recursively",
			lpm_deps.len()
		));
	}

	for (dep_name, dep_range) in &lpm_deps {
		if !json_output {
			output::info(&format!("  Adding dependency: {dep_name}@{dep_range}"));
		}
		// Recursive add (source delivery for recursive deps)
		Box::pin(run(
			client,
			project_dir,
			dep_name,
			None,
			yes,
			json_output,
			force,
			dry_run,
			no_install_deps,
			no_skills,
			no_editor_setup,
			pm,
		))
		.await?;
	}

	Ok(())
}

/// Print security warnings for a single package version.
pub fn print_security_warnings(
	name: &str,
	version: &str,
	ver_meta: &lpm_registry::VersionMetadata,
) {
	let mut warnings: Vec<String> = Vec::new();

	if let Some(findings) = &ver_meta.security_findings {
		for finding in findings {
			let severity = finding.severity.as_deref().unwrap_or("info");
			let desc = finding
				.description
				.as_deref()
				.unwrap_or("security concern detected");
			warnings.push(format!("[{}] {}", severity, desc));
		}
	}

	if let Some(tags) = &ver_meta.behavioral_tags {
		let mut dangerous = Vec::new();
		if tags.eval { dangerous.push("eval()"); }
		if tags.child_process { dangerous.push("child_process"); }
		if tags.shell { dangerous.push("shell exec"); }
		if tags.dynamic_require { dangerous.push("dynamic require"); }
		if !dangerous.is_empty() {
			warnings.push(format!("uses {}", dangerous.join(", ")));
		}
	}

	if let Some(scripts) = &ver_meta.lifecycle_scripts {
		let script_names: Vec<&str> = scripts.keys().map(|s| s.as_str()).collect();
		if !script_names.is_empty() {
			warnings.push(format!("has lifecycle scripts: {}", script_names.join(", ")));
		}
	}

	if warnings.is_empty() {
		return;
	}

	println!();
	output::warn(&format!("{} ({}) has {} issue(s):", name.bold(), version, warnings.len()));
	for warning in &warnings {
		println!("    {} {}", "\u{26a0}".yellow(), warning);
	}
	println!("  Run {} for details", "lpm audit".bold());
}
