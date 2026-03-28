use crate::output;
use lpm_common::{LpmError, PackageName};
use lpm_registry::RegistryClient;
use owo_colors::OwoColorize;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

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
) -> Result<(), LpmError> {
	// Step 1: Parse package reference
	let (pkg_ref, version_spec, inline_config) = parse_package_ref(package_spec);

	let name = PackageName::parse(&pkg_ref)?;
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

	// Step 3: Download & extract tarball (source delivery path)
	let tarball_url = ver_meta.tarball_url().ok_or_else(|| {
		LpmError::NotFound("no tarball URL".into())
	})?;
	let tarball_data = client.download_tarball(tarball_url).await?;

	let temp_dir = tempfile::tempdir()
		.map_err(|e| LpmError::Io(e.into()))?;
	lpm_extractor::extract_tarball(&tarball_data, temp_dir.path())?;

	// Step 4: Read lpm.config.json
	let lpm_config = read_lpm_config(temp_dir.path());

	// Step 5: Detect ecosystem and determine target
	let ecosystem = lpm_config
		.as_ref()
		.and_then(|c| c.get("ecosystem").and_then(|v| v.as_str()))
		.unwrap_or("js");

	let target_dir = resolve_target_dir(project_dir, target_path, ecosystem, yes)?;

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

	// Step 7: Prepare import rewriting
	let author_alias = lpm_config
		.as_ref()
		.and_then(|c| c.get("importAlias"))
		.and_then(|v| v.as_str())
		.map(|s| s.to_string());

	let buyer_alias = detect_buyer_alias(project_dir);

	// Build src→dest map and dest file set for import resolution
	let src_to_dest: HashMap<String, String> = files.iter().cloned().collect();
	let dest_files: HashSet<String> = files.iter().map(|(_, d)| d.clone()).collect();

	// Step 8: Copy files to target (with import rewriting)
	let mut copied = 0;
	let mut skipped = 0;
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

		// Check for conflicts
		if dest_path.exists() {
			let existing = std::fs::read_to_string(&dest_path).unwrap_or_default();
			if Some(existing.as_str()) == final_content {
				skipped += 1;
				continue;
			}
		}

		// Write (rewritten text or copy binary)
		if let Some(text) = final_content {
			std::fs::write(&dest_path, text)?;
		} else {
			std::fs::copy(&src_path, &dest_path)?;
		}
		copied += 1;
	}

	// Step 9: Handle dependencies
	let dep_count = handle_dependencies(
		project_dir,
		&lpm_config,
		&inline_config,
		ecosystem,
		yes,
		json_output,
	)
	.await?;

	// Step 10: For Swift, handle recursive LPM dependencies
	if ecosystem == "swift" {
		handle_swift_lpm_deps(client, project_dir, ver_meta, yes, json_output).await?;
	}

	// Step 11: Output
	if json_output {
		let json = serde_json::json!({
			"package": name.scoped(),
			"version": version,
			"files_copied": copied,
			"files_skipped": skipped,
			"dependencies_installed": dep_count,
			"target": target_dir.strip_prefix(project_dir).unwrap_or(&target_dir).display().to_string(),
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

	Ok(())
}

/// Detect the buyer's import alias from tsconfig.json or jsconfig.json.
///
/// Reads `compilerOptions.paths` and returns the first alias ending with `/*`.
/// e.g., `{ "@/*": ["./src/*"] }` → `"@/"`
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
				// "@/*" → "@/"
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
	let (rest, query) = if let Some(pos) = spec.find('?') {
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
			_ => {} // "always" or missing — include
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
				// Add with "*" range — lpm install will resolve to latest
				if !deps.contains_key(dep) {
					deps.insert(dep.clone(), serde_json::Value::String("*".into()));
				}
			}
		}

		let updated = serde_json::to_string_pretty(&doc)
			.map_err(|e| LpmError::Registry(format!("failed to serialize package.json: {e}")))?;
		std::fs::write(&pkg_json_path, format!("{updated}\n"))
			.map_err(|e| LpmError::Registry(format!("failed to write package.json: {e}")))?;

		// Run lpm install to resolve and link the new dependencies
		let registry_url = std::env::var("LPM_REGISTRY_URL")
			.unwrap_or_else(|_| lpm_common::DEFAULT_REGISTRY_URL.to_string());
		let client = lpm_registry::RegistryClient::new()
			.with_base_url(&registry_url);

		if let Err(e) = crate::commands::install::run_with_options(
			&client, project_dir, json_output, false,
		).await {
			output::warn(&format!("install failed: {e} — you may need to run `lpm install` manually"));
		}
	} else {
		output::warn("no package.json found — dependencies not installed. Run `lpm install` manually.");
	}

	Ok(npm_deps.len())
}

/// For Swift packages: recursively install LPM dependencies.
async fn handle_swift_lpm_deps(
	client: &RegistryClient,
	project_dir: &Path,
	ver_meta: &lpm_registry::VersionMetadata,
	yes: bool,
	json_output: bool,
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
			"This package has {} LPM dependencies — installing recursively",
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
		println!("    {} {}", "⚠".yellow(), warning);
	}
	println!("  Run {} for details", "lpm audit".bold());
}
