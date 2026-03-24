use crate::{output, quality};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use lpm_common::LpmError;
use lpm_registry::RegistryClient;
use owo_colors::OwoColorize;
use sha2::{Digest, Sha512};
use std::path::Path;

pub async fn run(
	client: &RegistryClient,
	project_dir: &Path,
	dry_run: bool,
	check_only: bool,
	yes: bool,
	json_output: bool,
) -> Result<(), LpmError> {
	// Step 1: Read package.json
	let pkg_json_path = project_dir.join("package.json");
	if !pkg_json_path.exists() {
		return Err(LpmError::NotFound(
			"no package.json found in current directory".to_string(),
		));
	}

	let content = std::fs::read_to_string(&pkg_json_path)?;
	let pkg_json: serde_json::Value =
		serde_json::from_str(&content).map_err(|e| LpmError::Registry(e.to_string()))?;

	let name = pkg_json
		.get("name")
		.and_then(|v| v.as_str())
		.ok_or_else(|| LpmError::Registry("package.json missing \"name\"".into()))?;

	let version = pkg_json
		.get("version")
		.and_then(|v| v.as_str())
		.ok_or_else(|| LpmError::Registry("package.json missing \"version\"".into()))?;

	// Validate LPM name format
	if !name.starts_with("@lpm.dev/") {
		return Err(LpmError::Registry(format!(
			"package name must start with @lpm.dev/ (got \"{name}\")"
		)));
	}

	if !json_output {
		output::info(&format!("Publishing {}@{}", name.bold(), version));
	}

	// Step 2: Read README
	let readme = read_readme(project_dir);

	// Step 3: Create tarball
	if !json_output {
		output::info("Packing tarball...");
	}
	let (tarball_data, tarball_files) = create_tarball(project_dir, &pkg_json)?;

	let tarball_size = tarball_data.len();
	if tarball_size > 500 * 1024 * 1024 {
		return Err(LpmError::Registry(format!(
			"tarball too large: {} (max 500MB)",
			lpm_common::format_bytes(tarball_size as u64)
		)));
	}

	if !json_output {
		output::info(&format!(
			"Packed {} files ({}) → tarball {}",
			tarball_files.len(),
			lpm_common::format_bytes(
				tarball_files.iter().map(|f| f.size).sum::<u64>()
			),
			lpm_common::format_bytes(tarball_size as u64),
		));
	}

	// Step 4: Quality checks
	let file_names: Vec<String> = tarball_files.iter().map(|f| f.path.clone()).collect();
	let quality_result =
		quality::run_quality_checks(&pkg_json, readme.as_deref(), project_dir, &file_names);

	if !json_output {
		print_quality_report(&quality_result);
	}

	// Step 5: Check-only or dry-run modes
	if check_only {
		if json_output {
			println!(
				"{}",
				serde_json::to_string_pretty(&quality_result).unwrap()
			);
		}
		return Ok(());
	}

	if dry_run {
		if json_output {
			let json = serde_json::json!({
				"name": name,
				"version": version,
				"files": tarball_files.len(),
				"tarball_size": tarball_size,
				"quality": quality_result,
			});
			println!("{}", serde_json::to_string_pretty(&json).unwrap());
		} else {
			println!();
			output::info("Dry run — not publishing.");
		}
		return Ok(());
	}

	// Step 6: Confirm
	if !json_output && !yes {
		println!();
		let is_tty = std::io::IsTerminal::is_terminal(&std::io::stdin());
		if is_tty {
			let confirm = dialoguer::Confirm::new()
				.with_prompt(format!("Publish {name}@{version}?"))
				.default(true)
				.interact()
				.map_err(|e| LpmError::Registry(e.to_string()))?;

			if !confirm {
				output::info("Publish cancelled.");
				return Ok(());
			}
		}
	}

	// Step 7: Verify token has publish scope
	let whoami = client.whoami().await.map_err(|e| {
		LpmError::Registry(format!("authentication failed: {e}"))
	})?;

	let username = whoami
		.profile_username
		.as_deref()
		.or(whoami.username.as_deref())
		.unwrap_or("unknown");

	if !json_output {
		output::info(&format!("Publishing as {}", username.bold()));
	}

	// Step 7b: 2FA check — prompt before uploading to avoid re-transmitting large tarballs
	let otp_code: Option<String> = if whoami.mfa_enabled == Some(true) {
		if json_output {
			return Err(LpmError::Registry(
				"2FA required but running in JSON mode — use --token with a CI token instead"
					.into(),
			));
		}
		let code: String = dialoguer::Input::new()
			.with_prompt("Enter 2FA code")
			.validate_with(|input: &String| -> Result<(), &str> {
				if input.len() == 6 && input.chars().all(|c| c.is_ascii_digit()) {
					Ok(())
				} else {
					Err("must be a 6-digit code")
				}
			})
			.interact_text()
			.map_err(|e| LpmError::Registry(e.to_string()))?;
		Some(code)
	} else {
		None
	};

	// Step 8: Hash the tarball
	let shasum = {
		use sha1::Digest as Sha1Digest;
		let mut hasher = sha1::Sha1::new();
		hasher.update(&tarball_data);
		format!("{:x}", hasher.finalize())
	};

	let integrity = {
		let mut hasher = Sha512::new();
		hasher.update(&tarball_data);
		let hash = hasher.finalize();
		format!("sha512-{}", BASE64.encode(hash))
	};

	// Step 9: Build version data
	let mut version_data = pkg_json.clone();
	version_data["_id"] = serde_json::json!(format!("{name}@{version}"));
	if let Some(readme_text) = &readme {
		version_data["readme"] = serde_json::json!(readme_text);
	}
	version_data["dist"] = serde_json::json!({
		"shasum": shasum,
		"integrity": integrity,
	});

	// Add quality checks as hints for server
	version_data["_qualityChecks"] = serde_json::to_value(&quality_result.checks)
		.unwrap_or(serde_json::json!(null));
	version_data["_qualityMeta"] = serde_json::json!({
		"score": quality_result.score,
		"maxScore": quality_result.max_score,
		"ecosystem": "js",
	});

	// Add npm pack metadata
	version_data["_npmPackMeta"] = serde_json::json!({
		"files": tarball_files.iter().map(|f| {
			serde_json::json!({
				"path": f.path,
				"size": f.size,
			})
		}).collect::<Vec<_>>(),
		"unpackedSize": tarball_files.iter().map(|f| f.size).sum::<u64>(),
		"fileCount": tarball_files.len(),
	});

	// Read lpm.config.json if present
	let mut detected_ecosystem = "js".to_string();
	let lpm_config_path = project_dir.join("lpm.config.json");
	if lpm_config_path.exists() {
		if let Ok(config_str) = std::fs::read_to_string(&lpm_config_path) {
			if let Ok(config) = serde_json::from_str::<serde_json::Value>(&config_str) {
				// Extract ecosystem from lpm.config.json
				if let Some(eco) = config.get("ecosystem").and_then(|v| v.as_str()) {
					detected_ecosystem = eco.to_string();
				}
				version_data["_lpmConfig"] = config;
			}
		}
	}

	// Auto-detect Swift if Package.swift exists
	if project_dir.join("Package.swift").exists() && detected_ecosystem == "js" {
		detected_ecosystem = "swift".to_string();
	}

	// Set ecosystem on version data
	if detected_ecosystem != "js" {
		version_data["_ecosystem"] = serde_json::json!(detected_ecosystem);
	}

	// For Swift: include the swift manifest from `swift package dump-package`
	if detected_ecosystem == "swift" {
		if let Ok(output) = std::process::Command::new("swift")
			.args(["package", "dump-package"])
			.current_dir(project_dir)
			.output()
		{
			if output.status.success() {
				if let Ok(manifest) =
					serde_json::from_slice::<serde_json::Value>(&output.stdout)
				{
					version_data["_swiftManifest"] = manifest;
				}
			}
		}
	}

	// Step 10: Build publish payload
	let tarball_key = format!(
		"{}-{}.tgz",
		name.replace('/', "-").replace('@', ""),
		version
	);
	let tarball_base64 = BASE64.encode(&tarball_data);

	let payload = serde_json::json!({
		"_id": name,
		"name": name,
		"description": pkg_json.get("description"),
		"readme": readme,
		"_ecosystem": detected_ecosystem,
		"dist-tags": {
			"latest": version,
		},
		"versions": {
			version: version_data,
		},
		"_attachments": {
			tarball_key: {
				"content_type": "application/gzip",
				"data": tarball_base64,
				"length": tarball_size,
			}
		},
	});

	// Step 11: Upload
	if !json_output {
		output::info("Uploading...");
	}

	let encoded_name = urlencoding::encode(name);
	let result = client
		.publish_package(&encoded_name, &payload, otp_code.as_deref())
		.await?;

	if json_output {
		println!("{}", serde_json::to_string_pretty(&result).unwrap());
	} else {
		println!();
		output::success(&format!(
			"Published {}@{}",
			name.bold(),
			version.bold()
		));

		// Show warnings from server
		if let Some(warnings) = result.get("warnings").and_then(|w| w.as_array()) {
			for warning in warnings {
				if let Some(msg) = warning.as_str() {
					output::warn(msg);
				}
			}
		}

		// Show quality score
		println!(
			"  Quality: {}/{}",
			quality_result.score, quality_result.max_score
		);
		println!();
	}

	Ok(())
}

/// Read the README file from the project directory.
fn read_readme(project_dir: &Path) -> Option<String> {
	let candidates = [
		"README.md",
		"readme.md",
		"Readme.md",
		"README",
		"readme",
		"README.txt",
		"README.markdown",
	];

	for name in &candidates {
		let path = project_dir.join(name);
		if path.exists() {
			if let Ok(content) = std::fs::read_to_string(&path) {
				// Cap at 1MB
				let trimmed = if content.len() > 1_000_000 {
					content[..1_000_000].to_string()
				} else {
					content
				};
				return Some(trimmed);
			}
		}
	}
	None
}

#[derive(Debug, Clone)]
struct TarballFile {
	path: String,
	size: u64,
}

/// Create a tarball from the project directory.
///
/// Respects `files` field in package.json if present.
/// Falls back to including everything except common ignores.
fn create_tarball(
	project_dir: &Path,
	pkg_json: &serde_json::Value,
) -> Result<(Vec<u8>, Vec<TarballFile>), LpmError> {
	use flate2::Compression;
	use flate2::write::GzEncoder;
	use std::io::Write;

	let files = collect_package_files(project_dir, pkg_json)?;
	if files.is_empty() {
		return Err(LpmError::Registry(
			"no files to pack (check package.json 'files' field)".to_string(),
		));
	}

	let mut tar_data = Vec::new();
	{
		let mut builder = tar::Builder::new(&mut tar_data);

		for file in &files {
			let full_path = project_dir.join(&file.path);
			if !full_path.is_file() {
				continue;
			}

			let content = std::fs::read(&full_path)?;
			let mut header = tar::Header::new_gnu();
			header.set_size(content.len() as u64);
			header.set_mode(0o644);
			header.set_cksum();

			// npm tarballs have a `package/` prefix
			let tar_path = format!("package/{}", file.path);
			builder
				.append_data(&mut header, &tar_path, &content[..])
				.map_err(|e| LpmError::Io(e))?;
		}

		builder.finish().map_err(|e| LpmError::Io(e))?;
	}

	// Gzip compress
	let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
	encoder.write_all(&tar_data)?;
	let gzipped = encoder.finish()?;

	Ok((gzipped, files))
}

/// Collect files to include in the tarball.
///
/// If `files` field exists in package.json, only include those.
/// Otherwise include everything with common ignores.
fn collect_package_files(
	project_dir: &Path,
	pkg_json: &serde_json::Value,
) -> Result<Vec<TarballFile>, LpmError> {
	let mut result = Vec::new();

	// Always include package.json
	let pkg_json_path = project_dir.join("package.json");
	if pkg_json_path.exists() {
		let meta = std::fs::metadata(&pkg_json_path)?;
		result.push(TarballFile {
			path: "package.json".to_string(),
			size: meta.len(),
		});
	}

	// Check for `files` field (explicit include list)
	if let Some(files_arr) = pkg_json.get("files").and_then(|f| f.as_array()) {
		let patterns: Vec<String> = files_arr
			.iter()
			.filter_map(|v| v.as_str().map(|s| s.to_string()))
			.collect();

		for pattern in &patterns {
			let glob_pattern = project_dir.join(pattern);
			let glob_str = glob_pattern.to_string_lossy();

			match glob::glob(&glob_str) {
				Ok(entries) => {
					for entry in entries.flatten() {
						if entry.is_file() {
							if let Ok(rel) = entry.strip_prefix(project_dir) {
								let rel_str = rel.to_string_lossy().to_string();
								if rel_str != "package.json" {
									let meta = std::fs::metadata(&entry)?;
									result.push(TarballFile {
										path: rel_str,
										size: meta.len(),
									});
								}
							}
						} else if entry.is_dir() {
							// Expand directory
							collect_dir_files(
								&entry,
								project_dir,
								&mut result,
							)?;
						}
					}
				}
				Err(_) => {
					// Treat as literal path
					let path = project_dir.join(pattern);
					if path.is_file() {
						let rel_str = pattern.to_string();
						if rel_str != "package.json" {
							let meta = std::fs::metadata(&path)?;
							result.push(TarballFile {
								path: rel_str,
								size: meta.len(),
							});
						}
					} else if path.is_dir() {
						collect_dir_files(&path, project_dir, &mut result)?;
					}
				}
			}
		}
	} else {
		// No `files` field — include everything with common ignores
		collect_all_files(project_dir, project_dir, &mut result)?;
	}

	// Always include README and LICENSE
	for extra in ["README.md", "readme.md", "LICENSE", "LICENSE.md", "CHANGELOG.md"] {
		let path = project_dir.join(extra);
		if path.exists() && !result.iter().any(|f| f.path.eq_ignore_ascii_case(extra)) {
			let meta = std::fs::metadata(&path)?;
			result.push(TarballFile {
				path: extra.to_string(),
				size: meta.len(),
			});
		}
	}

	// Deduplicate by path
	let mut seen = std::collections::HashSet::new();
	result.retain(|f| seen.insert(f.path.clone()));

	Ok(result)
}

fn collect_dir_files(
	dir: &Path,
	project_root: &Path,
	result: &mut Vec<TarballFile>,
) -> Result<(), LpmError> {
	for entry in std::fs::read_dir(dir)? {
		let entry = entry?;
		let path = entry.path();

		if path.is_file() {
			if let Ok(rel) = path.strip_prefix(project_root) {
				let rel_str = rel.to_string_lossy().to_string();
				if rel_str != "package.json" {
					let meta = std::fs::metadata(&path)?;
					result.push(TarballFile {
						path: rel_str,
						size: meta.len(),
					});
				}
			}
		} else if path.is_dir() {
			collect_dir_files(&path, project_root, result)?;
		}
	}
	Ok(())
}

/// Common ignore patterns when no `files` field is specified.
const IGNORE_DIRS: &[&str] = &[
	"node_modules",
	".git",
	".svn",
	".hg",
	"coverage",
	".nyc_output",
	".cache",
	"dist",
	".next",
	".nuxt",
	"build",
];

const IGNORE_FILES: &[&str] = &[
	".gitignore",
	".npmignore",
	".DS_Store",
	"Thumbs.db",
	".env",
	".env.local",
	".env.live",
];

fn collect_all_files(
	dir: &Path,
	project_root: &Path,
	result: &mut Vec<TarballFile>,
) -> Result<(), LpmError> {
	for entry in std::fs::read_dir(dir)? {
		let entry = entry?;
		let file_name = entry.file_name();
		let name_str = file_name.to_string_lossy();
		let path = entry.path();

		if path.is_dir() {
			if IGNORE_DIRS.contains(&name_str.as_ref()) {
				continue;
			}
			collect_all_files(&path, project_root, result)?;
		} else if path.is_file() {
			if IGNORE_FILES.contains(&name_str.as_ref()) {
				continue;
			}
			if let Ok(rel) = path.strip_prefix(project_root) {
				let rel_str = rel.to_string_lossy().to_string();
				if rel_str != "package.json" {
					let meta = std::fs::metadata(&path)?;
					result.push(TarballFile {
						path: rel_str,
						size: meta.len(),
					});
				}
			}
		}
	}
	Ok(())
}

fn print_quality_report(result: &quality::QualityResult) {
	let tier = match result.score {
		90..=100 => "Excellent".green().to_string(),
		70..=89 => "Good".blue().to_string(),
		50..=69 => "Fair".yellow().to_string(),
		_ => "Needs Work".dimmed().to_string(),
	};

	println!();
	println!(
		"  Quality: {}/{} ({})",
		result.score.to_string().bold(),
		result.max_score,
		tier,
	);

	// Group by category
	let mut categories: std::collections::BTreeMap<&str, Vec<&quality::QualityCheck>> =
		std::collections::BTreeMap::new();
	for check in &result.checks {
		categories
			.entry(&check.category)
			.or_default()
			.push(check);
	}

	for (category, checks) in &categories {
		let cat_score: u32 = checks.iter().map(|c| c.points).sum();
		let cat_max: u32 = checks.iter().map(|c| c.max_points).sum();
		println!("  {} ({}/{})", category.bold(), cat_score, cat_max);

		for check in checks {
			if check.server_only {
				continue;
			}
			let icon = if check.passed {
				"✔".green().to_string()
			} else {
				"✖".red().to_string()
			};
			let pts_str = format!("{}/{}", check.points, check.max_points);
			let pts = pts_str.dimmed();
			print!("    {icon} {} {pts}", check.name);
			if let Some(detail) = &check.detail {
				print!(" {}", detail.dimmed());
			}
			println!();
		}
	}
	println!();
}
