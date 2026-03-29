use crate::output;
use lpm_common::{LpmError, PackageName};
use lpm_registry::RegistryClient;
use owo_colors::OwoColorize;
use std::path::Path;

/// Upgrade outdated LPM dependencies to their latest versions.
///
/// Reads package.json, checks registry for latest versions, updates
/// package.json in-place, then runs `lpm install`.
///
/// Modes:
/// - Default: upgrade to latest within semver range (patch + minor)
/// - `--major`: upgrade to latest major version
/// - `--dry-run`: show what would be upgraded without making changes
pub async fn run(
	client: &RegistryClient,
	project_dir: &Path,
	major: bool,
	dry_run: bool,
	json_output: bool,
) -> Result<(), LpmError> {
	let pkg_json_path = project_dir.join("package.json");
	if !pkg_json_path.exists() {
		return Err(LpmError::NotFound("no package.json found".into()));
	}

	// Read raw JSON to preserve formatting and non-dep fields
	let content = std::fs::read_to_string(&pkg_json_path)
		.map_err(|e| LpmError::Script(format!("failed to read package.json: {e}")))?;
	let mut doc: serde_json::Value = serde_json::from_str(&content)
		.map_err(|e| LpmError::Script(format!("failed to parse package.json: {e}")))?;

	let pkg = lpm_workspace::read_package_json(&pkg_json_path)
		.map_err(|e| LpmError::Script(format!("{e}")))?;

	// Collect all deps (dependencies + devDependencies)
	let all_deps: Vec<(String, String, bool)> = pkg
		.dependencies
		.iter()
		.map(|(k, v)| (k.clone(), v.clone(), false))
		.chain(
			pkg.dev_dependencies
				.iter()
				.map(|(k, v)| (k.clone(), v.clone(), true)),
		)
		.collect();

	let mut upgrades: Vec<UpgradeInfo> = Vec::new();

	for (name, current_range, is_dev) in &all_deps {
		// Only check LPM packages for now (npm packages need npm registry)
		if !name.starts_with("@lpm.dev/") {
			continue;
		}

		let pkg_name = match PackageName::parse(name) {
			Ok(n) => n,
			Err(_) => continue,
		};

		let metadata = match client.get_package_metadata(&pkg_name).await {
			Ok(m) => m,
			Err(_) => continue,
		};

		let latest = match metadata.latest_version_tag() {
			Some(v) => v.to_string(),
			None => continue,
		};

		// Check lockfile for current installed version
		let lockfile_path = project_dir.join("lpm.lock");
		let installed = if lockfile_path.exists() {
			lpm_lockfile::Lockfile::read_fast(&lockfile_path)
				.ok()
				.and_then(|lf| lf.find_package(name).map(|p| p.version.clone()))
		} else {
			None
		};

		let installed_ver = installed.as_deref().unwrap_or("?");

		// Determine if upgrade is needed
		if installed_ver == latest {
			continue; // Already latest
		}

		// For non-major mode, check if latest is within the current range prefix
		if !major {
			// Simple heuristic: if range starts with ^ or ~, keep the prefix
			let new_range = if current_range.starts_with('^') {
				format!("^{latest}")
			} else if current_range.starts_with('~') {
				format!("~{latest}")
			} else {
				latest.clone()
			};

			upgrades.push(UpgradeInfo {
				name: name.clone(),
				from: installed_ver.to_string(),
				to: latest.clone(),
				new_range,
				is_dev: *is_dev,
			});
		} else {
			// Major mode: always upgrade to latest
			let prefix = if current_range.starts_with('^') {
				"^"
			} else if current_range.starts_with('~') {
				"~"
			} else {
				""
			};
			upgrades.push(UpgradeInfo {
				name: name.clone(),
				from: installed_ver.to_string(),
				to: latest.clone(),
				new_range: format!("{prefix}{latest}"),
				is_dev: *is_dev,
			});
		}
	}

	if upgrades.is_empty() {
		if json_output {
			println!("{}", serde_json::json!({"upgraded": 0, "packages": []}));
		} else {
			output::success("All LPM packages are up to date");
		}
		return Ok(());
	}

	// Display upgrades
	if json_output {
		let pkgs: Vec<serde_json::Value> = upgrades
			.iter()
			.map(|u| {
				serde_json::json!({
					"name": u.name,
					"from": u.from,
					"to": u.to,
					"newRange": u.new_range,
					"isDev": u.is_dev,
				})
			})
			.collect();
		if dry_run {
			println!(
				"{}",
				serde_json::to_string_pretty(&serde_json::json!({
					"dryRun": true,
					"upgraded": upgrades.len(),
					"packages": pkgs,
				}))
				.unwrap_or_default()
			);
		} else {
			println!(
				"{}",
				serde_json::to_string_pretty(&serde_json::json!({
					"upgraded": upgrades.len(),
					"packages": pkgs,
				}))
				.unwrap_or_default()
			);
		}
	} else {
		println!();
		for u in &upgrades {
			let dev_tag = if u.is_dev { " (dev)" } else { "" };
			println!(
				"  {} {} → {}{}",
				u.name.bold(),
				u.from.dimmed(),
				u.to.green(),
				dev_tag.dimmed(),
			);
		}
		println!();

		if dry_run {
			output::info(&format!(
				"{} package(s) would be upgraded (dry run)",
				upgrades.len()
			));
			return Ok(());
		}
	}

	// Apply upgrades to package.json
	for u in &upgrades {
		let section = if u.is_dev { "devDependencies" } else { "dependencies" };
		if let Some(deps) = doc.get_mut(section).and_then(|d| d.as_object_mut()) {
			deps.insert(u.name.clone(), serde_json::Value::String(u.new_range.clone()));
		}
	}

	// Write updated package.json
	let updated = serde_json::to_string_pretty(&doc)
		.map_err(|e| LpmError::Script(format!("failed to serialize package.json: {e}")))?;
	std::fs::write(&pkg_json_path, format!("{updated}\n"))
		.map_err(|e| LpmError::Script(format!("failed to write package.json: {e}")))?;

	if !json_output {
		output::success(&format!("updated {} package(s) in package.json", upgrades.len()));
	}

	// Run lpm install to resolve and lock new versions
	if !json_output {
		output::info("running lpm install...");
	}

	crate::commands::install::run_with_options(client, project_dir, json_output, false, false, None, false).await?;

	if !json_output {
		output::success(&format!("{} package(s) upgraded", upgrades.len()));
	}

	Ok(())
}

struct UpgradeInfo {
	name: String,
	from: String,
	to: String,
	new_range: String,
	is_dev: bool,
}
