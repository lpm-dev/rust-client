use crate::output;
use lpm_common::{LpmError, PackageName};
use lpm_registry::RegistryClient;
use owo_colors::OwoColorize;
use std::path::Path;

/// Check for newer versions of installed dependencies.
pub async fn run(
	client: &RegistryClient,
	project_dir: &Path,
	json_output: bool,
) -> Result<(), LpmError> {
	let pkg_json_path = project_dir.join("package.json");
	if !pkg_json_path.exists() {
		return Err(LpmError::NotFound("no package.json found".into()));
	}

	let pkg = lpm_workspace::read_package_json(&pkg_json_path)
		.map_err(|e| LpmError::Registry(format!("failed to read package.json: {e}")))?;

	let deps = pkg.dependencies;
	if deps.is_empty() {
		if !json_output {
			output::info("No dependencies to check.");
		}
		return Ok(());
	}

	let mut results = Vec::new();

	for (name, range) in &deps {
		if !name.starts_with("@lpm.dev/") {
			continue; // Only check LPM packages
		}

		let pkg_name = match PackageName::parse(name) {
			Ok(n) => n,
			Err(_) => continue,
		};

		match client.get_package_metadata(&pkg_name).await {
			Ok(metadata) => {
				let latest = metadata
					.latest_version_tag()
					.unwrap_or("unknown")
					.to_string();

				// Check lockfile for installed version
				let lockfile_path = project_dir.join("lpm.lock");
				let installed = if lockfile_path.exists() {
					lpm_lockfile::Lockfile::read_fast(&lockfile_path)
						.ok()
						.and_then(|lf| lf.find_package(name).map(|p| p.version.clone()))
				} else {
					None
				};

				let installed_str = installed.as_deref().unwrap_or("?");
				let is_outdated = installed.as_deref() != Some(latest.as_str());

				results.push(serde_json::json!({
					"name": name,
					"current": installed_str,
					"wanted": range,
					"latest": latest,
					"outdated": is_outdated,
				}));
			}
			Err(_) => continue,
		}
	}

	if json_output {
		println!("{}", serde_json::to_string_pretty(&results).unwrap());
	} else {
		let outdated: Vec<_> = results.iter().filter(|r| r["outdated"] == true).collect();
		if outdated.is_empty() {
			output::success("All LPM packages are up to date");
		} else {
			println!();
			println!(
				"  {:<40} {:<12} {:<12}",
				"Package".bold(),
				"Current".bold(),
				"Latest".bold()
			);
			for r in &outdated {
				println!(
					"  {:<40} {:<12} {}",
					r["name"].as_str().unwrap_or(""),
					r["current"].as_str().unwrap_or("?").dimmed(),
					r["latest"].as_str().unwrap_or("?").green(),
				);
			}
			println!();
			output::info(&format!(
				"{} package(s) can be updated",
				outdated.len()
			));
		}
		println!();
	}

	Ok(())
}
