use crate::output;
use lpm_common::LpmError;
use lpm_registry::RegistryClient;
use owo_colors::OwoColorize;
use std::path::Path;

pub async fn run(
	_client: &RegistryClient,
	project_dir: &Path,
	packages: &[String],
	json_output: bool,
) -> Result<(), LpmError> {
	if packages.is_empty() {
		return Err(LpmError::Registry(
			"specify at least one package to uninstall".to_string(),
		));
	}

	let pkg_json_path = project_dir.join("package.json");
	if !pkg_json_path.exists() {
		return Err(LpmError::NotFound(
			"no package.json found in current directory".to_string(),
		));
	}

	// Read and parse package.json
	let content = std::fs::read_to_string(&pkg_json_path)?;
	let mut doc: serde_json::Value =
		serde_json::from_str(&content).map_err(|e| LpmError::Registry(e.to_string()))?;

	let mut removed = Vec::new();
	let mut not_found = Vec::new();

	for name in packages {
		let mut found = false;

		// Check both dependencies and devDependencies
		for key in &["dependencies", "devDependencies"] {
			if let Some(deps) = doc.get_mut(*key) {
				if let Some(obj) = deps.as_object_mut() {
					if obj.remove(name).is_some() {
						found = true;
						if !json_output {
							output::info(&format!("Removed {} from {}", name.bold(), key));
						}
					}
				}
			}
		}

		if found {
			removed.push(name.clone());
		} else {
			not_found.push(name.clone());
		}
	}

	if removed.is_empty() {
		if !json_output {
			output::warn("No packages were removed (not found in dependencies)");
		}
		return Ok(());
	}

	// Write updated package.json
	let updated = serde_json::to_string_pretty(&doc)
		.map_err(|e| LpmError::Registry(e.to_string()))?;
	std::fs::write(&pkg_json_path, format!("{updated}\n"))?;

	// Remove lockfile to force re-resolution on next install
	let lockfile_path = project_dir.join(lpm_lockfile::LOCKFILE_NAME);
	if lockfile_path.exists() {
		std::fs::remove_file(&lockfile_path)?;
	}

	// Clean up node_modules symlinks for removed direct deps
	let node_modules = project_dir.join("node_modules");
	for name in &removed {
		let link = node_modules.join(name);
		if link.symlink_metadata().is_ok() {
			if link.is_dir() || link.symlink_metadata().map(|m| m.file_type().is_symlink()).unwrap_or(false) {
				// Remove symlink (don't follow it)
				#[cfg(unix)]
				std::fs::remove_file(&link).or_else(|_| std::fs::remove_dir(&link)).ok();
				#[cfg(windows)]
				std::fs::remove_dir(&link).ok();
			}
		}
	}

	if json_output {
		let json = serde_json::json!({
			"removed": removed,
			"not_found": not_found,
		});
		println!("{}", serde_json::to_string_pretty(&json).unwrap());
	} else {
		if !not_found.is_empty() {
			output::warn(&format!(
				"Not found in dependencies: {}",
				not_found.join(", ")
			));
		}
		println!();
		output::success(&format!(
			"Removed {} package(s)",
			removed.len().to_string().bold()
		));
		println!();
	}

	Ok(())
}
