//! Plugin storage management at `~/.lpm/plugins/`.

use lpm_common::LpmError;
use std::path::PathBuf;

/// Base directory for all plugins.
pub fn plugins_dir() -> Result<PathBuf, LpmError> {
	let home = dirs::home_dir()
		.ok_or_else(|| LpmError::Script("could not determine home directory".into()))?;
	Ok(home.join(".lpm").join("plugins"))
}

/// Directory for a specific plugin version.
pub fn plugin_version_dir(name: &str, version: &str) -> Result<PathBuf, LpmError> {
	Ok(plugins_dir()?.join(name).join(version))
}

/// Full path to a plugin's binary.
pub fn plugin_binary_path(name: &str, version: &str, binary_name: &str) -> PathBuf {
	let dir = plugins_dir()
		.unwrap_or_else(|_| PathBuf::from("/tmp/.lpm/plugins"));
	dir.join(name).join(version).join(binary_name)
}

/// Check if a plugin version is installed.
pub fn is_installed(name: &str, version: &str, binary_name: &str) -> bool {
	plugin_binary_path(name, version, binary_name).exists()
}

/// List installed versions of a plugin.
pub fn list_installed_versions(name: &str) -> Result<Vec<String>, LpmError> {
	let dir = plugins_dir()?.join(name);
	if !dir.exists() {
		return Ok(vec![]);
	}

	let mut versions = Vec::new();
	for entry in std::fs::read_dir(&dir)? {
		let entry = entry?;
		if entry.path().is_dir() {
			versions.push(entry.file_name().to_string_lossy().to_string());
		}
	}

	versions.sort();
	Ok(versions)
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn plugin_path_structure() {
		let path = plugin_binary_path("oxlint", "1.57.0", "oxlint");
		let path_str = path.to_string_lossy();
		assert!(path_str.contains(".lpm/plugins/oxlint/1.57.0/oxlint"));
	}

	#[test]
	fn not_installed_returns_false() {
		assert!(!is_installed("nonexistent-plugin", "0.0.0", "nope"));
	}
}
