//! Plugin storage management at `~/.lpm/plugins/`.

use lpm_common::{LpmError, LpmRoot};
use std::path::PathBuf;

/// Validate that a plugin version string is safe for use in file paths.
///
/// Rejects path traversal attempts, empty strings, and control characters.
fn validate_plugin_version(version: &str) -> Result<(), LpmError> {
    if version.is_empty() {
        return Err(LpmError::Plugin("plugin version must not be empty".into()));
    }

    if version.contains("..") {
        return Err(LpmError::Plugin(format!(
            "plugin version contains forbidden sequence '..': {version}"
        )));
    }

    if !version
        .chars()
        .all(|c| c.is_alphanumeric() || c == '.' || c == '-' || c == '_')
    {
        return Err(LpmError::Plugin(format!(
            "plugin version contains invalid characters: {version}"
        )));
    }

    Ok(())
}

/// Base directory for all plugins (`~/.lpm/plugins/`).
///
/// Routed through [`LpmRoot::from_env`] so the plugin tree respects
/// `$LPM_HOME` overrides and the single canonical home-resolution rule.
pub fn plugins_dir() -> Result<PathBuf, LpmError> {
    let root = LpmRoot::from_env()
        .map_err(|e| LpmError::Plugin(format!("could not determine LPM home: {e}")))?;
    Ok(root.plugins_root())
}

/// Directory for a specific plugin version.
pub fn plugin_version_dir(name: &str, version: &str) -> Result<PathBuf, LpmError> {
    validate_plugin_version(version)?;
    Ok(plugins_dir()?.join(name).join(version))
}

/// Full path to a plugin's binary.
pub fn plugin_binary_path(
    name: &str,
    version: &str,
    binary_name: &str,
) -> Result<PathBuf, LpmError> {
    validate_plugin_version(version)?;
    let dir = plugins_dir()?;
    Ok(dir.join(name).join(version).join(binary_name))
}

/// Check if a plugin version is installed.
pub fn is_installed(name: &str, version: &str, binary_name: &str) -> bool {
    plugin_binary_path(name, version, binary_name)
        .map(|p| p.exists())
        .unwrap_or(false)
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

/// Remove a specific plugin version.
pub fn remove_version(name: &str, version: &str) -> Result<bool, LpmError> {
    let dir = plugin_version_dir(name, version)?;
    if dir.exists() {
        std::fs::remove_dir_all(&dir)?;
        Ok(true)
    } else {
        Ok(false)
    }
}

/// Remove all versions of a plugin.
pub fn remove_all(name: &str) -> Result<usize, LpmError> {
    let dir = plugins_dir()?.join(name);
    if !dir.exists() {
        return Ok(0);
    }

    let versions = list_installed_versions(name)?;
    let count = versions.len();
    std::fs::remove_dir_all(&dir)?;
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plugin_path_structure() {
        let path = plugin_binary_path("oxlint", "1.57.0", "oxlint").unwrap();
        let path_str = path.to_string_lossy();
        assert!(path_str.contains(".lpm/plugins/oxlint/1.57.0/oxlint"));
    }

    #[test]
    fn not_installed_returns_false() {
        assert!(!is_installed("nonexistent-plugin", "0.0.0", "nope"));
    }

    // --- Finding #1: Path traversal validation ---

    #[test]
    fn valid_versions_accepted() {
        assert!(validate_plugin_version("1.57.0").is_ok());
        assert!(validate_plugin_version("2.4.8-rc1").is_ok());
        assert!(validate_plugin_version("1.0.0_beta").is_ok());
    }

    #[test]
    fn path_traversal_rejected() {
        assert!(validate_plugin_version("../../etc").is_err());
    }

    #[test]
    fn slash_in_version_rejected() {
        assert!(validate_plugin_version("1.0/../../").is_err());
    }

    #[test]
    fn empty_version_rejected() {
        assert!(validate_plugin_version("").is_err());
    }

    #[test]
    fn null_byte_in_version_rejected() {
        assert!(validate_plugin_version("v1\0").is_err());
    }

    // --- Finding #7: No /tmp fallback ---

    #[test]
    fn plugin_binary_path_returns_result() {
        // Verify it returns Result, not a raw PathBuf with /tmp fallback
        let result = plugin_binary_path("oxlint", "1.57.0", "oxlint");
        assert!(result.is_ok());
        let path_str = result.unwrap().to_string_lossy().to_string();
        assert!(
            !path_str.contains("/tmp"),
            "path should not fall back to /tmp: {path_str}"
        );
    }
}
