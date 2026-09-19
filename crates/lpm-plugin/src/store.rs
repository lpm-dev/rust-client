//! Plugin storage management at `~/.lpm/plugins/`.
//!
//! Layout:
//!
//! ```text
//! ~/.lpm/plugins/
//!   {name}/
//!     {version}/
//!       {platform}/
//!         {binary}
//!         .lpm-plugin.json    ← sidecar metadata
//!   .version-cache.json       ← latest-known versions per plugin
//! ```
//!
//! The `{platform}` segment is required for correctness — without it,
//! a `$LPM_HOME` shared across architectures (cross-arch CI runners,
//! NFS, Docker bind mounts) would let one host install a binary that
//! a sibling host then attempts to exec, hitting "Exec format error".

use lpm_common::{LpmError, LpmRoot};
use std::path::PathBuf;

/// Validate that a plugin version string is safe for use in file paths.
///
/// Rejects path traversal attempts, empty strings, and control characters.
fn validate_plugin_version(version: &str) -> Result<(), LpmError> {
    if version.is_empty() {
        return Err(LpmError::Plugin("plugin version must not be empty".into()));
    }

    if version == "." || version.contains("..") {
        return Err(LpmError::Plugin(format!(
            "plugin version contains a forbidden path component: {version}"
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

/// Validate that a platform string is safe for use in file paths. The
/// `Platform::to_string()` shape is `<os>-<arch>` with both sides drawn
/// from a fixed allowlist, so this is belt-and-braces against a
/// caller passing untrusted input.
fn validate_platform(platform: &str) -> Result<(), LpmError> {
    if platform.is_empty() {
        return Err(LpmError::Plugin("platform must not be empty".into()));
    }
    if platform.contains("..") || platform.contains('/') || platform.contains('\\') {
        return Err(LpmError::Plugin(format!(
            "platform contains forbidden characters: {platform}"
        )));
    }
    if !platform.chars().all(|c| c.is_alphanumeric() || c == '-') {
        return Err(LpmError::Plugin(format!(
            "platform contains invalid characters: {platform}"
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

fn tool_dir(name: &str) -> Result<PathBuf, LpmError> {
    crate::storage::validate_name(name)?;
    let directory = plugins_dir()?.join(name);
    crate::storage::directory_if_present(&directory)?;
    Ok(directory)
}

/// Directory holding all platforms for a given plugin version.
pub fn plugin_version_dir(name: &str, version: &str) -> Result<PathBuf, LpmError> {
    validate_plugin_version(version)?;
    let directory = tool_dir(name)?.join(version);
    crate::storage::directory_if_present(&directory)?;
    Ok(directory)
}

/// Directory for a specific plugin version on a specific platform — the
/// container for the binary and its sidecar.
pub fn plugin_platform_dir(name: &str, version: &str, platform: &str) -> Result<PathBuf, LpmError> {
    validate_plugin_version(version)?;
    validate_platform(platform)?;
    let directory = plugin_version_dir(name, version)?.join(platform);
    crate::storage::directory_if_present(&directory)?;
    Ok(directory)
}

/// Full path to a plugin's binary on a specific platform.
pub fn plugin_binary_path(
    name: &str,
    version: &str,
    platform: &str,
    binary_name: &str,
) -> Result<PathBuf, LpmError> {
    Ok(plugin_platform_dir(name, version, platform)?.join(binary_name))
}

/// Full path to a plugin's sidecar metadata on a specific platform.
pub fn plugin_sidecar_path(name: &str, version: &str, platform: &str) -> Result<PathBuf, LpmError> {
    Ok(plugin_platform_dir(name, version, platform)?.join(crate::sidecar::SIDECAR_FILE_NAME))
}

/// Stable mutation lock shared by installation, update, and removal.
pub fn plugin_install_lock_path(name: &str, version: &str) -> Result<PathBuf, LpmError> {
    validate_plugin_version(version)?;
    crate::storage::operation_lock("plugins", name)
}

/// The same mutation lock used by installation and removal.
pub fn plugin_update_lock_path(name: &str) -> Result<PathBuf, LpmError> {
    crate::storage::operation_lock("plugins", name)
}

/// Pre-platform-segment plugin layout that shipped before the platform
/// scoping fix. `~/.lpm/plugins/{name}/{version}/{binary}`. Detected at
/// reuse time and treated as a cache miss; the legacy bytes are deleted
/// only after a successful re-verify-and-install via [`finalize_legacy_cleanup`].
pub fn legacy_plugin_binary_path(
    name: &str,
    version: &str,
    binary_name: &str,
) -> Result<PathBuf, LpmError> {
    Ok(plugin_version_dir(name, version)?.join(binary_name))
}

/// Remove a legacy unscoped binary after the new platform-scoped install
/// has succeeded. Best-effort: failure to remove is logged but does not
/// fail the install (the user can clean up manually with `lpm plugin remove`).
pub fn finalize_legacy_cleanup(name: &str, version: &str, binary_name: &str) {
    if let Ok(legacy) = legacy_plugin_binary_path(name, version, binary_name)
        && legacy.exists()
    {
        match std::fs::remove_file(&legacy) {
            Ok(()) => tracing::debug!(
                "removed legacy plugin binary at {} (replaced by platform-scoped install)",
                legacy.display(),
            ),
            Err(e) => tracing::warn!(
                "failed to remove legacy plugin binary at {}: {e}",
                legacy.display(),
            ),
        }
    }
}

/// Check if a plugin version is installed on the current platform.
pub fn is_installed(name: &str, version: &str, platform: &str, binary_name: &str) -> bool {
    plugin_binary_path(name, version, platform, binary_name).is_ok_and(|p| p.exists())
}

/// List installed versions of a plugin (across all platforms — the
/// version directory contains one subdir per platform).
pub fn list_installed_versions(name: &str) -> Result<Vec<String>, LpmError> {
    let dir = tool_dir(name)?;
    if !dir.exists() {
        return Ok(vec![]);
    }

    let Some(def) = crate::registry::get_plugin(name) else {
        return Ok(Vec::new());
    };
    let mut versions = Vec::new();
    for entry in std::fs::read_dir(&dir)? {
        let entry = entry?;
        let version = entry.file_name().to_string_lossy().into_owned();
        if !entry.file_type()?.is_dir()
            || validate_plugin_version(&version).is_err()
            || version.starts_with('.')
        {
            continue;
        }
        for platform in std::fs::read_dir(entry.path())? {
            let platform = platform?;
            if !platform.file_type()?.is_dir() {
                continue;
            }
            let directory = platform.path();
            let Ok(receipt) =
                crate::sidecar::read_sidecar(&directory.join(crate::sidecar::SIDECAR_FILE_NAME))
            else {
                continue;
            };
            if receipt.schema_version == crate::sidecar::SCHEMA_VERSION
                && receipt.plugin_name == name
                && receipt.version == version
                && receipt.platform == platform.file_name().to_string_lossy()
                && directory.join(def.binary_name).is_file()
            {
                versions.push(version);
                break;
            }
        }
    }
    versions.sort_by(|a, b| crate::versions::compare_versions(a, b));
    Ok(versions)
}

/// Remove a specific plugin version (all platforms).
pub fn remove_version(name: &str, version: &str) -> Result<bool, LpmError> {
    let lock = plugin_install_lock_path(name, version)?;
    lpm_common::with_exclusive_lock(lock, || {
        let directory = plugin_version_dir(name, version)?;
        if directory.exists() {
            std::fs::remove_dir_all(directory)?;
            Ok(true)
        } else {
            Ok(false)
        }
    })
}

/// Remove every installed version while holding the stable tool lock.
pub fn remove_all(name: &str) -> Result<usize, LpmError> {
    lpm_common::with_exclusive_lock(plugin_update_lock_path(name)?, || {
        let directory = tool_dir(name)?;
        if !directory.exists() {
            return Ok(0);
        }
        let count = list_installed_versions(name)?.len();
        std::fs::remove_dir_all(directory)?;
        Ok(count)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plugin_path_structure() {
        let path = plugin_binary_path("oxlint", "1.57.0", "darwin-arm64", "oxlint").unwrap();
        let path_str = path.to_string_lossy();
        assert!(path_str.contains(".lpm/plugins/oxlint/1.57.0/darwin-arm64/oxlint"));
    }

    #[test]
    fn sidecar_lives_next_to_binary() {
        let bin = plugin_binary_path("oxlint", "1.57.0", "darwin-arm64", "oxlint").unwrap();
        let sidecar = plugin_sidecar_path("oxlint", "1.57.0", "darwin-arm64").unwrap();
        assert_eq!(bin.parent(), sidecar.parent());
    }

    #[test]
    fn legacy_path_omits_platform_segment() {
        let legacy = legacy_plugin_binary_path("oxlint", "1.57.0", "oxlint").unwrap();
        let new = plugin_binary_path("oxlint", "1.57.0", "darwin-arm64", "oxlint").unwrap();
        assert_ne!(legacy, new);
        // Legacy is one segment shorter (no platform dir).
        assert!(new.starts_with(legacy.parent().unwrap()));
    }

    #[test]
    fn not_installed_returns_false() {
        assert!(!is_installed(
            "nonexistent-plugin",
            "0.0.0",
            "darwin-arm64",
            "nope"
        ));
    }

    // --- Path traversal validation ---

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

    #[test]
    fn valid_platforms_accepted() {
        for p in &[
            "darwin-arm64",
            "darwin-x64",
            "linux-x64",
            "linux-arm64",
            "win-x64",
        ] {
            assert!(validate_platform(p).is_ok());
        }
    }

    #[test]
    fn platform_traversal_rejected() {
        assert!(validate_platform("../../etc").is_err());
        assert!(validate_platform("darwin/arm64").is_err());
        assert!(validate_platform("").is_err());
        assert!(validate_platform("darwin\\arm64").is_err());
    }

    // --- Lock-path helpers ---

    #[test]
    fn install_lock_is_shared_across_versions_and_platforms() {
        let a = plugin_install_lock_path("oxlint", "1.57.0").unwrap();
        let b = plugin_install_lock_path("oxlint", "1.58.0").unwrap();
        assert_eq!(a, b);
        assert!(a.ends_with(".locks/plugins/operations/oxlint.lock"));
    }

    #[test]
    fn install_lock_path_rejects_traversal_version() {
        assert!(plugin_install_lock_path("oxlint", "../../etc").is_err());
        assert!(plugin_install_lock_path("oxlint", "").is_err());
    }

    #[test]
    fn update_lock_path_differs_per_name() {
        let a = plugin_update_lock_path("oxlint").unwrap();
        let b = plugin_update_lock_path("biome").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn install_and_update_share_the_tool_operation_lock() {
        assert_eq!(
            plugin_install_lock_path("oxlint", "1.57.0").unwrap(),
            plugin_update_lock_path("oxlint").unwrap()
        );
    }

    #[test]
    fn plugin_binary_path_returns_result() {
        let result = plugin_binary_path("oxlint", "1.57.0", "darwin-arm64", "oxlint");
        assert!(result.is_ok());
        let path_str = result.unwrap().to_string_lossy().to_string();
        assert!(
            !path_str.contains("/tmp"),
            "path should not fall back to /tmp: {path_str}"
        );
    }

    #[test]
    fn every_plugin_storage_path_rejects_nonleaf_names() {
        for name in [
            "",
            ".",
            "..",
            "../victim",
            "/tmp/victim",
            "C:\\victim",
            "a/b",
            "a\\b",
        ] {
            assert!(plugin_version_dir(name, "1.0.0").is_err(), "{name}");
            assert!(
                plugin_platform_dir(name, "1.0.0", "darwin-arm64").is_err(),
                "{name}"
            );
            assert!(plugin_install_lock_path(name, "1.0.0").is_err(), "{name}");
            assert!(plugin_update_lock_path(name).is_err(), "{name}");
        }
    }

    #[test]
    fn plugin_operation_locks_survive_removal_of_the_install_tree() {
        let removed = plugins_dir().unwrap().join("oxlint");
        assert!(
            !plugin_install_lock_path("oxlint", "1.0.0")
                .unwrap()
                .starts_with(&removed)
        );
        assert!(
            !plugin_update_lock_path("oxlint")
                .unwrap()
                .starts_with(&removed)
        );
    }

    #[test]
    fn dot_is_not_a_managed_version_directory() {
        assert!(validate_plugin_version(".").is_err());
    }
}
