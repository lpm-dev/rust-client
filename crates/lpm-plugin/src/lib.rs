//! Plugin management for LPM — lazy-download external tool binaries.
//!
//! Plugins are stored globally at `~/.lpm/plugins/{name}/{version}/`.
//! Per-project version pinning via `lpm.json` `tools` section.
//!
//! ```text
//! ~/.lpm/plugins/
//!   oxlint/
//!     1.57.0/
//!       oxlint           ← downloaded binary
//!   biome/
//!     2.4.8/
//!       biome
//!   .version-cache.json  ← cached latest versions (1h TTL)
//! ```

pub mod download;
pub mod registry;
pub mod store;
pub mod versions;

use lpm_common::LpmError;
use std::path::PathBuf;

/// Ensure a plugin is installed and return the path to its binary.
///
/// If `pinned_version` is provided (from `lpm.json` tools), uses that exact version.
/// Otherwise, fetches the latest version from GitHub (cached 1h).
/// Downloads the plugin on first use.
pub async fn ensure_plugin(
	plugin_name: &str,
	pinned_version: Option<&str>,
	auto_download: bool,
) -> Result<PathBuf, LpmError> {
	let def = registry::get_plugin(plugin_name)
		.ok_or_else(|| LpmError::Script(format!("unknown plugin: '{plugin_name}'")))?;

	// Resolve version: pinned > cached latest > hardcoded fallback
	let version = match pinned_version {
		Some(v) => v.to_string(),
		None => versions::get_latest_version(def).await,
	};

	// Check if already installed
	let bin_path = store::plugin_binary_path(plugin_name, &version, def.binary_name);
	if bin_path.exists() {
		tracing::debug!("plugin {plugin_name}@{version} already installed");
		return Ok(bin_path);
	}

	// Not installed — need to download
	if !auto_download {
		let env_auto = std::env::var("LPM_AUTO_DOWNLOAD")
			.map(|v| v == "true" || v == "1")
			.unwrap_or(false);

		if !env_auto {
			eprintln!(
				"  Plugin '{}' not installed. Downloading {} v{}...",
				plugin_name, def.binary_name, version
			);
		}
	}

	let platform = lpm_runtime::platform::Platform::current();
	download::download_plugin(def, &version, &platform).await?;

	if bin_path.exists() {
		Ok(bin_path)
	} else {
		Err(LpmError::Script(format!(
			"plugin {plugin_name}@{version} downloaded but binary not found at {}",
			bin_path.display()
		)))
	}
}

/// Update a plugin to the latest version.
///
/// Always fetches the latest version from GitHub (bypasses cache).
/// Downloads if not already installed.
pub async fn update_plugin(plugin_name: &str) -> Result<String, LpmError> {
	let def = registry::get_plugin(plugin_name)
		.ok_or_else(|| LpmError::Script(format!("unknown plugin: '{plugin_name}'")))?;

	// Force fresh fetch (ignore cache)
	let latest = versions::get_latest_version(def).await;

	let bin_path = store::plugin_binary_path(plugin_name, &latest, def.binary_name);
	if bin_path.exists() {
		return Ok(latest);
	}

	let platform = lpm_runtime::platform::Platform::current();
	download::download_plugin(def, &latest, &platform).await?;

	Ok(latest)
}
