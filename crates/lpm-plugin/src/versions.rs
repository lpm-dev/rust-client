//! Fetch latest plugin versions from GitHub Releases API.
//!
//! Caches results at `~/.lpm/plugins/.version-cache.json` with a 1-hour TTL.
//! Falls back to hardcoded versions when offline.

use crate::registry::PluginDef;
use lpm_common::LpmError;
use std::collections::HashMap;
use std::path::PathBuf;

const CACHE_TTL_SECS: u64 = 3600; // 1 hour

/// Cached version info for all plugins.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct VersionCache {
	/// Plugin name → latest version.
	versions: HashMap<String, String>,
	/// Unix timestamp of last fetch.
	fetched_at: u64,
}

/// Get the latest version for a plugin.
///
/// Checks cache first (1h TTL), then fetches from GitHub API.
/// Falls back to hardcoded `def.latest_version` if offline.
pub async fn get_latest_version(def: &PluginDef) -> String {
	// Try cache first
	if let Some(cached) = read_cached_version(def.name) {
		return cached;
	}

	// Fetch from GitHub
	match fetch_latest_from_github(def).await {
		Ok(version) => {
			// Update cache
			let _ = write_cached_version(def.name, &version);
			version
		}
		Err(e) => {
			tracing::warn!(
				"failed to check for {} updates: {e}. Using cached version {}.",
				def.name,
				def.latest_version
			);
			eprintln!(
				"  \x1b[33m⚠\x1b[0m Using {} v{} (couldn't check for updates)",
				def.name,
				def.latest_version,
			);
			def.latest_version.to_string()
		}
	}
}

/// Fetch latest versions for all plugins (batch, for `lpm plugin list`).
pub async fn get_all_latest_versions() -> HashMap<String, String> {
	let mut result = HashMap::new();

	for def in crate::registry::list_plugins() {
		let version = get_latest_version(def).await;
		result.insert(def.name.to_string(), version);
	}

	result
}

/// Read a cached version for a plugin (if cache is fresh).
fn read_cached_version(plugin_name: &str) -> Option<String> {
	let cache = read_cache().ok()?;

	let now = now_secs();
	if now - cache.fetched_at > CACHE_TTL_SECS {
		return None; // Cache is stale
	}

	cache.versions.get(plugin_name).cloned()
}

/// Write a version to the cache.
fn write_cached_version(plugin_name: &str, version: &str) -> Result<(), LpmError> {
	let mut cache = read_cache().unwrap_or(VersionCache {
		versions: HashMap::new(),
		fetched_at: 0,
	});

	cache.versions.insert(plugin_name.to_string(), version.to_string());
	cache.fetched_at = now_secs();

	let path = cache_path()?;
	if let Some(parent) = path.parent() {
		std::fs::create_dir_all(parent)?;
	}

	let json = serde_json::to_string(&cache)
		.map_err(|e| LpmError::Plugin(format!("failed to serialize version cache: {e}")))?;
	std::fs::write(&path, json)?;

	Ok(())
}

/// Read the version cache file.
fn read_cache() -> Result<VersionCache, LpmError> {
	let path = cache_path()?;
	let content = std::fs::read_to_string(&path)?;
	let cache: VersionCache = serde_json::from_str(&content)
		.map_err(|e| LpmError::Plugin(format!("failed to parse version cache: {e}")))?;
	Ok(cache)
}

fn cache_path() -> Result<PathBuf, LpmError> {
	let dir = crate::store::plugins_dir()?;
	Ok(dir.join(".version-cache.json"))
}

fn now_secs() -> u64 {
	std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.unwrap_or_default()
		.as_secs()
}

/// Fetch the latest release tag from GitHub for a plugin.
async fn fetch_latest_from_github(def: &PluginDef) -> Result<String, String> {
	// Extract owner/repo from URL template
	let api_url = github_api_url(def)?;

	let client = reqwest::Client::builder()
		.timeout(std::time::Duration::from_secs(5))
		.build()
		.map_err(|e| format!("http client error: {e}"))?;

	let resp = client
		.get(&api_url)
		.header("User-Agent", "lpm-cli")
		.header("Accept", "application/vnd.github.v3+json")
		.send()
		.await
		.map_err(|e| format!("github request failed: {e}"))?;

	if !resp.status().is_success() {
		return Err(format!("github API returned {}", resp.status()));
	}

	let body: serde_json::Value = resp
		.json()
		.await
		.map_err(|e| format!("failed to parse github response: {e}"))?;

	let tag = body
		.get("tag_name")
		.and_then(|v| v.as_str())
		.ok_or("no tag_name in github release")?;

	// Parse version from tag — handles various formats:
	// "v1.57.0", "apps_v1.57.0", "@biomejs/biome@2.4.8"
	let version = extract_version_from_tag(tag);
	Ok(version)
}

/// Build the GitHub API URL for the latest release.
fn github_api_url(def: &PluginDef) -> Result<String, String> {
	// Parse owner/repo from url_template
	// "https://github.com/oxc-project/oxc/releases/..." → "oxc-project/oxc"
	let url = def.url_template;
	let after_github = url
		.strip_prefix("https://github.com/")
		.ok_or("not a github URL")?;

	let parts: Vec<&str> = after_github.split('/').collect();
	if parts.len() < 2 {
		return Err("invalid github URL".into());
	}

	Ok(format!(
		"https://api.github.com/repos/{}/{}/releases/latest",
		parts[0], parts[1]
	))
}

/// Extract a semver version from a git tag.
///
/// "v1.57.0" → "1.57.0"
/// "apps_v1.57.0" → "1.57.0"
/// "@biomejs/biome@2.4.8" → "2.4.8"
fn extract_version_from_tag(tag: &str) -> String {
	// Try @scope/name@version format
	if let Some(idx) = tag.rfind('@') {
		if idx > 0 {
			return tag[idx + 1..].to_string();
		}
	}

	// Try apps_v or v prefix
	let stripped = tag
		.strip_prefix("apps_v")
		.or_else(|| tag.strip_prefix("cli_v"))
		.or_else(|| tag.strip_prefix("v"))
		.unwrap_or(tag);

	stripped.to_string()
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn extract_version_simple() {
		assert_eq!(extract_version_from_tag("v1.57.0"), "1.57.0");
	}

	#[test]
	fn extract_version_apps_prefix() {
		assert_eq!(extract_version_from_tag("apps_v1.57.0"), "1.57.0");
	}

	#[test]
	fn extract_version_scoped() {
		assert_eq!(extract_version_from_tag("@biomejs/biome@2.4.8"), "2.4.8");
	}

	#[test]
	fn extract_version_no_prefix() {
		assert_eq!(extract_version_from_tag("1.0.0"), "1.0.0");
	}

	#[test]
	fn github_api_url_oxlint() {
		let def = crate::registry::get_plugin("oxlint").unwrap();
		let url = github_api_url(def).unwrap();
		assert_eq!(url, "https://api.github.com/repos/oxc-project/oxc/releases/latest");
	}

	#[test]
	fn github_api_url_biome() {
		let def = crate::registry::get_plugin("biome").unwrap();
		let url = github_api_url(def).unwrap();
		assert_eq!(url, "https://api.github.com/repos/biomejs/biome/releases/latest");
	}
}
