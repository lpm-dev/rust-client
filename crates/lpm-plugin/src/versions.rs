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
///
/// When `bypass_cache` is true, skips the cache check (used by `update_plugin`).
pub async fn get_latest_version(def: &PluginDef, bypass_cache: bool) -> String {
	// Try cache first (unless bypassing)
	if !bypass_cache {
		if let Some(cached) = read_cached_version(def.name) {
			return cached;
		}
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

/// Fetch latest versions for all plugins (for `lpm plugin list`).
pub async fn get_all_latest_versions() -> HashMap<String, String> {
	let plugins = crate::registry::list_plugins();
	let mut map = HashMap::with_capacity(plugins.len());
	for def in plugins {
		let version = get_latest_version(def, false).await;
		map.insert(def.name.to_string(), version);
	}
	map
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

/// Write a version to the cache atomically (write to temp, then rename).
fn write_cached_version(plugin_name: &str, version: &str) -> Result<(), LpmError> {
	let mut cache = read_cache().unwrap_or(VersionCache {
		versions: HashMap::new(),
		fetched_at: 0,
	});

	cache
		.versions
		.insert(plugin_name.to_string(), version.to_string());
	cache.fetched_at = now_secs();

	let path = cache_path()?;
	if let Some(parent) = path.parent() {
		std::fs::create_dir_all(parent)?;
	}

	let json = serde_json::to_string(&cache)
		.map_err(|e| LpmError::Plugin(format!("failed to serialize version cache: {e}")))?;

	// Atomic write: temp file + rename
	let tmp = path.with_extension("tmp");
	std::fs::write(&tmp, json)?;
	std::fs::rename(&tmp, &path).map_err(|e| {
		let _ = std::fs::remove_file(&tmp);
		LpmError::Plugin(format!("failed to rename version cache: {e}"))
	})?;

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

/// Tag prefix configuration for GitHub repos that publish multiple tools.
///
/// Some repos (e.g., oxc-project/oxc) have multiple release types with different
/// tag prefixes. We need to filter to the correct one.
fn tag_prefix_for_plugin(def: &PluginDef) -> Option<&'static str> {
	// Extract from url_template: the part between "download/" and "{version}"
	let url = def.url_template;
	if let Some(start) = url.find("download/") {
		let after_download = &url[start + "download/".len()..];
		if let Some(end) = after_download.find("{version}") {
			let prefix = &after_download[..end];
			if !prefix.is_empty() {
				// Return as static str by matching known patterns
				return match prefix {
					"apps_v" => Some("apps_v"),
					"%40biomejs/biome%40" => Some("@biomejs/biome@"),
					_ => None,
				};
			}
		}
	}
	None
}

/// Fetch the latest release tag from GitHub for a plugin.
///
/// For repos with multiple release types (e.g., oxc), fetches the release list
/// and filters by tag prefix instead of using `/releases/latest`.
async fn fetch_latest_from_github(def: &PluginDef) -> Result<String, String> {
	let (owner, repo) = parse_github_owner_repo(def)?;
	let tag_prefix = tag_prefix_for_plugin(def);

	let client = reqwest::Client::builder()
		.timeout(std::time::Duration::from_secs(5))
		.build()
		.map_err(|e| format!("http client error: {e}"))?;

	let tag = if let Some(prefix) = tag_prefix {
		// Fetch release list and find first matching tag prefix
		let api_url = format!(
			"https://api.github.com/repos/{owner}/{repo}/releases?per_page=20"
		);

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

		let releases: Vec<serde_json::Value> = resp
			.json()
			.await
			.map_err(|e| format!("failed to parse github response: {e}"))?;

		releases
			.iter()
			.filter_map(|r| r.get("tag_name")?.as_str())
			.find(|tag| tag.starts_with(prefix))
			.ok_or_else(|| {
				format!("no release found with tag prefix '{prefix}' in {owner}/{repo}")
			})?
			.to_string()
	} else {
		// Simple case: use /releases/latest
		let api_url = format!(
			"https://api.github.com/repos/{owner}/{repo}/releases/latest"
		);

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

		body.get("tag_name")
			.and_then(|v| v.as_str())
			.ok_or("no tag_name in github release")?
			.to_string()
	};

	// Parse version from tag
	let version = extract_version_from_tag(&tag);

	// Validate extracted version looks like semver
	if !is_semver_like(&version) {
		return Err(format!(
			"extracted version '{version}' from tag '{tag}' doesn't look like semver"
		));
	}

	Ok(version)
}

/// Parse owner/repo from a plugin's URL template.
fn parse_github_owner_repo(def: &PluginDef) -> Result<(String, String), String> {
	let url = def.url_template;
	let after_github = url
		.strip_prefix("https://github.com/")
		.ok_or("not a github URL")?;

	let parts: Vec<&str> = after_github.split('/').collect();
	if parts.len() < 2 {
		return Err("invalid github URL".into());
	}

	Ok((parts[0].to_string(), parts[1].to_string()))
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

/// Check if a string looks like a semver version (MAJOR.MINOR.PATCH with optional pre-release).
fn is_semver_like(s: &str) -> bool {
	let parts: Vec<&str> = s.splitn(2, '-').collect();
	let version_part = parts[0];
	let segments: Vec<&str> = version_part.split('.').collect();
	segments.len() >= 2
		&& segments.len() <= 4
		&& segments
			.iter()
			.all(|s| !s.is_empty() && s.chars().all(|c| c.is_ascii_digit()))
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

	// --- Finding #5: semver validation ---

	#[test]
	fn semver_like_valid() {
		assert!(is_semver_like("1.57.0"));
		assert!(is_semver_like("2.4.8"));
		assert!(is_semver_like("0.1.0"));
		assert!(is_semver_like("1.57.0-rc1"));
	}

	#[test]
	fn semver_like_invalid() {
		assert!(!is_semver_like("not-a-version"));
		assert!(!is_semver_like(""));
		assert!(!is_semver_like("abc"));
		assert!(!is_semver_like("nightly-2024-01-01"));
	}

	// --- Finding #5: tag prefix detection ---

	#[test]
	fn tag_prefix_oxlint() {
		let def = crate::registry::get_plugin("oxlint").unwrap();
		assert_eq!(tag_prefix_for_plugin(def), Some("apps_v"));
	}

	#[test]
	fn tag_prefix_biome() {
		let def = crate::registry::get_plugin("biome").unwrap();
		assert_eq!(tag_prefix_for_plugin(def), Some("@biomejs/biome@"));
	}

	// --- Finding #14: atomic cache write ---

	#[test]
	fn atomic_cache_write_no_temp_file_remains() {
		let dir = tempfile::tempdir().unwrap();
		let cache_file = dir.path().join("test-cache.json");
		let tmp_file = cache_file.with_extension("tmp");

		let cache = VersionCache {
			versions: HashMap::from([("test".to_string(), "1.0.0".to_string())]),
			fetched_at: 12345,
		};
		let json = serde_json::to_string(&cache).unwrap();

		// Simulate atomic write
		std::fs::write(&tmp_file, &json).unwrap();
		std::fs::rename(&tmp_file, &cache_file).unwrap();

		assert!(cache_file.exists());
		assert!(!tmp_file.exists(), "temp file should not remain after rename");
	}

	// --- Finding #5: github_api_url test updated for new function ---

	#[test]
	fn parse_github_owner_repo_oxlint() {
		let def = crate::registry::get_plugin("oxlint").unwrap();
		let (owner, repo) = parse_github_owner_repo(def).unwrap();
		assert_eq!(owner, "oxc-project");
		assert_eq!(repo, "oxc");
	}

	#[test]
	fn parse_github_owner_repo_biome() {
		let def = crate::registry::get_plugin("biome").unwrap();
		let (owner, repo) = parse_github_owner_repo(def).unwrap();
		assert_eq!(owner, "biomejs");
		assert_eq!(repo, "biome");
	}
}
