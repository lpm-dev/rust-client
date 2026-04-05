//! Plugin version resolution.
//!
//! Default version = hardcoded in registry (SHA-256 verified on download).
//! `lpm plugin update` explicitly fetches GitHub latest and caches it.
//! Cached versions are sticky: never downgrade from a previously resolved version.
//!
//! Version resolution order:
//!   1. `lpm.json` pin (per-project, exact)
//!   2. Cached version from `lpm plugin update` (if newer than hardcoded)
//!   3. Hardcoded `latest_version` from registry (verified by checksums)
//!
//! Cache file: `~/.lpm/plugins/.version-cache.json`

use crate::registry::PluginDef;
use lpm_common::LpmError;
use std::collections::HashMap;
use std::path::PathBuf;

/// Cached version info for all plugins.
///
/// Cache entries from `lpm plugin update` are sticky — they never expire
/// automatically. This prevents downgrading from an explicitly chosen version.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct VersionCache {
    /// Plugin name → latest version.
    versions: HashMap<String, String>,
    /// Unix timestamp of last fetch.
    fetched_at: u64,
}

/// Get the resolved version for a plugin.
///
/// Returns `max(hardcoded, cached)` — never downgrades from a previously
/// resolved version. The hardcoded version is the verified default; the
/// cached version comes from `lpm plugin update`.
///
/// When `bypass_cache` is true, fetches from GitHub API (used by `update_plugin`).
pub async fn get_latest_version(def: &PluginDef, bypass_cache: bool) -> String {
    if bypass_cache {
        // Explicit update: fetch from GitHub, cache the result
        match fetch_latest_from_github(def).await {
            Ok(version) => {
                let _ = write_cached_version(def.name, &version);
                return version;
            }
            Err(e) => {
                eprintln!(
                    "  \x1b[33m⚠\x1b[0m Failed to check for {} updates: {e}",
                    def.name,
                );
            }
        }
    }

    // Use max(hardcoded, cached) — never downgrade
    let hardcoded = def.latest_version.to_string();
    match read_cached_version(def.name) {
        Some(cached) if is_newer_semver(&cached, &hardcoded) => cached,
        _ => hardcoded,
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

/// Compare two semver-like strings. Returns `true` if `a` is strictly newer than `b`.
///
/// Only compares numeric segments (MAJOR.MINOR.PATCH). Pre-release suffixes
/// are ignored for simplicity — this is a best-effort comparison for plugin
/// version selection, not a full semver resolver.
fn is_newer_semver(a: &str, b: &str) -> bool {
    let parse = |s: &str| -> Vec<u64> {
        // Strip pre-release suffix: "1.58.0-rc1" → "1.58.0"
        let version_part = s.split('-').next().unwrap_or(s);
        version_part
            .split('.')
            .filter_map(|seg| seg.parse::<u64>().ok())
            .collect()
    };
    let va = parse(a);
    let vb = parse(b);
    va > vb
}

/// Read a cached version for a plugin.
///
/// Cache entries from `lpm plugin update` are sticky (never expire).
fn read_cached_version(plugin_name: &str) -> Option<String> {
    let cache = read_cache().ok()?;
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

/// Read a GitHub token from environment variables.
///
/// Checks `GITHUB_TOKEN` first (standard), then `GH_TOKEN` (gh CLI convention).
/// Returns `None` if neither is set — unauthenticated requests are rate-limited
/// to 60/hour vs 5000/hour with a token.
fn github_token() -> Option<String> {
    std::env::var("GITHUB_TOKEN")
        .or_else(|_| std::env::var("GH_TOKEN"))
        .ok()
        .filter(|t| !t.is_empty())
}

/// Build a GitHub API request with optional authentication and rate limit handling.
fn build_github_request(client: &reqwest::Client, url: &str) -> reqwest::RequestBuilder {
    let mut req = client
        .get(url)
        .header("User-Agent", "lpm-cli")
        .header("Accept", "application/vnd.github.v3+json");

    if let Some(token) = github_token() {
        req = req.header("Authorization", format!("Bearer {token}"));
    }

    req
}

/// Check GitHub API response for rate limiting and return a specific error.
fn check_rate_limit(resp: &reqwest::Response) -> Option<String> {
    if resp.status().as_u16() == 403
        && let Some(remaining) = resp.headers().get("x-ratelimit-remaining")
        && remaining.to_str().unwrap_or("") == "0"
    {
        return Some(
            "GitHub API rate limit exceeded. Set GITHUB_TOKEN or GH_TOKEN env var \
            for 5000 req/hr (vs 60 unauthenticated)."
                .to_string(),
        );
    }
    None
}

/// Fetch the latest release tag from GitHub for a plugin.
///
/// For repos with multiple release types (e.g., oxc), fetches the release list
/// and filters by tag prefix instead of using `/releases/latest`.
///
/// Supports `GITHUB_TOKEN` / `GH_TOKEN` env vars for authenticated requests
/// (5000 req/hr vs 60 unauthenticated).
async fn fetch_latest_from_github(def: &PluginDef) -> Result<String, String> {
    let (owner, repo) = parse_github_owner_repo(def)?;
    let tag_prefix = tag_prefix_for_plugin(def);

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .map_err(|e| format!("http client error: {e}"))?;

    let tag = if let Some(prefix) = tag_prefix {
        // Fetch release list and find first matching tag prefix
        let api_url = format!("https://api.github.com/repos/{owner}/{repo}/releases?per_page=20");

        let resp = build_github_request(&client, &api_url)
            .send()
            .await
            .map_err(|e| format!("github request failed: {e}"))?;

        if let Some(rate_err) = check_rate_limit(&resp) {
            return Err(rate_err);
        }
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
        let api_url = format!("https://api.github.com/repos/{owner}/{repo}/releases/latest");

        let resp = build_github_request(&client, &api_url)
            .send()
            .await
            .map_err(|e| format!("github request failed: {e}"))?;

        if let Some(rate_err) = check_rate_limit(&resp) {
            return Err(rate_err);
        }
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
    if let Some(idx) = tag.rfind('@')
        && idx > 0
    {
        return tag[idx + 1..].to_string();
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
        assert!(
            !tmp_file.exists(),
            "temp file should not remain after rename"
        );
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

    // --- GitHub token support ---

    #[test]
    fn github_token_reads_github_token_env() {
        // We can't easily test env vars in parallel, but verify the function exists
        // and returns Option<String>
        let _: Option<String> = github_token();
    }

    // --- Sticky cache: entries never expire ---
    // Cache entries from `lpm plugin update` are sticky (no TTL).
    // read_cached_version() returns the value without checking timestamps.

    // --- Semver comparison ---

    #[test]
    fn newer_semver_basic() {
        assert!(is_newer_semver("1.58.0", "1.57.0"));
        assert!(is_newer_semver("2.0.0", "1.99.99"));
        assert!(is_newer_semver("1.57.1", "1.57.0"));
    }

    #[test]
    fn newer_semver_equal() {
        assert!(!is_newer_semver("1.58.0", "1.58.0"));
    }

    #[test]
    fn newer_semver_older() {
        assert!(!is_newer_semver("1.57.0", "1.58.0"));
        assert!(!is_newer_semver("1.0.0", "2.0.0"));
    }

    #[test]
    fn newer_semver_with_prerelease() {
        // Pre-release suffix is stripped — "1.58.0-rc1" is compared as "1.58.0"
        assert!(is_newer_semver("1.58.0-rc1", "1.57.0"));
        assert!(!is_newer_semver("1.58.0-rc1", "1.58.0"));
    }

    #[test]
    fn newer_semver_different_segment_count() {
        // "1.58" vs "1.58.0" — Vec comparison handles different lengths
        assert!(!is_newer_semver("1.58", "1.58.0"));
        assert!(is_newer_semver("1.58.0", "1.58"));
    }

    // --- Version resolution (max of hardcoded vs cached) ---

    #[test]
    fn version_resolution_uses_hardcoded_when_no_cache() {
        let def = crate::registry::get_plugin("oxlint").unwrap();
        // With no cache file, should return hardcoded
        let hardcoded = def.latest_version.to_string();
        let cached = read_cached_version(def.name);
        let resolved = match cached {
            Some(c) if is_newer_semver(&c, &hardcoded) => c,
            _ => hardcoded.clone(),
        };
        assert_eq!(resolved, hardcoded);
    }
}
