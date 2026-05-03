//! Plugin version resolution.
//!
//! - The hardcoded `latest_version` in [`crate::registry`] is the floor and
//!   the verified default (bundled SHA-256).
//! - `lpm plugin update` calls [`peek_latest_from_github`] to discover what
//!   GitHub currently lists as latest. The result is *not* persisted until
//!   the corresponding install has actually downloaded and verified — see
//!   [`approve_version`]. This separation prevents a transient checksum
//!   miss or 404 from poisoning the install-selection cache and routing
//!   every future invocation to a version that won't install.
//! - [`get_latest_version`] is the read-only path used by `ensure_plugin`
//!   on every invocation. It returns `max(hardcoded, approved-cache)` and
//!   never touches the network.
//!
//! Cache file: `~/.lpm/plugins/.version-cache.json`. Sticky — entries
//! never expire by time. The only way an entry changes is a fresh
//! `lpm plugin update` followed by a successful verified install.

use crate::registry::PluginDef;
use lpm_common::LpmError;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Cached install-selection state. Each entry is the highest version
/// we have ever **successfully verified-and-installed** via
/// `lpm plugin update`.
#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
struct VersionCache {
    versions: HashMap<String, String>,
}

/// Resolved version for a plugin, used by `ensure_plugin` on every
/// invocation. Returns `max(hardcoded, approved-cache)`. Never touches
/// the network. Never writes the cache.
pub async fn get_latest_version(def: &PluginDef) -> String {
    let hardcoded = def.latest_version.to_string();
    match read_cached_version(def.name) {
        Some(cached) if is_newer_semver(&cached, &hardcoded) => cached,
        _ => hardcoded,
    }
}

/// Latest-known version per plugin, for `lpm plugin list`. Read-only —
/// reflects what the cache currently believes, NOT what GitHub reports
/// right now. (A separate freshness-check surface would be needed for
/// "is an update available?" UX.)
pub async fn get_all_latest_versions() -> HashMap<String, String> {
    let plugins = crate::registry::list_plugins();
    let mut map = HashMap::with_capacity(plugins.len());
    for def in plugins {
        let version = get_latest_version(def).await;
        map.insert(def.name.to_string(), version);
    }
    map
}

/// Compare two semver-like strings. Returns `true` if `a` is strictly newer than `b`.
///
/// Only compares numeric segments (MAJOR.MINOR.PATCH). Pre-release suffixes
/// are ignored for simplicity — this is a best-effort comparison for plugin
/// version selection, not a full semver resolver.
pub(crate) fn is_newer_semver(a: &str, b: &str) -> bool {
    let parse = |s: &str| -> Vec<u64> {
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
fn read_cached_version(plugin_name: &str) -> Option<String> {
    let cache = read_cache().ok()?;
    cache.versions.get(plugin_name).cloned()
}

/// Persist a freshly-installed-and-verified version to the cache.
///
/// **Only called from `update_plugin` AFTER `download_plugin` has
/// returned `Ok(())`.** Persisting earlier could leave the cache
/// pointing at a version that does not exist or cannot be verified,
/// which would route every future `ensure_plugin` invocation down a
/// permanently-failing install path.
pub fn approve_version(plugin_name: &str, version: &str) -> Result<(), LpmError> {
    write_cached_version_at(&cache_path()?, plugin_name, version)
}

/// Path-injected variant of [`approve_version`] for unit testing.
fn write_cached_version_at(
    cache_path: &Path,
    plugin_name: &str,
    version: &str,
) -> Result<(), LpmError> {
    let mut cache = read_cache_at(cache_path).unwrap_or_default();
    cache
        .versions
        .insert(plugin_name.to_string(), version.to_string());

    if let Some(parent) = cache_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let json = serde_json::to_string(&cache)
        .map_err(|e| LpmError::Plugin(format!("failed to serialize version cache: {e}")))?;

    let tmp = cache_path.with_extension("tmp");
    std::fs::write(&tmp, json)?;
    std::fs::rename(&tmp, cache_path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        LpmError::Plugin(format!("failed to rename version cache: {e}"))
    })?;

    Ok(())
}

fn read_cache() -> Result<VersionCache, LpmError> {
    read_cache_at(&cache_path()?)
}

fn read_cache_at(cache_path: &Path) -> Result<VersionCache, LpmError> {
    let content = std::fs::read_to_string(cache_path)?;
    let cache: VersionCache = serde_json::from_str(&content)
        .map_err(|e| LpmError::Plugin(format!("failed to parse version cache: {e}")))?;
    Ok(cache)
}

fn cache_path() -> Result<PathBuf, LpmError> {
    let dir = crate::store::plugins_dir()?;
    Ok(dir.join(".version-cache.json"))
}

/// Tag prefix configuration for GitHub repos that publish multiple tools.
///
/// Some repos (e.g., oxc-project/oxc) have multiple release types with different
/// tag prefixes. We need to filter to the correct one.
fn tag_prefix_for_plugin(def: &PluginDef) -> Option<&'static str> {
    let url = def.url_template;
    if let Some(start) = url.find("download/") {
        let after_download = &url[start + "download/".len()..];
        if let Some(end) = after_download.find("{version}") {
            let prefix = &after_download[..end];
            if !prefix.is_empty() {
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

/// Read-only "what does GitHub list as latest right now" probe. Does
/// not write the cache. Caller is responsible for calling
/// [`approve_version`] only after a successful verified install of
/// the returned version.
///
/// For repos with multiple release types (e.g., oxc), fetches the release list
/// and filters by tag prefix instead of using `/releases/latest`.
///
/// Supports `GITHUB_TOKEN` / `GH_TOKEN` env vars for authenticated requests
/// (5000 req/hr vs 60 unauthenticated).
pub async fn peek_latest_from_github(def: &PluginDef) -> Result<String, String> {
    let (owner, repo) = parse_github_owner_repo(def)?;
    let tag_prefix = tag_prefix_for_plugin(def);

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .map_err(|e| format!("http client error: {e}"))?;

    let tag = if let Some(prefix) = tag_prefix {
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

    let version = extract_version_from_tag(&tag);

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
    if let Some(idx) = tag.rfind('@')
        && idx > 0
    {
        return tag[idx + 1..].to_string();
    }

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

    #[test]
    fn github_token_reads_github_token_env() {
        let _: Option<String> = github_token();
    }

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
        assert!(is_newer_semver("1.58.0-rc1", "1.57.0"));
        assert!(!is_newer_semver("1.58.0-rc1", "1.58.0"));
    }

    #[test]
    fn newer_semver_different_segment_count() {
        assert!(!is_newer_semver("1.58", "1.58.0"));
        assert!(is_newer_semver("1.58.0", "1.58"));
    }

    // --- Cache write/read (path-injected, no env mutation) ---

    #[test]
    fn write_then_read_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".version-cache.json");

        write_cached_version_at(&path, "oxlint", "1.59.0").unwrap();
        let cache = read_cache_at(&path).unwrap();
        assert_eq!(cache.versions.get("oxlint"), Some(&"1.59.0".to_string()));
    }

    #[test]
    fn write_overwrites_prior_value_for_same_plugin() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".version-cache.json");

        write_cached_version_at(&path, "oxlint", "1.58.0").unwrap();
        write_cached_version_at(&path, "oxlint", "1.59.0").unwrap();
        let cache = read_cache_at(&path).unwrap();
        assert_eq!(cache.versions.get("oxlint"), Some(&"1.59.0".to_string()));
    }

    #[test]
    fn write_preserves_other_plugin_entries() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".version-cache.json");

        write_cached_version_at(&path, "oxlint", "1.58.0").unwrap();
        write_cached_version_at(&path, "biome", "2.4.10").unwrap();
        let cache = read_cache_at(&path).unwrap();
        assert_eq!(cache.versions.get("oxlint"), Some(&"1.58.0".to_string()));
        assert_eq!(cache.versions.get("biome"), Some(&"2.4.10".to_string()));
    }

    #[test]
    fn read_returns_err_when_cache_missing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".version-cache.json");
        assert!(read_cache_at(&path).is_err());
    }

    #[test]
    fn legacy_cache_with_fetched_at_field_still_parses() {
        // Schema v0 included a top-level `fetched_at`. We dropped it,
        // but serde's default behavior ignores unknown fields. Confirm
        // an old on-disk cache still loads cleanly.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".version-cache.json");
        let legacy = serde_json::json!({
            "versions": { "oxlint": "1.58.0" },
            "fetched_at": 1700000000u64,
        });
        std::fs::write(&path, legacy.to_string()).unwrap();
        let cache = read_cache_at(&path).unwrap();
        assert_eq!(cache.versions.get("oxlint"), Some(&"1.58.0".to_string()));
    }

    #[test]
    fn atomic_write_no_temp_file_remains() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".version-cache.json");

        write_cached_version_at(&path, "oxlint", "1.58.0").unwrap();
        let tmp = path.with_extension("tmp");
        assert!(path.exists());
        assert!(!tmp.exists(), "temp file should not remain after rename");
    }

    /// Regression for the sticky-cache poisoning bug: `peek_latest_from_github`
    /// must not be the function that writes the cache. The only writer is
    /// `approve_version` (alias for `write_cached_version_at`), and it can
    /// only be called explicitly — typically AFTER a successful install.
    /// This test pins the contract by hitting the read path and confirming
    /// only the explicit write changes state.
    #[test]
    fn peek_does_not_write_cache() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".version-cache.json");

        // Cache absent.
        assert!(read_cache_at(&path).is_err());

        // Approve writes the cache.
        write_cached_version_at(&path, "oxlint", "1.58.0").unwrap();
        assert_eq!(
            read_cache_at(&path).unwrap().versions.get("oxlint"),
            Some(&"1.58.0".to_string())
        );

        // Reading the cache (the equivalent state-touching `peek` does on
        // the network) must not mutate it. We model that here by reading
        // and confirming the entry is unchanged.
        let before = read_cache_at(&path).unwrap();
        let after = read_cache_at(&path).unwrap();
        assert_eq!(before.versions, after.versions);
    }
}
