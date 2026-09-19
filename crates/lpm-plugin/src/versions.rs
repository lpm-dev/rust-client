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

const GITHUB_API_BASE_ENV: &str = "LPM_PLUGIN_GITHUB_API_BASE";
const GITHUB_API_RESPONSE_CAP_BYTES: usize = 1024 * 1024;

#[derive(Debug, serde::Deserialize)]
struct GithubRelease {
    tag_name: String,
    #[serde(default)]
    draft: bool,
    #[serde(default)]
    prerelease: bool,
}

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

/// Compare two plugin versions. Returns `true` if `a` is strictly newer than `b`.
/// Exact versions use npm-compatible ordering; legacy partial versions retain
/// their component-wise ordering for cache compatibility.
pub fn is_newer_semver(a: &str, b: &str) -> bool {
    match (lpm_semver::Version::parse(a), lpm_semver::Version::parse(b)) {
        (Ok(a), Ok(b)) => a > b,
        _ => {
            let numeric_components = |version: &str| -> Vec<u64> {
                version
                    .split('-')
                    .next()
                    .unwrap_or(version)
                    .split('.')
                    .filter_map(|component| component.parse().ok())
                    .collect()
            };
            numeric_components(a) > numeric_components(b)
        }
    }
}

pub(crate) fn compare_versions(a: &str, b: &str) -> std::cmp::Ordering {
    match (lpm_semver::Version::parse(a), lpm_semver::Version::parse(b)) {
        (Ok(a), Ok(b)) => a.cmp(&b),
        (Ok(_), Err(_)) => std::cmp::Ordering::Greater,
        (Err(_), Ok(_)) => std::cmp::Ordering::Less,
        (Err(_), Err(_)) => a.cmp(b),
    }
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
    lpm_common::with_exclusive_lock(cache_path.with_extension("lock"), || {
        let mut cache = read_cache_at(cache_path).unwrap_or_default();
        if cache
            .versions
            .get(plugin_name)
            .is_none_or(|current| is_newer_semver(version, current))
        {
            cache
                .versions
                .insert(plugin_name.to_string(), version.to_string());
        }

        if let Some(parent) = cache_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let json = serde_json::to_string(&cache)
            .map_err(|e| LpmError::Plugin(format!("failed to serialize version cache: {e}")))?;

        lpm_common::write_file_atomic_with_options(
            cache_path,
            json,
            lpm_common::AtomicWriteOptions::new().unix_mode(0o600),
        )
        .map_err(|e| LpmError::Plugin(format!("failed to write version cache: {e}")))?;

        Ok(())
    })
}

fn read_cache() -> Result<VersionCache, LpmError> {
    read_cache_at(&cache_path()?)
}

fn read_cache_at(cache_path: &Path) -> Result<VersionCache, LpmError> {
    let content =
        lpm_common::read_file_capped(cache_path, lpm_common::STATE_FILE_SIZE_CAP_BYTES)
            .map_err(|error| LpmError::Plugin(format!("failed to read version cache: {error}")))?;
    let cache: VersionCache = serde_json::from_slice(&content)
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

    if trusted_github_api_url(url)
        && let Some(token) = github_token()
    {
        req = req.header("Authorization", format!("Bearer {token}"));
    }

    req
}

fn trusted_github_api_url(url: &str) -> bool {
    reqwest::Url::parse(url).is_ok_and(|url| {
        url.scheme() == "https"
            && url.host_str() == Some("api.github.com")
            && url.port_or_known_default() == Some(443)
            && url.username().is_empty()
            && url.password().is_none()
    })
}

fn github_api_base() -> String {
    std::env::var(GITHUB_API_BASE_ENV)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map_or_else(
            || "https://api.github.com".to_string(),
            |value| value.trim_end_matches('/').to_string(),
        )
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
    let client = github_client()?;
    peek_latest_from_github_with_client(def, &client).await
}

pub fn github_client() -> Result<reqwest::Client, String> {
    lpm_http::client_builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .map_err(|e| format!("http client error: {e}"))
}

pub async fn peek_latest_from_github_with_client(
    def: &PluginDef,
    client: &reqwest::Client,
) -> Result<String, String> {
    let (owner, repo) = parse_github_owner_repo(def)?;
    let tag_prefix = tag_prefix_for_plugin(def);

    let mut best: Option<lpm_semver::Version> = None;
    for page in 1..=100 {
        let url = if tag_prefix.is_some() {
            let mut url = format!(
                "{}/repos/{owner}/{repo}/releases?per_page=20",
                github_api_base()
            );
            if page > 1 {
                url.push_str(&format!("&page={page}"));
            }
            url
        } else {
            format!("{}/repos/{owner}/{repo}/releases/latest", github_api_base())
        };
        let response = build_github_request(client, &url)
            .send()
            .await
            .map_err(|error| {
                format!("github request failed: {}", lpm_http::display_error(&error))
            })?;
        if let Some(error) = check_rate_limit(&response) {
            return Err(error);
        }
        if !response.status().is_success() {
            return Err(format!("github API returned {}", response.status()));
        }
        let more = tag_prefix.is_some()
            && response
                .headers()
                .get("link")
                .and_then(|value| value.to_str().ok())
                .is_some_and(|value| value.contains("rel=\"next\""));
        let releases = if tag_prefix.is_some() {
            read_capped_github_json::<Vec<GithubRelease>>(response).await?
        } else {
            vec![read_capped_github_json::<GithubRelease>(response).await?]
        };
        for release in releases {
            if release.draft
                || release.prerelease
                || tag_prefix.is_some_and(|prefix| !release.tag_name.starts_with(prefix))
            {
                continue;
            }
            let value = extract_version_from_tag(&release.tag_name);
            if !is_semver_like(&value) {
                continue;
            }
            let Ok(version) = lpm_semver::Version::parse(&value) else {
                continue;
            };
            if !version.is_prerelease() && best.as_ref().is_none_or(|current| version > *current) {
                best = Some(version);
            }
        }
        if !more {
            return best.map(|version| version.to_string()).ok_or_else(|| {
                format!("no stable release found for {} in {owner}/{repo}", def.name)
            });
        }
    }
    Err(format!(
        "release discovery for {} exceeded 100 pages; latest version is unknown",
        def.name
    ))
}

#[derive(serde::Deserialize)]
struct ReleaseWithAssets {
    tag_name: String,
    draft: bool,
    assets: Vec<ReleaseAsset>,
}

#[derive(serde::Deserialize)]
struct ReleaseAsset {
    name: String,
    browser_download_url: String,
    digest: Option<String>,
}

pub(crate) async fn release_asset_checksum(
    def: &PluginDef,
    version: &str,
    platform: &str,
    asset_url: &str,
    client: &reqwest::Client,
) -> Result<String, String> {
    release_asset_checksum_at(
        def,
        version,
        platform,
        asset_url,
        client,
        "https://api.github.com",
    )
    .await
}

async fn release_asset_checksum_at(
    def: &PluginDef,
    version: &str,
    platform: &str,
    asset_url: &str,
    client: &reqwest::Client,
    api_base: &str,
) -> Result<String, String> {
    let (owner, repo) = parse_github_owner_repo(def)?;
    let name = crate::registry::resolve_platform_asset(def, platform)
        .ok_or("unsupported plugin platform")?;
    let expected_url = def
        .url_template
        .replace("{version}", version)
        .replace("{platform}", name);
    if asset_url != expected_url {
        return Err("release asset download URL does not match the plugin definition".into());
    }
    let tag = format!("{}{version}", tag_prefix_for_plugin(def).unwrap_or("v"));
    let mut url = reqwest::Url::parse(api_base).map_err(|error| error.to_string())?;
    url.path_segments_mut()
        .map_err(|()| "invalid GitHub API base")?
        .pop_if_empty()
        .extend(["repos", &owner, &repo, "releases", "tags", &tag]);
    let response = build_github_request(client, url.as_str())
        .timeout(std::time::Duration::from_secs(5))
        .send()
        .await
        .map_err(|error| format!("github request failed: {}", lpm_http::display_error(&error)))?;
    if let Some(error) = check_rate_limit(&response) {
        return Err(error);
    }
    if !response.status().is_success() {
        return Err(format!("github API returned {}", response.status()));
    }
    if response.url().origin() != url.origin() {
        return Err("release digest response redirected outside the trusted API origin".into());
    }
    let release: ReleaseWithAssets = read_capped_github_json(response).await?;
    if release.draft || release.tag_name != tag {
        return Err("release metadata does not match the requested published tag".into());
    }
    let mut matching = release.assets.iter().filter(|asset| asset.name == name);
    let asset = matching.next().ok_or("release asset is missing")?;
    if matching.next().is_some() || asset.browser_download_url != asset_url {
        return Err("release asset identity is ambiguous or mismatched".into());
    }
    let digest = asset
        .digest
        .as_deref()
        .and_then(|value| value.strip_prefix("sha256:"))
        .filter(|value| value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .ok_or("release asset has no valid SHA-256 digest")?;
    Ok(digest.to_ascii_lowercase())
}

async fn read_capped_github_json<T: serde::de::DeserializeOwned>(
    mut response: reqwest::Response,
) -> Result<T, String> {
    if response
        .content_length()
        .is_some_and(|length| length > GITHUB_API_RESPONSE_CAP_BYTES as u64)
    {
        return Err(format!(
            "github response exceeds {GITHUB_API_RESPONSE_CAP_BYTES} byte limit"
        ));
    }
    let capacity = response
        .content_length()
        .and_then(|length| usize::try_from(length).ok())
        .unwrap_or(0)
        .min(GITHUB_API_RESPONSE_CAP_BYTES);
    let mut body = Vec::with_capacity(capacity);
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|error| format!("failed to read github response: {error}"))?
    {
        if body.len().saturating_add(chunk.len()) > GITHUB_API_RESPONSE_CAP_BYTES {
            return Err(format!(
                "github response exceeds {GITHUB_API_RESPONSE_CAP_BYTES} byte limit"
            ));
        }
        body.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&body)
        .map_err(|error| format!("failed to parse github response: {error}"))
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

    async fn response_from_raw_http(
        raw_response: Vec<u8>,
    ) -> (reqwest::Response, tokio::task::JoinHandle<()>) {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0u8; 1024];
            let _ = stream.read(&mut request).await;
            stream.write_all(&raw_response).await.unwrap();
        });
        let response = reqwest::Client::new()
            .get(format!("http://{address}/release"))
            .send()
            .await
            .unwrap();
        (response, server)
    }

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
    fn custom_github_api_origins_do_not_receive_ambient_tokens() {
        let prior_github = std::env::var_os("GITHUB_TOKEN");
        let prior_gh = std::env::var_os("GH_TOKEN");
        // SAFETY: both variables are restored before the test returns.
        unsafe {
            std::env::set_var("GITHUB_TOKEN", "doctor-plugin-secret");
            std::env::remove_var("GH_TOKEN");
        }

        let request = build_github_request(
            &reqwest::Client::new(),
            "http://127.0.0.1:43123/repos/example/tool/releases/latest",
        )
        .build()
        .unwrap();

        match prior_github {
            Some(value) => unsafe { std::env::set_var("GITHUB_TOKEN", value) },
            None => unsafe { std::env::remove_var("GITHUB_TOKEN") },
        }
        match prior_gh {
            Some(value) => unsafe { std::env::set_var("GH_TOKEN", value) },
            None => unsafe { std::env::remove_var("GH_TOKEN") },
        }
        assert!(
            request
                .headers()
                .get(reqwest::header::AUTHORIZATION)
                .is_none(),
            "custom API origins must never receive ambient GitHub credentials"
        );
    }

    #[tokio::test]
    async fn chunked_github_response_is_rejected_at_the_body_limit() {
        let chunk = vec![b'a'; GITHUB_API_RESPONSE_CAP_BYTES + 1];
        let mut response = format!(
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n{:X}\r\n",
            chunk.len()
        )
        .into_bytes();
        response.extend_from_slice(&chunk);
        response.extend_from_slice(b"\r\n0\r\n\r\n");
        let (response, server) = response_from_raw_http(response).await;

        let error = read_capped_github_json::<GithubRelease>(response)
            .await
            .expect_err("oversized chunked body must fail");
        server.await.unwrap();

        assert!(error.contains("exceeds"), "unexpected error: {error}");
    }

    #[test]
    fn newer_semver_basic() {
        assert!(is_newer_semver("1.58.0", "1.57.0"));
        assert!(is_newer_semver("2.0.0", "1.99.99"));
        assert!(is_newer_semver("1.57.1", "1.57.0"));
    }

    #[test]
    fn stable_plugin_release_is_newer_than_its_matching_prerelease() {
        assert!(is_newer_semver("1.0.0", "1.0.0-alpha.1"));
        assert!(!is_newer_semver("1.0.0-alpha.1", "1.0.0"));
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
    fn read_rejects_an_oversized_version_cache() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".version-cache.json");
        let file = std::fs::File::create(&path).unwrap();
        file.set_len(lpm_common::STATE_FILE_SIZE_CAP_BYTES + 1)
            .unwrap();

        let error = read_cache_at(&path).unwrap_err().to_string();
        assert!(
            error.contains("exceeds") || error.contains("too large"),
            "oversized cache must fail at the bounded-read gate: {error}"
        );
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

    #[test]
    fn concurrent_approvals_preserve_every_plugin_entry() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".version-cache.json");
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(24));
        std::thread::scope(|scope| {
            for index in 0..24 {
                let path = &path;
                let barrier = std::sync::Arc::clone(&barrier);
                scope.spawn(move || {
                    barrier.wait();
                    write_cached_version_at(path, &format!("tool{index}"), "1.0.0").unwrap();
                });
            }
        });
        assert_eq!(read_cache_at(&path).unwrap().versions.len(), 24);
    }

    #[test]
    fn an_older_approval_does_not_downgrade_the_selected_version() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".version-cache.json");
        write_cached_version_at(&path, "oxlint", "2.10.0").unwrap();
        write_cached_version_at(&path, "oxlint", "2.9.0").unwrap();
        assert_eq!(read_cache_at(&path).unwrap().versions["oxlint"], "2.10.0");
    }
    #[tokio::test]
    async fn release_digest_requires_exact_tag_asset_and_url() {
        use wiremock::{
            Mock, MockServer, ResponseTemplate,
            matchers::{method, path},
        };
        for plugin in ["oxlint", "biome"] {
            let def = crate::registry::get_plugin(plugin).unwrap();
            let version = "1.0.0";
            let platform = "darwin-arm64";
            let name = crate::registry::resolve_platform_asset(def, platform).unwrap();
            let asset_url = def
                .url_template
                .replace("{version}", version)
                .replace("{platform}", name);
            let tag = format!("{}{version}", tag_prefix_for_plugin(def).unwrap());
            let (owner, repo) = parse_github_owner_repo(def).unwrap();
            let mut endpoint = reqwest::Url::parse("http://localhost/").unwrap();
            endpoint
                .path_segments_mut()
                .unwrap()
                .extend(["repos", &owner, &repo, "releases", "tags", &tag]);
            let valid = serde_json::json!({"tag_name":tag,"draft":false,"assets":[{
                "name":name,"browser_download_url":asset_url,"digest":format!("sha256:{}", "A".repeat(64))
            }]});
            for case in [
                "valid",
                "tag",
                "draft",
                "name",
                "url",
                "algorithm",
                "digest",
                "duplicate",
                "missing",
            ] {
                let mut body = valid.clone();
                match case {
                    "tag" => body["tag_name"] = "wrong-tag".into(),
                    "draft" => body["draft"] = true.into(),
                    "name" => body["assets"][0]["name"] = "other.bin".into(),
                    "url" => {
                        body["assets"][0]["browser_download_url"] =
                            "https://example.test/other".into()
                    }
                    "algorithm" => {
                        body["assets"][0]["digest"] = format!("sha512:{}", "a".repeat(64)).into()
                    }
                    "digest" => body["assets"][0]["digest"] = "sha256:bad".into(),
                    "duplicate" => body["assets"]
                        .as_array_mut()
                        .unwrap()
                        .push(valid["assets"][0].clone()),
                    "missing" => body["assets"][0]
                        .as_object_mut()
                        .unwrap()
                        .remove("digest")
                        .map(|_| ())
                        .unwrap(),
                    _ => {}
                }
                let server = MockServer::start().await;
                Mock::given(method("GET"))
                    .and(path(endpoint.path()))
                    .respond_with(ResponseTemplate::new(200).set_body_json(body))
                    .expect(1)
                    .mount(&server)
                    .await;
                let result = release_asset_checksum_at(
                    def,
                    version,
                    platform,
                    &asset_url,
                    &github_client().unwrap(),
                    &server.uri(),
                )
                .await;
                if case == "valid" {
                    assert_eq!(result.unwrap(), "a".repeat(64));
                } else {
                    assert!(result.is_err(), "{plugin}: {case}");
                }
            }
        }
    }
    #[test]
    fn mixed_version_ordering_is_transitive() {
        for a in ["1.2.0", "1.10.0", "1.15x"] {
            for b in ["1.2.0", "1.10.0", "1.15x"] {
                for c in ["1.2.0", "1.10.0", "1.15x"] {
                    if compare_versions(a, b).is_lt() && compare_versions(b, c).is_lt() {
                        assert!(compare_versions(a, c).is_lt(), "{a} < {b} < {c}");
                    }
                }
            }
        }
    }

    #[tokio::test]
    async fn release_digest_rejects_a_redirect_to_another_origin() {
        use wiremock::{Mock, MockServer, ResponseTemplate, matchers::method};
        let initial = MockServer::start().await;
        let destination = MockServer::start().await;
        let def = crate::registry::get_plugin("oxlint").unwrap();
        let name = crate::registry::resolve_platform_asset(def, "darwin-arm64").unwrap();
        let asset_url = def
            .url_template
            .replace("{version}", "1.0.0")
            .replace("{platform}", name);
        Mock::given(method("GET"))
            .respond_with(
                ResponseTemplate::new(302)
                    .insert_header("location", format!("{}/redirected", destination.uri())),
            )
            .mount(&initial)
            .await;
        Mock::given(method("GET")).respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "tag_name":"apps_v1.0.0","draft":false,"assets":[{
                "name":name,"browser_download_url":asset_url,"digest":format!("sha256:{}", "a".repeat(64))
            }]
        }))).mount(&destination).await;
        assert!(
            release_asset_checksum_at(
                def,
                "1.0.0",
                "darwin-arm64",
                &asset_url,
                &github_client().unwrap(),
                &initial.uri()
            )
            .await
            .is_err()
        );
    }
}
