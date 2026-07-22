//! Bun runtime management — GitHub release fetching, version resolution, install paths.

use crate::download;
use crate::node;
use crate::platform::Platform;
use lpm_common::LpmError;
use serde::Deserialize;
use std::path::PathBuf;

const BUN_RELEASES_URL: &str = "https://api.github.com/repos/oven-sh/bun/releases?per_page=100";
const GITHUB_API_VERSION: &str = "2022-11-28";
const USER_AGENT: &str = "lpm-runtime";

/// A single Bun release from GitHub.
#[derive(Debug, Clone, Deserialize)]
pub struct BunRelease {
    /// Release tag, usually `bun-v1.3.14`.
    pub tag_name: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub draft: bool,
    #[serde(default)]
    pub prerelease: bool,
    #[serde(default)]
    pub assets: Vec<BunAsset>,
}

/// A downloadable asset on a Bun GitHub release.
#[derive(Debug, Clone, Deserialize)]
pub struct BunAsset {
    pub name: String,
    pub browser_download_url: String,
    #[serde(default)]
    pub digest: Option<String>,
}

impl BunRelease {
    /// Version without Bun's release-tag prefix.
    pub fn version_bare(&self) -> &str {
        normalize_bun_version_label(&self.tag_name)
    }

    /// Download URL for the release-level SHASUMS file, if present.
    pub fn shasums_url(&self) -> Option<&str> {
        self.assets
            .iter()
            .find(|asset| asset.name == "SHASUMS256.txt")
            .map(|asset| asset.browser_download_url.as_str())
    }

    /// Select the Bun zip for the current host platform.
    pub fn asset_for_platform(&self, platform: &Platform) -> Option<BunAsset> {
        let expected = format!("bun-{}.zip", platform.bun_suffix());
        self.assets
            .iter()
            .find(|asset| asset.name == expected)
            .cloned()
    }
}

/// Directory for a specific installed Bun version.
pub fn bun_version_dir(version: &str) -> Result<PathBuf, LpmError> {
    Ok(node::runtimes_dir()?.join("bun").join(version))
}

/// Path to the `bun` binary for a specific installed version.
pub fn bun_binary_path(version: &str) -> Result<PathBuf, LpmError> {
    let binary = if cfg!(windows) { "bun.exe" } else { "bun" };
    Ok(bun_bin_dir(version)?.join(binary))
}

/// Path to the `bin/` directory for a specific installed version.
pub fn bun_bin_dir(version: &str) -> Result<PathBuf, LpmError> {
    Ok(bun_version_dir(version)?.join("bin"))
}

/// Check if a Bun version is installed.
pub fn is_installed(version: &str) -> bool {
    bun_binary_path(version).is_ok_and(|path| path.exists())
}

/// List all installed Bun versions.
pub fn list_installed() -> Result<Vec<String>, LpmError> {
    let bun_dir = node::runtimes_dir()?.join("bun");
    if !bun_dir.exists() {
        return Ok(Vec::new());
    }

    let mut versions = Vec::new();
    for entry in std::fs::read_dir(&bun_dir)? {
        let entry = entry?;
        if entry.path().is_dir() {
            let name = entry.file_name().to_string_lossy().to_string();
            if is_installed(&name) {
                versions.push(name);
            }
        }
    }

    versions.sort_by(|a, b| node::compare_versions(b, a));
    Ok(versions)
}

/// Fetch Bun releases from GitHub.
///
/// Caches to `~/.lpm/runtimes/bun-index-cache.json` with a 1-hour TTL.
pub async fn fetch_releases(client: &reqwest::Client) -> Result<Vec<BunRelease>, LpmError> {
    let cache_path = node::runtimes_dir()?.join("bun-index-cache.json");

    if let Ok(meta) = std::fs::metadata(&cache_path)
        && let Ok(modified) = meta.modified()
    {
        let age = std::time::SystemTime::now()
            .duration_since(modified)
            .unwrap_or_default();
        if age.as_secs() < 3600
            && let Ok(Some(content)) = lpm_common::read_capped_state_file(
                &cache_path,
                lpm_common::STATE_FILE_SIZE_CAP_BYTES,
            )
            && let Ok(releases) = serde_json::from_slice::<Vec<BunRelease>>(&content)
        {
            tracing::debug!(
                "using cached bun release index ({} releases)",
                releases.len()
            );
            return Ok(releases);
        }
    }

    tracing::debug!("fetching bun release index");
    let resp = client
        .get(BUN_RELEASES_URL)
        .header(reqwest::header::USER_AGENT, USER_AGENT)
        .header(reqwest::header::ACCEPT, "application/vnd.github+json")
        .header("X-GitHub-Api-Version", GITHUB_API_VERSION)
        .send()
        .await
        .map_err(|e| {
            LpmError::Network(format!(
                "failed to fetch bun releases: {}",
                lpm_http::display_error(&e)
            ))
        })?;

    if !resp.status().is_success() {
        return Err(LpmError::Http {
            status: resp.status().as_u16(),
            message: "failed to fetch Bun releases from GitHub".into(),
        });
    }

    let body = resp
        .text()
        .await
        .map_err(|e| LpmError::Network(format!("failed to read bun releases body: {e}")))?;

    let mut releases: Vec<BunRelease> = serde_json::from_str(&body)
        .map_err(|e| LpmError::Script(format!("failed to parse Bun releases: {e}")))?;
    releases.sort_by(|a, b| node::compare_versions(b.version_bare(), a.version_bare()));

    if let Some(parent) = cache_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let temp_cache = cache_path.with_extension("json.tmp");
    if download::write_restricted_file(&temp_cache, body.as_bytes()).is_ok() {
        let _ = std::fs::rename(&temp_cache, &cache_path);
    }

    Ok(releases)
}

/// Validate a Bun version spec string against injection attacks.
pub fn validate_version_spec(spec: &str) -> Result<(), LpmError> {
    node::validate_version_spec(spec)?;
    let normalized = normalize_spec(spec);
    if normalized.eq_ignore_ascii_case("lts") {
        return Err(LpmError::Script(
            "Bun does not publish an LTS channel; use bun@latest or bun@<version>".into(),
        ));
    }
    Ok(())
}

/// Resolve a Bun version spec to an exact GitHub release.
pub fn resolve_version(
    releases: &[BunRelease],
    spec: &str,
) -> Result<Option<BunRelease>, LpmError> {
    validate_version_spec(spec)?;
    let spec = normalize_spec(spec);
    let candidates: Vec<&BunRelease> = releases
        .iter()
        .filter(|release| !release.draft && !release.prerelease)
        .collect();

    if spec.eq_ignore_ascii_case("latest") {
        return Ok(candidates.into_iter().next().cloned());
    }

    if let Some(release) = candidates
        .iter()
        .copied()
        .find(|release| release.version_bare() == spec)
    {
        return Ok(Some(release.clone()));
    }

    if is_range_spec(&spec) {
        let req = lpm_semver::VersionReq::parse(&spec)
            .map_err(|e| LpmError::Script(format!("invalid Bun version range '{spec}': {e}")))?;
        return Ok(best_release_match(candidates, |release| {
            lpm_semver::Version::parse(release.version_bare())
                .ok()
                .is_some_and(|version| req.matches(&version))
        }));
    }

    if lpm_semver::Version::parse(&spec).is_ok() {
        return Ok(None);
    }

    let prefix = format!("{spec}.");
    Ok(best_release_match(candidates, |release| {
        release.version_bare().starts_with(&prefix) || release.version_bare() == spec
    }))
}

/// Find the best matching installed Bun version for a version spec.
pub fn find_matching_installed(spec: &str, installed: &[String]) -> Option<String> {
    let normalized = normalize_spec(spec);

    if normalized.eq_ignore_ascii_case("lts") {
        return None;
    }

    if normalized.eq_ignore_ascii_case("latest") {
        let mut versions: Vec<String> = installed.to_vec();
        versions.sort_by(|a, b| node::compare_versions(b, a));
        return versions.into_iter().next();
    }

    if let Some(version) = installed
        .iter()
        .find(|version| version.as_str() == normalized)
    {
        return Some(version.clone());
    }

    if is_range_spec(&normalized) {
        let req = lpm_semver::VersionReq::parse(&normalized).ok()?;
        let mut matches: Vec<&String> = installed
            .iter()
            .filter(|version| {
                lpm_semver::Version::parse(version)
                    .ok()
                    .is_some_and(|parsed| req.matches(&parsed))
            })
            .collect();
        matches.sort_by(|a, b| node::compare_versions(b, a));
        return matches.first().map(|version| (*version).clone());
    }

    if lpm_semver::Version::parse(&normalized).is_ok() {
        return None;
    }

    let prefix = format!("{normalized}.");
    let mut matches: Vec<&String> = installed
        .iter()
        .filter(|version| version.starts_with(&prefix) || version.as_str() == normalized)
        .collect();
    matches.sort_by(|a, b| node::compare_versions(b, a));
    matches.first().map(|version| (*version).clone())
}

/// Remove an installed Bun version.
pub fn uninstall(version: &str) -> Result<(), LpmError> {
    let dir = bun_version_dir(version)?;
    if dir.exists() {
        std::fs::remove_dir_all(&dir)?;
    }
    Ok(())
}

fn best_release_match<F>(candidates: Vec<&BunRelease>, matches: F) -> Option<BunRelease>
where
    F: Fn(&BunRelease) -> bool,
{
    candidates
        .into_iter()
        .filter(|release| matches(release))
        .max_by(|a, b| node::compare_versions(a.version_bare(), b.version_bare()))
        .cloned()
}

pub fn normalize_spec(spec: &str) -> String {
    normalize_bun_version_label(spec.trim()).to_string()
}

fn normalize_bun_version_label(label: &str) -> &str {
    label
        .strip_prefix("bun-v")
        .or_else(|| label.strip_prefix('v'))
        .unwrap_or(label)
}

fn is_range_spec(spec: &str) -> bool {
    spec.contains('>')
        || spec.contains('<')
        || spec.contains('^')
        || spec.contains('~')
        || spec.contains('|')
        || spec.contains('*')
        || spec.split_whitespace().count() > 1
}

#[cfg(test)]
mod tests {
    use super::*;

    fn asset(name: &str) -> BunAsset {
        BunAsset {
            name: name.into(),
            browser_download_url: format!("https://example.test/{name}"),
            digest: Some("sha256:abc".into()),
        }
    }

    fn release(version: &str) -> BunRelease {
        BunRelease {
            tag_name: format!("bun-v{version}"),
            name: Some(format!("Bun {version}")),
            draft: false,
            prerelease: false,
            assets: vec![
                asset("bun-darwin-aarch64.zip"),
                asset("bun-linux-x64.zip"),
                asset("bun-linux-x64-baseline.zip"),
                asset("bun-linux-x64-musl.zip"),
                asset("bun-linux-x64-musl-baseline.zip"),
                asset("SHASUMS256.txt"),
            ],
        }
    }

    #[test]
    fn version_bare_strips_bun_tag_prefixes() {
        assert_eq!(release("1.3.14").version_bare(), "1.3.14");
        let mut prefixed = release("1.3.14");
        prefixed.tag_name = "v1.3.14".into();
        assert_eq!(prefixed.version_bare(), "1.3.14");
    }

    #[test]
    fn resolve_version_accepts_exact_prefixed_and_latest_specs() {
        let releases = vec![release("1.3.14"), release("1.2.23")];

        assert_eq!(
            resolve_version(&releases, "1.3.14")
                .unwrap()
                .unwrap()
                .version_bare(),
            "1.3.14"
        );
        assert_eq!(
            resolve_version(&releases, "bun-v1.2.23")
                .unwrap()
                .unwrap()
                .version_bare(),
            "1.2.23"
        );
        assert_eq!(
            resolve_version(&releases, "latest")
                .unwrap()
                .unwrap()
                .version_bare(),
            "1.3.14"
        );
    }

    #[test]
    fn resolve_version_accepts_prefixes_and_ranges() {
        let releases = vec![release("1.3.14"), release("1.3.9"), release("1.2.23")];

        assert_eq!(
            resolve_version(&releases, "1.3")
                .unwrap()
                .unwrap()
                .version_bare(),
            "1.3.14"
        );
        assert_eq!(
            resolve_version(&releases, ">=1.2.0 <1.3.0")
                .unwrap()
                .unwrap()
                .version_bare(),
            "1.2.23"
        );
    }

    #[test]
    fn resolve_version_rejects_lts_with_clear_error() {
        let err = resolve_version(&[release("1.3.14")], "lts").unwrap_err();
        assert!(
            err.to_string()
                .contains("Bun does not publish an LTS channel"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn find_matching_installed_handles_latest_prefix_and_ranges() {
        let installed = vec![
            "1.3.14".to_string(),
            "1.3.9".to_string(),
            "1.2.23".to_string(),
        ];

        assert_eq!(
            find_matching_installed("latest", &installed),
            Some("1.3.14".into())
        );
        assert_eq!(
            find_matching_installed("bun-v1.3", &installed),
            Some("1.3.14".into())
        );
        assert_eq!(
            find_matching_installed(">=1.2.0 <1.3.0", &installed),
            Some("1.2.23".into())
        );
    }

    #[test]
    fn asset_for_platform_uses_installer_compatible_target_name() {
        let release = release("1.3.14");
        let platform = Platform {
            os: "linux",
            arch: "x64",
        };

        let asset = release.asset_for_platform(&platform).unwrap();
        assert!(
            asset.name == "bun-linux-x64-musl-baseline.zip"
                || asset.name == "bun-linux-x64-musl.zip"
                || asset.name == "bun-linux-x64-baseline.zip"
                || asset.name == "bun-linux-x64.zip",
            "platform-specific host features choose one linux-x64 asset, got {}",
            asset.name
        );
    }
}
