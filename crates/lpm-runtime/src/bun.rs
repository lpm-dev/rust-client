//! Bun runtime management — GitHub release fetching, version resolution, install paths.

use crate::download;
use crate::node;
use crate::platform::Platform;
use lpm_common::LpmError;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

const BUN_RELEASES_URL: &str = "https://api.github.com/repos/oven-sh/bun/releases?per_page=100";
const GITHUB_API_VERSION: &str = "2022-11-28";
const USER_AGENT: &str = "lpm-runtime";

/// A single Bun release from GitHub.
#[derive(Debug, Clone, Deserialize, Serialize)]
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
#[derive(Debug, Clone, Deserialize, Serialize)]
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
            .find(|asset| {
                asset.name == "SHASUMS256.txt"
                    && is_allowed_bun_download_url(&asset.browser_download_url)
            })
            .map(|asset| asset.browser_download_url.as_str())
    }

    /// Select the Bun zip for the current host platform.
    pub fn asset_for_platform(&self, platform: &Platform) -> Option<BunAsset> {
        let expected = format!("bun-{}.zip", platform.bun_suffix());
        self.assets
            .iter()
            .find(|asset| {
                asset.name == expected && is_allowed_bun_download_url(&asset.browser_download_url)
            })
            .cloned()
    }
}

fn is_allowed_bun_download_url(raw: &str) -> bool {
    let Ok(url) = reqwest::Url::parse(raw) else {
        return false;
    };
    if !url.username().is_empty() || url.password().is_some() {
        return false;
    }
    let loopback = url.host_str().is_some_and(|host| {
        host.eq_ignore_ascii_case("localhost")
            || host
                .parse::<std::net::IpAddr>()
                .is_ok_and(|address| address.is_loopback())
    });
    if loopback {
        return matches!(url.scheme(), "http" | "https");
    }
    url.scheme() == "https"
        && url
            .host_str()
            .is_some_and(|host| host.eq_ignore_ascii_case("github.com"))
        && url.path().starts_with("/oven-sh/bun/releases/download/")
}

/// Directory for a specific installed Bun version.
pub fn bun_version_dir(version: &str) -> Result<PathBuf, LpmError> {
    node::validate_exact_version(version)?;
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
    bun_binary_path(version).is_ok_and(|path| node::is_executable_file(&path))
}

/// List all installed Bun versions.
pub fn list_installed() -> Result<Vec<String>, LpmError> {
    let bun_dir = node::runtimes_dir()?.join("bun");
    let entries = match std::fs::read_dir(&bun_dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error.into()),
    };

    let mut versions = Vec::new();
    let mut binary_path = PathBuf::with_capacity(bun_dir.as_os_str().len() + 64);
    for entry in entries {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let name = entry.file_name();
        let Some(version) = name.to_str() else {
            continue;
        };
        if node::validate_exact_version(version).is_err() {
            continue;
        }
        binary_path.clear();
        binary_path.push(&bun_dir);
        binary_path.push(&name);
        binary_path.push("bin");
        binary_path.push(if cfg!(windows) { "bun.exe" } else { "bun" });
        if node::is_executable_file(&binary_path) {
            versions.push(version.to_string());
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
    fetch_releases_at(client, &cache_path, BUN_RELEASES_URL).await
}

#[derive(Deserialize, Serialize)]
struct ReleaseIndex {
    schema_version: u32,
    releases: Vec<BunRelease>,
}

fn cached_releases(bytes: &[u8]) -> Option<Vec<BunRelease>> {
    if let Ok(index) = serde_json::from_slice::<ReleaseIndex>(bytes) {
        return (index.schema_version == 1).then_some(index.releases);
    }
    // Older caches contain only page one. A short page proves completeness.
    let releases = serde_json::from_slice::<Vec<BunRelease>>(bytes).ok()?;
    (releases.len() < 100).then_some(releases)
}

async fn fetch_releases_at(
    client: &reqwest::Client,
    cache_path: &std::path::Path,
    endpoint: &str,
) -> Result<Vec<BunRelease>, LpmError> {
    if let Ok(meta) = std::fs::metadata(cache_path)
        && let Ok(modified) = meta.modified()
        && std::time::SystemTime::now()
            .duration_since(modified)
            .unwrap_or_default()
            .as_secs()
            < 3600
        && let Ok(Some(content)) =
            lpm_common::read_capped_state_file(cache_path, lpm_common::STATE_FILE_SIZE_CAP_BYTES)
        && let Some(releases) = cached_releases(&content)
    {
        return Ok(releases);
    }

    let mut releases = Vec::new();
    let mut remaining_bytes = lpm_common::STATE_FILE_SIZE_CAP_BYTES as usize;
    for page in 1..=100 {
        let mut url = reqwest::Url::parse(endpoint)
            .map_err(|e| LpmError::Network(format!("invalid Bun releases URL: {e}")))?;
        url.set_query(None);
        url.query_pairs_mut()
            .append_pair("per_page", "100")
            .append_pair("page", &page.to_string());
        let resp = client
            .get(url)
            .header(reqwest::header::USER_AGENT, USER_AGENT)
            .header(reqwest::header::ACCEPT, "application/vnd.github+json")
            .header("X-GitHub-Api-Version", GITHUB_API_VERSION)
            .send()
            .await
            .map_err(|e| {
                LpmError::Network(format!(
                    "failed to fetch Bun releases: {}",
                    lpm_http::display_error(&e)
                ))
            })?;
        if !resp.status().is_success() {
            return Err(LpmError::Http {
                status: resp.status().as_u16(),
                message: "failed to fetch Bun releases from GitHub".into(),
            });
        }
        let body = lpm_http::read_body_capped(resp, remaining_bytes)
            .await
            .map_err(|e| LpmError::Network(format!("failed to read Bun release index: {e}")))?;
        remaining_bytes = remaining_bytes.saturating_sub(body.len());
        let mut batch: Vec<BunRelease> = serde_json::from_slice(&body)
            .map_err(|e| LpmError::Script(format!("failed to parse Bun releases: {e}")))?;
        if batch.len() > 100 {
            return Err(LpmError::Network(
                "Bun release page exceeds 100 entries".into(),
            ));
        }
        let complete = batch.len() < 100;
        releases.append(&mut batch);
        if complete {
            let index = ReleaseIndex {
                schema_version: 1,
                releases,
            };
            let bytes = serde_json::to_vec(&index).map_err(|e| {
                LpmError::Script(format!("failed to encode Bun release cache: {e}"))
            })?;
            if bytes.len() <= lpm_common::STATE_FILE_SIZE_CAP_BYTES as usize {
                if let Some(parent) = cache_path.parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                let _ = download::write_restricted_file(cache_path, &bytes);
            }
            return Ok(index.releases);
        }
    }
    Err(LpmError::Network(
        "Bun release index exceeds the 100-page coverage limit".into(),
    ))
}

/// Validate an explicit Bun selector. Bun has no LTS channel.
pub fn validate_version_spec(spec: &str) -> Result<(), LpmError> {
    let normalized = normalize_spec(spec);
    if node::is_channel_spec(normalized) && !normalized.eq_ignore_ascii_case("latest") {
        return Err(LpmError::Script(
            "Bun does not publish an LTS channel; use bun@latest or bun@<version>".into(),
        ));
    }
    node::validate_version_spec(normalized)
}

/// Resolve the highest stable Bun release that satisfies the selector.
pub fn resolve_version(
    releases: &[BunRelease],
    spec: &str,
) -> Result<Option<BunRelease>, LpmError> {
    validate_version_spec(spec)?;
    let spec = normalize_spec(spec);
    let range = if spec.eq_ignore_ascii_case("latest") {
        None
    } else {
        Some(lpm_semver::StrictVersionReq::parse(spec)?)
    };
    Ok(releases
        .iter()
        .filter_map(|release| {
            if release.draft || release.prerelease {
                return None;
            }
            let version = lpm_semver::Version::parse(release.version_bare()).ok()?;
            if !version.pre_release().is_empty()
                || range.as_ref().is_some_and(|range| !range.matches(&version))
            {
                return None;
            }
            Some((release, version))
        })
        .max_by(|(_, a), (_, b)| a.cmp(b))
        .map(|(release, _)| release.clone()))
}

/// Find the highest matching installed Bun version.
pub fn find_matching_installed(spec: &str, installed: &[String]) -> Option<String> {
    let normalized = normalize_spec(spec);
    let selector = if normalized.eq_ignore_ascii_case("latest") {
        "*"
    } else {
        normalized
    };
    node::find_matching_installed(selector, installed)
}

/// Remove an installed Bun version.
pub fn uninstall(version: &str) -> Result<(), LpmError> {
    let dir = bun_version_dir(version)?;
    let _lock =
        lpm_common::acquire_single_file_exclusive_lock(download::runtime_install_lock_path(&dir)?)?;
    if dir.exists() {
        std::fs::remove_dir_all(&dir)?;
    }
    Ok(())
}

pub fn normalize_spec(spec: &str) -> &str {
    normalize_bun_version_label(spec.trim())
}

fn normalize_bun_version_label(label: &str) -> &str {
    label
        .strip_prefix("bun-v")
        .or_else(|| label.strip_prefix('v'))
        .unwrap_or(label)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bun_latest_is_the_semantic_maximum_of_an_unordered_index() {
        let releases = vec![release("1.2.0"), release("1.3.14"), release("1.3.9")];
        assert_eq!(
            resolve_version(&releases, "latest")
                .unwrap()
                .unwrap()
                .version_bare(),
            "1.3.14"
        );
    }

    #[test]
    fn bun_installed_selectors_include_equals_and_wildcards() {
        for spec in ["=1.3.14", "1.x", "1.X"] {
            assert_eq!(
                find_matching_installed(spec, &["1.2.0".into(), "1.3.14".into()]),
                Some("1.3.14".into()),
                "{spec}"
            );
        }
    }

    fn asset(name: &str) -> BunAsset {
        BunAsset {
            name: name.into(),
            browser_download_url: format!(
                "https://github.com/oven-sh/bun/releases/download/bun-v1.3.14/{name}"
            ),
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
    fn resolve_version_rejects_remote_release_with_path_like_version() {
        let releases = vec![release("../../outside")];

        assert!(resolve_version(&releases, "latest").unwrap().is_none());
    }

    #[test]
    fn bun_version_dir_rejects_non_semver_path_component() {
        let error = bun_version_dir("../outside").expect_err("path-like version must be rejected");

        assert!(error.to_string().contains("runtime version"));
    }

    #[test]
    fn release_selection_rejects_assets_outside_the_official_download_origin() {
        let platform = Platform::current().unwrap();
        let expected = format!("bun-{}.zip", platform.bun_suffix());
        let mut release = release("1.3.14");
        release.assets = vec![BunAsset {
            name: expected,
            browser_download_url: "https://attacker.example/bun.zip".into(),
            digest: Some(
                "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".into(),
            ),
        }];

        assert!(release.asset_for_platform(&platform).is_none());
    }

    #[test]
    fn release_selection_rejects_cleartext_asset_urls() {
        let platform = Platform::current().unwrap();
        let expected = format!("bun-{}.zip", platform.bun_suffix());
        let mut release = release("1.3.14");
        release.assets = vec![BunAsset {
            name: expected,
            browser_download_url:
                "http://github.com/oven-sh/bun/releases/download/bun-v1.3.14/bun.zip".into(),
            digest: Some(
                "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".into(),
            ),
        }];

        assert!(release.asset_for_platform(&platform).is_none());
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

#[cfg(test)]
mod release_index_tests {
    use super::*;
    use wiremock::matchers::{method, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn bun_discovery_includes_versions_after_the_first_hundred_releases() {
        let server = MockServer::start().await;
        let first: Vec<_> = (0..100)
            .map(|i| serde_json::json!({"tag_name":format!("bun-v2.0.{i}")}))
            .collect();
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_json(first))
            .with_priority(10)
            .mount(&server)
            .await;
        Mock::given(query_param("page", "2"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!([{"tag_name":"bun-v1.3.14"}])),
            )
            .mount(&server)
            .await;
        let root = tempfile::tempdir().unwrap();
        let cache = root.path().join("cache.json");
        let releases = fetch_releases_at(&reqwest::Client::new(), &cache, &server.uri())
            .await
            .unwrap();
        assert!(releases.iter().any(|r| r.version_bare() == "1.3.14"));
        let cached = fetch_releases_at(&reqwest::Client::new(), &cache, &server.uri())
            .await
            .unwrap();
        assert_eq!(cached.len(), 101);
        assert_eq!(server.received_requests().await.unwrap().len(), 2);
    }

    #[tokio::test]
    async fn failed_later_bun_release_pages_do_not_publish_a_partial_cache() {
        let server = MockServer::start().await;
        let first: Vec<_> = (0..100)
            .map(|i| serde_json::json!({"tag_name":format!("bun-v2.0.{i}")}))
            .collect();
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_json(first))
            .with_priority(10)
            .mount(&server)
            .await;
        Mock::given(query_param("page", "2"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;
        let root = tempfile::tempdir().unwrap();
        let cache = root.path().join("cache.json");
        assert!(
            fetch_releases_at(&reqwest::Client::new(), &cache, &server.uri())
                .await
                .is_err()
        );
        assert!(!cache.exists());
    }
}
