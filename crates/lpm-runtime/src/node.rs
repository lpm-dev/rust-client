//! Node.js version management — index fetching, version resolution, install/uninstall.

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
		let ext = if platform.os == "win" { "zip" } else { "tar.gz" };
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
		format!(
			"https://nodejs.org/dist/{}/SHASUMS256.txt",
			self.version
		)
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
pub async fn fetch_index(
	client: &reqwest::Client,
) -> Result<Vec<NodeRelease>, LpmError> {
	let cache_path = runtimes_dir()?.join("index-cache.json");

	// Check cache freshness (1 hour TTL)
	if let Ok(meta) = std::fs::metadata(&cache_path) {
		if let Ok(modified) = meta.modified() {
			let age = std::time::SystemTime::now()
				.duration_since(modified)
				.unwrap_or_default();
			if age.as_secs() < 3600 {
				if let Ok(content) = std::fs::read_to_string(&cache_path) {
					if let Ok(releases) = serde_json::from_str::<Vec<NodeRelease>>(&content) {
						tracing::debug!("using cached node index ({} releases)", releases.len());
						return Ok(releases);
					}
				}
			}
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

	// Cache it
	if let Some(parent) = cache_path.parent() {
		let _ = std::fs::create_dir_all(parent);
	}
	let _ = std::fs::write(&cache_path, &body);

	Ok(releases)
}

/// Resolve a version spec (e.g., "22", "22.5", "22.5.0", "lts") to an exact version.
pub fn resolve_version(
	releases: &[NodeRelease],
	spec: &str,
) -> Option<NodeRelease> {
	let spec = spec.strip_prefix('v').unwrap_or(spec);

	// "lts" → latest LTS
	if spec.eq_ignore_ascii_case("lts") {
		return releases.iter().find(|r| r.lts.is_lts()).cloned();
	}

	// "latest" → latest release
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

	// Partial match: "22" → latest 22.x.x, "22.5" → latest 22.5.x
	let prefix = format!("v{spec}.");
	releases
		.iter()
		.find(|r| r.version.starts_with(&prefix) || r.version == format!("v{spec}"))
		.cloned()
}

/// Simple version string comparison for sorting (descending).
fn compare_versions(a: &str, b: &str) -> std::cmp::Ordering {
	let parse = |s: &str| -> Vec<u64> {
		s.split('.').filter_map(|p| p.parse().ok()).collect()
	};
	parse(a).cmp(&parse(b))
}

/// Find the best matching installed version for a version spec.
///
/// Handles both exact specs ("22.5.0") and range-stripped specs ("22.0.0" from ">=22.0.0").
/// Tries in order:
/// 1. Exact match ("22.0.0" matches "22.0.0")
/// 2. Prefix match ("22" matches "22.22.2", "22.5" matches "22.5.1")
/// 3. Major-version match ("22.0.0" → major "22" → matches "22.22.2")
///
/// Returns the best (highest) matching version.
pub fn find_matching_installed(clean_spec: &str, installed: &[String]) -> Option<String> {
	// 1. Exact match
	if let Some(v) = installed.iter().find(|v| v.as_str() == clean_spec) {
		return Some(v.clone());
	}

	// 2. Prefix match (e.g., "22" matches "22.22.2")
	let prefix = format!("{clean_spec}.");
	if let Some(v) = installed.iter().find(|v| v.starts_with(&prefix)) {
		return Some(v.clone());
	}

	// 3. Major-version fallback for full semver specs like "22.0.0" from ">=22.0.0"
	//    Extract major and match any installed version with that major.
	if let Some(major) = clean_spec.split('.').next() {
		if major != clean_spec {
			// Only do this if clean_spec has dots (i.e., is more than just a major)
			let major_prefix = format!("{major}.");
			return installed
				.iter()
				.find(|v| v.as_str() == major || v.starts_with(&major_prefix))
				.cloned();
		}
	}

	None
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
	fn find_matching_range_stripped_spec() {
		// This is the key test: ">=22.0.0" gets stripped to "22.0.0",
		// and we should find "22.22.2" via major-version fallback.
		let installed = vec!["22.22.2".into(), "20.20.2".into()];
		assert_eq!(
			find_matching_installed("22.0.0", &installed),
			Some("22.22.2".into())
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
		let p = Platform { os: "darwin", arch: "arm64" };
		let url = r.download_url(&p);
		assert_eq!(url, "https://nodejs.org/dist/v22.5.0/node-v22.5.0-darwin-arm64.tar.gz");
	}
}
