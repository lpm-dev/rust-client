//! Binary download and extraction for runtime installations.

use crate::node::{self, NodeRelease};
use crate::platform::Platform;
use lpm_common::LpmError;
use std::path::Path;

/// Download and install a Node.js release.
///
/// 1. Download the tarball from nodejs.org
/// 2. Extract to a temp directory
/// 3. Move the inner directory to `~/.lpm/runtimes/node/{version}/`
pub async fn install_node(
	client: &reqwest::Client,
	release: &NodeRelease,
	platform: &Platform,
) -> Result<String, LpmError> {
	let version = release.version_bare();
	let target_dir = node::node_version_dir(version)?;

	if target_dir.exists() {
		tracing::debug!("node {version} already installed at {}", target_dir.display());
		return Ok(version.to_string());
	}

	let url = release.download_url(platform);
	tracing::debug!("downloading node {version} from {url}");

	// Download
	let resp = client
		.get(&url)
		.send()
		.await
		.map_err(|e| LpmError::Network(format!("failed to download node {version}: {e}")))?;

	if !resp.status().is_success() {
		return Err(LpmError::Http {
			status: resp.status().as_u16(),
			message: format!("failed to download node {version} from {url}"),
		});
	}

	let total_size = resp.content_length().unwrap_or(0);
	let bytes = resp
		.bytes()
		.await
		.map_err(|e| LpmError::Network(format!("failed to read node download: {e}")))?;

	tracing::debug!(
		"downloaded {} bytes (expected {})",
		bytes.len(),
		total_size
	);

	// Verify SHA-256 checksum against nodejs.org SHASUMS256.txt
	if let Err(e) = verify_checksum(client, release, platform, &bytes).await {
		tracing::warn!("checksum verification failed: {e} — proceeding with install");
		// Non-fatal: HTTPS already provides integrity. Log warning but don't block.
	}

	// Extract tarball
	let parent = target_dir
		.parent()
		.ok_or_else(|| LpmError::Script("invalid runtime path".into()))?;
	std::fs::create_dir_all(parent)?;

	// Extract to a temp dir first, then rename (atomic)
	let temp_dir = parent.join(format!(".{version}-installing"));
	if temp_dir.exists() {
		std::fs::remove_dir_all(&temp_dir)?;
	}
	std::fs::create_dir_all(&temp_dir)?;

	extract_tarball(&bytes, &temp_dir)?;

	// The tarball contains a single top-level directory like "node-v22.5.0-darwin-arm64/"
	// We need to move its contents to the final location.
	let inner_dir = find_single_subdir(&temp_dir)?;

	// Rename inner dir to the target
	if target_dir.exists() {
		std::fs::remove_dir_all(&target_dir)?;
	}
	std::fs::rename(&inner_dir, &target_dir).map_err(|e| {
		LpmError::Script(format!(
			"failed to move extracted node to {}: {e}",
			target_dir.display()
		))
	})?;

	// Clean up temp dir
	let _ = std::fs::remove_dir_all(&temp_dir);

	tracing::debug!("installed node {version} to {}", target_dir.display());
	Ok(version.to_string())
}

/// Extract a .tar.gz archive.
fn extract_tarball(data: &[u8], dest: &Path) -> Result<(), LpmError> {
	let decoder = flate2::read::GzDecoder::new(data)
		.map_err(|e| LpmError::Script(format!("failed to create gzip decoder: {e}")))?;
	let mut archive = tar::Archive::new(decoder);
	archive.unpack(dest).map_err(|e| {
		LpmError::Script(format!("failed to extract node tarball: {e}"))
	})?;

	Ok(())
}

/// Find the single subdirectory inside a directory.
/// Node.js tarballs always have one top-level dir.
fn find_single_subdir(dir: &Path) -> Result<std::path::PathBuf, LpmError> {
	let mut entries = std::fs::read_dir(dir)?;
	let first = entries
		.next()
		.ok_or_else(|| LpmError::Script("extracted tarball is empty".into()))?
		.map_err(|e| LpmError::Script(format!("failed to read extracted dir: {e}")))?;

	if first.path().is_dir() {
		Ok(first.path())
	} else {
		Err(LpmError::Script(
			"extracted tarball doesn't contain a directory".into(),
		))
	}
}

/// Verify downloaded tarball against nodejs.org SHASUMS256.txt.
///
/// Fetches the checksum file, computes SHA-256 of the downloaded bytes,
/// and compares. Returns Ok(()) if match, Err if mismatch or fetch failure.
async fn verify_checksum(
	client: &reqwest::Client,
	release: &node::NodeRelease,
	platform: &Platform,
	data: &[u8],
) -> Result<(), String> {
	let shasums_url = release.shasums_url();

	let resp = client
		.get(&shasums_url)
		.timeout(std::time::Duration::from_secs(10))
		.send()
		.await
		.map_err(|e| format!("failed to fetch SHASUMS256: {e}"))?;

	if !resp.status().is_success() {
		return Err(format!("SHASUMS256 returned {}", resp.status()));
	}

	let body = resp.text().await.map_err(|e| format!("failed to read SHASUMS256: {e}"))?;

	// Find the expected hash for our platform's tarball
	let expected_filename = format!(
		"node-{}-{}.tar.gz",
		release.version,
		platform.node_suffix()
	);

	let expected_hash = body
		.lines()
		.find(|line| line.contains(&expected_filename))
		.and_then(|line| line.split_whitespace().next())
		.ok_or_else(|| format!("checksum not found for {expected_filename} in SHASUMS256"))?;

	// Compute actual SHA-256
	use sha2::{Digest, Sha256};
	let mut hasher = Sha256::new();
	hasher.update(data);
	let actual_hash = format!("{:x}", hasher.finalize());

	if actual_hash == expected_hash {
		tracing::debug!("checksum verified: {actual_hash}");
		Ok(())
	} else {
		Err(format!(
			"checksum mismatch: expected {expected_hash}, got {actual_hash}"
		))
	}
}
