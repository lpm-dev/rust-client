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

	// Finding #3: Check Content-Length header for early rejection of oversized downloads
	if let Some(content_length) = resp.content_length() {
		validate_download_size(content_length as usize)?;
	}

	let total_size = resp.content_length().unwrap_or(0);
	let bytes = resp
		.bytes()
		.await
		.map_err(|e| LpmError::Network(format!("failed to read node download: {e}")))?;

	// Finding #3: Also validate actual size (Content-Length can lie or be absent)
	validate_download_size(bytes.len())?;

	tracing::debug!(
		"downloaded {} bytes (expected {})",
		bytes.len(),
		total_size
	);

	// Finding #2: Verify SHA-256 checksum — hard failure on mismatch
	verify_checksum(client, release, platform, &bytes).await?;

	// Extract tarball
	let parent = target_dir
		.parent()
		.ok_or_else(|| LpmError::Script("invalid runtime path".into()))?;

	// Finding #4: Create parent directory with restricted permissions
	create_restricted_dir(parent)?;

	// Extract to a temp dir first, then rename (atomic)
	let temp_dir = parent.join(format!(".{version}-installing"));
	if temp_dir.exists() {
		std::fs::remove_dir_all(&temp_dir)?;
	}
	create_restricted_dir(&temp_dir)?;

	// Finding #14: Windows uses .zip, others use .tar.gz
	if platform.os == "win" {
		extract_zip(&bytes, &temp_dir)?;
	} else {
		extract_tarball(&bytes, &temp_dir)?;
	}

	// The tarball contains a single top-level directory like "node-v22.5.0-darwin-arm64/"
	// We need to move its contents to the final location.
	let inner_dir = find_single_subdir(&temp_dir)?;

	// Finding #6: Rename with TOCTOU race recovery
	rename_with_fallback(&inner_dir, &target_dir)?;

	// Clean up temp dir
	let _ = std::fs::remove_dir_all(&temp_dir);

	tracing::debug!("installed node {version} to {}", target_dir.display());
	Ok(version.to_string())
}

/// Extract a .tar.gz archive with path traversal protection.
///
/// Each entry is validated to ensure it does not escape the destination directory
/// via `..` path components (zip-slip attack). See CVE-2018-1002200.
fn extract_tarball(data: &[u8], dest: &Path) -> Result<(), LpmError> {
	let decoder = flate2::read::GzDecoder::new(data)
		.map_err(|e| LpmError::Script(format!("failed to create gzip decoder: {e}")))?;
	let mut archive = tar::Archive::new(decoder);

	for entry in archive.entries().map_err(|e| {
		LpmError::Script(format!("failed to read tarball entries: {e}"))
	})? {
		let mut entry = entry.map_err(|e| {
			LpmError::Script(format!("failed to read tarball entry: {e}"))
		})?;

		let path = entry.path().map_err(|e| {
			LpmError::Script(format!("failed to read tarball entry path: {e}"))
		})?;

		// Reject any entry containing `..` components (path traversal / zip-slip)
		if path
			.components()
			.any(|c| matches!(c, std::path::Component::ParentDir))
		{
			return Err(LpmError::Script(format!(
				"path traversal detected in tarball entry: {}",
				path.display()
			)));
		}

		entry.unpack_in(dest).map_err(|e| {
			LpmError::Script(format!("failed to extract tarball entry: {e}"))
		})?;
	}

	Ok(())
}

/// Extract a .zip archive with path traversal protection.
///
/// Used for Windows Node.js distributions which are distributed as .zip files.
/// Each entry is validated to ensure it does not escape the destination directory.
fn extract_zip(data: &[u8], dest: &Path) -> Result<(), LpmError> {
	use std::io::Cursor;

	let reader = Cursor::new(data);
	let mut archive = zip::ZipArchive::new(reader).map_err(|e| {
		LpmError::Script(format!("failed to open zip archive: {e}"))
	})?;

	for i in 0..archive.len() {
		let mut file = archive.by_index(i).map_err(|e| {
			LpmError::Script(format!("failed to read zip entry {i}: {e}"))
		})?;

		let outpath = match file.enclosed_name() {
			Some(path) => dest.join(path),
			None => {
				// enclosed_name() returns None for entries with path traversal
				return Err(LpmError::Script(format!(
					"path traversal detected in zip entry: {}",
					file.name()
				)));
			}
		};

		if file.is_dir() {
			std::fs::create_dir_all(&outpath)?;
		} else {
			if let Some(parent) = outpath.parent() {
				if !parent.exists() {
					std::fs::create_dir_all(parent)?;
				}
			}
			let mut outfile = std::fs::File::create(&outpath)?;
			std::io::copy(&mut file, &mut outfile).map_err(|e| {
				LpmError::Script(format!("failed to extract zip entry: {e}"))
			})?;

			// Set executable permission on Unix for binaries
			#[cfg(unix)]
			{
				use std::os::unix::fs::PermissionsExt;
				if let Some(mode) = file.unix_mode() {
					std::fs::set_permissions(&outpath, std::fs::Permissions::from_mode(mode))?;
				}
			}
		}
	}

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

/// Maximum download size: 200 MiB.
///
/// Prevents OOM from malicious or unexpectedly large downloads.
const MAX_DOWNLOAD_SIZE: usize = 200 * 1024 * 1024;

/// Validate that a download size is within the allowed limit.
///
/// Called both for the `Content-Length` header (early reject) and
/// after buffering bytes (defence against lying headers / chunked encoding).
fn validate_download_size(size: usize) -> Result<(), LpmError> {
	if size > MAX_DOWNLOAD_SIZE {
		return Err(LpmError::Network(format!(
			"download size {size} bytes exceeds maximum allowed size of {MAX_DOWNLOAD_SIZE} bytes ({}MB)",
			MAX_DOWNLOAD_SIZE / (1024 * 1024)
		)));
	}
	Ok(())
}

/// Compare an expected hex-encoded SHA-256 hash against the SHA-256 of raw bytes.
///
/// Returns `Ok(())` on match, `Err` on mismatch.
fn compare_checksum(expected_hex: &str, actual_bytes: &[u8]) -> Result<(), LpmError> {
	use sha2::{Digest, Sha256};
	let mut hasher = Sha256::new();
	hasher.update(actual_bytes);
	let actual_hex = format!("{:x}", hasher.finalize());

	if actual_hex == expected_hex {
		Ok(())
	} else {
		Err(LpmError::IntegrityMismatch {
			expected: expected_hex.to_string(),
			actual: actual_hex,
		})
	}
}

/// Create a directory with restricted permissions (0o700 on Unix).
///
/// Ensures that runtime directories are not world-readable.
pub(crate) fn create_restricted_dir(path: &Path) -> Result<(), LpmError> {
	std::fs::create_dir_all(path)?;

	#[cfg(unix)]
	{
		use std::os::unix::fs::PermissionsExt;
		std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
	}

	Ok(())
}

/// Write data to a file with restricted permissions (0o600 on Unix).
#[allow(dead_code)]
pub(crate) fn write_restricted_file(path: &Path, data: &[u8]) -> Result<(), LpmError> {
	#[cfg(unix)]
	{
		use std::io::Write;
		use std::os::unix::fs::OpenOptionsExt;
		let mut file = std::fs::OpenOptions::new()
			.write(true)
			.create(true)
			.truncate(true)
			.mode(0o600)
			.open(path)?;
		file.write_all(data)?;
		return Ok(());
	}

	#[cfg(not(unix))]
	{
		std::fs::write(path, data)?;
		Ok(())
	}
}

/// Rename a directory to a target path with TOCTOU race recovery.
///
/// If the rename fails because the target already exists (another process
/// installed the same version concurrently), this is treated as success.
///
/// # Finding #22: Cross-filesystem rename
///
/// `std::fs::rename()` fails with `EXDEV` across filesystem boundaries.
/// This is currently safe because the temp dir is always a sibling of the
/// target (both under `~/.lpm/runtimes/node/`), so they are on the same
/// filesystem. If the temp dir location is ever changed, a recursive
/// copy + delete fallback would be needed.
fn rename_with_fallback(source: &Path, target: &Path) -> Result<(), LpmError> {
	if target.exists() {
		// Another process already installed it — success.
		return Ok(());
	}

	match std::fs::rename(source, target) {
		Ok(()) => Ok(()),
		Err(_) if target.exists() => {
			// Race condition: rename failed because another process created target
			// between our exists() check and rename(). That's fine — it's installed.
			tracing::debug!(
				"rename failed but target already exists (concurrent install): {}",
				target.display()
			);
			Ok(())
		}
		Err(e) => Err(LpmError::Script(format!(
			"failed to move extracted node to {}: {e}",
			target.display()
		))),
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
) -> Result<(), LpmError> {
	let shasums_url = release.shasums_url();

	let resp = client
		.get(&shasums_url)
		.timeout(std::time::Duration::from_secs(10))
		.send()
		.await
		.map_err(|e| LpmError::Network(format!("failed to fetch SHASUMS256: {e}")))?;

	if !resp.status().is_success() {
		return Err(LpmError::Network(format!(
			"SHASUMS256 returned {}",
			resp.status()
		)));
	}

	let body = resp
		.text()
		.await
		.map_err(|e| LpmError::Network(format!("failed to read SHASUMS256: {e}")))?;

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
		.ok_or_else(|| {
			LpmError::Network(format!(
				"checksum not found for {expected_filename} in SHASUMS256"
			))
		})?;

	compare_checksum(expected_hash, data)
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::io::Write;
	use tempfile::TempDir;

	// --- Finding #1: Tar path traversal (zip slip) ---

	/// Helper: build a tar.gz in memory with the given entry paths.
	///
	/// For paths without `..`, uses the normal tar builder. For paths with `..`
	/// (malicious test entries), constructs raw tar blocks to bypass the builder's
	/// own path validation.
	fn build_tar_gz(entries: &[(&str, &[u8])]) -> Vec<u8> {
		let mut tar_bytes = Vec::new();

		for &(path, data) in entries {
			if path.contains("..") {
				// Build raw tar entry to bypass builder validation
				tar_bytes.extend_from_slice(&build_raw_tar_entry(path, data));
			} else {
				let mut builder = tar::Builder::new(Vec::new());
				let mut header = tar::Header::new_gnu();
				header.set_path(path).unwrap();
				header.set_size(data.len() as u64);
				header.set_mode(0o644);
				header.set_cksum();
				builder.append(&header, &data[..]).unwrap();
				// Get raw bytes without the end-of-archive marker
				let built = builder.into_inner().unwrap();
				// Each entry is header (512) + data (padded to 512). Builder adds
				// 1024 zero bytes at the end as EOF marker; strip those.
				if built.len() > 1024 {
					tar_bytes.extend_from_slice(&built[..built.len() - 1024]);
				} else {
					tar_bytes.extend_from_slice(&built);
				}
			}
		}

		// End-of-archive: two 512-byte blocks of zeros
		tar_bytes.extend_from_slice(&[0u8; 1024]);

		let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::Fast);
		gz.write_all(&tar_bytes).unwrap();
		gz.finish().unwrap()
	}

	/// Build a raw tar entry with arbitrary path (bypassing validation).
	fn build_raw_tar_entry(path: &str, data: &[u8]) -> Vec<u8> {
		let mut header = [0u8; 512];

		// Name field: bytes 0..100
		let path_bytes = path.as_bytes();
		let copy_len = path_bytes.len().min(100);
		header[..copy_len].copy_from_slice(&path_bytes[..copy_len]);

		// Mode field: bytes 100..108 (octal ASCII "0000644\0")
		header[100..108].copy_from_slice(b"0000644\0");

		// UID: bytes 108..116
		header[108..116].copy_from_slice(b"0001000\0");

		// GID: bytes 116..124
		header[116..124].copy_from_slice(b"0001000\0");

		// Size field: bytes 124..136 (octal ASCII, 11 digits + null)
		let size_str = format!("{:011o}\0", data.len());
		header[124..136].copy_from_slice(size_str.as_bytes());

		// Mtime: bytes 136..148
		header[136..148].copy_from_slice(b"00000000000\0");

		// Typeflag: byte 156 = '0' (regular file)
		header[156] = b'0';

		// Magic: bytes 257..263 = "ustar\0"
		header[257..263].copy_from_slice(b"ustar\0");

		// Version: bytes 263..265 = "00"
		header[263..265].copy_from_slice(b"00");

		// Compute checksum: bytes 148..156 should be spaces during calculation
		header[148..156].copy_from_slice(b"        ");
		let cksum: u32 = header.iter().map(|&b| b as u32).sum();
		let cksum_str = format!("{:06o}\0 ", cksum);
		header[148..156].copy_from_slice(&cksum_str.as_bytes()[..8]);

		let mut entry = Vec::with_capacity(512 + ((data.len() + 511) / 512) * 512);
		entry.extend_from_slice(&header);
		entry.extend_from_slice(data);
		// Pad to 512-byte boundary
		let padding = (512 - (data.len() % 512)) % 512;
		entry.extend_from_slice(&vec![0u8; padding]);
		entry
	}

	#[test]
	fn extract_tarball_rejects_path_traversal() {
		let malicious_tar = build_tar_gz(&[("../escape.txt", b"pwned")]);
		let dest = TempDir::new().unwrap();
		let result = extract_tarball(&malicious_tar, dest.path());
		assert!(result.is_err(), "extract_tarball must reject path traversal entries");
		let err_msg = result.unwrap_err().to_string();
		assert!(
			err_msg.contains("path traversal"),
			"error should mention path traversal, got: {err_msg}"
		);
	}

	#[test]
	fn extract_tarball_rejects_nested_traversal() {
		let malicious_tar = build_tar_gz(&[("foo/../../escape.txt", b"pwned")]);
		let dest = TempDir::new().unwrap();
		let result = extract_tarball(&malicious_tar, dest.path());
		assert!(result.is_err(), "extract_tarball must reject nested path traversal");
	}

	#[test]
	fn extract_tarball_allows_normal_entries() {
		let normal_tar = build_tar_gz(&[
			("mydir/file.txt", b"hello"),
			("mydir/sub/deep.txt", b"world"),
		]);
		let dest = TempDir::new().unwrap();
		let result = extract_tarball(&normal_tar, dest.path());
		assert!(result.is_ok(), "normal tarball should extract fine: {result:?}");
		assert!(dest.path().join("mydir/file.txt").exists());
		assert!(dest.path().join("mydir/sub/deep.txt").exists());
	}

	// --- Finding #2: Checksum failure must be fatal ---

	#[test]
	fn compare_checksum_matching() {
		let data = b"hello world";
		// SHA-256 of "hello world"
		let expected = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";
		assert!(compare_checksum(expected, data).is_ok());
	}

	#[test]
	fn compare_checksum_mismatch_is_error() {
		let data = b"hello world";
		let wrong = "0000000000000000000000000000000000000000000000000000000000000000";
		let result = compare_checksum(wrong, data);
		assert!(result.is_err(), "checksum mismatch must be an error");
		match result.unwrap_err() {
			LpmError::IntegrityMismatch { expected, actual } => {
				assert_eq!(expected, wrong);
				assert_eq!(
					actual,
					"b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
				);
			}
			other => panic!("expected IntegrityMismatch, got: {other:?}"),
		}
	}

	// --- Finding #3: Download size limit ---

	#[test]
	fn validate_download_size_within_limit() {
		assert!(validate_download_size(100 * 1024 * 1024).is_ok());
		assert!(validate_download_size(0).is_ok());
		assert!(validate_download_size(MAX_DOWNLOAD_SIZE).is_ok());
	}

	#[test]
	fn validate_download_size_exceeds_limit() {
		let result = validate_download_size(MAX_DOWNLOAD_SIZE + 1);
		assert!(result.is_err(), "oversized download must be rejected");
		let err_msg = result.unwrap_err().to_string();
		assert!(err_msg.contains("exceeds maximum"), "got: {err_msg}");
	}

	// --- Finding #4: Directory and file permissions ---

	#[cfg(unix)]
	#[test]
	fn create_restricted_dir_sets_0o700() {
		use std::os::unix::fs::PermissionsExt;
		let tmp = TempDir::new().unwrap();
		let dir = tmp.path().join("restricted");
		create_restricted_dir(&dir).unwrap();
		let mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
		assert_eq!(mode, 0o700, "directory should be 0o700, got {mode:o}");
	}

	#[cfg(unix)]
	#[test]
	fn write_restricted_file_sets_0o600() {
		use std::os::unix::fs::PermissionsExt;
		let tmp = TempDir::new().unwrap();
		let file = tmp.path().join("secret.json");
		write_restricted_file(&file, b"{}").unwrap();
		let mode = std::fs::metadata(&file).unwrap().permissions().mode() & 0o777;
		assert_eq!(mode, 0o600, "file should be 0o600, got {mode:o}");
	}

	// --- Finding #6: TOCTOU race — recovery when target already exists ---

	#[test]
	fn rename_recovery_when_target_exists() {
		// Simulate: rename fails because another process already installed the version.
		// The function should detect that target_dir now exists and return success.
		let tmp = TempDir::new().unwrap();
		let source = tmp.path().join("source");
		let target = tmp.path().join("target");

		// Create both source and target (simulating the race)
		std::fs::create_dir_all(&source).unwrap();
		std::fs::write(source.join("node"), b"binary").unwrap();
		std::fs::create_dir_all(&target).unwrap();
		std::fs::write(target.join("node"), b"binary").unwrap();

		// rename_with_fallback should succeed because target already exists
		let result = rename_with_fallback(&source, &target);
		assert!(result.is_ok(), "should succeed when target already exists: {result:?}");
	}

	#[test]
	fn rename_with_fallback_normal_case() {
		let tmp = TempDir::new().unwrap();
		let source = tmp.path().join("source");
		let target = tmp.path().join("target");

		std::fs::create_dir_all(&source).unwrap();
		std::fs::write(source.join("node"), b"binary").unwrap();

		let result = rename_with_fallback(&source, &target);
		assert!(result.is_ok());
		assert!(target.join("node").exists());
	}
}
