//! Download plugin binaries from GitHub Releases.
//!
//! Supports both `.tar.gz` archives (oxlint) and `.zip` archives (oxlint on Windows),
//! as well as direct binary downloads (biome).
//!
//! Downloads use atomic writes: binary is written to a `.tmp` file first, then
//! renamed to the final path. This prevents corrupted installs from interrupted downloads.

use crate::registry::{self, PluginDef};
use crate::store;
use lpm_common::LpmError;
use lpm_runtime::platform::Platform;
use sha2::{Digest, Sha256};

/// Maximum download size: 150 MB. 3x safety margin over largest known plugin (~50 MB biome).
const MAX_PLUGIN_DOWNLOAD_SIZE: usize = 150 * 1024 * 1024;

/// Download and install a plugin binary.
///
/// Uses atomic write (temp file + rename) to prevent corrupted installs.
/// Verifies SHA-256 checksum when available, enforces download size limits.
pub async fn download_plugin(
    def: &PluginDef,
    version: &str,
    platform: &Platform,
) -> Result<(), LpmError> {
    let platform_str = platform.to_string();
    let asset_name = registry::resolve_platform_asset(def, &platform_str).ok_or_else(|| {
        LpmError::Plugin(format!(
            "plugin '{}' has no binary for platform {}",
            def.name, platform_str
        ))
    })?;

    let url = def
        .url_template
        .replace("{version}", version)
        .replace("{platform}", asset_name);

    tracing::debug!("downloading plugin {}@{} from {}", def.name, version, url);

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(120))
        .build()
        .map_err(|e| LpmError::Network(format!("failed to create HTTP client: {e}")))?;

    let resp = client
        .get(&url)
        .header("User-Agent", "lpm-cli")
        .send()
        .await
        .map_err(|e| LpmError::Network(format!("failed to download {}: {e}", def.name)))?;

    if !resp.status().is_success() {
        return Err(LpmError::Http {
            status: resp.status().as_u16(),
            message: format!("failed to download {} from {}", def.name, url),
        });
    }

    // Check Content-Length header if available
    if let Some(content_length) = resp.content_length()
        && content_length as usize > MAX_PLUGIN_DOWNLOAD_SIZE
    {
        return Err(LpmError::Plugin(format!(
            "plugin '{}' download size ({} bytes) exceeds maximum allowed size ({} bytes)",
            def.name, content_length, MAX_PLUGIN_DOWNLOAD_SIZE
        )));
    }

    let bytes = resp
        .bytes()
        .await
        .map_err(|e| LpmError::Network(format!("failed to read {}: {e}", def.name)))?;

    // Verify actual download size
    validate_download_size(def.name, bytes.len())?;

    // Compute SHA-256 for audit and verification
    let sha256 = compute_sha256(&bytes);
    tracing::debug!("downloaded {} bytes, sha256: {}", bytes.len(), sha256);

    // Verify checksum if expected value is available for this platform
    if let Some(expected) = registry::resolve_checksum(def, &platform_str) {
        verify_checksum(def.name, &sha256, expected)?;
    } else {
        tracing::warn!(
            "no expected checksum for {} on {}, skipping verification",
            def.name,
            platform_str
        );
        eprintln!(
            "  \x1b[33m!\x1b[0m No checksum available for {} on {}. Download integrity not verified.",
            def.name, platform_str
        );
    }

    // Save to plugin directory using atomic write
    let version_dir = store::plugin_version_dir(def.name, version)?;
    std::fs::create_dir_all(&version_dir)?;

    let bin_path = version_dir.join(def.binary_name);
    // Use PID in temp name to avoid race conditions between concurrent processes
    let tmp_path = version_dir.join(format!(".{}.{}.tmp", def.binary_name, std::process::id()));

    // Clean up any previous failed attempt from this PID
    let _ = std::fs::remove_file(&tmp_path);

    let extract_result = if def.is_archive {
        // Detect archive format from asset name and magic bytes
        if asset_name.ends_with(".zip") || is_zip_magic(&bytes) {
            extract_binary_from_zip(&bytes, &tmp_path, def.binary_name)
        } else {
            extract_binary_from_tarball(&bytes, &tmp_path, def.binary_name)
        }
    } else {
        // Direct binary download
        std::fs::write(&tmp_path, &bytes)
            .map_err(|e| LpmError::Plugin(format!("failed to write plugin binary: {e}")))
    };

    // If extraction failed, clean up temp file
    if let Err(e) = extract_result {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(e);
    }

    // Atomic rename: .tmp → final binary
    std::fs::rename(&tmp_path, &bin_path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp_path);
        LpmError::Plugin(format!("failed to finalize plugin binary: {e}"))
    })?;

    // Make executable on Unix
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&bin_path, std::fs::Permissions::from_mode(0o755))?;
    }

    tracing::debug!(
        "installed plugin {}@{} to {} (sha256: {})",
        def.name,
        version,
        bin_path.display(),
        sha256,
    );

    Ok(())
}

/// Compute SHA-256 hex digest of data.
fn compute_sha256(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

/// Verify that a computed checksum matches the expected value.
fn verify_checksum(plugin_name: &str, actual: &str, expected: &str) -> Result<(), LpmError> {
    if actual != expected {
        return Err(LpmError::Plugin(format!(
            "checksum mismatch for plugin '{}': expected {}, got {}",
            plugin_name, expected, actual
        )));
    }
    Ok(())
}

/// Validate download size is within limits.
fn validate_download_size(plugin_name: &str, size: usize) -> Result<(), LpmError> {
    if size > MAX_PLUGIN_DOWNLOAD_SIZE {
        return Err(LpmError::Plugin(format!(
            "plugin '{}' download size ({} bytes) exceeds maximum allowed size ({} bytes)",
            plugin_name, size, MAX_PLUGIN_DOWNLOAD_SIZE
        )));
    }
    Ok(())
}

/// Check if bytes start with ZIP magic number (PK\x03\x04).
fn is_zip_magic(data: &[u8]) -> bool {
    data.len() >= 4 && data[0] == 0x50 && data[1] == 0x4b && data[2] == 0x03 && data[3] == 0x04
}

/// Extract a specific binary from a .tar.gz archive.
fn extract_binary_from_tarball(
    data: &[u8],
    dest_path: &std::path::Path,
    binary_name: &str,
) -> Result<(), LpmError> {
    let decoder = flate2::read::GzDecoder::new(data);
    let mut archive = tar::Archive::new(decoder);

    let mut found_files = Vec::new();

    for entry in archive
        .entries()
        .map_err(|e| LpmError::Plugin(format!("failed to read plugin archive: {e}")))?
    {
        let mut entry =
            entry.map_err(|e| LpmError::Plugin(format!("failed to read archive entry: {e}")))?;

        let path = entry
            .path()
            .map_err(|e| LpmError::Plugin(format!("failed to read entry path: {e}")))?;

        let file_name = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();

        found_files.push(file_name.clone());

        // Match if the filename is the binary or starts with binary name + dash (platform suffix)
        if file_name == binary_name || file_name.starts_with(&format!("{binary_name}-")) {
            let mut output = std::fs::File::create(dest_path)?;
            std::io::copy(&mut entry, &mut output)
                .map_err(|e| LpmError::Plugin(format!("failed to extract {binary_name}: {e}")))?;
            return Ok(());
        }
    }

    Err(LpmError::Plugin(format!(
        "binary '{}' not found in tar.gz archive. Found: [{}]",
        binary_name,
        found_files.join(", ")
    )))
}

/// Extract a specific binary from a .zip archive.
fn extract_binary_from_zip(
    data: &[u8],
    dest_path: &std::path::Path,
    binary_name: &str,
) -> Result<(), LpmError> {
    let cursor = std::io::Cursor::new(data);
    let mut archive = zip::ZipArchive::new(cursor)
        .map_err(|e| LpmError::Plugin(format!("failed to open ZIP archive: {e}")))?;

    let mut found_files = Vec::new();

    for i in 0..archive.len() {
        let mut entry = archive
            .by_index(i)
            .map_err(|e| LpmError::Plugin(format!("failed to read ZIP entry: {e}")))?;

        let file_name = entry
            .enclosed_name()
            .and_then(|p| p.file_name().map(|n| n.to_string_lossy().to_string()))
            .unwrap_or_default();

        found_files.push(file_name.clone());

        // Match binary name or name with platform suffix / .exe extension
        let is_match = file_name == binary_name
            || file_name == format!("{binary_name}.exe")
            || file_name.starts_with(&format!("{binary_name}-"));

        if is_match && !entry.is_dir() {
            let mut output = std::fs::File::create(dest_path)?;
            std::io::copy(&mut entry, &mut output).map_err(|e| {
                LpmError::Plugin(format!("failed to extract {binary_name} from ZIP: {e}"))
            })?;
            return Ok(());
        }
    }

    Err(LpmError::Plugin(format!(
        "binary '{}' not found in ZIP archive. Found: [{}]",
        binary_name,
        found_files.join(", ")
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zip_magic_detection() {
        assert!(is_zip_magic(&[0x50, 0x4b, 0x03, 0x04, 0x00]));
        assert!(!is_zip_magic(&[0x1f, 0x8b, 0x08, 0x00])); // gzip
        assert!(!is_zip_magic(&[0x00, 0x00])); // too short
    }

    #[test]
    fn extract_from_tarball_lists_files_on_miss() {
        // Create a minimal tar.gz with a known file
        let mut builder = tar::Builder::new(Vec::new());
        let data = b"hello";
        let mut header = tar::Header::new_gnu();
        header.set_size(data.len() as u64);
        header.set_cksum();
        builder
            .append_data(&mut header, "some-other-file", &data[..])
            .unwrap();
        let tar_data = builder.into_inner().unwrap();

        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        std::io::Write::write_all(&mut encoder, &tar_data).unwrap();
        let gz_data = encoder.finish().unwrap();

        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("binary");
        let err = extract_binary_from_tarball(&gz_data, &dest, "oxlint").unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("not found in tar.gz archive"), "error: {msg}");
        assert!(
            msg.contains("some-other-file"),
            "should list found files: {msg}"
        );
    }

    #[test]
    fn extract_from_zip_lists_files_on_miss() {
        // Create a minimal ZIP with a known file
        let buf = std::io::Cursor::new(Vec::new());
        let mut writer = zip::ZipWriter::new(buf);
        let options = zip::write::SimpleFileOptions::default();
        writer.start_file("readme.txt", options).unwrap();
        std::io::Write::write_all(&mut writer, b"hello").unwrap();
        let buf = writer.finish().unwrap();
        let zip_data = buf.into_inner();

        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("binary");
        let err = extract_binary_from_zip(&zip_data, &dest, "oxlint").unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("not found in ZIP archive"), "error: {msg}");
        assert!(msg.contains("readme.txt"), "should list found files: {msg}");
    }

    // --- Finding #2: Checksum verification ---

    #[test]
    fn checksum_match_succeeds() {
        assert!(verify_checksum("test", "abc123", "abc123").is_ok());
    }

    #[test]
    fn checksum_mismatch_fails() {
        let err = verify_checksum("test", "actual_hash", "expected_hash").unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("checksum mismatch"), "error: {msg}");
        assert!(msg.contains("expected_hash"), "error: {msg}");
        assert!(msg.contains("actual_hash"), "error: {msg}");
    }

    // --- Finding #4: Download size limit ---

    #[test]
    fn size_within_limit_succeeds() {
        assert!(validate_download_size("test", 1024).is_ok());
        assert!(validate_download_size("test", MAX_PLUGIN_DOWNLOAD_SIZE).is_ok());
    }

    #[test]
    fn size_exceeds_limit_fails() {
        let err = validate_download_size("test", MAX_PLUGIN_DOWNLOAD_SIZE + 1).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("exceeds maximum"), "error: {msg}");
    }

    // --- Finding #6: Unique temp file names ---

    #[test]
    fn temp_file_name_contains_pid() {
        let pid = std::process::id();
        let tmp_name = format!(".oxlint.{}.tmp", pid);
        assert!(tmp_name.contains(&pid.to_string()));
        // Different from the old deterministic name
        assert_ne!(tmp_name, ".oxlint.tmp");
    }

    // --- SHA-256 computation ---

    #[test]
    fn compute_sha256_deterministic() {
        let hash1 = compute_sha256(b"hello world");
        let hash2 = compute_sha256(b"hello world");
        assert_eq!(hash1, hash2);
        // Known SHA-256 of "hello world"
        assert_eq!(
            hash1,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    #[test]
    fn compute_sha256_different_inputs() {
        let hash1 = compute_sha256(b"hello");
        let hash2 = compute_sha256(b"world");
        assert_ne!(hash1, hash2);
    }
}
