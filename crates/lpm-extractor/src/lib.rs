//! Tarball download, verification, decompression, and extraction for LPM.
//!
//! Handles the pipeline: raw .tgz bytes → verify integrity → decompress gzip → extract tar.
//!
//! npm tarballs have a `package/` prefix directory that gets stripped during extraction
//! (equivalent to `tar x --strip-components=1`).
//!
//! # TODOs for Phase 3
//! - [ ] Pre-read gzip final 4 bytes for single-allocation decompression (Bun technique)
//! - [ ] Parallel extraction with `rayon` for multiple tarballs
//! - [ ] Streaming extraction (decompress + extract without buffering decompressed data)
//! - [ ] `libdeflate` / `zlib-ng` for faster decompression (Phase 6)

use flate2::read::GzDecoder;
use lpm_common::{Integrity, LpmError};
use std::io::Read;
use std::path::{Path, PathBuf};
use tar::Archive;

/// Verify a tarball's integrity against an expected SRI hash.
///
/// Returns `Ok(())` if the hash matches, `Err` with details if not.
pub fn verify_integrity(data: &[u8], expected_sri: &str) -> Result<(), LpmError> {
    let expected = Integrity::parse(expected_sri)?;
    expected.verify(data)
}

/// Decompress gzip data in memory.
///
/// Used when you need the raw tar data (e.g., for inspection before extraction).
pub fn decompress_gzip(compressed: &[u8]) -> Result<Vec<u8>, LpmError> {
    let mut decoder = GzDecoder::new(compressed);
    let mut decompressed = Vec::new();
    decoder
        .read_to_end(&mut decompressed)
        .map_err(|e| LpmError::Io(e))?;
    Ok(decompressed)
}

/// Extract a .tgz (gzip-compressed tar) to a target directory.
///
/// Strips the first path component (the `package/` prefix that npm pack adds).
/// Returns the list of extracted file paths (relative to `target_dir`).
pub fn extract_tarball(data: &[u8], target_dir: &Path) -> Result<Vec<PathBuf>, LpmError> {
    let decoder = GzDecoder::new(data);
    let mut archive = Archive::new(decoder);
    let mut extracted_files = Vec::new();

    std::fs::create_dir_all(target_dir)?;

    for entry_result in archive.entries()? {
        let mut entry = entry_result?;

        let original_path = entry.path()?.into_owned();

        // Strip first component (e.g., "package/src/index.js" → "src/index.js")
        let stripped = strip_first_component(&original_path);
        let Some(relative_path) = stripped else {
            continue;
        };

        let target_path = target_dir.join(&relative_path);

        // Safety: prevent path traversal
        if !target_path.starts_with(target_dir) {
            return Err(LpmError::Registry(format!(
                "path traversal detected in tarball: {}",
                original_path.display()
            )));
        }

        // Create parent directories
        if let Some(parent) = target_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        // Only extract regular files (skip symlinks for security)
        if entry.header().entry_type().is_file() {
            entry.unpack(&target_path)?;
            extracted_files.push(relative_path);
        }
    }

    Ok(extracted_files)
}

/// Extract + verify in one step. The typical pipeline.
///
/// 1. Verify integrity hash matches
/// 2. Decompress gzip + extract tar
/// 3. Strip `package/` prefix
/// 4. Return list of extracted files
pub fn verify_and_extract(
    data: &[u8],
    expected_sri: &str,
    target_dir: &Path,
) -> Result<Vec<PathBuf>, LpmError> {
    verify_integrity(data, expected_sri)?;
    extract_tarball(data, target_dir)
}

/// List files in a tarball without extracting.
///
/// Useful for `lpm info --files` or source browsing.
pub fn list_tarball_contents(data: &[u8]) -> Result<Vec<PathBuf>, LpmError> {
    let decoder = GzDecoder::new(data);
    let mut archive = Archive::new(decoder);
    let mut files = Vec::new();

    for entry_result in archive.entries()? {
        let entry = entry_result?;
        if entry.header().entry_type().is_file() {
            let path = entry.path()?.into_owned();
            if let Some(stripped) = strip_first_component(&path) {
                files.push(stripped);
            }
        }
    }

    Ok(files)
}

/// Strip the first path component. `package/src/index.js` → `src/index.js`.
/// Returns `None` for paths that are just the prefix directory itself.
fn strip_first_component(path: &Path) -> Option<PathBuf> {
    let mut components = path.components();
    components.next()?; // Skip first component
    let rest: PathBuf = components.collect();
    if rest.as_os_str().is_empty() {
        None
    } else {
        Some(rest)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use lpm_common::integrity::HashAlgorithm;
    use std::io::Write;

    /// Create a test .tgz with a single file inside `package/`.
    fn create_test_tarball(filename: &str, content: &[u8]) -> Vec<u8> {
        let mut tar_data = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_data);
            let mut header = tar::Header::new_gnu();
            header.set_size(content.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();

            let tar_path = format!("package/{filename}");
            builder
                .append_data(&mut header, &tar_path, content)
                .unwrap();
            builder.finish().unwrap();
        }

        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&tar_data).unwrap();
        encoder.finish().unwrap()
    }

    #[test]
    fn extract_simple_tarball() {
        let tgz = create_test_tarball("index.js", b"console.log('hello')");
        let dir = tempfile::tempdir().unwrap();

        let files = extract_tarball(&tgz, dir.path()).unwrap();

        assert_eq!(files.len(), 1);
        assert_eq!(files[0], PathBuf::from("index.js"));

        let content = std::fs::read_to_string(dir.path().join("index.js")).unwrap();
        assert_eq!(content, "console.log('hello')");
    }

    #[test]
    fn extract_nested_file() {
        let tgz = create_test_tarball("src/lib/utils.js", b"export const x = 1");
        let dir = tempfile::tempdir().unwrap();

        let files = extract_tarball(&tgz, dir.path()).unwrap();

        assert_eq!(files.len(), 1);
        assert_eq!(files[0], PathBuf::from("src/lib/utils.js"));
        assert!(dir.path().join("src/lib/utils.js").exists());
    }

    #[test]
    fn list_tarball_contents_works() {
        let tgz = create_test_tarball("package.json", b"{}");
        let files = list_tarball_contents(&tgz).unwrap();

        assert_eq!(files.len(), 1);
        assert_eq!(files[0], PathBuf::from("package.json"));
    }

    #[test]
    fn verify_integrity_passes() {
        let data = b"test tarball data";
        let integrity = Integrity::from_bytes(HashAlgorithm::Sha512, data);
        let sri = integrity.to_string();

        assert!(verify_integrity(data, &sri).is_ok());
    }

    #[test]
    fn verify_integrity_fails_on_mismatch() {
        let data = b"test tarball data";
        let wrong_integrity = Integrity::from_bytes(HashAlgorithm::Sha512, b"different data");
        let sri = wrong_integrity.to_string();

        assert!(verify_integrity(data, &sri).is_err());
    }

    #[test]
    fn verify_and_extract_full_pipeline() {
        let tgz = create_test_tarball("readme.md", b"# Hello");
        let integrity = Integrity::from_bytes(HashAlgorithm::Sha512, &tgz);
        let sri = integrity.to_string();
        let dir = tempfile::tempdir().unwrap();

        let files = verify_and_extract(&tgz, &sri, dir.path()).unwrap();

        assert_eq!(files.len(), 1);
        let content = std::fs::read_to_string(dir.path().join("readme.md")).unwrap();
        assert_eq!(content, "# Hello");
    }

    #[test]
    fn decompress_gzip_works() {
        let original = b"hello world compressed";
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(original).unwrap();
        let compressed = encoder.finish().unwrap();

        let decompressed = decompress_gzip(&compressed).unwrap();
        assert_eq!(decompressed, original);
    }

    #[test]
    fn strip_first_component_works() {
        assert_eq!(
            strip_first_component(Path::new("package/src/index.js")),
            Some(PathBuf::from("src/index.js"))
        );
        assert_eq!(
            strip_first_component(Path::new("package/file.txt")),
            Some(PathBuf::from("file.txt"))
        );
        // Just the prefix directory itself → None
        assert_eq!(strip_first_component(Path::new("package")), None);
    }
}
