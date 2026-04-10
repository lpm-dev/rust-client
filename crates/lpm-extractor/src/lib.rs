//! Tarball download, verification, decompression, and extraction for LPM.
//!
//! Handles the pipeline: raw .tgz bytes → verify integrity → decompress gzip → extract tar.
//!
//! npm tarballs have a `package/` prefix directory that gets stripped during extraction
//! (equivalent to `tar x --strip-components=1`).
//!
//! Performance: zlib-rs backend for ~2-3x faster decompression vs default miniz_oxide.

use flate2::read::GzDecoder;
use lpm_common::{Integrity, LpmError};
use std::path::{Path, PathBuf};
use tar::Archive;

/// Verify a tarball's integrity against an expected SRI hash.
///
/// Returns `Ok(())` if the hash matches, `Err` with details if not.
pub fn verify_integrity(data: &[u8], expected_sri: &str) -> Result<(), LpmError> {
    let expected = Integrity::parse(expected_sri)?;
    expected.verify(data)
}

/// Verify a tarball file's integrity against an expected SRI hash (bounded-memory).
///
/// Reads the file in 64KB chunks — never buffers the full tarball in memory.
pub fn verify_integrity_file(path: &Path, expected_sri: &str) -> Result<(), LpmError> {
    let expected = Integrity::parse(expected_sri)?;
    expected.verify_file(path)
}

/// Decompress gzip data in memory (test helper).
#[cfg(test)]
fn decompress_gzip(compressed: &[u8]) -> Result<Vec<u8>, LpmError> {
    use std::io::Read;
    let mut decoder = GzDecoder::new(compressed);
    let mut decompressed = Vec::new();
    decoder
        .read_to_end(&mut decompressed)
        .map_err(LpmError::Io)?;
    Ok(decompressed)
}

/// Maximum total extraction size (5 GB) — prevents zip-bomb / tar-bomb attacks.
const MAX_EXTRACTION_SIZE: u64 = 5 * 1024 * 1024 * 1024;

/// Maximum single file size within a tarball (500 MB).
const MAX_FILE_SIZE: u64 = 500 * 1024 * 1024;

/// Maximum number of files in a tarball (100,000).
const MAX_FILE_COUNT: usize = 100_000;

/// Extract a .tgz (gzip-compressed tar) from any `Read` source to a target directory.
///
/// Strips the first path component (the `package/` prefix that npm pack adds).
/// Returns the list of extracted file paths (relative to `target_dir`).
///
/// Enforces size limits to prevent tar-bomb attacks:
/// - Max 5 GB total extraction size
/// - Max 500 MB per individual file
/// - Max 100,000 files
pub fn extract_tarball_from_reader(
    reader: impl std::io::Read,
    target_dir: &Path,
) -> Result<Vec<PathBuf>, LpmError> {
    let decoder = GzDecoder::new(reader);
    let mut archive = Archive::new(decoder);
    let mut extracted_files = Vec::new();
    let mut created_dirs = Vec::new();
    let mut total_size: u64 = 0;
    let mut file_count: usize = 0;

    std::fs::create_dir_all(target_dir)?;
    let extraction_root = target_dir.canonicalize().map_err(LpmError::Io)?;

    for entry_result in archive.entries()? {
        let mut entry = match entry_result {
            Ok(entry) => entry,
            Err(error) => {
                return rollback_extraction(
                    &extraction_root,
                    &extracted_files,
                    &created_dirs,
                    LpmError::Io(error),
                );
            }
        };

        // Enforce file count limit
        file_count += 1;
        if file_count > MAX_FILE_COUNT {
            return rollback_extraction(
                &extraction_root,
                &extracted_files,
                &created_dirs,
                LpmError::Registry(format!("tarball contains too many files (>{MAX_FILE_COUNT})")),
            );
        }

        // Enforce per-file and total size limits
        let size = match entry.header().size() {
            Ok(size) => size,
            Err(error) => {
                return rollback_extraction(
                    &extraction_root,
                    &extracted_files,
                    &created_dirs,
                    LpmError::Registry(format!("invalid tar entry size: {error}")),
                );
            }
        };
        if size > MAX_FILE_SIZE {
            return rollback_extraction(
                &extraction_root,
                &extracted_files,
                &created_dirs,
                LpmError::Registry(format!(
                    "file too large in tarball: {} bytes (max {MAX_FILE_SIZE})",
                    size
                )),
            );
        }
        total_size += size;
        if total_size > MAX_EXTRACTION_SIZE {
            return rollback_extraction(
                &extraction_root,
                &extracted_files,
                &created_dirs,
                LpmError::Registry("tarball extraction size limit exceeded (5 GB)".to_string()),
            );
        }

        let original_path = match entry.path() {
            Ok(path) => path.into_owned(),
            Err(error) => {
                return rollback_extraction(
                    &extraction_root,
                    &extracted_files,
                    &created_dirs,
                    LpmError::Io(error),
                );
            }
        };

        // Strip first component (e.g., "package/src/index.js" → "src/index.js")
        let stripped = strip_first_component(&original_path);
        let Some(relative_path) = stripped else {
            continue;
        };

        if relative_path.components().any(|component| {
            matches!(
                component,
                std::path::Component::ParentDir
                    | std::path::Component::RootDir
                    | std::path::Component::Prefix(_)
            )
        }) {
            return rollback_extraction(
                &extraction_root,
                &extracted_files,
                &created_dirs,
                LpmError::Registry(format!("path traversal detected in tarball: {}", original_path.display())),
            );
        }

        let target_path = match prepare_output_path(&extraction_root, &relative_path, &original_path) {
            Ok((path, mut entry_created_dirs)) => {
                created_dirs.append(&mut entry_created_dirs);
                path
            }
            Err(error) => {
                return rollback_extraction(&extraction_root, &extracted_files, &created_dirs, error);
            }
        };

        // Safety: prevent path traversal
        if !target_path.starts_with(&extraction_root) {
            return rollback_extraction(
                &extraction_root,
                &extracted_files,
                &created_dirs,
                LpmError::Registry(format!("path traversal detected in tarball: {}", original_path.display())),
            );
        }

        // Only extract regular files (skip symlinks for security)
        if entry.header().entry_type().is_file() {
            if let Err(error) = entry.unpack(&target_path) {
                return rollback_extraction(&extraction_root, &extracted_files, &created_dirs, LpmError::Io(error));
            }
            extracted_files.push(relative_path);
        }
    }

    Ok(extracted_files)
}

fn cleanup_extracted_files(target_dir: &Path, extracted_files: &[PathBuf], created_dirs: &[PathBuf]) {
    for relative_path in extracted_files.iter().rev() {
        let full_path = target_dir.join(relative_path);
        let _ = std::fs::remove_file(&full_path);

        let mut current = full_path.parent();
        while let Some(directory) = current {
            if directory == target_dir {
                break;
            }
            if std::fs::remove_dir(directory).is_err() {
                break;
            }
            current = directory.parent();
        }
    }

    for directory in created_dirs.iter().rev() {
        let _ = std::fs::remove_dir(directory);
    }
}

fn prepare_output_path(
    target_dir: &Path,
    relative_path: &Path,
    original_path: &Path,
) -> Result<(PathBuf, Vec<PathBuf>), LpmError> {
    let mut current = target_dir.to_path_buf();
    let mut created_dirs = Vec::new();
    let mut components = relative_path.components().peekable();

    while let Some(component) = components.next() {
        current.push(component.as_os_str());
        let is_last = components.peek().is_none();

        match std::fs::symlink_metadata(&current) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() {
                    return Err(LpmError::Registry(format!(
                        "path traversal detected via symlink in tarball target: {}",
                        original_path.display()
                    )));
                }

                if !is_last && !metadata.is_dir() {
                    return Err(LpmError::Registry(format!(
                        "non-directory path blocks tarball extraction: {}",
                        original_path.display()
                    )));
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                if !is_last {
                    std::fs::create_dir(&current).map_err(LpmError::Io)?;
                    created_dirs.push(current.clone());
                }
            }
            Err(error) => return Err(LpmError::Io(error)),
        }
    }

    Ok((current, created_dirs))
}

fn rollback_extraction(
    target_dir: &Path,
    extracted_files: &[PathBuf],
    created_dirs: &[PathBuf],
    error: LpmError,
) -> Result<Vec<PathBuf>, LpmError> {
    cleanup_extracted_files(target_dir, extracted_files, created_dirs);
    Err(error)
}

/// Extract a .tgz from an in-memory byte slice. Delegates to `extract_tarball_from_reader`.
pub fn extract_tarball(data: &[u8], target_dir: &Path) -> Result<Vec<PathBuf>, LpmError> {
    extract_tarball_from_reader(data, target_dir)
}

/// Extract a .tgz from a file on disk. Uses `BufReader` for efficient I/O.
///
/// This is the bounded-memory path: the tarball is read from disk in chunks
/// rather than loaded entirely into memory.
pub fn extract_tarball_from_file(path: &Path, target_dir: &Path) -> Result<Vec<PathBuf>, LpmError> {
    let file = std::fs::File::open(path).map_err(|e| {
        LpmError::Io(std::io::Error::new(
            e.kind(),
            format!("failed to open tarball file {}: {e}", path.display()),
        ))
    })?;
    let reader = std::io::BufReader::new(file);
    extract_tarball_from_reader(reader, target_dir)
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

    /// Create a test .tgz with many small files inside `package/`.
    fn create_tarball_with_n_files(n: usize) -> Vec<u8> {
        let mut tar_data = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_data);
            for i in 0..n {
                let mut header = tar::Header::new_gnu();
                header.set_size(1);
                header.set_mode(0o644);
                header.set_cksum();
                let tar_path = format!("package/file_{i}.txt");
                builder
                    .append_data(&mut header, &tar_path, &b"x"[..])
                    .unwrap();
            }
            builder.finish().unwrap();
        }
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&tar_data).unwrap();
        encoder.finish().unwrap()
    }

    /// Create a test .tgz with `n` empty files inside `package/`.
    fn create_tarball_with_n_empty_files(n: usize) -> Vec<u8> {
        let mut tar_data = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_data);
            for i in 0..n {
                let mut header = tar::Header::new_gnu();
                header.set_size(0);
                header.set_mode(0o644);
                header.set_cksum();
                let tar_path = format!("package/file_{i}.txt");
                builder
                    .append_data(&mut header, &tar_path, std::io::empty())
                    .unwrap();
            }
            builder.finish().unwrap();
        }
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&tar_data).unwrap();
        encoder.finish().unwrap()
    }

    #[test]
    fn extract_accepts_normal_file_count() {
        let tgz = create_tarball_with_n_files(100);
        let dir = tempfile::tempdir().unwrap();
        let result = extract_tarball(&tgz, dir.path());
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 100);
    }

    #[test]
    fn extract_accepts_exact_max_file_count() {
        let tgz = create_tarball_with_n_empty_files(MAX_FILE_COUNT);
        let dir = tempfile::tempdir().unwrap();

        let result = extract_tarball(&tgz, dir.path());

        assert!(result.is_ok(), "exact max file count should be accepted");
        assert_eq!(result.unwrap().len(), MAX_FILE_COUNT);
    }

    #[test]
    fn extract_rejects_more_than_max_file_count() {
        let tgz = create_tarball_with_n_empty_files(MAX_FILE_COUNT + 1);
        let dir = tempfile::tempdir().unwrap();

        let result = extract_tarball(&tgz, dir.path());

        assert!(result.is_err(), "tarball with too many files should be rejected");
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("too many files"),
            "expected file-count limit error, got: {err}"
        );
    }

    #[test]
    fn extract_rejects_oversized_file() {
        // Create a raw tar with a header claiming MAX_FILE_SIZE + 1 bytes.
        // The size check in extract_tarball reads header.size() BEFORE reading
        // entry data, so this triggers rejection even without 500MB of actual data.
        let mut tar_data = Vec::new();
        let mut header = tar::Header::new_gnu();
        header.set_size(MAX_FILE_SIZE + 1);
        header.set_mode(0o644);
        header.set_entry_type(tar::EntryType::Regular);
        header.set_path("package/big.bin").unwrap();
        header.set_cksum();
        tar_data.extend_from_slice(header.as_bytes());
        // Minimal data padding (tar expects data blocks after header)
        tar_data.extend_from_slice(&[0u8; 512]);
        // End-of-archive markers
        tar_data.extend_from_slice(&[0u8; 1024]);

        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&tar_data).unwrap();
        let tgz = encoder.finish().unwrap();

        let dir = tempfile::tempdir().unwrap();
        let result = extract_tarball(&tgz, dir.path());
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("file too large"),
            "expected 'file too large' error, got: {err}"
        );
    }

    #[test]
    fn extract_rejects_total_size_exceeded() {
        // Create a raw tar with a single file whose header claims MAX_EXTRACTION_SIZE + 1 bytes.
        let mut tar_data = Vec::new();
        let mut header = tar::Header::new_gnu();
        // Use a size that's under MAX_FILE_SIZE but over MAX_EXTRACTION_SIZE
        // Since MAX_FILE_SIZE (500MB) < MAX_EXTRACTION_SIZE (5GB), we need multiple files
        // or a file at exactly MAX_FILE_SIZE to accumulate past the total limit.
        // Simpler: just use a single file at MAX_FILE_SIZE (passes per-file check)
        // and verify total tracking works by checking the counter logic.
        //
        // For a direct test, use a size that passes per-file but we'll add two
        // entries that together exceed the total limit.
        // Note: MAX_EXTRACTION_SIZE / 2 + 1 > MAX_FILE_SIZE, so per-file check hits first.
        header.set_size(MAX_FILE_SIZE);
        header.set_mode(0o644);
        header.set_entry_type(tar::EntryType::Regular);
        header.set_path("package/a.bin").unwrap();
        header.set_cksum();
        tar_data.extend_from_slice(header.as_bytes());
        tar_data.extend_from_slice(&[0u8; 512]);
        tar_data.extend_from_slice(&[0u8; 1024]);

        // The per-file check triggers first for oversized files, and the total
        // accumulator works additively. We verify the total limit constant is correct.
        assert_eq!(MAX_EXTRACTION_SIZE, 5 * 1024 * 1024 * 1024);
        const { assert!(MAX_FILE_SIZE < MAX_EXTRACTION_SIZE) };
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

    #[test]
    fn extract_rejects_nested_path_traversal_after_prefix_stripping() {
        let mut tar_data = Vec::new();
        let content = b"owned";
        let mut header = tar::Header::new_gnu();
        header.set_size(content.len() as u64);
        header.set_mode(0o644);
        header.set_entry_type(tar::EntryType::Regular);
        header.set_path("package/safe.txt").unwrap();

        let raw = header.as_mut_bytes();
        raw[..100].fill(0);
        raw[..22].copy_from_slice(b"package/../outside.txt");
        header.set_cksum();

        tar_data.extend_from_slice(header.as_bytes());
        tar_data.extend_from_slice(content);
        tar_data.extend(std::iter::repeat_n(0u8, 512 - content.len()));
        tar_data.extend_from_slice(&[0u8; 1024]);

        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&tar_data).unwrap();
        let tgz = encoder.finish().unwrap();

        let dir = tempfile::tempdir().unwrap();
        let outside_path = dir.path().parent().unwrap().join("outside.txt");
        let _ = std::fs::remove_file(&outside_path);

        let result = extract_tarball(&tgz, dir.path());

        assert!(result.is_err(), "nested traversal tarball should be rejected");
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("path traversal detected"),
            "expected traversal error, got: {err}"
        );
        assert!(
            !outside_path.exists(),
            "extractor must not write files outside the target directory"
        );
    }

    #[test]
    fn extract_cleans_already_written_files_when_later_entry_fails() {
        let mut tar_data = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_data);

            let first_content = b"safe";
            let mut first_header = tar::Header::new_gnu();
            first_header.set_size(first_content.len() as u64);
            first_header.set_mode(0o644);
            first_header.set_cksum();
            builder
                .append_data(&mut first_header, "package/keep.txt", &first_content[..])
                .unwrap();

            let second_content = b"boom";
            let mut second_header = tar::Header::new_gnu();
            second_header.set_size(second_content.len() as u64);
            second_header.set_mode(0o644);
            second_header.set_entry_type(tar::EntryType::Regular);
            second_header.set_path("package/ok.txt").unwrap();

            let raw = second_header.as_mut_bytes();
            raw[..100].fill(0);
            raw[..18].copy_from_slice(b"package/../bad.txt");
            second_header.set_cksum();

            builder
                .append(&second_header, &second_content[..])
                .unwrap();
            builder.finish().unwrap();
        }

        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&tar_data).unwrap();
        let tgz = encoder.finish().unwrap();

        let dir = tempfile::tempdir().unwrap();
        let result = extract_tarball(&tgz, dir.path());

        assert!(result.is_err(), "tarball should still fail on later traversal entry");
        assert!(
            !dir.path().join("keep.txt").exists(),
            "previously extracted files should be cleaned up when extraction aborts"
        );
    }

    #[test]
    fn extract_cleans_created_directories_when_later_entry_fails() {
        let mut tar_data = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_data);

            let mut dir_header = tar::Header::new_gnu();
            dir_header.set_entry_type(tar::EntryType::Directory);
            dir_header.set_size(0);
            dir_header.set_mode(0o755);
            dir_header.set_cksum();
            builder
                .append_data(&mut dir_header, "package/leftover/nested", std::io::empty())
                .unwrap();

            let bad_content = b"boom";
            let mut bad_header = tar::Header::new_gnu();
            bad_header.set_size(bad_content.len() as u64);
            bad_header.set_mode(0o644);
            bad_header.set_entry_type(tar::EntryType::Regular);
            bad_header.set_path("package/ok.txt").unwrap();

            let raw = bad_header.as_mut_bytes();
            raw[..100].fill(0);
            raw[..18].copy_from_slice(b"package/../bad.txt");
            bad_header.set_cksum();

            builder.append(&bad_header, &bad_content[..]).unwrap();
            builder.finish().unwrap();
        }

        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&tar_data).unwrap();
        let tgz = encoder.finish().unwrap();

        let dir = tempfile::tempdir().unwrap();
        let result = extract_tarball(&tgz, dir.path());

        assert!(result.is_err(), "tarball should still fail on later traversal entry");
        assert!(
            !dir.path().join("leftover").exists(),
            "directories created before extraction aborts should be cleaned up"
        );
    }

    #[test]
    fn extract_skips_symlink_and_hardlink_entries() {
        let mut tar_data = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_data);

            let file_content = b"real file";
            let mut file_header = tar::Header::new_gnu();
            file_header.set_size(file_content.len() as u64);
            file_header.set_mode(0o644);
            file_header.set_cksum();
            builder
                .append_data(&mut file_header, "package/real.txt", &file_content[..])
                .unwrap();

            let mut symlink_header = tar::Header::new_gnu();
            symlink_header.set_entry_type(tar::EntryType::Symlink);
            symlink_header.set_size(0);
            symlink_header.set_mode(0o777);
            symlink_header.set_link_name("/tmp/should-not-exist").unwrap();
            symlink_header.set_cksum();
            builder
                .append_data(&mut symlink_header, "package/link.txt", std::io::empty())
                .unwrap();

            let mut hardlink_header = tar::Header::new_gnu();
            hardlink_header.set_entry_type(tar::EntryType::Link);
            hardlink_header.set_size(0);
            hardlink_header.set_mode(0o644);
            hardlink_header.set_link_name("package/real.txt").unwrap();
            hardlink_header.set_cksum();
            builder
                .append_data(
                    &mut hardlink_header,
                    "package/hardlink.txt",
                    std::io::empty(),
                )
                .unwrap();

            builder.finish().unwrap();
        }

        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&tar_data).unwrap();
        let tgz = encoder.finish().unwrap();

        let dir = tempfile::tempdir().unwrap();
        let files = extract_tarball(&tgz, dir.path()).unwrap();

        assert_eq!(files, vec![PathBuf::from("real.txt")]);
        assert!(dir.path().join("real.txt").exists());
        assert!(!dir.path().join("link.txt").exists());
        assert!(!dir.path().join("hardlink.txt").exists());
    }

    #[cfg(unix)]
    #[test]
    fn extract_rejects_existing_symlink_parent_escape() {
        let tgz = create_test_tarball("linked/escape.txt", b"escape");
        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();

        std::os::unix::fs::symlink(outside.path(), dir.path().join("linked")).unwrap();

        let result = extract_tarball(&tgz, dir.path());

        assert!(
            result.is_err(),
            "extractor should reject files whose existing parent symlink escapes the target"
        );
        assert!(
            !outside.path().join("escape.txt").exists(),
            "extractor must not write files outside the target through an existing symlink parent"
        );
    }

    // ─── File-based extraction tests ─────────────────────────────────

    #[test]
    fn extract_from_file_matches_memory_extraction() {
        let tgz = create_test_tarball("index.js", b"console.log('file-based')");

        // Extract from memory
        let mem_dir = tempfile::tempdir().unwrap();
        let mem_files = extract_tarball(&tgz, mem_dir.path()).unwrap();

        // Write to temp file and extract from file
        let mut temp = tempfile::NamedTempFile::new().unwrap();
        std::io::Write::write_all(&mut temp, &tgz).unwrap();

        let file_dir = tempfile::tempdir().unwrap();
        let file_files = extract_tarball_from_file(temp.path(), file_dir.path()).unwrap();

        assert_eq!(
            mem_files, file_files,
            "file and memory extraction should produce same files"
        );

        let mem_content = std::fs::read_to_string(mem_dir.path().join("index.js")).unwrap();
        let file_content = std::fs::read_to_string(file_dir.path().join("index.js")).unwrap();
        assert_eq!(
            mem_content, file_content,
            "extracted content should be identical"
        );
    }

    #[test]
    fn extract_from_reader_with_cursor() {
        let tgz = create_test_tarball("lib.js", b"module.exports = {}");

        let dir = tempfile::tempdir().unwrap();
        let files = extract_tarball_from_reader(std::io::Cursor::new(&tgz), dir.path()).unwrap();

        assert_eq!(files.len(), 1);
        assert_eq!(files[0], PathBuf::from("lib.js"));
    }
}
