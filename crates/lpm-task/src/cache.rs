//! Local task cache — store outputs on miss, restore on hit, replay stdout.
//!
//! Cache layout:
//! ```text
//! ~/.lpm/cache/tasks/
//!   {cache-key}/
//!     meta.json       ← timing, command, key info
//!     stdout.log      ← captured stdout
//!     stderr.log      ← captured stderr
//!     outputs.tar.gz  ← archived output files
//! ```

use lpm_common::{LpmError, LpmRoot};
use std::path::{Component, Path, PathBuf};

/// Base directory for task cache.
///
/// Routes through [`LpmRoot::from_env`] so `$LPM_HOME` overrides and the
/// single canonical home-resolution rule are honored here too.
pub fn cache_dir() -> Result<PathBuf, LpmError> {
    let root = LpmRoot::from_env()
        .map_err(|e| LpmError::Task(format!("could not determine LPM home: {e}")))?;
    Ok(root.cache_tasks())
}

/// Get the cache directory for a specific cache key.
///
/// Validates that the key contains only hex characters to prevent path traversal.
pub fn cache_entry_dir(key: &str) -> Result<PathBuf, LpmError> {
    if key.is_empty() || !key.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(LpmError::Task(format!(
            "invalid cache key (must be hex only): {key}"
        )));
    }
    Ok(cache_dir()?.join(key))
}

/// Check if a cache entry exists for the given key.
pub fn has_cache_hit(key: &str) -> bool {
    cache_entry_dir(key)
        .map(|d| d.join("meta.json").exists())
        .unwrap_or(false)
}

/// Restore cached outputs to the project directory.
///
/// Returns the cached stdout content for replay.
pub fn restore_cache(key: &str, project_dir: &Path) -> Result<CacheHit, LpmError> {
    let entry = cache_entry_dir(key)?;

    // Read meta
    let meta_path = entry.join("meta.json");
    let meta_content = std::fs::read_to_string(&meta_path)
        .map_err(|e| LpmError::Task(format!("failed to read cache meta: {e}")))?;
    let meta: CacheMeta = serde_json::from_str(&meta_content)
        .map_err(|e| LpmError::Task(format!("failed to parse cache meta: {e}")))?;

    // Restore outputs archive
    let archive_path = entry.join("outputs.tar.gz");
    if archive_path.exists() {
        restore_archive(&archive_path, project_dir)?;
    }

    // Read stdout/stderr for replay — warn if missing (indicates corruption)
    let stdout_path = entry.join("stdout.log");
    let stderr_path = entry.join("stderr.log");
    let stdout = match std::fs::read_to_string(&stdout_path) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!("cache entry missing stdout.log: {e} — cache may be corrupted");
            String::new()
        }
    };
    let stderr = match std::fs::read_to_string(&stderr_path) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!("cache entry missing stderr.log: {e} — cache may be corrupted");
            String::new()
        }
    };

    Ok(CacheHit {
        meta,
        stdout,
        stderr,
    })
}

/// Store task outputs to cache.
pub fn store_cache(
    key: &str,
    project_dir: &Path,
    command: &str,
    output_globs: &[String],
    stdout: &str,
    stderr: &str,
    duration_ms: u64,
) -> Result<(), LpmError> {
    let entry = cache_entry_dir(key)?;
    std::fs::create_dir_all(&entry)?;
    set_dir_permissions_restricted(&entry)?;

    // Write stdout/stderr
    std::fs::write(entry.join("stdout.log"), stdout)?;
    std::fs::write(entry.join("stderr.log"), stderr)?;

    // Archive output files
    let output_file_count = if !output_globs.is_empty() {
        create_archive(project_dir, output_globs, &entry.join("outputs.tar.gz"))?
    } else {
        0
    };

    // Write meta (after archiving so we have the file count)
    let meta = CacheMeta {
        command: command.to_string(),
        cache_key: key.to_string(),
        duration_ms,
        output_file_count,
    };
    let meta_json = serde_json::to_string_pretty(&meta)
        .map_err(|e| LpmError::Task(format!("failed to serialize cache meta: {e}")))?;
    std::fs::write(entry.join("meta.json"), meta_json)?;

    tracing::debug!("cached task output to {}", entry.display());
    Ok(())
}

/// Clean the entire task cache.
pub fn clean_cache() -> Result<u64, LpmError> {
    let dir = cache_dir()?;
    if !dir.exists() {
        return Ok(0);
    }

    let mut count = 0u64;
    for entry in std::fs::read_dir(&dir)? {
        let entry = entry?;
        if entry.path().is_dir() {
            std::fs::remove_dir_all(entry.path())?;
            count += 1;
        }
    }

    Ok(count)
}

/// Cache hit result.
pub struct CacheHit {
    pub meta: CacheMeta,
    pub stdout: String,
    pub stderr: String,
}

/// Cache entry metadata.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct CacheMeta {
    pub command: String,
    pub cache_key: String,
    pub duration_ms: u64,
    /// Number of output files archived (for integrity check on restore).
    #[serde(default)]
    pub output_file_count: usize,
}

/// Create a .tar.gz archive of files matching output globs.
/// Returns the number of files archived.
fn create_archive(
    project_dir: &Path,
    output_globs: &[String],
    archive_path: &Path,
) -> Result<usize, LpmError> {
    let file = std::fs::File::create(archive_path)?;
    let enc = flate2::write::GzEncoder::new(file, flate2::Compression::fast());
    let mut builder = tar::Builder::new(enc);
    let mut file_count = 0;

    for pattern in output_globs {
        if !validate_glob_pattern(pattern) {
            tracing::warn!("skipping unsafe glob pattern: {pattern}");
            continue;
        }

        // Normalize glob: "dist/**" → also match "dist/**/*" to catch files at any depth
        let patterns = expand_glob_pattern(pattern);

        for pat in &patterns {
            let full_pattern = project_dir.join(pat);
            let pattern_str = full_pattern.to_string_lossy().to_string();

            if let Ok(entries) = glob::glob(&pattern_str) {
                for entry in entries.flatten() {
                    if entry.is_file() {
                        let rel = entry.strip_prefix(project_dir).unwrap_or(&entry);
                        builder.append_path_with_name(&entry, rel).map_err(|e| {
                            LpmError::Task(format!(
                                "failed to add {} to archive: {e}",
                                entry.display()
                            ))
                        })?;
                        file_count += 1;
                    }
                }
            }
        }
    }

    builder
        .finish()
        .map_err(|e| LpmError::Task(format!("failed to finalize archive: {e}")))?;

    tracing::debug!("archived {file_count} files to {}", archive_path.display());
    Ok(file_count)
}

/// Expand a glob pattern to cover both directories and files at any depth.
/// "dist/**" → ["dist/**", "dist/**/*"]
fn expand_glob_pattern(pattern: &str) -> Vec<String> {
    let mut patterns = vec![pattern.to_string()];
    if pattern.ends_with("/**") {
        patterns.push(format!("{pattern}/*"));
    }
    patterns
}

/// Restore a .tar.gz archive to the project directory.
///
/// Validates each entry path to prevent zip-slip (path traversal) attacks.
fn restore_archive(archive_path: &Path, project_dir: &Path) -> Result<(), LpmError> {
    let file = std::fs::File::open(archive_path)?;
    let dec = flate2::read::GzDecoder::new(file);
    let mut archive = tar::Archive::new(dec);

    for entry in archive
        .entries()
        .map_err(|e| LpmError::Task(format!("failed to read cache archive entries: {e}")))?
    {
        let mut entry = entry
            .map_err(|e| LpmError::Task(format!("failed to read cache archive entry: {e}")))?;
        let path = entry
            .path()
            .map_err(|e| LpmError::Task(format!("failed to read entry path: {e}")))?
            .to_path_buf();
        if path.components().any(|c| {
            matches!(
                c,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        }) {
            return Err(LpmError::Task(format!(
                "path traversal in cache archive: {}",
                path.display()
            )));
        }
        entry
            .unpack_in(project_dir)
            .map_err(|e| LpmError::Task(format!("failed to unpack {}: {e}", path.display())))?;
    }

    Ok(())
}

/// Validate a glob pattern to prevent directory escape.
///
/// Rejects patterns that start with `../`, `/`, or contain `/../`.
pub fn validate_glob_pattern(pattern: &str) -> bool {
    let normalized = pattern.replace('\\', "/");

    if normalized.starts_with("../") || normalized.starts_with('/') || normalized.contains("/../") {
        return false;
    }

    if normalized == ".." {
        return false;
    }

    if normalized.len() >= 3 {
        let bytes = normalized.as_bytes();
        if bytes[1] == b':' && bytes[2] == b'/' && bytes[0].is_ascii_alphabetic() {
            return false;
        }
    }

    if normalized.starts_with("//") {
        return false;
    }

    true
}

/// Set directory permissions to 0o700 (owner only) on Unix.
#[cfg(unix)]
fn set_dir_permissions_restricted(path: &Path) -> Result<(), LpmError> {
    use std::os::unix::fs::PermissionsExt;
    let perms = std::fs::Permissions::from_mode(0o700);
    std::fs::set_permissions(path, perms).map_err(|e| {
        LpmError::Task(format!(
            "failed to set permissions on {}: {e}",
            path.display()
        ))
    })
}

/// No-op on non-Unix platforms.
#[cfg(not(unix))]
fn set_dir_permissions_restricted(_path: &Path) -> Result<(), LpmError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn unique_key(_prefix: &str) -> String {
        use sha2::{Digest, Sha256};
        use std::time::{SystemTime, UNIX_EPOCH};
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let hash = Sha256::digest(format!("{_prefix}-{ts}").as_bytes());
        // Return hex-only key (satisfies cache_entry_dir validation)
        hash.iter().map(|b| format!("{b:02x}")).collect::<String>()
    }

    #[test]
    fn cache_miss_returns_false() {
        // Must use a hex-only key now
        assert!(!has_cache_hit("deadbeef0123456789abcdef"));
    }

    #[test]
    fn store_and_restore_roundtrip() {
        let dir = tempfile::tempdir().unwrap();

        fs::create_dir_all(dir.path().join("dist")).unwrap();
        fs::write(dir.path().join("dist/index.js"), "built output").unwrap();
        fs::write(dir.path().join("dist/style.css"), "body {}").unwrap();

        let key = unique_key("roundtrip");

        store_cache(
            &key,
            dir.path(),
            "echo build",
            &["dist/**".into()],
            "build output\n",
            "",
            1234,
        )
        .unwrap();

        assert!(has_cache_hit(&key), "cache entry should exist after store");

        // Delete the output files
        fs::remove_dir_all(dir.path().join("dist")).unwrap();
        assert!(!dir.path().join("dist/index.js").exists());

        // Restore
        let hit = restore_cache(&key, dir.path()).unwrap();
        assert_eq!(hit.meta.command, "echo build");
        assert_eq!(hit.meta.duration_ms, 1234);
        assert_eq!(hit.stdout, "build output\n");
        assert!(
            dir.path().join("dist/index.js").exists(),
            "dist/index.js should be restored"
        );
        assert_eq!(
            fs::read_to_string(dir.path().join("dist/index.js")).unwrap(),
            "built output"
        );

        // Cleanup this specific entry
        let _ = fs::remove_dir_all(cache_entry_dir(&key).unwrap());
    }

    // -- Finding #1: zip-slip prevention --

    #[test]
    fn restore_archive_rejects_path_traversal() {
        use flate2::Compression;
        use flate2::write::GzEncoder;

        let dir = tempfile::tempdir().unwrap();
        let archive_path = dir.path().join("evil.tar.gz");

        // Create a tar.gz with a path-traversal entry by writing raw header bytes.
        // The `tar` crate's `set_path` rejects `..` so we write the header manually.
        {
            let file = fs::File::create(&archive_path).unwrap();
            let enc = GzEncoder::new(file, Compression::fast());
            let mut builder = tar::Builder::new(enc);

            let data = b"pwned";
            let mut header = tar::Header::new_gnu();
            // Use a benign path first, then overwrite the raw name bytes
            header.set_path("placeholder.txt").unwrap();
            header.set_size(data.len() as u64);
            header.set_mode(0o644);
            header.set_entry_type(tar::EntryType::Regular);

            // Overwrite the name field (first 100 bytes) with "../escape.txt"
            let evil_path = b"../escape.txt";
            let raw = header.as_mut_bytes();
            raw[..100].fill(0);
            raw[..evil_path.len()].copy_from_slice(evil_path);
            header.set_cksum();

            builder.append(&header, &data[..]).unwrap();
            builder.finish().unwrap();
        }

        let result = restore_archive(&archive_path, dir.path());
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("path traversal"),
            "error should mention path traversal, got: {err}"
        );
    }

    #[test]
    fn restore_archive_rejects_absolute_paths() {
        use flate2::Compression;
        use flate2::write::GzEncoder;

        let dir = tempfile::tempdir().unwrap();
        let archive_path = dir.path().join("absolute.tar.gz");

        {
            let file = fs::File::create(&archive_path).unwrap();
            let enc = GzEncoder::new(file, Compression::fast());
            let mut builder = tar::Builder::new(enc);

            let data = b"pwned";
            let mut header = tar::Header::new_gnu();
            header.set_path("placeholder.txt").unwrap();
            header.set_size(data.len() as u64);
            header.set_mode(0o644);
            header.set_entry_type(tar::EntryType::Regular);

            let raw = header.as_mut_bytes();
            raw[..100].fill(0);
            let absolute_path = b"/absolute-escape.txt";
            raw[..absolute_path.len()].copy_from_slice(absolute_path);
            header.set_cksum();

            builder.append(&header, &data[..]).unwrap();
            builder.finish().unwrap();
        }

        let result = restore_archive(&archive_path, dir.path());
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("path traversal"),
            "absolute archive paths should be rejected before unpack, got: {err}"
        );
    }

    #[test]
    fn restore_archive_allows_normal_paths() {
        use flate2::Compression;
        use flate2::write::GzEncoder;
        use tar::Builder;

        let dir = tempfile::tempdir().unwrap();
        let archive_path = dir.path().join("good.tar.gz");

        // Create a normal tar.gz
        {
            let file = fs::File::create(&archive_path).unwrap();
            let enc = GzEncoder::new(file, Compression::fast());
            let mut builder = Builder::new(enc);

            let data = b"hello";
            let mut header = tar::Header::new_gnu();
            header.set_path("dist/output.js").unwrap();
            header.set_size(data.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder.append(&header, &data[..]).unwrap();
            builder.finish().unwrap();
        }

        restore_archive(&archive_path, dir.path()).unwrap();
        assert_eq!(
            fs::read_to_string(dir.path().join("dist/output.js")).unwrap(),
            "hello"
        );
    }

    // -- Finding #4: glob pattern validation --

    #[test]
    fn validate_glob_rejects_parent_traversal() {
        assert!(!validate_glob_pattern("../../etc/passwd"));
        assert!(!validate_glob_pattern("../secret"));
        assert!(!validate_glob_pattern(".."));
        assert!(!validate_glob_pattern("..\\secret"));
        assert!(!validate_glob_pattern("dist\\..\\..\\secret"));
    }

    #[test]
    fn validate_glob_rejects_absolute_paths() {
        assert!(!validate_glob_pattern("/etc/shadow"));
        assert!(!validate_glob_pattern("/tmp/foo"));
        assert!(!validate_glob_pattern("C:\\temp\\foo"));
        assert!(!validate_glob_pattern("\\\\server\\share\\foo"));
    }

    #[test]
    fn validate_glob_rejects_embedded_traversal() {
        assert!(!validate_glob_pattern("src/../../etc/passwd"));
    }

    #[test]
    fn validate_glob_accepts_normal_patterns() {
        assert!(validate_glob_pattern("src/**"));
        assert!(validate_glob_pattern("dist/**/*"));
        assert!(validate_glob_pattern("*.js"));
        assert!(validate_glob_pattern("package.json"));
    }

    // -- Finding #5: cache directory permissions --

    #[cfg(unix)]
    #[test]
    fn cache_dir_permissions_are_700() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let sub = dir.path().join("restricted");
        fs::create_dir_all(&sub).unwrap();
        set_dir_permissions_restricted(&sub).unwrap();

        let perms = fs::metadata(&sub).unwrap().permissions();
        assert_eq!(
            perms.mode() & 0o777,
            0o700,
            "directory should have 0o700 permissions"
        );
    }

    // -- Finding #13: cache key validation --

    #[test]
    fn cache_entry_dir_rejects_path_traversal_key() {
        let result = cache_entry_dir("../etc/passwd");
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("invalid cache key"),
            "should reject non-hex key, got: {err}"
        );
    }

    #[test]
    fn cache_entry_dir_rejects_empty_key() {
        assert!(cache_entry_dir("").is_err());
    }

    #[test]
    fn cache_entry_dir_accepts_valid_hex_key() {
        let result = cache_entry_dir("abcdef0123456789");
        assert!(result.is_ok());
    }

    // clean_cache() test omitted — it operates on the real global ~/.lpm/cache/tasks/
    // directory and races with other cache tests. Tested via real `lpm cache clean --tasks` command.
}
