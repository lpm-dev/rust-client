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
use std::io::{Read, Write};
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
    cache_entry_dir(key).is_ok_and(|d| d.join("meta.json").exists())
}

/// Restore cached outputs to the project directory.
///
/// Returns the cached stdout content for replay.
pub fn restore_cache(key: &str, project_dir: &Path) -> Result<CacheHit, LpmError> {
    let entry = cache_entry_dir(key)?;

    // Read meta
    let meta_path = entry.join("meta.json");
    let meta_bytes =
        lpm_common::read_capped_state_file(&meta_path, lpm_common::STATE_FILE_SIZE_CAP_BYTES)
            .map_err(|e| LpmError::Task(format!("failed to read cache meta: {e}")))?
            .ok_or_else(|| LpmError::Task("cache meta is missing or oversized".into()))?;
    let meta: CacheMeta = serde_json::from_slice(&meta_bytes)
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

pub struct RemoteArtifactCreate<'a> {
    pub key: &'a str,
    pub project_dir: &'a Path,
    pub command: &'a str,
    pub output_globs: &'a [String],
    pub stdout: &'a str,
    pub stderr: &'a str,
    pub duration_ms: u64,
    pub artifact_path: &'a Path,
}

/// Create a portable remote-cache artifact for a successful task run.
pub fn create_remote_artifact(args: RemoteArtifactCreate<'_>) -> Result<(), LpmError> {
    let file = std::fs::File::create(args.artifact_path)?;
    let enc = flate2::write::GzEncoder::new(file, flate2::Compression::fast());
    let mut builder = tar::Builder::new(enc);

    let output_file_count = append_output_files(
        &mut builder,
        args.project_dir,
        args.output_globs,
        Some(Path::new("outputs")),
    )?;

    let meta = CacheMeta {
        command: args.command.to_string(),
        cache_key: args.key.to_string(),
        duration_ms: args.duration_ms,
        output_file_count,
    };
    let meta_json = serde_json::to_string_pretty(&meta)
        .map_err(|e| LpmError::Task(format!("failed to serialize remote cache meta: {e}")))?;

    append_bytes(
        &mut builder,
        Path::new(".lpm-cache/meta.json"),
        meta_json.as_bytes(),
    )?;
    append_bytes(
        &mut builder,
        Path::new(".lpm-cache/stdout.log"),
        args.stdout.as_bytes(),
    )?;
    append_bytes(
        &mut builder,
        Path::new(".lpm-cache/stderr.log"),
        args.stderr.as_bytes(),
    )?;

    builder
        .finish()
        .map_err(|e| LpmError::Task(format!("failed to finalize remote cache artifact: {e}")))?;

    Ok(())
}

/// Restore a portable remote-cache artifact into a project directory.
pub fn restore_remote_artifact(
    expected_key: &str,
    artifact_path: &Path,
    project_dir: &Path,
) -> Result<CacheHit, LpmError> {
    let file = std::fs::File::open(artifact_path)?;
    let dec = flate2::read::GzDecoder::new(file);
    let mut archive = tar::Archive::new(dec);
    archive.set_preserve_permissions(false);
    archive.set_preserve_ownerships(false);

    let mut total_bytes: u64 = 0;
    let mut entries_seen: usize = 0;
    let mut meta_json: Option<String> = None;
    let mut stdout = String::new();
    let mut stderr = String::new();
    let mut output_file_count = 0usize;

    for entry in archive
        .entries()
        .map_err(|e| LpmError::Task(format!("failed to read remote cache artifact entries: {e}")))?
    {
        let mut entry = entry.map_err(|e| {
            LpmError::Task(format!("failed to read remote cache artifact entry: {e}"))
        })?;

        entries_seen += 1;
        if entries_seen > MAX_CACHE_ARCHIVE_ENTRIES {
            return Err(LpmError::Task(format!(
                "remote cache artifact exceeds entry-count cap ({MAX_CACHE_ARCHIVE_ENTRIES} entries)"
            )));
        }

        let path = entry
            .path()
            .map_err(|e| LpmError::Task(format!("failed to read entry path: {e}")))?
            .to_path_buf();
        validate_archive_path(&path, "remote cache artifact")?;
        validate_archive_entry_type(&entry, &path, "remote cache artifact")?;

        let entry_size = entry.header().size().unwrap_or(0);
        check_archive_size_limits(entry_size, &mut total_bytes, &path, "remote cache artifact")?;

        if path == Path::new(".lpm-cache/meta.json") {
            meta_json = Some(read_entry_to_string(&mut entry, &path)?);
            continue;
        }
        if path == Path::new(".lpm-cache/stdout.log") {
            stdout = read_entry_to_string(&mut entry, &path)?;
            continue;
        }
        if path == Path::new(".lpm-cache/stderr.log") {
            stderr = read_entry_to_string(&mut entry, &path)?;
            continue;
        }

        let Ok(rel) = path.strip_prefix("outputs") else {
            return Err(LpmError::Task(format!(
                "remote cache artifact contains unexpected entry: {}",
                path.display()
            )));
        };
        if rel.as_os_str().is_empty() {
            continue;
        }

        if entry.header().entry_type().is_dir() {
            std::fs::create_dir_all(project_dir.join(rel))?;
        } else {
            restore_remote_output_file(&mut entry, project_dir, rel)?;
            output_file_count += 1;
        }
    }

    let meta_json = meta_json.ok_or_else(|| {
        LpmError::Task("remote cache artifact is missing .lpm-cache/meta.json".into())
    })?;
    let meta: CacheMeta = serde_json::from_str(&meta_json)
        .map_err(|e| LpmError::Task(format!("failed to parse remote cache meta: {e}")))?;

    if meta.cache_key != expected_key {
        return Err(LpmError::Task(format!(
            "remote cache artifact key mismatch (expected {expected_key}, got {})",
            meta.cache_key
        )));
    }
    if meta.output_file_count != output_file_count {
        return Err(LpmError::Task(format!(
            "remote cache artifact output count mismatch (expected {}, restored {})",
            meta.output_file_count, output_file_count
        )));
    }

    Ok(CacheHit {
        meta,
        stdout,
        stderr,
    })
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
#[derive(Debug)]
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

    let file_count = append_output_files(&mut builder, project_dir, output_globs, None)?;

    builder
        .finish()
        .map_err(|e| LpmError::Task(format!("failed to finalize archive: {e}")))?;

    tracing::debug!("archived {file_count} files to {}", archive_path.display());
    Ok(file_count)
}

fn append_output_files<W: Write>(
    builder: &mut tar::Builder<W>,
    project_dir: &Path,
    output_globs: &[String],
    archive_prefix: Option<&Path>,
) -> Result<usize, LpmError> {
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
                        let archive_name = archive_prefix
                            .map_or_else(|| rel.to_path_buf(), |prefix| prefix.join(rel));
                        builder
                            .append_path_with_name(&entry, &archive_name)
                            .map_err(|e| {
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

    Ok(file_count)
}

fn append_bytes<W: Write>(
    builder: &mut tar::Builder<W>,
    path: &Path,
    bytes: &[u8],
) -> Result<(), LpmError> {
    let mut header = tar::Header::new_gnu();
    header.set_size(bytes.len() as u64);
    header.set_mode(0o600);
    header.set_entry_type(tar::EntryType::Regular);
    header.set_cksum();
    builder
        .append_data(&mut header, path, bytes)
        .map_err(|e| LpmError::Task(format!("failed to add {} to artifact: {e}", path.display())))
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

/// H25: hard cap on a restored entry's size — defense against a
/// task-cache archive whose entries grew unbounded between cache
/// store and restore (CI shared cache, sync conflict).
const MAX_CACHE_ENTRY_BYTES: u64 = 256 * 1024 * 1024;

/// H25: hard cap on the total bytes restored across all entries —
/// bounds the worst case where many small entries individually pass
/// the per-entry cap but together exhaust disk.
const MAX_CACHE_ARCHIVE_BYTES: u64 = 1024 * 1024 * 1024;

/// H25: hard cap on the number of entries unpacked from a single
/// archive — bounds the inode-pressure / filesystem-walking cost
/// of a malicious entry-count-bomb.
const MAX_CACHE_ARCHIVE_ENTRIES: usize = 100_000;

/// Restore a .tar.gz archive to the project directory.
///
/// H25: hardens the previously-default `entry.unpack_in(project_dir)`
/// call. The lpm-extractor's full hardening surface (mode floors,
/// SUID/SGID strip, entry-type filter, etc.) is not directly reusable
/// here because lpm-extractor walks tarballs from packages while
/// task cache restores arbitrary project files — different policy.
/// What we DO mirror from the extractor:
///   * Per-entry size cap (`MAX_CACHE_ENTRY_BYTES`).
///   * Aggregate restore byte cap (`MAX_CACHE_ARCHIVE_BYTES`).
///   * Entry count cap (`MAX_CACHE_ARCHIVE_ENTRIES`).
///   * `preserve_permissions(false)` + `preserve_ownerships(false)`
///     so a malicious archive can't restore SUID/SGID bits or
///     attempt to chown into another user.
///   * Symlink / hardlink / FIFO / char-device / block-device entry
///     types are refused — task cache should only carry regular
///     files and directories. Symlinks introduce arbitrary-file
///     disclosure if the linked path later gets `cat`-ed by another
///     task; FIFOs/devices have no legitimate task-cache purpose.
///   * The pre-existing parent-dir / root-dir / prefix component
///     check stays as the first-line zip-slip defense.
fn restore_archive(archive_path: &Path, project_dir: &Path) -> Result<(), LpmError> {
    let file = std::fs::File::open(archive_path)?;
    let dec = flate2::read::GzDecoder::new(file);
    let mut archive = tar::Archive::new(dec);
    archive.set_preserve_permissions(false);
    archive.set_preserve_ownerships(false);

    let mut total_bytes: u64 = 0;
    let mut entries_seen: usize = 0;

    for entry in archive
        .entries()
        .map_err(|e| LpmError::Task(format!("failed to read cache archive entries: {e}")))?
    {
        let mut entry = entry
            .map_err(|e| LpmError::Task(format!("failed to read cache archive entry: {e}")))?;

        entries_seen += 1;
        if entries_seen > MAX_CACHE_ARCHIVE_ENTRIES {
            return Err(LpmError::Task(format!(
                "task cache archive exceeds entry-count cap ({MAX_CACHE_ARCHIVE_ENTRIES} entries)"
            )));
        }

        let path = entry
            .path()
            .map_err(|e| LpmError::Task(format!("failed to read entry path: {e}")))?
            .to_path_buf();
        validate_archive_path(&path, "cache archive")?;

        validate_archive_entry_type(&entry, &path, "task cache archive")?;

        let entry_size = entry.header().size().unwrap_or(0);
        check_archive_size_limits(entry_size, &mut total_bytes, &path, "task cache archive")?;

        entry
            .unpack_in(project_dir)
            .map_err(|e| LpmError::Task(format!("failed to unpack {}: {e}", path.display())))?;
    }

    Ok(())
}

fn validate_archive_path(path: &Path, label: &str) -> Result<(), LpmError> {
    if path.components().any(|c| {
        matches!(
            c,
            Component::ParentDir | Component::RootDir | Component::Prefix(_)
        )
    }) {
        return Err(LpmError::Task(format!(
            "path traversal in {label}: {}",
            path.display()
        )));
    }
    Ok(())
}

fn validate_archive_entry_type(
    entry: &tar::Entry<'_, impl Read>,
    path: &Path,
    label: &str,
) -> Result<(), LpmError> {
    let header_type = entry.header().entry_type();
    if !(header_type.is_file() || header_type.is_dir()) {
        return Err(LpmError::Task(format!(
            "{label} contains non-regular entry ({:?}): {}",
            header_type,
            path.display(),
        )));
    }
    Ok(())
}

fn check_archive_size_limits(
    entry_size: u64,
    total_bytes: &mut u64,
    path: &Path,
    label: &str,
) -> Result<(), LpmError> {
    if entry_size > MAX_CACHE_ENTRY_BYTES {
        return Err(LpmError::Task(format!(
            "{label} entry exceeds size cap ({} > {} bytes): {}",
            entry_size,
            MAX_CACHE_ENTRY_BYTES,
            path.display(),
        )));
    }
    *total_bytes = total_bytes.saturating_add(entry_size);
    if *total_bytes > MAX_CACHE_ARCHIVE_BYTES {
        return Err(LpmError::Task(format!(
            "{label} exceeds aggregate cap ({MAX_CACHE_ARCHIVE_BYTES} bytes)"
        )));
    }
    Ok(())
}

fn read_entry_to_string(
    entry: &mut tar::Entry<'_, impl Read>,
    path: &Path,
) -> Result<String, LpmError> {
    let mut content = String::new();
    entry
        .read_to_string(&mut content)
        .map_err(|e| LpmError::Task(format!("failed to read {}: {e}", path.display())))?;
    Ok(content)
}

fn restore_remote_output_file(
    entry: &mut tar::Entry<'_, impl Read>,
    project_dir: &Path,
    rel: &Path,
) -> Result<(), LpmError> {
    let target = project_dir.join(rel);
    if let Some(parent) = target.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut file = std::fs::File::create(&target)?;
    std::io::copy(entry, &mut file)
        .map_err(|e| LpmError::Task(format!("failed to restore {}: {e}", rel.display())))?;
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
#[expect(
    clippy::unnecessary_wraps,
    reason = "non-Unix stub keeps the same fallible helper signature"
)]
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

    #[test]
    fn remote_artifact_roundtrip_restores_outputs_and_logs() {
        let dir = tempfile::tempdir().unwrap();

        fs::create_dir_all(dir.path().join("dist")).unwrap();
        fs::write(dir.path().join("dist/index.js"), "remote output").unwrap();

        let key = unique_key("remote-roundtrip");
        let artifact_path = dir.path().join("remote-artifact.tar.gz");

        create_remote_artifact(RemoteArtifactCreate {
            key: &key,
            project_dir: dir.path(),
            command: "node build.js",
            output_globs: &["dist/**".into()],
            stdout: "remote stdout\n",
            stderr: "remote stderr\n",
            duration_ms: 4321,
            artifact_path: &artifact_path,
        })
        .unwrap();

        fs::remove_dir_all(dir.path().join("dist")).unwrap();

        let hit = restore_remote_artifact(&key, &artifact_path, dir.path()).unwrap();

        assert_eq!(hit.meta.command, "node build.js");
        assert_eq!(hit.meta.cache_key, key);
        assert_eq!(hit.meta.duration_ms, 4321);
        assert_eq!(hit.meta.output_file_count, 1);
        assert_eq!(hit.stdout, "remote stdout\n");
        assert_eq!(hit.stderr, "remote stderr\n");
        assert_eq!(
            fs::read_to_string(dir.path().join("dist/index.js")).unwrap(),
            "remote output"
        );
    }

    #[test]
    fn remote_artifact_rejects_cache_key_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join("dist")).unwrap();
        fs::write(dir.path().join("dist/index.js"), "remote output").unwrap();

        let key = unique_key("remote-key");
        let artifact_path = dir.path().join("remote-key.tar.gz");
        create_remote_artifact(RemoteArtifactCreate {
            key: &key,
            project_dir: dir.path(),
            command: "node build.js",
            output_globs: &["dist/**".into()],
            stdout: "",
            stderr: "",
            duration_ms: 1,
            artifact_path: &artifact_path,
        })
        .unwrap();

        let err = restore_remote_artifact("deadbeef", &artifact_path, dir.path()).unwrap_err();
        assert!(
            err.to_string().contains("key mismatch"),
            "mismatched remote artifact key must be rejected, got: {err}"
        );
    }

    #[test]
    fn remote_artifact_rejects_unexpected_top_level_entry() {
        use flate2::Compression;
        use flate2::write::GzEncoder;

        let dir = tempfile::tempdir().unwrap();
        let artifact_path = dir.path().join("unexpected.tar.gz");
        let key = unique_key("remote-unexpected");

        {
            let file = fs::File::create(&artifact_path).unwrap();
            let enc = GzEncoder::new(file, Compression::fast());
            let mut builder = tar::Builder::new(enc);

            let meta = CacheMeta {
                command: "build".into(),
                cache_key: key.clone(),
                duration_ms: 1,
                output_file_count: 0,
            };
            let meta_json = serde_json::to_string(&meta).unwrap();
            append_bytes(
                &mut builder,
                Path::new(".lpm-cache/meta.json"),
                meta_json.as_bytes(),
            )
            .unwrap();
            append_bytes(&mut builder, Path::new("outside.txt"), b"nope").unwrap();
            builder.finish().unwrap();
        }

        let err = restore_remote_artifact(&key, &artifact_path, dir.path()).unwrap_err();
        assert!(
            err.to_string().contains("unexpected entry"),
            "unexpected top-level entries must be rejected, got: {err}"
        );
    }

    // -- zip-slip prevention --

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

    /// H25: a symlink entry in the task-cache archive is the
    /// arbitrary-file-disclosure shape — refuse before unpack.
    #[test]
    fn restore_archive_refuses_symlink_entry() {
        use flate2::Compression;
        use flate2::write::GzEncoder;
        use tar::Builder;

        let dir = tempfile::tempdir().unwrap();
        let archive_path = dir.path().join("symlink.tar.gz");

        {
            let file = fs::File::create(&archive_path).unwrap();
            let enc = GzEncoder::new(file, Compression::fast());
            let mut builder = Builder::new(enc);

            let mut header = tar::Header::new_gnu();
            header.set_size(0);
            header.set_mode(0o777);
            header.set_entry_type(tar::EntryType::Symlink);
            header.set_path("evil-link").unwrap();
            header.set_link_name("/etc/passwd").unwrap();
            header.set_cksum();
            builder.append(&header, std::io::empty()).unwrap();
            builder.finish().unwrap();
        }

        let err = restore_archive(&archive_path, dir.path()).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("non-regular entry"),
            "symlink must be rejected; got: {msg}"
        );
    }

    /// H25: a FIFO / char-device / block-device entry has no
    /// legitimate task-output meaning — refuse before unpack.
    #[test]
    fn restore_archive_refuses_fifo_entry() {
        use flate2::Compression;
        use flate2::write::GzEncoder;
        use tar::Builder;

        let dir = tempfile::tempdir().unwrap();
        let archive_path = dir.path().join("fifo.tar.gz");

        {
            let file = fs::File::create(&archive_path).unwrap();
            let enc = GzEncoder::new(file, Compression::fast());
            let mut builder = Builder::new(enc);

            let mut header = tar::Header::new_gnu();
            header.set_size(0);
            header.set_mode(0o600);
            header.set_entry_type(tar::EntryType::Fifo);
            header.set_path("evil-fifo").unwrap();
            header.set_cksum();
            builder.append(&header, std::io::empty()).unwrap();
            builder.finish().unwrap();
        }

        let err = restore_archive(&archive_path, dir.path()).unwrap_err();
        assert!(err.to_string().contains("non-regular entry"));
    }

    // -- glob pattern validation --

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

    // -- cache directory permissions --

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

    // -- cache key validation --

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
