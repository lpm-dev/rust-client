//! Conversions between a local cache entry and a portable remote-cache
//! artifact that read the archive already written instead of the project.
//!
//! The local entry holds its outputs as `outputs.tar.gz` with paths relative
//! to the project. The remote artifact holds the same files under `outputs/`,
//! followed by `.lpm-cache/meta.json`, `stdout.log` and `stderr.log`.

use super::{
    CacheMeta, MAX_CACHE_ARCHIVE_ENTRIES, MAX_CACHE_ENTRY_BYTES, MAX_CACHE_LOG_BYTES, append_bytes,
    cache_entry_lock_path, check_archive_size_limits, create_private_cache_file, open_cache_entry,
    open_cache_entry_file, open_task_cache, publish_cache_entry, read_cache_log, read_cache_meta,
    read_entry_to_string, validate_archive_entry_type, validate_archive_path, validate_cache_key,
    validate_local_cache_entry, validate_text_entry_size, write_cache_meta,
    write_private_cache_file,
};
use lpm_common::{LpmError, LpmRoot};
use std::io::{Read, Seek, Write};
use std::path::Path;

const REMOTE_OUTPUTS_DIR: &str = "outputs";
const REMOTE_META: &str = ".lpm-cache/meta.json";
const REMOTE_STDOUT: &str = ".lpm-cache/stdout.log";
const REMOTE_STDERR: &str = ".lpm-cache/stderr.log";

fn archive_limits() -> lpm_extractor::TarArchiveLimits {
    lpm_extractor::TarArchiveLimits {
        max_entry_bytes: MAX_CACHE_ENTRY_BYTES,
        ..lpm_extractor::TarArchiveLimits::new(MAX_CACHE_ARCHIVE_ENTRIES)
    }
}

/// Writes the remote-cache artifact for `key` to `writer` from the local
/// cache entry, which holds the outputs as the task left them. The local
/// entry must exist, as it does right after [`super::store_cache`].
///
/// Returns `writer`, after the gzip stream is finished, so a caller that
/// hashes what it writes can take the digests from it.
pub fn write_remote_artifact_from_local_entry<W: Write>(
    key: &str,
    writer: W,
) -> Result<W, LpmError> {
    let root = LpmRoot::from_env()
        .map_err(|error| LpmError::Task(format!("could not determine LPM home: {error}")))?;
    write_remote_artifact_from_local_entry_with_root(&root, key, writer)
}

pub(super) fn write_remote_artifact_from_local_entry_with_root<W: Write>(
    root: &LpmRoot,
    key: &str,
    writer: W,
) -> Result<W, LpmError> {
    validate_cache_key(key)?;
    let cache = open_task_cache(root, false)?.ok_or_else(|| {
        LpmError::Task(format!(
            "task cache directory is missing: {}",
            root.cache_tasks().display()
        ))
    })?;
    lpm_common::with_shared_lock(root.cache_clean_lock(), || {
        let _entry_lock =
            lpm_common::acquire_single_file_shared_lock(cache_entry_lock_path(root, key)?)?;
        let entry = open_cache_entry(&cache, key)?;
        let meta = read_cache_meta(&entry, key)?;
        let stdout = read_cache_log(&entry, "stdout.log")?;
        let stderr = read_cache_log(&entry, "stderr.log")?;
        let archive = open_cache_entry_file(&entry, "outputs.tar.gz", "task cache archive")?;

        let encoder = flate2::write::GzEncoder::new(writer, flate2::Compression::fast());
        let mut builder = tar::Builder::new(encoder);
        let mut copied = 0;
        if let Some(archive) = archive {
            let mut total_bytes = 0;
            lpm_extractor::visit_tar_archive(
                flate2::read::GzDecoder::new(archive),
                archive_limits(),
                |mut entry| {
                    let path = entry.path().to_path_buf();
                    validate_output_entry(&entry, &path, &mut total_bytes, "task cache archive")?;
                    copy_entry(
                        &mut builder,
                        &mut entry,
                        &Path::new(REMOTE_OUTPUTS_DIR).join(&path),
                    )?;
                    copied += 1;
                    Ok(std::ops::ControlFlow::<()>::Continue(()))
                },
            )?;
        }
        if copied != meta.output_file_count {
            return Err(LpmError::Task(format!(
                "cache entry output count mismatch (expected {}, found {copied})",
                meta.output_file_count
            )));
        }

        let meta_json = serde_json::to_string_pretty(&meta)
            .map_err(|e| LpmError::Task(format!("failed to serialize remote cache meta: {e}")))?;
        append_bytes(&mut builder, Path::new(REMOTE_META), meta_json.as_bytes())?;
        append_bytes(&mut builder, Path::new(REMOTE_STDOUT), stdout.as_bytes())?;
        append_bytes(&mut builder, Path::new(REMOTE_STDERR), stderr.as_bytes())?;
        builder.finish().map_err(|e| {
            LpmError::Task(format!("failed to finalize remote cache artifact: {e}"))
        })?;
        let encoder = builder.into_inner().map_err(|e| {
            LpmError::Task(format!(
                "failed to finish remote cache artifact archive: {e}"
            ))
        })?;
        encoder
            .finish()
            .map_err(|e| LpmError::Task(format!("failed to finish remote cache gzip stream: {e}")))
    })
}

/// Fills the local cache entry for `key` from a remote-cache artifact that
/// was verified and restored, rather than archiving the restored outputs
/// again. Leaves an entry that is already valid in place.
pub fn store_cache_from_remote_artifact(
    key: &str,
    artifact: std::fs::File,
) -> Result<(), LpmError> {
    let root = LpmRoot::from_env()
        .map_err(|error| LpmError::Task(format!("could not determine LPM home: {error}")))?;
    store_cache_from_remote_artifact_with_root(&root, key, artifact)
}

pub(super) fn store_cache_from_remote_artifact_with_root(
    root: &LpmRoot,
    key: &str,
    mut artifact: std::fs::File,
) -> Result<(), LpmError> {
    validate_cache_key(key)?;
    let cache = open_task_cache(root, true)?.expect("created task cache directory");
    lpm_common::with_shared_lock(root.cache_clean_lock(), || {
        let _entry_lock =
            lpm_common::acquire_single_file_exclusive_lock(cache_entry_lock_path(root, key)?)?;
        if validate_local_cache_entry(&cache, key).is_ok() {
            return Ok(());
        }
        artifact.rewind()?;
        publish_cache_entry(&cache, key, |staging| {
            write_local_entry_from_remote_artifact(staging, key, &mut artifact)
        })
    })
}

fn write_local_entry_from_remote_artifact(
    staging: &cap_std::fs::Dir,
    key: &str,
    artifact: &mut std::fs::File,
) -> Result<(), LpmError> {
    let label = "remote cache artifact";
    let mut meta_json = None;
    let mut stdout = None;
    let mut stderr = None;
    let mut outputs: Option<tar::Builder<flate2::write::GzEncoder<std::fs::File>>> = None;
    let mut output_file_count = 0;
    let mut total_bytes = 0;

    lpm_extractor::visit_tar_archive(
        flate2::read::GzDecoder::new(artifact),
        archive_limits(),
        |mut entry| {
            let path = entry.path().to_path_buf();
            let log = match path.to_str() {
                Some(REMOTE_META) => Some((&mut meta_json, lpm_common::STATE_FILE_SIZE_CAP_BYTES)),
                Some(REMOTE_STDOUT) => Some((&mut stdout, MAX_CACHE_LOG_BYTES)),
                Some(REMOTE_STDERR) => Some((&mut stderr, MAX_CACHE_LOG_BYTES)),
                _ => None,
            };
            if let Some((slot, cap)) = log {
                validate_archive_entry_type(entry.header().entry_type(), &path, label)?;
                let size = entry.header().size().unwrap_or(0);
                check_archive_size_limits(size, &mut total_bytes, &path, label)?;
                validate_text_entry_size(size, cap, &path)?;
                if slot.is_some() {
                    return Err(LpmError::Task(format!(
                        "{label} contains a duplicate {}",
                        path.display()
                    )));
                }
                *slot = Some(read_entry_to_string(&mut entry, &path)?);
                return Ok(std::ops::ControlFlow::<()>::Continue(()));
            }

            let relative = match path.strip_prefix(REMOTE_OUTPUTS_DIR) {
                Ok(relative) if !relative.as_os_str().is_empty() => relative.to_path_buf(),
                _ => {
                    return Err(LpmError::Task(format!(
                        "{label} contains unexpected entry: {}",
                        path.display()
                    )));
                }
            };
            validate_output_entry(&entry, &path, &mut total_bytes, label)?;
            let builder = match &mut outputs {
                Some(builder) => builder,
                empty => empty.insert(tar::Builder::new(flate2::write::GzEncoder::new(
                    create_private_cache_file(staging, "outputs.tar.gz")?,
                    flate2::Compression::fast(),
                ))),
            };
            copy_entry(builder, &mut entry, &relative)?;
            output_file_count += 1;
            Ok(std::ops::ControlFlow::<()>::Continue(()))
        },
    )?;

    let meta_json =
        meta_json.ok_or_else(|| LpmError::Task(format!("{label} is missing {REMOTE_META}")))?;
    let meta: CacheMeta = serde_json::from_str(&meta_json)
        .map_err(|e| LpmError::Task(format!("failed to parse remote cache meta: {e}")))?;
    if meta.cache_key != key {
        return Err(LpmError::Task(format!(
            "{label} key mismatch (expected {key}, got {})",
            meta.cache_key
        )));
    }
    if meta.output_file_count != output_file_count {
        return Err(LpmError::Task(format!(
            "{label} output count mismatch (expected {}, found {output_file_count})",
            meta.output_file_count
        )));
    }
    let stdout =
        stdout.ok_or_else(|| LpmError::Task(format!("{label} is missing {REMOTE_STDOUT}")))?;
    let stderr =
        stderr.ok_or_else(|| LpmError::Task(format!("{label} is missing {REMOTE_STDERR}")))?;

    if let Some(builder) = outputs {
        let file = builder
            .into_inner()
            .and_then(flate2::write::GzEncoder::finish)
            .map_err(|e| LpmError::Task(format!("failed to finish task cache archive: {e}")))?;
        file.sync_all()?;
    }
    write_private_cache_file(staging, "stdout.log", stdout.as_bytes())?;
    write_private_cache_file(staging, "stderr.log", stderr.as_bytes())?;
    write_cache_meta(staging, &meta)
}

fn validate_output_entry<R: Read>(
    entry: &lpm_extractor::BoundedTarEntry<'_, R>,
    path: &Path,
    total_bytes: &mut u64,
    label: &str,
) -> Result<(), LpmError> {
    validate_archive_path(path, label)?;
    validate_archive_entry_type(entry.header().entry_type(), path, label)?;
    check_archive_size_limits(entry.header().size().unwrap_or(0), total_bytes, path, label)
}

/// Appends `entry` under `path`, keeping its mode, times and size.
fn copy_entry<R: Read, W: Write>(
    builder: &mut tar::Builder<W>,
    entry: &mut lpm_extractor::BoundedTarEntry<'_, R>,
    path: &Path,
) -> Result<(), LpmError> {
    let mut header = entry.header().clone();
    builder
        .append_data(&mut header, path, entry)
        .map_err(|e| LpmError::Task(format!("failed to add {} to archive: {e}", path.display())))
}
