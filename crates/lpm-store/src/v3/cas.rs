use std::collections::{HashMap, HashSet};
use std::ffi::{OsStr, OsString};
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use lpm_common::{LpmError, write_file_atomic};
use serde::{Deserialize, Serialize};

use crate::v2::fs_util::tmp_sibling;
#[cfg(any(target_os = "macos", test))]
use crate::v2::fs_util::{create_fs_symlink, create_tmp_dir_locked};
use crate::v2::tree_hash::is_object_metadata_sidecar;

const CAS_SCHEMA_VERSION: u32 = 1;
const MANIFEST_MAX_BYTES: u64 = 64 * 1024 * 1024;
const SOURCE_RECORD_MAX_BYTES: u64 = 16 * 1024;
const SOURCE_VALIDATION_MAX_BYTES: u64 = 4 * 1024;
const MAX_TREE_DEPTH: usize = 256;
const MATERIALIZED_COMPLETE_FILENAME: &str = ".complete";

#[derive(Clone, Debug)]
pub(crate) struct FileCas {
    store_root: PathBuf,
    blobs_root: PathBuf,
    trees_root: PathBuf,
    sources_root: PathBuf,
    source_validations_root: PathBuf,
    materialized_root: PathBuf,
    secured_directories: Arc<Mutex<HashSet<PathBuf>>>,
    manifest_cache: Arc<Mutex<HashMap<String, ManifestCacheEntry>>>,
}

#[derive(Clone, Debug)]
struct ManifestCacheEntry {
    size: u64,
    fingerprint: BlobStatFingerprint,
    manifest: Arc<CasManifest>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct FileCasReuseTimings {
    pub source_record_read_count: u64,
    pub source_record_read_ms: u128,
    pub manifest_read_count: u64,
    pub manifest_read_ms: u128,
    pub manifest_validate_ms: u128,
    pub blob_stat_count: u64,
    pub blob_stat_cache_hit_count: u64,
    pub blob_stat_ms: u128,
    pub source_validation_read_count: u64,
    pub source_validation_read_ms: u128,
    pub blob_rehash_count: u64,
    pub blob_rehash_ms: u128,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct FileCasValidationBatch {
    blob_stats: Arc<Mutex<HashMap<BlobKey, BlobStatFingerprint>>>,
}

#[derive(Clone, Debug)]
pub(crate) struct PreparedSourceRecord {
    object_segment: OsString,
    record: SourceRecord,
    validation: SourceValidationRecord,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SourceReuseStatus {
    Reusable,
    MissingOrInvalid,
    CorruptBlob,
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct BlobStatFingerprint {
    dev: u64,
    ino: u64,
    mtime: i64,
    mtime_nsec: i64,
    ctime: i64,
    ctime_nsec: i64,
}

#[cfg(windows)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct BlobStatFingerprint {
    volume_serial_number: u32,
    file_index: u64,
    creation_time: u64,
    last_write_time: u64,
    change_time: i64,
    file_attributes: u32,
}

#[cfg(not(any(unix, windows)))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct BlobStatFingerprint {
    modified: u128,
    created: u128,
    readonly: bool,
}

#[derive(Debug)]
pub(crate) struct RegistryCasIngest {
    object_segment: OsString,
    source_sri: String,
    entries: Vec<CasManifestEntry>,
    entry_indexes: HashMap<Vec<u8>, usize>,
    hash_buffer: Vec<u8>,
}

struct TreeIngestContext<'a> {
    object_root: &'a Path,
    entries: &'a mut Vec<CasManifestEntry>,
    hash_buffer: &'a mut [u8],
    allows_symlinks: bool,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct BlobKey {
    pub digest: String,
    pub mode: u32,
    pub size: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum CasEntryKind {
    Directory,
    File,
    Symlink,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CasManifestEntry {
    pub path: Vec<u8>,
    pub kind: CasEntryKind,
    pub mode: u32,
    pub size: u64,
    pub blob: Option<BlobKey>,
    pub symlink_target: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CasManifest {
    pub schema: u32,
    pub path_encoding: String,
    pub allows_symlinks: bool,
    pub entries: Vec<CasManifestEntry>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SourceRecord {
    pub schema: u32,
    pub source_sri: String,
    pub object_segment: Vec<u8>,
    pub tree_digest: String,
    pub local_source: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct SourceValidationRecord {
    schema: u32,
    source_sri: String,
    tree_digest: String,
    blob_stat_fingerprint: String,
}

impl FileCas {
    pub(crate) fn at(store_root: &Path) -> Self {
        Self {
            store_root: store_root.to_path_buf(),
            blobs_root: store_root.join("blobs").join("blake3"),
            trees_root: store_root.join("trees"),
            sources_root: store_root.join("sources"),
            source_validations_root: store_root.join("metadata").join("source-validations"),
            materialized_root: store_root.join("materialized"),
            secured_directories: Arc::new(Mutex::new(HashSet::with_capacity(1_024))),
            manifest_cache: Arc::new(Mutex::new(HashMap::with_capacity(256))),
        }
    }

    pub(crate) fn ingest_object_tree(
        &self,
        object_dir: &Path,
        source_sri: &str,
        allows_symlinks: bool,
    ) -> Result<PreparedSourceRecord, LpmError> {
        self.ingest_object_tree_as(object_dir, object_dir, source_sri, allows_symlinks)
    }

    pub(crate) fn ingest_object_tree_as(
        &self,
        object_dir: &Path,
        published_object_dir: &Path,
        source_sri: &str,
        allows_symlinks: bool,
    ) -> Result<PreparedSourceRecord, LpmError> {
        let object_segment = published_object_dir
            .file_name()
            .ok_or_else(|| {
                LpmError::Store(format!(
                    "v3 CAS object path has no final segment: {}",
                    published_object_dir.display()
                ))
            })?
            .to_os_string();
        let mut entries = Vec::new();
        let mut relative = Vec::new();
        let mut hash_buffer = vec![0_u8; 64 * 1024];
        let mut ingest = TreeIngestContext {
            object_root: object_dir,
            entries: &mut entries,
            hash_buffer: &mut hash_buffer,
            allows_symlinks,
        };
        self.ingest_dir(&mut ingest, object_dir, &mut relative, 0)?;
        self.prepare_source_record(object_segment, source_sri, allows_symlinks, entries)
    }

    pub(crate) fn begin_registry_ingest(
        &self,
        published_object_dir: &Path,
        source_sri: &str,
    ) -> Result<RegistryCasIngest, LpmError> {
        let object_segment = published_object_dir
            .file_name()
            .ok_or_else(|| {
                LpmError::Store(format!(
                    "v3 CAS object path has no final segment: {}",
                    published_object_dir.display()
                ))
            })?
            .to_os_string();
        Ok(RegistryCasIngest {
            object_segment,
            source_sri: source_sri.to_string(),
            entries: Vec::with_capacity(128),
            entry_indexes: HashMap::with_capacity(128),
            hash_buffer: vec![0_u8; 64 * 1024],
        })
    }

    pub(crate) fn ingest_registry_file(
        &self,
        ingest: &mut RegistryCasIngest,
        object_root: &Path,
        relative_path: &Path,
        expected_size: u64,
        digest: [u8; 32],
    ) -> Result<(), LpmError> {
        let path_bytes = encode_relative_path(relative_path)?;
        let existing_entry = ingest.entry_indexes.get(&path_bytes).copied();
        if existing_entry.is_some_and(|index| ingest.entries[index].kind != CasEntryKind::File) {
            return Err(LpmError::Store(format!(
                "v3 CAS registry file conflicts with a directory at {}",
                relative_path.display()
            )));
        }
        let source = object_root.join(relative_path);
        let metadata = fs::symlink_metadata(&source).map_err(|error| {
            LpmError::Store(format!(
                "failed to inspect extracted v3 CAS entry {}: {error}",
                source.display()
            ))
        })?;
        if !metadata.file_type().is_file() || metadata.len() != expected_size {
            return Err(LpmError::Store(format!(
                "extracted v3 CAS entry changed before publication at {}",
                source.display()
            )));
        }
        let key = BlobKey {
            digest: blake3::Hash::from_bytes(digest).to_hex().to_string(),
            mode: normalized_mode(&metadata),
            size: expected_size,
        };
        self.publish_blob(&source, &key, &mut ingest.hash_buffer)?;

        let mut parent = relative_path.parent();
        while let Some(directory) = parent {
            if directory.as_os_str().is_empty() {
                break;
            }
            let encoded = encode_relative_path(directory)?;
            if let Some(index) = ingest.entry_indexes.get(&encoded).copied() {
                if ingest.entries[index].kind != CasEntryKind::Directory {
                    return Err(LpmError::Store(format!(
                        "v3 CAS registry directory conflicts with a file at {}",
                        directory.display()
                    )));
                }
            } else {
                let directory_path = object_root.join(directory);
                let metadata = fs::symlink_metadata(&directory_path).map_err(|error| {
                    LpmError::Store(format!(
                        "failed to inspect extracted v3 CAS directory {}: {error}",
                        directory_path.display()
                    ))
                })?;
                if !metadata.file_type().is_dir() {
                    return Err(LpmError::Store(format!(
                        "extracted v3 CAS parent is not a directory at {}",
                        directory_path.display()
                    )));
                }
                ingest
                    .entry_indexes
                    .insert(encoded.clone(), ingest.entries.len());
                ingest.entries.push(CasManifestEntry {
                    path: encoded,
                    kind: CasEntryKind::Directory,
                    mode: normalized_mode(&metadata),
                    size: 0,
                    blob: None,
                    symlink_target: Vec::new(),
                });
            }
            parent = directory.parent();
        }
        let entry = CasManifestEntry {
            path: path_bytes,
            kind: CasEntryKind::File,
            mode: key.mode,
            size: key.size,
            blob: Some(key),
            symlink_target: Vec::new(),
        };
        if let Some(index) = existing_entry {
            ingest.entries[index] = entry;
        } else {
            ingest
                .entry_indexes
                .insert(entry.path.clone(), ingest.entries.len());
            ingest.entries.push(entry);
        }
        Ok(())
    }

    pub(crate) fn finish_registry_ingest(
        &self,
        ingest: RegistryCasIngest,
    ) -> Result<PreparedSourceRecord, LpmError> {
        self.prepare_source_record(
            ingest.object_segment,
            &ingest.source_sri,
            false,
            ingest.entries,
        )
    }

    fn prepare_source_record(
        &self,
        object_segment: OsString,
        source_sri: &str,
        allows_symlinks: bool,
        mut entries: Vec<CasManifestEntry>,
    ) -> Result<PreparedSourceRecord, LpmError> {
        entries.sort_unstable_by(|left, right| left.path.cmp(&right.path));
        let manifest = CasManifest {
            schema: CAS_SCHEMA_VERSION,
            path_encoding: platform_path_encoding().to_string(),
            allows_symlinks,
            entries,
        };
        let manifest_bytes = rmp_serde::to_vec_named(&manifest).map_err(|error| {
            LpmError::Store(format!("failed to serialize v3 CAS tree manifest: {error}"))
        })?;
        let tree_digest = blake3::hash(&manifest_bytes).to_hex().to_string();
        self.publish_tree_manifest(&tree_digest, &manifest_bytes)?;
        let mut timings = FileCasReuseTimings::default();
        let blob_stat_fingerprint = self.blob_stat_fingerprint(&manifest, &mut timings, None)?;
        Ok(PreparedSourceRecord {
            validation: SourceValidationRecord {
                schema: CAS_SCHEMA_VERSION,
                source_sri: source_sri.to_string(),
                tree_digest: tree_digest.clone(),
                blob_stat_fingerprint,
            },
            record: SourceRecord {
                schema: CAS_SCHEMA_VERSION,
                source_sri: source_sri.to_string(),
                object_segment: encode_os_str(&object_segment),
                tree_digest,
                local_source: allows_symlinks,
            },
            object_segment,
        })
    }

    pub(crate) fn publish_source_record(
        &self,
        object_dir: &Path,
        prepared: &PreparedSourceRecord,
    ) -> Result<(), LpmError> {
        if object_dir.file_name() != Some(prepared.object_segment.as_os_str()) {
            return Err(LpmError::Store(format!(
                "v3 CAS source record object mismatch at {}",
                object_dir.display()
            )));
        }
        let path = self.source_record_path(&prepared.record.source_sri)?;
        let parent = path.parent().ok_or_else(|| {
            LpmError::Store(format!(
                "v3 CAS source record has no parent: {}",
                path.display()
            ))
        })?;
        self.ensure_cas_directory(parent).map_err(|error| {
            LpmError::Store(format!(
                "failed to create v3 CAS source metadata at {}: {error}",
                parent.display()
            ))
        })?;
        let bytes = rmp_serde::to_vec_named(&prepared.record).map_err(|error| {
            LpmError::Store(format!("failed to serialize v3 CAS source record: {error}"))
        })?;
        let result = match read_capped_io(&path, SOURCE_RECORD_MAX_BYTES) {
            Ok(existing) if existing == bytes => Ok(()),
            Ok(_) if prepared.record.local_source => {
                write_file_atomic(&path, bytes).map_err(|error| {
                    LpmError::Store(format!(
                        "failed to atomically update v3 CAS local-source record at {}: {error}",
                        path.display()
                    ))
                })
            }
            Ok(existing) => {
                if self.valid_registry_source_collision(&path, &existing, prepared) {
                    Err(LpmError::Store(format!(
                        "immutable v3 CAS registry source record changed at {}",
                        path.display()
                    )))
                } else {
                    self.quarantine_entry(&path, "sources")?;
                    publish_bytes_no_replace(&path, &bytes, SOURCE_RECORD_MAX_BYTES)
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                publish_bytes_no_replace(&path, &bytes, SOURCE_RECORD_MAX_BYTES)
            }
            Err(_) => {
                self.quarantine_entry(&path, "sources")?;
                publish_bytes_no_replace(&path, &bytes, SOURCE_RECORD_MAX_BYTES)
            }
        };
        result?;
        self.write_source_validation(&prepared.validation)
    }

    fn valid_registry_source_collision(
        &self,
        path: &Path,
        bytes: &[u8],
        prepared: &PreparedSourceRecord,
    ) -> bool {
        let Ok(record) = rmp_serde::from_slice::<SourceRecord>(bytes) else {
            return false;
        };
        record.schema == CAS_SCHEMA_VERSION
            && !record.local_source
            && record.source_sri == prepared.record.source_sri
            && record.object_segment == prepared.record.object_segment
            && valid_hex_digest(&record.tree_digest)
            && self
                .source_record_path(&record.source_sri)
                .is_ok_and(|record_path| record_path == path)
            && self.manifest_for_source_record(&record).is_ok()
    }

    #[cfg(test)]
    pub(crate) fn source_reuse_status(
        &self,
        object_dir: &Path,
        source_sri: &str,
    ) -> Result<SourceReuseStatus, LpmError> {
        let mut timings = FileCasReuseTimings::default();
        self.source_reuse_status_with_timings(object_dir, source_sri, &mut timings)
    }

    #[cfg(test)]
    pub(crate) fn source_reuse_status_with_timings(
        &self,
        object_dir: &Path,
        source_sri: &str,
        timings: &mut FileCasReuseTimings,
    ) -> Result<SourceReuseStatus, LpmError> {
        self.source_reuse_status_with_timings_in_batch(object_dir, source_sri, timings, None)
    }

    pub(crate) fn source_reuse_status_with_timings_in_batch(
        &self,
        object_dir: &Path,
        source_sri: &str,
        timings: &mut FileCasReuseTimings,
        batch: Option<&FileCasValidationBatch>,
    ) -> Result<SourceReuseStatus, LpmError> {
        let source_record_start = std::time::Instant::now();
        let source_record = self.read_source_record(source_sri);
        timings.source_record_read_count = timings.source_record_read_count.saturating_add(1);
        timings.source_record_read_ms = timings
            .source_record_read_ms
            .saturating_add(source_record_start.elapsed().as_millis());
        let record = match source_record {
            Ok(record) => record,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(SourceReuseStatus::MissingOrInvalid);
            }
            Err(error) => {
                tracing::warn!(
                    target = %object_dir.display(),
                    "v3 CAS source record is unusable: {error}"
                );
                return Ok(SourceReuseStatus::MissingOrInvalid);
            }
        };
        let Some(segment) = object_dir.file_name() else {
            return Ok(SourceReuseStatus::MissingOrInvalid);
        };
        if record.schema != CAS_SCHEMA_VERSION
            || record.source_sri != source_sri
            || record.object_segment != encode_os_str(segment)
            || !valid_hex_digest(&record.tree_digest)
        {
            return Ok(SourceReuseStatus::MissingOrInvalid);
        }
        let manifest = match self.manifest_for_source_record_with_timings(&record, timings) {
            Ok(manifest) => manifest,
            Err(error) => {
                tracing::warn!(
                    target = %object_dir.display(),
                    "v3 CAS tree manifest is unusable: {error}"
                );
                return Ok(SourceReuseStatus::MissingOrInvalid);
            }
        };
        let observed_fingerprint = match self.blob_stat_fingerprint(&manifest, timings, batch) {
            Ok(fingerprint) => fingerprint,
            Err(error) => {
                tracing::warn!(
                    target = %object_dir.display(),
                    "v3 CAS blob metadata changed: {error}"
                );
                return self.rehash_changed_source_blobs(&record, &manifest, timings, batch);
            }
        };
        let source_validation_start = std::time::Instant::now();
        let source_validation = self.read_source_validation(source_sri);
        timings.source_validation_read_count =
            timings.source_validation_read_count.saturating_add(1);
        timings.source_validation_read_ms = timings
            .source_validation_read_ms
            .saturating_add(source_validation_start.elapsed().as_millis());
        if source_validation.is_ok_and(|validation| {
            validation.schema == CAS_SCHEMA_VERSION
                && validation.source_sri == source_sri
                && validation.tree_digest == record.tree_digest
                && validation.blob_stat_fingerprint == observed_fingerprint
        }) {
            return Ok(SourceReuseStatus::Reusable);
        }
        self.rehash_changed_source_blobs(&record, &manifest, timings, batch)
    }

    fn rehash_changed_source_blobs(
        &self,
        record: &SourceRecord,
        manifest: &CasManifest,
        timings: &mut FileCasReuseTimings,
        batch: Option<&FileCasValidationBatch>,
    ) -> Result<SourceReuseStatus, LpmError> {
        let mut hash_buffer = vec![0_u8; 64 * 1024];
        for key in unique_manifest_blob_keys(manifest) {
            let rehash_start = std::time::Instant::now();
            timings.blob_rehash_count = timings.blob_rehash_count.saturating_add(1);
            if let Err(error) = self.validate_blob(&self.blob_path(key)?, key, &mut hash_buffer) {
                timings.blob_rehash_ms = timings
                    .blob_rehash_ms
                    .saturating_add(rehash_start.elapsed().as_millis());
                let blob = self.blob_path(key)?;
                self.quarantine_entry(&blob, "blobs")?;
                tracing::warn!(
                    target = %blob.display(),
                    "v3 CAS blob failed validation after its stat fingerprint changed: {error}"
                );
                return Ok(SourceReuseStatus::CorruptBlob);
            }
            timings.blob_rehash_ms = timings
                .blob_rehash_ms
                .saturating_add(rehash_start.elapsed().as_millis());
        }
        let validation = SourceValidationRecord {
            schema: CAS_SCHEMA_VERSION,
            source_sri: record.source_sri.clone(),
            tree_digest: record.tree_digest.clone(),
            blob_stat_fingerprint: self.blob_stat_fingerprint(manifest, timings, batch)?,
        };
        self.write_source_validation(&validation)?;
        Ok(SourceReuseStatus::Reusable)
    }

    fn blob_stat_fingerprint(
        &self,
        manifest: &CasManifest,
        timings: &mut FileCasReuseTimings,
        batch: Option<&FileCasValidationBatch>,
    ) -> Result<String, LpmError> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"lpm-v3-source-blob-stat-v1\0");
        for key in unique_manifest_blob_keys(manifest) {
            let fingerprint = self.blob_stat(key, timings, batch)?;
            hasher.update(key.digest.as_bytes());
            hasher.update(&key.mode.to_le_bytes());
            hasher.update(&key.size.to_le_bytes());
            fingerprint.update_hasher(&mut hasher);
        }
        Ok(hasher.finalize().to_hex().to_string())
    }

    fn blob_stat(
        &self,
        key: &BlobKey,
        timings: &mut FileCasReuseTimings,
        batch: Option<&FileCasValidationBatch>,
    ) -> Result<BlobStatFingerprint, LpmError> {
        if let Some(fingerprint) = batch.and_then(|batch| {
            batch
                .blob_stats
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .get(key)
                .copied()
        }) {
            timings.blob_stat_cache_hit_count = timings.blob_stat_cache_hit_count.saturating_add(1);
            return Ok(fingerprint);
        }
        let start = std::time::Instant::now();
        timings.blob_stat_count = timings.blob_stat_count.saturating_add(1);
        let result = self.read_blob_stat(key);
        timings.blob_stat_ms = timings
            .blob_stat_ms
            .saturating_add(start.elapsed().as_millis());
        if let (Ok(fingerprint), Some(batch)) = (result.as_ref(), batch) {
            batch
                .blob_stats
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .insert(key.clone(), *fingerprint);
        }
        result
    }

    fn read_blob_stat(&self, key: &BlobKey) -> Result<BlobStatFingerprint, LpmError> {
        let path = self.blob_path(key)?;
        let metadata = fs::symlink_metadata(&path).map_err(|error| {
            LpmError::Store(format!(
                "failed to inspect v3 CAS blob {}: {error}",
                path.display()
            ))
        })?;
        if !metadata.file_type().is_file()
            || metadata.len() != key.size
            || normalized_mode(&metadata) != key.mode
        {
            return Err(LpmError::Store(format!(
                "v3 CAS blob metadata mismatch at {}",
                path.display()
            )));
        }
        #[cfg(windows)]
        let fingerprint = BlobStatFingerprint::from_path(&path)?;
        #[cfg(not(windows))]
        let fingerprint = BlobStatFingerprint::from_metadata(&metadata);
        Ok(fingerprint)
    }

    fn write_source_validation(&self, validation: &SourceValidationRecord) -> Result<(), LpmError> {
        let path = self.source_validation_path(&validation.source_sri)?;
        let parent = path.parent().ok_or_else(|| {
            LpmError::Store(format!(
                "v3 CAS source validation has no parent: {}",
                path.display()
            ))
        })?;
        self.ensure_cas_directory(parent).map_err(|error| {
            LpmError::Store(format!(
                "failed to create v3 CAS source validation metadata at {}: {error}",
                parent.display()
            ))
        })?;
        let bytes = rmp_serde::to_vec_named(validation).map_err(|error| {
            LpmError::Store(format!(
                "failed to serialize v3 CAS source validation: {error}"
            ))
        })?;
        if bytes.len() as u64 > SOURCE_VALIDATION_MAX_BYTES {
            return Err(LpmError::Store(format!(
                "v3 CAS source validation is {} bytes; cap is {SOURCE_VALIDATION_MAX_BYTES}",
                bytes.len()
            )));
        }
        write_file_atomic(&path, bytes).map_err(|error| {
            LpmError::Store(format!(
                "failed to atomically update v3 CAS source validation at {}: {error}",
                path.display()
            ))
        })
    }

    pub(crate) fn source_tree_digest(
        &self,
        object_dir: &Path,
        source_sri: &str,
    ) -> Result<String, LpmError> {
        let record = self.read_source_record(source_sri).map_err(|error| {
            LpmError::Store(format!(
                "failed to read v3 CAS source record for {}: {error}",
                object_dir.display()
            ))
        })?;
        let segment = object_dir.file_name().ok_or_else(|| {
            LpmError::Store(format!(
                "v3 CAS source object has no path segment: {}",
                object_dir.display()
            ))
        })?;
        if record.schema != CAS_SCHEMA_VERSION
            || record.source_sri != source_sri
            || record.object_segment != encode_os_str(segment)
            || !valid_hex_digest(&record.tree_digest)
        {
            return Err(LpmError::Store(format!(
                "invalid v3 CAS source record for {}",
                object_dir.display()
            )));
        }
        Ok(record.tree_digest)
    }

    pub(crate) fn source_manifest_for_verify(
        &self,
        object_dir: &Path,
        source_sri: &str,
    ) -> Result<(SourceRecord, Arc<CasManifest>), LpmError> {
        let record = self.read_source_record(source_sri).map_err(|error| {
            LpmError::Store(format!(
                "failed to read v3 CAS source record for {}: {error}",
                object_dir.display()
            ))
        })?;
        let segment = object_dir.file_name().ok_or_else(|| {
            LpmError::Store(format!(
                "v3 CAS source object has no path segment: {}",
                object_dir.display()
            ))
        })?;
        if record.schema != CAS_SCHEMA_VERSION
            || record.source_sri != source_sri
            || record.object_segment != encode_os_str(segment)
            || !valid_hex_digest(&record.tree_digest)
        {
            return Err(LpmError::Store(format!(
                "invalid v3 CAS source record for {}",
                object_dir.display()
            )));
        }
        let manifest = self.manifest_for_digest(&record.tree_digest)?;
        if record.local_source != manifest.allows_symlinks {
            return Err(LpmError::Store(format!(
                "invalid v3 CAS tree manifest for {}",
                object_dir.display()
            )));
        }
        Ok((record, manifest))
    }

    pub(crate) fn source_record_from_file(&self, path: &Path) -> Result<SourceRecord, LpmError> {
        let bytes = read_capped(path, SOURCE_RECORD_MAX_BYTES)?;
        let record: SourceRecord = rmp_serde::from_slice(&bytes).map_err(|error| {
            LpmError::Store(format!(
                "failed to parse v3 CAS source record {}: {error}",
                path.display()
            ))
        })?;
        if record.schema != CAS_SCHEMA_VERSION
            || record.source_sri.is_empty()
            || record.object_segment.is_empty()
            || !valid_hex_digest(&record.tree_digest)
            || self.source_record_path(&record.source_sri)? != path
        {
            return Err(LpmError::Store(format!(
                "invalid v3 CAS source record at {}",
                path.display()
            )));
        }
        Ok(record)
    }

    pub(crate) fn manifest_for_source_record(
        &self,
        record: &SourceRecord,
    ) -> Result<Arc<CasManifest>, LpmError> {
        let manifest = self.manifest_for_digest(&record.tree_digest)?;
        if manifest.allows_symlinks != record.local_source {
            return Err(LpmError::Store(format!(
                "v3 CAS source/tree symlink policy mismatch for {}",
                record.source_sri
            )));
        }
        Ok(manifest)
    }

    fn manifest_for_source_record_with_timings(
        &self,
        record: &SourceRecord,
        timings: &mut FileCasReuseTimings,
    ) -> Result<Arc<CasManifest>, LpmError> {
        let manifest = self.manifest_for_digest_with_timings(&record.tree_digest, timings)?;
        if manifest.allows_symlinks != record.local_source {
            return Err(LpmError::Store(format!(
                "v3 CAS source/tree symlink policy mismatch for {}",
                record.source_sri
            )));
        }
        Ok(manifest)
    }

    #[cfg(any(target_os = "macos", test))]
    pub(crate) fn materialized_source(
        &self,
        object_dir: &Path,
        source_sri: &str,
    ) -> Result<PathBuf, LpmError> {
        let (record, manifest) = self.source_manifest_for_verify(object_dir, source_sri)?;
        self.ensure_materialized_entry(&record.tree_digest, &manifest)
    }

    #[cfg_attr(
        not(target_os = "macos"),
        expect(
            clippy::unnecessary_wraps,
            reason = "the cross-platform API is fallible on macOS without adding I/O elsewhere"
        )
    )]
    pub(crate) fn link_materialization_source(
        &self,
        object_dir: &Path,
        source_sri: &str,
        freshly_validated: bool,
    ) -> Result<PathBuf, LpmError> {
        #[cfg(target_os = "macos")]
        {
            // A current extraction handle proves the object was validated in this
            // operation. Recursive clonefile creates independent CoW inodes, so
            // cloning it directly avoids changing CAS blob ctimes via an
            // intermediate hardlink farm without exposing the blobs to writes.
            if freshly_validated {
                return Ok(object_dir.to_path_buf());
            }
            self.materialized_source(object_dir, source_sri)
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (source_sri, freshly_validated);
            Ok(object_dir.to_path_buf())
        }
    }

    #[cfg(any(target_os = "macos", test))]
    fn ensure_materialized_entry(
        &self,
        tree_digest: &str,
        manifest: &CasManifest,
    ) -> Result<PathBuf, LpmError> {
        let final_entry = self.materialized_entry_dir(tree_digest)?;
        let final_package = final_entry.join("package");
        if final_entry.exists() {
            if self.materialized_entry_is_complete(&final_entry, tree_digest) {
                return Ok(final_package);
            }
            if self
                .validate_materialized_entry(&final_entry, tree_digest, manifest)
                .is_ok()
            {
                self.write_materialized_complete(&final_entry, tree_digest)?;
                return Ok(final_package);
            }
            self.quarantine_entry(&final_entry, "materialized")?;
        }

        let parent = final_entry.parent().ok_or_else(|| {
            LpmError::Store(format!(
                "v3 CAS materialized entry has no parent: {}",
                final_entry.display()
            ))
        })?;
        self.ensure_cas_directory(parent).map_err(|error| {
            LpmError::Store(format!(
                "failed to create v3 CAS materialized shard at {}: {error}",
                parent.display()
            ))
        })?;
        let staged_entry = tmp_sibling(&final_entry);
        create_materialized_stage(&staged_entry)?;
        let staged_package = staged_entry.join("package");
        let result = self.materialize_manifest_into(manifest, &staged_package);
        if let Err(error) = result {
            let _ = fs::remove_dir_all(&staged_entry);
            return Err(error);
        }
        if let Err(error) = self.write_materialized_complete(&staged_entry, tree_digest) {
            let _ = fs::remove_dir_all(&staged_entry);
            return Err(error);
        }

        match fs::rename(&staged_entry, &final_entry) {
            Ok(()) => Ok(final_package),
            Err(first_error) => {
                if self.materialized_entry_is_complete(&final_entry, tree_digest) {
                    let _ = fs::remove_dir_all(&staged_entry);
                    return Ok(final_package);
                }
                if final_entry.exists() {
                    self.quarantine_entry(&final_entry, "materialized")?;
                }
                match fs::rename(&staged_entry, &final_entry) {
                    Ok(()) => Ok(final_package),
                    Err(second_error) => {
                        let _ = fs::remove_dir_all(&staged_entry);
                        Err(LpmError::Store(format!(
                            "failed to publish v3 CAS materialized entry {}: {first_error}; retry: {second_error}",
                            final_entry.display()
                        )))
                    }
                }
            }
        }
    }

    pub(crate) fn materialized_entry_is_complete(
        &self,
        entry_dir: &Path,
        tree_digest: &str,
    ) -> bool {
        fs::symlink_metadata(entry_dir).is_ok_and(|metadata| metadata.file_type().is_dir())
            && fs::symlink_metadata(entry_dir.join("package"))
                .is_ok_and(|metadata| metadata.file_type().is_dir())
            && read_capped_io(
                &entry_dir.join(MATERIALIZED_COMPLETE_FILENAME),
                tree_digest.len() as u64,
            )
            .is_ok_and(|bytes| bytes == tree_digest.as_bytes())
    }

    #[cfg(any(target_os = "macos", test))]
    fn write_materialized_complete(
        &self,
        entry_dir: &Path,
        tree_digest: &str,
    ) -> Result<(), LpmError> {
        write_file_atomic(
            &entry_dir.join(MATERIALIZED_COMPLETE_FILENAME),
            tree_digest.as_bytes(),
        )
        .map_err(|error| {
            LpmError::Store(format!(
                "failed to write v3 CAS materialized completion marker at {}: {error}",
                entry_dir.display()
            ))
        })
    }

    #[cfg(any(target_os = "macos", test))]
    fn materialize_manifest_into(
        &self,
        manifest: &CasManifest,
        destination: &Path,
    ) -> Result<(), LpmError> {
        let mut directory_modes = Vec::new();
        for entry in &manifest.entries {
            let relative = decode_relative_path(&entry.path)?;
            let path = destination.join(relative);
            match entry.kind {
                CasEntryKind::Directory => {
                    fs::create_dir_all(&path).map_err(|error| {
                        LpmError::Store(format!(
                            "failed to create v3 CAS materialized directory {}: {error}",
                            path.display()
                        ))
                    })?;
                    directory_modes.push((path, entry.mode));
                }
                CasEntryKind::File => {
                    let key = entry.blob.as_ref().ok_or_else(|| {
                        LpmError::Store("v3 CAS file entry is missing its blob key".into())
                    })?;
                    let blob = self.verify_blob(key, false, &mut [])?;
                    if let Some(parent) = path.parent() {
                        fs::create_dir_all(parent).map_err(|error| {
                            LpmError::Store(format!(
                                "failed to create v3 CAS materialized parent {}: {error}",
                                parent.display()
                            ))
                        })?;
                    }
                    fs::hard_link(&blob, &path).map_err(|error| {
                        LpmError::Store(format!(
                            "failed to hardlink v3 CAS blob {} into materialized cache {}: {error}",
                            blob.display(),
                            path.display()
                        ))
                    })?;
                }
                CasEntryKind::Symlink => {
                    if let Some(parent) = path.parent() {
                        fs::create_dir_all(parent).map_err(|error| {
                            LpmError::Store(format!(
                                "failed to create v3 CAS materialized symlink parent {}: {error}",
                                parent.display()
                            ))
                        })?;
                    }
                    let target = decode_os_string(&entry.symlink_target)?;
                    create_fs_symlink(Path::new(&target), &path).map_err(|error| {
                        LpmError::Store(format!(
                            "failed to create v3 CAS materialized symlink {}: {error}",
                            path.display()
                        ))
                    })?;
                }
            }
        }
        for (path, mode) in directory_modes.into_iter().rev() {
            set_normalized_mode(&path, mode)?;
        }
        Ok(())
    }

    pub(crate) fn validate_materialized_entry(
        &self,
        entry_dir: &Path,
        tree_digest: &str,
        manifest: &CasManifest,
    ) -> Result<(), LpmError> {
        if self.materialized_entry_dir(tree_digest)? != entry_dir {
            return Err(LpmError::Store(format!(
                "invalid v3 CAS materialized entry path {}",
                entry_dir.display()
            )));
        }
        let package = entry_dir.join("package");
        let package_metadata = fs::symlink_metadata(&package).map_err(|error| {
            LpmError::Store(format!(
                "failed to inspect v3 CAS materialized package {}: {error}",
                package.display()
            ))
        })?;
        if !package_metadata.file_type().is_dir() {
            return Err(LpmError::Store(format!(
                "v3 CAS materialized package is not a directory at {}",
                package.display()
            )));
        }
        if count_tree_entries(&package)? != manifest.entries.len() {
            return Err(LpmError::Store(format!(
                "v3 CAS materialized entry count mismatch at {}",
                package.display()
            )));
        }
        for entry in &manifest.entries {
            let relative = decode_relative_path(&entry.path)?;
            let path = package.join(relative);
            let metadata = fs::symlink_metadata(&path).map_err(|error| {
                LpmError::Store(format!(
                    "failed to inspect v3 CAS materialized entry {}: {error}",
                    path.display()
                ))
            })?;
            match entry.kind {
                CasEntryKind::Directory
                    if metadata.file_type().is_dir()
                        && normalized_mode(&metadata) == entry.mode => {}
                CasEntryKind::File if metadata.file_type().is_file() => {
                    let key = entry.blob.as_ref().ok_or_else(|| {
                        LpmError::Store("v3 CAS file entry is missing its blob key".into())
                    })?;
                    let blob = self.verify_blob(key, false, &mut [])?;
                    if metadata.len() != key.size
                        || normalized_mode(&metadata) != key.mode
                        || !same_file_identity(&metadata, &fs::metadata(&blob)?)
                    {
                        return Err(LpmError::Store(format!(
                            "v3 CAS materialized file does not match blob at {}",
                            path.display()
                        )));
                    }
                }
                CasEntryKind::Symlink if metadata.file_type().is_symlink() => {
                    let target = fs::read_link(&path).map_err(|error| {
                        LpmError::Store(format!(
                            "failed to read v3 CAS materialized symlink {}: {error}",
                            path.display()
                        ))
                    })?;
                    if encode_os_str(target.as_os_str()) != entry.symlink_target {
                        return Err(LpmError::Store(format!(
                            "v3 CAS materialized symlink target mismatch at {}",
                            path.display()
                        )));
                    }
                }
                _ => {
                    return Err(LpmError::Store(format!(
                        "v3 CAS materialized entry type mismatch at {}",
                        path.display()
                    )));
                }
            }
        }
        Ok(())
    }

    pub(crate) fn manifest_from_file(
        &self,
        path: &Path,
    ) -> Result<(String, Arc<CasManifest>), LpmError> {
        let file_name = path.file_name().and_then(OsStr::to_str).ok_or_else(|| {
            LpmError::Store(format!(
                "invalid v3 CAS tree manifest path {}",
                path.display()
            ))
        })?;
        let digest = file_name.strip_suffix(".msgpack").ok_or_else(|| {
            LpmError::Store(format!(
                "invalid v3 CAS tree manifest name {}",
                path.display()
            ))
        })?;
        if !valid_hex_digest(digest) || self.tree_manifest_path(digest)? != path {
            return Err(LpmError::Store(format!(
                "invalid v3 CAS tree manifest path {}",
                path.display()
            )));
        }
        self.manifest_for_digest(digest)
            .map(|manifest| (digest.to_string(), manifest))
    }

    pub(crate) fn blob_key_from_file(&self, path: &Path) -> Result<BlobKey, LpmError> {
        let file_name = path.file_name().and_then(OsStr::to_str).ok_or_else(|| {
            LpmError::Store(format!("invalid v3 CAS blob path {}", path.display()))
        })?;
        let (digest, mode) = file_name.rsplit_once('-').ok_or_else(|| {
            LpmError::Store(format!("invalid v3 CAS blob name {}", path.display()))
        })?;
        let mode = u32::from_str_radix(mode, 8)
            .map_err(|_| LpmError::Store(format!("invalid v3 CAS blob mode {}", path.display())))?;
        let metadata = fs::symlink_metadata(path).map_err(|error| {
            LpmError::Store(format!(
                "failed to inspect v3 CAS blob {}: {error}",
                path.display()
            ))
        })?;
        let key = BlobKey {
            digest: digest.to_string(),
            mode,
            size: metadata.len(),
        };
        if !metadata.file_type().is_file()
            || !valid_hex_digest(digest)
            || self.blob_path(&key)? != path
            || normalized_mode(&metadata) != mode
        {
            return Err(LpmError::Store(format!(
                "invalid v3 CAS blob at {}",
                path.display()
            )));
        }
        Ok(key)
    }

    fn manifest_for_digest(&self, digest: &str) -> Result<Arc<CasManifest>, LpmError> {
        let mut timings = FileCasReuseTimings::default();
        self.manifest_for_digest_with_timings(digest, &mut timings)
    }

    fn manifest_for_digest_with_timings(
        &self,
        digest: &str,
        timings: &mut FileCasReuseTimings,
    ) -> Result<Arc<CasManifest>, LpmError> {
        let path = self.tree_manifest_path(digest)?;
        let (size, fingerprint) = manifest_file_fingerprint(&path)?;
        if let Some(manifest) = self
            .manifest_cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(digest)
            .filter(|entry| entry.size == size && entry.fingerprint == fingerprint)
            .map(|entry| Arc::clone(&entry.manifest))
        {
            return Ok(manifest);
        }
        let read_start = std::time::Instant::now();
        let manifest_bytes = read_capped(&path, MANIFEST_MAX_BYTES)?;
        timings.manifest_read_count = timings.manifest_read_count.saturating_add(1);
        timings.manifest_read_ms = timings
            .manifest_read_ms
            .saturating_add(read_start.elapsed().as_millis());
        let (size_after_read, fingerprint_after_read) = manifest_file_fingerprint(&path)?;
        if size != size_after_read || fingerprint != fingerprint_after_read {
            return Err(LpmError::Store(format!(
                "v3 CAS tree manifest changed while being read for {digest}"
            )));
        }
        let validate_start = std::time::Instant::now();
        if blake3::hash(&manifest_bytes).to_hex().as_str() != digest {
            return Err(LpmError::Store(format!(
                "v3 CAS tree digest mismatch for {digest}"
            )));
        }
        let manifest: CasManifest = rmp_serde::from_slice(&manifest_bytes).map_err(|error| {
            LpmError::Store(format!(
                "failed to parse v3 CAS tree manifest {digest}: {error}"
            ))
        })?;
        if !validate_manifest(&manifest)? {
            return Err(LpmError::Store(format!(
                "invalid v3 CAS tree manifest {digest}"
            )));
        }
        timings.manifest_validate_ms = timings
            .manifest_validate_ms
            .saturating_add(validate_start.elapsed().as_millis());
        let manifest = Arc::new(manifest);
        self.manifest_cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(
                digest.to_string(),
                ManifestCacheEntry {
                    size,
                    fingerprint,
                    manifest: Arc::clone(&manifest),
                },
            );
        Ok(manifest)
    }

    pub(crate) fn verify_blob(
        &self,
        key: &BlobKey,
        deep: bool,
        hash_buffer: &mut [u8],
    ) -> Result<PathBuf, LpmError> {
        let path = self.blob_path(key)?;
        if deep {
            self.validate_blob(&path, key, hash_buffer)?;
        } else if !blob_metadata_is_valid(&path, key) {
            return Err(LpmError::Store(format!(
                "v3 CAS blob metadata mismatch at {}",
                path.display()
            )));
        }
        Ok(path)
    }

    fn ingest_dir(
        &self,
        ingest: &mut TreeIngestContext<'_>,
        dir: &Path,
        relative: &mut Vec<u8>,
        depth: usize,
    ) -> Result<(), LpmError> {
        if depth > MAX_TREE_DEPTH {
            return Err(LpmError::Store(format!(
                "v3 CAS tree exceeds maximum depth ({MAX_TREE_DEPTH}) at {}",
                dir.display()
            )));
        }
        let mut names = Vec::new();
        for entry in fs::read_dir(dir).map_err(|error| {
            LpmError::Store(format!(
                "failed to read v3 CAS source tree at {}: {error}",
                dir.display()
            ))
        })? {
            names.push(entry?.file_name());
        }
        names.sort_unstable();

        let mut path = dir.to_path_buf();
        for name in names {
            path.push(&name);
            if is_object_metadata_sidecar(ingest.object_root, &path) {
                path.pop();
                continue;
            }
            let relative_len = relative.len();
            if relative_len != 0 {
                push_path_separator(relative);
            }
            push_os_str(relative, &name);
            validate_relative_path(relative)?;
            let metadata = fs::symlink_metadata(&path).map_err(|error| {
                LpmError::Store(format!(
                    "failed to inspect v3 CAS source entry {}: {error}",
                    path.display()
                ))
            })?;
            let file_type = metadata.file_type();
            if file_type.is_dir() {
                ingest.entries.push(CasManifestEntry {
                    path: relative.clone(),
                    kind: CasEntryKind::Directory,
                    mode: normalized_mode(&metadata),
                    size: 0,
                    blob: None,
                    symlink_target: Vec::new(),
                });
                self.ingest_dir(ingest, &path, relative, depth + 1)?;
            } else if file_type.is_file() {
                let blob = self.ingest_file(&path, &metadata, ingest.hash_buffer)?;
                ingest.entries.push(CasManifestEntry {
                    path: relative.clone(),
                    kind: CasEntryKind::File,
                    mode: blob.mode,
                    size: blob.size,
                    blob: Some(blob),
                    symlink_target: Vec::new(),
                });
            } else if file_type.is_symlink() && ingest.allows_symlinks {
                let target = fs::read_link(&path).map_err(|error| {
                    LpmError::Store(format!(
                        "failed to read v3 CAS local-source symlink {}: {error}",
                        path.display()
                    ))
                })?;
                ingest.entries.push(CasManifestEntry {
                    path: relative.clone(),
                    kind: CasEntryKind::Symlink,
                    mode: normalized_mode(&metadata),
                    size: 0,
                    blob: None,
                    symlink_target: encode_os_str(target.as_os_str()),
                });
            } else {
                return Err(LpmError::Store(format!(
                    "unsupported entry type in v3 CAS object at {}",
                    path.display()
                )));
            }
            relative.truncate(relative_len);
            path.pop();
        }
        Ok(())
    }

    fn ingest_file(
        &self,
        source: &Path,
        metadata: &fs::Metadata,
        hash_buffer: &mut [u8],
    ) -> Result<BlobKey, LpmError> {
        let digest = hash_file(source, hash_buffer)?;
        let key = BlobKey {
            digest,
            mode: normalized_mode(metadata),
            size: metadata.len(),
        };
        self.publish_blob(source, &key, hash_buffer)?;
        Ok(key)
    }

    fn publish_blob(
        &self,
        source: &Path,
        key: &BlobKey,
        hash_buffer: &mut [u8],
    ) -> Result<(), LpmError> {
        let blob = self.blob_path(key)?;
        let parent = blob.parent().ok_or_else(|| {
            LpmError::Store(format!("v3 CAS blob has no parent: {}", blob.display()))
        })?;
        self.ensure_cas_directory(parent).map_err(|error| {
            LpmError::Store(format!(
                "failed to create v3 CAS blob shard at {}: {error}",
                parent.display()
            ))
        })?;

        match fs::hard_link(source, &blob) {
            Ok(()) => return Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => {
                return Err(LpmError::Store(format!(
                    "failed to publish v3 CAS blob {}: {error}",
                    blob.display()
                )));
            }
        }
        if self.validate_blob(&blob, key, hash_buffer).is_err() {
            self.quarantine_entry(&blob, "blobs")?;
            match fs::hard_link(source, &blob) {
                Ok(()) => return Ok(()),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    self.validate_blob(&blob, key, hash_buffer)?;
                }
                Err(error) => {
                    return Err(LpmError::Store(format!(
                        "failed to repair v3 CAS blob {}: {error}",
                        blob.display()
                    )));
                }
            }
        }
        replace_with_hardlink(&blob, source)?;
        Ok(())
    }

    fn ensure_cas_directory(&self, path: &Path) -> std::io::Result<()> {
        let mut secured = self
            .secured_directories
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if secured.contains(path) {
            return Ok(());
        }
        ensure_cas_directory_chain_locked(&self.store_root, path)?;
        secured.insert(path.to_path_buf());
        Ok(())
    }

    fn validate_blob(
        &self,
        blob: &Path,
        key: &BlobKey,
        hash_buffer: &mut [u8],
    ) -> Result<(), LpmError> {
        let metadata = fs::symlink_metadata(blob).map_err(|error| {
            LpmError::Store(format!(
                "failed to inspect existing v3 CAS blob {}: {error}",
                blob.display()
            ))
        })?;
        if !metadata.file_type().is_file()
            || metadata.len() != key.size
            || normalized_mode(&metadata) != key.mode
            || hash_file(blob, hash_buffer)? != key.digest
        {
            return Err(LpmError::Store(format!(
                "existing v3 CAS blob failed integrity validation at {}",
                blob.display()
            )));
        }
        Ok(())
    }

    fn publish_tree_manifest(&self, digest: &str, bytes: &[u8]) -> Result<(), LpmError> {
        let path = self.tree_manifest_path(digest)?;
        let parent = path.parent().ok_or_else(|| {
            LpmError::Store(format!(
                "v3 CAS tree manifest has no parent: {}",
                path.display()
            ))
        })?;
        self.ensure_cas_directory(parent).map_err(|error| {
            LpmError::Store(format!(
                "failed to create v3 CAS tree shard at {}: {error}",
                parent.display()
            ))
        })?;
        match read_capped_io(&path, MANIFEST_MAX_BYTES) {
            Ok(existing) if existing == bytes => Ok(()),
            Ok(_) => {
                self.quarantine_entry(&path, "trees")?;
                publish_bytes_no_replace(&path, bytes, MANIFEST_MAX_BYTES)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                publish_bytes_no_replace(&path, bytes, MANIFEST_MAX_BYTES)
            }
            Err(_) => {
                self.quarantine_entry(&path, "trees")?;
                publish_bytes_no_replace(&path, bytes, MANIFEST_MAX_BYTES)
            }
        }
    }

    #[cfg(test)]
    fn read_tree_manifest_bytes(&self, digest: &str) -> Result<Vec<u8>, LpmError> {
        read_capped(&self.tree_manifest_path(digest)?, MANIFEST_MAX_BYTES)
    }

    pub(crate) fn blob_path(&self, key: &BlobKey) -> Result<PathBuf, LpmError> {
        if !valid_hex_digest(&key.digest) {
            return Err(LpmError::Store("invalid v3 CAS blob digest".into()));
        }
        let shard = key
            .digest
            .get(..2)
            .ok_or_else(|| LpmError::Store("invalid v3 CAS blob digest shard".into()))?;
        Ok(self
            .blobs_root
            .join(shard)
            .join(format!("{}-{:04o}", key.digest, key.mode)))
    }

    pub(crate) fn tree_manifest_path(&self, digest: &str) -> Result<PathBuf, LpmError> {
        if !valid_hex_digest(digest) {
            return Err(LpmError::Store("invalid v3 CAS tree digest".into()));
        }
        let shard = digest
            .get(..2)
            .ok_or_else(|| LpmError::Store("invalid v3 CAS tree digest shard".into()))?;
        Ok(self
            .trees_root
            .join(shard)
            .join(format!("{digest}.msgpack")))
    }

    pub(crate) fn source_record_path(&self, source_sri: &str) -> Result<PathBuf, LpmError> {
        if source_sri.is_empty() {
            return Err(LpmError::Store("empty v3 CAS source identity".into()));
        }
        let digest = blake3::hash(source_sri.as_bytes()).to_hex().to_string();
        Ok(self
            .sources_root
            .join(&digest[..2])
            .join(format!("{digest}.msgpack")))
    }

    pub(crate) fn source_validation_path(&self, source_sri: &str) -> Result<PathBuf, LpmError> {
        if source_sri.is_empty() {
            return Err(LpmError::Store("empty v3 CAS source identity".into()));
        }
        let digest = blake3::hash(source_sri.as_bytes()).to_hex().to_string();
        Ok(self
            .source_validations_root
            .join(&digest[..2])
            .join(format!("{digest}.msgpack")))
    }

    pub(crate) fn materialized_entry_dir(&self, digest: &str) -> Result<PathBuf, LpmError> {
        if !valid_hex_digest(digest) {
            return Err(LpmError::Store(
                "invalid v3 CAS materialized tree digest".into(),
            ));
        }
        let shard = digest
            .get(..2)
            .ok_or_else(|| LpmError::Store("invalid v3 CAS materialized digest shard".into()))?;
        Ok(self.materialized_root.join(shard).join(digest))
    }

    pub(crate) fn materialized_digest_from_entry(&self, path: &Path) -> Result<String, LpmError> {
        let digest = path.file_name().and_then(OsStr::to_str).ok_or_else(|| {
            LpmError::Store(format!(
                "invalid v3 CAS materialized entry path {}",
                path.display()
            ))
        })?;
        if !valid_hex_digest(digest) || self.materialized_entry_dir(digest)? != path {
            return Err(LpmError::Store(format!(
                "invalid v3 CAS materialized entry path {}",
                path.display()
            )));
        }
        Ok(digest.to_string())
    }

    fn read_source_record(&self, source_sri: &str) -> Result<SourceRecord, std::io::Error> {
        let path = self
            .source_record_path(source_sri)
            .map_err(std::io::Error::other)?;
        let bytes = read_capped_io(&path, SOURCE_RECORD_MAX_BYTES)?;
        rmp_serde::from_slice(&bytes).map_err(std::io::Error::other)
    }

    fn read_source_validation(
        &self,
        source_sri: &str,
    ) -> Result<SourceValidationRecord, std::io::Error> {
        let path = self
            .source_validation_path(source_sri)
            .map_err(std::io::Error::other)?;
        let bytes = read_capped_io(&path, SOURCE_VALIDATION_MAX_BYTES)?;
        rmp_serde::from_slice(&bytes).map_err(std::io::Error::other)
    }

    pub(crate) fn blob_files(&self) -> Result<Vec<PathBuf>, LpmError> {
        list_sharded_regular_files(&self.blobs_root)
    }

    pub(crate) fn tree_manifest_files(&self) -> Result<Vec<PathBuf>, LpmError> {
        list_sharded_regular_files(&self.trees_root)
    }

    pub(crate) fn source_record_files(&self) -> Result<Vec<PathBuf>, LpmError> {
        list_sharded_regular_files(&self.sources_root)
    }

    pub(crate) fn source_validation_files(&self) -> Result<Vec<PathBuf>, LpmError> {
        list_sharded_regular_files(&self.source_validations_root)
    }

    pub(crate) fn materialized_entry_dirs(&self) -> Result<Vec<PathBuf>, LpmError> {
        list_sharded_directories(&self.materialized_root)
    }

    fn quarantine_entry(&self, path: &Path, kind: &str) -> Result<(), LpmError> {
        let file_name = path.file_name().ok_or_else(|| {
            LpmError::Store(format!(
                "v3 CAS quarantine target has no file name: {}",
                path.display()
            ))
        })?;
        let quarantine_root = self.store_root.join("quarantine").join(kind);
        self.ensure_cas_directory(&quarantine_root)
            .map_err(|error| {
                LpmError::Store(format!(
                    "failed to create v3 CAS quarantine at {}: {error}",
                    quarantine_root.display()
                ))
            })?;
        let destination = tmp_sibling(&quarantine_root.join(file_name));
        match fs::rename(path, &destination) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(LpmError::Store(format!(
                "failed to quarantine v3 CAS entry {}: {error}",
                path.display()
            ))),
        }
    }
}

fn ensure_cas_directory_chain_locked(store_root: &Path, path: &Path) -> io::Result<()> {
    let relative = path.strip_prefix(store_root).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "CAS directory {} is outside store root {}",
                path.display(),
                store_root.display()
            ),
        )
    })?;
    if let Some(parent) = store_root.parent() {
        fs::create_dir_all(parent)?;
    }
    ensure_real_directory_locked(store_root)?;

    let mut current = store_root.to_path_buf();
    for component in relative.components() {
        match component {
            std::path::Component::Normal(name) => current.push(name),
            std::path::Component::CurDir => continue,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("invalid CAS directory component in {}", path.display()),
                ));
            }
        }
        ensure_real_directory_locked(&current)?;
    }
    Ok(())
}

fn ensure_real_directory_locked(path: &Path) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_dir() => tighten_directory_permissions(path),
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "CAS path component is not a directory at {}",
                path.display()
            ),
        )),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            match create_directory_locked(path) {
                Ok(()) => Ok(()),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                    match fs::symlink_metadata(path) {
                        Ok(metadata) if metadata.file_type().is_dir() => {
                            tighten_directory_permissions(path)
                        }
                        Ok(_) => Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!(
                                "CAS path component is not a directory at {}",
                                path.display()
                            ),
                        )),
                        Err(error) => Err(error),
                    }
                }
                Err(error) => Err(error),
            }
        }
        Err(error) => Err(error),
    }
}

#[cfg(unix)]
fn create_directory_locked(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;

    let mut builder = fs::DirBuilder::new();
    builder.mode(0o700).create(path)
}

#[cfg(not(unix))]
fn create_directory_locked(path: &Path) -> io::Result<()> {
    fs::create_dir(path)
}

#[cfg(unix)]
fn tighten_directory_permissions(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
}

#[cfg(not(unix))]
fn tighten_directory_permissions(_path: &Path) -> io::Result<()> {
    Ok(())
}

fn list_sharded_regular_files(root: &Path) -> Result<Vec<PathBuf>, LpmError> {
    ensure_cas_root_directory(root)?;
    if !root.try_exists()? {
        return Ok(Vec::new());
    }
    let mut files = Vec::new();
    for shard in fs::read_dir(root).map_err(|error| {
        LpmError::Store(format!(
            "failed to enumerate v3 CAS root {}: {error}",
            root.display()
        ))
    })? {
        let shard = shard.map_err(|error| {
            LpmError::Store(format!("failed to enumerate v3 CAS shard: {error}"))
        })?;
        let shard_type = shard
            .file_type()
            .map_err(|error| LpmError::Store(format!("failed to inspect v3 CAS shard: {error}")))?;
        if !shard_type.is_dir() {
            return Err(LpmError::Store(format!(
                "v3 CAS shard is not a directory at {}",
                shard.path().display()
            )));
        }
        for entry in fs::read_dir(shard.path()).map_err(|error| {
            LpmError::Store(format!(
                "failed to enumerate v3 CAS shard {}: {error}",
                shard.path().display()
            ))
        })? {
            let entry = entry.map_err(|error| {
                LpmError::Store(format!("failed to enumerate v3 CAS entry: {error}"))
            })?;
            let file_type = entry.file_type().map_err(|error| {
                LpmError::Store(format!(
                    "failed to inspect v3 CAS entry {}: {error}",
                    entry.path().display()
                ))
            })?;
            if !file_type.is_file() {
                return Err(LpmError::Store(format!(
                    "v3 CAS entry is not a regular file at {}",
                    entry.path().display()
                )));
            }
            files.push(entry.path());
        }
    }
    files.sort_unstable();
    Ok(files)
}

fn list_sharded_directories(root: &Path) -> Result<Vec<PathBuf>, LpmError> {
    ensure_cas_root_directory(root)?;
    if !root.try_exists()? {
        return Ok(Vec::new());
    }
    let mut directories = Vec::new();
    for shard in fs::read_dir(root).map_err(|error| {
        LpmError::Store(format!(
            "failed to enumerate v3 CAS root {}: {error}",
            root.display()
        ))
    })? {
        let shard = shard.map_err(|error| {
            LpmError::Store(format!("failed to enumerate v3 CAS shard: {error}"))
        })?;
        let shard_type = shard
            .file_type()
            .map_err(|error| LpmError::Store(format!("failed to inspect v3 CAS shard: {error}")))?;
        if !shard_type.is_dir() {
            return Err(LpmError::Store(format!(
                "v3 CAS shard is not a directory at {}",
                shard.path().display()
            )));
        }
        for entry in fs::read_dir(shard.path()).map_err(|error| {
            LpmError::Store(format!(
                "failed to enumerate v3 CAS shard {}: {error}",
                shard.path().display()
            ))
        })? {
            let entry = entry.map_err(|error| {
                LpmError::Store(format!("failed to enumerate v3 CAS entry: {error}"))
            })?;
            let file_type = entry.file_type().map_err(|error| {
                LpmError::Store(format!(
                    "failed to inspect v3 CAS entry {}: {error}",
                    entry.path().display()
                ))
            })?;
            if !file_type.is_dir() {
                return Err(LpmError::Store(format!(
                    "v3 CAS entry is not a directory at {}",
                    entry.path().display()
                )));
            }
            directories.push(entry.path());
        }
    }
    directories.sort_unstable();
    Ok(directories)
}

fn ensure_cas_root_directory(root: &Path) -> Result<(), LpmError> {
    match fs::symlink_metadata(root) {
        Ok(metadata) if metadata.file_type().is_dir() => Ok(()),
        Ok(_) => Err(LpmError::Store(format!(
            "v3 CAS root is not a directory at {}",
            root.display()
        ))),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(LpmError::Store(format!(
            "failed to inspect v3 CAS root {}: {error}",
            root.display()
        ))),
    }
}

#[cfg(any(target_os = "macos", test))]
fn create_materialized_stage(path: &Path) -> Result<(), LpmError> {
    create_tmp_dir_locked(path).map_err(|error| {
        LpmError::Store(format!(
            "failed to create v3 CAS materialized stage {}: {error}",
            path.display()
        ))
    })?;
    let package = path.join("package");
    create_tmp_dir_locked(&package).map_err(|error| {
        let _ = fs::remove_dir_all(path);
        LpmError::Store(format!(
            "failed to create v3 CAS materialized package stage {}: {error}",
            package.display()
        ))
    })
}

fn count_tree_entries(root: &Path) -> Result<usize, LpmError> {
    let mut count = 0_usize;
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(&directory).map_err(|error| {
            LpmError::Store(format!(
                "failed to enumerate v3 CAS materialized directory {}: {error}",
                directory.display()
            ))
        })? {
            let entry = entry.map_err(|error| {
                LpmError::Store(format!(
                    "failed to enumerate v3 CAS materialized entry: {error}"
                ))
            })?;
            count = count.saturating_add(1);
            if entry
                .file_type()
                .map_err(|error| {
                    LpmError::Store(format!(
                        "failed to inspect v3 CAS materialized entry {}: {error}",
                        entry.path().display()
                    ))
                })?
                .is_dir()
            {
                pending.push(entry.path());
            }
        }
    }
    Ok(count)
}

#[cfg(unix)]
fn same_file_identity(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    (left.dev(), left.ino()) == (right.dev(), right.ino())
}

#[cfg(not(unix))]
fn same_file_identity(_left: &fs::Metadata, _right: &fs::Metadata) -> bool {
    true
}

#[cfg(all(unix, any(target_os = "macos", test)))]
fn set_normalized_mode(path: &Path, mode: u32) -> Result<(), LpmError> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).map_err(|error| {
        LpmError::Store(format!(
            "failed to apply v3 CAS materialized mode at {}: {error}",
            path.display()
        ))
    })
}

#[cfg(all(not(unix), any(target_os = "macos", test)))]
fn set_normalized_mode(path: &Path, mode: u32) -> Result<(), LpmError> {
    let mut permissions = fs::metadata(path)
        .map_err(|error| {
            LpmError::Store(format!(
                "failed to inspect v3 CAS materialized mode at {}: {error}",
                path.display()
            ))
        })?
        .permissions();
    permissions.set_readonly(mode & 0o222 == 0);
    fs::set_permissions(path, permissions).map_err(|error| {
        LpmError::Store(format!(
            "failed to apply v3 CAS materialized mode at {}: {error}",
            path.display()
        ))
    })
}

fn blob_metadata_is_valid(path: &Path, key: &BlobKey) -> bool {
    fs::symlink_metadata(path).is_ok_and(|metadata| {
        metadata.file_type().is_file()
            && metadata.len() == key.size
            && normalized_mode(&metadata) == key.mode
    })
}

fn unique_manifest_blob_keys(manifest: &CasManifest) -> Vec<&BlobKey> {
    let mut keys = manifest
        .entries
        .iter()
        .filter_map(|entry| entry.blob.as_ref())
        .collect::<Vec<_>>();
    keys.sort_unstable_by(|left, right| {
        (&left.digest, left.mode, left.size).cmp(&(&right.digest, right.mode, right.size))
    });
    keys.dedup();
    keys
}

#[cfg(unix)]
impl BlobStatFingerprint {
    fn from_metadata(metadata: &fs::Metadata) -> Self {
        use std::os::unix::fs::MetadataExt;

        Self {
            dev: metadata.dev(),
            ino: metadata.ino(),
            mtime: metadata.mtime(),
            mtime_nsec: metadata.mtime_nsec(),
            ctime: metadata.ctime(),
            ctime_nsec: metadata.ctime_nsec(),
        }
    }

    fn update_hasher(self, hasher: &mut blake3::Hasher) {
        hasher.update(&self.dev.to_le_bytes());
        hasher.update(&self.ino.to_le_bytes());
        hasher.update(&self.mtime.to_le_bytes());
        hasher.update(&self.mtime_nsec.to_le_bytes());
        hasher.update(&self.ctime.to_le_bytes());
        hasher.update(&self.ctime_nsec.to_le_bytes());
    }
}

#[cfg(windows)]
impl BlobStatFingerprint {
    fn from_path(path: &Path) -> Result<Self, LpmError> {
        use std::os::windows::fs::MetadataExt;
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Storage::FileSystem::{
            BY_HANDLE_FILE_INFORMATION, FILE_BASIC_INFO, FileBasicInfo, GetFileInformationByHandle,
            GetFileInformationByHandleEx,
        };

        let file = open_regular_file_nofollow(path).map_err(|error| {
            LpmError::Store(format!(
                "failed to open v3 CAS blob for Windows identity at {}: {error}",
                path.display()
            ))
        })?;
        let metadata = file.metadata().map_err(|error| {
            LpmError::Store(format!(
                "failed to inspect v3 CAS blob identity at {}: {error}",
                path.display()
            ))
        })?;
        let handle = file.as_raw_handle();
        let mut handle_info = BY_HANDLE_FILE_INFORMATION::default();
        // SAFETY: `handle` comes from the live `File` above and
        // `handle_info` is writable storage of the exact Win32 type.
        if unsafe { GetFileInformationByHandle(handle, &mut handle_info) } == 0 {
            return Err(LpmError::Store(format!(
                "failed to read v3 CAS blob identity at {}: {}",
                path.display(),
                std::io::Error::last_os_error()
            )));
        }
        let mut basic_info = FILE_BASIC_INFO::default();
        // SAFETY: `handle` is live and `basic_info` is writable storage for
        // the `FileBasicInfo` result requested from Win32.
        if unsafe {
            GetFileInformationByHandleEx(
                handle,
                FileBasicInfo,
                &mut basic_info as *mut _ as *mut _,
                std::mem::size_of::<FILE_BASIC_INFO>() as u32,
            )
        } == 0
        {
            return Err(LpmError::Store(format!(
                "failed to read v3 CAS blob change time at {}: {}",
                path.display(),
                std::io::Error::last_os_error()
            )));
        }

        Ok(Self {
            volume_serial_number: handle_info.dwVolumeSerialNumber,
            file_index: (u64::from(handle_info.nFileIndexHigh) << 32)
                | u64::from(handle_info.nFileIndexLow),
            creation_time: metadata.creation_time(),
            last_write_time: metadata.last_write_time(),
            change_time: basic_info.ChangeTime,
            file_attributes: metadata.file_attributes(),
        })
    }

    fn update_hasher(self, hasher: &mut blake3::Hasher) {
        hasher.update(&self.volume_serial_number.to_le_bytes());
        hasher.update(&self.file_index.to_le_bytes());
        hasher.update(&self.creation_time.to_le_bytes());
        hasher.update(&self.last_write_time.to_le_bytes());
        hasher.update(&self.change_time.to_le_bytes());
        hasher.update(&self.file_attributes.to_le_bytes());
    }
}

#[cfg(not(any(unix, windows)))]
impl BlobStatFingerprint {
    fn from_metadata(metadata: &fs::Metadata) -> Self {
        use std::time::UNIX_EPOCH;

        let modified = metadata
            .modified()
            .ok()
            .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
            .map_or(0, |duration| duration.as_nanos());
        let created = metadata
            .created()
            .ok()
            .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
            .map_or(0, |duration| duration.as_nanos());
        Self {
            modified,
            created,
            readonly: metadata.permissions().readonly(),
        }
    }

    fn update_hasher(self, hasher: &mut blake3::Hasher) {
        hasher.update(&self.modified.to_le_bytes());
        hasher.update(&self.created.to_le_bytes());
        hasher.update(&[u8::from(self.readonly)]);
    }
}

fn manifest_file_fingerprint(path: &Path) -> Result<(u64, BlobStatFingerprint), LpmError> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        LpmError::Store(format!(
            "failed to inspect v3 CAS tree manifest {}: {error}",
            path.display()
        ))
    })?;
    if !metadata.file_type().is_file() || metadata.len() > MANIFEST_MAX_BYTES {
        return Err(LpmError::Store(format!(
            "invalid v3 CAS tree manifest file at {}",
            path.display()
        )));
    }
    #[cfg(windows)]
    let fingerprint = BlobStatFingerprint::from_path(path)?;
    #[cfg(not(windows))]
    let fingerprint = BlobStatFingerprint::from_metadata(&metadata);
    Ok((metadata.len(), fingerprint))
}

fn read_capped(path: &Path, cap: u64) -> Result<Vec<u8>, LpmError> {
    read_capped_io(path, cap).map_err(|error| {
        LpmError::Store(format!(
            "failed to read capped v3 CAS metadata at {}: {error}",
            path.display()
        ))
    })
}

fn read_capped_io(path: &Path, cap: u64) -> Result<Vec<u8>, std::io::Error> {
    let file = open_regular_file_nofollow(path)?;
    let metadata = file.metadata()?;
    if metadata.len() > cap {
        return Err(std::io::Error::other(format!(
            "CAS metadata is {} bytes; cap is {cap}",
            metadata.len()
        )));
    }
    let read_cap = cap
        .checked_add(1)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "CAS read cap is too large"))?;
    let capacity = usize::try_from(metadata.len().min(read_cap)).unwrap_or(0);
    let mut bytes = Vec::with_capacity(capacity);
    BufReader::new(file)
        .take(read_cap)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > cap {
        return Err(io::Error::other(format!(
            "CAS metadata exceeded {cap} bytes while being read"
        )));
    }
    Ok(bytes)
}

fn open_regular_file_nofollow(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file() {
        return Err(io::Error::other("CAS entry is not a regular file"));
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(io::Error::other("CAS entry is a reparse point"));
        }
    }
    Ok(file)
}

fn publish_bytes_no_replace(path: &Path, bytes: &[u8], cap: u64) -> Result<(), LpmError> {
    if bytes.len() as u64 > cap {
        return Err(LpmError::Store(format!(
            "v3 CAS metadata is {} bytes; cap is {cap}",
            bytes.len()
        )));
    }
    let tmp = tmp_sibling(path);
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut staged = options.open(&tmp).map_err(|error| {
        LpmError::Store(format!(
            "failed to stage v3 CAS metadata at {}: {error}",
            tmp.display()
        ))
    })?;
    if let Err(error) = staged.write_all(bytes) {
        let _ = fs::remove_file(&tmp);
        return Err(LpmError::Store(format!(
            "failed to write v3 CAS metadata at {}: {error}",
            tmp.display()
        )));
    }
    drop(staged);
    match fs::hard_link(&tmp, path) {
        Ok(()) => {
            fs::remove_file(&tmp).map_err(|error| {
                LpmError::Store(format!(
                    "failed to remove staged v3 CAS metadata at {}: {error}",
                    tmp.display()
                ))
            })?;
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let _ = fs::remove_file(&tmp);
            let existing = read_capped(path, cap)?;
            if existing == bytes {
                Ok(())
            } else {
                Err(LpmError::Store(format!(
                    "v3 CAS metadata publication collision at {}",
                    path.display()
                )))
            }
        }
        Err(error) => {
            let _ = fs::remove_file(&tmp);
            Err(LpmError::Store(format!(
                "failed to publish v3 CAS metadata at {}: {error}",
                path.display()
            )))
        }
    }
}

fn replace_with_hardlink(source: &Path, destination: &Path) -> Result<(), LpmError> {
    let backup = tmp_sibling(destination);
    fs::rename(destination, &backup).map_err(|error| {
        LpmError::Store(format!(
            "failed to stage duplicate v3 CAS object file {}: {error}",
            destination.display()
        ))
    })?;
    match fs::hard_link(source, destination) {
        Ok(()) => {
            fs::remove_file(&backup).map_err(|error| {
                LpmError::Store(format!(
                    "failed to remove replaced v3 CAS object file {}: {error}",
                    backup.display()
                ))
            })?;
            Ok(())
        }
        Err(error) => {
            let _ = fs::rename(&backup, destination);
            Err(LpmError::Store(format!(
                "failed to hardlink existing v3 CAS blob into {}: {error}",
                destination.display()
            )))
        }
    }
}

fn hash_file(path: &Path, buffer: &mut [u8]) -> Result<String, LpmError> {
    let mut reader = BufReader::new(open_regular_file_nofollow(path).map_err(|error| {
        LpmError::Store(format!(
            "failed to open v3 CAS source file {}: {error}",
            path.display()
        ))
    })?);
    let mut hasher = blake3::Hasher::new();
    loop {
        let read = reader.read(buffer).map_err(|error| {
            LpmError::Store(format!(
                "failed to hash v3 CAS source file {}: {error}",
                path.display()
            ))
        })?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hasher.finalize().to_hex().to_string())
}

fn validate_manifest(manifest: &CasManifest) -> Result<bool, LpmError> {
    if manifest.schema != CAS_SCHEMA_VERSION || manifest.path_encoding != platform_path_encoding() {
        return Ok(false);
    }
    let mut previous: Option<&[u8]> = None;
    for entry in &manifest.entries {
        validate_relative_path(&entry.path)?;
        if previous.is_some_and(|path| path >= entry.path.as_slice()) {
            return Ok(false);
        }
        match entry.kind {
            CasEntryKind::Directory if entry.blob.is_none() && entry.symlink_target.is_empty() => {}
            CasEntryKind::File
                if entry.blob.as_ref().is_some_and(|blob| {
                    valid_hex_digest(&blob.digest)
                        && blob.mode == entry.mode
                        && blob.size == entry.size
                }) && entry.symlink_target.is_empty() => {}
            CasEntryKind::Symlink
                if manifest.allows_symlinks
                    && entry.blob.is_none()
                    && !entry.symlink_target.is_empty() => {}
            _ => return Ok(false),
        }
        previous = Some(&entry.path);
    }
    Ok(true)
}

fn valid_hex_digest(digest: &str) -> bool {
    digest.len() == 64
        && digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn encode_relative_path(path: &Path) -> Result<Vec<u8>, LpmError> {
    let encoded = encode_os_str(path.as_os_str());
    validate_relative_path(&encoded)?;
    Ok(encoded)
}

fn decode_relative_path(encoded: &[u8]) -> Result<PathBuf, LpmError> {
    validate_relative_path(encoded)?;
    decode_os_string(encoded).map(PathBuf::from)
}

#[cfg(unix)]
fn decode_os_string(encoded: &[u8]) -> Result<OsString, LpmError> {
    use std::os::unix::ffi::OsStringExt;

    if encoded.contains(&0) {
        return Err(LpmError::Store(
            "invalid v3 CAS path encoding contains an embedded NUL byte".into(),
        ));
    }
    Ok(OsString::from_vec(encoded.to_vec()))
}

#[cfg(windows)]
fn decode_os_string(encoded: &[u8]) -> Result<OsString, LpmError> {
    use std::os::windows::ffi::OsStringExt;
    if !encoded.len().is_multiple_of(2) {
        return Err(LpmError::Store(
            "invalid v3 CAS UTF-16 path encoding".into(),
        ));
    }
    let wide = encoded
        .chunks_exact(2)
        .map(|bytes| u16::from_le_bytes([bytes[0], bytes[1]]))
        .collect::<Vec<_>>();
    Ok(OsString::from_wide(&wide))
}

#[cfg(not(any(unix, windows)))]
fn decode_os_string(encoded: &[u8]) -> Result<OsString, LpmError> {
    String::from_utf8(encoded.to_vec())
        .map(OsString::from)
        .map_err(|_| LpmError::Store("invalid v3 CAS path encoding".into()))
}

fn validate_relative_path(path: &[u8]) -> Result<(), LpmError> {
    if path.is_empty() {
        return Err(LpmError::Store(
            "empty or absolute v3 CAS manifest path".into(),
        ));
    }
    #[cfg(unix)]
    for component in path.split(|byte| *byte == b'/') {
        if component.is_empty() || component == b"." || component == b".." || component.contains(&0)
        {
            return Err(LpmError::Store("unsafe v3 CAS manifest path".into()));
        }
    }
    #[cfg(windows)]
    validate_windows_relative_path(path)?;
    #[cfg(not(any(unix, windows)))]
    for component in path.split(|byte| *byte == b'/') {
        if component.is_empty() || component == b"." || component == b".." || component.contains(&0)
        {
            return Err(LpmError::Store("unsafe v3 CAS manifest path".into()));
        }
    }
    Ok(())
}

#[cfg(windows)]
fn validate_windows_relative_path(path: &[u8]) -> Result<(), LpmError> {
    if !path.len().is_multiple_of(2) {
        return Err(LpmError::Store(
            "invalid UTF-16 v3 CAS manifest path".into(),
        ));
    }
    let units = path
        .chunks_exact(2)
        .map(|bytes| u16::from_le_bytes([bytes[0], bytes[1]]))
        .collect::<Vec<_>>();
    if matches!(units.first(), Some(unit) if *unit == u16::from(b'/') || *unit == u16::from(b'\\'))
    {
        return Err(LpmError::Store("absolute v3 CAS manifest path".into()));
    }
    let mut first = true;
    for component in units.split(|unit| *unit == u16::from(b'/') || *unit == u16::from(b'\\')) {
        let unsafe_component = component.is_empty()
            || component == [u16::from(b'.')]
            || component == [u16::from(b'.'), u16::from(b'.')]
            || component.iter().any(|unit| {
                *unit <= 31 || matches!(*unit, 34 | 42 | 47 | 58 | 60 | 62 | 63 | 92 | 124)
            })
            || matches!(component.last(), Some(unit) if *unit == u16::from(b'.') || *unit == u16::from(b' '))
            || windows_component_is_reserved(component);
        if unsafe_component
            || (first
                && component
                    .get(1)
                    .is_some_and(|unit| *unit == u16::from(b':')))
        {
            return Err(LpmError::Store("unsafe v3 CAS manifest path".into()));
        }
        first = false;
    }
    Ok(())
}

#[cfg(windows)]
fn windows_component_is_reserved(component: &[u16]) -> bool {
    let stem_end = component
        .iter()
        .position(|unit| *unit == u16::from(b'.'))
        .unwrap_or(component.len());
    let stem = &component[..stem_end];
    let equals_ascii = |candidate: &[u8]| {
        stem.len() == candidate.len()
            && stem.iter().zip(candidate).all(|(unit, byte)| {
                u8::try_from(*unit).is_ok_and(|unit| unit.eq_ignore_ascii_case(byte))
            })
    };
    equals_ascii(b"CON")
        || equals_ascii(b"PRN")
        || equals_ascii(b"AUX")
        || equals_ascii(b"NUL")
        || (stem.len() == 4
            && (stem[..3].iter().zip(b"COM").all(|(unit, byte)| {
                u8::try_from(*unit).is_ok_and(|unit| unit.eq_ignore_ascii_case(byte))
            }) || stem[..3].iter().zip(b"LPT").all(|(unit, byte)| {
                u8::try_from(*unit).is_ok_and(|unit| unit.eq_ignore_ascii_case(byte))
            }))
            && matches!(stem[3], 49..=57))
}

#[cfg(unix)]
fn normalized_mode(metadata: &fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    metadata.permissions().mode() & 0o7777
}

#[cfg(not(unix))]
fn normalized_mode(metadata: &fs::Metadata) -> u32 {
    if metadata.permissions().readonly() {
        0o444
    } else {
        0o644
    }
}

#[cfg(unix)]
fn platform_path_encoding() -> &'static str {
    "unix-bytes-v1"
}

#[cfg(windows)]
fn platform_path_encoding() -> &'static str {
    "windows-utf16le-v1"
}

#[cfg(not(any(unix, windows)))]
fn platform_path_encoding() -> &'static str {
    "lossy-utf8-v1"
}

#[cfg(unix)]
fn encode_os_str(value: &OsStr) -> Vec<u8> {
    use std::os::unix::ffi::OsStrExt;
    value.as_bytes().to_vec()
}

#[cfg(windows)]
fn encode_os_str(value: &OsStr) -> Vec<u8> {
    use std::os::windows::ffi::OsStrExt;
    let mut bytes = Vec::new();
    for unit in value.encode_wide() {
        bytes.extend_from_slice(&unit.to_le_bytes());
    }
    bytes
}

#[cfg(not(any(unix, windows)))]
fn encode_os_str(value: &OsStr) -> Vec<u8> {
    value.to_string_lossy().into_owned().into_bytes()
}

#[cfg(unix)]
fn push_os_str(out: &mut Vec<u8>, value: &OsStr) {
    use std::os::unix::ffi::OsStrExt;
    out.extend_from_slice(value.as_bytes());
}

#[cfg(windows)]
fn push_os_str(out: &mut Vec<u8>, value: &OsStr) {
    use std::os::windows::ffi::OsStrExt;
    for unit in value.encode_wide() {
        out.extend_from_slice(&unit.to_le_bytes());
    }
}

#[cfg(not(any(unix, windows)))]
fn push_os_str(out: &mut Vec<u8>, value: &OsStr) {
    out.extend_from_slice(value.to_string_lossy().as_bytes());
}

#[cfg(unix)]
fn push_path_separator(out: &mut Vec<u8>) {
    out.push(b'/');
}

#[cfg(windows)]
fn push_path_separator(out: &mut Vec<u8>) {
    out.extend_from_slice(&(b'/' as u16).to_le_bytes());
}

#[cfg(not(any(unix, windows)))]
fn push_path_separator(out: &mut Vec<u8>) {
    out.push(b'/');
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_file(path: &Path, bytes: &[u8], mode: u32) {
        fs::write(path, bytes).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
        }
        #[cfg(not(unix))]
        let _ = mode;
    }

    #[test]
    fn identical_content_and_mode_share_one_blob_inode() {
        let root = tempfile::tempdir().unwrap();
        let cas = FileCas::at(root.path());
        let first = root.path().join("objects").join("first");
        let second = root.path().join("objects").join("second");
        fs::create_dir_all(&first).unwrap();
        fs::create_dir_all(&second).unwrap();
        write_file(&first.join("index.js"), b"same", 0o644);
        write_file(&second.join("index.js"), b"same", 0o644);

        cas.ingest_object_tree(&first, "sha512-first", false)
            .unwrap();
        cas.ingest_object_tree(&second, "sha512-second", false)
            .unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let first_meta = fs::metadata(first.join("index.js")).unwrap();
            let second_meta = fs::metadata(second.join("index.js")).unwrap();
            assert_eq!(
                (first_meta.dev(), first_meta.ino()),
                (second_meta.dev(), second_meta.ino())
            );
        }
    }

    #[test]
    fn identical_content_with_different_modes_uses_distinct_blobs() {
        let root = tempfile::tempdir().unwrap();
        let cas = FileCas::at(root.path());
        let first = root.path().join("objects").join("first");
        let second = root.path().join("objects").join("second");
        fs::create_dir_all(&first).unwrap();
        fs::create_dir_all(&second).unwrap();
        write_file(&first.join("cli.js"), b"same", 0o644);
        write_file(&second.join("cli.js"), b"same", 0o755);

        cas.ingest_object_tree(&first, "sha512-first", false)
            .unwrap();
        cas.ingest_object_tree(&second, "sha512-second", false)
            .unwrap();

        let blob_count = fs::read_dir(root.path().join("blobs").join("blake3"))
            .unwrap()
            .map(|shard| fs::read_dir(shard.unwrap().path()).unwrap().count())
            .sum::<usize>();
        assert_eq!(blob_count, 2);
    }

    #[test]
    fn registry_object_rejects_symlink_entries() {
        let root = tempfile::tempdir().unwrap();
        let cas = FileCas::at(root.path());
        let object = root.path().join("objects").join("source");
        fs::create_dir_all(&object).unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink("target", object.join("escape")).unwrap();
        #[cfg(windows)]
        if let Err(error) = std::os::windows::fs::symlink_file("target", object.join("escape")) {
            if error.kind() == std::io::ErrorKind::PermissionDenied {
                return;
            }
            panic!("failed to create test symlink: {error}");
        }

        let error = cas
            .ingest_object_tree(&object, "sha512-source", false)
            .unwrap_err();
        assert!(error.to_string().contains("unsupported entry type"));
    }

    #[test]
    fn source_record_requires_matching_tree_manifest() {
        let root = tempfile::tempdir().unwrap();
        let cas = FileCas::at(root.path());
        let object = root.path().join("objects").join("source");
        fs::create_dir_all(&object).unwrap();
        write_file(&object.join("index.js"), b"content", 0o644);
        let prepared = cas
            .ingest_object_tree(&object, "sha512-source", false)
            .unwrap();
        cas.publish_source_record(&object, &prepared).unwrap();
        assert_eq!(
            cas.source_reuse_status(&object, "sha512-source").unwrap(),
            SourceReuseStatus::Reusable
        );
    }

    #[test]
    fn unchanged_tree_manifest_is_read_once_across_source_reuse_checks() {
        let root = tempfile::tempdir().unwrap();
        let cas = FileCas::at(root.path());
        let first = root.path().join("objects/first");
        let second = root.path().join("objects/second");
        fs::create_dir_all(&first).unwrap();
        fs::create_dir_all(&second).unwrap();
        write_file(&first.join("index.js"), b"shared", 0o644);
        write_file(&second.join("index.js"), b"shared", 0o644);
        let first_record = cas
            .ingest_object_tree(&first, "sha512-first", false)
            .unwrap();
        let second_record = cas
            .ingest_object_tree(&second, "sha512-second", false)
            .unwrap();
        cas.publish_source_record(&first, &first_record).unwrap();
        cas.publish_source_record(&second, &second_record).unwrap();
        let mut timings = FileCasReuseTimings::default();

        assert_eq!(
            cas.source_reuse_status_with_timings(&first, "sha512-first", &mut timings)
                .unwrap(),
            SourceReuseStatus::Reusable
        );
        assert_eq!(
            cas.source_reuse_status_with_timings(&second, "sha512-second", &mut timings)
                .unwrap(),
            SourceReuseStatus::Reusable
        );
        assert_eq!(timings.manifest_read_count, 1);
    }

    #[test]
    fn manifest_cache_rechecks_change_metadata_before_reuse() {
        let root = tempfile::tempdir().unwrap();
        let cas = FileCas::at(root.path());
        let object = root.path().join("objects/source");
        fs::create_dir_all(&object).unwrap();
        write_file(&object.join("index.js"), b"content", 0o644);
        let prepared = cas
            .ingest_object_tree(&object, "sha512-source", false)
            .unwrap();
        cas.publish_source_record(&object, &prepared).unwrap();
        assert_eq!(
            cas.source_reuse_status(&object, "sha512-source").unwrap(),
            SourceReuseStatus::Reusable
        );
        let manifest_path = cas
            .tree_manifest_path(&prepared.record.tree_digest)
            .unwrap();
        let original_mtime =
            filetime::FileTime::from_last_modification_time(&fs::metadata(&manifest_path).unwrap());
        let mut bytes = fs::read(&manifest_path).unwrap();
        bytes[0] ^= 0x01;
        fs::write(&manifest_path, bytes).unwrap();
        filetime::set_file_mtime(&manifest_path, original_mtime).unwrap();

        assert_eq!(
            cas.source_reuse_status(&object, "sha512-source").unwrap(),
            SourceReuseStatus::MissingOrInvalid
        );
    }

    #[test]
    fn registry_source_record_is_immutable_after_publication() {
        let root = tempfile::tempdir().unwrap();
        let cas = FileCas::at(root.path());
        let published = root.path().join("objects/source");
        let first = root.path().join("staging-first");
        let second = root.path().join("staging-second");
        fs::create_dir_all(&first).unwrap();
        fs::create_dir_all(&second).unwrap();
        write_file(&first.join("index.js"), b"first", 0o644);
        write_file(&second.join("index.js"), b"second", 0o644);
        let first = cas
            .ingest_object_tree_as(&first, &published, "sha512-source", false)
            .unwrap();
        let second = cas
            .ingest_object_tree_as(&second, &published, "sha512-source", false)
            .unwrap();
        fs::create_dir_all(&published).unwrap();
        cas.publish_source_record(&published, &first).unwrap();

        let error = cas.publish_source_record(&published, &second).unwrap_err();

        assert!(error.to_string().contains("immutable"));
    }

    #[test]
    fn registry_source_publication_quarantines_and_repairs_corrupt_metadata() {
        let root = tempfile::tempdir().unwrap();
        let cas = FileCas::at(root.path());
        let published = root.path().join("objects/source");
        fs::create_dir_all(&published).unwrap();
        write_file(&published.join("index.js"), b"content", 0o644);
        let prepared = cas
            .ingest_object_tree(&published, "sha512-source", false)
            .unwrap();
        cas.publish_source_record(&published, &prepared).unwrap();
        let source_record = cas.source_record_path("sha512-source").unwrap();
        fs::write(&source_record, b"interrupted").unwrap();

        cas.publish_source_record(&published, &prepared).unwrap();

        assert_eq!(
            cas.read_source_record("sha512-source").unwrap().tree_digest,
            prepared.record.tree_digest
        );
        assert!(
            cas.store_root
                .join("quarantine/sources")
                .read_dir()
                .unwrap()
                .next()
                .is_some()
        );
    }

    #[test]
    fn local_source_record_atomically_moves_to_the_new_tree() {
        let root = tempfile::tempdir().unwrap();
        let cas = FileCas::at(root.path());
        let published = root.path().join("objects/source");
        let first = root.path().join("staging-first");
        let second = root.path().join("staging-second");
        fs::create_dir_all(&first).unwrap();
        fs::create_dir_all(&second).unwrap();
        write_file(&first.join("index.js"), b"first", 0o644);
        write_file(&second.join("index.js"), b"second", 0o644);
        let first = cas
            .ingest_object_tree_as(&first, &published, "local-source", true)
            .unwrap();
        let second = cas
            .ingest_object_tree_as(&second, &published, "local-source", true)
            .unwrap();
        fs::create_dir_all(&published).unwrap();
        cas.publish_source_record(&published, &first).unwrap();
        cas.publish_source_record(&published, &second).unwrap();

        assert_eq!(
            cas.read_source_record("local-source").unwrap().tree_digest,
            second.record.tree_digest
        );
    }

    #[test]
    fn ingest_quarantines_and_repairs_a_tampered_blob() {
        let root = tempfile::tempdir().unwrap();
        let cas = FileCas::at(root.path());
        let first = root.path().join("objects/first");
        let second = root.path().join("objects/second");
        fs::create_dir_all(&first).unwrap();
        fs::create_dir_all(&second).unwrap();
        write_file(&first.join("index.js"), b"clean", 0o644);
        let prepared = cas
            .ingest_object_tree(&first, "sha512-first", false)
            .unwrap();
        let manifest = cas
            .manifest_for_digest(&prepared.record.tree_digest)
            .unwrap();
        let key = manifest.entries[0].blob.as_ref().unwrap();
        let blob = cas.blob_path(key).unwrap();
        fs::write(&blob, b"dirty").unwrap();
        write_file(&second.join("index.js"), b"clean", 0o644);

        cas.ingest_object_tree(&second, "sha512-second", false)
            .unwrap();

        assert_eq!(fs::read(&blob).unwrap(), b"clean");
        assert!(
            cas.store_root
                .join("quarantine/blobs")
                .read_dir()
                .unwrap()
                .next()
                .is_some()
        );
    }

    #[test]
    fn tree_manifest_entries_are_sorted_by_full_relative_path() {
        let root = tempfile::tempdir().unwrap();
        let cas = FileCas::at(root.path());
        let object = root.path().join("objects").join("source");
        fs::create_dir_all(object.join("a")).unwrap();
        write_file(&object.join("a").join("child.js"), b"child", 0o644);
        write_file(&object.join("a.js"), b"sibling", 0o644);

        let prepared = cas
            .ingest_object_tree(&object, "sha512-source", false)
            .unwrap();
        let bytes = cas
            .read_tree_manifest_bytes(&prepared.record.tree_digest)
            .unwrap();
        let manifest: CasManifest = rmp_serde::from_slice(&bytes).unwrap();
        assert!(
            manifest
                .entries
                .windows(2)
                .all(|pair| pair[0].path < pair[1].path)
        );
    }

    #[test]
    fn identical_trees_share_one_materialized_cache() {
        let root = tempfile::tempdir().unwrap();
        let cas = FileCas::at(root.path());
        let first = root.path().join("objects/first");
        let second = root.path().join("objects/second");
        fs::create_dir_all(&first).unwrap();
        fs::create_dir_all(&second).unwrap();
        write_file(&first.join("index.js"), b"same", 0o644);
        write_file(&second.join("index.js"), b"same", 0o644);
        let first_record = cas
            .ingest_object_tree(&first, "sha512-first", false)
            .unwrap();
        let second_record = cas
            .ingest_object_tree(&second, "sha512-second", false)
            .unwrap();
        cas.publish_source_record(&first, &first_record).unwrap();
        cas.publish_source_record(&second, &second_record).unwrap();

        let first_cache = cas.materialized_source(&first, "sha512-first").unwrap();
        let second_cache = cas.materialized_source(&second, "sha512-second").unwrap();

        assert_eq!(first_cache, second_cache);
        assert_eq!(cas.materialized_entry_dirs().unwrap().len(), 1);
    }

    #[test]
    fn materialization_repairs_an_interrupted_cache_entry() {
        let root = tempfile::tempdir().unwrap();
        let cas = FileCas::at(root.path());
        let object = root.path().join("objects/source");
        fs::create_dir_all(&object).unwrap();
        write_file(&object.join("index.js"), b"complete", 0o644);
        let prepared = cas
            .ingest_object_tree(&object, "sha512-source", false)
            .unwrap();
        cas.publish_source_record(&object, &prepared).unwrap();
        let interrupted = cas
            .materialized_entry_dir(&prepared.record.tree_digest)
            .unwrap();
        fs::create_dir_all(interrupted.join("package")).unwrap();
        write_file(&interrupted.join("package/partial.js"), b"partial", 0o644);

        let package = cas.materialized_source(&object, "sha512-source").unwrap();

        assert_eq!(fs::read(package.join("index.js")).unwrap(), b"complete");
        assert!(!package.join("partial.js").exists());
        assert!(
            cas.store_root
                .join("quarantine/materialized")
                .read_dir()
                .unwrap()
                .next()
                .is_some()
        );
    }

    #[test]
    fn uppercase_digest_is_not_a_canonical_cas_key() {
        assert!(!valid_hex_digest(
            "ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
        ));
    }

    #[cfg(unix)]
    #[test]
    fn cas_enumeration_rejects_symlinked_blob_entries() {
        let root = tempfile::tempdir().unwrap();
        let cas = FileCas::at(root.path());
        let shard = root.path().join("blobs/blake3/ab");
        fs::create_dir_all(&shard).unwrap();
        std::os::unix::fs::symlink(
            root.path().join("outside"),
            shard.join(format!("{}-644", "a".repeat(64))),
        )
        .unwrap();

        let error = cas.blob_files().unwrap_err();

        assert!(error.to_string().contains("not a regular file"));
    }

    #[cfg(unix)]
    #[test]
    fn cas_enumeration_rejects_symlinked_shards() {
        let root = tempfile::tempdir().unwrap();
        let cas = FileCas::at(root.path());
        fs::create_dir_all(root.path().join("blobs/blake3")).unwrap();
        std::os::unix::fs::symlink(
            root.path().join("outside"),
            root.path().join("blobs/blake3/ab"),
        )
        .unwrap();

        let error = cas.blob_files().unwrap_err();

        assert!(error.to_string().contains("not a directory"));
    }

    #[cfg(unix)]
    #[test]
    fn capped_metadata_reads_reject_symlinked_files() {
        let root = tempfile::tempdir().unwrap();
        let target = root.path().join("target");
        let link = root.path().join("metadata.msgpack");
        fs::write(&target, b"metadata").unwrap();
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let error = read_capped_io(&link, 64).unwrap_err();

        assert!(matches!(error.raw_os_error(), Some(libc::ELOOP)));
    }

    #[cfg(unix)]
    #[test]
    fn blob_hashing_rejects_symlinked_files() {
        let root = tempfile::tempdir().unwrap();
        let target = root.path().join("target");
        let link = root.path().join("blob");
        fs::write(&target, b"content").unwrap();
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let mut buffer = [0_u8; 64];

        let error = hash_file(&link, &mut buffer).unwrap_err();

        assert!(
            error
                .to_string()
                .contains("failed to open v3 CAS source file")
        );
    }

    #[cfg(unix)]
    #[test]
    fn cas_publication_rejects_symlinked_shard_directories() {
        let root = tempfile::tempdir().unwrap();
        let cas = FileCas::at(&root.path().join("v3"));
        let outside = root.path().join("outside");
        fs::create_dir_all(&outside).unwrap();
        let trees = root.path().join("v3/trees");
        fs::create_dir_all(&trees).unwrap();
        std::os::unix::fs::symlink(&outside, trees.join("aa")).unwrap();

        let digest = format!("aa{}", "0".repeat(62));
        cas.publish_tree_manifest(&digest, b"manifest")
            .expect_err("CAS publication must reject symlinked shards");
        assert!(!outside.join(format!("{digest}.msgpack")).exists());
    }

    #[cfg(unix)]
    #[test]
    fn unix_path_decoding_rejects_embedded_nul_bytes() {
        let error = decode_os_string(b"safe\0escape").unwrap_err();

        assert!(error.to_string().contains("embedded NUL"));
    }
}
