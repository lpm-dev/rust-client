use std::collections::{HashMap, HashSet};
use std::ffi::{OsStr, OsString};
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufReader, Read, Seek, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use lpm_common::{FileIdentity, LpmError, write_file_atomic};
use lpm_extractor::ExtractedFileStamp;
use serde::{Deserialize, Serialize};

use crate::v2::fs_util::tmp_sibling;
#[cfg(any(target_os = "macos", test))]
use crate::v2::fs_util::{create_fs_symlink, create_tmp_dir_locked};
use crate::v2::tree_hash::is_object_metadata_sidecar;

const CAS_SCHEMA_VERSION: u32 = 1;
const MANIFEST_MAX_BYTES: u64 = 64 * 1024 * 1024;
const SOURCE_RECORD_MAX_BYTES: u64 = 16 * 1024;
const SOURCE_VALIDATION_HEADER_MAX_BYTES: u64 = 16 * 1024;
const SOURCE_VALIDATION_TRAILER_MAGIC: &[u8; 4] = b"LPMB";
const SOURCE_VALIDATION_TRAILER_VERSION: u32 = 1;
const SOURCE_VALIDATION_MAX_TRAILER_BLOBS: usize = 262_144;
const SOURCE_VALIDATION_MAX_FILE_BYTES: u64 =
    SOURCE_VALIDATION_HEADER_MAX_BYTES + 12 + (SOURCE_VALIDATION_MAX_TRAILER_BLOBS as u64 * 16);
const SOURCE_BLOB_STAT_DOMAIN: &[u8] = b"lpm-v3-source-blob-stat-v3\0";
const MAX_TREE_DEPTH: usize = 256;
const MATERIALIZED_COMPLETE_FILENAME: &str = ".complete";
const MAX_CACHED_MANIFESTS: usize = 256;
const MAX_CACHED_MANIFEST_BYTES: usize = 32 * 1024 * 1024;
const MAX_VALIDATED_BLOBS: usize = 65_536;
/// Minimum age before a session-validated blob's mtime and ctime are treated as
/// settled past coarse OS filesystem timestamp granularity (Linux HZ ticks and
/// Windows 15.6 ms system clock). Blobs newer than this margin rehash on dedup
/// hits so same-tick in-place tampering cannot bypass repair.
const SETTLED_BLOB_MTIME_MARGIN: Duration = Duration::from_millis(50);

/// Allocation-free identity for a CAS blob file `(blake3_digest, normalized_mode)`.
pub(crate) type CompactBlobKey = ([u8; 32], u32);

/// Allocation-free key for in-memory blob stat and validation maps.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct CompactBlobId {
    digest: [u8; 32],
    mode: u32,
    size: u64,
}

impl CompactBlobId {
    fn from_raw(digest: [u8; 32], mode: u32, size: u64) -> Self {
        Self { digest, mode, size }
    }

    fn try_from_key(key: &BlobKey) -> Option<Self> {
        if !valid_hex_digest(&key.digest) {
            return None;
        }
        let mut digest = [0_u8; 32];
        hex::decode_to_slice(&key.digest, &mut digest).ok()?;
        Some(Self {
            digest,
            mode: key.mode,
            size: key.size,
        })
    }
}

const MAX_VALIDATE_BLOB_ATTEMPTS: usize = 4;

enum ValidateBlobError {
    Corrupt {
        error: Box<LpmError>,
        bad_identity: Option<FileIdentity>,
    },
    Contended(Box<LpmError>),
}

impl ValidateBlobError {
    fn corrupt(error: LpmError, bad_identity: Option<FileIdentity>) -> Self {
        Self::Corrupt {
            error: Box::new(error),
            bad_identity,
        }
    }

    fn contended(error: LpmError) -> Self {
        Self::Contended(Box::new(error))
    }

    fn into_error(self) -> LpmError {
        match self {
            Self::Corrupt { error, .. } | Self::Contended(error) => *error,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FirstPublishTrust {
    Verified,
    DeferUntilFinalized,
}

struct PublishedBlob {
    fingerprint: BlobStatFingerprint,
    deferred_validation: bool,
}

#[derive(Clone, Debug)]
pub(crate) struct FileCas {
    store_root: PathBuf,
    blobs_root: PathBuf,
    trees_root: PathBuf,
    sources_root: PathBuf,
    source_validations_root: PathBuf,
    materialized_root: PathBuf,
    secured_directories: Arc<RwLock<HashSet<PathBuf>>>,
    manifest_cache: Arc<Mutex<ManifestCacheState>>,
    validated_blobs: Arc<RwLock<HashMap<CompactBlobId, BlobStatFingerprint>>>,
}

#[derive(Debug)]
struct ManifestCacheState {
    entries: HashMap<String, ManifestCacheEntry>,
    total_bytes: usize,
}

impl ManifestCacheState {
    fn new() -> Self {
        Self {
            entries: HashMap::with_capacity(MAX_CACHED_MANIFESTS),
            total_bytes: 0,
        }
    }

    fn insert(&mut self, digest: String, entry: ManifestCacheEntry) {
        if entry.encoded_bytes > MAX_CACHED_MANIFEST_BYTES {
            return;
        }
        if let Some(previous) = self.entries.remove(&digest) {
            self.total_bytes = self.total_bytes.saturating_sub(previous.encoded_bytes);
        }
        if self.entries.len() >= MAX_CACHED_MANIFESTS
            || self.total_bytes.saturating_add(entry.encoded_bytes) > MAX_CACHED_MANIFEST_BYTES
        {
            self.entries.clear();
            self.total_bytes = 0;
        }
        self.total_bytes = self.total_bytes.saturating_add(entry.encoded_bytes);
        self.entries.insert(digest, entry);
    }
}

#[derive(Clone, Debug)]
struct ManifestCacheEntry {
    size: u64,
    encoded_bytes: usize,
    fingerprint: ManifestStatFingerprint,
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
    blob_stats: Arc<Mutex<HashMap<CompactBlobId, BlobStatFingerprint>>>,
}

#[derive(Clone, Debug)]
pub(crate) struct PreparedSourceRecord {
    object_segment: OsString,
    record: SourceRecord,
    validation: SourceValidationRecord,
    blob_stat_digests: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SourceReuseStatus {
    Reusable,
    MissingOrInvalid,
    CorruptBlob,
}

/// Stat fingerprint for CAS tree manifests. Retains `ctime` / `ChangeTime` so
/// in-place manifest tampering that restores `mtime` still invalidates the
/// in-memory cache; tree manifests are never hardlinked into consumer trees.
#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ManifestStatFingerprint {
    dev: u64,
    ino: u64,
    mtime: i64,
    mtime_nsec: i64,
    ctime: i64,
    ctime_nsec: i64,
}

#[cfg(windows)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ManifestStatFingerprint {
    volume_serial_number: u64,
    file_index: u128,
    creation_time: u64,
    last_write_time: u64,
    change_time: i64,
    file_attributes: u32,
}

#[cfg(not(any(unix, windows)))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ManifestStatFingerprint {
    modified: u128,
    created: u128,
    readonly: bool,
}

/// Stat fingerprint for shared CAS blobs. Retains `ctime` / `ChangeTime` so
/// same-size in-place tampering that restores `mtime` is always detected.
/// Expected `ctime` transitions caused by LPM's own hardlinks are reconciled
/// via per-blob validation digests and the session `validated_blobs` table.
#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct BlobStatFingerprint {
    dev: u64,
    ino: u64,
    mode: u32,
    nlink: u64,
    mtime: i64,
    mtime_nsec: i64,
    ctime: i64,
    ctime_nsec: i64,
}

#[cfg(windows)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct BlobStatFingerprint {
    volume_serial_number: u64,
    file_index: u128,
    creation_time: u64,
    last_write_time: u64,
    change_time: i64,
    file_attributes: u32,
    nlink: u32,
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
    seen_identities: HashMap<FileIdentity, Vec<u8>>,
    blob_stats: HashMap<CompactBlobId, BlobStatFingerprint>,
    deferred_validated: Vec<(CompactBlobId, BlobStatFingerprint)>,
    hash_buffer: Vec<u8>,
}

struct TreeIngestContext<'a> {
    object_root: &'a Path,
    entries: &'a mut Vec<CasManifestEntry>,
    blob_stats: &'a mut HashMap<CompactBlobId, BlobStatFingerprint>,
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

struct OpenSourceValidation {
    record: SourceValidationRecord,
    reader: BufReader<File>,
}

impl OpenSourceValidation {
    fn read_per_blob_digests(mut self, expected_count: usize) -> Option<Vec<u8>> {
        if expected_count == 0 || expected_count > SOURCE_VALIDATION_MAX_TRAILER_BLOBS {
            return None;
        }
        let mut header = [0_u8; 12];
        self.reader.read_exact(&mut header).ok()?;
        if &header[0..4] != SOURCE_VALIDATION_TRAILER_MAGIC {
            return None;
        }
        if u32::from_le_bytes(header[4..8].try_into().ok()?) != SOURCE_VALIDATION_TRAILER_VERSION {
            return None;
        }
        let count = u32::from_le_bytes(header[8..12].try_into().ok()?) as usize;
        if count != expected_count {
            return None;
        }
        let payload_len = count.checked_mul(16)?;
        let mut digests = vec![0_u8; payload_len];
        self.reader.read_exact(&mut digests).ok()?;
        let mut trailing = [0_u8; 1];
        if self.reader.read(&mut trailing).ok()? != 0 {
            return None;
        }
        Some(digests)
    }
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
            secured_directories: Arc::new(RwLock::new(HashSet::with_capacity(1_024))),
            manifest_cache: Arc::new(Mutex::new(ManifestCacheState::new())),
            validated_blobs: Arc::new(RwLock::new(HashMap::with_capacity(1_024))),
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
        let mut blob_stats = HashMap::new();
        let mut relative = Vec::new();
        let mut hash_buffer = vec![0_u8; 64 * 1024];
        let mut ingest = TreeIngestContext {
            object_root: object_dir,
            entries: &mut entries,
            blob_stats: &mut blob_stats,
            hash_buffer: &mut hash_buffer,
            allows_symlinks,
        };
        self.ingest_dir(&mut ingest, object_dir, &mut relative, 0)?;
        self.prepare_source_record(
            object_segment,
            source_sri,
            allows_symlinks,
            entries,
            Some(&blob_stats),
        )
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
            seen_identities: HashMap::with_capacity(128),
            blob_stats: HashMap::with_capacity(128),
            deferred_validated: Vec::with_capacity(128),
            hash_buffer: vec![0_u8; 64 * 1024],
        })
    }

    pub(crate) fn ingest_registry_file(
        &self,
        ingest: &mut RegistryCasIngest,
        object_root: &Path,
        relative_path: &Path,
        expected_size: Option<u64>,
        digest: [u8; 32],
        expected_stamp: Option<ExtractedFileStamp>,
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
        let (file_size, mode, identity, live_stamp) = inspect_registry_source_file(&source)?;
        if expected_size.is_some_and(|expected| file_size != expected) {
            return Err(LpmError::Store(format!(
                "extracted v3 CAS entry changed before publication at {}",
                source.display()
            )));
        }
        if let Some(identity) = identity {
            if let Some(prior_path) = ingest.seen_identities.get(&identity)
                && prior_path != &path_bytes
            {
                return Err(LpmError::Store(format!(
                    "extracted v3 CAS entry aliases an already-ingested file identity at {}",
                    relative_path.display()
                )));
            }
            ingest.seen_identities.insert(identity, path_bytes.clone());
        }
        let stamp_matches = matches!(
            (expected_stamp, live_stamp),
            (Some(expected), Some(live)) if expected == live
        );
        if !stamp_matches {
            let (mut file, open_meta) = open_regular_file_nofollow(&source).map_err(|error| {
                LpmError::Store(format!(
                    "failed to open extracted v3 CAS entry {}: {error}",
                    source.display()
                ))
            })?;
            let open_identity = file_identity_from_open_file(&source, &file, &open_meta)?;
            if open_identity != identity
                || open_meta.len() != file_size
                || normalized_mode(&open_meta) != mode
            {
                return Err(LpmError::Store(format!(
                    "extracted v3 CAS entry changed before publication at {}",
                    source.display()
                )));
            }
            let actual_digest = hash_open_file_bytes(&mut file, &source, &mut ingest.hash_buffer)?;
            if actual_digest != digest {
                return Err(LpmError::Store(format!(
                    "extracted v3 CAS entry digest changed before publication at {}",
                    source.display()
                )));
            }
        }
        let compact_id = CompactBlobId::from_raw(digest, mode, file_size);
        let key = BlobKey {
            digest: blake3::Hash::from_bytes(digest).to_hex().to_string(),
            mode,
            size: file_size,
        };
        let published = self.publish_blob(
            &source,
            &key,
            &mut ingest.hash_buffer,
            FirstPublishTrust::DeferUntilFinalized,
            identity,
        )?;
        ingest.blob_stats.insert(compact_id, published.fingerprint);
        if published.deferred_validation {
            ingest
                .deferred_validated
                .push((compact_id, published.fingerprint));
        }

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
                break;
            }
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
        for (compact_id, fingerprint) in ingest.deferred_validated {
            self.record_validated_blob_id(compact_id, fingerprint);
        }
        self.prepare_source_record(
            ingest.object_segment,
            &ingest.source_sri,
            false,
            ingest.entries,
            Some(&ingest.blob_stats),
        )
    }

    fn prepare_source_record(
        &self,
        object_segment: OsString,
        source_sri: &str,
        allows_symlinks: bool,
        mut entries: Vec<CasManifestEntry>,
        known_blob_stats: Option<&HashMap<CompactBlobId, BlobStatFingerprint>>,
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
        let keys = unique_manifest_blob_keys(&manifest);
        let mut observed_stats = Vec::with_capacity(keys.len());
        let blob_stat_fingerprint = self.collect_blob_stat_fingerprint(
            &keys,
            &mut timings,
            None,
            known_blob_stats,
            &mut observed_stats,
        )?;
        let blob_stat_digests = encode_per_blob_stat_digests(&keys, &observed_stats);
        Ok(PreparedSourceRecord {
            validation: SourceValidationRecord {
                schema: CAS_SCHEMA_VERSION,
                source_sri: source_sri.to_string(),
                tree_digest: tree_digest.clone(),
                blob_stat_fingerprint,
            },
            blob_stat_digests,
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
        self.write_source_validation(&prepared.validation, &prepared.blob_stat_digests)
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
        let keys = unique_manifest_blob_keys(&manifest);
        let mut observed_stats = Vec::with_capacity(keys.len());
        let mut hasher = blake3::Hasher::new();
        hasher.update(SOURCE_BLOB_STAT_DOMAIN);
        let mut all_stats_ok = true;
        for key in &keys {
            match self.blob_stat(key, timings, batch) {
                Ok(fingerprint) => {
                    hasher.update(key.digest.as_bytes());
                    hasher.update(&key.mode.to_le_bytes());
                    hasher.update(&key.size.to_le_bytes());
                    fingerprint.update_hasher(&mut hasher);
                    observed_stats.push(Some(fingerprint));
                }
                Err(error) => {
                    tracing::warn!(
                        target = %object_dir.display(),
                        "v3 CAS blob metadata changed: {error}"
                    );
                    all_stats_ok = false;
                    observed_stats.push(None);
                }
            }
        }
        let source_validation_start = std::time::Instant::now();
        let source_validation = self.open_source_validation(source_sri).ok();
        timings.source_validation_read_count =
            timings.source_validation_read_count.saturating_add(1);
        timings.source_validation_read_ms = timings
            .source_validation_read_ms
            .saturating_add(source_validation_start.elapsed().as_millis());
        if all_stats_ok {
            let observed_fingerprint = hasher.finalize().to_hex().to_string();
            if source_validation.as_ref().is_some_and(|open| {
                open.record.schema == CAS_SCHEMA_VERSION
                    && open.record.source_sri == source_sri
                    && open.record.tree_digest == record.tree_digest
                    && open.record.blob_stat_fingerprint == observed_fingerprint
            }) {
                self.record_validated_blobs_batch(&keys, &observed_stats);
                return Ok(SourceReuseStatus::Reusable);
            }
        }
        self.rehash_changed_source_blobs(
            &record,
            &keys,
            &observed_stats,
            source_validation,
            timings,
        )
    }

    fn rehash_changed_source_blobs(
        &self,
        record: &SourceRecord,
        keys: &[&BlobKey],
        observed_stats: &[Option<BlobStatFingerprint>],
        prior_validation: Option<OpenSourceValidation>,
        timings: &mut FileCasReuseTimings,
    ) -> Result<SourceReuseStatus, LpmError> {
        let prior_digests = prior_validation
            .filter(|open| {
                open.record.schema == CAS_SCHEMA_VERSION
                    && open.record.source_sri == record.source_sri
                    && open.record.tree_digest == record.tree_digest
            })
            .and_then(|open| open.read_per_blob_digests(keys.len()));
        let mut hash_buffer = Vec::new();
        let mut hasher = blake3::Hasher::new();
        hasher.update(SOURCE_BLOB_STAT_DOMAIN);
        let emit_trailer = keys.len() <= SOURCE_VALIDATION_MAX_TRAILER_BLOBS;
        let mut per_blob_digests = if emit_trailer {
            Vec::with_capacity(keys.len().saturating_mul(16))
        } else {
            Vec::new()
        };
        for (index, key) in keys.iter().enumerate() {
            let observed = observed_stats.get(index).copied().flatten();
            let trusted = observed.and_then(|fp| {
                let digest = single_blob_stat_digest(key, fp);
                let unchanged_since_prior = prior_digests.as_ref().is_some_and(|digests| {
                    let start = index * 16;
                    digests.get(start..start + 16) == Some(digest.as_slice())
                });
                let validated_in_session =
                    !unchanged_since_prior && self.cached_validated_blob(key) == Some(fp);
                (unchanged_since_prior || validated_in_session).then_some((fp, digest))
            });
            let (fingerprint, digest) = if let Some(pair) = trusted {
                pair
            } else {
                if hash_buffer.is_empty() {
                    hash_buffer.resize(64 * 1024, 0);
                }
                let rehash_start = std::time::Instant::now();
                timings.blob_rehash_count = timings.blob_rehash_count.saturating_add(1);
                let blob = self.blob_path(key)?;
                let validated = match self.validate_blob(&blob, key, &mut hash_buffer) {
                    Ok(fingerprint) => {
                        self.record_validated_blob(key, fingerprint);
                        fingerprint
                    }
                    Err(ValidateBlobError::Contended(error)) => {
                        timings.blob_rehash_ms = timings
                            .blob_rehash_ms
                            .saturating_add(rehash_start.elapsed().as_millis());
                        tracing::warn!(
                            target = %blob.display(),
                            "v3 CAS blob experienced concurrent link updates during validation: {error}"
                        );
                        return Ok(SourceReuseStatus::MissingOrInvalid);
                    }
                    Err(ValidateBlobError::Corrupt {
                        error,
                        bad_identity,
                    }) => {
                        timings.blob_rehash_ms = timings
                            .blob_rehash_ms
                            .saturating_add(rehash_start.elapsed().as_millis());
                        self.evict_validated_blob(key);
                        if self.blob_matches_bad_identity(&blob, bad_identity) {
                            self.quarantine_entry(&blob, "blobs")?;
                        }
                        tracing::warn!(
                            target = %blob.display(),
                            "v3 CAS blob failed validation after its stat fingerprint changed: {error}"
                        );
                        return Ok(SourceReuseStatus::CorruptBlob);
                    }
                };
                timings.blob_rehash_ms = timings
                    .blob_rehash_ms
                    .saturating_add(rehash_start.elapsed().as_millis());
                (validated, single_blob_stat_digest(key, validated))
            };
            hasher.update(key.digest.as_bytes());
            hasher.update(&key.mode.to_le_bytes());
            hasher.update(&key.size.to_le_bytes());
            fingerprint.update_hasher(&mut hasher);
            if emit_trailer {
                per_blob_digests.extend_from_slice(&digest);
            }
        }
        let validation = SourceValidationRecord {
            schema: CAS_SCHEMA_VERSION,
            source_sri: record.source_sri.clone(),
            tree_digest: record.tree_digest.clone(),
            blob_stat_fingerprint: hasher.finalize().to_hex().to_string(),
        };
        self.write_source_validation(&validation, &per_blob_digests)?;
        Ok(SourceReuseStatus::Reusable)
    }

    fn collect_blob_stat_fingerprint(
        &self,
        keys: &[&BlobKey],
        timings: &mut FileCasReuseTimings,
        batch: Option<&FileCasValidationBatch>,
        known_blob_stats: Option<&HashMap<CompactBlobId, BlobStatFingerprint>>,
        out_stats: &mut Vec<BlobStatFingerprint>,
    ) -> Result<String, LpmError> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(SOURCE_BLOB_STAT_DOMAIN);
        for key in keys {
            let fingerprint = if let Some(fp) = known_blob_stats
                .and_then(|map| CompactBlobId::try_from_key(key).and_then(|id| map.get(&id)))
            {
                *fp
            } else {
                self.blob_stat(key, timings, batch)?
            };
            hasher.update(key.digest.as_bytes());
            hasher.update(&key.mode.to_le_bytes());
            hasher.update(&key.size.to_le_bytes());
            fingerprint.update_hasher(&mut hasher);
            out_stats.push(fingerprint);
        }
        Ok(hasher.finalize().to_hex().to_string())
    }

    fn blob_stat(
        &self,
        key: &BlobKey,
        timings: &mut FileCasReuseTimings,
        batch: Option<&FileCasValidationBatch>,
    ) -> Result<BlobStatFingerprint, LpmError> {
        let compact_id = CompactBlobId::try_from_key(key);
        if let (Some(id), Some(batch)) = (compact_id, batch)
            && let Some(fingerprint) = batch
                .blob_stats
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .get(&id)
                .copied()
        {
            timings.blob_stat_cache_hit_count = timings.blob_stat_cache_hit_count.saturating_add(1);
            return Ok(fingerprint);
        }
        let start = std::time::Instant::now();
        timings.blob_stat_count = timings.blob_stat_count.saturating_add(1);
        let result = self.read_blob_stat(key);
        timings.blob_stat_ms = timings
            .blob_stat_ms
            .saturating_add(start.elapsed().as_millis());
        if let (Ok(fingerprint), Some(id), Some(batch)) = (result.as_ref(), compact_id, batch) {
            batch
                .blob_stats
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .insert(id, *fingerprint);
        }
        result
    }

    fn read_blob_stat(&self, key: &BlobKey) -> Result<BlobStatFingerprint, LpmError> {
        let path = self.blob_path(key)?;
        self.read_path_stat_as_blob(&path, key)
    }

    fn read_path_stat_as_blob(
        &self,
        path: &Path,
        key: &BlobKey,
    ) -> Result<BlobStatFingerprint, LpmError> {
        #[cfg(windows)]
        {
            BlobStatFingerprint::from_validated_blob_path(path, key)
        }
        #[cfg(not(windows))]
        {
            let metadata = fs::symlink_metadata(path).map_err(|error| {
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
            Ok(BlobStatFingerprint::from_metadata(&metadata))
        }
    }

    fn write_source_validation(
        &self,
        validation: &SourceValidationRecord,
        per_blob_digests: &[u8],
    ) -> Result<(), LpmError> {
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
        let mut bytes = rmp_serde::to_vec_named(validation).map_err(|error| {
            LpmError::Store(format!(
                "failed to serialize v3 CAS source validation: {error}"
            ))
        })?;
        if bytes.len() as u64 > SOURCE_VALIDATION_HEADER_MAX_BYTES {
            return Err(LpmError::Store(format!(
                "v3 CAS source validation header is {} bytes; cap is {SOURCE_VALIDATION_HEADER_MAX_BYTES}",
                bytes.len()
            )));
        }
        if !per_blob_digests.is_empty() && per_blob_digests.len().is_multiple_of(16) {
            let blob_count = per_blob_digests.len() / 16;
            if blob_count <= SOURCE_VALIDATION_MAX_TRAILER_BLOBS
                && let Ok(count_u32) = u32::try_from(blob_count)
            {
                bytes.reserve(12 + per_blob_digests.len());
                bytes.extend_from_slice(SOURCE_VALIDATION_TRAILER_MAGIC);
                bytes.extend_from_slice(&SOURCE_VALIDATION_TRAILER_VERSION.to_le_bytes());
                bytes.extend_from_slice(&count_u32.to_le_bytes());
                bytes.extend_from_slice(per_blob_digests);
            }
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

    pub(crate) fn source_record_for_prune(
        &self,
        object_dir: &Path,
        source_sri: &str,
    ) -> Result<SourceRecord, LpmError> {
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
        Ok(record)
    }

    pub(crate) fn manifest_for_prune(&self, digest: &str) -> Result<CasManifest, LpmError> {
        let path = self.tree_manifest_path(digest)?;
        let (manifest_bytes, _, _) = read_manifest_file_with_fingerprint(&path, digest)?;
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
        Ok(manifest)
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
        let mut hash_buffer = Vec::new();
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
                    let blob = self.blob_path(key)?;
                    let pre_fp = self.read_blob_stat(key)?;
                    let prior_validated = self.cached_validated_blob(key);
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
                    let fast_path_post = prior_validated.and_then(|cached| {
                        (pre_fp == cached && cached.is_settled())
                            .then(|| self.read_path_stat_as_blob(&path, key).ok())
                            .flatten()
                            .filter(|post_fp| post_fp.is_hardlink_only_transition_from(pre_fp))
                    });
                    if let Some(post_fp) = fast_path_post {
                        self.record_validated_blob(key, post_fp);
                    } else {
                        if hash_buffer.is_empty() {
                            hash_buffer.resize(64 * 1024, 0);
                        }
                        match self.validate_blob(&path, key, &mut hash_buffer) {
                            Ok(validated) => self.record_validated_blob(key, validated),
                            Err(ValidateBlobError::Contended(error)) => return Err(*error),
                            Err(ValidateBlobError::Corrupt {
                                error,
                                bad_identity,
                            }) => {
                                self.evict_validated_blob(key);
                                if self.blob_matches_bad_identity(&blob, bad_identity) {
                                    self.quarantine_entry(&blob, "blobs")?;
                                }
                                return Err(*error);
                            }
                        }
                    }
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
                    let identity_matches = {
                        #[cfg(any(unix, windows))]
                        {
                            paths_share_file_identity(&path, &blob)
                        }
                        #[cfg(not(any(unix, windows)))]
                        {
                            true
                        }
                    };
                    if metadata.len() != key.size
                        || normalized_mode(&metadata) != key.mode
                        || !identity_matches
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
            .entries
            .get(digest)
            .filter(|entry| entry.size == size && entry.fingerprint == fingerprint)
            .map(|entry| Arc::clone(&entry.manifest))
        {
            return Ok(manifest);
        }
        let read_start = std::time::Instant::now();
        let (manifest_bytes, read_size, read_fingerprint) =
            read_manifest_file_with_fingerprint(&path, digest)?;
        timings.manifest_read_count = timings.manifest_read_count.saturating_add(1);
        timings.manifest_read_ms = timings
            .manifest_read_ms
            .saturating_add(read_start.elapsed().as_millis());
        if size != read_size || fingerprint != read_fingerprint {
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
        let encoded_bytes = manifest_bytes.len();
        let manifest = Arc::new(manifest);
        self.manifest_cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(
                digest.to_string(),
                ManifestCacheEntry {
                    size: read_size,
                    encoded_bytes,
                    fingerprint: read_fingerprint,
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
            self.validate_blob(&path, key, hash_buffer)
                .map_err(ValidateBlobError::into_error)?;
        } else if !blob_metadata_is_valid(&path, key) {
            return Err(LpmError::Store(format!(
                "v3 CAS blob metadata mismatch at {}",
                path.display()
            )));
        }
        Ok(path)
    }

    pub(crate) fn verify_blob_at_path(
        &self,
        path: &Path,
        key: &BlobKey,
        hash_buffer: &mut [u8],
    ) -> Result<(), LpmError> {
        self.validate_blob(path, key, hash_buffer)
            .map(|_| ())
            .map_err(ValidateBlobError::into_error)
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
                let (blob, compact_id, fingerprint) =
                    self.ingest_file(&path, &metadata, ingest.hash_buffer)?;
                ingest.blob_stats.insert(compact_id, fingerprint);
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
    ) -> Result<(BlobKey, CompactBlobId, BlobStatFingerprint), LpmError> {
        let (mut file, open_meta) = open_regular_file_nofollow(source).map_err(|error| {
            LpmError::Store(format!(
                "failed to open v3 CAS source file {}: {error}",
                source.display()
            ))
        })?;
        let source_identity = file_identity_from_open_file(source, &file, &open_meta)?;
        let raw_digest = hash_open_file_bytes(&mut file, source, hash_buffer)?;
        let mode = normalized_mode(metadata);
        let size = metadata.len();
        if open_meta.len() != size || normalized_mode(&open_meta) != mode {
            return Err(LpmError::Store(format!(
                "v3 CAS source file changed while hashing {}",
                source.display()
            )));
        }
        let compact_id = CompactBlobId::from_raw(raw_digest, mode, size);
        let key = BlobKey {
            digest: blake3::Hash::from_bytes(raw_digest).to_hex().to_string(),
            mode,
            size,
        };
        let published = self.publish_blob(
            source,
            &key,
            hash_buffer,
            FirstPublishTrust::Verified,
            source_identity,
        )?;
        Ok((key, compact_id, published.fingerprint))
    }

    fn record_validated_blob(&self, key: &BlobKey, fingerprint: BlobStatFingerprint) {
        if let Some(id) = CompactBlobId::try_from_key(key) {
            self.record_validated_blob_id(id, fingerprint);
        }
    }

    fn record_validated_blobs_batch(
        &self,
        keys: &[&BlobKey],
        observed_stats: &[Option<BlobStatFingerprint>],
    ) {
        let mut guard = self
            .validated_blobs
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for (key, maybe_fp) in keys.iter().zip(observed_stats.iter().copied()) {
            let (Some(id), Some(fingerprint)) = (CompactBlobId::try_from_key(key), maybe_fp) else {
                continue;
            };
            if guard.len() >= MAX_VALIDATED_BLOBS && !guard.contains_key(&id) {
                guard.clear();
            }
            guard.insert(id, fingerprint);
        }
    }

    fn record_validated_blob_id(&self, id: CompactBlobId, fingerprint: BlobStatFingerprint) {
        let mut guard = self
            .validated_blobs
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if guard.len() >= MAX_VALIDATED_BLOBS && !guard.contains_key(&id) {
            guard.clear();
        }
        guard.insert(id, fingerprint);
    }

    fn evict_validated_blob(&self, key: &BlobKey) {
        if let Some(id) = CompactBlobId::try_from_key(key) {
            self.validated_blobs
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .remove(&id);
        }
    }

    fn cached_validated_blob(&self, key: &BlobKey) -> Option<BlobStatFingerprint> {
        let id = CompactBlobId::try_from_key(key)?;
        self.validated_blobs
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&id)
            .copied()
    }

    fn blob_matches_bad_identity(&self, blob: &Path, bad_identity: Option<FileIdentity>) -> bool {
        let Some(bad_id) = bad_identity else {
            return true;
        };
        let Ok(metadata) = fs::symlink_metadata(blob) else {
            return false;
        };
        if !metadata.file_type().is_file() {
            return true;
        }
        match file_identity_for_path(blob, &metadata) {
            Ok(Some(live_id)) => live_id == bad_id,
            Ok(None) | Err(_) => true,
        }
    }

    fn publish_blob(
        &self,
        source: &Path,
        key: &BlobKey,
        hash_buffer: &mut [u8],
        first_publish_trust: FirstPublishTrust,
        expected_source_identity: Option<FileIdentity>,
    ) -> Result<PublishedBlob, LpmError> {
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
            Ok(()) => {
                let fingerprint = self.read_blob_stat(key)?;
                if let Some(expected_id) = expected_source_identity
                    && fingerprint
                        .file_identity()
                        .is_some_and(|live| live != expected_id)
                {
                    if self.blob_matches_bad_identity(&blob, fingerprint.file_identity()) {
                        let _ = self.quarantine_entry(&blob, "blobs");
                    }
                    return Err(LpmError::Store(format!(
                        "source file changed during v3 CAS blob publication at {}",
                        source.display()
                    )));
                }
                let deferred_validation =
                    first_publish_trust == FirstPublishTrust::DeferUntilFinalized;
                if !deferred_validation {
                    self.record_validated_blob(key, fingerprint);
                }
                return Ok(PublishedBlob {
                    fingerprint,
                    deferred_validation,
                });
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => {
                return Err(LpmError::Store(format!(
                    "failed to publish v3 CAS blob {}: {error}",
                    blob.display()
                )));
            }
        }

        if paths_share_file_identity(source, &blob) {
            let validated = self
                .validate_blob(source, key, hash_buffer)
                .map_err(ValidateBlobError::into_error)?;
            self.record_validated_blob(key, validated);
            return Ok(PublishedBlob {
                fingerprint: validated,
                deferred_validation: false,
            });
        }

        let pre_fp = self.read_blob_stat(key).ok();
        let cached = self.cached_validated_blob(key);
        let backup = HardlinkReplaceGuard::stage(&blob, source)?;
        #[cfg(test)]
        run_test_after_publish_hardlink_hook(&blob);
        if let (Some(cached), Some(pre_fp)) = (cached, pre_fp)
            && pre_fp == cached
            && cached.is_settled()
            && let Ok(post_fp) = self.read_path_stat_as_blob(source, key)
            && post_fp.is_hardlink_only_transition_from(pre_fp)
        {
            backup.commit()?;
            self.record_validated_blob(key, post_fp);
            return Ok(PublishedBlob {
                fingerprint: post_fp,
                deferred_validation: false,
            });
        }
        match self.validate_blob(source, key, hash_buffer) {
            Ok(validated) => {
                backup.commit()?;
                self.record_validated_blob(key, validated);
                Ok(PublishedBlob {
                    fingerprint: validated,
                    deferred_validation: false,
                })
            }
            Err(ValidateBlobError::Contended(error)) => {
                backup.rollback()?;
                Err(*error)
            }
            Err(ValidateBlobError::Corrupt { bad_identity, .. }) => {
                self.evict_validated_blob(key);
                backup.rollback()?;
                if self.blob_matches_bad_identity(&blob, bad_identity) {
                    self.quarantine_entry(&blob, "blobs")?;
                }
                match fs::hard_link(source, &blob) {
                    Ok(()) => {
                        let fingerprint = self.read_blob_stat(key)?;
                        if let Some(expected_id) = expected_source_identity
                            && fingerprint
                                .file_identity()
                                .is_some_and(|live| live != expected_id)
                        {
                            if self.blob_matches_bad_identity(&blob, fingerprint.file_identity()) {
                                let _ = self.quarantine_entry(&blob, "blobs");
                            }
                            return Err(LpmError::Store(format!(
                                "source file changed during v3 CAS blob repair at {}",
                                source.display()
                            )));
                        }
                        let deferred_validation =
                            first_publish_trust == FirstPublishTrust::DeferUntilFinalized;
                        if !deferred_validation {
                            self.record_validated_blob(key, fingerprint);
                        }
                        Ok(PublishedBlob {
                            fingerprint,
                            deferred_validation,
                        })
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                        let retry_backup = HardlinkReplaceGuard::stage(&blob, source)?;
                        match self.validate_blob(source, key, hash_buffer) {
                            Ok(fingerprint) => {
                                retry_backup.commit()?;
                                self.record_validated_blob(key, fingerprint);
                                Ok(PublishedBlob {
                                    fingerprint,
                                    deferred_validation: false,
                                })
                            }
                            Err(err) => {
                                retry_backup.rollback()?;
                                Err(err.into_error())
                            }
                        }
                    }
                    Err(error) => Err(LpmError::Store(format!(
                        "failed to repair v3 CAS blob {}: {error}",
                        blob.display()
                    ))),
                }
            }
        }
    }

    fn ensure_cas_directory(&self, path: &Path) -> std::io::Result<()> {
        if self
            .secured_directories
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .contains(path)
        {
            return Ok(());
        }
        ensure_cas_directory_chain_locked(&self.store_root, path)?;
        self.secured_directories
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(path.to_path_buf());
        Ok(())
    }

    fn validate_blob(
        &self,
        blob: &Path,
        key: &BlobKey,
        hash_buffer: &mut [u8],
    ) -> Result<BlobStatFingerprint, ValidateBlobError> {
        let (mut file, mut pre_meta) = open_regular_file_nofollow(blob).map_err(|error| {
            ValidateBlobError::corrupt(
                LpmError::Store(format!(
                    "failed to inspect existing v3 CAS blob {}: {error}",
                    blob.display()
                )),
                None,
            )
        })?;
        for attempt in 0..MAX_VALIDATE_BLOB_ATTEMPTS {
            if attempt > 0 {
                file.seek(io::SeekFrom::Start(0)).map_err(|error| {
                    ValidateBlobError::corrupt(
                        LpmError::Store(format!(
                            "failed to rewind existing v3 CAS blob {}: {error}",
                            blob.display()
                        )),
                        None,
                    )
                })?;
                pre_meta = file.metadata().map_err(|error| {
                    ValidateBlobError::corrupt(
                        LpmError::Store(format!(
                            "failed to re-inspect existing v3 CAS blob {}: {error}",
                            blob.display()
                        )),
                        None,
                    )
                })?;
            }
            #[cfg(windows)]
            let pre_fp = BlobStatFingerprint::from_open_file(blob, &file)
                .map_err(|error| ValidateBlobError::corrupt(error, None))?;
            #[cfg(not(windows))]
            let pre_fp = BlobStatFingerprint::from_metadata(&pre_meta);
            let bad_identity = pre_fp.file_identity();

            if !pre_meta.file_type().is_file()
                || pre_meta.len() != key.size
                || normalized_mode(&pre_meta) != key.mode
            {
                return Err(ValidateBlobError::corrupt(
                    LpmError::Store(format!(
                        "existing v3 CAS blob failed integrity validation at {}",
                        blob.display()
                    )),
                    bad_identity,
                ));
            }

            let digest = hash_open_file(&mut file, blob, hash_buffer)
                .map_err(|error| ValidateBlobError::corrupt(error, bad_identity))?;
            if digest != key.digest {
                return Err(ValidateBlobError::corrupt(
                    LpmError::Store(format!(
                        "existing v3 CAS blob failed integrity validation at {}",
                        blob.display()
                    )),
                    bad_identity,
                ));
            }
            #[cfg(test)]
            run_test_after_validate_hash_hook(blob);
            let post_meta = file.metadata().map_err(|error| {
                ValidateBlobError::corrupt(
                    LpmError::Store(format!(
                        "failed to re-inspect existing v3 CAS blob {}: {error}",
                        blob.display()
                    )),
                    bad_identity,
                )
            })?;
            if !post_meta.file_type().is_file()
                || post_meta.len() != key.size
                || normalized_mode(&post_meta) != key.mode
            {
                return Err(ValidateBlobError::corrupt(
                    LpmError::Store(format!(
                        "existing v3 CAS blob changed during integrity validation at {}",
                        blob.display()
                    )),
                    bad_identity,
                ));
            }
            #[cfg(windows)]
            let post_fp = BlobStatFingerprint::from_open_file(blob, &file)
                .map_err(|error| ValidateBlobError::corrupt(error, bad_identity))?;
            #[cfg(not(windows))]
            let post_fp = BlobStatFingerprint::from_metadata(&post_meta);

            if post_fp == pre_fp {
                return Ok(post_fp);
            }
            if post_fp.is_link_count_only_transition_from(pre_fp) {
                if attempt + 1 < MAX_VALIDATE_BLOB_ATTEMPTS {
                    continue;
                }
                return Err(ValidateBlobError::contended(LpmError::Store(format!(
                    "existing v3 CAS blob experienced concurrent link updates during validation at {}",
                    blob.display()
                ))));
            }
            return Err(ValidateBlobError::corrupt(
                LpmError::Store(format!(
                    "existing v3 CAS blob changed during integrity validation at {}",
                    blob.display()
                )),
                bad_identity,
            ));
        }
        Err(ValidateBlobError::contended(LpmError::Store(format!(
            "existing v3 CAS blob experienced concurrent link updates during validation at {}",
            blob.display()
        ))))
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
        use std::fmt::Write as _;

        if !valid_hex_digest(&key.digest) {
            return Err(LpmError::Store("invalid v3 CAS blob digest".into()));
        }
        let shard = key
            .digest
            .get(..2)
            .ok_or_else(|| LpmError::Store("invalid v3 CAS blob digest shard".into()))?;
        let mut name = String::with_capacity(key.digest.len() + 5);
        let _ = write!(&mut name, "{}-{:04o}", key.digest, key.mode);
        let mut path = PathBuf::with_capacity(self.blobs_root.as_os_str().len() + 4 + name.len());
        path.push(&self.blobs_root);
        path.push(shard);
        path.push(&name);
        Ok(path)
    }

    pub(crate) fn tree_manifest_path(&self, digest: &str) -> Result<PathBuf, LpmError> {
        if !valid_hex_digest(digest) {
            return Err(LpmError::Store("invalid v3 CAS tree digest".into()));
        }
        let shard = digest
            .get(..2)
            .ok_or_else(|| LpmError::Store("invalid v3 CAS tree digest shard".into()))?;
        let mut name = String::with_capacity(digest.len() + ".msgpack".len());
        name.push_str(digest);
        name.push_str(".msgpack");
        let mut path = PathBuf::with_capacity(self.trees_root.as_os_str().len() + 4 + name.len());
        path.push(&self.trees_root);
        path.push(shard);
        path.push(&name);
        Ok(path)
    }

    pub(crate) fn compact_blob_key(
        &self,
        digest: &str,
        mode: u32,
    ) -> Result<CompactBlobKey, LpmError> {
        if !valid_hex_digest(digest) {
            return Err(LpmError::Store("invalid v3 CAS blob digest".into()));
        }
        let mut bytes = [0u8; 32];
        hex::decode_to_slice(digest, &mut bytes)
            .map_err(|_| LpmError::Store("invalid v3 CAS blob digest".into()))?;
        Ok((bytes, mode))
    }

    pub(crate) fn compact_blob_key_from_path(
        &self,
        path: &Path,
    ) -> Result<CompactBlobKey, LpmError> {
        let name = path.file_name().and_then(OsStr::to_str).ok_or_else(|| {
            LpmError::Store(format!("invalid v3 CAS blob path {}", path.display()))
        })?;
        let (digest, mode_str) = name.rsplit_once('-').ok_or_else(|| {
            LpmError::Store(format!("invalid v3 CAS blob name {}", path.display()))
        })?;
        if mode_str.len() != 4 || !valid_hex_digest(digest) {
            return Err(LpmError::Store(format!(
                "invalid v3 CAS blob name {}",
                path.display()
            )));
        }
        let shard = &digest[..2];
        if path.parent().and_then(Path::file_name) != Some(OsStr::new(shard))
            || path.parent().and_then(Path::parent) != Some(self.blobs_root.as_path())
        {
            return Err(LpmError::Store(format!(
                "invalid v3 CAS blob path {}",
                path.display()
            )));
        }
        let mode = u32::from_str_radix(mode_str, 8)
            .map_err(|_| LpmError::Store(format!("invalid v3 CAS blob mode {}", path.display())))?;
        let mut bytes = [0u8; 32];
        hex::decode_to_slice(digest, &mut bytes).map_err(|_| {
            LpmError::Store(format!("invalid v3 CAS blob digest {}", path.display()))
        })?;
        Ok((bytes, mode))
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

    fn open_source_validation(
        &self,
        source_sri: &str,
    ) -> Result<OpenSourceValidation, std::io::Error> {
        let path = self
            .source_validation_path(source_sri)
            .map_err(std::io::Error::other)?;
        let (file, metadata) = open_regular_file_nofollow(&path)?;
        if metadata.len() > SOURCE_VALIDATION_MAX_FILE_BYTES {
            return Err(std::io::Error::other(format!(
                "CAS source validation is {} bytes; cap is {SOURCE_VALIDATION_MAX_FILE_BYTES}",
                metadata.len()
            )));
        }
        let mut reader = BufReader::with_capacity(1024, file);
        let record = {
            let mut limited = reader.by_ref().take(SOURCE_VALIDATION_HEADER_MAX_BYTES);
            rmp_serde::decode::from_read(&mut limited).map_err(std::io::Error::other)?
        };
        Ok(OpenSourceValidation { record, reader })
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

    pub(crate) fn prune_tree_inventory(
        &self,
        live_tree_digests: &HashMap<String, bool>,
    ) -> Result<(usize, Vec<PathBuf>), LpmError> {
        collect_sharded_orphans(&self.trees_root, PruneInventoryKind::File, |path| {
            let digest = sharded_digest(path, &self.trees_root, ".msgpack", "tree manifest")?;
            Ok(live_tree_digests.contains_key(digest))
        })
    }

    pub(crate) fn prune_blob_inventory(
        &self,
        live_blobs: &HashSet<CompactBlobKey>,
    ) -> Result<(usize, Vec<PathBuf>), LpmError> {
        collect_sharded_orphans(&self.blobs_root, PruneInventoryKind::File, |path| {
            Ok(self
                .compact_blob_key_from_path(path)
                .is_ok_and(|key| live_blobs.contains(&key)))
        })
    }

    pub(crate) fn prune_source_record_inventory(
        &self,
        live_source_digests: &HashSet<String>,
    ) -> Result<(usize, Vec<PathBuf>), LpmError> {
        collect_sharded_orphans(&self.sources_root, PruneInventoryKind::File, |path| {
            let digest = sharded_digest(path, &self.sources_root, ".msgpack", "source record")?;
            Ok(live_source_digests.contains(digest))
        })
    }

    pub(crate) fn prune_source_validation_inventory(
        &self,
        live_source_digests: &HashSet<String>,
    ) -> Result<(usize, Vec<PathBuf>), LpmError> {
        collect_sharded_orphans(
            &self.source_validations_root,
            PruneInventoryKind::File,
            |path| {
                let digest = sharded_digest(
                    path,
                    &self.source_validations_root,
                    ".msgpack",
                    "source validation",
                )?;
                Ok(live_source_digests.contains(digest))
            },
        )
    }

    pub(crate) fn prune_materialized_inventory(
        &self,
        live_tree_digests: &HashMap<String, bool>,
    ) -> Result<(usize, Vec<PathBuf>), LpmError> {
        collect_sharded_orphans(
            &self.materialized_root,
            PruneInventoryKind::Directory,
            |path| {
                let digest = sharded_digest(path, &self.materialized_root, "", "materialized")?;
                Ok(live_tree_digests.contains_key(digest))
            },
        )
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
        Ok(metadata) if metadata.file_type().is_dir() => {
            tighten_directory_permissions(path, &metadata)
        }
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
                            tighten_directory_permissions(path, &metadata)
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
fn tighten_directory_permissions(path: &Path, metadata: &fs::Metadata) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    if (metadata.permissions().mode() & 0o7777) == 0o700 {
        return Ok(());
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
}

#[cfg(not(unix))]
#[expect(
    clippy::unnecessary_wraps,
    reason = "matches the Unix implementation, which sets the directory mode"
)]
fn tighten_directory_permissions(_path: &Path, _metadata: &fs::Metadata) -> io::Result<()> {
    Ok(())
}

#[derive(Clone, Copy)]
enum PruneInventoryKind {
    File,
    Directory,
}

fn collect_sharded_orphans(
    root: &Path,
    kind: PruneInventoryKind,
    mut is_live: impl FnMut(&Path) -> Result<bool, LpmError>,
) -> Result<(usize, Vec<PathBuf>), LpmError> {
    ensure_cas_root_directory(root)?;
    if !root.try_exists()? {
        return Ok((0, Vec::new()));
    }
    let mut total = 0usize;
    let mut orphaned = Vec::new();
    for shard in fs::read_dir(root).map_err(|error| {
        LpmError::Store(format!(
            "failed to enumerate v3 CAS root {}: {error}",
            root.display()
        ))
    })? {
        let shard = shard.map_err(|error| {
            LpmError::Store(format!("failed to enumerate v3 CAS shard: {error}"))
        })?;
        if !shard
            .file_type()
            .map_err(|error| LpmError::Store(format!("failed to inspect v3 CAS shard: {error}")))?
            .is_dir()
        {
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
            let expected_type = match kind {
                PruneInventoryKind::File => file_type.is_file(),
                PruneInventoryKind::Directory => file_type.is_dir(),
            };
            if !expected_type {
                return Err(LpmError::Store(format!(
                    "v3 CAS entry has an invalid type at {}",
                    entry.path().display()
                )));
            }
            total = total.saturating_add(1);
            let path = entry.path();
            if !is_live(&path)? {
                orphaned.push(path);
            }
        }
    }
    orphaned.sort_unstable();
    Ok((total, orphaned))
}

fn sharded_digest<'a>(
    path: &'a Path,
    root: &Path,
    suffix: &str,
    kind: &str,
) -> Result<&'a str, LpmError> {
    let name = path
        .file_name()
        .and_then(OsStr::to_str)
        .ok_or_else(|| LpmError::Store(format!("invalid v3 CAS {kind} path {}", path.display())))?;
    let digest = name
        .strip_suffix(suffix)
        .ok_or_else(|| LpmError::Store(format!("invalid v3 CAS {kind} name {}", path.display())))?;
    let shard = digest.get(..2).ok_or_else(|| {
        LpmError::Store(format!("invalid v3 CAS {kind} digest {}", path.display()))
    })?;
    if !valid_hex_digest(digest)
        || path.parent().and_then(Path::file_name) != Some(OsStr::new(shard))
        || path.parent().and_then(Path::parent) != Some(root)
    {
        return Err(LpmError::Store(format!(
            "invalid v3 CAS {kind} path {}",
            path.display()
        )));
    }
    Ok(digest)
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
impl ManifestStatFingerprint {
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
}

#[cfg(windows)]
impl ManifestStatFingerprint {
    fn from_open_file(
        path: &Path,
        file: &fs::File,
        metadata: &fs::Metadata,
    ) -> Result<Self, LpmError> {
        use std::os::windows::fs::MetadataExt;
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_BASIC_INFO, FileBasicInfo, GetFileInformationByHandleEx,
        };

        let identity = FileIdentity::from_open_file(file).map_err(|error| {
            LpmError::Store(format!(
                "failed to read v3 CAS manifest identity at {}: {error}",
                path.display()
            ))
        })?;
        let mut basic_info = FILE_BASIC_INFO::default();
        // SAFETY: `file` is live and `basic_info` is writable storage for
        // the `FileBasicInfo` result requested from Win32.
        if unsafe {
            GetFileInformationByHandleEx(
                file.as_raw_handle(),
                FileBasicInfo,
                &mut basic_info as *mut _ as *mut _,
                std::mem::size_of::<FILE_BASIC_INFO>() as u32,
            )
        } == 0
        {
            return Err(LpmError::Store(format!(
                "failed to read v3 CAS manifest change time at {}: {}",
                path.display(),
                std::io::Error::last_os_error()
            )));
        }

        Ok(Self {
            volume_serial_number: identity.volume,
            file_index: identity.file_id,
            creation_time: metadata.creation_time(),
            last_write_time: metadata.last_write_time(),
            change_time: basic_info.ChangeTime,
            file_attributes: metadata.file_attributes(),
        })
    }
}

#[cfg(not(any(unix, windows)))]
impl ManifestStatFingerprint {
    fn from_metadata(metadata: &fs::Metadata) -> Self {
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
}

#[cfg(unix)]
#[expect(
    clippy::unnecessary_wraps,
    reason = "matches the Windows implementation, which opens the path to read handle identity"
)]
fn file_identity_for_path(
    _path: &Path,
    metadata: &fs::Metadata,
) -> Result<Option<FileIdentity>, LpmError> {
    Ok(Some(FileIdentity::from_unix_metadata(metadata)))
}

#[cfg(windows)]
fn file_identity_for_path(
    path: &Path,
    _metadata: &fs::Metadata,
) -> Result<Option<FileIdentity>, LpmError> {
    let file = open_attributes_nofollow(path).map_err(|error| {
        LpmError::Store(format!(
            "failed to inspect v3 CAS file identity at {}: {error}",
            path.display()
        ))
    })?;
    let identity = FileIdentity::from_open_file(&file).map_err(|error| {
        LpmError::Store(format!(
            "failed to read v3 CAS file identity at {}: {error}",
            path.display()
        ))
    })?;
    Ok(Some(identity))
}

#[cfg(not(any(unix, windows)))]
#[expect(
    clippy::unnecessary_wraps,
    reason = "matches the Windows implementation, which opens the path to read handle identity"
)]
fn file_identity_for_path(
    _path: &Path,
    _metadata: &fs::Metadata,
) -> Result<Option<FileIdentity>, LpmError> {
    Ok(None)
}

#[cfg(unix)]
#[expect(
    clippy::unnecessary_wraps,
    reason = "matches the Windows implementation, which queries handle identity"
)]
fn file_identity_from_open_file(
    _path: &Path,
    _file: &fs::File,
    metadata: &fs::Metadata,
) -> Result<Option<FileIdentity>, LpmError> {
    Ok(Some(FileIdentity::from_unix_metadata(metadata)))
}

#[cfg(windows)]
fn file_identity_from_open_file(
    path: &Path,
    file: &fs::File,
    _metadata: &fs::Metadata,
) -> Result<Option<FileIdentity>, LpmError> {
    let identity = FileIdentity::from_open_file(file).map_err(|error| {
        LpmError::Store(format!(
            "failed to read v3 CAS file identity at {}: {error}",
            path.display()
        ))
    })?;
    Ok(Some(identity))
}

#[cfg(not(any(unix, windows)))]
#[expect(
    clippy::unnecessary_wraps,
    reason = "matches the Windows implementation, which queries handle identity"
)]
fn file_identity_from_open_file(
    _path: &Path,
    _file: &fs::File,
    _metadata: &fs::Metadata,
) -> Result<Option<FileIdentity>, LpmError> {
    Ok(None)
}

#[cfg(unix)]
fn unix_extracted_stamp_from_metadata(metadata: &fs::Metadata) -> Option<ExtractedFileStamp> {
    use std::os::unix::fs::MetadataExt;

    let mtime_ns = u64::try_from(metadata.mtime())
        .ok()?
        .checked_mul(1_000_000_000)?
        .checked_add(u64::try_from(metadata.mtime_nsec()).ok()?)?;
    let ctime_ns = u64::try_from(metadata.ctime())
        .ok()?
        .checked_mul(1_000_000_000)?
        .checked_add(u64::try_from(metadata.ctime_nsec()).ok()?)?;
    Some(ExtractedFileStamp {
        identity: FileIdentity::from_unix_metadata(metadata),
        size: metadata.len(),
        mode: normalized_mode(metadata),
        mtime_ns,
        ctime_ns,
    })
}

fn inspect_registry_source_file(
    source: &Path,
) -> Result<(u64, u32, Option<FileIdentity>, Option<ExtractedFileStamp>), LpmError> {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

        let file = open_attributes_nofollow(source).map_err(|error| {
            LpmError::Store(format!(
                "failed to inspect extracted v3 CAS entry {}: {error}",
                source.display()
            ))
        })?;
        let metadata = file.metadata().map_err(|error| {
            LpmError::Store(format!(
                "failed to inspect extracted v3 CAS entry {}: {error}",
                source.display()
            ))
        })?;
        if !metadata.file_type().is_file()
            || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
        {
            return Err(LpmError::Store(format!(
                "extracted v3 CAS entry changed before publication at {}",
                source.display()
            )));
        }
        let file_size = metadata.len();
        let mode = normalized_mode(&metadata);
        if let Some(win_stamp) = lpm_common::windows_regular_file_stamp_from_open_file(&file) {
            let identity = win_stamp.identity;
            let live_stamp = ExtractedFileStamp {
                identity,
                size: win_stamp.len,
                mode,
                mtime_ns: win_stamp.mtime_ns,
                ctime_ns: win_stamp.ctime_ns,
            };
            Ok((file_size, mode, Some(identity), Some(live_stamp)))
        } else {
            let identity = file_identity_from_open_file(source, &file, &metadata)?;
            Ok((file_size, mode, identity, None))
        }
    }
    #[cfg(not(windows))]
    {
        let metadata = fs::symlink_metadata(source).map_err(|error| {
            LpmError::Store(format!(
                "failed to inspect extracted v3 CAS entry {}: {error}",
                source.display()
            ))
        })?;
        if !metadata.file_type().is_file() {
            return Err(LpmError::Store(format!(
                "extracted v3 CAS entry changed before publication at {}",
                source.display()
            )));
        }
        let file_size = metadata.len();
        let mode = normalized_mode(&metadata);
        let identity = file_identity_for_path(source, &metadata)?;
        #[cfg(unix)]
        let live_stamp = unix_extracted_stamp_from_metadata(&metadata);
        #[cfg(not(unix))]
        let live_stamp = None;
        Ok((file_size, mode, identity, live_stamp))
    }
}

fn paths_share_file_identity(left: &Path, right: &Path) -> bool {
    let Ok(left_meta) = fs::symlink_metadata(left) else {
        return false;
    };
    let Ok(right_meta) = fs::symlink_metadata(right) else {
        return false;
    };
    matches!(
        (
            file_identity_for_path(left, &left_meta),
            file_identity_for_path(right, &right_meta),
        ),
        (Ok(Some(a)), Ok(Some(b))) if a == b
    )
}

#[cfg(unix)]
fn unix_timestamp_is_settled(secs: i64, nanos: i64, now: SystemTime) -> bool {
    let Ok(secs) = u64::try_from(secs) else {
        return false;
    };
    let Ok(nanos) = u32::try_from(nanos) else {
        return false;
    };
    if nanos >= 1_000_000_000 {
        return false;
    }
    let Some(ts) = UNIX_EPOCH.checked_add(Duration::new(secs, nanos)) else {
        return false;
    };
    now.duration_since(ts)
        .is_ok_and(|age| age >= SETTLED_BLOB_MTIME_MARGIN)
}

#[cfg(unix)]
impl BlobStatFingerprint {
    fn from_metadata(metadata: &fs::Metadata) -> Self {
        use std::os::unix::fs::MetadataExt;

        Self {
            dev: metadata.dev(),
            ino: metadata.ino(),
            mode: normalized_mode(metadata),
            nlink: metadata.nlink(),
            mtime: metadata.mtime(),
            mtime_nsec: metadata.mtime_nsec(),
            ctime: metadata.ctime(),
            ctime_nsec: metadata.ctime_nsec(),
        }
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "matches platforms where file identity cannot be queried"
    )]
    fn file_identity(self) -> Option<FileIdentity> {
        Some(FileIdentity {
            volume: self.dev,
            file_id: u128::from(self.ino),
        })
    }

    fn same_content_identity(self, other: Self) -> bool {
        (self.dev, self.ino, self.mode, self.mtime, self.mtime_nsec)
            == (
                other.dev,
                other.ino,
                other.mode,
                other.mtime,
                other.mtime_nsec,
            )
    }

    fn is_hardlink_only_transition_from(self, prior: Self) -> bool {
        self.same_content_identity(prior) && self.nlink > prior.nlink
    }

    fn is_link_count_only_transition_from(self, prior: Self) -> bool {
        self.same_content_identity(prior) && self.nlink != prior.nlink
    }

    fn update_hasher(self, hasher: &mut blake3::Hasher) {
        hasher.update(&self.dev.to_le_bytes());
        hasher.update(&self.ino.to_le_bytes());
        hasher.update(&self.mode.to_le_bytes());
        hasher.update(&self.nlink.to_le_bytes());
        hasher.update(&self.mtime.to_le_bytes());
        hasher.update(&self.mtime_nsec.to_le_bytes());
        hasher.update(&self.ctime.to_le_bytes());
        hasher.update(&self.ctime_nsec.to_le_bytes());
    }

    fn is_settled(self) -> bool {
        self.is_settled_at(SystemTime::now())
    }

    fn is_settled_at(self, now: SystemTime) -> bool {
        unix_timestamp_is_settled(self.mtime, self.mtime_nsec, now)
            && unix_timestamp_is_settled(self.ctime, self.ctime_nsec, now)
    }
}

#[cfg(windows)]
fn windows_filetime_is_settled(ticks_100ns: u64, now: SystemTime) -> bool {
    const WINDOWS_TO_UNIX_EPOCH_100NS: u64 = 116_444_736_000_000_000;
    let Some(since_unix_100ns) = ticks_100ns.checked_sub(WINDOWS_TO_UNIX_EPOCH_100NS) else {
        return false;
    };
    let secs = since_unix_100ns / 10_000_000;
    let nanos = ((since_unix_100ns % 10_000_000) * 100) as u32;
    let Some(ts) = UNIX_EPOCH.checked_add(Duration::new(secs, nanos)) else {
        return false;
    };
    now.duration_since(ts)
        .is_ok_and(|age| age >= SETTLED_BLOB_MTIME_MARGIN)
}

#[cfg(windows)]
impl BlobStatFingerprint {
    fn from_validated_blob_path(path: &Path, key: &BlobKey) -> Result<Self, LpmError> {
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_READONLY, FILE_ATTRIBUTE_REPARSE_POINT,
        };

        let file = open_attributes_nofollow(path).map_err(|error| {
            LpmError::Store(format!(
                "failed to open v3 CAS blob for Windows identity at {}: {error}",
                path.display()
            ))
        })?;
        let (fingerprint, size) = Self::from_open_file_with_size(path, &file)?;
        let mode = if fingerprint.file_attributes & FILE_ATTRIBUTE_READONLY != 0 {
            0o444
        } else {
            0o644
        };
        if fingerprint.file_attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)
            != 0
            || size != key.size
            || mode != key.mode
        {
            return Err(LpmError::Store(format!(
                "v3 CAS blob metadata mismatch at {}",
                path.display()
            )));
        }
        Ok(fingerprint)
    }

    fn from_open_file(path: &Path, file: &fs::File) -> Result<Self, LpmError> {
        Self::from_open_file_with_size(path, file).map(|(fingerprint, _)| fingerprint)
    }

    fn from_open_file_with_size(path: &Path, file: &fs::File) -> Result<(Self, u64), LpmError> {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Storage::FileSystem::{
            BY_HANDLE_FILE_INFORMATION, FILE_BASIC_INFO, FileBasicInfo, GetFileInformationByHandle,
            GetFileInformationByHandleEx,
        };

        let handle = file.as_raw_handle();
        let mut handle_info = BY_HANDLE_FILE_INFORMATION::default();
        // SAFETY: `handle` is live and `handle_info` is writable storage of the exact Win32 type.
        if unsafe { GetFileInformationByHandle(handle, &mut handle_info) } == 0 {
            return Err(LpmError::Store(format!(
                "failed to read v3 CAS blob identity at {}: {}",
                path.display(),
                std::io::Error::last_os_error()
            )));
        }
        let mut basic_info = FILE_BASIC_INFO::default();
        // SAFETY: `handle` is live and `basic_info` is writable storage for `FileBasicInfo`.
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
        let identity = FileIdentity::from_open_file(file).map_err(|error| {
            LpmError::Store(format!(
                "failed to read v3 CAS blob file ID at {}: {error}",
                path.display()
            ))
        })?;
        let creation_time = (u64::from(handle_info.ftCreationTime.dwHighDateTime) << 32)
            | u64::from(handle_info.ftCreationTime.dwLowDateTime);
        let last_write_time = (u64::from(handle_info.ftLastWriteTime.dwHighDateTime) << 32)
            | u64::from(handle_info.ftLastWriteTime.dwLowDateTime);
        let size =
            (u64::from(handle_info.nFileSizeHigh) << 32) | u64::from(handle_info.nFileSizeLow);
        Ok((
            Self {
                volume_serial_number: identity.volume,
                file_index: identity.file_id,
                creation_time,
                last_write_time,
                change_time: basic_info.ChangeTime,
                file_attributes: handle_info.dwFileAttributes,
                nlink: handle_info.nNumberOfLinks,
            },
            size,
        ))
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "matches platforms where file identity cannot be queried"
    )]
    fn file_identity(self) -> Option<FileIdentity> {
        Some(FileIdentity {
            volume: self.volume_serial_number,
            file_id: self.file_index,
        })
    }

    fn same_content_identity(self, other: Self) -> bool {
        (
            self.volume_serial_number,
            self.file_index,
            self.creation_time,
            self.last_write_time,
            self.file_attributes,
        ) == (
            other.volume_serial_number,
            other.file_index,
            other.creation_time,
            other.last_write_time,
            other.file_attributes,
        )
    }

    fn is_hardlink_only_transition_from(self, prior: Self) -> bool {
        self.same_content_identity(prior) && self.nlink > prior.nlink
    }

    fn is_link_count_only_transition_from(self, prior: Self) -> bool {
        self.same_content_identity(prior) && self.nlink != prior.nlink
    }

    fn update_hasher(self, hasher: &mut blake3::Hasher) {
        hasher.update(&self.volume_serial_number.to_le_bytes());
        hasher.update(&self.file_index.to_le_bytes());
        hasher.update(&self.creation_time.to_le_bytes());
        hasher.update(&self.last_write_time.to_le_bytes());
        hasher.update(&self.change_time.to_le_bytes());
        hasher.update(&self.file_attributes.to_le_bytes());
        hasher.update(&self.nlink.to_le_bytes());
    }

    fn is_settled(self) -> bool {
        self.is_settled_at(SystemTime::now())
    }

    fn is_settled_at(self, now: SystemTime) -> bool {
        let Ok(change_time) = u64::try_from(self.change_time) else {
            return false;
        };
        windows_filetime_is_settled(self.last_write_time, now)
            && windows_filetime_is_settled(change_time, now)
    }
}

#[cfg(not(any(unix, windows)))]
impl BlobStatFingerprint {
    fn from_metadata(metadata: &fs::Metadata) -> Self {
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

    fn file_identity(self) -> Option<FileIdentity> {
        None
    }

    fn is_hardlink_only_transition_from(self, _prior: Self) -> bool {
        false
    }

    fn is_link_count_only_transition_from(self, _prior: Self) -> bool {
        false
    }

    fn update_hasher(self, hasher: &mut blake3::Hasher) {
        hasher.update(&self.modified.to_le_bytes());
        hasher.update(&self.created.to_le_bytes());
        hasher.update(&[u8::from(self.readonly)]);
    }

    fn is_settled(self) -> bool {
        self.is_settled_at(SystemTime::now())
    }

    fn is_settled_at(self, now: SystemTime) -> bool {
        let nanos_is_settled = |ts_nanos: u128| {
            let secs = u64::try_from(ts_nanos / 1_000_000_000).ok();
            let nanos = (ts_nanos % 1_000_000_000) as u32;
            let Some(ts) = secs.and_then(|s| UNIX_EPOCH.checked_add(Duration::new(s, nanos)))
            else {
                return false;
            };
            now.duration_since(ts)
                .is_ok_and(|age| age >= SETTLED_BLOB_MTIME_MARGIN)
        };
        nanos_is_settled(self.modified) && (self.created == 0 || nanos_is_settled(self.created))
    }
}

fn single_blob_stat_digest(key: &BlobKey, fingerprint: BlobStatFingerprint) -> [u8; 16] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"lpm-v3-blob-stat-entry-v2\0");
    hasher.update(key.digest.as_bytes());
    hasher.update(&key.mode.to_le_bytes());
    hasher.update(&key.size.to_le_bytes());
    fingerprint.update_hasher(&mut hasher);
    let bytes = *hasher.finalize().as_bytes();
    bytes[0..16].try_into().unwrap()
}

fn encode_per_blob_stat_digests(keys: &[&BlobKey], stats: &[BlobStatFingerprint]) -> Vec<u8> {
    if keys.len() > SOURCE_VALIDATION_MAX_TRAILER_BLOBS {
        return Vec::new();
    }
    let mut digests = Vec::with_capacity(keys.len().saturating_mul(16));
    for (key, fingerprint) in keys.iter().zip(stats.iter().copied()) {
        digests.extend_from_slice(&single_blob_stat_digest(key, fingerprint));
    }
    digests
}

#[cfg(windows)]
fn open_attributes_nofollow(path: &Path) -> io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ,
        FILE_SHARE_WRITE,
    };

    OpenOptions::new()
        .access_mode(FILE_READ_ATTRIBUTES)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
}

fn manifest_file_fingerprint(path: &Path) -> Result<(u64, ManifestStatFingerprint), LpmError> {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

        let file = open_attributes_nofollow(path).map_err(|error| {
            LpmError::Store(format!(
                "failed to inspect v3 CAS tree manifest {}: {error}",
                path.display()
            ))
        })?;
        let metadata = file.metadata().map_err(|error| {
            LpmError::Store(format!(
                "failed to inspect v3 CAS tree manifest {}: {error}",
                path.display()
            ))
        })?;
        if !metadata.file_type().is_file()
            || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
            || metadata.len() > MANIFEST_MAX_BYTES
        {
            return Err(LpmError::Store(format!(
                "invalid v3 CAS tree manifest file at {}",
                path.display()
            )));
        }
        let fingerprint = ManifestStatFingerprint::from_open_file(path, &file, &metadata)?;
        Ok((metadata.len(), fingerprint))
    }
    #[cfg(not(windows))]
    {
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
        Ok((
            metadata.len(),
            ManifestStatFingerprint::from_metadata(&metadata),
        ))
    }
}

fn read_manifest_file_with_fingerprint(
    path: &Path,
    digest: &str,
) -> Result<(Vec<u8>, u64, ManifestStatFingerprint), LpmError> {
    let (mut file, pre_meta) = open_regular_file_nofollow(path).map_err(|error| {
        LpmError::Store(format!(
            "failed to read capped v3 CAS metadata at {}: {error}",
            path.display()
        ))
    })?;
    if pre_meta.len() > MANIFEST_MAX_BYTES {
        return Err(LpmError::Store(format!(
            "v3 CAS tree manifest is {} bytes; cap is {MANIFEST_MAX_BYTES}",
            pre_meta.len()
        )));
    }
    #[cfg(windows)]
    let pre_fingerprint = ManifestStatFingerprint::from_open_file(path, &file, &pre_meta)?;
    #[cfg(not(windows))]
    let pre_fingerprint = ManifestStatFingerprint::from_metadata(&pre_meta);

    let read_cap = MANIFEST_MAX_BYTES + 1;
    let capacity = usize::try_from(pre_meta.len().min(read_cap)).unwrap_or(0);
    let mut bytes = Vec::with_capacity(capacity);
    (&mut file)
        .take(read_cap)
        .read_to_end(&mut bytes)
        .map_err(|error| {
            LpmError::Store(format!(
                "failed to read capped v3 CAS metadata at {}: {error}",
                path.display()
            ))
        })?;
    if bytes.len() as u64 > MANIFEST_MAX_BYTES {
        return Err(LpmError::Store(format!(
            "v3 CAS tree manifest exceeded {MANIFEST_MAX_BYTES} bytes while being read for {digest}"
        )));
    }
    let post_meta = file.metadata().map_err(|error| {
        LpmError::Store(format!(
            "failed to re-inspect v3 CAS tree manifest {}: {error}",
            path.display()
        ))
    })?;
    #[cfg(windows)]
    let post_fingerprint = ManifestStatFingerprint::from_open_file(path, &file, &post_meta)?;
    #[cfg(not(windows))]
    let post_fingerprint = ManifestStatFingerprint::from_metadata(&post_meta);

    if pre_meta.len() != post_meta.len()
        || bytes.len() as u64 != post_meta.len()
        || pre_fingerprint != post_fingerprint
    {
        return Err(LpmError::Store(format!(
            "v3 CAS tree manifest changed while being read for {digest}"
        )));
    }
    Ok((bytes, post_meta.len(), post_fingerprint))
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
    let (file, metadata) = open_regular_file_nofollow(path)?;
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
    file.take(read_cap).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > cap {
        return Err(io::Error::other(format!(
            "CAS metadata exceeded {cap} bytes while being read"
        )));
    }
    Ok(bytes)
}

fn open_regular_file_nofollow(path: &Path) -> io::Result<(File, fs::Metadata)> {
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
    Ok((file, metadata))
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

struct HardlinkReplaceGuard<'a> {
    destination: &'a Path,
    backup: PathBuf,
    active: bool,
}

impl<'a> HardlinkReplaceGuard<'a> {
    fn stage(source: &Path, destination: &'a Path) -> Result<Self, LpmError> {
        let backup = tmp_sibling(destination);
        fs::rename(destination, &backup).map_err(|error| {
            LpmError::Store(format!(
                "failed to stage duplicate v3 CAS object file {}: {error}",
                destination.display()
            ))
        })?;
        match fs::hard_link(source, destination) {
            Ok(()) => Ok(Self {
                destination,
                backup,
                active: true,
            }),
            Err(error) => {
                let _ = fs::rename(&backup, destination);
                Err(LpmError::Store(format!(
                    "failed to hardlink existing v3 CAS blob into {}: {error}",
                    destination.display()
                )))
            }
        }
    }

    fn commit(self) -> Result<(), LpmError> {
        self.commit_with(|backup| fs::remove_file(backup))
    }

    fn commit_with(
        mut self,
        remove_backup: impl FnOnce(&Path) -> io::Result<()>,
    ) -> Result<(), LpmError> {
        match remove_backup(&self.backup) {
            Ok(()) => {
                self.active = false;
                Ok(())
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                self.active = false;
                Ok(())
            }
            Err(error) => Err(LpmError::Store(format!(
                "failed to remove replaced v3 CAS object file {}: {error}",
                self.backup.display()
            ))),
        }
    }

    fn rollback(self) -> Result<(), LpmError> {
        self.rollback_with(
            |destination| fs::remove_file(destination),
            |backup, destination| fs::rename(backup, destination),
        )
    }

    fn rollback_with(
        mut self,
        remove_destination: impl FnOnce(&Path) -> io::Result<()>,
        rename_backup: impl FnOnce(&Path, &Path) -> io::Result<()>,
    ) -> Result<(), LpmError> {
        if let Err(error) = remove_destination(self.destination)
            && error.kind() != std::io::ErrorKind::NotFound
        {
            return Err(LpmError::Store(format!(
                "failed to remove staged v3 CAS object file {}: {error}",
                self.destination.display()
            )));
        }
        rename_backup(&self.backup, self.destination).map_err(|error| {
            LpmError::Store(format!(
                "failed to restore staged v3 CAS object file {}: {error}",
                self.destination.display()
            ))
        })?;
        self.active = false;
        Ok(())
    }
}

impl Drop for HardlinkReplaceGuard<'_> {
    fn drop(&mut self) {
        if self.active {
            let _ = fs::remove_file(self.destination);
            let _ = fs::rename(&self.backup, self.destination);
        }
    }
}

#[cfg(all(unix, test))]
fn hash_file_bytes(path: &Path, buffer: &mut [u8]) -> Result<[u8; 32], LpmError> {
    let (mut file, _) = open_regular_file_nofollow(path).map_err(|error| {
        LpmError::Store(format!(
            "failed to open v3 CAS source file {}: {error}",
            path.display()
        ))
    })?;
    hash_open_file_bytes(&mut file, path, buffer)
}

#[cfg(all(unix, test))]
fn hash_file(path: &Path, buffer: &mut [u8]) -> Result<String, LpmError> {
    Ok(blake3::Hash::from_bytes(hash_file_bytes(path, buffer)?)
        .to_hex()
        .to_string())
}

fn hash_open_file(file: &mut File, path: &Path, buffer: &mut [u8]) -> Result<String, LpmError> {
    Ok(
        blake3::Hash::from_bytes(hash_open_file_bytes(file, path, buffer)?)
            .to_hex()
            .to_string(),
    )
}

fn hash_open_file_bytes(
    file: &mut File,
    path: &Path,
    buffer: &mut [u8],
) -> Result<[u8; 32], LpmError> {
    let mut hasher = blake3::Hasher::new();
    loop {
        let read = file.read(buffer).map_err(|error| {
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
    Ok(*hasher.finalize().as_bytes())
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
    let (pairs, []) = encoded.as_chunks::<2>() else {
        return Err(LpmError::Store(
            "invalid v3 CAS UTF-16 path encoding".into(),
        ));
    };
    let wide = pairs
        .iter()
        .map(|pair| u16::from_le_bytes(*pair))
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
    let (pairs, []) = path.as_chunks::<2>() else {
        return Err(LpmError::Store(
            "invalid UTF-16 v3 CAS manifest path".into(),
        ));
    };
    let units = pairs
        .iter()
        .map(|pair| u16::from_le_bytes(*pair))
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
        {
            let mut permissions = fs::metadata(path).unwrap().permissions();
            permissions.set_readonly(mode & 0o222 == 0);
            fs::set_permissions(path, permissions).unwrap();
        }
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
        #[cfg(unix)]
        let distinct_mode = 0o755;
        #[cfg(not(unix))]
        let distinct_mode = 0o444;
        write_file(&second.join("cli.js"), b"same", distinct_mode);

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
        let original_mtime = fs::metadata(&manifest_path).unwrap().modified().unwrap();
        let mut bytes = fs::read(&manifest_path).unwrap();
        bytes[0] ^= 0x01;
        fs::write(&manifest_path, bytes).unwrap();
        fs::set_times(
            &manifest_path,
            fs::FileTimes::new().set_modified(original_mtime),
        )
        .unwrap();

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

    #[test]
    fn hardlinking_shared_blob_into_second_package_does_not_invalidate_first_package_validation() {
        let root = tempfile::tempdir().unwrap();
        let cas = FileCas::at(root.path());
        let first = root.path().join("objects/first");
        let second = root.path().join("objects/second");
        fs::create_dir_all(&first).unwrap();
        fs::create_dir_all(&second).unwrap();
        write_file(&first.join("index.js"), b"shared-blob-content", 0o644);
        write_file(&second.join("index.js"), b"shared-blob-content", 0o644);

        let first_record = cas
            .ingest_object_tree(&first, "sha512-first", false)
            .unwrap();
        cas.publish_source_record(&first, &first_record).unwrap();

        // Advance past a coarse kernel clock tick so hardlinking the shared
        // blob into `second` changes the blob's inode ctime/ChangeTime.
        std::thread::sleep(std::time::Duration::from_millis(25));

        let second_record = cas
            .ingest_object_tree(&second, "sha512-second", false)
            .unwrap();
        cas.publish_source_record(&second, &second_record).unwrap();

        let mut timings = FileCasReuseTimings::default();
        assert_eq!(
            cas.source_reuse_status_with_timings(&first, "sha512-first", &mut timings)
                .unwrap(),
            SourceReuseStatus::Reusable
        );
        assert_eq!(
            timings.blob_rehash_count, 0,
            "hardlinking a shared blob into a second package must not invalidate the first package's blob validation"
        );
    }

    #[test]
    fn cross_process_hardlink_rehashes_only_shared_blob_and_reuses_unchanged_siblings() {
        let root = tempfile::tempdir().unwrap();
        let writer_one = FileCas::at(root.path());
        let first = root.path().join("objects/first");
        let second = root.path().join("objects/second");
        let third = root.path().join("objects/third");
        fs::create_dir_all(&first).unwrap();
        fs::create_dir_all(&second).unwrap();
        fs::create_dir_all(&third).unwrap();
        write_file(&first.join("shared.js"), b"shared-license-text", 0o644);
        write_file(&first.join("unique-a.js"), b"unique-package-a", 0o644);
        write_file(&third.join("shared.js"), b"shared-license-text", 0o644);
        write_file(&third.join("unique-c.js"), b"unique-package-c", 0o644);

        let first_record = writer_one
            .ingest_object_tree(&first, "sha512-first", false)
            .unwrap();
        writer_one
            .publish_source_record(&first, &first_record)
            .unwrap();
        let third_record = writer_one
            .ingest_object_tree(&third, "sha512-third", false)
            .unwrap();
        writer_one
            .publish_source_record(&third, &third_record)
            .unwrap();

        std::thread::sleep(std::time::Duration::from_millis(25));

        let writer_two = FileCas::at(root.path());
        write_file(&second.join("shared.js"), b"shared-license-text", 0o644);
        let second_record = writer_two
            .ingest_object_tree(&second, "sha512-second", false)
            .unwrap();
        writer_two
            .publish_source_record(&second, &second_record)
            .unwrap();

        // A fresh process sees only the shared blob's ctime changed: it
        // rehashes that one blob for `first`, skips `unique-a.js`, and reuses
        // the session-verified blob with zero rehashes for `third`.
        let reader = FileCas::at(root.path());
        let mut first_timings = FileCasReuseTimings::default();
        assert_eq!(
            reader
                .source_reuse_status_with_timings(&first, "sha512-first", &mut first_timings)
                .unwrap(),
            SourceReuseStatus::Reusable
        );
        assert_eq!(first_timings.blob_rehash_count, 1);

        let mut third_timings = FileCasReuseTimings::default();
        assert_eq!(
            reader
                .source_reuse_status_with_timings(&third, "sha512-third", &mut third_timings)
                .unwrap(),
            SourceReuseStatus::Reusable
        );
        assert_eq!(third_timings.blob_rehash_count, 0);
    }

    #[test]
    fn settled_cached_blob_still_detects_and_repairs_tampering() {
        let root = tempfile::tempdir().unwrap();
        let cas = FileCas::at(root.path());
        let first = root.path().join("objects/first");
        let second = root.path().join("objects/second");
        let third = root.path().join("objects/third");
        fs::create_dir_all(&first).unwrap();
        fs::create_dir_all(&second).unwrap();
        fs::create_dir_all(&third).unwrap();
        write_file(&first.join("index.js"), b"clean-bytes", 0o644);
        write_file(&second.join("index.js"), b"clean-bytes", 0o644);
        write_file(&third.join("index.js"), b"clean-bytes", 0o644);

        let prepared = cas
            .ingest_object_tree(&first, "sha512-first", false)
            .unwrap();
        let manifest = cas
            .manifest_for_digest(&prepared.record.tree_digest)
            .unwrap();
        let key = manifest.entries[0].blob.as_ref().unwrap();
        let blob = cas.blob_path(key).unwrap();

        // Backdate the blob's mtime; `set_times` still refreshes ctime on Unix
        // so it must not be considered settled at `now`, only once both mtime
        // and ctime age past the settle margin.
        let old_time = SystemTime::now() - Duration::from_secs(60);
        fs::set_times(&blob, fs::FileTimes::new().set_modified(old_time)).unwrap();
        let settled_fp = cas.read_blob_stat(key).unwrap();
        #[cfg(unix)]
        assert!(!settled_fp.is_settled());
        assert!(settled_fp.is_settled_at(SystemTime::now() + Duration::from_secs(1)));
        cas.record_validated_blob(key, settled_fp);

        cas.ingest_object_tree(&second, "sha512-second", false)
            .unwrap();
        assert_eq!(fs::read(&blob).unwrap(), b"clean-bytes");

        // Tampering with the blob updates its timestamps, invalidating the
        // session cache so `third` quarantines and repairs it.
        fs::write(&blob, b"dirty-bytes").unwrap();
        cas.ingest_object_tree(&third, "sha512-third", false)
            .unwrap();
        assert_eq!(fs::read(&blob).unwrap(), b"clean-bytes");
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
    fn registry_ingest_rejects_distinct_paths_sharing_same_file_identity() {
        let root = tempfile::tempdir().unwrap();
        let cas = FileCas::at(root.path());
        let object_dir = root.path().join("objects/pkg-a");
        fs::create_dir_all(&object_dir).unwrap();
        let first_file = object_dir.join("first.js");
        let aliased_file = object_dir.join("second.js");
        write_file(&first_file, b"genuine-bytes", 0o644);
        fs::hard_link(&first_file, &aliased_file).unwrap();

        let digest = *blake3::hash(b"genuine-bytes").as_bytes();
        let mut ingest = cas
            .begin_registry_ingest(&object_dir, "sha512-alias")
            .unwrap();
        cas.ingest_registry_file(
            &mut ingest,
            &object_dir,
            Path::new("first.js"),
            Some(13),
            digest,
            None,
        )
        .unwrap();

        let key = BlobKey {
            digest: blake3::Hash::from_bytes(digest).to_hex().to_string(),
            mode: normalized_mode(&fs::symlink_metadata(&first_file).unwrap()),
            size: 13,
        };
        assert!(
            cas.cached_validated_blob(&key).is_none(),
            "unfinalized registry ingest must not mark first-publish blobs session-validated"
        );

        let err = cas
            .ingest_registry_file(
                &mut ingest,
                &object_dir,
                Path::new("second.js"),
                Some(13),
                digest,
                None,
            )
            .unwrap_err();
        assert!(
            err.to_string().contains("aliases") || err.to_string().contains("identity"),
            "unexpected error: {err}"
        );

        let prepared = cas.finish_registry_ingest(ingest).unwrap();
        cas.publish_source_record(&object_dir, &prepared).unwrap();
        assert!(
            cas.cached_validated_blob(&key).is_some(),
            "finalized registry ingest records deferred first-publish blobs"
        );
    }

    #[test]
    fn materialization_does_not_promote_tampered_blob_from_stale_session_cache() {
        let root = tempfile::tempdir().unwrap();
        let cas = FileCas::at(root.path());
        let first = root.path().join("objects/first");
        fs::create_dir_all(&first).unwrap();
        write_file(&first.join("index.js"), b"clean-bytes", 0o644);

        let prepared = cas
            .ingest_object_tree(&first, "sha512-first", false)
            .unwrap();
        cas.publish_source_record(&first, &prepared).unwrap();
        let manifest = cas
            .manifest_for_digest(&prepared.record.tree_digest)
            .unwrap();
        let key = manifest.entries[0].blob.as_ref().unwrap();
        let blob = cas.blob_path(key).unwrap();

        let orig_mtime = fs::metadata(&blob).unwrap().modified().unwrap();
        std::thread::sleep(Duration::from_millis(25));
        fs::write(&blob, b"dirty-bytes").unwrap();
        fs::set_times(&blob, fs::FileTimes::new().set_modified(orig_mtime)).unwrap();

        let materialize_err = cas.materialized_source(&first, "sha512-first");
        assert!(
            materialize_err.is_err(),
            "materialization must fail when a cached blob was tampered before hardlinking"
        );
        let status = cas.source_reuse_status(&first, "sha512-first").unwrap();
        assert_eq!(
            status,
            SourceReuseStatus::CorruptBlob,
            "materialization must never re-bless a tampered blob whose ctime changed"
        );
    }

    #[test]
    fn dedup_hardlink_window_tamper_with_restored_mtime_is_rejected_and_repaired() {
        let root = tempfile::tempdir().unwrap();
        let cas = FileCas::at(root.path());
        let first = root.path().join("objects/first");
        let second = root.path().join("objects/second");
        fs::create_dir_all(&first).unwrap();
        fs::create_dir_all(&second).unwrap();
        write_file(&first.join("index.js"), b"clean-bytes", 0o644);
        write_file(&second.join("index.js"), b"clean-bytes", 0o644);

        let first_prepared = cas
            .ingest_object_tree(&first, "sha512-first", false)
            .unwrap();
        cas.publish_source_record(&first, &first_prepared).unwrap();
        let manifest = cas
            .manifest_for_digest(&first_prepared.record.tree_digest)
            .unwrap();
        let key = manifest.entries[0].blob.as_ref().unwrap();
        let blob = cas.blob_path(key).unwrap();
        let orig_mtime = fs::metadata(&blob).unwrap().modified().unwrap();

        let fired = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let fired_clone = Arc::clone(&fired);
        let target_blob = blob.clone();
        let _guard = TestAfterPublishHardlinkGuard::install(move |path| {
            if path == target_blob && !fired_clone.swap(true, std::sync::atomic::Ordering::SeqCst) {
                std::thread::sleep(Duration::from_millis(25));
                fs::write(path, b"dirty-bytes").unwrap();
                fs::set_times(path, fs::FileTimes::new().set_modified(orig_mtime)).unwrap();
            }
        });

        let second_prepared = cas
            .ingest_object_tree(&second, "sha512-second", false)
            .unwrap();
        cas.publish_source_record(&second, &second_prepared)
            .unwrap();
        assert!(fired.load(std::sync::atomic::Ordering::SeqCst));
        assert_eq!(
            fs::read(&blob).unwrap(),
            b"clean-bytes",
            "blob tampered inside the hardlink window must be detected and repaired"
        );
        assert_eq!(
            fs::read(second.join("index.js")).unwrap(),
            b"clean-bytes",
            "second package must retain genuine bytes"
        );
    }

    #[test]
    fn validate_blob_rejects_same_length_write_landing_after_hash() {
        let root = tempfile::tempdir().unwrap();
        let cas = FileCas::at(root.path());
        let first = root.path().join("objects/first");
        fs::create_dir_all(&first).unwrap();
        write_file(&first.join("index.js"), b"clean-bytes", 0o644);

        let prepared = cas
            .ingest_object_tree(&first, "sha512-first", false)
            .unwrap();
        let manifest = cas
            .manifest_for_digest(&prepared.record.tree_digest)
            .unwrap();
        let key = manifest.entries[0].blob.as_ref().unwrap();
        let blob = cas.blob_path(key).unwrap();

        let target_blob = blob.clone();
        let _guard = TestAfterValidateHashGuard::install(move |path| {
            if path == target_blob {
                std::thread::sleep(Duration::from_millis(25));
                fs::write(path, b"tamper-data").unwrap();
            }
        });

        let mut buf = vec![0_u8; 64 * 1024];
        let result = cas.validate_blob(&blob, key, &mut buf);
        assert!(
            result.is_err(),
            "validate_blob must reject a file modified after its content hash completed"
        );
    }

    #[cfg(unix)]
    #[test]
    fn blob_fingerprint_with_old_mtime_and_recent_ctime_is_not_settled() {
        let root = tempfile::tempdir().unwrap();
        let cas = FileCas::at(root.path());
        let first = root.path().join("objects/first");
        fs::create_dir_all(&first).unwrap();
        write_file(&first.join("index.js"), b"clean-bytes", 0o644);

        let prepared = cas
            .ingest_object_tree(&first, "sha512-first", false)
            .unwrap();
        let manifest = cas
            .manifest_for_digest(&prepared.record.tree_digest)
            .unwrap();
        let key = manifest.entries[0].blob.as_ref().unwrap();
        let blob = cas.blob_path(key).unwrap();

        let old_time = SystemTime::now() - Duration::from_secs(60);
        fs::set_times(&blob, fs::FileTimes::new().set_modified(old_time)).unwrap();
        let fp = cas.read_blob_stat(key).unwrap();
        assert!(
            !fp.is_settled(),
            "old mtime with a freshly updated ctime must not be treated as settled"
        );
        assert!(
            fp.is_settled_at(SystemTime::now() + Duration::from_secs(1)),
            "fingerprint settles once both mtime and ctime age past the settle margin"
        );
    }

    #[test]
    fn source_validation_handles_70000_unique_blobs_without_failing_publication() {
        let root = tempfile::tempdir().unwrap();
        let cas = FileCas::at(root.path());
        let first = root.path().join("objects/first");
        fs::create_dir_all(&first).unwrap();
        write_file(&first.join("index.js"), b"seed", 0o644);
        let seed_prepared = cas
            .ingest_object_tree(&first, "sha512-seed", false)
            .unwrap();
        let seed_manifest = cas
            .manifest_for_digest(&seed_prepared.record.tree_digest)
            .unwrap();
        let sample_fp = cas
            .read_blob_stat(seed_manifest.entries[0].blob.as_ref().unwrap())
            .unwrap();

        let count = 70_000usize;
        let keys: Vec<BlobKey> = (0..count)
            .map(|i| BlobKey {
                digest: blake3::hash(&i.to_le_bytes()).to_hex().to_string(),
                mode: 0o644,
                size: 4,
            })
            .collect();
        let key_refs: Vec<&BlobKey> = keys.iter().collect();
        let stats = vec![sample_fp; count];
        let digests = encode_per_blob_stat_digests(&key_refs, &stats);
        let validation = SourceValidationRecord {
            schema: CAS_SCHEMA_VERSION,
            source_sri: "sha512-large-package".to_string(),
            tree_digest: "a".repeat(64),
            blob_stat_fingerprint: "b".repeat(64),
        };
        cas.write_source_validation(&validation, &digests).expect(
            "packages with 70,000 unique blobs must publish source validation without hitting cap",
        );
        let open = cas.open_source_validation("sha512-large-package").unwrap();
        assert_eq!(open.record.blob_stat_fingerprint, "b".repeat(64));
        let loaded_digests = open
            .read_per_blob_digests(count)
            .expect("lazy trailer should round-trip all 70,000 per-blob digests");
        assert_eq!(loaded_digests, digests);
    }

    #[test]
    fn source_validation_omits_optional_trailer_above_cap_without_failing() {
        let root = tempfile::tempdir().unwrap();
        let cas = FileCas::at(root.path());
        let validation = SourceValidationRecord {
            schema: CAS_SCHEMA_VERSION,
            source_sri: "sha512-huge-package".to_string(),
            tree_digest: "c".repeat(64),
            blob_stat_fingerprint: "d".repeat(64),
        };
        let oversized = vec![0xAB_u8; (SOURCE_VALIDATION_MAX_TRAILER_BLOBS + 1) * 16];
        cas.write_source_validation(&validation, &oversized)
            .expect("oversized per-blob digest trailer must be omitted rather than failing");
        let open = cas.open_source_validation("sha512-huge-package").unwrap();
        assert_eq!(open.record.blob_stat_fingerprint, "d".repeat(64));
        assert!(
            open.read_per_blob_digests(SOURCE_VALIDATION_MAX_TRAILER_BLOBS + 1)
                .is_none()
        );
    }

    #[cfg(unix)]
    #[test]
    fn publish_blob_reuses_settled_session_validated_blob_without_rehashing() {
        let root = tempfile::tempdir().unwrap();
        let cas = FileCas::at(root.path());
        let first = root.path().join("objects/first");
        let second = root.path().join("objects/second");
        fs::create_dir_all(&first).unwrap();
        fs::create_dir_all(&second).unwrap();
        write_file(&first.join("shared.js"), b"shared-payload-bytes", 0o644);
        write_file(&second.join("shared.js"), b"shared-payload-bytes", 0o644);

        cas.ingest_object_tree(&first, "sha512-first", false)
            .unwrap();
        std::thread::sleep(SETTLED_BLOB_MTIME_MARGIN + Duration::from_millis(20));

        let hash_calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = std::sync::Arc::clone(&hash_calls);
        let _guard = TestAfterValidateHashGuard::install(move |_| {
            counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        });
        cas.ingest_object_tree(&second, "sha512-second", false)
            .unwrap();
        assert_eq!(
            hash_calls.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "deduplicating against a settled session-validated blob must not re-hash it"
        );
    }

    #[cfg(unix)]
    #[test]
    fn materialize_manifest_reuses_settled_session_validated_blob_without_rehashing() {
        let root = tempfile::tempdir().unwrap();
        let cas = FileCas::at(root.path());
        let first = root.path().join("objects/mat-first");
        fs::create_dir_all(&first).unwrap();
        write_file(&first.join("index.js"), b"materialized-bytes", 0o644);
        let prepared = cas
            .ingest_object_tree(&first, "sha512-mat-first", false)
            .unwrap();
        let manifest = cas
            .manifest_for_digest(&prepared.record.tree_digest)
            .unwrap();
        std::thread::sleep(SETTLED_BLOB_MTIME_MARGIN + Duration::from_millis(20));

        let hash_calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = std::sync::Arc::clone(&hash_calls);
        let _guard = TestAfterValidateHashGuard::install(move |_| {
            counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        });
        let materialized = cas
            .ensure_materialized_entry(&prepared.record.tree_digest, &manifest)
            .unwrap();
        assert_eq!(
            fs::read(materialized.join("index.js")).unwrap(),
            b"materialized-bytes"
        );
        assert_eq!(
            hash_calls.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "materializing a settled session-validated blob must not re-hash it"
        );
    }

    #[cfg(unix)]
    #[test]
    fn publish_blob_cannot_commit_corrupt_staged_inode_when_blob_path_is_replaced_mid_stage() {
        let root = tempfile::tempdir().unwrap();
        let cas = FileCas::at(root.path());
        let clean_bytes = b"clean-content-for-race";
        let corrupt_bytes = b"CORRUPT-INODE-PAYLOAD!";
        assert_eq!(clean_bytes.len(), corrupt_bytes.len());

        let first = root.path().join("objects/seed");
        let second = root.path().join("objects/victim");
        fs::create_dir_all(&first).unwrap();
        fs::create_dir_all(&second).unwrap();
        write_file(&first.join("index.js"), clean_bytes, 0o644);
        let prepared = cas
            .ingest_object_tree(&first, "sha512-seed-race", false)
            .unwrap();
        let manifest = cas
            .manifest_for_digest(&prepared.record.tree_digest)
            .unwrap();
        let key = manifest.entries[0].blob.as_ref().unwrap().clone();
        let blob_path = cas.blob_path(&key).unwrap();

        // Replace blob at path with a corrupt inode X of identical length and mode.
        let corrupt_staging = root.path().join("corrupt.tmp");
        write_file(&corrupt_staging, corrupt_bytes, 0o644);
        fs::rename(&corrupt_staging, &blob_path).unwrap();
        cas.evict_validated_blob(&key);

        // Prepare clean replacement inode Y that Worker B publishes between A's stage and validate.
        let clean_replacement = root.path().join("clean-replacement.tmp");
        write_file(&clean_replacement, clean_bytes, 0o644);
        let fired = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let fired_clone = std::sync::Arc::clone(&fired);
        let _guard = TestAfterPublishHardlinkGuard::install(move |blob| {
            if !fired_clone.swap(true, std::sync::atomic::Ordering::SeqCst) {
                let _ = fs::rename(&clean_replacement, blob);
            }
        });

        let victim_file = second.join("index.js");
        write_file(&victim_file, clean_bytes, 0o644);
        cas.ingest_object_tree(&second, "sha512-victim-race", false)
            .unwrap();

        assert_eq!(
            fs::read(&victim_file).unwrap(),
            clean_bytes,
            "staged source file must never remain hardlinked to corrupt inode X after blob path is replaced with clean inode Y"
        );
    }

    #[cfg(unix)]
    #[test]
    fn validate_blob_does_not_quarantine_valid_blob_on_concurrent_nlink_decrease_or_double_increase()
     {
        let root = tempfile::tempdir().unwrap();
        let cas = FileCas::at(root.path());
        let first = root.path().join("objects/nlink-seed");
        let second = root.path().join("objects/nlink-second");
        fs::create_dir_all(&first).unwrap();
        fs::create_dir_all(&second).unwrap();
        write_file(&first.join("index.js"), b"valid-nlink-bytes", 0o644);
        let prepared = cas
            .ingest_object_tree(&first, "sha512-nlink-seed", false)
            .unwrap();
        let manifest = cas
            .manifest_for_digest(&prepared.record.tree_digest)
            .unwrap();
        let key = manifest.entries[0].blob.as_ref().unwrap().clone();
        let blob_path = cas.blob_path(&key).unwrap();
        let orig_id =
            file_identity_for_path(&blob_path, &fs::symlink_metadata(&blob_path).unwrap())
                .unwrap()
                .unwrap();
        let quarantine_blobs = root.path().join("quarantine/blobs");

        // Case 1: concurrent hardlink unlink (nlink decreases) during validation.
        let extra_link = root.path().join("extra-link");
        fs::hard_link(&blob_path, &extra_link).unwrap();
        cas.evict_validated_blob(&key);
        let unlinked = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let unlinked_clone = std::sync::Arc::clone(&unlinked);
        let extra_for_hook = extra_link;
        {
            let _guard = TestAfterValidateHashGuard::install(move |_| {
                if !unlinked_clone.swap(true, std::sync::atomic::Ordering::SeqCst) {
                    let _ = fs::remove_file(&extra_for_hook);
                }
            });
            write_file(&second.join("index.js"), b"valid-nlink-bytes", 0o644);
            cas.ingest_object_tree(&second, "sha512-nlink-second", false)
                .unwrap();
        }
        assert_eq!(
            file_identity_for_path(&blob_path, &fs::symlink_metadata(&blob_path).unwrap())
                .unwrap()
                .unwrap(),
            orig_id,
            "valid blob must keep its original inode when a sibling hardlink is unlinked during validation"
        );
        assert!(
            !quarantine_blobs.exists(),
            "concurrent hardlink unlink must never quarantine a valid blob"
        );

        // Case 2: two consecutive nlink increases during validation.
        let third = root.path().join("objects/nlink-third");
        fs::create_dir_all(&third).unwrap();
        cas.evict_validated_blob(&key);
        let adds = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let adds_clone = std::sync::Arc::clone(&adds);
        let link_root = root.path().to_path_buf();
        {
            let _guard = TestAfterValidateHashGuard::install(move |path| {
                let n = adds_clone.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                if n < 2 {
                    let _ = fs::hard_link(path, link_root.join(format!("burst-link-{n}")));
                }
            });
            write_file(&third.join("index.js"), b"valid-nlink-bytes", 0o644);
            cas.ingest_object_tree(&third, "sha512-nlink-third", false)
                .unwrap();
        }
        assert_eq!(
            file_identity_for_path(&blob_path, &fs::symlink_metadata(&blob_path).unwrap())
                .unwrap()
                .unwrap(),
            orig_id,
            "valid blob must keep its original inode on two concurrent hardlink additions during validation"
        );
        assert!(
            !quarantine_blobs.exists(),
            "two concurrent hardlink additions must never quarantine a valid blob"
        );

        // Case 3: sustained contention across every attempt must fail without quarantining.
        let fourth = root.path().join("objects/nlink-fourth");
        fs::create_dir_all(&fourth).unwrap();
        cas.evict_validated_blob(&key);
        let sustained = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let sustained_clone = std::sync::Arc::clone(&sustained);
        let link_root = root.path().to_path_buf();
        {
            let _guard = TestAfterValidateHashGuard::install(move |path| {
                let n = sustained_clone.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let _ = fs::hard_link(path, link_root.join(format!("sustained-link-{n}")));
            });
            write_file(&fourth.join("index.js"), b"valid-nlink-bytes", 0o644);
            assert!(
                cas.ingest_object_tree(&fourth, "sha512-nlink-fourth", false)
                    .is_err(),
                "sustained link-count contention across all validation retries must return an error"
            );
        }
        assert_eq!(
            file_identity_for_path(&blob_path, &fs::symlink_metadata(&blob_path).unwrap())
                .unwrap()
                .unwrap(),
            orig_id,
            "sustained link-count contention must preserve the original healthy blob inode"
        );
        assert!(
            !quarantine_blobs.exists(),
            "sustained link-count contention must never quarantine a healthy blob"
        );
    }

    #[cfg(unix)]
    #[test]
    fn ingest_registry_file_rejects_same_length_substitution_before_publication() {
        let root = tempfile::tempdir().unwrap();
        let cas = FileCas::at(root.path());
        let obj_dir = root.path().join("objects/subst");
        fs::create_dir_all(&obj_dir).unwrap();
        let clean = b"clean-bytes-1234";
        let swapped = b"EVIL!-bytes-1234";
        assert_eq!(clean.len(), swapped.len());

        let clean_digest = *blake3::hash(clean).as_bytes();
        let target = obj_dir.join("index.js");
        write_file(&target, clean, 0o644);
        let original_stamp =
            unix_extracted_stamp_from_metadata(&fs::symlink_metadata(&target).unwrap()).unwrap();

        // Replace the file atomically with same-length malicious bytes (new inode).
        let replacement = obj_dir.join("evil.tmp");
        write_file(&replacement, swapped, 0o644);
        fs::rename(&replacement, &target).unwrap();

        let mut ingest = cas
            .begin_registry_ingest(&obj_dir, "sha512-subst-none")
            .unwrap();
        let without_stamp = cas.ingest_registry_file(
            &mut ingest,
            &obj_dir,
            Path::new("index.js"),
            Some(clean.len() as u64),
            clean_digest,
            None,
        );
        assert!(
            without_stamp.is_err(),
            "ingest_registry_file without extractor stamp must reject substituted same-length bytes"
        );

        let mut ingest_stale = cas
            .begin_registry_ingest(&obj_dir, "sha512-subst-stale")
            .unwrap();
        let with_stale_stamp = cas.ingest_registry_file(
            &mut ingest_stale,
            &obj_dir,
            Path::new("index.js"),
            Some(clean.len() as u64),
            clean_digest,
            Some(original_stamp),
        );
        assert!(
            with_stale_stamp.is_err(),
            "ingest_registry_file with stale extractor stamp must reject substituted same-length bytes"
        );

        // Positive control: genuine file matching its captured stamp publishes cleanly.
        let clean_dir = root.path().join("objects/clean-ok");
        fs::create_dir_all(&clean_dir).unwrap();
        let clean_target = clean_dir.join("index.js");
        write_file(&clean_target, clean, 0o644);
        let clean_stamp =
            unix_extracted_stamp_from_metadata(&fs::symlink_metadata(&clean_target).unwrap())
                .unwrap();
        let mut ingest_ok = cas
            .begin_registry_ingest(&clean_dir, "sha512-clean-ok")
            .unwrap();
        cas.ingest_registry_file(
            &mut ingest_ok,
            &clean_dir,
            Path::new("index.js"),
            Some(clean.len() as u64),
            clean_digest,
            Some(clean_stamp),
        )
        .unwrap();
        let prepared = cas.finish_registry_ingest(ingest_ok).unwrap();
        cas.publish_source_record(&clean_dir, &prepared).unwrap();
        assert_eq!(
            cas.source_reuse_status(&clean_dir, "sha512-clean-ok")
                .unwrap(),
            SourceReuseStatus::Reusable
        );
    }

    #[test]
    fn hardlink_replace_guard_retains_recovery_state_on_commit_and_rollback_errors() {
        let root = tempfile::tempdir().unwrap();
        let blob = root.path().join("blob");
        let dest = root.path().join("dest");
        fs::write(&blob, b"shared-blob").unwrap();
        fs::write(&dest, b"original-dest").unwrap();

        // Fault during commit must keep recovery active so drop restores the original file.
        let guard = HardlinkReplaceGuard::stage(&blob, &dest).unwrap();
        let backup_path = guard.backup.clone();
        let commit_err = guard.commit_with(|_| {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "transient unlink failure",
            ))
        });
        assert!(commit_err.is_err());
        assert_eq!(
            fs::read(&dest).unwrap(),
            b"original-dest",
            "failed commit must restore original destination via drop recovery"
        );
        assert!(
            !backup_path.exists(),
            "backup must not be leaked after failed commit drop recovery"
        );

        // Transient rename failure during rollback must keep recovery active so drop restores it.
        let guard = HardlinkReplaceGuard::stage(&blob, &dest).unwrap();
        let backup_path = guard.backup.clone();
        let rollback_err = guard.rollback_with(
            |destination| fs::remove_file(destination),
            |_, _| {
                Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "transient rename failure",
                ))
            },
        );
        assert!(rollback_err.is_err());
        assert_eq!(
            fs::read(&dest).unwrap(),
            b"original-dest",
            "failed rollback must still recover original destination on drop"
        );
        assert!(
            !backup_path.exists(),
            "backup must be restored cleanly on drop after transient rollback rename failure"
        );

        // Non-NotFound remove_file failure during rollback must be surfaced as an error.
        let guard = HardlinkReplaceGuard::stage(&blob, &dest).unwrap();
        let remove_err = guard.rollback_with(
            |_| {
                Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "cannot remove staged link",
                ))
            },
            |backup, destination| fs::rename(backup, destination),
        );
        assert!(remove_err.is_err());
        assert_eq!(fs::read(&dest).unwrap(), b"original-dest");
    }

    #[test]
    fn file_identity_distinguishes_128_bit_ids_with_identical_lower_64_bits() {
        let low = 0x0000_0000_DEAD_BEEF_u128;
        let first = FileIdentity {
            volume: 42,
            file_id: (1_u128 << 64) | low,
        };
        let second = FileIdentity {
            volume: 42,
            file_id: (2_u128 << 64) | low,
        };
        assert_ne!(
            first, second,
            "128-bit file IDs sharing the lower 64 bits must not collide as aliases"
        );
        let mut seen = HashMap::new();
        seen.insert(first, b"a.js".to_vec());
        assert!(!seen.contains_key(&second));
    }
}

#[cfg(test)]
type PathHookFn = Box<dyn Fn(&Path)>;

#[cfg(test)]
thread_local! {
    static TEST_AFTER_PUBLISH_HARDLINK_HOOK: std::cell::RefCell<Option<PathHookFn>> =
        std::cell::RefCell::new(None);
    static TEST_AFTER_VALIDATE_HASH_HOOK: std::cell::RefCell<Option<PathHookFn>> =
        std::cell::RefCell::new(None);
}

#[cfg(test)]
fn run_test_after_publish_hardlink_hook(path: &Path) {
    TEST_AFTER_PUBLISH_HARDLINK_HOOK.with(|cell| {
        if let Some(hook) = cell.borrow().as_ref() {
            hook(path);
        }
    });
}

#[cfg(test)]
fn run_test_after_validate_hash_hook(path: &Path) {
    TEST_AFTER_VALIDATE_HASH_HOOK.with(|cell| {
        if let Some(hook) = cell.borrow().as_ref() {
            hook(path);
        }
    });
}

#[cfg(test)]
struct TestAfterPublishHardlinkGuard;

#[cfg(test)]
impl TestAfterPublishHardlinkGuard {
    fn install(hook: impl Fn(&Path) + 'static) -> Self {
        TEST_AFTER_PUBLISH_HARDLINK_HOOK.with(|cell| {
            *cell.borrow_mut() = Some(Box::new(hook));
        });
        Self
    }
}

#[cfg(test)]
impl Drop for TestAfterPublishHardlinkGuard {
    fn drop(&mut self) {
        TEST_AFTER_PUBLISH_HARDLINK_HOOK.with(|cell| {
            *cell.borrow_mut() = None;
        });
    }
}

#[cfg(test)]
struct TestAfterValidateHashGuard;

#[cfg(test)]
impl TestAfterValidateHashGuard {
    fn install(hook: impl Fn(&Path) + 'static) -> Self {
        TEST_AFTER_VALIDATE_HASH_HOOK.with(|cell| {
            *cell.borrow_mut() = Some(Box::new(hook));
        });
        Self
    }
}

#[cfg(test)]
impl Drop for TestAfterValidateHashGuard {
    fn drop(&mut self) {
        TEST_AFTER_VALIDATE_HASH_HOOK.with(|cell| {
            *cell.borrow_mut() = None;
        });
    }
}
