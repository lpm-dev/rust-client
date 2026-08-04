use std::path::{Path, PathBuf};

use lpm_common::{LpmError, write_file_atomic};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::fs_util::tmp_sibling;
use super::tree_hash::{
    TreeIntegrities, compute_object_tree_integrities, compute_tree_metadata_integrity,
};

/// Store-owned metadata namespace for object attributes that must not
/// collide with package contents.
const OBJECT_METADATA_DIR: &str = ".lpm-object-meta";
const LOCAL_SOURCE_OBJECT_SENTINEL: &str = "local-source";

/// Object identity sidecar. `.integrity` records the source tarball SRI;
/// this file records the policy-specific digest used for object and link
/// reuse.
pub(crate) const OBJECT_INTEGRITY_FILENAME: &str = ".lpm-object-integrity";
pub(crate) const TREE_SNAPSHOT_FILENAME: &str = ".lpm-tree-snapshot.json";
const TREE_SNAPSHOT_SCHEMA_VERSION: u32 = 1;
const TREE_SNAPSHOT_MAX_BYTES: u64 = 4096;
pub const ENV_V2_OBJECT_INTEGRITY: &str = "LPM_V2_OBJECT_INTEGRITY";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectIntegrityPolicy {
    Tree,
    Source,
}

impl ObjectIntegrityPolicy {
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim() {
            value if value.eq_ignore_ascii_case("source") => Some(Self::Source),
            value if value.eq_ignore_ascii_case("tree") => Some(Self::Tree),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tree => "tree",
            Self::Source => "source",
        }
    }

    pub fn from_env_value(value: Option<&str>) -> Self {
        match value.map(str::trim) {
            Some(value) if value.eq_ignore_ascii_case("tree") => Self::Tree,
            Some(value)
                if value.eq_ignore_ascii_case("source")
                    || value.eq_ignore_ascii_case("sri")
                    || value.eq_ignore_ascii_case("tarball") =>
            {
                Self::Source
            }
            None | Some("") => Self::Source,
            _ => Self::Tree,
        }
    }
}

pub(crate) fn object_integrity_policy_from_env() -> ObjectIntegrityPolicy {
    ObjectIntegrityPolicy::from_env_value(std::env::var(ENV_V2_OBJECT_INTEGRITY).ok().as_deref())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct TreeSnapshot {
    pub(crate) schema: u32,
    pub(crate) content_integrity: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) layout_content_integrity: Option<String>,
    pub(crate) metadata_integrity: String,
}

/// Object digest validated according to the active integrity policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedObjectIntegrity(String);

impl VerifiedObjectIntegrity {
    #[inline]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    #[inline]
    pub(crate) fn new(digest: String) -> Self {
        Self(digest)
    }
}

/// Object digest produced by the extraction path for immediate link populate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FreshObjectIntegrity(VerifiedObjectIntegrity);

impl FreshObjectIntegrity {
    #[inline]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    #[inline]
    pub(crate) fn new(digest: VerifiedObjectIntegrity) -> Self {
        Self(digest)
    }

    #[inline]
    pub(crate) fn as_verified(&self) -> &VerifiedObjectIntegrity {
        &self.0
    }
}

/// Timing and path counters for one reusable-object validation check.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ReusableObjectCheckTimings {
    /// End-to-end time spent checking this object candidate.
    pub total_ms: u128,
    /// Whether the object directory was absent before validation.
    pub missing_count: u64,
    /// Time spent checking the object directory completeness predicate.
    pub complete_check_ms: u128,
    /// Number of object integrity sidecar reads.
    pub object_sidecar_read_count: u64,
    /// Time spent reading and validating the object integrity sidecar.
    pub object_sidecar_read_ms: u128,
    /// Number of metadata snapshot reads attempted.
    pub snapshot_read_count: u64,
    /// Time spent reading and parsing metadata snapshots.
    pub snapshot_read_ms: u128,
    /// Number of candidates accepted by the metadata-snapshot fast path.
    pub snapshot_hit_count: u64,
    /// Number of candidates that missed the metadata-snapshot fast path.
    pub snapshot_miss_count: u64,
    /// Number of metadata-only tree hash computations.
    pub metadata_hash_count: u64,
    /// Time spent hashing tree metadata.
    pub metadata_hash_ms: u128,
    /// Number of full content-tree hash fallbacks.
    pub full_hash_count: u64,
    /// Time spent hashing full object contents.
    pub full_hash_ms: u128,
    /// Number of object directories removed as unusable.
    pub removed_count: u64,
    /// Time spent removing unusable object directories.
    pub remove_ms: u128,
    /// Number of v3 source-record reads attempted.
    pub cas_source_record_read_count: u64,
    /// Time spent reading and parsing v3 source records.
    pub cas_source_record_read_ms: u128,
    /// Number of v3 tree-manifest reads performed.
    pub cas_manifest_read_count: u64,
    /// Time spent reading v3 tree-manifest bytes.
    pub cas_manifest_read_ms: u128,
    /// Time spent hashing, parsing, and validating v3 tree manifests.
    pub cas_manifest_validate_ms: u128,
    /// Number of v3 blob metadata reads performed.
    pub cas_blob_stat_count: u64,
    /// Number of shared v3 blob stats reused inside one validation batch.
    pub cas_blob_stat_cache_hit_count: u64,
    /// Time spent reading and checking v3 blob metadata.
    pub cas_blob_stat_ms: u128,
    /// Number of v3 source-validation record reads attempted.
    pub cas_source_validation_read_count: u64,
    /// Time spent reading and parsing v3 source-validation records.
    pub cas_source_validation_read_ms: u128,
    /// Number of v3 blob content rehashes after metadata changes.
    pub cas_blob_rehash_count: u64,
    /// Time spent rehashing v3 blobs after metadata changes.
    pub cas_blob_rehash_ms: u128,
}

impl ReusableObjectCheckTimings {
    pub(crate) fn record_file_cas(&mut self, timings: crate::v3::FileCasReuseTimings) {
        self.cas_source_record_read_count = self
            .cas_source_record_read_count
            .saturating_add(timings.source_record_read_count);
        self.cas_source_record_read_ms = self
            .cas_source_record_read_ms
            .saturating_add(timings.source_record_read_ms);
        self.cas_manifest_read_count = self
            .cas_manifest_read_count
            .saturating_add(timings.manifest_read_count);
        self.cas_manifest_read_ms = self
            .cas_manifest_read_ms
            .saturating_add(timings.manifest_read_ms);
        self.cas_manifest_validate_ms = self
            .cas_manifest_validate_ms
            .saturating_add(timings.manifest_validate_ms);
        self.cas_blob_stat_count = self
            .cas_blob_stat_count
            .saturating_add(timings.blob_stat_count);
        self.cas_blob_stat_cache_hit_count = self
            .cas_blob_stat_cache_hit_count
            .saturating_add(timings.blob_stat_cache_hit_count);
        self.cas_blob_stat_ms = self.cas_blob_stat_ms.saturating_add(timings.blob_stat_ms);
        self.cas_source_validation_read_count = self
            .cas_source_validation_read_count
            .saturating_add(timings.source_validation_read_count);
        self.cas_source_validation_read_ms = self
            .cas_source_validation_read_ms
            .saturating_add(timings.source_validation_read_ms);
        self.cas_blob_rehash_count = self
            .cas_blob_rehash_count
            .saturating_add(timings.blob_rehash_count);
        self.cas_blob_rehash_ms = self
            .cas_blob_rehash_ms
            .saturating_add(timings.blob_rehash_ms);
    }
}

pub(crate) fn try_migrate_legacy_tree_object_integrity_to_source(
    dir: &Path,
    source_sri: &str,
) -> Result<Option<VerifiedObjectIntegrity>, LpmError> {
    let legacy_integrity = read_object_integrity(dir)?;
    let actual = compute_object_tree_integrities(dir)?;
    migrate_legacy_tree_object_integrity_to_source(dir, source_sri, &legacy_integrity, &actual)
}

pub(crate) fn try_migrate_legacy_tree_object_integrity_to_source_with_timings(
    dir: &Path,
    source_sri: &str,
    timings: &mut ReusableObjectCheckTimings,
) -> Result<Option<VerifiedObjectIntegrity>, LpmError> {
    timings.object_sidecar_read_count = timings.object_sidecar_read_count.saturating_add(1);
    let sidecar_start = std::time::Instant::now();
    let legacy_integrity = read_object_integrity(dir)?;
    timings.object_sidecar_read_ms = timings
        .object_sidecar_read_ms
        .saturating_add(sidecar_start.elapsed().as_millis());

    timings.full_hash_count = timings.full_hash_count.saturating_add(1);
    let full_hash_start = std::time::Instant::now();
    let actual = compute_object_tree_integrities(dir)?;
    timings.full_hash_ms = timings
        .full_hash_ms
        .saturating_add(full_hash_start.elapsed().as_millis());

    migrate_legacy_tree_object_integrity_to_source(dir, source_sri, &legacy_integrity, &actual)
}

pub(crate) fn verified_source_object_integrity_or_migrate(
    dir: &Path,
    source_sri: &str,
) -> Result<VerifiedObjectIntegrity, LpmError> {
    match verified_source_object_integrity(dir, source_sri).map(VerifiedObjectIntegrity::new) {
        Ok(digest) => Ok(digest),
        Err(source_err) => {
            match try_migrate_legacy_tree_object_integrity_to_source(dir, source_sri) {
                Ok(Some(digest)) => Ok(digest),
                Ok(None) => Err(source_err),
                Err(migration_err) => Err(migration_err),
            }
        }
    }
}

pub(crate) fn migrate_legacy_tree_object_integrity_to_source(
    dir: &Path,
    source_sri: &str,
    legacy_integrity: &str,
    actual: &TreeIntegrities,
) -> Result<Option<VerifiedObjectIntegrity>, LpmError> {
    if legacy_integrity != actual.content {
        return Ok(None);
    }
    let migrated = write_source_object_integrity_with_tree(dir, source_sri, actual)?;
    Ok(Some(VerifiedObjectIntegrity::new(migrated.content)))
}

pub(crate) fn verified_tree_object_integrity_or_migrate(
    dir: &Path,
    source_sri: &str,
) -> Result<VerifiedObjectIntegrity, LpmError> {
    let expected = read_object_integrity(dir)?;
    if tree_snapshot_matches(dir, dir, &expected)? {
        return Ok(VerifiedObjectIntegrity::new(expected));
    }
    if let Some(digest) = try_migrate_source_object_integrity_to_tree(dir, source_sri, &expected)? {
        return Ok(digest);
    }
    let actual = compute_object_tree_integrities(dir)?;
    if expected == actual.content {
        write_tree_snapshot_best_effort(dir, &actual);
        return Ok(VerifiedObjectIntegrity::new(expected));
    }
    Err(LpmError::Store(format!(
        "virtual-store object integrity mismatch at {}: expected {expected}, actual {}",
        dir.display(),
        actual.content
    )))
}

/// Object dir is complete iff the package root and both object identity
/// sidecars are present. This is a cheap crash-recovery predicate;
/// callers that will reuse the object must also validate the active
/// integrity policy.
pub(crate) fn is_complete_object_dir(dir: &Path) -> bool {
    dir.is_dir()
        && is_regular_file_no_symlink(&dir.join("package.json"))
        && is_regular_file_no_symlink(&dir.join(".integrity"))
        && is_regular_file_no_symlink(&dir.join(OBJECT_INTEGRITY_FILENAME))
}

pub(crate) fn is_regular_file_no_symlink(path: &Path) -> bool {
    std::fs::symlink_metadata(path)
        .map(|metadata| metadata.file_type().is_file())
        .unwrap_or(false)
}

pub(crate) fn object_metadata_dir(dir: &Path) -> Result<PathBuf, LpmError> {
    let parent = dir.parent().ok_or_else(|| {
        LpmError::Store(format!(
            "virtual-store object dir has no parent for metadata path: {}",
            dir.display()
        ))
    })?;
    let name = dir.file_name().ok_or_else(|| {
        LpmError::Store(format!(
            "virtual-store object dir has no filename for metadata path: {}",
            dir.display()
        ))
    })?;
    Ok(parent.join(OBJECT_METADATA_DIR).join(name))
}

pub(crate) fn local_source_sentinel_path(dir: &Path) -> Result<PathBuf, LpmError> {
    Ok(object_metadata_dir(dir)?.join(LOCAL_SOURCE_OBJECT_SENTINEL))
}

pub(crate) fn has_local_source_sentinel(dir: &Path) -> bool {
    match local_source_sentinel_path(dir) {
        Ok(path) => is_regular_file_no_symlink(&path),
        Err(_) => false,
    }
}

pub(crate) fn remove_object_metadata_dir_best_effort(object_dir: &Path) {
    if let Ok(metadata_dir) = object_metadata_dir(object_dir) {
        let _ = std::fs::remove_dir_all(metadata_dir);
    }
}

pub(crate) fn source_policy_uses_source_integrity(
    dir: &Path,
    policy: ObjectIntegrityPolicy,
) -> bool {
    matches!(policy, ObjectIntegrityPolicy::Source) && !has_local_source_sentinel(dir)
}

pub(crate) fn object_dir_is_reusable_or_remove(
    dir: &Path,
    context: &str,
    source_sri: &str,
    policy: ObjectIntegrityPolicy,
) -> Result<bool, LpmError> {
    Ok(object_integrity_or_remove(dir, context, source_sri, policy)?.is_some())
}

pub(crate) fn object_integrity_or_remove_with_timings(
    dir: &Path,
    context: &str,
    source_sri: &str,
    timings: &mut ReusableObjectCheckTimings,
    policy: ObjectIntegrityPolicy,
) -> Result<Option<VerifiedObjectIntegrity>, LpmError> {
    let complete_check_start = std::time::Instant::now();
    let complete = is_complete_object_dir(dir);
    timings.complete_check_ms = timings
        .complete_check_ms
        .saturating_add(complete_check_start.elapsed().as_millis());
    if !complete {
        let remove_start = std::time::Instant::now();
        remove_unusable_object_dir(dir, context)?;
        timings.removed_count = timings.removed_count.saturating_add(1);
        timings.remove_ms = timings
            .remove_ms
            .saturating_add(remove_start.elapsed().as_millis());
        return Ok(None);
    }
    if source_policy_uses_source_integrity(dir, policy) {
        timings.object_sidecar_read_count = timings.object_sidecar_read_count.saturating_add(1);
        let sidecar_start = std::time::Instant::now();
        let result =
            verified_source_object_integrity(dir, source_sri).map(VerifiedObjectIntegrity::new);
        timings.object_sidecar_read_ms = timings
            .object_sidecar_read_ms
            .saturating_add(sidecar_start.elapsed().as_millis());
        return match result {
            Ok(digest) => Ok(Some(digest)),
            Err(err) => {
                match try_migrate_legacy_tree_object_integrity_to_source_with_timings(
                    dir, source_sri, timings,
                ) {
                    Ok(Some(digest)) => return Ok(Some(digest)),
                    Ok(None) => {}
                    Err(migration_err) => {
                        tracing::warn!(
                            target = %dir.display(),
                            "virtual store: treating object as unusable {context}: {migration_err}"
                        );
                        let remove_start = std::time::Instant::now();
                        remove_unusable_object_dir(dir, context)?;
                        timings.removed_count = timings.removed_count.saturating_add(1);
                        timings.remove_ms = timings
                            .remove_ms
                            .saturating_add(remove_start.elapsed().as_millis());
                        return Ok(None);
                    }
                }
                tracing::warn!(
                    target = %dir.display(),
                    "virtual store: treating object as unusable {context}: {err}"
                );
                let remove_start = std::time::Instant::now();
                remove_unusable_object_dir(dir, context)?;
                timings.removed_count = timings.removed_count.saturating_add(1);
                timings.remove_ms = timings
                    .remove_ms
                    .saturating_add(remove_start.elapsed().as_millis());
                Ok(None)
            }
        };
    }
    match verified_tree_object_integrity_or_migrate_with_timings(dir, source_sri, timings) {
        Ok(digest) => Ok(Some(digest)),
        Err(err) => {
            if source_object_lacks_tree_baseline(dir, source_sri).unwrap_or(false) {
                return Ok(None);
            }
            tracing::warn!(
                target = %dir.display(),
                "virtual store: treating object as unusable {context}: {err}"
            );
            let remove_start = std::time::Instant::now();
            remove_unusable_object_dir(dir, context)?;
            timings.removed_count = timings.removed_count.saturating_add(1);
            timings.remove_ms = timings
                .remove_ms
                .saturating_add(remove_start.elapsed().as_millis());
            Ok(None)
        }
    }
}

pub(crate) fn object_integrity_or_remove(
    dir: &Path,
    context: &str,
    source_sri: &str,
    policy: ObjectIntegrityPolicy,
) -> Result<Option<VerifiedObjectIntegrity>, LpmError> {
    if !is_complete_object_dir(dir) {
        remove_unusable_object_dir(dir, context)?;
        return Ok(None);
    }
    if source_policy_uses_source_integrity(dir, policy) {
        return match verified_source_object_integrity_or_migrate(dir, source_sri) {
            Ok(digest) => Ok(Some(digest)),
            Err(err) => {
                tracing::warn!(
                    target = %dir.display(),
                    "virtual store: treating object as unusable {context}: {err}"
                );
                remove_unusable_object_dir(dir, context)?;
                Ok(None)
            }
        };
    }
    match verified_tree_object_integrity_or_migrate(dir, source_sri) {
        Ok(digest) => Ok(Some(digest)),
        Err(err) => {
            if source_object_lacks_tree_baseline(dir, source_sri).unwrap_or(false) {
                return Ok(None);
            }
            tracing::warn!(
                target = %dir.display(),
                "virtual store: treating object as unusable {context}: {err}"
            );
            remove_unusable_object_dir(dir, context)?;
            Ok(None)
        }
    }
}

pub(crate) fn remove_unusable_object_dir(dir: &Path, context: &str) -> Result<(), LpmError> {
    remove_unusable_object_dir_inner(dir, context, true)
}

pub(crate) fn remove_unusable_object_dir_quiet(dir: &Path, context: &str) -> Result<(), LpmError> {
    remove_unusable_object_dir_inner(dir, context, false)
}

pub(crate) fn remove_unusable_object_dir_inner(
    dir: &Path,
    context: &str,
    warn: bool,
) -> Result<(), LpmError> {
    let claimed_dir = claim_unusable_object_dir(dir, context)?;
    let Some(claimed_dir) = claimed_dir else {
        return Ok(());
    };
    if warn {
        tracing::warn!(
            target = %dir.display(),
            "virtual store: removing incomplete or unverifiable object {context}"
        );
    }
    std::fs::remove_dir_all(&claimed_dir).map_err(|e| {
        LpmError::Store(format!(
            "failed to remove incomplete or unverifiable virtual-store object at {} {context}: {e}",
            dir.display()
        ))
    })?;
    remove_object_metadata_dir_best_effort(dir);
    Ok(())
}

pub(crate) fn claim_unusable_object_dir(
    dir: &Path,
    context: &str,
) -> Result<Option<PathBuf>, LpmError> {
    for _ in 0..8 {
        let claimed_dir = tmp_sibling(dir);
        match std::fs::rename(dir, &claimed_dir) {
            Ok(()) => return Ok(Some(claimed_dir)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => {
                return Err(LpmError::Store(format!(
                    "failed to claim incomplete or unverifiable virtual-store object at {} {context}: {e}",
                    dir.display()
                )));
            }
        }
    }
    Err(LpmError::Store(format!(
        "failed to claim incomplete or unverifiable virtual-store object at {} {context}: could not allocate a temporary removal path",
        dir.display()
    )))
}

pub(crate) fn finish_object_rename_after_collision(
    tmp_dir: &Path,
    object_dir: &Path,
    source_sri: &str,
    context: &str,
    original_error: std::io::Error,
    policy: ObjectIntegrityPolicy,
) -> Result<PathBuf, LpmError> {
    if object_dir.exists() {
        match is_verified_object_dir(object_dir, source_sri, policy) {
            Ok(true) => {
                let _ = std::fs::remove_dir_all(tmp_dir);
                return Ok(object_dir.to_path_buf());
            }
            Ok(false)
                if source_object_lacks_tree_baseline(object_dir, source_sri).unwrap_or(false) =>
            {
                remove_unusable_object_dir_quiet(object_dir, "after rename collision")?;
            }
            Ok(false) => remove_unusable_object_dir(object_dir, "after rename collision")?,
            Err(err) => {
                if source_object_lacks_tree_baseline(object_dir, source_sri).unwrap_or(false) {
                    remove_unusable_object_dir_quiet(object_dir, "after rename collision")?;
                } else {
                    tracing::warn!(
                        target = %object_dir.display(),
                        "virtual store: treating collided object as unusable during {context}: {err}"
                    );
                    remove_unusable_object_dir(object_dir, "after rename collision")?;
                }
            }
        }
        return std::fs::rename(tmp_dir, object_dir)
            .map(|()| object_dir.to_path_buf())
            .map_err(|retry_error| {
                let _ = std::fs::remove_dir_all(tmp_dir);
                LpmError::Store(format!(
                    "{context}: failed to replace unusable virtual-store object after rename collision: {retry_error}; original rename error: {original_error}"
                ))
            });
    }

    let _ = std::fs::remove_dir_all(tmp_dir);
    Err(LpmError::Store(format!(
        "{context}: failed to atomically install virtual-store object: {original_error}"
    )))
}

pub(crate) fn is_verified_object_dir(
    dir: &Path,
    source_sri: &str,
    policy: ObjectIntegrityPolicy,
) -> Result<bool, LpmError> {
    if !is_complete_object_dir(dir) {
        return Ok(false);
    }
    if source_policy_uses_source_integrity(dir, policy) {
        return verified_source_object_integrity_or_migrate(dir, source_sri).map(|_| true);
    }
    verified_tree_object_integrity_or_migrate(dir, source_sri).map(|_| true)
}

pub(crate) fn verified_source_object_integrity(
    dir: &Path,
    source_sri: &str,
) -> Result<String, LpmError> {
    let expected = source_object_integrity(source_sri);
    let actual = read_object_integrity(dir)?;
    if actual == expected {
        return Ok(actual);
    }
    Err(LpmError::Store(format!(
        "virtual-store object source integrity mismatch at {}: expected {expected}, actual {actual}",
        dir.display()
    )))
}

pub(crate) fn source_object_lacks_tree_baseline(
    dir: &Path,
    source_sri: &str,
) -> Result<bool, LpmError> {
    let expected = read_object_integrity(dir)?;
    if expected != source_object_integrity(source_sri) {
        return Ok(false);
    }
    Ok(match read_tree_snapshot(dir) {
        Some(snapshot) => snapshot.content_integrity == expected,
        None => true,
    })
}

pub(crate) fn object_integrity_for_link(
    dir: &Path,
    source_sri: &str,
    policy: ObjectIntegrityPolicy,
) -> Result<String, LpmError> {
    if source_policy_uses_source_integrity(dir, policy) {
        verified_source_object_integrity_or_migrate(dir, source_sri)
            .map(|digest| digest.as_str().to_owned())
    } else {
        verified_tree_object_integrity_or_migrate(dir, source_sri)
            .map(|digest| digest.as_str().to_owned())
    }
}

pub(crate) fn verified_tree_object_integrity_or_migrate_with_timings(
    dir: &Path,
    source_sri: &str,
    timings: &mut ReusableObjectCheckTimings,
) -> Result<VerifiedObjectIntegrity, LpmError> {
    timings.object_sidecar_read_count = timings.object_sidecar_read_count.saturating_add(1);
    let sidecar_start = std::time::Instant::now();
    let expected = read_object_integrity(dir)?;
    timings.object_sidecar_read_ms = timings
        .object_sidecar_read_ms
        .saturating_add(sidecar_start.elapsed().as_millis());
    if tree_snapshot_matches_with_timings(dir, dir, &expected, timings)? {
        return Ok(VerifiedObjectIntegrity::new(expected));
    }
    if let Some(digest) = try_migrate_source_object_integrity_to_tree_with_timings(
        dir, source_sri, &expected, timings,
    )? {
        return Ok(digest);
    }
    timings.full_hash_count = timings.full_hash_count.saturating_add(1);
    let full_hash_start = std::time::Instant::now();
    let actual = compute_object_tree_integrities(dir)?;
    timings.full_hash_ms = timings
        .full_hash_ms
        .saturating_add(full_hash_start.elapsed().as_millis());
    if expected == actual.content {
        write_tree_snapshot_best_effort(dir, &actual);
        return Ok(VerifiedObjectIntegrity::new(expected));
    }
    Err(LpmError::Store(format!(
        "virtual-store object integrity mismatch at {}: expected {expected}, actual {}",
        dir.display(),
        actual.content
    )))
}

pub(crate) fn try_migrate_source_object_integrity_to_tree(
    dir: &Path,
    source_sri: &str,
    expected: &str,
) -> Result<Option<VerifiedObjectIntegrity>, LpmError> {
    if expected != source_object_integrity(source_sri) {
        return Ok(None);
    }
    if let Some(snapshot) = read_tree_snapshot(dir)
        && snapshot.content_integrity != expected
    {
        if let Some(actual) = current_tree_content_matches_snapshot(dir, &snapshot)? {
            write_tree_object_integrity_from_integrities(dir, &actual)?;
            return Ok(Some(VerifiedObjectIntegrity::new(actual.content)));
        }
        return Ok(None);
    }
    Ok(None)
}

pub(crate) fn try_migrate_source_object_integrity_to_tree_with_timings(
    dir: &Path,
    source_sri: &str,
    expected: &str,
    timings: &mut ReusableObjectCheckTimings,
) -> Result<Option<VerifiedObjectIntegrity>, LpmError> {
    if expected != source_object_integrity(source_sri) {
        return Ok(None);
    }
    if let Some(snapshot) = read_tree_snapshot(dir)
        && snapshot.content_integrity != expected
    {
        if let Some(actual) =
            current_tree_content_matches_snapshot_with_timings(dir, &snapshot, timings)?
        {
            write_tree_object_integrity_from_integrities(dir, &actual)?;
            return Ok(Some(VerifiedObjectIntegrity::new(actual.content)));
        }
        return Ok(None);
    }
    Ok(None)
}

pub(crate) fn current_tree_content_matches_snapshot(
    dir: &Path,
    snapshot: &TreeSnapshot,
) -> Result<Option<TreeIntegrities>, LpmError> {
    let actual = compute_object_tree_integrities(dir)?;
    if actual.content == snapshot.content_integrity {
        Ok(Some(actual))
    } else {
        Ok(None)
    }
}

pub(crate) fn current_tree_content_matches_snapshot_with_timings(
    dir: &Path,
    snapshot: &TreeSnapshot,
    timings: &mut ReusableObjectCheckTimings,
) -> Result<Option<TreeIntegrities>, LpmError> {
    timings.full_hash_count = timings.full_hash_count.saturating_add(1);
    let full_hash_start = std::time::Instant::now();
    let actual = compute_object_tree_integrities(dir)?;
    timings.full_hash_ms = timings
        .full_hash_ms
        .saturating_add(full_hash_start.elapsed().as_millis());
    if actual.content == snapshot.content_integrity {
        Ok(Some(actual))
    } else {
        timings.snapshot_miss_count = timings.snapshot_miss_count.saturating_add(1);
        Ok(None)
    }
}

pub(crate) fn tree_snapshot_matches(
    snapshot_dir: &Path,
    tree_dir: &Path,
    expected_content_integrity: &str,
) -> Result<bool, LpmError> {
    let Some(snapshot) = read_tree_snapshot(snapshot_dir) else {
        return Ok(false);
    };
    if snapshot.content_integrity != expected_content_integrity {
        return Ok(false);
    }
    let actual_metadata = compute_tree_metadata_integrity(tree_dir)?;
    Ok(actual_metadata == snapshot.metadata_integrity)
}

pub(crate) fn tree_snapshot_matches_with_timings(
    snapshot_dir: &Path,
    tree_dir: &Path,
    expected_content_integrity: &str,
    timings: &mut ReusableObjectCheckTimings,
) -> Result<bool, LpmError> {
    timings.snapshot_read_count = timings.snapshot_read_count.saturating_add(1);
    let snapshot_read_start = std::time::Instant::now();
    let Some(snapshot) = read_tree_snapshot(snapshot_dir) else {
        timings.snapshot_read_ms = timings
            .snapshot_read_ms
            .saturating_add(snapshot_read_start.elapsed().as_millis());
        timings.snapshot_miss_count = timings.snapshot_miss_count.saturating_add(1);
        return Ok(false);
    };
    timings.snapshot_read_ms = timings
        .snapshot_read_ms
        .saturating_add(snapshot_read_start.elapsed().as_millis());
    if snapshot.content_integrity != expected_content_integrity {
        timings.snapshot_miss_count = timings.snapshot_miss_count.saturating_add(1);
        return Ok(false);
    }
    timings.metadata_hash_count = timings.metadata_hash_count.saturating_add(1);
    let metadata_hash_start = std::time::Instant::now();
    let actual_metadata = compute_tree_metadata_integrity(tree_dir)?;
    timings.metadata_hash_ms = timings
        .metadata_hash_ms
        .saturating_add(metadata_hash_start.elapsed().as_millis());
    if actual_metadata == snapshot.metadata_integrity {
        timings.snapshot_hit_count = timings.snapshot_hit_count.saturating_add(1);
        Ok(true)
    } else {
        timings.snapshot_miss_count = timings.snapshot_miss_count.saturating_add(1);
        Ok(false)
    }
}

pub(crate) fn read_tree_snapshot(dir: &Path) -> Option<TreeSnapshot> {
    let path = dir.join(TREE_SNAPSHOT_FILENAME);
    let metadata = match std::fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return None,
        Err(error) => {
            tracing::debug!(
                target = %path.display(),
                "virtual store: ignoring unreadable tree snapshot: {error}"
            );
            return None;
        }
    };
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return None;
    }
    if metadata.len() > TREE_SNAPSHOT_MAX_BYTES {
        tracing::debug!(
            target = %path.display(),
            bytes = metadata.len(),
            "virtual store: ignoring oversized tree snapshot"
        );
        return None;
    }
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) => {
            tracing::debug!(
                target = %path.display(),
                "virtual store: ignoring unreadable tree snapshot: {error}"
            );
            return None;
        }
    };
    let snapshot: TreeSnapshot = match serde_json::from_slice(&bytes) {
        Ok(snapshot) => snapshot,
        Err(error) => {
            tracing::debug!(
                target = %path.display(),
                "virtual store: ignoring malformed tree snapshot: {error}"
            );
            return None;
        }
    };
    if snapshot.schema != TREE_SNAPSHOT_SCHEMA_VERSION {
        return None;
    }
    if !valid_sha256_integrity(&snapshot.content_integrity)
        || snapshot
            .layout_content_integrity
            .as_deref()
            .is_some_and(|integrity| !valid_sha256_integrity(integrity))
        || !valid_sha256_integrity(&snapshot.metadata_integrity)
    {
        return None;
    }
    Some(snapshot)
}

pub(crate) fn valid_sha256_integrity(value: &str) -> bool {
    let Some(hex_part) = value.strip_prefix("sha256-") else {
        return false;
    };
    hex_part.len() == 64 && hex_part.as_bytes().iter().all(u8::is_ascii_hexdigit)
}

pub(crate) fn write_tree_snapshot_best_effort(dir: &Path, integrities: &TreeIntegrities) {
    if let Err(error) = write_tree_snapshot(dir, integrities) {
        tracing::debug!(
            target = %dir.display(),
            "virtual store: failed to refresh tree snapshot: {error}"
        );
    }
}

pub(crate) fn write_tree_snapshot(
    dir: &Path,
    integrities: &TreeIntegrities,
) -> Result<(), LpmError> {
    write_tree_snapshot_fields(dir, &integrities.content, None, &integrities.metadata)
}

pub(crate) fn write_tree_snapshot_with_layout_content(
    dir: &Path,
    source_content_integrity: &str,
    layout_integrities: &TreeIntegrities,
) -> Result<(), LpmError> {
    write_tree_snapshot_fields(
        dir,
        source_content_integrity,
        Some(&layout_integrities.content),
        &layout_integrities.metadata,
    )
}

fn write_tree_snapshot_fields(
    dir: &Path,
    content_integrity: &str,
    layout_content_integrity: Option<&str>,
    metadata_integrity: &str,
) -> Result<(), LpmError> {
    let snapshot = TreeSnapshot {
        schema: TREE_SNAPSHOT_SCHEMA_VERSION,
        content_integrity: content_integrity.to_owned(),
        layout_content_integrity: layout_content_integrity.map(str::to_owned),
        metadata_integrity: metadata_integrity.to_owned(),
    };
    let bytes = serde_json::to_vec(&snapshot).map_err(|e| {
        LpmError::Store(format!(
            "failed to serialize virtual-store tree snapshot: {e}"
        ))
    })?;
    let final_path = dir.join(TREE_SNAPSHOT_FILENAME);
    write_file_atomic(&final_path, bytes).map_err(|error| {
        LpmError::Store(format!(
            "failed to atomically install virtual-store tree snapshot at {}: {error}",
            final_path.display()
        ))
    })
}

pub(crate) fn read_object_integrity(dir: &Path) -> Result<String, LpmError> {
    let path = dir.join(OBJECT_INTEGRITY_FILENAME);
    if !is_regular_file_no_symlink(&path) {
        return Err(LpmError::Store(format!(
            "virtual-store object integrity sidecar is missing or not a regular file at {}",
            path.display()
        )));
    }
    let raw = std::fs::read_to_string(&path).map_err(|e| {
        LpmError::Store(format!(
            "failed to read virtual-store object integrity sidecar at {}: {e}",
            path.display()
        ))
    })?;
    let digest = raw.trim();
    let hex_part = digest.strip_prefix("sha256-").ok_or_else(|| {
        LpmError::Store(format!(
            "invalid virtual-store object integrity sidecar at {}: expected sha256-<hex>",
            path.display()
        ))
    })?;
    if hex_part.len() != 64 || !hex_part.as_bytes().iter().all(u8::is_ascii_hexdigit) {
        return Err(LpmError::Store(format!(
            "invalid virtual-store object integrity sidecar at {}: expected sha256-<64 hex chars>",
            path.display()
        )));
    }
    Ok(digest.to_string())
}

pub(crate) fn write_tree_object_integrity(dir: &Path) -> Result<TreeIntegrities, LpmError> {
    let integrities = compute_object_tree_integrities(dir)?;
    write_tree_object_integrity_from_integrities(dir, &integrities)?;
    Ok(integrities)
}

pub(crate) fn write_tree_object_integrity_from_integrities(
    dir: &Path,
    integrities: &TreeIntegrities,
) -> Result<(), LpmError> {
    write_object_integrity_content(dir, &integrities.content)?;
    write_tree_snapshot(dir, integrities)?;
    Ok(())
}

pub(crate) fn write_object_integrity_for_policy(
    dir: &Path,
    source_sri: &str,
    policy: ObjectIntegrityPolicy,
) -> Result<TreeIntegrities, LpmError> {
    match policy {
        ObjectIntegrityPolicy::Tree => write_tree_object_integrity(dir),
        ObjectIntegrityPolicy::Source => write_source_object_integrity(dir, source_sri),
    }
}

pub(crate) fn write_source_object_integrity(
    dir: &Path,
    source_sri: &str,
) -> Result<TreeIntegrities, LpmError> {
    let actual = compute_object_tree_integrities(dir)?;
    write_source_object_integrity_with_tree(dir, source_sri, &actual)
}

pub(crate) fn write_source_object_integrity_with_tree(
    dir: &Path,
    source_sri: &str,
    actual: &TreeIntegrities,
) -> Result<TreeIntegrities, LpmError> {
    let content = source_object_integrity(source_sri);
    write_object_integrity_content(dir, &content)?;
    write_tree_snapshot(dir, actual)?;
    Ok(TreeIntegrities {
        content,
        metadata: actual.metadata.clone(),
        stats: actual.stats,
    })
}

pub(crate) fn write_object_integrity_content(dir: &Path, content: &str) -> Result<(), LpmError> {
    let path = dir.join(OBJECT_INTEGRITY_FILENAME);
    write_file_atomic(&path, format!("{content}\n")).map_err(|e| {
        LpmError::Store(format!(
            "failed to write virtual-store object integrity sidecar: {e}"
        ))
    })
}

pub(crate) fn source_object_integrity(source_sri: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"lpm-v2-source-object-integrity\0");
    hasher.update(source_sri.as_bytes());
    format!("sha256-{}", hex::encode(hasher.finalize()))
}
