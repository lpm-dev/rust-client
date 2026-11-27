use std::path::{Path, PathBuf};

use lpm_common::{LpmError, write_file_atomic};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::fs_util::{harden_store_tier_once, tmp_sibling};
use super::tree_hash::{
    TreeContentSchema, TreeIntegrities, compute_object_tree_integrities,
    compute_object_tree_integrities_for_schema, compute_tree_metadata_integrity,
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
const TREE_SNAPSHOT_MAX_BYTES: u64 = 4096;
pub const ENV_V2_OBJECT_INTEGRITY: &str = "LPM_V2_OBJECT_INTEGRITY";
/// Explicit opt-in for ephemeral CI runners restoring `~/.lpm/store` from an
/// archive (which bumps file `ctime`, truncates `mtime` subseconds, and alters
/// directory `st_size` while preserving regular-file size, mode, and whole-second
/// `mtime`). Honored only under `ObjectIntegrityPolicy::Source` (never `Tree`)
/// and never overwrites strict `metadata_integrity` or shallow guards.
pub const ENV_TRUST_RESTORED_STORE: &str = "LPM_TRUST_RESTORED_STORE";

static TRUST_RESTORED_STORE_CACHED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
static TRUST_RESTORED_STORE_WARNED: std::sync::Once = std::sync::Once::new();

#[cfg(debug_assertions)]
static TRUST_RESTORED_STORE_TEST_OVERRIDE: std::sync::atomic::AtomicU8 =
    std::sync::atomic::AtomicU8::new(0);

#[cfg(debug_assertions)]
pub struct TrustRestoredStoreOverrideGuard {
    previous: u8,
}

#[cfg(debug_assertions)]
impl Drop for TrustRestoredStoreOverrideGuard {
    fn drop(&mut self) {
        TRUST_RESTORED_STORE_TEST_OVERRIDE
            .store(self.previous, std::sync::atomic::Ordering::SeqCst);
    }
}

#[cfg(debug_assertions)]
pub fn override_trust_restored_store_for_test(
    value: Option<bool>,
) -> TrustRestoredStoreOverrideGuard {
    let encoded = match value {
        None => 0,
        Some(false) => 1,
        Some(true) => 2,
    };
    let previous = TRUST_RESTORED_STORE_TEST_OVERRIDE
        .swap(encoded, std::sync::atomic::Ordering::SeqCst);
    TrustRestoredStoreOverrideGuard { previous }
}

fn parse_trust_restored_store_env() -> bool {
    std::env::var(ENV_TRUST_RESTORED_STORE)
        .ok()
        .is_some_and(|value| {
            matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
}

pub fn trust_restored_store_from_env() -> bool {
    #[cfg(debug_assertions)]
    {
        match TRUST_RESTORED_STORE_TEST_OVERRIDE.load(std::sync::atomic::Ordering::SeqCst) {
            1 => return false,
            2 => return true,
            _ => {}
        }
    }
    *TRUST_RESTORED_STORE_CACHED.get_or_init(parse_trust_restored_store_env)
}

/// Whether restored-store ctime/subsecond-mtime tolerance is active for `policy`.
///
/// Strict `ObjectIntegrityPolicy::Tree` never weakens tamper detection, even
/// when `LPM_TRUST_RESTORED_STORE` is set in the environment.
pub fn trust_restored_store_enabled(policy: ObjectIntegrityPolicy) -> bool {
    if policy != ObjectIntegrityPolicy::Source {
        return false;
    }
    let enabled = trust_restored_store_from_env();
    if enabled {
        TRUST_RESTORED_STORE_WARNED.call_once(|| {
            tracing::warn!(
                "{ENV_TRUST_RESTORED_STORE} is enabled: reusing restored source-policy store entries via ctime-free metadata digests without content rehashing"
            );
        });
    }
    enabled
}

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

// Git-style racily-clean safety window: if package mtimes were within 2 seconds
// of snapshot capture, fall back to full metadata hashing to catch same-tick edits.
pub(crate) const SHALLOW_GUARD_RACILY_CLEAN_WINDOW_NANOS: i128 = 2_000_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ShallowPackageGuard {
    pub(crate) package_dir_mtime_nanos: i128,
    pub(crate) package_dir_ctime_nanos: Option<i128>,
    pub(crate) package_json_size: u64,
    pub(crate) package_json_mtime_nanos: i128,
    pub(crate) package_json_ctime_nanos: Option<i128>,
    pub(crate) package_dir_entry_count: Option<u64>,
    pub(crate) captured_at_nanos: Option<i128>,
}

impl ShallowPackageGuard {
    /// Returns true iff `self` was captured safely after both directory and
    /// manifest mtimes (outside the racily-clean window).
    pub(crate) fn is_non_racy(&self) -> bool {
        let Some(captured_at) = self.captured_at_nanos else {
            return false;
        };
        captured_at.saturating_sub(self.package_dir_mtime_nanos)
            >= SHALLOW_GUARD_RACILY_CLEAN_WINDOW_NANOS
            && captured_at.saturating_sub(self.package_json_mtime_nanos)
                >= SHALLOW_GUARD_RACILY_CLEAN_WINDOW_NANOS
    }

    /// Returns true iff `self` (the current filesystem observation) matches
    /// `recorded` AND `recorded` was captured safely after both mtimes (outside
    /// the racily-clean window).
    pub(crate) fn matches_non_racy(&self, recorded: &ShallowPackageGuard) -> bool {
        if self.package_dir_mtime_nanos != recorded.package_dir_mtime_nanos
            || self.package_dir_ctime_nanos != recorded.package_dir_ctime_nanos
            || self.package_json_size != recorded.package_json_size
            || self.package_json_mtime_nanos != recorded.package_json_mtime_nanos
            || self.package_json_ctime_nanos != recorded.package_json_ctime_nanos
            || self.package_dir_entry_count != recorded.package_dir_entry_count
        {
            return false;
        }
        recorded.is_non_racy()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct TreeSnapshot {
    pub(crate) schema: u32,
    pub(crate) content_integrity: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) layout_content_integrity: Option<String>,
    pub(crate) metadata_integrity: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) metadata_integrity_no_ctime: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) package_dir_mtime_nanos: Option<i128>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) package_dir_ctime_nanos: Option<i128>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) package_json_size: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) package_json_mtime_nanos: Option<i128>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) package_json_ctime_nanos: Option<i128>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) package_dir_entry_count: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) snapshot_captured_at_nanos: Option<i128>,
}

impl TreeSnapshot {
    pub(crate) fn content_schema(&self) -> TreeContentSchema {
        TreeContentSchema::from_snapshot_schema(self.schema)
            .unwrap_or(TreeContentSchema::SequentialV1)
    }

    pub(crate) fn shallow_guard(&self) -> Option<ShallowPackageGuard> {
        Some(ShallowPackageGuard {
            package_dir_mtime_nanos: self.package_dir_mtime_nanos?,
            package_dir_ctime_nanos: self.package_dir_ctime_nanos,
            package_json_size: self.package_json_size?,
            package_json_mtime_nanos: self.package_json_mtime_nanos?,
            package_json_ctime_nanos: self.package_json_ctime_nanos,
            package_dir_entry_count: self.package_dir_entry_count,
            captured_at_nanos: self.snapshot_captured_at_nanos,
        })
    }
}

fn system_time_nanos(time: std::time::SystemTime) -> i128 {
    match time.duration_since(std::time::UNIX_EPOCH) {
        Ok(duration) => duration.as_nanos() as i128,
        Err(error) => -(error.duration().as_nanos() as i128),
    }
}

#[cfg(unix)]
#[allow(clippy::unnecessary_wraps)]
fn metadata_ctime_nanos(metadata: &std::fs::Metadata) -> Option<i128> {
    use std::os::unix::fs::MetadataExt;
    Some(i128::from(metadata.ctime()) * 1_000_000_000 + i128::from(metadata.ctime_nsec()))
}

#[cfg(not(unix))]
fn metadata_ctime_nanos(_metadata: &std::fs::Metadata) -> Option<i128> {
    None
}

pub(crate) fn read_shallow_package_guard(package_dir: &Path) -> Option<ShallowPackageGuard> {
    let dir_meta = std::fs::symlink_metadata(package_dir).ok()?;
    if !dir_meta.is_dir() || dir_meta.file_type().is_symlink() {
        return None;
    }
    let dir_mtime = dir_meta.modified().ok()?;
    let pkg_json_meta = std::fs::symlink_metadata(package_dir.join("package.json")).ok()?;
    if !pkg_json_meta.is_file() || pkg_json_meta.file_type().is_symlink() {
        return None;
    }
    let pkg_json_mtime = pkg_json_meta.modified().ok()?;
    // NTFS directory mtimes quantize to coarse timer ticks, so a same-tick
    // add/remove in `package_dir` can keep `dir_mtime` unchanged; count
    // top-level entries on Windows to detect structural mutations reliably.
    #[cfg(windows)]
    let package_dir_entry_count = {
        let mut count = 0u64;
        for entry in std::fs::read_dir(package_dir).ok()? {
            entry.ok()?;
            count = count.checked_add(1)?;
        }
        Some(count)
    };
    #[cfg(not(windows))]
    let package_dir_entry_count = None;
    Some(ShallowPackageGuard {
        package_dir_mtime_nanos: system_time_nanos(dir_mtime),
        package_dir_ctime_nanos: metadata_ctime_nanos(&dir_meta),
        package_json_size: pkg_json_meta.len(),
        package_json_mtime_nanos: system_time_nanos(pkg_json_mtime),
        package_json_ctime_nanos: metadata_ctime_nanos(&pkg_json_meta),
        package_dir_entry_count,
        captured_at_nanos: Some(system_time_nanos(std::time::SystemTime::now())),
    })
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
    let actual = compute_tree_integrities_matching_expected(dir, &legacy_integrity)?;
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
    let actual = compute_tree_integrities_matching_expected(dir, &legacy_integrity)?;
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
    let actual = compute_tree_integrities_matching_expected(dir, &expected)?;
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
    is_real_directory(dir)
        && is_regular_file_no_symlink(&dir.join("package.json"))
        && is_regular_file_no_symlink(&dir.join(".integrity"))
        && is_regular_file_no_symlink(&dir.join(OBJECT_INTEGRITY_FILENAME))
}

fn is_real_directory(path: &Path) -> bool {
    std::fs::symlink_metadata(path)
        .is_ok_and(|metadata| metadata.is_dir() && !lpm_common::is_symlink_or_junction(&metadata))
}

pub(crate) fn is_regular_file_no_symlink(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok_and(|metadata| metadata.file_type().is_file())
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

/// Keeps the store tier holding the entry `dir` to its owner, once per
/// process, before anything in it is reused: an earlier release may have
/// left the tier open to other accounts, and what it holds is readable
/// through it. `tier` names the tier in the error.
pub(crate) fn harden_tier_of(dir: &Path, tier: &str) -> Result<(), LpmError> {
    let Some(parent) = dir.parent() else {
        return Ok(());
    };
    harden_store_tier_once(parent).map_err(|error| {
        LpmError::Store(format!(
            "failed to keep the virtual-store {tier} dir private: {error}"
        ))
    })
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
    harden_tier_of(dir, "objects")?;
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
    harden_tier_of(dir, "objects")?;
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
    let actual = compute_tree_integrities_matching_expected(dir, &expected)?;
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
    let actual = compute_object_tree_integrities_for_schema(dir, snapshot.content_schema())?;
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
    let actual = compute_object_tree_integrities_for_schema(dir, snapshot.content_schema())?;
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

fn compute_tree_integrities_matching_expected(
    dir: &Path,
    expected: &str,
) -> Result<TreeIntegrities, LpmError> {
    let primary_schema = read_tree_snapshot(dir)
        .map_or(TreeContentSchema::SequentialV1, |snapshot| {
            snapshot.content_schema()
        });
    let primary = compute_object_tree_integrities_for_schema(dir, primary_schema)?;
    if primary.content == expected {
        return Ok(primary);
    }
    let alternate_schema = match primary_schema {
        TreeContentSchema::SequentialV1 => TreeContentSchema::EntryDigestV2,
        TreeContentSchema::EntryDigestV2 => TreeContentSchema::SequentialV1,
    };
    let alternate = compute_object_tree_integrities_for_schema(dir, alternate_schema)?;
    if alternate.content == expected {
        Ok(alternate)
    } else {
        Ok(primary)
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
    TreeContentSchema::from_snapshot_schema(snapshot.schema)?;
    if !valid_sha256_integrity(&snapshot.content_integrity)
        || snapshot
            .layout_content_integrity
            .as_deref()
            .is_some_and(|integrity| !valid_sha256_integrity(integrity))
        || !valid_sha256_integrity(&snapshot.metadata_integrity)
        || snapshot
            .metadata_integrity_no_ctime
            .as_deref()
            .is_some_and(|integrity| !valid_sha256_integrity(integrity))
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

pub(crate) fn write_link_tree_snapshot_best_effort(
    dir: &Path,
    package_dir: &Path,
    integrities: &TreeIntegrities,
) {
    let shallow_guard = read_shallow_package_guard(package_dir);
    if let Err(error) = write_tree_snapshot_fields(
        dir,
        integrities.content_schema,
        &integrities.content,
        None,
        &integrities.metadata,
        Some(&integrities.metadata_no_ctime),
        shallow_guard,
        false,
    ) {
        tracing::debug!(
            target = %dir.display(),
            "virtual store: failed to refresh link tree snapshot: {error}"
        );
    }
}

pub(crate) fn refresh_link_snapshot_shallow_guard_best_effort(
    dir: &Path,
    package_dir: &Path,
    snapshot: &TreeSnapshot,
    actual_metadata_integrity: &str,
    actual_metadata_no_ctime: Option<&str>,
) {
    let Some(shallow_guard) = read_shallow_package_guard(package_dir) else {
        return;
    };
    let needs_backfill = snapshot.metadata_integrity_no_ctime.is_none()
        && actual_metadata_no_ctime.is_some();
    if !shallow_guard.is_non_racy() && !needs_backfill {
        return;
    }
    if let Err(error) = write_tree_snapshot_fields(
        dir,
        snapshot.content_schema(),
        &snapshot.content_integrity,
        snapshot.layout_content_integrity.as_deref(),
        actual_metadata_integrity,
        actual_metadata_no_ctime.or(snapshot.metadata_integrity_no_ctime.as_deref()),
        Some(shallow_guard),
        false,
    ) {
        tracing::debug!(
            target = %dir.display(),
            "virtual store: failed to stamp shallow guard on link tree snapshot: {error}"
        );
    }
}

pub(crate) fn write_tree_snapshot(
    dir: &Path,
    integrities: &TreeIntegrities,
) -> Result<(), LpmError> {
    write_tree_snapshot_fields(
        dir,
        integrities.content_schema,
        &integrities.content,
        None,
        &integrities.metadata,
        Some(&integrities.metadata_no_ctime),
        None,
        false,
    )
}

pub(crate) fn write_tree_snapshot_unpublished(
    dir: &Path,
    integrities: &TreeIntegrities,
) -> Result<(), LpmError> {
    write_tree_snapshot_fields(
        dir,
        integrities.content_schema,
        &integrities.content,
        None,
        &integrities.metadata,
        Some(&integrities.metadata_no_ctime),
        None,
        true,
    )
}

pub(crate) fn write_link_tree_snapshot_unpublished(
    dir: &Path,
    package_dir: &Path,
    integrities: &TreeIntegrities,
) -> Result<(), LpmError> {
    write_tree_snapshot_fields(
        dir,
        integrities.content_schema,
        &integrities.content,
        None,
        &integrities.metadata,
        Some(&integrities.metadata_no_ctime),
        read_shallow_package_guard(package_dir),
        true,
    )
}

pub(crate) fn write_tree_snapshot_with_layout_content(
    dir: &Path,
    source_content_integrity: &str,
    layout_integrities: &TreeIntegrities,
) -> Result<(), LpmError> {
    write_tree_snapshot_fields(
        dir,
        layout_integrities.content_schema,
        source_content_integrity,
        Some(&layout_integrities.content),
        &layout_integrities.metadata,
        Some(&layout_integrities.metadata_no_ctime),
        None,
        false,
    )
}

pub(crate) fn write_tree_snapshot_with_layout_content_unpublished(
    dir: &Path,
    source_content_integrity: &str,
    layout_integrities: &TreeIntegrities,
) -> Result<(), LpmError> {
    write_tree_snapshot_fields(
        dir,
        layout_integrities.content_schema,
        source_content_integrity,
        Some(&layout_integrities.content),
        &layout_integrities.metadata,
        Some(&layout_integrities.metadata_no_ctime),
        None,
        true,
    )
}

#[allow(clippy::too_many_arguments)]
fn write_tree_snapshot_fields(
    dir: &Path,
    content_schema: TreeContentSchema,
    content_integrity: &str,
    layout_content_integrity: Option<&str>,
    metadata_integrity: &str,
    metadata_integrity_no_ctime: Option<&str>,
    shallow_guard: Option<ShallowPackageGuard>,
    unpublished: bool,
) -> Result<(), LpmError> {
    let snapshot = TreeSnapshot {
        schema: content_schema.snapshot_schema(),
        content_integrity: content_integrity.to_owned(),
        layout_content_integrity: layout_content_integrity.map(str::to_owned),
        metadata_integrity: metadata_integrity.to_owned(),
        metadata_integrity_no_ctime: metadata_integrity_no_ctime.map(str::to_owned),
        package_dir_mtime_nanos: shallow_guard.map(|guard| guard.package_dir_mtime_nanos),
        package_dir_ctime_nanos: shallow_guard.and_then(|guard| guard.package_dir_ctime_nanos),
        package_json_size: shallow_guard.map(|guard| guard.package_json_size),
        package_json_mtime_nanos: shallow_guard.map(|guard| guard.package_json_mtime_nanos),
        package_json_ctime_nanos: shallow_guard.and_then(|guard| guard.package_json_ctime_nanos),
        package_dir_entry_count: shallow_guard.and_then(|guard| guard.package_dir_entry_count),
        snapshot_captured_at_nanos: shallow_guard.and_then(|guard| guard.captured_at_nanos),
    };
    let bytes = serde_json::to_vec(&snapshot).map_err(|e| {
        LpmError::Store(format!(
            "failed to serialize virtual-store tree snapshot: {e}"
        ))
    })?;
    let final_path = dir.join(TREE_SNAPSHOT_FILENAME);
    if unpublished {
        use std::io::Write as _;

        let mut file = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&final_path)
            .map_err(|error| {
                LpmError::Store(format!(
                    "failed to write virtual-store tree snapshot at {}: {error}",
                    final_path.display()
                ))
            })?;
        file.write_all(&bytes).map_err(|error| {
            LpmError::Store(format!(
                "failed to write virtual-store tree snapshot at {}: {error}",
                final_path.display()
            ))
        })
    } else {
        write_file_atomic(&final_path, bytes).map_err(|error| {
            LpmError::Store(format!(
                "failed to atomically install virtual-store tree snapshot at {}: {error}",
                final_path.display()
            ))
        })
    }
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

pub(crate) fn write_object_integrity_for_policy_with_tree(
    dir: &Path,
    source_sri: &str,
    policy: ObjectIntegrityPolicy,
    actual: TreeIntegrities,
) -> Result<TreeIntegrities, LpmError> {
    match policy {
        ObjectIntegrityPolicy::Tree => {
            write_tree_object_integrity_from_integrities(dir, &actual)?;
            Ok(actual)
        }
        ObjectIntegrityPolicy::Source => {
            write_source_object_integrity_with_tree(dir, source_sri, &actual)
        }
    }
}

/// Write object integrity + tree snapshot directly inside an unpublished staging
/// directory that will be atomically renamed into `objects/` as a whole.
pub(crate) fn write_object_integrity_for_policy_with_tree_unpublished(
    dir: &Path,
    source_sri: &str,
    policy: ObjectIntegrityPolicy,
    actual: TreeIntegrities,
) -> Result<TreeIntegrities, LpmError> {
    match policy {
        ObjectIntegrityPolicy::Tree => {
            write_object_integrity_content_unpublished(dir, &actual.content)?;
            write_tree_snapshot_unpublished(dir, &actual)?;
            Ok(actual)
        }
        ObjectIntegrityPolicy::Source => {
            let content = source_object_integrity(source_sri);
            write_object_integrity_content_unpublished(dir, &content)?;
            write_tree_snapshot_unpublished(dir, &actual)?;
            Ok(TreeIntegrities {
                content,
                metadata: actual.metadata,
                metadata_no_ctime: actual.metadata_no_ctime,
                stats: actual.stats,
                content_schema: actual.content_schema,
            })
        }
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
        metadata_no_ctime: actual.metadata_no_ctime.clone(),
        stats: actual.stats,
        content_schema: actual.content_schema,
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

fn write_object_integrity_content_unpublished(dir: &Path, content: &str) -> Result<(), LpmError> {
    let path = dir.join(OBJECT_INTEGRITY_FILENAME);
    let mut bytes = Vec::with_capacity(content.len() + 1);
    bytes.extend_from_slice(content.as_bytes());
    bytes.push(b'\n');
    std::fs::write(&path, bytes).map_err(|e| {
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
