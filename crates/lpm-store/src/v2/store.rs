//! v2 store filesystem layer.
//!
//! Splits responsibility cleanly:
//! - [`StoreV2Paths`] — pure path computations (no I/O).
//! - [`Store`] — I/O entry points: object extraction and link-entry
//!   population (independent clone/reflink/copy from objects + sibling symlinks
//!   + atomic rename + sidecar write).
//!
//! The install command uses this writer by default. The retained v1 writer
//! is reached only through the explicit `LPM_STORE_VERSION=v1` rollback.

use std::borrow::Cow;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use lpm_common::integrity::{HashAlgorithm, Integrity};
use lpm_common::{LpmError, LpmRoot};
use sha2::{Digest, Sha256};

use super::finalize_permits::v2_finalize_limiter;
use super::fs_util::{
    copy_dir_recursively, create_dir_symlink, create_tmp_dir_locked, ensure_store_tier_dir_locked,
    materialize_into_with_integrity, tmp_sibling,
};
pub use super::integrity::{
    ENV_V2_OBJECT_INTEGRITY, FreshObjectIntegrity, ObjectIntegrityPolicy,
    ReusableObjectCheckTimings, VerifiedObjectIntegrity,
};
use super::integrity::{
    current_tree_content_matches_snapshot, finish_object_rename_after_collision,
    has_local_source_sentinel, is_complete_object_dir, object_dir_is_reusable_or_remove,
    object_integrity_for_link, object_integrity_or_remove, object_integrity_or_remove_with_timings,
    object_integrity_policy_from_env, read_object_integrity, read_tree_snapshot,
    remove_unusable_object_dir, source_object_integrity, source_policy_uses_source_integrity,
    tree_snapshot_matches, write_object_integrity_for_policy, write_tree_snapshot,
    write_tree_snapshot_best_effort, write_tree_snapshot_with_layout_content,
};
use super::local_source::{
    LocalSourceFingerprint, compute_local_source_fingerprint, local_source_snapshot_matches,
    populate_local_source_object_into, replace_local_source_object,
    stored_local_source_fingerprint_matches, write_local_source_fingerprint,
};
use super::tree_hash::{
    ExtractedObjectStats, ObjectTreeStats, TreeIntegrities, compute_object_tree_integrities,
    compute_tree_metadata_integrity,
};
use crate::v2::graph_key::GraphKey;
use crate::v2::link_meta::{
    LINK_META_FILENAME, LinkMeta, LinkMetaDep, LinkMetaPlatform, validate_name_for_path_join,
};
use crate::v3::{
    FileCas, FileCasReuseTimings, FileCasValidationBatch, PreparedSourceRecord, SourceReuseStatus,
};
use crate::{SecurityAnalysisPolicy, StageTimings, StoreVersion};

/// v2 layout version segment under `~/.lpm/store/`. Bumped whenever
/// the on-disk shape changes; lpm reading a higher-numbered store
/// MUST refuse rather than silently misinterpret.
const STORE_V2_VERSION: &str = "v2";
const STORE_V3_VERSION: &str = "v3";

/// Subdirectory holding the content-addressable object dirs.
const OBJECTS_DIR: &str = "objects";

const INTEGRITY_MARKER_SIZE_CAP_BYTES: u64 = 1024;

/// Subdirectory holding per-graph-key link entries.
const LINKS_DIR: &str = "links";

/// Subdirectory holding cached project-compatibility islands, keyed by the
/// content hash of the island's entry set. A framework-toolchain island
/// (Next/Turbopack + transitive closure) is built here once and then
/// `clonefile`d into each project's `node_modules/.lpm/compat`, so a warm
/// install reproduces the island in a single recursive syscall instead of
/// re-copying every package.
const COMPAT_DIR: &str = "compat";

/// Subdirectory holding lifecycle-build artifacts keyed by their complete
/// execution inputs.
const BUILDS_DIR: &str = "builds";

enum FileCasSourceFinish {
    Ready(Option<VerifiedObjectIntegrity>),
    Unusable,
}

struct FileCasFinishContext<'a> {
    prepared: Option<&'a PreparedSourceRecord>,
    reuse_timings: Option<&'a mut ReusableObjectCheckTimings>,
    validation_batch: Option<&'a ReusableObjectValidationBatch>,
}

enum TarballInput<'a> {
    Bytes(&'a [u8]),
    File(std::io::BufReader<std::fs::File>),
}

/// Subdirectory holding per-build-key advisory lock files.
const BUILD_LOCKS_DIR: &str = "build-locks";

/// Subdirectory holding per-graph-entry advisory lock files.
const BUILD_ENTRY_LOCKS_DIR: &str = "build-entry-locks";

/// Schema tag folded into [`compat_island_key`] so a change to the island's
/// on-disk layout invalidates every cached island instead of silently
/// reusing a stale shape.
const COMPAT_ISLAND_SCHEMA: &str = "lpm-compat-island-v1";

/// Sentinel file the linker writes last when publishing a cached island.
/// Its presence marks a complete island (an island dir without it crashed
/// mid-build); its mtime is the island's "last used" stamp for LRU prune.
/// Lives in `lpm-store` so both the linker (writer) and `lpm cache prune`
/// (reader) agree on the layout convention.
pub const COMPAT_ISLAND_COMPLETE_FILENAME: &str = ".lpm-island-complete";

/// One package row folded into [`compat_island_key`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompatIslandKeyEntry<'a> {
    pub dir_name: &'a str,
    pub source_sri: &'a str,
    pub content_integrity: &'a str,
}

/// Derive the filesystem-safe content key for a cached compatibility island
/// from its entry set.
///
/// The key is a SHA-256 over the schema tag plus each package's graph-key
/// dir-name, source SRI, and current link-entry content digest in sorted
/// order. The content digest keeps stable-SRI local sources from reusing an
/// island built from older bytes.
pub fn compat_island_key(entries: &[CompatIslandKeyEntry<'_>]) -> String {
    let mut entries = entries.to_vec();
    entries.sort_unstable_by(|left, right| {
        left.dir_name
            .cmp(right.dir_name)
            .then_with(|| left.source_sri.cmp(right.source_sri))
            .then_with(|| left.content_integrity.cmp(right.content_integrity))
    });
    let mut hasher = Sha256::new();
    hasher.update(COMPAT_ISLAND_SCHEMA.as_bytes());
    hasher.update(b"\0");
    for entry in &entries {
        hasher.update(entry.dir_name.as_bytes());
        hasher.update(b"\0");
        hasher.update(entry.source_sri.as_bytes());
        hasher.update(b"\0");
        hasher.update(entry.content_integrity.as_bytes());
        hasher.update(b"\0");
    }
    hex::encode(hasher.finalize())
}

/// One row yielded by [`Store::iter_link_entries_for_verify`]: the
/// link directory plus either its parsed sidecar or the read/parse/
/// schema/validation failure encountered. Named so the public
/// signature stays readable.
pub type VerifyLinkEntry = (PathBuf, Result<LinkMeta, LpmError>);

/// `node_modules/` sub-name inside each `links/<graph-key>/` entry.
const LINK_NODE_MODULES: &str = "node_modules";

/// Pure path helper for the v2 store layout.
///
/// Holds an immutable handle on the v2 root; every method is a pure
/// path computation (no filesystem access). Useful in tests and in
/// `lpm doctor` / `lpm cache prune` where we want to enumerate
/// expected paths without touching disk.
#[derive(Debug, Clone)]
pub struct StoreV2Paths {
    /// `~/.lpm/store/v2/`
    root: PathBuf,
    /// `~/.lpm/store/v2/objects/` — precomputed to avoid one PathBuf
    /// allocation per `object_dir` call on hot install paths.
    objects_root: PathBuf,
    /// `~/.lpm/store/v2/links/` — precomputed for the same reason.
    links_root: PathBuf,
    /// `~/.lpm/store/v2/compat/` — precomputed for the same reason.
    compat_root: PathBuf,
    /// `~/.lpm/store/v2/builds/` — precomputed for build-cache operations.
    builds_root: PathBuf,
    /// `~/.lpm/store/v2/build-locks/` — precomputed for per-key serialization.
    build_locks_root: PathBuf,
    /// `~/.lpm/store/v2/build-entry-locks/` — precomputed for link-tree mutation.
    build_entry_locks_root: PathBuf,
}

impl StoreV2Paths {
    /// Build the path helper rooted at `<lpm_home>/store/v2/`.
    pub fn from_lpm_root(lpm_root: &LpmRoot) -> Self {
        let root = lpm_root.store_root().join(STORE_V2_VERSION);
        Self::at(root)
    }

    pub fn from_lpm_root_v3(lpm_root: &LpmRoot) -> Self {
        let root = lpm_root.store_root().join(STORE_V3_VERSION);
        Self::at(root)
    }

    /// Build the path helper at an arbitrary base (test seam).
    pub fn at(root: impl Into<PathBuf>) -> Self {
        let root = root.into();
        let objects_root = root.join(OBJECTS_DIR);
        let links_root = root.join(LINKS_DIR);
        let compat_root = root.join(COMPAT_DIR);
        let builds_root = root.join(BUILDS_DIR);
        let build_locks_root = root.join(BUILD_LOCKS_DIR);
        let build_entry_locks_root = root.join(BUILD_ENTRY_LOCKS_DIR);
        Self {
            root,
            objects_root,
            links_root,
            compat_root,
            builds_root,
            build_locks_root,
            build_entry_locks_root,
        }
    }

    /// `~/.lpm/store/v2/`
    ///
    /// `#[inline]` on these small accessors so cross-crate hot-path
    /// callers (linker, install pipeline) skip the call indirection
    /// even without LTO.
    #[inline]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// `~/.lpm/store/v2/objects/`
    #[inline]
    pub fn objects_root(&self) -> PathBuf {
        self.objects_root.clone()
    }

    /// `~/.lpm/store/v2/links/`
    #[inline]
    pub fn links_root(&self) -> PathBuf {
        self.links_root.clone()
    }

    /// `~/.lpm/store/v2/compat/` — root of the cached compatibility islands.
    #[inline]
    pub fn compat_root(&self) -> &Path {
        &self.compat_root
    }

    /// `~/.lpm/store/v2/builds/` — root of lifecycle-build artifacts.
    #[inline]
    pub fn builds_root(&self) -> &Path {
        &self.builds_root
    }

    /// Return the content-addressed directory for a lifecycle-build key.
    #[inline]
    pub fn build_artifact_dir(&self, key: &crate::v2::BuildCacheKey) -> PathBuf {
        self.builds_root.join(key.as_str())
    }

    /// Advisory lock path serializing work for one lifecycle-build key.
    #[inline]
    pub fn build_lock_path(&self, key: &crate::v2::BuildCacheKey) -> PathBuf {
        self.build_lock_path_for_key(key.as_str())
    }

    /// Advisory lock path for a validated hexadecimal build-key string.
    #[inline]
    pub fn build_lock_path_for_key(&self, key: &str) -> PathBuf {
        self.build_locks_root.join(format!("{key}.lock"))
    }

    /// `~/.lpm/store/v2/build-locks/` — per-key advisory locks.
    #[inline]
    pub fn build_locks_root(&self) -> &Path {
        &self.build_locks_root
    }

    /// Advisory lock path serializing mutation of one v2 graph entry.
    #[inline]
    pub fn build_entry_lock_path(&self, graph_key_digest: &str) -> Result<PathBuf, LpmError> {
        if !crate::v2::link_meta::is_lower_hex_digest(graph_key_digest) {
            return Err(LpmError::Store(
                "invalid graph-key digest for build-entry lock".into(),
            ));
        }
        Ok(self
            .build_entry_locks_root
            .join(format!("{graph_key_digest}.lock")))
    }

    /// `~/.lpm/store/v2/build-entry-locks/` — per-graph-entry advisory locks.
    #[inline]
    pub fn build_entry_locks_root(&self) -> &Path {
        &self.build_entry_locks_root
    }

    /// `~/.lpm/store/v2/compat/<island-key>/` — the cached island for a
    /// given entry-set content key. `key` is a hex digest the caller
    /// derives from the island's entry set, so the path is filesystem-safe.
    #[inline]
    pub fn compat_island_dir(&self, key: &str) -> PathBuf {
        self.compat_root.join(key)
    }

    /// `~/.lpm/store/v2/objects/<algo>-<hex>/` for a given SRI.
    ///
    /// Returns [`LpmError::InvalidIntegrity`] if `sri` doesn't parse
    /// as a canonical SRI string.
    #[inline]
    pub fn object_dir(&self, sri: &str) -> Result<PathBuf, LpmError> {
        Ok(self.objects_root.join(sri_to_segment(sri)?))
    }

    /// Path that the sidecar would record for `sri` — the same as
    /// [`Self::object_dir`] but expressed relative to [`Self::root`]
    /// so the on-disk form is `$LPM_HOME`-portable.
    pub fn relative_object_path(&self, sri: &str) -> Result<String, LpmError> {
        Ok(format!("{OBJECTS_DIR}/{}", sri_to_segment(sri)?))
    }

    /// `~/.lpm/store/v2/links/<graph-key>/` for a given key.
    #[inline]
    pub fn link_dir(&self, key: &GraphKey) -> PathBuf {
        self.links_root.join(key.dir_name())
    }

    /// `~/.lpm/store/v2/links/<graph-key>/node_modules/`.
    ///
    /// Pre-sized single-allocation build. The naïve `self.link_dir(key)
    /// .join(LINK_NODE_MODULES)` chain allocates two intermediate
    /// `PathBuf`s; this builds one buffer of the known total length.
    pub fn link_node_modules_dir(&self, key: &GraphKey) -> PathBuf {
        let dir_name = key.dir_name();
        let cap =
            self.links_root.as_os_str().len() + 1 + dir_name.len() + 1 + LINK_NODE_MODULES.len();
        let mut p = PathBuf::with_capacity(cap);
        p.push(&self.links_root);
        p.push(dir_name);
        p.push(LINK_NODE_MODULES);
        p
    }

    /// `~/.lpm/store/v2/links/<graph-key>/node_modules/<pkg>/` —
    /// where the canonical bytes for THIS link entry live. Sibling deps
    /// live alongside as symlinks.
    ///
    /// Pre-sized single-allocation build (see
    /// [`Self::link_node_modules_dir`]). The chained `.join()` shape
    /// allocates three intermediate `PathBuf`s per call.
    pub fn link_package_dir(&self, key: &GraphKey) -> PathBuf {
        let dir_name = key.dir_name();
        let pkg_name = key.name();
        let cap = self.links_root.as_os_str().len()
            + 1
            + dir_name.len()
            + 1
            + LINK_NODE_MODULES.len()
            + 1
            + pkg_name.len();
        let mut p = PathBuf::with_capacity(cap);
        p.push(&self.links_root);
        p.push(dir_name);
        p.push(LINK_NODE_MODULES);
        p.push(pkg_name);
        p
    }
}

/// Convert an SRI integrity string into a filesystem-safe segment
/// (`<algo>-<hex>`). Hex (vs base64) keeps the segment safe on every
/// platform — no `/`, `+`, or `=` characters.
///
/// Single-allocation build via `String::with_capacity` + direct byte
/// writes, avoiding the intermediate `hex::encode` String a naïve
/// `format!` would produce.
fn sri_to_segment(sri: &str) -> Result<String, LpmError> {
    use std::fmt::Write as _;
    let int = Integrity::parse(sri)?;
    let algo = match int.algorithm {
        HashAlgorithm::Sha1 => "sha1",
        HashAlgorithm::Sha256 => "sha256",
        HashAlgorithm::Sha512 => "sha512",
    };
    let mut result = String::with_capacity(algo.len() + 1 + int.hash.len() * 2);
    result.push_str(algo);
    result.push('-');
    for byte in &int.hash {
        let _ = write!(result, "{byte:02x}");
    }
    Ok(result)
}

/// Sibling symlink target known at populate time.
#[derive(Debug, Clone)]
pub struct LinkEntryRequest {
    /// Canonical name of the package being materialized at
    /// `links/<graph-key>/node_modules/<name>/`. Always equals
    /// `graph_key.name()` — kept on the request struct for explicit
    /// readability at call sites.
    pub graph_key: Arc<GraphKey>,
    /// SRI integrity string of the source tarball. Same value the
    /// install pipeline carries from the registry response.
    pub source_sri: String,
    /// Path to the already-extracted object directory at
    /// `objects/<sri>/`. Caller is responsible for ensuring the object
    /// exists (typically via [`Store::extract_object`]).
    pub object_dir: PathBuf,
    /// Sibling-dep targets to materialize as symlinks alongside the
    /// package. Each tuple is
    /// `(local_name, target_graph_key, target_name, target_version)`.
    /// Order is irrelevant; symlinks are created independently.
    pub deps: Vec<DepLink>,
    /// Platform tuple to record in the sidecar.
    pub platform: Arc<LinkMetaPlatform>,
}

/// Object directory that is complete and has verified object identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReusableObject {
    pub path: PathBuf,
    pub object_integrity: VerifiedObjectIntegrity,
}

#[derive(Clone, Debug, Default)]
pub struct ReusableObjectValidationBatch {
    file_cas: Option<FileCasValidationBatch>,
}

/// Object directory just produced or validated by an extraction call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractedObject {
    path: PathBuf,
    source_sri: String,
    object_integrity: FreshObjectIntegrity,
}

/// Single sibling-dep symlink to create inside
/// `links/<graph-key>/node_modules/<dep_local>/`.
#[derive(Debug, Clone)]
pub struct DepLink {
    /// Local name as it should appear in the consumer's `node_modules/`
    /// (e.g. `debug`, or `strip-ansi-cjs` for an aliased dep).
    pub local: String,
    /// Target's [`GraphKey`]. The symlink points at
    /// `../../<target.dir_name>/node_modules/<target.name>/`.
    /// Stored as `Arc` so the key can be shared across multiple consumers
    /// that depend on the same target without cloning the name/version strings.
    pub target: Arc<GraphKey>,
}

impl DepLink {
    fn into_meta_dep(self) -> LinkMetaDep {
        LinkMetaDep {
            local: self.local,
            target_graph_key: self.target.digest_hex(),
            target_name: self.target.name().to_string(),
            target_version: self.target.version().to_string(),
        }
    }
}

/// Result of [`Store::populate_link_entry`].
#[derive(Debug, Clone)]
pub struct LinkEntry {
    /// Final on-disk path: `~/.lpm/store/v2/links/<graph-key>/`.
    pub link_dir: PathBuf,
    /// Whether the entry was newly populated this call (`true`) or
    /// already existed and we short-circuited (`false`).
    pub freshly_populated: bool,
    /// Sidecar payload.
    ///
    /// `Some` only when [`Self::freshly_populated`] is `true`. On a
    /// cache hit, callers that need the sidecar must read it lazily
    /// via [`crate::v2::LinkMeta::read_from`] from [`Self::link_dir`]
    /// — eager read+parse here would cost a JSON round-trip per
    /// package on warm installs (~30 µs × 256 packages adds up).
    pub sidecar: Option<LinkMeta>,
    /// Best-effort wall-clock attribution for this populate call.
    pub timings: LinkEntryTimings,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LinkEntryTimings {
    pub total_ms: u128,
    pub reuse_check_ms: u128,
    pub object_integrity_ms: u128,
    pub materialize_ms: u128,
    pub snapshot_ms: u128,
    pub symlink_ms: u128,
    pub sidecar_ms: u128,
    pub rename_ms: u128,
    pub collision_recovery_ms: u128,
}

/// I/O front-end for the v2 store.
///
/// Holds the [`StoreV2Paths`] and exposes the two write entry points:
/// [`Self::extract_object`] (object population) and
/// [`Self::populate_link_entry`] (link entry + sidecar), plus the
/// read-side helpers below.
#[derive(Debug, Clone)]
pub struct Store {
    paths: StoreV2Paths,
    file_cas: Option<FileCas>,
    migration_paths: Option<StoreV2Paths>,
    object_integrity_policy: ObjectIntegrityPolicy,
    security_analysis_policy: SecurityAnalysisPolicy,
    #[cfg(test)]
    object_publish_barriers: Option<(Arc<std::sync::Barrier>, Arc<std::sync::Barrier>)>,
}

impl Store {
    pub fn from_lpm_root_for_version(lpm_root: &LpmRoot, version: StoreVersion) -> Self {
        Self::from_lpm_root_for_version_with_policies(
            lpm_root,
            version,
            object_integrity_policy_from_env(),
            SecurityAnalysisPolicy::Enabled,
        )
    }

    pub fn from_lpm_root_for_version_with_object_integrity_policy(
        lpm_root: &LpmRoot,
        version: StoreVersion,
        object_integrity_policy: ObjectIntegrityPolicy,
    ) -> Self {
        Self::from_lpm_root_for_version_with_policies(
            lpm_root,
            version,
            object_integrity_policy,
            SecurityAnalysisPolicy::Enabled,
        )
    }

    pub fn from_lpm_root_for_version_with_policies(
        lpm_root: &LpmRoot,
        version: StoreVersion,
        object_integrity_policy: ObjectIntegrityPolicy,
        security_analysis_policy: SecurityAnalysisPolicy,
    ) -> Self {
        if version == StoreVersion::V3 {
            Self::from_lpm_root_v3_with_policies(
                lpm_root,
                object_integrity_policy,
                security_analysis_policy,
            )
        } else {
            Self::from_lpm_root_with_policies(
                lpm_root,
                object_integrity_policy,
                security_analysis_policy,
            )
        }
    }

    /// Resolve the v2 store from the given LPM home.
    pub fn from_lpm_root(lpm_root: &LpmRoot) -> Self {
        Self::from_lpm_root_with_object_integrity_policy(
            lpm_root,
            object_integrity_policy_from_env(),
        )
    }

    pub fn from_lpm_root_with_object_integrity_policy(
        lpm_root: &LpmRoot,
        object_integrity_policy: ObjectIntegrityPolicy,
    ) -> Self {
        Self::from_lpm_root_with_policies(
            lpm_root,
            object_integrity_policy,
            SecurityAnalysisPolicy::Enabled,
        )
    }

    /// Create a v2 store with explicit integrity and source-analysis policies.
    pub fn from_lpm_root_with_policies(
        lpm_root: &LpmRoot,
        object_integrity_policy: ObjectIntegrityPolicy,
        security_analysis_policy: SecurityAnalysisPolicy,
    ) -> Self {
        Self {
            paths: StoreV2Paths::from_lpm_root(lpm_root),
            file_cas: None,
            migration_paths: Some(StoreV2Paths::from_lpm_root_v3(lpm_root)),
            object_integrity_policy,
            security_analysis_policy,
            #[cfg(test)]
            object_publish_barriers: None,
        }
    }

    pub fn from_lpm_root_v3(lpm_root: &LpmRoot) -> Self {
        Self::from_lpm_root_v3_with_policies(
            lpm_root,
            object_integrity_policy_from_env(),
            SecurityAnalysisPolicy::Enabled,
        )
    }

    pub fn from_lpm_root_v3_with_object_integrity_policy(
        lpm_root: &LpmRoot,
        object_integrity_policy: ObjectIntegrityPolicy,
    ) -> Self {
        Self::from_lpm_root_v3_with_policies(
            lpm_root,
            object_integrity_policy,
            SecurityAnalysisPolicy::Enabled,
        )
    }

    pub fn from_lpm_root_v3_with_policies(
        lpm_root: &LpmRoot,
        object_integrity_policy: ObjectIntegrityPolicy,
        security_analysis_policy: SecurityAnalysisPolicy,
    ) -> Self {
        let paths = StoreV2Paths::from_lpm_root_v3(lpm_root);
        let file_cas = Some(FileCas::at(paths.root()));
        Self {
            paths,
            file_cas,
            migration_paths: Some(StoreV2Paths::from_lpm_root(lpm_root)),
            object_integrity_policy,
            security_analysis_policy,
            #[cfg(test)]
            object_publish_barriers: None,
        }
    }

    /// Mount the store at an arbitrary path (test seam).
    pub fn at(root: impl Into<PathBuf>) -> Self {
        Self::at_with_object_integrity_policy(root, object_integrity_policy_from_env())
    }

    pub fn at_with_object_integrity_policy(
        root: impl Into<PathBuf>,
        object_integrity_policy: ObjectIntegrityPolicy,
    ) -> Self {
        Self::at_with_policies(
            root,
            object_integrity_policy,
            SecurityAnalysisPolicy::Enabled,
        )
    }

    /// Create a v2 store at a specific path with explicit policies.
    pub fn at_with_policies(
        root: impl Into<PathBuf>,
        object_integrity_policy: ObjectIntegrityPolicy,
        security_analysis_policy: SecurityAnalysisPolicy,
    ) -> Self {
        Self {
            paths: StoreV2Paths::at(root),
            file_cas: None,
            migration_paths: None,
            object_integrity_policy,
            security_analysis_policy,
            #[cfg(test)]
            object_publish_barriers: None,
        }
    }

    pub fn at_v3(root: impl Into<PathBuf>) -> Self {
        Self::at_v3_with_policies(
            root,
            object_integrity_policy_from_env(),
            SecurityAnalysisPolicy::Enabled,
        )
    }

    pub fn at_v3_with_policies(
        root: impl Into<PathBuf>,
        object_integrity_policy: ObjectIntegrityPolicy,
        security_analysis_policy: SecurityAnalysisPolicy,
    ) -> Self {
        let paths = StoreV2Paths::at(root);
        let file_cas = Some(FileCas::at(paths.root()));
        Self {
            paths,
            file_cas,
            migration_paths: None,
            object_integrity_policy,
            security_analysis_policy,
            #[cfg(test)]
            object_publish_barriers: None,
        }
    }

    #[cfg(test)]
    fn with_object_publish_barriers(
        mut self,
        arrived: Arc<std::sync::Barrier>,
        resume: Arc<std::sync::Barrier>,
    ) -> Self {
        self.object_publish_barriers = Some((arrived, resume));
        self
    }

    /// The path helper this Store wraps.
    pub fn paths(&self) -> &StoreV2Paths {
        &self.paths
    }

    pub fn object_integrity_policy(&self) -> ObjectIntegrityPolicy {
        self.object_integrity_policy
    }

    /// Return the policy used for extraction and cache-hit backfills.
    pub fn security_analysis_policy(&self) -> SecurityAnalysisPolicy {
        self.security_analysis_policy
    }

    fn prepare_file_cas_source(
        &self,
        object_dir: &Path,
        published_object_dir: &Path,
        source_sri: &str,
        local_source: bool,
    ) -> Result<Option<PreparedSourceRecord>, LpmError> {
        self.file_cas
            .as_ref()
            .map(|cas| {
                cas.ingest_object_tree_as(
                    object_dir,
                    published_object_dir,
                    source_sri,
                    local_source,
                )
            })
            .transpose()
    }

    fn finish_file_cas_source(
        &self,
        object_dir: &Path,
        source_sri: &str,
        local_source: bool,
        prepared: Option<&PreparedSourceRecord>,
        policy: ObjectIntegrityPolicy,
    ) -> Result<FileCasSourceFinish, LpmError> {
        self.finish_file_cas_source_with_timings(
            object_dir,
            source_sri,
            local_source,
            policy,
            FileCasFinishContext {
                prepared,
                reuse_timings: None,
                validation_batch: None,
            },
        )
    }

    fn finish_file_cas_source_with_timings(
        &self,
        object_dir: &Path,
        source_sri: &str,
        local_source: bool,
        policy: ObjectIntegrityPolicy,
        context: FileCasFinishContext<'_>,
    ) -> Result<FileCasSourceFinish, LpmError> {
        let FileCasFinishContext {
            prepared,
            reuse_timings,
            validation_batch,
        } = context;
        let Some(cas) = &self.file_cas else {
            return Ok(FileCasSourceFinish::Ready(None));
        };
        if let Some(prepared) = prepared {
            cas.publish_source_record(object_dir, prepared)?;
            return Ok(FileCasSourceFinish::Ready(None));
        }
        let mut cas_timings = FileCasReuseTimings::default();
        let reuse_status = cas.source_reuse_status_with_timings_in_batch(
            object_dir,
            source_sri,
            &mut cas_timings,
            validation_batch.and_then(|batch| batch.file_cas.as_ref()),
        )?;
        if let Some(reuse_timings) = reuse_timings {
            reuse_timings.record_file_cas(cas_timings);
        }
        match reuse_status {
            SourceReuseStatus::Reusable => return Ok(FileCasSourceFinish::Ready(None)),
            SourceReuseStatus::CorruptBlob => {
                remove_unusable_object_dir(object_dir, "after v3 CAS blob corruption")?;
                return Ok(FileCasSourceFinish::Unusable);
            }
            SourceReuseStatus::MissingOrInvalid => {}
        }
        let snapshot_is_valid = read_tree_snapshot(object_dir)
            .map(|snapshot| current_tree_content_matches_snapshot(object_dir, &snapshot))
            .transpose()?
            .flatten()
            .is_some();
        if !snapshot_is_valid {
            remove_unusable_object_dir(object_dir, "before v3 CAS metadata reconstruction")?;
            return Ok(FileCasSourceFinish::Unusable);
        }
        let prepared = cas.ingest_object_tree(object_dir, source_sri, local_source)?;
        let integrities = write_object_integrity_for_policy(object_dir, source_sri, policy)?;
        cas.publish_source_record(object_dir, &prepared)?;
        Ok(FileCasSourceFinish::Ready(Some(
            VerifiedObjectIntegrity::new(integrities.content),
        )))
    }

    fn try_migrate_prior_virtual_object(
        &self,
        source_sri: &str,
        policy: ObjectIntegrityPolicy,
    ) -> Result<bool, LpmError> {
        let Some(prior_paths) = &self.migration_paths else {
            return Ok(false);
        };
        let source_dir = prior_paths.object_dir(source_sri)?;
        if !is_complete_object_dir(&source_dir) || has_local_source_sentinel(&source_dir) {
            return Ok(false);
        }
        let stored_sri = match std::fs::read_to_string(source_dir.join(".integrity")) {
            Ok(stored_sri) => stored_sri,
            Err(error) => {
                tracing::debug!(
                    target = %source_dir.display(),
                    "prior virtual-store object is not migration-safe: {error}"
                );
                return Ok(false);
            }
        };
        if stored_sri.trim() != source_sri {
            return Ok(false);
        }
        let expected = match read_object_integrity(&source_dir) {
            Ok(expected) => expected,
            Err(error) => {
                tracing::debug!(
                    target = %source_dir.display(),
                    "prior virtual-store object is not migration-safe: {error}"
                );
                return Ok(false);
            }
        };
        let valid = if matches!(policy, ObjectIntegrityPolicy::Source) {
            expected == source_object_integrity(source_sri)
        } else {
            match compute_object_tree_integrities(&source_dir) {
                Ok(actual) => actual.content == expected,
                Err(error) => {
                    tracing::debug!(
                        target = %source_dir.display(),
                        "prior virtual-store object is not migration-safe: {error}"
                    );
                    false
                }
            }
        };
        if !valid {
            return Ok(false);
        }
        self.populate_object_from_existing_tree(
            &source_dir,
            source_sri,
            "virtual-store generation migration",
        )?;
        Ok(true)
    }

    /// Ensure the cached compatibility-island root exists with store-tier
    /// permissions.
    pub fn ensure_compat_root_locked(&self) -> Result<(), LpmError> {
        ensure_store_tier_dir_locked(self.paths.compat_root()).map_err(|e| {
            LpmError::Store(format!(
                "failed to create virtual-store compat islands dir at {}: {e}",
                self.paths.compat_root().display()
            ))
        })
    }

    /// Serialize mutation of one graph-keyed link entry across installs and
    /// lifecycle rebuilds.
    pub fn acquire_build_entry_lock(
        &self,
        graph_key_digest: &str,
    ) -> Result<lpm_common::SingleFileExclusiveLockHandle, LpmError> {
        ensure_store_tier_dir_locked(self.paths.build_entry_locks_root()).map_err(|error| {
            LpmError::Store(format!(
                "failed to create virtual-store build-entry locks dir: {error}"
            ))
        })?;
        let lock_path = self.paths.build_entry_lock_path(graph_key_digest)?;
        lpm_common::acquire_single_file_exclusive_lock(lock_path)
    }

    fn acquire_build_entry_read_lock(
        &self,
        graph_key_digest: &str,
    ) -> Result<lpm_common::SingleFileSharedLockHandle, LpmError> {
        ensure_store_tier_dir_locked(self.paths.build_entry_locks_root()).map_err(|error| {
            LpmError::Store(format!(
                "failed to create virtual-store build-entry locks dir: {error}"
            ))
        })?;
        let lock_path = self.paths.build_entry_lock_path(graph_key_digest)?;
        lpm_common::acquire_single_file_shared_lock(lock_path)
    }

    /// Return the object directory when `sri` is already present and
    /// its object identity is reusable. Incomplete or stale
    /// objects are removed so callers can safely refetch before
    /// linking.
    pub fn reusable_object_dir(&self, sri: &str) -> Result<Option<PathBuf>, LpmError> {
        Ok(self.reusable_object(sri)?.map(|object| object.path))
    }

    /// Return the object directory plus the verified object digest.
    pub fn reusable_object(&self, sri: &str) -> Result<Option<ReusableObject>, LpmError> {
        self.reusable_object_with_policy(sri, self.object_integrity_policy)
    }

    fn reusable_object_with_policy(
        &self,
        sri: &str,
        policy: ObjectIntegrityPolicy,
    ) -> Result<Option<ReusableObject>, LpmError> {
        let object_dir = self.paths.object_dir(sri)?;
        if !object_dir.exists() && !self.try_migrate_prior_virtual_object(sri, policy)? {
            return Ok(None);
        }
        let Some(mut object_integrity) =
            object_integrity_or_remove(&object_dir, "before cache reuse", sri, policy)?
        else {
            return Ok(None);
        };
        match self.finish_file_cas_source(
            &object_dir,
            sri,
            has_local_source_sentinel(&object_dir),
            None,
            policy,
        )? {
            FileCasSourceFinish::Ready(Some(refreshed)) => object_integrity = refreshed,
            FileCasSourceFinish::Ready(None) => {}
            FileCasSourceFinish::Unusable => return Ok(None),
        }
        self.backfill_security_cache_if_enabled(&object_dir, sri);
        Ok(Some(ReusableObject {
            path: object_dir,
            object_integrity,
        }))
    }

    /// Return the reusable object and timing counters for its validation path.
    pub fn reusable_object_with_timings(
        &self,
        sri: &str,
    ) -> Result<(Option<ReusableObject>, ReusableObjectCheckTimings), LpmError> {
        self.reusable_object_with_timings_and_policy(sri, self.object_integrity_policy, None)
    }

    pub fn reusable_object_validation_batch(&self) -> ReusableObjectValidationBatch {
        ReusableObjectValidationBatch {
            file_cas: self
                .file_cas
                .as_ref()
                .map(|_| FileCasValidationBatch::default()),
        }
    }

    pub fn reusable_object_with_timings_in_batch(
        &self,
        sri: &str,
        batch: &ReusableObjectValidationBatch,
    ) -> Result<(Option<ReusableObject>, ReusableObjectCheckTimings), LpmError> {
        self.reusable_object_with_timings_and_policy(sri, self.object_integrity_policy, Some(batch))
    }

    fn reusable_object_with_timings_and_policy(
        &self,
        sri: &str,
        policy: ObjectIntegrityPolicy,
        validation_batch: Option<&ReusableObjectValidationBatch>,
    ) -> Result<(Option<ReusableObject>, ReusableObjectCheckTimings), LpmError> {
        let total_start = std::time::Instant::now();
        let mut timings = ReusableObjectCheckTimings::default();
        let object_dir = self.paths.object_dir(sri)?;
        if !object_dir.exists() && !self.try_migrate_prior_virtual_object(sri, policy)? {
            timings.missing_count = 1;
            timings.total_ms = total_start.elapsed().as_millis();
            return Ok((None, timings));
        }
        let Some(mut object_integrity) = object_integrity_or_remove_with_timings(
            &object_dir,
            "before cache reuse",
            sri,
            &mut timings,
            policy,
        )?
        else {
            timings.total_ms = total_start.elapsed().as_millis();
            return Ok((None, timings));
        };
        match self.finish_file_cas_source_with_timings(
            &object_dir,
            sri,
            has_local_source_sentinel(&object_dir),
            policy,
            FileCasFinishContext {
                prepared: None,
                reuse_timings: Some(&mut timings),
                validation_batch,
            },
        )? {
            FileCasSourceFinish::Ready(Some(refreshed)) => object_integrity = refreshed,
            FileCasSourceFinish::Ready(None) => {}
            FileCasSourceFinish::Unusable => {
                timings.removed_count = timings.removed_count.saturating_add(1);
                timings.total_ms = total_start.elapsed().as_millis();
                return Ok((None, timings));
            }
        }
        self.backfill_security_cache_if_enabled(&object_dir, sri);
        timings.total_ms = total_start.elapsed().as_millis();
        Ok((
            Some(ReusableObject {
                path: object_dir,
                object_integrity,
            }),
            timings,
        ))
    }

    /// Extract the supplied tarball bytes into
    /// `objects/<algo>-<hex>/`, optionally run behavioral security analysis,
    /// and atomically rename into place. Idempotent: returns the existing
    /// object dir if it's already populated.
    ///
    /// Atomic via the standard `dir.with_extension(tmp.<pid>.<tid>)` →
    /// `rename` pattern. `.integrity` and, when source analysis is enabled,
    /// `.lpm-security.json` are staged inside the tmp dir before the rename.
    ///
    /// When enabled, behavioral security analysis lives next to the OBJECT,
    /// not next to each link entry — the analysis is a property of the
    /// content bytes, so link entries sharing a `source_sri` share the
    /// result. This matches v1's placement at
    /// `<HOME>/.lpm/store/v1/<pkg>/<version>/.lpm-security.json`.
    ///
    /// Uses the fused extractor+analyzer path:
    /// `PackageAnalyzer::should_scan` filters scannable source entries
    /// during the tar walk, and the inspector closure feeds their
    /// bytes into the analyzer while still in the extractor's write
    /// buffer. Eliminates the post-extract directory walk and the
    /// per-source-file disk re-read of the unfused path.
    pub fn extract_object(&self, sri: &str, tarball_data: &[u8]) -> Result<PathBuf, LpmError> {
        Ok(self.extract_object_with_timings(sri, tarball_data)?.0)
    }

    /// Same as [`Self::extract_object`] plus a [`StageTimings`]
    /// breakdown. Used by the install pipeline so `lpm install --json`
    /// keeps emitting an extract / security / finalize split under v2
    /// mode that's shape-compatible with the v1 telemetry. On the
    /// store-hit fast path every field is zero.
    pub fn extract_object_with_timings(
        &self,
        sri: &str,
        tarball_data: &[u8],
    ) -> Result<(PathBuf, StageTimings), LpmError> {
        self.extract_object_with_timings_and_policy(sri, tarball_data, self.object_integrity_policy)
            .map(|(object, timings)| (object.path, timings))
    }

    /// Same as [`Self::extract_object_with_timings`], but returns the
    /// fresh object handle produced by this extraction. Install's
    /// event-driven v2 linker uses this only for the immediate fresh
    /// link-entry populate, avoiding a second object validation pass.
    pub fn extract_object_with_timings_and_fresh_integrity(
        &self,
        sri: &str,
        tarball_data: &[u8],
    ) -> Result<(ExtractedObject, StageTimings), LpmError> {
        self.extract_object_with_timings_and_policy(sri, tarball_data, self.object_integrity_policy)
    }

    /// Extract a verified tarball file without materializing its compressed
    /// bytes in memory.
    pub fn extract_object_from_file(
        &self,
        tarball_path: &Path,
        expected_integrity: &str,
    ) -> Result<(PathBuf, StageTimings), LpmError> {
        let expected = Integrity::parse(expected_integrity)?;
        expected.verify_file(tarball_path)?;
        let file = std::fs::File::open(tarball_path).map_err(LpmError::Io)?;
        self.extract_object_from_input_with_policy(
            expected_integrity,
            TarballInput::File(std::io::BufReader::new(file)),
            self.object_integrity_policy,
        )
        .map(|(object, timings)| (object.path, timings))
    }

    /// Extract a downloaded file-backed tarball and return the fresh object
    /// proof used by same-task link population. The caller must supply the
    /// SHA-512 SRI computed while writing this exact file. The object key is
    /// therefore canonical, independent of the declaration's algorithm.
    pub fn extract_object_from_file_with_fresh_integrity(
        &self,
        tarball_path: &Path,
        canonical_sri: &str,
        expected_integrity: Option<&str>,
    ) -> Result<(ExtractedObject, String, StageTimings), LpmError> {
        self.extract_object_from_file_with_fresh_integrity_timed(
            tarball_path,
            canonical_sri,
            expected_integrity,
        )
        .map(|(object, sri, timings, _)| (object, sri, timings))
    }

    /// File-backed extraction with the integrity-verification wall time.
    pub fn extract_object_from_file_with_fresh_integrity_timed(
        &self,
        tarball_path: &Path,
        canonical_sri: &str,
        expected_integrity: Option<&str>,
    ) -> Result<(ExtractedObject, String, StageTimings, u128), LpmError> {
        if Integrity::parse(canonical_sri)?.algorithm != HashAlgorithm::Sha512 {
            return Err(LpmError::InvalidIntegrity(
                "virtual-store object identity must use sha512".to_string(),
            ));
        }
        let expected = expected_integrity
            .filter(|expected| *expected != canonical_sri)
            .map(Integrity::parse)
            .transpose()?;
        let verification_start = std::time::Instant::now();
        if let Some(expected) = &expected {
            expected.verify_file(tarball_path)?;
        }
        let verification_ms = verification_start.elapsed().as_millis();
        let file = std::fs::File::open(tarball_path).map_err(LpmError::Io)?;
        let (object, timings) = self.extract_object_from_input_with_policy(
            canonical_sri,
            TarballInput::File(std::io::BufReader::new(file)),
            self.object_integrity_policy,
        )?;
        Ok((object, canonical_sri.to_string(), timings, verification_ms))
    }

    fn extract_object_with_timings_and_policy(
        &self,
        sri: &str,
        tarball_data: &[u8],
        policy: ObjectIntegrityPolicy,
    ) -> Result<(ExtractedObject, StageTimings), LpmError> {
        self.extract_object_from_input_with_policy(sri, TarballInput::Bytes(tarball_data), policy)
    }

    fn extract_object_from_input_with_policy(
        &self,
        sri: &str,
        tarball_input: TarballInput<'_>,
        policy: ObjectIntegrityPolicy,
    ) -> Result<(ExtractedObject, StageTimings), LpmError> {
        let object_dir = self.paths.object_dir(sri)?;
        let mut timings = StageTimings::default();

        if !object_dir.exists() {
            self.try_migrate_prior_virtual_object(sri, policy)?;
        }

        // Mirrors v1's `store_at_dir` recovery: a leftover `objects/<sri>/`
        // from a crashed extract (no `.integrity`, no `package.json`) is
        // NOT a hit — remove it and re-extract. Without this, a partial
        // crash leaves the install pipeline returning success on a
        // half-populated object dir and downstream link entries inherit
        // the corruption.
        if object_dir.exists()
            && let Some(mut object_integrity) =
                object_integrity_or_remove(&object_dir, "before re-extract", sri, policy)?
        {
            let reusable = match self.finish_file_cas_source(
                &object_dir,
                sri,
                has_local_source_sentinel(&object_dir),
                None,
                policy,
            )? {
                FileCasSourceFinish::Ready(Some(refreshed)) => {
                    object_integrity = refreshed;
                    true
                }
                FileCasSourceFinish::Ready(None) => true,
                FileCasSourceFinish::Unusable => false,
            };
            if reusable {
                self.backfill_security_cache_if_enabled(&object_dir, sri);
                tracing::debug!(
                    target = %object_dir.display(),
                    "virtual store: object hit"
                );
                return Ok((
                    ExtractedObject {
                        path: object_dir,
                        source_sri: sri.to_string(),
                        object_integrity: FreshObjectIntegrity::new(object_integrity),
                    },
                    timings,
                ));
            }
        }

        if let Some(parent) = object_dir.parent() {
            ensure_store_tier_dir_locked(parent).map_err(|e| {
                LpmError::Store(format!("failed to create virtual-store objects dir: {e}"))
            })?;
        }

        let tmp_dir = tmp_sibling(&object_dir);
        if tmp_dir.exists() {
            let _ = std::fs::remove_dir_all(&tmp_dir);
        }
        create_tmp_dir_locked(&tmp_dir).map_err(|e| {
            LpmError::Store(format!(
                "failed to create virtual-store tmp staging dir: {e}"
            ))
        })?;

        // Fused extract + behavioral scan in a single pass: small source
        // entries are buffered and fed directly into the analyzer, while
        // oversized source entries stream to disk first and then get a
        // bounded head/tail sample. The post-extract `finalize` only reads
        // `package.json` for manifest-level tags.
        //
        // `RefCell` wraps the analyzer so the `FnMut` closure can mutate
        // it without exclusive borrows escaping the call site.
        let extract_start = std::time::Instant::now();
        let source_analysis_enabled = self.security_analysis_policy.is_enabled();
        let analyzer = std::cell::RefCell::new(lpm_security::behavioral::PackageAnalyzer::new());
        let extracted_stats = std::cell::RefCell::new(ExtractedObjectStats::default());
        let registry_cas_ingest = self
            .file_cas
            .as_ref()
            .map(|cas| cas.begin_registry_ingest(&object_dir, sri))
            .transpose()?
            .map(std::cell::RefCell::new);
        let registry_cas_error = std::cell::RefCell::new(None);
        let inspect_entry = |entry: lpm_extractor::EntryInfo<'_>| {
            if registry_cas_error.borrow().is_none()
                && let (Some(ingest), Some(cas)) =
                    (registry_cas_ingest.as_ref(), self.file_cas.as_ref())
            {
                let result = entry
                    .blake3_digest
                    .ok_or_else(|| {
                        LpmError::Store(format!(
                            "v3 CAS extraction omitted a digest for {}",
                            entry.relative_path.display()
                        ))
                    })
                    .and_then(|digest| {
                        cas.ingest_registry_file(
                            &mut ingest.borrow_mut(),
                            &tmp_dir,
                            entry.relative_path,
                            entry.size,
                            digest,
                        )
                    });
                if let Err(error) = result {
                    *registry_cas_error.borrow_mut() = Some(error);
                }
            }
            extracted_stats
                .borrow_mut()
                .record_file(entry.relative_path, entry.size);
            if !source_analysis_enabled {
                return;
            }
            if let Some(bytes) = entry.bytes {
                analyzer.borrow_mut().feed(entry.relative_path, bytes);
            } else {
                analyzer.borrow_mut().feed_oversized_source_file(
                    entry.relative_path,
                    &tmp_dir.join(entry.relative_path),
                    entry.size,
                );
            }
        };
        let buffer_predicate = |path: &Path, size: u64| {
            source_analysis_enabled
                && lpm_security::behavioral::PackageAnalyzer::should_buffer_source(path, size)
        };
        let extract_result = match (tarball_input, registry_cas_ingest.is_some()) {
            (TarballInput::Bytes(bytes), true) => {
                lpm_extractor::extract_tarball_with_entry_digests(
                    bytes,
                    &tmp_dir,
                    buffer_predicate,
                    inspect_entry,
                )
            }
            (TarballInput::Bytes(bytes), false) => lpm_extractor::extract_tarball_with_inspector(
                bytes,
                &tmp_dir,
                buffer_predicate,
                inspect_entry,
            ),
            (TarballInput::File(reader), true) => {
                lpm_extractor::extract_tarball_from_reader_hybrid_with_entry_digests(
                    reader,
                    &tmp_dir,
                    buffer_predicate,
                    inspect_entry,
                )
            }
            (TarballInput::File(reader), false) => {
                lpm_extractor::extract_tarball_from_reader_hybrid_with_inspector(
                    reader,
                    &tmp_dir,
                    buffer_predicate,
                    inspect_entry,
                )
            }
        };
        if let Err(error) = extract_result {
            let _ = std::fs::remove_dir_all(&tmp_dir);
            return Err(error);
        }
        if let Some(error) = registry_cas_error.into_inner() {
            let _ = std::fs::remove_dir_all(&tmp_dir);
            return Err(error);
        }
        timings.extract_ms = extract_start.elapsed().as_millis();

        // Manifest-level analysis + cache write. Done BEFORE the atomic
        // rename so the cache file is part of the atomically-published
        // state. Analysis failures are non-fatal: warn and continue
        // (subsequent installs will retry).
        if source_analysis_enabled {
            let security_start = std::time::Instant::now();
            let analyzer = analyzer.into_inner();
            timings.source_scan_ns = analyzer.source_scan_ns();
            let analysis = analyzer.finalize(&tmp_dir);
            if let Err(e) = lpm_security::behavioral::write_cached_analysis(&tmp_dir, &analysis) {
                tracing::warn!(
                    target = %tmp_dir.display(),
                    "virtual store: failed to write .lpm-security.json: {e}"
                );
            }
            timings.security_ms = security_start.elapsed().as_millis();
        }

        let finalize_permit_wait_start = std::time::Instant::now();
        let _finalize_permit = v2_finalize_limiter().map(|limiter| limiter.acquire());
        timings.finalize_permit_wait_ms = finalize_permit_wait_start.elapsed().as_millis();

        let prepared_cas = match registry_cas_ingest {
            Some(ingest) => self
                .file_cas
                .as_ref()
                .map(|cas| cas.finish_registry_ingest(ingest.into_inner()))
                .transpose(),
            None => Ok(None),
        };
        let prepared_cas = match prepared_cas {
            Ok(prepared) => prepared,
            Err(error) => {
                let _ = std::fs::remove_dir_all(&tmp_dir);
                return Err(error);
            }
        };

        // Persist the SRI alongside the object bytes for
        // post-extraction integrity verification — same `.integrity`
        // file as v1 so `lpm store verify --deep` keeps working in
        // mixed-v1/v2 environments. Also load-bearing for
        // [`is_complete_object_dir`]'s incompleteness probe.
        let finalize_start = std::time::Instant::now();
        let object_integrity_start = std::time::Instant::now();
        let integrities = match write_object_integrity_for_policy(&tmp_dir, sri, policy) {
            Ok(integrities) => integrities,
            Err(e) => {
                let _ = std::fs::remove_dir_all(&tmp_dir);
                return Err(e);
            }
        };
        timings.finalize_tree_integrity_ms = object_integrity_start.elapsed().as_millis();
        let stats = if matches!(policy, ObjectIntegrityPolicy::Source) {
            extracted_stats.into_inner().finish()
        } else {
            integrities.stats
        };
        timings.file_count = stats.file_count;
        timings.dir_count = stats.dir_count;
        timings.symlink_count = stats.symlink_count;
        timings.unpacked_bytes = stats.unpacked_bytes;
        let object_integrity =
            FreshObjectIntegrity::new(VerifiedObjectIntegrity::new(integrities.content));

        let integrity_write_start = std::time::Instant::now();
        let integrity_result = std::fs::write(tmp_dir.join(".integrity"), sri);
        timings.finalize_integrity_write_ms = integrity_write_start.elapsed().as_millis();
        if let Err(e) = integrity_result {
            let _ = std::fs::remove_dir_all(&tmp_dir);
            return Err(LpmError::Store(format!(
                "failed to write virtual-store .integrity: {e}"
            )));
        }

        #[cfg(test)]
        if let Some((arrived, resume)) = &self.object_publish_barriers {
            arrived.wait();
            resume.wait();
        }
        let rename_start = std::time::Instant::now();
        let rename_result = std::fs::rename(&tmp_dir, &object_dir);
        timings.finalize_rename_ms = rename_start.elapsed().as_millis();
        let result = match rename_result {
            Ok(()) => {
                if matches!(
                    self.finish_file_cas_source(
                        &object_dir,
                        sri,
                        false,
                        prepared_cas.as_ref(),
                        policy,
                    )?,
                    FileCasSourceFinish::Unusable
                ) {
                    return Err(LpmError::Store(format!(
                        "freshly extracted v3 CAS source became unusable at {}",
                        object_dir.display()
                    )));
                }
                Ok(ExtractedObject {
                    path: object_dir,
                    source_sri: sri.to_string(),
                    object_integrity,
                })
            }
            Err(e) => {
                let collision_start = std::time::Instant::now();
                let result = finish_object_rename_after_collision(
                    &tmp_dir,
                    &object_dir,
                    sri,
                    "virtual-store extract",
                    e,
                    policy,
                );
                timings.finalize_collision_recovery_ms = collision_start.elapsed().as_millis();
                let object_dir = result?;
                let mut object_integrity = object_integrity_or_remove(
                    &object_dir,
                    "after virtual-store extract collision",
                    sri,
                    policy,
                )?
                .ok_or_else(|| {
                    LpmError::Store(format!(
                        "virtual-store extract collision left no reusable object at {}",
                        object_dir.display()
                    ))
                })?;
                match self.finish_file_cas_source(&object_dir, sri, false, None, policy)? {
                    FileCasSourceFinish::Ready(Some(refreshed)) => {
                        object_integrity = refreshed;
                    }
                    FileCasSourceFinish::Ready(None) => {}
                    FileCasSourceFinish::Unusable => {
                        return Err(LpmError::Store(format!(
                            "v3 CAS extract collision left no reusable object at {}",
                            object_dir.display()
                        )));
                    }
                }
                self.backfill_security_cache_if_enabled(&object_dir, sri);
                Ok(ExtractedObject {
                    path: object_dir,
                    source_sri: sri.to_string(),
                    object_integrity: FreshObjectIntegrity::new(object_integrity),
                })
            }
        };
        timings.finalize_ms = finalize_start.elapsed().as_millis();

        result.map(|object| (object, timings))
    }

    /// Extract from a buffered byte slice when the SRI isn't known
    /// upfront. Hashes the bytes (SHA-512), verifies against
    /// `expected_integrity` if provided, then delegates to
    /// [`Self::extract_object_with_timings`].
    ///
    /// This remains the byte-slice entry point for callers that already own
    /// an archive buffer. Install downloads use the file-backed sibling so
    /// compressed bodies do not accumulate on the heap.
    ///
    /// `expected_integrity` is the registry-supplied SRI. If `Some`
    /// and uses SHA-1, SHA-256, or SHA-512, mismatch returns
    /// [`LpmError::IntegrityMismatch`].
    pub fn extract_object_from_bytes(
        &self,
        tarball_data: &[u8],
        expected_integrity: Option<&str>,
    ) -> Result<(PathBuf, String, StageTimings), LpmError> {
        self.extract_object_from_bytes_with_fresh_integrity(tarball_data, expected_integrity)
            .map(|(object, sri, timings)| (object.path, sri, timings))
    }

    /// Same as [`Self::extract_object_from_bytes`], but returns the
    /// fresh object handle for same-task link-entry population.
    pub fn extract_object_from_bytes_with_fresh_integrity(
        &self,
        tarball_data: &[u8],
        expected_integrity: Option<&str>,
    ) -> Result<(ExtractedObject, String, StageTimings), LpmError> {
        self.extract_object_from_bytes_with_policy(
            tarball_data,
            expected_integrity,
            self.object_integrity_policy,
        )
    }

    fn extract_object_from_bytes_with_policy(
        &self,
        tarball_data: &[u8],
        expected_integrity: Option<&str>,
        policy: ObjectIntegrityPolicy,
    ) -> Result<(ExtractedObject, String, StageTimings), LpmError> {
        let computed_sri = crate::compute_sri_hash(tarball_data);

        // Verify against the algorithm declared in `expected`.
        // The v2 path mirrors v1: sha512 stays the canonical algorithm
        // (`computed_sri`), sha256 is computed on-demand from the
        // already-buffered tarball bytes when the lockfile declares it.
        // Pre-fix the non-sha512 path silently trusted the computed
        // sha512 — letting a coerced lockfile pass without any check.
        if let Some(expected) = expected_integrity {
            use subtle::ConstantTimeEq;
            let candidate_owned;
            let candidate = if expected.starts_with("sha512-") {
                &computed_sri
            } else if expected.starts_with("sha256-") {
                candidate_owned = crate::compute_sri_hash_sha256(tarball_data);
                &candidate_owned
            } else if expected.starts_with("sha1-") {
                candidate_owned = crate::compute_sri_hash_sha1(tarball_data);
                &candidate_owned
            } else {
                return Err(LpmError::Registry(format!(
                    "unsupported integrity algorithm in virtual-store extract: {expected} — \
                     expected sha512-… (preferred), sha256-…, or sha1-…"
                )));
            };
            let matches_expected = expected.len() == candidate.len()
                && expected.as_bytes().ct_eq(candidate.as_bytes()).into();
            if !matches_expected {
                return Err(LpmError::IntegrityMismatch {
                    expected: expected.to_string(),
                    actual: candidate.to_string(),
                });
            }
        }

        let (object, timings) =
            self.extract_object_with_timings_and_policy(&computed_sri, tarball_data, policy)?;
        Ok((object, computed_sri, timings))
    }

    /// Populate `links/<graph-key>/` with the package bytes, sibling
    /// symlinks, and sidecar metadata. Idempotent: if the entry is
    /// already complete and its package tree still matches the source
    /// object identity, refreshes [`LinkMeta::last_referenced_at`] and
    /// short-circuits.
    ///
    /// Atomicity contract:
    /// - Final visible state is created via
    ///   `links/<graph-key>.tmp.<pid>.<tid>/` → atomic rename.
    /// - The sidecar is written INSIDE the tmp dir before the rename,
    ///   so the published entry already has its `.lpm-link-meta.json`
    ///   on first visibility — no observer can see a half-populated
    ///   entry with missing metadata.
    /// - On any error mid-way, the tmp dir is cleaned up before
    ///   returning.
    pub fn populate_link_entry(&self, request: LinkEntryRequest) -> Result<LinkEntry, LpmError> {
        self.populate_link_entry_inner(request, None, None, self.object_integrity_policy)
    }

    /// Populate a link entry using a previously verified object digest.
    pub fn populate_link_entry_with_verified_object(
        &self,
        request: LinkEntryRequest,
        verified_object_integrity: &VerifiedObjectIntegrity,
    ) -> Result<LinkEntry, LpmError> {
        self.populate_link_entry_inner(
            request,
            Some(verified_object_integrity),
            None,
            self.object_integrity_policy,
        )
    }

    /// Populate a link entry immediately after this install extracted
    /// the object and computed its object digest.
    pub fn populate_link_entry_with_fresh_object(
        &self,
        request: LinkEntryRequest,
        fresh_object: &ExtractedObject,
    ) -> Result<LinkEntry, LpmError> {
        if fresh_object.source_sri != request.source_sri {
            return Err(LpmError::Store(format!(
                "fresh virtual-store link extracted object SRI mismatch: fresh {}, request {}",
                fresh_object.source_sri, request.source_sri
            )));
        }
        let expected_object_dir = self.paths.object_dir(&request.source_sri)?;
        if request.object_dir != expected_object_dir {
            return Err(LpmError::Store(format!(
                "fresh virtual-store link request object path mismatch for {}: request {}, expected {}",
                request.source_sri,
                request.object_dir.display(),
                expected_object_dir.display()
            )));
        }
        if fresh_object.path != expected_object_dir {
            return Err(LpmError::Store(format!(
                "fresh virtual-store link extracted object path mismatch for {}: fresh {}, expected {}",
                request.source_sri,
                fresh_object.path.display(),
                expected_object_dir.display()
            )));
        }
        self.populate_link_entry_inner(
            request,
            Some(fresh_object.object_integrity.as_verified()),
            Some(&fresh_object.object_integrity),
            self.object_integrity_policy,
        )
    }

    fn populate_link_entry_inner(
        &self,
        request: LinkEntryRequest,
        verified_object_digest: Option<&VerifiedObjectIntegrity>,
        fresh_object_digest: Option<&FreshObjectIntegrity>,
        policy: ObjectIntegrityPolicy,
    ) -> Result<LinkEntry, LpmError> {
        let total_start = std::time::Instant::now();
        let mut timings = LinkEntryTimings::default();
        let LinkEntryRequest {
            graph_key,
            source_sri,
            object_dir,
            deps,
            platform,
        } = request;

        let final_dir = self.paths.link_dir(&graph_key);
        let sidecar_dir_relpath = self.paths.relative_object_path(&source_sri)?;
        let cas_tree_digest = self
            .file_cas
            .as_ref()
            .map(|cas| cas.source_tree_digest(&object_dir, &source_sri))
            .transpose()?;

        if final_dir.exists() {
            let _entry_read_lock = self.acquire_build_entry_read_lock(&graph_key.digest_hex())?;
            let reuse_check_start = std::time::Instant::now();
            if link_entry_is_reusable(
                &final_dir,
                &graph_key,
                &object_dir,
                &source_sri,
                verified_object_digest,
                cas_tree_digest.as_deref(),
                policy,
            )? {
                timings.reuse_check_ms = reuse_check_start.elapsed().as_millis();
                return Ok(Self::reused_link_entry(final_dir, total_start, timings));
            }
            timings.reuse_check_ms = reuse_check_start.elapsed().as_millis();
        }

        let _entry_lock = self.acquire_build_entry_lock(&graph_key.digest_hex())?;

        // Mirrors the v1 store's "incomplete-on-disk → remove and
        // re-populate" recovery (lib.rs:303-315). Without it, a crash
        // mid-populate leaves a partial `links/<graph-key>/` that
        // either masquerades as complete (sidecar lingered, but the
        // package dir got truncated) or causes the subsequent rename
        // to hard-fail with ENOTEMPTY against a non-empty leftover.
        if final_dir.exists() {
            let reuse_check_start = std::time::Instant::now();
            if link_entry_is_reusable(
                &final_dir,
                &graph_key,
                &object_dir,
                &source_sri,
                verified_object_digest,
                cas_tree_digest.as_deref(),
                policy,
            )? {
                timings.reuse_check_ms = reuse_check_start.elapsed().as_millis();
                return Ok(Self::reused_link_entry(final_dir, total_start, timings));
            }
            timings.reuse_check_ms = reuse_check_start.elapsed().as_millis();

            tracing::warn!(
                target = %final_dir.display(),
                "virtual store: incomplete or stale link entry; removing before re-populate"
            );
            std::fs::remove_dir_all(&final_dir).map_err(|e| {
                LpmError::Store(format!(
                    "failed to remove incomplete or stale virtual-store link entry at {}: {e}",
                    final_dir.display()
                ))
            })?;
        }

        let materialize_dir = self
            .file_cas
            .as_ref()
            .map(|cas| {
                cas.link_materialization_source(
                    &object_dir,
                    &source_sri,
                    fresh_object_digest.is_some() || verified_object_digest.is_some(),
                )
            })
            .transpose()?;
        let materialize_dir = materialize_dir.as_deref().unwrap_or(&object_dir);

        if let Some(parent) = final_dir.parent() {
            ensure_store_tier_dir_locked(parent).map_err(|e| {
                LpmError::Store(format!("failed to create virtual-store links dir: {e}"))
            })?;
        }

        let tmp_dir = tmp_sibling(&final_dir);
        if tmp_dir.exists() {
            let _ = std::fs::remove_dir_all(&tmp_dir);
        }
        create_tmp_dir_locked(&tmp_dir).map_err(|e| {
            LpmError::Store(format!(
                "failed to create virtual-store tmp staging dir: {e}"
            ))
        })?;

        // Run the atomic-staging body in a closure so a single error
        // path can clean up the tmp dir uniformly. Anything that
        // fails inside `populate_into` removes `tmp_dir` and surfaces
        // the original error.
        let result = populate_into(
            &tmp_dir,
            &graph_key,
            PopulateObject {
                dir: &object_dir,
                materialize_dir,
                source_sri: &source_sri,
                sidecar_relpath: &sidecar_dir_relpath,
                policy,
                fresh_object_integrity: fresh_object_digest,
                tree_digest: cas_tree_digest.as_deref(),
            },
            &deps,
            &platform,
        );

        let sidecar = match result {
            Ok(populated) => {
                timings.object_integrity_ms = populated.timings.object_integrity_ms;
                timings.materialize_ms = populated.timings.materialize_ms;
                timings.snapshot_ms = populated.timings.snapshot_ms;
                timings.symlink_ms = populated.timings.symlink_ms;
                timings.sidecar_ms = populated.timings.sidecar_ms;
                populated.sidecar
            }
            Err(e) => {
                let _ = std::fs::remove_dir_all(&tmp_dir);
                return Err(e);
            }
        };

        let rename_start = std::time::Instant::now();
        let rename_result = std::fs::rename(&tmp_dir, &final_dir);
        timings.rename_ms = rename_start.elapsed().as_millis();
        match rename_result {
            Ok(()) => Ok(LinkEntry {
                link_dir: final_dir,
                freshly_populated: true,
                sidecar: Some(sidecar),
                timings: LinkEntryTimings {
                    total_ms: total_start.elapsed().as_millis(),
                    ..timings
                },
            }),
            Err(e) => {
                let recovery_start = std::time::Instant::now();
                if link_entry_is_reusable(
                    &final_dir,
                    &graph_key,
                    &object_dir,
                    &source_sri,
                    verified_object_digest,
                    cas_tree_digest.as_deref(),
                    policy,
                )? {
                    // Concurrent install beat us — discard our stage and
                    // refresh the existing sidecar's mtime.
                    let _ = std::fs::remove_dir_all(&tmp_dir);
                    let sidecar_path = final_dir.join(LINK_META_FILENAME);
                    if let Err(e) = LinkMeta::touch_on_disk(&sidecar_path) {
                        tracing::debug!("virtual store: race-loss touch failed: {e}");
                    }
                    timings.collision_recovery_ms = timings
                        .collision_recovery_ms
                        .saturating_add(recovery_start.elapsed().as_millis());
                    return Ok(LinkEntry {
                        link_dir: final_dir,
                        freshly_populated: false,
                        sidecar: None,
                        timings: LinkEntryTimings {
                            total_ms: total_start.elapsed().as_millis(),
                            ..timings
                        },
                    });
                }
                if final_dir.exists() {
                    // Final dir exists but is incomplete or stale. Remove the
                    // leftover and retry the rename once; a third attempt won't
                    // change filesystem-level failures such as permission errors.
                    tracing::warn!(
                        target = %final_dir.display(),
                        "virtual store: rename hit incomplete or stale leftover; removing and retrying once"
                    );
                    if let Err(e) = std::fs::remove_dir_all(&final_dir) {
                        let _ = std::fs::remove_dir_all(&tmp_dir);
                        return Err(LpmError::Store(format!(
                            "failed to remove incomplete or stale virtual-store link entry during retry at {}: {e}",
                            final_dir.display()
                        )));
                    }
                    timings.collision_recovery_ms = timings
                        .collision_recovery_ms
                        .saturating_add(recovery_start.elapsed().as_millis());
                    let retry_rename_start = std::time::Instant::now();
                    let retry_rename_result = std::fs::rename(&tmp_dir, &final_dir);
                    timings.rename_ms = timings
                        .rename_ms
                        .saturating_add(retry_rename_start.elapsed().as_millis());
                    return match retry_rename_result {
                        Ok(()) => Ok(LinkEntry {
                            link_dir: final_dir,
                            freshly_populated: true,
                            sidecar: Some(sidecar),
                            timings: LinkEntryTimings {
                                total_ms: total_start.elapsed().as_millis(),
                                ..timings
                            },
                        }),
                        Err(e) => {
                            let _ = std::fs::remove_dir_all(&tmp_dir);
                            Err(LpmError::Store(format!(
                                "failed to atomically install virtual-store link entry on retry: {e}"
                            )))
                        }
                    };
                }
                let _ = std::fs::remove_dir_all(&tmp_dir);
                Err(LpmError::Store(format!(
                    "failed to atomically install virtual-store link entry: {e}"
                )))
            }
        }
    }

    fn reused_link_entry(
        final_dir: PathBuf,
        total_start: std::time::Instant,
        timings: LinkEntryTimings,
    ) -> LinkEntry {
        let sidecar_path = final_dir.join(LINK_META_FILENAME);
        if let Err(error) = LinkMeta::touch_on_disk(&sidecar_path) {
            tracing::debug!("virtual store: cache-hit touch failed: {error}");
        }
        LinkEntry {
            link_dir: final_dir,
            freshly_populated: false,
            sidecar: None,
            timings: LinkEntryTimings {
                total_ms: total_start.elapsed().as_millis(),
                ..timings
            },
        }
    }

    // ── Read API ─────────────────────────────────────────────────────

    /// Iterate every link-entry directory under `links/` that has a
    /// readable `.lpm-link-meta.json` sidecar.
    ///
    /// Yields `(link_dir, sidecar)` tuples in directory-iteration order
    /// (filesystem-defined, not sorted — callers that need stable order
    /// sort downstream).
    ///
    /// Skips:
    /// - Non-directories at the `links/` level (defensive — a stray
    ///   file there isn't a link entry).
    /// - **Symlinks at the `links/` level.** The store writer never
    ///   creates symlinks at `links/<entry>`; one appearing here is a
    ///   tamper / corruption signal that an outside-store path could
    ///   resolve into the v2 enumeration. Symlinks are refused with a
    ///   `tracing::warn` so callers (cache prune, rebuild lookup) never
    ///   see a poisoned entry whose deletion target would resolve
    ///   outside the store.
    /// - Directories with a missing or malformed sidecar (mid-write
    ///   tmp dirs from a crashed populate, prune leftovers, etc.).
    ///   These get a debug trace; callers see them as absent rather
    ///   than failing the whole walk.
    ///
    /// Used by [`Self::find_link_package_dir`] (rebuild's
    /// transitive-package lookup) and by `lpm cache prune`. Walking
    /// the directory listing is cheap at any reasonable cache size
    /// (~1 ms for 10k entries on macOS APFS) so neither caller caches.
    pub fn iter_link_entries(
        &self,
    ) -> Result<impl Iterator<Item = (PathBuf, LinkMeta)> + '_, LpmError> {
        let links_root = self.paths.links_root();
        if !links_root.exists() {
            // Empty store (or a fresh `~/.lpm/` on an upgrade-in-place
            // user with no v2 installs yet) — return an empty iterator.
            return Ok(
                Box::new(std::iter::empty()) as Box<dyn Iterator<Item = (PathBuf, LinkMeta)>>
            );
        }
        let read_dir = std::fs::read_dir(&links_root).map_err(|e| {
            LpmError::Store(format!(
                "failed to enumerate virtual-store links root at {}: {e}",
                links_root.display()
            ))
        })?;
        let iter = read_dir.filter_map(|entry| {
            let entry = entry.ok()?;
            let link_dir = entry.path();
            let file_type = entry.file_type().ok()?;
            if file_type.is_symlink() {
                tracing::warn!(
                    "virtual store: refusing symlinked link entry at {} (store writer never creates symlinks here; tamper signal)",
                    link_dir.display()
                );
                return None;
            }
            if !file_type.is_dir() {
                return None;
            }
            match LinkMeta::read_from(&link_dir) {
                Ok(meta) => Some((link_dir, meta)),
                Err(e) => {
                    tracing::debug!(
                        "virtual store: skipping {}: sidecar unreadable ({e})",
                        link_dir.display()
                    );
                    None
                }
            }
        });
        Ok(Box::new(iter) as Box<dyn Iterator<Item = (PathBuf, LinkMeta)>>)
    }

    /// Verify-specific enumeration of every v2 link directory.
    ///
    /// Unlike [`Self::iter_link_entries`], this surfaces sidecar
    /// read/parse/schema/validation failures as `Err` entries instead
    /// of silently filtering them out — a corrupt sidecar is itself a
    /// store-integrity problem that `lpm store verify` must report.
    /// Non-directory children of `links/` are still filtered (a stray
    /// file isn't a link entry to begin with), and symlinks at the
    /// `links/` level surface as a corruption Err so verify reports
    /// them rather than dereferencing into an outside-store path.
    pub fn iter_link_entries_for_verify(&self) -> Result<Vec<VerifyLinkEntry>, LpmError> {
        let links_root = self.paths.links_root();
        if !links_root.exists() {
            return Ok(Vec::new());
        }
        let read_dir = std::fs::read_dir(&links_root).map_err(|e| {
            LpmError::Store(format!(
                "failed to enumerate virtual-store links root at {}: {e}",
                links_root.display()
            ))
        })?;
        let mut out = Vec::new();
        for entry in read_dir {
            let Ok(entry) = entry else { continue };
            let link_dir = entry.path();
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            if file_type.is_symlink() {
                out.push((
                    link_dir,
                    Err(LpmError::Store(
                        "virtual-store link entry is a symlink (store writer never creates symlinks at links/<entry>; refusing to follow into an outside-store path)".to_string(),
                    )),
                ));
                continue;
            }
            if !file_type.is_dir() {
                continue;
            }
            let result = LinkMeta::read_from(&link_dir);
            out.push((link_dir, result));
        }
        Ok(out)
    }

    /// Find the package directory for `(name, version)` by walking the
    /// link entries. Returns the absolute path to
    /// `links/<key>/node_modules/<name>/` of the first matching entry,
    /// or `Ok(None)` if no link entry has this `(name, version)`.
    ///
    /// **Match shape.** A link entry matches when its sidecar's name
    /// and version exactly equal the caller's. Two distinct sources
    /// can share `(name, version)` and produce different graph keys;
    /// this lookup picks the first match in directory-iteration order,
    /// which is non-deterministic on its own but acceptable for
    /// `rebuild`'s lifecycle-script path. A full
    /// `(name, version, wrapper_id)` lookup is the proper fix once
    /// `wrapper_id` is threaded through dep edges and persisted in
    /// the lockfile.
    pub fn find_link_package_dir(
        &self,
        name: &str,
        version: &str,
    ) -> Result<Option<PathBuf>, LpmError> {
        for (link_dir, meta) in self.iter_link_entries()? {
            if meta.name == name && meta.version == version {
                return Ok(Some(link_dir.join(LINK_NODE_MODULES).join(name)));
            }
        }
        Ok(None)
    }

    /// Return the current content digest for a populated link entry.
    pub fn link_entry_content_integrity(&self, key: &GraphKey) -> Result<String, LpmError> {
        self.link_entry_content_integrity_with_policy(key, self.object_integrity_policy)
    }

    /// Return a metadata digest for a cached compatibility-island entry.
    pub fn compat_island_entry_metadata_integrity(
        &self,
        entry_dir: &Path,
    ) -> Result<String, LpmError> {
        let compat_root = self.paths.compat_root();
        let relative = entry_dir.strip_prefix(compat_root).map_err(|_| {
            LpmError::Store(format!(
                "compatibility island entry is outside the store cache at {}",
                entry_dir.display()
            ))
        })?;
        if relative.as_os_str().is_empty()
            || relative.components().any(|component| {
                matches!(
                    component,
                    std::path::Component::ParentDir | std::path::Component::RootDir
                )
            })
        {
            return Err(LpmError::Store(format!(
                "compatibility island entry is outside the store cache at {}",
                entry_dir.display()
            )));
        }
        let metadata = entry_dir.symlink_metadata().map_err(|error| {
            LpmError::Store(format!(
                "failed to inspect compatibility island entry at {}: {error}",
                entry_dir.display()
            ))
        })?;
        if !metadata.is_dir() || lpm_common::is_symlink_or_junction(&metadata) {
            return Err(LpmError::Store(format!(
                "refusing non-directory compatibility island entry at {}",
                entry_dir.display()
            )));
        }
        compute_tree_metadata_integrity(entry_dir)
    }

    fn link_entry_content_integrity_with_policy(
        &self,
        key: &GraphKey,
        policy: ObjectIntegrityPolicy,
    ) -> Result<String, LpmError> {
        let link_dir = self.paths.link_dir(key);
        if let Some(snapshot) = read_tree_snapshot(&link_dir) {
            return Ok(snapshot.content_integrity);
        }
        if !is_complete_link_entry(&link_dir, key) {
            return Err(LpmError::Store(format!(
                "virtual-store link entry {} is incomplete; cannot key compatibility island",
                link_dir.display()
            )));
        }
        let package_dir = link_entry_package_dir(&link_dir, key);
        let meta = LinkMeta::read_from(&link_dir)?;
        let object_dir = self.paths.object_dir(&meta.source_sri)?;
        if source_policy_uses_source_integrity(&object_dir, policy) {
            let content = source_object_integrity(&meta.source_sri);
            let metadata = compute_tree_metadata_integrity(&package_dir)?;
            write_tree_snapshot(
                &link_dir,
                &TreeIntegrities {
                    content: content.clone(),
                    metadata,
                    stats: ObjectTreeStats::default(),
                },
            )?;
            return Ok(content);
        }
        let actual = compute_object_tree_integrities(&package_dir)?;
        write_tree_snapshot_best_effort(&link_dir, &actual);
        Ok(actual.content)
    }

    /// **v1 → v2 cache-hit translation.** When the v1 store already
    /// has the extracted bytes for a `(name, version)`
    /// at `<HOME>/.lpm/store/v1/<name>/<version>/`, populate the v2
    /// `objects/<sri>/` directly from those bytes instead of
    /// re-downloading the tarball.
    ///
    /// Idempotent: if the v2 object dir is already complete, no work
    /// happens. Otherwise the helper recursively copies every file
    /// from `v1_pkg_dir` into a tmp staging dir, then atomically
    /// renames into place — same atomicity contract as
    /// [`Self::extract_object`].
    ///
    /// **What gets copied.**
    /// - All package files at the root of `v1_pkg_dir` (e.g.,
    ///   `package.json`, `index.js`, `dist/`).
    /// - The `.integrity` sidecar after it is verified to represent the
    ///   same content identity as `sri`.
    /// - The `.lpm-security.json` cache, if present in `v1_pkg_dir`.
    ///   Security analysis is content-determined; copying the cache
    ///   skips the multi-millisecond re-analysis on warm-cache
    ///   migrations. If absent, the helper re-runs analysis to
    ///   match `extract_object`'s post-write contract.
    ///
    pub fn populate_object_from_v1(
        &self,
        v1_pkg_dir: &Path,
        sri: &str,
    ) -> Result<PathBuf, LpmError> {
        let requested_integrity = Integrity::parse(sri)?;
        let marker_path = v1_pkg_dir.join(".integrity");
        let recorded_sri =
            lpm_common::read_text_file_capped(&marker_path, INTEGRITY_MARKER_SIZE_CAP_BYTES)
                .map_err(|error| {
                    LpmError::Store(format!(
                        "v1 to virtual-store translation: failed to read {}: {error}",
                        marker_path.display()
                    ))
                })?;
        let recorded_sri = recorded_sri.trim();
        let recorded_integrity = Integrity::parse(recorded_sri).map_err(|error| {
            LpmError::Store(format!(
                "v1 to virtual-store translation: invalid integrity marker at {}: {error}",
                marker_path.display()
            ))
        })?;
        if recorded_integrity != requested_integrity {
            return Err(LpmError::IntegrityMismatch {
                expected: sri.to_string(),
                actual: recorded_sri.to_string(),
            });
        }
        self.populate_object_from_existing_tree(v1_pkg_dir, sri, "v1 to virtual-store translation")
    }

    fn populate_object_from_existing_tree(
        &self,
        source_dir: &Path,
        sri: &str,
        context: &str,
    ) -> Result<PathBuf, LpmError> {
        let policy = self.object_integrity_policy;
        let object_dir = self.paths.object_dir(sri)?;
        if object_dir.exists()
            && object_dir_is_reusable_or_remove(&object_dir, context, sri, policy)?
            && !matches!(
                self.finish_file_cas_source(&object_dir, sri, false, None, policy)?,
                FileCasSourceFinish::Unusable
            )
        {
            return Ok(object_dir);
        }
        if !source_dir.is_dir() {
            return Err(LpmError::Store(format!(
                "{context}: source dir {} is not readable",
                source_dir.display()
            )));
        }
        if let Some(parent) = object_dir.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                LpmError::Store(format!("failed to create virtual-store objects dir: {e}"))
            })?;
        }
        let tmp_dir = tmp_sibling(&object_dir);
        if tmp_dir.exists() {
            let _ = std::fs::remove_dir_all(&tmp_dir);
        }
        create_tmp_dir_locked(&tmp_dir).map_err(|e| {
            LpmError::Store(format!(
                "failed to create virtual-store tmp staging dir: {e}"
            ))
        })?;

        copy_dir_recursively(source_dir, &tmp_dir).map_err(|e| {
            let _ = std::fs::remove_dir_all(&tmp_dir);
            LpmError::Store(format!(
                "{context}: failed to copy {} → {}: {e}",
                source_dir.display(),
                tmp_dir.display()
            ))
        })?;

        // If v1 didn't ship a security cache (rare, but possible on
        // a stale or partial v1 entry), re-run analysis so the v2
        // post-write contract holds.
        if self.security_analysis_policy.is_enabled()
            && lpm_security::behavioral::read_cached_analysis(&tmp_dir).is_none()
        {
            let analysis = lpm_security::behavioral::analyze_package(&tmp_dir);
            if let Err(e) = lpm_security::behavioral::write_cached_analysis(&tmp_dir, &analysis) {
                tracing::warn!("{context}: failed to write .lpm-security.json: {e}");
            }
        }

        let prepared_cas = match self.prepare_file_cas_source(&tmp_dir, &object_dir, sri, false) {
            Ok(prepared) => prepared,
            Err(error) => {
                let _ = std::fs::remove_dir_all(&tmp_dir);
                return Err(error);
            }
        };

        if let Err(e) = write_object_integrity_for_policy(&tmp_dir, sri, policy) {
            let _ = std::fs::remove_dir_all(&tmp_dir);
            return Err(e);
        }
        if let Err(e) = std::fs::write(tmp_dir.join(".integrity"), sri) {
            let _ = std::fs::remove_dir_all(&tmp_dir);
            return Err(LpmError::Store(format!(
                "failed to write .integrity during {context}: {e}"
            )));
        }

        let (published, used_prepared) = match std::fs::rename(&tmp_dir, &object_dir) {
            Ok(()) => (object_dir, true),
            Err(error) => (
                finish_object_rename_after_collision(
                    &tmp_dir,
                    &object_dir,
                    sri,
                    context,
                    error,
                    policy,
                )?,
                false,
            ),
        };
        if matches!(
            self.finish_file_cas_source(
                &published,
                sri,
                false,
                if used_prepared {
                    prepared_cas.as_ref()
                } else {
                    None
                },
                policy,
            )?,
            FileCasSourceFinish::Unusable
        ) {
            return Err(LpmError::Store(format!(
                "published v3 CAS source became unusable at {}",
                published.display()
            )));
        }
        Ok(published)
    }

    fn backfill_security_cache_if_enabled(&self, object_dir: &Path, sri: &str) {
        if !self.security_analysis_policy.is_enabled() {
            return;
        }
        match lpm_security::behavioral::backfill_cached_analysis(object_dir) {
            Ok(true) => tracing::debug!(
                target = %object_dir.display(),
                "virtual store: backfilled security analysis cache for {sri}"
            ),
            Ok(false) => {}
            Err(error) => tracing::warn!(
                target = %object_dir.display(),
                "virtual store: failed to backfill .lpm-security.json for {sri}: {error}"
            ),
        }
    }

    /// Populate `objects/<sri>/` from a live local source directory.
    ///
    /// The populated object is a real-file snapshot of the source
    /// tree. The synthetic SRI is a stable identity key rather than a
    /// content hash, so reuse requires comparing the live source with
    /// the stored tree and validating the stored tree's integrity.
    pub fn populate_object_from_local_source(
        &self,
        source_dir: &Path,
        sri: &str,
    ) -> Result<PathBuf, LpmError> {
        let canonical_source = source_dir.canonicalize().map_err(|e| {
            LpmError::Store(format!(
                "virtual-store local-source object: failed to canonicalize {}: {e}",
                source_dir.display()
            ))
        })?;
        let object_dir = self.paths.object_dir(sri)?;

        // Concurrent installs in one process (recursive workspace
        // targets) refresh the same snapshot; serialize per object so
        // one populate's replace can't swap the tree out from under a
        // sibling's populate or its identical-content comparison.
        let populate_lock = local_source_populate_lock(&object_dir);
        let _populate_guard = populate_lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        let source_fingerprint = compute_local_source_fingerprint(&canonical_source)?;
        let fingerprint_matches = source_fingerprint.as_ref().is_some_and(|fingerprint| {
            stored_local_source_fingerprint_matches(&object_dir, fingerprint)
        });
        let snapshot_matches =
            fingerprint_matches || local_source_snapshot_matches(&canonical_source, &object_dir)?;
        // A local-source SRI identifies a mutable path, not its bytes, so source-policy
        // verification cannot detect corruption of the stored snapshot.
        let verified_object = object_integrity_or_remove(
            &object_dir,
            "before local-source snapshot reuse or refresh",
            sri,
            ObjectIntegrityPolicy::Tree,
        )?;
        if snapshot_matches && verified_object.is_some() {
            let stable_source = fingerprint_matches
                || compute_local_source_fingerprint(&canonical_source)? == source_fingerprint;
            if stable_source {
                if !fingerprint_matches {
                    record_local_source_fingerprint(&object_dir, source_fingerprint.as_ref());
                }
                let cas_ready = !matches!(
                    self.finish_file_cas_source(
                        &object_dir,
                        sri,
                        true,
                        None,
                        ObjectIntegrityPolicy::Tree,
                    )?,
                    FileCasSourceFinish::Unusable
                );
                if cas_ready {
                    self.backfill_security_cache_if_enabled(&object_dir, sri);
                    return Ok(object_dir);
                }
            }
        }

        if let Some(parent) = object_dir.parent() {
            ensure_store_tier_dir_locked(parent).map_err(|e| {
                LpmError::Store(format!("failed to create virtual-store objects dir: {e}"))
            })?;
        }

        let tmp_dir = tmp_sibling(&object_dir);
        for attempt in 0..2 {
            if tmp_dir.exists() {
                let _ = std::fs::remove_dir_all(&tmp_dir);
            }
            create_tmp_dir_locked(&tmp_dir).map_err(|e| {
                LpmError::Store(format!(
                    "failed to create virtual-store tmp staging dir: {e}"
                ))
            })?;

            let before_population = compute_local_source_fingerprint(&canonical_source)?;
            if let Err(e) = populate_local_source_object_into(
                &canonical_source,
                &tmp_dir,
                sri,
                self.security_analysis_policy,
            ) {
                let _ = std::fs::remove_dir_all(&tmp_dir);
                return Err(e);
            }
            let after_population = compute_local_source_fingerprint(&canonical_source)?;
            if before_population != after_population {
                let _ = std::fs::remove_dir_all(&tmp_dir);
                if attempt == 0 {
                    continue;
                }
                return Err(LpmError::Store(format!(
                    "virtual-store local-source object changed while snapshotting {}",
                    canonical_source.display()
                )));
            }

            let prepared_cas = match self.prepare_file_cas_source(&tmp_dir, &object_dir, sri, true)
            {
                Ok(prepared) => prepared,
                Err(error) => {
                    let _ = std::fs::remove_dir_all(&tmp_dir);
                    return Err(error);
                }
            };
            if let Err(error) =
                write_object_integrity_for_policy(&tmp_dir, sri, ObjectIntegrityPolicy::Tree)
            {
                let _ = std::fs::remove_dir_all(&tmp_dir);
                return Err(error);
            }

            replace_local_source_object(&tmp_dir, &object_dir, &canonical_source)?;
            record_local_source_fingerprint(&object_dir, after_population.as_ref());
            if matches!(
                self.finish_file_cas_source(
                    &object_dir,
                    sri,
                    true,
                    prepared_cas.as_ref(),
                    ObjectIntegrityPolicy::Tree,
                )?,
                FileCasSourceFinish::Unusable
            ) {
                return Err(LpmError::Store(format!(
                    "fresh local-source v3 CAS snapshot became unusable at {}",
                    object_dir.display()
                )));
            }
            return Ok(object_dir);
        }
        Err(LpmError::Store(format!(
            "virtual-store local-source object changed repeatedly while snapshotting {}",
            canonical_source.display()
        )))
    }

    /// Iterate every object directory under `objects/` that has a
    /// readable `.integrity` marker (i.e., looks complete).
    ///
    /// Yields `(object_dir, sri_segment)` tuples in directory-iteration
    /// order. `sri_segment` is the on-disk filename (e.g.
    /// `sha512-deadbeef.../`) and matches what `LinkMeta.object_path`
    /// records as its trailing component — `lpm cache prune` uses
    /// this as the join key when computing object orphan reachability.
    ///
    /// Skips:
    /// - Non-directories at the `objects/` level.
    /// - Directories without a `.integrity` marker (incomplete
    ///   extracts, mid-write tmp dirs).
    /// - Empty `objects/` root or missing root entirely.
    pub fn iter_object_dirs(
        &self,
    ) -> Result<impl Iterator<Item = (PathBuf, String)> + '_, LpmError> {
        let objects_root = self.paths.objects_root();
        if !objects_root.exists() {
            return Ok(Box::new(std::iter::empty()) as Box<dyn Iterator<Item = (PathBuf, String)>>);
        }
        let read_dir = std::fs::read_dir(&objects_root).map_err(|e| {
            LpmError::Store(format!(
                "failed to enumerate virtual-store objects root at {}: {e}",
                objects_root.display()
            ))
        })?;
        let iter = read_dir.filter_map(|entry| {
            let entry = entry.ok()?;
            let object_dir = entry.path();
            let file_type = entry.file_type().ok()?;
            if file_type.is_symlink() {
                tracing::warn!(
                    "virtual store: refusing symlinked object entry at {} (store writer never creates symlinks here; tamper signal)",
                    object_dir.display()
                );
                return None;
            }
            if !file_type.is_dir() {
                return None;
            }
            if !is_complete_object_dir(&object_dir) {
                return None;
            }
            let segment = object_dir.file_name()?.to_string_lossy().to_string();
            Some((object_dir, segment))
        });
        Ok(Box::new(iter) as Box<dyn Iterator<Item = (PathBuf, String)>>)
    }

    pub fn verify_file_cas(
        &self,
        deep: bool,
    ) -> Result<Option<crate::v3::FileCasVerification>, LpmError> {
        let Some(cas) = &self.file_cas else {
            return Ok(None);
        };
        let mut verification = crate::v3::FileCasVerification::default();
        let mut expected_sources = std::collections::HashMap::new();
        for (object_dir, _) in self.iter_object_dirs()? {
            let source_sri = match std::fs::read_to_string(object_dir.join(".integrity")) {
                Ok(source_sri) => source_sri,
                Err(error) => {
                    verification.issues.push(format!(
                        "{}: failed to read source integrity: {error}",
                        object_dir.display()
                    ));
                    continue;
                }
            };
            let source_sri = source_sri.trim().to_string();
            match cas.source_record_path(&source_sri) {
                Ok(path) => {
                    expected_sources.insert(path, (object_dir, source_sri));
                }
                Err(error) => verification.issues.push(error.to_string()),
            }
        }

        let source_files = cas.source_record_files()?;
        let _source_validation_files = cas.source_validation_files()?;
        verification.sources = source_files.len();
        let mut reachable_tree_paths = std::collections::HashSet::new();
        let mut reachable_tree_digests = std::collections::HashSet::new();
        for source_path in &source_files {
            let record = match cas.source_record_from_file(source_path) {
                Ok(record) => record,
                Err(error) => {
                    verification.issues.push(error.to_string());
                    continue;
                }
            };
            match expected_sources.remove(source_path) {
                Some((object_dir, source_sri)) => {
                    if let Err(error) = cas.source_manifest_for_verify(&object_dir, &source_sri) {
                        verification.issues.push(error.to_string());
                        continue;
                    }
                }
                None => {
                    verification.orphaned_sources = verification.orphaned_sources.saturating_add(1);
                    if let Err(error) = cas.manifest_for_source_record(&record) {
                        verification.issues.push(error.to_string());
                    }
                    continue;
                }
            }
            match cas.tree_manifest_path(&record.tree_digest) {
                Ok(path) => {
                    reachable_tree_paths.insert(path);
                    reachable_tree_digests.insert(record.tree_digest);
                }
                Err(error) => verification.issues.push(error.to_string()),
            }
        }
        for (_, (object_dir, _)) in expected_sources {
            verification.issues.push(format!(
                "missing v3 CAS source record for {}",
                object_dir.display()
            ));
        }

        let tree_files = cas.tree_manifest_files()?;
        verification.trees = tree_files.len();
        let mut all_tree_blobs = std::collections::HashSet::new();
        let mut reachable_blob_paths = std::collections::HashSet::new();
        let mut tree_manifests = std::collections::HashMap::new();
        for tree_path in &tree_files {
            let (digest, manifest) = match cas.manifest_from_file(tree_path) {
                Ok(manifest) => manifest,
                Err(error) => {
                    verification.issues.push(error.to_string());
                    continue;
                }
            };
            if !reachable_tree_paths.contains(tree_path) {
                verification.orphaned_trees = verification.orphaned_trees.saturating_add(1);
            }
            let tree_is_reachable = reachable_tree_digests.contains(&digest);
            tree_manifests.insert(digest, manifest.clone());
            for key in manifest
                .entries
                .iter()
                .filter_map(|entry| entry.blob.as_ref())
            {
                match cas.blob_path(key) {
                    Ok(path) => {
                        if tree_is_reachable {
                            reachable_blob_paths.insert(path);
                        }
                        all_tree_blobs.insert(key.clone());
                    }
                    Err(error) => verification.issues.push(error.to_string()),
                }
            }
        }

        let materialized_entries = cas.materialized_entry_dirs()?;
        verification.materialized = materialized_entries.len();
        for entry_dir in &materialized_entries {
            let digest = match cas.materialized_digest_from_entry(entry_dir) {
                Ok(digest) => digest,
                Err(error) => {
                    verification.orphaned_materialized =
                        verification.orphaned_materialized.saturating_add(1);
                    verification.issues.push(error.to_string());
                    continue;
                }
            };
            if !reachable_tree_digests.contains(&digest) {
                verification.orphaned_materialized =
                    verification.orphaned_materialized.saturating_add(1);
            }
            let Some(manifest) = tree_manifests.get(&digest) else {
                verification.issues.push(format!(
                    "v3 CAS materialized entry has no tree manifest at {}",
                    entry_dir.display()
                ));
                continue;
            };
            if !cas.materialized_entry_is_complete(entry_dir, &digest) {
                verification.issues.push(format!(
                    "v3 CAS materialized entry is incomplete at {}",
                    entry_dir.display()
                ));
            }
            if let Err(error) = cas.validate_materialized_entry(entry_dir, &digest, manifest) {
                verification.issues.push(error.to_string());
            }
        }

        let blob_files = cas.blob_files()?;
        verification.blobs = blob_files.len();
        let mut hash_buffer = vec![0_u8; 64 * 1024];
        let mut verified_blob_paths = std::collections::HashSet::with_capacity(blob_files.len());
        for blob_path in &blob_files {
            let key = match cas.blob_key_from_file(blob_path) {
                Ok(key) => key,
                Err(error) => {
                    verification.issues.push(error.to_string());
                    continue;
                }
            };
            verified_blob_paths.insert(blob_path.clone());
            if !reachable_blob_paths.contains(blob_path) {
                verification.orphaned_blobs = verification.orphaned_blobs.saturating_add(1);
            }
            if deep {
                verification.blobs_rehashed = verification.blobs_rehashed.saturating_add(1);
                if let Err(error) = cas.verify_blob(&key, true, &mut hash_buffer) {
                    verification.issues.push(error.to_string());
                }
            }
        }
        for key in &all_tree_blobs {
            let path = cas.blob_path(key)?;
            if verified_blob_paths.contains(&path) {
                continue;
            }
            if let Err(error) = cas.verify_blob(key, deep, &mut hash_buffer) {
                verification.issues.push(error.to_string());
            }
        }
        verification.issues.sort_unstable();
        verification.issues.dedup();
        Ok(Some(verification))
    }

    pub fn file_cas_tree_digest(&self, source_sri: &str) -> Result<Option<String>, LpmError> {
        let Some(cas) = &self.file_cas else {
            return Ok(None);
        };
        let object_dir = self.paths.object_dir(source_sri)?;
        cas.source_tree_digest(&object_dir, source_sri).map(Some)
    }

    pub fn file_cas_prune_plan(
        &self,
        objects_to_remove: &std::collections::HashSet<PathBuf>,
    ) -> Result<Option<crate::v3::FileCasPrunePlan>, LpmError> {
        let Some(cas) = &self.file_cas else {
            return Ok(None);
        };
        let mut reachable_trees = std::collections::HashSet::new();
        let mut reachable_blobs = std::collections::HashSet::new();
        let mut reachable_materialized = std::collections::HashSet::new();
        let mut live_source_records = std::collections::HashSet::new();
        let mut live_source_validations = std::collections::HashSet::new();
        for (object_dir, _) in self.iter_object_dirs()? {
            if objects_to_remove.contains(&object_dir) {
                continue;
            }
            let source_sri =
                std::fs::read_to_string(object_dir.join(".integrity")).map_err(|error| {
                    LpmError::Store(format!(
                        "failed to read v3 source integrity at {}: {error}",
                        object_dir.display()
                    ))
                })?;
            let (record, manifest) =
                cas.source_manifest_for_verify(&object_dir, source_sri.trim())?;
            reachable_trees.insert(cas.tree_manifest_path(&record.tree_digest)?);
            reachable_materialized.insert(cas.materialized_entry_dir(&record.tree_digest)?);
            live_source_records.insert(cas.source_record_path(source_sri.trim())?);
            live_source_validations.insert(cas.source_validation_path(source_sri.trim())?);
            for blob in manifest
                .entries
                .iter()
                .filter_map(|entry| entry.blob.as_ref())
            {
                reachable_blobs.insert(cas.blob_path(blob)?);
            }
        }

        let tree_files = cas.tree_manifest_files()?;
        let blob_files = cas.blob_files()?;
        let source_record_files = cas.source_record_files()?;
        let source_validation_files = cas.source_validation_files()?;
        let materialized_entries = cas.materialized_entry_dirs()?;
        Ok(Some(crate::v3::FileCasPrunePlan {
            trees_total: tree_files.len(),
            tree_files_orphaned: tree_files
                .into_iter()
                .filter(|path| !reachable_trees.contains(path))
                .collect(),
            blobs_total: blob_files.len(),
            blob_files_orphaned: blob_files
                .into_iter()
                .filter(|path| !reachable_blobs.contains(path))
                .collect(),
            source_record_files_orphaned: source_record_files
                .into_iter()
                .filter(|path| !live_source_records.contains(path))
                .collect(),
            source_validation_files_orphaned: source_validation_files
                .into_iter()
                .filter(|path| !live_source_validations.contains(path))
                .collect(),
            materialized_total: materialized_entries.len(),
            materialized_entries_orphaned: materialized_entries
                .into_iter()
                .filter(|path| !reachable_materialized.contains(path))
                .collect(),
        }))
    }

    /// Returns `true` iff `path` (after symlink resolution) lives under
    /// this store's `links/` root. Used by `lpm doctor` and `lpm
    /// rebuild` to detect a v2-shaped install — every v2 project-side
    /// `node_modules/<dep>` symlink resolves into `links/<key>/...`.
    ///
    /// `path` is canonicalized internally; callers can pass the raw
    /// symlink path and let this function dereference. Any I/O error
    /// during canonicalization (broken symlink, permission denied)
    /// returns `false` — it's a "best evidence" predicate, not a
    /// validity check.
    pub fn path_lives_in_store(&self, path: &Path) -> bool {
        let canonical = match std::fs::canonicalize(path) {
            Ok(c) => c,
            Err(_) => return false,
        };
        let canonical_links_root = match std::fs::canonicalize(self.paths.links_root()) {
            Ok(c) => c,
            Err(_) => return false,
        };
        canonical.starts_with(canonical_links_root)
    }
}

struct PopulateObject<'a> {
    dir: &'a Path,
    materialize_dir: &'a Path,
    source_sri: &'a str,
    sidecar_relpath: &'a str,
    policy: ObjectIntegrityPolicy,
    fresh_object_integrity: Option<&'a FreshObjectIntegrity>,
    tree_digest: Option<&'a str>,
}

struct PopulateIntoResult {
    sidecar: LinkMeta,
    timings: LinkEntryTimings,
}

fn populate_into(
    tmp_dir: &Path,
    graph_key: &GraphKey,
    object: PopulateObject<'_>,
    deps: &[DepLink],
    platform: &Arc<LinkMetaPlatform>,
) -> Result<PopulateIntoResult, LpmError> {
    let mut timings = LinkEntryTimings::default();
    let node_modules = tmp_dir.join(LINK_NODE_MODULES);
    std::fs::create_dir_all(&node_modules).map_err(|e| {
        LpmError::Store(format!(
            "failed to create virtual-store link node_modules at {}: {e}",
            node_modules.display()
        ))
    })?;

    // Materialize the package itself from the verified object directory.
    // Link entries must not share hardlink inodes with objects: writes
    // through executable package bytes must never mutate the object store.
    let object_integrity_start = std::time::Instant::now();
    let object_integrity = match object.fresh_object_integrity {
        Some(digest) => Cow::Borrowed(digest.as_str()),
        None => Cow::Owned(object_integrity_for_link(
            object.dir,
            object.source_sri,
            object.policy,
        )?),
    };
    timings.object_integrity_ms = object_integrity_start.elapsed().as_millis();
    let pkg_dir = node_modules.join(graph_key.name());
    if let Some(parent) = pkg_dir.parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            LpmError::Store(format!(
                "failed to create virtual-store link package parent at {}: {e}",
                parent.display()
            ))
        })?;
    }
    let materialize_start = std::time::Instant::now();
    let materialized_metadata_integrity = materialize_into_with_integrity(
        object.materialize_dir,
        &pkg_dir,
        has_local_source_sentinel(object.dir),
    )?;
    timings.materialize_ms = materialize_start.elapsed().as_millis();

    // Sibling-dep symlinks. Each lives next to the package (siblings
    // under the wrapper-level node_modules) — same shape as the
    // existing isolated linker contract.
    let symlink_start = std::time::Instant::now();
    let mut package_tree_changed = false;
    for dep in deps {
        package_tree_changed |= dep.local == graph_key.name();
        create_sibling_symlink(&node_modules, dep, graph_key)?;
    }
    timings.symlink_ms = symlink_start.elapsed().as_millis();

    let snapshot_start = std::time::Instant::now();
    let object_integrity = object_integrity.into_owned();
    if package_tree_changed {
        let layout_integrities = compute_object_tree_integrities(&pkg_dir)?;
        write_tree_snapshot_with_layout_content(tmp_dir, &object_integrity, &layout_integrities)?;
    } else {
        let package_metadata_integrity = match materialized_metadata_integrity {
            Some(integrity) => integrity,
            None => compute_tree_metadata_integrity(&pkg_dir)?,
        };
        write_tree_snapshot(
            tmp_dir,
            &TreeIntegrities {
                content: object_integrity,
                metadata: package_metadata_integrity,
                stats: ObjectTreeStats::default(),
            },
        )?;
    }
    timings.snapshot_ms = snapshot_start.elapsed().as_millis();

    // Stage the sidecar BEFORE the rename so the published entry is
    // never observable without its metadata.
    let mut deps_meta: Vec<LinkMetaDep> = Vec::with_capacity(deps.len());
    for dep in deps {
        deps_meta.push(dep.clone().into_meta_dep());
    }
    let sidecar = LinkMeta::new(
        graph_key,
        object.source_sri,
        object.sidecar_relpath,
        deps_meta,
        Arc::clone(platform),
    )
    .with_tree_digest(object.tree_digest.map(str::to_owned));
    // `tmp_dir` is the unpublished staging dir; the outer rename in
    // `populate_link_entry` is the visibility boundary, so we can skip the
    // tmp+rename dance and write the sidecar straight in. See
    // [`LinkMeta::write_to_unpublished`] for the atomicity contract.
    let sidecar_start = std::time::Instant::now();
    sidecar.write_to_unpublished(tmp_dir)?;
    timings.sidecar_ms = sidecar_start.elapsed().as_millis();

    Ok(PopulateIntoResult { sidecar, timings })
}

fn create_sibling_symlink(
    node_modules: &Path,
    dep: &DepLink,
    self_key: &GraphKey,
) -> Result<(), LpmError> {
    if let Err(why) = validate_name_for_path_join(&dep.local) {
        return Err(LpmError::Store(format!(
            "unsafe dependency local name {:?} in virtual-store link entry for {}: {why}",
            dep.local,
            self_key.dir_name()
        )));
    }

    let (link_path, ascents) = if dep.local == self_key.name() {
        let package_dir = node_modules.join(self_key.name());
        let nested_node_modules = package_dir.join(LINK_NODE_MODULES);
        ensure_real_dir_or_create(&nested_node_modules, "same-name dependency node_modules")?;
        let link_path = nested_node_modules.join(&dep.local);
        ensure_sibling_parent_dir(&nested_node_modules, &link_path, "same-name sibling")?;
        (
            link_path,
            depth_of_local(self_key.name()) + depth_of_local(&dep.local) + 4,
        )
    } else {
        let link_path = node_modules.join(&dep.local);
        ensure_sibling_parent_dir(node_modules, &link_path, "sibling")?;
        (link_path, depth_of_local(&dep.local) + 2)
    };

    let mut target = PathBuf::new();
    for _ in 0..ascents {
        target.push("..");
    }
    target.push(dep.target.dir_name());
    target.push(LINK_NODE_MODULES);
    target.push(dep.target.name());

    create_dir_symlink(&target, &link_path).map_err(|e| {
        LpmError::Store(format!(
            "failed to create virtual-store sibling symlink {} → {} (self={}): {e}",
            link_path.display(),
            target.display(),
            self_key.dir_name()
        ))
    })
}

fn ensure_sibling_parent_dir(base: &Path, link_path: &Path, label: &str) -> Result<(), LpmError> {
    let Some(parent) = link_path.parent() else {
        return Err(LpmError::Store(format!(
            "virtual-store {label} link path has no parent: {}",
            link_path.display()
        )));
    };
    if parent == base {
        return Ok(());
    }
    let relative = parent.strip_prefix(base).map_err(|e| {
        LpmError::Store(format!(
            "virtual-store {label} parent {} is outside base {}: {e}",
            parent.display(),
            base.display()
        ))
    })?;
    let mut current = base.to_path_buf();
    for component in relative.components() {
        let std::path::Component::Normal(name) = component else {
            return Err(LpmError::Store(format!(
                "virtual-store {label} parent contains unsafe component at {}",
                parent.display()
            )));
        };
        current.push(name);
        ensure_real_dir_or_create(&current, label)?;
    }
    Ok(())
}

fn ensure_real_dir_or_create(path: &Path, label: &str) -> Result<(), LpmError> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_dir() && !metadata.file_type().is_symlink() => {
            Ok(())
        }
        Ok(_) => Err(LpmError::Store(format!(
            "refusing to create virtual-store {label} through non-directory path at {}",
            path.display()
        ))),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            match std::fs::create_dir(path) {
                Ok(()) => Ok(()),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    ensure_real_dir_or_create(path, label)
                }
                Err(error) => Err(LpmError::Store(format!(
                    "failed to create virtual-store {label} directory at {}: {error}",
                    path.display()
                ))),
            }
        }
        Err(error) => Err(LpmError::Store(format!(
            "failed to inspect virtual-store {label} directory at {}: {error}",
            path.display()
        ))),
    }
}

fn depth_of_local(local: &str) -> usize {
    // Number of `/` characters in the local name. `debug` → 0,
    // `@scope/dep` → 1.
    local.chars().filter(|c| *c == '/').count()
}

/// A v2 link entry is complete iff:
///
/// 1. The link dir itself is a directory.
/// 2. The sidecar `.lpm-link-meta.json` is present (rules out
///    crashed-before-rename leftovers — the staging code writes the
///    sidecar inside the tmp dir before the atomic rename).
/// 3. The package's own `package.json` is present at
///    `node_modules/<name>/package.json` (rules out tmp/final-dir
///    leftovers where the sidecar got staged but the package
///    materialization failed mid-write — symmetric to v1's
///    `is_complete_package_dir` check at lib.rs:883).
///
/// All three are cheap stat calls; combined they make
/// `populate_link_entry`'s short-circuit fast-path correct under
/// crash recovery.
fn is_complete_link_entry(dir: &Path, key: &GraphKey) -> bool {
    if !dir.is_dir() {
        return false;
    }
    // Reuse a single PathBuf via push/pop rather than allocating four
    // separate PathBufs (sidecar, node_modules, node_modules/<name>,
    // node_modules/<name>/package.json).
    let mut path = dir.to_path_buf();
    path.push(crate::v2::link_meta::LINK_META_FILENAME);
    if !path.is_file() {
        return false;
    }
    path.pop();
    path.push(LINK_NODE_MODULES);
    path.push(key.name());
    path.push("package.json");
    path.is_file()
}

fn link_entry_is_reusable(
    dir: &Path,
    key: &GraphKey,
    object_dir: &Path,
    source_sri: &str,
    verified_object_digest: Option<&VerifiedObjectIntegrity>,
    tree_digest: Option<&str>,
    policy: ObjectIntegrityPolicy,
) -> Result<bool, LpmError> {
    if !is_complete_link_entry(dir, key) {
        return Ok(false);
    }
    let sidecar = LinkMeta::read_from(dir)?;
    if sidecar.graph_key_digest_hex != key.digest_hex()
        || sidecar.source_sri != source_sri
        || sidecar.tree_digest.as_deref() != tree_digest
    {
        return Ok(false);
    }
    let expected = match verified_object_digest {
        Some(digest) => Cow::Borrowed(digest.as_str()),
        None => Cow::Owned(object_integrity_for_link(object_dir, source_sri, policy)?),
    };
    let package_dir = link_entry_package_dir(dir, key);
    if tree_snapshot_matches(dir, &package_dir, expected.as_ref())? {
        return Ok(true);
    }
    let actual = compute_object_tree_integrities(&package_dir)?;
    if actual.content == expected.as_ref() {
        write_tree_snapshot_best_effort(dir, &actual);
        return Ok(true);
    }
    if read_tree_snapshot(dir).is_some_and(|snapshot| {
        snapshot.content_integrity == expected.as_ref()
            && snapshot.layout_content_integrity.as_deref() == Some(actual.content.as_str())
    }) {
        if let Err(error) = write_tree_snapshot_with_layout_content(dir, expected.as_ref(), &actual)
        {
            tracing::debug!(
                target = %dir.display(),
                "virtual store: failed to refresh link layout snapshot: {error}"
            );
        }
        return Ok(true);
    }
    if source_policy_uses_source_integrity(object_dir, policy)
        && link_tree_matches_object_tree(&actual, object_dir)?
    {
        write_tree_snapshot_best_effort(
            dir,
            &TreeIntegrities {
                content: expected.as_ref().to_owned(),
                metadata: actual.metadata,
                stats: actual.stats,
            },
        );
        return Ok(true);
    }
    Ok(false)
}

fn link_entry_package_dir(dir: &Path, key: &GraphKey) -> PathBuf {
    let capacity = dir.as_os_str().len() + LINK_NODE_MODULES.len() + key.name().len() + 2;
    let mut path = PathBuf::with_capacity(capacity);
    path.push(dir);
    path.push(LINK_NODE_MODULES);
    path.push(key.name());
    path
}

fn link_tree_matches_object_tree(
    link_integrities: &TreeIntegrities,
    object_dir: &Path,
) -> Result<bool, LpmError> {
    let object_integrities = compute_object_tree_integrities(object_dir)?;
    Ok(link_integrities.content == object_integrities.content)
}

/// Process-wide striped mutexes serializing local-source snapshot populates.
/// Hash collisions only reduce concurrency; the fixed stripe count bounds
/// memory in long-lived processes that consume many distinct local sources.
fn local_source_populate_lock(object_dir: &Path) -> &'static std::sync::Mutex<()> {
    use std::hash::{Hash, Hasher};

    const LOCK_SHARDS: usize = 256;
    static LOCKS: std::sync::OnceLock<Box<[std::sync::Mutex<()>]>> = std::sync::OnceLock::new();
    let locks = LOCKS.get_or_init(|| {
        std::iter::repeat_with(|| std::sync::Mutex::new(()))
            .take(LOCK_SHARDS)
            .collect()
    });
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    object_dir.hash(&mut hasher);
    &locks[hasher.finish() as usize % LOCK_SHARDS]
}

fn record_local_source_fingerprint(
    object_dir: &Path,
    fingerprint: Option<&LocalSourceFingerprint>,
) {
    let Some(fingerprint) = fingerprint else {
        return;
    };
    if let Err(error) = write_local_source_fingerprint(object_dir, fingerprint) {
        tracing::warn!(
            target = %object_dir.display(),
            "virtual-store local-source object: failed to record source fingerprint: {error}"
        );
    }
}

#[cfg(test)]
mod tests;
