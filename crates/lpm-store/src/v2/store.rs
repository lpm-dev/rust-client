//! v2 store filesystem layer.
//!
//! Splits responsibility cleanly:
//! - [`StoreV2Paths`] — pure path computations (no I/O).
//! - [`Store`] — I/O entry points: object extraction (clonefile-able),
//!   link-entry population (clonefile from objects + sibling symlinks
//!   + atomic rename + sidecar write).
//!
//! v2 writes are gated behind `LPM_STORE_VERSION=v2`.

use std::borrow::Cow;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use lpm_common::integrity::{HashAlgorithm, Integrity};
use lpm_common::{LpmError, LpmRoot};
use sha2::{Digest, Sha256};

use super::finalize_permits::v2_finalize_limiter;
use super::fs_util::{
    copy_dir_recursively, create_dir_symlink, create_tmp_dir_locked, ensure_store_tier_dir_locked,
    materialize_into, tmp_sibling,
};
pub use super::integrity::{
    ENV_V2_OBJECT_INTEGRITY, FreshObjectIntegrity, ObjectIntegrityPolicy,
    ReusableObjectCheckTimings, VerifiedObjectIntegrity,
};
use super::integrity::{
    finish_object_rename_after_collision, is_complete_object_dir, object_dir_is_reusable_or_remove,
    object_integrity_for_link, object_integrity_or_remove, object_integrity_or_remove_with_timings,
    object_integrity_policy_from_env, read_tree_snapshot, source_object_integrity,
    source_policy_uses_source_integrity, tree_snapshot_matches, write_object_integrity_for_policy,
    write_tree_snapshot, write_tree_snapshot_best_effort,
};
use super::local_source::{populate_local_source_object_into, replace_local_source_object};
use super::tree_hash::{
    ExtractedObjectStats, ObjectTreeStats, TreeIntegrities, compute_object_tree_integrities,
    compute_tree_metadata_integrity,
};
use crate::StageTimings;
use crate::v2::graph_key::GraphKey;
use crate::v2::link_meta::{
    LINK_META_FILENAME, LinkMeta, LinkMetaDep, LinkMetaPlatform, validate_name_for_path_join,
};

/// v2 layout version segment under `~/.lpm/store/`. Bumped whenever
/// the on-disk shape changes; lpm reading a higher-numbered store
/// MUST refuse rather than silently misinterpret.
const STORE_V2_VERSION: &str = "v2";

/// Subdirectory holding the content-addressable object dirs.
const OBJECTS_DIR: &str = "objects";

/// Subdirectory holding per-graph-key link entries.
const LINKS_DIR: &str = "links";

/// Subdirectory holding cached project-compatibility islands, keyed by the
/// content hash of the island's entry set. A framework-toolchain island
/// (Next/Turbopack + transitive closure) is built here once and then
/// `clonefile`d into each project's `node_modules/.lpm/compat`, so a warm
/// install reproduces the island in a single recursive syscall instead of
/// re-copying every package.
const COMPAT_DIR: &str = "compat";

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
}

impl StoreV2Paths {
    /// Build the path helper rooted at `<lpm_home>/store/v2/`.
    pub fn from_lpm_root(lpm_root: &LpmRoot) -> Self {
        let root = lpm_root.store_root().join(STORE_V2_VERSION);
        let objects_root = root.join(OBJECTS_DIR);
        let links_root = root.join(LINKS_DIR);
        let compat_root = root.join(COMPAT_DIR);
        Self {
            root,
            objects_root,
            links_root,
            compat_root,
        }
    }

    /// Build the path helper at an arbitrary base (test seam).
    pub fn at(root: impl Into<PathBuf>) -> Self {
        let root = root.into();
        let objects_root = root.join(OBJECTS_DIR);
        let links_root = root.join(LINKS_DIR);
        let compat_root = root.join(COMPAT_DIR);
        Self {
            root,
            objects_root,
            links_root,
            compat_root,
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
    object_integrity_policy: ObjectIntegrityPolicy,
}

impl Store {
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
        Self {
            paths: StoreV2Paths::from_lpm_root(lpm_root),
            object_integrity_policy,
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
        Self {
            paths: StoreV2Paths::at(root),
            object_integrity_policy,
        }
    }

    /// The path helper this Store wraps.
    pub fn paths(&self) -> &StoreV2Paths {
        &self.paths
    }

    pub fn object_integrity_policy(&self) -> ObjectIntegrityPolicy {
        self.object_integrity_policy
    }

    /// Ensure the cached compatibility-island root exists with store-tier
    /// permissions.
    pub fn ensure_compat_root_locked(&self) -> Result<(), LpmError> {
        ensure_store_tier_dir_locked(self.paths.compat_root()).map_err(|e| {
            LpmError::Store(format!(
                "failed to create v2 compat islands dir at {}: {e}",
                self.paths.compat_root().display()
            ))
        })
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
        if !object_dir.exists() {
            return Ok(None);
        }
        let Some(object_integrity) =
            object_integrity_or_remove(&object_dir, "before cache reuse", sri, policy)?
        else {
            return Ok(None);
        };
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
        self.reusable_object_with_timings_and_policy(sri, self.object_integrity_policy)
    }

    fn reusable_object_with_timings_and_policy(
        &self,
        sri: &str,
        policy: ObjectIntegrityPolicy,
    ) -> Result<(Option<ReusableObject>, ReusableObjectCheckTimings), LpmError> {
        let total_start = std::time::Instant::now();
        let mut timings = ReusableObjectCheckTimings::default();
        let object_dir = self.paths.object_dir(sri)?;
        if !object_dir.exists() {
            timings.missing_count = 1;
            timings.total_ms = total_start.elapsed().as_millis();
            return Ok((None, timings));
        }
        let Some(object_integrity) = object_integrity_or_remove_with_timings(
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
    /// `objects/<algo>-<hex>/`, run behavioral security analysis, write
    /// the cache file, and atomically rename into place. Idempotent:
    /// returns the existing object dir if it's already populated.
    ///
    /// Atomic via the standard `dir.with_extension(tmp.<pid>.<tid>)` →
    /// `rename` pattern. `.integrity` and `.lpm-security.json` are
    /// staged inside the tmp dir before the rename, so the published
    /// entry is observable only with both files present.
    ///
    /// Behavioral security analysis lives next to the OBJECT, not next
    /// to each link entry — the analysis is a property of the content
    /// bytes, so link entries sharing a `source_sri` share the result.
    /// This matches v1's placement at
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

    fn extract_object_with_timings_and_policy(
        &self,
        sri: &str,
        tarball_data: &[u8],
        policy: ObjectIntegrityPolicy,
    ) -> Result<(ExtractedObject, StageTimings), LpmError> {
        let object_dir = self.paths.object_dir(sri)?;
        let mut timings = StageTimings::default();

        // Mirrors v1's `store_at_dir` recovery: a leftover `objects/<sri>/`
        // from a crashed extract (no `.integrity`, no `package.json`) is
        // NOT a hit — remove it and re-extract. Without this, a partial
        // crash leaves the install pipeline returning success on a
        // half-populated object dir and downstream link entries inherit
        // the corruption.
        if object_dir.exists()
            && let Some(object_integrity) =
                object_integrity_or_remove(&object_dir, "before re-extract", sri, policy)?
        {
            tracing::debug!(
                target = %object_dir.display(),
                "v2 store: object hit"
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

        if let Some(parent) = object_dir.parent() {
            ensure_store_tier_dir_locked(parent)
                .map_err(|e| LpmError::Store(format!("failed to create v2 objects dir: {e}")))?;
        }

        let tmp_dir = tmp_sibling(&object_dir);
        if tmp_dir.exists() {
            let _ = std::fs::remove_dir_all(&tmp_dir);
        }
        create_tmp_dir_locked(&tmp_dir)
            .map_err(|e| LpmError::Store(format!("failed to create v2 tmp staging dir: {e}")))?;

        // Fused extract + behavioral scan in a single pass: small source
        // entries are buffered and fed directly into the analyzer, while
        // oversized source entries stream to disk first and then get a
        // bounded head/tail sample. The post-extract `finalize` only reads
        // `package.json` for manifest-level tags.
        //
        // `RefCell` wraps the analyzer so the `FnMut` closure can mutate
        // it without exclusive borrows escaping the call site.
        let extract_start = std::time::Instant::now();
        let analyzer = std::cell::RefCell::new(lpm_security::behavioral::PackageAnalyzer::new());
        let extracted_stats = std::cell::RefCell::new(ExtractedObjectStats::default());
        let extract_result = lpm_extractor::extract_tarball_from_reader_with_inspector(
            tarball_data,
            &tmp_dir,
            lpm_security::behavioral::PackageAnalyzer::should_buffer_source,
            |entry| {
                extracted_stats
                    .borrow_mut()
                    .record_file(entry.relative_path, entry.size);
                if let Some(bytes) = entry.bytes {
                    analyzer.borrow_mut().feed(entry.relative_path, bytes);
                } else {
                    analyzer.borrow_mut().feed_oversized_source_file(
                        entry.relative_path,
                        &tmp_dir.join(entry.relative_path),
                        entry.size,
                    );
                }
            },
        );
        if let Err(error) = extract_result {
            let _ = std::fs::remove_dir_all(&tmp_dir);
            return Err(error);
        }
        timings.extract_ms = extract_start.elapsed().as_millis();

        // Manifest-level analysis + cache write. Done BEFORE the atomic
        // rename so the cache file is part of the atomically-published
        // state. Analysis failures are non-fatal: warn and continue
        // (subsequent installs will retry).
        let security_start = std::time::Instant::now();
        let analysis = analyzer.into_inner().finalize(&tmp_dir);
        if let Err(e) = lpm_security::behavioral::write_cached_analysis(&tmp_dir, &analysis) {
            tracing::warn!(
                target = %tmp_dir.display(),
                "v2 store: failed to write .lpm-security.json: {e}"
            );
        }
        timings.security_ms = security_start.elapsed().as_millis();

        let finalize_permit_wait_start = std::time::Instant::now();
        let _finalize_permit = v2_finalize_limiter().map(|limiter| limiter.acquire());
        timings.finalize_permit_wait_ms = finalize_permit_wait_start.elapsed().as_millis();

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
                "failed to write v2 .integrity: {e}"
            )));
        }

        let rename_start = std::time::Instant::now();
        let rename_result = std::fs::rename(&tmp_dir, &object_dir);
        timings.finalize_rename_ms = rename_start.elapsed().as_millis();
        let result = match rename_result {
            Ok(()) => Ok(ExtractedObject {
                path: object_dir,
                source_sri: sri.to_string(),
                object_integrity,
            }),
            Err(e) => {
                let collision_start = std::time::Instant::now();
                let result = finish_object_rename_after_collision(
                    &tmp_dir,
                    &object_dir,
                    sri,
                    "v2 extract",
                    e,
                    policy,
                );
                timings.finalize_collision_recovery_ms = collision_start.elapsed().as_millis();
                let object_dir = result?;
                let object_integrity = object_integrity_or_remove(
                    &object_dir,
                    "after v2 extract collision",
                    sri,
                    policy,
                )?
                .ok_or_else(|| {
                    LpmError::Store(format!(
                        "v2 extract collision left no reusable object at {}",
                        object_dir.display()
                    ))
                })?;
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
    /// This is the install pipeline's v2 entry point: it pairs with
    /// the post-W6a flow that buffers `response.bytes()` into memory
    /// before extracting (the permit is released between download
    /// and extract, so the buffer doesn't pin a network slot).
    ///
    /// `expected_integrity` is the registry-supplied SRI. If `Some`
    /// and starts with `sha512-`, mismatch returns
    /// [`LpmError::IntegrityMismatch`]. Non-sha512 expected values
    /// are logged + trusted (matches v1's
    /// `stream_and_store_package` policy at lib.rs:644-658).
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
                    "unsupported integrity algorithm in v2 extract: {expected} — \
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
                "fresh v2 link extracted object SRI mismatch: fresh {}, request {}",
                fresh_object.source_sri, request.source_sri
            )));
        }
        let expected_object_dir = self.paths.object_dir(&request.source_sri)?;
        if request.object_dir != expected_object_dir {
            return Err(LpmError::Store(format!(
                "fresh v2 link request object path mismatch for {}: request {}, expected {}",
                request.source_sri,
                request.object_dir.display(),
                expected_object_dir.display()
            )));
        }
        if fresh_object.path != expected_object_dir {
            return Err(LpmError::Store(format!(
                "fresh v2 link extracted object path mismatch for {}: fresh {}, expected {}",
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
                policy,
            )? {
                timings.reuse_check_ms = reuse_check_start.elapsed().as_millis();
                // Refresh the sidecar's "last referenced" via a single
                // set_modified() call instead of read+touch+write+rename.
                // On a 256-package warm install that's 256 fewer JSON
                // parses and rename syscall trios. `lpm cache prune
                // --max-age` reads the effective time via
                // `LinkMeta::effective_last_referenced_at`, which takes
                // `max(json_field, file_mtime)`.
                let sidecar_path = final_dir.join(LINK_META_FILENAME);
                if let Err(e) = LinkMeta::touch_on_disk(&sidecar_path) {
                    // Non-fatal: a missed touch only widens prune's
                    // view of cold entries by one install cycle.
                    tracing::debug!("v2 store: cache-hit touch failed: {e}");
                }
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
            timings.reuse_check_ms = reuse_check_start.elapsed().as_millis();

            tracing::warn!(
                target = %final_dir.display(),
                "v2 store: incomplete or stale link entry; removing before re-populate"
            );
            std::fs::remove_dir_all(&final_dir).map_err(|e| {
                LpmError::Store(format!(
                    "failed to remove incomplete or stale v2 link entry at {}: {e}",
                    final_dir.display()
                ))
            })?;
        }

        if let Some(parent) = final_dir.parent() {
            ensure_store_tier_dir_locked(parent)
                .map_err(|e| LpmError::Store(format!("failed to create v2 links dir: {e}")))?;
        }

        let tmp_dir = tmp_sibling(&final_dir);
        if tmp_dir.exists() {
            let _ = std::fs::remove_dir_all(&tmp_dir);
        }
        create_tmp_dir_locked(&tmp_dir)
            .map_err(|e| LpmError::Store(format!("failed to create v2 tmp staging dir: {e}")))?;

        // Run the atomic-staging body in a closure so a single error
        // path can clean up the tmp dir uniformly. Anything that
        // fails inside `populate_into` removes `tmp_dir` and surfaces
        // the original error.
        let result = populate_into(
            &tmp_dir,
            &graph_key,
            PopulateObject {
                dir: &object_dir,
                source_sri: &source_sri,
                sidecar_relpath: &sidecar_dir_relpath,
                policy,
                fresh_object_integrity: fresh_object_digest,
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
                    policy,
                )? {
                    // Concurrent install beat us — discard our stage and
                    // refresh the existing sidecar's mtime.
                    let _ = std::fs::remove_dir_all(&tmp_dir);
                    let sidecar_path = final_dir.join(LINK_META_FILENAME);
                    if let Err(e) = LinkMeta::touch_on_disk(&sidecar_path) {
                        tracing::debug!("v2 store: race-loss touch failed: {e}");
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
                        "v2 store: rename hit incomplete or stale leftover; removing and retrying once"
                    );
                    if let Err(e) = std::fs::remove_dir_all(&final_dir) {
                        let _ = std::fs::remove_dir_all(&tmp_dir);
                        return Err(LpmError::Store(format!(
                            "failed to remove incomplete or stale v2 link entry during retry at {}: {e}",
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
                                "failed to atomically install v2 link entry on retry: {e}"
                            )))
                        }
                    };
                }
                let _ = std::fs::remove_dir_all(&tmp_dir);
                Err(LpmError::Store(format!(
                    "failed to atomically install v2 link entry: {e}"
                )))
            }
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
                "failed to enumerate v2 links root at {}: {e}",
                links_root.display()
            ))
        })?;
        let iter = read_dir.filter_map(|entry| {
            let entry = entry.ok()?;
            let link_dir = entry.path();
            let file_type = entry.file_type().ok()?;
            if file_type.is_symlink() {
                tracing::warn!(
                    "v2 store: refusing symlinked link entry at {} (store writer never creates symlinks here; tamper signal)",
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
                        "v2 store: skipping {}: sidecar unreadable ({e})",
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
                "failed to enumerate v2 links root at {}: {e}",
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
                        "v2 link entry is a symlink (store writer never creates symlinks at links/<entry>; refusing to follow into an outside-store path)".to_string(),
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
                "v2 link entry {} is incomplete; cannot key compatibility island",
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
    /// - The `.integrity` sidecar (rewritten to `sri` for byte-
    ///   accuracy, since v1 may have a slightly different normalized
    ///   form).
    /// - The `.lpm-security.json` cache, if present in `v1_pkg_dir`.
    ///   Security analysis is content-determined; copying the cache
    ///   skips the multi-millisecond re-analysis on warm-cache
    ///   migrations. If absent, the helper re-runs analysis to
    ///   match `extract_object`'s post-write contract.
    ///
    /// **Limitation.** This helper trusts the caller to provide a
    /// `(v1_pkg_dir, sri)` pair where the SRI matches the extracted
    /// bytes. The install pipeline derives `sri` from the lockfile
    /// or from the prior install's recorded integrity; both come
    /// from the same SHA-512 the v1 extract recorded, so the trust
    /// is sound under normal flows. A pathological `(v1_pkg_dir,
    /// wrong_sri)` pair would land bytes at the wrong v2 key, but
    /// that's an upstream programmer error, not a security boundary
    /// the helper enforces.
    pub fn populate_object_from_v1(
        &self,
        v1_pkg_dir: &Path,
        sri: &str,
    ) -> Result<PathBuf, LpmError> {
        let policy = self.object_integrity_policy;
        let object_dir = self.paths.object_dir(sri)?;
        if object_dir.exists()
            && object_dir_is_reusable_or_remove(
                &object_dir,
                "before v1 to v2 translation",
                sri,
                policy,
            )?
        {
            return Ok(object_dir);
        }
        if !v1_pkg_dir.is_dir() {
            return Err(LpmError::Store(format!(
                "v1 → v2 translation: source dir {} is not readable",
                v1_pkg_dir.display()
            )));
        }
        if let Some(parent) = object_dir.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| LpmError::Store(format!("failed to create v2 objects dir: {e}")))?;
        }
        let tmp_dir = tmp_sibling(&object_dir);
        if tmp_dir.exists() {
            let _ = std::fs::remove_dir_all(&tmp_dir);
        }
        create_tmp_dir_locked(&tmp_dir)
            .map_err(|e| LpmError::Store(format!("failed to create v2 tmp staging dir: {e}")))?;

        copy_dir_recursively(v1_pkg_dir, &tmp_dir).map_err(|e| {
            let _ = std::fs::remove_dir_all(&tmp_dir);
            LpmError::Store(format!(
                "v1 → v2 translation: failed to copy {} → {}: {e}",
                v1_pkg_dir.display(),
                tmp_dir.display()
            ))
        })?;

        // If v1 didn't ship a security cache (rare, but possible on
        // a stale or partial v1 entry), re-run analysis so the v2
        // post-write contract holds.
        if !tmp_dir.join(".lpm-security.json").is_file() {
            let analysis = lpm_security::behavioral::analyze_package(&tmp_dir);
            if let Err(e) = lpm_security::behavioral::write_cached_analysis(&tmp_dir, &analysis) {
                tracing::warn!("v2 translation: failed to write .lpm-security.json: {e}");
            }
        }

        if let Err(e) = write_object_integrity_for_policy(&tmp_dir, sri, policy) {
            let _ = std::fs::remove_dir_all(&tmp_dir);
            return Err(e);
        }
        if let Err(e) = std::fs::write(tmp_dir.join(".integrity"), sri) {
            let _ = std::fs::remove_dir_all(&tmp_dir);
            return Err(LpmError::Store(format!(
                "failed to write v2 .integrity during v1 translation: {e}"
            )));
        }

        std::fs::rename(&tmp_dir, &object_dir)
            .map(|()| object_dir.clone())
            .or_else(|e| {
                finish_object_rename_after_collision(
                    &tmp_dir,
                    &object_dir,
                    sri,
                    "v1 to v2 translation",
                    e,
                    policy,
                )
            })
    }

    /// Populate `objects/<sri>/` from a live local source directory.
    ///
    /// The populated object is a real-file snapshot of the source
    /// tree. The synthetic SRI is a stable identity key rather than a
    /// content hash, so each populate refreshes the snapshot to pick
    /// up added, changed, and removed files.
    pub fn populate_object_from_local_source(
        &self,
        source_dir: &Path,
        sri: &str,
    ) -> Result<PathBuf, LpmError> {
        let canonical_source = source_dir.canonicalize().map_err(|e| {
            LpmError::Store(format!(
                "v2 local-source object: failed to canonicalize {}: {e}",
                source_dir.display()
            ))
        })?;
        let object_dir = self.paths.object_dir(sri)?;

        if let Some(parent) = object_dir.parent() {
            ensure_store_tier_dir_locked(parent)
                .map_err(|e| LpmError::Store(format!("failed to create v2 objects dir: {e}")))?;
        }

        let tmp_dir = tmp_sibling(&object_dir);
        if tmp_dir.exists() {
            let _ = std::fs::remove_dir_all(&tmp_dir);
        }
        create_tmp_dir_locked(&tmp_dir)
            .map_err(|e| LpmError::Store(format!("failed to create v2 tmp staging dir: {e}")))?;

        if let Err(e) = populate_local_source_object_into(&canonical_source, &tmp_dir, sri) {
            let _ = std::fs::remove_dir_all(&tmp_dir);
            return Err(e);
        }

        replace_local_source_object(&tmp_dir, &object_dir, &canonical_source)?;
        Ok(object_dir)
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
                "failed to enumerate v2 objects root at {}: {e}",
                objects_root.display()
            ))
        })?;
        let iter = read_dir.filter_map(|entry| {
            let entry = entry.ok()?;
            let object_dir = entry.path();
            let file_type = entry.file_type().ok()?;
            if file_type.is_symlink() {
                tracing::warn!(
                    "v2 store: refusing symlinked object entry at {} (store writer never creates symlinks here; tamper signal)",
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
    source_sri: &'a str,
    sidecar_relpath: &'a str,
    policy: ObjectIntegrityPolicy,
    fresh_object_integrity: Option<&'a FreshObjectIntegrity>,
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
            "failed to create v2 link node_modules at {}: {e}",
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
                "failed to create v2 link package parent at {}: {e}",
                parent.display()
            ))
        })?;
    }
    let materialize_start = std::time::Instant::now();
    materialize_into(object.dir, &pkg_dir)?;
    timings.materialize_ms = materialize_start.elapsed().as_millis();
    let snapshot_start = std::time::Instant::now();
    let package_metadata_integrity = compute_tree_metadata_integrity(&pkg_dir)?;
    write_tree_snapshot(
        tmp_dir,
        &TreeIntegrities {
            content: object_integrity.into_owned(),
            metadata: package_metadata_integrity,
            stats: ObjectTreeStats::default(),
        },
    )?;
    timings.snapshot_ms = snapshot_start.elapsed().as_millis();

    // Sibling-dep symlinks. Each lives next to the package (siblings
    // under the wrapper-level node_modules) — same shape as the
    // existing isolated linker contract.
    let symlink_start = std::time::Instant::now();
    for dep in deps {
        create_sibling_symlink(&node_modules, dep, graph_key)?;
    }
    timings.symlink_ms = symlink_start.elapsed().as_millis();

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
    );
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
            "unsafe dependency local name {:?} in v2 link entry for {}: {why}",
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
            "failed to create v2 sibling symlink {} → {} (self={}): {e}",
            link_path.display(),
            target.display(),
            self_key.dir_name()
        ))
    })
}

fn ensure_sibling_parent_dir(base: &Path, link_path: &Path, label: &str) -> Result<(), LpmError> {
    let Some(parent) = link_path.parent() else {
        return Err(LpmError::Store(format!(
            "v2 {label} link path has no parent: {}",
            link_path.display()
        )));
    };
    if parent == base {
        return Ok(());
    }
    let relative = parent.strip_prefix(base).map_err(|e| {
        LpmError::Store(format!(
            "v2 {label} parent {} is outside base {}: {e}",
            parent.display(),
            base.display()
        ))
    })?;
    let mut current = base.to_path_buf();
    for component in relative.components() {
        let std::path::Component::Normal(name) = component else {
            return Err(LpmError::Store(format!(
                "v2 {label} parent contains unsafe component at {}",
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
            "refusing to create v2 {label} through non-directory path at {}",
            path.display()
        ))),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            match std::fs::create_dir(path) {
                Ok(()) => Ok(()),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    ensure_real_dir_or_create(path, label)
                }
                Err(error) => Err(LpmError::Store(format!(
                    "failed to create v2 {label} directory at {}: {error}",
                    path.display()
                ))),
            }
        }
        Err(error) => Err(LpmError::Store(format!(
            "failed to inspect v2 {label} directory at {}: {error}",
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
    policy: ObjectIntegrityPolicy,
) -> Result<bool, LpmError> {
    if !is_complete_link_entry(dir, key) {
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

#[cfg(test)]
mod tests;
