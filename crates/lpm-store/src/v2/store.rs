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
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use lpm_common::integrity::{HashAlgorithm, Integrity};
use lpm_common::{LpmError, LpmRoot, write_file_atomic};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

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

/// Derive the filesystem-safe content key for a cached compatibility island
/// from its entry set.
///
/// The key is a SHA-256 over the schema tag plus the island's
/// graph-key dir-names in sorted order, so two installs that produce the
/// same island (same toolchain dependency closure) resolve to the same
/// cached island regardless of entry order. Each dir-name already encodes
/// `name@version+<context-digest>`, and a package's content SRI is fixed for
/// a given `name@version`, so the dir-name set fully determines island
/// content.
pub fn compat_island_key(entry_dir_names: &[&str]) -> String {
    let mut names: Vec<&str> = entry_dir_names.to_vec();
    names.sort_unstable();
    let mut hasher = Sha256::new();
    hasher.update(COMPAT_ISLAND_SCHEMA.as_bytes());
    hasher.update(b"\0");
    for name in &names {
        hasher.update(name.as_bytes());
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

/// Marker file written into synthetic local-source objects.
const LOCAL_SOURCE_OBJECT_SENTINEL: &str = ".lpm-local-source";

/// Deterministic digest over the extracted package tree. `.integrity`
/// records the source tarball SRI; this records the bytes lpm links
/// from cache on later installs.
const OBJECT_TREE_INTEGRITY_FILENAME: &str = ".lpm-object-integrity";
const TREE_SNAPSHOT_FILENAME: &str = ".lpm-tree-snapshot.json";
const TREE_SNAPSHOT_SCHEMA_VERSION: u32 = 1;
const TREE_SNAPSHOT_MAX_BYTES: u64 = 4096;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct TreeSnapshot {
    schema: u32,
    content_integrity: String,
    metadata_integrity: String,
}

struct TreeIntegrities {
    content: String,
    metadata: String,
}

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

/// Object-tree digest that has been checked against the object bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedObjectTreeIntegrity(String);

impl VerifiedObjectTreeIntegrity {
    #[inline]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    #[inline]
    fn new(digest: String) -> Self {
        Self(digest)
    }
}

/// Object directory that is complete and has a verified tree digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReusableObject {
    pub path: PathBuf,
    pub tree_integrity: VerifiedObjectTreeIntegrity,
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
}

impl Store {
    /// Resolve the v2 store from the given LPM home.
    pub fn from_lpm_root(lpm_root: &LpmRoot) -> Self {
        Self {
            paths: StoreV2Paths::from_lpm_root(lpm_root),
        }
    }

    /// Mount the store at an arbitrary path (test seam).
    pub fn at(root: impl Into<PathBuf>) -> Self {
        Self {
            paths: StoreV2Paths::at(root),
        }
    }

    /// The path helper this Store wraps.
    pub fn paths(&self) -> &StoreV2Paths {
        &self.paths
    }

    /// Return the object directory when `sri` is already present and
    /// its extracted-tree digest still matches. Incomplete or stale
    /// objects are removed so callers can safely refetch before
    /// linking.
    pub fn reusable_object_dir(&self, sri: &str) -> Result<Option<PathBuf>, LpmError> {
        Ok(self.reusable_object(sri)?.map(|object| object.path))
    }

    /// Return the object directory plus the verified object-tree digest.
    pub fn reusable_object(&self, sri: &str) -> Result<Option<ReusableObject>, LpmError> {
        let object_dir = self.paths.object_dir(sri)?;
        if !object_dir.exists() {
            return Ok(None);
        }
        let Some(tree_integrity) =
            object_tree_integrity_or_remove(&object_dir, "before cache reuse")?
        else {
            return Ok(None);
        };
        Ok(Some(ReusableObject {
            path: object_dir,
            tree_integrity,
        }))
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
        let object_dir = self.paths.object_dir(sri)?;
        let mut timings = StageTimings::default();

        // Mirrors v1's `store_at_dir` recovery: a leftover `objects/<sri>/`
        // from a crashed extract (no `.integrity`, no `package.json`) is
        // NOT a hit — remove it and re-extract. Without this, a partial
        // crash leaves the install pipeline returning success on a
        // half-populated object dir and downstream link entries inherit
        // the corruption.
        if object_dir.exists()
            && object_dir_is_reusable_or_remove(&object_dir, "before re-extract")?
        {
            tracing::debug!(
                target = %object_dir.display(),
                "v2 store: object hit"
            );
            return Ok((object_dir, timings));
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

        // Fused extract + behavioral scan in a single pass: `should_scan`
        // filters per entry inside the tar walk, and the inspector
        // closure feeds matching entries' bytes into the analyzer while
        // they're still in the extractor's write buffer. The
        // post-extract `finalize` only reads `package.json` for
        // manifest-level tags — no second tree walk, no re-`read()` of
        // source files.
        //
        // `RefCell` wraps the analyzer so the `FnMut` closure can mutate
        // it without exclusive borrows escaping the call site.
        let extract_start = std::time::Instant::now();
        let analyzer = std::cell::RefCell::new(lpm_security::behavioral::PackageAnalyzer::new());
        let extract_result = lpm_extractor::extract_tarball_from_reader_with_inspector(
            tarball_data,
            &tmp_dir,
            lpm_security::behavioral::PackageAnalyzer::should_scan,
            |entry| {
                if let Some(bytes) = entry.bytes {
                    analyzer.borrow_mut().feed(entry.relative_path, bytes);
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

        // Persist the SRI alongside the object bytes for
        // post-extraction integrity verification — same `.integrity`
        // file as v1 so `lpm store verify --deep` keeps working in
        // mixed-v1/v2 environments. Also load-bearing for
        // [`is_complete_object_dir`]'s incompleteness probe.
        let finalize_start = std::time::Instant::now();
        if let Err(e) = write_object_tree_integrity(&tmp_dir) {
            let _ = std::fs::remove_dir_all(&tmp_dir);
            return Err(e);
        }
        if let Err(e) = std::fs::write(tmp_dir.join(".integrity"), sri) {
            let _ = std::fs::remove_dir_all(&tmp_dir);
            return Err(LpmError::Store(format!(
                "failed to write v2 .integrity: {e}"
            )));
        }

        let result = std::fs::rename(&tmp_dir, &object_dir)
            .map(|()| object_dir.clone())
            .or_else(|e| {
                finish_object_rename_after_collision(&tmp_dir, &object_dir, "v2 extract", e)
            });
        timings.finalize_ms = finalize_start.elapsed().as_millis();

        result.map(|dir| (dir, timings))
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
        let computed_sri = crate::compute_sri_hash(tarball_data);

        // M18: verify against the algorithm declared in `expected`.
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

        let (object_dir, timings) =
            self.extract_object_with_timings(&computed_sri, tarball_data)?;
        Ok((object_dir, computed_sri, timings))
    }

    /// Populate `links/<graph-key>/` with the package bytes, sibling
    /// symlinks, and sidecar metadata. Idempotent: if the entry is
    /// already complete and its package tree still matches the source
    /// object digest, refreshes [`LinkMeta::last_referenced_at`] and
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
        self.populate_link_entry_inner(request, None)
    }

    /// Populate a link entry using a previously verified object-tree digest.
    pub fn populate_link_entry_with_verified_object(
        &self,
        request: LinkEntryRequest,
        verified_object_tree_integrity: &VerifiedObjectTreeIntegrity,
    ) -> Result<LinkEntry, LpmError> {
        self.populate_link_entry_inner(request, Some(verified_object_tree_integrity))
    }

    fn populate_link_entry_inner(
        &self,
        request: LinkEntryRequest,
        verified_object_tree_digest: Option<&VerifiedObjectTreeIntegrity>,
    ) -> Result<LinkEntry, LpmError> {
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
            if link_entry_is_reusable(
                &final_dir,
                &graph_key,
                &object_dir,
                verified_object_tree_digest,
            )? {
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
                });
            }

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
            &object_dir,
            &deps,
            &source_sri,
            &sidecar_dir_relpath,
            &platform,
        );

        let sidecar = match result {
            Ok(sidecar) => sidecar,
            Err(e) => {
                let _ = std::fs::remove_dir_all(&tmp_dir);
                return Err(e);
            }
        };

        match std::fs::rename(&tmp_dir, &final_dir) {
            Ok(()) => Ok(LinkEntry {
                link_dir: final_dir,
                freshly_populated: true,
                sidecar: Some(sidecar),
            }),
            Err(_)
                if link_entry_is_reusable(
                    &final_dir,
                    &graph_key,
                    &object_dir,
                    verified_object_tree_digest,
                )? =>
            {
                // Concurrent install beat us — discard our stage and
                // refresh the existing sidecar's mtime.
                let _ = std::fs::remove_dir_all(&tmp_dir);
                let sidecar_path = final_dir.join(LINK_META_FILENAME);
                if let Err(e) = LinkMeta::touch_on_disk(&sidecar_path) {
                    tracing::debug!("v2 store: race-loss touch failed: {e}");
                }
                Ok(LinkEntry {
                    link_dir: final_dir,
                    freshly_populated: false,
                    sidecar: None,
                })
            }
            Err(_) if final_dir.exists() => {
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
                match std::fs::rename(&tmp_dir, &final_dir) {
                    Ok(()) => Ok(LinkEntry {
                        link_dir: final_dir,
                        freshly_populated: true,
                        sidecar: Some(sidecar),
                    }),
                    Err(e) => {
                        let _ = std::fs::remove_dir_all(&tmp_dir);
                        Err(LpmError::Store(format!(
                            "failed to atomically install v2 link entry on retry: {e}"
                        )))
                    }
                }
            }
            Err(e) => {
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
        let object_dir = self.paths.object_dir(sri)?;
        if object_dir.exists()
            && object_dir_is_reusable_or_remove(&object_dir, "before v1 to v2 translation")?
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

        if let Err(e) = write_object_tree_integrity(&tmp_dir) {
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
                    "v1 to v2 translation",
                    e,
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

        replace_local_source_object(&tmp_dir, &object_dir)?;
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

fn populate_into(
    tmp_dir: &Path,
    graph_key: &GraphKey,
    object_dir: &Path,
    deps: &[DepLink],
    source_sri: &str,
    sidecar_relpath: &str,
    platform: &Arc<LinkMetaPlatform>,
) -> Result<LinkMeta, LpmError> {
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
    let object_integrity = verified_object_tree_integrity(object_dir)?;
    let pkg_dir = node_modules.join(graph_key.name());
    if let Some(parent) = pkg_dir.parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            LpmError::Store(format!(
                "failed to create v2 link package parent at {}: {e}",
                parent.display()
            ))
        })?;
    }
    materialize_into(object_dir, &pkg_dir)?;
    let package_metadata_integrity = compute_tree_metadata_integrity(&pkg_dir)?;
    write_tree_snapshot(
        tmp_dir,
        &TreeIntegrities {
            content: object_integrity,
            metadata: package_metadata_integrity,
        },
    )?;

    // Sibling-dep symlinks. Each lives next to the package (siblings
    // under the wrapper-level node_modules) — same shape as the
    // existing isolated linker contract.
    for dep in deps {
        create_sibling_symlink(&node_modules, dep, graph_key)?;
    }

    // Stage the sidecar BEFORE the rename so the published entry is
    // never observable without its metadata.
    let mut deps_meta: Vec<LinkMetaDep> = Vec::with_capacity(deps.len());
    for dep in deps {
        deps_meta.push(dep.clone().into_meta_dep());
    }
    let sidecar = LinkMeta::new(
        graph_key,
        source_sri,
        sidecar_relpath,
        deps_meta,
        Arc::clone(platform),
    );
    // `tmp_dir` is the unpublished staging dir; the outer rename in
    // `populate_link_entry` is the visibility boundary, so we can skip the
    // tmp+rename dance and write the sidecar straight in. See
    // [`LinkMeta::write_to_unpublished`] for the atomicity contract.
    sidecar.write_to_unpublished(tmp_dir)?;

    Ok(sidecar)
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

    // Link path: `<...>/node_modules/<dep.local>/`.
    let link_path = node_modules.join(&dep.local);

    // For scoped deps (`@scope/name`), the local will already contain a
    // `/`. We need to make sure the parent (`@scope/`) directory exists.
    if let Some(parent) = link_path.parent()
        && parent != node_modules
        && !parent.exists()
    {
        std::fs::create_dir_all(parent).map_err(|e| {
            LpmError::Store(format!(
                "failed to create v2 sibling parent at {}: {e}",
                parent.display()
            ))
        })?;
    }

    // The symlink at `links/<self>/node_modules/<dep.local>/` resolves
    // relative to its parent directory `links/<self>/node_modules/`.
    // To reach the sibling target at
    // `links/<dep.target.dir>/node_modules/<dep.target.name>/` we need
    // to ascend two levels (out of `node_modules/`, then out of
    // `<self>/`) and then descend back down. Scoped locals
    // (`@scope/dep`) sit one level deeper, so add one `..` per `/`
    // segment in the local name. The shape is
    // `../../<dep.dir>/node_modules/<dep.name>` for non-scoped deps.
    let depth = depth_of_local(&dep.local);
    let mut target = PathBuf::new();
    for _ in 0..(depth + 2) {
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
    verified_object_tree_digest: Option<&VerifiedObjectTreeIntegrity>,
) -> Result<bool, LpmError> {
    if !is_complete_link_entry(dir, key) {
        return Ok(false);
    }
    let expected = match verified_object_tree_digest {
        Some(digest) => Cow::Borrowed(digest.as_str()),
        None => Cow::Owned(verified_object_tree_integrity(object_dir)?),
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

/// Object dir is complete iff the package root and both object
/// integrity sidecars are present. This is a cheap crash-recovery
/// predicate; callers that will reuse the object must also verify the
/// tree digest.
fn is_complete_object_dir(dir: &Path) -> bool {
    dir.is_dir()
        && is_regular_file_no_symlink(&dir.join("package.json"))
        && is_regular_file_no_symlink(&dir.join(".integrity"))
        && is_regular_file_no_symlink(&dir.join(OBJECT_TREE_INTEGRITY_FILENAME))
}

fn is_regular_file_no_symlink(path: &Path) -> bool {
    std::fs::symlink_metadata(path)
        .map(|metadata| metadata.file_type().is_file())
        .unwrap_or(false)
}

fn object_dir_is_reusable_or_remove(dir: &Path, context: &str) -> Result<bool, LpmError> {
    Ok(object_tree_integrity_or_remove(dir, context)?.is_some())
}

fn object_tree_integrity_or_remove(
    dir: &Path,
    context: &str,
) -> Result<Option<VerifiedObjectTreeIntegrity>, LpmError> {
    if !is_complete_object_dir(dir) {
        remove_unusable_object_dir(dir, context)?;
        return Ok(None);
    }
    match verified_object_tree_integrity(dir) {
        Ok(digest) => Ok(Some(VerifiedObjectTreeIntegrity::new(digest))),
        Err(err) => {
            tracing::warn!(
                target = %dir.display(),
                "v2 store: treating object as unusable {context}: {err}"
            );
            remove_unusable_object_dir(dir, context)?;
            Ok(None)
        }
    }
}

fn remove_unusable_object_dir(dir: &Path, context: &str) -> Result<(), LpmError> {
    let claimed_dir = claim_unusable_object_dir(dir, context)?;
    let Some(claimed_dir) = claimed_dir else {
        return Ok(());
    };
    tracing::warn!(
        target = %dir.display(),
        "v2 store: removing incomplete or unverifiable object {context}"
    );
    std::fs::remove_dir_all(&claimed_dir).map_err(|e| {
        LpmError::Store(format!(
            "failed to remove incomplete or unverifiable v2 object at {} {context}: {e}",
            dir.display()
        ))
    })
}

fn claim_unusable_object_dir(dir: &Path, context: &str) -> Result<Option<PathBuf>, LpmError> {
    for _ in 0..8 {
        let claimed_dir = tmp_sibling(dir);
        match std::fs::rename(dir, &claimed_dir) {
            Ok(()) => return Ok(Some(claimed_dir)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => {
                return Err(LpmError::Store(format!(
                    "failed to claim incomplete or unverifiable v2 object at {} {context}: {e}",
                    dir.display()
                )));
            }
        }
    }
    Err(LpmError::Store(format!(
        "failed to claim incomplete or unverifiable v2 object at {} {context}: could not allocate a temporary removal path",
        dir.display()
    )))
}

fn finish_object_rename_after_collision(
    tmp_dir: &Path,
    object_dir: &Path,
    context: &str,
    original_error: std::io::Error,
) -> Result<PathBuf, LpmError> {
    if object_dir.exists() {
        match is_verified_object_dir(object_dir) {
            Ok(true) => {
                let _ = std::fs::remove_dir_all(tmp_dir);
                return Ok(object_dir.to_path_buf());
            }
            Ok(false) => remove_unusable_object_dir(object_dir, "after rename collision")?,
            Err(err) => {
                tracing::warn!(
                    target = %object_dir.display(),
                    "v2 store: treating collided object as unusable during {context}: {err}"
                );
                remove_unusable_object_dir(object_dir, "after rename collision")?;
            }
        }
        return std::fs::rename(tmp_dir, object_dir)
            .map(|()| object_dir.to_path_buf())
            .map_err(|retry_error| {
                let _ = std::fs::remove_dir_all(tmp_dir);
                LpmError::Store(format!(
                    "{context}: failed to replace unusable v2 object after rename collision: {retry_error}; original rename error: {original_error}"
                ))
            });
    }

    let _ = std::fs::remove_dir_all(tmp_dir);
    Err(LpmError::Store(format!(
        "{context}: failed to atomically install v2 object: {original_error}"
    )))
}

fn is_verified_object_dir(dir: &Path) -> Result<bool, LpmError> {
    if !is_complete_object_dir(dir) {
        return Ok(false);
    }
    object_tree_integrity_matches(dir)
}

fn object_tree_integrity_matches(dir: &Path) -> Result<bool, LpmError> {
    let expected = read_object_tree_integrity(dir)?;
    let actual = compute_object_tree_integrity(dir)?;
    Ok(expected == actual)
}

fn verified_object_tree_integrity(dir: &Path) -> Result<String, LpmError> {
    let expected = read_object_tree_integrity(dir)?;
    if tree_snapshot_matches(dir, dir, &expected)? {
        return Ok(expected);
    }
    let actual = compute_object_tree_integrities(dir)?;
    if expected == actual.content {
        write_tree_snapshot_best_effort(dir, &actual);
        return Ok(expected);
    }
    Err(LpmError::Store(format!(
        "v2 object integrity mismatch at {}: expected {expected}, actual {}",
        dir.display(),
        actual.content
    )))
}

fn tree_snapshot_matches(
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

fn read_tree_snapshot(dir: &Path) -> Option<TreeSnapshot> {
    let path = dir.join(TREE_SNAPSHOT_FILENAME);
    let metadata = match std::fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return None,
        Err(error) => {
            tracing::debug!(
                target = %path.display(),
                "v2 store: ignoring unreadable tree snapshot: {error}"
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
            "v2 store: ignoring oversized tree snapshot"
        );
        return None;
    }
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) => {
            tracing::debug!(
                target = %path.display(),
                "v2 store: ignoring unreadable tree snapshot: {error}"
            );
            return None;
        }
    };
    let snapshot: TreeSnapshot = match serde_json::from_slice(&bytes) {
        Ok(snapshot) => snapshot,
        Err(error) => {
            tracing::debug!(
                target = %path.display(),
                "v2 store: ignoring malformed tree snapshot: {error}"
            );
            return None;
        }
    };
    if snapshot.schema != TREE_SNAPSHOT_SCHEMA_VERSION {
        return None;
    }
    if !valid_sha256_integrity(&snapshot.content_integrity)
        || !valid_sha256_integrity(&snapshot.metadata_integrity)
    {
        return None;
    }
    Some(snapshot)
}

fn valid_sha256_integrity(value: &str) -> bool {
    let Some(hex_part) = value.strip_prefix("sha256-") else {
        return false;
    };
    hex_part.len() == 64 && hex_part.as_bytes().iter().all(u8::is_ascii_hexdigit)
}

fn write_tree_snapshot_best_effort(dir: &Path, integrities: &TreeIntegrities) {
    if let Err(error) = write_tree_snapshot(dir, integrities) {
        tracing::debug!(
            target = %dir.display(),
            "v2 store: failed to refresh tree snapshot: {error}"
        );
    }
}

fn write_tree_snapshot(dir: &Path, integrities: &TreeIntegrities) -> Result<(), LpmError> {
    let snapshot = TreeSnapshot {
        schema: TREE_SNAPSHOT_SCHEMA_VERSION,
        content_integrity: integrities.content.clone(),
        metadata_integrity: integrities.metadata.clone(),
    };
    let bytes = serde_json::to_vec(&snapshot)
        .map_err(|e| LpmError::Store(format!("failed to serialize v2 tree snapshot: {e}")))?;
    let final_path = dir.join(TREE_SNAPSHOT_FILENAME);
    write_file_atomic(&final_path, bytes).map_err(|error| {
        LpmError::Store(format!(
            "failed to atomically install v2 tree snapshot at {}: {error}",
            final_path.display()
        ))
    })
}

fn read_object_tree_integrity(dir: &Path) -> Result<String, LpmError> {
    let path = dir.join(OBJECT_TREE_INTEGRITY_FILENAME);
    if !is_regular_file_no_symlink(&path) {
        return Err(LpmError::Store(format!(
            "v2 object integrity sidecar is missing or not a regular file at {}",
            path.display()
        )));
    }
    let raw = std::fs::read_to_string(&path).map_err(|e| {
        LpmError::Store(format!(
            "failed to read v2 object integrity sidecar at {}: {e}",
            path.display()
        ))
    })?;
    let digest = raw.trim();
    let hex_part = digest.strip_prefix("sha256-").ok_or_else(|| {
        LpmError::Store(format!(
            "invalid v2 object integrity sidecar at {}: expected sha256-<hex>",
            path.display()
        ))
    })?;
    if hex_part.len() != 64 || !hex_part.as_bytes().iter().all(u8::is_ascii_hexdigit) {
        return Err(LpmError::Store(format!(
            "invalid v2 object integrity sidecar at {}: expected sha256-<64 hex chars>",
            path.display()
        )));
    }
    Ok(digest.to_string())
}

fn write_object_tree_integrity(dir: &Path) -> Result<(), LpmError> {
    let integrities = compute_object_tree_integrities(dir)?;
    std::fs::write(
        dir.join(OBJECT_TREE_INTEGRITY_FILENAME),
        format!("{}\n", integrities.content),
    )
    .map_err(|e| LpmError::Store(format!("failed to write v2 object integrity sidecar: {e}")))?;
    write_tree_snapshot(dir, &integrities)
}

fn compute_object_tree_integrity(dir: &Path) -> Result<String, LpmError> {
    Ok(compute_object_tree_integrities(dir)?.content)
}

fn compute_object_tree_integrities(dir: &Path) -> Result<TreeIntegrities, LpmError> {
    let mut content_hasher = Sha256::new();
    let mut metadata_hasher = Sha256::new();
    hash_object_tree_dir(dir, dir, Some(&mut content_hasher), &mut metadata_hasher)?;
    Ok(TreeIntegrities {
        content: format!("sha256-{}", hex::encode(content_hasher.finalize())),
        metadata: format!("sha256-{}", hex::encode(metadata_hasher.finalize())),
    })
}

fn compute_tree_metadata_integrity(dir: &Path) -> Result<String, LpmError> {
    let mut hasher = Sha256::new();
    hash_object_tree_dir(dir, dir, None, &mut hasher)?;
    Ok(format!("sha256-{}", hex::encode(hasher.finalize())))
}

fn hash_object_tree_dir(
    root: &Path,
    dir: &Path,
    mut content_hasher: Option<&mut Sha256>,
    metadata_hasher: &mut Sha256,
) -> Result<(), LpmError> {
    let mut entries = Vec::new();
    for entry in std::fs::read_dir(dir).map_err(|e| {
        LpmError::Store(format!(
            "failed to read v2 object tree at {}: {e}",
            dir.display()
        ))
    })? {
        entries.push(entry.map_err(|e| {
            LpmError::Store(format!("failed to enumerate v2 object tree entry: {e}"))
        })?);
    }
    entries.sort_by_key(|entry| entry.file_name());

    for entry in entries {
        let path = entry.path();
        if is_object_metadata_sidecar(root, &path) {
            continue;
        }
        let metadata = std::fs::symlink_metadata(&path).map_err(|e| {
            LpmError::Store(format!(
                "failed to stat v2 object tree entry {}: {e}",
                path.display()
            ))
        })?;
        let relative = object_tree_relative_path(root, &path)?;
        let file_type = metadata.file_type();
        if file_type.is_dir() {
            let mode = object_entry_mode(&metadata).to_le_bytes();
            if let Some(hasher) = content_hasher.as_deref_mut() {
                hash_object_tree_record(hasher, b"dir", &relative, &mode);
            }
            hash_tree_metadata_record(metadata_hasher, b"dir", &relative, &metadata, &[]);
            hash_object_tree_dir(root, &path, content_hasher.as_deref_mut(), metadata_hasher)?;
        } else if file_type.is_file() {
            hash_tree_metadata_record(metadata_hasher, b"file", &relative, &metadata, &[]);
            if let Some(hasher) = content_hasher.as_deref_mut() {
                hash_object_file(hasher, &relative, &path, &metadata)?;
            }
        } else if file_type.is_symlink() {
            let target = std::fs::read_link(&path).map_err(|e| {
                LpmError::Store(format!(
                    "failed to read v2 object symlink {}: {e}",
                    path.display()
                ))
            })?;
            let mut target_bytes = Vec::new();
            push_os_str_bytes(&mut target_bytes, target.as_os_str());
            if let Some(hasher) = content_hasher.as_deref_mut() {
                hash_object_tree_record(hasher, b"symlink", &relative, &target_bytes);
            }
            hash_tree_metadata_record(
                metadata_hasher,
                b"symlink",
                &relative,
                &metadata,
                &target_bytes,
            );
        } else {
            return Err(LpmError::Store(format!(
                "unsupported v2 object entry type at {}",
                path.display()
            )));
        }
    }
    Ok(())
}

fn hash_tree_metadata_record(
    hasher: &mut Sha256,
    kind: &[u8],
    relative: &[u8],
    metadata: &std::fs::Metadata,
    payload: &[u8],
) {
    hasher.update(kind);
    hasher.update(b"\0");
    hasher.update(relative);
    hasher.update(b"\0");
    hasher.update(object_entry_mode(metadata).to_le_bytes());
    hasher.update(metadata.len().to_le_bytes());
    hasher.update(modified_time_nanos(metadata).to_le_bytes());
    hasher.update(change_time_nanos(metadata).to_le_bytes());
    hasher.update((payload.len() as u64).to_le_bytes());
    hasher.update(payload);
}

fn modified_time_nanos(metadata: &std::fs::Metadata) -> i128 {
    let Ok(modified) = metadata.modified() else {
        return 0;
    };
    match modified.duration_since(std::time::UNIX_EPOCH) {
        Ok(duration) => duration.as_nanos() as i128,
        Err(error) => -(error.duration().as_nanos() as i128),
    }
}

#[cfg(unix)]
fn change_time_nanos(metadata: &std::fs::Metadata) -> i128 {
    use std::os::unix::fs::MetadataExt;
    i128::from(metadata.ctime()) * 1_000_000_000 + i128::from(metadata.ctime_nsec())
}

#[cfg(not(unix))]
fn change_time_nanos(_metadata: &std::fs::Metadata) -> i128 {
    0
}

fn hash_object_file(
    hasher: &mut Sha256,
    relative: &[u8],
    path: &Path,
    metadata: &std::fs::Metadata,
) -> Result<(), LpmError> {
    hasher.update(b"file\0");
    hasher.update(relative);
    hasher.update(b"\0");
    hasher.update(object_entry_mode(metadata).to_le_bytes());
    hasher.update(metadata.len().to_le_bytes());
    let file = std::fs::File::open(path).map_err(|e| {
        LpmError::Store(format!(
            "failed to open v2 object file {} for integrity hashing: {e}",
            path.display()
        ))
    })?;
    let mut reader = BufReader::new(file);
    let mut buf = [0_u8; 64 * 1024];
    loop {
        let read = reader.read(&mut buf).map_err(|e| {
            LpmError::Store(format!(
                "failed to read v2 object file {} for integrity hashing: {e}",
                path.display()
            ))
        })?;
        if read == 0 {
            break;
        }
        hasher.update(&buf[..read]);
    }
    Ok(())
}
fn hash_object_tree_record(hasher: &mut Sha256, kind: &[u8], relative: &[u8], payload: &[u8]) {
    hasher.update(kind);
    hasher.update(b"\0");
    hasher.update(relative);
    hasher.update(b"\0");
    hasher.update((payload.len() as u64).to_le_bytes());
    hasher.update(payload);
}

fn object_tree_relative_path(root: &Path, path: &Path) -> Result<Vec<u8>, LpmError> {
    let relative = path.strip_prefix(root).map_err(|e| {
        LpmError::Store(format!(
            "failed to relativize v2 object path {} under {}: {e}",
            path.display(),
            root.display()
        ))
    })?;
    let mut out = Vec::new();
    for component in relative.components() {
        if !out.is_empty() {
            out.push(b'/');
        }
        push_os_str_bytes(&mut out, component.as_os_str());
    }
    Ok(out)
}

#[cfg(unix)]
fn push_os_str_bytes(out: &mut Vec<u8>, value: &std::ffi::OsStr) {
    use std::os::unix::ffi::OsStrExt;
    out.extend_from_slice(value.as_bytes());
}

#[cfg(windows)]
fn push_os_str_bytes(out: &mut Vec<u8>, value: &std::ffi::OsStr) {
    use std::os::windows::ffi::OsStrExt;
    for unit in value.encode_wide() {
        out.extend_from_slice(&unit.to_le_bytes());
    }
}

#[cfg(not(any(unix, windows)))]
fn push_os_str_bytes(out: &mut Vec<u8>, value: &std::ffi::OsStr) {
    out.extend_from_slice(value.to_string_lossy().as_bytes());
}

#[cfg(unix)]
fn object_entry_mode(metadata: &std::fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    metadata.permissions().mode() & 0o7777
}

#[cfg(not(unix))]
fn object_entry_mode(metadata: &std::fs::Metadata) -> u32 {
    u32::from(metadata.permissions().readonly())
}

fn is_object_metadata_sidecar(root: &Path, path: &Path) -> bool {
    if path.parent() != Some(root) {
        return false;
    }
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    matches!(
        name,
        ".integrity"
            | ".lpm-security.json"
            | OBJECT_TREE_INTEGRITY_FILENAME
            | TREE_SNAPSHOT_FILENAME
            | LOCAL_SOURCE_OBJECT_SENTINEL
    ) || name.starts_with(".lpm-tree-snapshot.json.tmp.")
        || name.starts_with("..lpm-tree-snapshot.json.tmp.")
}

fn is_complete_local_source_object_dir(dir: &Path) -> bool {
    is_complete_object_dir(dir) && dir.join(LOCAL_SOURCE_OBJECT_SENTINEL).is_file()
}

fn replace_local_source_object(tmp_dir: &Path, object_dir: &Path) -> Result<(), LpmError> {
    if !object_dir.exists() {
        return finish_local_source_object_rename(tmp_dir, object_dir);
    }

    let backup_dir = tmp_sibling(object_dir);
    if backup_dir.exists() {
        let _ = std::fs::remove_dir_all(&backup_dir);
    }

    match std::fs::rename(object_dir, &backup_dir) {
        Ok(()) => {}
        Err(_) if !object_dir.exists() => {
            return finish_local_source_object_rename(tmp_dir, object_dir);
        }
        Err(e) => {
            let _ = std::fs::remove_dir_all(tmp_dir);
            return Err(LpmError::Store(format!(
                "failed to move previous v2 local-source object at {} aside: {e}",
                object_dir.display()
            )));
        }
    }

    match std::fs::rename(tmp_dir, object_dir) {
        Ok(()) => {
            if let Err(e) = std::fs::remove_dir_all(&backup_dir) {
                tracing::warn!(
                    target = %backup_dir.display(),
                    "v2 local-source object: failed to remove replaced object backup: {e}"
                );
            }
            Ok(())
        }
        Err(e) if is_complete_local_source_object_dir(object_dir) => {
            let _ = std::fs::remove_dir_all(tmp_dir);
            let _ = std::fs::remove_dir_all(&backup_dir);
            tracing::debug!(
                target = %object_dir.display(),
                "v2 local-source object: concurrent refresh completed first: {e}"
            );
            Ok(())
        }
        Err(e) => {
            let _ = std::fs::remove_dir_all(tmp_dir);
            if !object_dir.exists() {
                let _ = std::fs::rename(&backup_dir, object_dir);
            } else {
                let _ = std::fs::remove_dir_all(&backup_dir);
            }
            Err(LpmError::Store(format!(
                "failed to atomically refresh v2 local-source object at {}: {e}",
                object_dir.display()
            )))
        }
    }
}

fn finish_local_source_object_rename(tmp_dir: &Path, object_dir: &Path) -> Result<(), LpmError> {
    match std::fs::rename(tmp_dir, object_dir) {
        Ok(()) => Ok(()),
        Err(_) if is_complete_local_source_object_dir(object_dir) => {
            let _ = std::fs::remove_dir_all(tmp_dir);
            Ok(())
        }
        Err(e) => {
            let _ = std::fs::remove_dir_all(tmp_dir);
            Err(LpmError::Store(format!(
                "failed to atomically install v2 local-source object: {e}"
            )))
        }
    }
}

fn tmp_sibling(dir: &Path) -> PathBuf {
    // Random 64-bit suffix replaces the pid+tid pair so a same-UID
    // attacker can't predict the tmp path and plant a symlink there
    // before we create the dir. PID + thread::id() are both
    // observable in /proc on Linux; the random suffix is uniformly
    // unpredictable across all UIDs that can read the parent dir.
    use rand::RngCore;
    let suffix: u64 = rand::thread_rng().next_u64();
    dir.with_extension(format!("tmp.{suffix:016x}"))
}

/// Pre-create a tmp staging dir at 0o700 on Unix so partial extracts
/// can't be read by other UIDs on a shared host. The extractor will
/// `create_dir_all` again on this same path — a no-op once the dir
/// already exists at the restricted mode. On filesystems without
/// POSIX modes the mode is silently ignored, which matches the
/// broader credential-metadata posture.
fn create_tmp_dir_locked(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        let mut b = std::fs::DirBuilder::new();
        b.recursive(true);
        b.mode(0o700);
        b.create(path)
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(path)
    }
}

const MAX_LOCAL_SOURCE_OBJECT_DEPTH: usize = 256;

fn populate_local_source_object_into(
    source_root: &Path,
    tmp_dir: &Path,
    sri: &str,
) -> Result<(), LpmError> {
    walk_local_source_object(source_root, source_root, tmp_dir, 0)?;
    let analysis = lpm_security::behavioral::analyze_package(tmp_dir);
    if let Err(e) = lpm_security::behavioral::write_cached_analysis(tmp_dir, &analysis) {
        tracing::warn!("v2 local-source object: failed to write .lpm-security.json: {e}");
    }

    write_object_tree_integrity(tmp_dir)?;
    std::fs::write(tmp_dir.join(".integrity"), sri).map_err(|e| {
        LpmError::Store(format!(
            "failed to write v2 local-source .integrity at {}: {e}",
            tmp_dir.display()
        ))
    })?;
    std::fs::write(
        tmp_dir.join(LOCAL_SOURCE_OBJECT_SENTINEL),
        source_root.display().to_string(),
    )
    .map_err(|e| {
        LpmError::Store(format!(
            "failed to write v2 local-source sentinel at {}: {e}",
            tmp_dir.display()
        ))
    })?;

    Ok(())
}

fn walk_local_source_object(
    source_root: &Path,
    src: &Path,
    dst: &Path,
    depth: usize,
) -> Result<(), LpmError> {
    if depth > MAX_LOCAL_SOURCE_OBJECT_DEPTH {
        return Err(LpmError::Store(format!(
            "v2 local-source object exceeds maximum walk depth ({MAX_LOCAL_SOURCE_OBJECT_DEPTH}) at {}",
            src.display()
        )));
    }
    std::fs::create_dir_all(dst).map_err(|e| {
        LpmError::Store(format!(
            "failed to create v2 local-source object dir at {}: {e}",
            dst.display()
        ))
    })?;

    for entry in std::fs::read_dir(src).map_err(|e| {
        LpmError::Store(format!(
            "failed to read local source directory {}: {e}",
            src.display()
        ))
    })? {
        let entry = entry
            .map_err(|e| LpmError::Store(format!("failed to enumerate local source entry: {e}")))?;
        let name = entry.file_name();
        if name == "node_modules" || name == ".git" {
            continue;
        }

        let entry_src = entry.path();
        let entry_dst = dst.join(&name);
        let metadata = std::fs::symlink_metadata(&entry_src).map_err(|e| {
            LpmError::Store(format!(
                "failed to stat local source entry {}: {e}",
                entry_src.display()
            ))
        })?;
        let ft = metadata.file_type();
        if ft.is_dir() {
            walk_local_source_object(source_root, &entry_src, &entry_dst, depth + 1)?;
        } else if ft.is_file() {
            materialize_local_source_file(&entry_src, &entry_dst)?;
        } else if ft.is_symlink() {
            let abs_target = entry_src
                .canonicalize()
                .unwrap_or_else(|_| entry_src.clone());
            if ft.is_symlink() && !abs_target.starts_with(source_root) {
                tracing::warn!(
                    source = %source_root.display(),
                    symlink = %entry_src.display(),
                    target = %abs_target.display(),
                    "v2 local-source object: symlink escapes source root; exposing target as-is"
                );
            }
            match std::fs::metadata(&abs_target) {
                Ok(meta) if meta.is_file() => {
                    materialize_local_source_file(&abs_target, &entry_dst)?;
                }
                _ => {
                    create_fs_symlink(&abs_target, &entry_dst).map_err(|e| {
                        LpmError::Store(format!(
                            "failed to stage v2 local-source symlink {} → {}: {e}",
                            entry_dst.display(),
                            abs_target.display()
                        ))
                    })?;
                }
            }
        }
    }

    Ok(())
}

fn materialize_local_source_file(src: &Path, dst: &Path) -> Result<(), LpmError> {
    if let Some(parent) = dst.parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            LpmError::Store(format!(
                "failed to create v2 local-source object parent at {}: {e}",
                parent.display()
            ))
        })?;
    }
    if let Err(e) = std::fs::hard_link(src, dst) {
        tracing::trace!(
            src = %src.display(),
            dst = %dst.display(),
            error = %e,
            "v2 local-source object: hardlink failed, falling back to copy"
        );
        std::fs::copy(src, dst).map_err(|copy_err| {
            LpmError::Store(format!(
                "failed to copy v2 local-source file {} → {}: {copy_err}",
                src.display(),
                dst.display()
            ))
        })?;
    }
    Ok(())
}

/// Ensure a store-tier directory exists at 0o700. Idempotent — if the
/// directory is already present, its perms are tightened in place.
///
/// `~/.lpm/store/v2/objects/` and `~/.lpm/store/v2/links/` carry
/// extracted package bytes (including private `@org/*` packages).
/// `create_dir_all`'s default-umask creation lets shared-host /
/// shared-CI-runner / NFS-mounted layouts disclose those bytes to
/// every other local uid. Stamping 0o700 on the store-tier dirs
/// closes that shape without touching how each link entry stages —
/// the per-entry tmp dir is also 0o700, and intra-tree perms are
/// preserved via the atomic rename.
///
/// No-op on platforms without POSIX modes, where the perms knob does
/// not apply.
fn ensure_store_tier_dir_locked(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        use std::os::unix::fs::PermissionsExt;
        let mut b = std::fs::DirBuilder::new();
        b.recursive(true);
        b.mode(0o700);
        b.create(path)?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(path)
    }
}

/// Recursively copy `src/` to `dst/`. Used by the v1 → v2 cache-hit
/// translation. `std::fs::copy` invokes the kernel's
/// `copy_file_range(2)` on Linux (CoW reflink on Btrfs/XFS) and
/// `fcopyfile(2)` on macOS, so the copy is essentially free on
/// reflink-capable filesystems and bounded by a single tar-extract's
/// IO cost otherwise. We don't reach for `clonefile()` directly — the
/// translation runs once per package per machine, never on the hot
/// install path.
fn copy_dir_recursively(src: &Path, dst: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let entry_src = entry.path();
        let entry_dst = dst.join(entry.file_name());
        let ft = entry.file_type()?;
        if ft.is_dir() {
            copy_dir_recursively(&entry_src, &entry_dst)?;
        } else if ft.is_symlink() {
            // Refuse to migrate symlinks from a v1 store entry into the
            // v2 object dir (L8). The v1 extractor's `is_file()` filter
            // already prevents symlinks from being written into store
            // entries under normal operation, so a symlink here is
            // either (a) a manually-planted artefact by a local attacker
            // or (b) a regression in the v1 extractor's filter. Both
            // cases would faithfully reproduce the symlink target into
            // every link entry that consumed the migrated object —
            // i.e. a `/etc/passwd` symlink becomes readable through
            // every consuming project's node_modules. Skip with a
            // tracing::warn so the migration completes for the
            // surrounding files but the unsafe link is dropped.
            tracing::warn!(
                src = %entry_src.display(),
                "v1→v2 copy: skipping symlink (refused — v1 store entries should not contain symlinks)",
            );
        } else if ft.is_file() {
            std::fs::copy(&entry_src, &entry_dst)?;
        }
        // Block / char / fifo entries inside an extracted npm
        // package would be malformed input — silently skip.
    }
    Ok(())
}

// Centralized symlink helper so v2 inherits the linker's Windows
// `mklink /J` junction fallback automatically — a hand-written
// `symlink_dir`-only path would regress Windows users without
// Developer Mode.
use lpm_common::symlink::create_dir_symlink_or_junction as create_dir_symlink;
use lpm_common::symlink::create_symlink as create_fs_symlink;

/// Materialize `src/` into `dst/` using independent bytes.
///
/// macOS gets `clonefile()` for whole-directory copy-on-write. Other
/// platforms use file copies, which lets Linux choose copy_file_range or
/// filesystem reflinks without sharing hardlink inodes between the object
/// store and executable link entries.
fn materialize_into(src: &Path, dst: &Path) -> Result<(), LpmError> {
    let allow_source_symlinks = src.join(LOCAL_SOURCE_OBJECT_SENTINEL).is_file();
    materialize_into_inner(src, src, dst, allow_source_symlinks)
}

fn materialize_into_inner(
    root: &Path,
    src: &Path,
    dst: &Path,
    allow_source_symlinks: bool,
) -> Result<(), LpmError> {
    #[cfg(target_os = "macos")]
    {
        if try_clonefile(src, dst) {
            remove_materialized_object_sidecars(dst)?;
            return Ok(());
        }
    }

    std::fs::create_dir_all(dst).map_err(|e| {
        LpmError::Store(format!(
            "failed to create v2 link package dir at {}: {e}",
            dst.display()
        ))
    })?;

    for entry in std::fs::read_dir(src).map_err(|e| {
        LpmError::Store(format!(
            "failed to read v2 source object dir {}: {e}",
            src.display()
        ))
    })? {
        let entry = entry
            .map_err(|e| LpmError::Store(format!("failed to enumerate v2 source dir: {e}")))?;
        if allow_source_symlinks && entry.file_name() == LOCAL_SOURCE_OBJECT_SENTINEL {
            continue;
        }
        let src_path = entry.path();
        if is_object_metadata_sidecar(root, &src_path) {
            continue;
        }
        let dst_path = dst.join(entry.file_name());

        let file_type = entry.file_type().map_err(|e| {
            LpmError::Store(format!(
                "failed to stat v2 source entry {}: {e}",
                src_path.display()
            ))
        })?;

        if file_type.is_dir() {
            materialize_into_inner(root, &src_path, &dst_path, allow_source_symlinks)?;
        } else if file_type.is_symlink() {
            if !allow_source_symlinks {
                // Refuse symlink entries — the extractor's `is_file()`
                // filter blocks them at extract time, so a symlink under
                // `objects/` means a same-UID actor planted it. Symmetric
                // with the v1→v2 `copy_dir_recursively` refusal.
                let target = std::fs::read_link(&src_path).unwrap_or_default();
                return Err(LpmError::Store(format!(
                    "refusing v2 symlink entry {} → {}; symlinks must not appear under objects/",
                    src_path.display(),
                    target.display(),
                )));
            }
            let target = std::fs::read_link(&src_path).map_err(|e| {
                LpmError::Store(format!(
                    "failed to read v2 local-source symlink {}: {e}",
                    src_path.display()
                ))
            })?;
            create_fs_symlink(&target, &dst_path).map_err(|e| {
                LpmError::Store(format!(
                    "failed to recreate v2 local-source symlink {} → {}: {e}",
                    dst_path.display(),
                    target.display()
                ))
            })?;
        } else {
            std::fs::copy(&src_path, &dst_path).map_err(|copy_err| {
                LpmError::Store(format!(
                    "failed to copy v2 source file {} → {}: {copy_err}",
                    src_path.display(),
                    dst_path.display()
                ))
            })?;
        }
    }

    Ok(())
}

#[cfg(target_os = "macos")]
fn remove_materialized_object_sidecars(dst: &Path) -> Result<(), LpmError> {
    for name in [
        ".integrity",
        ".lpm-security.json",
        OBJECT_TREE_INTEGRITY_FILENAME,
        LOCAL_SOURCE_OBJECT_SENTINEL,
    ] {
        let path = dst.join(name);
        if path.exists() {
            std::fs::remove_file(&path).map_err(|e| {
                LpmError::Store(format!(
                    "failed to remove v2 metadata sidecar from materialized package at {}: {e}",
                    path.display()
                ))
            })?;
        }
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn try_clonefile(src: &Path, dst: &Path) -> bool {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let Ok(src_c) = CString::new(src.as_os_str().as_bytes()) else {
        return false;
    };
    let Ok(dst_c) = CString::new(dst.as_os_str().as_bytes()) else {
        return false;
    };

    // SAFETY: clonefile takes two NUL-terminated C strings and a flags
    // word. Both pointers are valid for the duration of the call (the
    // CStrings outlive it), and we pass `0` for flags (no special
    // behavior). Returns 0 on success, -1 on failure.
    let result = unsafe { libc::clonefile(src_c.as_ptr(), dst_c.as_ptr(), 0) };
    if result == 0 {
        tracing::debug!(
            src = %src.display(),
            dst = %dst.display(),
            "v2 materialize: clonefile"
        );
        true
    } else {
        false
    }
}

#[cfg(target_os = "macos")]
mod libc {
    unsafe extern "C" {
        pub fn clonefile(
            src: *const std::os::raw::c_char,
            dst: *const std::os::raw::c_char,
            flags: u32,
        ) -> std::os::raw::c_int;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v2::graph_key::{GraphKeyInputs, LinkerModeTag, PeerEntry};
    use crate::v2::link_meta::LinkMetaPlatform;
    use crate::v2::platform::PlatformTuple;

    fn macos_arm64() -> PlatformTuple {
        PlatformTuple::new("darwin", "arm64", None)
    }

    fn sample_platform() -> PlatformTuple {
        PlatformTuple::new("darwin", "arm64", None)
    }

    fn sample_meta_platform() -> LinkMetaPlatform {
        LinkMetaPlatform {
            os: "darwin".into(),
            cpu: "arm64".into(),
            libc: None,
        }
    }

    fn sample_key(name: &str, version: &str) -> GraphKey {
        let inputs = GraphKeyInputs::new(name, version, sample_platform(), LinkerModeTag::Isolated);
        GraphKey::derive(&inputs)
    }

    fn arc_key(name: &str, version: &str) -> Arc<GraphKey> {
        Arc::new(sample_key(name, version))
    }

    /// Compute a real SHA-512 SRI string over `seed`. Tests need
    /// valid base64-padded SRIs because [`Integrity::parse`] enforces
    /// canonical encoding; hand-rolled placeholders fail at parse time.
    fn synthetic_sri(seed: &[u8]) -> String {
        crate::compute_sri_hash(seed)
    }

    fn write_object(store: &Store, sri: &str, files: &[(&str, &[u8])]) -> PathBuf {
        let dir = store.paths().object_dir(sri).unwrap();
        std::fs::create_dir_all(&dir).unwrap();
        for (name, contents) in files {
            let path = dir.join(name);
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).unwrap();
            }
            std::fs::write(path, contents).unwrap();
        }
        write_object_tree_integrity(&dir).unwrap();
        std::fs::write(dir.join(".integrity"), sri).unwrap();
        dir
    }

    #[test]
    fn reusable_object_recreates_missing_tree_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::at(dir.path());
        let sri = synthetic_sri(b"reusable_object_recreates_missing_tree_snapshot");
        let object_dir = write_object(
            &store,
            &sri,
            &[
                ("package.json", b"{\"name\":\"snapshot\"}"),
                ("index.js", b"ok"),
            ],
        );
        let snapshot_path = object_dir.join(TREE_SNAPSHOT_FILENAME);
        assert!(snapshot_path.is_file());

        std::fs::remove_file(&snapshot_path).unwrap();
        let reusable = store.reusable_object(&sri).unwrap().unwrap();

        assert_eq!(reusable.path, object_dir);
        assert!(
            snapshot_path.is_file(),
            "full-hash fallback must refresh the fast metadata snapshot"
        );
    }

    #[test]
    fn reusable_object_ignores_atomic_tree_snapshot_tmp_file() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::at(dir.path());
        let sri = synthetic_sri(b"reusable_object_ignores_atomic_tree_snapshot_tmp_file");
        let object_dir = write_object(
            &store,
            &sri,
            &[
                ("package.json", b"{\"name\":\"snapshot-tmp\"}"),
                ("index.js", b"ok"),
            ],
        );
        std::fs::write(
            object_dir.join("..lpm-tree-snapshot.json.tmp.1234.0"),
            b"partial",
        )
        .unwrap();

        let reusable = store.reusable_object(&sri).unwrap().unwrap();

        assert_eq!(reusable.path, object_dir);
    }

    #[test]
    fn populate_link_entry_refreshes_missing_tree_snapshot_on_reuse() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::at(dir.path());
        let sri = synthetic_sri(b"populate_link_entry_refreshes_missing_tree_snapshot_on_reuse");
        let object_dir = write_object(
            &store,
            &sri,
            &[
                ("package.json", b"{\"name\":\"snapshot-link\"}"),
                ("index.js", b"ok"),
            ],
        );
        let key = arc_key("snapshot-link", "1.0.0");
        let request = || LinkEntryRequest {
            graph_key: key.clone(),
            source_sri: sri.clone(),
            object_dir: object_dir.clone(),
            deps: vec![],
            platform: Arc::new(sample_meta_platform()),
        };

        let first = store.populate_link_entry(request()).unwrap();
        let snapshot_path = first.link_dir.join(TREE_SNAPSHOT_FILENAME);
        assert!(snapshot_path.is_file());

        std::fs::remove_file(&snapshot_path).unwrap();
        let second = store.populate_link_entry(request()).unwrap();

        assert!(!second.freshly_populated);
        assert!(
            snapshot_path.is_file(),
            "reusable link entries must refresh missing metadata snapshots"
        );
    }

    #[test]
    fn paths_for_known_sri() {
        let root = std::env::temp_dir().join(format!(
            "lpm-v2-paths-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let store = Store::at(&root);
        let sri = synthetic_sri(b"paths_for_known_sri");
        let dir = store.paths().object_dir(&sri).unwrap();
        assert!(dir.starts_with(&root));
        assert!(dir.to_string_lossy().contains("/objects/"));
        assert!(dir.to_string_lossy().contains("sha512-"));
        // Hex segment: 128 hex chars + "sha512-" prefix.
        let segment = dir.file_name().unwrap().to_string_lossy().to_string();
        assert_eq!(segment.len(), "sha512-".len() + 128);
    }

    #[test]
    fn link_path_contains_graph_key_dir_name() {
        let store = Store::at(std::env::temp_dir().join("lpm-v2-link-path"));
        let key = sample_key("react", "18.3.0");
        let dir = store.paths().link_dir(&key);
        assert!(
            dir.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("react@18.3.0+")
        );
        assert_eq!(
            store.paths().link_package_dir(&key),
            dir.join("node_modules").join("react")
        );
    }

    #[test]
    fn populate_then_read_sidecar() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::at(dir.path());

        let sri = synthetic_sri(b"populate_then_read_sidecar");
        let object_dir = write_object(
            &store,
            &sri,
            &[("package.json", b"{\"name\":\"a\"}"), ("index.js", b"//ok")],
        );

        let key = arc_key("a", "1.0.0");
        let entry = store
            .populate_link_entry(LinkEntryRequest {
                graph_key: key,
                source_sri: sri.clone(),
                object_dir,
                deps: vec![],
                platform: Arc::new(sample_meta_platform()),
            })
            .unwrap();

        assert!(entry.freshly_populated);
        assert!(entry.link_dir.is_dir());
        let pkg_dir = entry.link_dir.join("node_modules").join("a");
        assert!(pkg_dir.is_dir());
        assert!(pkg_dir.join("package.json").is_file());

        // Sidecar lives at the link-dir root, not inside node_modules.
        let sidecar_path = entry
            .link_dir
            .join(crate::v2::link_meta::LINK_META_FILENAME);
        assert!(sidecar_path.is_file());

        let read_back = LinkMeta::read_from(&entry.link_dir).unwrap();
        assert_eq!(read_back.name, "a");
        assert_eq!(read_back.version, "1.0.0");
        assert_eq!(read_back.source_sri, sri);
        assert!(read_back.object_path.starts_with("objects/sha512-"));
        assert_eq!(read_back.deps, vec![]);
    }

    #[test]
    fn reusable_object_dir_removes_tampered_object_tree() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::at(dir.path());
        let sri = synthetic_sri(b"reusable_object_dir_removes_tampered_object_tree");
        let object_dir = write_object(
            &store,
            &sri,
            &[("package.json", b"{\"name\":\"a\"}"), ("index.js", b"//ok")],
        );
        std::fs::write(object_dir.join("index.js"), b"//tampered").unwrap();

        let reusable = store.reusable_object_dir(&sri).unwrap();

        assert!(reusable.is_none());
        assert!(
            !object_dir.exists(),
            "tampered v2 objects must be removed before cache reuse"
        );
    }

    #[test]
    fn reusable_object_dir_removes_malformed_object_tree_sidecar() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::at(dir.path());
        let sri = synthetic_sri(b"reusable_object_dir_removes_malformed_object_tree_sidecar");
        let object_dir = write_object(
            &store,
            &sri,
            &[("package.json", b"{\"name\":\"a\"}"), ("index.js", b"//ok")],
        );
        std::fs::write(
            object_dir.join(OBJECT_TREE_INTEGRITY_FILENAME),
            b"sha256-not-hex\n",
        )
        .unwrap();

        let reusable = store.reusable_object_dir(&sri).unwrap();

        assert!(reusable.is_none());
        assert!(
            !object_dir.exists(),
            "malformed object integrity sidecars must force a fresh cache write"
        );
    }

    #[test]
    fn reusable_object_returns_verified_tree_integrity() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::at(dir.path());
        let sri = synthetic_sri(b"reusable_object_returns_verified_tree_integrity");
        let object_dir = write_object(
            &store,
            &sri,
            &[("package.json", b"{\"name\":\"a\"}"), ("index.js", b"//ok")],
        );

        let reusable = store.reusable_object(&sri).unwrap().unwrap();

        assert_eq!(reusable.path, object_dir);
        assert_eq!(
            reusable.tree_integrity.as_str(),
            read_object_tree_integrity(&reusable.path).unwrap()
        );
    }

    #[test]
    fn remove_unusable_object_dir_treats_concurrent_delete_as_success() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("objects").join("sha512-missing");

        remove_unusable_object_dir(&missing, "during concurrent cleanup").unwrap();
    }

    #[test]
    fn populate_link_entry_rejects_object_tree_integrity_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::at(dir.path());
        let sri = synthetic_sri(b"populate_link_entry_rejects_object_tree_integrity_mismatch");
        let object_dir = write_object(
            &store,
            &sri,
            &[("package.json", b"{\"name\":\"a\"}"), ("index.js", b"//ok")],
        );
        std::fs::write(object_dir.join("index.js"), b"//tampered").unwrap();

        let key = arc_key("a", "1.0.0");
        let err = store
            .populate_link_entry(LinkEntryRequest {
                graph_key: Arc::clone(&key),
                source_sri: sri,
                object_dir,
                deps: vec![],
                platform: Arc::new(sample_meta_platform()),
            })
            .unwrap_err();

        assert!(
            err.to_string().contains("v2 object integrity mismatch"),
            "link population must fail before reading tampered object bytes, got: {err}"
        );
        assert!(
            !store.paths().link_dir(&key).exists(),
            "failed link population must clean up its staging dir"
        );
    }

    #[cfg(unix)]
    #[test]
    fn populate_object_from_local_source_materializes_real_files_for_node_resolution() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::at(dir.path());
        let source = dir.path().join("source");
        std::fs::create_dir_all(source.join("node_modules")).unwrap();
        std::fs::write(
            source.join("package.json"),
            b"{\"name\":\"local-pkg\",\"version\":\"1.0.0\"}",
        )
        .unwrap();
        std::fs::write(source.join("index.js"), b"module.exports = 'before';\n").unwrap();
        std::fs::write(source.join("node_modules/ignored.js"), b"ignored\n").unwrap();

        let sri = synthetic_sri(b"populate_object_from_local_source");
        let object_dir = store
            .populate_object_from_local_source(&source, &sri)
            .unwrap();

        assert!(object_dir.join(LOCAL_SOURCE_OBJECT_SENTINEL).is_file());
        assert!(
            !object_dir
                .join("package.json")
                .symlink_metadata()
                .unwrap()
                .file_type()
                .is_symlink(),
            "local-source package files must be real files so Node keeps module realpaths inside the v2 link entry"
        );
        assert!(
            !object_dir
                .join("index.js")
                .symlink_metadata()
                .unwrap()
                .file_type()
                .is_symlink(),
            "local-source entrypoints must not be symlinks"
        );
        assert!(
            !object_dir.join("node_modules").exists(),
            "local-source objects must exclude node_modules/"
        );
        assert_eq!(
            std::fs::read_to_string(object_dir.join("index.js")).unwrap(),
            "module.exports = 'before';\n"
        );
    }

    #[cfg(unix)]
    #[test]
    fn populate_object_from_local_source_refreshes_file_set_on_reinstall() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::at(dir.path());
        let source = dir.path().join("source");
        std::fs::create_dir_all(&source).unwrap();
        std::fs::write(
            source.join("package.json"),
            b"{\"name\":\"local-pkg\",\"version\":\"1.0.0\"}",
        )
        .unwrap();
        std::fs::write(source.join("index.js"), b"module.exports = 'before';\n").unwrap();

        let sri = synthetic_sri(b"populate_object_from_local_source_refresh");
        let object_dir = store
            .populate_object_from_local_source(&source, &sri)
            .unwrap();

        assert!(object_dir.join("index.js").symlink_metadata().is_ok());
        assert!(object_dir.join("new.js").symlink_metadata().is_err());

        std::fs::write(source.join("new.js"), b"module.exports = 'new';\n").unwrap();
        let refreshed_dir = store
            .populate_object_from_local_source(&source, &sri)
            .unwrap();

        assert_eq!(refreshed_dir, object_dir);
        assert_eq!(
            std::fs::read_to_string(object_dir.join("new.js")).unwrap(),
            "module.exports = 'new';\n"
        );

        std::fs::remove_file(source.join("index.js")).unwrap();
        store
            .populate_object_from_local_source(&source, &sri)
            .unwrap();

        assert!(
            object_dir.join("index.js").symlink_metadata().is_err(),
            "reinstall must remove stale object entries for source files that no longer exist"
        );
    }

    #[test]
    fn populate_is_idempotent_and_touches_last_referenced_at() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::at(dir.path());

        let sri = synthetic_sri(b"populate_is_idempotent");
        let object_dir = write_object(&store, &sri, &[("package.json", b"{}")]);
        let key = arc_key("b", "2.0.0");
        let req = || LinkEntryRequest {
            graph_key: key.clone(),
            source_sri: sri.clone(),
            object_dir: object_dir.clone(),
            deps: vec![],
            platform: Arc::new(sample_meta_platform()),
        };

        let first = store.populate_link_entry(req()).unwrap();
        assert!(first.freshly_populated);
        assert!(first.sidecar.is_some(), "fresh population returns sidecar");
        let first_sidecar = first.sidecar.unwrap();
        let sidecar_path = first.link_dir.join(LINK_META_FILENAME);
        let mtime_before = std::fs::metadata(&sidecar_path)
            .unwrap()
            .modified()
            .unwrap();

        // Sleep enough that the file mtime granularity advances on
        // every supported FS — APFS resolves to ns, ext4 to ms, but
        // some test runners hit FAT-style 1-s granularity. 1100 ms
        // is the conservative floor.
        std::thread::sleep(std::time::Duration::from_millis(1100));

        let second = store.populate_link_entry(req()).unwrap();
        assert!(!second.freshly_populated);
        assert_eq!(second.link_dir, first.link_dir);
        // Cache-hit returns no sidecar; the touch is observable via
        // the sidecar file's mtime, and the effective last-referenced
        // timestamp is max(json, mtime).
        assert!(second.sidecar.is_none(), "cache hit skips sidecar read");
        let mtime_after = std::fs::metadata(&sidecar_path)
            .unwrap()
            .modified()
            .unwrap();
        assert!(
            mtime_after > mtime_before,
            "sidecar mtime must advance on cache hit"
        );
        let read_back = LinkMeta::read_from(&first.link_dir).unwrap();
        assert_eq!(
            read_back.created_at, first_sidecar.created_at,
            "created_at is immutable across cache hits"
        );
        // The JSON `last_referenced_at` is frozen at creation; the
        // effective time tracks file mtime.
        let effective = read_back.effective_last_referenced_at(&sidecar_path);
        assert!(effective > first_sidecar.last_referenced_at);
    }

    #[test]
    fn populate_link_entry_copies_bytes_without_sharing_object_inode() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::at(dir.path());

        let sri = synthetic_sri(b"populate_link_entry_copies_bytes_without_sharing_object_inode");
        let object_dir = write_object(
            &store,
            &sri,
            &[
                ("package.json", b"{\"name\":\"copy-safe\"}"),
                ("index.js", b"module.exports = {};"),
            ],
        );
        let key = arc_key("copy-safe", "1.0.0");

        let entry = store
            .populate_link_entry(LinkEntryRequest {
                graph_key: key,
                source_sri: sri,
                object_dir: object_dir.clone(),
                deps: vec![],
                platform: Arc::new(sample_meta_platform()),
            })
            .unwrap();
        let link_index = entry.link_dir.join("node_modules/copy-safe/index.js");

        std::fs::write(object_dir.join("index.js"), b"module.exports = 'tampered';").unwrap();

        assert_eq!(
            std::fs::read(link_index).unwrap(),
            b"module.exports = {};",
            "link entry bytes must not alias the object-store inode"
        );
    }

    #[test]
    fn populate_link_entry_rebuilds_stale_existing_entry() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::at(dir.path());

        let sri = synthetic_sri(b"populate_link_entry_rebuilds_stale_existing_entry");
        let object_dir = write_object(
            &store,
            &sri,
            &[
                ("package.json", b"{\"name\":\"stale-link\"}"),
                ("index.js", b"module.exports = {};"),
            ],
        );
        let key = arc_key("stale-link", "1.0.0");
        let request = || LinkEntryRequest {
            graph_key: key.clone(),
            source_sri: sri.clone(),
            object_dir: object_dir.clone(),
            deps: vec![],
            platform: Arc::new(sample_meta_platform()),
        };

        let first = store.populate_link_entry(request()).unwrap();
        let link_index = first.link_dir.join("node_modules/stale-link/index.js");
        std::fs::write(&link_index, b"module.exports = 'stale';").unwrap();

        let second = store.populate_link_entry(request()).unwrap();

        assert!(second.freshly_populated);
        assert_eq!(
            std::fs::read(link_index).unwrap(),
            b"module.exports = {};",
            "stale link entry must be rebuilt from the verified object"
        );
    }

    #[test]
    fn populate_link_entry_with_verified_object_rebuilds_stale_existing_entry() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::at(dir.path());

        let sri = synthetic_sri(b"populate_link_entry_with_verified_object_rebuilds_stale");
        let object_dir = write_object(
            &store,
            &sri,
            &[
                ("package.json", b"{\"name\":\"verified-stale-link\"}"),
                ("index.js", b"module.exports = {};"),
            ],
        );
        let verified = store.reusable_object(&sri).unwrap().unwrap().tree_integrity;
        let key = arc_key("verified-stale-link", "1.0.0");
        let request = || LinkEntryRequest {
            graph_key: key.clone(),
            source_sri: sri.clone(),
            object_dir: object_dir.clone(),
            deps: vec![],
            platform: Arc::new(sample_meta_platform()),
        };

        let first = store
            .populate_link_entry_with_verified_object(request(), &verified)
            .unwrap();
        let link_index = first
            .link_dir
            .join("node_modules/verified-stale-link/index.js");
        std::fs::write(&link_index, b"module.exports = 'stale';").unwrap();

        let second = store
            .populate_link_entry_with_verified_object(request(), &verified)
            .unwrap();

        assert!(second.freshly_populated);
        assert_eq!(
            std::fs::read(link_index).unwrap(),
            b"module.exports = {};",
            "verified-object fast path must still rebuild stale link entries"
        );
    }

    #[test]
    fn populate_writes_sibling_symlinks() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::at(dir.path());

        // Two objects: one for the package itself, one for its dep.
        let pkg_sri = synthetic_sri(b"populate_writes_sibling_symlinks/pkg");
        let dep_sri = synthetic_sri(b"populate_writes_sibling_symlinks/dep");
        let pkg_obj = write_object(&store, &pkg_sri, &[("package.json", b"{}")]);
        write_object(&store, &dep_sri, &[("package.json", b"{}")]);

        let pkg_key = arc_key("express", "4.21.0");
        let dep_key = arc_key("debug", "4.3.4");

        // Materialize the dep first so its link dir exists for the
        // symlink target. The store doesn't enforce ordering (caller's
        // responsibility) — we exercise the realistic path here.
        store
            .populate_link_entry(LinkEntryRequest {
                graph_key: dep_key.clone(),
                source_sri: dep_sri.clone(),
                object_dir: store.paths().object_dir(&dep_sri).unwrap(),
                deps: vec![],
                platform: Arc::new(sample_meta_platform()),
            })
            .unwrap();

        let entry = store
            .populate_link_entry(LinkEntryRequest {
                graph_key: pkg_key,
                source_sri: pkg_sri,
                object_dir: pkg_obj,
                deps: vec![DepLink {
                    local: "debug".into(),
                    target: dep_key.clone(),
                }],
                platform: Arc::new(sample_meta_platform()),
            })
            .unwrap();

        let sibling = entry.link_dir.join("node_modules").join("debug");
        let target = std::fs::read_link(&sibling).unwrap();
        // Target string format: `../../<dep_key.dir>/node_modules/debug`.
        assert_eq!(
            target.to_string_lossy(),
            format!("../../{}/node_modules/debug", dep_key.dir_name())
        );
        // Symlink should resolve to the dep's link package dir.
        assert!(sibling.exists(), "sibling symlink must resolve");
        assert!(sibling.join("package.json").is_file());

        // Sidecar records the dep edge.
        let sidecar = entry.sidecar.expect("fresh population returns sidecar");
        assert_eq!(sidecar.deps.len(), 1);
        assert_eq!(sidecar.deps[0].local, "debug");
        assert_eq!(sidecar.deps[0].target_graph_key, dep_key.digest_hex());
    }

    #[test]
    fn populate_rejects_dependency_local_name_with_traversal() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::at(dir.path());

        let pkg_sri = synthetic_sri(b"populate_rejects_unsafe_dep/pkg");
        let dep_sri = synthetic_sri(b"populate_rejects_unsafe_dep/dep");
        let pkg_obj = write_object(&store, &pkg_sri, &[("package.json", b"{}")]);
        write_object(&store, &dep_sri, &[("package.json", b"{}")]);

        let pkg_key = arc_key("consumer", "1.0.0");
        let dep_key = arc_key("debug", "4.3.4");
        store
            .populate_link_entry(LinkEntryRequest {
                graph_key: dep_key.clone(),
                source_sri: dep_sri.clone(),
                object_dir: store.paths().object_dir(&dep_sri).unwrap(),
                deps: vec![],
                platform: Arc::new(sample_meta_platform()),
            })
            .unwrap();

        let err = store
            .populate_link_entry(LinkEntryRequest {
                graph_key: pkg_key.clone(),
                source_sri: pkg_sri,
                object_dir: pkg_obj,
                deps: vec![DepLink {
                    local: "../../../../escape".into(),
                    target: dep_key,
                }],
                platform: Arc::new(sample_meta_platform()),
            })
            .unwrap_err();

        assert!(
            format!("{err}").contains("unsafe dependency local name"),
            "error should identify the unsafe local name, got: {err}",
        );
        assert!(
            !store.paths().link_dir(&pkg_key).exists(),
            "failed population must not publish a partial link entry",
        );
    }

    #[test]
    fn populate_writes_scoped_sibling_symlink_with_extra_dotdot() {
        // Scoped local names live one level deeper inside
        // `node_modules/`, so the relative symlink target needs an
        // additional `..` segment vs the non-scoped case.
        let dir = tempfile::tempdir().unwrap();
        let store = Store::at(dir.path());

        let pkg_sri = synthetic_sri(b"scoped/pkg");
        let dep_sri = synthetic_sri(b"scoped/dep");
        let pkg_obj = write_object(&store, &pkg_sri, &[("package.json", b"{}")]);
        write_object(&store, &dep_sri, &[("package.json", b"{}")]);

        let pkg_key = arc_key("consumer", "1.0.0");
        let dep_key = arc_key("@types/node", "20.10.0");

        store
            .populate_link_entry(LinkEntryRequest {
                graph_key: dep_key.clone(),
                source_sri: dep_sri.clone(),
                object_dir: store.paths().object_dir(&dep_sri).unwrap(),
                deps: vec![],
                platform: Arc::new(sample_meta_platform()),
            })
            .unwrap();

        let entry = store
            .populate_link_entry(LinkEntryRequest {
                graph_key: pkg_key,
                source_sri: pkg_sri,
                object_dir: pkg_obj,
                deps: vec![DepLink {
                    local: "@types/node".into(),
                    target: dep_key.clone(),
                }],
                platform: Arc::new(sample_meta_platform()),
            })
            .unwrap();

        let sibling = entry
            .link_dir
            .join("node_modules")
            .join("@types")
            .join("node");
        let target = std::fs::read_link(&sibling).unwrap();
        // Three `..` segments because the symlink itself sits one
        // level deeper under `node_modules/@types/`.
        assert_eq!(
            target.to_string_lossy(),
            format!(
                "../../../{}/node_modules/{}",
                dep_key.dir_name(),
                dep_key.name()
            )
        );
        // Even though the dep's package dir is also at a scoped path
        // inside its own node_modules, its OWN dir name (sample_key
        // "@types/node") goes through the same `+` sanitization so the
        // path resolves cleanly.
        assert!(
            sibling.exists(),
            "scoped sibling symlink must resolve to the dep's package dir"
        );
    }

    #[test]
    fn extract_object_is_idempotent() {
        // We can't easily invoke the real extractor on a synthetic
        // tarball without pulling in flate2/tar in the test (already
        // dev-deps but it's still 30+ lines). Instead, simulate the
        // extracted state and confirm the idempotent path returns the
        // existing dir without error.
        let dir = tempfile::tempdir().unwrap();
        let store = Store::at(dir.path());
        let sri = synthetic_sri(b"extract_object_is_idempotent");
        let object_dir = write_object(&store, &sri, &[("package.json", b"{}")]);

        // extract_object on already-populated SRI must short-circuit.
        let returned = store.extract_object(&sri, b"unused-because-hit").unwrap();
        assert_eq!(returned, object_dir);
    }

    #[test]
    fn populate_failure_cleans_up_tmp_dir() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::at(dir.path());

        // Object dir doesn't exist → materialize_into fails → tmp cleanup.
        let sri = synthetic_sri(b"populate_failure_cleans_up_tmp_dir");
        let nonexistent_object = store.paths().object_dir(&sri).unwrap();
        let key = arc_key("missing", "0.0.1");

        let err = store
            .populate_link_entry(LinkEntryRequest {
                graph_key: key.clone(),
                source_sri: sri,
                object_dir: nonexistent_object,
                deps: vec![],
                platform: Arc::new(sample_meta_platform()),
            })
            .unwrap_err();
        assert!(format!("{err}").contains("v2"));

        // No `links/<dir>` should exist (final or tmp).
        let final_dir = store.paths().link_dir(&key);
        assert!(!final_dir.exists());

        // No tmp leftover at the parent.
        let parent = final_dir.parent().unwrap();
        if parent.is_dir() {
            for entry in std::fs::read_dir(parent).unwrap() {
                let entry = entry.unwrap();
                let name = entry.file_name().to_string_lossy().to_string();
                assert!(!name.contains("tmp."), "tmp dir leaked: {name}");
            }
        }
    }

    #[test]
    fn invalid_sri_in_object_dir_returns_error() {
        let store = Store::at(std::env::temp_dir().join("lpm-v2-bad-sri"));
        let err = store.paths().object_dir("not-a-sri").unwrap_err();
        // Surface as InvalidIntegrity by way of the parse failure.
        assert!(matches!(err, LpmError::InvalidIntegrity(_)));
    }

    // -------- Crash-recovery and integrity invariants ----------

    #[test]
    fn populate_recovers_from_partial_link_entry_with_sidecar_only() {
        // A leftover `links/<graph-key>/` with only the sidecar (no
        // `node_modules/<pkg>/`) must be detected as incomplete and
        // re-populated, not silently accepted as a cache hit.
        let dir = tempfile::tempdir().unwrap();
        let store = Store::at(dir.path());

        let sri = synthetic_sri(b"recover_partial_link_entry");
        let object_dir = write_object(&store, &sri, &[("package.json", b"{}")]);
        let key = arc_key("c", "0.1.0");
        let final_dir = store.paths().link_dir(&key);

        // Create a partial entry: only the sidecar, no package dir.
        std::fs::create_dir_all(&final_dir).unwrap();
        let stub = LinkMeta::new(
            &key,
            sri.clone(),
            store.paths().relative_object_path(&sri).unwrap(),
            vec![],
            Arc::new(sample_meta_platform()),
        );
        stub.write_to(&final_dir).unwrap();

        let entry = store
            .populate_link_entry(LinkEntryRequest {
                graph_key: key,
                source_sri: sri,
                object_dir,
                deps: vec![],
                platform: Arc::new(sample_meta_platform()),
            })
            .unwrap();

        assert!(
            entry.freshly_populated,
            "incomplete leftover should force re-populate"
        );
        let pkg_dir = entry.link_dir.join("node_modules").join("c");
        assert!(pkg_dir.is_dir());
        assert!(pkg_dir.join("package.json").is_file());
    }

    #[test]
    fn extract_object_recovers_from_partial_object_dir() {
        // Audit finding 3: a leftover `objects/<sri>/` from a crashed
        // extract (no `package.json`, no `.integrity`) used to be
        // treated as a hit. After the tightening, `extract_object`
        // detects the incompleteness and removes the leftover before
        // re-extracting.
        //
        // Synthesizes an empty leftover dir, then exercises the
        // recovery short-circuit by re-running with a real object
        // populated via the `write_object` helper. Bypasses the
        // tarball extractor — these tests don't exercise the
        // gzip/tar pipeline directly.
        let dir = tempfile::tempdir().unwrap();
        let store = Store::at(dir.path());
        let sri = synthetic_sri(b"recover_partial_object_dir");
        let object_dir = store.paths().object_dir(&sri).unwrap();

        // Stage a partial leftover: dir exists but missing both
        // `package.json` AND `.integrity`.
        std::fs::create_dir_all(&object_dir).unwrap();
        std::fs::write(object_dir.join("garbage"), b"x").unwrap();
        assert!(!is_complete_object_dir(&object_dir));

        // Manually populate the same path with a complete object
        // (mimics what a clean extract would produce). The recovery
        // path inside `extract_object` should remove the garbage and
        // re-stage; here we exercise the helper directly via
        // `write_object` and confirm the partial doesn't masquerade
        // as a hit.
        std::fs::remove_dir_all(&object_dir).unwrap();
        write_object(&store, &sri, &[("package.json", b"{}")]);
        assert!(is_complete_object_dir(&object_dir));

        // Now the short-circuit hit path should return without
        // touching the disk further.
        let returned = store.extract_object(&sri, b"unused").unwrap();
        assert_eq!(returned, object_dir);
    }

    #[test]
    fn populate_overwrites_incomplete_final_dir_on_rename_collision() {
        // Audit finding 3: if `final_dir` exists but is incomplete
        // when populate_link_entry's atomic rename runs (a crashed
        // peer process left a half-written entry), the rename retry
        // path removes the leftover and tries once more.
        //
        // We simulate a crashed-peer leftover by manually creating
        // an empty `final_dir` between the existence check and the
        // rename. With the tightened recovery this still ends in a
        // clean populate.
        let dir = tempfile::tempdir().unwrap();
        let store = Store::at(dir.path());

        let sri = synthetic_sri(b"rename_overwrites_incomplete");
        let object_dir = write_object(&store, &sri, &[("package.json", b"{}")]);
        let key = arc_key("d", "0.0.1");
        let final_dir = store.paths().link_dir(&key);

        // Pre-create an empty leftover. Because it's empty (no
        // sidecar, no node_modules), `is_complete_link_entry` returns
        // false and the existence-check branch in populate_link_entry
        // removes it before staging.
        std::fs::create_dir_all(&final_dir).unwrap();
        assert!(!is_complete_link_entry(&final_dir, &key));

        let entry = store
            .populate_link_entry(LinkEntryRequest {
                graph_key: key.clone(),
                source_sri: sri,
                object_dir,
                deps: vec![],
                platform: Arc::new(sample_meta_platform()),
            })
            .unwrap();

        assert!(entry.freshly_populated);
        assert!(is_complete_link_entry(&entry.link_dir, &key));
    }

    #[test]
    fn hoisted_graph_key_distinguishes_peers() {
        // Hoisted link entries materialize peer sibling symlinks, so
        // peer pinning is part of the shared-entry identity. Two
        // hoisted inputs that differ only in peers must not reuse one
        // link entry.
        let no_peers =
            GraphKeyInputs::new("react", "18.3.0", macos_arm64(), LinkerModeTag::Hoisted);
        let with_peers =
            GraphKeyInputs::new("react", "18.3.0", macos_arm64(), LinkerModeTag::Hoisted)
                .with_peers([PeerEntry {
                    name: "react-dom".into(),
                    version: "18.3.0".into(),
                }]);
        assert_ne!(GraphKey::derive(&no_peers), GraphKey::derive(&with_peers));
    }

    #[test]
    fn isolated_graph_key_still_distinguishes_peers() {
        // Isolated mode keeps the same peer identity contract as
        // hoisted mode: different peer layouts get different link
        // entries.
        let p1 = GraphKeyInputs::new("react", "18.3.0", macos_arm64(), LinkerModeTag::Isolated);
        let p2 = p1.clone().with_peers([PeerEntry {
            name: "react-dom".into(),
            version: "18.3.0".into(),
        }]);
        assert_ne!(GraphKey::derive(&p1), GraphKey::derive(&p2));
    }

    /// Build a small gzip+tar tarball with `package/<path>` entries —
    /// matches the npm-tarball convention. Used by the
    /// extract-from-bytes tests below.
    fn build_test_tarball(files: &[(&str, &[u8])]) -> Vec<u8> {
        use flate2::Compression;
        use flate2::write::GzEncoder;
        use std::io::Write;

        let mut tar_data = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_data);
            for (path, content) in files {
                let mut header = tar::Header::new_gnu();
                header.set_size(content.len() as u64);
                header.set_mode(0o644);
                header.set_cksum();
                builder
                    .append_data(&mut header, format!("package/{path}"), &content[..])
                    .unwrap();
            }
            builder.finish().unwrap();
        }
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&tar_data).unwrap();
        encoder.finish().unwrap()
    }

    #[test]
    fn extract_object_from_bytes_populates_object_dir() {
        // End-to-end round trip from raw bytes through SRI
        // computation, extraction, security analysis, and atomic
        // rename. The install pipeline's v2 entry point must produce a
        // complete object dir (package.json + .integrity +
        // .lpm-security.json all present).
        let dir = tempfile::tempdir().unwrap();
        let store = Store::at(dir.path());
        let tarball =
            build_test_tarball(&[("package.json", b"{\"name\":\"x\",\"version\":\"1.0.0\"}")]);

        let (obj_dir, sri, _timings) = store.extract_object_from_bytes(&tarball, None).unwrap();

        assert!(sri.starts_with("sha512-"));
        assert!(obj_dir.is_dir());
        assert!(obj_dir.join("package.json").is_file());
        assert!(obj_dir.join(".integrity").is_file());
        assert!(obj_dir.join(OBJECT_TREE_INTEGRITY_FILENAME).is_file());
        // Security cache lives next to the object.
        assert!(
            obj_dir.join(".lpm-security.json").is_file(),
            "v2 security analysis must run inside extract_object"
        );
    }

    #[test]
    fn extract_object_from_bytes_repairs_tampered_hot_object() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::at(dir.path());
        let tarball = build_test_tarball(&[
            ("package.json", b"{\"name\":\"x\",\"version\":\"1.0.0\"}"),
            ("index.js", b"module.exports = 1;\n"),
        ]);

        let (obj_dir, _sri, _) = store.extract_object_from_bytes(&tarball, None).unwrap();
        std::fs::write(obj_dir.join("index.js"), b"module.exports = 99;\n").unwrap();

        let (repaired_dir, _sri, _) = store.extract_object_from_bytes(&tarball, None).unwrap();

        assert_eq!(repaired_dir, obj_dir);
        assert_eq!(
            std::fs::read(repaired_dir.join("index.js")).unwrap(),
            b"module.exports = 1;\n"
        );
    }

    #[test]
    fn extract_object_from_bytes_repairs_malformed_object_tree_sidecar() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::at(dir.path());
        let tarball = build_test_tarball(&[
            ("package.json", b"{\"name\":\"x\",\"version\":\"1.0.0\"}"),
            ("index.js", b"module.exports = 1;\n"),
        ]);

        let (obj_dir, _sri, _) = store.extract_object_from_bytes(&tarball, None).unwrap();
        std::fs::write(
            obj_dir.join(OBJECT_TREE_INTEGRITY_FILENAME),
            b"sha256-not-hex\n",
        )
        .unwrap();

        let (repaired_dir, _sri, _) = store.extract_object_from_bytes(&tarball, None).unwrap();

        assert_eq!(repaired_dir, obj_dir);
        assert_eq!(
            std::fs::read_to_string(repaired_dir.join(OBJECT_TREE_INTEGRITY_FILENAME))
                .unwrap()
                .trim()
                .len(),
            "sha256-".len() + 64
        );
    }

    #[test]
    fn extract_object_from_bytes_verifies_expected_integrity() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::at(dir.path());
        let tarball = build_test_tarball(&[("package.json", b"{}")]);

        // Wrong expected SRI (sha512 form) → IntegrityMismatch.
        let bogus = "sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==";
        let err = store
            .extract_object_from_bytes(&tarball, Some(bogus))
            .unwrap_err();
        match err {
            LpmError::IntegrityMismatch { expected, .. } => {
                assert_eq!(expected, bogus);
            }
            other => panic!("expected IntegrityMismatch, got {other:?}"),
        }
    }

    #[test]
    fn extract_object_from_bytes_accepts_correct_integrity() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::at(dir.path());
        let tarball = build_test_tarball(&[("package.json", b"{}")]);

        // Compute the SRI ourselves and pass it as expected — the
        // verification path should accept it.
        let expected = crate::compute_sri_hash(&tarball);
        let (_obj_dir, sri, _) = store
            .extract_object_from_bytes(&tarball, Some(&expected))
            .unwrap();
        assert_eq!(sri, expected);
    }

    #[test]
    fn extract_object_from_bytes_accepts_correct_sha1_integrity() {
        use base64::Engine;
        use sha1::{Digest, Sha1};

        let dir = tempfile::tempdir().unwrap();
        let store = Store::at(dir.path());
        let tarball = build_test_tarball(&[("package.json", b"{}")]);
        let expected = format!(
            "sha1-{}",
            base64::engine::general_purpose::STANDARD.encode(Sha1::digest(&tarball))
        );

        let (_obj_dir, sri, _) = store
            .extract_object_from_bytes(&tarball, Some(&expected))
            .unwrap();
        assert_eq!(sri, crate::compute_sri_hash(&tarball));
    }

    #[test]
    fn extract_object_from_bytes_emits_zero_timings_on_hot_path() {
        // The contract worth testing: a re-extract of an already-
        // populated object hits the store-cache short-circuit and
        // emits zero wall-clock timings (the whole point is the
        // hot install path skipping ALL the I/O).
        //
        // We don't assert that the COLD extract emits non-zero ms.
        // Wall-clock timings on a 100-byte synthetic tarball can
        // round to 0 ms on a fast SSD even when actual extract +
        // finalize work runs to completion — milliseconds is too
        // coarse a unit to distinguish "didn't run" from "ran
        // sub-millisecond." The hot-path zero assertion is the
        // load-bearing contract; cold-path > 0 was an implementation
        // detail that flaked on fast machines.
        let dir = tempfile::tempdir().unwrap();
        let store = Store::at(dir.path());
        let tarball =
            build_test_tarball(&[("package.json", b"{\"name\":\"x\",\"version\":\"1.0.0\"}")]);

        // Cold extract — populates the store. We only need a
        // successful return; timing values on this run are not
        // contract.
        let _ = store.extract_object_from_bytes(&tarball, None).unwrap();

        // Hot path (already populated) — re-extract takes the
        // store-hit short-circuit and emits zero timings.
        let (_, _, timings_hot) = store.extract_object_from_bytes(&tarball, None).unwrap();
        assert_eq!(timings_hot.extract_ms, 0);
        assert_eq!(timings_hot.security_ms, 0);
        assert_eq!(timings_hot.finalize_ms, 0);
    }

    #[test]
    #[cfg(unix)]
    fn create_dir_symlink_uses_lpm_common_helper() {
        // Audit finding 1: lpm-store v2 shares lpm-common's symlink
        // helper so the Windows junction fallback isn't accidentally
        // dropped. On Unix we just confirm the function reference
        // resolves and produces a working symlink — the Windows
        // fallback is exercised by lpm-common's own test module
        // when compiled on Windows.
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("real");
        std::fs::create_dir(&target).unwrap();
        let link = dir.path().join("link");
        super::create_dir_symlink(&target, &link).unwrap();
        let read = std::fs::read_link(&link).unwrap();
        assert_eq!(read, target);
    }

    // ── Read API tests ───────────────────────────────────────────────

    /// Populate two link entries, then iterate. Both must surface with
    /// readable sidecars, in some order.
    #[test]
    fn iter_link_entries_returns_populated_entries() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::at(dir.path());

        let sri_a = synthetic_sri(b"iter_link_entries/a");
        let sri_b = synthetic_sri(b"iter_link_entries/b");
        write_object(
            &store,
            &sri_a,
            &[("package.json", b"{\"name\":\"a\",\"version\":\"1.0.0\"}")],
        );
        write_object(
            &store,
            &sri_b,
            &[("package.json", b"{\"name\":\"b\",\"version\":\"2.0.0\"}")],
        );

        let key_a = arc_key("a", "1.0.0");
        let key_b = arc_key("b", "2.0.0");
        store
            .populate_link_entry(LinkEntryRequest {
                graph_key: key_a,
                source_sri: sri_a,
                object_dir: store
                    .paths()
                    .object_dir(&synthetic_sri(b"iter_link_entries/a"))
                    .unwrap(),
                deps: vec![],
                platform: Arc::new(sample_meta_platform()),
            })
            .unwrap();
        store
            .populate_link_entry(LinkEntryRequest {
                graph_key: key_b,
                source_sri: sri_b,
                object_dir: store
                    .paths()
                    .object_dir(&synthetic_sri(b"iter_link_entries/b"))
                    .unwrap(),
                deps: vec![],
                platform: Arc::new(sample_meta_platform()),
            })
            .unwrap();

        let mut names: Vec<String> = store
            .iter_link_entries()
            .unwrap()
            .map(|(_dir, meta)| meta.name)
            .collect();
        names.sort();
        assert_eq!(names, vec!["a".to_string(), "b".to_string()]);
    }

    /// Empty store (no `links/` root yet) returns an empty iterator
    /// rather than an error. Mirrors the upgrade-in-place case where a
    /// user runs `lpm doctor` before any v2 install has populated the
    /// store.
    #[test]
    fn iter_link_entries_handles_missing_links_root() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::at(dir.path());
        let count = store.iter_link_entries().unwrap().count();
        assert_eq!(count, 0);
    }

    /// A poisoned link entry shaped as a symlink (e.g. corrupted store,
    /// hostile same-user writer) must NOT surface in the iterator. The
    /// store writer never produces symlinks at `links/<entry>`; one
    /// appearing is a tamper signal that would otherwise cause `cache
    /// prune --apply` to delete the symlink target (outside the store).
    #[test]
    #[cfg(unix)]
    fn iter_link_entries_refuses_symlinked_entry_at_links_root() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::at(dir.path());

        let sri = synthetic_sri(b"iter_link_entries/legit");
        write_object(
            &store,
            &sri,
            &[(
                "package.json",
                b"{\"name\":\"legit\",\"version\":\"1.0.0\"}",
            )],
        );
        store
            .populate_link_entry(LinkEntryRequest {
                graph_key: arc_key("legit", "1.0.0"),
                source_sri: sri.clone(),
                object_dir: store.paths().object_dir(&sri).unwrap(),
                deps: vec![],
                platform: Arc::new(sample_meta_platform()),
            })
            .unwrap();

        let outside = dir.path().join("outside-of-store");
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(
            outside.join(".lpm-link-meta.json"),
            br#"{"schema":1,"name":"poisoned","version":"99.0.0","source_sri":"sha512-x","object_path":"objects/sha512-x","graph_key_digest_hex":"deadbeef","deps":[],"platform":{"os":"darwin","cpu":"arm64"},"last_referenced_at":"2024-01-01T00:00:00Z"}"#,
        )
        .unwrap();
        std::os::unix::fs::symlink(&outside, store.paths().links_root().join("poisoned")).unwrap();

        let names: Vec<String> = store
            .iter_link_entries()
            .unwrap()
            .map(|(_dir, meta)| meta.name)
            .collect();
        assert_eq!(
            names,
            vec!["legit".to_string()],
            "symlinked link entry must not surface"
        );

        let verify_entries = store.iter_link_entries_for_verify().unwrap();
        let symlink_issue = verify_entries
            .iter()
            .find(|(p, _)| p.file_name().and_then(|n| n.to_str()) == Some("poisoned"));
        let (_, result) = symlink_issue.expect("verify must surface the symlinked entry");
        assert!(
            matches!(result, Err(LpmError::Store(msg)) if msg.contains("symlink")),
            "verify must report the symlinked entry as a store-integrity issue, got {result:?}"
        );
    }

    /// `find_link_package_dir` returns the package dir for a `(name,
    /// version)` that's been populated. Used by `lpm rebuild` to find
    /// transitive packages with lifecycle scripts under v2.
    #[test]
    fn find_link_package_dir_locates_populated_entry() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::at(dir.path());

        let sri = synthetic_sri(b"find_link_package_dir/c");
        let object_dir = write_object(
            &store,
            &sri,
            &[("package.json", b"{\"name\":\"c\",\"version\":\"3.1.4\"}")],
        );
        let key = arc_key("c", "3.1.4");
        store
            .populate_link_entry(LinkEntryRequest {
                graph_key: key.clone(),
                source_sri: sri,
                object_dir,
                deps: vec![],
                platform: Arc::new(sample_meta_platform()),
            })
            .unwrap();

        let resolved = store.find_link_package_dir("c", "3.1.4").unwrap();
        assert!(resolved.is_some(), "must locate populated entry");
        let resolved = resolved.unwrap();
        assert_eq!(resolved, store.paths().link_package_dir(&key));
        assert!(resolved.join("package.json").is_file());

        // Wrong version → None.
        assert_eq!(store.find_link_package_dir("c", "0.0.0").unwrap(), None);
        // Wrong name → None.
        assert_eq!(store.find_link_package_dir("nope", "3.1.4").unwrap(), None);
    }

    /// `populate_object_from_v1` copies an extracted v1 package dir
    /// into a v2 object dir atomically, preserving package contents
    /// and `.lpm-security.json` if present.
    #[test]
    fn populate_object_from_v1_copies_extracted_package_dir() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::at(dir.path());

        // Synthesize a fake v1 package dir at an arbitrary location.
        // Real v1's `<HOME>/.lpm/store/v1/<name>/<version>/` is just
        // a directory of extracted bytes plus `.integrity` +
        // `.lpm-security.json`; the helper accepts any directory in
        // the same shape.
        let v1_pkg_dir = dir.path().join("fake-v1/pkg/1.0.0");
        std::fs::create_dir_all(&v1_pkg_dir).unwrap();
        std::fs::write(
            v1_pkg_dir.join("package.json"),
            b"{\"name\":\"e\",\"version\":\"1.0.0\"}",
        )
        .unwrap();
        std::fs::write(v1_pkg_dir.join("index.js"), b"module.exports = 42;").unwrap();
        std::fs::create_dir_all(v1_pkg_dir.join("src")).unwrap();
        std::fs::write(v1_pkg_dir.join("src/inner.js"), b"// inner").unwrap();
        std::fs::write(v1_pkg_dir.join(".lpm-security.json"), b"{\"tags\":[]}").unwrap();
        std::fs::write(v1_pkg_dir.join(".integrity"), b"sha512-stale").unwrap();

        let sri = synthetic_sri(b"populate_object_from_v1");
        let object_dir = store.populate_object_from_v1(&v1_pkg_dir, &sri).unwrap();
        assert_eq!(object_dir, store.paths().object_dir(&sri).unwrap());
        // Package contents copied through.
        assert_eq!(
            std::fs::read(object_dir.join("package.json")).unwrap(),
            b"{\"name\":\"e\",\"version\":\"1.0.0\"}"
        );
        assert_eq!(
            std::fs::read(object_dir.join("index.js")).unwrap(),
            b"module.exports = 42;"
        );
        assert_eq!(
            std::fs::read(object_dir.join("src/inner.js")).unwrap(),
            b"// inner"
        );
        // `.lpm-security.json` preserved (skips re-analysis).
        assert_eq!(
            std::fs::read(object_dir.join(".lpm-security.json")).unwrap(),
            b"{\"tags\":[]}"
        );
        // `.integrity` rewritten to the caller-supplied SRI rather
        // than v1's stale value.
        assert_eq!(
            std::fs::read(object_dir.join(".integrity")).unwrap(),
            sri.as_bytes()
        );

        // Idempotent: second call returns the same path without
        // touching anything.
        let again = store.populate_object_from_v1(&v1_pkg_dir, &sri).unwrap();
        assert_eq!(again, object_dir);
    }

    /// When `.lpm-security.json` is missing in v1 (rare, e.g. a
    /// partial or pre-security-cache install), the helper re-runs
    /// behavioral analysis so v2's post-write contract holds.
    #[test]
    fn populate_object_from_v1_runs_analysis_when_security_cache_missing() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::at(dir.path());

        let v1_pkg_dir = dir.path().join("fake-v1/pkg-no-cache/1.0.0");
        std::fs::create_dir_all(&v1_pkg_dir).unwrap();
        std::fs::write(
            v1_pkg_dir.join("package.json"),
            b"{\"name\":\"f\",\"version\":\"1.0.0\"}",
        )
        .unwrap();

        let sri = synthetic_sri(b"populate_object_from_v1_no_cache");
        let object_dir = store.populate_object_from_v1(&v1_pkg_dir, &sri).unwrap();
        assert!(
            object_dir.join(".lpm-security.json").is_file(),
            "translation must regenerate security cache when v1 didn't ship one"
        );
    }

    #[test]
    #[cfg(unix)]
    fn path_lives_in_store_recognizes_canonical_descendants() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::at(dir.path());

        let sri = synthetic_sri(b"path_lives_in_store/d");
        let object_dir = write_object(
            &store,
            &sri,
            &[("package.json", b"{\"name\":\"d\",\"version\":\"1.0.0\"}")],
        );
        let key = arc_key("d", "1.0.0");
        let entry = store
            .populate_link_entry(LinkEntryRequest {
                graph_key: key.clone(),
                source_sri: sri,
                object_dir,
                deps: vec![],
                platform: Arc::new(sample_meta_platform()),
            })
            .unwrap();

        // Direct probe.
        assert!(store.path_lives_in_store(&entry.link_dir));
        assert!(store.path_lives_in_store(&store.paths().link_package_dir(&key)));

        // A symlink pointing at the link entry — the canonicalize step
        // dereferences and the predicate still recognizes the target.
        let proxy_dir = dir.path().join("proxy");
        std::os::unix::fs::symlink(&entry.link_dir, &proxy_dir).unwrap();
        assert!(store.path_lives_in_store(&proxy_dir));

        // A path completely outside the store.
        let outside = dir.path().join("not-the-store");
        std::fs::create_dir_all(&outside).unwrap();
        assert!(!store.path_lives_in_store(&outside));
    }

    // ── sri_to_segment parity ──────────────────────────────────────────────

    /// The optimized `sri_to_segment` (single-alloc write loop) must
    /// produce identical output to the naïve `format!("{algo}-{hex}")` it
    /// replaced.
    #[test]
    fn sri_to_segment_parity_sha512() {
        let sri = synthetic_sri(b"trial28-parity-sha512");
        // Round-trip through the public API to exercise sri_to_segment.
        let store = Store::at(std::env::temp_dir().join("lpm-v2-t28-sri-parity"));
        let segment_path = store.paths().object_dir(&sri).unwrap();
        let segment = segment_path
            .file_name()
            .unwrap()
            .to_string_lossy()
            .to_string();
        // SHA-512 segment: "sha512-" + 128 lowercase hex chars.
        assert!(segment.starts_with("sha512-"), "expected sha512- prefix");
        assert_eq!(segment.len(), "sha512-".len() + 128);
        assert!(
            segment["sha512-".len()..]
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase()),
            "hex portion must be lowercase"
        );
    }

    /// SHA-256 SRI produces the correct segment prefix and length.
    #[test]
    fn sri_to_segment_parity_sha256() {
        use sha2::Digest as _;
        let hash = sha2::Sha256::digest(b"trial28-parity-sha256");
        let b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, hash);
        let sri = format!("sha256-{b64}");
        let store = Store::at(std::env::temp_dir().join("lpm-v2-t28-sri-parity-256"));
        let segment_path = store.paths().object_dir(&sri).unwrap();
        let segment = segment_path
            .file_name()
            .unwrap()
            .to_string_lossy()
            .to_string();
        // SHA-256 segment: "sha256-" + 64 lowercase hex chars.
        assert!(segment.starts_with("sha256-"), "expected sha256- prefix");
        assert_eq!(segment.len(), "sha256-".len() + 64);
        assert!(
            segment["sha256-".len()..]
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase()),
            "hex portion must be lowercase"
        );
    }

    /// M28: tmp_sibling now uses a random 64-bit suffix instead of
    /// the predictable pid+thread::id pair. Two calls in quick
    /// succession should produce distinct paths with overwhelming
    /// probability — confirms the suffix is actually random and not
    /// re-derived from a deterministic source.
    #[test]
    fn tmp_sibling_produces_unpredictable_suffix_across_calls() {
        let base = std::path::PathBuf::from("/tmp/foo-object");
        let a = tmp_sibling(&base);
        let b = tmp_sibling(&base);
        assert_ne!(
            a, b,
            "two tmp_sibling calls on the same path must produce different suffixes",
        );
        // Sanity: shape is `<base>.tmp.<16-hex>`.
        let a_name = a.file_name().unwrap().to_string_lossy().into_owned();
        assert!(
            a_name.starts_with("foo-object.tmp."),
            "expected `<name>.tmp.<suffix>` shape, got {a_name}",
        );
        let suffix = a_name.trim_start_matches("foo-object.tmp.");
        assert_eq!(suffix.len(), 16, "suffix should be 16 hex chars: {suffix}");
        assert!(
            suffix.chars().all(|c| c.is_ascii_hexdigit()),
            "suffix should be hex: {suffix}",
        );
    }

    /// M28: pre-created tmp staging dirs land at 0o700 on Unix so a
    /// partial extract cannot be read by other UIDs on a shared host.
    #[cfg(unix)]
    #[test]
    fn create_tmp_dir_locked_sets_0o700() {
        use std::os::unix::fs::PermissionsExt;
        let parent = tempfile::tempdir().unwrap();
        let target = parent.path().join("staging");
        create_tmp_dir_locked(&target).unwrap();
        let mode = std::fs::metadata(&target).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "expected 0o700, got 0o{mode:o}");
    }

    /// `ensure_store_tier_dir_locked` creates the store-tier dir at
    /// 0o700 on a fresh path. Closes the shared-host disclosure shape
    /// where `create_dir_all`'s default-umask inheritance leaves
    /// `objects/` and `links/` at 0o755.
    #[cfg(unix)]
    #[test]
    fn ensure_store_tier_dir_locked_creates_at_0o700() {
        use std::os::unix::fs::PermissionsExt;
        let parent = tempfile::tempdir().unwrap();
        let target = parent.path().join("v2").join("objects");
        ensure_store_tier_dir_locked(&target).unwrap();
        let mode = std::fs::metadata(&target).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o700,
            "store-tier dir must be 0o700 on first create, got 0o{mode:o}"
        );
    }

    /// Idempotency: a pre-existing 0o755 dir (e.g., one created by an
    /// older lpm release that predated this fix) is tightened in
    /// place on the next install touch.
    #[cfg(unix)]
    #[test]
    fn ensure_store_tier_dir_locked_tightens_existing_world_readable_dir() {
        use std::os::unix::fs::PermissionsExt;
        let parent = tempfile::tempdir().unwrap();
        let target = parent.path().join("v2").join("links");
        std::fs::create_dir_all(&target).unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o755)).unwrap();
        ensure_store_tier_dir_locked(&target).unwrap();
        let mode = std::fs::metadata(&target).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o700,
            "store-tier dir must be tightened to 0o700 on re-use, got 0o{mode:o}"
        );
    }

    /// L8: a stray symlink in a v1 store entry must NOT propagate
    /// into the v2 object dir via the v1→v2 migration copy. A
    /// regression or local-attacker plant would otherwise reproduce
    /// the symlink target (e.g. `/etc/passwd`) into every consuming
    /// link entry.
    #[cfg(unix)]
    #[test]
    fn copy_dir_recursively_skips_symlinks_from_v1_source() {
        let parent = tempfile::tempdir().unwrap();
        let v1 = parent.path().join("v1");
        let dst = parent.path().join("v2");
        std::fs::create_dir_all(&v1).unwrap();
        // Real file alongside the symlink — proves the migration
        // completes for the surrounding files.
        std::fs::write(v1.join("package.json"), b"{}").unwrap();
        // Hostile symlink pointing outside the package dir.
        std::os::unix::fs::symlink("/etc/passwd", v1.join("escape")).unwrap();

        copy_dir_recursively(&v1, &dst).expect("copy should succeed");

        assert!(
            dst.join("package.json").is_file(),
            "regular file must be copied",
        );
        assert!(
            dst.join("escape").symlink_metadata().is_err(),
            "symlink must be skipped — refusing to migrate v1→v2 symlinks",
        );
    }
}
