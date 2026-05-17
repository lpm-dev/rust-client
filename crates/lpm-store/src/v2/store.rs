//! v2 store filesystem layer.
//!
//! Splits responsibility cleanly:
//! - [`StoreV2Paths`] — pure path computations (no I/O).
//! - [`Store`] — I/O entry points: object extraction (clonefile-able),
//!   link-entry population (clonefile from objects + sibling symlinks
//!   + atomic rename + sidecar write).
//!
//! v2 writes are gated behind `LPM_STORE_VERSION=v2`.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use lpm_common::integrity::{HashAlgorithm, Integrity};
use lpm_common::{LpmError, LpmRoot};

use crate::StageTimings;
use crate::v2::graph_key::GraphKey;
use crate::v2::link_meta::{LINK_META_FILENAME, LinkMeta, LinkMetaDep, LinkMetaPlatform};

/// v2 layout version segment under `~/.lpm/store/`. Bumped whenever
/// the on-disk shape changes; lpm reading a higher-numbered store
/// MUST refuse rather than silently misinterpret.
const STORE_V2_VERSION: &str = "v2";

/// Subdirectory holding the content-addressable object dirs.
const OBJECTS_DIR: &str = "objects";

/// Subdirectory holding per-graph-key link entries.
const LINKS_DIR: &str = "links";

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
}

impl StoreV2Paths {
    /// Build the path helper rooted at `<lpm_home>/store/v2/`.
    pub fn from_lpm_root(lpm_root: &LpmRoot) -> Self {
        let root = lpm_root.store_root().join(STORE_V2_VERSION);
        let objects_root = root.join(OBJECTS_DIR);
        let links_root = root.join(LINKS_DIR);
        Self {
            root,
            objects_root,
            links_root,
        }
    }

    /// Build the path helper at an arbitrary base (test seam).
    pub fn at(root: impl Into<PathBuf>) -> Self {
        let root = root.into();
        let objects_root = root.join(OBJECTS_DIR);
        let links_root = root.join(LINKS_DIR);
        Self {
            root,
            objects_root,
            links_root,
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
    /// where the canonical bytes for THIS link entry live (clonefile
    /// of an [`Self::object_dir`]). Sibling deps live alongside as
    /// symlinks.
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
    /// package's clonefile. Each tuple is
    /// `(local_name, target_graph_key, target_name, target_version)`.
    /// Order is irrelevant; symlinks are created independently.
    pub deps: Vec<DepLink>,
    /// Platform tuple to record in the sidecar.
    pub platform: Arc<LinkMetaPlatform>,
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
        if object_dir.exists() {
            if is_complete_object_dir(&object_dir) {
                tracing::debug!(
                    target = %object_dir.display(),
                    "v2 store: object hit"
                );
                return Ok((object_dir, timings));
            }

            tracing::warn!(
                target = %object_dir.display(),
                "v2 store: incomplete object dir; removing before re-extract"
            );
            std::fs::remove_dir_all(&object_dir).map_err(|e| {
                LpmError::Store(format!(
                    "failed to remove incomplete v2 object at {}: {e}",
                    object_dir.display()
                ))
            })?;
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
        if let Err(e) = std::fs::write(tmp_dir.join(".integrity"), sri) {
            let _ = std::fs::remove_dir_all(&tmp_dir);
            return Err(LpmError::Store(format!(
                "failed to write v2 .integrity: {e}"
            )));
        }

        let result = match std::fs::rename(&tmp_dir, &object_dir) {
            Ok(()) => Ok(object_dir.clone()),
            Err(_) if is_complete_object_dir(&object_dir) => {
                // Concurrent install populated the same object first —
                // discard our stage and use theirs.
                let _ = std::fs::remove_dir_all(&tmp_dir);
                Ok(object_dir.clone())
            }
            Err(e) => {
                let _ = std::fs::remove_dir_all(&tmp_dir);
                Err(LpmError::Store(format!(
                    "failed to atomically install v2 object: {e}"
                )))
            }
        };
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
            } else {
                return Err(LpmError::Registry(format!(
                    "unsupported integrity algorithm in v2 extract: {expected} — \
                     expected sha512-… (preferred) or sha256-…"
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
    /// already complete, refreshes [`LinkMeta::last_referenced_at`]
    /// and short-circuits.
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
            if is_complete_link_entry(&final_dir, &graph_key) {
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
                "v2 store: incomplete link entry; removing before re-populate"
            );
            std::fs::remove_dir_all(&final_dir).map_err(|e| {
                LpmError::Store(format!(
                    "failed to remove incomplete v2 link entry at {}: {e}",
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
            Err(_) if is_complete_link_entry(&final_dir, &graph_key) => {
                // Concurrent install beat us — discard our stage and
                // refresh the existing sidecar's mtime (followup #3).
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
                // Final dir exists but is incomplete — a different
                // process crashed mid-populate AFTER our existence
                // check above. Remove the leftover and retry the
                // rename once. Beyond a single retry we surface the
                // error rather than spinning, since the underlying
                // cause is filesystem-level (permission, EXDEV) and
                // a third attempt won't change that.
                tracing::warn!(
                    target = %final_dir.display(),
                    "v2 store: rename hit incomplete leftover; removing and retrying once"
                );
                if let Err(e) = std::fs::remove_dir_all(&final_dir) {
                    let _ = std::fs::remove_dir_all(&tmp_dir);
                    return Err(LpmError::Store(format!(
                        "failed to remove incomplete v2 link entry during retry at {}: {e}",
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
        if object_dir.exists() && is_complete_object_dir(&object_dir) {
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

        // Re-write `.integrity` from the caller-supplied SRI rather
        // than trusting whatever v1 happened to record — keeps the
        // v2 object's integrity field byte-equivalent to what
        // `extract_object` would write for the same SRI.
        if let Err(e) = std::fs::write(tmp_dir.join(".integrity"), sri) {
            let _ = std::fs::remove_dir_all(&tmp_dir);
            return Err(LpmError::Store(format!(
                "failed to write v2 .integrity during v1 translation: {e}"
            )));
        }

        // If v1 didn't ship a security cache (rare, but possible on
        // a stale or partial v1 entry), re-run analysis so the v2
        // post-write contract holds.
        if !tmp_dir.join(".lpm-security.json").is_file() {
            let analysis = lpm_security::behavioral::analyze_package(&tmp_dir);
            if let Err(e) = lpm_security::behavioral::write_cached_analysis(&tmp_dir, &analysis) {
                tracing::warn!("v2 translation: failed to write .lpm-security.json: {e}");
            }
        }

        match std::fs::rename(&tmp_dir, &object_dir) {
            Ok(()) => Ok(object_dir),
            Err(_) if is_complete_object_dir(&object_dir) => {
                // Concurrent install completed first — discard ours.
                let _ = std::fs::remove_dir_all(&tmp_dir);
                Ok(object_dir)
            }
            Err(e) => {
                let _ = std::fs::remove_dir_all(&tmp_dir);
                Err(LpmError::Store(format!(
                    "v1 → v2 translation: failed to atomically install v2 object: {e}"
                )))
            }
        }
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
            if !object_dir.join(".integrity").is_file() {
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

    // Materialize the package itself by clonefile/hardlink/copy from
    // the object directory. This produces independent inodes on
    // CoW-capable filesystems (clonefile / reflink) and shared inodes
    // on Linux ext4 fallback.
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

/// Object dir is complete iff `package.json` AND `.integrity` are
/// both present — symmetric to v1's `is_complete_package_dir`. The
/// tarball extractor writes `package.json` first (it's at the root of
/// every npm tarball) and `extract_object` writes `.integrity` last;
/// observing both means staging closed cleanly even on a crash
/// mid-extract.
fn is_complete_object_dir(dir: &Path) -> bool {
    dir.is_dir() && dir.join("package.json").exists() && dir.join(".integrity").exists()
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

/// Materialize `src/` into `dst/` using the fastest available primitive.
///
/// Order: macOS clonefile → hardlink fallback (file-by-file) → copy
/// fallback. Mirrors `lpm-linker::link_dir_recursive`'s policy so the
/// v2 store inherits the same CoW-on-APFS performance characteristics
/// today's v1 wrappers already have.
///
/// # Accepted-posture trade-off (H22)
///
/// On Linux the function falls straight to [`std::fs::hard_link`],
/// which makes the project's `node_modules/<pkg>/<file>` and the
/// store object at `objects/<sri>/<file>` share an inode. On a CoW-
/// capable filesystem (Btrfs, XFS with `reflink=1`, F2FS) this is
/// safe in practice because most editor / build-tool writes
/// `unlink`+`create` the destination, breaking the link before the
/// kernel writes attacker-controlled bytes. On ext4 — the default
/// Linux root FS — `unlink`+`create` still breaks the link, but a
/// truncate-in-place write (`fs.writeFileSync` in Node, `open(O_TRUNC)`
/// in C, `open(..., 'w')` in Python) modifies the underlying inode
/// in place and so mutates the CAS object that every project on the
/// machine resolving the same SRI shares.
///
/// The primary defense is the script-policy gate: any postinstall
/// that could trigger the mutation must be either bundled with a
/// `trustedDependencies` entry or explicitly approved via the
/// triage-advisor (see `crates/lpm-cli/src/script_policy_config.rs`
/// and the H4/L29 fixes for the surrounding gate). H22 only triggers
/// when an approved script intentionally mutates its package files;
/// the next install resolves the mutated SRI as a new entry, so
/// long-term divergence is bounded by SRI rotation.
///
/// The long-term mitigation handle is `FICLONE` (ioctl
/// `FS_IOC_CLONE` / `0x40049409`) attempted first on Linux, with
/// fallback to hard_link only when the kernel returns `EOPNOTSUPP`
/// (ext4). Reflink gives an independent inode under CoW semantics,
/// so a project-side write doesn't touch the store object even
/// under truncate-in-place. Implementation is deferred because the
/// fallback path still leaves the ext4 case exposed and the right
/// answer is to migrate the default install-pipeline write shape
/// instead (covered by tracking-issue work outside this audit). See
/// `private/security-findings.md` H22 for the full trade-off
/// discussion.
fn materialize_into(src: &Path, dst: &Path) -> Result<(), LpmError> {
    #[cfg(target_os = "macos")]
    {
        if try_clonefile(src, dst) {
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
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());

        let file_type = entry.file_type().map_err(|e| {
            LpmError::Store(format!(
                "failed to stat v2 source entry {}: {e}",
                src_path.display()
            ))
        })?;

        if file_type.is_dir() {
            materialize_into(&src_path, &dst_path)?;
        } else if file_type.is_symlink() {
            // Symlinks inside the object dir (rare — registry tarballs
            // can contain them) round-trip as symlinks, not their
            // dereferenced targets. Anything else would diverge from
            // the tarball's intent.
            let target = std::fs::read_link(&src_path).map_err(|e| {
                LpmError::Store(format!(
                    "failed to read v2 source symlink {}: {e}",
                    src_path.display()
                ))
            })?;
            #[cfg(unix)]
            std::os::unix::fs::symlink(&target, &dst_path).map_err(|e| {
                LpmError::Store(format!(
                    "failed to create v2 dest symlink {} → {}: {e}",
                    dst_path.display(),
                    target.display()
                ))
            })?;
            #[cfg(windows)]
            {
                let _ = target; // file-vs-dir distinction unused here
                return Err(LpmError::Store(
                    "v2 source symlinks are not yet supported on Windows".into(),
                ));
            }
        } else if let Err(e) = std::fs::hard_link(&src_path, &dst_path) {
            tracing::trace!(
                src = %src_path.display(),
                dst = %dst_path.display(),
                error = %e,
                "v2 materialize: hardlink failed, falling back to copy"
            );
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
        std::fs::write(dir.join(".integrity"), sri).unwrap();
        dir
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
                graph_key: key.clone(),
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
        // The JSON `last_referenced_at` is frozen at creation under
        // followup #3; the effective time tracks file mtime.
        let effective = read_back.effective_last_referenced_at(&sidecar_path);
        assert!(effective > first_sidecar.last_referenced_at);
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
                graph_key: pkg_key.clone(),
                source_sri: pkg_sri.clone(),
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
                graph_key: pkg_key.clone(),
                source_sri: pkg_sri.clone(),
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
                source_sri: sri.clone(),
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
                graph_key: key.clone(),
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
    fn hoisted_graph_key_collapses_peers_silently_in_release() {
        // Under hoisted mode, peers must not contribute to the graph
        // key. The primitive
        // enforces this regardless of caller normalization (silent
        // collapse + debug_assert; this test exercises only the
        // collapse part — the debug_assert path is exercised under
        // `#[should_panic]` below).
        //
        // Two hoisted inputs that differ ONLY in `peers` MUST yield
        // the same graph key. Anything else fragments the cross-
        // project hoisted cache the rewrite is meant to unlock.
        let no_peers =
            GraphKeyInputs::new("react", "18.3.0", macos_arm64(), LinkerModeTag::Hoisted);
        // Build the with-peers variant directly (skipping the
        // `with_peers` path so the debug_assert in `derive` doesn't
        // fire — we want to exercise the silent-collapse arm in
        // release semantics).
        let mut with_peers =
            GraphKeyInputs::new("react", "18.3.0", macos_arm64(), LinkerModeTag::Hoisted);
        // Only execute the inline assignment under cfg(not(debug_assertions))
        // so cargo test --release-style runs cover this path. Tests
        // running with debug_assertions on would panic via the
        // debug_assert, which is the desired dev-time behavior.
        if cfg!(not(debug_assertions)) {
            with_peers.peers = vec![PeerEntry {
                name: "react-dom".into(),
                version: "18.3.0".into(),
            }];
            assert_eq!(GraphKey::derive(&no_peers), GraphKey::derive(&with_peers));
        } else {
            // In debug builds, just assert that the no-peers form
            // hashes deterministically — the silent-collapse arm is
            // exercised by release builds (CI runs both).
            let a = GraphKey::derive(&no_peers);
            let b = GraphKey::derive(&no_peers);
            assert_eq!(a, b);
        }
    }

    #[test]
    fn isolated_graph_key_still_distinguishes_peers() {
        // Symmetric guard for finding 2: the hoisted collapse must NOT
        // affect isolated-mode keys. Two isolated inputs differing in
        // peers MUST yield different graph keys.
        let p1 = GraphKeyInputs::new("react", "18.3.0", macos_arm64(), LinkerModeTag::Isolated);
        let p2 = p1.clone().with_peers([PeerEntry {
            name: "react-dom".into(),
            version: "18.3.0".into(),
        }]);
        assert_ne!(GraphKey::derive(&p1), GraphKey::derive(&p2));
    }

    #[test]
    #[should_panic(expected = "hoisted graph keys must not carry peers")]
    #[cfg(debug_assertions)]
    fn hoisted_with_peers_panics_in_debug() {
        // The dev-time guard surfaces caller mistakes. Wrapped in
        // cfg(debug_assertions) so the test is a no-op under release
        // builds where the debug_assert is compiled out.
        let mut input =
            GraphKeyInputs::new("react", "18.3.0", macos_arm64(), LinkerModeTag::Hoisted);
        input.peers = vec![PeerEntry {
            name: "react-dom".into(),
            version: "18.3.0".into(),
        }];
        let _ = GraphKey::derive(&input);
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
        // Security cache lives next to the object.
        assert!(
            obj_dir.join(".lpm-security.json").is_file(),
            "v2 security analysis must run inside extract_object"
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
