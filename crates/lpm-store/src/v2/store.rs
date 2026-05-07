//! v2 store filesystem layer.
//!
//! Splits responsibility cleanly:
//! - [`StoreV2Paths`] — pure path computations (no I/O).
//! - [`Store`] — I/O entry points: object extraction (clonefile-able),
//!   link-entry population (clonefile from objects + sibling symlinks
//!   + atomic rename + sidecar write).
//!
//! Phase 4a ships these as **dead code**: no install pipeline calls
//! them yet. Phase 4b wires them in behind `LPM_STORE_VERSION=v2`.

use std::path::{Path, PathBuf};

use lpm_common::integrity::{HashAlgorithm, Integrity};
use lpm_common::{LpmError, LpmRoot};

use crate::v2::graph_key::GraphKey;
use crate::v2::link_meta::{LinkMeta, LinkMetaDep, LinkMetaPlatform};

/// v2 layout version segment under `~/.lpm/store/`. Bumped whenever
/// the on-disk shape changes; lpm reading a higher-numbered store
/// MUST refuse rather than silently misinterpret.
const STORE_V2_VERSION: &str = "v2";

/// Subdirectory holding the content-addressable object dirs.
const OBJECTS_DIR: &str = "objects";

/// Subdirectory holding per-graph-key link entries.
const LINKS_DIR: &str = "links";

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
}

impl StoreV2Paths {
    /// Build the path helper rooted at `<lpm_home>/store/v2/`.
    pub fn from_lpm_root(lpm_root: &LpmRoot) -> Self {
        Self {
            root: lpm_root.store_root().join(STORE_V2_VERSION),
        }
    }

    /// Build the path helper at an arbitrary base (test seam).
    pub fn at(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// `~/.lpm/store/v2/`
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// `~/.lpm/store/v2/objects/`
    pub fn objects_root(&self) -> PathBuf {
        self.root.join(OBJECTS_DIR)
    }

    /// `~/.lpm/store/v2/links/`
    pub fn links_root(&self) -> PathBuf {
        self.root.join(LINKS_DIR)
    }

    /// `~/.lpm/store/v2/objects/<algo>-<hex>/` for a given SRI.
    ///
    /// Returns [`LpmError::InvalidIntegrity`] if `sri` doesn't parse
    /// as a canonical SRI string.
    pub fn object_dir(&self, sri: &str) -> Result<PathBuf, LpmError> {
        Ok(self.objects_root().join(sri_to_segment(sri)?))
    }

    /// Path that the sidecar would record for `sri` — the same as
    /// [`Self::object_dir`] but expressed relative to [`Self::root`]
    /// so the on-disk form is `$LPM_HOME`-portable.
    pub fn relative_object_path(&self, sri: &str) -> Result<String, LpmError> {
        Ok(format!("{OBJECTS_DIR}/{}", sri_to_segment(sri)?))
    }

    /// `~/.lpm/store/v2/links/<graph-key>/` for a given key.
    pub fn link_dir(&self, key: &GraphKey) -> PathBuf {
        self.links_root().join(key.dir_name())
    }

    /// `~/.lpm/store/v2/links/<graph-key>/node_modules/`.
    pub fn link_node_modules_dir(&self, key: &GraphKey) -> PathBuf {
        self.link_dir(key).join(LINK_NODE_MODULES)
    }

    /// `~/.lpm/store/v2/links/<graph-key>/node_modules/<pkg>/` —
    /// where the canonical bytes for THIS link entry live (clonefile
    /// of an [`Self::object_dir`]). Sibling deps live alongside as
    /// symlinks.
    pub fn link_package_dir(&self, key: &GraphKey) -> PathBuf {
        self.link_node_modules_dir(key).join(key.name())
    }
}

/// Convert an SRI integrity string into a filesystem-safe segment
/// (`<algo>-<hex>`). Hex (vs base64) keeps the segment safe on every
/// platform — no `/`, `+`, or `=` characters.
fn sri_to_segment(sri: &str) -> Result<String, LpmError> {
    let int = Integrity::parse(sri)?;
    let algo = match int.algorithm {
        HashAlgorithm::Sha256 => "sha256",
        HashAlgorithm::Sha512 => "sha512",
    };
    let hex = hex::encode(&int.hash);
    Ok(format!("{algo}-{hex}"))
}

/// Sibling symlink target known at populate time.
#[derive(Debug, Clone)]
pub struct LinkEntryRequest {
    /// Canonical name of the package being materialized at
    /// `links/<graph-key>/node_modules/<name>/`. Always equals
    /// `graph_key.name()` — kept on the request struct for explicit
    /// readability at call sites.
    pub graph_key: GraphKey,
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
    pub platform: LinkMetaPlatform,
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
    pub target: GraphKey,
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
    /// Sidecar that was written / refreshed.
    pub sidecar: LinkMeta,
}

/// I/O front-end for the v2 store.
///
/// Holds the [`StoreV2Paths`] and exposes the two write entry points:
/// [`Self::extract_object`] (object population) and
/// [`Self::populate_link_entry`] (link entry + sidecar). Read-side
/// helpers will land in Phase 4c.
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
    /// `objects/<algo>-<hex>/`. Idempotent: returns the existing object
    /// dir if it's already populated.
    ///
    /// Atomic via the standard `dir.with_extension(tmp.<pid>.<tid>)` →
    /// `rename` pattern (mirrors v1's `store_package_into` to keep the
    /// failure-recovery story consistent).
    ///
    /// **Note:** Phase 4a ships extraction into `objects/<sri>/` only.
    /// Behavioral security analysis (`.lpm-security.json` from
    /// `lpm-security::behavioral`) is intentionally NOT run here — Phase
    /// 4b will decide whether the analysis lives next to the object
    /// (current v1 placement) or next to each link entry. Either way
    /// the question doesn't gate Phase 4a's primitives.
    pub fn extract_object(&self, sri: &str, tarball_data: &[u8]) -> Result<PathBuf, LpmError> {
        let object_dir = self.paths.object_dir(sri)?;
        if object_dir.is_dir() {
            tracing::debug!(
                target = %object_dir.display(),
                "v2 store: object hit"
            );
            return Ok(object_dir);
        }

        if let Some(parent) = object_dir.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| LpmError::Store(format!("failed to create v2 objects dir: {e}")))?;
        }

        let tmp_dir = tmp_sibling(&object_dir);
        if tmp_dir.exists() {
            let _ = std::fs::remove_dir_all(&tmp_dir);
        }

        if let Err(error) = lpm_extractor::extract_tarball(tarball_data, &tmp_dir) {
            let _ = std::fs::remove_dir_all(&tmp_dir);
            return Err(error);
        }

        // Persist the SRI alongside the object bytes for
        // post-extraction integrity verification — same `.integrity`
        // file as v1 so `lpm store verify --deep` keeps working in
        // mixed-v1/v2 environments.
        if let Err(e) = std::fs::write(tmp_dir.join(".integrity"), sri) {
            let _ = std::fs::remove_dir_all(&tmp_dir);
            return Err(LpmError::Store(format!(
                "failed to write v2 .integrity: {e}"
            )));
        }

        match std::fs::rename(&tmp_dir, &object_dir) {
            Ok(()) => Ok(object_dir),
            Err(_) if object_dir.exists() => {
                // Concurrent install populated the same object first —
                // discard our stage and use theirs.
                let _ = std::fs::remove_dir_all(&tmp_dir);
                Ok(object_dir)
            }
            Err(e) => {
                let _ = std::fs::remove_dir_all(&tmp_dir);
                Err(LpmError::Store(format!(
                    "failed to atomically install v2 object: {e}"
                )))
            }
        }
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

        if is_complete_link_entry(&final_dir) {
            // Already populated — touch sidecar's last-referenced
            // timestamp so prune sees a fresh root.
            let mut existing = LinkMeta::read_from(&final_dir)?;
            existing.touch();
            existing.write_to(&final_dir)?;
            return Ok(LinkEntry {
                link_dir: final_dir,
                freshly_populated: false,
                sidecar: existing,
            });
        }

        if let Some(parent) = final_dir.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| LpmError::Store(format!("failed to create v2 links dir: {e}")))?;
        }

        let tmp_dir = tmp_sibling(&final_dir);
        if tmp_dir.exists() {
            let _ = std::fs::remove_dir_all(&tmp_dir);
        }

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
                sidecar,
            }),
            Err(_) if is_complete_link_entry(&final_dir) => {
                // Concurrent install beat us — discard our stage and
                // refresh the existing sidecar's last-referenced time.
                let _ = std::fs::remove_dir_all(&tmp_dir);
                let mut existing = LinkMeta::read_from(&final_dir)?;
                existing.touch();
                existing.write_to(&final_dir)?;
                Ok(LinkEntry {
                    link_dir: final_dir,
                    freshly_populated: false,
                    sidecar: existing,
                })
            }
            Err(e) => {
                let _ = std::fs::remove_dir_all(&tmp_dir);
                Err(LpmError::Store(format!(
                    "failed to atomically install v2 link entry: {e}"
                )))
            }
        }
    }
}

fn populate_into(
    tmp_dir: &Path,
    graph_key: &GraphKey,
    object_dir: &Path,
    deps: &[DepLink],
    source_sri: &str,
    sidecar_relpath: &str,
    platform: &LinkMetaPlatform,
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
    // existing isolated linker contract (preplan §2.3).
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
        platform.clone(),
    );
    sidecar.write_to(tmp_dir)?;

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
    // segment in the local name. Preplan §2.3 fixes this shape as
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

fn is_complete_link_entry(dir: &Path) -> bool {
    if !dir.is_dir() {
        return false;
    }
    let sidecar = dir.join(crate::v2::link_meta::LINK_META_FILENAME);
    sidecar.is_file()
}

fn tmp_sibling(dir: &Path) -> PathBuf {
    let pid = std::process::id();
    let tid = format!("{:?}", std::thread::current().id());
    dir.with_extension(format!("tmp.{pid}.{tid}"))
}

#[cfg(unix)]
fn create_dir_symlink(target: &Path, link: &Path) -> std::io::Result<()> {
    std::os::unix::fs::symlink(target, link)
}

#[cfg(windows)]
fn create_dir_symlink(target: &Path, link: &Path) -> std::io::Result<()> {
    // Windows requires distinguishing file vs dir symlinks. Sibling
    // entries always point at directory targets in v2.
    std::os::windows::fs::symlink_dir(target, link)
}

/// Materialize `src/` into `dst/` using the fastest available primitive.
///
/// Order: macOS clonefile → hardlink fallback (file-by-file) → copy
/// fallback. Mirrors `lpm-linker::link_dir_recursive`'s policy so the
/// v2 store inherits the same CoW-on-APFS performance characteristics
/// today's v1 wrappers already have. Lives here (rather than being
/// shared via lpm-common) to keep Phase 4a's blast radius confined to
/// lpm-store; later phases can dedupe.
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
    use crate::v2::graph_key::{GraphKeyInputs, LinkerModeTag};
    use crate::v2::link_meta::LinkMetaPlatform;
    use crate::v2::platform::PlatformTuple;

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

        let key = sample_key("a", "1.0.0");
        let entry = store
            .populate_link_entry(LinkEntryRequest {
                graph_key: key.clone(),
                source_sri: sri.clone(),
                object_dir,
                deps: vec![],
                platform: sample_meta_platform(),
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
        let key = sample_key("b", "2.0.0");
        let req = || LinkEntryRequest {
            graph_key: key.clone(),
            source_sri: sri.clone(),
            object_dir: object_dir.clone(),
            deps: vec![],
            platform: sample_meta_platform(),
        };

        let first = store.populate_link_entry(req()).unwrap();
        assert!(first.freshly_populated);

        // Sleep enough that chrono's UTC nanosecond clock advances.
        std::thread::sleep(std::time::Duration::from_millis(2));

        let second = store.populate_link_entry(req()).unwrap();
        assert!(!second.freshly_populated);
        assert_eq!(second.link_dir, first.link_dir);
        assert!(second.sidecar.last_referenced_at >= first.sidecar.last_referenced_at);
        assert!(second.sidecar.created_at == first.sidecar.created_at);
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

        let pkg_key = sample_key("express", "4.21.0");
        let dep_key = sample_key("debug", "4.3.4");

        // Materialize the dep first so its link dir exists for the
        // symlink target. (Phase 4a doesn't enforce ordering — caller's
        // responsibility — but we exercise the realistic path.)
        store
            .populate_link_entry(LinkEntryRequest {
                graph_key: dep_key.clone(),
                source_sri: dep_sri.clone(),
                object_dir: store.paths().object_dir(&dep_sri).unwrap(),
                deps: vec![],
                platform: sample_meta_platform(),
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
                platform: sample_meta_platform(),
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
        assert_eq!(entry.sidecar.deps.len(), 1);
        assert_eq!(entry.sidecar.deps[0].local, "debug");
        assert_eq!(entry.sidecar.deps[0].target_graph_key, dep_key.digest_hex());
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

        let pkg_key = sample_key("consumer", "1.0.0");
        let dep_key = sample_key("@types/node", "20.10.0");

        store
            .populate_link_entry(LinkEntryRequest {
                graph_key: dep_key.clone(),
                source_sri: dep_sri.clone(),
                object_dir: store.paths().object_dir(&dep_sri).unwrap(),
                deps: vec![],
                platform: sample_meta_platform(),
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
                platform: sample_meta_platform(),
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
        let key = sample_key("missing", "0.0.1");

        let err = store
            .populate_link_entry(LinkEntryRequest {
                graph_key: key.clone(),
                source_sri: sri.clone(),
                object_dir: nonexistent_object,
                deps: vec![],
                platform: sample_meta_platform(),
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
}
