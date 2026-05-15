//! node_modules layout manager for LPM.
//!
//! Creates pnpm-style isolated node_modules with symlinks:
//!
//! ```text
//! <project>/
//!   .lpm/
//!     wrappers/                                ← internal store
//!       express@4.22.1/
//!         .linked                              ← stamp marker (incremental cache)
//!         node_modules/
//!           express/  → <global-store>         ← hardlink/copy from store
//!           debug/    → ../../debug@2.6.9/node_modules/debug
//!           send/     → ../../send@0.19.2/node_modules/send
//!       debug@2.6.9/
//!         node_modules/
//!           debug/    → <global-store>
//!           ms/       → ../../ms@2.0.0/node_modules/ms
//!       .version                               ← layout schema version
//!   node_modules/
//!     express/ → ../.lpm/wrappers/express@4.22.1/node_modules/express  ← direct dep
//!     .bin/
//!       <cmd> → ../../.lpm/wrappers/<seg>/node_modules/<pkg>/<bin-script>
//! ```
//!
//! Properties:
//! - Only direct dependencies appear in root `node_modules/` as symlinks
//! - All wrappers live in `<project>/.lpm/wrappers/` (a project-root sibling)
//! - Strict isolation: phantom dependencies are not importable
//!
//! Relocation: wrappers used to live under `node_modules/.lpm/`,
//! which meant `rm -rf node_modules` wiped the entire incremental cache.
//! Moving them out of `node_modules` makes the warm-install path actually
//! incremental.
//!
//! Compatibility: hoisted mode supported as opt-in via `LPM_LINKER=hoisted`
//! (npm v3+ flat layout, ~25% faster on full-wipe workloads, stricter peer-dep
//! semantics); Windows junctions provide admin-free symlink fallback (not in CI);
//! self-reference works in both modes.
//! Performance: incremental linking via `.linked` marker files, `--force` bypasses markers.

use lpm_common::LpmError;
use rayon::prelude::*;
use std::collections::{BTreeMap, HashMap};
use std::path::{Component, Path, PathBuf};

pub mod layout;
pub use layout::{InstallHealth, LayoutPaths, LinkerLayout};

// Virtual-store-aware linker. Selected when
// `LPM_STORE_VERSION=v2`; sits next to the v1 isolated/hoisted code
// paths in this crate. See `src/v2.rs` for the design doc.
pub mod v2;

/// Per-package link outcome — exposes Stage 1 action + Stage 2
/// symlink count to the event-driven caller so totals match the
/// single-shot [`link_packages`] path.
#[derive(Debug, Default, Clone, Copy)]
pub struct OnePackageResult {
    /// `true` if Stage 1 freshly linked the package; `false` if the
    /// incremental `.linked` marker caused a skip.
    pub linked: bool,
    /// Stage 2 internal-symlink count for this package (one per entry in
    /// the package's `dependencies` that wasn't already symlinked).
    pub symlinks_created: usize,
}

/// Final-stage result — Stage 3 root symlinks + Stage 3.5
/// self-reference + Stage 4 `.bin` creation, aggregated into the tail
/// end of the `LinkResult` that [`link_packages`] returns.
#[derive(Debug, Default)]
pub struct FinalizeResult {
    /// Stage 3 + 3.5 symlink count (direct-dep root symlinks + optional
    /// self-reference).
    pub symlinks_created: usize,
    /// Stage 4 `.bin` entries created.
    pub bin_count: usize,
    /// `true` iff the self-reference symlink at `node_modules/<self>`
    /// was created on this call.
    pub self_referenced: bool,
}

/// Validate a self-reference package name to prevent path traversal.
///
/// Returns `true` if the name is safe to use as a directory name under `node_modules/`.
fn is_valid_self_ref_name(name: &str) -> bool {
    !name.is_empty()
        && !name.contains("..")
        && !name.contains('\\')
        && !name.starts_with('/')
        && !name.contains('\0')
}

/// System binaries that packages should not shadow without warning.
const SHADOWED_BINARIES: &[&str] = &[
    "node", "npm", "npx", "sh", "bash", "zsh", "fish", "git", "curl", "wget", "sudo", "python",
    "python3", "ruby", "perl", "env", "cat", "ls", "rm", "cp", "mv", "mkdir", "chmod",
];

/// Validate a bin entry name. Returns `Ok(())` if the name is acceptable,
/// `Err(reason)` if it must be rejected entirely.
/// Logs a warning (but does not reject) for names that shadow common system binaries.
///
/// Public so user-supplied alias names (`--alias orig=alias`) can
/// reuse the same safety bar — every path on PATH should meet the
/// same sanity check regardless of whether it came from
/// `package.json` or a CLI flag.
pub fn validate_bin_name(name: &str, pkg_name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("bin name is empty".to_string());
    }
    if name.contains('\0') {
        return Err("bin name contains null byte".to_string());
    }
    if name.contains('/') || name.contains('\\') || name.contains("..") {
        return Err(format!(
            "bin name \"{name}\" contains path separators or traversal components"
        ));
    }

    // Warn (don't reject) for shadowing common system binaries
    if SHADOWED_BINARIES.contains(&name) {
        tracing::warn!(
            "package \"{pkg_name}\" declares bin \"{name}\" which shadows a common system binary"
        );
    }

    Ok(())
}

/// Validate that a bin script path does not escape its package directory via path traversal.
/// Returns `Ok(canonical_target)` with the validated canonical path, or `Err(reason)`.
fn validate_bin_target(pkg_dir: &Path, script_path: &str) -> Result<PathBuf, String> {
    // Quick reject: script_path must not contain `..` components
    let joined = pkg_dir.join(script_path);
    for component in joined.components() {
        if component == Component::ParentDir {
            return Err(format!(
                "bin target \"{script_path}\" contains path traversal (\"..\")"
            ));
        }
    }

    // Canonicalize and verify containment (the target file must exist for canonicalize)
    let canonical_target = joined
        .canonicalize()
        .map_err(|e| format!("cannot resolve bin target \"{script_path}\": {e}"))?;
    let canonical_pkg = pkg_dir
        .canonicalize()
        .map_err(|e| format!("cannot resolve package dir: {e}"))?;

    if !canonical_target.starts_with(&canonical_pkg) {
        return Err(format!(
            "bin target \"{}\" resolves outside package directory \"{}\"",
            canonical_target.display(),
            canonical_pkg.display()
        ));
    }

    Ok(canonical_target)
}

#[cfg(unix)]
fn relative_symlink_target_from_parent(target: &Path, link_parent: &Path) -> PathBuf {
    let link_parent_canonical = link_parent
        .canonicalize()
        .unwrap_or_else(|_| link_parent.to_path_buf());
    pathdiff::diff_paths(target, &link_parent_canonical).unwrap_or_else(|| target.to_path_buf())
}

// Follow-up: cmd-path validation moved to
// `lpm_common::symlink` so lpm-store v2 shares the same security check
// (was duplicated). Re-imported under the legacy local name to keep
// the surrounding call sites untouched.
#[cfg(windows)]
use lpm_common::symlink::validate_cmd_path;

/// Linking strategy for node_modules.
///
/// **Default flipped to [`Hoisted`] in **
/// (post-virtual-store-ship). pre- the default was
/// [`Isolated`] — the strict pnpm-style layout — but its everyday
/// dev workflow (`rm -rf node_modules` → `lpm install`) under v1
/// required clonefiling all bytes back from `~/.lpm/store/v1/`,
/// which made hoisted 2.7× slower than isolated on warm install
/// and would have made the flip user-hostile despite hoisted's
/// 1.3× cold-install win.
///
/// 's virtual store ([`lpm_store::v2`]) restructured both
/// modes to symlink project `node_modules/<dep>` into a global
/// `~/.lpm/store/v2/links/<graph-key>/` materialization. After 4d
/// the default `LPM_STORE_VERSION=v2` made warm-install identical
/// between modes (Stage 4 (post-flip) bench: isolated median 110 ms, hoisted
/// median 110 ms, paired delta +0 ms). Flipping the default to
/// `Hoisted` gives users:
///
/// - Cold-install win — hoisted is ~497 ms faster than isolated
///   on `bench/fixture-large` cold/full.
/// - Same warm-install (post-v2 — see above).
/// - Phantom-dep accessibility for tooling that relied on
///   npm-style flat node_modules (most ecosystem projects).
///
/// [`Isolated`] remains a valid opt-in via `LPM_LINKER=isolated`,
/// `package.json > lpm > linker`, `~/.lpm/config.toml > linker`,
/// or `--linker isolated`. Use it when you want strict
/// no-phantom-deps semantics — the layout that catches "I forgot
/// to declare this dep" bugs early.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub enum LinkerMode {
    /// pnpm-style isolated layout. Strict, no phantom deps.
    /// Available via explicit `--linker isolated` /
    /// `LPM_LINKER=isolated` / `package.json > lpm > linker`.
    Isolated,
    /// npm v3+ style hoisted layout. Flat, phantom deps accessible. Default.
    #[default]
    Hoisted,
}

impl LinkerMode {
    /// Accepted string values across every config surface: the `--linker`
    /// CLI flag (clamped at parse time by clap), `package.json > lpm > linker`,
    /// `~/.lpm/config.toml > linker`, and the `LPM_LINKER` env var.
    pub const ACCEPTED_VALUES: &'static [&'static str] = &["isolated", "hoisted"];

    /// Parse a linker mode string from any non-CLI config surface
    /// (`package.json`, `config.toml`, env). Unknown values produce a
    /// human-readable error so the install entry point can surface them
    /// loudly before any work begins. The CLI surface is parsed by clap
    /// directly via the `LinkerCli` value-enum and never reaches this
    /// function as a free string.
    pub fn parse_str(s: &str) -> Result<Self, String> {
        match s {
            "isolated" => Ok(Self::Isolated),
            "hoisted" => Ok(Self::Hoisted),
            other => Err(format!(
                "unknown linker mode {other:?}. Accepted values: {accepted}.",
                accepted = Self::ACCEPTED_VALUES
                    .iter()
                    .map(|v| format!("{v:?}"))
                    .collect::<Vec<_>>()
                    .join(", "),
            )),
        }
    }

    /// Stable string representation that round-trips through `parse_str`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Isolated => "isolated",
            Self::Hoisted => "hoisted",
        }
    }
}

#[cfg(test)]
mod linker_mode_tests {
    use super::LinkerMode;

    #[test]
    fn parse_str_accepts_canonical_values() {
        assert_eq!(
            LinkerMode::parse_str("isolated").unwrap(),
            LinkerMode::Isolated
        );
        assert_eq!(
            LinkerMode::parse_str("hoisted").unwrap(),
            LinkerMode::Hoisted
        );
    }

    #[test]
    fn parse_str_rejects_legacy_symlink_alias() {
        // "symlink" was documented as a legacy alias on the package.json
        // schema but never recognized by the install dispatch — typing it
        // silently fell back to Isolated. The new contract is fail-loud.
        let err = LinkerMode::parse_str("symlink").unwrap_err();
        assert!(err.contains("unknown linker mode"));
        assert!(err.contains("\"isolated\""));
        assert!(err.contains("\"hoisted\""));
    }

    #[test]
    fn parse_str_rejects_typos_loudly() {
        for bad in ["hosited", "Isolated", "HOISTED", "", " hoisted ", "default"] {
            let err = LinkerMode::parse_str(bad).unwrap_err();
            assert!(
                err.contains("unknown linker mode"),
                "value {bad:?} should reject"
            );
        }
    }

    #[test]
    fn as_str_round_trips() {
        for mode in [LinkerMode::Isolated, LinkerMode::Hoisted] {
            assert_eq!(LinkerMode::parse_str(mode.as_str()).unwrap(), mode);
        }
    }
}

/// Create a symlink (Unix) or junction (Windows) from `link` pointing to `target`.
///
/// On Windows, NTFS junctions don't require admin privileges (unlike symlinks).
/// We use `cmd /c mklink /J` which handles junction creation natively.
/// Junctions require absolute paths, so we resolve relative targets before creating.
/// Falls back to `symlink_dir` if junction creation fails.
///
// Follow-up: directory-link creation moved to
// `lpm_common::symlink::create_dir_symlink_or_junction` so lpm-store
// v2 shares the same Windows symlink-then-junction fallback (`mklink
// /J`) — duplicating it would have left v2 regressing on Windows
// setups without Developer Mode. Re-imported under the legacy local
// name to keep call sites untouched.
use lpm_common::symlink::create_dir_symlink_or_junction as create_symlink_or_junction;

/// Drives the materialization branch in [`link_one_package`].
///
/// Decoupled from [`LinkTarget::wrapper_id`] so tarball sources can
/// carry a wrapper_id (for collision-free `.lpm/<safe>+<wrapper_id>/`
/// segments) WITHOUT inheriting the directory-source per-file-symlink
/// materialization. Using `wrapper_id.is_some()` as the proxy stopped
/// working once Tarball started using it for cross-source collision
/// avoidance — these two concerns need separate fields.
///
/// The default ([`Materialization::CasBacked`]) matches the legacy
/// behavior for every CAS-backed source (Registry, Tarball remote,
/// Tarball local, Git): clonefile / hardlink / copy from
/// [`LinkTarget::store_path`] (which lives inside the global CAS
/// store).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Materialization {
    /// CAS-backed: [`link_dir_recursive`] copies the package tree
    /// from the global store into the wrapper. Used for Registry,
    /// Tarball (remote + local), and Git sources.
    #[default]
    CasBacked,
    /// Local-source directory: [`materialize_directory_source`]
    /// builds the wrapper as per-file absolute symlinks pointing at
    /// `store_path` (the source's realpath, OUTSIDE the global
    /// store). Used for `Source::Directory` (`file:`) and
    /// `Source::Link` (`link:`). Edits to the source are visible
    /// through the wrapper without re-running `lpm install`.
    DirectorySource,
}

/// A package to be linked into node_modules.
#[derive(Debug, Clone)]
pub struct LinkTarget {
    /// Canonical registry package name (e.g., "express", "@types/node").
    /// Used as the `.lpm/<name>@<version>/node_modules/<name>/` key and
    /// the default root-symlink filename for non-aliased direct deps.
    pub name: String,
    /// Exact version string.
    pub version: String,
    /// Path to the package in the global store.
    pub store_path: PathBuf,
    /// Dependencies of this package: `(local_name_in_this_package, dep_version)`.
    ///
    /// The local name is what appears as `node_modules/<local>/` inside
    /// THIS package's `.lpm/<self>@<ver>/node_modules/`. For regular
    /// deps the local name equals the child's canonical registry name.
    /// For npm-alias edges, it is the alias key from this
    /// package's `package.json` (e.g., `strip-ansi-cjs`), and
    /// [`Self::aliases`] records the canonical registry name so the
    /// linker can resolve the symlink target to `<target>@<ver>`.
    pub dependencies: Vec<(String, String)>,
    /// npm-alias edges: `local_name → target_canonical_name`.
    /// Populated only for local names that refer to a different
    /// registry-canonical target than themselves (the common case is
    /// empty). Lookup rule: `aliases.get(local).unwrap_or(local)`
    /// produces the target used for the store path.
    pub aliases: HashMap<String, String>,
    /// Whether this is a direct dependency of the root project.
    ///
    /// Used for lifecycle-script filtering and display purposes. For
    /// Stage 3 root-symlink creation, the linker consults
    /// [`Self::root_link_names`] instead — that field expresses the
    /// alias-aware "what filenames do I get at the project root"
    /// contract, including the (rare) case of a single package
    /// referenced by its canonical name AND by one or more aliases at
    /// the same version.
    pub is_direct: bool,
    /// Explicit list of `node_modules/<entry>/`
    /// symlinks to create at the project root for this package.
    ///
    /// Callers may leave this `None` to get the default pre-P2
    /// behavior: Stage 3 creates a single `node_modules/<name>/`
    /// symlink when `is_direct` is true, nothing otherwise. Callers
    /// that have alias info from the resolver set this to
    /// `Some(vec![...])`:
    ///
    /// - `Some([pkg.name])`: regular direct dep (equivalent to the
    ///   default, but explicit).
    /// - `Some([local])` where `local != pkg.name`: aliased root dep —
    ///   the consumer declared `"local": "npm:<pkg.name>@<range>"`.
    ///   Stage 3 creates `node_modules/<local>/` with the target set to
    ///   `.lpm/<pkg.name>@<version>/node_modules/<pkg.name>/`.
    /// - `Some([name, alias1, ...])`: the same resolved `(name,
    ///   version)` is referenced from the root under multiple names
    ///   (canonical plus one or more aliases). One symlink per entry.
    /// - `Some([])`: never a root dep, no root symlink. Distinguishes
    ///   "explicitly zero" from "use the default."
    ///
    /// When `Some`, the `is_direct` flag is ignored for Stage 3
    /// purposes; `is_direct` is still consulted elsewhere (lifecycle
    /// filtering, display). When `None`, Stage 3 falls back to the
    /// `is_direct ? [name] : []` default.
    pub root_link_names: Option<Vec<String>>,
    /// When `Some`, the `.lpm/` wrapper segment is
    /// `<safe_name>+<wrapper_id>` instead of `<safe_name>@<version>`.
    /// Used for any source whose `(name, version)` could collide
    /// with another source kind — every NON-Registry source.
    /// Required so `Source::Registry { foo@1.0.0 }` and
    /// `Source::Tarball { foo@1.0.0 from custom URL }` stay distinct
    /// in the wrapper tree.
    ///
    /// Materialization strategy is controlled by the orthogonal
    /// [`LinkTarget::materialization`] field, NOT
    /// `wrapper_id.is_some()`.
    ///
    /// The `+` separator visually distinguishes wrapped sources from
    /// unwrapped (Registry-only) deps in the `.lpm/` tree. Node
    /// module resolution from inside the wrapped package walks
    /// ancestors that stay inside the consumer's `node_modules/`
    /// tree, so transitive deps resolve correctly (which a direct
    /// `node_modules/<name>` symlink at the source realpath would
    /// NOT achieve).
    ///
    /// `None` for `Source::Registry` only — registry deps are
    /// keyed by `(name, version)` alone (no cross-source collision
    /// risk because no other source kind shares the registry
    /// namespace).
    ///
    /// `wrapper_id` is opaque to the linker — typically the source's
    /// `lpm_lockfile::Source::source_id()` output (e.g., `"f-{16hex}"`
    /// for Directory, `"l-{16hex}"` for Link, `"t-{16hex}"` for
    /// Tarball). The linker accepts whatever the caller supplies;
    /// correctness depends on the caller producing a stable,
    /// collision-free identifier per `(name, version)` group.
    pub wrapper_id: Option<String>,
    /// Drives the materialization branch in [`link_one_package`].
    /// See [`Materialization`] for the full contract.
    ///
    /// Defaults to [`Materialization::CasBacked`] — every source kind
    /// EXCEPT `Source::Directory` and `Source::Link` materializes
    /// from the global CAS store via [`link_dir_recursive`].
    pub materialization: Materialization,
    /// Resolved peers in scope for this package's instance in the
    /// install graph.
    ///
    /// Shape: `(peer_name, resolved_version)`, sorted by peer_name.
    /// Empty under any of:
    /// - The package declares no peers in its `package.json`.
    /// - All declared peers are absent from the install set
    ///   (`check_unmet_peers` surfaces those upstream).
    /// - The lockfile fast-path constructed this LinkTarget (peers
    ///   not persisted in the lockfile today; v2 linker re-derives
    ///   from the extracted `package.json` when needed).
    ///
    /// **Used by the v2 isolated linker** to:
    /// 1. Synthesize peer-edge sibling symlinks inside each link
    ///    entry (peer must be a sibling of the consumer's package
    ///    dir for Node's symlink-walk-up resolution).
    /// 2. Fold into [`lpm_store::v2::GraphKeyInputs::with_peers`] so
    ///    two projects with the same edge graph but different peer
    ///    pinning produce distinct graph keys (the cross-project
    ///    cross-project sharing invariant).
    ///
    /// **Ignored under v1** — v1's relative-symlink wrappers walk
    /// up to the project root for peers, so threading is
    /// informational. The field is populated regardless so a future
    /// hoisted-mode v1 wanting to share wrappers across projects
    /// can fold it in.
    pub peers: Vec<(String, String)>,
    /// Patch identity, plumbed through to v2's
    /// [`GraphKeyInputs::patch_fingerprint`].
    ///
    /// `Some("p-<16hex>")` when the install pipeline detected a
    /// `lpm.patchedDependencies` entry covering this `(name, version)`,
    /// `None` otherwise. The 16-hex suffix is the first 16 chars of
    /// `sha256(patch_bytes || originalIntegrity)` — content-derived so
    /// (a) two projects applying byte-identical patches share a single
    /// link entry, and (b) any edit to the patch text or to the pinned
    /// baseline integrity splits into a fresh entry.
    ///
    /// **Ignored under v1.** v1 wrappers live at `<project>/.lpm/<seg>/`,
    /// already project-private, so cross-project mutation isn't a
    /// concern there. The field is populated regardless so a future
    /// shared-v1-wrapper variant can fold it in without revisiting the
    /// install pipeline plumbing.
    pub patch_fingerprint: Option<String>,
}

impl LinkTarget {
    /// The `.lpm/<segment>/` directory name
    /// for this target.
    ///
    /// - `<safe_name>+<wrapper_id>` for non-Registry deps. Visually
    ///   distinct from the CAS shape so `lpm doctor`
    ///   / `lpm why` output is parseable at a glance.
    /// - `<safe_name>@<version>` for CAS-backed deps (the legacy
    ///   shape — Registry + Tarball remote + Tarball local all use
    ///   this).
    ///
    /// Used by [`link_one_package`], [`link_finalize`], and
    /// [`cleanup_stale_entries`] so the wrapper-segment shape is
    /// computed in one place.
    ///
    /// Delegates to [`LayoutPaths::wrapper_segment`] (the cross-crate
    /// source of truth) so non-linker consumers (`lpm rebuild`,
    /// `lpm doctor`, etc.) cannot accidentally compute a different
    /// shape from the same `(name, version, wrapper_id)` inputs.
    pub fn wrapper_segment(&self) -> String {
        LayoutPaths::wrapper_segment(&self.name, &self.version, self.wrapper_id.as_deref())
    }
}

/// Create the pnpm-style node_modules layout.
///
/// # Arguments
/// * `project_dir` - The project root (where node_modules/ will be created)
/// * `packages` - All resolved packages with their store paths and dependencies
/// * `force` - When true, ignore `.linked` marker files and re-link everything
/// * `self_package_name` - If set, creates a self-referencing symlink so the package
///   can `require("itself")`. This is a node_modules/<name> → project_dir symlink.
///   Skipped if a direct dependency already occupies that name.
pub fn link_packages(
    project_dir: &Path,
    packages: &[LinkTarget],
    force: bool,
    self_package_name: Option<&str>,
) -> Result<LinkResult, LpmError> {
    // `link_packages` is now a thin composition over three
    // smaller helpers so the event-driven install path can run them
    // independently (stale cleanup up front, per-pkg link as each tarball
    // lands, finalize once everything is materialized). The single-shot
    // path still calls them serially so existing callers are unaffected.
    cleanup_stale_entries(project_dir, packages)?;

    // Stage 1 + Stage 2 per package, in a parallel pass. `link_one_package`
    // is the same helper the event-driven path invokes on each fetch
    // completion — byte-identical work, just scheduled differently.
    let per_pkg: Vec<(MaterializedPackage, OnePackageResult)> = packages
        .par_iter()
        .map(|pkg| link_one_package(project_dir, pkg, force))
        .collect::<Result<Vec<_>, LpmError>>()?;

    let mut linked_count = 0;
    let mut skipped_count = 0;
    let mut symlinked_count = 0;
    let mut materialized: Vec<MaterializedPackage> = Vec::with_capacity(per_pkg.len());
    for (m, r) in per_pkg {
        materialized.push(m);
        if r.linked {
            linked_count += 1;
        } else {
            skipped_count += 1;
        }
        symlinked_count += r.symlinks_created;
    }

    let finalize = link_finalize(project_dir, packages, self_package_name)?;
    symlinked_count += finalize.symlinks_created;

    Ok(LinkResult {
        linked: linked_count,
        symlinked: symlinked_count,
        bin_linked: finalize.bin_count,
        skipped: skipped_count,
        self_referenced: finalize.self_referenced,
        materialized,
    })
}

/// Identity stamp written to the wrapper's `.linked` marker.
///
/// On subsequent installs, [`link_one_package`] reads the stamp and
/// compares it against the new target — if they don't match (or the
/// marker is empty / from a pre-stamp build), the wrapper is treated
/// as stale and re-materialized.
///
/// **Why the stamp encodes dep edges.** An empty marker — "a
/// previous install completed here" — lets a stale tarball wrapper
/// at `.lpm/foo@1.0.0/` survive a subsequent install of registry
/// `foo@1.0.0` (same segment, cleanup preserves it, fast path
/// skips relinking, stale tarball bytes masquerade as the registry
/// package). Stamping `wrapper_id` + `materialization` +
/// `store_path` alone is also insufficient: two installs with the
/// same `store_path` but different `target.dependencies` produce
/// identical stamps, so the "skip if exists" dep loop preserves
/// stale sibling symlinks. Folding `dependencies` and `aliases`
/// into the stamp means any change to the wrapper's internal edge
/// set forces a relink; the stamp-mismatch path then wipes the
/// wrapper's `pkg_entry_dir` before re-materializing, cleaning
/// stale edges alongside the stale package bytes.
///
/// **Format v2** (newline-separated header + key=value lines):
/// ```text
/// lpm-link-stamp v2
/// wrapper_id=<id-or-empty>
/// materialization=<cas|dir>
/// store_path=<abs path>
/// deps=<sorted name@version, comma-sep, empty when none>
/// aliases=<sorted local→canonical, comma-sep, empty when none>
/// ```
///
/// Header version is bumped if the schema changes; readers MUST
/// reject unknown versions and force a relink. Empty, unparseable,
/// or older-schema markers are treated identically to a mismatch.
fn compute_link_stamp(target: &LinkTarget) -> String {
    let materialization = match target.materialization {
        Materialization::CasBacked => "cas",
        Materialization::DirectorySource => "dir",
    };
    let wrapper_id = target.wrapper_id.as_deref().unwrap_or("");
    let store_path = target.store_path.to_string_lossy();

    // Sort the dep + alias lists so the stamp is deterministic
    // regardless of `target.dependencies` / `target.aliases` iteration
    // order (Vec preserves insertion order; the resolver doesn't
    // guarantee a stable order across runs).
    let mut deps_sorted: Vec<&(String, String)> = target.dependencies.iter().collect();
    deps_sorted.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
    let deps_str = deps_sorted
        .iter()
        .map(|(n, v)| format!("{n}@{v}"))
        .collect::<Vec<_>>()
        .join(",");

    let mut aliases_sorted: Vec<(&String, &String)> = target.aliases.iter().collect();
    aliases_sorted.sort_by(|a, b| a.0.cmp(b.0));
    let aliases_str = aliases_sorted
        .iter()
        .map(|(local, canonical)| format!("{local}→{canonical}"))
        .collect::<Vec<_>>()
        .join(",");

    format!(
        "lpm-link-stamp v2\nwrapper_id={wrapper_id}\nmaterialization={materialization}\nstore_path={store_path}\ndeps={deps_str}\naliases={aliases_str}\n",
    )
}

/// Read the on-disk stamp at `marker_path` and compare it to the
/// stamp the new target would write.
///
/// Returns `true` only if the on-disk stamp matches the v2 stamp
/// `compute_link_stamp` would produce for the new target — every
/// field must agree. Empty markers (legacy, pre-round-3), v1
/// stamps (round-3 era — round-5 schema bump invalidates them so
/// upgrades force a one-time relink that captures the new dep edge
/// set), unparseable bytes, or unknown versions all produce `false`
/// so the caller force-relinks.
fn link_stamp_matches(marker_path: &Path, target: &LinkTarget) -> bool {
    let Ok(on_disk) = std::fs::read_to_string(marker_path) else {
        return false;
    };
    on_disk == compute_link_stamp(target)
}

/// Stale-entry cleanup — removes `.lpm/<pkg>@<ver>`
/// directories and root `node_modules/<pkg>` symlinks that are no longer
/// in the resolver's output. Must run BEFORE any per-package linking so
/// its `read_dir` scans see a stable snapshot; calling it more than once
/// per install is safe but wasteful.
///
/// Also creates the wrapper root if it doesn't exist (the path is
/// resolved through [`LayoutPaths`] so a future relayout flips
/// the location automatically).
///
/// Writes `<wrapper-root>/.version` recording the
/// layout schema version (`1`). A future shape change can detect
/// old wrappers via this file and trigger a clean wipe-and-rebuild
/// without ambiguity.
pub fn cleanup_stale_entries(project_dir: &Path, packages: &[LinkTarget]) -> Result<(), LpmError> {
    let layout = LayoutPaths::for_project(project_dir);
    let node_modules = project_dir.join("node_modules");
    let lpm_dir = layout.isolated_wrapper_root();

    // Pre- a single `create_dir_all` covered both
    // `node_modules/` and the wrapper root (the wrapper root WAS
    // `node_modules/.lpm/`, so creating it implied creating its
    // parent). They're now disjoint paths, so each gets its
    // own create.
    std::fs::create_dir_all(&node_modules)?;
    std::fs::create_dir_all(&lpm_dir)?;

    // D6: layout schema version. Written best-effort — if the write
    // fails (read-only FS, permissions), the install still proceeds;
    // the file is purely a forward-compat tag.
    let version_path = layout.isolated_layout_version_path();
    if !version_path.exists() {
        let _ = std::fs::write(&version_path, b"1\n");
    }
    // Note: pruning of stale hoisted state at `<project>/.lpm/hoisted/`
    // is deferred to [`link_finalize`] so a failed isolated install
    // doesn't strand the user with neither layout's state present.
    // See the audit response in the hoisted-symmetry follow-up.

    // Incremental: collect expected entries so we can clean up stale ones.
    //
    // The wrapper-segment shape is centralized
    // in [`LinkTarget::wrapper_segment`] so this set covers both
    // `<safe>@<version>` (CAS-backed) and `<safe>+<wrapper_id>`
    // (local-source) shapes uniformly.
    let expected_entries: std::collections::HashSet<String> =
        packages.iter().map(|p| p.wrapper_segment()).collect();

    // Clean up stale wrapper entries that are no longer in the resolution.
    //
    // Skip the `.version` schema-tag file at the wrapper-
    // root — it's a sibling of the per-package wrapper directories,
    // not a stale wrapper. Any entry starting with `.` is a sibling
    // metadata file and gets the same skip; the wrapper-segment
    // sanitizer (`replace('/', '+')`) never produces a leading dot.
    if let Ok(entries) = std::fs::read_dir(&lpm_dir) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.starts_with('.') {
                continue;
            }
            if !expected_entries.contains(&name) {
                let _ = std::fs::remove_dir_all(entry.path());
                tracing::debug!("incremental: removed stale wrapper {name}");
            }
        }
    }

    // Also clean up stale root symlinks
    //
    // The "expected root link names" come from
    // `root_link_names` on each package, not `is_direct + pkg.name`.
    // That set already includes every alias the resolver decided to
    // plant at the root (e.g. `strip-ansi-cjs` as an alias for
    // `strip-ansi@6.0.1`), so aliased root entries survive the stale
    // sweep.
    //
    // Audit fix — also retarget legacy-shape root symlinks.
    // Pre-fix, an upgrade-in-place install whose 61.3 migration
    // wiped `node_modules/.lpm/` left dangling root symlinks at
    // `node_modules/<pkg>` whose targets pointed at the wiped legacy
    // location. Stage 3's `if root_link.exists` guard then skipped
    // recreation, so the user's `node_modules/<pkg>` stayed broken
    // (or — if the legacy tree was somehow restored — silently used
    // the wrong target). The fix: a symlink whose target points at
    // the legacy wrapper-root shape (`.lpm/<seg>/...` without the
    // `wrappers/` segment) is removed regardless of `direct_names`
    // membership, and Stage 3 recreates it with the correct new
    // target. Self-refs (target = `..`) and workspace-member
    // symlinks (target outside `.lpm/`) are unaffected — the
    // predicate requires `.lpm/` to be present.
    if let Ok(entries) = std::fs::read_dir(&node_modules) {
        let direct_names: std::collections::HashSet<String> = packages
            .iter()
            .flat_map(|p| match (&p.root_link_names, p.is_direct) {
                (Some(explicit), _) => explicit.to_vec(),
                (None, true) => vec![p.name.clone()],
                (None, false) => Vec::new(),
            })
            .collect();

        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name == ".lpm" || name.starts_with('.') {
                continue;
            }
            // For scoped packages, check the full path
            let full_name = if entry.path().is_dir() && name.starts_with('@') {
                // Check children of scope dir
                if let Ok(scope_entries) = std::fs::read_dir(entry.path()) {
                    for se in scope_entries.flatten() {
                        let se_path = se.path();
                        let scoped_name = format!("{name}/{}", se.file_name().to_string_lossy());
                        let is_symlink = se_path
                            .symlink_metadata()
                            .map(|m| m.file_type().is_symlink())
                            .unwrap_or(false);
                        if !is_symlink {
                            continue;
                        }
                        let stale = !direct_names.contains(scoped_name.as_str());
                        let legacy_shape = is_legacy_wrapper_symlink_target(&se_path);
                        if stale || legacy_shape {
                            let _ = std::fs::remove_file(&se_path);
                            tracing::debug!(
                                "incremental: removed {} root symlink {scoped_name}",
                                if legacy_shape {
                                    "legacy-shape"
                                } else {
                                    "stale"
                                },
                            );
                        }
                    }
                }
                continue;
            } else {
                name.clone()
            };
            let entry_path = entry.path();
            let is_symlink = entry_path
                .symlink_metadata()
                .map(|m| m.file_type().is_symlink())
                .unwrap_or(false);
            if !is_symlink {
                continue;
            }
            let stale = !direct_names.contains(full_name.as_str());
            let legacy_shape = is_legacy_wrapper_symlink_target(&entry_path);
            if stale || legacy_shape {
                let _ = std::fs::remove_file(&entry_path);
                tracing::debug!(
                    "incremental: removed {} root symlink {full_name}",
                    if legacy_shape {
                        "legacy-shape"
                    } else {
                        "stale"
                    },
                );
            }
        }
    }

    // Hoisted→isolated convergence sweep.
    //
    // The existing root-symlink sweep above only operates on
    // entries that ARE symlinks, so a `node_modules/<pkg>/` real
    // directory left behind by a previous hoisted install is invisible
    // to it. Stage 3's `if root_link.exists` guard then refuses to
    // create the isolated root symlink, leaving direct dependencies
    // resolving through the stale hoisted bytes — a silent
    // mode-switch failure.
    //
    // Fix: walk `node_modules/` once more and remove any entry that
    // looks like a hoisted-shape package directory. Detection:
    //   * Real directory (skip symlinks — handled above).
    //   * Contains a `package.json` immediately inside (the marker of
    //     a hoisted package; mere `.bin/`, scope dirs, and arbitrary
    //     user content don't satisfy this).
    //   * Skip the LPM-owned siblings `.bin`, `.lpm`, `.cache`, etc.
    //     and dotfiles by leading-dot rule.
    //
    // Scope handling: a scope dir (`@types/`) is a real directory
    // without a `package.json`. We recurse into it and apply the
    // same rule per scoped child.
    if let Ok(entries) = std::fs::read_dir(&node_modules) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if name_str.starts_with('.') {
                continue;
            }
            let path = entry.path();
            let is_symlink = path
                .symlink_metadata()
                .map(|m| m.file_type().is_symlink())
                .unwrap_or(false);
            if is_symlink || !path.is_dir() {
                continue;
            }
            if name_str.starts_with('@') {
                // Scope dir — recurse one level.
                if let Ok(scope_entries) = std::fs::read_dir(&path) {
                    for se in scope_entries.flatten() {
                        let se_path = se.path();
                        let se_is_symlink = se_path
                            .symlink_metadata()
                            .map(|m| m.file_type().is_symlink())
                            .unwrap_or(false);
                        if se_is_symlink || !se_path.is_dir() {
                            continue;
                        }
                        if se_path.join("package.json").is_file() {
                            let _ = std::fs::remove_dir_all(&se_path);
                            tracing::debug!(
                                "incremental: removed stale hoisted dir @{}/{}",
                                name_str,
                                se.file_name().to_string_lossy()
                            );
                        }
                    }
                }
                continue;
            }
            if path.join("package.json").is_file() {
                let _ = std::fs::remove_dir_all(&path);
                tracing::debug!("incremental: removed stale hoisted dir {name_str}");
            }
        }
    }

    Ok(())
}

/// Return `true` iff the given path is a symlink whose target points
/// at the pre- wrapper-root shape (`.lpm/<seg>/...` without
/// the `wrappers/` segment).
///
/// Used by [`cleanup_stale_entries`] to retarget root symlinks left
/// behind by an upgrade-in-place install. The new-shape target
/// always traverses `.lpm/wrappers/`; the legacy shape traverses
/// `.lpm/<seg>` directly. Self-refs (target = `..`) and workspace-
/// member symlinks (target outside `.lpm/`) don't traverse `.lpm/`
/// at all and produce `false`.
///
/// Walks `Path::components()` so the predicate is robust to whether
/// the relative target starts with `.lpm/` directly (unscoped root
/// link) or with `../.lpm/` (scoped root link), and across separator
/// styles on Windows.
///
/// Read failures (the path isn't a symlink, or the target can't be
/// read) collapse to `false` — the caller already gates on
/// `is_symlink()` so the error case here is just defensive.
fn is_legacy_wrapper_symlink_target(link: &Path) -> bool {
    let Ok(target) = std::fs::read_link(link) else {
        return false;
    };
    let mut found_lpm = false;
    let mut found_wrappers_after_lpm = false;
    for component in target.components() {
        if let Component::Normal(seg) = component {
            if seg == ".lpm" {
                found_lpm = true;
            } else if found_lpm && seg == "wrappers" {
                found_wrappers_after_lpm = true;
            }
        }
    }
    found_lpm && !found_wrappers_after_lpm
}

/// Per-package link. Does Stage 1 (materialize
/// `.lpm/<pkg>/node_modules/<pkg>` from the store) + Stage 2 (internal
/// symlinks for this package's dependencies).
///
/// Safe to call concurrently for different packages — each call writes
/// to a unique `.lpm/<safe_name>@<version>` subtree. Stage 2 symlinks
/// target relative strings that don't require the destination package
/// to be materialized yet, so callers can pipeline per-package work
/// into the fetch pipeline.
///
/// Preconditions:
/// - The wrapper root exists (created by [`cleanup_stale_entries`];
///   path resolved via [`LayoutPaths::isolated_wrapper_root`]).
/// - `target.store_path` exists (the store directory for this package).
pub fn link_one_package(
    project_dir: &Path,
    target: &LinkTarget,
    force: bool,
) -> Result<(MaterializedPackage, OnePackageResult), LpmError> {
    let layout = LayoutPaths::for_project(project_dir);
    let safe_name = target.name.replace('/', "+");
    let wrapper_segment = target.wrapper_segment();
    let pkg_entry_dir = layout.isolated_wrapper_dir(&wrapper_segment);
    let marker_path = layout.isolated_marker_path(&wrapper_segment);
    let pkg_nm = pkg_entry_dir.join("node_modules").join(&target.name);

    // **.** Always record the canonical destination,
    // even on the marker-skip fast path — the package IS materialized
    // there from a prior install run, just not freshly relinked.
    let materialized = MaterializedPackage {
        name: target.name.clone(),
        version: target.version.clone(),
        destination: pkg_nm.clone(),
    };

    // Incremental: skip packages that already have a completed link marker
    // **with a stamp matching the new target's identity** (round-3 audit
    // response).
    //
    // NOTE: The .linked marker check is not atomic with the linking
    // operation. A local attacker with filesystem access could plant a
    // fake marker to prevent re-linking. However, local filesystem access
    // already implies full compromise (can modify node_modules directly),
    // so this is an accepted risk. The marker is a performance
    // optimization, not a security boundary.
    //
    // **Stamp identity check (round-3 audit).** Pre-round-3 the marker was
    // an empty sentinel and the fast path always skipped relinking when
    // it existed. That allowed a wrapper materialized from one source
    // kind (e.g., a pre-round-1 tarball at `.lpm/foo@1.0.0/`) to be
    // reused unchanged by a later install of a different source kind
    // sharing the same wrapper segment (e.g., post-round-1 registry
    // `foo@1.0.0` — same segment because Registry uses
    // `wrapper_id=None`). [`compute_link_stamp`] writes the new target's
    // identity at materialization time; [`link_stamp_matches`] compares
    // it on subsequent runs. Mismatch (or empty / legacy / unparseable
    // stamp) drops to the `force=true`-style remove-and-relink branch
    // below.
    //
    // **Round-7 audit response — single fs snapshot for branch
    // dispatch.** Pre-round-7 the cleanup gate read `marker_path.exists()`
    // and called `link_stamp_matches` twice each (once for `stamp_matches`,
    // once for `stamp_mismatch_relink`), then re-read `pkg_entry_dir.exists()`
    // and `pkg_nm.exists()` on every branch. Three independent reads of the
    // same fs state can desynchronize under concurrent installs (workspace
    // monorepos with parallel member installs being the realistic exposure):
    // a `.linked` deletion observed AFTER the stamp-match read but BEFORE
    // the wipe branch flipped `stamp_mismatch_relink` to false, skipping
    // the wipe and leaving a half-stale wrapper in place. We now snapshot
    // every fs predicate ONCE at function entry, then dispatch on locals.
    // Concurrent mutations after the snapshot still produce a consistent
    // outcome — the worst case is one extra relink on the next install,
    // never a leaked wrapper.
    let marker_present = marker_path.exists();
    let stamp_match = marker_present && link_stamp_matches(&marker_path, target);
    let pkg_entry_present = pkg_entry_dir.exists();
    let pkg_nm_present = pkg_nm.exists();

    if !force && marker_present && stamp_match {
        tracing::debug!("incremental: skipping {wrapper_segment} (marker present, stamp matches)");
        return Ok((
            materialized,
            OnePackageResult {
                linked: false,
                symlinks_created: 0,
            },
        ));
    }

    // Stamp mismatch (or `force`, or marker absent): clear any prior
    // materialization at `pkg_entry_dir` so the new contents land
    // cleanly. Pre-round-3 this branch only fired on `force` or
    // interrupted installs; round-3 added the stamp-mismatch trigger;
    // round-4 widened the wipe scope from `pkg_nm` to the full
    // `pkg_entry_dir`.
    //
    // **Round-4 audit response — wipe the wrapper, not just the pkg.**
    // The pre-round-4 code removed only `pkg_nm`
    // (`.lpm/<segment>/node_modules/<name>/`), leaving the SIBLING
    // `.lpm/<segment>/node_modules/<other>` symlinks (the wrapper's
    // dep edges) in place. The Stage 2 dep loop below skips any
    // `dep_link.exists()` entry to avoid clobbering valid symlinks,
    // so a stale dep edge from the previous LinkTarget would survive
    // a relink even when the new target's `dependencies` no longer
    // mentions it. The auditor reproduced this against a small
    // harness: target A creates a `leftpad` symlink, target B reuses
    // the same `foo@1.0.0` segment with no deps, leftpad survives.
    // Wiping the whole `pkg_entry_dir` (which includes
    // `node_modules/`, the marker, and any other per-wrapper state)
    // ensures the new materialization starts from a clean slate.
    let stamp_mismatch_relink = !force && marker_present && !stamp_match;
    let interrupted_link_recovery = !force && pkg_nm_present && !marker_present;
    if force && pkg_entry_present {
        let _ = std::fs::remove_dir_all(&pkg_entry_dir);
    } else if stamp_mismatch_relink && pkg_entry_present {
        tracing::debug!(
            "incremental: stamp mismatch for {wrapper_segment}; re-materializing from {}",
            target.store_path.display(),
        );
        let _ = std::fs::remove_dir_all(&pkg_entry_dir);
    } else if interrupted_link_recovery {
        // The package dir was created but the marker never landed.
        // Wipe the full wrapper (round-4) because Stage 2 may have
        // planted partial sibling symlinks.
        tracing::debug!("cleaning up interrupted link for {safe_name}");
        let _ = std::fs::remove_dir_all(&pkg_entry_dir);
    }

    if !pkg_nm.exists() {
        if let Some(parent) = pkg_nm.parent() {
            std::fs::create_dir_all(parent)?;
        }
        // + audit response: materialization
        // strategy is dispatched by the explicit `materialization`
        // field, NOT by `wrapper_id.is_some()`. Day-2 used the
        // `wrapper_id`-presence proxy because only Directory/Link
        // had a wrapper id; once the audit extended `wrapper_id`
        // to Tarball sources (to prevent registry/tarball wrapper-
        // segment collisions) the proxy stopped being load-bearing
        // and the two concerns had to be separated.
        //
        // CasBacked: hardlink / clonefile / copy from
        //   `target.store_path` (lives inside the global CAS store).
        //   Used for Registry + Tarball remote + Tarball local + Git.
        // DirectorySource: per-file absolute symlinks from
        //   `target.store_path` (the canonicalized source realpath
        //   OUTSIDE the global store). Used for `Source::Directory`
        //   (`file:` dir) and `Source::Link` (`link:`).
        match target.materialization {
            Materialization::DirectorySource => {
                materialize_directory_source(&target.store_path, &pkg_nm)?;
            }
            Materialization::CasBacked => {
                link_dir_recursive(&target.store_path, &pkg_nm)?;
            }
        }
    }

    // Stage 2: internal symlinks from this package's node_modules/ to
    // each dependency's `.lpm/<dep>@<ver>/node_modules/<dep>` entry.
    //
    // Local-name / target-name split. The symlink
    // FILENAME uses the local name (what the parent's source code
    // expects via `require(dep_local)`). The symlink TARGET's
    // directory names use the TARGET canonical name (how the store
    // keys the `.lpm/<name>@<version>/` entry). For non-aliased
    // edges these coincide, so the code stays byte-identical to the
    // pre-P2 behavior. For aliases, `aliases.get(local)` provides
    // the target:
    //   parent/.lpm/.../node_modules/strip-ansi-cjs
    //     -> ../../strip-ansi@6.0.1/node_modules/strip-ansi
    let pkg_nm_dir = pkg_entry_dir.join("node_modules");
    let mut symlinks_created = 0;

    // Pre-create the small set of unique scope dirs
    // (`@types/`, `@scope/`, …) needed by scoped deps in ONE pass,
    // outside the per-dep loop. The flat `pkg_nm_dir` itself is already
    // materialized by the line-521 `create_dir_all` + `link_dir_recursive`
    // for the package, so non-scoped deps need no parent mkdir at all.
    // pre- the loop did `create_dir_all(dep_link.parent)` per
    // dep — for a webpack-style install that's ~1500–2500 redundant
    // stat-heavy syscall sequences (one per dep edge across 255 pkgs).
    // The samply warm-relink flamegraph shows mkdir at 20.5% of CPU; this
    // dedup is one of the levers identified in the close-out.
    let mut scope_dirs_created: std::collections::HashSet<&str> = std::collections::HashSet::new();
    for (dep_local, _) in &target.dependencies {
        if let Some((scope, _)) = dep_local.split_once('/')
            && scope.starts_with('@')
            && scope_dirs_created.insert(scope)
        {
            std::fs::create_dir_all(pkg_nm_dir.join(scope))?;
        }
    }

    for (dep_local, dep_version) in &target.dependencies {
        let dep_link = pkg_nm_dir.join(dep_local);

        if dep_link.exists() || dep_link.symlink_metadata().is_ok() {
            continue;
        }

        let dep_target = target
            .aliases
            .get(dep_local)
            .map(String::as_str)
            .unwrap_or(dep_local.as_str());

        // Symlink to the dep's location in .lpm/
        // Base: ../../<dep_target>@<ver>/node_modules/<dep_target>
        // For scoped LOCAL names like @types/node, the symlink lives
        // at `.lpm/<pkg>/node_modules/@types/node` — one extra level
        // deep — so we traverse one more `..`. The `..` depth is
        // computed from the LOCAL name (which decides where the
        // symlink FILE sits).
        let safe_target = dep_target.replace('/', "+");
        let depth = 2 + dep_local.matches('/').count();
        let mut sym_target = PathBuf::new();
        for _ in 0..depth {
            sym_target.push("..");
        }
        // Wrapper-segment shape branch. Targets whose `wrapper_id` is
        // non-None use `<safe>+<wrapper_id>` instead of
        // `<safe>@<version>`. The `dep_version` slot carries the
        // resolved SemVer for Registry targets, and the source-id
        // (`f-{16hex}` / `l-{16hex}` / `t-{16hex}`) for every other
        // source kind. The `t-` arm exists so
        // transitive Tarball deps (when they're tracked in a future
        // phase) route to the same `<safe>+t-{16hex}` wrapper that
        // immediate Tarball deps already use.
        //
        // The `<letter>-` prefix is the discriminator: SemVer
        // versions never start with `f-` / `l-` / `t-` (`t-…` would
        // need to be the major-version slot, which can't be
        // alphabetic). Day-5 commit body documents this contract;
        // if a future version-string shape ever collides, the
        // escape hatch is a `dep_kinds` field on LinkTarget.
        let is_source_id = dep_version.starts_with("f-")
            || dep_version.starts_with("l-")
            || dep_version.starts_with("t-");
        let wrapper_segment = if is_source_id {
            format!("{safe_target}+{dep_version}")
        } else {
            format!("{safe_target}@{dep_version}")
        };
        sym_target.push(wrapper_segment);
        sym_target.push("node_modules");
        sym_target.push(dep_target);

        create_symlink_or_junction(&sym_target, &dep_link)?;
        symlinks_created += 1;
    }

    // Write the stamped marker after a successful link + symlink pass.
    // The stamp's identity check on the next install distinguishes a
    // wrapper materialized from THIS LinkTarget from one materialized
    // from a different source kind that happens to share the same
    // wrapper segment (round-3 audit response).
    let stamp = compute_link_stamp(target);
    if let Err(e) = std::fs::write(&marker_path, &stamp) {
        tracing::warn!(
            "failed to write link marker for {}@{}: {}",
            safe_name,
            target.version,
            e
        );
    }

    Ok((
        materialized,
        OnePackageResult {
            linked: true,
            symlinks_created,
        },
    ))
}

/// Link finalization — Stage 3 root symlinks for direct
/// deps, Stage 3.5 self-reference, Stage 4 `.bin` creation.
///
/// Must run AFTER [`link_one_package`] has completed for every package
/// in `packages`. Stage 4 reads `package.json#bin` from each
/// materialized package.
pub fn link_finalize(
    project_dir: &Path,
    packages: &[LinkTarget],
    self_package_name: Option<&str>,
) -> Result<FinalizeResult, LpmError> {
    let layout = LayoutPaths::for_project(project_dir);
    let node_modules = project_dir.join("node_modules");
    let lpm_dir = layout.isolated_wrapper_root();

    // Stage 3: root symlinks — parallel, one iteration per (pkg, link_name)
    // pair. A package with no root link names contributes nothing
    // (transitive deps); one entry is the common case (pkg.name);
    // multiple entries support the scenario where the
    // same resolved `(name, version)` is referenced from the root
    // under multiple local names (canonical + one or more aliases).
    //
    // The store-path portion is ALWAYS keyed on `pkg.name` (the
    // canonical registry identity) so aliased `node_modules/<local>/`
    // symlinks land on the same `.lpm/<target>@<version>/node_modules/<target>/`
    // as their canonical-named sibling would.
    //
    // When `root_link_names` is `None` (legacy callers), fall back to
    // `[pkg.name]` iff `is_direct` — byte-identical to the pre-P2
    // behavior of "iterate direct packages, use pkg.name as root
    // symlink filename."
    let default_link: Vec<String> = Vec::new();
    let link_pairs: Vec<(&LinkTarget, String)> = packages
        .iter()
        .flat_map(|pkg| {
            let names: Vec<String> = match (&pkg.root_link_names, pkg.is_direct) {
                (Some(explicit), _) => explicit.clone(),
                (None, true) => vec![pkg.name.clone()],
                (None, false) => default_link.clone(),
            };
            names.into_iter().map(move |n| (pkg, n))
        })
        .collect();

    // Pre-create the small set of unique `@scope/` dirs at
    // `node_modules/` ONCE, before the parallel root-link loop. For
    // non-scoped link names the parent is `node_modules/` itself, which
    // is already materialized by `cleanup_stale_entries` (it does
    // `create_dir_all(node_modules/.lpm)` which recursively creates
    // `node_modules/`). The pre- loop did
    // `create_dir_all(root_link.parent())` per pair — most calls were
    // redundant stat sequences against an already-existing dir. For a
    // webpack-style install with ~370 root link pairs that's ~370
    // redundant calls. Pair this with the `link_one_package` dedup in
    // Commit 1 to attack the 20.5% mkdir cost identified in the
    // warm-relink samply flamegraph.
    let mut root_scope_dirs: std::collections::HashSet<&str> = std::collections::HashSet::new();
    for (_, link_name) in &link_pairs {
        if let Some((scope, _)) = link_name.split_once('/')
            && scope.starts_with('@')
            && root_scope_dirs.insert(scope)
        {
            std::fs::create_dir_all(node_modules.join(scope))?;
        }
    }

    let phase3_count = link_pairs
        .par_iter()
        .map(|(pkg, link_name)| -> Result<usize, LpmError> {
            let root_link = node_modules.join(link_name);

            if root_link.exists() || root_link.symlink_metadata().is_ok() {
                return Ok(0);
            }

            // Wrapper-segment shape is centralized in
            // `LinkTarget::wrapper_segment` so this path computation
            // handles both `<safe>@<version>` (CAS-backed) and
            // `<safe>+<wrapper_id>` (non-Registry) deps uniformly.
            //
            // The relative-path computation (depth + `..`
            // count, leading wrapper-root segments) is centralized in
            // [`LayoutPaths::root_symlink_target`] so the wrapper-root
            // relayout (now `<project>/.lpm/wrappers/`) is reflected
            // here automatically. The link FILENAME uses the local
            // name (what the parent's source code expects); the
            // symlink TARGET's directory names use the canonical
            // wrapper segment — matching the local/canonical split
            // documented on [`LinkTarget::root_link_names`].
            let target = layout.root_symlink_target(link_name, &pkg.wrapper_segment(), &pkg.name);

            // **race tolerance.** `link_pairs` is iterated in
            // parallel via rayon; the check at the top of this closure
            // (`root_link.exists()`) is a TOCTOU check — two threads
            // targeting the same `link_name` can both read "doesn't
            // exist" and both try to create the symlink. Only one wins;
            // the loser returns `AlreadyExists`. Historically this
            // surfaced when `resolved_to_install_packages` produced
            // duplicate `(canonical_name, version)` rows for
            // split contexts. The upstream fix dedups at the source,
            // but we keep this tolerance as a race-safe belt-and-braces:
            // a benign concurrent create should never abort an install.
            match create_symlink_or_junction(&target, &root_link) {
                Ok(()) => Ok(1),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(0),
                Err(e) => Err(LpmError::Io(e)),
            }
        })
        .try_reduce(|| 0usize, |a, b| Ok(a + b))?;

    // Stage 3.5: self-reference — package can require("itself").
    let mut self_referenced = false;
    let mut self_ref_count = 0;
    if let Some(self_name) = self_package_name {
        if !is_valid_self_ref_name(self_name) {
            tracing::warn!(
                "skipping self-reference for invalid package name: {}",
                self_name
            );
        } else {
            let self_link = node_modules.join(self_name);
            if !self_link.exists() && self_link.symlink_metadata().is_err() {
                // Handle scoped packages: create @scope/ directory first
                if self_name.starts_with('@')
                    && let Some(scope_dir) = self_link.parent()
                {
                    let _ = std::fs::create_dir_all(scope_dir);
                }
                // Symlink node_modules/{name} → project root
                // For scoped packages, we need to go up one extra level
                let depth = self_name.matches('/').count();
                let mut target = PathBuf::new();
                for _ in 0..depth {
                    target.push("..");
                }
                target.push(".."); // up from node_modules/
                create_symlink_or_junction(&target, &self_link)?;
                self_referenced = true;
                self_ref_count = 1;
            }
        }
    }

    // Stage 4: node_modules/.bin/ entries.
    let bin_count = create_bin_links(&node_modules, &lpm_dir, packages)?;

    // Hoisted-symmetry — deferred inactive-mode state prune.
    //
    // We only prune `<project>/.lpm/hoisted/` once isolated linking
    // has completed every fallible step (Stage 3 root symlinks +
    // Stage 3.5 self-ref + Stage 4 bin links). If anything above
    // returned `Err`, the user keeps both layouts' state on disk and
    // can recover by re-running install. Best-effort wipe.
    let stale_hoisted = layout.hoisted_root();
    if stale_hoisted.exists() {
        let _ = std::fs::remove_dir_all(&stale_hoisted);
        tracing::debug!(
            "isolated: pruned stale hoisted state at {}",
            stale_hoisted.display()
        );
    }

    Ok(FinalizeResult {
        symlinks_created: phase3_count + self_ref_count,
        bin_count,
        self_referenced,
    })
}

/// Create a `node_modules/<package_name>` symlink that points at a workspace
/// member's source directory.
///
/// **audit fix #3** (workspace:^ resolver bug). The install
/// pipeline strips workspace member dependencies from the resolver input
/// before resolution and links them locally with this helper after the
/// regular linking pass has finished. The function is idempotent — if a stale
/// entry already exists at the link path it is removed first so re-running
/// `lpm install` does not error out on the second invocation.
///
/// The symlink target is a relative path computed via [`pathdiff::diff_paths`]
/// from the link's parent directory to the canonicalized member source
/// directory. Relative symlinks are resilient to workspace moves and match
/// the strategy already used elsewhere in this crate (see the bin link path
/// at the bottom of `link_packages`).
///
/// On Windows, the relative path is resolved into an absolute target before
/// being passed to [`create_symlink_or_junction`] because NTFS junctions
/// require absolute targets.
///
/// Errors:
/// - I/O failures creating parent directories or the symlink itself
/// - The member source directory cannot be canonicalized (does not exist)
pub fn link_workspace_member(
    node_modules_dir: &Path,
    package_name: &str,
    member_source_dir: &Path,
) -> Result<(), LpmError> {
    // Defensive validation: reject anything that would let an attacker
    // escape `node_modules_dir/` via path traversal in the package name.
    // Mirrors the existing `is_valid_self_ref_name` check used by the
    // self-reference symlink creation in `link_packages`.
    if !is_valid_self_ref_name(package_name) {
        return Err(LpmError::Registry(format!(
            "refusing to link workspace member with unsafe name: {package_name:?}"
        )));
    }

    // Resolve the canonical source dir up front. The relative-symlink
    // computation needs both endpoints in canonical form to be correct.
    let source_canonical = member_source_dir.canonicalize().map_err(|e| {
        LpmError::Io(std::io::Error::new(
            e.kind(),
            format!(
                "workspace member source directory {} does not exist or is unreadable: {e}",
                member_source_dir.display()
            ),
        ))
    })?;

    let link_path = node_modules_dir.join(package_name);

    // Make sure the parent of the link path exists. For scoped packages
    // (`@scope/name`) this creates the `@scope/` directory; for unscoped
    // packages this is a no-op because `node_modules/` itself is the parent.
    if let Some(link_parent) = link_path.parent() {
        std::fs::create_dir_all(link_parent)?;
    }

    // Defensive cleanup: any existing entry (file, dir, symlink) at the link
    // path must go before we create the new symlink. The most common case is
    // a stale workspace symlink from a previous install — those are still
    // technically symlinks so `remove_file` succeeds. The fallback handles
    // the rare case where someone (or another tool) put a real directory
    // there: we want the install to recover, not crash.
    if link_path.symlink_metadata().is_ok() && std::fs::remove_file(&link_path).is_err() {
        let _ = std::fs::remove_dir_all(&link_path);
    }

    // Compute the symlink target relative to the link's parent directory.
    // Relative symlinks survive `mv workspace_root /elsewhere/` and match the
    // strategy used by the bin shim path at the bottom of `link_packages`.
    let link_parent = link_path
        .parent()
        .expect("link_path was joined under node_modules_dir, must have a parent");
    let link_parent_canonical = link_parent
        .canonicalize()
        .unwrap_or_else(|_| link_parent.to_path_buf());
    let relative_target = pathdiff::diff_paths(&source_canonical, &link_parent_canonical)
        .unwrap_or_else(|| source_canonical.clone());

    create_symlink_or_junction(&relative_target, &link_path).map_err(LpmError::Io)?;
    Ok(())
}

/// Walk the consumer chain from `start_idx` upward until we find a
/// package whose `(name, version)` IS the hoisted-at-root instance for
/// its name (i.e., `hoisted[pkg.name] == cur_idx`). Returns that
/// package's name — the **anchor** under which a conflict-version
/// package should be nested. Returns `None` if no hoisted ancestor
/// exists in the chain (orphan, cycle, or chain that exits the graph).
///
/// **Why this is the right anchor.** In hoisted layout, Node's resolver
/// for a package P@v at `<anchor>/node_modules/P/` walks up through
/// `<anchor>/node_modules/` first, then the project root. Sibling-style
/// placement (P@v directly inside the anchor's node_modules, not nested
/// further inside the consumer that needs P@v) is npm v3's layout
/// strategy and is correct because Node walks `node_modules/` directories
/// upward — finding P@v as a sibling of the consumer, before reaching
/// the root's conflicting version, satisfies the consumer's `require`.
///
/// **Pre-fix bug this resolves.** The old algorithm picked the consumer
/// by NAME alone (`depended_by: HashMap<(String, String), Vec<String>>`)
/// and used that name directly as the parent. When the same consumer
/// name existed at multiple versions (e.g., minimatch@3 hoisted +
/// minimatch@10 nested), the parent lookup couldn't tell them apart,
/// so brace-expansion@5 (consumed by minimatch@10) was placed under
/// `node_modules/minimatch/` — which was minimatch@3's slot. Node's
/// resolver from any caller of minimatch@3 then found brace-expansion@5
/// nested there, with the wrong API for v1, and crashed.
fn find_hoisted_anchor(
    start_idx: usize,
    hoisted: &HashMap<String, usize>,
    packages: &[LinkTarget],
    depended_by: &HashMap<(&str, &str), Vec<usize>>,
) -> Option<String> {
    let mut cur = start_idx;
    let mut visited: std::collections::HashSet<usize> = std::collections::HashSet::new();
    while visited.insert(cur) {
        let pkg = &packages[cur];
        // Alias-aware anchor lookup: pre-fix this checked
        // `hoisted.get(&pkg.name) == Some(&cur)`.
        // That breaks under aliases: an aliased direct dep with
        // `root_link_names = ["a-alias"]` and `pkg.name = "lodash"`
        // is hoisted at slot "a-alias", not "lodash" — the lookup
        // by pkg.name returns nothing and the anchor walk fails
        // even though `cur` IS the hoisted-at-root instance.
        //
        // Generalize: check whether `cur` IS hoisted under ANY slot.
        // If yes, return that slot — it's the on-disk parent dir
        // name. The scan is O(hoisted_count) per anchor step. With
        // typical install sizes (hundreds of packages, single-digit
        // anchor walks) this is negligible vs the link-recursive
        // wall. Deterministic order: scan via `iter()`, take first
        // match. Multi-slot (aliased package with several
        // root_link_names) returns whichever slot enumerates first
        // — which is fine since any of them is a valid Node-resolver
        // walk-up target.
        if let Some((slot, _)) = hoisted.iter().find(|&(_, &idx)| idx == cur) {
            return Some(slot.clone());
        }
        // Otherwise walk up: find a consumer of this package and recurse.
        // Pick the first consumer (deterministic — packages are processed
        // in resolver-determined order, so first-encountered is stable).
        match depended_by.get(&(pkg.name.as_str(), pkg.version.as_str())) {
            Some(consumers) if !consumers.is_empty() => cur = consumers[0],
            _ => return None,
        }
    }
    None // cycle detected
}

/// Create the npm v3+ style hoisted node_modules layout.
///
/// All packages are placed directly into `node_modules/` (flat). When two packages
/// need different versions of the same dependency, the direct dependency (or the
/// first encountered) wins the root position, and the other is nested under a
/// hoisted ancestor of its consumer (sibling-style nesting — see
/// [`find_hoisted_anchor`] for the placement rule).
///
/// Layout:
/// ```text
/// node_modules/
///   express/    -> <store>   (hoisted)
///   debug/      -> <store>   (hoisted, version used by express)
///   ms/         -> <store>   (hoisted)
///   other-pkg/
///     node_modules/
///       debug/  -> <store>   (nested, different version than root)
/// ```
pub fn link_packages_hoisted(
    project_dir: &Path,
    packages: &[LinkTarget],
    force: bool,
    self_package_name: Option<&str>,
) -> Result<LinkResult, LpmError> {
    let layout = LayoutPaths::for_project(project_dir);
    let node_modules = project_dir.join("node_modules");

    // Hoisted-symmetry follow-up: hoisted state now lives under
    // `<project>/.lpm/hoisted/` (see [`LayoutPaths::hoisted_root`]), so
    // `node_modules/.lpm/` is purely legacy debris on this branch. The
    // pre-symmetry exclusion that preserved `.lpm` during a `force`
    // wipe is removed: any `.lpm` directly inside `node_modules/`
    // belongs to a pre-migration install and is about to be wiped by
    // the migration helper anyway. Keeping it would just preserve
    // stale state across `--force`.
    if node_modules.exists()
        && force
        && let Ok(entries) = std::fs::read_dir(&node_modules)
    {
        for entry in entries.flatten() {
            let name = entry.file_name();
            if name != ".bin" {
                let path = entry.path();
                if path.is_dir() {
                    let _ = std::fs::remove_dir_all(&path);
                } else {
                    let _ = std::fs::remove_file(&path);
                }
            }
        }
    }

    std::fs::create_dir_all(&node_modules)?;

    // Hoisted-symmetry: bootstrap the project-local hoisted state
    // directory so the metadata write at the bottom of this function
    // (and any nested-fallback materialization in Stage 3) doesn't
    // have to call `create_dir_all` per write. Idempotent by
    // construction.
    std::fs::create_dir_all(layout.hoisted_root())?;

    // Schema-version tag, mirroring the wrapper-root version stamp
    // written by [`cleanup_stale_entries`]. Best-effort write — a
    // read-only FS or permission error doesn't block the install;
    // the file is purely a forward-compat marker.
    let hoisted_version_path = layout.hoisted_layout_version_path();
    if !hoisted_version_path.exists() {
        let _ = std::fs::write(&hoisted_version_path, b"1\n");
    }

    // Isolated→hoisted convergence sweep.
    //
    // The previous mode (isolated) left `node_modules/<pkg>` and
    // `node_modules/@scope/<pkg>` as symlinks pointing into
    // `<project>/.lpm/wrappers/<seg>/node_modules/<pkg>/`. The
    // hoisted link loop calls `link_dir_recursive` which starts with
    // `std::fs::create_dir_all(dst)` — when `dst` is an intact
    // symlink that resolves to a directory, the call is a silent
    // no-op and Stage 3 falls through `if target_dir.exists`
    // skipping materialization (the user keeps their stale isolated
    // shape). When `dst` is a broken symlink (e.g., we already
    // pruned the wrapper root), `create_dir_all` fails on macOS.
    // Either failure mode yields a non-converging install.
    //
    // Fix: walk `node_modules/` and `node_modules/@scope/` once and
    // remove every symlink. Recreations downstream:
    //   * Hoisted package symlinks: not used in hoisted mode (full
    //     copies via `link_dir_recursive`).
    //   * Self-reference symlink: recreated by Stage 3.5 below.
    //   * Workspace-member symlinks: recreated by `link_workspace_members`
    //     in the install pipeline after this function returns.
    //   * `.bin` shims: still real files inside `node_modules/.bin/`,
    //     not at the top-level — untouched.
    if let Ok(entries) = std::fs::read_dir(&node_modules) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if name_str == ".bin" || name_str.starts_with('.') {
                continue;
            }
            let path = entry.path();
            let is_symlink = path
                .symlink_metadata()
                .map(|m| m.file_type().is_symlink())
                .unwrap_or(false);
            if is_symlink {
                let _ = std::fs::remove_file(&path);
                tracing::debug!(
                    "hoisted: removed stale isolated symlink at node_modules/{name_str}",
                );
                continue;
            }
            // Scope dir — recurse one level for scoped symlinks.
            if name_str.starts_with('@')
                && path.is_dir()
                && let Ok(scope_entries) = std::fs::read_dir(&path)
            {
                for se in scope_entries.flatten() {
                    let se_path = se.path();
                    let se_is_symlink = se_path
                        .symlink_metadata()
                        .map(|m| m.file_type().is_symlink())
                        .unwrap_or(false);
                    if se_is_symlink {
                        let _ = std::fs::remove_file(&se_path);
                        tracing::debug!(
                            "hoisted: removed stale isolated symlink at node_modules/{}/{}",
                            name_str,
                            se.file_name().to_string_lossy()
                        );
                    }
                }
            }
        }
    }

    // Note: pruning of stale isolated state at
    // `<project>/.lpm/wrappers/` is deferred to the end of this
    // function so a failed hoisted install doesn't strand the user
    // with neither layout's state present. See the post-link prune
    // before the function's `Ok(LinkResult)` return.

    // Stage 1: Determine hoisting layout.
    //
    // Build a dependency graph so we can figure out which package "depends on"
    // which conflicting version. The algorithm:
    //   1. Walk all packages in order. Try to claim the root node_modules/<name> slot.
    //   2. If a name is already claimed by a different version, decide who gets root:
    //      - Direct deps always win root over transitive deps.
    //      - Among equal priority, first-come-first-served (stable for determinism).
    //   3. The loser gets nested under one of its dependents.
    let mut hoisted: HashMap<String, usize> = HashMap::with_capacity(packages.len());
    // (package_index, parent_name) -- packages that must be nested.
    // `parent_name` is the name of a hoisted ancestor under which this
    // conflict-version is placed (npm v3 sibling-style nesting).
    let mut nested: Vec<(usize, String)> = Vec::new();

    // Reverse-dependency map: dep (name, version) → list of consumer
    // package indices. **Indices, not names** — when the same name
    // appears as a consumer at multiple versions (e.g., minimatch@3
    // consumes brace-expansion@1 AND minimatch@10 consumes
    // brace-expansion@5), we need to know WHICH instance consumes
    // which version of the dep. Keying by index instead of name
    // preserves the (name, version) identity through the lookup chain
    // — `depended_by[(brace-expansion, 5.0.5)][0]` is minimatch@10's
    // index, not just "minimatch". The pre-fix code used names and
    // misplaced brace-expansion@5 under whatever minimatch happened to
    // be hoisted (v3), which broke ESLint 9's flat-config because
    // v3 needs brace-expansion@1's API and Node resolved to v5's.
    // Use (&str, &str) keys instead of (String, String): the keys borrow
    // from the `packages` slice which outlives this map, eliminating
    // ~2 String heap allocations per dependency edge (~1,600 allocs
    // saved on a 266-package install like bench/fixture-large).
    let mut depended_by: HashMap<(&str, &str), Vec<usize>> = HashMap::new();
    for (idx, pkg) in packages.iter().enumerate() {
        for (dep_name, dep_ver) in &pkg.dependencies {
            depended_by
                .entry((dep_name.as_str(), dep_ver.as_str()))
                .or_default()
                .push(idx);
        }
    }

    // (package_index_to_nest, consumer_index_or_None) — Stage 1
    // records this; Stage 1.5 resolves each consumer_index to a
    // hoisted-ancestor name via `find_hoisted_anchor`. None means
    // "no consumer found in the graph for this conflict version,"
    // which can happen for orphan-nested entries; the resolution
    // step falls back to the conflict name itself in that case.
    let mut nested_pending: Vec<(usize, Option<usize>)> = Vec::new();

    // npm-alias root-slot claiming: pre-fix Stage 1 claimed slots
    // keyed strictly on `pkg.name` (the
    // canonical/registry identity). For a `npm:<target>@<range>` alias
    // declared at root level, `resolved_to_install_packages` populates
    // `LinkTarget.root_link_names` with the LOCAL alias name(s) — which
    // can differ from `pkg.name` (e.g., user wrote `lodash-a:
    // npm:lodash@^4`, so root_link_names = ["lodash-a"] and pkg.name =
    // "lodash"). The pre-fix loop would claim slot "lodash" for the
    // package and never create `node_modules/lodash-a/`, leaving the
    // alias unresolvable at runtime. Symmetric with v2's
    // [`v2.rs::root_link_names`] helper but extended to the hoisting
    // algorithm's slot-claim level rather than just the symlink-emit
    // level.
    //
    // Slot derivation (per package):
    //   - `Some(names)`: claim each entry. Empty Vec means "explicitly
    //     no root surface" — the package still gets bin shims via
    //     other paths but no top-level `node_modules/<name>/` entry
    //     (matches v2's contract).
    //   - `None`: claim `[pkg.name]`. Covers transitive deps (always
    //     None) and direct deps that pre-date alias plumbing or
    //     deliberately use the canonical-only shape.
    let slots_for_pkg = |pkg: &LinkTarget| -> Vec<String> {
        match &pkg.root_link_names {
            Some(names) => names.clone(),
            None => vec![pkg.name.clone()],
        }
    };

    for (idx, pkg) in packages.iter().enumerate() {
        for slot in slots_for_pkg(pkg) {
            if let Some(&existing_idx) = hoisted.get(&slot) {
                let existing = &packages[existing_idx];
                if existing.version == pkg.version && existing.name == pkg.name {
                    // Same identity, already hoisted. Common path for
                    // duplicate (canonical, version) entries the
                    // resolver dedupes upstream + the bench cases
                    // where the same alias surfaces multiple times.
                    continue;
                }
                // Slot conflict: two distinct packages want the same
                // top-level slot. Direct dep wins; transitive nests.
                // Note: under aliases, this is reached when an
                // aliased direct dep collides with an unaliased
                // transitive at the same name (rare but legal —
                // e.g., a user aliases `lodash-a → npm:react@…` while
                // a transitive also wants `lodash-a`). The tie-breaker
                // is identical to the canonical-only path.
                if pkg.is_direct && !existing.is_direct {
                    // Evict existing to nested, hoist the new one.
                    let consumer_idx = depended_by
                        .get(&(existing.name.as_str(), existing.version.as_str()))
                        .and_then(|v: &Vec<usize>| v.first().copied());
                    nested_pending.push((existing_idx, consumer_idx));
                    hoisted.insert(slot, idx);
                } else {
                    // Keep existing at root, nest the new one.
                    let consumer_idx = depended_by
                        .get(&(pkg.name.as_str(), pkg.version.as_str()))
                        .and_then(|v: &Vec<usize>| v.first().copied());
                    nested_pending.push((idx, consumer_idx));
                }
            } else {
                hoisted.insert(slot, idx);
            }
        }
    }

    // Stage 1.5: resolve each pending nested entry's anchor.
    //
    // For a conflict-versioned package P@v that won't be hoisted,
    // find a "hoisted ancestor" by walking from one of its consumers
    // up the consumer chain until we hit a package whose `(name,
    // version)` IS the hoisted instance for that name. Place P@v
    // under that ancestor's name in node_modules — sibling-style
    // (npm v3 layout: `node_modules/<anchor>/node_modules/P/`). This
    // is correct because Node's resolver from P@v's location walks
    // up through `<anchor>/node_modules/` and finds P@v there
    // before reaching the root's conflicting version.
    //
    // If no hoisted ancestor exists in the chain (orphan, cycle, or
    // graph error), fall back to the conflict's own name — same as
    // the pre-fix behavior, which Stage 3's `hoisted.contains_key`
    // gate handles correctly via `hoisted_nested_root()`.
    for (idx, consumer_idx) in nested_pending {
        let parent = consumer_idx
            .and_then(|c_idx| find_hoisted_anchor(c_idx, &hoisted, packages, &depended_by))
            .unwrap_or_else(|| packages[idx].name.clone());
        nested.push((idx, parent));
    }

    // Build the desired layout snapshot: name → "name@version" for both hoisted
    // and nested packages. BTreeMap gives deterministic serialization order.
    let mut desired_hoisted: BTreeMap<String, String> = BTreeMap::new();
    for (name, &pkg_idx) in &hoisted {
        let pkg = &packages[pkg_idx];
        desired_hoisted.insert(name.clone(), pkg.version.clone());
    }

    // Nested entries: "parent/name" → version (parent prefix makes them unique)
    let mut desired_nested: BTreeMap<String, String> = BTreeMap::new();
    for (pkg_idx, parent_name) in &nested {
        let pkg = &packages[*pkg_idx];
        let key = format!("{}/{}", parent_name, pkg.name);
        desired_nested.insert(key, pkg.version.clone());
    }

    // Stage 1.5: Incremental check — read saved metadata and compare.
    // If the desired layout is identical to what we wrote last time, and
    // every expected directory still exists on disk, skip the expensive I/O.
    let metadata_path = layout.hoisted_metadata_path();
    let mut skipped_count = 0;

    let needs_relink = force || {
        match read_hoist_metadata(&metadata_path) {
            Some(saved)
                if saved.hoisted == desired_hoisted
                    && saved.nested == desired_nested
                    && saved.self_ref == self_package_name.map(|s| s.to_string()) =>
            {
                // Metadata matches. Spot-check that key directories still exist.
                let dirs_intact = desired_hoisted
                    .keys()
                    .all(|name| node_modules.join(name).exists());
                if dirs_intact {
                    tracing::debug!(
                        "hoisted: layout unchanged ({} packages), skipping re-link",
                        desired_hoisted.len() + desired_nested.len()
                    );
                    false
                } else {
                    tracing::debug!("hoisted: metadata matches but dirs missing, re-linking");
                    true
                }
            }
            _ => true, // no metadata or mismatch → full re-link
        }
    };

    let mut linked_count = 0;
    let mut self_referenced = false;
    // **`lpm patch`.** Track materialized destinations.
    // Hoisted mode has up to three shapes per package:
    //   - hoisted root:                 node_modules/<name>/
    //   - nested under hoisted parent:  node_modules/<parent>/node_modules/<name>/
    //   - nested under nested parent:   <project>/.lpm/hoisted/nested/<name>/
    // The patch-apply pass needs ALL physical copies. We populate the
    // list whether the linker takes the full re-link path OR the
    // metadata-skip fast path — both branches push entries explicitly
    // below. Capacity is hoisted + nested.
    let mut materialized: Vec<MaterializedPackage> =
        Vec::with_capacity(hoisted.len() + nested.len());

    if needs_relink {
        // Remove stale entries: anything in the old metadata that's been removed
        // or changed version needs to be cleaned up from disk so we can re-link.
        if let Some(saved) = read_hoist_metadata(&metadata_path) {
            for (name, old_ver) in &saved.hoisted {
                let removed = !desired_hoisted.contains_key(name);
                let version_changed = desired_hoisted
                    .get(name)
                    .is_some_and(|new_ver| new_ver != old_ver);
                if removed || version_changed {
                    let stale = node_modules.join(name);
                    let _ = std::fs::remove_dir_all(&stale);
                    tracing::debug!("hoisted: removed stale {name}@{old_ver}");
                }
            }
            for (key, old_ver) in &saved.nested {
                let removed = !desired_nested.contains_key(key);
                let version_changed = desired_nested
                    .get(key)
                    .is_some_and(|new_ver| new_ver != old_ver);
                if (removed || version_changed)
                    && let Some((parent, pkg_name)) = key.split_once('/')
                {
                    let stale = if desired_hoisted.contains_key(parent) {
                        node_modules
                            .join(parent)
                            .join("node_modules")
                            .join(pkg_name)
                    } else {
                        layout.hoisted_nested_root().join(pkg_name)
                    };
                    let _ = std::fs::remove_dir_all(&stale);
                    tracing::debug!("hoisted: removed stale nested {key}@{old_ver}");
                }
            }
        }

        // Stage 2: Link hoisted packages directly into root node_modules/
        for (name, &pkg_idx) in &hoisted {
            let pkg = &packages[pkg_idx];
            let target_dir = node_modules.join(name);

            // Record materialized destination BEFORE
            // the early-continue so the patch pass sees both freshly-
            // linked and already-existing entries.
            materialized.push(MaterializedPackage {
                name: pkg.name.clone(),
                version: pkg.version.clone(),
                destination: target_dir.clone(),
            });

            if target_dir.exists() {
                continue;
            }

            // Handle scoped packages (@scope/name -> create @scope/ dir first)
            if name.starts_with('@')
                && let Some(parent) = target_dir.parent()
            {
                std::fs::create_dir_all(parent)?;
            }

            link_dir_recursive(&pkg.store_path, &target_dir)?;
            linked_count += 1;
        }

        // Stage 3: Link nested (conflicting) packages under their parent's node_modules/
        for (pkg_idx, parent_name) in &nested {
            let pkg = &packages[*pkg_idx];

            let parent_nm = if hoisted.contains_key(parent_name) {
                node_modules.join(parent_name).join("node_modules")
            } else {
                layout.hoisted_nested_root()
            };

            let nested_dir = parent_nm.join(&pkg.name);

            // Record materialized destination BEFORE
            // the early-continue. Both nested-shape branches (under
            // hoisted parent AND under .lpm/nested) flow through here.
            materialized.push(MaterializedPackage {
                name: pkg.name.clone(),
                version: pkg.version.clone(),
                destination: nested_dir.clone(),
            });

            if nested_dir.exists() {
                continue;
            }

            if let Some(parent) = nested_dir.parent() {
                std::fs::create_dir_all(parent)?;
            }

            link_dir_recursive(&pkg.store_path, &nested_dir)?;
            linked_count += 1;
        }

        // Write updated metadata for next incremental run.
        // Self-reference is materialized below the join point so it
        // runs on BOTH branches — the metadata-skip path needs it
        // too, because the pre-link symlink sweep deletes the
        // existing self-ref before we get here.
        write_hoist_metadata(
            &metadata_path,
            &desired_hoisted,
            &desired_nested,
            self_package_name,
        );
    } else {
        skipped_count = desired_hoisted.len() + desired_nested.len();
        // Self-reference handled at the join point below.

        // **.** Even on the metadata-skip fast path,
        // the patch-apply pass needs the materialized location list.
        // Re-derive it from the same `packages` slice + `hoisted` /
        // `nested` decision tables we already built above. The
        // destinations are identical to the full re-link branch.
        for (name, &pkg_idx) in &hoisted {
            let pkg = &packages[pkg_idx];
            materialized.push(MaterializedPackage {
                name: pkg.name.clone(),
                version: pkg.version.clone(),
                destination: node_modules.join(name),
            });
        }
        for (pkg_idx, parent_name) in &nested {
            let pkg = &packages[*pkg_idx];
            let parent_nm = if hoisted.contains_key(parent_name) {
                node_modules.join(parent_name).join("node_modules")
            } else {
                layout.hoisted_nested_root()
            };
            materialized.push(MaterializedPackage {
                name: pkg.name.clone(),
                version: pkg.version.clone(),
                destination: parent_nm.join(&pkg.name),
            });
        }
    }

    // Stage 3.5 (post-symmetry placement): self-reference — package
    // can require("itself"). Runs unconditionally on BOTH the full
    // re-link branch AND the metadata-skip fast path, because the
    // isolated→hoisted convergence sweep above deleted the
    // pre-existing self-ref symlink. Without this unconditional
    // recreation, every incremental hoisted install on a named
    // project would silently drop `require("self")`.
    //
    // Three on-disk states are possible at `node_modules/<self_name>`:
    //   1. Nothing — create the self-ref.
    //   2. A real directory — a dep happens to share the project's
    //      name. The dep won the slot; do NOT clobber it. Leave
    //      `self_referenced = false`.
    //   3. An existing symlink — typically the self-ref the sweep
    //      missed (e.g. a permission glitch). Trust it as the
    //      self-ref and report `self_referenced = true`. Distinguished
    //      from case 2 by `file_type().is_symlink()`.
    if let Some(self_name) = self_package_name {
        if !is_valid_self_ref_name(self_name) {
            tracing::warn!(
                "skipping self-reference for invalid package name: {}",
                self_name
            );
        } else {
            let self_link = node_modules.join(self_name);
            let existing = self_link.symlink_metadata();
            match existing {
                Err(_) => {
                    if self_name.starts_with('@')
                        && let Some(scope_dir) = self_link.parent()
                    {
                        let _ = std::fs::create_dir_all(scope_dir);
                    }
                    let depth = self_name.matches('/').count();
                    let mut target = PathBuf::new();
                    for _ in 0..depth {
                        target.push("..");
                    }
                    target.push(".."); // up from node_modules/
                    create_symlink_or_junction(&target, &self_link)?;
                    self_referenced = true;
                }
                Ok(meta) if meta.file_type().is_symlink() => {
                    // Self-ref survived the sweep (rare). Trust it.
                    self_referenced = true;
                }
                Ok(_) => {
                    // Real dir — dep with the same name took the slot.
                    // Don't clobber; self_referenced stays false.
                }
            }
        }
    }

    // Stage 4: Binary links for hoisted packages (always runs — cheap idempotent check).
    let bin_count = create_bin_links_hoisted(&node_modules, packages, &hoisted)?;

    // Hoisted-symmetry — deferred inactive-mode state prune.
    //
    // Only after every fallible step above has succeeded (link loop +
    // bin links) do we wipe `<project>/.lpm/wrappers/`. If this
    // function returned `Err` earlier, the stale isolated state stays
    // intact so the user can recover by re-running install or by
    // reverting to the previous mode. Best-effort wipe.
    let stale_isolated = layout.isolated_wrapper_root();
    if stale_isolated.exists() {
        let _ = std::fs::remove_dir_all(&stale_isolated);
        tracing::debug!(
            "hoisted: pruned stale isolated state at {}",
            stale_isolated.display()
        );
    }

    Ok(LinkResult {
        linked: linked_count,
        symlinked: 0, // hoisted mode uses direct copies, not symlinks
        bin_linked: bin_count,
        skipped: skipped_count,
        self_referenced,
        materialized,
    })
}

// ─── Hoisted metadata persistence ───────────────────────────────────────────

/// Saved state from a previous hoisted link run.
struct HoistMetadata {
    hoisted: BTreeMap<String, String>,
    nested: BTreeMap<String, String>,
    self_ref: Option<String>,
}

/// Read `.lpm-metadata.json` from a previous hoisted run.
/// Returns `None` if the file is missing, corrupt, or has an unexpected format.
fn read_hoist_metadata(path: &Path) -> Option<HoistMetadata> {
    let data = std::fs::read_to_string(path).ok()?;
    let val: serde_json::Value = serde_json::from_str(&data).ok()?;

    let hoisted = val.get("hoisted")?.as_object()?;
    let nested = val.get("nested")?.as_object()?;

    let h: BTreeMap<String, String> = hoisted
        .iter()
        .filter_map(|(k, v)| Some((k.clone(), v.as_str()?.to_string())))
        .collect();

    let n: BTreeMap<String, String> = nested
        .iter()
        .filter_map(|(k, v)| Some((k.clone(), v.as_str()?.to_string())))
        .collect();

    let self_ref = val
        .get("self_ref")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    Some(HoistMetadata {
        hoisted: h,
        nested: n,
        self_ref,
    })
}

/// Write `.lpm-metadata.json` after a successful hoisted link.
fn write_hoist_metadata(
    path: &Path,
    hoisted: &BTreeMap<String, String>,
    nested: &BTreeMap<String, String>,
    self_ref: Option<&str>,
) {
    let val = serde_json::json!({
        "hoisted": hoisted,
        "nested": nested,
        "self_ref": self_ref,
    });
    // Best-effort — failure here only means next install won't be incremental.
    let _ = std::fs::write(path, serde_json::to_string_pretty(&val).unwrap_or_default());
}

// ─── Hoisted bin links ─────────────────────────────────────────────────────

/// Create bin links for hoisted mode.
///
/// In hoisted mode, packages live directly in `node_modules/<name>/` rather than
/// `.lpm/<name>@<ver>/node_modules/<name>/`. We read package.json from the
/// hoisted location.
fn create_bin_links_hoisted(
    node_modules: &Path,
    packages: &[LinkTarget],
    hoisted: &HashMap<String, usize>,
) -> Result<usize, LpmError> {
    let bin_dir = node_modules.join(".bin");
    let mut count = 0;

    // Reuse a single PathBuf across all package iterations — eliminates the
    // `node_modules.join(name)` and `pkg_dir.join("package.json")` allocations
    // that otherwise happen unconditionally for every package regardless of
    // whether it has bins. For a 266-package fixture like bench/fixture-large,
    // this saves ~532 PathBuf allocations in a single function call.
    //
    // Scoped packages (e.g., "@scope/pkg") push two path components, so we
    // count components with `Path::new(name).components().count()` to know
    // how many `pop()` calls restore the buffer to `node_modules/`.
    let mut pkg_path = node_modules.to_owned();
    pkg_path.reserve(128);

    for (name, &pkg_idx) in hoisted {
        let pkg = &packages[pkg_idx];
        // Count path components so pop() calls correctly restore pkg_path.
        // Unscoped ("react") = 1, scoped ("@scope/pkg") = 2.
        let n = Path::new(name.as_str()).components().count();
        pkg_path.push(name.as_str()); // pkg_path = node_modules/<name>
        pkg_path.push("package.json"); // pkg_path = node_modules/<name>/package.json

        if !pkg_path.exists() {
            pkg_path.pop();
            for _ in 0..n {
                pkg_path.pop();
            }
            continue;
        }

        let pkg_json = match lpm_workspace::read_package_json(&pkg_path) {
            Ok(p) => p,
            Err(e) => {
                tracing::debug!(
                    "skipping bin links for {}: failed to parse package.json: {e}",
                    pkg.name
                );
                pkg_path.pop();
                for _ in 0..n {
                    pkg_path.pop();
                }
                continue;
            }
        };
        pkg_path.pop(); // pkg_path = node_modules/<name>

        let bin_config = match &pkg_json.bin {
            Some(b) => b,
            None => {
                for _ in 0..n {
                    pkg_path.pop();
                }
                continue;
            }
        };

        let pkg_name = pkg_json.name.as_deref().unwrap_or(&pkg.name);
        let entries = bin_config.entries(pkg_name);

        if entries.is_empty() {
            for _ in 0..n {
                pkg_path.pop();
            }
            continue;
        }

        std::fs::create_dir_all(&bin_dir)?;

        for (cmd_name, script_path) in &entries {
            // Validate bin name
            if let Err(reason) = validate_bin_name(cmd_name, pkg_name) {
                tracing::warn!("bin: rejecting \"{cmd_name}\" from {pkg_name}: {reason}");
                continue;
            }

            // Validate bin target path (no traversal).
            // pkg_path = node_modules/<name> here, same as the old &pkg_dir.
            let target = match validate_bin_target(&pkg_path, script_path) {
                Ok(t) => t,
                Err(reason) => {
                    tracing::warn!("bin: rejecting {cmd_name} from {pkg_name}: {reason}");
                    continue;
                }
            };

            let bin_link = bin_dir.join(cmd_name);

            if bin_link.symlink_metadata().is_ok() {
                let _ = std::fs::remove_file(&bin_link);
            }

            // Use relative symlinks for portability
            #[cfg(unix)]
            {
                let rel_target = relative_symlink_target_from_parent(&target, &bin_dir);
                std::os::unix::fs::symlink(&rel_target, &bin_link)?;

                // Add execute only (0o111), not full 0o755
                use std::os::unix::fs::PermissionsExt;
                if let Ok(meta) = std::fs::metadata(&target) {
                    let mode = meta.permissions().mode();
                    if mode & 0o111 == 0 {
                        std::fs::set_permissions(
                            &target,
                            std::fs::Permissions::from_mode(mode | 0o111),
                        )?;
                    }
                }
            }

            #[cfg(windows)]
            {
                let target_str = target.to_string_lossy();
                // Validate target path before interpolating into .cmd
                if let Err(reason) = validate_cmd_path(&target_str) {
                    tracing::warn!("bin: skipping .cmd shim for {cmd_name}: {reason}");
                    continue;
                }
                let cmd_content = format!(
                    "@IF EXIST \"%~dp0\\node.exe\" (\n  \"%~dp0\\node.exe\" \"{target_str}\" %*\n) ELSE (\n  node \"{target_str}\" %*\n)",
                );
                let cmd_path = bin_dir.join(format!("{cmd_name}.cmd"));
                std::fs::write(&cmd_path, cmd_content)?;
            }

            tracing::debug!("bin: {cmd_name} -> {}", target.display());
            count += 1;
        }

        // Restore pkg_path to node_modules/ for the next iteration.
        for _ in 0..n {
            pkg_path.pop();
        }
    }

    Ok(count)
}

/// Create `node_modules/.bin/` directory with symlinks to package executables.
///
/// Reads each package's `package.json` for the `"bin"` field and creates
/// executable symlinks in `node_modules/.bin/`.
pub fn create_bin_links(
    node_modules: &Path,
    lpm_dir: &Path,
    packages: &[LinkTarget],
) -> Result<usize, LpmError> {
    let bin_dir = node_modules.join(".bin");
    let mut count = 0;

    for pkg in packages {
        // Audit fix #3: route the wrapper-segment shape
        // through [`LinkTarget::wrapper_segment`] so local-source deps
        // (Directory/Link, with `wrapper_id = Some(_)`, segment shape
        // `<safe>+<wrapper_id>`) resolve correctly. The pre-fix code
        // hardcoded `format!("{safe}@{version}")`, silently producing
        // `node_modules/.bin/<cmd>` shims that pointed at non-existent
        // wrapper paths for any local-source dep that shipped a `bin`
        // field.
        let pkg_dir = lpm_dir
            .join(pkg.wrapper_segment())
            .join("node_modules")
            .join(&pkg.name);

        let pkg_json_path = pkg_dir.join("package.json");
        if !pkg_json_path.exists() {
            continue;
        }

        // Read the bin field from the installed package's package.json
        let pkg_json = match lpm_workspace::read_package_json(&pkg_json_path) {
            Ok(p) => p,
            Err(e) => {
                tracing::debug!(
                    "skipping bin links for {}: failed to parse package.json: {e}",
                    pkg.name
                );
                continue;
            }
        };

        let bin_config = match &pkg_json.bin {
            Some(b) => b,
            None => continue,
        };

        let pkg_name = pkg_json.name.as_deref().unwrap_or(&pkg.name);
        let entries = bin_config.entries(pkg_name);

        if entries.is_empty() {
            continue;
        }

        // Create .bin dir only if we have entries
        std::fs::create_dir_all(&bin_dir)?;

        for (cmd_name, script_path) in &entries {
            // Validate bin name
            if let Err(reason) = validate_bin_name(cmd_name, pkg_name) {
                tracing::warn!("bin: rejecting \"{cmd_name}\" from {pkg_name}: {reason}");
                continue;
            }

            // Validate bin target path (no traversal)
            let target = match validate_bin_target(&pkg_dir, script_path) {
                Ok(t) => t,
                Err(reason) => {
                    tracing::warn!("bin: rejecting {cmd_name} from {pkg_name}: {reason}");
                    continue;
                }
            };

            let bin_link = bin_dir.join(cmd_name);

            // Remove existing link if present
            if bin_link.symlink_metadata().is_ok() {
                let _ = std::fs::remove_file(&bin_link);
            }

            // Use relative symlinks for portability
            #[cfg(unix)]
            {
                let rel_target = relative_symlink_target_from_parent(&target, &bin_dir);
                std::os::unix::fs::symlink(&rel_target, &bin_link)?;

                // Add execute only (0o111), not full 0o755
                use std::os::unix::fs::PermissionsExt;
                if let Ok(meta) = std::fs::metadata(&target) {
                    let mode = meta.permissions().mode();
                    if mode & 0o111 == 0 {
                        std::fs::set_permissions(
                            &target,
                            std::fs::Permissions::from_mode(mode | 0o111),
                        )?;
                    }
                }
            }

            #[cfg(windows)]
            {
                let target_str = target.to_string_lossy();
                // Validate target path before interpolating into .cmd
                if let Err(reason) = validate_cmd_path(&target_str) {
                    tracing::warn!("bin: skipping .cmd shim for {cmd_name}: {reason}");
                    continue;
                }
                let cmd_content = format!(
                    "@IF EXIST \"%~dp0\\node.exe\" (\n  \"%~dp0\\node.exe\" \"{target_str}\" %*\n) ELSE (\n  node \"{target_str}\" %*\n)",
                );
                let cmd_path = bin_dir.join(format!("{cmd_name}.cmd"));
                std::fs::write(&cmd_path, cmd_content)?;
            }

            tracing::debug!("bin: {cmd_name} → {}", target.display());
            count += 1;
        }
    }

    Ok(count)
}

/// Result of the linking operation.
#[derive(Debug)]
pub struct LinkResult {
    /// Number of packages copied from store.
    pub linked: usize,
    /// Number of symlinks created.
    pub symlinked: usize,
    /// Number of bin links created.
    pub bin_linked: usize,
    /// Number of packages skipped (already linked, marker present).
    pub skipped: usize,
    /// Whether a self-referencing symlink was created for the project package.
    pub self_referenced: bool,
    /// **`lpm patch`.** Every physical destination
    /// where a package was materialized in this run. The patch-apply
    /// pass consumes this slice directly so it never has to
    /// reverse-engineer the linker's destination shapes from
    /// `(name, version)` — which would silently miss the
    /// `<project>/.lpm/hoisted/nested/<name>/` shape used in hoisted
    /// mode when a nested loser's parent is itself nested
    /// (`link_packages_hoisted` else branch).
    ///
    /// **Population:**
    /// - Isolated mode: one entry per `(name, version)` pointing at
    ///   `<project>/.lpm/wrappers/<safe_name>@<version>/node_modules/<name>/`.
    /// - Hoisted mode (full re-link path): one entry per hoisted
    ///   package + one per nested package (under hoisted parent OR
    ///   under `<project>/.lpm/hoisted/nested/`).
    /// - Hoisted mode (incremental skip): re-derived from the saved
    ///   `desired_hoisted` / `desired_nested` maps so the patch pass
    ///   still gets a complete location list when the linker took the
    ///   metadata fast path.
    pub materialized: Vec<MaterializedPackage>,
}

/// One physical destination of a linked package. .
///
/// Returned in [`LinkResult::materialized`] so the patch-apply pass
/// always operates on the linker's authoritative location list and
/// stays correct across linker layout changes.
#[derive(Debug, Clone)]
pub struct MaterializedPackage {
    /// Package name (e.g., `"lodash"`, `"@types/node"`).
    pub name: String,
    /// Exact version string (e.g., `"4.17.21"`).
    pub version: String,
    /// Absolute path to the package directory in `node_modules`. The
    /// directory directly contains the package's `package.json` (and
    /// the LPM-internal sentinels `.integrity` /
    /// `.lpm-security.json`, which the patch engine filters out).
    pub destination: PathBuf,
}

/// Materialize a `Source::Directory`
/// (file: directory dep) into the consumer's `.lpm/<wrapper>/...`
/// tree via per-file symlinks pointing at the source realpath.
///
/// Walks `src` recursively; mirrors directory structure as real
/// dirs in `dst`; for every regular file (or non-recursive symlink),
/// creates an absolute symlink at the corresponding path inside
/// `dst` pointing at the source file. The source dir is
/// canonicalized first so the realpath is stable even if `src` is
/// a symlink chain.
///
/// **Why per-file symlinks (not a single dir-symlink at
/// `node_modules/<name>`):** a directory symlink would make the
/// wrapped package's *realpath* `src`, which lives outside the
/// consumer's `node_modules/` tree. Node's module-resolution
/// algorithm walks ancestors from the realpath, so transitive
/// `require('lodash')` from inside the wrapped package would NOT
/// find the consumer's `node_modules/lodash/`. Per-file symlinks
/// keep the realpath inside the wrapper, where ancestor walks
/// still land in the consumer's `node_modules/`.
///
/// **Excludes** `node_modules/` and `.git/` at *any* depth.
/// Source-tree `node_modules/` would let untracked host state
/// silently change install output. `.git/` is huge and meaningless to
/// expose. Other dotfiles/dotdirs are NOT excluded — they may
/// carry intentional package metadata (`.npmrc`, `.npmignore`,
/// dotted bin shims).
///
/// **Symlinks are absolute** (mirrors bun's strategy). Both
/// absolute and relative are equally fragile under moves: identity
/// includes the source path, so any move is already a re-resolve
/// event. Absolute is the simpler default and matches the
/// reference contract.
///
/// Returns the count of symlinks created (used by the caller's
/// `OnePackageResult::symlinks_created` stat).
fn materialize_directory_source(src: &Path, dst: &Path) -> Result<u64, LpmError> {
    let src = src.canonicalize().map_err(|e| {
        LpmError::Io(std::io::Error::new(
            e.kind(),
            format!(
                "phase-59.1 F7: failed to canonicalize directory source {}: {e}",
                src.display()
            ),
        ))
    })?;
    let mut count = 0u64;
    walk_directory_source(&src, &src, dst, &mut count, 0)?;
    Ok(count)
}

/// Maximum directory-source walk depth.
///
/// **Round-7 audit response.** Pre-round-7 `walk_directory_source` was
/// unbounded — a maliciously-deep or accidentally-cyclic source tree
/// (e.g., a Yarn-style nested workspace symlink resolved away by
/// `canonicalize` at the top of [`materialize_directory_source`] but
/// then deeper symlinks inside the tree pointing back out) could blow
/// the stack on Unix or exhaust the filesystem walker on Windows.
/// 256 is two orders of magnitude beyond what any real JS package
/// uses (typical max is ~10–20); legitimate trees never hit it.
///
/// Independent of F7a's `max_depth=3` in
/// `install_state::collect_file_link_manifest_bytes` — that's the
/// install-hash freshness walker (depth-3 = "consumer + 3 levels of
/// transitive local sources"). This is the linker's structural walk
/// inside ONE source's tree.
const MAX_DIRECTORY_SOURCE_DEPTH: usize = 256;

fn walk_directory_source(
    source_root: &Path,
    src: &Path,
    dst: &Path,
    count: &mut u64,
    depth: usize,
) -> Result<(), LpmError> {
    if depth > MAX_DIRECTORY_SOURCE_DEPTH {
        return Err(LpmError::Io(std::io::Error::other(format!(
            "phase-59.1 F7: directory source exceeds maximum walk depth ({MAX_DIRECTORY_SOURCE_DEPTH}) at {}",
            src.display()
        ))));
    }
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let name = entry.file_name();
        // Recursively exclude node_modules + .git from any depth.
        if name == "node_modules" || name == ".git" {
            continue;
        }
        let entry_src = entry.path();
        let entry_dst = dst.join(&name);
        let metadata = std::fs::symlink_metadata(&entry_src)?;
        let ft = metadata.file_type();
        if ft.is_dir() {
            walk_directory_source(source_root, &entry_src, &entry_dst, count, depth + 1)?;
        } else if ft.is_file() || ft.is_symlink() {
            // For symlinks, dereference once via canonicalize so the
            // wrapper exposes the file's real content rather than a
            // chain. canonicalize on a missing/broken symlink errors;
            // fall back to the entry's lexical path so a broken link
            // in the source doesn't fail the whole materialize (the
            // wrapper will then point at the same broken target,
            // matching what Node would see in the source).
            let abs_target = entry_src
                .canonicalize()
                .unwrap_or_else(|_| entry_src.clone());
            // **Round-7 audit response — symlink-escape warn.** When a
            // symlink in the source tree resolves OUTSIDE the source's
            // own realpath (e.g., `a/b → ../../etc`), the wrapper
            // exposes content the consumer probably didn't intend to
            // import. Node never re-follows wrapper symlinks during
            // module resolution (the wrapper is the realpath as far as
            // require() is concerned), so the escape is inert at
            // runtime — but it's worth surfacing so a packager can see
            // they're shipping a path that won't survive a tarball
            // round-trip. `tracing::warn!` lands in `lpm install -v`
            // output; default-level installs see nothing, matching the
            // "passes through what Node would see" contract.
            if ft.is_symlink() && !abs_target.starts_with(source_root) {
                tracing::warn!(
                    source = %source_root.display(),
                    symlink = %entry_src.display(),
                    target = %abs_target.display(),
                    "phase-59.1 F7: symlink escapes directory source root; \
                     exposing target as-is (matches Node resolution from the source itself)",
                );
            }
            create_symlink_or_junction(&abs_target, &entry_dst)?;
            *count += 1;
        }
        // Other file types (devices, sockets, fifos) silently
        // skipped — they have no business in a JS package.
    }
    Ok(())
}

/// Recursively link a directory from the global store into node_modules.
///
/// Strategy priority:
/// 1. macOS APFS: `clonefile()` (copy-on-write, instant, zero disk cost until modified)
/// 2. Hardlink (same filesystem, zero disk cost, shared inode)
/// 3. Copy (fallback for cross-device or permissions)
fn link_dir_recursive(src: &Path, dst: &Path) -> Result<(), LpmError> {
    // On macOS, try clonefile first (copies entire directory tree as CoW in one syscall)
    #[cfg(target_os = "macos")]
    {
        if try_clonefile(src, dst) {
            return Ok(());
        }
    }

    // Fallback: file-by-file hardlink/copy
    std::fs::create_dir_all(dst)?;

    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());

        if src_path.is_dir() {
            link_dir_recursive(&src_path, &dst_path)?;
        } else {
            // Try hardlink first (instant, zero disk cost on same filesystem)
            if let Err(e) = std::fs::hard_link(&src_path, &dst_path) {
                // **Round-7 audit response — trace fallback.** Hardlink
                // refusals fall into a few classes: cross-volume
                // (EXDEV, common in container/CI setups), permission
                // (EPERM, rare), Windows junctions inside the CAS
                // store (silent fallback otherwise). The fallback to
                // `std::fs::copy` is correct in every case but turns a
                // CoW/hardlink-cheap install into a per-file disk
                // copy, which is a real perf cliff worth surfacing
                // under `lpm install -v`.
                tracing::trace!(
                    src = %src_path.display(),
                    dst = %dst_path.display(),
                    error = %e,
                    "link_dir_recursive: hardlink failed, falling back to copy",
                );
                std::fs::copy(&src_path, &dst_path)?;
            }
        }
    }

    Ok(())
}

/// Try to use macOS `clonefile()` syscall for instant copy-on-write.
/// Returns true if successful, false if not (caller should fall back).
#[cfg(target_os = "macos")]
fn try_clonefile(src: &Path, dst: &Path) -> bool {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let src_c = match CString::new(src.as_os_str().as_bytes()) {
        Ok(c) => c,
        Err(_) => return false,
    };
    let dst_c = match CString::new(dst.as_os_str().as_bytes()) {
        Ok(c) => c,
        Err(_) => return false,
    };

    // Clonefile(src, dst, flags) — flag 0 = no special flags
    // Returns 0 on success, -1 on failure
    let result = unsafe { libc::clonefile(src_c.as_ptr(), dst_c.as_ptr(), 0) };

    if result == 0 {
        tracing::debug!("clonefile: {} → {}", src.display(), dst.display());
        true
    } else {
        false
    }
}

// Declare the libc clonefile function for macOS
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

/// Follow-up — break shared inodes inside a live per-package
/// directory so subsequent writes don't propagate into the global
/// content-addressable store at `~/.lpm/store/v1/`.
///
/// **Why this exists.** [`link_dir_recursive`] uses `std::fs::hard_link`
/// on Linux. A hard link makes the live file and the store file
/// share an inode, so a lifecycle script that mutates a file in
/// its own package directory mutates the store too. macOS uses
/// `clonefile()` (CoW), which makes writes independent at link
/// time, and Windows always copies, so the bug is Linux-specific.
///
/// **What it does.** Walks `dir` recursively. For every regular file
/// with `nlink > 1`, copies the content to a sibling temp file and
/// atomically renames it back over the original. After the rename
/// the live entry points at a fresh inode (nlink = 1) while the
/// store entry still points at the original inode (nlink decremented
/// by 1). Subsequent writes through the live path no longer reach
/// the store.
///
/// **Why this is fast where it matters.** `std::fs::copy` on Linux
/// uses the `copy_file_range(2)` syscall, which the kernel implements
/// as a copy-on-write reflink on filesystems that support it
/// (Btrfs, XFS with `reflink=1`, F2FS, OverlayFS-on-Btrfs) and as a
/// kernel-side bulk copy elsewhere (ext4). So on CoW filesystems the
/// detach is essentially free; on ext4 it pays the IO cost of one
/// copy of each scripted package's tree, which is bounded by the
/// fact that only packages with lifecycle scripts hit this path
/// (~10% of dependencies in a typical install).
///
/// **Symlinks are preserved**, not detached. The isolated linker
/// uses symlinks under `<project>/node_modules/.lpm/<safe>@<ver>/node_modules/`
/// to expose a package's siblings — breaking those would corrupt the
/// dep graph. We use [`std::fs::symlink_metadata`] to inspect file
/// type without following links.
///
/// **No-op on macOS / Windows.** macOS already gets CoW from
/// `clonefile()`; Windows already gets independent copies. The
/// function compiles to a constant-zero return on those platforms.
///
/// Returns the number of files detached (always 0 on non-Linux,
/// 0 on Linux when every file already had `nlink == 1`).
pub fn detach_package_hardlinks(dir: &Path) -> Result<usize, LpmError> {
    #[cfg(target_os = "linux")]
    {
        detach_hardlinks_recursive(dir)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = dir;
        Ok(0)
    }
}

#[cfg(target_os = "linux")]
const DETACH_TMP_PREFIX: &str = ".lpm-detach-tmp-";

#[cfg(target_os = "linux")]
fn detach_hardlinks_recursive(dir: &Path) -> Result<usize, LpmError> {
    use std::os::unix::fs::MetadataExt;

    // Materialize the entry list before we start mutating the dir.
    // Doing so lets us (a) sweep leftover temp files from a prior
    // interrupted detach without invalidating the iterator, and
    // (b) keep ownership of OsString file names independent of the
    // open dir handle.
    let entries: Vec<std::fs::DirEntry> = std::fs::read_dir(dir)?.collect::<Result<_, _>>()?;

    let mut detached = 0usize;
    for entry in entries {
        let path = entry.path();
        let file_name_os = entry.file_name();
        let file_name = file_name_os.to_string_lossy();

        // Sweep leftover temp files from a previous run that crashed
        // between `fs::copy` and `fs::rename`. These have nlink == 1
        // (fresh-from-copy) so the detach loop below would skip them,
        // leaving them visible to Node's `readdir` calls inside the
        // package directory. Best-effort: a remove failure here is
        // not fatal — surface it but keep going. A successful sweep
        // is logged at debug so an operator chasing "where did file
        // X go" has a paper trail without polluting normal output.
        if file_name.starts_with(DETACH_TMP_PREFIX) {
            match std::fs::remove_file(&path) {
                Ok(()) => tracing::debug!("swept stale detach temp file: {}", path.display()),
                Err(e) => tracing::warn!(
                    "could not remove stale detach temp file {}: {e}",
                    path.display()
                ),
            }
            continue;
        }

        // `symlink_metadata` does NOT follow symlinks — required so
        // sibling-dep symlinks under `.lpm/<safe>@<ver>/node_modules/`
        // are left alone (their targets are other packages' live
        // dirs, which get detached by their own pre-script pass if
        // they themselves run scripts).
        let metadata = std::fs::symlink_metadata(&path)?;
        let file_type = metadata.file_type();

        if file_type.is_symlink() {
            continue;
        }
        if file_type.is_dir() {
            detached += detach_hardlinks_recursive(&path)?;
            continue;
        }
        if !file_type.is_file() {
            continue;
        }
        if metadata.nlink() <= 1 {
            // Already independent (could be a copy from the
            // cross-device fallback in `link_dir_recursive`, or a
            // file we detached in a previous run). Idempotent skip.
            continue;
        }

        // Build a temp filename that's reserved for our use
        // (`.lpm-detach-tmp-<ino>`) so it (a) won't collide with any
        // package file, (b) is per-inode unique inside the dir.
        let temp_name = format!("{DETACH_TMP_PREFIX}{}", metadata.ino());
        let temp_path = path.with_file_name(temp_name);

        // Copy → rename. `fs::copy` creates a new inode populated
        // with the source bytes (using `copy_file_range` on Linux),
        // and `fs::rename` is atomic when src + dst are on the same
        // filesystem (which they are, both under `dir`). After this
        // the original directory entry points at the new inode and
        // the store's entry still points at the old one.
        std::fs::copy(&path, &temp_path)?;
        std::fs::rename(&temp_path, &path)?;
        detached += 1;
    }
    Ok(detached)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_fake_store_package(dir: &Path, name: &str) -> PathBuf {
        let pkg_dir = dir.join(name);
        std::fs::create_dir_all(&pkg_dir).unwrap();
        std::fs::write(
            pkg_dir.join("package.json"),
            format!("{{\"name\":\"{name}\"}}"),
        )
        .unwrap();
        std::fs::write(pkg_dir.join("index.js"), "module.exports = {}").unwrap();
        pkg_dir
    }

    #[test]
    fn link_single_direct_dep() {
        let store_dir = tempfile::tempdir().unwrap();
        let project_dir = tempfile::tempdir().unwrap();

        let store_path = create_fake_store_package(store_dir.path(), "foo");

        let packages = vec![LinkTarget {
            name: "foo".to_string(),
            version: "1.0.0".to_string(),
            store_path,
            dependencies: vec![],
            aliases: HashMap::new(),
            is_direct: true,
            root_link_names: None,
            wrapper_id: None,
            materialization: Materialization::CasBacked,
            peers: Vec::new(),
            patch_fingerprint: None,
        }];

        let result = link_packages(project_dir.path(), &packages, false, None).unwrap();
        assert_eq!(result.linked, 1);

        // Root symlink exists
        let root_link = project_dir.path().join("node_modules/foo");
        assert!(root_link.symlink_metadata().is_ok());

        // Can read through symlink
        assert!(root_link.join("package.json").exists());
    }

    #[test]
    fn link_with_transitive_dep() {
        let store_dir = tempfile::tempdir().unwrap();
        let project_dir = tempfile::tempdir().unwrap();

        let express_store = create_fake_store_package(store_dir.path(), "express");
        let debug_store = create_fake_store_package(store_dir.path(), "debug");

        let packages = vec![
            LinkTarget {
                name: "express".to_string(),
                version: "4.22.1".to_string(),
                store_path: express_store,
                dependencies: vec![("debug".to_string(), "2.6.9".to_string())],
                aliases: HashMap::new(),
                is_direct: true,
                root_link_names: None,
                wrapper_id: None,
                materialization: Materialization::CasBacked,
                peers: Vec::new(),
                patch_fingerprint: None,
            },
            LinkTarget {
                name: "debug".to_string(),
                version: "2.6.9".to_string(),
                store_path: debug_store,
                dependencies: vec![],
                aliases: HashMap::new(),
                is_direct: false,
                root_link_names: None,
                wrapper_id: None,
                materialization: Materialization::CasBacked,
                peers: Vec::new(),
                patch_fingerprint: None,
            },
        ];

        let result = link_packages(project_dir.path(), &packages, false, None).unwrap();

        // Express is accessible from root
        assert!(
            project_dir
                .path()
                .join("node_modules/express")
                .symlink_metadata()
                .is_ok()
        );

        // Debug is NOT in root (it's transitive)
        assert!(
            project_dir
                .path()
                .join("node_modules/debug")
                .symlink_metadata()
                .is_err()
        );

        // Debug IS accessible from express's node_modules
        let express_debug = project_dir
            .path()
            .join(".lpm/wrappers/express@4.22.1/node_modules/debug");
        assert!(express_debug.symlink_metadata().is_ok());

        assert!(result.linked >= 2);
    }

    #[test]
    fn lpm_dir_created() {
        let store_dir = tempfile::tempdir().unwrap();
        let project_dir = tempfile::tempdir().unwrap();

        let store_path = create_fake_store_package(store_dir.path(), "x");

        link_packages(
            project_dir.path(),
            &[LinkTarget {
                name: "x".to_string(),
                version: "1.0.0".to_string(),
                store_path,
                dependencies: vec![],
                aliases: HashMap::new(),
                is_direct: true,
                root_link_names: None,
                wrapper_id: None,
                materialization: Materialization::CasBacked,
                peers: Vec::new(),
                patch_fingerprint: None,
            }],
            false,
            None,
        )
        .unwrap();

        // Wrapper root is now a project-root sibling.
        assert!(project_dir.path().join(".lpm/wrappers").is_dir());
    }

    fn create_fake_store_package_with_bin(dir: &Path, name: &str, bin_field: &str) -> PathBuf {
        let pkg_dir = dir.join(name);
        std::fs::create_dir_all(&pkg_dir).unwrap();
        std::fs::write(
            pkg_dir.join("package.json"),
            format!("{{\"name\":\"{name}\",\"bin\":{bin_field}}}"),
        )
        .unwrap();
        std::fs::write(
            pkg_dir.join("cli.js"),
            "#!/usr/bin/env node\nconsole.log('hi')",
        )
        .unwrap();
        pkg_dir
    }

    #[test]
    fn bin_links_created_for_string_bin() {
        let store_dir = tempfile::tempdir().unwrap();
        let project_dir = tempfile::tempdir().unwrap();

        let store_path =
            create_fake_store_package_with_bin(store_dir.path(), "my-tool", "\"./cli.js\"");

        let packages = vec![LinkTarget {
            name: "my-tool".to_string(),
            version: "1.0.0".to_string(),
            store_path,
            dependencies: vec![],
            aliases: HashMap::new(),
            is_direct: true,
            root_link_names: None,
            wrapper_id: None,
            materialization: Materialization::CasBacked,
            peers: Vec::new(),
            patch_fingerprint: None,
        }];

        let result = link_packages(project_dir.path(), &packages, false, None).unwrap();
        assert_eq!(result.bin_linked, 1);

        let bin_link = project_dir.path().join("node_modules/.bin/my-tool");
        assert!(
            bin_link.symlink_metadata().is_ok(),
            ".bin/my-tool should exist"
        );
    }

    #[test]
    fn bin_links_created_for_map_bin() {
        let store_dir = tempfile::tempdir().unwrap();
        let project_dir = tempfile::tempdir().unwrap();

        let store_path = create_fake_store_package_with_bin(
            store_dir.path(),
            "multi-bin",
            "{\"cmd-a\": \"./cli.js\", \"cmd-b\": \"./cli.js\"}",
        );

        let packages = vec![LinkTarget {
            name: "multi-bin".to_string(),
            version: "2.0.0".to_string(),
            store_path,
            dependencies: vec![],
            aliases: HashMap::new(),
            is_direct: true,
            root_link_names: None,
            wrapper_id: None,
            materialization: Materialization::CasBacked,
            peers: Vec::new(),
            patch_fingerprint: None,
        }];

        let result = link_packages(project_dir.path(), &packages, false, None).unwrap();
        assert_eq!(result.bin_linked, 2);

        assert!(
            project_dir
                .path()
                .join("node_modules/.bin/cmd-a")
                .symlink_metadata()
                .is_ok()
        );
        assert!(
            project_dir
                .path()
                .join("node_modules/.bin/cmd-b")
                .symlink_metadata()
                .is_ok()
        );
    }

    #[test]
    fn no_bin_dir_without_bins() {
        let store_dir = tempfile::tempdir().unwrap();
        let project_dir = tempfile::tempdir().unwrap();

        // Package without "bin" field
        let store_path = create_fake_store_package(store_dir.path(), "no-bin");

        let packages = vec![LinkTarget {
            name: "no-bin".to_string(),
            version: "1.0.0".to_string(),
            store_path,
            dependencies: vec![],
            aliases: HashMap::new(),
            is_direct: true,
            root_link_names: None,
            wrapper_id: None,
            materialization: Materialization::CasBacked,
            peers: Vec::new(),
            patch_fingerprint: None,
        }];

        let result = link_packages(project_dir.path(), &packages, false, None).unwrap();
        assert_eq!(result.bin_linked, 0);
        assert!(!project_dir.path().join("node_modules/.bin").exists());
    }

    #[test]
    fn incremental_link_creates_marker() {
        let store_dir = tempfile::tempdir().unwrap();
        let project_dir = tempfile::tempdir().unwrap();

        let store_path = create_fake_store_package(store_dir.path(), "foo");

        let packages = vec![LinkTarget {
            name: "foo".to_string(),
            version: "1.0.0".to_string(),
            store_path,
            dependencies: vec![],
            aliases: HashMap::new(),
            is_direct: true,
            root_link_names: None,
            wrapper_id: None,
            materialization: Materialization::CasBacked,
            peers: Vec::new(),
            patch_fingerprint: None,
        }];

        link_packages(project_dir.path(), &packages, false, None).unwrap();

        // Marker file should exist after linking
        let marker = project_dir.path().join(".lpm/wrappers/foo@1.0.0/.linked");
        assert!(
            marker.exists(),
            ".linked marker should be created after linking"
        );
    }

    #[test]
    fn incremental_link_skips_if_marker_present() {
        let store_dir = tempfile::tempdir().unwrap();
        let project_dir = tempfile::tempdir().unwrap();

        let store_path = create_fake_store_package(store_dir.path(), "bar");

        let packages = vec![LinkTarget {
            name: "bar".to_string(),
            version: "2.0.0".to_string(),
            store_path,
            dependencies: vec![],
            aliases: HashMap::new(),
            is_direct: true,
            root_link_names: None,
            wrapper_id: None,
            materialization: Materialization::CasBacked,
            peers: Vec::new(),
            patch_fingerprint: None,
        }];

        // First link — creates everything
        let result1 = link_packages(project_dir.path(), &packages, false, None).unwrap();
        assert_eq!(result1.linked, 1);
        assert_eq!(result1.skipped, 0);

        // Second link — marker present, should skip
        let result2 = link_packages(project_dir.path(), &packages, false, None).unwrap();
        assert_eq!(result2.linked, 0);
        assert_eq!(result2.skipped, 1);

        // Files still accessible through symlinks
        assert!(
            project_dir
                .path()
                .join("node_modules/bar/package.json")
                .exists()
        );
    }

    #[test]
    fn incremental_link_relinks_if_marker_missing() {
        let store_dir = tempfile::tempdir().unwrap();
        let project_dir = tempfile::tempdir().unwrap();

        let store_path = create_fake_store_package(store_dir.path(), "baz");

        let packages = vec![LinkTarget {
            name: "baz".to_string(),
            version: "3.0.0".to_string(),
            store_path,
            dependencies: vec![],
            aliases: HashMap::new(),
            is_direct: true,
            root_link_names: None,
            wrapper_id: None,
            materialization: Materialization::CasBacked,
            peers: Vec::new(),
            patch_fingerprint: None,
        }];

        // First link — creates marker
        let result1 = link_packages(project_dir.path(), &packages, false, None).unwrap();
        assert_eq!(result1.linked, 1);

        // Delete marker to simulate corruption/manual cleanup
        let marker = project_dir.path().join(".lpm/wrappers/baz@3.0.0/.linked");
        assert!(marker.exists());
        std::fs::remove_file(&marker).unwrap();

        // Remove the linked package dir to force re-link
        let pkg_dir = project_dir
            .path()
            .join(".lpm/wrappers/baz@3.0.0/node_modules/baz");
        std::fs::remove_dir_all(&pkg_dir).unwrap();

        // Re-link — marker gone, should re-link
        let result2 = link_packages(project_dir.path(), &packages, false, None).unwrap();
        assert_eq!(result2.linked, 1);
        assert_eq!(result2.skipped, 0);

        // Marker should be re-created
        assert!(marker.exists());
    }

    #[test]
    fn force_relinks_despite_marker() {
        let store_dir = tempfile::tempdir().unwrap();
        let project_dir = tempfile::tempdir().unwrap();

        let store_path = create_fake_store_package(store_dir.path(), "qux");

        let packages = vec![LinkTarget {
            name: "qux".to_string(),
            version: "1.0.0".to_string(),
            store_path,
            dependencies: vec![],
            aliases: HashMap::new(),
            is_direct: true,
            root_link_names: None,
            wrapper_id: None,
            materialization: Materialization::CasBacked,
            peers: Vec::new(),
            patch_fingerprint: None,
        }];

        // First link
        link_packages(project_dir.path(), &packages, false, None).unwrap();
        let marker = project_dir.path().join(".lpm/wrappers/qux@1.0.0/.linked");
        assert!(marker.exists());

        // Force re-link — should NOT skip despite marker
        let result = link_packages(project_dir.path(), &packages, true, None).unwrap();
        assert_eq!(result.skipped, 0, "force should not skip any packages");
        assert_eq!(
            result.linked, 1,
            "force should actually re-link the package"
        );
    }

    #[test]
    fn force_relink_actually_recreates_files() {
        let store_dir = tempfile::tempdir().unwrap();
        let project_dir = tempfile::tempdir().unwrap();

        let store_path = create_fake_store_package(store_dir.path(), "force-test");

        let packages = vec![LinkTarget {
            name: "force-test".to_string(),
            version: "2.0.0".to_string(),
            store_path,
            dependencies: vec![],
            aliases: HashMap::new(),
            is_direct: true,
            root_link_names: None,
            wrapper_id: None,
            materialization: Materialization::CasBacked,
            peers: Vec::new(),
            patch_fingerprint: None,
        }];

        // First link
        let result1 = link_packages(project_dir.path(), &packages, false, None).unwrap();
        assert_eq!(result1.linked, 1);
        assert_eq!(result1.skipped, 0);

        // Second link without force — should skip
        let result2 = link_packages(project_dir.path(), &packages, false, None).unwrap();
        assert_eq!(result2.linked, 0);
        assert_eq!(result2.skipped, 1);

        // Third link with force — should re-link
        let result3 = link_packages(project_dir.path(), &packages, true, None).unwrap();
        assert_eq!(result3.linked, 1, "force should re-link the package");
        assert_eq!(result3.skipped, 0, "force should not skip any packages");
    }

    #[test]
    fn force_relink_hoisted_cleans_and_recreates() {
        let store_dir = tempfile::tempdir().unwrap();
        let project_dir = tempfile::tempdir().unwrap();

        let store_path = create_fake_store_package(store_dir.path(), "hoisted-force");

        let packages = vec![LinkTarget {
            name: "hoisted-force".to_string(),
            version: "1.0.0".to_string(),
            store_path,
            dependencies: vec![],
            aliases: HashMap::new(),
            is_direct: true,
            root_link_names: None,
            wrapper_id: None,
            materialization: Materialization::CasBacked,
            peers: Vec::new(),
            patch_fingerprint: None,
        }];

        // First link in hoisted mode
        let result1 = link_packages_hoisted(project_dir.path(), &packages, false, None).unwrap();
        assert!(result1.linked > 0);

        let hoisted_pkg = project_dir
            .path()
            .join("node_modules")
            .join("hoisted-force");
        assert!(hoisted_pkg.exists(), "package should be hoisted to root");

        // Force re-link in hoisted mode — should clean and recreate
        let result2 = link_packages_hoisted(project_dir.path(), &packages, true, None).unwrap();
        assert!(result2.linked > 0, "force should re-link in hoisted mode");
        assert!(
            hoisted_pkg.exists(),
            "package should still exist after force re-link"
        );
    }

    #[test]
    fn self_reference_created_for_named_package() {
        let store_dir = tempfile::tempdir().unwrap();
        let project_dir = tempfile::tempdir().unwrap();

        let store_path = create_fake_store_package(store_dir.path(), "foo");

        let packages = vec![LinkTarget {
            name: "foo".to_string(),
            version: "1.0.0".to_string(),
            store_path,
            dependencies: vec![],
            aliases: HashMap::new(),
            is_direct: true,
            root_link_names: None,
            wrapper_id: None,
            materialization: Materialization::CasBacked,
            peers: Vec::new(),
            patch_fingerprint: None,
        }];

        let result =
            link_packages(project_dir.path(), &packages, false, Some("my-project")).unwrap();
        assert!(result.self_referenced);

        // Self-reference symlink should exist
        let self_link = project_dir.path().join("node_modules/my-project");
        assert!(
            self_link.symlink_metadata().is_ok(),
            "self-reference symlink should exist"
        );
    }

    #[test]
    fn self_reference_scoped_creates_scope_dir() {
        let store_dir = tempfile::tempdir().unwrap();
        let project_dir = tempfile::tempdir().unwrap();

        let store_path = create_fake_store_package(store_dir.path(), "foo");

        let packages = vec![LinkTarget {
            name: "foo".to_string(),
            version: "1.0.0".to_string(),
            store_path,
            dependencies: vec![],
            aliases: HashMap::new(),
            is_direct: true,
            root_link_names: None,
            wrapper_id: None,
            materialization: Materialization::CasBacked,
            peers: Vec::new(),
            patch_fingerprint: None,
        }];

        let result = link_packages(
            project_dir.path(),
            &packages,
            false,
            Some("@myorg/my-project"),
        )
        .unwrap();
        assert!(result.self_referenced);

        // Scope directory should be created
        let scope_dir = project_dir.path().join("node_modules/@myorg");
        assert!(scope_dir.is_dir(), "@myorg scope dir should exist");

        // Self-reference symlink should exist
        let self_link = project_dir.path().join("node_modules/@myorg/my-project");
        assert!(
            self_link.symlink_metadata().is_ok(),
            "scoped self-reference symlink should exist"
        );
    }

    #[test]
    fn no_self_reference_without_name() {
        let store_dir = tempfile::tempdir().unwrap();
        let project_dir = tempfile::tempdir().unwrap();

        let store_path = create_fake_store_package(store_dir.path(), "foo");

        let packages = vec![LinkTarget {
            name: "foo".to_string(),
            version: "1.0.0".to_string(),
            store_path,
            dependencies: vec![],
            aliases: HashMap::new(),
            is_direct: true,
            root_link_names: None,
            wrapper_id: None,
            materialization: Materialization::CasBacked,
            peers: Vec::new(),
            patch_fingerprint: None,
        }];

        let result = link_packages(project_dir.path(), &packages, false, None).unwrap();
        assert!(!result.self_referenced);
    }

    #[test]
    fn self_reference_skipped_when_dep_exists_with_same_name() {
        let store_dir = tempfile::tempdir().unwrap();
        let project_dir = tempfile::tempdir().unwrap();

        let store_path = create_fake_store_package(store_dir.path(), "conflicting");

        // Direct dep has the same name as the self-reference
        let packages = vec![LinkTarget {
            name: "conflicting".to_string(),
            version: "1.0.0".to_string(),
            store_path,
            dependencies: vec![],
            aliases: HashMap::new(),
            is_direct: true,
            root_link_names: None,
            wrapper_id: None,
            materialization: Materialization::CasBacked,
            peers: Vec::new(),
            patch_fingerprint: None,
        }];

        // Self-package name matches a direct dep — dep should win
        let result =
            link_packages(project_dir.path(), &packages, false, Some("conflicting")).unwrap();
        assert!(
            !result.self_referenced,
            "self-reference should be skipped when dep occupies the name"
        );

        // The link should point to the dep, not the project root
        let link = project_dir.path().join("node_modules/conflicting");
        assert!(link.symlink_metadata().is_ok());
    }

    // ---- Hoisted mode tests ----

    #[test]
    fn hoisted_mode_flattens_all_packages() {
        let store_dir = tempfile::tempdir().unwrap();
        let project_dir = tempfile::tempdir().unwrap();

        let express_store = create_fake_store_package(store_dir.path(), "express");
        let debug_store = create_fake_store_package(store_dir.path(), "debug");
        let ms_store = create_fake_store_package(store_dir.path(), "ms");

        let packages = vec![
            LinkTarget {
                name: "express".to_string(),
                version: "4.22.1".to_string(),
                store_path: express_store,
                dependencies: vec![("debug".to_string(), "2.6.9".to_string())],
                aliases: HashMap::new(),
                is_direct: true,
                root_link_names: None,
                wrapper_id: None,
                materialization: Materialization::CasBacked,
                peers: Vec::new(),
                patch_fingerprint: None,
            },
            LinkTarget {
                name: "debug".to_string(),
                version: "2.6.9".to_string(),
                store_path: debug_store,
                dependencies: vec![("ms".to_string(), "2.0.0".to_string())],
                aliases: HashMap::new(),
                is_direct: false,
                root_link_names: None,
                wrapper_id: None,
                materialization: Materialization::CasBacked,
                peers: Vec::new(),
                patch_fingerprint: None,
            },
            LinkTarget {
                name: "ms".to_string(),
                version: "2.0.0".to_string(),
                store_path: ms_store,
                dependencies: vec![],
                aliases: HashMap::new(),
                is_direct: false,
                root_link_names: None,
                wrapper_id: None,
                materialization: Materialization::CasBacked,
                peers: Vec::new(),
                patch_fingerprint: None,
            },
        ];

        let result = link_packages_hoisted(project_dir.path(), &packages, false, None).unwrap();
        assert_eq!(result.linked, 3);

        // All packages should be at root node_modules/
        assert!(project_dir.path().join("node_modules/express").exists());
        assert!(project_dir.path().join("node_modules/debug").exists());
        assert!(project_dir.path().join("node_modules/ms").exists());
    }

    #[test]
    fn hoisted_mode_creates_top_level_dir_per_alias_root_link_name() {
        // Regression test: alias-aware root-slot claiming.
        //
        // Pre-fix `link_packages_hoisted` claimed root slots strictly
        // by `pkg.name` (canonical/registry identity). For an
        // `npm:<target>@<range>` alias declared at root level,
        // `LinkTarget.root_link_names` carries the LOCAL alias
        // surface, which can differ from `pkg.name`. Pre-fix the
        // alias slots were never claimed → no
        // `node_modules/<alias>/` directory → `require('<alias>')`
        // hard-failed at runtime.
        //
        // Surfaced by `bench/audit-fixtures/source-kind/npm-aliases`
        // under `LPM_STORE_VERSION=v1` + hoisted: 4 of 5 require()s
        // failed because the alias dirs were missing. v2 hoisted
        // worked because `v2.rs::root_link_names` already iterated
        // the alias surface at the symlink-emit level — v1's
        // hoisting algorithm needed the same generalization at the
        // slot-claim level.
        //
        // This test pins the v1 contract: a single LinkTarget with
        // multiple `root_link_names` entries produces a top-level
        // `node_modules/<name>/` directory FOR EACH name, all
        // backed by the same store path. The alias-rich npm-aliases
        // audit fixture exercises the multi-store-package shape;
        // this test isolates the slot-claim logic without the audit
        // harness scaffolding so a future regression fires here
        // first.
        let store_dir = tempfile::tempdir().unwrap();
        let project_dir = tempfile::tempdir().unwrap();
        let lodash_store = create_fake_store_package(store_dir.path(), "lodash");

        // One LinkTarget for lodash@4.18.1 with FOUR root link slots:
        // the canonical name + three npm-alias names. Mirrors what
        // `resolved_to_install_packages` produces for a project
        // that declares `lodash, lodash-a: npm:lodash, lodash-b:
        // npm:lodash, lodash-c: npm:lodash`.
        let packages = vec![LinkTarget {
            name: "lodash".to_string(),
            version: "4.18.1".to_string(),
            store_path: lodash_store,
            dependencies: vec![],
            aliases: HashMap::new(),
            is_direct: true,
            root_link_names: Some(vec![
                "lodash".to_string(),
                "lodash-a".to_string(),
                "lodash-b".to_string(),
                "lodash-c".to_string(),
            ]),
            wrapper_id: None,
            materialization: Materialization::CasBacked,
            peers: Vec::new(),
            patch_fingerprint: None,
        }];

        let result = link_packages_hoisted(project_dir.path(), &packages, false, None).unwrap();
        // Four top-level slots → four link operations.
        assert_eq!(
            result.linked, 4,
            "v1 hoisted must materialize each root_link_names entry as a \
             distinct top-level node_modules/<name>/ directory; pre-fix \
             only the canonical (`lodash`) was created and the three \
             aliases lost their dirs"
        );

        for slot in ["lodash", "lodash-a", "lodash-b", "lodash-c"] {
            let path = project_dir.path().join("node_modules").join(slot);
            assert!(
                path.exists(),
                "node_modules/{slot}/ must exist after install — pre-fix \
                 only `lodash` survived; aliases were silently dropped"
            );
            // Each alias dir must carry the canonical's package.json
            // contents (the alias is just a different on-disk name
            // for the same source bytes).
            let pj = path.join("package.json");
            assert!(
                pj.exists(),
                "node_modules/{slot}/package.json must be the canonical \
                 lodash manifest — alias slots are different on-disk \
                 names backed by the same store entry"
            );
        }

        // Sanity: aliased deps are NOT direct UNDER the alias name —
        // the canonical's `is_direct = true` is preserved through
        // the slot expansion. (Materialized records use `pkg.name`
        // for identity, so all 4 destinations share `name=lodash`.)
        assert_eq!(result.materialized.len(), 4);
        assert!(
            result.materialized.iter().all(|m| m.name == "lodash"),
            "all 4 MaterializedPackage entries must share the canonical \
             name (`lodash`) — the slot only affects on-disk path, not \
             package identity used by patches and lifecycle scripts"
        );
    }

    #[test]
    fn hoisted_mode_nests_conflicts() {
        let store_dir = tempfile::tempdir().unwrap();
        let project_dir = tempfile::tempdir().unwrap();

        let express_store = create_fake_store_package(store_dir.path(), "express");
        let debug_v2_store = create_fake_store_package(store_dir.path(), "debug-v2");
        let debug_v3_store = create_fake_store_package(store_dir.path(), "debug-v3");
        let other_store = create_fake_store_package(store_dir.path(), "other");

        let packages = vec![
            LinkTarget {
                name: "express".to_string(),
                version: "4.22.1".to_string(),
                store_path: express_store,
                dependencies: vec![("debug".to_string(), "2.6.9".to_string())],
                aliases: HashMap::new(),
                is_direct: true,
                root_link_names: None,
                wrapper_id: None,
                materialization: Materialization::CasBacked,
                peers: Vec::new(),
                patch_fingerprint: None,
            },
            LinkTarget {
                name: "debug".to_string(),
                version: "2.6.9".to_string(),
                store_path: debug_v2_store,
                dependencies: vec![],
                aliases: HashMap::new(),
                is_direct: false,
                root_link_names: None,
                wrapper_id: None,
                materialization: Materialization::CasBacked,
                peers: Vec::new(),
                patch_fingerprint: None,
            },
            LinkTarget {
                name: "other".to_string(),
                version: "1.0.0".to_string(),
                store_path: other_store,
                dependencies: vec![("debug".to_string(), "3.0.0".to_string())],
                aliases: HashMap::new(),
                is_direct: true,
                root_link_names: None,
                wrapper_id: None,
                materialization: Materialization::CasBacked,
                peers: Vec::new(),
                patch_fingerprint: None,
            },
            LinkTarget {
                name: "debug".to_string(),
                version: "3.0.0".to_string(),
                store_path: debug_v3_store,
                dependencies: vec![],
                aliases: HashMap::new(),
                is_direct: false,
                root_link_names: None,
                wrapper_id: None,
                materialization: Materialization::CasBacked,
                peers: Vec::new(),
                patch_fingerprint: None,
            },
        ];

        let result = link_packages_hoisted(project_dir.path(), &packages, false, None).unwrap();

        // One debug at root, one nested
        assert!(project_dir.path().join("node_modules/debug").exists());

        // The conflicting version should be nested under its dependent
        let nested_debug = project_dir
            .path()
            .join("node_modules/other/node_modules/debug");
        assert!(
            nested_debug.exists(),
            "conflicting debug version should be nested under its dependent"
        );

        // Total linked = express + debug@root + other + debug@nested = 4
        assert_eq!(result.linked, 4);
    }

    #[test]
    fn hoisted_mode_prefers_direct_deps() {
        let store_dir = tempfile::tempdir().unwrap();
        let project_dir = tempfile::tempdir().unwrap();

        let parent_store = create_fake_store_package(store_dir.path(), "parent");
        let debug_v2_store = create_fake_store_package(store_dir.path(), "debug-v2");
        let debug_v3_store = create_fake_store_package(store_dir.path(), "debug-v3");

        let packages = vec![
            LinkTarget {
                name: "parent".to_string(),
                version: "1.0.0".to_string(),
                store_path: parent_store,
                dependencies: vec![("debug".to_string(), "2.6.9".to_string())],
                aliases: HashMap::new(),
                is_direct: true,
                root_link_names: None,
                wrapper_id: None,
                materialization: Materialization::CasBacked,
                peers: Vec::new(),
                patch_fingerprint: None,
            },
            LinkTarget {
                name: "debug".to_string(),
                version: "2.6.9".to_string(),
                store_path: debug_v2_store,
                dependencies: vec![],
                aliases: HashMap::new(),
                is_direct: false,
                root_link_names: None,
                wrapper_id: None,
                materialization: Materialization::CasBacked,
                peers: Vec::new(),
                patch_fingerprint: None,
            },
            // Direct dep with different version should win root
            LinkTarget {
                name: "debug".to_string(),
                version: "3.0.0".to_string(),
                store_path: debug_v3_store,
                dependencies: vec![],
                aliases: HashMap::new(),
                is_direct: true,
                root_link_names: None,
                wrapper_id: None,
                materialization: Materialization::CasBacked,
                peers: Vec::new(),
                patch_fingerprint: None,
            },
        ];

        let result = link_packages_hoisted(project_dir.path(), &packages, false, None).unwrap();

        // Debug at root should exist
        assert!(project_dir.path().join("node_modules/debug").exists());

        // The direct dep (3.0.0) should have won root position.
        // The transitive (2.6.9) should be nested under "parent".
        let nested_debug = project_dir
            .path()
            .join("node_modules/parent/node_modules/debug");
        assert!(
            nested_debug.exists(),
            "transitive debug should be nested under parent"
        );

        assert!(result.linked >= 3);
    }

    // ---- Security audit tests ----

    // Path traversal in bin targets
    #[test]
    fn bin_target_path_traversal_rejected() {
        let store_dir = tempfile::tempdir().unwrap();
        let project_dir = tempfile::tempdir().unwrap();

        // Create an "outside" file that the traversal would target
        let outside_file = store_dir.path().join("outside_secret");
        std::fs::write(&outside_file, "secret data").unwrap();

        // Create a package whose bin points to ../../outside_secret
        let pkg_name = "evil-pkg";
        let pkg_dir = store_dir.path().join(pkg_name);
        std::fs::create_dir_all(&pkg_dir).unwrap();
        std::fs::write(
            pkg_dir.join("package.json"),
            r#"{"name":"evil-pkg","bin":{"evil":"../../outside_secret"}}"#,
        )
        .unwrap();
        // Create a dummy file so the package dir exists but the target escapes
        std::fs::write(pkg_dir.join("index.js"), "").unwrap();

        let packages = vec![LinkTarget {
            name: pkg_name.to_string(),
            version: "1.0.0".to_string(),
            store_path: pkg_dir,
            dependencies: vec![],
            aliases: HashMap::new(),
            is_direct: true,
            root_link_names: None,
            wrapper_id: None,
            materialization: Materialization::CasBacked,
            peers: Vec::new(),
            patch_fingerprint: None,
        }];

        let result = link_packages(project_dir.path(), &packages, false, None).unwrap();

        // The traversal bin should be rejected — no bin link created
        assert_eq!(
            result.bin_linked, 0,
            "path traversal bin target should be rejected"
        );

        // Verify no symlink was created in .bin/
        let bin_link = project_dir.path().join("node_modules/.bin/evil");
        assert!(
            bin_link.symlink_metadata().is_err(),
            "no symlink should exist for path-traversing bin"
        );
    }

    // Bin name validation
    #[test]
    fn bin_name_with_path_separator_rejected() {
        assert!(validate_bin_name("../escape", "pkg").is_err());
    }

    #[test]
    fn bin_name_empty_rejected() {
        assert!(validate_bin_name("", "pkg").is_err());
    }

    #[test]
    fn bin_name_normal_allowed() {
        assert!(validate_bin_name("normal-cli", "pkg").is_ok());
    }

    #[test]
    fn bin_name_node_warns_but_allowed() {
        // "node" should be allowed (Ok) but logs a warning
        assert!(validate_bin_name("node", "pkg").is_ok());
    }

    #[test]
    fn bin_name_with_null_byte_rejected() {
        assert!(validate_bin_name("bad\0name", "pkg").is_err());
    }

    #[test]
    fn bin_name_with_backslash_rejected() {
        assert!(validate_bin_name("bad\\name", "pkg").is_err());
    }

    // Windows cmd shim injection
    #[test]
    #[cfg(windows)]
    fn cmd_path_with_metacharacters_rejected() {
        assert!(validate_cmd_path(r#"" & whoami & echo ""#).is_err());
        assert!(validate_cmd_path("normal/path/to/script.js").is_ok());
        assert!(validate_cmd_path("path|injection").is_err());
        assert!(validate_cmd_path("path<injection").is_err());
        assert!(validate_cmd_path("path>injection").is_err());
        assert!(validate_cmd_path("path^injection").is_err());
        assert!(validate_cmd_path("path%injection").is_err());
        assert!(validate_cmd_path("path\ninjection").is_err());
    }

    // Validate cmd paths for junction creation
    #[test]
    #[cfg(windows)]
    fn validate_cmd_path_rejects_ampersand() {
        assert!(validate_cmd_path("C:\\foo & del C:\\").is_err());
    }

    #[test]
    #[cfg(windows)]
    fn validate_cmd_path_allows_normal_path() {
        assert!(validate_cmd_path("C:\\Users\\foo\\node_modules").is_ok());
    }

    // Permission bits
    #[cfg(unix)]
    #[test]
    fn permission_bits_add_execute_only() {
        // Mode | 0o111 should add execute without adding write for group/other
        let original_mode: u32 = 0o644;
        let fixed = original_mode | 0o111;
        assert_eq!(fixed, 0o755, "644 | 111 should be 755");

        let original_mode_2: u32 = 0o600;
        let fixed_2 = original_mode_2 | 0o111;
        assert_eq!(fixed_2, 0o711, "600 | 111 should be 711, not 755");

        // Prove the old code was wrong:
        let old_broken: u32 = 0o600 | 0o755;
        assert_eq!(old_broken, 0o755, "old code would force 755 regardless");
        assert_ne!(
            fixed_2, old_broken,
            "new code preserves restrictive permissions"
        );
    }

    // Relative symlinks
    #[cfg(unix)]
    #[test]
    fn bin_links_use_relative_symlinks() {
        let store_dir = tempfile::tempdir().unwrap();
        let project_dir = tempfile::tempdir().unwrap();

        let store_path =
            create_fake_store_package_with_bin(store_dir.path(), "rel-tool", "\"./cli.js\"");

        let packages = vec![LinkTarget {
            name: "rel-tool".to_string(),
            version: "1.0.0".to_string(),
            store_path,
            dependencies: vec![],
            aliases: HashMap::new(),
            is_direct: true,
            root_link_names: None,
            wrapper_id: None,
            materialization: Materialization::CasBacked,
            peers: Vec::new(),
            patch_fingerprint: None,
        }];

        let result = link_packages(project_dir.path(), &packages, false, None).unwrap();
        assert_eq!(result.bin_linked, 1);

        let bin_link = project_dir.path().join("node_modules/.bin/rel-tool");
        assert!(
            bin_link.symlink_metadata().is_ok(),
            ".bin/rel-tool should exist"
        );

        // Read the symlink target and verify it's relative
        let link_target = std::fs::read_link(&bin_link).unwrap();
        assert!(
            !link_target.is_absolute(),
            "bin symlink should be relative, got: {}",
            link_target.display()
        );
    }

    #[cfg(all(unix, target_os = "macos"))]
    #[test]
    fn bin_links_from_logical_tmp_paths_do_not_dangle() {
        let store_dir = tempfile::tempdir().unwrap();
        let project_dir = tempfile::Builder::new()
            .prefix("lpm-linker-macos-tmp-")
            .tempdir_in("/tmp")
            .unwrap();

        let store_path =
            create_fake_store_package_with_bin(store_dir.path(), "tmp-tool", "\"./cli.js\"");

        let packages = vec![LinkTarget {
            name: "tmp-tool".to_string(),
            version: "1.0.0".to_string(),
            store_path,
            dependencies: vec![],
            aliases: HashMap::new(),
            is_direct: true,
            root_link_names: None,
            wrapper_id: None,
            materialization: Materialization::CasBacked,
            peers: Vec::new(),
            patch_fingerprint: None,
        }];

        let lexical_root = project_dir.path();
        assert!(
            lexical_root.starts_with("/tmp"),
            "test requires a logical /tmp path, got {}",
            lexical_root.display()
        );
        assert_ne!(
            lexical_root,
            lexical_root.canonicalize().unwrap().as_path(),
            "test requires /tmp to canonicalize differently on macOS"
        );

        let result = link_packages(lexical_root, &packages, false, None).unwrap();
        assert_eq!(result.bin_linked, 1);

        let bin_link = lexical_root.join("node_modules/.bin/tmp-tool");
        assert!(
            bin_link.symlink_metadata().is_ok(),
            ".bin/tmp-tool should exist"
        );
        assert!(
            bin_link.exists(),
            ".bin/tmp-tool should resolve even when project root is addressed through logical /tmp"
        );
    }

    // Path traversal in hoisted mode
    #[test]
    fn bin_target_path_traversal_rejected_hoisted() {
        let store_dir = tempfile::tempdir().unwrap();
        let project_dir = tempfile::tempdir().unwrap();

        let outside_file = store_dir.path().join("outside_secret");
        std::fs::write(&outside_file, "secret data").unwrap();

        let pkg_name = "evil-pkg";
        let pkg_dir = store_dir.path().join(pkg_name);
        std::fs::create_dir_all(&pkg_dir).unwrap();
        std::fs::write(
            pkg_dir.join("package.json"),
            r#"{"name":"evil-pkg","bin":{"evil":"../../outside_secret"}}"#,
        )
        .unwrap();
        std::fs::write(pkg_dir.join("index.js"), "").unwrap();

        let packages = vec![LinkTarget {
            name: pkg_name.to_string(),
            version: "1.0.0".to_string(),
            store_path: pkg_dir,
            dependencies: vec![],
            aliases: HashMap::new(),
            is_direct: true,
            root_link_names: None,
            wrapper_id: None,
            materialization: Materialization::CasBacked,
            peers: Vec::new(),
            patch_fingerprint: None,
        }];

        let result = link_packages_hoisted(project_dir.path(), &packages, false, None).unwrap();
        assert_eq!(
            result.bin_linked, 0,
            "path traversal bin target should be rejected in hoisted mode"
        );
    }

    #[cfg(unix)]
    #[test]
    fn bin_target_symlink_escape_rejected() {
        let store_dir = tempfile::tempdir().unwrap();
        let project_dir = tempfile::tempdir().unwrap();

        let outside_file = store_dir.path().join("outside_secret.js");
        std::fs::write(&outside_file, "console.log('secret')").unwrap();

        let pkg_name = "symlink-escape";
        let pkg_dir = store_dir.path().join(pkg_name);
        std::fs::create_dir_all(&pkg_dir).unwrap();
        std::fs::write(
            pkg_dir.join("package.json"),
            r#"{"name":"symlink-escape","bin":{"escape":"./link.js"}}"#,
        )
        .unwrap();
        std::os::unix::fs::symlink(&outside_file, pkg_dir.join("link.js")).unwrap();

        let packages = vec![LinkTarget {
            name: pkg_name.to_string(),
            version: "1.0.0".to_string(),
            store_path: pkg_dir,
            dependencies: vec![],
            aliases: HashMap::new(),
            is_direct: true,
            root_link_names: None,
            wrapper_id: None,
            materialization: Materialization::CasBacked,
            peers: Vec::new(),
            patch_fingerprint: None,
        }];

        let result = link_packages(project_dir.path(), &packages, false, None).unwrap();
        assert_eq!(
            result.bin_linked, 0,
            "bin symlinks that resolve outside the package directory should be rejected"
        );
    }

    #[test]
    fn bin_target_absolute_path_rejected() {
        let store_dir = tempfile::tempdir().unwrap();
        let project_dir = tempfile::tempdir().unwrap();

        let outside_file = store_dir.path().join("outside_secret.js");
        std::fs::write(&outside_file, "console.log('secret')").unwrap();

        let pkg_name = "absolute-escape";
        let pkg_dir = store_dir.path().join(pkg_name);
        std::fs::create_dir_all(&pkg_dir).unwrap();
        std::fs::write(
            pkg_dir.join("package.json"),
            format!(
                "{{\"name\":\"{pkg_name}\",\"bin\":{{\"escape\":\"{}\"}}}}",
                outside_file.display()
            ),
        )
        .unwrap();

        let packages = vec![LinkTarget {
            name: pkg_name.to_string(),
            version: "1.0.0".to_string(),
            store_path: pkg_dir,
            dependencies: vec![],
            aliases: HashMap::new(),
            is_direct: true,
            root_link_names: None,
            wrapper_id: None,
            materialization: Materialization::CasBacked,
            peers: Vec::new(),
            patch_fingerprint: None,
        }];

        let result = link_packages(project_dir.path(), &packages, false, None).unwrap();
        assert_eq!(
            result.bin_linked, 0,
            "absolute bin targets outside the package directory should be rejected"
        );
    }

    // Bin name ../escape should not create a link
    #[test]
    fn bin_name_escape_not_linked() {
        let store_dir = tempfile::tempdir().unwrap();
        let project_dir = tempfile::tempdir().unwrap();

        let pkg_name = "escape-pkg";
        let pkg_dir = store_dir.path().join(pkg_name);
        std::fs::create_dir_all(&pkg_dir).unwrap();
        std::fs::write(
            pkg_dir.join("package.json"),
            r#"{"name":"escape-pkg","bin":{"../escape":"./cli.js"}}"#,
        )
        .unwrap();
        std::fs::write(pkg_dir.join("cli.js"), "#!/usr/bin/env node").unwrap();

        let packages = vec![LinkTarget {
            name: pkg_name.to_string(),
            version: "1.0.0".to_string(),
            store_path: pkg_dir,
            dependencies: vec![],
            aliases: HashMap::new(),
            is_direct: true,
            root_link_names: None,
            wrapper_id: None,
            materialization: Materialization::CasBacked,
            peers: Vec::new(),
            patch_fingerprint: None,
        }];

        let result = link_packages(project_dir.path(), &packages, false, None).unwrap();
        assert_eq!(
            result.bin_linked, 0,
            "bin name with path traversal should be rejected"
        );
    }

    // ---- Finding: Self-reference name validation ----

    #[test]
    fn self_ref_name_valid_plain() {
        assert!(is_valid_self_ref_name("my-package"));
    }

    #[test]
    fn self_ref_name_valid_scoped() {
        assert!(is_valid_self_ref_name("@scope/my-package"));
    }

    #[test]
    fn self_ref_name_invalid_traversal() {
        assert!(!is_valid_self_ref_name("../../etc"));
    }

    #[test]
    fn self_ref_name_invalid_empty() {
        assert!(!is_valid_self_ref_name(""));
    }

    #[test]
    fn self_ref_name_invalid_null_byte() {
        assert!(!is_valid_self_ref_name("a\0b"));
    }

    #[test]
    fn self_ref_name_invalid_backslash() {
        assert!(!is_valid_self_ref_name("foo\\bar"));
    }

    #[test]
    fn self_ref_name_invalid_absolute() {
        assert!(!is_valid_self_ref_name("/etc/passwd"));
    }

    #[test]
    fn self_ref_traversal_skipped_no_error() {
        let store_dir = tempfile::tempdir().unwrap();
        let project_dir = tempfile::tempdir().unwrap();

        let store_path = create_fake_store_package(store_dir.path(), "foo");

        let packages = vec![LinkTarget {
            name: "foo".to_string(),
            version: "1.0.0".to_string(),
            store_path,
            dependencies: vec![],
            aliases: HashMap::new(),
            is_direct: true,
            root_link_names: None,
            wrapper_id: None,
            materialization: Materialization::CasBacked,
            peers: Vec::new(),
            patch_fingerprint: None,
        }];

        // Use a traversal name — should not create symlink, should not error
        let result =
            link_packages(project_dir.path(), &packages, false, Some("../../evil")).unwrap();
        assert!(!result.self_referenced);

        // No symlink created outside node_modules
        let evil_link = project_dir.path().join("node_modules/../../evil");
        assert!(evil_link.symlink_metadata().is_err());
    }

    // ---- Finding: Additional hoisted mode tests ----

    #[test]
    fn hoisted_mode_empty_packages() {
        let project_dir = tempfile::tempdir().unwrap();

        let result = link_packages_hoisted(project_dir.path(), &[], false, None).unwrap();
        assert_eq!(result.linked, 0);
        assert_eq!(result.bin_linked, 0);
    }

    #[test]
    fn hoisted_mode_single_package() {
        let store_dir = tempfile::tempdir().unwrap();
        let project_dir = tempfile::tempdir().unwrap();

        let store_path = create_fake_store_package(store_dir.path(), "solo");

        let packages = vec![LinkTarget {
            name: "solo".to_string(),
            version: "1.0.0".to_string(),
            store_path,
            dependencies: vec![],
            aliases: HashMap::new(),
            is_direct: true,
            root_link_names: None,
            wrapper_id: None,
            materialization: Materialization::CasBacked,
            peers: Vec::new(),
            patch_fingerprint: None,
        }];

        let result = link_packages_hoisted(project_dir.path(), &packages, false, None).unwrap();
        assert_eq!(result.linked, 1);
        assert!(project_dir.path().join("node_modules/solo").exists());
        assert!(
            project_dir
                .path()
                .join("node_modules/solo/package.json")
                .exists()
        );
    }

    #[test]
    fn hoisted_mode_multiple_conflicts() {
        let store_dir = tempfile::tempdir().unwrap();
        let project_dir = tempfile::tempdir().unwrap();

        let a_store = create_fake_store_package(store_dir.path(), "a");
        let b_store = create_fake_store_package(store_dir.path(), "b");
        let shared_v1_store = create_fake_store_package(store_dir.path(), "shared-v1");
        let shared_v2_store = create_fake_store_package(store_dir.path(), "shared-v2");
        let util_v1_store = create_fake_store_package(store_dir.path(), "util-v1");
        let util_v2_store = create_fake_store_package(store_dir.path(), "util-v2");

        let packages = vec![
            LinkTarget {
                name: "a".to_string(),
                version: "1.0.0".to_string(),
                store_path: a_store,
                dependencies: vec![
                    ("shared".to_string(), "1.0.0".to_string()),
                    ("util".to_string(), "1.0.0".to_string()),
                ],
                aliases: HashMap::new(),
                is_direct: true,
                root_link_names: None,
                wrapper_id: None,
                materialization: Materialization::CasBacked,
                peers: Vec::new(),
                patch_fingerprint: None,
            },
            LinkTarget {
                name: "shared".to_string(),
                version: "1.0.0".to_string(),
                store_path: shared_v1_store,
                dependencies: vec![],
                aliases: HashMap::new(),
                is_direct: false,
                root_link_names: None,
                wrapper_id: None,
                materialization: Materialization::CasBacked,
                peers: Vec::new(),
                patch_fingerprint: None,
            },
            LinkTarget {
                name: "util".to_string(),
                version: "1.0.0".to_string(),
                store_path: util_v1_store,
                dependencies: vec![],
                aliases: HashMap::new(),
                is_direct: false,
                root_link_names: None,
                wrapper_id: None,
                materialization: Materialization::CasBacked,
                peers: Vec::new(),
                patch_fingerprint: None,
            },
            LinkTarget {
                name: "b".to_string(),
                version: "1.0.0".to_string(),
                store_path: b_store,
                dependencies: vec![
                    ("shared".to_string(), "2.0.0".to_string()),
                    ("util".to_string(), "2.0.0".to_string()),
                ],
                aliases: HashMap::new(),
                is_direct: true,
                root_link_names: None,
                wrapper_id: None,
                materialization: Materialization::CasBacked,
                peers: Vec::new(),
                patch_fingerprint: None,
            },
            LinkTarget {
                name: "shared".to_string(),
                version: "2.0.0".to_string(),
                store_path: shared_v2_store,
                dependencies: vec![],
                aliases: HashMap::new(),
                is_direct: false,
                root_link_names: None,
                wrapper_id: None,
                materialization: Materialization::CasBacked,
                peers: Vec::new(),
                patch_fingerprint: None,
            },
            LinkTarget {
                name: "util".to_string(),
                version: "2.0.0".to_string(),
                store_path: util_v2_store,
                dependencies: vec![],
                aliases: HashMap::new(),
                is_direct: false,
                root_link_names: None,
                wrapper_id: None,
                materialization: Materialization::CasBacked,
                peers: Vec::new(),
                patch_fingerprint: None,
            },
        ];

        let result = link_packages_hoisted(project_dir.path(), &packages, false, None).unwrap();

        // Root should have: a, b, shared (v1 wins first-come), util (v1 wins first-come)
        assert!(project_dir.path().join("node_modules/a").exists());
        assert!(project_dir.path().join("node_modules/b").exists());
        assert!(project_dir.path().join("node_modules/shared").exists());
        assert!(project_dir.path().join("node_modules/util").exists());

        // Conflicting v2 should be nested under b
        assert!(
            project_dir
                .path()
                .join("node_modules/b/node_modules/shared")
                .exists()
        );
        assert!(
            project_dir
                .path()
                .join("node_modules/b/node_modules/util")
                .exists()
        );

        // 4 root + 2 nested = 6
        assert_eq!(result.linked, 6);
    }

    /// Regression test for the conflict-nesting bug found in the
    /// hoisted-mode compatibility audit (eslint-flat-config fixture).
    /// Pre-fix, when two conflict-versioned packages had
    /// different consumers that were themselves at different versions,
    /// the algorithm misplaced the deeper conflict under whichever
    /// hoisted package shared the consumer's name — which was the
    /// **wrong** consumer instance.
    ///
    /// Setup mirrors the real eslint failure mode in miniature:
    /// - `anchor` (direct, hoisted) → depends on `consumer@10`
    /// - `consumer@3` (transitive, hoisted) → depends on `dep@1`
    /// - `dep@1` (hoisted)
    /// - `consumer@10` (transitive, nested under `anchor`) → depends on `dep@5`
    /// - `dep@5` (transitive, must nest under **anchor**, NOT under hoisted `consumer@3`)
    ///
    /// Pre-fix lpm placed `dep@5` at `node_modules/consumer/node_modules/dep`
    /// (under `consumer@3`!), which broke Node resolution because
    /// `consumer@3` would `require('dep')` and find v5 first instead of
    /// the v1 it actually needs. Post-fix, `dep@5` lands at
    /// `node_modules/anchor/node_modules/dep` — sibling to `consumer@10`,
    /// which is where Node's resolver finds it from `consumer@10`'s
    /// position when walking up.
    #[test]
    fn hoisted_mode_nests_conflict_under_consumer_anchor_not_same_named_root() {
        let store_dir = tempfile::tempdir().unwrap();
        let project_dir = tempfile::tempdir().unwrap();

        let anchor_store = create_fake_store_package(store_dir.path(), "anchor");
        let consumer_v3_store = create_fake_store_package(store_dir.path(), "consumer-v3");
        let consumer_v10_store = create_fake_store_package(store_dir.path(), "consumer-v10");
        let dep_v1_store = create_fake_store_package(store_dir.path(), "dep-v1");
        let dep_v5_store = create_fake_store_package(store_dir.path(), "dep-v5");

        let packages = vec![
            // Anchor (direct) → consumer@10
            LinkTarget {
                name: "anchor".to_string(),
                version: "1.0.0".to_string(),
                store_path: anchor_store,
                dependencies: vec![("consumer".to_string(), "10.0.0".to_string())],
                aliases: HashMap::new(),
                is_direct: true,
                root_link_names: None,
                wrapper_id: None,
                materialization: Materialization::CasBacked,
                peers: Vec::new(),
                patch_fingerprint: None,
            },
            // Consumer@3 (transitive, encountered first → hoisted) → dep@1
            LinkTarget {
                name: "consumer".to_string(),
                version: "3.0.0".to_string(),
                store_path: consumer_v3_store,
                dependencies: vec![("dep".to_string(), "1.0.0".to_string())],
                aliases: HashMap::new(),
                is_direct: false,
                root_link_names: None,
                wrapper_id: None,
                materialization: Materialization::CasBacked,
                peers: Vec::new(),
                patch_fingerprint: None,
            },
            // Dep@1 (transitive, hoisted)
            LinkTarget {
                name: "dep".to_string(),
                version: "1.0.0".to_string(),
                store_path: dep_v1_store,
                dependencies: vec![],
                aliases: HashMap::new(),
                is_direct: false,
                root_link_names: None,
                wrapper_id: None,
                materialization: Materialization::CasBacked,
                peers: Vec::new(),
                patch_fingerprint: None,
            },
            // Some-other-direct (forces consumer@3 to come before consumer@10
            // in declaration order — this test would be vacuous without
            // ordering control). Actually we rely on packages-vec order.
            LinkTarget {
                name: "consumer".to_string(),
                version: "10.0.0".to_string(),
                store_path: consumer_v10_store,
                dependencies: vec![("dep".to_string(), "5.0.0".to_string())],
                aliases: HashMap::new(),
                is_direct: false,
                root_link_names: None,
                wrapper_id: None,
                materialization: Materialization::CasBacked,
                peers: Vec::new(),
                patch_fingerprint: None,
            },
            // Dep@5 (transitive, must nest under anchor)
            LinkTarget {
                name: "dep".to_string(),
                version: "5.0.0".to_string(),
                store_path: dep_v5_store,
                dependencies: vec![],
                aliases: HashMap::new(),
                is_direct: false,
                root_link_names: None,
                wrapper_id: None,
                materialization: Materialization::CasBacked,
                peers: Vec::new(),
                patch_fingerprint: None,
            },
        ];

        let result = link_packages_hoisted(project_dir.path(), &packages, false, None).unwrap();

        // Hoisted at root: anchor, consumer@3, dep@1.
        assert!(project_dir.path().join("node_modules/anchor").exists());
        assert!(project_dir.path().join("node_modules/consumer").exists());
        assert!(project_dir.path().join("node_modules/dep").exists());

        // Consumer@10 nests under anchor (its consumer is anchor, hoisted).
        assert!(
            project_dir
                .path()
                .join("node_modules/anchor/node_modules/consumer")
                .exists(),
            "consumer@10 should nest under anchor, its hoisted consumer"
        );

        // **The bug fix.** dep@5 must nest under `anchor`, NOT under
        // `consumer` (which is consumer@3's slot). Pre-fix, the algorithm
        // would have placed dep@5 at node_modules/consumer/node_modules/dep,
        // which is WRONG because consumer@3 needs dep@1, not dep@5.
        assert!(
            project_dir
                .path()
                .join("node_modules/anchor/node_modules/dep")
                .exists(),
            "dep@5 MUST nest under anchor (consumer@10's hoisted ancestor), \
             not under consumer (which is consumer@3's slot — would shadow dep@1 \
             from consumer@3's perspective and break Node resolution)"
        );
        assert!(
            !project_dir
                .path()
                .join("node_modules/consumer/node_modules/dep")
                .exists(),
            "dep@5 must NOT be nested under consumer@3 (the pre-fix bug)"
        );

        // Total linked = anchor + consumer@3 + dep@1 (3 hoisted) +
        // consumer@10 + dep@5 (2 nested) = 5.
        assert_eq!(result.linked, 5);
    }

    #[test]
    fn interrupted_link_cleaned_up_and_relinked() {
        let store_dir = tempfile::tempdir().unwrap();
        let project_dir = tempfile::tempdir().unwrap();

        let store_path = create_fake_store_package(store_dir.path(), "partial");

        // Simulate an interrupted link: create the pkg_nm directory but NOT the .linked marker.
        // wrapper root is `.lpm/wrappers/`, not `node_modules/.lpm/`.
        let lpm_dir = project_dir.path().join(".lpm/wrappers");
        let pkg_entry_dir = lpm_dir.join("partial@1.0.0");
        let pkg_nm = pkg_entry_dir.join("node_modules").join("partial");
        std::fs::create_dir_all(&pkg_nm).unwrap();
        // Write a partial file to prove this directory gets cleaned up
        std::fs::write(pkg_nm.join("stale.txt"), "should be removed").unwrap();
        // Crucially, do NOT create pkg_entry_dir.join(".linked")

        let packages = vec![LinkTarget {
            name: "partial".to_string(),
            version: "1.0.0".to_string(),
            store_path,
            dependencies: vec![],
            aliases: HashMap::new(),
            is_direct: true,
            root_link_names: None,
            wrapper_id: None,
            materialization: Materialization::CasBacked,
            peers: Vec::new(),
            patch_fingerprint: None,
        }];

        let result = link_packages(project_dir.path(), &packages, false, None).unwrap();

        // The stale directory should have been cleaned up and re-linked
        assert_eq!(
            result.linked, 1,
            "package should be re-linked after cleanup"
        );

        // The stale file should be gone
        assert!(
            !pkg_nm.join("stale.txt").exists(),
            "stale file should be removed"
        );

        // The real package files should be present
        assert!(
            pkg_nm.join("package.json").exists(),
            "package.json should exist after re-link"
        );

        // The .linked marker should now exist
        assert!(
            pkg_entry_dir.join(".linked").exists(),
            ".linked marker should be created"
        );
    }

    // ─── Hoisted self-reference tests ──────────────────────────────────

    #[test]
    fn hoisted_self_reference_created() {
        let store_dir = tempfile::tempdir().unwrap();
        let project_dir = tempfile::tempdir().unwrap();

        let store_path = create_fake_store_package(store_dir.path(), "dep-a");
        let packages = vec![LinkTarget {
            name: "dep-a".to_string(),
            version: "1.0.0".to_string(),
            store_path,
            dependencies: vec![],
            aliases: HashMap::new(),
            is_direct: true,
            root_link_names: None,
            wrapper_id: None,
            materialization: Materialization::CasBacked,
            peers: Vec::new(),
            patch_fingerprint: None,
        }];

        let result =
            link_packages_hoisted(project_dir.path(), &packages, false, Some("my-project"))
                .unwrap();

        assert!(result.self_referenced);
        let self_link = project_dir.path().join("node_modules/my-project");
        assert!(
            self_link.symlink_metadata().is_ok(),
            "self-ref symlink should exist"
        );
    }

    #[test]
    fn hoisted_self_reference_skipped_when_dep_has_same_name() {
        let store_dir = tempfile::tempdir().unwrap();
        let project_dir = tempfile::tempdir().unwrap();

        let store_path = create_fake_store_package(store_dir.path(), "clash");
        let packages = vec![LinkTarget {
            name: "clash".to_string(),
            version: "1.0.0".to_string(),
            store_path,
            dependencies: vec![],
            aliases: HashMap::new(),
            is_direct: true,
            root_link_names: None,
            wrapper_id: None,
            materialization: Materialization::CasBacked,
            peers: Vec::new(),
            patch_fingerprint: None,
        }];

        let result =
            link_packages_hoisted(project_dir.path(), &packages, false, Some("clash")).unwrap();

        // Dependency "clash" takes the slot — self-reference should NOT be created
        assert!(!result.self_referenced);
        // But the dependency should be linked
        assert!(
            project_dir
                .path()
                .join("node_modules/clash/package.json")
                .exists()
        );
    }

    #[test]
    fn hoisted_self_reference_scoped() {
        let store_dir = tempfile::tempdir().unwrap();
        let project_dir = tempfile::tempdir().unwrap();

        let store_path = create_fake_store_package(store_dir.path(), "dep");
        let packages = vec![LinkTarget {
            name: "dep".to_string(),
            version: "1.0.0".to_string(),
            store_path,
            dependencies: vec![],
            aliases: HashMap::new(),
            is_direct: true,
            root_link_names: None,
            wrapper_id: None,
            materialization: Materialization::CasBacked,
            peers: Vec::new(),
            patch_fingerprint: None,
        }];

        let result = link_packages_hoisted(
            project_dir.path(),
            &packages,
            false,
            Some("@my-org/my-project"),
        )
        .unwrap();

        assert!(result.self_referenced);
        let scope_dir = project_dir.path().join("node_modules/@my-org");
        assert!(scope_dir.exists(), "@scope dir should be created");
        let self_link = scope_dir.join("my-project");
        assert!(
            self_link.symlink_metadata().is_ok(),
            "scoped self-ref should exist"
        );
    }

    #[test]
    fn hoisted_self_reference_none_when_no_name() {
        let store_dir = tempfile::tempdir().unwrap();
        let project_dir = tempfile::tempdir().unwrap();

        let store_path = create_fake_store_package(store_dir.path(), "dep");
        let packages = vec![LinkTarget {
            name: "dep".to_string(),
            version: "1.0.0".to_string(),
            store_path,
            dependencies: vec![],
            aliases: HashMap::new(),
            is_direct: true,
            root_link_names: None,
            wrapper_id: None,
            materialization: Materialization::CasBacked,
            peers: Vec::new(),
            patch_fingerprint: None,
        }];

        let result = link_packages_hoisted(project_dir.path(), &packages, false, None).unwrap();

        assert!(!result.self_referenced);
    }

    // ─── Hoisted metadata incremental tests ────────────────────────────

    #[test]
    fn hoisted_metadata_written_after_link() {
        let store_dir = tempfile::tempdir().unwrap();
        let project_dir = tempfile::tempdir().unwrap();

        let store_path = create_fake_store_package(store_dir.path(), "pkg");
        let packages = vec![LinkTarget {
            name: "pkg".to_string(),
            version: "2.0.0".to_string(),
            store_path,
            dependencies: vec![],
            aliases: HashMap::new(),
            is_direct: true,
            root_link_names: None,
            wrapper_id: None,
            materialization: Materialization::CasBacked,
            peers: Vec::new(),
            patch_fingerprint: None,
        }];

        link_packages_hoisted(project_dir.path(), &packages, false, None).unwrap();

        // Hoisted-symmetry: metadata sidecar lives at
        // `<project>/.lpm/hoisted/metadata.json` — sibling of
        // `.lpm/wrappers/`, no longer under `node_modules/`.
        let metadata_path = LayoutPaths::for_project(project_dir.path()).hoisted_metadata_path();
        assert!(metadata_path.exists(), "metadata file should be written");

        let data: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&metadata_path).unwrap()).unwrap();
        let hoisted = data["hoisted"].as_object().unwrap();
        assert_eq!(hoisted.get("pkg").unwrap().as_str().unwrap(), "2.0.0");
    }

    #[test]
    fn hoisted_incremental_skip_when_unchanged() {
        let store_dir = tempfile::tempdir().unwrap();
        let project_dir = tempfile::tempdir().unwrap();

        let store_path = create_fake_store_package(store_dir.path(), "stable");
        let packages = vec![LinkTarget {
            name: "stable".to_string(),
            version: "1.0.0".to_string(),
            store_path,
            dependencies: vec![],
            aliases: HashMap::new(),
            is_direct: true,
            root_link_names: None,
            wrapper_id: None,
            materialization: Materialization::CasBacked,
            peers: Vec::new(),
            patch_fingerprint: None,
        }];

        // First link — should actually link
        let r1 = link_packages_hoisted(project_dir.path(), &packages, false, None).unwrap();
        assert_eq!(r1.linked, 1);
        assert_eq!(r1.skipped, 0);

        // Second link with same packages — should skip via metadata
        let r2 = link_packages_hoisted(project_dir.path(), &packages, false, None).unwrap();
        assert_eq!(r2.linked, 0, "no new links on unchanged layout");
        assert_eq!(r2.skipped, 1, "should skip all packages");
    }

    #[test]
    fn hoisted_incremental_relinks_on_version_change() {
        let store_dir = tempfile::tempdir().unwrap();
        let project_dir = tempfile::tempdir().unwrap();

        let store_v1 = create_fake_store_package(store_dir.path(), "pkg-v1");
        let store_v2 = create_fake_store_package(store_dir.path(), "pkg-v2");

        let packages_v1 = vec![LinkTarget {
            name: "pkg".to_string(),
            version: "1.0.0".to_string(),
            store_path: store_v1,
            dependencies: vec![],
            aliases: HashMap::new(),
            is_direct: true,
            root_link_names: None,
            wrapper_id: None,
            materialization: Materialization::CasBacked,
            peers: Vec::new(),
            patch_fingerprint: None,
        }];

        // First link with v1
        let r1 = link_packages_hoisted(project_dir.path(), &packages_v1, false, None).unwrap();
        assert_eq!(r1.linked, 1);

        // Second link with v2 — should detect version change and re-link
        let packages_v2 = vec![LinkTarget {
            name: "pkg".to_string(),
            version: "2.0.0".to_string(),
            store_path: store_v2,
            dependencies: vec![],
            aliases: HashMap::new(),
            is_direct: true,
            root_link_names: None,
            wrapper_id: None,
            materialization: Materialization::CasBacked,
            peers: Vec::new(),
            patch_fingerprint: None,
        }];

        let r2 = link_packages_hoisted(project_dir.path(), &packages_v2, false, None).unwrap();
        assert_eq!(r2.linked, 1, "should re-link on version change");
        assert_eq!(r2.skipped, 0);
    }

    #[test]
    fn hoisted_incremental_cleans_stale_packages() {
        let store_dir = tempfile::tempdir().unwrap();
        let project_dir = tempfile::tempdir().unwrap();

        let store_a = create_fake_store_package(store_dir.path(), "pkg-a");
        let store_b = create_fake_store_package(store_dir.path(), "pkg-b");

        // First link: pkg-a + pkg-b
        let packages_v1 = vec![
            LinkTarget {
                name: "pkg-a".to_string(),
                version: "1.0.0".to_string(),
                store_path: store_a.clone(),
                dependencies: vec![],
                aliases: HashMap::new(),
                is_direct: true,
                root_link_names: None,
                wrapper_id: None,
                materialization: Materialization::CasBacked,
                peers: Vec::new(),
                patch_fingerprint: None,
            },
            LinkTarget {
                name: "pkg-b".to_string(),
                version: "1.0.0".to_string(),
                store_path: store_b,
                dependencies: vec![],
                aliases: HashMap::new(),
                is_direct: true,
                root_link_names: None,
                wrapper_id: None,
                materialization: Materialization::CasBacked,
                peers: Vec::new(),
                patch_fingerprint: None,
            },
        ];

        link_packages_hoisted(project_dir.path(), &packages_v1, false, None).unwrap();
        assert!(project_dir.path().join("node_modules/pkg-b").exists());

        // Second link: only pkg-a (pkg-b removed from deps)
        let packages_v2 = vec![LinkTarget {
            name: "pkg-a".to_string(),
            version: "1.0.0".to_string(),
            store_path: store_a,
            dependencies: vec![],
            aliases: HashMap::new(),
            is_direct: true,
            root_link_names: None,
            wrapper_id: None,
            materialization: Materialization::CasBacked,
            peers: Vec::new(),
            patch_fingerprint: None,
        }];

        let _r2 = link_packages_hoisted(project_dir.path(), &packages_v2, false, None).unwrap();

        // Pkg-a should still be there (already existed, no re-link needed)
        assert!(project_dir.path().join("node_modules/pkg-a").exists());
        // Pkg-b should be cleaned up
        assert!(
            !project_dir.path().join("node_modules/pkg-b").exists(),
            "stale pkg-b should be removed"
        );
        // Metadata should reflect only pkg-a (post-symmetry location).
        let meta_path = LayoutPaths::for_project(project_dir.path()).hoisted_metadata_path();
        let data: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&meta_path).unwrap()).unwrap();
        assert!(data["hoisted"].get("pkg-a").is_some());
        assert!(data["hoisted"].get("pkg-b").is_none());
    }

    #[test]
    fn hoisted_force_ignores_metadata() {
        let store_dir = tempfile::tempdir().unwrap();
        let project_dir = tempfile::tempdir().unwrap();

        let store_path = create_fake_store_package(store_dir.path(), "forced");
        let packages = vec![LinkTarget {
            name: "forced".to_string(),
            version: "1.0.0".to_string(),
            store_path,
            dependencies: vec![],
            aliases: HashMap::new(),
            is_direct: true,
            root_link_names: None,
            wrapper_id: None,
            materialization: Materialization::CasBacked,
            peers: Vec::new(),
            patch_fingerprint: None,
        }];

        // First link
        link_packages_hoisted(project_dir.path(), &packages, false, None).unwrap();

        // Force re-link — should not skip even though metadata matches
        let r2 = link_packages_hoisted(project_dir.path(), &packages, true, None).unwrap();
        // Force=true cleans then re-copies, so linked should be > 0
        assert_eq!(r2.linked, 1, "force should re-link everything");
        assert_eq!(r2.skipped, 0);
    }

    // ── Hoisted-symmetry mode-switch convergence regression tests ────

    /// Hoisted → isolated: previous hoisted install left
    /// `node_modules/<pkg>/` as a real directory (clonefile/hardlink
    /// content). Subsequent isolated install must REPLACE that with a
    /// symlink into `<project>/.lpm/wrappers/...`, not silently leave
    /// the hoisted bytes in place.
    #[test]
    fn mode_switch_hoisted_to_isolated_replaces_root_dir_with_symlink() {
        let store_dir = tempfile::tempdir().unwrap();
        let project_dir = tempfile::tempdir().unwrap();
        let store_path = create_fake_store_package(store_dir.path(), "express");

        let packages = vec![LinkTarget {
            name: "express".to_string(),
            version: "4.22.1".to_string(),
            store_path,
            dependencies: vec![],
            aliases: HashMap::new(),
            is_direct: true,
            root_link_names: None,
            wrapper_id: None,
            materialization: Materialization::CasBacked,
            peers: Vec::new(),
            patch_fingerprint: None,
        }];

        // Step 1 — hoisted install. Plants a real directory at
        // node_modules/express/ via link_dir_recursive.
        link_packages_hoisted(project_dir.path(), &packages, false, None).unwrap();
        let express_path = project_dir.path().join("node_modules").join("express");
        assert!(express_path.is_dir());
        let post_hoisted_is_symlink = express_path
            .symlink_metadata()
            .unwrap()
            .file_type()
            .is_symlink();
        assert!(
            !post_hoisted_is_symlink,
            "post-hoisted: node_modules/express must be a real directory, not a symlink"
        );

        // Step 2 — isolated install on the same project. Must clean
        // the hoisted dir and plant the isolated symlink.
        link_packages(project_dir.path(), &packages, false, None).unwrap();

        let post_iso_meta = express_path.symlink_metadata().unwrap();
        assert!(
            post_iso_meta.file_type().is_symlink(),
            "post-isolated: node_modules/express MUST be a symlink (was hoisted dir)"
        );

        // The wrapper tree must exist at the new location and contain
        // the actual package bytes.
        let wrapper_dir = project_dir
            .path()
            .join(".lpm")
            .join("wrappers")
            .join("express@4.22.1")
            .join("node_modules")
            .join("express");
        assert!(
            wrapper_dir.join("package.json").is_file(),
            "isolated wrapper must hold the package bytes"
        );

        // Inactive-mode hoisted state pruned by the deferred
        // finalize-step prune.
        assert!(
            !project_dir.path().join(".lpm").join("hoisted").exists(),
            "isolated finalize must prune .lpm/hoisted/"
        );
    }

    /// Isolated → hoisted: previous isolated install left
    /// `node_modules/<pkg>` as a symlink pointing into
    /// `<project>/.lpm/wrappers/...`. Subsequent hoisted install must
    /// (1) not crash on `create_dir_all` against the (possibly broken)
    /// symlink and (2) materialize a real hoisted directory there.
    #[test]
    fn mode_switch_isolated_to_hoisted_replaces_root_symlink_with_dir() {
        let store_dir = tempfile::tempdir().unwrap();
        let project_dir = tempfile::tempdir().unwrap();
        let store_path = create_fake_store_package(store_dir.path(), "lodash");

        let packages = vec![LinkTarget {
            name: "lodash".to_string(),
            version: "4.17.21".to_string(),
            store_path,
            dependencies: vec![],
            aliases: HashMap::new(),
            is_direct: true,
            root_link_names: None,
            wrapper_id: None,
            materialization: Materialization::CasBacked,
            peers: Vec::new(),
            patch_fingerprint: None,
        }];

        // Step 1 — isolated install. Plants a root symlink at
        // node_modules/lodash → ../.lpm/wrappers/lodash@4.17.21/node_modules/lodash/.
        link_packages(project_dir.path(), &packages, false, None).unwrap();
        let lodash_path = project_dir.path().join("node_modules").join("lodash");
        assert!(
            lodash_path
                .symlink_metadata()
                .unwrap()
                .file_type()
                .is_symlink(),
            "post-isolated: node_modules/lodash must be a symlink"
        );

        // Step 2 — hoisted install on the same project. Must succeed
        // (no `create_dir_all` errors against the leftover symlink),
        // and leave a real directory at node_modules/lodash/.
        link_packages_hoisted(project_dir.path(), &packages, false, None).unwrap();

        let post_hoisted_meta = lodash_path.symlink_metadata().unwrap();
        assert!(
            !post_hoisted_meta.file_type().is_symlink(),
            "post-hoisted: node_modules/lodash MUST be a real directory (was isolated symlink)"
        );
        assert!(
            lodash_path.join("package.json").is_file(),
            "hoisted dir must hold the package bytes"
        );

        // Inactive-mode wrapper state pruned by the deferred
        // post-link prune.
        assert!(
            !project_dir.path().join(".lpm").join("wrappers").exists(),
            "hoisted post-link must prune .lpm/wrappers/"
        );
    }

    /// Isolated → hoisted with a BROKEN leftover symlink (the user
    /// already wiped `<project>/.lpm/wrappers/` manually before
    /// re-running install in the other mode). Hoisted's own pre-link
    /// sweep must remove the broken symlink so `link_dir_recursive`'s
    /// `create_dir_all(dst)` doesn't error on macOS.
    #[test]
    fn mode_switch_isolated_to_hoisted_handles_broken_leftover_symlink() {
        let store_dir = tempfile::tempdir().unwrap();
        let project_dir = tempfile::tempdir().unwrap();
        let store_path = create_fake_store_package(store_dir.path(), "react");

        let nm = project_dir.path().join("node_modules");
        std::fs::create_dir_all(&nm).unwrap();
        // Synthesize a broken isolated-shape symlink directly,
        // simulating the post-wrapper-wipe state.
        let dangling_target = project_dir
            .path()
            .join(".lpm")
            .join("wrappers")
            .join("react@18.2.0")
            .join("node_modules")
            .join("react");
        std::os::unix::fs::symlink(&dangling_target, nm.join("react")).unwrap();

        let packages = vec![LinkTarget {
            name: "react".to_string(),
            version: "18.2.0".to_string(),
            store_path,
            dependencies: vec![],
            aliases: HashMap::new(),
            is_direct: true,
            root_link_names: None,
            wrapper_id: None,
            materialization: Materialization::CasBacked,
            peers: Vec::new(),
            patch_fingerprint: None,
        }];

        // Must not panic / error on the broken symlink.
        link_packages_hoisted(project_dir.path(), &packages, false, None).unwrap();

        let react_path = nm.join("react");
        let meta = react_path.symlink_metadata().unwrap();
        assert!(
            !meta.file_type().is_symlink(),
            "broken symlink must be removed and replaced with hoisted dir"
        );
        assert!(react_path.join("package.json").is_file());
    }

    /// Audit response: the pre-link symlink sweep added for
    /// isolated→hoisted convergence deletes EVERY top-level symlink
    /// under `node_modules/`, which includes the self-reference
    /// symlink at `node_modules/<self_name>`. The metadata-skip fast
    /// path (taken on every incremental install where the dep set
    /// is unchanged) used to assume the previous run's self-ref was
    /// still in place; post-sweep that's no longer true. Without an
    /// unconditional recreation step, every incremental hoisted
    /// install on a named project silently drops `require("self")`.
    /// This test pins the contract that the self-ref survives the
    /// incremental path.
    #[test]
    fn incremental_hoisted_install_preserves_self_reference() {
        let store_dir = tempfile::tempdir().unwrap();
        let project_dir = tempfile::tempdir().unwrap();
        let store_path = create_fake_store_package(store_dir.path(), "dep");

        let packages = vec![LinkTarget {
            name: "dep".to_string(),
            version: "1.0.0".to_string(),
            store_path,
            dependencies: vec![],
            aliases: HashMap::new(),
            is_direct: true,
            root_link_names: None,
            wrapper_id: None,
            materialization: Materialization::CasBacked,
            peers: Vec::new(),
            patch_fingerprint: None,
        }];

        let self_name = "myproj";
        let self_link = project_dir.path().join("node_modules").join(self_name);

        // First hoisted install — creates self-ref via the full re-link
        // branch.
        let r1 =
            link_packages_hoisted(project_dir.path(), &packages, false, Some(self_name)).unwrap();
        assert!(r1.self_referenced, "first install must create self-ref");
        let meta1 = self_link.symlink_metadata().unwrap();
        assert!(meta1.file_type().is_symlink());

        // Second hoisted install with identical packages — hits the
        // metadata-skip fast path (skipped > 0). Without the
        // unconditional self-ref recreation, the sweep deletes the
        // existing self-ref and the skip branch never restores it.
        let r2 =
            link_packages_hoisted(project_dir.path(), &packages, false, Some(self_name)).unwrap();
        assert_eq!(r2.skipped, 1, "second install must hit metadata fast path");
        assert!(
            self_link.symlink_metadata().is_ok(),
            "incremental install must not drop the self-ref symlink"
        );
        assert!(
            r2.self_referenced,
            "LinkResult.self_referenced must remain true on incremental"
        );
    }

    /// Same regression for SCOPED self-reference names
    /// (`@org/pkg`). The sweep recurses into `@org/` and removes the
    /// scoped self-ref; recreation must handle the scope-dir parent.
    #[test]
    fn incremental_hoisted_install_preserves_scoped_self_reference() {
        let store_dir = tempfile::tempdir().unwrap();
        let project_dir = tempfile::tempdir().unwrap();
        let store_path = create_fake_store_package(store_dir.path(), "dep");

        let packages = vec![LinkTarget {
            name: "dep".to_string(),
            version: "1.0.0".to_string(),
            store_path,
            dependencies: vec![],
            aliases: HashMap::new(),
            is_direct: true,
            root_link_names: None,
            wrapper_id: None,
            materialization: Materialization::CasBacked,
            peers: Vec::new(),
            patch_fingerprint: None,
        }];

        let self_name = "@myorg/foo";
        let self_link = project_dir
            .path()
            .join("node_modules")
            .join("@myorg")
            .join("foo");

        let r1 =
            link_packages_hoisted(project_dir.path(), &packages, false, Some(self_name)).unwrap();
        assert!(r1.self_referenced);
        assert!(
            self_link
                .symlink_metadata()
                .unwrap()
                .file_type()
                .is_symlink()
        );

        let r2 =
            link_packages_hoisted(project_dir.path(), &packages, false, Some(self_name)).unwrap();
        assert_eq!(r2.skipped, 1);
        assert!(
            self_link.symlink_metadata().is_ok(),
            "incremental install must not drop the scoped self-ref symlink"
        );
        assert!(r2.self_referenced);
    }

    /// Hoisted → isolated convergence under scoped names
    /// (`@scope/foo`). The scope dir is itself a real directory; the
    /// inner package dir is what we need to clean.
    #[test]
    fn mode_switch_hoisted_to_isolated_handles_scoped_dirs() {
        let store_dir = tempfile::tempdir().unwrap();
        let project_dir = tempfile::tempdir().unwrap();
        let store_path = create_fake_store_package(store_dir.path(), "node");

        let packages = vec![LinkTarget {
            name: "@types/node".to_string(),
            version: "20.0.0".to_string(),
            store_path,
            dependencies: vec![],
            aliases: HashMap::new(),
            is_direct: true,
            root_link_names: None,
            wrapper_id: None,
            materialization: Materialization::CasBacked,
            peers: Vec::new(),
            patch_fingerprint: None,
        }];

        // Hoisted install — synthesizes node_modules/@types/node/ as
        // a real dir.
        link_packages_hoisted(project_dir.path(), &packages, false, None).unwrap();
        let scoped_path = project_dir
            .path()
            .join("node_modules")
            .join("@types")
            .join("node");
        assert!(scoped_path.is_dir());
        assert!(
            !scoped_path
                .symlink_metadata()
                .unwrap()
                .file_type()
                .is_symlink()
        );

        // Isolated install on the same project.
        link_packages(project_dir.path(), &packages, false, None).unwrap();

        let post_iso_meta = scoped_path.symlink_metadata().unwrap();
        assert!(
            post_iso_meta.file_type().is_symlink(),
            "post-isolated: node_modules/@types/node MUST be a symlink"
        );
    }

    // ── `LinkResult.materialized` population ─────────────────────────
    //
    // The patch engine consumes `LinkResult.materialized` directly so it
    // never has to reverse-engineer linker shapes. These tests pin the
    // contract that the linker reports every physical destination it
    // wrote — including the `<project>/.lpm/hoisted/nested/<name>/`
    // shape (post-symmetry; pre-symmetry: `node_modules/.lpm/nested/`)
    // that the first draft of missed (D-design-1).

    #[test]
    fn isolated_mode_records_canonical_destination() {
        let store_dir = tempfile::tempdir().unwrap();
        let project_dir = tempfile::tempdir().unwrap();
        let store_path = create_fake_store_package(store_dir.path(), "lodash");

        let packages = vec![LinkTarget {
            name: "lodash".to_string(),
            version: "4.17.21".to_string(),
            store_path,
            dependencies: vec![],
            aliases: HashMap::new(),
            is_direct: true,
            root_link_names: None,
            wrapper_id: None,
            materialization: Materialization::CasBacked,
            peers: Vec::new(),
            patch_fingerprint: None,
        }];

        let result = link_packages(project_dir.path(), &packages, false, None).unwrap();

        // Exactly one materialized entry, pointing at the canonical
        // .lpm/<safe>@<ver>/node_modules/<name>/ path.
        assert_eq!(result.materialized.len(), 1);
        let m = &result.materialized[0];
        assert_eq!(m.name, "lodash");
        assert_eq!(m.version, "4.17.21");
        assert_eq!(
            m.destination,
            project_dir
                .path()
                .join(".lpm/wrappers/lodash@4.17.21/node_modules/lodash")
        );
        // The recorded destination must actually exist on disk after a
        // successful link — this is the user-visible contract.
        assert!(m.destination.exists());
        assert!(m.destination.join("package.json").exists());
    }

    #[test]
    fn isolated_mode_records_destination_on_marker_skip_path() {
        let store_dir = tempfile::tempdir().unwrap();
        let project_dir = tempfile::tempdir().unwrap();
        let store_path = create_fake_store_package(store_dir.path(), "lodash");

        let packages = vec![LinkTarget {
            name: "lodash".to_string(),
            version: "4.17.21".to_string(),
            store_path,
            dependencies: vec![],
            aliases: HashMap::new(),
            is_direct: true,
            root_link_names: None,
            wrapper_id: None,
            materialization: Materialization::CasBacked,
            peers: Vec::new(),
            patch_fingerprint: None,
        }];

        // First link populates the marker
        let _ = link_packages(project_dir.path(), &packages, false, None).unwrap();
        // Second link takes the marker-skip fast path
        let r2 = link_packages(project_dir.path(), &packages, false, None).unwrap();

        assert_eq!(r2.skipped, 1);
        // Materialized list MUST still be populated even on the skip
        // path — the patch engine needs the destination either way.
        assert_eq!(r2.materialized.len(), 1);
        assert!(r2.materialized[0].destination.exists());
    }

    #[test]
    fn hoisted_mode_records_root_and_under_hoisted_parent_destinations() {
        // Express + a transitive debug. Root-hoisted express, root-hoisted
        // debug. Materialized list should contain both roots.
        let store_dir = tempfile::tempdir().unwrap();
        let project_dir = tempfile::tempdir().unwrap();

        let express_store = create_fake_store_package(store_dir.path(), "express");
        let debug_store = create_fake_store_package(store_dir.path(), "debug");

        let packages = vec![
            LinkTarget {
                name: "express".to_string(),
                version: "4.22.1".to_string(),
                store_path: express_store,
                dependencies: vec![("debug".to_string(), "2.6.9".to_string())],
                aliases: HashMap::new(),
                is_direct: true,
                root_link_names: None,
                wrapper_id: None,
                materialization: Materialization::CasBacked,
                peers: Vec::new(),
                patch_fingerprint: None,
            },
            LinkTarget {
                name: "debug".to_string(),
                version: "2.6.9".to_string(),
                store_path: debug_store,
                dependencies: vec![],
                aliases: HashMap::new(),
                is_direct: false,
                root_link_names: None,
                wrapper_id: None,
                materialization: Materialization::CasBacked,
                peers: Vec::new(),
                patch_fingerprint: None,
            },
        ];

        let result = link_packages_hoisted(project_dir.path(), &packages, false, None).unwrap();

        // Both packages should be at root (no version conflict)
        let dests: Vec<&PathBuf> = result.materialized.iter().map(|m| &m.destination).collect();
        assert!(
            dests.contains(&&project_dir.path().join("node_modules/express")),
            "express root destination missing from materialized list"
        );
        assert!(
            dests.contains(&&project_dir.path().join("node_modules/debug")),
            "debug root destination missing from materialized list"
        );
    }

    #[test]
    fn hoisted_mode_records_lpm_nested_destination_when_parent_not_hoisted() {
        // Two competing versions of `debug`, neither parent is hoisted —
        // the loser-of-conflict should land at the hoisted-nested
        // fallback root (post-symmetry: `<project>/.lpm/hoisted/nested/debug`).
        // This is the F-V4 third shape that the first design draft
        // missed.
        let store_dir = tempfile::tempdir().unwrap();
        let project_dir = tempfile::tempdir().unwrap();

        // Create a fixture where the linker must use the .lpm/nested
        // shape. We need:
        //  - a hoisted "debug@2" (won the root slot first)
        //  - a "debug@3" that loses, with NO hoisted parent depending on it
        //
        // The simplest construction: two transitive deps under a
        // single direct dep, where the conflicting "debug@3" is depended
        // on by another transitive that is itself NOT hoisted (because
        // the same name was already taken).
        let direct_store = create_fake_store_package(store_dir.path(), "direct");
        let trans_store = create_fake_store_package(store_dir.path(), "trans");
        let trans2_store = create_fake_store_package(store_dir.path(), "trans");
        let debug_v2_store = create_fake_store_package(store_dir.path(), "debug-v2");
        let debug_v3_store = create_fake_store_package(store_dir.path(), "debug-v3");

        let packages = vec![
            LinkTarget {
                name: "direct".to_string(),
                version: "1.0.0".to_string(),
                store_path: direct_store,
                dependencies: vec![
                    ("trans".to_string(), "1.0.0".to_string()),
                    ("debug".to_string(), "2.0.0".to_string()),
                ],
                aliases: HashMap::new(),
                is_direct: true,
                root_link_names: None,
                wrapper_id: None,
                materialization: Materialization::CasBacked,
                peers: Vec::new(),
                patch_fingerprint: None,
            },
            LinkTarget {
                name: "trans".to_string(),
                version: "1.0.0".to_string(),
                store_path: trans_store,
                dependencies: vec![("debug".to_string(), "3.0.0".to_string())],
                aliases: HashMap::new(),
                is_direct: false,
                root_link_names: None,
                wrapper_id: None,
                materialization: Materialization::CasBacked,
                peers: Vec::new(),
                patch_fingerprint: None,
            },
            // Force a second `trans` version so trans@1.0.0 is NOT hoisted
            // (the second version wins root because it's identical here;
            // either way, neither variant is `is_direct`, so both lose to
            // a directly-declared `trans@2.0.0` if present).
            LinkTarget {
                name: "trans".to_string(),
                version: "2.0.0".to_string(),
                store_path: trans2_store,
                dependencies: vec![],
                aliases: HashMap::new(),
                is_direct: true,
                root_link_names: None,
                wrapper_id: None,
                materialization: Materialization::CasBacked,
                peers: Vec::new(),
                patch_fingerprint: None,
            },
            LinkTarget {
                name: "debug".to_string(),
                version: "2.0.0".to_string(),
                store_path: debug_v2_store,
                dependencies: vec![],
                aliases: HashMap::new(),
                is_direct: false,
                root_link_names: None,
                wrapper_id: None,
                materialization: Materialization::CasBacked,
                peers: Vec::new(),
                patch_fingerprint: None,
            },
            LinkTarget {
                name: "debug".to_string(),
                version: "3.0.0".to_string(),
                store_path: debug_v3_store,
                dependencies: vec![],
                aliases: HashMap::new(),
                is_direct: false,
                root_link_names: None,
                wrapper_id: None,
                materialization: Materialization::CasBacked,
                peers: Vec::new(),
                patch_fingerprint: None,
            },
        ];

        let result = link_packages_hoisted(project_dir.path(), &packages, false, None).unwrap();

        // The patch engine relies on the linker being authoritative.
        // We assert two contracts:
        //   1. Every physical copy on disk is reported in `materialized`.
        //   2. If any package landed at .lpm/nested/, it appears in the list.
        let dests: Vec<&PathBuf> = result.materialized.iter().map(|m| &m.destination).collect();
        for dest in &dests {
            assert!(
                dest.exists(),
                "materialized destination {dest:?} does not exist on disk"
            );
        }

        // The hoisted-nested shape may or may not be exercised
        // depending on hoist tie-breaking, but if the nested fallback
        // root exists at all, every package inside it must be in the
        // materialized list. Post-symmetry the nested root is at
        // `<project>/.lpm/hoisted/nested/`, resolved through
        // [`LayoutPaths`] so the fixture and production code can
        // never disagree on the location.
        let nested_root = LayoutPaths::for_project(project_dir.path()).hoisted_nested_root();
        if nested_root.exists() {
            for entry in std::fs::read_dir(&nested_root).unwrap().flatten() {
                let path = entry.path();
                assert!(
                    dests.contains(&&path),
                    "linker created {path:?} but did not report it in materialized"
                );
            }
        }
    }

    #[test]
    fn hoisted_mode_records_destinations_on_metadata_skip_path() {
        // Run the linker twice. The second run should hit the
        // metadata-fast-path (`needs_relink == false`). The materialized
        // list MUST still be populated — that's the offline-correctness
        // contract for the patch engine.
        let store_dir = tempfile::tempdir().unwrap();
        let project_dir = tempfile::tempdir().unwrap();

        let express_store = create_fake_store_package(store_dir.path(), "express");
        let debug_store = create_fake_store_package(store_dir.path(), "debug");

        let packages = vec![
            LinkTarget {
                name: "express".to_string(),
                version: "4.22.1".to_string(),
                store_path: express_store,
                dependencies: vec![],
                aliases: HashMap::new(),
                is_direct: true,
                root_link_names: None,
                wrapper_id: None,
                materialization: Materialization::CasBacked,
                peers: Vec::new(),
                patch_fingerprint: None,
            },
            LinkTarget {
                name: "debug".to_string(),
                version: "2.6.9".to_string(),
                store_path: debug_store,
                dependencies: vec![],
                aliases: HashMap::new(),
                is_direct: false,
                root_link_names: None,
                wrapper_id: None,
                materialization: Materialization::CasBacked,
                peers: Vec::new(),
                patch_fingerprint: None,
            },
        ];

        let _r1 = link_packages_hoisted(project_dir.path(), &packages, false, None).unwrap();
        let r2 = link_packages_hoisted(project_dir.path(), &packages, false, None).unwrap();

        // Skip path was taken
        assert!(r2.skipped > 0);
        // Materialized still populated end-to-end
        assert_eq!(r2.materialized.len(), 2);
        for m in &r2.materialized {
            assert!(m.destination.exists());
        }
    }

    // ── detach_package_hardlinks ─────────────────────────────────────
    //
    // Cross-platform invariants of the public function (returns 0 on
    // non-Linux, leaves files alone on every platform when nlink == 1,
    // never touches symlinks). The Linux-only inode-break test is
    // gated on `target_os = "linux"` because nlink semantics differ
    // on macOS APFS (clonefile produces nlink=1 by design).

    #[test]
    fn detach_returns_zero_on_empty_dir() {
        let dir = tempfile::tempdir().unwrap();
        let n = detach_package_hardlinks(dir.path()).unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn detach_leaves_symlinks_intact() {
        let dir = tempfile::tempdir().unwrap();
        // Plain file the symlink will point at.
        let target = dir.path().join("real.js");
        std::fs::write(&target, b"module.exports = 1").unwrap();
        // Symlink "alias.js" → "real.js" (relative).
        let link = dir.path().join("alias.js");
        #[cfg(unix)]
        std::os::unix::fs::symlink("real.js", &link).unwrap();
        #[cfg(windows)]
        std::os::windows::fs::symlink_file("real.js", &link).unwrap();

        detach_package_hardlinks(dir.path()).unwrap();

        // Symlink still exists AND still points at "real.js".
        let meta = std::fs::symlink_metadata(&link).unwrap();
        assert!(meta.file_type().is_symlink());
        let resolved = std::fs::read_link(&link).unwrap();
        assert_eq!(resolved, std::path::PathBuf::from("real.js"));
    }

    #[test]
    fn detach_recurses_into_subdirs_without_panicking() {
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("a").join("b").join("c");
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::write(nested.join("file.txt"), b"hello").unwrap();
        // No hardlinks → 0 detached, but recursion must visit every
        // level without blowing up.
        let n = detach_package_hardlinks(dir.path()).unwrap();
        assert_eq!(n, 0);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn detach_breaks_hardlink_so_writes_dont_touch_store() {
        use std::os::unix::fs::MetadataExt;

        // Simulate the linker's Linux path: a "store" dir holds the
        // canonical bytes; a "live" dir hardlinks them. After detach,
        // mutating the live copy must NOT mutate the store copy.
        let store = tempfile::tempdir().unwrap();
        let live = tempfile::tempdir().unwrap();

        let store_file = store.path().join("package.json");
        std::fs::write(&store_file, b"{\"name\":\"esbuild\",\"v\":\"0.21.5\"}").unwrap();

        let live_file = live.path().join("package.json");
        std::fs::hard_link(&store_file, &live_file).unwrap();

        // Sanity: shared inode, nlink == 2 on both sides.
        let store_ino_before = std::fs::metadata(&store_file).unwrap().ino();
        let live_ino_before = std::fs::metadata(&live_file).unwrap().ino();
        assert_eq!(store_ino_before, live_ino_before);
        assert_eq!(std::fs::metadata(&store_file).unwrap().nlink(), 2);

        // Detach.
        let detached = detach_package_hardlinks(live.path()).unwrap();
        assert_eq!(detached, 1, "exactly one file should have been detached");

        // After detach: live and store have DIFFERENT inodes.
        let store_ino_after = std::fs::metadata(&store_file).unwrap().ino();
        let live_ino_after = std::fs::metadata(&live_file).unwrap().ino();
        assert_ne!(
            store_ino_after, live_ino_after,
            "live and store must point at different inodes after detach"
        );
        // Store's nlink is back to 1 (we removed our link to it).
        assert_eq!(std::fs::metadata(&store_file).unwrap().nlink(), 1);
        // Content preserved on both sides.
        assert_eq!(
            std::fs::read(&store_file).unwrap(),
            b"{\"name\":\"esbuild\",\"v\":\"0.21.5\"}"
        );
        assert_eq!(
            std::fs::read(&live_file).unwrap(),
            b"{\"name\":\"esbuild\",\"v\":\"0.21.5\"}"
        );

        // The core invariant: writing to live must NOT mutate store.
        std::fs::write(&live_file, b"MUTATED-BY-POSTINSTALL").unwrap();
        assert_eq!(
            std::fs::read(&store_file).unwrap(),
            b"{\"name\":\"esbuild\",\"v\":\"0.21.5\"}",
            "store content must be unchanged after writing to live copy"
        );
        assert_eq!(
            std::fs::read(&live_file).unwrap(),
            b"MUTATED-BY-POSTINSTALL"
        );

        // No leftover .lpm-detach-tmp-* files.
        for entry in std::fs::read_dir(live.path()).unwrap() {
            let n = entry.unwrap().file_name();
            let s = n.to_string_lossy();
            assert!(
                !s.starts_with(".lpm-detach-tmp-"),
                "temp file leaked into the live dir: {s}"
            );
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn detach_is_idempotent_already_independent_files_skipped() {
        // First call detaches; second call observes nlink == 1 and
        // does nothing. This matches the rebuild-loop invariant where
        // a re-run of `lpm rebuild` on an already-detached project
        // must be a fast no-op, not a redundant copy.
        use std::os::unix::fs::MetadataExt;

        let store = tempfile::tempdir().unwrap();
        let live = tempfile::tempdir().unwrap();
        let store_file = store.path().join("file");
        std::fs::write(&store_file, b"x").unwrap();
        std::fs::hard_link(&store_file, live.path().join("file")).unwrap();

        let first = detach_package_hardlinks(live.path()).unwrap();
        assert_eq!(first, 1);
        let second = detach_package_hardlinks(live.path()).unwrap();
        assert_eq!(second, 0);

        // And a plain non-hardlinked file (nlink == 1) is left alone
        // even on the first pass.
        let solo = tempfile::tempdir().unwrap();
        std::fs::write(solo.path().join("solo.txt"), b"y").unwrap();
        assert_eq!(
            std::fs::metadata(solo.path().join("solo.txt"))
                .unwrap()
                .nlink(),
            1
        );
        let n = detach_package_hardlinks(solo.path()).unwrap();
        assert_eq!(n, 0);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn detach_recurses_and_breaks_links_in_subdirs() {
        // The lifecycle-script package shape has nested files
        // (`./bin/foo`, `./lib/index.js`, etc). Detach must reach
        // them, not just the top level.
        use std::os::unix::fs::MetadataExt;

        let store = tempfile::tempdir().unwrap();
        let live = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(store.path().join("bin")).unwrap();
        std::fs::create_dir_all(live.path().join("bin")).unwrap();
        let store_bin = store.path().join("bin").join("esbuild");
        std::fs::write(&store_bin, b"#!/bin/sh\necho real").unwrap();
        std::fs::hard_link(&store_bin, live.path().join("bin").join("esbuild")).unwrap();

        let n = detach_package_hardlinks(live.path()).unwrap();
        assert_eq!(n, 1);

        let store_ino = std::fs::metadata(&store_bin).unwrap().ino();
        let live_ino = std::fs::metadata(live.path().join("bin").join("esbuild"))
            .unwrap()
            .ino();
        assert_ne!(store_ino, live_ino);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn detach_sweeps_leftover_temp_files_from_a_prior_failed_run() {
        // Simulate the post-crash state where a previous detach pass
        // got interrupted between `fs::copy` and `fs::rename`: a
        // `.lpm-detach-tmp-<ino>` file is left in the package dir.
        // The next pass must remove it (otherwise Node `readdir`
        // calls inside the package would see it and could break
        // packages that enumerate their own files).
        let dir = tempfile::tempdir().unwrap();
        let stale = dir.path().join(".lpm-detach-tmp-99999");
        std::fs::write(&stale, b"orphaned").unwrap();
        std::fs::write(dir.path().join("real.json"), b"{}").unwrap();

        detach_package_hardlinks(dir.path()).unwrap();

        assert!(!stale.exists(), "stale temp file must be swept");
        assert!(
            dir.path().join("real.json").exists(),
            "non-temp files must be left alone"
        );
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn detach_is_noop_on_non_linux() {
        // The function compiles on every platform but only does
        // work on Linux. On macOS / Windows the linker uses
        // clonefile / copy respectively, so the live copy is
        // already independent at link time.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("file.txt"), b"x").unwrap();
        let n = detach_package_hardlinks(dir.path()).unwrap();
        assert_eq!(n, 0);
        // File untouched.
        assert_eq!(std::fs::read(dir.path().join("file.txt")).unwrap(), b"x");
    }

    // ── wrapper_segment + materialize_directory_source ───────────────

    fn make_local_source_dir(root: &Path, name: &str) -> PathBuf {
        let pkg = root.join(name);
        std::fs::create_dir_all(&pkg).unwrap();
        std::fs::write(
            pkg.join("package.json"),
            format!("{{\"name\":\"{name}\",\"version\":\"0.0.0\"}}"),
        )
        .unwrap();
        std::fs::write(pkg.join("index.js"), b"module.exports = 'src';").unwrap();
        pkg
    }

    #[test]
    fn wrapper_segment_uses_at_for_cas_backed_targets() {
        let target = LinkTarget {
            name: "express".to_string(),
            version: "4.22.1".to_string(),
            store_path: PathBuf::from("/tmp/store"),
            dependencies: vec![],
            aliases: HashMap::new(),
            is_direct: true,
            root_link_names: None,
            wrapper_id: None,
            materialization: Materialization::CasBacked,
            peers: Vec::new(),
            patch_fingerprint: None,
        };
        assert_eq!(target.wrapper_segment(), "express@4.22.1");
    }

    #[test]
    fn wrapper_segment_uses_plus_for_local_source_targets() {
        let target = LinkTarget {
            name: "my-lib".to_string(),
            version: "0.0.0".to_string(),
            store_path: PathBuf::from("/tmp/source"),
            dependencies: vec![],
            aliases: HashMap::new(),
            is_direct: true,
            root_link_names: None,
            wrapper_id: Some("f-1234567890abcdef".to_string()),
            materialization: Materialization::DirectorySource,
            peers: Vec::new(),
            patch_fingerprint: None,
        };
        assert_eq!(target.wrapper_segment(), "my-lib+f-1234567890abcdef");
    }

    #[test]
    fn wrapper_segment_sanitizes_scoped_names() {
        // `/` is replaced with `+` for filesystem safety in BOTH
        // shapes — the only difference is the version-vs-wrapper-id
        // tail.
        let cas = LinkTarget {
            name: "@scope/pkg".to_string(),
            version: "1.0.0".to_string(),
            store_path: PathBuf::from("/tmp/store"),
            dependencies: vec![],
            aliases: HashMap::new(),
            is_direct: true,
            root_link_names: None,
            wrapper_id: None,
            materialization: Materialization::CasBacked,
            peers: Vec::new(),
            patch_fingerprint: None,
        };
        assert_eq!(cas.wrapper_segment(), "@scope+pkg@1.0.0");

        let local = LinkTarget {
            name: "@scope/pkg".to_string(),
            version: "0.0.0".to_string(),
            store_path: PathBuf::from("/tmp/source"),
            dependencies: vec![],
            aliases: HashMap::new(),
            is_direct: true,
            root_link_names: None,
            wrapper_id: Some("f-abcd".to_string()),
            materialization: Materialization::DirectorySource,
            peers: Vec::new(),
            patch_fingerprint: None,
        };
        assert_eq!(local.wrapper_segment(), "@scope+pkg+f-abcd");
    }

    #[test]
    fn materialize_directory_source_creates_per_file_symlinks() {
        let root = tempfile::tempdir().unwrap();
        let src = make_local_source_dir(root.path(), "lib");
        let dst = root.path().join("dst");

        let count = materialize_directory_source(&src, &dst).unwrap();

        // package.json + index.js = 2 files → 2 symlinks.
        assert_eq!(count, 2);
        assert!(
            dst.join("package.json")
                .symlink_metadata()
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert!(
            dst.join("index.js")
                .symlink_metadata()
                .unwrap()
                .file_type()
                .is_symlink()
        );
        // Read-through works.
        assert_eq!(
            std::fs::read(dst.join("index.js")).unwrap(),
            b"module.exports = 'src';"
        );
    }

    #[test]
    fn materialize_directory_source_handles_nested_subdirectories() {
        let root = tempfile::tempdir().unwrap();
        let src = make_local_source_dir(root.path(), "nested-lib");
        let lib_subdir = src.join("src").join("util");
        std::fs::create_dir_all(&lib_subdir).unwrap();
        std::fs::write(lib_subdir.join("helper.js"), b"export const x = 1").unwrap();

        let dst = root.path().join("dst");
        let count = materialize_directory_source(&src, &dst).unwrap();

        // 2 top-level + 1 nested = 3 symlinks. Subdirectories are
        // real dirs in the wrapper.
        assert_eq!(count, 3);
        assert!(dst.join("src").join("util").is_dir());
        assert!(
            !dst.join("src")
                .symlink_metadata()
                .unwrap()
                .file_type()
                .is_symlink(),
            "nested dir must be a real dir, not a symlink",
        );
        assert!(
            dst.join("src/util/helper.js")
                .symlink_metadata()
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }

    #[test]
    fn materialize_directory_source_excludes_node_modules() {
        let root = tempfile::tempdir().unwrap();
        let src = make_local_source_dir(root.path(), "with-deps");
        // Top-level node_modules.
        let nm = src.join("node_modules");
        std::fs::create_dir_all(nm.join("hidden")).unwrap();
        std::fs::write(nm.join("hidden/index.js"), b"hidden").unwrap();
        // Nested node_modules under a regular subdir — also excluded
        // (recursive exclusion).
        std::fs::create_dir_all(src.join("packages/inner/node_modules")).unwrap();
        std::fs::write(
            src.join("packages/inner/node_modules/hidden.js"),
            b"hidden-nested",
        )
        .unwrap();
        std::fs::write(src.join("packages/inner/visible.js"), b"visible").unwrap();

        let dst = root.path().join("dst");
        materialize_directory_source(&src, &dst).unwrap();

        // node_modules/ subtree never created.
        assert!(!dst.join("node_modules").exists());
        // Nested node_modules also skipped, but its sibling visible.js
        // survives.
        assert!(!dst.join("packages/inner/node_modules").exists());
        assert!(dst.join("packages/inner/visible.js").exists());
    }

    #[test]
    fn materialize_directory_source_excludes_dot_git() {
        let root = tempfile::tempdir().unwrap();
        let src = make_local_source_dir(root.path(), "with-git");
        let git = src.join(".git");
        std::fs::create_dir_all(git.join("objects/aa")).unwrap();
        std::fs::write(git.join("HEAD"), b"ref: refs/heads/main").unwrap();
        std::fs::write(git.join("objects/aa/something"), b"git-object").unwrap();

        let dst = root.path().join("dst");
        materialize_directory_source(&src, &dst).unwrap();

        assert!(!dst.join(".git").exists(), ".git must be excluded");
        // Other dotfiles preserved (e.g., .npmrc would be).
        std::fs::write(src.join(".npmrc"), b"registry=https://x").unwrap();
        let dst2 = root.path().join("dst2");
        materialize_directory_source(&src, &dst2).unwrap();
        assert!(
            dst2.join(".npmrc").exists(),
            "non-.git/non-node_modules dotfiles must survive",
        );
    }

    #[test]
    fn materialize_directory_source_symlinks_target_canonical_source() {
        let root = tempfile::tempdir().unwrap();
        let src = make_local_source_dir(root.path(), "abs-target");
        let dst = root.path().join("dst");
        materialize_directory_source(&src, &dst).unwrap();

        let link_target = std::fs::read_link(dst.join("index.js")).unwrap();
        // Symlinks are absolute (matches bun's strategy).
        assert!(
            link_target.is_absolute(),
            "wrapper symlinks must be absolute, got {link_target:?}",
        );
        // And they point at the canonicalized source path.
        let canon_src = src.canonicalize().unwrap();
        assert_eq!(link_target, canon_src.join("index.js"));
    }

    #[test]
    fn materialize_directory_source_edits_visible_through_wrapper() {
        // The point of per-file symlinks: edits to the source file
        // are visible immediately via the wrapper, no relink needed.
        // This is the dev-loop UX contract for file: deps.
        let root = tempfile::tempdir().unwrap();
        let src = make_local_source_dir(root.path(), "live-edit");
        let dst = root.path().join("dst");
        materialize_directory_source(&src, &dst).unwrap();

        // Initial content visible.
        assert_eq!(
            std::fs::read(dst.join("index.js")).unwrap(),
            b"module.exports = 'src';"
        );

        // Mutate the SOURCE file (not the wrapper).
        std::fs::write(src.join("index.js"), b"module.exports = 'edited';").unwrap();

        // Edit visible through the wrapper — no re-link required.
        assert_eq!(
            std::fs::read(dst.join("index.js")).unwrap(),
            b"module.exports = 'edited';"
        );
    }

    #[test]
    fn materialize_directory_source_errors_on_missing_source() {
        let root = tempfile::tempdir().unwrap();
        let missing = root.path().join("does-not-exist");
        let dst = root.path().join("dst");
        let err = materialize_directory_source(&missing, &dst)
            .expect_err("materialize must error when the source path does not exist");
        // Error message names the source path so users can debug.
        let msg = format!("{err:?}");
        assert!(
            msg.contains("does-not-exist") || msg.contains("phase-59.1"),
            "got: {msg}"
        );
    }

    /// **symlink escape.** A
    /// symlink in the source tree that resolves OUTSIDE the source's
    /// own realpath still materializes successfully (matches Node's
    /// resolution from the source itself), but the wrapper symlink
    /// points at the off-tree target. The contract is intentional:
    /// the linker is transparent to whatever the source declares.
    /// This test pins the success-with-escape behavior so a future
    /// reviewer doesn't tighten the warn into a hard error.
    #[cfg(unix)]
    #[test]
    fn materialize_directory_source_passes_through_symlink_that_escapes_root() {
        let root = tempfile::tempdir().unwrap();
        // Create the escape target OUTSIDE the source root.
        let outside_dir = root.path().join("outside");
        std::fs::create_dir_all(&outside_dir).unwrap();
        let outside_file = outside_dir.join("config.json");
        std::fs::write(&outside_file, b"{\"escape\":true}").unwrap();

        let src = make_local_source_dir(root.path(), "escape-pkg");
        // Symlink inside the source pointing OUT of the source root.
        let escape_link = src.join("config.json");
        std::os::unix::fs::symlink(&outside_file, &escape_link).unwrap();

        let dst = root.path().join("dst");
        let count = materialize_directory_source(&src, &dst)
            .expect("escape symlinks materialize successfully (warn-only)");
        assert!(
            count > 0,
            "at least one entry (the escape symlink + the package.json from make_local_source_dir) materialized"
        );
        // Wrapper symlink points at the off-tree target's realpath.
        let wrapper_link = dst.join("config.json");
        assert!(
            wrapper_link
                .symlink_metadata()
                .unwrap()
                .file_type()
                .is_symlink(),
            "wrapper entry must be a symlink, even when target escapes",
        );
        let resolved = wrapper_link.canonicalize().unwrap();
        assert_eq!(
            resolved,
            outside_file.canonicalize().unwrap(),
            "wrapper symlink resolves to the off-tree target, transparent to the source",
        );
    }

    /// **depth bound.** Pre-
    /// round-7 `walk_directory_source` was unbounded; a maliciously-
    /// or accidentally-deep source tree could blow the stack. This
    /// test verifies that depth beyond [`MAX_DIRECTORY_SOURCE_DEPTH`]
    /// produces a clean error rather than a stack overflow.
    ///
    /// Constructs a chain `src/a/a/a/.../a/file.js` with depth +5
    /// past the bound. Single-letter dir names keep total path under
    /// the OS's PATH_MAX even at depth 261.
    #[test]
    fn materialize_directory_source_errors_above_depth_bound() {
        let root = tempfile::tempdir().unwrap();
        let src = root.path().join("deep-pkg");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(
            src.join("package.json"),
            br#"{"name":"deep-pkg","version":"0.0.0"}"#,
        )
        .unwrap();

        let mut deep_path = src.clone();
        for _ in 0..(MAX_DIRECTORY_SOURCE_DEPTH + 5) {
            deep_path.push("a");
        }
        std::fs::create_dir_all(&deep_path).unwrap();
        std::fs::write(deep_path.join("leaf.js"), b"// leaf\n").unwrap();

        let dst = root.path().join("dst");
        let err = materialize_directory_source(&src, &dst)
            .expect_err("walk must error past MAX_DIRECTORY_SOURCE_DEPTH");
        let msg = format!("{err:?}");
        assert!(
            msg.contains("maximum walk depth"),
            "depth-bound error message should mention the limit; got: {msg}"
        );
    }

    // ── link_one_package + link_finalize integration with wrapper_id ────────

    #[test]
    fn link_one_package_directory_uses_per_file_symlinks_and_plus_wrapper() {
        // End-to-end: a LinkTarget with wrapper_id Some(...) goes
        // through the per-file-symlink path AND lands in a
        // `+`-shaped wrapper. The `.linked` marker is written
        // post-link so the marker check still works.
        let root = tempfile::tempdir().unwrap();
        let project_dir = root.path().join("project");
        let src = make_local_source_dir(root.path(), "local-foo");

        // Cleanup_stale_entries creates node_modules/.lpm; we mimic
        // its precondition by calling link_packages() directly.
        let target = LinkTarget {
            name: "local-foo".to_string(),
            version: "0.0.0".to_string(),
            store_path: src.clone(),
            dependencies: vec![],
            aliases: HashMap::new(),
            is_direct: true,
            root_link_names: Some(vec!["local-foo".to_string()]),
            wrapper_id: Some("f-deadbeef00000000".to_string()),
            materialization: Materialization::DirectorySource,
            peers: Vec::new(),
            patch_fingerprint: None,
        };

        let result = link_packages(&project_dir, &[target], false, None).unwrap();
        assert_eq!(result.linked, 1);

        // Wrapper at the `+` shape, not `@`.
        let wrapper = project_dir.join(".lpm/wrappers/local-foo+f-deadbeef00000000");
        assert!(wrapper.is_dir(), "expected wrapper at {wrapper:?}");
        let pkg_nm = wrapper.join("node_modules/local-foo");
        assert!(pkg_nm.is_dir(), "wrapper's pkg dir missing: {pkg_nm:?}");
        // Per-file symlinks materialized.
        assert!(
            pkg_nm
                .join("index.js")
                .symlink_metadata()
                .unwrap()
                .file_type()
                .is_symlink()
        );
        // `.linked` marker present on the wrapper itself, not the
        // pkg_nm subtree.
        assert!(wrapper.join(".linked").exists());

        // Root symlink at node_modules/local-foo points at the
        // wrapper's pkg_nm slot.
        let root_link = project_dir.join("node_modules/local-foo");
        let resolved = root_link.canonicalize().unwrap();
        assert_eq!(resolved, pkg_nm.canonicalize().unwrap());
    }

    #[test]
    fn link_one_package_registry_unaffected_by_wrapper_id_change() {
        // Regression: when wrapper_id is None, link_one_package
        // continues to use link_dir_recursive (hardlink/clonefile/
        // copy) and the `@`-shape wrapper. Day-2 must not regress
        // any registry-source linking.
        let root = tempfile::tempdir().unwrap();
        let store_dir = root.path().join("store");
        let project_dir = root.path().join("project");
        let store_path = create_fake_store_package(&store_dir, "foo");

        let target = LinkTarget {
            name: "foo".to_string(),
            version: "1.0.0".to_string(),
            store_path,
            dependencies: vec![],
            aliases: HashMap::new(),
            is_direct: true,
            root_link_names: None,
            wrapper_id: None,
            materialization: Materialization::CasBacked,
            peers: Vec::new(),
            patch_fingerprint: None,
        };

        link_packages(&project_dir, &[target], false, None).unwrap();

        // Wrapper at `@`-shape.
        assert!(
            project_dir
                .join(".lpm/wrappers/foo@1.0.0/node_modules/foo/package.json")
                .exists(),
        );
        // Top-level pkg files materialized as REAL files (hardlink
        // / clonefile), not symlinks. (On macOS this is a clonefile
        // result, which symlink_metadata reports as a regular file.)
        let pkg_json_meta = project_dir
            .join(".lpm/wrappers/foo@1.0.0/node_modules/foo/package.json")
            .symlink_metadata()
            .unwrap();
        assert!(
            !pkg_json_meta.file_type().is_symlink(),
            "registry-source materialization must not be symlinks",
        );
    }

    /// The `.linked` marker carries a stamp encoding the LinkTarget's
    /// identity. After a successful materialization the marker file
    /// must contain the stamp text, not empty bytes.
    #[test]
    fn link_one_package_writes_stamped_marker() {
        let root = tempfile::tempdir().unwrap();
        let store_dir = root.path().join("store");
        let project_dir = root.path().join("project");
        let store_path = create_fake_store_package(&store_dir, "foo");

        let target = LinkTarget {
            name: "foo".to_string(),
            version: "1.0.0".to_string(),
            store_path: store_path.clone(),
            dependencies: vec![],
            aliases: HashMap::new(),
            is_direct: true,
            root_link_names: None,
            wrapper_id: None,
            materialization: Materialization::CasBacked,
            peers: Vec::new(),
            patch_fingerprint: None,
        };

        link_packages(&project_dir, std::slice::from_ref(&target), false, None).unwrap();

        let marker = project_dir.join(".lpm/wrappers/foo@1.0.0/.linked");
        let on_disk = std::fs::read_to_string(&marker).unwrap();
        assert!(
            !on_disk.is_empty(),
            "post-round-3 marker must carry an identity stamp, not be empty",
        );
        assert!(
            on_disk.starts_with("lpm-link-stamp v2\n"),
            "stamp must start with the v2 header for forward-compat reads: {on_disk:?}",
        );
        assert_eq!(
            on_disk,
            compute_link_stamp(&target),
            "on-disk stamp must round-trip with compute_link_stamp",
        );
    }

    /// **stamp mismatch.** The
    /// auditor's MEDIUM scenario: a wrapper materialized from one
    /// LinkTarget (e.g., a pre-round-1 tarball at `.lpm/foo@1.0.0/`)
    /// must not be reused by a subsequent install of a DIFFERENT
    /// source kind that happens to share the same wrapper segment
    /// (e.g., post-round-1 registry `foo@1.0.0`). The stamp check
    /// detects the mismatch and forces re-materialization.
    #[test]
    fn link_one_package_relinks_when_marker_stamp_does_not_match() {
        let root = tempfile::tempdir().unwrap();
        let store_dir = root.path().join("store");
        let project_dir = root.path().join("project");

        // First install: source A lands at `.lpm/foo@1.0.0/` with
        // marker stamp identifying source A.
        let store_a = create_fake_store_package(&store_dir, "foo-a");
        std::fs::write(
            store_a.join("package.json"),
            r#"{"name":"foo","version":"1.0.0","_marker":"source-a"}"#,
        )
        .unwrap();
        let target_a = LinkTarget {
            name: "foo".to_string(),
            version: "1.0.0".to_string(),
            store_path: store_a,
            dependencies: vec![],
            aliases: HashMap::new(),
            is_direct: true,
            root_link_names: None,
            wrapper_id: None,
            materialization: Materialization::CasBacked,
            peers: Vec::new(),
            patch_fingerprint: None,
        };
        link_packages(&project_dir, &[target_a], false, None).unwrap();

        let pkg_json_path =
            project_dir.join(".lpm/wrappers/foo@1.0.0/node_modules/foo/package.json");
        let marker = project_dir.join(".lpm/wrappers/foo@1.0.0/.linked");
        let after_first: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&pkg_json_path).unwrap()).unwrap();
        assert_eq!(after_first["_marker"].as_str(), Some("source-a"));
        assert!(marker.exists(), "first install must write marker");

        // Second install: a DIFFERENT source materialized to the
        // same wrapper segment. Different store_path means a
        // different stamp; the marker check must detect the
        // mismatch and re-materialize.
        let store_b = create_fake_store_package(&store_dir, "foo-b");
        std::fs::write(
            store_b.join("package.json"),
            r#"{"name":"foo","version":"1.0.0","_marker":"source-b"}"#,
        )
        .unwrap();
        let target_b = LinkTarget {
            name: "foo".to_string(),
            version: "1.0.0".to_string(),
            store_path: store_b,
            dependencies: vec![],
            aliases: HashMap::new(),
            is_direct: true,
            root_link_names: None,
            wrapper_id: None,
            materialization: Materialization::CasBacked,
            peers: Vec::new(),
            patch_fingerprint: None,
        };
        link_packages(&project_dir, std::slice::from_ref(&target_b), false, None).unwrap();

        // The wrapper now contains source B's package.json — proves
        // the stamp-mismatch branch fired and re-materialized
        // instead of silently reusing source A's bytes.
        let after_second: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&pkg_json_path).unwrap()).unwrap();
        assert_eq!(
            after_second["_marker"].as_str(),
            Some("source-b"),
            "stamp mismatch must force re-materialization with the new source",
        );
        // And the marker now reflects target_b's identity.
        let new_stamp = std::fs::read_to_string(&marker).unwrap();
        assert_eq!(
            new_stamp,
            compute_link_stamp(&target_b),
            "marker must be rewritten with the new target's stamp on relink",
        );
    }

    /// Legacy empty `.linked` markers (`fs::write(marker, "")`) must
    /// be treated as a stamp mismatch and force re-materialization,
    /// not silently trusted as "wrapper is valid".
    #[test]
    fn link_one_package_relinks_when_legacy_empty_marker_present() {
        let root = tempfile::tempdir().unwrap();
        let store_dir = root.path().join("store");
        let project_dir = root.path().join("project");

        // Manually plant a pre-round-3 wrapper: a directory with
        // some "stale" bytes and an EMPTY .linked marker — the exact
        // shape pre-round-3 installs left on disk.
        let wrapper_pkg_nm = project_dir.join(".lpm/wrappers/foo@1.0.0/node_modules/foo");
        std::fs::create_dir_all(&wrapper_pkg_nm).unwrap();
        std::fs::write(
            wrapper_pkg_nm.join("package.json"),
            r#"{"name":"foo","version":"1.0.0","_marker":"stale-pre-r3"}"#,
        )
        .unwrap();
        let marker = project_dir.join(".lpm/wrappers/foo@1.0.0/.linked");
        std::fs::write(&marker, "").unwrap();

        // Sanity: the marker is empty as a pre-round-3 install would leave it.
        assert_eq!(std::fs::read_to_string(&marker).unwrap(), "");

        // New install with a fresh source. Same wrapper segment as
        // the legacy planted dir.
        let store_path = create_fake_store_package(&store_dir, "fresh-foo");
        std::fs::write(
            store_path.join("package.json"),
            r#"{"name":"foo","version":"1.0.0","_marker":"fresh-r3"}"#,
        )
        .unwrap();
        let target = LinkTarget {
            name: "foo".to_string(),
            version: "1.0.0".to_string(),
            store_path,
            dependencies: vec![],
            aliases: HashMap::new(),
            is_direct: true,
            root_link_names: None,
            wrapper_id: None,
            materialization: Materialization::CasBacked,
            peers: Vec::new(),
            patch_fingerprint: None,
        };
        link_packages(&project_dir, std::slice::from_ref(&target), false, None).unwrap();

        // Wrapper must now reflect the FRESH source, not the legacy
        // planted bytes — proves the empty-marker fast-path didn't
        // skip the relink.
        let pkg_json_path = wrapper_pkg_nm.join("package.json");
        let after: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&pkg_json_path).unwrap()).unwrap();
        assert_eq!(
            after["_marker"].as_str(),
            Some("fresh-r3"),
            "legacy empty marker must not bypass the round-3 stamp check",
        );
        // Marker now stamped.
        assert_eq!(
            std::fs::read_to_string(&marker).unwrap(),
            compute_link_stamp(&target),
        );
    }

    /// **stale dep edges.** The
    /// auditor's MEDIUM finding for round 4: round-3's stamp check
    /// removed only `pkg_nm` on relink, leaving the SIBLING
    /// `.lpm/<segment>/node_modules/<other>` symlinks (the wrapper's
    /// dep edges) in place. Stage 2's "skip if dep_link.exists"
    /// guard then preserved any stale dep edge from the previous
    /// LinkTarget. The auditor reproduced this with a small harness:
    /// target A creates a `leftpad` symlink, target B reuses the same
    /// `foo@1.0.0` segment with no deps, leftpad survives. Round-4
    /// fix: wipe the full `pkg_entry_dir` instead of just `pkg_nm`,
    /// so the next materialization starts from a clean slate.
    #[test]
    fn link_one_package_clears_stale_dep_edges_on_stamp_mismatch_relink() {
        let root = tempfile::tempdir().unwrap();
        let store_dir = root.path().join("store");
        let project_dir = root.path().join("project");

        // Sibling dep target (so the Stage 2 dep loop has somewhere
        // to point its symlink). Doesn't need a wrapper id; CAS-shape
        // segment lands at `.lpm/leftpad@1.0.0/`.
        let leftpad_store = create_fake_store_package(&store_dir, "leftpad");
        let leftpad_target = LinkTarget {
            name: "leftpad".to_string(),
            version: "1.0.0".to_string(),
            store_path: leftpad_store,
            dependencies: vec![],
            aliases: HashMap::new(),
            is_direct: false,
            root_link_names: Some(Vec::new()),
            wrapper_id: None,
            materialization: Materialization::CasBacked,
            peers: Vec::new(),
            patch_fingerprint: None,
        };

        // First install: target A declares a `leftpad` dep, so the
        // wrapper at `.lpm/foo@1.0.0/` will get a sibling symlink at
        // `node_modules/leftpad`.
        let pkg_a_store = create_fake_store_package(&store_dir, "foo-a");
        std::fs::write(
            pkg_a_store.join("package.json"),
            r#"{"name":"foo","version":"1.0.0","_marker":"a"}"#,
        )
        .unwrap();
        let target_a = LinkTarget {
            name: "foo".to_string(),
            version: "1.0.0".to_string(),
            store_path: pkg_a_store,
            dependencies: vec![("leftpad".to_string(), "1.0.0".to_string())],
            aliases: HashMap::new(),
            is_direct: true,
            root_link_names: Some(vec!["foo".to_string()]),
            wrapper_id: None,
            materialization: Materialization::CasBacked,
            peers: Vec::new(),
            patch_fingerprint: None,
        };
        link_packages(
            &project_dir,
            &[target_a, leftpad_target.clone()],
            false,
            None,
        )
        .unwrap();

        let leftpad_symlink = project_dir.join(".lpm/wrappers/foo@1.0.0/node_modules/leftpad");
        assert!(
            leftpad_symlink.symlink_metadata().is_ok(),
            "leftpad sibling symlink must exist after target A's install",
        );

        // Second install: target B reuses the SAME `foo@1.0.0` segment
        // (so cleanup_stale_entries preserves the wrapper) but has a
        // DIFFERENT `store_path` (so the stamp mismatches) AND no
        // dependencies. Round-4 fix: the stamp-mismatch branch must
        // wipe the full pkg_entry_dir, taking the stale leftpad
        // sibling symlink with it. Pre-round-4 only `pkg_nm` was
        // removed and leftpad survived.
        let pkg_b_store = create_fake_store_package(&store_dir, "foo-b");
        std::fs::write(
            pkg_b_store.join("package.json"),
            r#"{"name":"foo","version":"1.0.0","_marker":"b"}"#,
        )
        .unwrap();
        let target_b = LinkTarget {
            name: "foo".to_string(),
            version: "1.0.0".to_string(),
            store_path: pkg_b_store,
            dependencies: vec![], // <- intentionally empty
            aliases: HashMap::new(),
            is_direct: true,
            root_link_names: Some(vec!["foo".to_string()]),
            wrapper_id: None,
            materialization: Materialization::CasBacked,
            peers: Vec::new(),
            patch_fingerprint: None,
        };
        link_packages(&project_dir, &[target_b, leftpad_target], false, None).unwrap();

        // Strongest assertion of the round-4 fix: leftpad sibling is
        // GONE because the wrapper was wiped on stamp mismatch.
        assert!(
            leftpad_symlink.symlink_metadata().is_err(),
            "stale sibling dep edge must be cleared on stamp-mismatch relink — \
             round-4 contract: wipe pkg_entry_dir, not just pkg_nm. Found: {:?}",
            leftpad_symlink.symlink_metadata(),
        );

        // Sanity: target B's package.json is what's at the wrapper now.
        let after: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(
                project_dir.join(".lpm/wrappers/foo@1.0.0/node_modules/foo/package.json"),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(after["_marker"].as_str(), Some("b"));
    }

    /// The stamp must encode dep edges. Without them, two installs
    /// with the SAME `store_path` but DIFFERENT `target.dependencies`
    /// (e.g., child resolved version went `leftpad@1.0.0` →
    /// `leftpad@2.0.0`) produce identical stamps. The fast path then
    /// skips relinking and Stage 2's "skip if exists" dep loop keeps
    /// the stale dep symlink pointing at the OLD child wrapper.
    #[test]
    fn link_one_package_relinks_when_only_dep_edges_change_v2_stamp() {
        let root = tempfile::tempdir().unwrap();
        let store_dir = root.path().join("store");
        let project_dir = root.path().join("project");

        // Two distinct child versions, materialized at distinct
        // wrapper segments by the linker's CAS-shape rule.
        let leftpad1_store = create_fake_store_package(&store_dir, "leftpad-v1");
        let leftpad1_target = LinkTarget {
            name: "leftpad".to_string(),
            version: "1.0.0".to_string(),
            store_path: leftpad1_store,
            dependencies: vec![],
            aliases: HashMap::new(),
            is_direct: false,
            root_link_names: Some(Vec::new()),
            wrapper_id: None,
            materialization: Materialization::CasBacked,
            peers: Vec::new(),
            patch_fingerprint: None,
        };
        let leftpad2_store = create_fake_store_package(&store_dir, "leftpad-v2");
        let leftpad2_target = LinkTarget {
            name: "leftpad".to_string(),
            version: "2.0.0".to_string(),
            store_path: leftpad2_store,
            dependencies: vec![],
            aliases: HashMap::new(),
            is_direct: false,
            root_link_names: Some(Vec::new()),
            wrapper_id: None,
            materialization: Materialization::CasBacked,
            peers: Vec::new(),
            patch_fingerprint: None,
        };

        // The same `foo` source — same `store_path` across both runs.
        // Only `dependencies` changes between target_a and target_b.
        let foo_source = create_fake_store_package(&store_dir, "foo-source");
        let target_a = LinkTarget {
            name: "foo".to_string(),
            version: "1.0.0".to_string(),
            store_path: foo_source.clone(),
            dependencies: vec![("leftpad".to_string(), "1.0.0".to_string())],
            aliases: HashMap::new(),
            is_direct: true,
            root_link_names: Some(vec!["foo".to_string()]),
            wrapper_id: Some("f-aaaa".to_string()),
            materialization: Materialization::DirectorySource,
            peers: Vec::new(),
            patch_fingerprint: None,
        };
        link_packages(&project_dir, &[leftpad1_target, target_a], false, None).unwrap();

        let leftpad_symlink = project_dir.join(".lpm/wrappers/foo+f-aaaa/node_modules/leftpad");
        let after_a = std::fs::read_link(&leftpad_symlink).unwrap();
        assert!(
            after_a.to_string_lossy().contains("leftpad@1.0.0"),
            "after run 1 leftpad symlink must point at v1 wrapper, got {after_a:?}",
        );

        // Run 2: same `foo` store_path, same wrapper_id — but a
        // different `dependencies` slot pointing at leftpad@2.0.0.
        // Pre-round-5 the v1 stamp matched (only wrapper_id +
        // materialization + store_path were checked), the fast path
        // skipped relinking, and the leftpad symlink stayed pointed
        // at the v1 wrapper. With the v2 stamp, the deps line
        // differs → mismatch → re-materialize → new symlink target.
        let target_b = LinkTarget {
            name: "foo".to_string(),
            version: "1.0.0".to_string(),
            store_path: foo_source,
            dependencies: vec![("leftpad".to_string(), "2.0.0".to_string())],
            aliases: HashMap::new(),
            is_direct: true,
            root_link_names: Some(vec!["foo".to_string()]),
            wrapper_id: Some("f-aaaa".to_string()),
            materialization: Materialization::DirectorySource,
            peers: Vec::new(),
            patch_fingerprint: None,
        };
        link_packages(&project_dir, &[leftpad2_target, target_b], false, None).unwrap();

        let after_b = std::fs::read_link(&leftpad_symlink).unwrap();
        assert!(
            after_b.to_string_lossy().contains("leftpad@2.0.0"),
            "round-5 fix: stamp must include dep edges so a deps-only \
             change forces a relink. leftpad symlink should now point \
             at the v2 wrapper, got {after_b:?}",
        );
        // Negative regression: must NOT still point at v1.
        assert!(
            !after_b.to_string_lossy().contains("leftpad@1.0.0"),
            "stale dep edge from run 1 survived run 2 — v2 stamp didn't \
             catch the deps-only change. Got: {after_b:?}",
        );
    }

    /// Stamp content is deterministic — same target → same stamp.
    #[test]
    fn compute_link_stamp_is_deterministic_for_same_target() {
        let target = LinkTarget {
            name: "foo".to_string(),
            version: "1.0.0".to_string(),
            store_path: PathBuf::from("/tmp/store/foo"),
            dependencies: vec![],
            aliases: HashMap::new(),
            is_direct: true,
            root_link_names: None,
            wrapper_id: Some("t-deadbeef".to_string()),
            materialization: Materialization::CasBacked,
            peers: Vec::new(),
            patch_fingerprint: None,
        };
        let s1 = compute_link_stamp(&target);
        let s2 = compute_link_stamp(&target);
        assert_eq!(s1, s2);
        assert!(s1.starts_with("lpm-link-stamp v2\n"));
        assert!(s1.contains("wrapper_id=t-deadbeef"));
        assert!(s1.contains("materialization=cas"));
        assert!(s1.contains("store_path=/tmp/store/foo"));
    }

    /// Distinct identity → distinct stamps. Specifically: same
    /// `(name, version, wrapper_segment)` but different `store_path`
    /// or `materialization` or `wrapper_id` produce different
    /// stamps. This is what guards the auditor's MEDIUM scenario.
    #[test]
    fn compute_link_stamp_changes_when_identity_differs() {
        let base = LinkTarget {
            name: "foo".to_string(),
            version: "1.0.0".to_string(),
            store_path: PathBuf::from("/tmp/store/registry/foo"),
            dependencies: vec![],
            aliases: HashMap::new(),
            is_direct: true,
            root_link_names: None,
            wrapper_id: None,
            materialization: Materialization::CasBacked,
            peers: Vec::new(),
            patch_fingerprint: None,
        };

        // Same wrapper segment (`foo@1.0.0`), DIFFERENT store_path:
        // the auditor's exact pre-round-1-tarball-vs-post-round-1-
        // registry scenario.
        let other_store = LinkTarget {
            store_path: PathBuf::from("/tmp/store/tarball-local/sha256-aaaa/foo"),
            ..base.clone()
        };
        assert_ne!(compute_link_stamp(&base), compute_link_stamp(&other_store));

        // Different materialization.
        let other_mat = LinkTarget {
            materialization: Materialization::DirectorySource,
            peers: Vec::new(),
            ..base.clone()
        };
        assert_ne!(compute_link_stamp(&base), compute_link_stamp(&other_mat));

        // Different wrapper_id (None vs Some).
        let other_wid = LinkTarget {
            wrapper_id: Some("t-1234567890abcdef".to_string()),
            ..base.clone()
        };
        assert_ne!(compute_link_stamp(&base), compute_link_stamp(&other_wid));
    }

    /// `link_stamp_matches` returns false for missing markers, empty
    /// markers, garbled bytes, and stamps that don't match the
    /// target's identity.
    #[test]
    fn link_stamp_matches_rejects_missing_empty_garbled_and_mismatched_markers() {
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join(".linked");
        let target = LinkTarget {
            name: "foo".to_string(),
            version: "1.0.0".to_string(),
            store_path: PathBuf::from("/tmp/store/foo"),
            dependencies: vec![],
            aliases: HashMap::new(),
            is_direct: true,
            root_link_names: None,
            wrapper_id: None,
            materialization: Materialization::CasBacked,
            peers: Vec::new(),
            patch_fingerprint: None,
        };

        // Missing.
        assert!(!link_stamp_matches(&marker, &target));

        // Empty (pre-round-3 legacy).
        std::fs::write(&marker, "").unwrap();
        assert!(!link_stamp_matches(&marker, &target));

        // Garbled.
        std::fs::write(&marker, "not a stamp at all").unwrap();
        assert!(!link_stamp_matches(&marker, &target));

        // Mismatched (different store_path).
        let other = LinkTarget {
            store_path: PathBuf::from("/tmp/store/bar"),
            ..target.clone()
        };
        std::fs::write(&marker, compute_link_stamp(&other)).unwrap();
        assert!(!link_stamp_matches(&marker, &target));

        // Match.
        std::fs::write(&marker, compute_link_stamp(&target)).unwrap();
        assert!(link_stamp_matches(&marker, &target));
    }

    #[test]
    fn cleanup_stale_entries_recognizes_directory_wrapper_segments() {
        // `+`-shape wrappers must be recognized by cleanup as
        // expected entries when their LinkTarget is in the package
        // set. Otherwise directory deps would get swept on the second
        // `lpm install` run.
        //
        // Wrappers live at `<project>/.lpm/wrappers/`,
        // resolved through `LayoutPaths` so the test setup tracks
        // production semantics automatically.
        let root = tempfile::tempdir().unwrap();
        let project_dir = root.path().join("project");
        let layout = LayoutPaths::for_project(&project_dir);
        let lpm_dir = layout.isolated_wrapper_root();
        std::fs::create_dir_all(&lpm_dir).unwrap();
        // Pre-create a `+`-shape wrapper as if from a prior install.
        let wrapper = lpm_dir.join("local-foo+f-deadbeef00000000");
        std::fs::create_dir_all(&wrapper).unwrap();
        std::fs::write(wrapper.join("marker"), b"x").unwrap();
        // Also a stale `+`-shape wrapper that isn't expected.
        let stale = lpm_dir.join("stale-pkg+f-1111222233334444");
        std::fs::create_dir_all(&stale).unwrap();

        let target = LinkTarget {
            name: "local-foo".to_string(),
            version: "0.0.0".to_string(),
            store_path: PathBuf::from("/tmp/source"),
            dependencies: vec![],
            aliases: HashMap::new(),
            is_direct: true,
            root_link_names: None,
            wrapper_id: Some("f-deadbeef00000000".to_string()),
            materialization: Materialization::DirectorySource,
            peers: Vec::new(),
            patch_fingerprint: None,
        };

        cleanup_stale_entries(&project_dir, &[target]).unwrap();

        assert!(wrapper.exists(), "expected wrapper must survive cleanup");
        assert!(!stale.exists(), "stale wrapper must be removed");
    }

    #[test]
    fn link_finalize_directory_root_symlink_targets_plus_wrapper() {
        // Stage 3 root-symlink target path uses `wrapper_segment`
        // so the `+`-shape lookup is honored.
        let root = tempfile::tempdir().unwrap();
        let project_dir = root.path().join("project");
        let src = make_local_source_dir(root.path(), "local-bar");

        let target = LinkTarget {
            name: "local-bar".to_string(),
            version: "0.0.0".to_string(),
            store_path: src.clone(),
            dependencies: vec![],
            aliases: HashMap::new(),
            is_direct: true,
            root_link_names: Some(vec!["local-bar".to_string()]),
            wrapper_id: Some("f-cafebabe00000000".to_string()),
            materialization: Materialization::DirectorySource,
            peers: Vec::new(),
            patch_fingerprint: None,
        };

        link_packages(&project_dir, &[target], false, None).unwrap();

        let root_link = project_dir.join("node_modules/local-bar");
        let symlink_target = std::fs::read_link(&root_link).unwrap();
        // Relative shape:
        // `node_modules/local-bar` → `../.lpm/wrappers/local-bar+f-.../node_modules/local-bar`
        let expected = PathBuf::from("..")
            .join(".lpm")
            .join("wrappers")
            .join("local-bar+f-cafebabe00000000")
            .join("node_modules")
            .join("local-bar");
        assert_eq!(symlink_target, expected);
    }

    // ── Legacy root-symlink retarget ─────────────────────────────────
    //
    // Pre-fix bug: the layout migration wipes `node_modules/.lpm/` but
    // does NOT touch root symlinks at `node_modules/<pkg>` whose
    // targets point into the legacy wrapper-root shape (`.lpm/<seg>/...`,
    // no `wrappers/` segment). Stage 3 root-symlink creation skips
    // any `root_link.exists()` entry, so the legacy symlink survives,
    // its target points at a wiped location → broken `node_modules/<pkg>`.
    //
    // Post-fix: `cleanup_stale_entries` removes any root symlink whose
    // target string identifies it as the legacy shape. Stage 3 then
    // recreates with the correct new target.

    #[test]
    fn cleanup_stale_entries_removes_legacy_shape_root_symlink() {
        let root = tempfile::tempdir().unwrap();
        let project_dir = root.path().join("project");
        let nm = project_dir.join("node_modules");
        std::fs::create_dir_all(&nm).unwrap();

        // Plant a legacy-shape root symlink — `.lpm/<seg>/node_modules/<pkg>`
        // (the pre- target shape), no `wrappers/` segment.
        let legacy_target = PathBuf::from(".lpm")
            .join("express@4.22.1")
            .join("node_modules")
            .join("express");
        let root_link = nm.join("express");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&legacy_target, &root_link).unwrap();
        #[cfg(windows)]
        let _ = std::os::windows::fs::symlink_dir(&legacy_target, &root_link);

        // Sanity: the legacy link IS present pre-cleanup.
        assert!(root_link.symlink_metadata().is_ok());

        // Express IS in the resolution set (a direct dep we're keeping).
        let express = LinkTarget {
            name: "express".to_string(),
            version: "4.22.1".to_string(),
            store_path: project_dir.join("does-not-matter"),
            dependencies: vec![],
            aliases: HashMap::new(),
            is_direct: true,
            root_link_names: Some(vec!["express".to_string()]),
            wrapper_id: None,
            materialization: Materialization::CasBacked,
            peers: Vec::new(),
            patch_fingerprint: None,
        };

        cleanup_stale_entries(&project_dir, &[express]).unwrap();

        // The legacy-shape symlink must be removed so Stage 3 can
        // create a fresh one with the new target shape.
        assert!(
            root_link.symlink_metadata().is_err(),
            "cleanup must remove legacy-shape root symlink so Stage 3 retargets it"
        );
    }

    #[test]
    fn cleanup_stale_entries_removes_legacy_shape_scoped_root_symlink() {
        // Scoped names (`@scope/pkg`) live one level deeper in
        // `node_modules/` and traverse a separate branch in the
        // cleanup sweep. The legacy-shape detector must apply
        // there too — without it, scoped legacy symlinks
        // (`node_modules/@types/node` → `../.lpm/@types+node@.../...`)
        // would survive the migration broken just like the
        // unscoped case.
        let root = tempfile::tempdir().unwrap();
        let project_dir = root.path().join("project");
        let nm = project_dir.join("node_modules");
        std::fs::create_dir_all(nm.join("@types")).unwrap();

        // Pre- scoped target shape: `../.lpm/<seg>/node_modules/<scope>/<name>`
        // (one extra `..` for the scope dir, no `wrappers/` segment).
        let legacy_target = PathBuf::from("..")
            .join(".lpm")
            .join("@types+node@20.0.0")
            .join("node_modules")
            .join("@types")
            .join("node");
        let scoped_link = nm.join("@types").join("node");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&legacy_target, &scoped_link).unwrap();
        #[cfg(windows)]
        let _ = std::os::windows::fs::symlink_dir(&legacy_target, &scoped_link);

        // The scoped pkg IS in the resolution set (a kept direct dep).
        let types_node = LinkTarget {
            name: "@types/node".to_string(),
            version: "20.0.0".to_string(),
            store_path: project_dir.join("does-not-matter"),
            dependencies: vec![],
            aliases: HashMap::new(),
            is_direct: true,
            root_link_names: Some(vec!["@types/node".to_string()]),
            wrapper_id: None,
            materialization: Materialization::CasBacked,
            peers: Vec::new(),
            patch_fingerprint: None,
        };

        cleanup_stale_entries(&project_dir, &[types_node]).unwrap();

        // Legacy-shape scoped symlink must be removed so Stage 3
        // can recreate it pointing at `../../.lpm/wrappers/<seg>/...`.
        assert!(
            scoped_link.symlink_metadata().is_err(),
            "scoped legacy-shape symlink must be removed during cleanup"
        );
    }

    #[test]
    fn cleanup_stale_entries_preserves_new_shape_root_symlink() {
        // Counterpoint: a NEW-shape root symlink (target contains
        // `.lpm/wrappers/`) must NOT be removed. Stage 3's "skip if
        // exists" guard then keeps the install fast on the warm path.
        let root = tempfile::tempdir().unwrap();
        let project_dir = root.path().join("project");
        let nm = project_dir.join("node_modules");
        std::fs::create_dir_all(&nm).unwrap();

        let new_target = PathBuf::from("..")
            .join(".lpm")
            .join("wrappers")
            .join("express@4.22.1")
            .join("node_modules")
            .join("express");
        let root_link = nm.join("express");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&new_target, &root_link).unwrap();
        #[cfg(windows)]
        let _ = std::os::windows::fs::symlink_dir(&new_target, &root_link);

        let express = LinkTarget {
            name: "express".to_string(),
            version: "4.22.1".to_string(),
            store_path: project_dir.join("does-not-matter"),
            dependencies: vec![],
            aliases: HashMap::new(),
            is_direct: true,
            root_link_names: Some(vec!["express".to_string()]),
            wrapper_id: None,
            materialization: Materialization::CasBacked,
            peers: Vec::new(),
            patch_fingerprint: None,
        };

        cleanup_stale_entries(&project_dir, &[express]).unwrap();

        assert!(
            root_link.symlink_metadata().is_ok(),
            "new-shape root symlink must survive cleanup (warm-install fast path)"
        );
    }

    #[test]
    fn cleanup_stale_entries_preserves_workspace_member_symlink() {
        // Workspace member symlinks point at workspace source dirs
        // (e.g., `../packages/foo`) — their target string contains
        // neither `.lpm/` nor `.lpm/wrappers/`. The legacy-shape
        // detector must leave them alone.
        let root = tempfile::tempdir().unwrap();
        let project_dir = root.path().join("project");
        let nm = project_dir.join("node_modules");
        std::fs::create_dir_all(&nm).unwrap();
        let member_src = root.path().join("packages").join("foo");
        std::fs::create_dir_all(&member_src).unwrap();
        let workspace_target = PathBuf::from("..").join("packages").join("foo");
        let root_link = nm.join("foo");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&workspace_target, &root_link).unwrap();
        #[cfg(windows)]
        let _ = std::os::windows::fs::symlink_dir(&workspace_target, &root_link);

        // Foo is a direct dep so the existing stale-name sweep keeps it.
        let foo = LinkTarget {
            name: "foo".to_string(),
            version: "0.0.0".to_string(),
            store_path: member_src,
            dependencies: vec![],
            aliases: HashMap::new(),
            is_direct: true,
            root_link_names: Some(vec!["foo".to_string()]),
            wrapper_id: None,
            materialization: Materialization::CasBacked,
            peers: Vec::new(),
            patch_fingerprint: None,
        };

        cleanup_stale_entries(&project_dir, &[foo]).unwrap();

        assert!(
            root_link.symlink_metadata().is_ok(),
            "workspace member symlink (target outside .lpm/) must survive cleanup"
        );
    }

    #[test]
    fn cleanup_stale_entries_preserves_self_reference_symlink() {
        // Self-ref `node_modules/<self>` → `..` (project root).
        // Target contains no `.lpm/`, must survive cleanup.
        let root = tempfile::tempdir().unwrap();
        let project_dir = root.path().join("project");
        let nm = project_dir.join("node_modules");
        std::fs::create_dir_all(&nm).unwrap();
        let self_link = nm.join("self-pkg");
        #[cfg(unix)]
        std::os::unix::fs::symlink(PathBuf::from(".."), &self_link).unwrap();
        #[cfg(windows)]
        let _ = std::os::windows::fs::symlink_dir(PathBuf::from(".."), &self_link);

        // Self-pkg is in the package set so the stale-name sweep keeps it.
        let self_pkg = LinkTarget {
            name: "self-pkg".to_string(),
            version: "0.0.0".to_string(),
            store_path: project_dir.join("does-not-matter"),
            dependencies: vec![],
            aliases: HashMap::new(),
            is_direct: true,
            root_link_names: Some(vec!["self-pkg".to_string()]),
            wrapper_id: None,
            materialization: Materialization::CasBacked,
            peers: Vec::new(),
            patch_fingerprint: None,
        };

        cleanup_stale_entries(&project_dir, &[self_pkg]).unwrap();

        assert!(
            self_link.symlink_metadata().is_ok(),
            "self-ref symlink (target = ..) must survive cleanup"
        );
    }

    #[test]
    fn link_finalize_retargets_legacy_root_symlink_after_migration() {
        // End-to-end: simulate an upgrade-in-place migration where
        // the legacy wrapper tree was wiped (61.3) but a legacy
        // root symlink survives. Re-running the install must
        // produce a working `node_modules/<pkg>` pointing at the
        // NEW wrapper-root shape.
        let store_dir = tempfile::tempdir().unwrap();
        let project_dir = tempfile::tempdir().unwrap();
        let store_path = create_fake_store_package(store_dir.path(), "express");

        // Simulate post-migration state: legacy `node_modules/.lpm/`
        // is gone (the 61.3 wipe ran), but the legacy root symlink
        // remains pointing at the wiped location.
        let nm = project_dir.path().join("node_modules");
        std::fs::create_dir_all(&nm).unwrap();
        let legacy_target = PathBuf::from(".lpm")
            .join("express@4.22.1")
            .join("node_modules")
            .join("express");
        let root_link = nm.join("express");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&legacy_target, &root_link).unwrap();
        #[cfg(windows)]
        let _ = std::os::windows::fs::symlink_dir(&legacy_target, &root_link);

        // Run a normal link pass.
        link_packages(
            project_dir.path(),
            &[LinkTarget {
                name: "express".to_string(),
                version: "4.22.1".to_string(),
                store_path,
                dependencies: vec![],
                aliases: HashMap::new(),
                is_direct: true,
                root_link_names: None,
                wrapper_id: None,
                materialization: Materialization::CasBacked,
                peers: Vec::new(),
                patch_fingerprint: None,
            }],
            false,
            None,
        )
        .unwrap();

        // The root symlink must now point at the NEW wrapper shape,
        // and the resolved target must actually exist (no broken link).
        let resolved_target = std::fs::read_link(&root_link).unwrap();
        let expected = PathBuf::from("..")
            .join(".lpm")
            .join("wrappers")
            .join("express@4.22.1")
            .join("node_modules")
            .join("express");
        assert_eq!(
            resolved_target, expected,
            "post-migration root symlink must point at the new wrapper shape, \
             not the wiped legacy location"
        );
        // `node_modules/express/package.json` resolves through the
        // new symlink — proves the install actually works.
        assert!(
            root_link.join("package.json").exists(),
            "post-migration `node_modules/<pkg>` must resolve to a real file"
        );
    }

    // ── dep-target wrapper-segment branch ────────────────────────────

    #[test]
    fn link_one_package_dep_target_uses_plus_shape_for_f_prefix_dep_version() {
        // F7-transitive contract: when an InstallPackage's
        // `dependencies: Vec<(String, String)>` carries a
        // `dep_version` starting with `f-` or `l-`, the dep symlink
        // target is `<safe>+<dep_version>` (matching the linker's
        // wrapper-segment shape for local-source deps), NOT
        // `<safe>@<dep_version>`. Without the branch, transitive
        // file:/link: deps from a directory source would point at
        // `.lpm/<dep>@f-{16hex}/...` — a wrapper that doesn't exist.
        let root = tempfile::tempdir().unwrap();
        let store_dir = root.path().join("store");
        let project_dir = root.path().join("project");
        let parent_store = create_fake_store_package(&store_dir, "parent");

        // Parent has a transitive dep with a `f-`-prefixed version
        // `apply_post_resolve_directory_link_fixup` produces this
        // shape for FileDir transitives.
        let parent = LinkTarget {
            name: "parent".to_string(),
            version: "1.0.0".to_string(),
            store_path: parent_store,
            dependencies: vec![("local-dep".to_string(), "f-deadbeef00000000".to_string())],
            aliases: HashMap::new(),
            is_direct: true,
            root_link_names: None,
            wrapper_id: None,
            materialization: Materialization::CasBacked,
            peers: Vec::new(),
            patch_fingerprint: None,
        };

        link_packages(&project_dir, &[parent], false, None).unwrap();

        // Inside parent's wrapper, `local-dep` symlink target uses `+`-shape.
        let dep_link = project_dir.join(".lpm/wrappers/parent@1.0.0/node_modules/local-dep");
        let target = std::fs::read_link(&dep_link).unwrap();
        // Expected: `../../local-dep+f-deadbeef00000000/node_modules/local-dep`
        let expected = PathBuf::from("..")
            .join("..")
            .join("local-dep+f-deadbeef00000000")
            .join("node_modules")
            .join("local-dep");
        assert_eq!(target, expected, "f- prefix MUST route to + shape");
    }

    #[test]
    fn link_one_package_dep_target_uses_plus_shape_for_l_prefix_dep_version() {
        // Same as above for `l-` prefix (link: deps).
        let root = tempfile::tempdir().unwrap();
        let store_dir = root.path().join("store");
        let project_dir = root.path().join("project");
        let parent_store = create_fake_store_package(&store_dir, "parent");

        let parent = LinkTarget {
            name: "parent".to_string(),
            version: "1.0.0".to_string(),
            store_path: parent_store,
            dependencies: vec![("linked-dep".to_string(), "l-cafebabe00000000".to_string())],
            aliases: HashMap::new(),
            is_direct: true,
            root_link_names: None,
            wrapper_id: None,
            materialization: Materialization::CasBacked,
            peers: Vec::new(),
            patch_fingerprint: None,
        };

        link_packages(&project_dir, &[parent], false, None).unwrap();

        let dep_link = project_dir.join(".lpm/wrappers/parent@1.0.0/node_modules/linked-dep");
        let target = std::fs::read_link(&dep_link).unwrap();
        let expected = PathBuf::from("..")
            .join("..")
            .join("linked-dep+l-cafebabe00000000")
            .join("node_modules")
            .join("linked-dep");
        assert_eq!(target, expected, "l- prefix MUST route to + shape");
    }

    #[test]
    fn link_one_package_dep_target_uses_at_shape_for_semver_version() {
        // Regression: `dep_version = "4.17.21"` (a normal SemVer)
        // continues to produce `<safe>@4.17.21` as before. Day-5's
        // branch must not regress the registry/tarball case.
        let root = tempfile::tempdir().unwrap();
        let store_dir = root.path().join("store");
        let project_dir = root.path().join("project");
        let parent_store = create_fake_store_package(&store_dir, "parent");

        let parent = LinkTarget {
            name: "parent".to_string(),
            version: "1.0.0".to_string(),
            store_path: parent_store,
            dependencies: vec![("lodash".to_string(), "4.17.21".to_string())],
            aliases: HashMap::new(),
            is_direct: true,
            root_link_names: None,
            wrapper_id: None,
            materialization: Materialization::CasBacked,
            peers: Vec::new(),
            patch_fingerprint: None,
        };

        link_packages(&project_dir, &[parent], false, None).unwrap();

        let dep_link = project_dir.join(".lpm/wrappers/parent@1.0.0/node_modules/lodash");
        let target = std::fs::read_link(&dep_link).unwrap();
        let expected = PathBuf::from("..")
            .join("..")
            .join("lodash@4.17.21")
            .join("node_modules")
            .join("lodash");
        assert_eq!(target, expected, "SemVer dep_version MUST keep the @ shape");
    }
}
