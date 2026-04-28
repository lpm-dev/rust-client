//! node_modules layout manager for LPM.
//!
//! Creates pnpm-style isolated node_modules with symlinks:
//!
//! ```text
//! node_modules/
//!   .lpm/                                    ← internal store
//!     express@4.22.1/
//!       node_modules/
//!         express/  → <global-store>         ← hardlink/copy from store
//!         debug/    → ../../debug@2.6.9/node_modules/debug
//!         send/     → ../../send@0.19.2/node_modules/send
//!     debug@2.6.9/
//!       node_modules/
//!         debug/    → <global-store>
//!         ms/       → ../../ms@2.0.0/node_modules/ms
//!   express/ → .lpm/express@4.22.1/node_modules/express   ← direct dep symlink
//! ```
//!
//! Properties:
//! - Only direct dependencies appear in root `node_modules/` as symlinks
//! - All packages live in `.lpm/` with their own `node_modules/` for their deps
//! - Strict isolation: phantom dependencies are not importable
//!
//! Compatibility: hoisted mode, Windows junctions, self-ref — see phase-20-todo.md.
//! Performance: incremental linking via `.linked` marker files, `--force` bypasses markers.

use lpm_common::LpmError;
use rayon::prelude::*;
use std::collections::{BTreeMap, HashMap};
use std::path::{Component, Path, PathBuf};

/// Phase 39 P2b per-package link outcome — exposes Phase 1 action + Phase 2
/// symlink count to the event-driven caller so totals match the
/// single-shot [`link_packages`] path.
#[derive(Debug, Default, Clone, Copy)]
pub struct OnePackageResult {
    /// `true` if Phase 1 freshly linked the package; `false` if the
    /// incremental `.linked` marker caused a skip.
    pub linked: bool,
    /// Phase 2 internal-symlink count for this package (one per entry in
    /// the package's `dependencies` that wasn't already symlinked).
    pub symlinks_created: usize,
}

/// Phase 39 P2b final-stage result — Phase 3 root symlinks + Phase 3.5
/// self-reference + Phase 4 `.bin` creation, aggregated into the tail
/// end of the `LinkResult` that [`link_packages`] returns.
#[derive(Debug, Default)]
pub struct FinalizeResult {
    /// Phase 3 + 3.5 symlink count (direct-dep root symlinks + optional
    /// self-reference).
    pub symlinks_created: usize,
    /// Phase 4 `.bin` entries created.
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
/// Public so Phase 37 M4 (collision UX) can reuse the same safety bar
/// for user-supplied alias names (`--alias orig=alias`) — every path on
/// PATH should meet the same sanity check regardless of whether it came
/// from `package.json` or a CLI flag.
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

/// Check if a path string contains cmd.exe metacharacters that could enable injection.
/// Returns `Err(reason)` if dangerous characters are found.
#[cfg(windows)]
fn validate_cmd_path(path: &str) -> Result<(), String> {
    const DANGEROUS: &[char] = &['"', '&', '|', '<', '>', '^', '%', '\n', '\r'];
    for ch in DANGEROUS {
        if path.contains(*ch) {
            return Err(format!(
                "bin target path contains dangerous character '{ch}' for cmd.exe"
            ));
        }
    }
    Ok(())
}

/// Linking strategy for node_modules.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub enum LinkerMode {
    /// pnpm-style isolated layout (default). Strict, no phantom deps.
    #[default]
    Isolated,
    /// npm v3+ style hoisted layout. Flat, phantom deps accessible.
    Hoisted,
}

/// Create a symlink (Unix) or junction (Windows) from `link` pointing to `target`.
///
/// On Windows, NTFS junctions don't require admin privileges (unlike symlinks).
/// We use `cmd /c mklink /J` which handles junction creation natively.
/// Junctions require absolute paths, so we resolve relative targets before creating.
/// Falls back to `symlink_dir` if junction creation fails.
///
/// On Unix, creates a standard symlink (relative paths work fine).
#[cfg(windows)]
fn create_symlink_or_junction(target: &Path, link: &Path) -> std::io::Result<()> {
    // Try symlink_dir first — works without admin on many modern Windows setups
    // (Developer Mode, or appropriate policy settings).
    if std::os::windows::fs::symlink_dir(target, link).is_ok() {
        return Ok(());
    }

    // Junctions require absolute target paths. If target is relative,
    // resolve it relative to the link's parent directory.
    let abs_target = if target.is_relative() {
        let base = link.parent().unwrap_or(Path::new("."));
        match base.canonicalize() {
            Ok(abs_base) => abs_base.join(target),
            Err(_) => base.join(target),
        }
    } else {
        target.to_path_buf()
    };

    // Validate paths before passing to cmd to prevent command injection.
    let link_str = link.to_string_lossy();
    let target_str = abs_target.to_string_lossy();
    if let Err(reason) = validate_cmd_path(&link_str) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("refusing junction: link path {reason}"),
        ));
    }
    if let Err(reason) = validate_cmd_path(&target_str) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("refusing junction: target path {reason}"),
        ));
    }

    // Fallback: junction via cmd /c mklink /J (no admin required)
    let status = std::process::Command::new("cmd")
        .args(["/c", "mklink", "/J", &link_str, &target_str])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();

    match status {
        Ok(s) if s.success() => Ok(()),
        _ => Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "failed to create junction or symlink",
        )),
    }
}

#[cfg(unix)]
fn create_symlink_or_junction(target: &Path, link: &Path) -> std::io::Result<()> {
    std::os::unix::fs::symlink(target, link)
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
    /// For Phase 40 P2 npm-alias edges, it is the alias key from this
    /// package's `package.json` (e.g., `strip-ansi-cjs`), and
    /// [`Self::aliases`] records the canonical registry name so the
    /// linker can resolve the symlink target to `<target>@<ver>`.
    pub dependencies: Vec<(String, String)>,
    /// **Phase 40 P2** — npm-alias edges: `local_name → target_canonical_name`.
    /// Populated only for local names that refer to a different
    /// registry-canonical target than themselves (the common case is
    /// empty). Lookup rule: `aliases.get(local).unwrap_or(local)`
    /// produces the target used for the store path.
    pub aliases: HashMap<String, String>,
    /// Whether this is a direct dependency of the root project.
    ///
    /// Used for lifecycle-script filtering and display purposes. For
    /// Phase 3 root-symlink creation, the linker consults
    /// [`Self::root_link_names`] instead — that field expresses the
    /// alias-aware "what filenames do I get at the project root"
    /// contract, including the (rare) case of a single package
    /// referenced by its canonical name AND by one or more aliases at
    /// the same version.
    pub is_direct: bool,
    /// **Phase 40 P2** — explicit list of `node_modules/<entry>/`
    /// symlinks to create at the project root for this package.
    ///
    /// Callers may leave this `None` to get the default pre-P2
    /// behavior: Phase 3 creates a single `node_modules/<name>/`
    /// symlink when `is_direct` is true, nothing otherwise. Callers
    /// that have alias info from the resolver set this to
    /// `Some(vec![...])`:
    ///
    /// - `Some([pkg.name])`: regular direct dep (equivalent to the
    ///   default, but explicit).
    /// - `Some([local])` where `local != pkg.name`: aliased root dep —
    ///   the consumer declared `"local": "npm:<pkg.name>@<range>"`.
    ///   Phase 3 creates `node_modules/<local>/` with the target set to
    ///   `.lpm/<pkg.name>@<version>/node_modules/<pkg.name>/`.
    /// - `Some([name, alias1, ...])`: the same resolved `(name,
    ///   version)` is referenced from the root under multiple names
    ///   (canonical plus one or more aliases). One symlink per entry.
    /// - `Some([])`: never a root dep, no root symlink. Distinguishes
    ///   "explicitly zero" from "use the default."
    ///
    /// When `Some`, the `is_direct` flag is ignored for Phase 3
    /// purposes; `is_direct` is still consulted elsewhere (lifecycle
    /// filtering, display). When `None`, Phase 3 falls back to the
    /// `is_direct ? [name] : []` default.
    pub root_link_names: Option<Vec<String>>,
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
    // Phase 39 P2b: `link_packages` is now a thin composition over three
    // smaller helpers so the event-driven install path can run them
    // independently (stale cleanup up front, per-pkg link as each tarball
    // lands, finalize once everything is materialized). The single-shot
    // path still calls them serially so existing callers are unaffected.
    cleanup_stale_entries(project_dir, packages)?;

    // Phase 1 + Phase 2 per package, in a parallel pass. `link_one_package`
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

/// Phase 39 P2b: stale-entry cleanup — removes `.lpm/<pkg>@<ver>`
/// directories and root `node_modules/<pkg>` symlinks that are no longer
/// in the resolver's output. Must run BEFORE any per-package linking so
/// its `read_dir` scans see a stable snapshot; calling it more than once
/// per install is safe but wasteful.
///
/// Also creates `node_modules/.lpm/` if it doesn't exist.
pub fn cleanup_stale_entries(project_dir: &Path, packages: &[LinkTarget]) -> Result<(), LpmError> {
    let node_modules = project_dir.join("node_modules");
    let lpm_dir = node_modules.join(".lpm");

    std::fs::create_dir_all(&lpm_dir)?;

    // Incremental: collect expected entries so we can clean up stale ones
    let expected_entries: std::collections::HashSet<String> = packages
        .iter()
        .map(|p| {
            let safe = p.name.replace('/', "+");
            format!("{safe}@{}", p.version)
        })
        .collect();

    // Clean up stale .lpm entries that are no longer in the resolution
    if let Ok(entries) = std::fs::read_dir(&lpm_dir) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if !expected_entries.contains(&name) {
                let _ = std::fs::remove_dir_all(entry.path());
                tracing::debug!("incremental: removed stale .lpm/{name}");
            }
        }
    }

    // Also clean up stale root symlinks
    //
    // Phase 40 P2 — the "expected root link names" come from
    // `root_link_names` on each package, not `is_direct + pkg.name`.
    // That set already includes every alias the resolver decided to
    // plant at the root (e.g. `strip-ansi-cjs` as an alias for
    // `strip-ansi@6.0.1`), so aliased root entries survive the stale
    // sweep.
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
                        let scoped_name = format!("{name}/{}", se.file_name().to_string_lossy());
                        if !direct_names.contains(scoped_name.as_str())
                            && se
                                .path()
                                .symlink_metadata()
                                .map(|m| m.file_type().is_symlink())
                                .unwrap_or(false)
                        {
                            let _ = std::fs::remove_file(se.path());
                            tracing::debug!(
                                "incremental: removed stale root symlink {scoped_name}"
                            );
                        }
                    }
                }
                continue;
            } else {
                name.clone()
            };
            if !direct_names.contains(full_name.as_str())
                && entry
                    .path()
                    .symlink_metadata()
                    .map(|m| m.file_type().is_symlink())
                    .unwrap_or(false)
            {
                let _ = std::fs::remove_file(entry.path());
                tracing::debug!("incremental: removed stale root symlink {full_name}");
            }
        }
    }

    Ok(())
}

/// Phase 39 P2b: per-package link. Does Phase 1 (materialize
/// `.lpm/<pkg>/node_modules/<pkg>` from the store) + Phase 2 (internal
/// symlinks for this package's dependencies).
///
/// Safe to call concurrently for different packages — each call writes
/// to a unique `.lpm/<safe_name>@<version>` subtree. Phase 2 symlinks
/// target relative strings that don't require the destination package
/// to be materialized yet, so callers can pipeline per-package work
/// into the fetch pipeline.
///
/// Preconditions:
/// - `node_modules/.lpm/` exists (created by [`cleanup_stale_entries`]).
/// - `target.store_path` exists (the store directory for this package).
pub fn link_one_package(
    project_dir: &Path,
    target: &LinkTarget,
    force: bool,
) -> Result<(MaterializedPackage, OnePackageResult), LpmError> {
    let lpm_dir = project_dir.join("node_modules").join(".lpm");
    let safe_name = target.name.replace('/', "+");
    let pkg_entry_dir = lpm_dir.join(format!("{safe_name}@{}", target.version));
    let marker_path = pkg_entry_dir.join(".linked");
    let pkg_nm = pkg_entry_dir.join("node_modules").join(&target.name);

    // **Phase 32 Phase 6.** Always record the canonical destination,
    // even on the marker-skip fast path — the package IS materialized
    // there from a prior install run, just not freshly relinked.
    let materialized = MaterializedPackage {
        name: target.name.clone(),
        version: target.version.clone(),
        destination: pkg_nm.clone(),
    };

    // Incremental: skip packages that already have a completed link marker.
    //
    // NOTE: The .linked marker check is not atomic with the linking
    // operation. A local attacker with filesystem access could plant a
    // fake marker to prevent re-linking. However, local filesystem access
    // already implies full compromise (can modify node_modules directly),
    // so this is an accepted risk. The marker is a performance
    // optimization, not a security boundary.
    if !force && marker_path.exists() {
        tracing::debug!(
            "incremental: skipping {safe_name}@{} (marker present)",
            target.version
        );
        return Ok((
            materialized,
            OnePackageResult {
                linked: false,
                symlinks_created: 0,
            },
        ));
    }

    if force && pkg_nm.exists() {
        let _ = std::fs::remove_dir_all(&pkg_nm);
    } else if !force && pkg_nm.exists() && !marker_path.exists() {
        tracing::debug!("cleaning up interrupted link for {}", safe_name);
        let _ = std::fs::remove_dir_all(&pkg_nm);
    }

    if !pkg_nm.exists() {
        if let Some(parent) = pkg_nm.parent() {
            std::fs::create_dir_all(parent)?;
        }
        link_dir_recursive(&target.store_path, &pkg_nm)?;
    }

    // Phase 2: internal symlinks from this package's node_modules/ to
    // each dependency's `.lpm/<dep>@<ver>/node_modules/<dep>` entry.
    //
    // Phase 40 P2 — local-name / target-name split. The symlink
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

    // Phase 57.2: pre-create the small set of unique scope dirs
    // (`@types/`, `@scope/`, …) needed by scoped deps in ONE pass,
    // outside the per-dep loop. The flat `pkg_nm_dir` itself is already
    // materialized by the line-521 `create_dir_all` + `link_dir_recursive`
    // for the package, so non-scoped deps need no parent mkdir at all.
    // Pre-Phase-57.2 the loop did `create_dir_all(dep_link.parent())` per
    // dep — for a webpack-style install that's ~1500–2500 redundant
    // stat-heavy syscall sequences (one per dep edge across 255 pkgs).
    // The samply warm-relink flamegraph shows mkdir at 20.5% of CPU; this
    // dedup is one of the levers identified in the Phase 57.2 close-out.
    let mut scope_dirs_created: std::collections::HashSet<&str> =
        std::collections::HashSet::new();
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
        sym_target.push(format!("{safe_target}@{dep_version}"));
        sym_target.push("node_modules");
        sym_target.push(dep_target);

        create_symlink_or_junction(&sym_target, &dep_link)?;
        symlinks_created += 1;
    }

    // Write marker after successful link + symlink pass.
    if let Err(e) = std::fs::write(&marker_path, "") {
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

/// Phase 39 P2b: link finalization — Phase 3 root symlinks for direct
/// deps, Phase 3.5 self-reference, Phase 4 `.bin` creation.
///
/// Must run AFTER [`link_one_package`] has completed for every package
/// in `packages`. Phase 4 reads `package.json#bin` from each
/// materialized package.
pub fn link_finalize(
    project_dir: &Path,
    packages: &[LinkTarget],
    self_package_name: Option<&str>,
) -> Result<FinalizeResult, LpmError> {
    let node_modules = project_dir.join("node_modules");
    let lpm_dir = node_modules.join(".lpm");

    // Phase 3: root symlinks — parallel, one iteration per (pkg, link_name)
    // pair. A package with no root link names contributes nothing
    // (transitive deps); one entry is the common case (pkg.name);
    // multiple entries support the Phase 40 P2 scenario where the
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

    let phase3_count = link_pairs
        .par_iter()
        .map(|(pkg, link_name)| -> Result<usize, LpmError> {
            let root_link = node_modules.join(link_name);

            if root_link.exists() || root_link.symlink_metadata().is_ok() {
                return Ok(0);
            }

            if let Some(parent) = root_link.parent() {
                std::fs::create_dir_all(parent)?;
            }

            let safe_target = pkg.name.replace('/', "+");

            // Symlink depth is computed from the LOCAL link name — a
            // scoped alias like `@internal/strip-ansi-cjs` would live
            // at `node_modules/@internal/strip-ansi-cjs`, one level
            // deeper than a plain root entry. The TARGET directory is
            // keyed on the canonical name.
            let depth = link_name.matches('/').count();
            let mut target = PathBuf::new();
            for _ in 0..depth {
                target.push("..");
            }
            target.push(".lpm");
            target.push(format!("{safe_target}@{}", pkg.version));
            target.push("node_modules");
            target.push(&pkg.name);

            // **Phase 41 race tolerance.** `link_pairs` is iterated in
            // parallel via rayon; the check at the top of this closure
            // (`root_link.exists()`) is a TOCTOU check — two threads
            // targeting the same `link_name` can both read "doesn't
            // exist" and both try to create the symlink. Only one wins;
            // the loser returns `AlreadyExists`. Historically this
            // surfaced when `resolved_to_install_packages` produced
            // duplicate `(canonical_name, version)` rows for Phase 40 P4
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

    // Phase 3.5: self-reference — package can require("itself").
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

    // Phase 4: node_modules/.bin/ entries.
    let bin_count = create_bin_links(&node_modules, &lpm_dir, packages)?;

    Ok(FinalizeResult {
        symlinks_created: phase3_count + self_ref_count,
        bin_count,
        self_referenced,
    })
}

/// Create a `node_modules/<package_name>` symlink that points at a workspace
/// member's source directory.
///
/// **Phase 32 Phase 2 audit fix #3** (workspace:^ resolver bug). The install
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

/// Create the npm v3+ style hoisted node_modules layout.
///
/// All packages are placed directly into `node_modules/` (flat). When two packages
/// need different versions of the same dependency, the direct dependency (or the
/// first encountered) wins the root position, and the other is nested under its
/// dependent's `node_modules/`.
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
    let node_modules = project_dir.join("node_modules");

    // Clean up old node_modules contents (but keep .bin/ and .lpm/)
    if node_modules.exists()
        && force
        && let Ok(entries) = std::fs::read_dir(&node_modules)
    {
        for entry in entries.flatten() {
            let name = entry.file_name();
            if name != ".bin" && name != ".lpm" {
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

    // Phase 1: Determine hoisting layout.
    //
    // Build a dependency graph so we can figure out which package "depends on"
    // which conflicting version. The algorithm:
    //   1. Walk all packages in order. Try to claim the root node_modules/<name> slot.
    //   2. If a name is already claimed by a different version, decide who gets root:
    //      - Direct deps always win root over transitive deps.
    //      - Among equal priority, first-come-first-served (stable for determinism).
    //   3. The loser gets nested under one of its dependents.
    let mut hoisted: HashMap<String, usize> = HashMap::with_capacity(packages.len());
    // (package_index, parent_name) -- packages that must be nested
    let mut nested: Vec<(usize, String)> = Vec::new();

    // Build a reverse-dependency map: (package_name, version) -> list of dependent names.
    // Used to decide where to nest a conflicting package.
    let mut depended_by: HashMap<(String, String), Vec<String>> = HashMap::new();
    for pkg in packages {
        for (dep_name, dep_ver) in &pkg.dependencies {
            depended_by
                .entry((dep_name.clone(), dep_ver.clone()))
                .or_default()
                .push(pkg.name.clone());
        }
    }

    for (idx, pkg) in packages.iter().enumerate() {
        if let Some(&existing_idx) = hoisted.get(&pkg.name) {
            let existing = &packages[existing_idx];
            if existing.version == pkg.version {
                // Same name, same version: already hoisted, skip duplicate.
                continue;
            }
            // Version conflict. Direct dep wins root position.
            if pkg.is_direct && !existing.is_direct {
                // Evict existing to nested, hoist the new one.
                let parent = depended_by
                    .get(&(existing.name.clone(), existing.version.clone()))
                    .and_then(|v: &Vec<String>| v.first().cloned())
                    .unwrap_or_else(|| pkg.name.clone());
                nested.push((existing_idx, parent));
                hoisted.insert(pkg.name.clone(), idx);
            } else {
                // Keep existing at root, nest the new one.
                let parent = depended_by
                    .get(&(pkg.name.clone(), pkg.version.clone()))
                    .and_then(|v: &Vec<String>| v.first().cloned())
                    .unwrap_or_else(|| existing.name.clone());
                nested.push((idx, parent));
            }
        } else {
            hoisted.insert(pkg.name.clone(), idx);
        }
    }

    // Build the desired layout snapshot: name → "name@version" for both hoisted
    // and nested packages. BTreeMap gives deterministic serialization order.
    let mut desired_hoisted: BTreeMap<String, String> = BTreeMap::new();
    for (name, &pkg_idx) in &hoisted {
        let pkg = &packages[pkg_idx];
        desired_hoisted.insert(name.clone(), pkg.version.clone());
    }

    // nested entries: "parent/name" → version (parent prefix makes them unique)
    let mut desired_nested: BTreeMap<String, String> = BTreeMap::new();
    for (pkg_idx, parent_name) in &nested {
        let pkg = &packages[*pkg_idx];
        let key = format!("{}/{}", parent_name, pkg.name);
        desired_nested.insert(key, pkg.version.clone());
    }

    // Phase 1.5: Incremental check — read saved metadata and compare.
    // If the desired layout is identical to what we wrote last time, and
    // every expected directory still exists on disk, skip the expensive I/O.
    let metadata_path = node_modules.join(".lpm-metadata.json");
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
    // **Phase 32 Phase 6 — `lpm patch`.** Track materialized destinations.
    // Hoisted mode has up to three shapes per package:
    //   - hoisted root:                 node_modules/<name>/
    //   - nested under hoisted parent:  node_modules/<parent>/node_modules/<name>/
    //   - nested under nested parent:   node_modules/.lpm/nested/<name>/
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
                        node_modules.join(".lpm").join("nested").join(pkg_name)
                    };
                    let _ = std::fs::remove_dir_all(&stale);
                    tracing::debug!("hoisted: removed stale nested {key}@{old_ver}");
                }
            }
        }

        // Phase 2: Link hoisted packages directly into root node_modules/
        for (name, &pkg_idx) in &hoisted {
            let pkg = &packages[pkg_idx];
            let target_dir = node_modules.join(name);

            // Phase 32 Phase 6: record materialized destination BEFORE
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

        // Phase 3: Link nested (conflicting) packages under their parent's node_modules/
        for (pkg_idx, parent_name) in &nested {
            let pkg = &packages[*pkg_idx];

            let parent_nm = if hoisted.contains_key(parent_name) {
                node_modules.join(parent_name).join("node_modules")
            } else {
                node_modules.join(".lpm").join("nested")
            };

            let nested_dir = parent_nm.join(&pkg.name);

            // Phase 32 Phase 6: record materialized destination BEFORE
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

        // Phase 3.5: Self-reference — package can require("itself").
        // Uses a symlink to project root, not a copy from the store.
        if let Some(self_name) = self_package_name {
            if !is_valid_self_ref_name(self_name) {
                tracing::warn!(
                    "skipping self-reference for invalid package name: {}",
                    self_name
                );
            } else {
                let self_link = node_modules.join(self_name);
                if !self_link.exists() && self_link.symlink_metadata().is_err() {
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
            }
        }

        // Write updated metadata for next incremental run.
        write_hoist_metadata(
            &metadata_path,
            &desired_hoisted,
            &desired_nested,
            self_package_name,
        );
    } else {
        skipped_count = desired_hoisted.len() + desired_nested.len();
        // Self-reference was created on the previous run if metadata matches.
        self_referenced =
            self_package_name.is_some_and(|n| node_modules.join(n).symlink_metadata().is_ok());

        // **Phase 32 Phase 6.** Even on the metadata-skip fast path,
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
                node_modules.join(".lpm").join("nested")
            };
            materialized.push(MaterializedPackage {
                name: pkg.name.clone(),
                version: pkg.version.clone(),
                destination: parent_nm.join(&pkg.name),
            });
        }
    }

    // Phase 4: Binary links for hoisted packages (always runs — cheap idempotent check).
    let bin_count = create_bin_links_hoisted(&node_modules, packages, &hoisted)?;

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

    for (name, &pkg_idx) in hoisted {
        let pkg = &packages[pkg_idx];
        let pkg_dir = node_modules.join(name);

        let pkg_json_path = pkg_dir.join("package.json");
        if !pkg_json_path.exists() {
            continue;
        }

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

        std::fs::create_dir_all(&bin_dir)?;

        for (cmd_name, script_path) in &entries {
            // Finding #2: validate bin name
            if let Err(reason) = validate_bin_name(cmd_name, pkg_name) {
                tracing::warn!("bin: rejecting \"{cmd_name}\" from {pkg_name}: {reason}");
                continue;
            }

            // Finding #1: validate bin target path (no traversal)
            let target = match validate_bin_target(&pkg_dir, script_path) {
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

            // Finding #13: use relative symlinks for portability
            #[cfg(unix)]
            {
                let rel_target = relative_symlink_target_from_parent(&target, &bin_dir);
                std::os::unix::fs::symlink(&rel_target, &bin_link)?;

                // Finding #6: add execute only (0o111), not full 0o755
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
                // Finding #3: validate target path before interpolating into .cmd
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
        let safe_name = pkg.name.replace('/', "+");
        let pkg_dir = lpm_dir
            .join(format!("{safe_name}@{}", pkg.version))
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
            // Finding #2: validate bin name
            if let Err(reason) = validate_bin_name(cmd_name, pkg_name) {
                tracing::warn!("bin: rejecting \"{cmd_name}\" from {pkg_name}: {reason}");
                continue;
            }

            // Finding #1: validate bin target path (no traversal)
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

            // Finding #13: use relative symlinks for portability
            #[cfg(unix)]
            {
                let rel_target = relative_symlink_target_from_parent(&target, &bin_dir);
                std::os::unix::fs::symlink(&rel_target, &bin_link)?;

                // Finding #6: add execute only (0o111), not full 0o755
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
                // Finding #3: validate target path before interpolating into .cmd
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
    /// **Phase 32 Phase 6 — `lpm patch`.** Every physical destination
    /// where a package was materialized in this run. The patch-apply
    /// pass consumes this slice directly so it never has to
    /// reverse-engineer the linker's destination shapes from
    /// `(name, version)` — which would silently miss the
    /// `node_modules/.lpm/nested/<name>/` shape used in hoisted mode
    /// when a nested loser's parent is itself nested
    /// (`link_packages_hoisted` else branch around line 781).
    ///
    /// **Population:**
    /// - Isolated mode: one entry per `(name, version)` pointing at
    ///   `<project_dir>/node_modules/.lpm/<safe_name>@<version>/node_modules/<name>/`.
    /// - Hoisted mode (full re-link path): one entry per hoisted
    ///   package + one per nested package (under hoisted parent OR
    ///   under `.lpm/nested/`).
    /// - Hoisted mode (incremental skip): re-derived from the saved
    ///   `desired_hoisted` / `desired_nested` maps so the patch pass
    ///   still gets a complete location list when the linker took the
    ///   metadata fast path.
    pub materialized: Vec<MaterializedPackage>,
}

/// One physical destination of a linked package. Phase 32 Phase 6.
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
            if std::fs::hard_link(&src_path, &dst_path).is_err() {
                // Fallback to copy
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

    // clonefile(src, dst, flags) — flag 0 = no special flags
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

/// Phase 57 follow-up — break shared inodes inside a live per-package
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

        // copy → rename. `fs::copy` creates a new inode populated
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
            },
            LinkTarget {
                name: "debug".to_string(),
                version: "2.6.9".to_string(),
                store_path: debug_store,
                dependencies: vec![],
                aliases: HashMap::new(),
                is_direct: false,
                root_link_names: None,
            },
        ];

        let result = link_packages(project_dir.path(), &packages, false, None).unwrap();

        // express is accessible from root
        assert!(
            project_dir
                .path()
                .join("node_modules/express")
                .symlink_metadata()
                .is_ok()
        );

        // debug is NOT in root (it's transitive)
        assert!(
            project_dir
                .path()
                .join("node_modules/debug")
                .symlink_metadata()
                .is_err()
        );

        // debug IS accessible from express's node_modules
        let express_debug = project_dir
            .path()
            .join("node_modules/.lpm/express@4.22.1/node_modules/debug");
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
            }],
            false,
            None,
        )
        .unwrap();

        assert!(project_dir.path().join("node_modules/.lpm").is_dir());
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
        }];

        link_packages(project_dir.path(), &packages, false, None).unwrap();

        // Marker file should exist after linking
        let marker = project_dir
            .path()
            .join("node_modules/.lpm/foo@1.0.0/.linked");
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
        }];

        // First link — creates marker
        let result1 = link_packages(project_dir.path(), &packages, false, None).unwrap();
        assert_eq!(result1.linked, 1);

        // Delete marker to simulate corruption/manual cleanup
        let marker = project_dir
            .path()
            .join("node_modules/.lpm/baz@3.0.0/.linked");
        assert!(marker.exists());
        std::fs::remove_file(&marker).unwrap();

        // Remove the linked package dir to force re-link
        let pkg_dir = project_dir
            .path()
            .join("node_modules/.lpm/baz@3.0.0/node_modules/baz");
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
        }];

        // First link
        link_packages(project_dir.path(), &packages, false, None).unwrap();
        let marker = project_dir
            .path()
            .join("node_modules/.lpm/qux@1.0.0/.linked");
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
            },
            LinkTarget {
                name: "debug".to_string(),
                version: "2.6.9".to_string(),
                store_path: debug_store,
                dependencies: vec![("ms".to_string(), "2.0.0".to_string())],
                aliases: HashMap::new(),
                is_direct: false,
                root_link_names: None,
            },
            LinkTarget {
                name: "ms".to_string(),
                version: "2.0.0".to_string(),
                store_path: ms_store,
                dependencies: vec![],
                aliases: HashMap::new(),
                is_direct: false,
                root_link_names: None,
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
            },
            LinkTarget {
                name: "debug".to_string(),
                version: "2.6.9".to_string(),
                store_path: debug_v2_store,
                dependencies: vec![],
                aliases: HashMap::new(),
                is_direct: false,
                root_link_names: None,
            },
            LinkTarget {
                name: "other".to_string(),
                version: "1.0.0".to_string(),
                store_path: other_store,
                dependencies: vec![("debug".to_string(), "3.0.0".to_string())],
                aliases: HashMap::new(),
                is_direct: true,
                root_link_names: None,
            },
            LinkTarget {
                name: "debug".to_string(),
                version: "3.0.0".to_string(),
                store_path: debug_v3_store,
                dependencies: vec![],
                aliases: HashMap::new(),
                is_direct: false,
                root_link_names: None,
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
            },
            LinkTarget {
                name: "debug".to_string(),
                version: "2.6.9".to_string(),
                store_path: debug_v2_store,
                dependencies: vec![],
                aliases: HashMap::new(),
                is_direct: false,
                root_link_names: None,
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
            },
        ];

        let result = link_packages_hoisted(project_dir.path(), &packages, false, None).unwrap();

        // debug at root should exist
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

    // Finding #1: Path traversal in bin targets
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

    // Finding #2: Bin name validation
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

    // Finding #3: Windows cmd shim injection
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

    // Finding #5: Validate cmd paths for junction creation
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

    // Finding #6: Permission bits
    #[cfg(unix)]
    #[test]
    fn permission_bits_add_execute_only() {
        // mode | 0o111 should add execute without adding write for group/other
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

    // Finding #13: Relative symlinks
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

    // Finding #1 in hoisted mode
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
        }];

        let result = link_packages(project_dir.path(), &packages, false, None).unwrap();
        assert_eq!(
            result.bin_linked, 0,
            "absolute bin targets outside the package directory should be rejected"
        );
    }

    // Finding #2 integration: bin name ../escape should not create a link
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
            },
            LinkTarget {
                name: "shared".to_string(),
                version: "1.0.0".to_string(),
                store_path: shared_v1_store,
                dependencies: vec![],
                aliases: HashMap::new(),
                is_direct: false,
                root_link_names: None,
            },
            LinkTarget {
                name: "util".to_string(),
                version: "1.0.0".to_string(),
                store_path: util_v1_store,
                dependencies: vec![],
                aliases: HashMap::new(),
                is_direct: false,
                root_link_names: None,
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
            },
            LinkTarget {
                name: "shared".to_string(),
                version: "2.0.0".to_string(),
                store_path: shared_v2_store,
                dependencies: vec![],
                aliases: HashMap::new(),
                is_direct: false,
                root_link_names: None,
            },
            LinkTarget {
                name: "util".to_string(),
                version: "2.0.0".to_string(),
                store_path: util_v2_store,
                dependencies: vec![],
                aliases: HashMap::new(),
                is_direct: false,
                root_link_names: None,
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

    #[test]
    fn interrupted_link_cleaned_up_and_relinked() {
        let store_dir = tempfile::tempdir().unwrap();
        let project_dir = tempfile::tempdir().unwrap();

        let store_path = create_fake_store_package(store_dir.path(), "partial");

        // Simulate an interrupted link: create the pkg_nm directory but NOT the .linked marker
        let lpm_dir = project_dir.path().join("node_modules/.lpm");
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
        }];

        link_packages_hoisted(project_dir.path(), &packages, false, None).unwrap();

        let metadata_path = project_dir.path().join("node_modules/.lpm-metadata.json");
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
            },
            LinkTarget {
                name: "pkg-b".to_string(),
                version: "1.0.0".to_string(),
                store_path: store_b,
                dependencies: vec![],
                aliases: HashMap::new(),
                is_direct: true,
                root_link_names: None,
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
        }];

        let _r2 = link_packages_hoisted(project_dir.path(), &packages_v2, false, None).unwrap();

        // pkg-a should still be there (already existed, no re-link needed)
        assert!(project_dir.path().join("node_modules/pkg-a").exists());
        // pkg-b should be cleaned up
        assert!(
            !project_dir.path().join("node_modules/pkg-b").exists(),
            "stale pkg-b should be removed"
        );
        // Metadata should reflect only pkg-a
        let meta_path = project_dir.path().join("node_modules/.lpm-metadata.json");
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
        }];

        // First link
        link_packages_hoisted(project_dir.path(), &packages, false, None).unwrap();

        // Force re-link — should not skip even though metadata matches
        let r2 = link_packages_hoisted(project_dir.path(), &packages, true, None).unwrap();
        // force=true cleans then re-copies, so linked should be > 0
        assert_eq!(r2.linked, 1, "force should re-link everything");
        assert_eq!(r2.skipped, 0);
    }

    // ── Phase 32 Phase 6 — `LinkResult.materialized` population ──────
    //
    // The patch engine consumes `LinkResult.materialized` directly so it
    // never has to reverse-engineer linker shapes. These tests pin the
    // contract that the linker reports every physical destination it
    // wrote — including the `node_modules/.lpm/nested/<name>/` shape that
    // the first draft of Phase 6 missed (D-design-1).

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
                .join("node_modules/.lpm/lodash@4.17.21/node_modules/lodash")
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
            },
            LinkTarget {
                name: "debug".to_string(),
                version: "2.6.9".to_string(),
                store_path: debug_store,
                dependencies: vec![],
                aliases: HashMap::new(),
                is_direct: false,
                root_link_names: None,
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
        // the loser-of-conflict should land at node_modules/.lpm/nested/debug.
        // This is the F-V4 third shape that the first Phase 6 design draft
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
            },
            LinkTarget {
                name: "trans".to_string(),
                version: "1.0.0".to_string(),
                store_path: trans_store,
                dependencies: vec![("debug".to_string(), "3.0.0".to_string())],
                aliases: HashMap::new(),
                is_direct: false,
                root_link_names: None,
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
            },
            LinkTarget {
                name: "debug".to_string(),
                version: "2.0.0".to_string(),
                store_path: debug_v2_store,
                dependencies: vec![],
                aliases: HashMap::new(),
                is_direct: false,
                root_link_names: None,
            },
            LinkTarget {
                name: "debug".to_string(),
                version: "3.0.0".to_string(),
                store_path: debug_v3_store,
                dependencies: vec![],
                aliases: HashMap::new(),
                is_direct: false,
                root_link_names: None,
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

        // The .lpm/nested shape may or may not be exercised depending
        // on hoist tie-breaking, but if a node_modules/.lpm/nested
        // directory exists at all, every package inside it must be in
        // the materialized list.
        let lpm_nested = project_dir.path().join("node_modules/.lpm/nested");
        if lpm_nested.exists() {
            for entry in std::fs::read_dir(&lpm_nested).unwrap().flatten() {
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
            },
            LinkTarget {
                name: "debug".to_string(),
                version: "2.6.9".to_string(),
                store_path: debug_store,
                dependencies: vec![],
                aliases: HashMap::new(),
                is_direct: false,
                root_link_names: None,
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

    // ── Phase 57 follow-up — detach_package_hardlinks ─────────────
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
}
