use crate::layout::LayoutPaths;
use crate::materialize::{link_dir_recursive, materialize_directory_source};
use crate::platform::create_symlink_or_junction;
#[cfg(windows)]
use crate::platform::validate_cmd_path;
#[cfg(unix)]
use crate::platform::{make_bin_target_executable, relative_symlink_target_from_parent};
use crate::types::{
    FinalizeResult, LinkDependency, LinkResult, LinkTarget, Materialization, MaterializedPackage,
    OnePackageResult,
};
use crate::validation::{
    ensure_child_dir, ensure_real_dir, filter_node_modules_entry_name,
    is_safe_node_modules_entry_name, is_valid_self_ref_name, validate_bin_name,
    validate_bin_target,
};
use lpm_common::{LpmError, is_symlink_or_junction, remove_path_entry};
use rayon::prelude::*;
use std::path::{Component, Path, PathBuf};

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
/// marker is empty / from an older schema), the wrapper is treated
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
pub(crate) fn compute_link_stamp(target: &LinkTarget) -> String {
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
    let mut deps_sorted: Vec<&LinkDependency> = target.dependencies.iter().collect();
    deps_sorted.sort_by(|a, b| {
        a.local
            .cmp(&b.local)
            .then_with(|| a.target_name.cmp(&b.target_name))
            .then_with(|| a.graph_key_value().cmp(b.graph_key_value()))
    });
    let deps_str = deps_sorted
        .iter()
        .map(|dep| {
            format!(
                "{}=>{}@{}",
                dep.local,
                dep.target_name,
                dep.graph_key_value()
            )
        })
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
/// field must agree. Empty legacy markers, older stamp schemas,
/// unparseable bytes, or unknown versions all produce `false` so the
/// caller force-relinks.
pub(crate) fn link_stamp_matches(marker_path: &Path, target: &LinkTarget) -> bool {
    let Ok(on_disk) =
        lpm_common::read_file_capped(marker_path, lpm_common::STATE_FILE_SIZE_CAP_BYTES)
    else {
        return false;
    };
    on_disk == compute_link_stamp(target).as_bytes()
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

    // `node_modules/` and the wrapper root are disjoint paths, so each
    // gets its own create and validation step.
    std::fs::create_dir_all(&node_modules)?;
    ensure_real_dir(&node_modules, "node_modules")?;
    std::fs::create_dir_all(&lpm_dir)?;

    // Layout schema version. Written best-effort — if the write fails
    // (read-only FS, permissions), the install still proceeds; the file
    // is purely a forward-compat tag.
    let version_path = layout.isolated_layout_version_path();
    if !version_path.exists() {
        let _ = std::fs::write(&version_path, b"1\n");
    }
    // Pruning of stale hoisted state at `<project>/.lpm/hoisted/` is
    // deferred to [`link_finalize`] so a failed isolated install doesn't
    // strand the user with neither layout's state present.

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
    // Retarget legacy-shape root symlinks. If an upgrade wipes the
    // old wrapper root, `node_modules/<pkg>` can be left as a dangling
    // symlink whose target still points at `.lpm/<seg>/...`. Remove
    // those links even when the name is still expected; Stage 3 will
    // recreate them against the current wrapper-root shape. Self-refs
    // (target = `..`) and workspace-member symlinks (target outside
    // `.lpm/`) are unaffected because the predicate requires `.lpm/`.
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
            let entry_path = entry.path();
            let Ok(entry_metadata) = entry_path.symlink_metadata() else {
                continue;
            };
            // For scoped packages, check the full path
            let full_name = if entry_metadata.is_dir()
                && !is_symlink_or_junction(&entry_metadata)
                && name.starts_with('@')
            {
                // Check children of scope dir
                if let Ok(scope_entries) = std::fs::read_dir(&entry_path) {
                    for se in scope_entries.flatten() {
                        let se_path = se.path();
                        let scoped_name = format!("{name}/{}", se.file_name().to_string_lossy());
                        let is_link = se_path
                            .symlink_metadata()
                            .is_ok_and(|metadata| is_symlink_or_junction(&metadata));
                        if !is_link {
                            continue;
                        }
                        let stale = !direct_names.contains(scoped_name.as_str());
                        let legacy_shape = is_legacy_wrapper_symlink_target(&se_path);
                        if stale || legacy_shape {
                            let _ = remove_path_entry(&se_path);
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
            let is_link = is_symlink_or_junction(&entry_metadata);
            if !is_link {
                continue;
            }
            let stale = !direct_names.contains(full_name.as_str());
            let legacy_shape = is_legacy_wrapper_symlink_target(&entry_path);
            if stale || legacy_shape {
                let _ = remove_path_entry(&entry_path);
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
            let is_link = path
                .symlink_metadata()
                .is_ok_and(|metadata| is_symlink_or_junction(&metadata));
            if is_link || !path.is_dir() {
                continue;
            }
            if name_str.starts_with('@') {
                // Scope dir — recurse one level.
                if let Ok(scope_entries) = std::fs::read_dir(&path) {
                    for se in scope_entries.flatten() {
                        let se_path = se.path();
                        let se_is_link = se_path
                            .symlink_metadata()
                            .is_ok_and(|metadata| is_symlink_or_junction(&metadata));
                        if se_is_link || !se_path.is_dir() {
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
/// at the legacy wrapper-root shape (`.lpm/<seg>/...` without
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

    // Always record the canonical destination, even on the marker-skip
    // fast path — the package is materialized there from a prior install
    // run, just not freshly relinked.
    let materialized = MaterializedPackage {
        name: target.name.clone(),
        version: target.version.clone(),
        destination: pkg_nm.clone(),
    };

    // Incremental: skip packages that already have a completed link
    // marker with a stamp matching the new target's identity.
    //
    // NOTE: The .linked marker check is not atomic with the linking
    // operation. A local attacker with filesystem access could plant a
    // fake marker to prevent re-linking. However, local filesystem access
    // already implies full compromise (can modify node_modules directly),
    // so this is an accepted risk. The marker is a performance
    // optimization, not a security boundary.
    //
    // The stamp distinguishes wrappers that share the same segment but
    // come from different source/materialization shapes. Mismatch (or an
    // empty, legacy, or unparseable marker) drops to the remove-and-relink
    // branch below.
    //
    // Snapshot every filesystem predicate once at function entry, then
    // dispatch on locals. Concurrent mutations after the snapshot still
    // produce a consistent outcome — the worst case is one extra relink
    // on the next install, not a leaked wrapper.
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

    // Stamp mismatch (or `force`, or marker absence): clear any prior
    // materialization at `pkg_entry_dir` so the new contents land
    // cleanly. Wiping the whole wrapper matters because Stage 2 sibling
    // symlinks live next to the package directory and are intentionally
    // skipped if already present.
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
        // The package dir was created but the marker never landed. Wipe
        // the full wrapper because Stage 2 may have planted partial
        // sibling symlinks.
        tracing::debug!("cleaning up interrupted link for {safe_name}");
        let _ = std::fs::remove_dir_all(&pkg_entry_dir);
    }

    if !pkg_nm.exists() {
        if let Some(parent) = pkg_nm.parent() {
            std::fs::create_dir_all(parent)?;
        }
        // Materialization strategy is dispatched by the explicit
        // `materialization` field, not by `wrapper_id.is_some()`;
        // wrapper identity and source materialization are separate
        // concerns.
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
    // Local-name / target-name split. The symlink filename uses the
    // local name (what the parent's source code expects via
    // `require(dep_local)`). The symlink target uses the canonical name
    // that keys the `.lpm/<name>@<version>/` entry. For aliases,
    // `aliases.get(local)` provides the target:
    //   parent/.lpm/.../node_modules/strip-ansi-cjs
    //     -> ../../strip-ansi@6.0.1/node_modules/strip-ansi
    let pkg_nm_dir = pkg_entry_dir.join("node_modules");
    let mut symlinks_created = 0;

    // Pre-create the small set of unique scope dirs (`@types/`,
    // `@scope/`, …) needed by scoped deps in one pass, outside the
    // per-dep loop. Non-scoped deps need no parent mkdir because
    // `pkg_nm_dir` itself already exists.
    let mut scope_dirs_created: std::collections::HashSet<&str> = std::collections::HashSet::new();
    for dep in &target.dependencies {
        if !is_safe_node_modules_entry_name(&dep.local) {
            tracing::warn!(
                "skipping unsafe dependency local name {:?} for {}@{}",
                dep.local,
                target.name,
                target.version
            );
            continue;
        }
        if let Some((scope, _)) = dep.local.split_once('/')
            && scope.starts_with('@')
            && scope_dirs_created.insert(scope)
        {
            ensure_child_dir(&pkg_nm_dir.join(scope), "dependency scope")?;
        }
    }

    for dep in &target.dependencies {
        let dep_local = dep.local.as_str();
        if !is_safe_node_modules_entry_name(dep_local) {
            continue;
        }
        let dep_link = pkg_nm_dir.join(dep_local);

        if dep_link.exists() || dep_link.symlink_metadata().is_ok() {
            continue;
        }

        // Symlink to the dep's location in .lpm/
        // Base: ../../<dep_target>@<ver>/node_modules/<dep_target>
        // For scoped LOCAL names like @types/node, the symlink lives
        // at `.lpm/<pkg>/node_modules/@types/node` — one extra level
        // deep — so we traverse one more `..`. The `..` depth is
        // computed from the LOCAL name (which decides where the
        // symlink FILE sits).
        let depth = 2 + dep_local.matches('/').count();
        let mut sym_target = PathBuf::new();
        for _ in 0..depth {
            sym_target.push("..");
        }
        sym_target.push(dep.wrapper_segment());
        sym_target.push("node_modules");
        sym_target.push(&dep.target_name);

        create_symlink_or_junction(&sym_target, &dep_link)?;
        symlinks_created += 1;
    }

    // Write the stamped marker after a successful link + symlink pass.
    // The stamp's identity check on the next install distinguishes a
    // wrapper materialized from this LinkTarget from one materialized
    // from a different source kind that happens to share the same
    // wrapper segment.
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
    // `[pkg.name]` iff `is_direct`.
    let default_link: Vec<String> = Vec::new();
    let link_pairs: Vec<(&LinkTarget, String)> = packages
        .iter()
        .flat_map(|pkg| {
            let names: Vec<String> = match (&pkg.root_link_names, pkg.is_direct) {
                (Some(explicit), _) => explicit.clone(),
                (None, true) => vec![pkg.name.clone()],
                (None, false) => default_link.clone(),
            };
            names.into_iter().filter_map(move |n| {
                filter_node_modules_entry_name(n, &pkg.name, &pkg.version, "root link")
                    .map(|name| (pkg, name))
            })
        })
        .collect();

    // Pre-create the small set of unique `@scope/` dirs at
    // `node_modules/` once, before the parallel root-link loop. For
    // non-scoped link names the parent is `node_modules/` itself.
    let mut root_scope_dirs: std::collections::HashSet<&str> = std::collections::HashSet::new();
    for (_, link_name) in &link_pairs {
        if let Some((scope, _)) = link_name.split_once('/')
            && scope.starts_with('@')
            && root_scope_dirs.insert(scope)
        {
            ensure_child_dir(&node_modules.join(scope), "root scope")?;
        }
    }

    let root_link_count = link_pairs
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
                    ensure_child_dir(scope_dir, "self-reference scope")?;
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
        symlinks_created: root_link_count + self_ref_count,
        bin_count,
        self_referenced,
    })
}

/// Create a `node_modules/<package_name>` symlink that points at a workspace
/// member's source directory.
///
/// The install pipeline strips workspace member dependencies from the
/// resolver input before resolution and links them locally with this
/// helper after the regular linking pass has finished. The function is
/// idempotent — if a stale entry already exists at the link path it is
/// removed first so re-running `lpm install` does not error out on the
/// second invocation.
///
/// The symlink target is a relative path computed via [`pathdiff::diff_paths`]
/// from the link's parent directory to the member source directory. Existing
/// ancestors are canonicalized, while a missing final target is preserved so
/// packages can declare a not-yet-built `publishConfig.directory`.
///
/// On Windows, the relative path is resolved into an absolute target before
/// being passed to [`create_symlink_or_junction`] because NTFS junctions
/// require absolute targets.
///
/// Errors:
/// - I/O failures creating parent directories or the symlink itself
/// - An existing ancestor of the member source directory cannot be resolved
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

    let requested_source = if member_source_dir.is_absolute() {
        member_source_dir.to_path_buf()
    } else {
        std::env::current_dir()?.join(member_source_dir)
    };
    let mut existing_ancestor = requested_source.as_path();
    let (canonical_ancestor, missing_suffix) = loop {
        match existing_ancestor.canonicalize() {
            Ok(canonical) => {
                let suffix = requested_source
                    .strip_prefix(existing_ancestor)
                    .unwrap_or_else(|_| Path::new(""));
                break (canonical, suffix);
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                existing_ancestor = existing_ancestor.parent().ok_or_else(|| {
                    LpmError::Io(std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        format!(
                            "workspace member source has no existing ancestor: {}",
                            member_source_dir.display()
                        ),
                    ))
                })?;
            }
            Err(error) => return Err(LpmError::Io(error)),
        }
    };
    let source_target = canonical_ancestor.join(missing_suffix);

    let link_path = node_modules_dir.join(package_name);

    // Make sure the parent of the link path exists. For scoped packages
    // (`@scope/name`) this creates the `@scope/` directory; for unscoped
    // packages this is a no-op because `node_modules/` itself is the parent.
    if let Some(link_parent) = link_path.parent() {
        ensure_child_dir(link_parent, "workspace member scope")?;
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
    let relative_target = pathdiff::diff_paths(&source_target, &link_parent_canonical)
        .unwrap_or_else(|| source_target.clone());

    #[cfg(unix)]
    {
        if link_path
            .symlink_metadata()
            .is_ok_and(|metadata| !is_symlink_or_junction(&metadata))
        {
            let _ = remove_path_entry(&link_path);
        }
        lpm_common::replace_symlink_atomic(&link_path, &relative_target).map_err(|error| {
            LpmError::Io(std::io::Error::new(
                error.kind(),
                format!(
                    "failed to link workspace member at {} to {}: {error}",
                    link_path.display(),
                    relative_target.display()
                ),
            ))
        })?;
    }
    #[cfg(windows)]
    {
        static WORKSPACE_LINK_LOCK: std::sync::OnceLock<std::sync::Mutex<()>> =
            std::sync::OnceLock::new();
        let _guard = WORKSPACE_LINK_LOCK
            .get_or_init(|| std::sync::Mutex::new(()))
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if link_path.symlink_metadata().is_ok() {
            let _ = remove_path_entry(&link_path);
        }
        create_symlink_or_junction(&relative_target, &link_path).map_err(LpmError::Io)?;
    }
    Ok(())
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
        // Route the wrapper-segment shape through
        // [`LinkTarget::wrapper_segment`] so local-source deps
        // (Directory/Link, with `wrapper_id = Some(_)`) resolve
        // correctly in `.bin` shims.
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

                make_bin_target_executable(&target)?;
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
