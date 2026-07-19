use crate::layout::LayoutPaths;
use crate::materialize::link_dir_recursive;
use crate::platform::create_symlink_or_junction;
#[cfg(windows)]
use crate::platform::validate_cmd_path;
#[cfg(unix)]
use crate::platform::{make_bin_target_executable, relative_symlink_target_from_parent};
use crate::types::{LinkResult, LinkTarget, MaterializedPackage};
use crate::validation::{
    ensure_child_dir, ensure_real_dir, filter_node_modules_entry_name, is_valid_self_ref_name,
    validate_bin_name, validate_bin_target,
};
use lpm_common::LpmError;
use lpm_common::remove_dir_symlink_or_junction;
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};

pub(crate) fn reconcile_empty_hoisted_root(project_dir: &Path) -> Result<(), LpmError> {
    let layout = LayoutPaths::for_project(project_dir);
    let node_modules = project_dir.join("node_modules");
    let node_modules_metadata = match node_modules.symlink_metadata() {
        Ok(metadata) => Some(metadata),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(LpmError::Io(error)),
    };
    if node_modules_metadata
        .as_ref()
        .is_some_and(|metadata| metadata.file_type().is_symlink())
    {
        remove_dir_symlink_or_junction(&node_modules).map_err(|error| {
            LpmError::Store(format!(
                "hoisted linker: failed to remove symlinked node_modules at {}: {error}",
                node_modules.display()
            ))
        })?;
    } else if node_modules_metadata.is_some() {
        let entries = std::fs::read_dir(&node_modules).map_err(|error| {
            LpmError::Store(format!(
                "hoisted linker: failed to read {} while reconciling an empty install: {error}",
                node_modules.display()
            ))
        })?;
        for entry in entries {
            let entry = entry.map_err(LpmError::Io)?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            let managed =
                !name.starts_with('.') || matches!(name, ".bin" | ".lpm" | ".lpm-metadata.json");
            if managed {
                remove_hoisted_entry(&entry.path())?;
            }
        }
    }

    let hoisted_root = layout.hoisted_root();
    if hoisted_root.exists() {
        std::fs::remove_dir_all(&hoisted_root).map_err(|error| {
            LpmError::Store(format!(
                "hoisted linker: failed to remove stale state at {}: {error}",
                hoisted_root.display()
            ))
        })?;
    }
    Ok(())
}

fn remove_hoisted_entry(path: &Path) -> Result<(), LpmError> {
    let metadata = match path.symlink_metadata() {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(LpmError::Io(error)),
    };
    let result = if metadata.file_type().is_dir() && !metadata.file_type().is_symlink() {
        std::fs::remove_dir_all(path)
    } else {
        std::fs::remove_file(path)
    };
    result.map_err(|error| {
        LpmError::Store(format!(
            "hoisted linker: failed to remove stale package entry at {}: {error}",
            path.display()
        ))
    })
}

#[cfg(all(test, unix))]
mod empty_reconcile_tests {
    use super::*;

    #[test]
    fn empty_reconcile_never_traverses_symlinked_node_modules() {
        let project = tempfile::tempdir().unwrap();
        let external = tempfile::tempdir().unwrap();
        let sentinel = external.path().join("must-survive");
        std::fs::write(&sentinel, b"external data").unwrap();
        std::os::unix::fs::symlink(external.path(), project.path().join("node_modules")).unwrap();

        reconcile_empty_hoisted_root(project.path()).unwrap();

        assert!(
            sentinel.exists(),
            "empty reconciliation must not delete through a node_modules symlink"
        );
    }
}

#[cfg(all(test, windows))]
mod empty_reconcile_windows_tests {
    use super::*;

    #[test]
    fn empty_reconcile_removes_a_node_modules_junction_without_touching_its_target() {
        let project = tempfile::tempdir().unwrap();
        let external = tempfile::tempdir().unwrap();
        let sentinel = external.path().join("must-survive");
        std::fs::write(&sentinel, b"external data").unwrap();
        create_symlink_or_junction(external.path(), &project.path().join("node_modules")).unwrap();

        reconcile_empty_hoisted_root(project.path()).unwrap();

        assert!(sentinel.exists());
        assert!(!project.path().join("node_modules").exists());
    }
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
/// The lookup must keep package version identity all the way through
/// the consumer chain. Picking a consumer by name alone is ambiguous
/// when the same package name appears at multiple versions.
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
        // Alias-aware anchor lookup: check whether `cur` is hoisted
        // under any slot. An aliased direct dep may have
        // `root_link_names = ["a-alias"]` while `pkg.name = "lodash"`;
        // the on-disk parent dir is the slot, not necessarily the
        // canonical package name.
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

    // Hoisted state lives under `<project>/.lpm/hoisted/`, so
    // `node_modules/.lpm/` is legacy debris for this mode. During a
    // forced hoisted relink, remove it alongside other stale entries.
    if node_modules.exists()
        && force
        && let Ok(entries) = std::fs::read_dir(&node_modules)
    {
        for entry in entries.flatten() {
            let name = entry.file_name();
            if name != ".bin" {
                let path = entry.path();
                if path
                    .symlink_metadata()
                    .is_ok_and(|metadata| metadata.is_dir() && !metadata.file_type().is_symlink())
                {
                    let _ = std::fs::remove_dir_all(&path);
                } else {
                    let _ = std::fs::remove_file(&path);
                }
            }
        }
    }

    std::fs::create_dir_all(&node_modules)?;
    ensure_real_dir(&node_modules, "node_modules")?;

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
                .is_ok_and(|m| m.file_type().is_symlink());
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
                        .is_ok_and(|m| m.file_type().is_symlink());
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
    // with neither layout's state present. The inactive-mode prune runs
    // just before the function's `Ok(LinkResult)` return.

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
    // package indices. Indices preserve identity when the same consumer
    // package name appears at multiple versions. Use borrowed keys from
    // the `packages` slice to avoid heap allocations per dependency edge.
    let mut depended_by: HashMap<(&str, &str), Vec<usize>> = HashMap::new();
    for (idx, pkg) in packages.iter().enumerate() {
        for dep in &pkg.dependencies {
            depended_by
                .entry((dep.target_name.as_str(), dep.target_version.as_str()))
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

    // npm-alias root-slot claiming: root slots are keyed by local
    // `root_link_names`, not only by canonical `pkg.name`. A
    // `npm:<target>@<range>` alias declared at root level can install a
    // package under `node_modules/<local-alias>/` while the package's
    // canonical name remains different.
    //
    // Slot derivation (per package):
    //   - `Some(names)`: claim each entry. Empty Vec means "explicitly
    //     no root surface" — the package still gets bin shims via
    //     other paths but no top-level `node_modules/<name>/` entry
    //     (matches v2's contract).
    //   - `None`: claim `[pkg.name]`. Covers transitive deps (always
    //     None) and direct deps that deliberately use the canonical-only
    //     shape.
    let slots_for_pkg = |pkg: &LinkTarget| -> Vec<String> {
        let raw = match &pkg.root_link_names {
            Some(names) => names.clone(),
            None => vec![pkg.name.clone()],
        };
        raw.into_iter()
            .filter_map(|slot| {
                filter_node_modules_entry_name(slot, &pkg.name, &pkg.version, "hoisted root")
            })
            .collect()
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
    // graph error), fall back to the conflict's own name; Stage 3's
    // `hoisted.contains_key` gate handles that via `hoisted_nested_root()`.
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
                ensure_child_dir(parent, "hoisted root scope")?;
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

        // Even on the metadata-skip fast path, the patch-apply pass
        // needs the materialized location list. Re-derive it from the
        // same `packages` slice plus the `hoisted` / `nested` decision
        // tables above. The destinations are identical to the full
        // re-link branch.
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

    // Stage 3.5: self-reference — package can require("itself"). Runs
    // unconditionally on both the full re-link branch and the
    // metadata-skip fast path because the isolated→hoisted convergence
    // sweep may delete an existing self-ref symlink.
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
                        ensure_child_dir(scope_dir, "self-reference scope")?;
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
