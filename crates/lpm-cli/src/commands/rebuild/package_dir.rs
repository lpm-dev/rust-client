use lpm_store::V2BaselineIndex;
use std::path::{Path, PathBuf};

#[derive(Clone, Copy)]
pub(super) struct PackageLookupIdentity<'a> {
    pub(super) name: &'a str,
    pub(super) version: &'a str,
    pub(super) wrapper_id: Option<&'a str>,
    pub(super) source_id: Option<&'a str>,
    pub(super) source_integrity: Option<&'a str>,
}

impl<'a> PackageLookupIdentity<'a> {
    pub(super) fn new(
        name: &'a str,
        version: &'a str,
        wrapper_id: Option<&'a str>,
        source_id: Option<&'a str>,
        source_integrity: Option<&'a str>,
    ) -> Self {
        Self {
            name,
            version,
            wrapper_id,
            source_id,
            source_integrity,
        }
    }
}

pub(super) fn live_package_dir(
    project_dir: &Path,
    identity: PackageLookupIdentity<'_>,
    store_path: &Path,
    baseline_index: Option<&V2BaselineIndex>,
) -> std::path::PathBuf {
    // — production v2 store handle resolves once per
    // call from the active `~/.lpm/`. Tests use the
    // [`live_package_dir_with_v2`] seam directly with a synthetic
    // store rooted in a tempdir, so the env-coupled wrapper here
    // stays simple.
    let v2_store = lpm_common::LpmRoot::from_env()
        .ok()
        .map(|root| lpm_store::v2::Store::from_lpm_root(&root));
    live_package_dir_with_v2(
        project_dir,
        identity,
        store_path,
        v2_store.as_ref(),
        baseline_index,
    )
}

/// Test-friendly variant of [`live_package_dir`] that takes the v2
/// store handle explicitly instead of resolving it from the
/// environment. Production callers use the env-coupled wrapper.
///
/// The optional `baseline_index` is the project-
/// scoped lookup the transitive-fallback branch uses. When present
/// it's authoritative — the global `find_link_package_dir` walk is
/// only used as a backstop for callers that haven't built an index
/// (test fixtures, defensive paths). Under same-coordinate same-coord
/// coexistence the global walk can return the wrong sibling
/// project's link entry; the project-scoped index is the correct
/// disambiguation.
pub(super) fn live_package_dir_with_v2(
    project_dir: &Path,
    identity: PackageLookupIdentity<'_>,
    store_path: &Path,
    v2_store: Option<&lpm_store::v2::Store>,
    baseline_index: Option<&V2BaselineIndex>,
) -> std::path::PathBuf {
    let PackageLookupIdentity {
        name,
        version,
        wrapper_id,
        source_id,
        source_integrity,
    } = identity;
    let layout = lpm_linker::LayoutPaths::for_project(project_dir);
    let nm = project_dir.join("node_modules");

    if let Some(index) = baseline_index
        && let Some(source_id) = source_id
    {
        return index
            .lookup_source_identity(name, version, source_id)
            .map_or_else(
                || store_path.to_path_buf(),
                |baseline| baseline.package_dir.clone(),
            );
    }

    // Isolated layout (default): `<wrapper-root>/<segment>/node_modules/<name>/`.
    //
    // — wrapper root is `<project>/.lpm/wrappers/`, resolved
    // through `LayoutPaths` so a future shape change is a single-file edit.
    //
    // segment shape comes from
    // [`LayoutPaths::wrapper_segment`], the same helper
    // [`lpm_linker::LinkTarget::wrapper_segment`] delegates to. For
    // Registry sources `wrapper_id` is `None` and the segment is
    // `<safe>@<version>`; for Tarball / Directory / Link / Git the
    // segment is `<safe>+<wid>`. Previously the inline `<safe>@<version>`
    // shape silently missed every non-Registry scripted package — its
    // wrapper probe failed and the lifecycle script ran from the store
    // path (or, after the store-path guard, hard-errored under the new `prepare_live_package_dir`).
    let segment = lpm_linker::LayoutPaths::wrapper_segment(name, version, wrapper_id);
    let isolated = layout
        .isolated_wrapper_dir(&segment)
        .join("node_modules")
        .join(name);
    if package_dir_matches(&isolated, identity) {
        return isolated;
    }

    // Hoisted layout: node_modules/<name>/. Doesn't disambiguate
    // version conflicts (a different version nested under a parent
    // would not be found by this probe), but covers the common case.
    //
    // Under v2 mode the project's `node_modules/<name>` may point at
    // a project-local compatibility copy for direct-bin runtime
    // behavior. Lifecycle scripts must mutate the store link entry
    // instead, so compatibility copies fall through to the indexed v2
    // lookup below.
    if let Some(hoisted) = find_hoisted_package_dir(project_dir, identity) {
        let compatibility_root = nm.join(".lpm").join("compat");
        if !path_resolves_under(&hoisted, &compatibility_root) {
            return hoisted;
        }
    }

    // — v2 store walk for transitive lifecycle scripts.
    // Direct deps under v2 are covered by the previous branch via the
    // project-side symlink; transitives have no project-root symlink,
    // so without a store walk they'd fall through to the pathological
    // store_path fallback (which under v2 isn't even meaningful — v2
    // doesn't populate v1's `~/.lpm/store/v1/<pkg>/<version>/`).
    //
    // Authoritative path: consult the project-scoped
    // `V2BaselineIndex`. Its BFS over `LinkMeta.deps` reaches every
    // transitive that THIS project actually uses, and a hit there is
    // unambiguously the right link entry under same-coordinate same-coord
    // coexistence (a sibling project's patched copy can't appear in
    // a project that didn't symlink it).
    if let Some(index) = baseline_index
        && let Some(b) = index.lookup(name, version, source_integrity)
    {
        return b.package_dir.clone();
    }
    // Backstop for callers without an index in scope (test fixtures,
    // defensive paths). The global walk is correct when only one link
    // entry exists per `(name, version)`. When duplicates exist on
    // disk, this branch may pick the wrong entry; the indexed path
    // above covers every reachable production path.
    if let Some(store) = v2_store
        && let Ok(Some(v2_pkg)) = store.find_link_package_dir(name, version)
    {
        return v2_pkg;
    }

    // Pathological fallback: package isn't linked. Lifecycle scripts
    // shouldn't reach this code path (they're gated on linked + scripted
    // upstream), but if they do, preserve existing behavior so the
    // failure mode at least matches what users were already seeing.
    store_path.to_path_buf()
}

fn find_hoisted_package_dir(
    project_dir: &Path,
    identity: PackageLookupIdentity<'_>,
) -> Option<PathBuf> {
    let node_modules = project_dir.join("node_modules");
    let mut package_roots = Vec::new();
    if let Ok(entries) = std::fs::read_dir(&node_modules) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            if name.starts_with('.') {
                continue;
            }
            let path = entry.path();
            if !is_real_directory(&path) {
                continue;
            }
            if name.starts_with('@') {
                if let Ok(scoped_entries) = std::fs::read_dir(&path) {
                    package_roots.extend(
                        scoped_entries
                            .flatten()
                            .map(|entry| entry.path())
                            .filter(|path| is_real_directory(path)),
                    );
                }
            } else {
                package_roots.push(path);
            }
        }
    }

    let mut matches = Vec::new();
    let root_candidate = node_modules.join(identity.name);
    if package_dir_matches(&root_candidate, identity) {
        matches.push(root_candidate);
    }
    for package_root in package_roots {
        if package_dir_matches(&package_root, identity) && !matches.contains(&package_root) {
            matches.push(package_root.clone());
        }
        let nested = package_root.join("node_modules").join(identity.name);
        if package_dir_matches(&nested, identity) && !matches.contains(&nested) {
            matches.push(nested);
        }
    }
    let fallback = lpm_linker::LayoutPaths::for_project(project_dir)
        .hoisted_nested_root()
        .join(identity.name);
    if package_dir_matches(&fallback, identity) && !matches.contains(&fallback) {
        matches.push(fallback);
    }

    match matches.as_slice() {
        [package_dir] => Some(package_dir.clone()),
        _ => None,
    }
}

fn package_dir_matches(path: &Path, identity: PackageLookupIdentity<'_>) -> bool {
    if !is_real_directory(path) {
        return false;
    }
    let Ok(manifest) = std::fs::read(path.join("package.json")) else {
        return false;
    };
    let Ok(manifest) = serde_json::from_slice::<serde_json::Value>(&manifest) else {
        return false;
    };
    if manifest.get("name").and_then(serde_json::Value::as_str) != Some(identity.name)
        || manifest.get("version").and_then(serde_json::Value::as_str) != Some(identity.version)
    {
        return false;
    }
    identity
        .source_integrity
        .is_none_or(|expected| lpm_store::read_stored_integrity(path).as_deref() == Some(expected))
}

fn is_real_directory(path: &Path) -> bool {
    path.symlink_metadata()
        .is_ok_and(|metadata| metadata.file_type().is_dir() && !metadata.file_type().is_symlink())
}

/// resolve the live per-package directory AND
/// detach hardlinks so a lifecycle script's writes can't propagate
/// to the global content-addressable store.
///
/// Composes [`live_package_dir`] (which only finds the path) with
/// [`lpm_linker::detach_package_hardlinks`] (which breaks shared
/// inodes on Linux; no-op elsewhere). The single entry point is the
/// load-bearing safety boundary for the rebuild loop, and exposing
/// it as a function lets the test suite assert the composition end-
/// to-end without spinning up the full async [`run`] machinery.
///
/// **Why the guard is store-root based, not a byte-equal
/// `live != store_path` check.** The earlier draft used `PathBuf`
/// equality, which would silently miss a future [`live_package_dir`]
/// change that produced a structurally-different fallback anywhere
/// under `~/.lpm/store/`. The semantic guard rejects canonical store
/// bytes while allowing v2 link entries under `store/v2/links/`,
/// because those entries are the mutable package directories scripts
/// are supposed to build in.
///
/// Before this guard, the function returned `Ok(store_path)` whenever
/// the live probe fell through to the v1/object store. The caller then
/// chdir'd into the store for the lifecycle script — which, on macOS
/// (clonefile, CoW) was a silent corruption of the canonical bytes on
/// first write, and on Linux (hardlinks) skipped the detach so the
/// script ran against shared inodes. The guard closes that hole while
/// preserving v2's intended lifecycle location:
/// `store/v2/links/<key>/node_modules/<pkg>`.
///
/// Returns the layout-aware live directory on success, or a human-
/// readable failure string on detach error or unlinked-package
/// fallback. The error string is caller-formatted (printed to stdout
/// in pretty mode + stderr always for JSON consumers) so this
/// function itself stays free of UI concerns.
pub(super) fn prepare_live_package_dir(
    project_dir: &Path,
    identity: PackageLookupIdentity<'_>,
    store_path: &Path,
    store_root: &Path,
    baseline_index: Option<&V2BaselineIndex>,
) -> Result<PathBuf, String> {
    let live = live_package_dir(project_dir, identity, store_path, baseline_index);

    let is_v2_link_entry = path_resolves_under(&live, &v2_links_root(store_root));
    if !is_v2_link_entry && path_lives_in_protected_store_area(&live, store_root) {
        return Err(format!(
            "package {}@{} not linked into project — \
             refusing to run lifecycle script inside the store. \
             Run `lpm install` to materialize the wrapper tree, then retry.",
            identity.name, identity.version,
        ));
    }
    if !is_v2_link_entry && path_is_symlink(&live) {
        return Err(format!(
            "package {}@{} resolved to a symlinked lifecycle directory at {}",
            identity.name,
            identity.version,
            live.display()
        ));
    }

    if let Err(e) = lpm_linker::detach_package_hardlinks(&live) {
        return Err(format!("hardlink detach failed: {e}"));
    }

    Ok(live)
}

fn path_lives_in_protected_store_area(path: &Path, store_root: &Path) -> bool {
    path.starts_with(store_root) || path_resolves_under(path, store_root)
}

fn path_resolves_under(path: &Path, root: &Path) -> bool {
    let canonical_path = match std::fs::canonicalize(path) {
        Ok(path) => path,
        Err(_) => return false,
    };
    let canonical_root = match std::fs::canonicalize(root) {
        Ok(root) => root,
        Err(_) => return false,
    };
    canonical_path.starts_with(canonical_root)
}

fn path_is_symlink(path: &Path) -> bool {
    path.symlink_metadata()
        .is_ok_and(|metadata| metadata.file_type().is_symlink())
}

fn v2_links_root(store_root: &Path) -> PathBuf {
    let mut root = PathBuf::with_capacity(store_root.as_os_str().len() + 9);
    root.push(store_root);
    root.push("v2");
    root.push("links");
    root
}
