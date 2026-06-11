use lpm_store::V2BaselineIndex;
use std::path::{Path, PathBuf};

pub(super) fn live_package_dir(
    project_dir: &Path,
    name: &str,
    version: &str,
    wrapper_id: Option<&str>,
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
        name,
        version,
        wrapper_id,
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
    name: &str,
    version: &str,
    wrapper_id: Option<&str>,
    store_path: &Path,
    v2_store: Option<&lpm_store::v2::Store>,
    baseline_index: Option<&V2BaselineIndex>,
) -> std::path::PathBuf {
    let layout = lpm_linker::LayoutPaths::for_project(project_dir);
    let nm = project_dir.join("node_modules");

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
    if isolated.is_dir() {
        return isolated;
    }

    // Hoisted layout: node_modules/<name>/. Doesn't disambiguate
    // version conflicts (a different version nested under a parent
    // would not be found by this probe), but covers the common case.
    //
    // Under
    // v2 mode the project's `node_modules/<name>` is a symlink into
    // `~/.lpm/store/v2/links/<key>/node_modules/<name>/`. `is_dir()`
    // follows the symlink, so this branch returns the (symlink) path
    // for direct-dep v2 installs — Node resolves through the symlink
    // at script time. No code change needed for direct deps under v2.
    let hoisted = nm.join(name);
    if hoisted.is_dir() {
        return hoisted;
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
        && let Some(b) = index.lookup(name, version)
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
/// **Why the guard is `!live.starts_with(store_root)`, not a byte-
/// equal `live != store_path` check.** The earlier draft used
/// `PathBuf` equality, which would silently miss a future
/// [`live_package_dir`] change that produced a structurally-different
/// fallback (anywhere under `~/.lpm/store/`). The semantic guard —
/// "never detach anything that lives inside the store root" — keeps
/// the safety property intact regardless of how the fallback path
/// is shaped, because detaching files inside `~/.lpm/store/` is
/// exactly what we're trying to prevent.
///
/// Pre-this
/// function returned `Ok(store_path)` whenever the live probe fell
/// through to the store. The caller then chdir'd into the store for
/// the lifecycle script — which, on macOS (clonefile, CoW) was a
/// silent corruption of the canonical bytes on first write, and on
/// Linux (hardlinks) the early `if !live.starts_with(store_root)`
/// branch skipped the detach so the script ran against shared
/// inodes. Either way, lifecycle scripts running inside the store
/// is a soundness violation; the install pipeline already gates
/// on "linked + scripted" so the fallback was unreachable in
/// practice but still load-bearing as a safety net.
/// closes the hole: when the resolved path is inside the store, we
/// return `Err(...)` instead of plowing forward. Callers already
/// format `Err(String)` results so no caller surface change is
/// needed.
///
/// Returns the layout-aware live directory on success, or a human-
/// readable failure string on detach error or unlinked-package
/// fallback. The error string is caller-formatted (printed to stdout
/// in pretty mode + stderr always for JSON consumers) so this
/// function itself stays free of UI concerns.
pub(super) fn prepare_live_package_dir(
    project_dir: &Path,
    pkg_name: &str,
    pkg_version: &str,
    wrapper_id: Option<&str>,
    store_path: &Path,
    store_root: &Path,
    baseline_index: Option<&V2BaselineIndex>,
) -> Result<PathBuf, String> {
    let live = live_package_dir(
        project_dir,
        pkg_name,
        pkg_version,
        wrapper_id,
        store_path,
        baseline_index,
    );

    // hard-error when the resolved live path lands
    // in the store. Previously this branch silently skipped detach AND
    // returned `Ok(store_path)`, letting the caller chdir into the
    // canonical bytes for a lifecycle script. See the function
    // doc-comment for the full motivation.
    if live.starts_with(store_root) {
        return Err(format!(
            "package {pkg_name}@{pkg_version} not linked into project — \
             refusing to run lifecycle script inside the store. \
             Run `lpm install` to materialize the wrapper tree, then retry."
        ));
    }

    if let Err(e) = lpm_linker::detach_package_hardlinks(&live) {
        return Err(format!("hardlink detach failed: {e}"));
    }

    Ok(live)
}
