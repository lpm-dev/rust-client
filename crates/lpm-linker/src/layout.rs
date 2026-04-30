//! Single source of truth for filesystem paths owned by the linker.
//!
//! Phase 61 introduces this module as the central place every consumer
//! (linker, rebuilder, doctor, install pipeline) consults to resolve
//! per-project wrapper / metadata / health-check paths. The motivation
//! is two-fold:
//!
//! 1. **Tier 2 relayout** — Phase 61 moves the isolated linker's
//!    `.lpm/<wrapper>/` tree out of `node_modules/` to `<project>/.lpm/
//!    wrappers/<wrapper>/`. Centralizing path construction here means
//!    61.1's flip is a one-line change in this file rather than a grep
//!    hunt across the workspace.
//!
//! 2. **Hoisted symmetry** — a future phase relocates hoisted-mode
//!    state (`.lpm-metadata.json`, `.lpm/nested/`) symmetrically. Those
//!    helpers ship in this module today as stubs returning the current
//!    `node_modules`-scoped paths, so the consumer migration is already
//!    done; the future phase flips the helpers, not the call sites.
//!
//! ## Behavior contract during 61.0.5 (this commit)
//!
//! Every helper returns the *legacy* path. `isolated_wrapper_root`,
//! `isolated_wrapper_dir`, `isolated_marker_path` all hand back paths
//! under `node_modules/.lpm/`. `needs_layout_migration` returns `false`
//! unconditionally — there is nowhere new to migrate to yet. The
//! migration to this module is purely a CSE refactor; no observable
//! behavior changes, every existing test stays green.
//!
//! 61.1 flips `isolated_*` helpers to `<project>/.lpm/wrappers/...`,
//! at which point `needs_layout_migration` and `install_appears_healthy`
//! become meaningful predicates.

use std::path::{Path, PathBuf};

/// Resolves filesystem paths for a single project. Cheap to construct
/// (borrows the project root); construct one per `lpm install` /
/// `lpm rebuild` / `lpm doctor` invocation rather than passing it
/// through the call graph.
#[derive(Debug, Clone, Copy)]
pub struct LayoutPaths<'a> {
    project_dir: &'a Path,
}

/// Which linker layout the project is using (or both, mid-migration).
///
/// Reported by [`LayoutPaths::install_appears_healthy`] when an install
/// is healthy. Hoisted/Isolated detection looks for the layout's
/// distinctive on-disk marker (a populated wrapper root for isolated;
/// the metadata sidecar for hoisted). `Mixed` only happens when both
/// markers are present simultaneously — typically a user who killed
/// `lpm install` mid-migration in 61.3.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkerLayout {
    /// Isolated layout: `<project>/.lpm/wrappers/<seg>/...` (post-61.1)
    /// or `node_modules/.lpm/<seg>/...` (legacy / pre-61.1).
    Isolated,
    /// Hoisted layout: `node_modules/<pkg>/...` flat with optional
    /// nested overrides under `node_modules/.lpm/nested/`.
    Hoisted,
    /// Both isolated and hoisted state is present on disk. The most
    /// common cause is a half-completed `lpm install` during the 61.3
    /// migration. `lpm install` is idempotent — re-running it converges
    /// the tree to whichever layout is active.
    Mixed,
}

/// Result of [`LayoutPaths::install_appears_healthy`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallHealth {
    /// Both `node_modules/` and the appropriate per-layout marker are
    /// present.
    Healthy { layout: LinkerLayout },
    /// `node_modules/` exists but neither layout's marker is present.
    /// Usually means `lpm install` was interrupted before it could
    /// write its state, or the user is in a project that was set up
    /// with a different package manager.
    NodeModulesPresentButNoStore,
    /// `node_modules/` itself is missing — install hasn't run yet.
    NoNodeModules,
}

impl<'a> LayoutPaths<'a> {
    /// Construct a layout resolver rooted at `project_dir`.
    ///
    /// The project dir is borrowed; the resolver does no I/O until a
    /// helper that explicitly probes the filesystem is called. Cheap
    /// to construct in hot paths.
    pub fn for_project(project_dir: &'a Path) -> Self {
        Self { project_dir }
    }

    // ── Isolated layout ──────────────────────────────────────────────
    //
    // 61.0.5 contract: every helper below returns the LEGACY path
    // (`node_modules/.lpm/...`). 61.1 flips them to the new
    // `<project>/.lpm/wrappers/...` shape.

    /// Root directory holding every per-package wrapper for this
    /// project. The linker creates this dir in
    /// [`crate::cleanup_stale_entries`]; consumers that need to
    /// enumerate wrappers (e.g., the migration check) read from here.
    ///
    /// **61.0.5 (this commit):** `<project>/node_modules/.lpm/`
    /// **61.1 (next sub-phase):** `<project>/.lpm/wrappers/`
    pub fn isolated_wrapper_root(&self) -> PathBuf {
        self.project_dir.join("node_modules").join(".lpm")
    }

    /// Pre-Phase-61 wrapper-root location. Used by
    /// [`Self::needs_layout_migration`] to detect upgrade-in-place
    /// users whose `node_modules/` was not wiped and is therefore
    /// still hosting the old layout.
    ///
    /// In 61.0.5 this returns the SAME path as
    /// [`Self::isolated_wrapper_root`] (no migration available yet);
    /// 61.1 makes them diverge.
    pub fn isolated_legacy_wrapper_root(&self) -> PathBuf {
        self.project_dir.join("node_modules").join(".lpm")
    }

    /// Per-package wrapper directory:
    /// `<wrapper-root>/<segment>/`.
    ///
    /// `segment` should be the value of [`crate::LinkTarget::wrapper_segment`].
    pub fn isolated_wrapper_dir(&self, segment: &str) -> PathBuf {
        self.isolated_wrapper_root().join(segment)
    }

    /// `.linked` stamp marker inside a per-package wrapper directory.
    /// Existence + content match indicates the wrapper is up-to-date
    /// with the resolver's intent for this `(name, version, source)`
    /// triple.
    pub fn isolated_marker_path(&self, segment: &str) -> PathBuf {
        self.isolated_wrapper_dir(segment).join(".linked")
    }

    /// Layout schema version file. Records the `LayoutPaths` shape
    /// version (`1`) so a future shape change can detect old wrappers
    /// for clean wipe-and-rebuild.
    ///
    /// Lands at `<wrapper-root>/.version` — a sibling of the wrapper
    /// directories, never inside a wrapper.
    pub fn isolated_layout_version_path(&self) -> PathBuf {
        self.isolated_wrapper_root().join(".version")
    }

    // ── Hoisted layout (unchanged in Phase 61) ───────────────────────

    /// `node_modules/.lpm-metadata.json` — incremental state for
    /// hoisted mode. Written by `link_packages_hoisted`.
    pub fn hoisted_metadata_path(&self) -> PathBuf {
        self.project_dir
            .join("node_modules")
            .join(".lpm-metadata.json")
    }

    /// `node_modules/.lpm/nested/` — fallback location for nested
    /// override packages whose parent isn't hoisted.
    pub fn hoisted_nested_root(&self) -> PathBuf {
        self.project_dir
            .join("node_modules")
            .join(".lpm")
            .join("nested")
    }

    // ── Predicates ───────────────────────────────────────────────────

    /// Layout-aware "is this install fresh?" predicate.
    ///
    /// Wired into [`crate`]'s install-state up-to-date checks so that
    /// upgrade-in-place users (binary upgraded but `node_modules/`
    /// not wiped) correctly trigger the 61.3 migration code path
    /// instead of short-circuiting on the install-hash match.
    ///
    /// Returns `true` iff the legacy wrapper root is populated AND
    /// the new wrapper root either does not exist or is empty —
    /// meaning a layout migration is owed.
    ///
    /// **61.0.5 contract:** always returns `false`. The new wrapper
    /// root and the legacy root are the same path in 61.0.5, so there
    /// is no migration to do. 61.1 makes them diverge and this
    /// predicate becomes meaningful.
    pub fn needs_layout_migration(&self) -> bool {
        let new_root = self.isolated_wrapper_root();
        let legacy_root = self.isolated_legacy_wrapper_root();

        // 61.0.5: same path on both sides → no migration possible.
        // The probe below short-circuits cheaply because the equality
        // check costs only a path comparison; once 61.1 makes the
        // paths diverge the comparison is false and we read both
        // dirs' state.
        if new_root == legacy_root {
            return false;
        }

        let legacy_populated = dir_is_nonempty(&legacy_root);
        let new_populated = dir_is_nonempty(&new_root);

        legacy_populated && !new_populated
    }

    /// Doctor-style health probe. Reads `node_modules/` and the
    /// per-layout markers to decide whether the project looks like
    /// it has a working install.
    ///
    /// Used by `lpm doctor` (61.4) and could be reused elsewhere if a
    /// pre-flight check needs to fail-fast on a clearly-broken install.
    pub fn install_appears_healthy(&self) -> InstallHealth {
        let nm = self.project_dir.join("node_modules");
        if !nm.exists() {
            return InstallHealth::NoNodeModules;
        }

        let isolated_present = dir_is_nonempty(&self.isolated_wrapper_root());
        let hoisted_present = self.hoisted_metadata_path().exists();

        match (isolated_present, hoisted_present) {
            (true, true) => InstallHealth::Healthy {
                layout: LinkerLayout::Mixed,
            },
            (true, false) => InstallHealth::Healthy {
                layout: LinkerLayout::Isolated,
            },
            (false, true) => InstallHealth::Healthy {
                layout: LinkerLayout::Hoisted,
            },
            (false, false) => InstallHealth::NodeModulesPresentButNoStore,
        }
    }
}

/// Returns `true` iff the path exists, is a directory, and contains
/// at least one entry. Used by the migration / health predicates to
/// avoid treating an empty (placeholder) directory as evidence of a
/// real layout.
fn dir_is_nonempty(path: &Path) -> bool {
    let Ok(mut entries) = std::fs::read_dir(path) else {
        return false;
    };
    entries.next().is_some()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn tmp_project() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    #[test]
    fn isolated_wrapper_root_returns_legacy_path_in_61_0_5() {
        let dir = tmp_project();
        let layout = LayoutPaths::for_project(dir.path());
        assert_eq!(
            layout.isolated_wrapper_root(),
            dir.path().join("node_modules").join(".lpm")
        );
    }

    #[test]
    fn isolated_legacy_wrapper_root_matches_current_in_61_0_5() {
        let dir = tmp_project();
        let layout = LayoutPaths::for_project(dir.path());
        assert_eq!(
            layout.isolated_legacy_wrapper_root(),
            layout.isolated_wrapper_root(),
            "61.0.5 contract: legacy and current paths are the same; 61.1 makes them diverge"
        );
    }

    #[test]
    fn isolated_wrapper_dir_appends_segment() {
        let dir = tmp_project();
        let layout = LayoutPaths::for_project(dir.path());
        assert_eq!(
            layout.isolated_wrapper_dir("express@4.22.1"),
            dir.path()
                .join("node_modules")
                .join(".lpm")
                .join("express@4.22.1")
        );
    }

    #[test]
    fn isolated_marker_path_lives_inside_wrapper_dir() {
        let dir = tmp_project();
        let layout = LayoutPaths::for_project(dir.path());
        assert_eq!(
            layout.isolated_marker_path("express@4.22.1"),
            dir.path()
                .join("node_modules")
                .join(".lpm")
                .join("express@4.22.1")
                .join(".linked")
        );
    }

    #[test]
    fn hoisted_metadata_path_unchanged_in_phase_61() {
        let dir = tmp_project();
        let layout = LayoutPaths::for_project(dir.path());
        assert_eq!(
            layout.hoisted_metadata_path(),
            dir.path().join("node_modules").join(".lpm-metadata.json")
        );
    }

    #[test]
    fn hoisted_nested_root_unchanged_in_phase_61() {
        let dir = tmp_project();
        let layout = LayoutPaths::for_project(dir.path());
        assert_eq!(
            layout.hoisted_nested_root(),
            dir.path()
                .join("node_modules")
                .join(".lpm")
                .join("nested")
        );
    }

    #[test]
    fn needs_layout_migration_is_false_in_61_0_5() {
        // 61.0.5 contract: legacy and new wrapper roots are the same
        // path, so a populated legacy can't be "owed migration."
        let dir = tmp_project();
        let layout = LayoutPaths::for_project(dir.path());
        // Populate the legacy/current wrapper root.
        let wrapper = layout.isolated_wrapper_root().join("express@4.22.1");
        fs::create_dir_all(&wrapper).unwrap();
        assert!(!layout.needs_layout_migration());
    }

    #[test]
    fn install_appears_healthy_no_node_modules() {
        let dir = tmp_project();
        let layout = LayoutPaths::for_project(dir.path());
        assert_eq!(layout.install_appears_healthy(), InstallHealth::NoNodeModules);
    }

    #[test]
    fn install_appears_healthy_node_modules_present_but_no_store() {
        let dir = tmp_project();
        fs::create_dir_all(dir.path().join("node_modules")).unwrap();
        let layout = LayoutPaths::for_project(dir.path());
        assert_eq!(
            layout.install_appears_healthy(),
            InstallHealth::NodeModulesPresentButNoStore
        );
    }

    #[test]
    fn install_appears_healthy_isolated() {
        let dir = tmp_project();
        let nm = dir.path().join("node_modules");
        fs::create_dir_all(nm.join(".lpm").join("express@4.22.1")).unwrap();
        let layout = LayoutPaths::for_project(dir.path());
        assert_eq!(
            layout.install_appears_healthy(),
            InstallHealth::Healthy {
                layout: LinkerLayout::Isolated
            }
        );
    }

    #[test]
    fn install_appears_healthy_hoisted() {
        let dir = tmp_project();
        let nm = dir.path().join("node_modules");
        fs::create_dir_all(&nm).unwrap();
        fs::write(nm.join(".lpm-metadata.json"), b"{}").unwrap();
        let layout = LayoutPaths::for_project(dir.path());
        assert_eq!(
            layout.install_appears_healthy(),
            InstallHealth::Healthy {
                layout: LinkerLayout::Hoisted
            }
        );
    }

    #[test]
    fn install_appears_healthy_mixed() {
        let dir = tmp_project();
        let nm = dir.path().join("node_modules");
        fs::create_dir_all(nm.join(".lpm").join("express@4.22.1")).unwrap();
        fs::write(nm.join(".lpm-metadata.json"), b"{}").unwrap();
        let layout = LayoutPaths::for_project(dir.path());
        assert_eq!(
            layout.install_appears_healthy(),
            InstallHealth::Healthy {
                layout: LinkerLayout::Mixed
            }
        );
    }

    #[test]
    fn empty_directory_is_not_nonempty() {
        let dir = tmp_project();
        fs::create_dir_all(dir.path().join("node_modules").join(".lpm")).unwrap();
        let layout = LayoutPaths::for_project(dir.path());
        assert_eq!(
            layout.install_appears_healthy(),
            InstallHealth::NodeModulesPresentButNoStore,
            "empty .lpm/ should not register as 'isolated layout present'"
        );
    }
}
