//! Single source of truth for filesystem paths owned by the linker.
//!
//! Phase 61 introduces this module as the central place every consumer
//! (linker, rebuilder, doctor, install pipeline) consults to resolve
//! per-project wrapper / metadata / health-check paths. The motivation
//! is two-fold:
//!
//! 1. **Tier 2 relayout (61.1).** Phase 61 moves the isolated linker's
//!    `.lpm/<wrapper>/` tree out of `node_modules/` to
//!    `<project>/.lpm/wrappers/<wrapper>/`. Centralizing path
//!    construction here means future shape changes are a one-line
//!    edit rather than a workspace-wide grep hunt.
//!
//! 2. **Hoisted symmetry.** A future phase relocates hoisted-mode
//!    state (`.lpm-metadata.json`, `.lpm/nested/`) symmetrically.
//!    Those helpers ship in this module as stubs returning the
//!    current `node_modules`-scoped paths, so the consumer migration
//!    is already done; the future phase flips the helpers, not the
//!    call sites.
//!
//! ## Layout (post-61.1)
//!
//! - `isolated_wrapper_root()` → `<project>/.lpm/wrappers/`
//! - `isolated_legacy_wrapper_root()` → `<project>/node_modules/.lpm/`
//!   (used by [`LayoutPaths::needs_layout_migration`] to detect
//!   upgrade-in-place users)
//! - Hoisted helpers — unchanged, still scoped to `node_modules/`
//!
//! ## Migration / freshness
//!
//! [`LayoutPaths::needs_layout_migration`] is the predicate the install
//! pipeline consults to drive the 61.3 wipe-and-rebuild migration. The
//! install-state up-to-date check in `lpm-cli::install_state` calls it
//! so that an upgrade-in-place user (binary upgraded but `node_modules/`
//! not wiped) actually triggers migration rather than short-circuiting
//! on the install-hash match.

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

    // ── Isolated layout (post-61.1) ─────────────────────────────────

    /// Root directory holding every per-package wrapper for this
    /// project. The linker creates this dir in
    /// [`crate::cleanup_stale_entries`]; consumers that need to
    /// enumerate wrappers (e.g., the migration check) read from here.
    ///
    /// **Phase 61 layout (this commit, 61.1):** `<project>/.lpm/wrappers/`.
    /// Sits as a project-root sibling of `.lpm/install-hash`,
    /// `.lpm/build-state.json`, etc. Survives `rm -rf node_modules`
    /// — the property that makes the warm-install bench (and the
    /// "wipe `node_modules` after a teammate's lockfile change" user
    /// pattern surfaced in Phase 57.2) actually exercise the
    /// incremental linker.
    pub fn isolated_wrapper_root(&self) -> PathBuf {
        self.project_dir.join(".lpm").join("wrappers")
    }

    /// Pre-Phase-61 wrapper-root location: `<project>/node_modules/.lpm/`.
    /// Used by [`Self::needs_layout_migration`] to detect
    /// upgrade-in-place users whose `node_modules/` was not wiped
    /// and is therefore still hosting the old layout.
    ///
    /// 61.3's migration code reads this path to wipe the legacy
    /// wrapper subtree before letting the install rebuild from store
    /// at the new location.
    pub fn isolated_legacy_wrapper_root(&self) -> PathBuf {
        self.project_dir.join("node_modules").join(".lpm")
    }

    /// Build the symlink target for a root-level entry at
    /// `node_modules/<link_name>` pointing at the package living in
    /// `<wrapper-root>/<segment>/node_modules/<target_name>`.
    ///
    /// Encapsulates the depth math: a root symlink lives one level
    /// below `node_modules/` (or two levels for scoped names like
    /// `@scope/foo`), and the wrapper root is now a project-root
    /// sibling. So the returned path is
    /// `(..){link_depth + 1}/.lpm/wrappers/<segment>/node_modules/<target_name>`.
    ///
    /// `link_name` is the symlink's relative-from-`node_modules/`
    /// filename — used only to count `/` separators (its scoped
    /// depth). The resulting relative path is what the linker hands
    /// to `std::os::unix::fs::symlink` or `mklink /J` (after absolute
    /// resolution on Windows).
    pub fn root_symlink_target(
        &self,
        link_name: &str,
        segment: &str,
        target_name: &str,
    ) -> PathBuf {
        let link_depth = link_name.matches('/').count();
        // +1 for `..` out of `node_modules/` itself; `link_depth`
        // additional ups for any scope directories (`@scope/foo`).
        let dotdot_count = link_depth + 1;
        let mut p = PathBuf::new();
        for _ in 0..dotdot_count {
            p.push("..");
        }
        p.push(".lpm");
        p.push("wrappers");
        p.push(segment);
        p.push("node_modules");
        p.push(target_name);
        p
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
    pub fn needs_layout_migration(&self) -> bool {
        let legacy_populated = dir_is_nonempty(&self.isolated_legacy_wrapper_root());
        let new_populated = dir_is_nonempty(&self.isolated_wrapper_root());
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
    fn isolated_wrapper_root_is_project_root_sibling_in_61_1() {
        let dir = tmp_project();
        let layout = LayoutPaths::for_project(dir.path());
        assert_eq!(
            layout.isolated_wrapper_root(),
            dir.path().join(".lpm").join("wrappers")
        );
    }

    #[test]
    fn isolated_legacy_wrapper_root_still_under_node_modules() {
        let dir = tmp_project();
        let layout = LayoutPaths::for_project(dir.path());
        assert_eq!(
            layout.isolated_legacy_wrapper_root(),
            dir.path().join("node_modules").join(".lpm")
        );
    }

    #[test]
    fn legacy_and_current_wrapper_roots_diverge_in_61_1() {
        let dir = tmp_project();
        let layout = LayoutPaths::for_project(dir.path());
        assert_ne!(
            layout.isolated_legacy_wrapper_root(),
            layout.isolated_wrapper_root(),
            "61.1: legacy lives under node_modules/, new lives at project root"
        );
    }

    #[test]
    fn isolated_wrapper_dir_appends_segment() {
        let dir = tmp_project();
        let layout = LayoutPaths::for_project(dir.path());
        assert_eq!(
            layout.isolated_wrapper_dir("express@4.22.1"),
            dir.path()
                .join(".lpm")
                .join("wrappers")
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
                .join(".lpm")
                .join("wrappers")
                .join("express@4.22.1")
                .join(".linked")
        );
    }

    #[test]
    fn root_symlink_target_unscoped_has_one_dotdot() {
        let dir = tmp_project();
        let layout = LayoutPaths::for_project(dir.path());
        // node_modules/express → ../.lpm/wrappers/express@4.22.1/node_modules/express
        let target = layout.root_symlink_target("express", "express@4.22.1", "express");
        assert_eq!(
            target,
            PathBuf::from("..")
                .join(".lpm")
                .join("wrappers")
                .join("express@4.22.1")
                .join("node_modules")
                .join("express")
        );
    }

    #[test]
    fn root_symlink_target_scoped_has_two_dotdots() {
        let dir = tmp_project();
        let layout = LayoutPaths::for_project(dir.path());
        // node_modules/@types/node → ../../.lpm/wrappers/@types+node@1.0.0/node_modules/@types/node
        let target = layout.root_symlink_target("@types/node", "@types+node@1.0.0", "@types/node");
        assert_eq!(
            target,
            PathBuf::from("..")
                .join("..")
                .join(".lpm")
                .join("wrappers")
                .join("@types+node@1.0.0")
                .join("node_modules")
                .join("@types/node")
        );
    }

    #[test]
    fn root_symlink_target_aliased_root_link() {
        // Phase 40 P2: aliased root link uses the canonical target name
        // for the wrapper-segment lookup but keeps the local link name.
        // node_modules/strip-ansi-cjs → ../.lpm/wrappers/strip-ansi@6.0.1/node_modules/strip-ansi
        let dir = tmp_project();
        let layout = LayoutPaths::for_project(dir.path());
        let target = layout.root_symlink_target("strip-ansi-cjs", "strip-ansi@6.0.1", "strip-ansi");
        assert_eq!(
            target,
            PathBuf::from("..")
                .join(".lpm")
                .join("wrappers")
                .join("strip-ansi@6.0.1")
                .join("node_modules")
                .join("strip-ansi")
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
            dir.path().join("node_modules").join(".lpm").join("nested")
        );
    }

    #[test]
    fn needs_layout_migration_false_when_no_layouts_present() {
        let dir = tmp_project();
        let layout = LayoutPaths::for_project(dir.path());
        assert!(!layout.needs_layout_migration());
    }

    #[test]
    fn needs_layout_migration_false_when_only_new_layout_present() {
        let dir = tmp_project();
        let layout = LayoutPaths::for_project(dir.path());
        fs::create_dir_all(layout.isolated_wrapper_root().join("express@4.22.1")).unwrap();
        assert!(!layout.needs_layout_migration());
    }

    #[test]
    fn needs_layout_migration_false_when_legacy_dir_is_empty() {
        // Empty `node_modules/.lpm/` (e.g., just-created by some other
        // path or a half-completed clean) doesn't count as "layout to
        // migrate from."
        let dir = tmp_project();
        let layout = LayoutPaths::for_project(dir.path());
        fs::create_dir_all(layout.isolated_legacy_wrapper_root()).unwrap();
        assert!(!layout.needs_layout_migration());
    }

    #[test]
    fn needs_layout_migration_true_when_only_legacy_populated() {
        let dir = tmp_project();
        let layout = LayoutPaths::for_project(dir.path());
        fs::create_dir_all(layout.isolated_legacy_wrapper_root().join("express@4.22.1")).unwrap();
        assert!(layout.needs_layout_migration());
    }

    #[test]
    fn needs_layout_migration_false_when_both_populated() {
        // Mid-migration state — install pipeline's job to converge,
        // not the freshness predicate's. Returning `false` here keeps
        // the convergence semantics in the install code path.
        let dir = tmp_project();
        let layout = LayoutPaths::for_project(dir.path());
        fs::create_dir_all(layout.isolated_legacy_wrapper_root().join("express@4.22.1")).unwrap();
        fs::create_dir_all(layout.isolated_wrapper_root().join("express@4.22.1")).unwrap();
        assert!(!layout.needs_layout_migration());
    }

    #[test]
    fn install_appears_healthy_no_node_modules() {
        let dir = tmp_project();
        let layout = LayoutPaths::for_project(dir.path());
        assert_eq!(
            layout.install_appears_healthy(),
            InstallHealth::NoNodeModules
        );
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
        // node_modules/ must exist for the predicate; populated wrapper
        // root lives at the new project-root sibling location.
        fs::create_dir_all(dir.path().join("node_modules")).unwrap();
        let layout = LayoutPaths::for_project(dir.path());
        fs::create_dir_all(layout.isolated_wrapper_root().join("express@4.22.1")).unwrap();
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
        fs::create_dir_all(&nm).unwrap();
        fs::write(nm.join(".lpm-metadata.json"), b"{}").unwrap();
        let layout = LayoutPaths::for_project(dir.path());
        // Isolated wrapper root populated at the new project-root sibling
        // location AND hoisted metadata sidecar present in node_modules/.
        fs::create_dir_all(layout.isolated_wrapper_root().join("express@4.22.1")).unwrap();
        assert_eq!(
            layout.install_appears_healthy(),
            InstallHealth::Healthy {
                layout: LinkerLayout::Mixed
            }
        );
    }

    #[test]
    fn empty_wrapper_root_is_not_healthy() {
        let dir = tmp_project();
        fs::create_dir_all(dir.path().join("node_modules")).unwrap();
        let layout = LayoutPaths::for_project(dir.path());
        // Empty `.lpm/wrappers/` (e.g., just-created by `cleanup_stale_entries`
        // before the first link runs) should not register as
        // 'isolated layout present'.
        fs::create_dir_all(layout.isolated_wrapper_root()).unwrap();
        assert_eq!(
            layout.install_appears_healthy(),
            InstallHealth::NodeModulesPresentButNoStore,
        );
    }
}
