//! Single source of truth for filesystem paths owned by the linker.
//!
//! Every consumer (linker, rebuilder, doctor, install pipeline)
//! resolves per-project wrapper / metadata / health-check paths
//! through this module. Both isolated and hoisted modes keep their
//! state under `<project>/.lpm/` rather than inside `node_modules/`,
//! so `rm -rf node_modules` doesn't orphan sibling metadata and the
//! `Mixed` health surface has a coherent mode-switch story.
//!
//! ## Layout
//!
//! - `isolated_wrapper_root()` → `<project>/.lpm/wrappers/`
//! - `isolated_legacy_wrapper_root()` → `<project>/node_modules/.lpm/`
//!   (used by `needs_isolated_layout_migration` to detect
//!   upgrade-in-place users still on the legacy layout)
//! - `hoisted_root()` → `<project>/.lpm/hoisted/`
//! - `hoisted_metadata_path()` → `<project>/.lpm/hoisted/metadata.json`
//! - `hoisted_nested_root()` → `<project>/.lpm/hoisted/nested/`
//! - `hoisted_legacy_metadata_path()` → `<project>/node_modules/.lpm-metadata.json`
//! - `hoisted_legacy_nested_root()` → `<project>/node_modules/.lpm/nested/`
//!   (both legacy helpers used by `needs_hoisted_layout_migration` to
//!   detect upgrade-in-place hoisted users)
//!
//! ## Migration / freshness
//!
//! [`LayoutPaths::needs_layout_migration`] is the public predicate the
//! install pipeline consults to drive a wipe-and-rebuild migration.
//! It is `||` over two private predicates,
//! [`LayoutPaths::needs_isolated_layout_migration`] and
//! [`LayoutPaths::needs_hoisted_layout_migration`], so each mode's
//! migration logic stays independently testable while callers see one
//! flag. The install-state up-to-date check in
//! `lpm-cli::install_state` calls only the public predicate so an
//! upgrade-in-place user on either legacy layout actually triggers
//! migration rather than short-circuiting on the install-hash match.

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
    /// Hoisted layout: `node_modules/<pkg>/...` flat with incremental
    /// state at `<project>/.lpm/hoisted/metadata.json` and any nested
    /// overrides under `<project>/.lpm/hoisted/nested/`
    /// (post-symmetry); legacy variants are
    /// `node_modules/.lpm-metadata.json` + `node_modules/.lpm/nested/`.
    Hoisted,
    /// Virtual-store layout: project `node_modules/<dep>` is a
    /// symlink into `~/.lpm/store/v2/links/<graph-key>/node_modules/<dep>/`.
    /// Neither `<project>/.lpm/wrappers/` nor `<project>/.lpm/hoisted/`
    /// is populated — the canonical bytes live globally and the
    /// project holds only the entry-point symlinks. Detected by
    /// [`LayoutPaths::is_v2_install`].
    Virtual,
    /// Both isolated and hoisted state is present on disk. The most
    /// common cause is a half-completed `lpm install` during a
    /// layout migration. `lpm install` is idempotent — re-running
    /// converges the tree to whichever layout is active.
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

    // ── Isolated layout ─────────────────────────────────────────────

    /// Root directory holding every per-package wrapper for this
    /// project. The linker creates this dir in
    /// [`crate::cleanup_stale_entries`]; consumers that need to
    /// enumerate wrappers (e.g., the migration check) read from here.
    ///
    /// Path: `<project>/.lpm/wrappers/`. Sits as a project-root
    /// sibling of `.lpm/install-hash`, `.lpm/build-state.json`, etc.
    /// Survives `rm -rf node_modules` — the property that lets the
    /// "wipe `node_modules` after a teammate's lockfile change" user
    /// pattern actually exercise the incremental linker.
    pub fn isolated_wrapper_root(&self) -> PathBuf {
        self.project_dir.join(".lpm").join("wrappers")
    }

    /// Legacy wrapper-root location: `<project>/node_modules/.lpm/`.
    /// Used by [`Self::needs_layout_migration`] to detect
    /// upgrade-in-place users whose `node_modules/` was not wiped
    /// and is still hosting the old layout. The migration code reads
    /// this path to wipe the legacy subtree before rebuilding from
    /// store at the new location.
    pub fn isolated_legacy_wrapper_root(&self) -> PathBuf {
        self.project_dir.join("node_modules").join(".lpm")
    }

    /// Returns `true` iff [`Self::isolated_legacy_wrapper_root`] both
    /// exists AND contains at least one entry that looks like a
    /// legacy wrapper segment — a non-dotfile entry whose name is
    /// not literally `nested` (which is the hoisted-mode fallback
    /// root, not isolated state).
    ///
    /// Exposed publicly so the install pipeline's migration helper
    /// can decide whether to print the "migrating wrapper layout"
    /// notice. Keying off bare `legacy_root.exists()` would fire on
    /// hoisted-only projects with transitive conflicts (their
    /// `node_modules/.lpm/nested/` makes the parent dir exist) and
    /// emit a spurious isolated-mode notice.
    pub fn legacy_isolated_root_has_wrapper_segments(&self) -> bool {
        legacy_isolated_has_wrapper_segments(&self.isolated_legacy_wrapper_root())
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
    /// `segment` should be the value of [`crate::LinkTarget::wrapper_segment`]
    /// (or, for callers that don't have a `LinkTarget`, the output
    /// of [`LayoutPaths::wrapper_segment`]).
    pub fn isolated_wrapper_dir(&self, segment: &str) -> PathBuf {
        self.isolated_wrapper_root().join(segment)
    }

    /// Compute the canonical wrapper-segment string for a `(name,
    /// version, wrapper_id)` triple. Mirrors the data-flow inside
    /// [`crate::LinkTarget::wrapper_segment`] for callers that don't
    /// hold a `LinkTarget` (e.g., the `lpm rebuild` loop iterates
    /// `lpm_lockfile::LockedPackage` entries and needs to find the
    /// per-package wrapper without going through the linker's own
    /// data model).
    ///
    /// Shape:
    /// - `wrapper_id == None` (Registry source): `<safe_name>@<version>`.
    /// - `wrapper_id == Some(wid)` (Tarball / Directory / Link / Git):
    ///   `<safe_name>+<wid>`.
    ///
    /// `safe_name` is `name.replace('/', "+")` so scoped names like
    /// `@types/node` produce a valid filesystem segment (`@types+node`).
    ///
    /// **Single source of truth.** [`crate::LinkTarget::wrapper_segment`]
    /// delegates to this function so the linker and the rebuild loop
    /// can never disagree on the segment shape.
    pub fn wrapper_segment(name: &str, version: &str, wrapper_id: Option<&str>) -> String {
        let safe = name.replace('/', "+");
        match wrapper_id {
            Some(wid) => format!("{safe}+{wid}"),
            None => format!("{safe}@{version}"),
        }
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

    // ── Hoisted layout (post-hoisted-symmetry) ───────────────────────

    /// Root directory holding all hoisted-mode incremental state for
    /// this project: the metadata sidecar and the nested-override
    /// fallback tree. Sits as a project-root sibling of
    /// `.lpm/wrappers/`, `.lpm/install-hash`, etc., so each linker
    /// mode owns its own subdirectory cleanly.
    ///
    /// Hoisted owns `<project>/.lpm/hoisted/` and isolated owns
    /// `<project>/.lpm/wrappers/`, with no overlap. (The legacy
    /// hoisted layout under `node_modules/.lpm-metadata.json` +
    /// `node_modules/.lpm/nested/` shared `node_modules/.lpm/` with
    /// the legacy isolated layout, which forced re-link on every
    /// `rm -rf node_modules`.)
    pub fn hoisted_root(&self) -> PathBuf {
        self.project_dir.join(".lpm").join("hoisted")
    }

    /// `<project>/.lpm/hoisted/metadata.json` — incremental state for
    /// hoisted mode. Written by [`crate::link_packages_hoisted`].
    pub fn hoisted_metadata_path(&self) -> PathBuf {
        self.hoisted_root().join("metadata.json")
    }

    /// `<project>/.lpm/hoisted/nested/` — fallback location for
    /// nested override packages whose parent isn't hoisted.
    pub fn hoisted_nested_root(&self) -> PathBuf {
        self.hoisted_root().join("nested")
    }

    /// Layout schema version file for hoisted mode. Mirrors
    /// [`Self::isolated_layout_version_path`] — sibling of the active
    /// state files, never co-located with them, so a future shape
    /// change can detect old hoisted state for clean wipe-and-rebuild.
    pub fn hoisted_layout_version_path(&self) -> PathBuf {
        self.hoisted_root().join(".version")
    }

    /// Legacy hoisted metadata location:
    /// `<project>/node_modules/.lpm-metadata.json`. Used by
    /// [`Self::needs_hoisted_layout_migration`] to detect
    /// upgrade-in-place hoisted users still on the old layout.
    pub fn hoisted_legacy_metadata_path(&self) -> PathBuf {
        self.project_dir
            .join("node_modules")
            .join(".lpm-metadata.json")
    }

    /// Legacy hoisted nested-fallback location:
    /// `<project>/node_modules/.lpm/nested/`. Wiped alongside
    /// [`Self::hoisted_legacy_metadata_path`] during migration.
    pub fn hoisted_legacy_nested_root(&self) -> PathBuf {
        self.project_dir
            .join("node_modules")
            .join(".lpm")
            .join("nested")
    }

    // ── Predicates ───────────────────────────────────────────────────

    /// Layout-aware "is this install fresh?" predicate.
    ///
    /// Wired into the install-state up-to-date checks in
    /// `lpm-cli::install_state` so that upgrade-in-place users (binary
    /// upgraded but `node_modules/` not wiped) correctly trigger the
    /// migration code path instead of short-circuiting on the
    /// install-hash match.
    ///
    /// `||` over two private per-mode predicates so each linker
    /// mode's migration logic stays independently testable while
    /// callers see a single flag.
    pub fn needs_layout_migration(&self) -> bool {
        self.needs_isolated_layout_migration() || self.needs_hoisted_layout_migration()
    }

    /// Pre-61.1 isolated layout detection: legacy
    /// `node_modules/.lpm/<seg>/` populated AND new
    /// `<project>/.lpm/wrappers/` empty.
    ///
    /// "Populated" specifically means at least one wrapper-segment
    /// directory is present at `node_modules/.lpm/`. The `nested/`
    /// sub-namespace (used by pre-symmetry hoisted mode) is
    /// **excluded** from this count — a hoisted-only legacy project
    /// with transitive conflicts left a `node_modules/.lpm/nested/`
    /// dir behind, and that's not isolated state. Without this
    /// exclusion the public union predicate would over-fire and the
    /// migration helper would emit a spurious "migrating wrapper
    /// layout" notice for hoisted-only projects.
    ///
    /// Private to the linker crate — surfaced through
    /// [`Self::needs_layout_migration`] for the install-state
    /// freshness gate. The install-pipeline migration helper inspects
    /// the legacy paths directly (via
    /// [`Self::isolated_legacy_wrapper_root`]) so it can decide on a
    /// per-subtree basis what to wipe and what to log; it never needs
    /// to discriminate between "isolated" and "hoisted" via this
    /// predicate.
    fn needs_isolated_layout_migration(&self) -> bool {
        let legacy_populated =
            legacy_isolated_has_wrapper_segments(&self.isolated_legacy_wrapper_root());
        let new_populated = dir_is_nonempty(&self.isolated_wrapper_root());
        legacy_populated && !new_populated
    }

    /// Pre-symmetry hoisted layout detection: legacy
    /// `node_modules/.lpm-metadata.json` exists AND new
    /// `<project>/.lpm/hoisted/metadata.json` does not.
    ///
    /// Why metadata-file existence rather than `dir_is_nonempty` on
    /// the nested root: the metadata sidecar is the primary marker
    /// of a completed hoisted install; the nested root is only
    /// populated when at least one transitive conflict landed under
    /// a non-hoisted parent. A hoisted install with no nested
    /// conflicts (the common case) never creates the legacy nested
    /// directory at all, so a nested-only predicate would miss every
    /// such project.
    ///
    /// Private to the linker crate — surfaced through
    /// [`Self::needs_layout_migration`]. As with the isolated
    /// counterpart, the install-pipeline migration helper inspects
    /// the legacy paths directly rather than calling this predicate.
    fn needs_hoisted_layout_migration(&self) -> bool {
        let legacy_present = self.hoisted_legacy_metadata_path().exists();
        let new_present = self.hoisted_metadata_path().exists();
        legacy_present && !new_present
    }

    /// Doctor-style health probe. Reads `node_modules/` and the
    /// per-layout markers to decide whether the project looks like
    /// it has a working install.
    ///
    /// Used by `lpm doctor` and reusable wherever a pre-flight check
    /// needs to fail-fast on a clearly-broken install.
    ///
    /// For v2 detection use [`Self::install_appears_healthy_with_v2`]
    /// and pass `Some(v2_links_root)` — this no-arg variant returns
    /// `NodeModulesPresentButNoStore` for any v2 install.
    pub fn install_appears_healthy(&self) -> InstallHealth {
        self.install_appears_healthy_with_v2(None)
    }

    /// Layout-aware variant that recognizes the virtual-store shape.
    /// See [`Self::install_appears_healthy`] for the predicate's
    /// no-v2 contract.
    pub fn install_appears_healthy_with_v2(&self, v2_links_root: Option<&Path>) -> InstallHealth {
        let nm = self.project_dir.join("node_modules");
        if !nm.exists() {
            return InstallHealth::NoNodeModules;
        }

        let isolated_present = dir_is_nonempty(&self.isolated_wrapper_root());
        let hoisted_present = self.hoisted_metadata_path().exists();

        match (isolated_present, hoisted_present) {
            (true, true) => {
                return InstallHealth::Healthy {
                    layout: LinkerLayout::Mixed,
                };
            }
            (true, false) => {
                return InstallHealth::Healthy {
                    layout: LinkerLayout::Isolated,
                };
            }
            (false, true) => {
                return InstallHealth::Healthy {
                    layout: LinkerLayout::Hoisted,
                };
            }
            (false, false) => {}
        }

        // Neither v1 marker is populated. Probe for v2 shape if the
        // caller supplied the virtual-store links root.
        if let Some(links_root) = v2_links_root
            && self.is_v2_install(links_root)
        {
            return InstallHealth::Healthy {
                layout: LinkerLayout::Virtual,
            };
        }

        InstallHealth::NodeModulesPresentButNoStore
    }

    /// Returns `true` iff this project's `node_modules/` contains at
    /// least one entry whose canonicalized path lives under
    /// `v2_links_root`. The probe is intentionally cheap — it stops at
    /// the first match — so a healthy v2 install with hundreds of
    /// deps still resolves in microseconds.
    ///
    /// Skipped: `.bin`, dotfile entries, and entries that fail to
    /// canonicalize (broken symlinks, permission issues). Workspace
    /// member symlinks (e.g. `file:./packages/foo`) canonicalize into
    /// the project tree, NOT under the v2 links root, so they don't
    /// trip this predicate.
    pub fn is_v2_install(&self, v2_links_root: &Path) -> bool {
        let nm = self.project_dir.join("node_modules");
        let Ok(entries) = std::fs::read_dir(&nm) else {
            return false;
        };
        let canonical_links_root = match std::fs::canonicalize(v2_links_root) {
            Ok(c) => c,
            Err(_) => return false,
        };
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            // Skip `.bin/` (always a real dir of shim symlinks pointing
            // at v2 link entries — but the dir ITSELF isn't a v2
            // marker; its contents are ALSO v2 symlinks but pointing
            // at bin scripts, not link-entry roots, so checking
            // `.bin/` would over-fire on the wrong shape) and any
            // dotfile entry (lpm housekeeping).
            if name.starts_with('.') {
                continue;
            }
            let path = entry.path();
            // For scoped packages (`@scope/foo`), the `@scope/` parent
            // is a real directory and its contents are the actual
            // symlinks. Recurse one level for scoped roots.
            if name.starts_with('@') && path.is_dir() {
                let Ok(scoped) = std::fs::read_dir(&path) else {
                    continue;
                };
                for scoped_entry in scoped.flatten() {
                    let scoped_path = scoped_entry.path();
                    if let Ok(canonical) = std::fs::canonicalize(&scoped_path)
                        && canonical.starts_with(&canonical_links_root)
                    {
                        return true;
                    }
                }
                continue;
            }
            if let Ok(canonical) = std::fs::canonicalize(&path)
                && canonical.starts_with(&canonical_links_root)
            {
                return true;
            }
        }
        false
    }
}

/// Returns `true` iff the path exists, is a directory, and contains
/// at least one **non-dotfile** entry. Used by the migration / health
/// predicates to avoid treating a directory whose only contents are
/// schema-tag files (`.version`) or other sibling metadata as
/// evidence of a populated layout.
///
/// The dotfile filter matters because `cleanup_stale_entries` writes
/// `.version` to the wrapper root before any wrapper is materialized.
/// Counting the schema tag would silently mask a needed migration
/// (legacy populated, new root has only `.version`) and report a
/// healthy isolated layout in `lpm doctor` when no wrappers actually
/// exist. Wrapper segment names from [`LayoutPaths::wrapper_segment`]
/// never start with a dot — `.replace('/', '+')` cannot produce a
/// leading dot from any valid package name — so the dotfile filter
/// can never miss a real wrapper.
fn dir_is_nonempty(path: &Path) -> bool {
    let Ok(entries) = std::fs::read_dir(path) else {
        return false;
    };
    entries
        .flatten()
        .any(|entry| !entry.file_name().to_string_lossy().starts_with('.'))
}

/// Returns `true` iff the legacy isolated wrapper root
/// (`node_modules/.lpm/`) contains at least one entry that is plausibly
/// a wrapper segment (`<safe>@<version>` or `<safe>+<wid>`).
fn legacy_isolated_has_wrapper_segments(path: &Path) -> bool {
    let Ok(entries) = std::fs::read_dir(path) else {
        return false;
    };
    entries.flatten().any(|entry| {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        legacy_isolated_entry_name_is_wrapper_segment(&name)
    })
}

fn legacy_isolated_entry_name_is_wrapper_segment(name: &str) -> bool {
    !name.starts_with('.') && (name.contains('@') || name.contains('+'))
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
        // Aliased root link uses the canonical target name for the
        // wrapper-segment lookup but keeps the local link name.
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
    fn hoisted_root_is_project_root_sibling_of_wrappers() {
        let dir = tmp_project();
        let layout = LayoutPaths::for_project(dir.path());
        assert_eq!(
            layout.hoisted_root(),
            dir.path().join(".lpm").join("hoisted")
        );
    }

    #[test]
    fn hoisted_metadata_path_lives_under_new_hoisted_root() {
        let dir = tmp_project();
        let layout = LayoutPaths::for_project(dir.path());
        assert_eq!(
            layout.hoisted_metadata_path(),
            dir.path()
                .join(".lpm")
                .join("hoisted")
                .join("metadata.json")
        );
    }

    #[test]
    fn hoisted_nested_root_lives_under_new_hoisted_root() {
        let dir = tmp_project();
        let layout = LayoutPaths::for_project(dir.path());
        assert_eq!(
            layout.hoisted_nested_root(),
            dir.path().join(".lpm").join("hoisted").join("nested")
        );
    }

    #[test]
    fn hoisted_legacy_metadata_path_lives_under_node_modules() {
        let dir = tmp_project();
        let layout = LayoutPaths::for_project(dir.path());
        assert_eq!(
            layout.hoisted_legacy_metadata_path(),
            dir.path().join("node_modules").join(".lpm-metadata.json")
        );
    }

    #[test]
    fn hoisted_legacy_nested_root_lives_under_node_modules() {
        let dir = tmp_project();
        let layout = LayoutPaths::for_project(dir.path());
        assert_eq!(
            layout.hoisted_legacy_nested_root(),
            dir.path().join("node_modules").join(".lpm").join("nested")
        );
    }

    #[test]
    fn legacy_and_current_hoisted_metadata_diverge() {
        let dir = tmp_project();
        let layout = LayoutPaths::for_project(dir.path());
        assert_ne!(
            layout.hoisted_legacy_metadata_path(),
            layout.hoisted_metadata_path(),
            "post-symmetry: legacy lives under node_modules/, new under .lpm/hoisted/"
        );
    }

    #[test]
    fn hoisted_layout_version_path_lives_under_hoisted_root() {
        let dir = tmp_project();
        let layout = LayoutPaths::for_project(dir.path());
        assert_eq!(
            layout.hoisted_layout_version_path(),
            dir.path().join(".lpm").join("hoisted").join(".version")
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
    fn needs_layout_migration_true_when_new_root_has_only_version_file() {
        // `cleanup_stale_entries` writes `.version` to the new wrapper root
        // BEFORE any wrapper is materialized. A
        // `.version`-only directory is NOT evidence of a populated
        // layout — a half-completed install (interrupted between
        // `.version` write and first wrapper materialization) must
        // still re-trigger the migration on the next install,
        // otherwise the user is silently stuck on the legacy layout
        // with a `.version` orphan in the new root.
        let dir = tmp_project();
        let layout = LayoutPaths::for_project(dir.path());
        // Legacy populated (the upgrade-in-place state).
        fs::create_dir_all(layout.isolated_legacy_wrapper_root().join("express@4.22.1")).unwrap();
        // New root has only the `.version` schema-tag file.
        fs::create_dir_all(layout.isolated_wrapper_root()).unwrap();
        fs::write(layout.isolated_layout_version_path(), b"1\n").unwrap();

        assert!(
            layout.needs_layout_migration(),
            "metadata-only new root must NOT mask migration"
        );
    }

    #[test]
    fn install_appears_healthy_metadata_only_root_is_not_isolated() {
        // Counterpart on the doctor surface: a `.version`-only new
        // root must NOT register as `Healthy { Isolated }` — there
        // are no wrappers materialized, so the install isn't
        // actually healthy and the doctor would otherwise lie.
        let dir = tmp_project();
        fs::create_dir_all(dir.path().join("node_modules")).unwrap();
        let layout = LayoutPaths::for_project(dir.path());
        fs::create_dir_all(layout.isolated_wrapper_root()).unwrap();
        fs::write(layout.isolated_layout_version_path(), b"1\n").unwrap();
        assert_eq!(
            layout.install_appears_healthy(),
            InstallHealth::NodeModulesPresentButNoStore,
            "metadata-only wrapper root must not register as healthy isolated"
        );
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

    // ── Hoisted migration predicate ──────────────────────────────────

    #[test]
    fn needs_hoisted_layout_migration_false_when_no_state_present() {
        let dir = tmp_project();
        let layout = LayoutPaths::for_project(dir.path());
        assert!(!layout.needs_hoisted_layout_migration());
    }

    #[test]
    fn needs_hoisted_layout_migration_true_when_only_legacy_metadata_present() {
        // Upgrade-in-place hoisted user — legacy file at
        // `node_modules/.lpm-metadata.json`, new location empty.
        let dir = tmp_project();
        let nm = dir.path().join("node_modules");
        fs::create_dir_all(&nm).unwrap();
        fs::write(nm.join(".lpm-metadata.json"), b"{}").unwrap();
        let layout = LayoutPaths::for_project(dir.path());
        assert!(layout.needs_hoisted_layout_migration());
    }

    #[test]
    fn needs_hoisted_layout_migration_false_when_only_new_metadata_present() {
        let dir = tmp_project();
        let layout = LayoutPaths::for_project(dir.path());
        fs::create_dir_all(layout.hoisted_root()).unwrap();
        fs::write(layout.hoisted_metadata_path(), b"{}").unwrap();
        assert!(!layout.needs_hoisted_layout_migration());
    }

    #[test]
    fn needs_hoisted_layout_migration_false_when_both_metadata_present() {
        // Mid-migration; install pipeline converges. Predicate
        // returns false so the freshness gate doesn't keep firing
        // on every subsequent install.
        let dir = tmp_project();
        let nm = dir.path().join("node_modules");
        fs::create_dir_all(&nm).unwrap();
        fs::write(nm.join(".lpm-metadata.json"), b"{}").unwrap();
        let layout = LayoutPaths::for_project(dir.path());
        fs::create_dir_all(layout.hoisted_root()).unwrap();
        fs::write(layout.hoisted_metadata_path(), b"{}").unwrap();
        assert!(!layout.needs_hoisted_layout_migration());
    }

    #[test]
    fn needs_hoisted_layout_migration_ignores_orphan_legacy_nested_dir() {
        // A pre-symmetry hoisted install with no transitive conflicts
        // never created `node_modules/.lpm/nested/`. Conversely, an
        // ordinary clean wipe could leave an empty `node_modules/.lpm/`
        // skeleton. Neither is evidence that legacy hoisted state
        // exists — the metadata sidecar is the marker.
        let dir = tmp_project();
        let layout = LayoutPaths::for_project(dir.path());
        fs::create_dir_all(layout.hoisted_legacy_nested_root()).unwrap();
        assert!(!layout.needs_hoisted_layout_migration());
    }

    // ── Public union predicate ───────────────────────────────────────

    // ── legacy_isolated_root_has_wrapper_segments — public predicate ─

    #[test]
    fn legacy_isolated_root_has_wrapper_segments_false_when_root_missing() {
        let dir = tmp_project();
        let layout = LayoutPaths::for_project(dir.path());
        assert!(!layout.legacy_isolated_root_has_wrapper_segments());
    }

    #[test]
    fn legacy_isolated_root_has_wrapper_segments_false_when_only_nested_present() {
        // Hoisted-only legacy project with transitive conflicts —
        // `node_modules/.lpm/nested/<pkg>/` exists but no wrapper
        // segments. The migration helper consumes this predicate to
        // decide whether to print "migrating wrapper layout"; without
        // this case returning false, hoisted-only users see a
        // spurious isolated-mode notice.
        let dir = tmp_project();
        let layout = LayoutPaths::for_project(dir.path());
        fs::create_dir_all(layout.hoisted_legacy_nested_root().join("debug")).unwrap();
        assert!(!layout.legacy_isolated_root_has_wrapper_segments());
    }

    #[test]
    fn legacy_isolated_root_has_wrapper_segments_true_when_wrapper_segment_present() {
        let dir = tmp_project();
        let layout = LayoutPaths::for_project(dir.path());
        fs::create_dir_all(layout.isolated_legacy_wrapper_root().join("express@4.22.1")).unwrap();
        assert!(layout.legacy_isolated_root_has_wrapper_segments());
    }

    #[test]
    fn legacy_isolated_root_has_wrapper_segments_true_when_wrapper_and_nested_coexist() {
        // Real mid-migration mixed: both wrapper segments AND nested
        // conflicts populated. The predicate must fire on the wrapper
        // segments alone, regardless of `nested/`.
        let dir = tmp_project();
        let layout = LayoutPaths::for_project(dir.path());
        fs::create_dir_all(layout.isolated_legacy_wrapper_root().join("express@4.22.1")).unwrap();
        fs::create_dir_all(layout.hoisted_legacy_nested_root().join("debug")).unwrap();
        assert!(layout.legacy_isolated_root_has_wrapper_segments());
    }

    #[test]
    fn needs_layout_migration_ignores_orphan_legacy_nested_dir_for_isolated() {
        // Audit response: a hoisted-only legacy project with at least
        // one transitive conflict leaves `node_modules/.lpm/nested/`
        // behind. Without the wrapper-segment-aware predicate this
        // would silently make the public migration flag fire and the
        // install-pipeline migration helper would print a spurious
        // "migrating wrapper layout" notice for what is in fact
        // hoisted-only legacy state.
        let dir = tmp_project();
        let layout = LayoutPaths::for_project(dir.path());
        // Only `node_modules/.lpm/nested/` populated — no wrapper
        // segments, no legacy hoisted metadata file.
        fs::create_dir_all(layout.hoisted_legacy_nested_root().join("debug")).unwrap();
        assert!(
            !layout.needs_layout_migration(),
            "orphan legacy nested/ must not register as isolated migration"
        );
    }

    #[test]
    fn needs_layout_migration_ignores_v2_compatibility_root() {
        let dir = tmp_project();
        let layout = LayoutPaths::for_project(dir.path());
        fs::create_dir_all(
            layout
                .isolated_legacy_wrapper_root()
                .join("compat")
                .join("eslint@9.39.4+51e8155e339ce359"),
        )
        .unwrap();

        assert!(
            !layout.needs_layout_migration(),
            "v2 compatibility islands under node_modules/.lpm/compat must not register as legacy isolated wrappers"
        );
    }

    #[test]
    fn needs_layout_migration_fires_when_wrapper_segments_coexist_with_nested() {
        // Counter-test: a project that genuinely has BOTH legacy
        // isolated wrapper segments AND legacy hoisted nested state
        // (the most awkward mid-mode-toggle case) still triggers the
        // public flag — the wrapper segment alone is enough.
        let dir = tmp_project();
        let layout = LayoutPaths::for_project(dir.path());
        fs::create_dir_all(layout.isolated_legacy_wrapper_root().join("express@4.22.1")).unwrap();
        fs::create_dir_all(layout.hoisted_legacy_nested_root().join("debug")).unwrap();
        assert!(layout.needs_layout_migration());
    }

    #[test]
    fn needs_layout_migration_unions_both_modes() {
        // Either legacy populated should trigger the public flag —
        // freshness gate doesn't need to know which mode.
        let dir = tmp_project();
        let layout = LayoutPaths::for_project(dir.path());

        // Legacy isolated only.
        fs::create_dir_all(layout.isolated_legacy_wrapper_root().join("express@4.22.1")).unwrap();
        assert!(layout.needs_layout_migration());

        // Reset, then legacy hoisted only.
        fs::remove_dir_all(layout.isolated_legacy_wrapper_root()).unwrap();
        let nm = dir.path().join("node_modules");
        fs::create_dir_all(&nm).unwrap();
        fs::write(nm.join(".lpm-metadata.json"), b"{}").unwrap();
        assert!(layout.needs_layout_migration());
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
        fs::create_dir_all(dir.path().join("node_modules")).unwrap();
        let layout = LayoutPaths::for_project(dir.path());
        // Post-symmetry: hoisted metadata lives at the new
        // `<project>/.lpm/hoisted/metadata.json` location.
        fs::create_dir_all(layout.hoisted_root()).unwrap();
        fs::write(layout.hoisted_metadata_path(), b"{}").unwrap();
        assert_eq!(
            layout.install_appears_healthy(),
            InstallHealth::Healthy {
                layout: LinkerLayout::Hoisted
            }
        );
    }

    #[test]
    fn install_appears_healthy_legacy_hoisted_does_not_register_as_hoisted() {
        // Upgrade-in-place hoisted user: legacy metadata exists,
        // new location empty. The doctor predicate by itself sees no
        // active layout and reports `NodeModulesPresentButNoStore`;
        // the migration warn at the doctor surface fires from
        // `needs_hoisted_layout_migration` upstream and supersedes
        // the health line. Pinning this here protects the contract
        // that the predicate doesn't pretend a not-yet-migrated
        // install is healthy.
        let dir = tmp_project();
        let nm = dir.path().join("node_modules");
        fs::create_dir_all(&nm).unwrap();
        fs::write(nm.join(".lpm-metadata.json"), b"{}").unwrap();
        let layout = LayoutPaths::for_project(dir.path());
        assert_eq!(
            layout.install_appears_healthy(),
            InstallHealth::NodeModulesPresentButNoStore
        );
    }

    #[test]
    fn install_appears_healthy_mixed() {
        let dir = tmp_project();
        fs::create_dir_all(dir.path().join("node_modules")).unwrap();
        let layout = LayoutPaths::for_project(dir.path());
        // True mixed = isolated wrapper root populated AND hoisted
        // metadata at the NEW location populated. Pre-symmetry the
        // hoisted half of this assertion lived at the legacy
        // `node_modules/.lpm-metadata.json`; post-symmetry both halves
        // are sub-namespaces of `<project>/.lpm/`.
        fs::create_dir_all(layout.isolated_wrapper_root().join("express@4.22.1")).unwrap();
        fs::create_dir_all(layout.hoisted_root()).unwrap();
        fs::write(layout.hoisted_metadata_path(), b"{}").unwrap();
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

    /// Virtual-store layout detection. A project whose
    /// `node_modules/<dep>` symlinks resolve into the v2 links root
    /// must register as `Healthy { Virtual }`, not the
    /// `NodeModulesPresentButNoStore` fall-through.
    #[cfg(unix)]
    #[test]
    fn install_appears_healthy_virtual_store() {
        let dir = tmp_project();
        let nm = dir.path().join("node_modules");
        fs::create_dir_all(&nm).unwrap();

        // Synthesize a fake v2 links root with one populated link entry.
        // The shape doesn't have to be a real LPM-shaped store — only the
        // canonical-path-prefix relationship matters for detection.
        let v2_root = dir.path().join("fake-lpm-home").join("store").join("v2");
        let links_root = v2_root.join("links");
        let link_entry = links_root.join("react@18.0.0+abc123/node_modules/react");
        fs::create_dir_all(&link_entry).unwrap();
        fs::write(link_entry.join("package.json"), b"{}").unwrap();

        // Wire the project-side symlink. On Unix we use `symlink`;
        // Windows would need `symlink_dir` but this test is gated on
        // Unix below.
        #[cfg(unix)]
        std::os::unix::fs::symlink(&link_entry, nm.join("react")).unwrap();

        let layout = LayoutPaths::for_project(dir.path());

        // Sanity: legacy-only probe must still report no-store, since
        // neither v1 marker is populated.
        #[cfg(unix)]
        {
            assert_eq!(
                layout.install_appears_healthy(),
                InstallHealth::NodeModulesPresentButNoStore,
                "legacy probe must NOT report a virtual install as healthy"
            );

            // v2-aware probe must recognize the layout.
            assert_eq!(
                layout.install_appears_healthy_with_v2(Some(&links_root)),
                InstallHealth::Healthy {
                    layout: LinkerLayout::Virtual
                }
            );

            assert!(layout.is_v2_install(&links_root));
        }
    }

    /// Workspace-member symlinks (`file:./packages/foo`) point into the
    /// project tree, NOT into the v2 links root. The v2 detection MUST
    /// not over-fire on a non-v2 install with workspace members.
    #[test]
    #[cfg(unix)]
    fn is_v2_install_does_not_fire_on_workspace_member_symlinks() {
        let dir = tmp_project();
        let nm = dir.path().join("node_modules");
        fs::create_dir_all(&nm).unwrap();

        let workspace_member = dir.path().join("packages").join("foo");
        fs::create_dir_all(&workspace_member).unwrap();
        fs::write(workspace_member.join("package.json"), b"{}").unwrap();
        std::os::unix::fs::symlink(&workspace_member, nm.join("foo")).unwrap();

        // Synthesize an unrelated v2 links root somewhere else.
        let v2_root = dir.path().join("fake-lpm-home").join("store").join("v2");
        let links_root = v2_root.join("links");
        fs::create_dir_all(&links_root).unwrap();

        let layout = LayoutPaths::for_project(dir.path());
        assert!(
            !layout.is_v2_install(&links_root),
            "workspace-member symlinks resolve inside the project tree, not the v2 links root"
        );
    }

    /// Scoped-package directory under v2 — `<project>/node_modules/@scope/`
    /// is a real directory, with its scoped entries as the actual
    /// symlinks into the v2 store. Detection must recurse one level.
    #[test]
    #[cfg(unix)]
    fn is_v2_install_recurses_scoped_package_directory() {
        let dir = tmp_project();
        let nm = dir.path().join("node_modules");
        fs::create_dir_all(nm.join("@scope")).unwrap();

        let v2_root = dir.path().join("fake-lpm-home").join("store").join("v2");
        let links_root = v2_root.join("links");
        let link_entry = links_root.join("@scope+pkg@1.0.0+abc123/node_modules/@scope/pkg");
        fs::create_dir_all(&link_entry).unwrap();
        fs::write(link_entry.join("package.json"), b"{}").unwrap();
        std::os::unix::fs::symlink(&link_entry, nm.join("@scope").join("pkg")).unwrap();

        let layout = LayoutPaths::for_project(dir.path());
        assert!(
            layout.is_v2_install(&links_root),
            "scoped-package symlinks are nested one level under node_modules/@scope/"
        );
    }
}
