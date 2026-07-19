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

pub mod layout;
mod materialize;
mod platform;
mod types;
mod v1_hoisted;
mod v1_isolated;
pub mod v2;
mod validation;

pub use layout::{InstallHealth, LayoutPaths, LinkerLayout};
pub use platform::detach_package_hardlinks;
pub use types::{
    FinalizeResult, LinkDependency, LinkResult, LinkTarget, LinkerMode, Materialization,
    MaterializedPackage, OnePackageResult,
};
pub use v1_hoisted::link_packages_hoisted;
pub use v1_isolated::{
    cleanup_stale_entries, create_bin_links, link_finalize, link_one_package, link_packages,
    link_workspace_member,
};
pub use validation::validate_bin_name;

/// Reconcile project-local linker state against an empty dependency graph.
pub fn reconcile_empty_install(
    project_dir: &std::path::Path,
    use_v2_store: bool,
    linker_mode: LinkerMode,
) -> Result<(), lpm_common::LpmError> {
    if use_v2_store {
        return v2::reconcile_empty_project(project_dir);
    }

    match linker_mode {
        LinkerMode::Isolated => {
            link_packages(project_dir, &[], false, None)?;
        }
        LinkerMode::Hoisted => {
            v1_hoisted::reconcile_empty_hoisted_root(project_dir)?;
            link_packages_hoisted(project_dir, &[], false, None)?;
        }
    }
    remove_project_bin_dir(project_dir)
}

fn remove_project_bin_dir(project_dir: &std::path::Path) -> Result<(), lpm_common::LpmError> {
    let bin_dir = project_dir.join("node_modules").join(".bin");
    let metadata = match bin_dir.symlink_metadata() {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(lpm_common::LpmError::Io(error)),
    };
    if metadata.file_type().is_dir() && !metadata.file_type().is_symlink() {
        std::fs::remove_dir_all(bin_dir).map_err(lpm_common::LpmError::Io)
    } else {
        std::fs::remove_file(bin_dir).map_err(lpm_common::LpmError::Io)
    }
}

#[cfg(test)]
mod tests;
