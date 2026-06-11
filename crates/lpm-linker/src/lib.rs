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

#[cfg(test)]
mod tests;
