//! `node_modules` layout manager for LPM.
//!
//! The default store-v2 linker creates project root symlinks into reusable
//! graph entries under `~/.lpm/store/v2/links/<graph-key>/`. Both
//! [`LinkerMode::Hoisted`] (the default) and [`LinkerMode::Isolated`] use
//! those shared entries while applying their own root-link semantics.
//!
//! ```text
//! <project>/node_modules/<dep>
//!   -> ~/.lpm/store/v2/links/<graph-key>/node_modules/<dep>
//! ```
//!
//! The [`link_packages`] and [`link_packages_hoisted`] exports are the v1
//! implementations retained for `LPM_STORE_VERSION=v1` rollback. They
//! materialize project-local state under `.lpm/wrappers/` or `.lpm/hoisted/`
//! and must remain paired with the v1 store writer for the rollback lifetime.
//! The v2 linker also recognizes and removes that project-local state during
//! migration; those compatibility readers outlive the rollback writer.

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
