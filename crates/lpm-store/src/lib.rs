//! Content-addressable package stores for LPM.
//!
//! The default v2 store separates immutable package objects from reusable
//! dependency-graph link entries. The v1 store and its `(name, version)`
//! package directories remain available only for the explicit
//! `LPM_STORE_VERSION=v1` rollback and for upgrade/maintenance readers.
//!
//! ```text
//! ~/.lpm/store/
//! ├── v2/                         # default writer
//! │   ├── objects/<sri>/          # content-addressable extracted bytes
//! │   ├── links/<graph-key>/      # reusable dependency graph entries
//! │   ├── compat/                 # cached compatibility islands
//! │   └── builds/                 # lifecycle build artifacts
//! └── v1/                         # rollback and migration compatibility
//!     └── <package>@<version>/    # legacy extracted package directory
//! ```
//!
//! [`StoreVersion`] owns the CLI selection contract: v2 is the default and
//! only `v1` or `1` explicitly selects the legacy writer. Compatibility
//! readers can still inspect v1 data while direct upgrades from v1-writing
//! releases remain supported.

mod baseline;
mod cas;
mod extraction;
mod gc;
mod integrity;
mod layout;
mod store;
mod timings;
mod version;

// Virtual-store v2 layout primitives. See `src/v2/mod.rs` for the
// on-disk shape and identity model.
pub mod v2;

pub use baseline::{
    InstalledPackageBaseline, PackageBaselineLayout, V2BaselineIndex,
    find_installed_package_baseline, find_installed_package_baseline_by_identity_indexed,
    find_installed_package_baseline_indexed,
};
pub use gc::{GcPreview, GcResult};
pub use integrity::{
    compute_sri_hash, compute_sri_hash_sha1, compute_sri_hash_sha256, read_stored_integrity,
};
pub use store::PackageStore;
pub use timings::StageTimings;
pub use version::StoreVersion;

pub(crate) use layout::is_complete_package_dir;
pub(crate) use version::STORE_VERSION;

#[cfg(test)]
mod test_support;
