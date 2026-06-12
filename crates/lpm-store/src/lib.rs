//! Content-addressable package store for LPM.
//!
//! Global store at `~/.lpm/store/` holds extracted packages keyed by
//! `name@version` hash. Projects link into this store via hardlinks or
//! copy-on-write (reflink on APFS/Btrfs).
//!
//! Layout:
//! ```text
//! ~/.lpm/store/
//!   v1/                          ← store version (for future migrations)
//!     react@19.2.4/              ← extracted package directory
//!       package.json
//!       index.js
//!       ...
//!     express@4.22.1/
//!       ...
//! ```
//!
//! Performance: package-level dedup (skip extraction on store hit), clonefile/reflink on macOS.
//! Maintenance: GC with age filtering, integrity verification (SRI hashes).

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
    find_installed_package_baseline, find_installed_package_baseline_indexed,
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
