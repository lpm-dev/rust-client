//! Content-addressable package stores for LPM.
//!
//! The default v2 store prioritizes install latency. The experimental v3 store
//! deduplicates package files by content plus normalized mode while writable
//! installed trees retain independent inodes. The v1 store remains available
//! as the downgrade path.
//!
//! ```text
//! ~/.lpm/store/
//! ├── v3/                         # explicit experimental file-CAS writer
//! │   ├── blobs/<shard>/<digest>  # immutable content-and-mode blobs
//! │   ├── trees/<shard>/<digest>  # deterministic package-tree manifests
//! │   ├── sources/<shard>/<id>    # source-integrity → tree records
//! │   ├── objects/<source>/       # compatibility projections over CAS blobs
//! │   ├── materialized/<tree>/    # reusable whole-tree clone/copy sources
//! │   └── links/<graph-key>/      # writable dependency graph entries
//! ├── v2/                         # default virtual-store writer
//! └── v1/                         # downgrade and migration compatibility
//!     └── <package>@<version>/    # legacy extracted package directory
//! ```
//!
//! The v3 `objects/` projections deliberately remain as compatibility caches
//! for readers shared with v2. Their package files hardlink to CAS blobs, so
//! they retain directory entries and sidecars without duplicating content
//! blocks. [`StoreVersion`] owns the selection contract: v2 is the default;
//! v3 and v1 are explicit modes.

mod baseline;
mod cas;
mod extraction;
mod gc;
mod integrity;
mod layout;
mod security_analysis;
mod store;
mod timings;
mod version;

// Shared virtual-store layout primitives. See `src/v2/mod.rs` for the
// compatibility surface and identity model.
pub mod v2;
pub mod v3;

pub use baseline::{
    InstalledPackageBaseline, PackageBaselineLayout, V2BaselineIndex,
    find_installed_package_baseline, find_installed_package_baseline_by_identity_indexed,
    find_installed_package_baseline_indexed,
};
pub use gc::{GcPreview, GcResult};
pub use integrity::{
    compute_sri_hash, compute_sri_hash_sha1, compute_sri_hash_sha256, read_stored_integrity,
};
pub use security_analysis::SecurityAnalysisPolicy;
pub use store::PackageStore;
pub use timings::StageTimings;
pub use version::StoreVersion;

pub(crate) use layout::is_complete_package_dir;
pub(crate) use version::STORE_VERSION;

#[cfg(test)]
mod test_support;
