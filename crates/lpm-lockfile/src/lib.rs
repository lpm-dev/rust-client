//! Lockfile read/write for LPM: `lpm.lock`, a human-readable TOML file.
//!
//! Design principles (from research doc Section 8):
//! - Sorted entries for deterministic diffs
//! - One entry per package for minimal merge conflicts
//! - Includes integrity hashes for verification
//! - Schema-versioned (`lockfile-version`), not tool-versioned

mod error;
mod io;
mod model;
mod parse_cache;
pub mod source;

pub use error::LockfileError;
pub use io::{ProjectLockfile, remove_obsolete_binary_lockfile};
pub use model::{
    CatalogSnapshotEntry, CatalogSnapshots, DEFAULT_RESOLVED_WITH, ImporterSnapshot,
    ImporterSnapshots, LOCKFILE_NAME, LOCKFILE_VERSION, LOCKFILE_VERSION_WITH_DEPENDENCY_ENGINES,
    LOCKFILE_VERSION_WITH_GIT_RESOLUTIONS, LOCKFILE_VERSION_WITH_LOCAL_MANIFEST_FINGERPRINTS,
    LOCKFILE_VERSION_WITH_PACKAGE_INSTANCES, LOCKFILE_VERSION_WITH_PROVENANCE,
    LOCKFILE_VERSION_WITH_ROOT_RESOLUTIONS, LOCKFILE_VERSION_WITH_STRUCTURED_PEERS,
    LOCKFILE_VERSION_WITH_WORKSPACE_PROJECTIONS, LockedPackage, LockedProvenance,
    LockedRegistrySignature, LockedRootResolution, Lockfile, LockfileMetadata, LockfilePatch,
    LockfilePatches, PackageKey, RootResolutions, ValidatedLockfile, is_safe_source,
};
pub use parse_cache::{ParseCacheStats, parse_cache_stats};
pub use source::{Source, SourceParseError, safe_source_identity};

/// The binary lockfile earlier LPM CLI versions wrote beside `lpm.lock`.
/// Nothing reads it. Lockfile writes remove it, and commands that publish,
/// copy or snapshot a project leave it out.
pub const OBSOLETE_BINARY_LOCKFILE_NAME: &str = "lpm.lockb";

/// Maximum accepted size of the authoritative human-readable lockfile.
pub const TOML_LOCKFILE_SIZE_CAP_BYTES: u64 = 64 * 1024 * 1024;

#[cfg(test)]
mod tests;
