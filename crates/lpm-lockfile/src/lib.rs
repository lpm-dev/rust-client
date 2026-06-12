//! Lockfile read/write for LPM.
//!
//! Two formats:
//! - `lpm.lock` (TOML) — human-readable, git-diffable, always written
//! - `lpm.lockb` (binary) — generated companion for doctor validation/writeback
//!
//! The binary lockfile is written alongside TOML on every resolution.
//! On read, commands use the reviewer-visible TOML as the authoritative input.
//!
//! Design principles (from research doc Section 8):
//! - Sorted entries for deterministic diffs
//! - One entry per package for minimal merge conflicts
//! - Includes integrity hashes for verification
//! - Schema-versioned (`lockfile-version`), not tool-versioned

pub mod binary;
mod error;
mod io;
mod model;
pub mod source;

pub use binary::{BINARY_LOCKFILE_NAME, BinaryLockfileReader};
pub use error::LockfileError;
pub use io::ensure_gitattributes;
pub use model::{
    CatalogSnapshotEntry, CatalogSnapshots, DEFAULT_RESOLVED_WITH, ImporterSnapshot,
    ImporterSnapshots, LOCKFILE_NAME, LOCKFILE_VERSION, LockedPackage, LockedRegistrySignature,
    Lockfile, LockfileMetadata, LockfilePatch, LockfilePatches, PackageKey, is_safe_source,
};
pub use source::{Source, SourceParseError};

#[cfg(test)]
mod tests;
