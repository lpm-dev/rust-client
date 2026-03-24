//! Lockfile read/write for LPM.
//!
//! Two formats:
//! - `lpm.lock` (TOML) — human-readable, git-diffable, always written
//! - `lpm.lockb` (binary) — mmap'd for zero-parse reads (~0.1ms vs ~10ms TOML)
//!
//! The binary lockfile is written alongside TOML on every resolution.
//! On read, the binary file is preferred when it exists and is newer than TOML.
//!
//! Design principles (from research doc Section 8):
//! - Sorted entries for deterministic diffs
//! - One entry per package for minimal merge conflicts
//! - Includes integrity hashes for verification
//! - Schema-versioned (`lockfile-version`), not tool-versioned

pub mod binary;

use serde::{Deserialize, Serialize};
use std::path::Path;

pub use binary::{BinaryLockfileReader, BINARY_LOCKFILE_NAME};

/// Current lockfile schema version.
pub const LOCKFILE_VERSION: u32 = 1;

/// Default lockfile filename.
pub const LOCKFILE_NAME: &str = "lpm.lock";

/// The full lockfile structure.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Lockfile {
    pub metadata: LockfileMetadata,
    /// Resolved packages, sorted by name for deterministic output.
    #[serde(default)]
    pub packages: Vec<LockedPackage>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LockfileMetadata {
    #[serde(rename = "lockfile-version")]
    pub lockfile_version: u32,
    /// Which resolver produced this lockfile.
    #[serde(default, rename = "resolved-with")]
    pub resolved_with: Option<String>,
}

/// A single resolved package in the lockfile.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LockedPackage {
    /// Package name (e.g., `@lpm.dev/neo.highlight` or `react`).
    pub name: String,
    /// Exact resolved version.
    pub version: String,
    /// Source registry (e.g., `registry+https://lpm.dev` or `registry+https://registry.npmjs.org`).
    #[serde(default)]
    pub source: Option<String>,
    /// SRI integrity hash (sha512-...). Populated when registry provides it.
    #[serde(default)]
    pub integrity: Option<String>,
    /// Direct dependencies of this package: name → exact version.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dependencies: Vec<String>,
}

impl Lockfile {
    /// Create a new empty lockfile.
    pub fn new() -> Self {
        Lockfile {
            metadata: LockfileMetadata {
                lockfile_version: LOCKFILE_VERSION,
                resolved_with: Some("pubgrub".to_string()),
            },
            packages: Vec::new(),
        }
    }

    /// Add a resolved package. Maintains sorted order by name.
    pub fn add_package(&mut self, pkg: LockedPackage) {
        // Insert in sorted position
        let pos = self
            .packages
            .binary_search_by(|p| p.name.cmp(&pkg.name))
            .unwrap_or_else(|pos| pos);
        self.packages.insert(pos, pkg);
    }

    /// Serialize to TOML string.
    pub fn to_toml(&self) -> Result<String, LockfileError> {
        toml::to_string_pretty(self).map_err(|e| LockfileError::Serialize(e.to_string()))
    }

    /// Deserialize from TOML string.
    pub fn from_toml(input: &str) -> Result<Self, LockfileError> {
        let lockfile: Lockfile =
            toml::from_str(input).map_err(|e| LockfileError::Deserialize(e.to_string()))?;

        if lockfile.metadata.lockfile_version > LOCKFILE_VERSION {
            return Err(LockfileError::UnsupportedVersion {
                found: lockfile.metadata.lockfile_version,
                max_supported: LOCKFILE_VERSION,
            });
        }

        Ok(lockfile)
    }

    /// Write lockfile to disk atomically (write to .tmp, then rename).
    pub fn write_to_file(&self, path: &Path) -> Result<(), LockfileError> {
        let content = self.to_toml()?;
        let tmp_path = path.with_extension("lock.tmp");

        std::fs::write(&tmp_path, &content)
            .map_err(|e| LockfileError::Io(format!("failed to write {}: {e}", tmp_path.display())))?;

        std::fs::rename(&tmp_path, path)
            .map_err(|e| LockfileError::Io(format!("failed to rename to {}: {e}", path.display())))?;

        Ok(())
    }

    /// Read lockfile from disk.
    pub fn read_from_file(path: &Path) -> Result<Self, LockfileError> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| LockfileError::Io(format!("failed to read {}: {e}", path.display())))?;
        Self::from_toml(&content)
    }

    /// Write both TOML and binary lockfiles atomically.
    /// The binary file is written alongside the TOML file as `lpm.lockb`.
    pub fn write_all(&self, toml_path: &Path) -> Result<(), LockfileError> {
        self.write_to_file(toml_path)?;
        let binary_path = toml_path.with_extension("lockb");
        binary::write_binary(self, &binary_path)?;
        Ok(())
    }

    /// Fast read: prefer binary lockfile (mmap) if it exists and is at least
    /// as new as the TOML file. Falls back to TOML parsing.
    pub fn read_fast(toml_path: &Path) -> Result<Self, LockfileError> {
        let binary_path = toml_path.with_extension("lockb");
        if binary_path.exists() {
            // Check if binary is at least as new as TOML
            let use_binary = match (toml_path.metadata(), binary_path.metadata()) {
                (Ok(toml_meta), Ok(bin_meta)) => {
                    match (toml_meta.modified(), bin_meta.modified()) {
                        (Ok(toml_time), Ok(bin_time)) => bin_time >= toml_time,
                        _ => true, // If we can't check times, prefer binary
                    }
                }
                _ => true,
            };

            if use_binary {
                if let Ok(Some(reader)) = BinaryLockfileReader::open(&binary_path) {
                    return Ok(reader.to_lockfile());
                }
            }
        }

        Self::read_from_file(toml_path)
    }

    /// Check if a lockfile exists at the given path.
    pub fn exists(path: &Path) -> bool {
        path.exists()
    }

    /// Look up a locked package by name.
    pub fn find_package(&self, name: &str) -> Option<&LockedPackage> {
        self.packages
            .binary_search_by(|p| p.name.as_str().cmp(name))
            .ok()
            .map(|idx| &self.packages[idx])
    }
}

impl Default for Lockfile {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum LockfileError {
    #[error("failed to serialize lockfile: {0}")]
    Serialize(String),

    #[error("failed to parse lockfile: {0}")]
    Deserialize(String),

    #[error("unsupported lockfile version {found} (max supported: {max_supported})")]
    UnsupportedVersion { found: u32, max_supported: u32 },

    #[error("IO error: {0}")]
    Io(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_lockfile() -> Lockfile {
        let mut lf = Lockfile::new();
        lf.add_package(LockedPackage {
            name: "@lpm.dev/neo.highlight".to_string(),
            version: "1.1.1".to_string(),
            source: Some("registry+https://lpm.dev".to_string()),
            integrity: Some("sha512-abc123...".to_string()),
            dependencies: vec!["react@999.999.999".to_string()],
        });
        lf.add_package(LockedPackage {
            name: "react".to_string(),
            version: "999.999.999".to_string(),
            source: Some("registry+https://registry.npmjs.org".to_string()),
            integrity: None,
            dependencies: vec![],
        });
        lf
    }

    #[test]
    fn serialize_roundtrip() {
        let lf = sample_lockfile();
        let toml_str = lf.to_toml().unwrap();
        let parsed = Lockfile::from_toml(&toml_str).unwrap();
        assert_eq!(lf, parsed);
    }

    #[test]
    fn toml_output_is_readable() {
        let lf = sample_lockfile();
        let toml_str = lf.to_toml().unwrap();

        assert!(toml_str.contains("[metadata]"));
        assert!(toml_str.contains("lockfile-version = 1"));
        assert!(toml_str.contains("[[packages]]"));
        assert!(toml_str.contains("@lpm.dev/neo.highlight"));
        assert!(toml_str.contains("react"));
    }

    #[test]
    fn packages_sorted_by_name() {
        let mut lf = Lockfile::new();
        lf.add_package(LockedPackage {
            name: "zlib".to_string(),
            version: "1.0.0".to_string(),
            source: None,
            integrity: None,
            dependencies: vec![],
        });
        lf.add_package(LockedPackage {
            name: "alpha".to_string(),
            version: "2.0.0".to_string(),
            source: None,
            integrity: None,
            dependencies: vec![],
        });

        assert_eq!(lf.packages[0].name, "alpha");
        assert_eq!(lf.packages[1].name, "zlib");
    }

    #[test]
    fn find_package_by_name() {
        let lf = sample_lockfile();
        let pkg = lf.find_package("react").unwrap();
        assert_eq!(pkg.version, "999.999.999");
        assert!(lf.find_package("nonexistent").is_none());
    }

    #[test]
    fn reject_future_lockfile_version() {
        let toml_str = r#"
[metadata]
lockfile-version = 999

[[packages]]
name = "foo"
version = "1.0.0"
"#;
        let result = Lockfile::from_toml(toml_str);
        assert!(result.is_err());
    }

    #[test]
    fn write_and_read_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("lpm.lock");

        let lf = sample_lockfile();
        lf.write_to_file(&path).unwrap();

        assert!(path.exists());

        let read_back = Lockfile::read_from_file(&path).unwrap();
        assert_eq!(lf, read_back);
    }

    #[test]
    fn atomic_write_no_partial_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("lpm.lock");
        let tmp_path = path.with_extension("lock.tmp");

        let lf = sample_lockfile();
        lf.write_to_file(&path).unwrap();

        // tmp file should be gone after successful write
        assert!(!tmp_path.exists());
        assert!(path.exists());
    }

    #[test]
    fn empty_deps_not_serialized() {
        let mut lf = Lockfile::new();
        lf.add_package(LockedPackage {
            name: "foo".to_string(),
            version: "1.0.0".to_string(),
            source: None,
            integrity: None,
            dependencies: vec![],
        });
        let toml_str = lf.to_toml().unwrap();
        // "dependencies" key should not appear when empty
        assert!(!toml_str.contains("dependencies"));
    }
}
