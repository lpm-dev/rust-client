//! Lockfile migration from npm/yarn/pnpm/bun to LPM.
//!
//! Parses foreign lockfiles into a common intermediate (`MigratedPackage`),
//! then converts to `lpm_lockfile::Lockfile` for writing.
//!
//! The converted lockfile is used by `lpm install`'s lockfile fast path
//! (skips PubGrub resolution entirely, goes straight to download + link).

pub mod detect;
pub mod normalize;
pub mod validate;
pub mod npm;
pub mod yarn;
pub mod pnpm;
pub mod bun;
pub mod ci;
pub mod backup;

use lpm_common::LpmError;
use std::path::Path;

/// Maximum number of packages allowed in a lockfile.
/// Protects against malicious/corrupt lockfiles causing unbounded memory usage.
const MAX_PACKAGES: usize = 200_000;

/// Common intermediate for all foreign lockfile formats.
/// Every parser normalizes its format into this structure.
#[derive(Debug, Clone, PartialEq)]
pub struct MigratedPackage {
    /// Package name (e.g., "express", "@scope/name").
    pub name: String,
    /// Exact resolved version.
    pub version: String,
    /// Tarball download URL (if available).
    pub resolved: Option<String>,
    /// SRI integrity hash (e.g., "sha512-...").
    pub integrity: Option<String>,
    /// Direct dependencies: (name, exact_version).
    pub dependencies: Vec<(String, String)>,
    /// Whether this is an optional dependency.
    pub is_optional: bool,
    /// Whether this is a dev dependency.
    pub is_dev: bool,
}

/// Detected source package manager.
#[derive(Debug, Clone, PartialEq)]
pub struct DetectedSource {
    /// Which package manager.
    pub kind: SourceKind,
    /// Path to the lockfile.
    pub path: std::path::PathBuf,
    /// Lockfile format version (e.g., 2, 3 for npm; 1 for yarn v1).
    pub version: u32,
}

/// Package manager type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceKind {
    Npm,
    Yarn,
    Pnpm,
    Bun,
}

impl std::fmt::Display for SourceKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SourceKind::Npm => write!(f, "npm"),
            SourceKind::Yarn => write!(f, "yarn"),
            SourceKind::Pnpm => write!(f, "pnpm"),
            SourceKind::Bun => write!(f, "bun"),
        }
    }
}

/// Result of a migration.
#[derive(Debug)]
pub struct MigrateResult {
    /// The converted lockfile.
    pub lockfile: lpm_lockfile::Lockfile,
    /// Detected source.
    pub source: DetectedSource,
    /// Total packages migrated.
    pub package_count: usize,
    /// Packages with integrity hashes preserved.
    pub integrity_count: usize,
    /// Warnings generated during migration.
    pub warnings: Vec<String>,
    /// Packages skipped (workspace links, git deps, etc.).
    pub skipped: Vec<SkippedPackage>,
}

/// A package that was skipped during migration.
#[derive(Debug, Clone)]
pub struct SkippedPackage {
    pub name: String,
    pub reason: String,
}

/// Run the full migration pipeline: detect → parse → normalize → validate.
///
/// Does NOT write files — caller decides what to do with the result.
pub fn migrate(project_dir: &Path) -> Result<MigrateResult, LpmError> {
    // Detect source
    let source = detect::detect_source(project_dir)?;

    // Parse foreign lockfile into common intermediate
    let packages = match source.kind {
        SourceKind::Npm => npm::parse(&source.path, source.version)?,
        SourceKind::Yarn => yarn::parse(&source.path)?,
        SourceKind::Pnpm => pnpm::parse(&source.path, source.version)?,
        SourceKind::Bun => bun::parse(&source.path)?,
    };

    // Guard against corrupt/malicious lockfiles with excessive entries
    if packages.len() > MAX_PACKAGES {
        return Err(LpmError::Script(format!(
            "lockfile contains {} packages (max: {}). This may indicate a corrupt lockfile.",
            packages.len(),
            MAX_PACKAGES
        )));
    }

    // Normalize to LPM lockfile
    let (lockfile, skipped) = normalize::to_lockfile(packages);

    // Validate
    let warnings = validate::validate(&lockfile, project_dir);

    let integrity_count = lockfile.packages.iter()
        .filter(|p| p.integrity.is_some())
        .count();

    Ok(MigrateResult {
        package_count: lockfile.packages.len(),
        integrity_count,
        lockfile,
        source,
        warnings,
        skipped,
    })
}
