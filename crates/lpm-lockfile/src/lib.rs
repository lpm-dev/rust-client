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

pub use binary::{BINARY_LOCKFILE_NAME, BinaryLockfileReader};

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
    /// **Phase 40 P2** — root-level npm-alias edges preserved so warm
    /// installs can match the original `node_modules/<local>/` layout
    /// without re-resolving. Shape: `local_name → target_canonical_name`.
    /// Empty when no root dep uses `npm:<target>@<range>` syntax;
    /// skipped in serialized output when empty (backwards-compatible
    /// with pre-P2 lockfiles).
    #[serde(
        default,
        rename = "root-aliases",
        skip_serializing_if = "std::collections::BTreeMap::is_empty"
    )]
    pub root_aliases: std::collections::BTreeMap<String, String>,
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
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
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
    /// Direct dependencies of this package: `<local_name>@<version>`
    /// where `local_name` is what this package uses in its own
    /// `dependencies` map. For non-aliased deps the local name equals
    /// the dep's canonical registry name; for Phase 40 P2 npm-alias
    /// edges the local name diverges from the target and the target
    /// is recorded in [`Self::alias_dependencies`] below.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dependencies: Vec<String>,
    /// **Phase 40 P2** — npm-alias dep edges. Each entry is
    /// `[local_name, target_canonical_name]`. The matching
    /// `<local_name>@<version>` entry in `dependencies` keys the
    /// resolved version; this map keys the alias TARGET for lookup
    /// of the `.lpm/<target>@<version>/` store path. Empty and
    /// skipped from serialization for the common non-aliased case —
    /// keeps lockfiles of pre-P2 projects byte-identical.
    #[serde(
        default,
        rename = "alias-dependencies",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub alias_dependencies: Vec<[String; 2]>,
    /// **Phase 43** — tarball URL as returned by the registry at
    /// resolve time (e.g.,
    /// `https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz`).
    /// Populated by the writer from `InstallPackage.tarball_url`;
    /// consumed by `try_lockfile_fast_path` to skip the per-package
    /// metadata round-trip on warm installs (gated behind
    /// `evaluate_cached_url` for scheme/shape/origin safety).
    /// `None` on old lockfiles written before Phase 43 — callers
    /// fall back to on-demand lookup.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tarball: Option<String>,
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
            root_aliases: std::collections::BTreeMap::new(),
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

        std::fs::write(&tmp_path, &content).map_err(|e| {
            LockfileError::Io(format!("failed to write {}: {e}", tmp_path.display()))
        })?;

        if let Err(e) = std::fs::rename(&tmp_path, path) {
            let _ = std::fs::remove_file(&tmp_path);
            return Err(LockfileError::Io(format!(
                "failed to rename to {}: {e}",
                path.display()
            )));
        }

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
    ///
    /// Phase 40 P2 — the v1 binary format has no section for
    /// npm-alias metadata, so we gate the binary write on
    /// [`binary::binary_format_supports`]. When the lockfile declares
    /// any alias (root or transitive), the binary file is skipped —
    /// and any stale binary file from a prior non-aliased install is
    /// removed so `read_fast` doesn't silently pick it over the
    /// authoritative TOML. A v2 binary format with an alias section
    /// would remove the skip; until then, aliased projects take the
    /// ~10ms TOML parse cost on warm install.
    pub fn write_all(&self, toml_path: &Path) -> Result<(), LockfileError> {
        self.write_to_file(toml_path)?;
        let binary_path = toml_path.with_extension("lockb");
        if binary::binary_format_supports(self) {
            binary::write_binary(self, &binary_path)?;
        } else if binary_path.exists() {
            let _ = std::fs::remove_file(&binary_path);
            tracing::debug!(
                "Phase 40 P2: removed stale binary lockfile ({}); project has npm-alias metadata not expressible in v1 binary format",
                binary_path.display()
            );
        }
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

            if use_binary && let Ok(Some(reader)) = BinaryLockfileReader::open(&binary_path) {
                return Ok(reader.to_lockfile());
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

/// Ensure `.gitattributes` marks `lpm.lockb` as binary.
///
/// Creates the file if missing, appends the entry if not already present.
/// This prevents CRLF corruption on Windows and marks the file as binary for git diff.
pub fn ensure_gitattributes(project_dir: &Path) -> Result<(), LockfileError> {
    let gitattributes = project_dir.join(".gitattributes");
    let marker = "lpm.lockb binary";

    if gitattributes.exists() {
        let content = std::fs::read_to_string(&gitattributes)
            .map_err(|e| LockfileError::Io(format!("failed to read .gitattributes: {e}")))?;

        // Already has the entry
        if content.lines().any(|line| line.trim() == marker) {
            return Ok(());
        }

        // Append atomically using OpenOptions::append (no file replacement on crash)
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&gitattributes)
            .map_err(|e| LockfileError::Io(format!("failed to open .gitattributes: {e}")))?;

        // Ensure newline before our entry if the file doesn't end with one
        if !content.ends_with('\n') {
            writeln!(file)
                .map_err(|e| LockfileError::Io(format!("failed to write .gitattributes: {e}")))?;
        }
        writeln!(file, "\n# lpm\n{marker}")
            .map_err(|e| LockfileError::Io(format!("failed to write .gitattributes: {e}")))?;
    } else {
        // Create new
        std::fs::write(&gitattributes, format!("# lpm\n{marker}\n"))
            .map_err(|e| LockfileError::Io(format!("failed to create .gitattributes: {e}")))?;
    }

    Ok(())
}

/// Validate that a package source URL in the lockfile is safe.
///
/// Only HTTPS registries and localhost (for development) are accepted.
/// Returns `false` for HTTP (non-localhost), file://, ftp://, or other schemes
/// that could indicate a tampered lockfile redirecting downloads to a malicious server.
pub fn is_safe_source(source: &str) -> bool {
    // Allow HTTPS registries (any host)
    if source.starts_with("registry+https://") {
        return true;
    }
    // Allow localhost/loopback for development
    if source.starts_with("registry+http://localhost")
        || source.starts_with("registry+http://127.0.0.1")
    {
        return true;
    }
    false
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
            alias_dependencies: vec![],
            tarball: None,
        });
        lf.add_package(LockedPackage {
            name: "react".to_string(),
            version: "999.999.999".to_string(),
            source: Some("registry+https://registry.npmjs.org".to_string()),
            integrity: None,
            dependencies: vec![],
            alias_dependencies: vec![],
            tarball: None,
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
            alias_dependencies: vec![],
            tarball: None,
        });
        lf.add_package(LockedPackage {
            name: "alpha".to_string(),
            version: "2.0.0".to_string(),
            source: None,
            integrity: None,
            dependencies: vec![],
            alias_dependencies: vec![],
            tarball: None,
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
    fn phase43_tarball_roundtrips_when_present() {
        let mut lf = Lockfile::new();
        lf.add_package(LockedPackage {
            name: "lodash".to_string(),
            version: "4.17.21".to_string(),
            source: Some("registry+https://registry.npmjs.org".to_string()),
            integrity: Some("sha512-xyz".to_string()),
            dependencies: vec![],
            alias_dependencies: vec![],
            tarball: Some("https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz".to_string()),
        });

        let toml_str = lf.to_toml().unwrap();
        // Serialized form must include the new field when populated.
        assert!(
            toml_str
                .contains("tarball = \"https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz\""),
            "expected tarball field in serialized TOML, got:\n{toml_str}"
        );

        let parsed = Lockfile::from_toml(&toml_str).unwrap();
        assert_eq!(lf, parsed);
        assert_eq!(
            parsed.packages[0].tarball.as_deref(),
            Some("https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz")
        );
    }

    #[test]
    fn phase43_tarball_absent_keeps_old_lockfiles_byte_identical() {
        // `#[serde(skip_serializing_if = "Option::is_none")]` must
        // keep pre-Phase-43 lockfiles byte-stable when no package has
        // a tarball URL. This is the invariant that makes P43-0 a
        // no-op for existing projects until they re-run `lpm install`.
        let lf = sample_lockfile();
        let toml_str = lf.to_toml().unwrap();
        assert!(
            !toml_str.contains("tarball"),
            "pre-Phase-43 lockfile must not emit a `tarball` field when all values are None, got:\n{toml_str}"
        );

        let parsed = Lockfile::from_toml(&toml_str).unwrap();
        assert_eq!(lf, parsed);
        for pkg in &parsed.packages {
            assert_eq!(pkg.tarball, None);
        }
    }

    #[test]
    fn phase43_tarball_mixed_population_roundtrips() {
        // Real-world rollout window: some entries have a tarball URL,
        // others don't. Per-package `None` must be preserved; `Some`
        // must round-trip with its value.
        let mut lf = Lockfile::new();
        lf.add_package(LockedPackage {
            name: "express".to_string(),
            version: "4.22.1".to_string(),
            source: Some("registry+https://registry.npmjs.org".to_string()),
            integrity: None,
            dependencies: vec![],
            alias_dependencies: vec![],
            tarball: None, // old entry, not yet re-resolved
        });
        lf.add_package(LockedPackage {
            name: "lodash".to_string(),
            version: "4.17.21".to_string(),
            source: Some("registry+https://registry.npmjs.org".to_string()),
            integrity: None,
            dependencies: vec![],
            alias_dependencies: vec![],
            tarball: Some("https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz".to_string()),
        });

        let toml_str = lf.to_toml().unwrap();
        let parsed = Lockfile::from_toml(&toml_str).unwrap();
        assert_eq!(lf, parsed);

        let express = parsed.find_package("express").unwrap();
        assert_eq!(express.tarball, None);
        let lodash = parsed.find_package("lodash").unwrap();
        assert_eq!(
            lodash.tarball.as_deref(),
            Some("https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz")
        );
    }

    #[test]
    fn phase43_old_lockfile_without_tarball_field_parses() {
        // Forward-compat: old lockfiles written before Phase 43 must
        // parse cleanly under the new schema (tarball = None).
        let toml_str = r#"
[metadata]
lockfile-version = 1
resolved-with = "pubgrub"

[[packages]]
name = "react"
version = "18.2.0"
source = "registry+https://registry.npmjs.org"
integrity = "sha512-old"
dependencies = []
"#;
        let parsed = Lockfile::from_toml(toml_str).unwrap();
        assert_eq!(parsed.packages.len(), 1);
        assert_eq!(parsed.packages[0].tarball, None);
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
    fn write_to_file_rename_failure_cleans_temp_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("lpm.lock");
        let tmp_path = path.with_extension("lock.tmp");
        let lf = sample_lockfile();

        std::fs::create_dir(&path).unwrap();

        let result = lf.write_to_file(&path);

        assert!(result.is_err(), "rename into a directory should fail");
        assert!(
            !tmp_path.exists(),
            "failed write should clean its temp file"
        );
    }

    #[test]
    fn ensure_gitattributes_creates_file() {
        let dir = tempfile::tempdir().unwrap();
        let ga = dir.path().join(".gitattributes");

        ensure_gitattributes(dir.path()).unwrap();

        assert!(ga.exists());
        let content = std::fs::read_to_string(&ga).unwrap();
        assert!(content.contains("lpm.lockb binary"));
        assert!(content.contains("# lpm"));
    }

    #[test]
    fn ensure_gitattributes_appends_to_existing() {
        let dir = tempfile::tempdir().unwrap();
        let ga = dir.path().join(".gitattributes");

        std::fs::write(&ga, "*.png binary\n").unwrap();
        ensure_gitattributes(dir.path()).unwrap();

        let content = std::fs::read_to_string(&ga).unwrap();
        assert!(content.starts_with("*.png binary\n"));
        assert!(content.contains("lpm.lockb binary"));
    }

    #[test]
    fn ensure_gitattributes_no_duplicate() {
        let dir = tempfile::tempdir().unwrap();
        let ga = dir.path().join(".gitattributes");

        ensure_gitattributes(dir.path()).unwrap();
        let content_first = std::fs::read_to_string(&ga).unwrap();

        ensure_gitattributes(dir.path()).unwrap();
        let content_second = std::fs::read_to_string(&ga).unwrap();

        assert_eq!(content_first, content_second);
    }

    #[test]
    fn ensure_gitattributes_preserves_existing_content() {
        let dir = tempfile::tempdir().unwrap();
        let ga = dir.path().join(".gitattributes");

        let existing = "# Git attributes\n*.jpg binary\n*.pdf binary\n";
        std::fs::write(&ga, existing).unwrap();

        ensure_gitattributes(dir.path()).unwrap();

        let content = std::fs::read_to_string(&ga).unwrap();
        assert!(content.starts_with(existing));
        assert!(content.contains("lpm.lockb binary"));
        assert!(content.contains("*.jpg binary"));
        assert!(content.contains("*.pdf binary"));
    }

    #[test]
    fn safe_source_https_lpm() {
        assert!(is_safe_source("registry+https://lpm.dev"));
    }

    #[test]
    fn safe_source_https_npm() {
        assert!(is_safe_source("registry+https://registry.npmjs.org"));
    }

    #[test]
    fn safe_source_https_custom_registry() {
        assert!(is_safe_source("registry+https://custom-registry.corp.com"));
    }

    #[test]
    fn unsafe_source_http() {
        assert!(!is_safe_source("registry+http://evil.com"));
    }

    #[test]
    fn safe_source_localhost() {
        assert!(is_safe_source("registry+http://localhost:3000"));
    }

    #[test]
    fn safe_source_loopback() {
        assert!(is_safe_source("registry+http://127.0.0.1:3000"));
    }

    #[test]
    fn unsafe_source_ftp() {
        assert!(!is_safe_source("ftp://evil.com/packages"));
    }

    #[test]
    fn unsafe_source_file() {
        assert!(!is_safe_source("file:///etc/passwd"));
    }

    /// Phase 40 P2 — npm-alias metadata round-trips through the TOML
    /// serializer. Both `root-aliases` (top-level) and per-package
    /// `alias-dependencies` must survive `to_toml` → `from_toml` with
    /// byte-identical shape, so warm installs reconstruct the original
    /// `node_modules/<local>/` layout.
    #[test]
    fn toml_roundtrips_npm_alias_metadata() {
        let mut lf = Lockfile::new();
        lf.root_aliases
            .insert("strip-ansi-cjs".to_string(), "strip-ansi".to_string());
        lf.add_package(LockedPackage {
            name: "strip-ansi".to_string(),
            version: "6.0.1".to_string(),
            source: Some("registry+https://registry.npmjs.org".to_string()),
            integrity: Some("sha512-abc".to_string()),
            dependencies: vec!["ansi-regex@5.0.1".to_string()],
            alias_dependencies: vec![],
            tarball: None,
        });
        lf.add_package(LockedPackage {
            name: "parent-with-alias-dep".to_string(),
            version: "1.0.0".to_string(),
            source: None,
            integrity: None,
            dependencies: vec!["strip-ansi-cjs@6.0.1".to_string()],
            alias_dependencies: vec![["strip-ansi-cjs".to_string(), "strip-ansi".to_string()]],
            tarball: None,
        });

        let toml = lf.to_toml().expect("TOML serialize must succeed");
        assert!(
            toml.contains("[root-aliases]"),
            "root-aliases must surface as a top-level TOML table"
        );
        assert!(
            toml.contains("alias-dependencies"),
            "per-package alias-dependencies must appear for packages with aliased deps"
        );

        let parsed = Lockfile::from_toml(&toml).expect("TOML parse must succeed");
        assert_eq!(
            parsed, lf,
            "round-trip must preserve every alias field byte-for-byte"
        );
    }

    /// Phase 40 P2 — the v1 binary format cannot express alias
    /// metadata; `binary::to_binary` rejects such lockfiles so callers
    /// fall back to TOML-only. `write_all` goes further and
    /// proactively removes any stale binary file from a prior
    /// non-aliased install, so `read_fast` never silently picks a
    /// binary that disagrees with the authoritative TOML.
    #[test]
    fn write_all_skips_binary_when_root_aliases_present() {
        let dir = tempfile::tempdir().unwrap();
        let toml_path = dir.path().join("lpm.lock");
        let binary_path = toml_path.with_extension("lockb");

        // First write — non-aliased lockfile produces BOTH files.
        let mut lf = Lockfile::new();
        lf.add_package(LockedPackage {
            name: "foo".to_string(),
            version: "1.0.0".to_string(),
            source: None,
            integrity: None,
            dependencies: vec![],
            alias_dependencies: vec![],
            tarball: None,
        });
        lf.write_all(&toml_path).unwrap();
        assert!(
            binary_path.exists(),
            "non-aliased lockfile must write binary"
        );

        // Second write — alias-bearing lockfile skips binary and
        // removes any stale file.
        lf.root_aliases
            .insert("alias".to_string(), "foo".to_string());
        lf.write_all(&toml_path).unwrap();
        assert!(
            !binary_path.exists(),
            "alias-bearing lockfile must not leave a stale binary behind"
        );
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
            alias_dependencies: vec![],
            tarball: None,
        });
        let toml_str = lf.to_toml().unwrap();
        // "dependencies" key should not appear when empty
        assert!(!toml_str.contains("dependencies"));
    }

    #[test]
    fn read_fast_prefers_binary_when_newer() {
        let dir = tempfile::tempdir().unwrap();
        let toml_path = dir.path().join("lpm.lock");
        let binary_path = dir.path().join("lpm.lockb");

        let lf = sample_lockfile();

        // Write TOML first
        lf.write_to_file(&toml_path).unwrap();

        // Small delay so binary has a strictly newer mtime
        std::thread::sleep(std::time::Duration::from_millis(50));

        // Write binary
        binary::write_binary(&lf, &binary_path).unwrap();

        // read_fast should succeed and return the same data
        let result = Lockfile::read_fast(&toml_path).unwrap();
        assert_eq!(result.packages.len(), lf.packages.len());
        for (orig, rest) in lf.packages.iter().zip(result.packages.iter()) {
            assert_eq!(orig.name, rest.name);
            assert_eq!(orig.version, rest.version);
        }
    }

    #[test]
    fn read_fast_falls_back_to_toml_when_binary_stale() {
        let dir = tempfile::tempdir().unwrap();
        let toml_path = dir.path().join("lpm.lock");
        let binary_path = dir.path().join("lpm.lockb");

        let lf = sample_lockfile();

        // Write binary first (older)
        binary::write_binary(&lf, &binary_path).unwrap();

        // Small delay so TOML has a strictly newer mtime
        std::thread::sleep(std::time::Duration::from_millis(50));

        // Write TOML with a different package to distinguish
        let mut lf2 = Lockfile::new();
        lf2.add_package(LockedPackage {
            name: "only-in-toml".to_string(),
            version: "9.9.9".to_string(),
            source: None,
            integrity: None,
            dependencies: vec![],
            alias_dependencies: vec![],
            tarball: None,
        });
        lf2.write_to_file(&toml_path).unwrap();

        // read_fast should fall back to TOML since binary is stale
        let result = Lockfile::read_fast(&toml_path).unwrap();
        assert_eq!(result.packages.len(), 1);
        assert_eq!(result.packages[0].name, "only-in-toml");
    }

    #[test]
    fn read_fast_falls_back_when_binary_corrupt() {
        let dir = tempfile::tempdir().unwrap();
        let toml_path = dir.path().join("lpm.lock");
        let binary_path = dir.path().join("lpm.lockb");

        let lf = sample_lockfile();
        lf.write_to_file(&toml_path).unwrap();

        // Write corrupt binary with bad magic (newer than TOML)
        std::thread::sleep(std::time::Duration::from_millis(50));
        std::fs::write(&binary_path, b"BADMxxxxxxxxxxxxxxxxx").unwrap();

        // read_fast should fall back to TOML since binary open fails
        let result = Lockfile::read_fast(&toml_path).unwrap();
        assert_eq!(result.packages.len(), lf.packages.len());
    }

    #[test]
    fn read_fast_falls_back_when_binary_dependency_table_is_corrupt() {
        let dir = tempfile::tempdir().unwrap();
        let toml_path = dir.path().join("lpm.lock");
        let binary_path = dir.path().join("lpm.lockb");

        let lf = sample_lockfile();
        lf.write_to_file(&toml_path).unwrap();

        let mut binary = binary::to_binary(&lf).unwrap();
        let deps_off_pos = 16 + 24;
        binary[deps_off_pos..deps_off_pos + 4].copy_from_slice(&1u32.to_le_bytes());

        std::thread::sleep(std::time::Duration::from_millis(50));
        std::fs::write(&binary_path, &binary).unwrap();

        let result = Lockfile::read_fast(&toml_path).unwrap();
        assert_eq!(
            result, lf,
            "corrupt binary should be rejected so read_fast falls back to TOML"
        );
    }

    #[test]
    fn read_fast_works_with_only_toml() {
        let dir = tempfile::tempdir().unwrap();
        let toml_path = dir.path().join("lpm.lock");

        let lf = sample_lockfile();
        lf.write_to_file(&toml_path).unwrap();

        // No binary file exists
        let binary_path = dir.path().join("lpm.lockb");
        assert!(!binary_path.exists());

        let result = Lockfile::read_fast(&toml_path).unwrap();
        assert_eq!(result, lf);
    }
}
