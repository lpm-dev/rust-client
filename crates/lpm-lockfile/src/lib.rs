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
pub mod source;

use serde::{Deserialize, Serialize};
use std::path::Path;

pub use binary::{BINARY_LOCKFILE_NAME, BinaryLockfileReader};
pub use source::{SafetyContext, Source, SourceParseError, SourceSafety, source_safety};

/// Three-tuple package identity for cross-source collision avoidance
/// (Phase 59.0 day-7, F1 finish-line).
///
/// The pre-Phase-59 install pipeline coordinated state on
/// `(name, version)` keys (fetch locks, integrity map, fresh-URL
/// writeback, root-link reconstruction, lockfile sort + lookup).
/// That was correct under the registry-only invariant of "one
/// registry per package name within a single graph". Once a
/// `Source::Tarball` package can land in the same graph as a
/// `Source::Registry` package with the same `(name, version)` —
/// e.g. a forked tarball whose package.json claims an upstream
/// name + version — the two-tuple key collapses identity and
/// makes the install attach state to the wrong package.
///
/// Day-5.5 closed the most user-visible silent-substitution paths
/// (cold-start existence check, store-path computation, link
/// target). Day-7 closes the remaining bookkeeping sites flagged
/// by the thorough audit's HIGH-2 follow-up.
///
/// `source_id` is [`Source::source_id`] for parsed sources, or
/// the literal string `"unknown"` for malformed/missing sources
/// (the lockfile reader gate already rejects unparseable sources;
/// this fallback keeps the helper total).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PackageKey {
    pub name: String,
    pub version: String,
    pub source_id: String,
}

impl PackageKey {
    /// Build a key from raw fields. Use [`LockedPackage::package_key`]
    /// or callers' equivalent helpers when possible — they handle
    /// the source parsing.
    pub fn new(
        name: impl Into<String>,
        version: impl Into<String>,
        source_id: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            version: version.into(),
            source_id: source_id.into(),
        }
    }

    /// Sentinel source_id used when the `source` field is `None` or
    /// malformed. Matches no real `Source::source_id` output (which
    /// always has a `<prefix>-<hex>` shape), so it can't collide
    /// with a parsed source.
    pub const UNKNOWN_SOURCE_ID: &'static str = "unknown";
}

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
    ///
    /// **Phase 59.0 (F4a) — disjointness with `Source::Tarball`:**
    /// this field is a *dist-URL hint cache* valid only for
    /// `Source::Registry` packages. For non-Registry sources
    /// (`Source::Tarball`, `Source::Git`, etc.) the URL is part of
    /// source identity (lives inside the source variant). Pairing
    /// a non-Registry source with this hint is rejected by
    /// [`Lockfile::from_toml`] — see
    /// [`LockedPackage::tarball_field_hint_is_consistent`] and
    /// [`LockfileError::InvalidTarballHint`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tarball: Option<String>,
}

impl LockedPackage {
    /// Parse the [`Self::source`] string into a typed [`Source`]
    /// (Phase 59.0 day-2, F1 cont.).
    ///
    /// Returns `None` when [`Self::source`] is `None`. Returns
    /// `Some(Err(_))` for malformed source strings — the legacy
    /// [`is_safe_source`] would also reject the same input.
    ///
    /// This is an *additive* accessor — the underlying `source: Option<String>`
    /// field is preserved for backwards compatibility; consumers
    /// migrate to typed access site-by-site.
    pub fn source_kind(&self) -> Option<Result<Source, SourceParseError>> {
        self.source.as_deref().map(Source::parse)
    }

    /// **Phase 59.0 day-7 (F1 finish-line)** — three-tuple identity
    /// for cross-source collision avoidance. See [`PackageKey`].
    ///
    /// The lockfile's bookkeeping (sort order, lookup, install
    /// pipeline coordination) keys on this triple to prevent a
    /// registry package and a tarball-URL package with the same
    /// `(name, version)` from clobbering each other's state.
    pub fn package_key(&self) -> PackageKey {
        let source_id = match self.source_kind() {
            Some(Ok(s)) => s.source_id(),
            _ => PackageKey::UNKNOWN_SOURCE_ID.to_string(),
        };
        PackageKey::new(self.name.clone(), self.version.clone(), source_id)
    }

    /// Whether the Phase 43 `tarball` field-hint is consistent with
    /// the parsed source kind (Phase 59.0 day-2, F4a contract).
    ///
    /// The `tarball` field is a dist-URL hint populated when
    /// resolving a Registry package — it lets warm installs skip a
    /// metadata round-trip. For non-Registry sources the URL is
    /// already part of the source identity (e.g. `Source::Tarball
    /// { url }`); a `tarball` hint on those is ill-formed and likely
    /// a sign of conflation between the identity slot and the
    /// optimization slot.
    ///
    /// Returns `true` when consistent:
    /// - source is `None`, OR
    /// - source is `Source::Registry` (any hint is valid), OR
    /// - tarball is `None` / empty (no hint to conflict).
    ///
    /// Returns `false` only for the conflation case: a non-Registry
    /// source kind paired with a non-empty `tarball` hint.
    ///
    /// Phase 59.0 day-2 ships this as a documented invariant; the
    /// lockfile-load gate in day-3 integrates it into a hard reject
    /// per OQ-4 (manifest-as-truth — invalid lockfile shapes drop
    /// to error, not silent acceptance).
    pub fn tarball_field_hint_is_consistent(&self) -> bool {
        let Some(hint) = self.tarball.as_deref() else {
            return true;
        };
        if hint.is_empty() {
            return true;
        }
        match self.source_kind() {
            None | Some(Err(_)) => true,
            Some(Ok(Source::Registry { .. })) => true,
            Some(Ok(_)) => false,
        }
    }
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

    /// Add a resolved package. Maintains sorted order by
    /// `(name, version, source_id)` triple — Phase 59.0 day-7
    /// (F1 finish-line) extension over the legacy name-only sort.
    /// Two packages with the same name but different
    /// `(version, source_id)` no longer race for the same slot,
    /// which closes the cross-source collision the audit flagged.
    pub fn add_package(&mut self, pkg: LockedPackage) {
        let key = pkg.package_key();
        let pos = self
            .packages
            .binary_search_by(|p| {
                let other = p.package_key();
                other
                    .name
                    .cmp(&key.name)
                    .then_with(|| other.version.cmp(&key.version))
                    .then_with(|| other.source_id.cmp(&key.source_id))
            })
            .unwrap_or_else(|pos| pos);
        self.packages.insert(pos, pkg);
    }

    /// Serialize to TOML string.
    ///
    /// **Phase 59.0 day-4.5 (F4a writer guard):** refuses to
    /// serialize a Lockfile whose package shape would fail the
    /// reader-side gate. Concretely, every package's
    /// `tarball_field_hint_is_consistent()` must hold — pairing a
    /// non-Registry source with a `tarball` field-hint is rejected
    /// here so the conflation never reaches disk. Symmetric with
    /// [`Lockfile::from_toml`]'s reader gate; together they make F4a
    /// a bidirectional invariant rather than parser-only.
    pub fn to_toml(&self) -> Result<String, LockfileError> {
        for pkg in &self.packages {
            if !pkg.tarball_field_hint_is_consistent() {
                return Err(LockfileError::InvalidTarballHint {
                    package: pkg.name.clone(),
                });
            }
        }
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

        // Phase 43 — reject empty-string optional fields at the TOML
        // layer, matching the binary writer's rejection. Without this,
        // a hand-edited or malformed `tarball = ""` / `source = ""` /
        // `integrity = ""` would parse cleanly here and only fail
        // later in `write_all` when the binary writer's
        // `insert_optional` helper fires. Failing loud at the parse
        // boundary avoids that asymmetric late failure.
        for pkg in &lockfile.packages {
            if let Some(s) = pkg.source.as_deref()
                && s.is_empty()
            {
                return Err(LockfileError::Deserialize(format!(
                    "package '{}' has empty 'source' — empty strings \
                     are not distinguishable from `None` in the binary \
                     format and are invalid input",
                    pkg.name
                )));
            }
            if let Some(s) = pkg.integrity.as_deref()
                && s.is_empty()
            {
                return Err(LockfileError::Deserialize(format!(
                    "package '{}' has empty 'integrity' — empty strings \
                     are not distinguishable from `None` in the binary \
                     format and are invalid input",
                    pkg.name
                )));
            }
            if let Some(s) = pkg.tarball.as_deref()
                && s.is_empty()
            {
                return Err(LockfileError::Deserialize(format!(
                    "package '{}' has empty 'tarball' — empty strings \
                     are not distinguishable from `None` in the binary \
                     format and are invalid input",
                    pkg.name
                )));
            }

            // Phase 59.0 day-3 (F4a wire-in) — `tarball` field-hint
            // is valid only for Registry sources. Reject non-Registry
            // shapes paired with a hint at the load boundary so the
            // conflation never propagates into the install path.
            if !pkg.tarball_field_hint_is_consistent() {
                return Err(LockfileError::InvalidTarballHint {
                    package: pkg.name.clone(),
                });
            }
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

            if use_binary {
                match BinaryLockfileReader::open(&binary_path) {
                    Ok(Some(reader)) => return Ok(reader.to_lockfile()),
                    Err(LockfileError::UnsupportedVersion { found, .. })
                        if found < binary::BINARY_VERSION =>
                    {
                        // Phase 43 — stale binary from an OLDER client.
                        // Best-effort delete so read-only commands
                        // (`lpm outdated`, `lpm upgrade`) don't pay the
                        // TOML-fallback cost on every invocation. Without
                        // this, a project with a pre-Phase-43 `lpm.lockb`
                        // would repeatedly open+reject the stale binary
                        // until an install fires P43-2's writeback.
                        //
                        // We restrict deletion to `found < BINARY_VERSION`
                        // (2nd-round GPT audit): a FUTURE-version binary
                        // (found > BINARY_VERSION) means the user likely
                        // has a newer LPM client on this machine that
                        // wrote it. Deleting would force regeneration on
                        // the next new-client install, churning the
                        // cache. The newer format is unreadable to us;
                        // falling through to TOML is correct either way,
                        // but preserving the file keeps the newer
                        // client's fast path intact.
                        //
                        // Swallow any delete failure (read-only FS,
                        // permission denied) — correctness still holds
                        // via the TOML fallback below.
                        let _ = std::fs::remove_file(&binary_path);
                    }
                    // Future-version binaries AND any other error
                    // (corrupted magic, structural validation, etc.)
                    // fall through to TOML without deleting the binary.
                    _ => {}
                }
            }
        }

        Self::read_from_file(toml_path)
    }

    /// Check if a lockfile exists at the given path.
    pub fn exists(path: &Path) -> bool {
        path.exists()
    }

    /// Look up a locked package by name. **Name-only — does NOT
    /// disambiguate cross-source collisions.** Returns the first
    /// match in sort order; under a `(name, version, source_id)`
    /// triple sort that's the lowest-source_id entry for the
    /// lowest-version with this name.
    ///
    /// **Phase 59.0 day-7 (F1 finish-line):** prefer
    /// [`Self::find_package_by_key`] for new code. This name-only
    /// method is retained for back-compat with pre-Phase-59
    /// callers (Phase 40 P2 alias resolution etc.) where the name
    /// uniquely identifies a package; non-Registry source kinds
    /// landing in the same lockfile may shadow such lookups.
    pub fn find_package(&self, name: &str) -> Option<&LockedPackage> {
        self.packages
            .binary_search_by(|p| p.name.as_str().cmp(name))
            .ok()
            .map(|idx| &self.packages[idx])
    }

    /// **Phase 59.0 day-7 (F1 finish-line)** — source-aware lookup
    /// keyed by the full `(name, version, source_id)` triple.
    /// Returns `Some(&LockedPackage)` only when the exact key
    /// matches; under cross-source collision (registry +
    /// tarball-URL with same `name@version`), returns the
    /// requested side, never an ambiguous shadow.
    pub fn find_package_by_key(&self, key: &PackageKey) -> Option<&LockedPackage> {
        self.packages
            .binary_search_by(|p| {
                let pk = p.package_key();
                pk.name
                    .cmp(&key.name)
                    .then_with(|| pk.version.cmp(&key.version))
                    .then_with(|| pk.source_id.cmp(&key.source_id))
            })
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

    /// **Phase 59.0 day-3 (F4a wire-in)** — a non-Registry source
    /// kind is paired with a `tarball` field-hint. The Phase 43
    /// `tarball` field is a dist-URL cache valid only for Registry
    /// sources; for `Source::Tarball`, `Source::Git`, etc. the URL
    /// is part of source identity (lives inside the `source`
    /// variant). The two slots must stay disjoint — conflation
    /// would let `lpm update` silently swap a tarball-URL dep for
    /// a registry package with the same dist URL.
    ///
    /// Detected by [`LockedPackage::tarball_field_hint_is_consistent`]
    /// at `from_toml` time — invalid lockfile shapes hard-reject
    /// at the load boundary per OQ-4 (manifest-as-truth: invalid
    /// shapes should never propagate).
    #[error(
        "package {package:?} has a `tarball` field-hint paired with a non-Registry source — \
         the hint is valid only for Registry sources (Phase 59.0 F4a)"
    )]
    InvalidTarballHint { package: String },
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
    fn phase43_from_toml_rejects_empty_optional_strings() {
        // Follow-up to the 2026-04-18 GPT audit (finding #3): the
        // binary writer rejects empty optional strings at
        // serialization time, but `from_toml` previously accepted
        // them at parse time, producing an asymmetric late failure.
        // Reject at the parse boundary for all three fields.
        for (field, snippet) in [
            ("tarball", "tarball = \"\""),
            ("source", "source = \"\""),
            ("integrity", "integrity = \"\""),
        ] {
            let toml_str = format!(
                r#"
[metadata]
lockfile-version = 1

[[packages]]
name = "bad-pkg"
version = "1.0.0"
{snippet}
"#
            );
            let err = Lockfile::from_toml(&toml_str).expect_err(&format!(
                "empty {field} must be rejected at TOML parse time"
            ));
            let msg = err.to_string();
            assert!(
                msg.contains(&format!("empty '{field}'")) && msg.contains("bad-pkg"),
                "error for {field} should name field and package, got: {msg}"
            );
        }
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
    fn phase43_read_fast_falls_back_to_toml_when_binary_is_v1() {
        // Client upgrade scenario: user has a v1 `lpm.lockb` on disk
        // (written by a pre-Phase-43 client) plus the v2-compatible
        // TOML lockfile. The new v2 reader must reject v1 and
        // read_fast must fall through to TOML cleanly — otherwise
        // the client would error out every install until something
        // else triggered a lockfile rewrite.
        let dir = tempfile::tempdir().unwrap();
        let toml_path = dir.path().join("lpm.lock");
        let binary_path = dir.path().join("lpm.lockb");

        let lf = sample_lockfile();
        lf.write_to_file(&toml_path).unwrap();

        // Hand-roll a minimal v1 binary lockfile header (version=1).
        // The reader rejects at version check; body doesn't need to
        // be a valid v1 body. Use magic = b"LPMB" (same as v2 so the
        // magic check passes, forcing the version check to fire).
        std::thread::sleep(std::time::Duration::from_millis(50));
        let mut v1_header = Vec::with_capacity(16);
        v1_header.extend_from_slice(b"LPMB");
        v1_header.extend_from_slice(&1u32.to_le_bytes()); // version = 1
        v1_header.extend_from_slice(&0u32.to_le_bytes()); // 0 packages
        v1_header.extend_from_slice(&16u32.to_le_bytes()); // string_table_off
        std::fs::write(&binary_path, &v1_header).unwrap();

        // read_fast must succeed via the TOML fallback, not error out.
        let result = Lockfile::read_fast(&toml_path).unwrap();
        assert_eq!(result.packages.len(), lf.packages.len());
        // Stale v1 binary must be deleted — otherwise read-only
        // commands (`lpm outdated`, `lpm upgrade`) would pay the
        // failed-open + TOML-parse cost on every invocation. After
        // deletion, subsequent read_fast calls skip the binary
        // check entirely until P43-2's writeback creates the v2
        // file.
        assert!(
            !binary_path.exists(),
            "stale v1 lpm.lockb must be deleted at read time so the \
             regression doesn't persist across read-only commands"
        );
    }

    #[test]
    fn phase43_read_fast_preserves_binary_on_future_version() {
        // Second-round GPT audit open question: an `UnsupportedVersion`
        // with `found > BINARY_VERSION` (a FUTURE binary format the
        // user's newer LPM client wrote) must NOT be deleted — the
        // newer client's fast path should stay intact. Deletion is
        // scoped to `found < BINARY_VERSION` only.
        let dir = tempfile::tempdir().unwrap();
        let toml_path = dir.path().join("lpm.lock");
        let binary_path = dir.path().join("lpm.lockb");

        let lf = sample_lockfile();
        lf.write_to_file(&toml_path).unwrap();

        // Hand-roll a header that looks like a future v99 binary.
        std::thread::sleep(std::time::Duration::from_millis(50));
        let mut v99_header = Vec::with_capacity(16);
        v99_header.extend_from_slice(b"LPMB");
        v99_header.extend_from_slice(&99u32.to_le_bytes()); // future version
        v99_header.extend_from_slice(&0u32.to_le_bytes());
        v99_header.extend_from_slice(&16u32.to_le_bytes());
        std::fs::write(&binary_path, &v99_header).unwrap();

        // read_fast must fall back to TOML cleanly.
        let result = Lockfile::read_fast(&toml_path).unwrap();
        assert_eq!(result.packages.len(), lf.packages.len());
        // Future-version binary stays on disk — a newer client can
        // use it on their next read.
        assert!(
            binary_path.exists(),
            "future-version binary must be preserved for newer clients"
        );
    }

    #[test]
    fn phase43_read_fast_preserves_binary_on_non_version_errors() {
        // Complement to the v1-delete behavior: only `UnsupportedVersion`
        // triggers deletion. Structural corruption (bad magic, truncated
        // body) leaves the file on disk in case the user wants to
        // forensically inspect it. This guards against aggressive
        // deletion creeping into other error paths.
        let dir = tempfile::tempdir().unwrap();
        let toml_path = dir.path().join("lpm.lock");
        let binary_path = dir.path().join("lpm.lockb");

        let lf = sample_lockfile();
        lf.write_to_file(&toml_path).unwrap();

        // Bad magic — NOT UnsupportedVersion.
        std::thread::sleep(std::time::Duration::from_millis(50));
        std::fs::write(&binary_path, b"BADMxxxxxxxxxxxxxxxx").unwrap();

        let result = Lockfile::read_fast(&toml_path).unwrap();
        assert_eq!(result.packages.len(), lf.packages.len());
        assert!(
            binary_path.exists(),
            "non-version binary errors must leave the file on disk \
             (forensic preservation)"
        );
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

    // ── Phase 59.0 day-2: source_kind() typed accessor ──────────────────────

    fn pkg_with_source(name: &str, source: Option<&str>) -> LockedPackage {
        LockedPackage {
            name: name.to_string(),
            version: "1.0.0".to_string(),
            source: source.map(|s| s.to_string()),
            integrity: None,
            dependencies: vec![],
            alias_dependencies: vec![],
            tarball: None,
        }
    }

    #[test]
    fn source_kind_none_when_source_absent() {
        let pkg = pkg_with_source("foo", None);
        assert!(pkg.source_kind().is_none());
    }

    #[test]
    fn source_kind_parses_existing_registry_format() {
        let pkg = pkg_with_source("react", Some("registry+https://registry.npmjs.org"));
        match pkg.source_kind() {
            Some(Ok(Source::Registry { url })) => assert_eq!(url, "https://registry.npmjs.org"),
            other => panic!("expected Registry, got {other:?}"),
        }
    }

    #[test]
    fn source_kind_parses_lpm_registry_format() {
        let pkg = pkg_with_source("@lpm.dev/foo", Some("registry+https://lpm.dev"));
        match pkg.source_kind() {
            Some(Ok(Source::Registry { url })) => assert_eq!(url, "https://lpm.dev"),
            other => panic!("expected Registry, got {other:?}"),
        }
    }

    #[test]
    fn source_kind_parses_tarball_url() {
        let pkg = pkg_with_source("foo", Some("tarball+https://example.com/foo-1.tgz"));
        match pkg.source_kind() {
            Some(Ok(Source::Tarball { url })) => {
                assert_eq!(url, "https://example.com/foo-1.tgz");
            }
            other => panic!("expected Tarball, got {other:?}"),
        }
    }

    #[test]
    fn source_kind_parses_directory() {
        let pkg = pkg_with_source("foo", Some("directory+../packages/foo"));
        match pkg.source_kind() {
            Some(Ok(Source::Directory { path })) => assert_eq!(path, "../packages/foo"),
            other => panic!("expected Directory, got {other:?}"),
        }
    }

    #[test]
    fn source_kind_parses_link() {
        let pkg = pkg_with_source("foo", Some("link+../packages/foo"));
        match pkg.source_kind() {
            Some(Ok(Source::Link { path })) => assert_eq!(path, "../packages/foo"),
            other => panic!("expected Link, got {other:?}"),
        }
    }

    #[test]
    fn source_kind_parses_git() {
        let pkg = pkg_with_source("foo", Some("git+https://github.com/foo/bar.git"));
        match pkg.source_kind() {
            Some(Ok(Source::Git { url })) => {
                assert_eq!(url, "git+https://github.com/foo/bar.git");
            }
            other => panic!("expected Git, got {other:?}"),
        }
    }

    #[test]
    fn source_kind_returns_err_for_unknown_kind() {
        let pkg = pkg_with_source("foo", Some("nonsense+whatever"));
        assert!(matches!(
            pkg.source_kind(),
            Some(Err(SourceParseError::UnknownKind(_)))
        ));
    }

    // ── Phase 59.0 day-2 (F4a): tarball field-hint disjointness ─────────────

    fn pkg_with_source_and_tarball(source: Option<&str>, tarball: Option<&str>) -> LockedPackage {
        LockedPackage {
            name: "foo".to_string(),
            version: "1.0.0".to_string(),
            source: source.map(|s| s.to_string()),
            integrity: None,
            dependencies: vec![],
            alias_dependencies: vec![],
            tarball: tarball.map(|s| s.to_string()),
        }
    }

    #[test]
    fn tarball_hint_consistent_when_no_source() {
        // No source set → trivially consistent (source-less packages
        // are workspace members or tombstones; the hint, if present,
        // is harmless legacy data).
        let pkg = pkg_with_source_and_tarball(None, Some("https://e.com/foo.tgz"));
        assert!(pkg.tarball_field_hint_is_consistent());
    }

    #[test]
    fn tarball_hint_consistent_when_no_hint() {
        let pkg = pkg_with_source_and_tarball(Some("tarball+https://e.com/foo.tgz"), None);
        assert!(pkg.tarball_field_hint_is_consistent());
    }

    #[test]
    fn tarball_hint_consistent_when_registry_source() {
        // Registry + dist-URL hint is the *intended* shape post-Phase 43.
        let pkg = pkg_with_source_and_tarball(
            Some("registry+https://registry.npmjs.org"),
            Some("https://registry.npmjs.org/foo/-/foo-1.0.0.tgz"),
        );
        assert!(pkg.tarball_field_hint_is_consistent());
    }

    #[test]
    fn tarball_hint_inconsistent_when_paired_with_tarball_source() {
        // The conflation case F4a guards against. `Source::Tarball`'s
        // URL is identity; a sibling `tarball` hint slot is ill-formed.
        let pkg = pkg_with_source_and_tarball(
            Some("tarball+https://e.com/foo.tgz"),
            Some("https://e.com/foo.tgz"),
        );
        assert!(
            !pkg.tarball_field_hint_is_consistent(),
            "Source::Tarball + tarball field-hint must be flagged inconsistent"
        );
    }

    #[test]
    fn tarball_hint_inconsistent_when_paired_with_git_source() {
        let pkg = pkg_with_source_and_tarball(
            Some("git+https://github.com/foo/bar.git"),
            Some("https://e.com/foo.tgz"),
        );
        assert!(!pkg.tarball_field_hint_is_consistent());
    }

    #[test]
    fn tarball_hint_inconsistent_when_paired_with_directory_source() {
        let pkg = pkg_with_source_and_tarball(
            Some("directory+../packages/foo"),
            Some("https://e.com/foo.tgz"),
        );
        assert!(!pkg.tarball_field_hint_is_consistent());
    }

    #[test]
    fn tarball_hint_inconsistent_when_paired_with_link_source() {
        let pkg = pkg_with_source_and_tarball(
            Some("link+../packages/foo"),
            Some("https://e.com/foo.tgz"),
        );
        assert!(!pkg.tarball_field_hint_is_consistent());
    }

    #[test]
    fn tarball_hint_consistent_when_source_unparseable() {
        // Malformed source → not our problem here; some other validator
        // will flag the source. We don't double-flag.
        let pkg = pkg_with_source_and_tarball(Some("garbage"), Some("https://e.com/foo.tgz"));
        assert!(pkg.tarball_field_hint_is_consistent());
    }

    #[test]
    fn tarball_field_hint_round_trips_through_toml_with_registry() {
        // The full-shape TOML round-trip with both source AND tarball
        // hint set must survive serialization unchanged.
        let mut lf = Lockfile::new();
        lf.add_package(pkg_with_source_and_tarball(
            Some("registry+https://registry.npmjs.org"),
            Some("https://registry.npmjs.org/foo/-/foo-1.0.0.tgz"),
        ));
        let toml = lf.to_toml().expect("serialize");
        let parsed = Lockfile::from_toml(&toml).expect("parse");
        assert_eq!(parsed, lf);
        assert!(parsed.packages[0].tarball_field_hint_is_consistent());
    }

    #[test]
    fn tarball_source_round_trips_through_toml_without_hint() {
        // A `Source::Tarball` package must NOT carry a tarball hint
        // through the round-trip — the parser preserves the shape we
        // wrote (no hint), and the consistency check stays green.
        let mut lf = Lockfile::new();
        lf.add_package(pkg_with_source_and_tarball(
            Some("tarball+https://e.com/foo-1.0.0.tgz"),
            None,
        ));
        let toml = lf.to_toml().expect("serialize");
        let parsed = Lockfile::from_toml(&toml).expect("parse");
        assert_eq!(parsed, lf);
        assert!(parsed.packages[0].tarball_field_hint_is_consistent());
        assert!(parsed.packages[0].tarball.is_none());
        match parsed.packages[0].source_kind() {
            Some(Ok(Source::Tarball { .. })) => {}
            other => panic!("expected Tarball source, got {other:?}"),
        }
    }

    // ── Phase 59.1 day-7 (F16): non-registry source round-trip coverage ─────

    #[test]
    fn directory_source_round_trips_through_toml() {
        // `Source::Directory { path }` — file: directory dep.
        // Wire-format `directory+<rel-path>` survives serialize +
        // parse; F4a disjointness invariant holds (no tarball hint).
        let mut lf = Lockfile::new();
        lf.add_package(pkg_with_source_and_tarball(
            Some("directory+./packages/foo"),
            None,
        ));
        let toml = lf.to_toml().expect("serialize");
        let parsed = Lockfile::from_toml(&toml).expect("parse");
        assert_eq!(parsed, lf);
        assert!(parsed.packages[0].tarball_field_hint_is_consistent());
        assert!(parsed.packages[0].tarball.is_none());
        match parsed.packages[0].source_kind() {
            Some(Ok(Source::Directory { path })) => {
                assert_eq!(path, "./packages/foo");
            }
            other => panic!("expected Directory source, got {other:?}"),
        }
    }

    #[test]
    fn link_source_round_trips_through_toml() {
        // `Source::Link { path }` — link: dep. Same shape as
        // Directory but with `link+` wire prefix.
        let mut lf = Lockfile::new();
        lf.add_package(pkg_with_source_and_tarball(
            Some("link+../shared/util"),
            None,
        ));
        let toml = lf.to_toml().expect("serialize");
        let parsed = Lockfile::from_toml(&toml).expect("parse");
        assert_eq!(parsed, lf);
        assert!(parsed.packages[0].tarball_field_hint_is_consistent());
        match parsed.packages[0].source_kind() {
            Some(Ok(Source::Link { path })) => {
                assert_eq!(path, "../shared/util");
            }
            other => panic!("expected Link source, got {other:?}"),
        }
    }

    #[test]
    fn tarball_local_source_round_trips_through_toml_with_sha256_integrity() {
        // `Source::Tarball { url: "file:..." }` — Phase 59.1 F6
        // local-file tarball. The wire format reuses `tarball+` for
        // both remote and local; the URL prefix is what
        // disambiguates downstream. Integrity is sha256 (computed
        // from the bytes at install time), distinct from the sha512
        // SRI typically used for remote registry tarballs.
        let mut lf = Lockfile::new();
        lf.add_package(LockedPackage {
            name: "local-bundle".to_string(),
            version: "1.0.0".to_string(),
            source: Some("tarball+file:./vendor/local-bundle-1.0.0.tgz".to_string()),
            integrity: Some("sha256-abc123def456".to_string()),
            dependencies: vec![],
            alias_dependencies: vec![],
            tarball: None,
        });
        let toml = lf.to_toml().expect("serialize");
        let parsed = Lockfile::from_toml(&toml).expect("parse");
        assert_eq!(parsed, lf);
        // F4a: tarball field-hint stays None for non-Registry sources.
        assert!(parsed.packages[0].tarball.is_none());
        assert!(parsed.packages[0].tarball_field_hint_is_consistent());
        // Integrity preserved exactly.
        assert_eq!(
            parsed.packages[0].integrity.as_deref(),
            Some("sha256-abc123def456"),
        );
        // The URL retains the file: prefix — this is what install.rs's
        // `store_path_source_aware` route discrimination depends on.
        match parsed.packages[0].source_kind() {
            Some(Ok(Source::Tarball { url })) => {
                assert!(
                    url.starts_with("file:"),
                    "local-tarball URL must keep file: prefix, got {url:?}",
                );
            }
            other => panic!("expected Tarball source, got {other:?}"),
        }
    }

    #[test]
    fn directory_link_sources_share_lockfile_with_registry_packages() {
        // Mixed-source lockfile: registry + tarball (remote) + tarball
        // (local) + directory + link, all in one graph. Round-trip
        // preserves every package's source identity. Exercises the
        // identity model end-to-end at the lockfile layer.
        let mut lf = Lockfile::new();
        lf.add_package(LockedPackage {
            name: "lodash".to_string(),
            version: "4.17.21".to_string(),
            source: Some("registry+https://registry.npmjs.org".to_string()),
            integrity: Some("sha512-lodash".to_string()),
            dependencies: vec![],
            alias_dependencies: vec![],
            tarball: Some("https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz".to_string()),
        });
        lf.add_package(LockedPackage {
            name: "remote-fork".to_string(),
            version: "1.0.0".to_string(),
            source: Some("tarball+https://e.com/remote-fork.tgz".to_string()),
            integrity: Some("sha512-remoteFork".to_string()),
            dependencies: vec![],
            alias_dependencies: vec![],
            tarball: None,
        });
        lf.add_package(LockedPackage {
            name: "local-tarball".to_string(),
            version: "1.0.0".to_string(),
            source: Some("tarball+file:./vendor/local-tarball.tgz".to_string()),
            integrity: Some("sha256-localTarball".to_string()),
            dependencies: vec![],
            alias_dependencies: vec![],
            tarball: None,
        });
        lf.add_package(LockedPackage {
            name: "local-dir".to_string(),
            version: "0.1.0".to_string(),
            source: Some("directory+./packages/local-dir".to_string()),
            integrity: None,
            dependencies: vec![],
            alias_dependencies: vec![],
            tarball: None,
        });
        lf.add_package(LockedPackage {
            name: "linked".to_string(),
            version: "0.1.0".to_string(),
            source: Some("link+../shared/linked".to_string()),
            integrity: None,
            dependencies: vec![],
            alias_dependencies: vec![],
            tarball: None,
        });

        let toml = lf.to_toml().expect("serialize");
        let parsed = Lockfile::from_toml(&toml).expect("parse");
        assert_eq!(parsed.packages.len(), 5);
        // Every package's source variant survives the round-trip.
        for pkg in &parsed.packages {
            assert!(
                pkg.source_kind().as_ref().is_some_and(|r| r.is_ok()),
                "source must parse for {}: got {:?}",
                pkg.name,
                pkg.source_kind(),
            );
            // F4a disjointness holds across all sources.
            assert!(
                pkg.tarball_field_hint_is_consistent(),
                "F4a violation for {}: {:?}",
                pkg.name,
                pkg,
            );
        }
        assert_eq!(parsed, lf);
    }

    #[test]
    fn from_toml_rejects_directory_source_with_tarball_hint() {
        // F4a wire-in: directory+ source + tarball field-hint is a
        // hard reject at lockfile-load time. The hint is registry-
        // specific (Phase 43 dist-URL cache); for non-Registry
        // sources, conflation could let `lpm update` silently swap
        // the dep.
        let toml = lockfile_with_bad_pair(
            "foo",
            "directory+./packages/foo",
            "https://anywhere.com/foo.tgz",
        );
        match Lockfile::from_toml(&toml) {
            Err(LockfileError::InvalidTarballHint { package }) => {
                assert_eq!(package, "foo");
            }
            other => panic!("expected InvalidTarballHint, got {other:?}"),
        }
    }

    #[test]
    fn from_toml_rejects_link_source_with_tarball_hint() {
        let toml = lockfile_with_bad_pair(
            "linked",
            "link+./packages/linked",
            "https://anywhere.com/linked.tgz",
        );
        match Lockfile::from_toml(&toml) {
            Err(LockfileError::InvalidTarballHint { package }) => {
                assert_eq!(package, "linked");
            }
            other => panic!("expected InvalidTarballHint, got {other:?}"),
        }
    }

    // ── Phase 59.0 day-3 (F4a wire-in): lockfile-load hard reject ───────────

    /// Hand-craft a conflated lockfile TOML string. We can't go
    /// through `to_toml` anymore — the day-4.5 writer guard
    /// (F4a wire-in, write side) refuses to serialize this shape.
    /// Tests that exercise the *reader* gate must produce the bytes
    /// directly, simulating a corrupt or hand-edited `lpm.lock`.
    fn lockfile_with_bad_pair(name: &str, source: &str, tarball: &str) -> String {
        format!(
            "[metadata]\n\
             lockfile-version = 1\n\
             resolved-with = \"pubgrub\"\n\
             \n\
             [[packages]]\n\
             name = \"{name}\"\n\
             version = \"1.0.0\"\n\
             source = \"{source}\"\n\
             tarball = \"{tarball}\"\n"
        )
    }

    #[test]
    fn from_toml_rejects_tarball_source_with_hint_conflation() {
        let toml = lockfile_with_bad_pair(
            "foo",
            "tarball+https://e.com/foo-1.0.0.tgz",
            "https://e.com/foo-1.0.0.tgz",
        );
        match Lockfile::from_toml(&toml) {
            Err(LockfileError::InvalidTarballHint { package }) => {
                assert_eq!(package, "foo");
            }
            other => panic!("expected InvalidTarballHint, got {other:?}"),
        }
    }

    #[test]
    fn from_toml_rejects_git_source_with_hint_conflation() {
        let toml = lockfile_with_bad_pair(
            "foo",
            "git+https://github.com/foo/bar.git",
            "https://e.com/foo.tgz",
        );
        match Lockfile::from_toml(&toml) {
            Err(LockfileError::InvalidTarballHint { package }) => {
                assert_eq!(package, "foo");
            }
            other => panic!("expected InvalidTarballHint, got {other:?}"),
        }
    }

    #[test]
    fn from_toml_rejects_directory_source_with_hint_conflation() {
        let toml =
            lockfile_with_bad_pair("foo", "directory+../packages/foo", "https://e.com/foo.tgz");
        assert!(matches!(
            Lockfile::from_toml(&toml),
            Err(LockfileError::InvalidTarballHint { .. })
        ));
    }

    #[test]
    fn from_toml_rejects_link_source_with_hint_conflation() {
        let toml = lockfile_with_bad_pair("foo", "link+../packages/foo", "https://e.com/foo.tgz");
        assert!(matches!(
            Lockfile::from_toml(&toml),
            Err(LockfileError::InvalidTarballHint { .. })
        ));
    }

    #[test]
    fn from_toml_accepts_registry_source_with_hint() {
        // The intended Phase 43 shape — registry source plus dist-URL
        // hint — must still parse cleanly post-gate.
        let mut lf = Lockfile::new();
        lf.add_package(pkg_with_source_and_tarball(
            Some("registry+https://registry.npmjs.org"),
            Some("https://registry.npmjs.org/foo/-/foo-1.0.0.tgz"),
        ));
        let toml = lf.to_toml().expect("serialize");
        Lockfile::from_toml(&toml).expect("registry+hint must parse cleanly post-gate");
    }

    #[test]
    fn from_toml_accepts_existing_lockfile_without_hint() {
        // Regression for legacy lockfiles that pre-date the Phase 43
        // hint — nothing here changed at the load boundary.
        let lf = sample_lockfile();
        let toml = lf.to_toml().expect("serialize");
        let parsed = Lockfile::from_toml(&toml).expect("legacy lockfile must still parse");
        assert_eq!(parsed, lf);
    }

    #[test]
    fn from_toml_gate_runs_per_package_and_names_first_offender() {
        // Two-package hand-crafted lockfile (writer guard prevents
        // round-tripping bad shapes; we simulate corruption directly):
        // first package is the legitimate Phase 43 shape (Registry +
        // hint), second has the conflation. Gate must fire on the
        // second and name it correctly — not silently skip after
        // seeing a valid first.
        let toml = "[metadata]\n\
             lockfile-version = 1\n\
             resolved-with = \"pubgrub\"\n\
             \n\
             [[packages]]\n\
             name = \"good-pkg\"\n\
             version = \"1.0.0\"\n\
             source = \"registry+https://registry.npmjs.org\"\n\
             tarball = \"https://registry.npmjs.org/good-pkg/-/good-pkg-1.0.0.tgz\"\n\
             \n\
             [[packages]]\n\
             name = \"bad-pkg\"\n\
             version = \"1.0.0\"\n\
             source = \"tarball+https://e.com/bad.tgz\"\n\
             tarball = \"https://e.com/bad.tgz\"\n";
        match Lockfile::from_toml(toml) {
            Err(LockfileError::InvalidTarballHint { package }) => {
                assert_eq!(package, "bad-pkg", "gate should name the offender");
            }
            other => panic!("expected InvalidTarballHint, got {other:?}"),
        }
    }

    // ── Phase 59.0 day-4.5: F4a writer guard (post-audit) ───────────────────

    #[test]
    fn to_toml_rejects_tarball_source_with_hint_conflation() {
        let mut lf = Lockfile::new();
        lf.add_package(pkg_with_source_and_tarball(
            Some("tarball+https://e.com/foo.tgz"),
            Some("https://e.com/foo.tgz"),
        ));
        match lf.to_toml() {
            Err(LockfileError::InvalidTarballHint { package }) => {
                assert_eq!(package, "foo");
            }
            other => panic!("expected InvalidTarballHint, got {other:?}"),
        }
    }

    #[test]
    fn to_toml_rejects_git_source_with_hint_conflation() {
        let mut lf = Lockfile::new();
        lf.add_package(pkg_with_source_and_tarball(
            Some("git+https://github.com/foo/bar.git"),
            Some("https://e.com/foo.tgz"),
        ));
        assert!(matches!(
            lf.to_toml(),
            Err(LockfileError::InvalidTarballHint { .. })
        ));
    }

    #[test]
    fn to_toml_rejects_directory_source_with_hint_conflation() {
        let mut lf = Lockfile::new();
        lf.add_package(pkg_with_source_and_tarball(
            Some("directory+../packages/foo"),
            Some("https://e.com/foo.tgz"),
        ));
        assert!(matches!(
            lf.to_toml(),
            Err(LockfileError::InvalidTarballHint { .. })
        ));
    }

    #[test]
    fn to_toml_rejects_link_source_with_hint_conflation() {
        let mut lf = Lockfile::new();
        lf.add_package(pkg_with_source_and_tarball(
            Some("link+../packages/foo"),
            Some("https://e.com/foo.tgz"),
        ));
        assert!(matches!(
            lf.to_toml(),
            Err(LockfileError::InvalidTarballHint { .. })
        ));
    }

    #[test]
    fn to_toml_accepts_registry_source_with_hint() {
        // Phase 43 shape — Registry + dist-URL hint — must continue
        // to serialize cleanly through the new guard.
        let mut lf = Lockfile::new();
        lf.add_package(pkg_with_source_and_tarball(
            Some("registry+https://registry.npmjs.org"),
            Some("https://registry.npmjs.org/foo/-/foo-1.0.0.tgz"),
        ));
        lf.to_toml().expect("registry+hint must serialize cleanly");
    }

    #[test]
    fn to_toml_accepts_tarball_source_without_hint() {
        let mut lf = Lockfile::new();
        lf.add_package(pkg_with_source_and_tarball(
            Some("tarball+https://e.com/foo.tgz"),
            None,
        ));
        lf.to_toml()
            .expect("tarball source without hint must serialize cleanly");
    }

    #[test]
    fn to_toml_writer_guard_runs_per_package_and_names_first_offender() {
        // Two-package case mirroring the reader-side test: first OK,
        // second conflated. Writer guard must surface the second.
        let mut lf = Lockfile::new();
        lf.add_package(LockedPackage {
            name: "good-pkg".to_string(),
            version: "1.0.0".to_string(),
            source: Some("registry+https://registry.npmjs.org".to_string()),
            integrity: None,
            dependencies: vec![],
            alias_dependencies: vec![],
            tarball: Some("https://registry.npmjs.org/good-pkg/-/good-pkg-1.0.0.tgz".to_string()),
        });
        lf.add_package(LockedPackage {
            name: "bad-pkg".to_string(),
            version: "1.0.0".to_string(),
            source: Some("git+https://github.com/foo/bar.git".to_string()),
            integrity: None,
            dependencies: vec![],
            alias_dependencies: vec![],
            tarball: Some("https://e.com/bad.tgz".to_string()),
        });
        match lf.to_toml() {
            Err(LockfileError::InvalidTarballHint { package }) => {
                assert_eq!(package, "bad-pkg", "writer guard should name the offender");
            }
            other => panic!("expected InvalidTarballHint, got {other:?}"),
        }
    }

    #[test]
    fn writer_guard_prevents_serialization_of_conflated_shape() {
        // Defense-in-depth: the writer guard means a conflated
        // Lockfile in memory can never be persisted, so the
        // reader-side gate is genuinely the last line of defense
        // against external corruption (hand-edits, CI tampering),
        // not a fallback for our own writer.
        let mut lf = Lockfile::new();
        lf.add_package(pkg_with_source_and_tarball(
            Some("tarball+https://e.com/foo.tgz"),
            Some("https://e.com/foo.tgz"),
        ));
        // to_toml fails.
        assert!(lf.to_toml().is_err());
        // write_to_file (which calls to_toml) also fails — and must
        // not leak partial state.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("lpm.lock");
        let result = lf.write_to_file(&path);
        assert!(
            result.is_err(),
            "write_to_file must fail on conflated shape"
        );
        assert!(
            !path.exists(),
            "no lockfile must be written when guard fires"
        );
    }

    // ── Phase 59.0 day-7: cross-source identity (PackageKey) ────────────────

    #[test]
    fn package_key_distinguishes_cross_source_same_name_version() {
        // Registry react@19.0.0 and Tarball react@19.0.0 must
        // produce distinct PackageKeys — that's the audit's
        // HIGH-1 collision case being structurally prevented.
        let reg = LockedPackage {
            name: "react".to_string(),
            version: "19.0.0".to_string(),
            source: Some("registry+https://registry.npmjs.org".to_string()),
            integrity: None,
            dependencies: vec![],
            alias_dependencies: vec![],
            tarball: None,
        };
        let tar = LockedPackage {
            name: "react".to_string(),
            version: "19.0.0".to_string(),
            source: Some("tarball+https://e.com/forks-of-react.tgz".to_string()),
            integrity: None,
            dependencies: vec![],
            alias_dependencies: vec![],
            tarball: None,
        };

        let reg_key = reg.package_key();
        let tar_key = tar.package_key();
        assert_eq!(reg_key.name, "react");
        assert_eq!(reg_key.version, "19.0.0");
        assert_eq!(tar_key.name, "react");
        assert_eq!(tar_key.version, "19.0.0");
        assert_ne!(reg_key.source_id, tar_key.source_id);
        assert_ne!(reg_key, tar_key);
    }

    #[test]
    fn package_key_uses_unknown_sentinel_when_source_missing() {
        let pkg = LockedPackage {
            name: "foo".to_string(),
            version: "1.0.0".to_string(),
            source: None,
            integrity: None,
            dependencies: vec![],
            alias_dependencies: vec![],
            tarball: None,
        };
        assert_eq!(pkg.package_key().source_id, PackageKey::UNKNOWN_SOURCE_ID);
    }

    #[test]
    fn add_package_sorts_cross_source_collisions_by_triple() {
        // Two packages with same (name, version) but different sources
        // must coexist in the Vec, sorted deterministically by the
        // (name, version, source_id) triple. Pre-Day-7's name-only
        // sort would have either dropped one or returned ambiguous
        // ordering on insert.
        let mut lf = Lockfile::new();
        lf.add_package(LockedPackage {
            name: "react".to_string(),
            version: "19.0.0".to_string(),
            source: Some("tarball+https://e.com/forks-of-react.tgz".to_string()),
            integrity: None,
            dependencies: vec![],
            alias_dependencies: vec![],
            tarball: None,
        });
        lf.add_package(LockedPackage {
            name: "react".to_string(),
            version: "19.0.0".to_string(),
            source: Some("registry+https://registry.npmjs.org".to_string()),
            integrity: None,
            dependencies: vec![],
            alias_dependencies: vec![],
            tarball: None,
        });

        // Both packages preserved.
        assert_eq!(lf.packages.len(), 2);
        // Sort order: registry's source_id starts with "npm-",
        // tarball's with "t-" — "npm-" < "t-" in ASCII order, so
        // registry first.
        assert!(
            lf.packages[0]
                .source
                .as_deref()
                .unwrap()
                .starts_with("registry+")
        );
        assert!(
            lf.packages[1]
                .source
                .as_deref()
                .unwrap()
                .starts_with("tarball+")
        );
    }

    #[test]
    fn find_package_by_key_disambiguates_cross_source_collisions() {
        let mut lf = Lockfile::new();
        let registry_pkg = LockedPackage {
            name: "react".to_string(),
            version: "19.0.0".to_string(),
            source: Some("registry+https://registry.npmjs.org".to_string()),
            integrity: Some("sha512-AAAAAAAAAA==".to_string()),
            dependencies: vec![],
            alias_dependencies: vec![],
            tarball: None,
        };
        let tarball_pkg = LockedPackage {
            name: "react".to_string(),
            version: "19.0.0".to_string(),
            source: Some("tarball+https://e.com/forks-of-react.tgz".to_string()),
            integrity: Some("sha512-BBBBBBBBBB==".to_string()),
            dependencies: vec![],
            alias_dependencies: vec![],
            tarball: None,
        };
        let reg_key = registry_pkg.package_key();
        let tar_key = tarball_pkg.package_key();
        lf.add_package(registry_pkg);
        lf.add_package(tarball_pkg);

        // find_package_by_key returns the EXACT match, never the
        // wrong sibling under collision.
        let by_reg = lf
            .find_package_by_key(&reg_key)
            .expect("registry must be findable");
        assert!(
            by_reg.source.as_deref().unwrap().starts_with("registry+"),
            "find_package_by_key(registry-key) must return the registry pkg, not the tarball one"
        );
        assert_eq!(by_reg.integrity.as_deref(), Some("sha512-AAAAAAAAAA=="));

        let by_tar = lf
            .find_package_by_key(&tar_key)
            .expect("tarball must be findable");
        assert!(by_tar.source.as_deref().unwrap().starts_with("tarball+"));
        assert_eq!(by_tar.integrity.as_deref(), Some("sha512-BBBBBBBBBB=="));
    }

    #[test]
    fn legacy_find_package_returns_a_match_under_collision_but_audit_warns() {
        // Documents the pre-existing name-only behavior: returns
        // *some* match but doesn't disambiguate. Callers that need
        // disambiguation must use find_package_by_key (Day 7).
        let mut lf = Lockfile::new();
        lf.add_package(LockedPackage {
            name: "react".to_string(),
            version: "19.0.0".to_string(),
            source: Some("registry+https://registry.npmjs.org".to_string()),
            integrity: None,
            dependencies: vec![],
            alias_dependencies: vec![],
            tarball: None,
        });
        lf.add_package(LockedPackage {
            name: "react".to_string(),
            version: "19.0.0".to_string(),
            source: Some("tarball+https://e.com/forks-of-react.tgz".to_string()),
            integrity: None,
            dependencies: vec![],
            alias_dependencies: vec![],
            tarball: None,
        });
        // Returns *some* react entry. Don't depend on which one.
        let found = lf.find_package("react");
        assert!(found.is_some());
    }
}
