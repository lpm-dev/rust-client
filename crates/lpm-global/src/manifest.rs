//! `~/.lpm/global/manifest.toml` — schema, atomic read/write.
//!
//! The manifest is the authoritative record of every globally-installed
//! package on a host. Phase 37 introduces three top-level tables besides
//! the schema version field:
//!
//! - `[packages.<name>]` — currently active installations. One row per
//!   package name. The version exposed on PATH is `packages.<name>.resolved`.
//! - `[pending.<name>]` — in-flight upgrades / installs. Lives alongside
//!   the active row during the slow extract / link phase so the user's
//!   shell keeps resolving the old version. Flipped into `[packages]` on
//!   commit, removed on rollback.
//! - `[aliases.<command>]` — explicit command-name overrides written
//!   when the user resolves a collision (`--alias` flag or interactive
//!   `Install new package under an alias`). The alias is the key; the
//!   value names the owning package and its declared bin entry.
//! - `tombstones = ["installs/..."]` — old install roots whose deletion
//!   is deferred outside the `.tx.lock` critical section so a Windows
//!   `tsc --watch` holding files in the old root doesn't trap the user
//!   in a recovery crash loop. Swept by `lpm store gc` and the post-commit
//!   janitor.
//!
//! ## Atomic write contract
//!
//! Writes go through [`write_manifest`], which serialises to TOML and
//! renames a tempfile in the manifest's parent directory over the live
//! file. POSIX rename is atomic on the same filesystem; on Windows the
//! `MoveFileEx`-backed `std::fs::rename` is functionally equivalent for
//! this size of file. **Callers are responsible for serialising
//! manifest mutations through the global `.tx.lock`** (see plan §M3).
//! `write_manifest` itself only guarantees that observers always see a
//! complete manifest, never a half-written one.
//!
//! ## Schema versioning
//!
//! `schema_version` is a `u32`. Readers tolerate unknown fields (serde
//! default) so additive changes don't break older binaries; bumps are
//! reserved for breaking changes. M2 ships v1.

use chrono::{DateTime, Utc};
use lpm_common::{LpmError, LpmRoot};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;

pub const SCHEMA_VERSION: u32 = 1;
pub const MANIFEST_FILENAME: &str = "manifest.toml";

/// Top-level shape of `~/.lpm/global/manifest.toml`.
///
/// `BTreeMap` (rather than `HashMap`) so on-disk ordering is deterministic
/// — important for diffability when a future reviewer wants to see what
/// changed between two installs.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GlobalManifest {
    pub schema_version: u32,

    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub packages: BTreeMap<String, PackageEntry>,

    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub pending: BTreeMap<String, PendingEntry>,

    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub aliases: BTreeMap<String, AliasEntry>,

    /// Install roots queued for deletion outside the tx-lock critical
    /// section. Stored as relative paths under `~/.lpm/global/` (the
    /// `installs/<name>@<ver>` shape), so the manifest remains portable
    /// across hosts with different `$LPM_HOME` locations even though
    /// portability is not a v1 goal.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tombstones: Vec<String>,
}

impl Default for GlobalManifest {
    fn default() -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            packages: BTreeMap::new(),
            pending: BTreeMap::new(),
            aliases: BTreeMap::new(),
            tombstones: Vec::new(),
        }
    }
}

/// One active global install.
///
/// `saved_spec` is what would have been written into a project's
/// `package.json` if this were a project dep — i.e. the output of Phase
/// 33's `decide_saved_dependency_spec`. It is **not** the resolved
/// version. `lpm global update <pkg>` re-resolves against this string
/// using exactly the same precedence as `lpm install` in a project.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PackageEntry {
    /// Phase 33 `spec_to_write` output. Stored verbatim. Examples:
    /// `"^9"`, `"~5.8"`, `"14.2.0"`, `"*"`.
    pub saved_spec: String,
    /// Resolved version installed at this row's creation time.
    pub resolved: String,
    /// SRI integrity hash of the package tarball.
    pub integrity: String,
    /// `"lpm-dev"` for first-party packages, `"upstream-npm"` for the
    /// proxied npm ecosystem. Determines which registry path
    /// `lpm global update` queries on re-resolution.
    pub source: PackageSource,
    /// When the install committed.
    pub installed_at: DateTime<Utc>,
    /// Path relative to `~/.lpm/global/` — typically `"installs/<name>@<ver>"`.
    pub root: String,
    /// Command names this install owns on PATH, in declaration order.
    /// Aliased commands appear under `[aliases]`, not here.
    pub commands: Vec<String>,
}

/// In-flight install or upgrade row.
///
/// Identical to [`PackageEntry`] aside from `started_at` (instead of
/// `installed_at`) and `replaces_version`, which records the prior
/// active version for rollback. On commit, the corresponding
/// `PackageEntry` is written from this row's fields and `[pending]` is
/// cleared.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PendingEntry {
    pub saved_spec: String,
    pub resolved: String,
    pub integrity: String,
    pub source: PackageSource,
    pub started_at: DateTime<Utc>,
    pub root: String,
    pub commands: Vec<String>,
    /// `Some(prior_version)` for upgrades / reinstalls; `None` for fresh
    /// installs. Recovery uses this to decide whether to roll back to a
    /// prior active row or simply remove the pending row.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replaces_version: Option<String>,
}

/// Explicit command-name override. Written during collision resolution
/// when a user runs `--alias <orig>=<alias>` or picks "Install under
/// alias" from the interactive prompt. The owning package's
/// `PackageEntry.commands` keeps the package's *declared* bin name; this
/// table maps the *exposed* name on PATH to that package + bin.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AliasEntry {
    pub package: String,
    pub bin: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum PackageSource {
    /// First-party `@lpm.dev/*` package.
    LpmDev,
    /// Proxied npm-ecosystem package.
    UpstreamNpm,
}

// ─── Read / write ─────────────────────────────────────────────────────

/// Parse the manifest at `path`. Returns [`GlobalManifest::default`] when
/// the file does not exist — that is the legitimate "fresh install" state
/// and is not an error.
///
/// Schema-version mismatches that *exceed* what this binary understands
/// are surfaced as an error rather than silently downgraded; a user
/// running an older `lpm` against a newer manifest should be told to
/// upgrade rather than corrupt their state.
pub fn read_manifest(path: &Path) -> Result<GlobalManifest, LpmError> {
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(GlobalManifest::default());
        }
        Err(e) => return Err(LpmError::Io(e)),
    };
    let text = std::str::from_utf8(&bytes)
        .map_err(|e| manifest_parse_error(format!("manifest is not valid UTF-8: {e}")))?;
    let manifest: GlobalManifest = toml::from_str(text)
        .map_err(|e| manifest_parse_error(format!("manifest TOML parse error: {e}")))?;
    if manifest.schema_version > SCHEMA_VERSION {
        return Err(manifest_parse_error(format!(
            "manifest schema_version {} is newer than this binary supports ({}). Upgrade lpm to read it.",
            manifest.schema_version, SCHEMA_VERSION
        )));
    }
    Ok(manifest)
}

/// Read the manifest at the canonical location for `root`.
pub fn read_for(root: &LpmRoot) -> Result<GlobalManifest, LpmError> {
    read_manifest(&root.global_manifest())
}

/// Atomically write `manifest` to `path` via tempfile + rename.
///
/// The tempfile is created in the same directory as `path` so the rename
/// is guaranteed to be on the same filesystem (cross-fs renames degrade
/// to copy-then-unlink, which is non-atomic). Caller must hold
/// `~/.lpm/global/.tx.lock` to serialise concurrent mutations — this
/// function only guarantees that observers see either the old or new
/// manifest, never a partial.
pub fn write_manifest(path: &Path, manifest: &GlobalManifest) -> Result<(), LpmError> {
    let parent = path
        .parent()
        .ok_or_else(|| manifest_parse_error("manifest path has no parent directory".to_string()))?;
    std::fs::create_dir_all(parent)?;

    let serialized = toml::to_string_pretty(manifest)
        .map_err(|e| manifest_parse_error(format!("manifest serialize error: {e}")))?;

    // Tempfile name includes the PID so two interleaved writers (which
    // shouldn't happen — caller must hold .tx.lock — but defence in
    // depth) can't clobber each other's tempfiles before either rename.
    let tmp_path = parent.join(format!(".{MANIFEST_FILENAME}.tmp.{}", std::process::id()));

    // Write + fsync the tempfile.
    {
        let mut tmp = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&tmp_path)?;
        std::io::Write::write_all(&mut tmp, serialized.as_bytes())?;
        tmp.sync_all()?;
    }

    // Rename into place (atomic on POSIX, MoveFileEx on Windows).
    if let Err(e) = std::fs::rename(&tmp_path, path) {
        // Best-effort cleanup so a failed rename doesn't leak debris.
        let _ = std::fs::remove_file(&tmp_path);
        return Err(LpmError::Io(e));
    }

    // fsync the parent directory so the rename itself survives a crash.
    // On Windows opening a directory as a file is not supported and the
    // rename's durability comes from the file system rather than an
    // explicit fsync; skip there.
    #[cfg(unix)]
    {
        if let Ok(parent_fd) = std::fs::File::open(parent) {
            let _ = parent_fd.sync_all();
        }
    }

    Ok(())
}

/// Write `manifest` to the canonical location for `root`.
pub fn write_for(root: &LpmRoot, manifest: &GlobalManifest) -> Result<(), LpmError> {
    write_manifest(&root.global_manifest(), manifest)
}

fn manifest_parse_error(msg: String) -> LpmError {
    LpmError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, msg))
}

// ─── Convenience accessors ────────────────────────────────────────────

impl GlobalManifest {
    /// True when the manifest holds neither active installs nor pending
    /// rows nor aliases — i.e. the global layer is unused on this host.
    pub fn is_empty(&self) -> bool {
        self.packages.is_empty() && self.pending.is_empty() && self.aliases.is_empty()
    }

    /// Set of every command name currently exposed on PATH. Union of all
    /// `packages.*.commands` and the keys of `[aliases]`. Used by collision
    /// detection at install time.
    pub fn exposed_commands(&self) -> std::collections::BTreeSet<String> {
        let mut out = std::collections::BTreeSet::new();
        for entry in self.packages.values() {
            for cmd in &entry.commands {
                out.insert(cmd.clone());
            }
        }
        for alias in self.aliases.keys() {
            out.insert(alias.clone());
        }
        out
    }

    /// Resolve a command name on PATH back to the owning package + the
    /// package's declared bin name. Returns `None` if no install exposes
    /// `command`. All borrows tie to `self` so the result outlives the
    /// input `command` slice.
    pub fn owner_of_command(&self, command: &str) -> Option<CommandOwner<'_>> {
        // Aliases take precedence — an alias is by construction the user's
        // explicit override.
        if let Some(alias) = self.aliases.get(command) {
            return Some(CommandOwner {
                package: alias.package.as_str(),
                bin: alias.bin.as_str(),
                via_alias: true,
            });
        }
        for (name, entry) in &self.packages {
            if let Some(bin) = entry.commands.iter().find(|c| c.as_str() == command) {
                return Some(CommandOwner {
                    package: name.as_str(),
                    bin: bin.as_str(),
                    via_alias: false,
                });
            }
        }
        None
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommandOwner<'a> {
    pub package: &'a str,
    pub bin: &'a str,
    /// True when the command was resolved via `[aliases]`, false when via
    /// the package's `commands` list directly.
    pub via_alias: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn sample_manifest() -> GlobalManifest {
        let mut m = GlobalManifest::default();
        m.packages.insert(
            "eslint".to_string(),
            PackageEntry {
                saved_spec: "^9".to_string(),
                resolved: "9.24.0".to_string(),
                integrity: "sha512-abc".to_string(),
                source: PackageSource::UpstreamNpm,
                installed_at: "2026-04-14T12:34:56Z".parse().unwrap(),
                root: "installs/eslint@9.24.0".to_string(),
                commands: vec!["eslint".to_string()],
            },
        );
        m.packages.insert(
            "@lpm.dev/owner.tool".to_string(),
            PackageEntry {
                saved_spec: "^1.2.0".to_string(),
                resolved: "1.2.0".to_string(),
                integrity: "sha512-xyz".to_string(),
                source: PackageSource::LpmDev,
                installed_at: "2026-04-14T12:35:00Z".parse().unwrap(),
                root: "installs/@lpm.dev+owner.tool@1.2.0".to_string(),
                commands: vec!["neo".to_string()],
            },
        );
        m.aliases.insert(
            "srv".to_string(),
            AliasEntry {
                package: "pkg-b".to_string(),
                bin: "serve".to_string(),
            },
        );
        m
    }

    #[test]
    fn default_manifest_is_v1_and_empty() {
        let m = GlobalManifest::default();
        assert_eq!(m.schema_version, SCHEMA_VERSION);
        assert!(m.is_empty());
    }

    #[test]
    fn round_trip_preserves_all_fields() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("manifest.toml");
        let original = sample_manifest();
        write_manifest(&path, &original).unwrap();
        let read = read_manifest(&path).unwrap();
        assert_eq!(original, read);
    }

    #[test]
    fn read_missing_file_returns_default() {
        let tmp = TempDir::new().unwrap();
        let m = read_manifest(&tmp.path().join("does-not-exist.toml")).unwrap();
        assert_eq!(m, GlobalManifest::default());
    }

    #[test]
    fn read_rejects_future_schema_version() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("manifest.toml");
        std::fs::write(&path, format!("schema_version = {}", SCHEMA_VERSION + 1)).unwrap();
        let err = read_manifest(&path).unwrap_err();
        assert!(format!("{err}").contains("newer than this binary supports"));
    }

    #[test]
    fn read_tolerates_unknown_fields_for_forward_compat() {
        // Additive schema changes must not break older binaries.
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("manifest.toml");
        std::fs::write(
            &path,
            r#"schema_version = 1
some_future_field = "ignored"

[packages."x"]
saved_spec = "1.0.0"
resolved = "1.0.0"
integrity = "sha512-z"
source = "lpm-dev"
installed_at = "2026-01-01T00:00:00Z"
root = "installs/x@1.0.0"
commands = ["x"]
mystery_field = 42
"#,
        )
        .unwrap();
        let m = read_manifest(&path).unwrap();
        assert_eq!(m.packages.len(), 1);
        assert!(m.packages.contains_key("x"));
    }

    #[test]
    fn write_creates_parent_dir() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("nested").join("dirs").join("manifest.toml");
        write_manifest(&path, &sample_manifest()).unwrap();
        assert!(path.is_file());
    }

    #[test]
    fn write_is_atomic_no_tempfile_leak_on_success() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("manifest.toml");
        write_manifest(&path, &sample_manifest()).unwrap();

        // No `.manifest.toml.tmp.*` debris should remain.
        let leaks: Vec<_> = std::fs::read_dir(tmp.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.file_name()
                    .to_string_lossy()
                    .starts_with(".manifest.toml.tmp.")
            })
            .collect();
        assert!(leaks.is_empty(), "tempfile leaked: {leaks:?}");
    }

    #[test]
    fn exposed_commands_unions_packages_and_aliases() {
        let m = sample_manifest();
        let cmds = m.exposed_commands();
        assert_eq!(cmds.len(), 3);
        assert!(cmds.contains("eslint"));
        assert!(cmds.contains("neo"));
        assert!(cmds.contains("srv"));
    }

    #[test]
    fn owner_of_command_resolves_packages() {
        let m = sample_manifest();
        let owner = m.owner_of_command("eslint").unwrap();
        assert_eq!(owner.package, "eslint");
        assert_eq!(owner.bin, "eslint");
        assert!(!owner.via_alias);
    }

    #[test]
    fn owner_of_command_resolves_aliases_with_via_alias_set() {
        let m = sample_manifest();
        let owner = m.owner_of_command("srv").unwrap();
        assert_eq!(owner.package, "pkg-b");
        assert_eq!(owner.bin, "serve");
        assert!(owner.via_alias);
    }

    #[test]
    fn owner_of_command_returns_none_for_unknown() {
        let m = sample_manifest();
        assert!(m.owner_of_command("does-not-exist").is_none());
    }

    #[test]
    fn empty_optional_fields_are_omitted_from_serialized_form() {
        let m = GlobalManifest::default();
        let s = toml::to_string_pretty(&m).unwrap();
        assert!(!s.contains("packages"));
        assert!(!s.contains("pending"));
        assert!(!s.contains("aliases"));
        assert!(!s.contains("tombstones"));
    }

    #[test]
    fn pending_entry_replaces_version_round_trips() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("manifest.toml");
        let mut m = GlobalManifest::default();
        m.pending.insert(
            "eslint".to_string(),
            PendingEntry {
                saved_spec: "^9.25".to_string(),
                resolved: "9.25.0".to_string(),
                integrity: "sha512-new".to_string(),
                source: PackageSource::UpstreamNpm,
                started_at: "2026-04-14T13:00:00Z".parse().unwrap(),
                root: "installs/eslint@9.25.0".to_string(),
                commands: vec!["eslint".to_string()],
                replaces_version: Some("9.24.0".to_string()),
            },
        );
        write_manifest(&path, &m).unwrap();
        let read = read_manifest(&path).unwrap();
        assert_eq!(
            read.pending.get("eslint").unwrap().replaces_version,
            Some("9.24.0".to_string())
        );
    }

    #[test]
    fn read_for_uses_canonical_location() {
        let tmp = TempDir::new().unwrap();
        let root = LpmRoot::from_dir(tmp.path());
        write_for(&root, &sample_manifest()).unwrap();
        let read = read_for(&root).unwrap();
        assert_eq!(read.packages.len(), 2);
    }
}
