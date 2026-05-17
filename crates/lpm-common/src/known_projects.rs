//! Machine-global registry of project directories
//! that have completed an `lpm install`.
//!
//! Lives at `~/.lpm/known-projects.json` (resolved through
//! [`crate::LpmRoot::known_projects`]) and feeds
//! [`lpm cache prune`](../../lpm-cli/src/commands/cache.rs) the root set
//! for v2-store orphan reachability.
//!
//! ## On-disk shape
//!
//! ```json
//! {
//!   "version": 1,
//!   "projects": [
//!     { "path": "/Users/tolga/Documents/Projects/foo", "last_seen": "2026-05-07T22:00:00Z" }
//!   ]
//! }
//! ```
//!
//! Paths are stored canonicalized (`std::fs::canonicalize`) so symlink-cwd
//! quirks and `~/`-relative variations don't accumulate aliased entries.
//! `last_seen` is set by [`register`] on every successful install (and
//! refreshed when an existing entry is re-registered). It is **not**
//! read by `lpm cache prune --max-age` — that filter operates on each
//! v2 link entry's `last_referenced_at` sidecar field. The registry
//! `last_seen` exists so future workflows that want to expire stale
//! root entries (e.g., `--gc-registry`) have a basis to filter on.
//!
//! ## Atomic rewrite contract
//!
//! All writes go through a `<path>.tmp.<pid>` staging file then
//! `rename` into place. Concurrent writers serialize naturally — a
//! second writer overwrites the first's atomic-final result; no
//! partial-write corruption is observable. Readers see either the old
//! file or the new file.
//!
//! ## Missing / unreadable registry policy
//!
//! Two helpers, two postures:
//!
//! - [`load`] is **lossy** — collapses missing-file, malformed-JSON,
//!   and schema-mismatch all to an empty [`Registry`]. Used by the
//!   install pipeline's `register()` path: the registry is a
//!   performance + UX cache there, not load-bearing, and a degraded
//!   file must never block a successful install. The next install
//!   rebuilds the file from scratch.
//!
//! - [`try_load`] surfaces specific failure modes via [`LoadError`].
//!   Used by `lpm cache prune` so a corrupt registry can be detected
//!   and treated as "no usable roots" rather than silently as "no
//!   registered projects" — the latter would mark every link entry as
//!   orphaned and wipe the live store under `--apply`.
//!
//! `lpm cache prune` degrades to **tombstone-only mode** whenever the
//! registry is unusable AND no `--project <path>` argument was
//! supplied — covering `NotFound`, `MalformedJson`, `SchemaMismatch`,
//! and `Io` outcomes from [`try_load`]. Orphan detection is skipped
//! (no roots → unsafe), but the global-install tombstone sweep still
//! runs under `--apply` so `lpm uninstall -g`'s deferred cleanup
//! retry remains reachable without a populated registry. The corrupt
//! variants emit an actionable warning naming the failure reason; the
//! missing variant emits a fresh-machine-state warning.

use crate::LpmError;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Schema version for [`Registry`]. Bump when the on-disk JSON shape
/// changes incompatibly. [`load`] silently drops files whose `version`
/// doesn't match — keeping the predicate "missing or wrong" → empty
/// registry rather than risking a parse error on upgrade-in-place users.
pub const REGISTRY_VERSION: u32 = 1;

/// Top-level on-disk shape.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct Registry {
    /// Schema version. Always [`REGISTRY_VERSION`] for files this
    /// build of lpm writes.
    pub version: u32,
    /// One entry per project directory that has ever completed an
    /// `lpm install`. Order is not significant on disk; the writer
    /// sorts by `path` for deterministic file content (helps human
    /// review and `git diff` if a user accidentally checks the
    /// registry into a dotfiles repo).
    pub projects: Vec<Entry>,
}

/// One registered project.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Entry {
    /// Canonicalized absolute path to the project root. Stored
    /// canonical (not user-typed) so symlink-cwd accumulations don't
    /// produce duplicate aliased entries.
    pub path: PathBuf,
    /// When [`register`] last touched this entry (initial registration
    /// or re-registration on a subsequent successful install). Not read
    /// by `lpm cache prune --max-age` (that filter operates on link-
    /// entry sidecar timestamps); reserved for future registry-GC
    /// workflows.
    pub last_seen: DateTime<Utc>,
}

impl Registry {
    /// Construct an empty registry at the current schema version.
    pub fn new() -> Self {
        Self {
            version: REGISTRY_VERSION,
            projects: Vec::new(),
        }
    }
}

/// Specific failure modes for [`try_load`]. The install pipeline uses
/// the lossy [`load`] helper because a degraded registry must never
/// block a successful install. `lpm cache prune --apply` uses
/// [`try_load`] because treating a corrupt registry as an empty root
/// set would mark every link entry as orphaned and wipe the live
/// store on the next apply — distinguishing the failure modes is
/// load-bearing for safety there.
#[derive(Debug)]
pub enum LoadError {
    /// The registry file does not exist at the given path. Normal on a
    /// fresh machine; callers that want to gate on this state should
    /// match it explicitly.
    NotFound,
    /// The file exists but `serde_json` couldn't parse it. Indicates
    /// disk corruption or a hand-edit gone wrong.
    MalformedJson,
    /// The file parses as JSON but its `version` field doesn't match
    /// [`REGISTRY_VERSION`]. Indicates a schema downgrade or a future
    /// build wrote it.
    SchemaMismatch,
    /// `std::fs::read` failed for a reason other than `NotFound`
    /// (permissions, I/O error, etc.).
    Io(std::io::Error),
}

impl std::fmt::Display for LoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LoadError::NotFound => write!(f, "registry file does not exist"),
            LoadError::MalformedJson => write!(f, "registry file is not valid JSON"),
            LoadError::SchemaMismatch => write!(f, "registry file has unknown schema version"),
            LoadError::Io(e) => write!(f, "registry file unreadable: {e}"),
        }
    }
}

/// Load the registry from the supplied path. **Lossy** — see [`load`]'s
/// rationale. Use [`try_load`] when the caller needs to distinguish
/// missing-from-corrupt.
///
/// Returns `Ok(Registry::new())` (empty + current schema) on:
/// - File doesn't exist.
/// - File is malformed JSON.
/// - File has a `version` other than [`REGISTRY_VERSION`].
///
/// The "best-effort" posture is intentional — the registry is a
/// performance + UX cache, not a load-bearing data structure for the
/// install pipeline. Real errors here would block every install on
/// every machine that ever shipped a buggy registry write; instead we
/// degrade silently and rebuild on the next successful install.
pub fn load(path: &Path) -> Registry {
    try_load(path).unwrap_or_else(|_| Registry::new())
}

/// Load the registry, surfacing specific failure modes via [`LoadError`].
///
/// Used by `lpm cache prune` so a corrupted registry can be detected
/// and treated as "no usable roots" rather than silently as "no
/// registered projects" — the latter would mark every link entry as
/// orphaned and wipe the live store under `--apply`.
pub fn try_load(path: &Path) -> Result<Registry, LoadError> {
    let bytes = match crate::read_capped_state_file(path, crate::STATE_FILE_SIZE_CAP_BYTES) {
        Ok(Some(b)) => b,
        Ok(None) => return Err(LoadError::NotFound),
        Err(e) => return Err(LoadError::Io(e)),
    };
    match serde_json::from_slice::<Registry>(&bytes) {
        Ok(r) if r.version == REGISTRY_VERSION => Ok(r),
        Ok(_) => Err(LoadError::SchemaMismatch),
        Err(_) => Err(LoadError::MalformedJson),
    }
}

/// Write `registry` to `path` atomically via `<path>.tmp.<pid>` →
/// `rename`. Sorts `projects` by canonical path before serializing so
/// the on-disk file is deterministic (helps human review and a
/// dotfiles-checked-in registry's `git diff`).
///
/// Creates the parent directory if missing.
///
/// Returns [`LpmError::Io`] if the write or rename fails. Callers in
/// the install pipeline log + continue (the registry is non-load-
/// bearing); callers in `lpm cache prune --apply` propagate the
/// error so the user sees an actionable failure.
pub fn write(path: &Path, registry: &Registry) -> Result<(), LpmError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut sorted = registry.clone();
    sorted.projects.sort_by(|a, b| a.path.cmp(&b.path));
    let bytes = serde_json::to_vec_pretty(&sorted).map_err(|e| {
        LpmError::Io(std::io::Error::other(format!(
            "known-projects: failed to serialize registry: {e}"
        )))
    })?;
    let tmp = path.with_extension(format!("tmp.{}", std::process::id()));
    std::fs::write(&tmp, &bytes)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// Add or refresh `project_dir` in the registry, updating
/// `last_seen` to the current UTC time. `project_dir` is canonicalized
/// internally — callers can pass any user-typed path and the registry
/// stays canonical.
///
/// Idempotent: a project already in the registry has its `last_seen`
/// bumped; a new project is appended. The combined set is then
/// atomically rewritten.
///
/// Returns the [`Entry`] that was registered (post-canonicalize). The
/// caller can `.path` it for downstream "where did we register this?"
/// telemetry without re-canonicalizing.
///
/// Failures during canonicalize, load, or write surface as
/// [`LpmError`] — but the install pipeline's call site logs + drops the
/// error so a flaky registry write never blocks a successful install.
pub fn register(path: &Path, project_dir: &Path) -> Result<Entry, LpmError> {
    let canonical = std::fs::canonicalize(project_dir).map_err(|e| {
        LpmError::Io(std::io::Error::new(
            e.kind(),
            format!(
                "known-projects: failed to canonicalize {}: {e}",
                project_dir.display()
            ),
        ))
    })?;
    let mut registry = load(path);
    let now = Utc::now();
    if let Some(existing) = registry.projects.iter_mut().find(|e| e.path == canonical) {
        existing.last_seen = now;
        let entry = existing.clone();
        write(path, &registry)?;
        return Ok(entry);
    }
    let entry = Entry {
        path: canonical.clone(),
        last_seen: now,
    };
    registry.projects.push(entry.clone());
    write(path, &registry)?;
    Ok(entry)
}

/// Drop entries whose `path` no longer exists on disk. Returns the
/// number of dropped entries. Used by `lpm cache prune` during the
/// registry-sweep step: if the path doesn't exist on disk, silently
/// drop the entry from the registry.
///
/// Atomically rewrites the registry on disk if any entries were
/// dropped; if none were dropped, the disk file is untouched.
pub fn drop_missing(path: &Path) -> Result<usize, LpmError> {
    let mut registry = load(path);
    let before = registry.projects.len();
    registry.projects.retain(|e| e.path.exists());
    let dropped = before - registry.projects.len();
    if dropped > 0 {
        write(path, &registry)?;
    }
    Ok(dropped)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn load_returns_empty_when_missing() {
        let dir = tempdir().unwrap();
        let r = load(&dir.path().join("does-not-exist.json"));
        assert_eq!(r.version, REGISTRY_VERSION);
        assert!(r.projects.is_empty());
    }

    #[test]
    fn load_returns_empty_on_malformed_json() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("known-projects.json");
        std::fs::write(&path, b"{not json").unwrap();
        let r = load(&path);
        assert!(r.projects.is_empty());
    }

    #[test]
    fn load_returns_empty_on_unknown_schema_version() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("known-projects.json");
        std::fs::write(&path, br#"{"version": 999, "projects": []}"#).unwrap();
        let r = load(&path);
        assert_eq!(r.version, REGISTRY_VERSION);
        assert!(r.projects.is_empty());
    }

    #[test]
    fn register_canonicalizes_and_dedupes() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("known-projects.json");

        let project = dir.path().join("project-a");
        std::fs::create_dir_all(&project).unwrap();

        let first = register(&path, &project).unwrap();
        let second = register(&path, &project).unwrap();
        assert_eq!(first.path, second.path);
        // Same canonical path → registry holds one entry, not two.
        let r = load(&path);
        assert_eq!(r.projects.len(), 1);
    }

    #[test]
    fn register_via_symlink_canonicalizes_to_realpath() {
        #[cfg(unix)]
        {
            let dir = tempdir().unwrap();
            let path = dir.path().join("known-projects.json");
            let real = dir.path().join("real-project");
            std::fs::create_dir_all(&real).unwrap();
            let alias = dir.path().join("alias-link");
            std::os::unix::fs::symlink(&real, &alias).unwrap();

            register(&path, &alias).unwrap();
            register(&path, &real).unwrap();

            // Both calls resolved to the same canonical path → one entry.
            let r = load(&path);
            assert_eq!(r.projects.len(), 1);
        }
    }

    #[test]
    fn register_bumps_last_seen() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("known-projects.json");
        let project = dir.path().join("p");
        std::fs::create_dir_all(&project).unwrap();

        let first = register(&path, &project).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(2));
        let second = register(&path, &project).unwrap();
        assert!(second.last_seen >= first.last_seen);
    }

    #[test]
    fn write_is_atomic_no_tmp_lingers() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("known-projects.json");
        let mut r = Registry::new();
        r.projects.push(Entry {
            path: PathBuf::from("/dev/null/synthetic"),
            last_seen: Utc::now(),
        });
        write(&path, &r).unwrap();

        let entries: Vec<String> = std::fs::read_dir(dir.path())
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().to_string())
            .collect();
        assert_eq!(entries, vec!["known-projects.json".to_string()]);
    }

    #[test]
    fn drop_missing_removes_dead_entries() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("known-projects.json");

        let alive = dir.path().join("alive");
        std::fs::create_dir_all(&alive).unwrap();
        let dead = dir.path().join("dead");

        let mut r = Registry::new();
        r.projects.push(Entry {
            path: alive.clone(),
            last_seen: Utc::now(),
        });
        r.projects.push(Entry {
            path: dead.clone(),
            last_seen: Utc::now(),
        });
        write(&path, &r).unwrap();

        let dropped = drop_missing(&path).unwrap();
        assert_eq!(dropped, 1);
        let r = load(&path);
        assert_eq!(r.projects.len(), 1);
        assert_eq!(r.projects[0].path, alive);
    }

    #[test]
    fn drop_missing_returns_zero_when_all_alive() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("known-projects.json");
        let alive = dir.path().join("alive");
        std::fs::create_dir_all(&alive).unwrap();
        let mut r = Registry::new();
        r.projects.push(Entry {
            path: alive,
            last_seen: Utc::now(),
        });
        write(&path, &r).unwrap();

        let dropped = drop_missing(&path).unwrap();
        assert_eq!(dropped, 0);
    }

    #[test]
    fn write_sorts_projects_by_path() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("known-projects.json");
        let mut r = Registry::new();
        r.projects.push(Entry {
            path: PathBuf::from("/z/zeta"),
            last_seen: Utc::now(),
        });
        r.projects.push(Entry {
            path: PathBuf::from("/a/alpha"),
            last_seen: Utc::now(),
        });
        r.projects.push(Entry {
            path: PathBuf::from("/m/middle"),
            last_seen: Utc::now(),
        });
        write(&path, &r).unwrap();

        let r2 = load(&path);
        let paths: Vec<&str> = r2
            .projects
            .iter()
            .map(|e| e.path.to_str().unwrap())
            .collect();
        assert_eq!(paths, vec!["/a/alpha", "/m/middle", "/z/zeta"]);
    }
}
