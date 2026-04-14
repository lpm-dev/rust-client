//! `lpm dlx` — utilities for running packages without installing them.
//!
//! Cache management, package name parsing, and binary execution.
//! The install step is handled in the CLI layer (self-hosted via LPM's resolver/store/linker).

use crate::bin_path;
use lpm_common::{LpmError, LpmRoot};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Once;

/// Default cache TTL in seconds (24 hours).
pub const CACHE_TTL_SECS: u64 = 24 * 60 * 60;

static DLX_LEGACY_MIGRATION: Once = Once::new();

/// Get the dlx cache directory for a given package spec.
///
/// Returns `~/.lpm/cache/dlx/{hash}/` (phase 37: moved from the pre-phase-37
/// location `~/.lpm/dlx-cache/` so all caches live under `~/.lpm/cache/`).
///
/// The first call after an upgrade silently migrates the legacy location by
/// renaming `~/.lpm/dlx-cache/` to `~/.lpm/cache/dlx/` when only the legacy
/// exists. The migration is idempotent: subsequent calls observe the
/// modern location and do nothing. See [`migrate_legacy_dlx_cache`] for
/// full semantics.
pub fn dlx_cache_dir(package_spec: &str) -> Result<PathBuf, LpmError> {
    let root = LpmRoot::from_env()
        .map_err(|e| LpmError::Script(format!("could not determine LPM home: {e}")))?;

    // Run the one-shot migration exactly once per process. If the migration
    // itself fails we log and continue — an inability to move the legacy
    // directory should not block dlx from working against the modern one.
    DLX_LEGACY_MIGRATION.call_once(|| {
        if let Err(e) = migrate_legacy_dlx_cache(&root) {
            tracing::warn!("dlx legacy cache migration failed (non-fatal): {e}");
        }
    });

    // Proactive sweep: before resolving the requested spec, drop any dlx
    // entries older than the TTL. Phase 37 addresses the unbounded-growth
    // concern — without this, a user who runs `lpm dlx cowsay` once and
    // never again never triggers cleanup for that entry. The sweep is
    // cheap: one `read_dir` + one `stat` per direct child, no registry
    // traffic.
    if let Err(e) = sweep_stale_dlx_entries(&root, CACHE_TTL_SECS) {
        tracing::debug!("dlx proactive sweep failed (non-fatal): {e}");
    }

    Ok(dlx_cache_dir_at(&root, package_spec))
}

/// Remove every direct child of `~/.lpm/cache/dlx/` whose `package.json`
/// is older than `ttl_secs`. Entries without a `package.json` (partial
/// installs, stray files) are left alone — they're either in-flight work
/// or not ours to touch. Failures on individual entries are logged and
/// swallowed; one stuck entry must not block cleanup of the others.
pub fn sweep_stale_dlx_entries(root: &LpmRoot, ttl_secs: u64) -> Result<usize, LpmError> {
    let dlx_root = root.cache_dlx();
    if !dlx_root.is_dir() {
        return Ok(0);
    }

    let now = std::time::SystemTime::now();
    let ttl = std::time::Duration::from_secs(ttl_secs);
    let mut removed = 0usize;

    for entry in std::fs::read_dir(&dlx_root)? {
        let Ok(entry) = entry else { continue };
        let path = entry.path();

        // We only sweep cache dirs — skip files, symlinks, and anything
        // that isn't a regular directory at the top level.
        if !entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
            continue;
        }

        let pkg_json = path.join("package.json");
        let Ok(meta) = std::fs::metadata(&pkg_json) else {
            // No `package.json` → not a recognized cache entry. Leave it
            // alone; it might be an in-flight install or stray debris
            // someone will want to investigate.
            continue;
        };
        let Ok(mtime) = meta.modified() else {
            continue;
        };
        let age = match now.duration_since(mtime) {
            Ok(d) => d,
            Err(_) => continue, // clock skew: mtime in the future. Leave it.
        };
        if age < ttl {
            continue;
        }

        match std::fs::remove_dir_all(&path) {
            Ok(()) => {
                removed += 1;
                tracing::debug!("dlx sweep: removed stale entry {}", path.display());
            }
            Err(e) => {
                tracing::debug!(
                    "dlx sweep: failed to remove {} (continuing): {}",
                    path.display(),
                    e
                );
            }
        }
    }

    Ok(removed)
}

/// Pure function mapping `(root, spec) -> cache entry path`. No filesystem
/// I/O, no environment reads, no migration side effect. Tests that only
/// care about path composition (stability, collision-freeness) should call
/// this with a temp-rooted [`LpmRoot`] rather than [`dlx_cache_dir`], which
/// would otherwise trigger the process-wide migration against the
/// developer's real `$HOME` / `$LPM_HOME`.
pub fn dlx_cache_dir_at(root: &LpmRoot, package_spec: &str) -> PathBuf {
    let hash = deterministic_hash(package_spec);
    root.cache_dlx().join(hash)
}

/// Heuristic completeness check for a dlx cache entry.
///
/// A dlx install is treated as complete only when both markers from
/// [`is_cache_fresh`] are present: a parsable `package.json` and a
/// `node_modules/.bin` directory. If the directory exists but either
/// marker is missing, the install was interrupted — treat the entry as
/// unusable so the migration does not prefer it over a complete legacy
/// copy on collision.
fn dlx_entry_appears_complete(entry: &Path) -> bool {
    entry.join("package.json").is_file() && entry.join("node_modules").join(".bin").is_dir()
}

/// Idempotent one-shot migration from `~/.lpm/dlx-cache/` to
/// `~/.lpm/cache/dlx/`.
///
/// Behavior matrix (legacy = `~/.lpm/dlx-cache/`, modern = `~/.lpm/cache/dlx/`):
///
/// | legacy exists? | modern exists? | action                                |
/// |----------------|----------------|---------------------------------------|
/// | no             | any            | no-op                                 |
/// | yes            | no             | rename legacy → modern                |
/// | yes            | yes            | move each legacy child into modern,   |
/// |                |                | then remove legacy dir                |
///
/// The merge path is important for the rare case where a user installed
/// both a pre-phase-37 build (populating legacy) and a post-phase-37 build
/// (populating modern) before the migration ran — we must not lose either
/// side's entries. Children are moved by rename; if a name collision
/// occurs the modern entry wins (it's the freshest the process knows
/// about) and the legacy child is removed.
pub fn migrate_legacy_dlx_cache(root: &LpmRoot) -> Result<(), LpmError> {
    let legacy = root.legacy_dlx_cache();
    let modern = root.cache_dlx();

    if !legacy.is_dir() {
        return Ok(());
    }

    // Ensure the parent of `modern` (the cache root) exists so a rename
    // into it will succeed even on a fresh install.
    if let Some(parent) = modern.parent() {
        std::fs::create_dir_all(parent)?;
    }

    if !modern.exists() {
        // Fast path: single rename. Same-filesystem rename is atomic on
        // Unix and effectively-atomic on Windows for a directory that is
        // not held open.
        std::fs::rename(&legacy, &modern)?;
        tracing::info!(
            "migrated dlx cache: {} → {}",
            legacy.display(),
            modern.display()
        );
        return Ok(());
    }

    // Merge path: move each child from legacy into modern, then drop legacy.
    //
    // Collision resolution: we must NOT unconditionally prefer the modern
    // entry — a half-written modern directory (crash during a previous
    // install) paired with a complete legacy copy would silently discard a
    // usable cache. The policy is:
    //
    //   legacy complete + modern complete   → modern wins (freshest known)
    //   legacy complete + modern incomplete → legacy replaces modern
    //   legacy incomplete                   → legacy dropped (nothing to save)
    //
    // Completeness is the same `{package.json, node_modules/.bin}` pair
    // that `is_cache_fresh` treats as a valid entry marker.
    std::fs::create_dir_all(&modern)?;
    let entries = std::fs::read_dir(&legacy)?;
    for entry in entries {
        let entry = entry?;
        let src = entry.path();
        let Some(name) = src.file_name() else {
            continue;
        };
        let dst = modern.join(name);
        if dst.exists() {
            let legacy_complete = src.is_dir() && dlx_entry_appears_complete(&src);
            let modern_complete = dst.is_dir() && dlx_entry_appears_complete(&dst);
            if legacy_complete && !modern_complete {
                // Replace modern with legacy. Remove modern first (it may be a
                // partial dir), then rename legacy into place.
                if dst.is_dir() {
                    std::fs::remove_dir_all(&dst)?;
                } else {
                    std::fs::remove_file(&dst)?;
                }
                std::fs::rename(&src, &dst)?;
                tracing::info!(
                    "dlx migration: replaced incomplete modern entry with complete legacy at {}",
                    dst.display()
                );
            } else {
                // Modern wins (it's at least as complete as legacy). Drop legacy.
                let _ = if src.is_dir() {
                    std::fs::remove_dir_all(&src)
                } else {
                    std::fs::remove_file(&src)
                };
            }
            continue;
        }
        std::fs::rename(&src, &dst)?;
    }
    // After moving children, the legacy dir itself should be empty (or
    // contain only discarded duplicates we deleted). remove_dir is strict
    // and will fail loudly if we accidentally left something behind.
    std::fs::remove_dir(&legacy)?;
    tracing::info!("merged legacy dlx cache into {}", modern.display());
    Ok(())
}

/// Create the dlx cache directory with restricted permissions.
///
/// On Unix, sets permissions to 0o700 so only the current user can access it.
pub fn create_cache_dir(cache_dir: &Path) -> Result<(), LpmError> {
    std::fs::create_dir_all(cache_dir)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(cache_dir, std::fs::Permissions::from_mode(0o700))?;
    }

    Ok(())
}

/// Check if a cached dlx installation is still fresh.
///
/// Returns `true` if the cache exists and was modified within `ttl_secs`.
pub fn is_cache_fresh(cache_dir: &Path, ttl_secs: u64) -> bool {
    let bin_dir = cache_dir.join("node_modules").join(".bin");
    if !bin_dir.is_dir() {
        return false;
    }

    // Check mtime of the package.json (written at install time)
    let pkg_json = cache_dir.join("package.json");
    match std::fs::metadata(&pkg_json) {
        Ok(meta) => {
            if let Ok(modified) = meta.modified() {
                let age = std::time::SystemTime::now()
                    .duration_since(modified)
                    .unwrap_or_default();
                age.as_secs() < ttl_secs
            } else {
                false
            }
        }
        Err(_) => false,
    }
}

/// Touch the cache to reset the TTL (called after successful install).
///
/// Uses `File::set_modified()` to update mtime without reading/rewriting file contents.
pub fn touch_cache(cache_dir: &Path) {
    let pkg_json = cache_dir.join("package.json");
    if pkg_json.exists()
        && let Ok(file) = std::fs::OpenOptions::new().write(true).open(&pkg_json)
    {
        let _ = file.set_modified(std::time::SystemTime::now());
    }
}

/// Parse a package spec into (name, version_spec).
///
/// Examples:
/// - `"cowsay"` → `("cowsay", "*")`
/// - `"cowsay@1.0.0"` → `("cowsay", "1.0.0")`
/// - `"create-next-app@latest"` → `("create-next-app", "latest")`
/// - `"@scope/pkg"` → `("@scope/pkg", "*")`
/// - `"@scope/pkg@2.0"` → `("@scope/pkg", "2.0")`
pub fn parse_package_spec(spec: &str) -> (String, String) {
    if let Some(rest) = spec.strip_prefix('@') {
        // Scoped package: @scope/name or @scope/name@version
        // Find the second '@' (version separator) — skip the leading '@'
        if let Some(at_pos) = rest.find('@') {
            let name = &spec[..at_pos + 1]; // includes leading @
            let version = &rest[at_pos + 1..];
            (name.to_string(), version.to_string())
        } else {
            // No version — @scope/name
            (spec.to_string(), "*".to_string())
        }
    } else if let Some(at_pos) = spec.find('@') {
        // Unscoped: name@version
        let name = &spec[..at_pos];
        let version = &spec[at_pos + 1..];
        (name.to_string(), version.to_string())
    } else {
        // No version
        (spec.to_string(), "*".to_string())
    }
}

/// Extract the binary name from a package spec.
///
/// Strips scope and version: `@scope/foo@1.0` → `foo`, `cowsay@2` → `cowsay`.
pub fn bin_name_from_spec(spec: &str) -> &str {
    // Strip scope and version from the original spec to return a &str (no allocation)

    (if let Some(rest) = spec.strip_prefix('@') {
        if let Some(slash_pos) = rest.find('/') {
            let after_slash = &rest[slash_pos + 1..];
            // Strip version if present
            if let Some(at_pos) = after_slash.find('@') {
                &after_slash[..at_pos]
            } else {
                after_slash
            }
        } else {
            spec
        }
    } else {
        // Unscoped — strip version
        if let Some(at_pos) = spec.find('@') {
            &spec[..at_pos]
        } else {
            spec
        }
    }) as _
}

/// Build a `Command` for executing a dlx binary.
///
/// Uses direct process spawn (`Command::new`) instead of `sh -c` to prevent
/// shell injection. Arguments are passed as separate argv entries, so
/// metacharacters like `;`, `|`, `&`, `$()` are treated as literals.
///
/// Returns the configured `Command` ready to be spawned.
pub fn build_dlx_command(
    project_dir: &Path,
    cache_dir: &Path,
    package_spec: &str,
    extra_args: &[String],
) -> Command {
    let bin_dir = cache_dir.join("node_modules").join(".bin");
    let bin_name = bin_name_from_spec(package_spec);
    let bin_path = bin_dir.join(bin_name);

    // Build PATH with the dlx cache's .bin prepended
    let mut path_parts = vec![bin_dir.to_string_lossy().to_string()];

    // Also include the project's .bin dirs
    let project_bin_dirs = bin_path::find_bin_dirs(project_dir);
    for d in &project_bin_dirs {
        path_parts.push(d.to_string_lossy().to_string());
    }

    let existing_path = std::env::var("PATH").unwrap_or_default();
    if !existing_path.is_empty() {
        path_parts.push(existing_path);
    }

    let separator = if cfg!(windows) { ";" } else { ":" };
    let path = path_parts.join(separator);

    let mut command = Command::new(&bin_path);
    command
        .args(extra_args)
        .current_dir(project_dir)
        .env("PATH", &path)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());

    command
}

/// Execute the dlx binary from the cache directory.
///
/// Uses direct process spawn (`Command::new`) instead of `sh -c` to prevent
/// shell injection. Arguments are passed as separate argv entries.
pub fn exec_dlx_binary(
    project_dir: &Path,
    cache_dir: &Path,
    package_spec: &str,
    extra_args: &[String],
) -> Result<(), LpmError> {
    let mut command = build_dlx_command(project_dir, cache_dir, package_spec, extra_args);

    let status = command.status().map_err(|e| {
        let bin_name = bin_name_from_spec(package_spec);
        LpmError::Script(format!("failed to execute '{bin_name}': {e}"))
    })?;

    if !status.success() {
        #[cfg(not(unix))]
        let code = status.code().unwrap_or(1);
        #[cfg(unix)]
        let code = {
            use std::os::unix::process::ExitStatusExt;
            status
                .code()
                .unwrap_or_else(|| status.signal().map(|s| 128 + s).unwrap_or(1))
        };
        return Err(LpmError::ExitCode(code));
    }

    Ok(())
}

/// Deterministic string hash for cache directory naming.
///
/// Uses FNV-1a, which produces stable output across Rust versions (unlike
/// `DefaultHasher`/SipHash which can change between compiler releases,
/// orphaning cache directories after toolchain upgrades).
pub fn deterministic_hash(s: &str) -> String {
    // FNV-1a 64-bit — deterministic, no external dependency
    const FNV_OFFSET: u64 = 0xcbf29ce484222325;
    const FNV_PRIME: u64 = 0x00000100000001B3;

    let mut hash = FNV_OFFSET;
    for byte in s.as_bytes() {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    format!("{hash:016x}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dlx_cache_dir_at_is_stable() {
        // Use the pure form against a temp-rooted LpmRoot so the test never
        // touches the developer's real $HOME / $LPM_HOME or triggers the
        // process-wide legacy migration. The public `dlx_cache_dir(&str)`
        // path is exercised by integration tests with a temp-rooted env.
        let dir = tempfile::tempdir().unwrap();
        let root = LpmRoot::from_dir(dir.path());
        let dir1 = dlx_cache_dir_at(&root, "cowsay");
        let dir2 = dlx_cache_dir_at(&root, "cowsay");
        assert_eq!(dir1, dir2);
    }

    #[test]
    fn dlx_cache_dir_at_differs_for_different_specs() {
        let dir = tempfile::tempdir().unwrap();
        let root = LpmRoot::from_dir(dir.path());
        let dir1 = dlx_cache_dir_at(&root, "cowsay");
        let dir2 = dlx_cache_dir_at(&root, "cowsay@1.0.0");
        assert_ne!(dir1, dir2);
    }

    // ─── Migration tests ──────────────────────────────────────────

    #[test]
    fn migrate_legacy_dlx_cache_is_noop_without_legacy() {
        let dir = tempfile::tempdir().unwrap();
        let root = LpmRoot::from_dir(dir.path());
        // Legacy absent, modern absent → no-op, no error.
        migrate_legacy_dlx_cache(&root).unwrap();
        assert!(!root.legacy_dlx_cache().exists());
        assert!(!root.cache_dlx().exists());
    }

    #[test]
    fn migrate_legacy_dlx_cache_renames_when_only_legacy_exists() {
        let dir = tempfile::tempdir().unwrap();
        let root = LpmRoot::from_dir(dir.path());

        // Populate legacy with one entry.
        let legacy = root.legacy_dlx_cache();
        std::fs::create_dir_all(legacy.join("abc123")).unwrap();
        std::fs::write(legacy.join("abc123").join("package.json"), "{}").unwrap();

        migrate_legacy_dlx_cache(&root).unwrap();

        assert!(!root.legacy_dlx_cache().exists(), "legacy should be gone");
        let modern_entry = root.cache_dlx().join("abc123");
        assert!(modern_entry.exists(), "modern should carry the entry");
        assert!(modern_entry.join("package.json").exists());
    }

    #[test]
    fn migrate_legacy_dlx_cache_merges_when_both_exist() {
        let dir = tempfile::tempdir().unwrap();
        let root = LpmRoot::from_dir(dir.path());

        // Both locations have distinct entries.
        std::fs::create_dir_all(root.legacy_dlx_cache().join("legacy-only")).unwrap();
        std::fs::create_dir_all(root.cache_dlx().join("modern-only")).unwrap();

        migrate_legacy_dlx_cache(&root).unwrap();

        assert!(!root.legacy_dlx_cache().exists());
        assert!(root.cache_dlx().join("legacy-only").exists());
        assert!(root.cache_dlx().join("modern-only").exists());
    }

    /// Make `entry` look like a complete dlx install — sufficient for
    /// `dlx_entry_appears_complete` to return true.
    fn make_complete_dlx_entry(entry: &Path, marker_text: &str) {
        std::fs::create_dir_all(entry.join("node_modules").join(".bin")).unwrap();
        std::fs::write(entry.join("package.json"), "{}").unwrap();
        std::fs::write(entry.join("marker"), marker_text).unwrap();
    }

    #[test]
    fn migrate_legacy_dlx_cache_modern_wins_on_collision_when_both_complete() {
        let dir = tempfile::tempdir().unwrap();
        let root = LpmRoot::from_dir(dir.path());

        // Both sides complete → modern wins (freshest known).
        let legacy_entry = root.legacy_dlx_cache().join("collide");
        make_complete_dlx_entry(&legacy_entry, "legacy");

        let modern_entry = root.cache_dlx().join("collide");
        make_complete_dlx_entry(&modern_entry, "modern");

        migrate_legacy_dlx_cache(&root).unwrap();

        let marker = std::fs::read_to_string(modern_entry.join("marker")).unwrap();
        assert_eq!(
            marker, "modern",
            "modern entry should win when both complete"
        );
        assert!(!root.legacy_dlx_cache().exists());
    }

    #[test]
    fn migrate_legacy_dlx_cache_legacy_wins_when_modern_incomplete() {
        // Regression test for the audit finding: a half-written modern entry
        // (e.g. from a crash during install) must NOT silently discard a
        // complete legacy copy.
        let dir = tempfile::tempdir().unwrap();
        let root = LpmRoot::from_dir(dir.path());

        // Legacy is complete.
        let legacy_entry = root.legacy_dlx_cache().join("collide");
        make_complete_dlx_entry(&legacy_entry, "legacy");

        // Modern exists but is missing the `node_modules/.bin` marker —
        // i.e. install was interrupted before linking bin entries. Only
        // `package.json` is in place.
        let modern_entry = root.cache_dlx().join("collide");
        std::fs::create_dir_all(&modern_entry).unwrap();
        std::fs::write(modern_entry.join("package.json"), "{}").unwrap();
        std::fs::write(modern_entry.join("marker"), "modern-incomplete").unwrap();

        migrate_legacy_dlx_cache(&root).unwrap();

        // Legacy should have replaced modern.
        let marker = std::fs::read_to_string(modern_entry.join("marker")).unwrap();
        assert_eq!(
            marker, "legacy",
            "legacy should replace an incomplete modern entry"
        );
        // And the legacy side should still be gone.
        assert!(!root.legacy_dlx_cache().exists());
        // Sanity: the replacement is now actually complete.
        assert!(
            dlx_entry_appears_complete(&modern_entry),
            "post-migration entry should be complete"
        );
    }

    #[test]
    fn migrate_legacy_dlx_cache_drops_incomplete_legacy_on_collision() {
        // If neither side is complete, drop legacy and keep modern — neither
        // is useful as a cache hit, but cleanup should at least remove the
        // legacy directory so we don't retry forever.
        let dir = tempfile::tempdir().unwrap();
        let root = LpmRoot::from_dir(dir.path());

        let legacy_entry = root.legacy_dlx_cache().join("collide");
        std::fs::create_dir_all(&legacy_entry).unwrap();
        // No markers — incomplete.
        std::fs::write(legacy_entry.join("scratch"), "x").unwrap();

        let modern_entry = root.cache_dlx().join("collide");
        std::fs::create_dir_all(&modern_entry).unwrap();
        std::fs::write(modern_entry.join("scratch"), "y").unwrap();

        migrate_legacy_dlx_cache(&root).unwrap();

        assert!(!root.legacy_dlx_cache().exists());
        // Modern is kept as-is (not replaced).
        assert_eq!(
            std::fs::read_to_string(modern_entry.join("scratch")).unwrap(),
            "y"
        );
    }

    // ─── Proactive sweep tests ────────────────────────────────────

    /// Build a dlx entry whose `package.json` mtime is set `age_secs`
    /// seconds in the past. Uses `filetime` semantics via a direct
    /// SystemTime write — the stdlib `set_modified` is enough.
    fn make_dlx_entry_with_age(entry: &Path, age_secs: u64) {
        std::fs::create_dir_all(entry).unwrap();
        let pkg = entry.join("package.json");
        std::fs::write(&pkg, "{}").unwrap();
        let file = std::fs::OpenOptions::new().write(true).open(&pkg).unwrap();
        let when = std::time::SystemTime::now() - std::time::Duration::from_secs(age_secs);
        file.set_modified(when).unwrap();
    }

    #[test]
    fn sweep_removes_entry_older_than_ttl() {
        let dir = tempfile::tempdir().unwrap();
        let root = LpmRoot::from_dir(dir.path());
        let stale = root.cache_dlx().join("stale");
        make_dlx_entry_with_age(&stale, 48 * 3600); // 48h old

        let removed = sweep_stale_dlx_entries(&root, CACHE_TTL_SECS).unwrap();
        assert_eq!(removed, 1);
        assert!(!stale.exists());
    }

    #[test]
    fn sweep_keeps_fresh_entry() {
        let dir = tempfile::tempdir().unwrap();
        let root = LpmRoot::from_dir(dir.path());
        let fresh = root.cache_dlx().join("fresh");
        make_dlx_entry_with_age(&fresh, 60); // 1 min old

        let removed = sweep_stale_dlx_entries(&root, CACHE_TTL_SECS).unwrap();
        assert_eq!(removed, 0);
        assert!(fresh.exists());
    }

    #[test]
    fn sweep_skips_entries_without_package_json() {
        // A dir with no package.json is either in-flight or not ours. We
        // must never delete it based on directory mtime alone — the
        // package.json marker is the contract for "this is a dlx entry".
        let dir = tempfile::tempdir().unwrap();
        let root = LpmRoot::from_dir(dir.path());
        let stray = root.cache_dlx().join("stray");
        std::fs::create_dir_all(&stray).unwrap();
        std::fs::write(stray.join("scratch"), "x").unwrap();

        let removed = sweep_stale_dlx_entries(&root, CACHE_TTL_SECS).unwrap();
        assert_eq!(removed, 0);
        assert!(stray.exists(), "stray dir must not be swept");
    }

    #[test]
    fn sweep_is_noop_when_dlx_root_absent() {
        let dir = tempfile::tempdir().unwrap();
        let root = LpmRoot::from_dir(dir.path());
        // cache_dlx directory never created.
        let removed = sweep_stale_dlx_entries(&root, CACHE_TTL_SECS).unwrap();
        assert_eq!(removed, 0);
    }

    #[test]
    fn sweep_mixed_ages_partitions_correctly() {
        let dir = tempfile::tempdir().unwrap();
        let root = LpmRoot::from_dir(dir.path());
        make_dlx_entry_with_age(&root.cache_dlx().join("a-fresh"), 60);
        make_dlx_entry_with_age(&root.cache_dlx().join("b-stale"), 48 * 3600);
        make_dlx_entry_with_age(&root.cache_dlx().join("c-fresh"), 300);
        make_dlx_entry_with_age(&root.cache_dlx().join("d-stale"), 72 * 3600);

        let removed = sweep_stale_dlx_entries(&root, CACHE_TTL_SECS).unwrap();
        assert_eq!(removed, 2);
        assert!(root.cache_dlx().join("a-fresh").exists());
        assert!(!root.cache_dlx().join("b-stale").exists());
        assert!(root.cache_dlx().join("c-fresh").exists());
        assert!(!root.cache_dlx().join("d-stale").exists());
    }

    #[test]
    fn migrate_legacy_dlx_cache_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let root = LpmRoot::from_dir(dir.path());
        std::fs::create_dir_all(root.legacy_dlx_cache().join("x")).unwrap();
        migrate_legacy_dlx_cache(&root).unwrap();
        // Second call is a clean no-op.
        migrate_legacy_dlx_cache(&root).unwrap();
        assert!(root.cache_dlx().join("x").exists());
    }

    // --- Finding #7: Deterministic hash tests ---

    #[test]
    fn deterministic_hash_stable() {
        assert_eq!(deterministic_hash("test"), deterministic_hash("test"));
        assert_ne!(deterministic_hash("a"), deterministic_hash("b"));
    }

    #[test]
    fn deterministic_hash_hardcoded_value() {
        // FNV-1a of "cowsay" — pinned to detect accidental algorithm changes.
        // If this test fails, the hash algorithm changed and existing caches
        // will be orphaned.
        assert_eq!(deterministic_hash("cowsay"), "810da9b113278083");
    }

    #[test]
    fn deterministic_hash_empty_string() {
        // Empty string should produce the FNV offset basis
        let h = deterministic_hash("");
        assert_eq!(h, "cbf29ce484222325");
    }

    // --- Finding #4: Command injection prevention tests ---

    #[test]
    fn build_dlx_command_no_shell_injection() {
        let dir = tempfile::tempdir().unwrap();
        let cache_dir = dir.path().join("cache");
        let bin_dir = cache_dir.join("node_modules/.bin");
        std::fs::create_dir_all(&bin_dir).unwrap();

        // Arguments with shell metacharacters should be passed as literals
        let malicious_args: Vec<String> = vec![
            "foo; rm -rf /".into(),
            "bar | cat /etc/passwd".into(),
            "baz && echo pwned".into(),
            "$(whoami)".into(),
            "`id`".into(),
        ];

        let cmd = build_dlx_command(dir.path(), &cache_dir, "cowsay", &malicious_args);

        // Verify the command is a direct binary invocation, not sh -c
        let program = cmd.get_program().to_string_lossy().to_string();
        assert!(
            program.ends_with("cowsay"),
            "program should be the binary path, not 'sh': {program}"
        );

        // Verify each arg is passed as a separate element (no joining)
        let args: Vec<String> = cmd
            .get_args()
            .map(|a| a.to_string_lossy().to_string())
            .collect();
        assert_eq!(args.len(), 5, "should have 5 separate args");
        assert_eq!(args[0], "foo; rm -rf /");
        assert_eq!(args[1], "bar | cat /etc/passwd");
        assert_eq!(args[2], "baz && echo pwned");
        assert_eq!(args[3], "$(whoami)");
        assert_eq!(args[4], "`id`");
    }

    #[test]
    fn build_dlx_command_no_args() {
        let dir = tempfile::tempdir().unwrap();
        let cache_dir = dir.path().join("cache");
        let bin_dir = cache_dir.join("node_modules/.bin");
        std::fs::create_dir_all(&bin_dir).unwrap();

        let cmd = build_dlx_command(dir.path(), &cache_dir, "cowsay", &[]);
        let args: Vec<String> = cmd
            .get_args()
            .map(|a| a.to_string_lossy().to_string())
            .collect();
        assert!(args.is_empty(), "should have no args");
    }

    // --- Finding #14: Cache directory permissions test ---

    #[cfg(unix)]
    #[test]
    fn create_cache_dir_sets_restricted_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let cache_dir = dir.path().join("dlx-cache").join("test-hash");

        create_cache_dir(&cache_dir).unwrap();

        let meta = std::fs::metadata(&cache_dir).unwrap();
        let mode = meta.permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o700,
            "cache dir should be owner-only (0o700), got 0o{mode:03o}"
        );
    }

    // --- Finding #15: touch_cache efficiency test ---

    #[test]
    fn touch_cache_updates_mtime() {
        let dir = tempfile::tempdir().unwrap();
        let pkg_json = dir.path().join("package.json");
        std::fs::write(&pkg_json, "{}").unwrap();

        let meta_before = std::fs::metadata(&pkg_json).unwrap();
        let mtime_before = meta_before.modified().unwrap();

        // Small sleep to ensure time difference
        std::thread::sleep(std::time::Duration::from_millis(50));

        touch_cache(dir.path());

        let meta_after = std::fs::metadata(&pkg_json).unwrap();
        let mtime_after = meta_after.modified().unwrap();

        assert!(
            mtime_after > mtime_before,
            "mtime should increase after touch"
        );

        // Verify contents unchanged (touch should not rewrite file)
        let content = std::fs::read_to_string(&pkg_json).unwrap();
        assert_eq!(content, "{}", "touch should not alter file contents");
    }

    // --- parse_package_spec tests ---

    #[test]
    fn parse_unscoped_no_version() {
        let (name, ver) = parse_package_spec("cowsay");
        assert_eq!(name, "cowsay");
        assert_eq!(ver, "*");
    }

    #[test]
    fn parse_unscoped_with_version() {
        let (name, ver) = parse_package_spec("cowsay@1.0.0");
        assert_eq!(name, "cowsay");
        assert_eq!(ver, "1.0.0");
    }

    #[test]
    fn parse_unscoped_latest() {
        let (name, ver) = parse_package_spec("create-next-app@latest");
        assert_eq!(name, "create-next-app");
        assert_eq!(ver, "latest");
    }

    #[test]
    fn parse_scoped_no_version() {
        let (name, ver) = parse_package_spec("@angular/cli");
        assert_eq!(name, "@angular/cli");
        assert_eq!(ver, "*");
    }

    #[test]
    fn parse_scoped_with_version() {
        let (name, ver) = parse_package_spec("@angular/cli@17.0.0");
        assert_eq!(name, "@angular/cli");
        assert_eq!(ver, "17.0.0");
    }

    #[test]
    fn parse_scoped_latest() {
        let (name, ver) = parse_package_spec("@sveltejs/kit@latest");
        assert_eq!(name, "@sveltejs/kit");
        assert_eq!(ver, "latest");
    }

    // --- bin_name_from_spec tests ---

    #[test]
    fn bin_name_unscoped() {
        assert_eq!(bin_name_from_spec("cowsay"), "cowsay");
        assert_eq!(bin_name_from_spec("cowsay@1.0"), "cowsay");
    }

    #[test]
    fn bin_name_scoped() {
        assert_eq!(bin_name_from_spec("@angular/cli"), "cli");
        assert_eq!(bin_name_from_spec("@angular/cli@17.0"), "cli");
        assert_eq!(bin_name_from_spec("@sveltejs/kit@latest"), "kit");
    }

    // --- is_cache_fresh tests ---

    #[test]
    fn cache_fresh_no_dir() {
        let dir = tempfile::tempdir().unwrap();
        assert!(!is_cache_fresh(dir.path(), 3600));
    }

    #[test]
    fn cache_fresh_with_recent_install() {
        let dir = tempfile::tempdir().unwrap();
        let bin_dir = dir.path().join("node_modules/.bin");
        std::fs::create_dir_all(&bin_dir).unwrap();
        std::fs::write(dir.path().join("package.json"), "{}").unwrap();

        assert!(is_cache_fresh(dir.path(), 3600));
    }

    #[test]
    fn cache_stale_zero_ttl() {
        let dir = tempfile::tempdir().unwrap();
        let bin_dir = dir.path().join("node_modules/.bin");
        std::fs::create_dir_all(&bin_dir).unwrap();
        std::fs::write(dir.path().join("package.json"), "{}").unwrap();

        // With 0 TTL, cache is always stale
        assert!(!is_cache_fresh(dir.path(), 0));
    }

    // --- Scoped package edge cases ---

    #[test]
    fn parse_scoped_no_slash_does_not_panic() {
        // "@justascope" has no slash — should return the full string as the name
        let (name, ver) = parse_package_spec("@justascope");
        assert_eq!(name, "@justascope");
        assert_eq!(ver, "*");
    }

    #[test]
    fn bin_name_scoped_no_slash_does_not_panic() {
        // Should return the original string since there's no slash to split on
        assert_eq!(bin_name_from_spec("@justascope"), "@justascope");
    }

    #[test]
    fn parse_empty_version_after_at() {
        // "cowsay@" — empty version string
        let (name, ver) = parse_package_spec("cowsay@");
        assert_eq!(name, "cowsay");
        assert_eq!(ver, "");
    }

    #[test]
    fn parse_scoped_empty_version_after_at() {
        // "@scope/pkg@" — empty version on scoped package
        let (name, ver) = parse_package_spec("@scope/pkg@");
        assert_eq!(name, "@scope/pkg");
        assert_eq!(ver, "");
    }

    #[test]
    fn touch_cache_nonexistent_dir_is_noop() {
        // touch_cache on a nonexistent path should not panic
        let dir = tempfile::tempdir().unwrap();
        let nonexistent = dir.path().join("does-not-exist");
        touch_cache(&nonexistent); // should not panic
    }

    #[test]
    fn cache_fresh_no_package_json() {
        // bin dir exists but no package.json — should be stale
        let dir = tempfile::tempdir().unwrap();
        let bin_dir = dir.path().join("node_modules/.bin");
        std::fs::create_dir_all(&bin_dir).unwrap();
        // No package.json written

        assert!(!is_cache_fresh(dir.path(), 3600));
    }
}
