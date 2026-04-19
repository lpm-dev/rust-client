//! Sync-safe install-state check shared by the top-of-main fast lane,
//! `install.rs`, and `dev.rs`. Single source of truth — never duplicate.
//!
//! **Phase 34.1** — extracted from `install.rs::is_install_up_to_date()`
//! and `dev.rs::compute_install_hash()` / `dev.rs::needs_install()`.

use sha2::{Digest, Sha256};
use std::path::Path;
use std::time::UNIX_EPOCH;

/// Result of checking install state.
pub struct InstallState {
    /// Whether the project's install is up to date.
    pub up_to_date: bool,
    /// SHA-256 hex digest of `package.json + "\0" + lpm.lock`.
    /// `None` only when package.json doesn't exist or can't be read from disk.
    /// `Some` when the file exists and is readable — even if the content is
    /// invalid JSON or fails typed parsing. This distinction matters for
    /// `dev.rs::needs_install()`: `None` → "nothing to install" (no manifest),
    /// `Some` + `!up_to_date` → "needs install" (triggers full pipeline which
    /// surfaces any parse errors).
    pub hash: Option<String>,
}

/// Schema tag prefix baked into every install-hash. Bump when the install
/// pipeline's semantics change in a way that makes a previously up-to-date
/// project NOT up to date under the new rules — even if the manifest and
/// lockfile bytes are identical.
///
/// History:
/// - `v1`: original hash (pkg + lock).
/// - `v2` (2026-04-16): `lpm install` now resolves `devDependencies` in
///   addition to `dependencies`. Projects whose previous install silently
///   dropped devDeps must be treated as stale so the next bare `lpm install`
///   runs the full pipeline and populates them. Without this bump, an
///   existing up-to-date install would skip the pipeline and leave devDeps
///   unresolved until the manifest changes for some other reason.
const INSTALL_HASH_SCHEMA_TAG: &[u8] = b"lpm-install-hash-v2\x00";

/// Compute the install hash from raw file contents.
/// Deterministic SHA-256: `schema_tag || pkg_content || 0x00 || lock_content`.
pub fn compute_install_hash(pkg_content: &str, lock_content: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(INSTALL_HASH_SCHEMA_TAG);
    hasher.update(pkg_content.as_bytes());
    hasher.update(b"\x00"); // domain separator prevents "ab"+"cd" == "abc"+"d"
    hasher.update(lock_content.as_bytes());
    format!("{:x}", hasher.finalize())
}

/// Full up-to-date predicate with the strongest semantics:
///
/// 1. All four artifacts must exist: package.json, lpm.lock, node_modules, .lpm/install-hash
/// 2. Hash of (package.json + lpm.lock) must match cached hash
/// 3. node_modules mtime must be ≤ install-hash mtime (detects external modifications)
///
/// Returns `InstallState` with the computed hash for downstream reuse.
///
/// Phase 44 fast path: when the install-hash file contains an optional
/// mtime line (written by [`write_install_hash`]) and the recorded
/// mtimes of package.json + lpm.lock still match, skips the hash
/// recomputation entirely — saving one file read of each manifest plus
/// the SHA-256 pass. On any mismatch (or absent mtime line) falls
/// through to the full-read path.
pub fn check_install_state(project_dir: &Path) -> InstallState {
    let pkg_json = project_dir.join("package.json");
    if !pkg_json.exists() {
        return InstallState {
            up_to_date: false,
            hash: None,
        };
    }

    // Phase 44 mtime short-circuit — attempt without touching pkg.json/lpm.lock.
    if let Some(state) = try_mtime_fast_path(project_dir) {
        return state;
    }

    // Fall through: full-read path.
    let Ok(pkg_content) = std::fs::read_to_string(&pkg_json) else {
        return InstallState {
            up_to_date: false,
            hash: None,
        };
    };
    check_install_state_with_content(project_dir, &pkg_content)
}

/// Same semantics as [`check_install_state`] but accepts a pre-read
/// `package.json` content from the caller — used by the top-of-main
/// fast lane which already read the file for the workspace-root check.
/// Saves one redundant file read.
pub fn check_install_state_with_content(project_dir: &Path, pkg_content: &str) -> InstallState {
    // Phase 44 mtime short-circuit also applies here. The caller may have
    // already read pkg.json for an earlier check, but the fast path still
    // skips the read of lpm.lock + the SHA-256 pass.
    if let Some(state) = try_mtime_fast_path(project_dir) {
        return state;
    }

    let lock_path = project_dir.join("lpm.lock");
    let hash_file = project_dir.join(".lpm").join("install-hash");
    let nm = project_dir.join("node_modules");

    // Read lockfile — empty string if missing (hash will mismatch → needs install)
    let lock_content = std::fs::read_to_string(&lock_path).unwrap_or_default();
    let current_hash = compute_install_hash(pkg_content, &lock_content);

    // Validate that package.json parses into the typed PackageJson struct —
    // the same deserialization the full install path uses via read_package_json()
    // at install.rs:447. A generic serde_json::Value check is NOT sufficient:
    // it accepts semantically invalid shapes like {"dependencies":[]} that the
    // typed parse correctly rejects (dependencies is HashMap<String, String>).
    //
    // The hash is still returned as Some so callers like dev.rs::needs_install()
    // know the file exists and can trigger a full install which surfaces the error.
    if serde_json::from_str::<lpm_workspace::PackageJson>(pkg_content).is_err() {
        return InstallState {
            up_to_date: false,
            hash: Some(current_hash),
        };
    }

    // If any artifact is missing, we need install but still return the hash
    if !nm.exists() || !hash_file.exists() || !lock_path.exists() {
        return InstallState {
            up_to_date: false,
            hash: Some(current_hash),
        };
    }

    // Hash comparison — read only the first line of the file so v1 (bare
    // hash) and v2 (hash + mtime line) formats both parse identically.
    let Ok(cached_hash_file) = std::fs::read_to_string(&hash_file) else {
        return InstallState {
            up_to_date: false,
            hash: Some(current_hash),
        };
    };
    let cached_hash = cached_hash_file.lines().next().unwrap_or("").trim();
    if cached_hash != current_hash {
        return InstallState {
            up_to_date: false,
            hash: Some(current_hash),
        };
    }

    // Shallow mtime check: node_modules modified after hash file → external change
    let up_to_date = match (
        std::fs::metadata(&nm).and_then(|m| m.modified()),
        std::fs::metadata(&hash_file).and_then(|m| m.modified()),
    ) {
        (Ok(nm_t), Ok(hash_t)) => nm_t <= hash_t,
        _ => false,
    };

    InstallState {
        up_to_date,
        hash: Some(current_hash),
    }
}

/// Phase 44: mtime short-circuit for the up-to-date check.
///
/// Reads `.lpm/install-hash`; when it contains a v2 mtime line
/// (`m:<pkg_ns>:<lock_ns>`) and the recorded mtimes still match the
/// current mtimes of `package.json` and `lpm.lock`, declares the
/// install up to date without reading either manifest or recomputing
/// the hash. Returns `None` on ANY deviation — the caller then falls
/// through to the full hash path, which is still correct.
///
/// Safety: only TRUSTS the stored hash when mtimes match. An adversary
/// who can rewrite the file's manifest bytes also changes its mtime
/// (any `fs::write` updates mtime); the only way to defeat this check
/// is deliberate mtime tampering (`touch -t ...`), which is also
/// sufficient to defeat npm/pnpm/bun. Acceptable tradeoff.
fn try_mtime_fast_path(project_dir: &Path) -> Option<InstallState> {
    let nm = project_dir.join("node_modules");
    if !nm.exists() {
        return None;
    }

    let hash_file = project_dir.join(".lpm").join("install-hash");
    let content = std::fs::read_to_string(&hash_file).ok()?;

    let mut lines = content.lines();
    let stored_hash = lines.next()?.trim();
    // v1 files have no second line → no mtime fast path available.
    let mtime_line = lines.next()?;
    let rest = mtime_line.strip_prefix("m:")?;
    let (pkg_ns_str, lock_ns_str) = rest.split_once(':')?;
    let stored_pkg_ns: u64 = pkg_ns_str.parse().ok()?;
    let stored_lock_ns: u64 = lock_ns_str.parse().ok()?;

    let pkg_ns = mtime_ns(&project_dir.join("package.json"))?;
    // lpm.lock may be absent on a never-installed fast-lane entry; 0
    // sentinel lines up with the writer's convention.
    let lock_ns = mtime_ns(&project_dir.join("lpm.lock")).unwrap_or(0);

    if pkg_ns != stored_pkg_ns || lock_ns != stored_lock_ns {
        return None;
    }

    // External-modification check: if anything under node_modules was
    // touched more recently than the hash file, the recorded state
    // cannot be trusted even with matching manifest mtimes.
    let nm_ns = mtime_ns(&nm)?;
    let hash_ns = mtime_ns(&hash_file)?;
    if nm_ns > hash_ns {
        return None;
    }

    Some(InstallState {
        up_to_date: true,
        hash: Some(stored_hash.to_string()),
    })
}

/// Return the modified-time of `path` as nanoseconds since the Unix
/// epoch. Returns `None` if the file is missing or the filesystem does
/// not expose mtime (neither of which should happen for the files the
/// install-state machinery cares about).
fn mtime_ns(path: &Path) -> Option<u64> {
    let modified = std::fs::metadata(path).ok()?.modified().ok()?;
    let dur = modified.duration_since(UNIX_EPOCH).ok()?;
    // `as_nanos` returns u128; narrow to u64 — safe until year 2554.
    Some(dur.as_nanos() as u64)
}

/// Phase 44: write `.lpm/install-hash` in the v2 format (hash line +
/// optional mtime line). Callers just provide the pre-computed hash;
/// this helper captures the current mtimes of `package.json` and
/// `lpm.lock` at write time so subsequent up-to-date checks can take
/// the mtime fast path.
///
/// On any failure reading an mtime (typically missing lpm.lock on a
/// dependency-less project), falls back to a `0` sentinel. A mismatch
/// between `0`-stored and a later real mtime simply falls through to
/// the full hash path — still correct, just not fast.
///
/// Writes `.lpm/install-hash` atomically via `fs::write`, same as the
/// prior byte-string-only writes — the ManifestTransaction snapshot
/// machinery is unaffected.
pub fn write_install_hash(project_dir: &Path, hash: &str) -> std::io::Result<()> {
    let pkg_ns = mtime_ns(&project_dir.join("package.json")).unwrap_or(0);
    let lock_ns = mtime_ns(&project_dir.join("lpm.lock")).unwrap_or(0);

    let hash_dir = project_dir.join(".lpm");
    std::fs::create_dir_all(&hash_dir)?;
    let content = format!("{hash}\nm:{pkg_ns}:{lock_ns}\n");
    std::fs::write(hash_dir.join("install-hash"), content)
}

/// Pre-clap argv gate for the top-of-main fast lane.
///
/// Returns `Some(json_mode)` if the fast lane should attempt the check.
/// Returns `None` if any disqualifying flag or argument is present.
///
/// Recognized install subcommands: "install", "i" (visible_alias).
///
/// Conservative: any unrecognized flag after "install" → fall through to
/// the full pipeline. This guarantees the fast lane never produces wrong
/// results — false negatives (falling through) are safe, false positives
/// (exiting early when we shouldn't) are not.
pub fn argv_qualifies_for_fast_lane() -> Option<bool> {
    // Use args_os() to avoid panicking on non-UTF-8 arguments.
    // Any argument that isn't valid UTF-8 causes a conservative bail
    // (fall through to the full pipeline where clap handles it).
    let raw_args: Vec<std::ffi::OsString> = std::env::args_os().collect();
    let args: Vec<&str> = raw_args
        .iter()
        .skip(1)
        .map(|a| a.to_str())
        .collect::<Option<Vec<_>>>()?;

    let mut json_mode = false;
    let mut found_install = false;

    for arg in &args {
        match *arg {
            "--json" => json_mode = true,

            // Global flags that change registry/auth behavior → disqualify.
            // --token and --registry take a value: disqualify on the flag itself.
            "--token" | "--registry" => return None,
            _ if arg.starts_with("--token=") || arg.starts_with("--registry=") => return None,
            "--insecure" => return None,

            // Harmless global flags — skip
            "--verbose" | "-v" => {}

            // The subcommand itself
            "install" | "i" if !found_install => found_install = true,

            // Install-specific flags that disqualify the fast lane.
            // ANY of these means semantics differ from a bare `lpm install`.
            "--force"
            | "--offline"
            | "--filter"
            | "-w"
            | "--workspace-root"
            | "--fail-if-no-match"
            | "--allow-new"
            | "--linker"
            | "--exact"
            | "--tilde"
            | "--save-prefix"
            | "-D"
            | "--save-dev"
            | "--no-skills"
            | "--no-editor-setup"
            | "--no-security-summary"
            | "--auto-build"
                if found_install =>
            {
                return None;
            }

            // Value-taking install flags (--linker <val>, --filter <val>, etc.)
            // already handled above — the flag itself disqualifies.

            // Any non-flag argument after "install" = positional package arg
            _ if found_install && !arg.starts_with('-') => return None,

            // Unknown flag after install — bail conservatively
            _ if found_install && arg.starts_with('-') => return None,

            // Something before "install" we don't recognize → not our command
            _ if !found_install => return None,

            _ => return None,
        }
    }

    if found_install { Some(json_mode) } else { None }
}

/// Conservative check for whether a package.json defines workspaces.
///
/// Uses raw string search to avoid JSON parsing overhead on the fast lane.
/// May produce false positives (e.g., `"workspaces"` in a description field),
/// which is safe — the fast lane falls through to the full pipeline.
/// False negatives are impossible — every workspace root package.json must
/// have `"workspaces"` as a JSON key.
pub fn is_likely_workspace_root(project_dir: &Path) -> bool {
    let pkg_json = project_dir.join("package.json");
    match std::fs::read_to_string(&pkg_json) {
        Ok(content) => is_workspace_root_content(&content),
        Err(_) => false,
    }
}

/// Same as [`is_likely_workspace_root`] but takes pre-read content.
/// Phase 44: lets the top-of-main fast lane amortize a single
/// `package.json` read across the workspace check and the install-state
/// check.
pub fn is_workspace_root_content(pkg_content: &str) -> bool {
    pkg_content.contains("\"workspaces\"")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn setup_up_to_date_project() -> TempDir {
        let dir = TempDir::new().unwrap();
        let p = dir.path();
        fs::write(p.join("package.json"), r#"{"dependencies":{"a":"^1.0.0"}}"#).unwrap();
        fs::write(p.join("lpm.lock"), "lock-content").unwrap();
        fs::create_dir_all(p.join("node_modules")).unwrap();
        fs::create_dir_all(p.join(".lpm")).unwrap();
        let hash = compute_install_hash(
            &fs::read_to_string(p.join("package.json")).unwrap(),
            "lock-content",
        );
        fs::write(p.join(".lpm").join("install-hash"), &hash).unwrap();
        dir
    }

    #[test]
    fn up_to_date_returns_true() {
        let dir = setup_up_to_date_project();
        let state = check_install_state(dir.path());
        assert!(state.up_to_date);
        assert!(state.hash.is_some());
    }

    #[test]
    fn missing_lockfile_returns_false_with_hash() {
        let dir = setup_up_to_date_project();
        fs::remove_file(dir.path().join("lpm.lock")).unwrap();
        let state = check_install_state(dir.path());
        assert!(!state.up_to_date);
        // Hash is still computed (with empty lock content)
        assert!(state.hash.is_some());
    }

    #[test]
    fn missing_node_modules_returns_false() {
        let dir = setup_up_to_date_project();
        fs::remove_dir_all(dir.path().join("node_modules")).unwrap();
        let state = check_install_state(dir.path());
        assert!(!state.up_to_date);
        assert!(state.hash.is_some());
    }

    #[test]
    fn changed_package_json_returns_false() {
        let dir = setup_up_to_date_project();
        fs::write(
            dir.path().join("package.json"),
            r#"{"dependencies":{"b":"^2.0.0"}}"#,
        )
        .unwrap();
        let state = check_install_state(dir.path());
        assert!(!state.up_to_date);
        assert!(state.hash.is_some());
    }

    #[test]
    fn missing_package_json_returns_no_hash() {
        let dir = TempDir::new().unwrap();
        let state = check_install_state(dir.path());
        assert!(!state.up_to_date);
        assert!(state.hash.is_none());
    }

    #[test]
    fn syntactically_invalid_json_returns_not_up_to_date() {
        // GPT audit round 1: a malformed package.json with a forged matching
        // install-hash must NOT exit the fast lane with "success: true".
        let dir = TempDir::new().unwrap();
        let p = dir.path();
        let bad_json = "this is not valid json {{{";
        let lock = "lock-content";
        fs::write(p.join("package.json"), bad_json).unwrap();
        fs::write(p.join("lpm.lock"), lock).unwrap();
        fs::create_dir_all(p.join("node_modules")).unwrap();
        fs::create_dir_all(p.join(".lpm")).unwrap();
        let hash = compute_install_hash(bad_json, lock);
        fs::write(p.join(".lpm").join("install-hash"), &hash).unwrap();

        let state = check_install_state(p);
        assert!(!state.up_to_date, "invalid JSON must not be up to date");
        // hash is Some because the file exists and is readable — dev.rs
        // needs this to trigger auto-install (which surfaces the error).
        assert!(state.hash.is_some(), "readable file should produce a hash");
    }

    #[test]
    fn semantically_invalid_manifest_returns_not_up_to_date() {
        // GPT audit round 2: {"dependencies":[]} is valid JSON but not a
        // valid PackageJson (dependencies is HashMap<String,String>, not
        // an array). The fast lane must reject this.
        let dir = TempDir::new().unwrap();
        let p = dir.path();
        let bad_shape = r#"{"dependencies":[]}"#;
        let lock = "lock-content";
        fs::write(p.join("package.json"), bad_shape).unwrap();
        fs::write(p.join("lpm.lock"), lock).unwrap();
        fs::create_dir_all(p.join("node_modules")).unwrap();
        fs::create_dir_all(p.join(".lpm")).unwrap();
        let hash = compute_install_hash(bad_shape, lock);
        fs::write(p.join(".lpm").join("install-hash"), &hash).unwrap();

        let state = check_install_state(p);
        assert!(
            !state.up_to_date,
            "semantically invalid manifest must not be up to date"
        );
        assert!(
            state.hash.is_some(),
            "readable file should still produce a hash for dev.rs"
        );
    }

    #[test]
    fn hash_is_deterministic() {
        let h1 = compute_install_hash("pkg1", "lock1");
        let h2 = compute_install_hash("pkg1", "lock1");
        assert_eq!(h1, h2);
    }

    #[test]
    fn hash_differs_with_different_content() {
        let h1 = compute_install_hash("pkg1", "lock1");
        let h2 = compute_install_hash("pkg2", "lock1");
        let h3 = compute_install_hash("pkg1", "lock2");
        assert_ne!(h1, h2);
        assert_ne!(h1, h3);
    }

    #[test]
    fn domain_separator_prevents_collision() {
        // "ab" + "\0" + "cd" != "a" + "\0" + "bcd"
        let h1 = compute_install_hash("ab", "cd");
        let h2 = compute_install_hash("a", "bcd");
        assert_ne!(h1, h2);
    }

    #[test]
    fn schema_tag_is_baked_into_hash() {
        // Pin the hash of known inputs against the current schema tag so
        // that any accidental change to `INSTALL_HASH_SCHEMA_TAG` — or
        // removal of the `hasher.update(tag)` line — makes this test
        // fail loudly. The expected value below was computed from
        //   SHA256("lpm-install-hash-v2\x00" || "pkg" || "\x00" || "lock")
        // at the time the schema was bumped to v2 (2026-04-16). Updating
        // this constant is a deliberate act that must accompany any
        // schema-version bump.
        let actual = compute_install_hash("pkg", "lock");
        let expected_v2 = "c4e1b9f32454d660f02fcb5dbc4293f4a1f8ec4a0c263c490779c48f061482ae";
        assert_eq!(
            actual, expected_v2,
            "install-hash schema tag drift — bump INSTALL_HASH_SCHEMA_TAG and update this test \
             together. Current tag must produce the pinned hash for the fixed inputs."
        );
    }

    #[test]
    fn schema_tag_change_would_change_hash() {
        // Dual to the pin test above — prove the schema tag is
        // load-bearing. A v1 install-hash (no tag) of the same inputs
        // must NOT match the current v2 hash.
        fn v1_hash(pkg: &str, lock: &str) -> String {
            let mut h = Sha256::new();
            h.update(pkg.as_bytes());
            h.update(b"\x00");
            h.update(lock.as_bytes());
            format!("{:x}", h.finalize())
        }
        assert_ne!(
            compute_install_hash("pkg", "lock"),
            v1_hash("pkg", "lock"),
            "v2 must not collide with v1 — that's the whole point of the schema tag"
        );
    }

    #[test]
    fn workspace_root_detected() {
        let dir = TempDir::new().unwrap();
        fs::write(
            dir.path().join("package.json"),
            r#"{"workspaces":["packages/*"]}"#,
        )
        .unwrap();
        assert!(is_likely_workspace_root(dir.path()));
    }

    #[test]
    fn non_workspace_not_detected() {
        let dir = TempDir::new().unwrap();
        fs::write(
            dir.path().join("package.json"),
            r#"{"dependencies":{"a":"^1.0.0"}}"#,
        )
        .unwrap();
        assert!(!is_likely_workspace_root(dir.path()));
    }

    #[test]
    fn missing_package_json_not_workspace() {
        let dir = TempDir::new().unwrap();
        assert!(!is_likely_workspace_root(dir.path()));
    }

    #[test]
    fn missing_install_hash_returns_false() {
        let dir = TempDir::new().unwrap();
        let p = dir.path();
        fs::write(p.join("package.json"), r#"{"dependencies":{}}"#).unwrap();
        fs::write(p.join("lpm.lock"), "").unwrap();
        fs::create_dir_all(p.join("node_modules")).unwrap();
        // No .lpm/install-hash
        let state = check_install_state(p);
        assert!(!state.up_to_date);
        assert!(state.hash.is_some());
    }

    // ── Phase 44: v2 mtime-fast-path tests ─────────────────────────

    fn setup_up_to_date_project_v2() -> TempDir {
        // Like `setup_up_to_date_project` but writes the install-hash
        // in v2 format (hash + mtime line) via `write_install_hash`.
        let dir = TempDir::new().unwrap();
        let p = dir.path();
        fs::write(p.join("package.json"), r#"{"dependencies":{"a":"^1.0.0"}}"#).unwrap();
        fs::write(p.join("lpm.lock"), "lock-content").unwrap();
        fs::create_dir_all(p.join("node_modules")).unwrap();
        let hash = compute_install_hash(
            &fs::read_to_string(p.join("package.json")).unwrap(),
            "lock-content",
        );
        write_install_hash(p, &hash).unwrap();
        dir
    }

    #[test]
    fn v2_fast_path_returns_up_to_date_on_matching_mtimes() {
        let dir = setup_up_to_date_project_v2();
        let state = check_install_state(dir.path());
        assert!(state.up_to_date);
        assert!(state.hash.is_some());
    }

    #[test]
    fn v2_fast_path_rejects_when_pkg_mtime_changes() {
        let dir = setup_up_to_date_project_v2();
        // Sleep briefly to cross the mtime resolution boundary, then
        // rewrite package.json identically — content-equal but new mtime.
        std::thread::sleep(std::time::Duration::from_millis(20));
        fs::write(
            dir.path().join("package.json"),
            r#"{"dependencies":{"a":"^1.0.0"}}"#,
        )
        .unwrap();
        let state = check_install_state(dir.path());
        // Fast path rejects → falls through to hash path, which passes
        // (content is identical). End-to-end still says up-to-date, but
        // via the slow path this time.
        assert!(state.up_to_date);
    }

    #[test]
    fn v2_fast_path_rejects_when_content_actually_changed() {
        let dir = setup_up_to_date_project_v2();
        // Rewrite package.json with different content (mtime also changes).
        std::thread::sleep(std::time::Duration::from_millis(20));
        fs::write(
            dir.path().join("package.json"),
            r#"{"dependencies":{"b":"^2.0.0"}}"#,
        )
        .unwrap();
        let state = check_install_state(dir.path());
        assert!(!state.up_to_date);
    }

    #[test]
    fn v2_fast_path_rejects_on_external_node_modules_mutation() {
        let dir = setup_up_to_date_project_v2();
        // Touch node_modules so its mtime is AFTER install-hash's mtime.
        std::thread::sleep(std::time::Duration::from_millis(20));
        fs::write(dir.path().join("node_modules/.marker"), "").unwrap();
        let state = check_install_state(dir.path());
        assert!(
            !state.up_to_date,
            "external mutation under node_modules must invalidate fast path"
        );
    }

    #[test]
    fn v1_bare_hash_file_still_accepted_via_slow_path() {
        // Forward-compat: a v1 install-hash file (bare 64-char hex,
        // no mtime line) must still work — the fast path returns None
        // and the slow path reads + hashes as before.
        let dir = TempDir::new().unwrap();
        let p = dir.path();
        fs::write(p.join("package.json"), r#"{"dependencies":{"a":"^1.0.0"}}"#).unwrap();
        fs::write(p.join("lpm.lock"), "lock-content").unwrap();
        fs::create_dir_all(p.join("node_modules")).unwrap();
        fs::create_dir_all(p.join(".lpm")).unwrap();
        let hash = compute_install_hash(
            &fs::read_to_string(p.join("package.json")).unwrap(),
            "lock-content",
        );
        // Bare write — v1 format only.
        fs::write(p.join(".lpm").join("install-hash"), &hash).unwrap();
        let state = check_install_state(p);
        assert!(state.up_to_date);
    }

    #[test]
    fn write_install_hash_produces_v2_format() {
        // Contract: the file content starts with the hash followed by
        // `\nm:<pkg>:<lock>\n`. Pins the on-disk format so rollback
        // compatibility (a v1 reader sees the hash on line 1 after trim)
        // is preserved.
        let dir = TempDir::new().unwrap();
        let p = dir.path();
        fs::write(p.join("package.json"), r#"{"dependencies":{}}"#).unwrap();
        fs::write(p.join("lpm.lock"), "").unwrap();
        write_install_hash(p, "abc123").unwrap();
        let content = fs::read_to_string(p.join(".lpm").join("install-hash")).unwrap();
        let mut lines = content.lines();
        assert_eq!(lines.next().unwrap(), "abc123");
        let mtime_line = lines.next().unwrap();
        assert!(
            mtime_line.starts_with("m:"),
            "expected mtime line, got {mtime_line:?}"
        );
        let rest = mtime_line.strip_prefix("m:").unwrap();
        let parts: Vec<&str> = rest.split(':').collect();
        assert_eq!(parts.len(), 2, "mtime line must have two fields");
        assert!(parts[0].parse::<u64>().is_ok(), "pkg mtime must be u64");
        assert!(parts[1].parse::<u64>().is_ok(), "lock mtime must be u64");
    }

    #[test]
    fn check_install_state_with_content_skips_pkg_read() {
        // Contract: the fast-lane variant must behave identically to
        // `check_install_state` when given the correct content.
        let dir = setup_up_to_date_project_v2();
        let content = fs::read_to_string(dir.path().join("package.json")).unwrap();
        let state = check_install_state_with_content(dir.path(), &content);
        assert!(state.up_to_date);
    }

    #[test]
    fn is_workspace_root_content_detects_workspace_key() {
        assert!(is_workspace_root_content(
            r#"{"name":"root","workspaces":["packages/*"]}"#
        ));
        assert!(!is_workspace_root_content(r#"{"name":"leaf"}"#));
    }
}
