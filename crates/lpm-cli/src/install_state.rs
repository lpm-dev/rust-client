//! Sync-safe install-state check shared by the top-of-main fast lane,
//! `install.rs`, and `dev.rs`. Single source of truth — never duplicate.
//!
//! **Phase 34.1** — extracted from `install.rs::is_install_up_to_date()`
//! and `dev.rs::compute_install_hash()` / `dev.rs::needs_install()`.

use sha2::{Digest, Sha256};
use std::path::Path;

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

/// Compute the install hash from raw file contents.
/// Deterministic SHA-256: `pkg_content || 0x00 || lock_content`.
pub fn compute_install_hash(pkg_content: &str, lock_content: &str) -> String {
    let mut hasher = Sha256::new();
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
/// Cost: two `stat` calls + two-three file reads + one SHA-256 hash ≈ 1-2ms.
pub fn check_install_state(project_dir: &Path) -> InstallState {
    let pkg_json = project_dir.join("package.json");
    if !pkg_json.exists() {
        return InstallState {
            up_to_date: false,
            hash: None,
        };
    }

    let lock_path = project_dir.join("lpm.lock");
    let hash_file = project_dir.join(".lpm").join("install-hash");
    let nm = project_dir.join("node_modules");

    // Read package.json — always needed for hash computation
    let Ok(pkg_content) = std::fs::read_to_string(&pkg_json) else {
        return InstallState {
            up_to_date: false,
            hash: None,
        };
    };

    // Read lockfile — empty string if missing (hash will mismatch → needs install)
    let lock_content = std::fs::read_to_string(&lock_path).unwrap_or_default();
    let current_hash = compute_install_hash(&pkg_content, &lock_content);

    // Validate that package.json parses into the typed PackageJson struct —
    // the same deserialization the full install path uses via read_package_json()
    // at install.rs:447. A generic serde_json::Value check is NOT sufficient:
    // it accepts semantically invalid shapes like {"dependencies":[]} that the
    // typed parse correctly rejects (dependencies is HashMap<String, String>).
    //
    // The hash is still returned as Some so callers like dev.rs::needs_install()
    // know the file exists and can trigger a full install which surfaces the error.
    if serde_json::from_str::<lpm_workspace::PackageJson>(&pkg_content).is_err() {
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

    // Hash comparison
    let Ok(cached_hash) = std::fs::read_to_string(&hash_file) else {
        return InstallState {
            up_to_date: false,
            hash: Some(current_hash),
        };
    };
    if cached_hash.trim() != current_hash {
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
        Ok(content) => content.contains("\"workspaces\""),
        Err(_) => false,
    }
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
}
