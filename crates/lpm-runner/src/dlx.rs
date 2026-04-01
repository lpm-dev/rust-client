//! `lpm dlx` — utilities for running packages without installing them.
//!
//! Cache management, package name parsing, and binary execution.
//! The install step is handled in the CLI layer (self-hosted via LPM's resolver/store/linker).

use crate::bin_path;
use lpm_common::LpmError;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// Default cache TTL in seconds (24 hours).
pub const CACHE_TTL_SECS: u64 = 24 * 60 * 60;

/// Get the dlx cache directory for a given package spec.
///
/// Returns `~/.lpm/dlx-cache/{hash}/` where hash is derived from the package spec.
pub fn dlx_cache_dir(package_spec: &str) -> Result<PathBuf, LpmError> {
    let lpm_home = dirs_home()?.join(".lpm").join("dlx-cache");

    // Deterministic hash of the package spec for cache key
    let hash = deterministic_hash(package_spec);
    Ok(lpm_home.join(hash))
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

/// Get the user's home directory.
fn dirs_home() -> Result<PathBuf, LpmError> {
    dirs::home_dir().ok_or_else(|| LpmError::Script("could not determine home directory".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dlx_cache_dir_is_stable() {
        let dir1 = dlx_cache_dir("cowsay").unwrap();
        let dir2 = dlx_cache_dir("cowsay").unwrap();
        assert_eq!(dir1, dir2);
    }

    #[test]
    fn dlx_cache_dir_differs_for_different_specs() {
        let dir1 = dlx_cache_dir("cowsay").unwrap();
        let dir2 = dlx_cache_dir("cowsay@1.0.0").unwrap();
        assert_ne!(dir1, dir2);
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
}
