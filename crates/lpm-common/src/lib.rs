pub mod color;
pub mod error;
pub mod integrity;
pub mod known_projects;
pub mod package_name;
pub mod paths;
pub mod provenance;
pub mod symlink;

pub use error::LpmError;
pub use integrity::Integrity;
pub use package_name::PackageName;
pub use paths::{
    ExclusiveLockHandle, FsKind, GLOBAL_INSTALL_PATH_BUDGET, INSTALL_READY_MARKER, LpmRoot,
    SharedLockHandle, as_extended_path, check_install_path_budget, is_local_fs,
    project_install_lock, try_with_exclusive_lock, with_exclusive_lock, with_exclusive_lock_async,
    with_shared_lock, with_shared_lock_async,
};
pub use provenance::ProvenanceSnapshot;
pub use symlink::create_dir_symlink_or_junction;

/// The LPM scope prefix. All LPM packages live under this scope.
pub const LPM_SCOPE: &str = "@lpm.dev";

/// Default LPM registry URL.
pub const DEFAULT_REGISTRY_URL: &str = "https://lpm.dev";

/// Default npm upstream registry URL.
pub const NPM_REGISTRY_URL: &str = "https://registry.npmjs.org";

/// Check whether a skill name is safe for use in filesystem paths.
///
/// Rejects empty strings, names longer than 128 chars, path separators,
/// parent-directory traversal, null bytes, and any non-ASCII-alphanumeric
/// character other than `-`, `_`, and `.`.
pub fn is_safe_skill_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && !name.contains('/')
        && !name.contains('\\')
        && !name.contains("..")
        && !name.contains('\0')
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
}

/// Sanitise a package short-name for use as a filesystem directory name.
///
/// Replaces path separators and null bytes with `-`. This is used when the
/// full `is_safe_skill_name` check is too strict (package names may contain
/// `.` which is allowed, but we still need to strip traversal characters).
pub fn sanitize_path_component(name: &str) -> String {
    name.replace("..", "_").replace(['/', '\\', '\0'], "-")
}

/// Default cap on small JSON/TOML state files that lpm reads at command
/// start (project-local `.lpm/build-state.json`, `.lpm/overrides-state.json`,
/// `.lpm/patch-state.json`, global `~/.lpm/known-projects.json`, global
/// manifest, L4 verdict cache, etc.).
///
/// Real-world state files are kilobytes; a 16 MB ceiling leaves several
/// orders of magnitude of headroom while preventing a malicious repo or
/// same-user state writer from forcing `read_to_string` + full serde
/// parse on a multi-GB file at every command start.
pub const STATE_FILE_SIZE_CAP_BYTES: u64 = 16 * 1024 * 1024;

/// Read a small state file with a size cap applied before any bytes
/// are buffered. Returns `Ok(None)` when the file is missing OR larger
/// than `cap`; returns `Ok(Some(bytes))` for files within budget;
/// returns `Err` only when the file exists, fits the cap, and the
/// read itself failed (disk error, permissions, etc.).
///
/// Caller treats the `Ok(None)` cap-overflow case the same as "missing
/// state" — these readers all fall back to "no prior state" when the
/// file fails to parse, so the cap is a stricter version of the
/// existing recovery posture. A `tracing::warn` fires on the overflow
/// arm so an operator can see the cap kicked in.
pub fn read_capped_state_file(
    path: &std::path::Path,
    cap: u64,
) -> std::io::Result<Option<Vec<u8>>> {
    let meta = match std::fs::metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    if meta.len() > cap {
        tracing::warn!(
            path = %path.display(),
            size = meta.len(),
            cap = cap,
            "state file exceeds size cap — treating as missing"
        );
        return Ok(None);
    }
    Ok(Some(std::fs::read(path)?))
}

/// Format bytes into a human-readable string (e.g., "1.2 KB", "3.4 MB").
pub fn format_bytes(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{bytes} B")
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else if bytes < 1024 * 1024 * 1024 {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.1} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── read_capped_state_file ────────────────────────────────────────

    /// Files under the cap round-trip transparently.
    #[test]
    fn capped_state_reader_returns_file_under_cap() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        std::fs::write(&path, br#"{"ok":true}"#).unwrap();
        let result = read_capped_state_file(&path, 64 * 1024)
            .expect("read must succeed")
            .expect("file under cap must return Some");
        assert_eq!(&result, br#"{"ok":true}"#);
    }

    /// Missing files map to `Ok(None)` — same shape callers used pre-fix
    /// via `read_to_string(..).ok()?`.
    #[test]
    fn capped_state_reader_treats_missing_as_none() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("does-not-exist.json");
        let result = read_capped_state_file(&path, 64 * 1024).expect("missing file is not an Err");
        assert!(result.is_none());
    }

    /// L28: files exceeding the cap are treated as missing — no bytes
    /// are buffered and no serde parse runs. A malicious repo state
    /// file can't force a multi-GB `read_to_string` at command start.
    #[test]
    fn capped_state_reader_treats_over_cap_as_none() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("huge.json");
        // 1 MB file with a tiny 256-byte cap — clearly oversize.
        std::fs::write(&path, vec![b'x'; 1024 * 1024]).unwrap();
        let result = read_capped_state_file(&path, 256).expect("over-cap is not an Err");
        assert!(
            result.is_none(),
            "file larger than cap must collapse to None"
        );
    }

    // ── is_safe_skill_name ────────────────────────────────────────────

    #[test]
    fn safe_skill_name_valid() {
        assert!(is_safe_skill_name("getting-started"));
        assert!(is_safe_skill_name("my_skill.v2"));
        assert!(is_safe_skill_name("a"));
        assert!(is_safe_skill_name("skill-123"));
    }

    #[test]
    fn safe_skill_name_rejects_traversal() {
        assert!(!is_safe_skill_name("../../etc/foo"));
        assert!(!is_safe_skill_name(".."));
        assert!(!is_safe_skill_name("foo/bar"));
        assert!(!is_safe_skill_name("foo\\bar"));
    }

    #[test]
    fn safe_skill_name_rejects_empty() {
        assert!(!is_safe_skill_name(""));
    }

    #[test]
    fn safe_skill_name_rejects_null_byte() {
        assert!(!is_safe_skill_name("a\0b"));
    }

    #[test]
    fn safe_skill_name_rejects_long() {
        let long = "a".repeat(129);
        assert!(!is_safe_skill_name(&long));
        // 128 is the limit
        let at_limit = "a".repeat(128);
        assert!(is_safe_skill_name(&at_limit));
    }

    #[test]
    fn safe_skill_name_rejects_special_chars() {
        assert!(!is_safe_skill_name("skill name"));
        assert!(!is_safe_skill_name("skill@name"));
        assert!(!is_safe_skill_name("skill#name"));
    }

    // ── sanitize_path_component ───────────────────────────────────────

    #[test]
    fn sanitize_strips_traversal() {
        assert_eq!(sanitize_path_component("../../etc"), "_-_-etc");
        assert_eq!(sanitize_path_component("foo/bar"), "foo-bar");
        assert_eq!(sanitize_path_component("ok.pkg"), "ok.pkg");
    }
}
