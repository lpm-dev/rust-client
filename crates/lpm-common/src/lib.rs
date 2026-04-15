pub mod error;
pub mod integrity;
pub mod package_name;
pub mod paths;

pub use error::LpmError;
pub use integrity::Integrity;
pub use package_name::PackageName;
pub use paths::{
    FsKind, INSTALL_READY_MARKER, LpmRoot, as_extended_path, is_local_fs, with_exclusive_lock,
};

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
