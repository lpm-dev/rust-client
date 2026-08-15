use std::path::Path;

/// Validate a project-relative glob used for task cache inputs or outputs.
pub fn validate_project_glob(pattern: &str) -> Result<(), String> {
    if pattern.is_empty() {
        return Err("glob must not be empty".into());
    }
    if pattern.contains('\0') {
        return Err("null bytes are not allowed".into());
    }
    let normalized = pattern.replace('\\', "/");
    if normalized == ".."
        || normalized.starts_with("../")
        || normalized.ends_with("/..")
        || normalized.contains("/../")
    {
        return Err("path traversal is not allowed".into());
    }
    if normalized.starts_with('/') {
        return Err("absolute paths are not allowed".into());
    }
    if normalized.len() >= 2 {
        let bytes = normalized.as_bytes();
        if bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
            return Err("absolute paths are not allowed".into());
        }
    }
    glob::Pattern::new(pattern)
        .map(|_| ())
        .map_err(|error| format!("invalid glob: {error}"))
}

/// Join a validated relative glob to a project path without interpreting
/// metacharacters that occur in the project path itself.
pub fn rooted_project_glob(project_dir: &Path, pattern: &str) -> String {
    let mut rooted = glob::Pattern::escape(project_dir.to_string_lossy().as_ref());
    if !rooted.ends_with(std::path::MAIN_SEPARATOR) {
        rooted.push(std::path::MAIN_SEPARATOR);
    }
    rooted.push_str(pattern);
    rooted
}

#[cfg(test)]
mod tests {
    use super::{rooted_project_glob, validate_project_glob};
    use std::path::Path;

    #[test]
    fn project_glob_rejects_invalid_syntax() {
        assert!(validate_project_glob("[").is_err());
    }

    #[test]
    fn project_glob_rejects_empty_and_null_patterns() {
        for pattern in ["", "dist/\0value"] {
            assert!(
                validate_project_glob(pattern).is_err(),
                "invalid project glob was accepted: {pattern:?}"
            );
        }
    }

    #[test]
    fn project_glob_rejects_relative_and_absolute_escape() {
        for pattern in [
            "../secret",
            "dist/../secret",
            "/etc/passwd",
            "C:relative\\file",
            "C:\\temp\\file",
        ] {
            assert!(
                validate_project_glob(pattern).is_err(),
                "unsafe project glob was accepted: {pattern}"
            );
        }
    }

    #[test]
    fn project_glob_accepts_portable_relative_patterns() {
        for pattern in ["dist/**", "src/**/*.{js,ts}", "*.config.js"] {
            assert!(
                validate_project_glob(pattern).is_ok(),
                "valid project glob was rejected: {pattern}"
            );
        }
    }

    #[test]
    fn rooted_glob_escapes_metacharacters_in_project_path() {
        let rooted = rooted_project_glob(Path::new("project[abc]"), "dist/**");
        let pattern = glob::Pattern::new(&rooted).unwrap();
        assert!(pattern.matches_path(&Path::new("project[abc]").join("dist/value.js")));
        assert!(!pattern.matches_path(&Path::new("projecta").join("dist/value.js")));
    }
}
