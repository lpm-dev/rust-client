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
/// metacharacters that occur in the project path itself. The path's prefix
/// and root stay as they are, as `glob` reads them literally: escaped, the
/// `\\?\C:` that `canonicalize` gives on Windows would name a UNC share.
pub fn rooted_project_glob(project_dir: &Path, pattern: &str) -> String {
    use std::path::{Component, MAIN_SEPARATOR};

    let mut rooted = String::new();
    for component in project_dir.components() {
        match component {
            Component::Prefix(prefix) => rooted.push_str(&prefix.as_os_str().to_string_lossy()),
            Component::RootDir => rooted.push(MAIN_SEPARATOR),
            name => {
                if !rooted.is_empty() && !rooted.ends_with(MAIN_SEPARATOR) {
                    rooted.push(MAIN_SEPARATOR);
                }
                rooted.push_str(&glob::Pattern::escape(&name.as_os_str().to_string_lossy()));
            }
        }
    }
    if !rooted.is_empty() && !rooted.ends_with(MAIN_SEPARATOR) {
        rooted.push(MAIN_SEPARATOR);
    }
    rooted.push_str(pattern);
    rooted
}

/// The path `glob` walks for `project_dir`, which its matches start with:
/// `project_dir`, but a verbatim UNC path, which `canonicalize` gives on
/// Windows for a network share or a drive mapped to one, as
/// `\\server\share\...`, since `glob` reads nothing under a verbatim path
/// but a drive's.
pub fn project_glob_root(project_dir: &Path) -> std::borrow::Cow<'_, Path> {
    #[cfg(windows)]
    {
        use std::path::{Component, Prefix};

        let mut components = project_dir.components();
        if let Some(Component::Prefix(prefix)) = components.next()
            && let Prefix::VerbatimUNC(server, share) = prefix.kind()
        {
            let mut root = std::ffi::OsString::from(r"\\");
            root.push(server);
            root.push(r"\");
            root.push(share);
            let mut path = std::path::PathBuf::from(root);
            path.extend(components);
            return std::borrow::Cow::Owned(path);
        }
    }
    std::borrow::Cow::Borrowed(project_dir)
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
    fn a_canonical_project_path_is_globbed_where_it_is() {
        use super::project_glob_root;

        let dir = tempfile::tempdir().unwrap();
        // `\\?\C:\...` on Windows, with a name that holds a glob metacharacter.
        let project = std::fs::canonicalize(dir.path()).unwrap().join("pro[j]");
        std::fs::create_dir_all(project.join("dist")).unwrap();
        std::fs::write(project.join("dist/value.js"), "1").unwrap();
        let root = project_glob_root(&project);

        // `**` matches directories only; task outputs add `/*` for files.
        let matched: Vec<_> = glob::glob(&rooted_project_glob(&root, "dist/**/*"))
            .unwrap()
            .map(Result::unwrap)
            .collect();

        let expected = Path::new("dist").join("value.js");
        assert!(
            matched
                .iter()
                .any(|entry| entry.strip_prefix(&root).ok() == Some(expected.as_path())),
            "{matched:?}"
        );
    }

    #[cfg(windows)]
    #[test]
    fn a_verbatim_share_is_globbed_by_its_share_name() {
        use super::project_glob_root;

        assert_eq!(
            project_glob_root(Path::new(r"\\?\UNC\server\share\project")),
            Path::new(r"\\server\share\project")
        );
        assert_eq!(
            project_glob_root(Path::new(r"\\?\C:\project")),
            Path::new(r"\\?\C:\project")
        );
    }

    #[test]
    fn rooted_glob_escapes_metacharacters_in_project_path() {
        let rooted = rooted_project_glob(Path::new("project[abc]"), "dist/**");
        let pattern = glob::Pattern::new(&rooted).unwrap();
        assert!(pattern.matches_path(&Path::new("project[abc]").join("dist/value.js")));
        assert!(!pattern.matches_path(&Path::new("projecta").join("dist/value.js")));
    }
}
