//! Cleanup for package-skill editor links created by earlier installs.
//!
//! Current package-skill installs only materialize `.lpm/skills/<package>/`
//! and never create editor links or modify editor configuration.

use cap_fs_ext::DirExt as _;
use std::path::Path;

/// Remove editor links associated with one package's skills.
pub fn remove_editor_skills(project_dir: &Path, package_short_name: &str) {
    let cursor_rules = project_dir.join(".cursor").join("rules");
    let directory = match crate::project_fs::open_directory(project_dir, Path::new(".cursor/rules"))
    {
        Ok(Some(directory)) => directory,
        Ok(None) => return,
        Err(error) => {
            tracing::debug!("could not safely open package-skill editor links: {error}");
            return;
        }
    };
    let entries = match directory.entries() {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return,
        Err(error) => {
            tracing::debug!(
                "could not inspect package-skill editor links at {}: {error}",
                cursor_rules.display()
            );
            return;
        }
    };
    let prefix = format!("{package_short_name}--");
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                tracing::debug!(
                    "could not inspect an editor-link entry at {}: {error}",
                    cursor_rules.display()
                );
                continue;
            }
        };
        let filename = entry.file_name();
        let filename_text = filename.to_string_lossy();
        let Some(skill_file) = filename_text.strip_prefix(&prefix) else {
            continue;
        };
        let Ok(target) = directory.read_link_contents(&filename) else {
            continue;
        };
        if is_package_skill_target(
            project_dir,
            package_short_name,
            skill_file,
            &cursor_rules,
            &target,
        ) && let Err(error) = directory.remove_file_or_symlink(&filename)
            && error.kind() != std::io::ErrorKind::NotFound
        {
            tracing::debug!(
                "could not remove package-skill editor link {}: {error}",
                cursor_rules.join(filename).display()
            );
        }
    }
}

pub(crate) fn is_package_skill_target(
    project: &Path,
    package: &str,
    skill_file: &str,
    link_parent: &Path,
    target: &Path,
) -> bool {
    let expected = project.join(".lpm/skills").join(package).join(skill_file);
    let Some(actual) = crate::project_fs::canonicalize_with_missing_tail(&link_parent.join(target))
    else {
        return false;
    };
    crate::project_fs::canonicalize_with_missing_tail(&expected).as_ref() == Some(&actual)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(any(unix, windows))]
    #[test]
    fn remove_editor_skills_only_cleans_matching_package_links() {
        let directory = tempfile::tempdir().unwrap();
        let cursor_rules = directory.path().join(".cursor/rules");
        std::fs::create_dir_all(&cursor_rules).unwrap();
        let skills = directory.path().join(".lpm/skills/owner.pkg");
        std::fs::create_dir_all(&skills).unwrap();
        std::fs::write(skills.join("guide.md"), "skill content").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(
            "../../.lpm/skills/owner.pkg/guide.md",
            cursor_rules.join("owner.pkg--guide.md"),
        )
        .unwrap();
        #[cfg(windows)]
        std::os::windows::fs::symlink_file(
            skills.join("guide.md"),
            cursor_rules.join("owner.pkg--guide.md"),
        )
        .unwrap();
        std::fs::write(cursor_rules.join("owner.pkg--api.md"), "user content").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(
            "other.pkg--guide.md",
            cursor_rules.join("owner.pkg--foreign.md"),
        )
        .unwrap();
        std::fs::write(cursor_rules.join("other.pkg--guide.md"), "other content").unwrap();

        remove_editor_skills(directory.path(), "owner.pkg");

        assert!(!cursor_rules.join("owner.pkg--guide.md").exists());
        assert!(cursor_rules.join("owner.pkg--api.md").exists());
        #[cfg(unix)]
        assert!(cursor_rules.join("owner.pkg--foreign.md").is_symlink());
        assert!(cursor_rules.join("other.pkg--guide.md").exists());
    }
}
