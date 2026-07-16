//! Cleanup for package-skill editor links created by earlier installs.
//!
//! Current package-skill installs only materialize `.lpm/skills/<package>/`
//! and never create editor links or modify editor configuration.

use std::path::Path;

/// Remove editor links associated with one package's skills.
pub fn remove_editor_skills(project_dir: &Path, package_short_name: &str) {
    let cursor_rules = project_dir.join(".cursor").join("rules");
    let entries = match std::fs::read_dir(&cursor_rules) {
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
        if entry.file_name().to_string_lossy().starts_with(&prefix)
            && let Err(error) = std::fs::remove_file(entry.path())
            && error.kind() != std::io::ErrorKind::NotFound
        {
            tracing::debug!(
                "could not remove package-skill editor link {}: {error}",
                entry.path().display()
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remove_editor_skills_only_cleans_matching_package_links() {
        let directory = tempfile::tempdir().unwrap();
        let cursor_rules = directory.path().join(".cursor/rules");
        std::fs::create_dir_all(&cursor_rules).unwrap();
        std::fs::write(cursor_rules.join("owner.pkg--guide.md"), "skill content").unwrap();
        std::fs::write(cursor_rules.join("owner.pkg--api.md"), "skill content").unwrap();
        std::fs::write(cursor_rules.join("other.pkg--guide.md"), "other content").unwrap();

        remove_editor_skills(directory.path(), "owner.pkg");

        assert!(!cursor_rules.join("owner.pkg--guide.md").exists());
        assert!(!cursor_rules.join("owner.pkg--api.md").exists());
        assert!(cursor_rules.join("other.pkg--guide.md").exists());
    }
}
