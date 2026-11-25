use cap_fs_ext::DirExt as _;
use lpm_skill::{
    MAX_SKILL_DIRECTORIES, MAX_SKILLS_ROOT_ENTRIES, SKILL_DIRECTORIES_ROOT, SKILL_DOCUMENT,
};
use std::io;
use std::path::Path;

/// The names of the skill directories a package ships: real directories
/// directly under its `skills/` with a valid skill name and a regular
/// `SKILL.md`, sorted. Links are never followed, and the listing stops at
/// the skills-root and skill-count limits.
pub(crate) fn skill_directory_names(package: &cap_std::fs::Dir) -> io::Result<Vec<String>> {
    match package.symlink_metadata(SKILL_DIRECTORIES_ROOT) {
        Ok(metadata) if metadata.is_dir() => {}
        Ok(_) => return Ok(Vec::new()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error),
    }
    let root = package.open_dir_nofollow(SKILL_DIRECTORIES_ROOT)?;
    let mut names = Vec::new();
    for entry in root.entries()?.take(MAX_SKILLS_ROOT_ENTRIES) {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let file_name = entry.file_name();
        let Some(name) = file_name.to_str() else {
            continue;
        };
        if !lpm_skill::is_skill_name(name) {
            continue;
        }
        let document = root.symlink_metadata(Path::new(name).join(SKILL_DOCUMENT));
        if document.is_ok_and(|metadata| metadata.is_file()) {
            names.push(name.to_string());
            if names.len() == MAX_SKILL_DIRECTORIES {
                break;
            }
        }
    }
    names.sort_unstable();
    Ok(names)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open(path: &Path) -> cap_std::fs::Dir {
        cap_std::fs::Dir::open_ambient_dir(path, cap_std::ambient_authority()).unwrap()
    }

    fn write_skill(root: &Path, name: &str) {
        let directory = root.join("skills").join(name);
        std::fs::create_dir_all(&directory).unwrap();
        std::fs::write(directory.join("SKILL.md"), "---\nname: x\n---\n").unwrap();
    }

    #[test]
    fn lists_only_named_directories_with_a_regular_skill_document() {
        let package = tempfile::tempdir().unwrap();
        write_skill(package.path(), "deploy");
        write_skill(package.path(), "audit");
        write_skill(package.path(), "Bad_Name");
        std::fs::create_dir_all(package.path().join("skills/no-document")).unwrap();
        std::fs::write(package.path().join("skills/notes.md"), "x").unwrap();
        std::fs::create_dir_all(package.path().join("skills/folder-document/SKILL.md")).unwrap();

        let names = skill_directory_names(&open(package.path())).unwrap();

        assert_eq!(names, ["audit", "deploy"]);
    }

    #[test]
    fn a_package_without_a_skills_directory_ships_none() {
        let package = tempfile::tempdir().unwrap();
        std::fs::write(package.path().join("skills"), "not a directory").unwrap();
        assert!(
            skill_directory_names(&open(package.path()))
                .unwrap()
                .is_empty()
        );

        let empty = tempfile::tempdir().unwrap();
        assert!(
            skill_directory_names(&open(empty.path()))
                .unwrap()
                .is_empty()
        );
    }

    #[cfg(unix)]
    #[test]
    fn linked_skills_directories_and_skills_are_never_followed() {
        let outside = tempfile::tempdir().unwrap();
        write_skill(outside.path(), "escaped");

        let linked_root = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(
            outside.path().join("skills"),
            linked_root.path().join("skills"),
        )
        .unwrap();
        assert!(
            skill_directory_names(&open(linked_root.path()))
                .unwrap()
                .is_empty()
        );

        let linked_skill = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(linked_skill.path().join("skills")).unwrap();
        std::os::unix::fs::symlink(
            outside.path().join("skills/escaped"),
            linked_skill.path().join("skills/escaped"),
        )
        .unwrap();
        write_skill(linked_skill.path(), "real");
        let documented = linked_skill.path().join("skills/linked-document");
        std::fs::create_dir_all(&documented).unwrap();
        std::os::unix::fs::symlink(
            outside.path().join("skills/escaped/SKILL.md"),
            documented.join("SKILL.md"),
        )
        .unwrap();

        assert_eq!(
            skill_directory_names(&open(linked_skill.path())).unwrap(),
            ["real"]
        );
    }
}
