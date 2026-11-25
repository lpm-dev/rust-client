use super::state::{STATE_FILE, create_root, open_root};
use cap_fs_ext::DirExt as _;
use cap_std::fs::Dir;
use lpm_common::LpmError;
use lpm_skill::{SkillDirectoryEntry, SkillEntryKind};
use std::io::{self, Write as _};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

/// Writes `entries`, the bytes the skill was checked and scanned as, as the
/// skill's copy under `.lpm/linked-skills/<skill>`. The copy is finished in
/// a staging directory and renamed into place, so links to it never see a
/// partial one. Files are read-only where the platform supports it, and
/// nothing is executable.
pub(crate) fn write_snapshot(
    project_dir: &Path,
    skill: &str,
    entries: &[SkillDirectoryEntry],
) -> Result<(), LpmError> {
    let root = create_root(project_dir)?;
    let staging = staging_name();
    root.create_dir(&staging)?;
    let result = stage_and_swap(&root, &staging, skill, entries);
    let _ = crate::project_fs::remove_entry(&root, Path::new(&staging));
    result
}

fn stage_and_swap(
    root: &Dir,
    staging: &str,
    skill: &str,
    entries: &[SkillDirectoryEntry],
) -> Result<(), LpmError> {
    let staged = format!("{staging}/{skill}");
    root.create_dir(&staged)?;
    write_tree(&root.open_dir_nofollow(&staged)?, skill, entries)?;
    let retired = format!("{staging}/.retired");
    let replaced = match root.symlink_metadata(skill) {
        Ok(metadata) if metadata.is_dir() && !crate::project_fs::is_link(&metadata) => {
            root.rename(skill, root, &retired)?;
            true
        }
        Ok(_) => {
            crate::project_fs::remove_entry(root, Path::new(skill))?;
            false
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => false,
        Err(error) => return Err(LpmError::Io(error)),
    };
    if let Err(error) = root.rename(&staged, root, skill) {
        if replaced {
            let _ = root.rename(&retired, root, skill);
        }
        return Err(LpmError::Io(error));
    }
    Ok(())
}

/// The prefix of a folder a removal moved aside to check before deleting
/// it. The sweep never deletes one: if the check fails and the folder
/// can't go back, it is someone else's.
pub(crate) const RETIRING_PREFIX: &str = ".retiring-";

/// A unique name for a folder a removal moves aside.
pub(crate) fn retiring_name() -> String {
    format!(
        "{RETIRING_PREFIX}{}",
        staging_name().trim_start_matches(".stage-")
    )
}

/// A fresh name for a folder LPM builds in its store, which [`sweep`]
/// removes if a run leaves it behind.
pub(crate) fn staging_name() -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_nanos());
    format!(
        ".stage-{}-{nanos}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    )
}

/// Writes a checked skill's `entries` into `directory`, a new empty one.
pub(crate) fn write_tree(
    directory: &Dir,
    skill: &str,
    entries: &[SkillDirectoryEntry],
) -> Result<(), LpmError> {
    for entry in entries {
        match entry.kind {
            SkillEntryKind::Directory => directory.create_dir_all(&entry.path)?,
            SkillEntryKind::File => {
                let Some(content) = entry.content.as_deref() else {
                    return Err(LpmError::Registry(format!(
                        "skill `{skill}` file {} was not read",
                        entry.path
                    )));
                };
                if let Some((parent, _)) = entry.path.rsplit_once('/') {
                    directory.create_dir_all(parent)?;
                }
                write_read_only(directory, &entry.path, content)?;
            }
            SkillEntryKind::Symlink | SkillEntryKind::Other => {
                return Err(LpmError::Registry(format!(
                    "skill `{skill}` entry {} is not a file or directory",
                    entry.path
                )));
            }
        }
    }
    Ok(())
}

fn write_read_only(directory: &Dir, path: &str, content: &[u8]) -> io::Result<()> {
    let mut options = cap_std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    let mut file = directory.open_with(path, &options)?.into_std();
    file.write_all(content)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        file.set_permissions(std::fs::Permissions::from_mode(0o444))?;
    }
    Ok(())
}

/// The digest of the skill's copy as it is on disk now, or `None` when it
/// is missing, isn't a plain directory, or holds something LPM never
/// writes. Equal to the recorded digest exactly when the copy is intact.
pub(crate) fn snapshot_digest(project_dir: &Path, skill: &str) -> Option<String> {
    let root = open_root(project_dir).ok()??;
    let copy = root.open_dir_nofollow(skill).ok()?;
    super::discovery::tree_digest(&copy, None)
}

/// The skill's copy as entries [`write_tree`] can write elsewhere.
#[cfg(windows)]
pub(crate) fn snapshot_entries(
    project_dir: &Path,
    skill: &str,
) -> Result<Vec<SkillDirectoryEntry>, LpmError> {
    let root = open_root(project_dir)?
        .ok_or_else(|| LpmError::Registry(format!("LPM's copy of `{skill}` is missing")))?;
    Ok(super::discovery::read_skill_tree(
        &root.open_dir_nofollow(skill)?,
    )?)
}

/// Removes every copy and leftover staging directory under
/// `.lpm/linked-skills` that `keep` doesn't hold, and never a folder a
/// removal set aside.
pub(crate) fn sweep(project_dir: &Path, keep: impl Fn(&str) -> bool) {
    let Ok(Some(root)) = open_root(project_dir) else {
        return;
    };
    let Ok(entries) = root.entries() else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if name == STATE_FILE || name.starts_with(RETIRING_PREFIX) || keep(name) {
            continue;
        }
        let _ = crate::project_fs::remove_entry(&root, Path::new(name));
    }
}

#[cfg(test)]
mod tests {
    use super::super::state::{linked_skills_dir, snapshot_dir};
    use super::*;

    fn file(path: &str, content: &str) -> SkillDirectoryEntry {
        SkillDirectoryEntry {
            path: path.into(),
            kind: SkillEntryKind::File,
            size: content.len() as u64,
            content: Some(content.as_bytes().to_vec()),
        }
    }

    #[test]
    fn a_folder_set_aside_by_an_unfinished_removal_survives_the_sweep() {
        let project = tempfile::tempdir().unwrap();
        let aside = linked_skills_dir(project.path()).join(".retiring-1-2-3");
        std::fs::create_dir_all(&aside).unwrap();
        std::fs::write(aside.join("SKILL.md"), "the user's own skill").unwrap();

        sweep(project.path(), |_| false);

        assert!(aside.join("SKILL.md").exists());
    }

    #[test]
    fn a_snapshot_holds_exactly_the_checked_bytes_and_replaces_the_previous_one() {
        let project = tempfile::tempdir().unwrap();
        write_snapshot(
            project.path(),
            "deploy",
            &[file("SKILL.md", "one"), file("references/api.md", "api")],
        )
        .unwrap();
        let copy = snapshot_dir(project.path(), "deploy");
        assert_eq!(
            std::fs::read_to_string(copy.join("SKILL.md")).unwrap(),
            "one"
        );
        assert_eq!(
            std::fs::read_to_string(copy.join("references/api.md")).unwrap(),
            "api"
        );
        assert_eq!(
            snapshot_digest(project.path(), "deploy").unwrap(),
            lpm_skill::skill_files_digest([
                ("SKILL.md", b"one".as_slice()),
                ("references/api.md", b"api".as_slice())
            ])
        );

        write_snapshot(project.path(), "deploy", &[file("SKILL.md", "two")]).unwrap();
        assert_eq!(
            std::fs::read_to_string(copy.join("SKILL.md")).unwrap(),
            "two"
        );
        assert!(!copy.join("references").exists());
        let leftovers: Vec<_> = std::fs::read_dir(linked_skills_dir(project.path()))
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(leftovers, ["deploy"]);
    }

    #[cfg(unix)]
    #[test]
    fn snapshot_files_are_read_only_and_never_executable() {
        use std::os::unix::fs::PermissionsExt as _;
        let project = tempfile::tempdir().unwrap();
        write_snapshot(project.path(), "deploy", &[file("run.sh", "echo")]).unwrap();
        let mode = std::fs::metadata(snapshot_dir(project.path(), "deploy").join("run.sh"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o444);
        sweep(project.path(), |_| false);
        assert!(snapshot_digest(project.path(), "deploy").is_none());
    }

    #[cfg(unix)]
    #[test]
    fn a_link_planted_where_the_copy_goes_is_replaced_not_followed() {
        let project = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("keep.txt"), "keep").unwrap();
        let root = linked_skills_dir(project.path());
        std::fs::create_dir_all(&root).unwrap();
        std::os::unix::fs::symlink(outside.path(), root.join("deploy")).unwrap();

        write_snapshot(project.path(), "deploy", &[file("SKILL.md", "x")]).unwrap();

        assert!(snapshot_digest(project.path(), "deploy").is_some());
        assert_eq!(
            std::fs::read_to_string(outside.path().join("keep.txt")).unwrap(),
            "keep"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_copy_holding_a_link_has_no_digest() {
        let project = tempfile::tempdir().unwrap();
        write_snapshot(project.path(), "deploy", &[file("SKILL.md", "x")]).unwrap();
        std::os::unix::fs::symlink(
            "/etc/hosts",
            snapshot_dir(project.path(), "deploy").join("extra.md"),
        )
        .unwrap();

        assert!(snapshot_digest(project.path(), "deploy").is_none());
    }
}
