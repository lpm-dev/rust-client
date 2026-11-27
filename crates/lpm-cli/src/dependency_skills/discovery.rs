use cap_fs_ext::{DirExt as _, FollowSymlinks, OpenOptionsFollowExt as _};
use lpm_skill::{
    MAX_SKILL_DIRECTORIES, MAX_SKILL_DIRECTORY_DEPTH, MAX_SKILL_DIRECTORY_ENTRIES,
    MAX_SKILL_DIRECTORY_FILE_SIZE, MAX_SKILL_DIRECTORY_SIZE, MAX_SKILL_DOCUMENT_SIZE,
    MAX_SKILLS_ROOT_ENTRIES, SKILL_DIRECTORIES_ROOT, SKILL_DOCUMENT, SkillDirectoryEntry,
    SkillEntryKind,
};
use std::io::{self, Read as _};
use std::path::Path;

/// The names of the skill directories a package ships: real directories
/// directly under its `skills/` with a valid skill name and a regular
/// `SKILL.md`, the first ones in name order up to the skill-count limit.
/// Links are never followed. A `skills/` holding more than
/// [`MAX_SKILLS_ROOT_ENTRIES`] entries is an [`io::ErrorKind::InvalidData`]
/// error.
pub(crate) fn skill_directory_names(package: &cap_std::fs::Dir) -> io::Result<Vec<String>> {
    skill_directory_listing(package).map(|listing| listing.names)
}

/// The skill directories a package ships, as [`skill_directory_names`] lists
/// them.
#[derive(Default)]
pub(crate) struct SkillListing {
    pub(crate) names: Vec<String>,
    /// Whether a listed directory's `SKILL.md` couldn't be inspected: it is
    /// listed so its skill is held as unreadable, but whether the package
    /// ships that skill is unknown.
    pub(crate) unconfirmed: bool,
}

/// [`skill_directory_names`], saying whether a listed `SKILL.md` couldn't be
/// inspected.
pub(crate) fn skill_directory_listing(package: &cap_std::fs::Dir) -> io::Result<SkillListing> {
    match package.symlink_metadata(SKILL_DIRECTORIES_ROOT) {
        Ok(metadata) if metadata.is_dir() && !crate::project_fs::is_link(&metadata) => {}
        Ok(_) => return Ok(SkillListing::default()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(SkillListing::default());
        }
        Err(error) => return Err(error),
    }
    let root = package.open_dir_nofollow(SKILL_DIRECTORIES_ROOT)?;
    let mut candidates = Vec::new();
    for (index, entry) in root.entries()?.enumerate() {
        if index == MAX_SKILLS_ROOT_ENTRIES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("its skills folder holds more than {MAX_SKILLS_ROOT_ENTRIES} entries"),
            ));
        }
        if let Some(name) = entry?
            .file_name()
            .to_str()
            .filter(|name| lpm_skill::is_skill_name(name))
        {
            candidates.push(name.to_string());
        }
    }
    let mut directories = Vec::with_capacity(candidates.len());
    for name in candidates {
        match root.symlink_metadata(&name) {
            Ok(metadata) if metadata.is_dir() && !crate::project_fs::is_link(&metadata) => {
                directories.push(name);
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    directories.sort_unstable();
    let mut names = Vec::with_capacity(directories.len().min(MAX_SKILL_DIRECTORIES));
    let mut unconfirmed = false;
    for name in directories {
        let listed = match root.symlink_metadata(Path::new(&name).join(SKILL_DOCUMENT)) {
            Ok(metadata) => metadata.is_file(),
            Err(error) if error.kind() == io::ErrorKind::NotFound => false,
            Err(_) => {
                unconfirmed = true;
                true
            }
        };
        if listed {
            names.push(name);
            if names.len() == MAX_SKILL_DIRECTORIES {
                break;
            }
        }
    }
    Ok(SkillListing { names, unconfirmed })
}

/// Reads one skill directory of a package, `skills/<name>`, for
/// [`lpm_skill::check_skill_directory`]: every entry, without following
/// links, with each file's bytes while the size limits allow. The walk stops
/// one entry past the entry limit and one level past the depth limit, so
/// the check reports an oversized skill instead of the walk reading it all.
pub(crate) fn read_skill_directory(
    package: &cap_std::fs::Dir,
    name: &str,
) -> io::Result<Vec<SkillDirectoryEntry>> {
    let root = package.open_dir_nofollow(SKILL_DIRECTORIES_ROOT)?;
    read_skill_tree(&root.open_dir_nofollow(name)?)
}

/// Reads an open skill directory as [`read_skill_directory`] does.
pub(crate) fn read_skill_tree(skill: &cap_std::fs::Dir) -> io::Result<Vec<SkillDirectoryEntry>> {
    read_tree(skill, 0, 0)
}

/// [`read_skill_tree`] with room for `extra_entries` entries and
/// `extra_bytes` bytes past a skill's limits, for a file LPM adds itself.
fn read_tree(
    skill: &cap_std::fs::Dir,
    extra_entries: usize,
    extra_bytes: u64,
) -> io::Result<Vec<SkillDirectoryEntry>> {
    let mut walk = Walk {
        entries: Vec::with_capacity(8),
        total: 0,
        path: String::with_capacity(64),
        max_entries: MAX_SKILL_DIRECTORY_ENTRIES + extra_entries,
        max_bytes: MAX_SKILL_DIRECTORY_SIZE + extra_bytes,
    };
    walk.visit(skill, 1)?;
    Ok(walk.entries)
}

/// The [`lpm_skill::skill_files_digest`] of an open skill directory's files,
/// leaving out `skip` at its top, LPM's copy marker, which doesn't count
/// against the skill's limits. `None` when it can't be read, or holds
/// something LPM never writes into a copy: a link, a special file, a file
/// past the size limits, or a folder deeper than the walk reads.
pub(crate) fn tree_digest(skill: &cap_std::fs::Dir, skip: Option<&str>) -> Option<String> {
    let extra_entries = usize::from(skip.is_some());
    let extra_bytes = if skip.is_some() {
        super::links::MAX_MARKER_BYTES
    } else {
        0
    };
    let entries = read_tree(skill, extra_entries, extra_bytes).ok()?;
    let counted = entries
        .iter()
        .filter(|entry| Some(entry.path.as_str()) != skip)
        .count();
    if entries.len() > MAX_SKILL_DIRECTORY_ENTRIES + extra_entries
        || counted > MAX_SKILL_DIRECTORY_ENTRIES
    {
        return None;
    }
    let mut files = Vec::with_capacity(entries.len());
    for entry in &entries {
        match entry.kind {
            SkillEntryKind::Directory
                if entry.path.split('/').count() > MAX_SKILL_DIRECTORY_DEPTH =>
            {
                return None;
            }
            SkillEntryKind::Directory => {}
            SkillEntryKind::File if Some(entry.path.as_str()) == skip => {}
            SkillEntryKind::File => files.push((entry.path.as_str(), entry.content.as_deref()?)),
            SkillEntryKind::Symlink | SkillEntryKind::Other => return None,
        }
    }
    Some(lpm_skill::skill_files_digest(files))
}

struct Walk {
    entries: Vec<SkillDirectoryEntry>,
    total: u64,
    path: String,
    max_entries: usize,
    max_bytes: u64,
}

impl Walk {
    fn full(&self) -> bool {
        self.entries.len() > self.max_entries
    }

    fn visit(&mut self, directory: &cap_std::fs::Dir, depth: usize) -> io::Result<()> {
        let mut names: Vec<std::ffi::OsString> = Vec::new();
        for entry in directory.entries()? {
            names.push(entry?.file_name());
            if names.len() > self.max_entries {
                break;
            }
        }
        names.sort_unstable();
        let parent_length = self.path.len();
        for file_name in names {
            if self.full() {
                return Ok(());
            }
            self.path.truncate(parent_length);
            if parent_length > 0 {
                self.path.push('/');
            }
            self.path.push_str(&file_name.to_string_lossy());
            let metadata = directory.symlink_metadata(&file_name)?;
            let file_type = metadata.file_type();
            if crate::project_fs::is_link(&metadata) {
                self.push(SkillEntryKind::Symlink, 0, None);
            } else if file_type.is_dir() {
                self.push(SkillEntryKind::Directory, 0, None);
                if depth <= MAX_SKILL_DIRECTORY_DEPTH {
                    let child = directory.open_dir_nofollow(&file_name)?;
                    self.visit(&child, depth + 1)?;
                }
            } else if file_type.is_file() {
                let size = metadata.len();
                let limit = if parent_length == 0 && file_name == SKILL_DOCUMENT {
                    MAX_SKILL_DOCUMENT_SIZE
                } else {
                    MAX_SKILL_DIRECTORY_FILE_SIZE
                };
                let content = if size <= limit && self.total.saturating_add(size) <= self.max_bytes
                {
                    let content = read_file(directory, &file_name, limit)?;
                    self.total = self.total.saturating_add(content.len() as u64);
                    Some(content)
                } else {
                    self.total = self.total.saturating_add(size);
                    None
                };
                self.push(SkillEntryKind::File, size, content);
            } else {
                self.push(SkillEntryKind::Other, 0, None);
            }
        }
        self.path.truncate(parent_length);
        Ok(())
    }

    fn push(&mut self, kind: SkillEntryKind, size: u64, content: Option<Vec<u8>>) {
        self.entries.push(SkillDirectoryEntry {
            path: self.path.clone(),
            kind,
            size,
            content,
        });
    }
}

fn read_file(
    directory: &cap_std::fs::Dir,
    name: &std::ffi::OsStr,
    limit: u64,
) -> io::Result<Vec<u8>> {
    let mut options = cap_std::fs::OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No);
    let file = directory.open_with(name, &options)?;
    let mut content = Vec::new();
    file.into_std().take(limit + 1).read_to_end(&mut content)?;
    Ok(content)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn past_the_limits_the_first_names_in_order_are_listed_whatever_the_listing_order() {
        let package = tempfile::tempdir().unwrap();
        let root = package.path().join("skills");
        for index in (0..(MAX_SKILL_DIRECTORIES + 20)).rev() {
            let skill = root.join(format!("skill-{index:03}"));
            std::fs::create_dir_all(&skill).unwrap();
            std::fs::write(skill.join("SKILL.md"), "x").unwrap();
        }
        let directory =
            cap_std::fs::Dir::open_ambient_dir(package.path(), cap_std::ambient_authority())
                .unwrap();

        let names = skill_directory_names(&directory).unwrap();

        let expected: Vec<String> = (0..MAX_SKILL_DIRECTORIES)
            .map(|index| format!("skill-{index:03}"))
            .collect();
        assert_eq!(names, expected);
    }

    #[test]
    fn a_skills_folder_past_the_listing_limit_is_refused_the_same_way_every_time() {
        let package = tempfile::tempdir().unwrap();
        let root = package.path().join("skills");
        for index in 0..=MAX_SKILLS_ROOT_ENTRIES {
            std::fs::create_dir_all(root.join(format!("skill-{index:05}"))).unwrap();
        }

        let error = skill_directory_names(&open(package.path())).unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn a_copy_with_files_below_the_depth_the_walk_reads_has_no_digest() {
        let copy = tempfile::tempdir().unwrap();
        std::fs::write(copy.path().join("SKILL.md"), "x").unwrap();
        let mut deep = copy.path().to_path_buf();
        for level in 0..=lpm_skill::MAX_SKILL_DIRECTORY_DEPTH {
            deep.push(format!("level-{level}"));
        }
        std::fs::create_dir_all(&deep).unwrap();
        std::fs::write(deep.join("hidden.md"), "unseen").unwrap();

        assert_eq!(tree_digest(&open(copy.path()), None), None);
    }

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
