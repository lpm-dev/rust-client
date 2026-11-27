use super::state::{LinkKind, Site, snapshot_dir};
use cap_fs_ext::{DirExt as _, FollowSymlinks, OpenOptionsFollowExt as _};
use cap_std::fs::Dir;
use lpm_common::LpmError;
use std::io::{self, Read as _};
use std::path::{Path, PathBuf};

/// The file a copied skill carries where links can't be made, naming the
/// skill it is a copy of and the digest of the files LPM wrote into it.
pub(crate) const COPY_MARKER: &str = ".lpm-linked-skill.json";
pub(crate) const MAX_MARKER_BYTES: u64 = 4096;
const MAX_PLACEHOLDER_BYTES: u64 = 4096;

/// What LPM recorded at a skill's place in a target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Recorded<'a> {
    pub(crate) kind: LinkKind,
    /// The digest of the files LPM linked there.
    pub(crate) digest: &'a str,
}

/// What is at a skill's place in a target directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum TargetEntry {
    Missing,
    /// A link to LPM's copy of the skill.
    Link,
    /// The file Git checks out for such a link where it can't make links.
    Placeholder,
    /// A copy carrying the skill's marker whose files still match the
    /// digest the marker records; holds that digest.
    Copy(String),
    /// Anything else, such as a skill the user wrote or a copy someone
    /// changed, which LPM never replaces or removes.
    Occupied,
}

impl TargetEntry {
    /// Whether this is LPM's entry for a skill recorded as `kind` with
    /// `digest`, as LPM made it.
    pub(crate) fn is_intact(&self, kind: LinkKind, digest: &str) -> bool {
        match (self, kind) {
            (Self::Link, LinkKind::Link) => true,
            (Self::Copy(found), LinkKind::Copy) => found == digest,
            _ => false,
        }
    }
}

/// A target directory, which every inspection and removal goes through. A
/// project's is reached through real directories only, since a checkout
/// can carry links; the home folder's agent folders may be links the user
/// made, as to a dotfiles repository, and are followed. Either way the
/// entries LPM makes inside are handled without following links.
pub(crate) struct TargetDir {
    directory: Dir,
    path: PathBuf,
}

impl TargetDir {
    /// Opens `target`, a directory relative to `site`'s base: `Ok(None)`
    /// when it doesn't exist, and an error when a file, or in a project a
    /// link, is in the way.
    pub(crate) fn open(site: &Site, target: &str) -> io::Result<Option<Self>> {
        let path = project_path(site.base(), target);
        if site.is_global() {
            return match Dir::open_ambient_dir(&path, cap_std::ambient_authority()) {
                Ok(directory) => Ok(Some(Self { directory, path })),
                Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
                Err(error) => Err(error),
            };
        }
        Ok(
            crate::project_fs::open_directory(site.base(), Path::new(target))?
                .map(|directory| Self { directory, path }),
        )
    }

    /// Opens `target`, creating what is missing of it, and refusing a file,
    /// or in a project a link, anywhere on the way. Adds the directories it
    /// created, outermost first, to `created`.
    pub(crate) fn create(site: &Site, target: &str, created: &mut Vec<String>) -> io::Result<Self> {
        if site.is_global() {
            return Self::create_following_links(site.base(), target, created);
        }
        let project_dir = site.base();
        let mut directory = Dir::open_ambient_dir(project_dir, cap_std::ambient_authority())?;
        let mut relative = String::with_capacity(target.len());
        for component in target.split('/') {
            if !relative.is_empty() {
                relative.push('/');
            }
            relative.push_str(component);
            let refuse = |error: io::Error| {
                io::Error::new(
                    error.kind(),
                    format!(
                        "refusing to link skills through {}, which is not a plain directory: {error}",
                        project_path(project_dir, &relative).display()
                    ),
                )
            };
            directory = match directory.open_dir_nofollow(component) {
                Ok(next) => next,
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    match directory.create_dir(component) {
                        Ok(()) => {
                            if !created.contains(&relative) {
                                created.push(relative.clone());
                            }
                        }
                        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                        Err(error) => return Err(error),
                    }
                    directory.open_dir_nofollow(component).map_err(refuse)?
                }
                Err(error) => return Err(refuse(error)),
            };
        }
        Ok(Self {
            directory,
            path: project_path(project_dir, target),
        })
    }

    /// [`Self::create`] for the home folder, through the links the user
    /// made on the way.
    fn create_following_links(
        base: &Path,
        target: &str,
        created: &mut Vec<String>,
    ) -> io::Result<Self> {
        let mut path = base.to_path_buf();
        let mut relative = String::with_capacity(target.len());
        for component in target.split('/') {
            path.push(component);
            if !relative.is_empty() {
                relative.push('/');
            }
            relative.push_str(component);
            match std::fs::metadata(&path) {
                Ok(metadata) if metadata.is_dir() => {}
                Ok(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::AlreadyExists,
                        format!(
                            "refusing to link skills through {}, which is not a directory",
                            path.display()
                        ),
                    ));
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    match std::fs::create_dir(&path) {
                        Ok(()) => {
                            if !created.contains(&relative) {
                                created.push(relative.clone());
                            }
                        }
                        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                            if !std::fs::metadata(&path).is_ok_and(|metadata| metadata.is_dir()) {
                                return Err(io::Error::new(
                                    io::ErrorKind::NotFound,
                                    format!(
                                        "refusing to link skills through {}, a link to something that doesn't exist",
                                        path.display()
                                    ),
                                ));
                            }
                        }
                        Err(error) => return Err(error),
                    }
                }
                Err(error) => return Err(error),
            }
        }
        Ok(Self {
            directory: Dir::open_ambient_dir(&path, cap_std::ambient_authority())?,
            path,
        })
    }

    pub(crate) fn inspect(&self, site: &Site, skill: &str) -> TargetEntry {
        let metadata = match self.directory.symlink_metadata(skill) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return TargetEntry::Missing,
            Err(_) => return TargetEntry::Occupied,
        };
        let copy = snapshot_dir(site, skill);
        if crate::project_fs::is_link(&metadata) {
            return if self.link_points_at(site, skill, &copy) {
                TargetEntry::Link
            } else {
                TargetEntry::Occupied
            };
        }
        if metadata.is_dir() {
            return self
                .copy_digest(skill)
                .map_or(TargetEntry::Occupied, TargetEntry::Copy);
        }
        if metadata.is_file() && self.is_placeholder(site, skill, &copy) {
            return TargetEntry::Placeholder;
        }
        TargetEntry::Occupied
    }

    /// Links `skill` here to its copy: a relative symbolic link, or on
    /// Windows a directory link, a junction, or a marked copy of the copy's
    /// files, `digest`.
    pub(crate) fn link(
        &self,
        site: &Site,
        skill: &str,
        digest: &str,
    ) -> Result<LinkKind, LpmError> {
        let copy = snapshot_dir(site, skill);
        let destination = link_destination(site, &copy, &self.path.join(skill));
        #[cfg(unix)]
        {
            let _ = digest;
            rustix::fs::symlinkat(&destination, &self.directory, skill).map_err(io::Error::from)?;
            Ok(LinkKind::Link)
        }
        #[cfg(windows)]
        {
            if self.directory.symlink_dir(&destination, skill).is_ok()
                || lpm_common::create_dir_symlink_or_junction(&copy, &self.path.join(skill)).is_ok()
            {
                return Ok(LinkKind::Link);
            }
            let entries = super::snapshot::snapshot_entries(site, skill)?;
            let store = super::state::create_root(site)?;
            let staging = super::snapshot::staging_name();
            store.create_dir(&staging)?;
            let staged = store.open_dir_nofollow(&staging)?;
            let built = super::snapshot::write_tree(&staged, skill, &entries).and_then(|()| {
                staged
                    .write(COPY_MARKER, copy_marker(skill, digest))
                    .map_err(LpmError::Io)
            });
            drop(staged);
            if let Err(error) =
                built.and_then(|()| Ok(store.rename(&staging, &self.directory, skill)?))
            {
                let _ = crate::project_fs::remove_entry(&store, Path::new(&staging));
                return Err(error);
            }
            Ok(LinkKind::Copy)
        }
    }

    /// Removes LPM's entry for `skill` after checking again that it is
    /// LPM's: a link or Git placeholder; a copy only when LPM `recorded` it
    /// there and it still holds the recorded files, so a copy LPM holds no
    /// record of, or one that changed, is never deleted; and a link it
    /// recorded that still points at a copies folder of the same shape
    /// elsewhere, as a junction does after the project moves. `Ok(false)`
    /// when something else is there.
    pub(crate) fn remove(
        &self,
        site: &Site,
        skill: &str,
        recorded: Option<Recorded<'_>>,
    ) -> Result<bool, LpmError> {
        let recorded_kind = recorded.map(|recorded| recorded.kind);
        match self.inspect(site, skill) {
            TargetEntry::Missing => Ok(true),
            TargetEntry::Link | TargetEntry::Placeholder => {
                self.remove_link(skill)?;
                Ok(true)
            }
            TargetEntry::Copy(found) => match recorded {
                Some(recorded) if recorded.kind == LinkKind::Copy && recorded.digest == found => {
                    self.remove_copy(site, skill, recorded.digest)
                }
                _ => Ok(false),
            },
            TargetEntry::Occupied
                if recorded_kind == Some(LinkKind::Link) && self.is_moved_link(site, skill) =>
            {
                self.remove_link(skill)?;
                Ok(true)
            }
            TargetEntry::Occupied => Ok(false),
        }
    }

    /// Removes `skill` here when it is a link, a junction or a file, and
    /// never a folder: whatever took the place of LPM's link since it was
    /// inspected is refused, not deleted.
    pub(crate) fn remove_link(&self, skill: &str) -> io::Result<()> {
        match self.directory.remove_file_or_symlink(skill) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            result => result,
        }
    }

    /// Removes the marked copy of `skill` here holding `digest`: moves it
    /// into LPM's store first, checks the folder that moved, and puts it
    /// back when it isn't that copy. A copy that can't be moved aside, as
    /// across file systems, stays where it is and its removal stays
    /// pending; a folder that fails the check and can't go back stays in
    /// the store under a name nothing deletes, and one that passes is
    /// renamed for the sweep to finish if deleting it fails.
    fn remove_copy(&self, site: &Site, skill: &str, digest: &str) -> Result<bool, LpmError> {
        let store = super::state::create_root(site)?;
        let retired = super::snapshot::retiring_name();
        self.directory
            .rename(skill, &store, &retired)
            .map_err(|error| {
                LpmError::Registry(format!(
                    "LPM's copy at {} couldn't be moved aside to remove it, so it stays for now: {error}",
                    self.path.join(skill).display()
                ))
            })?;
        let moved = store
            .open_dir_nofollow(&retired)
            .ok()
            .and_then(|copy| marked_copy_digest(&copy, skill));
        if moved.as_deref() != Some(digest) {
            crate::directory_transaction::publish_entry_noreplace(
                &store,
                std::ffi::OsStr::new(&retired),
                &self.directory,
                std::ffi::OsStr::new(skill),
            )
            .map_err(|error| {
                LpmError::Registry(format!(
                    "{} changed before LPM could remove it and couldn't be put back; it is at {}: {error}",
                    self.path.join(skill).display(),
                    site.store_dir().join(&retired).display()
                ))
            })?;
            return Ok(false);
        }
        let verified = super::snapshot::staging_name();
        store.rename(&retired, &store, &verified)?;
        crate::project_fs::remove_entry(&store, Path::new(&verified))?;
        Ok(true)
    }

    /// Whether `skill` here is a link to some `<state folder>/linked-skills/
    /// <skill>` other than this site's, the state folder named as this
    /// site's is: `.lpm` for a project. Never for the global links, whose
    /// copies don't move with a project, and where such a link belongs to
    /// another LPM root's global packages.
    pub(crate) fn is_moved_link(&self, site: &Site, skill: &str) -> bool {
        if site.is_global() {
            return false;
        }
        let is_link = self
            .directory
            .symlink_metadata(skill)
            .is_ok_and(|metadata| crate::project_fs::is_link(&metadata));
        if !is_link {
            return false;
        }
        let target = match self.directory.read_link_contents(skill) {
            Ok(target) => target,
            Err(_) => match std::fs::read_link(self.path.join(skill)) {
                Ok(target) => target,
                Err(_) => return false,
            },
        };
        let tail: Vec<_> = target.components().rev().take(3).collect();
        tail.len() == 3
            && tail[0].as_os_str() == skill
            && tail[1].as_os_str() == "linked-skills"
            && tail[2].as_os_str() == site.state_dir_name()
    }

    /// The names in this directory that could name a skill.
    pub(crate) fn skill_names(&self) -> Vec<String> {
        let Ok(entries) = self.directory.entries() else {
            return Vec::new();
        };
        entries
            .flatten()
            .filter_map(|entry| entry.file_name().to_str().map(str::to_string))
            .filter(|name| lpm_skill::is_skill_name(name))
            .collect()
    }

    fn link_points_at(&self, site: &Site, skill: &str, copy: &Path) -> bool {
        let entry = self.path.join(skill);
        let target = match self.directory.read_link_contents(skill) {
            Ok(target) => target,
            Err(_) => match std::fs::read_link(&entry) {
                Ok(target) => target,
                Err(_) => return false,
            },
        };
        if target == link_destination(site, copy, &entry) {
            return true;
        }
        let resolved = crate::project_fs::canonicalize_with_missing_tail(&self.path.join(&target));
        let expected = crate::project_fs::canonicalize_with_missing_tail(copy);
        resolved.is_some() && resolved == expected
    }

    /// The digest a marked copy's marker records, when its files still
    /// match it.
    fn copy_digest(&self, skill: &str) -> Option<String> {
        marked_copy_digest(&self.directory.open_dir_nofollow(skill).ok()?, skill)
    }

    /// Whether `skill` here is the file Git checks out for a committed link
    /// where it can't make links: a regular file holding just the link's
    /// destination.
    fn is_placeholder(&self, site: &Site, skill: &str, copy: &Path) -> bool {
        let destination = link_destination(site, copy, &self.path.join(skill));
        let expected: String = destination
            .components()
            .map(|component| component.as_os_str().to_string_lossy())
            .collect::<Vec<_>>()
            .join("/");
        read_capped(&self.directory, skill, MAX_PLACEHOLDER_BYTES)
            .is_some_and(|content| content == expected.as_bytes())
    }
}

/// Whether `target`, a project-relative directory, passes through a
/// symbolic link or junction on its way from `project_dir`. A missing part
/// doesn't: LPM creates it.
pub(crate) fn passes_through_link(project_dir: &Path, target: &str) -> bool {
    let mut path = project_dir.to_path_buf();
    for component in target.split('/') {
        path.push(component);
        match std::fs::symlink_metadata(&path) {
            Ok(metadata) if lpm_common::is_symlink_or_junction(&metadata) => return true,
            Ok(metadata) if metadata.is_dir() => {}
            _ => return false,
        }
    }
    false
}

/// `relative`, a `/`-separated project-relative path, under `project_dir`.
pub(crate) fn project_path(project_dir: &Path, relative: &str) -> PathBuf {
    let mut path = project_dir.to_path_buf();
    path.extend(
        relative
            .split('/')
            .filter(|component| !component.is_empty()),
    );
    path
}

/// Removes `directory`, relative to `site`'s base, if it is an empty plain
/// directory reached through plain directories; anything else stays. In
/// the home folder too: a folder LPM created through a link the user made
/// may since be another folder, once the link points elsewhere. `true` when
/// it is gone.
pub(crate) fn remove_if_empty(site: &Site, directory: &str) -> bool {
    let project_dir = site.base();
    let (parent, name) = directory.rsplit_once('/').unwrap_or(("", directory));
    let parent = if parent.is_empty() {
        match Dir::open_ambient_dir(project_dir, cap_std::ambient_authority()) {
            Ok(parent) => parent,
            Err(_) => return false,
        }
    } else {
        match crate::project_fs::open_directory(project_dir, Path::new(parent)) {
            Ok(Some(parent)) => parent,
            Ok(None) => return true,
            Err(_) => return false,
        }
    };
    match parent.symlink_metadata(name) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => true,
        Ok(metadata) if metadata.is_dir() && !crate::project_fs::is_link(&metadata) => {
            parent.remove_dir(name).is_ok()
        }
        _ => false,
    }
}

/// The digest the marker in `copy`, a marked copy of `skill`, records,
/// when the copy's files still match it.
fn marked_copy_digest(copy: &Dir, skill: &str) -> Option<String> {
    let marker: serde_json::Value =
        serde_json::from_slice(&read_capped(copy, COPY_MARKER, MAX_MARKER_BYTES)?).ok()?;
    if marker.get("skill").and_then(serde_json::Value::as_str) != Some(skill) {
        return None;
    }
    let recorded = marker.get("digest").and_then(serde_json::Value::as_str)?;
    let digest = super::discovery::tree_digest(copy, Some(COPY_MARKER))?;
    (digest == recorded).then_some(digest)
}

/// Where the link at `entry` points: the copy by a relative path in a
/// project, so the links keep working when the project moves, and by its
/// absolute path for the global links, which a relative path could miss
/// when the home folder or the LPM root is reached through a link.
fn link_destination(site: &Site, copy: &Path, entry: &Path) -> PathBuf {
    if site.is_global() {
        copy.to_path_buf()
    } else {
        relative_destination(copy, entry)
    }
}

fn relative_destination(copy: &Path, entry: &Path) -> PathBuf {
    entry
        .parent()
        .and_then(|parent| pathdiff::diff_paths(copy, parent))
        .unwrap_or_else(|| copy.to_path_buf())
}

fn read_capped(directory: &Dir, name: &str, limit: u64) -> Option<Vec<u8>> {
    let mut options = cap_std::fs::OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No);
    let file = directory.open_with(name, &options).ok()?;
    if !file.metadata().ok()?.is_file() {
        return None;
    }
    let mut content = Vec::new();
    file.into_std()
        .take(limit + 1)
        .read_to_end(&mut content)
        .ok()?;
    (content.len() as u64 <= limit).then_some(content)
}

#[cfg(any(windows, test))]
fn copy_marker(skill: &str, digest: &str) -> String {
    serde_json::json!({ "skill": skill, "digest": digest }).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn project_with_copy(skill: &str) -> tempfile::TempDir {
        let project = tempfile::tempdir().unwrap();
        let copy = snapshot_dir(&Site::project(project.path()), skill);
        std::fs::create_dir_all(&copy).unwrap();
        std::fs::write(copy.join("SKILL.md"), "x").unwrap();
        project
    }

    fn target(project: &Path, target: &str) -> TargetDir {
        TargetDir::create(&Site::project(project), target, &mut Vec::new()).unwrap()
    }

    #[cfg(unix)]
    #[test]
    fn a_global_link_points_at_its_copy_by_absolute_path() {
        let home = tempfile::tempdir().unwrap();
        let lpm_root = home.path().join(".lpm");
        let site = Site::global(home.path(), &lpm_root);
        let copy = snapshot_dir(&site, "deploy");
        std::fs::create_dir_all(&copy).unwrap();
        std::fs::write(copy.join("SKILL.md"), "x").unwrap();
        let skills = target(home.path(), ".agents/skills");

        skills.link(&site, "deploy", "sha256:x").unwrap();

        assert_eq!(
            std::fs::read_link(home.path().join(".agents/skills/deploy")).unwrap(),
            copy
        );
        assert!(matches!(skills.inspect(&site, "deploy"), TargetEntry::Link));
    }

    #[cfg(unix)]
    #[test]
    fn another_lpm_roots_global_link_is_never_taken_for_a_moved_one() {
        let home = tempfile::tempdir().unwrap();
        let site = Site::global(home.path(), &home.path().join(".lpm"));
        let other = Site::global(home.path(), &home.path().join("other-lpm"));
        let skills = target(home.path(), ".agents/skills");
        std::os::unix::fs::symlink(
            snapshot_dir(&other, "deploy"),
            home.path().join(".agents/skills/deploy"),
        )
        .unwrap();

        assert!(!skills.is_moved_link(&site, "deploy"));
        assert!(matches!(
            skills.inspect(&site, "deploy"),
            TargetEntry::Occupied
        ));
    }

    #[cfg(unix)]
    #[test]
    fn created_links_are_relative_and_owned() {
        let project = project_with_copy("deploy");
        let skills = target(project.path(), ".agents/skills");

        assert_eq!(
            skills
                .link(&Site::project(project.path()), "deploy", "sha256:x")
                .unwrap(),
            LinkKind::Link
        );
        assert_eq!(
            std::fs::read_link(project.path().join(".agents/skills/deploy")).unwrap(),
            Path::new("../../.lpm/linked-skills/deploy")
        );
        assert_eq!(
            skills.inspect(&Site::project(project.path()), "deploy"),
            TargetEntry::Link
        );
        assert!(
            skills
                .remove(&Site::project(project.path()), "deploy", None)
                .unwrap()
        );
        assert_eq!(
            skills.inspect(&Site::project(project.path()), "deploy"),
            TargetEntry::Missing
        );
        assert!(
            snapshot_dir(&Site::project(project.path()), "deploy")
                .join("SKILL.md")
                .exists()
        );
    }

    #[cfg(unix)]
    #[test]
    fn entries_the_user_made_are_occupied_and_never_removed() {
        let project = project_with_copy("deploy");
        let skills = target(project.path(), ".claude/skills");
        let entry = project.path().join(".claude/skills/deploy");
        std::fs::create_dir_all(&entry).unwrap();
        std::fs::write(entry.join("SKILL.md"), "mine").unwrap();
        assert_eq!(
            skills.inspect(&Site::project(project.path()), "deploy"),
            TargetEntry::Occupied
        );
        assert!(
            !skills
                .remove(
                    &Site::project(project.path()),
                    "deploy",
                    Some(Recorded {
                        kind: LinkKind::Copy,
                        digest: "sha256:x",
                    }),
                )
                .unwrap()
        );
        assert!(entry.join("SKILL.md").exists());

        std::os::unix::fs::symlink(
            "../../somewhere/else",
            project.path().join(".claude/skills/other"),
        )
        .unwrap();
        assert_eq!(
            skills.inspect(&Site::project(project.path()), "other"),
            TargetEntry::Occupied
        );
        std::os::unix::fs::symlink(
            "../../.lpm/linked-skills/deploy",
            project.path().join(".claude/skills/audit"),
        )
        .unwrap();
        assert_eq!(
            skills.inspect(&Site::project(project.path()), "audit"),
            TargetEntry::Occupied
        );
    }

    #[test]
    fn a_git_placeholder_for_the_link_is_lpms() {
        let project = project_with_copy("deploy");
        let skills = target(project.path(), ".agents/skills");
        std::fs::write(
            project.path().join(".agents/skills/deploy"),
            "../../.lpm/linked-skills/deploy",
        )
        .unwrap();
        assert_eq!(
            skills.inspect(&Site::project(project.path()), "deploy"),
            TargetEntry::Placeholder
        );
    }

    #[test]
    fn a_marked_copy_is_lpms_only_while_its_files_match_its_marker() {
        let project = project_with_copy("deploy");
        let skills = target(project.path(), ".agents/skills");
        let entry = project.path().join(".agents/skills/deploy");
        std::fs::create_dir_all(&entry).unwrap();
        std::fs::write(entry.join("SKILL.md"), "x").unwrap();
        let digest = lpm_skill::skill_files_digest([("SKILL.md", b"x".as_slice())]);
        std::fs::write(entry.join(COPY_MARKER), copy_marker("deploy", &digest)).unwrap();
        assert_eq!(
            skills.inspect(&Site::project(project.path()), "deploy"),
            TargetEntry::Copy(digest.clone())
        );
        assert!(
            !skills
                .remove(&Site::project(project.path()), "deploy", None)
                .unwrap()
        );
        assert!(entry.exists(), "an unrecorded copy is never removed");

        std::fs::write(entry.join(COPY_MARKER), copy_marker("audit", &digest)).unwrap();
        assert_eq!(
            skills.inspect(&Site::project(project.path()), "deploy"),
            TargetEntry::Occupied
        );
        std::fs::write(entry.join(COPY_MARKER), copy_marker("deploy", &digest)).unwrap();
        std::fs::write(entry.join("SKILL.md"), "edited").unwrap();
        assert_eq!(
            skills.inspect(&Site::project(project.path()), "deploy"),
            TargetEntry::Occupied
        );
        assert!(
            !skills
                .remove(
                    &Site::project(project.path()),
                    "deploy",
                    Some(Recorded {
                        kind: LinkKind::Copy,
                        digest: "sha256:x",
                    }),
                )
                .unwrap()
        );
        assert!(entry.join("SKILL.md").exists());
    }

    #[cfg(unix)]
    #[test]
    fn target_directories_never_pass_through_links() {
        let project = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(outside.path(), project.path().join(".agents")).unwrap();
        let site = Site::project(project.path());
        assert!(TargetDir::create(&site, ".agents/skills", &mut Vec::new()).is_err());
        assert!(TargetDir::open(&site, ".agents/skills").is_err());
        assert!(!outside.path().join("skills").exists());
    }

    #[cfg(unix)]
    #[test]
    fn a_global_target_follows_a_link_the_user_made_to_an_agent_folder() {
        let home = tempfile::tempdir().unwrap();
        let dotfiles = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(dotfiles.path(), home.path().join(".claude")).unwrap();
        let site = Site::global(home.path(), &home.path().join(".lpm"));
        let mut created = Vec::new();

        TargetDir::create(&site, ".claude/skills", &mut created).unwrap();

        assert_eq!(created, [".claude/skills"]);
        assert!(dotfiles.path().join("skills").is_dir());
        assert!(TargetDir::open(&site, ".claude/skills").unwrap().is_some());
        assert!(
            !remove_if_empty(&site, ".claude/skills"),
            "a folder reached through the user's link may since be someone else's"
        );
        assert!(dotfiles.path().join("skills").is_dir());
        assert!(!remove_if_empty(&site, ".claude"));
        std::fs::create_dir_all(home.path().join(".agents/skills")).unwrap();
        assert!(remove_if_empty(&site, ".agents/skills"));
    }

    #[cfg(unix)]
    #[test]
    fn a_global_target_behind_a_link_to_nothing_says_so() {
        let home = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(home.path().join("missing"), home.path().join(".claude"))
            .unwrap();
        let site = Site::global(home.path(), &home.path().join(".lpm"));

        let error = TargetDir::create(&site, ".claude/skills", &mut Vec::new())
            .err()
            .expect("a dangling link refuses the target");

        assert!(
            error
                .to_string()
                .contains("a link to something that doesn't exist"),
            "{error}"
        );
        assert!(!home.path().join("missing").exists());
    }

    #[test]
    fn created_directories_are_reported_and_removed_only_when_empty() {
        let project = tempfile::tempdir().unwrap();
        let mut created = Vec::new();
        let site = Site::project(project.path());
        TargetDir::create(&site, ".agents/skills", &mut created).unwrap();
        assert_eq!(created, [".agents", ".agents/skills"]);
        let mut again = Vec::new();
        TargetDir::create(&site, ".agents/skills", &mut again).unwrap();
        assert!(again.is_empty());
        std::fs::write(project.path().join(".agents/skills/note.md"), "x").unwrap();
        assert!(!remove_if_empty(&site, ".agents/skills"));
        std::fs::remove_file(project.path().join(".agents/skills/note.md")).unwrap();
        assert!(remove_if_empty(&site, ".agents/skills"));
        assert!(remove_if_empty(&site, ".agents"));
    }

    #[test]
    fn a_recorded_copy_is_removed_only_while_it_holds_the_files_lpm_recorded() {
        let project = project_with_copy("deploy");
        let skills = target(project.path(), ".agents/skills");
        let entry = project.path().join(".agents/skills/deploy");
        std::fs::create_dir_all(&entry).unwrap();
        std::fs::write(entry.join("SKILL.md"), "x").unwrap();
        let digest = lpm_skill::skill_files_digest([("SKILL.md", b"x".as_slice())]);
        std::fs::write(entry.join(COPY_MARKER), copy_marker("deploy", &digest)).unwrap();

        let other = Recorded {
            kind: LinkKind::Copy,
            digest: "sha256:another-copy",
        };
        assert!(
            !skills
                .remove(&Site::project(project.path()), "deploy", Some(other))
                .unwrap()
        );
        assert!(entry.join("SKILL.md").exists());

        let recorded = Recorded {
            kind: LinkKind::Copy,
            digest: &digest,
        };
        assert!(
            skills
                .remove(&Site::project(project.path()), "deploy", Some(recorded))
                .unwrap()
        );
        assert!(!entry.exists());
        let leftovers: Vec<_> = std::fs::read_dir(project.path().join(".lpm/linked-skills"))
            .unwrap()
            .flatten()
            .map(|entry| entry.file_name())
            .filter(|name| name.to_string_lossy().starts_with('.'))
            .collect();
        assert!(leftovers.is_empty(), "{leftovers:?}");
    }

    #[cfg(unix)]
    #[test]
    fn a_recorded_copy_lpm_cant_move_aside_stays_in_place_and_pending() {
        use std::os::unix::fs::PermissionsExt as _;

        // SAFETY: geteuid has no preconditions. Root ignores the mode below.
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let project = project_with_copy("deploy");
        let skills = target(project.path(), ".agents/skills");
        let entry = project.path().join(".agents/skills/deploy");
        std::fs::create_dir_all(&entry).unwrap();
        std::fs::write(entry.join("SKILL.md"), "x").unwrap();
        let digest = lpm_skill::skill_files_digest([("SKILL.md", b"x".as_slice())]);
        std::fs::write(entry.join(COPY_MARKER), copy_marker("deploy", &digest)).unwrap();
        let store = project.path().join(".lpm/linked-skills");
        std::fs::set_permissions(&store, std::fs::Permissions::from_mode(0o555)).unwrap();

        let removed = skills.remove(
            &Site::project(project.path()),
            "deploy",
            Some(Recorded {
                kind: LinkKind::Copy,
                digest: &digest,
            }),
        );

        std::fs::set_permissions(&store, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(removed.is_err(), "{removed:?}");
        assert!(entry.join("SKILL.md").exists());
    }

    #[test]
    fn a_copy_with_as_many_entries_as_a_skill_may_hold_is_still_recognized_with_its_marker() {
        let directory = tempfile::tempdir().unwrap();
        let mut files: Vec<(String, Vec<u8>)> = vec![("SKILL.md".into(), b"x".to_vec())];
        for index in 1..lpm_skill::MAX_SKILL_DIRECTORY_ENTRIES {
            files.push((format!("note-{index:03}.md"), b"n".to_vec()));
        }
        for (name, content) in &files {
            std::fs::write(directory.path().join(name), content).unwrap();
        }
        let digest = lpm_skill::skill_files_digest(
            files
                .iter()
                .map(|(name, content)| (name.as_str(), content.as_slice())),
        );
        std::fs::write(
            directory.path().join(COPY_MARKER),
            copy_marker("deploy", &digest),
        )
        .unwrap();
        let copy = Dir::open_ambient_dir(directory.path(), cap_std::ambient_authority()).unwrap();

        assert_eq!(marked_copy_digest(&copy, "deploy"), Some(digest));
    }

    #[test]
    fn removing_a_link_never_removes_a_folder_that_took_its_place() {
        let project = project_with_copy("deploy");
        let skills = target(project.path(), ".agents/skills");
        let entry = project.path().join(".agents/skills/deploy");
        std::fs::create_dir_all(&entry).unwrap();
        std::fs::write(entry.join("SKILL.md"), "mine").unwrap();

        assert!(skills.remove_link("deploy").is_err());
        assert!(entry.join("SKILL.md").exists());
    }
}
