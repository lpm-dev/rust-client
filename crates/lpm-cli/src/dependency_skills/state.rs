use super::plan::Naming;
use cap_fs_ext::{DirExt as _, FollowSymlinks, OpenOptionsFollowExt as _};
use cap_std::fs::Dir;
use lpm_common::LpmError;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};

/// The folder holding the scanned copies and the record of what LPM
/// linked, inside the project's `.lpm` or the LPM root's `global`.
const LINKED_SKILLS_NAME: &str = "linked-skills";
pub(crate) const STATE_FILE: &str = "state.json";
/// The lock that serializes changes, beside [`LINKED_SKILLS_NAME`].
const LOCK_NAME: &str = ".linked-skills.lock";
/// The folder in the LPM root that holds the global packages' state.
const GLOBAL_STATE_DIR: &str = "global";
const STATE_VERSION: u32 = 1;

/// Where one set of dependency-skill links lives: the folder its targets
/// and recorded entry paths are relative to, and the folder that keeps its
/// copies, record and lock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Site {
    base: PathBuf,
    /// The existing folder the state folder sits in.
    anchor: PathBuf,
    /// The state folder, a plain directory in `anchor`.
    state_dir: &'static str,
    global: bool,
}

impl Site {
    /// A project's links: targets in the project, copies in its
    /// `.lpm/linked-skills`.
    pub(crate) fn project(project_dir: &Path) -> Self {
        Self {
            base: project_dir.to_path_buf(),
            anchor: project_dir.to_path_buf(),
            state_dir: lpm_common::PROJECT_STATE_DIR,
            global: false,
        }
    }

    /// The links of the user's global packages: targets in `home`, copies
    /// in `global/linked-skills` under `lpm_root`.
    pub(crate) fn global(home: &Path, lpm_root: &Path) -> Self {
        Self {
            base: home.to_path_buf(),
            anchor: lpm_root.to_path_buf(),
            state_dir: GLOBAL_STATE_DIR,
            global: true,
        }
    }

    /// What target folders and recorded entry paths are relative to.
    #[inline]
    pub(crate) fn base(&self) -> &Path {
        &self.base
    }

    /// How messages and reports name `relative`, a target folder or entry
    /// path: under `~/` for the global links, which live in the home folder.
    pub(crate) fn label<'a>(&self, relative: &'a str) -> std::borrow::Cow<'a, str> {
        if self.global {
            std::borrow::Cow::Owned(format!("~/{relative}"))
        } else {
            std::borrow::Cow::Borrowed(relative)
        }
    }

    #[inline]
    pub(crate) fn is_global(&self) -> bool {
        self.global
    }

    /// The name of the folder that holds the copies' folder: `.lpm` in a
    /// project, `global` in the LPM root.
    #[inline]
    pub(crate) fn state_dir_name(&self) -> &'static str {
        self.state_dir
    }

    /// The folder holding the copies and the record.
    pub(crate) fn store_dir(&self) -> PathBuf {
        let mut path = PathBuf::with_capacity(self.anchor.as_os_str().len() + 32);
        path.push(&self.anchor);
        path.push(self.state_dir);
        path.push(LINKED_SKILLS_NAME);
        path
    }

    fn lock_path(&self) -> PathBuf {
        let mut path = self.anchor.join(self.state_dir);
        path.push(LOCK_NAME);
        path
    }

    /// Opens the state folder, creating it when missing and refusing a
    /// link in its place: for the global links, LPM's global folder, opened
    /// as global installs open it, never through a linked LPM home.
    fn create_state_dir(&self) -> Result<Dir, LpmError> {
        if self.global {
            return lpm_common::open_or_create_global_directory(&lpm_common::LpmRoot::from_dir(
                &self.anchor,
            ));
        }
        let project = Dir::open_ambient_dir(&self.anchor, cap_std::ambient_authority())?;
        Ok(lpm_common::ensure_project_state_dir_in(
            &project,
            &self.anchor,
        )?)
    }

    /// Opens the state folder when it exists, refusing a link in its place.
    fn open_state_dir(&self) -> Result<Option<Dir>, LpmError> {
        if self.global {
            return lpm_common::open_global_directory(&lpm_common::LpmRoot::from_dir(&self.anchor));
        }
        Ok(crate::project_fs::open_directory(
            &self.anchor,
            Path::new(self.state_dir),
        )?)
    }
}

/// Opens `name` in `parent`, creating it when missing, and refusing
/// anything but a plain directory.
fn open_or_create_plain_dir(parent: &Dir, name: &str, shown: &Path) -> Result<Dir, LpmError> {
    let refuse = |error: io::Error| {
        LpmError::Registry(format!(
            "refusing to keep linked skills in {}, which is not a plain directory: {error}",
            shown.display()
        ))
    };
    match parent.open_dir_nofollow(name) {
        Ok(directory) => Ok(directory),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            match parent.create_dir(name) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(LpmError::Io(error)),
            }
            parent.open_dir_nofollow(name).map_err(refuse)
        }
        Err(error) => Err(refuse(error)),
    }
}

/// How a target holds a skill.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum LinkKind {
    /// A symbolic link or Windows junction to the skill's copy.
    Link,
    /// A copy carrying [`super::links::COPY_MARKER`], where links can't be
    /// made.
    Copy,
}

/// One target entry LPM made for a skill.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct LinkRecord {
    /// Project-relative, `/`-separated.
    pub(crate) path: String,
    pub(crate) kind: LinkKind,
    /// For an entry whose removal is still pending, the digest of the
    /// files LPM linked there: a copy is removed only while it holds them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) digest: Option<String>,
}

/// A skill LPM linked, and what it was linked from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct LinkedSkillRecord {
    pub(crate) package: String,
    pub(crate) version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) integrity: Option<String>,
    /// The `sha256:` digest of the copy's files.
    pub(crate) digest: String,
    /// What the skill asks agents to allow, as `SkillPermission::as_str`.
    pub(crate) permission: String,
    /// How specifically an allowing entry had to name the skill to link it.
    pub(crate) requires: Naming,
    /// The registry whose review approved an LPM.dev package's copy. The
    /// copy stays only while LPM uses that registry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) reviewed_by: Option<String>,
    /// The release check this copy's npm package passed when it linked:
    /// the security provider's API and the npm registries LPM accepted.
    /// The copy stays on a later verdict only under the same check.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) checked_as: Option<String>,
    pub(crate) links: Vec<LinkRecord>,
    /// Target entries, project-relative, that something else held or that
    /// couldn't be made; reconciling tries them again once they're free.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) blocked: Vec<String>,
}

/// `lpm.lock`'s digest, with the size and modification time it had and
/// when the digest was taken, so an unchanged lockfile isn't read again.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct FileStamp {
    pub(crate) size: u64,
    pub(crate) modified_nanos: u64,
    pub(crate) checked_nanos: u64,
    pub(crate) digest: String,
}

/// What LPM linked in this checkout. Machine-local: it lives under `.lpm`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct LinkState {
    pub(crate) schema_version: u32,
    /// The inputs the links were last reconciled from; see
    /// [`super::fingerprint`]. Empty when that reconcile didn't finish, so
    /// the next one runs again.
    #[serde(default)]
    pub(crate) fingerprint: String,
    /// The digest of the policy the links were last reconciled under.
    #[serde(default)]
    pub(crate) policy: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) lockfile: Option<FileStamp>,
    #[serde(default)]
    pub(crate) skills: BTreeMap<String, LinkedSkillRecord>,
    /// Entries LPM made for skills it no longer links and couldn't remove
    /// yet, by skill; reconciling tries again.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub(crate) stale: BTreeMap<String, Vec<LinkRecord>>,
    /// Target directories LPM created, which it removes once empty.
    #[serde(default)]
    pub(crate) created_directories: Vec<String>,
    /// The workspace members, project-relative, whose materialized LPM.dev
    /// skills the links follow besides the project's own.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) members: Vec<String>,
    /// When a security verdict the links rest on comes due, in seconds
    /// since the Unix epoch: an install then reconciles again although
    /// nothing else changed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) recheck_at: Option<u64>,
    /// When the earliest security verdict the links rest on expires, in
    /// seconds since the Unix epoch: an install then reconciles, offline
    /// too, so copies it kept stop being kept.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) expires_at: Option<u64>,
    /// The verdict cache's stamp when the links read it, so an install,
    /// online or offline, reconciles once another project recorded verdicts
    /// since, a newly flagged release among them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) verdicts_stamp: Option<super::checks::CacheStamp>,
}

impl LinkState {
    /// The skills these links recorded, by package, with the naming each
    /// needed.
    pub(crate) fn recorded_skills(&self) -> super::plan::RecordedSkills {
        let mut recorded = super::plan::RecordedSkills::new();
        for (skill, record) in &self.skills {
            recorded
                .entry(record.package.clone())
                .or_default()
                .push((skill.clone(), record.requires));
        }
        recorded
    }
}

/// The state file as read.
pub(crate) enum StoredState {
    Missing,
    Present(Box<LinkState>),
    /// Unreadable or malformed: nothing it lists is trusted, so no
    /// existing entry is removed on its word.
    Unusable(String),
    /// Written by a newer LPM, whose records this one can't read: LPM
    /// leaves that version's links and copies alone.
    Newer(String),
}

pub(crate) fn snapshot_dir(site: &Site, skill: &str) -> PathBuf {
    let mut path = site.store_dir();
    path.push(skill);
    path
}

fn state_path(site: &Site) -> PathBuf {
    let mut path = site.store_dir();
    path.push(STATE_FILE);
    path
}

/// Opens the folder of copies through real directories only: `Ok(None)`
/// when it doesn't exist, and an error when a link or a file is in the way.
pub(crate) fn open_root(site: &Site) -> io::Result<Option<Dir>> {
    let Some(state) = site.open_state_dir().map_err(io::Error::other)? else {
        return Ok(None);
    };
    match state.open_dir_nofollow(LINKED_SKILLS_NAME) {
        Ok(root) => Ok(Some(root)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

/// Opens the folder of copies, creating it inside its state folder when
/// missing, and refusing a link anywhere on the way.
pub(crate) fn create_root(site: &Site) -> Result<Dir, LpmError> {
    let state = site.create_state_dir()?;
    open_or_create_plain_dir(&state, LINKED_SKILLS_NAME, &site.store_dir())
}

/// Removes the folder of copies when it holds nothing.
pub(crate) fn remove_root_if_empty(site: &Site) {
    if let Ok(Some(state)) =
        crate::project_fs::open_directory(&site.anchor, Path::new(site.state_dir))
    {
        let _ = state.remove_dir(LINKED_SKILLS_NAME);
    }
}

pub(crate) fn state_exists(site: &Site) -> bool {
    std::fs::symlink_metadata(state_path(site)).is_ok()
}

pub(crate) fn read_state(site: &Site) -> StoredState {
    let path = state_path(site);
    let root = match open_root(site) {
        Ok(Some(root)) => root,
        Ok(None) => return StoredState::Missing,
        Err(error) => {
            return StoredState::Unusable(format!("{} could not be read: {error}", path.display()));
        }
    };
    let mut options = cap_std::fs::OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No);
    let file = match root.open_with(STATE_FILE, &options) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return StoredState::Missing,
        Err(error) => {
            return StoredState::Unusable(format!("{} could not be read: {error}", path.display()));
        }
    };
    let content = match file.metadata().map_err(LpmError::Io).and_then(|metadata| {
        lpm_common::read_text_file_capped_from_open_file_with_known_size(
            file.into_std(),
            &path,
            lpm_common::STATE_FILE_SIZE_CAP_BYTES,
            metadata.len(),
        )
        .map_err(LpmError::from)
    }) {
        Ok(content) => content,
        Err(error) => {
            return StoredState::Unusable(format!("{} could not be read: {error}", path.display()));
        }
    };
    #[derive(Deserialize)]
    struct SchemaOnly {
        schema_version: u32,
    }
    match serde_json::from_str::<SchemaOnly>(&content) {
        Ok(found) if found.schema_version > STATE_VERSION => {
            return StoredState::Newer(format!(
                "{} was written by a newer LPM (schema {})",
                path.display(),
                found.schema_version
            ));
        }
        Ok(found) if found.schema_version < STATE_VERSION => {
            return StoredState::Unusable(format!(
                "{} has an unsupported schema ({})",
                path.display(),
                found.schema_version
            ));
        }
        _ => {}
    }
    match serde_json::from_str::<LinkState>(&content) {
        Ok(mut state) if state_is_sound(&state) => {
            lift_retired_permissions(&mut state);
            StoredState::Present(Box::new(state))
        }
        Ok(_) => StoredState::Unusable(format!("{} lists unsafe paths", path.display())),
        Err(error) => StoredState::Unusable(format!("{} is malformed: {error}", path.display())),
    }
}

/// The permission earlier builds recorded for a skill that pre-approved only
/// its own package's commands, which then linked under `#pkg`.
const RETIRED_OWN_COMMANDS: &str = "own_commands";

/// Reads a copy recorded under the retired own-commands permission as the
/// broad grant it is, since a command runs whatever the agent's `PATH`
/// resolves, so it is kept only for an entry naming the skill. The
/// fingerprint is cleared so the next install plans again.
fn lift_retired_permissions(state: &mut LinkState) {
    let mut lifted = false;
    for record in state.skills.values_mut() {
        if record.permission == RETIRED_OWN_COMMANDS {
            record.permission = lpm_skill::SkillPermission::Broad.as_str().to_string();
            record.requires = record.requires.max(Naming::Skill);
            lifted = true;
        }
    }
    if lifted {
        state.fingerprint.clear();
    }
}

/// Whether every recorded name and path could have come from LPM: skill
/// names follow the naming rules, and paths are relative and portable.
fn state_is_sound(state: &LinkState) -> bool {
    let entry_is_sound = |path: &str| super::policy::normalize_target_entry(path).is_ok();
    state.skills.iter().all(|(name, record)| {
        is_linked_skill_name(name)
            && record.links.iter().all(|link| entry_is_sound(&link.path))
            && record.blocked.iter().all(|path| entry_is_sound(path))
    }) && state.stale.iter().all(|(name, links)| {
        is_linked_skill_name(name) && links.iter().all(|link| entry_is_sound(&link.path))
    }) && state
        .created_directories
        .iter()
        .chain(&state.members)
        .all(|directory| super::policy::normalize_relative_dir(directory).is_ok())
}

/// Whether `name` can name a linked skill: a dependency skill's name, or an
/// LPM.dev skill's package-qualified one.
pub(crate) fn is_linked_skill_name(name: &str) -> bool {
    lpm_skill::is_skill_name(name)
}

pub(crate) fn write_state(site: &Site, state: &LinkState) -> Result<(), LpmError> {
    let root = create_root(site)?;
    let mut state = state.clone();
    state.schema_version = STATE_VERSION;
    let content = serde_json::to_vec_pretty(&state).map_err(|error| {
        LpmError::Registry(format!("failed to serialize linked skills: {error}"))
    })?;
    lpm_common::write_file_atomic_in_dir_with(&root, std::ffi::OsStr::new(STATE_FILE), |file| {
        use std::io::Write as _;
        file.write_all(&content)
    })?;
    Ok(())
}

pub(crate) fn remove_state(site: &Site) -> Result<(), LpmError> {
    let root = match open_root(site) {
        Ok(Some(root)) => root,
        Ok(None) => return Ok(()),
        Err(error) => return Err(LpmError::Io(error)),
    };
    match root.remove_file(STATE_FILE) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(LpmError::Io(error)),
    }
}

/// Takes the lock that serializes reconciling a site's links. Hold it from
/// reading the policy until the state is written, so a plan made from a
/// policy another process has since changed is never applied.
pub(crate) fn acquire_lock(site: &Site) -> Result<lpm_common::ExclusiveLockHandle, LpmError> {
    site.create_state_dir()?;
    lpm_common::acquire_exclusive_lock(site.lock_path())
}

/// [`acquire_lock`] without waiting: `Ok(None)` when another process holds
/// the lock.
pub(crate) fn try_acquire_lock(
    site: &Site,
) -> Result<Option<lpm_common::ExclusiveLockHandle>, LpmError> {
    site.create_state_dir()?;
    lpm_common::try_acquire_exclusive_lock(site.lock_path())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(path: &str) -> LinkedSkillRecord {
        LinkedSkillRecord {
            package: "agent-browser".into(),
            version: "0.44.0".into(),
            integrity: Some("sha512-x".into()),
            digest: "sha256:00".into(),
            permission: "broad".into(),
            requires: Naming::Package,
            reviewed_by: None,
            checked_as: None,
            links: vec![LinkRecord {
                path: path.into(),
                kind: LinkKind::Link,
                digest: None,
            }],
            blocked: Vec::new(),
        }
    }

    #[test]
    fn state_round_trips_through_the_file() {
        let project = tempfile::tempdir().unwrap();
        let mut state = LinkState {
            fingerprint: "f".into(),
            ..LinkState::default()
        };
        state.skills.insert(
            "agent-browser".into(),
            record(".agents/skills/agent-browser"),
        );
        write_state(&Site::project(project.path()), &state).unwrap();

        let StoredState::Present(read) = read_state(&Site::project(project.path())) else {
            panic!("state was not read back");
        };
        assert_eq!(read.skills, state.skills);
        assert_eq!(read.schema_version, STATE_VERSION);
    }

    #[test]
    fn a_copy_an_earlier_build_linked_for_its_own_command_needs_its_skill_named_and_a_new_plan() {
        let project = tempfile::tempdir().unwrap();
        let mut state = LinkState {
            fingerprint: "f".into(),
            ..LinkState::default()
        };
        let mut granting = record(".agents/skills/agent-browser");
        granting.permission = "own_commands".into();
        granting.requires = Naming::Package;
        state.skills.insert("agent-browser".into(), granting);
        write_state(&Site::project(project.path()), &state).unwrap();

        let StoredState::Present(read) = read_state(&Site::project(project.path())) else {
            panic!("state was not read back");
        };
        let record = &read.skills["agent-browser"];
        assert_eq!(record.permission, "broad");
        assert_eq!(record.requires, Naming::Skill);
        assert!(read.fingerprint.is_empty());
    }

    #[test]
    fn a_state_from_a_newer_lpm_or_with_unsafe_paths_is_not_trusted() {
        let project = tempfile::tempdir().unwrap();
        let directory = Site::project(project.path()).store_dir();
        std::fs::create_dir_all(&directory).unwrap();
        std::fs::write(
            directory.join(STATE_FILE),
            r#"{"schema_version":99,"skills":[{"name":"reshaped"}]}"#,
        )
        .unwrap();
        assert!(matches!(
            read_state(&Site::project(project.path())),
            StoredState::Newer(_)
        ));

        let mut state = LinkState::default();
        state.skills.insert(
            "agent-browser".into(),
            record("../../outside/agent-browser"),
        );
        write_state(&Site::project(project.path()), &state).unwrap();
        assert!(matches!(
            read_state(&Site::project(project.path())),
            StoredState::Unusable(_)
        ));

        let mut state = LinkState::default();
        state.stale.insert(
            "agent-browser".into(),
            vec![LinkRecord {
                path: "../outside/skills/agent-browser".into(),
                kind: LinkKind::Link,
                digest: None,
            }],
        );
        write_state(&Site::project(project.path()), &state).unwrap();
        assert!(matches!(
            read_state(&Site::project(project.path())),
            StoredState::Unusable(_)
        ));
    }

    #[test]
    fn a_missing_state_is_missing() {
        let project = tempfile::tempdir().unwrap();
        assert!(matches!(
            read_state(&Site::project(project.path())),
            StoredState::Missing
        ));
        assert!(!state_exists(&Site::project(project.path())));
    }

    #[cfg(unix)]
    #[test]
    fn a_state_reached_through_a_linked_directory_is_never_read() {
        let project = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(
            outside.path().join(STATE_FILE),
            r#"{"schema_version":1,"skills":{}}"#,
        )
        .unwrap();
        std::fs::create_dir(project.path().join(".lpm")).unwrap();
        std::os::unix::fs::symlink(outside.path(), Site::project(project.path()).store_dir())
            .unwrap();

        assert!(matches!(
            read_state(&Site::project(project.path())),
            StoredState::Unusable(_)
        ));
        assert!(create_root(&Site::project(project.path())).is_err());
    }
}
