use super::plan::Naming;
use cap_fs_ext::{DirExt as _, FollowSymlinks, OpenOptionsFollowExt as _};
use cap_std::fs::Dir;
use lpm_common::LpmError;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};

/// Where linked skills live in a project: their scanned copies, the record
/// of what LPM linked, and the lock that serializes changes.
pub(crate) const LINKED_SKILLS_DIR: &str = ".lpm/linked-skills";
const LINKED_SKILLS_NAME: &str = "linked-skills";
pub(crate) const STATE_FILE: &str = "state.json";
const LOCK_FILE: &str = ".lpm/.linked-skills.lock";
const STATE_VERSION: u32 = 1;

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

pub(crate) fn linked_skills_dir(project_dir: &Path) -> PathBuf {
    project_dir.join(LINKED_SKILLS_DIR)
}

pub(crate) fn snapshot_dir(project_dir: &Path, skill: &str) -> PathBuf {
    let mut path = linked_skills_dir(project_dir);
    path.push(skill);
    path
}

fn state_path(project_dir: &Path) -> PathBuf {
    let mut path = linked_skills_dir(project_dir);
    path.push(STATE_FILE);
    path
}

/// Opens `.lpm/linked-skills` through real directories only: `Ok(None)`
/// when it doesn't exist, and an error when a link or a file is in the way.
pub(crate) fn open_root(project_dir: &Path) -> io::Result<Option<Dir>> {
    crate::project_fs::open_directory(project_dir, Path::new(LINKED_SKILLS_DIR))
}

/// Opens `.lpm/linked-skills`, creating it inside the project's state
/// directory when missing, and refusing a link anywhere on the way.
pub(crate) fn create_root(project_dir: &Path) -> Result<Dir, LpmError> {
    let project = Dir::open_ambient_dir(project_dir, cap_std::ambient_authority())?;
    let state = lpm_common::ensure_project_state_dir_in(&project, project_dir)?;
    let refuse = |error: io::Error| {
        LpmError::Registry(format!(
            "refusing to keep linked skills in {}, which is not a plain directory: {error}",
            linked_skills_dir(project_dir).display()
        ))
    };
    match state.open_dir_nofollow(LINKED_SKILLS_NAME) {
        Ok(root) => Ok(root),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            match state.create_dir(LINKED_SKILLS_NAME) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(LpmError::Io(error)),
            }
            state.open_dir_nofollow(LINKED_SKILLS_NAME).map_err(refuse)
        }
        Err(error) => Err(refuse(error)),
    }
}

/// Removes `.lpm/linked-skills` when it holds nothing.
pub(crate) fn remove_root_if_empty(project_dir: &Path) {
    if let Ok(Some(state)) =
        crate::project_fs::open_directory(project_dir, Path::new(lpm_common::PROJECT_STATE_DIR))
    {
        let _ = state.remove_dir(LINKED_SKILLS_NAME);
    }
}

pub(crate) fn state_exists(project_dir: &Path) -> bool {
    std::fs::symlink_metadata(state_path(project_dir)).is_ok()
}

pub(crate) fn read_state(project_dir: &Path) -> StoredState {
    let path = state_path(project_dir);
    let root = match open_root(project_dir) {
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

pub(crate) fn write_state(project_dir: &Path, state: &LinkState) -> Result<(), LpmError> {
    create_root(project_dir)?;
    let mut state = state.clone();
    state.schema_version = STATE_VERSION;
    let content = serde_json::to_vec_pretty(&state).map_err(|error| {
        LpmError::Registry(format!("failed to serialize linked skills: {error}"))
    })?;
    lpm_common::write_file_atomic(&state_path(project_dir), content)?;
    Ok(())
}

pub(crate) fn remove_state(project_dir: &Path) -> Result<(), LpmError> {
    let root = match open_root(project_dir) {
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

/// Takes the lock that serializes reconciling a project's links. Hold it
/// from reading the policy until the state is written, so a plan made from
/// a policy another process has since changed is never applied.
pub(crate) fn acquire_lock(
    project_dir: &Path,
) -> Result<lpm_common::ExclusiveLockHandle, LpmError> {
    lpm_common::ensure_project_state_dir(project_dir)?;
    lpm_common::acquire_exclusive_lock(project_dir.join(LOCK_FILE))
}

/// [`acquire_lock`] without waiting: `Ok(None)` when another process holds
/// the lock.
pub(crate) fn try_acquire_lock(
    project_dir: &Path,
) -> Result<Option<lpm_common::ExclusiveLockHandle>, LpmError> {
    lpm_common::ensure_project_state_dir(project_dir)?;
    lpm_common::try_acquire_exclusive_lock(project_dir.join(LOCK_FILE))
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
        write_state(project.path(), &state).unwrap();

        let StoredState::Present(read) = read_state(project.path()) else {
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
        write_state(project.path(), &state).unwrap();

        let StoredState::Present(read) = read_state(project.path()) else {
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
        let directory = linked_skills_dir(project.path());
        std::fs::create_dir_all(&directory).unwrap();
        std::fs::write(
            directory.join(STATE_FILE),
            r#"{"schema_version":99,"skills":[{"name":"reshaped"}]}"#,
        )
        .unwrap();
        assert!(matches!(read_state(project.path()), StoredState::Newer(_)));

        let mut state = LinkState::default();
        state.skills.insert(
            "agent-browser".into(),
            record("../../outside/agent-browser"),
        );
        write_state(project.path(), &state).unwrap();
        assert!(matches!(
            read_state(project.path()),
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
        write_state(project.path(), &state).unwrap();
        assert!(matches!(
            read_state(project.path()),
            StoredState::Unusable(_)
        ));
    }

    #[test]
    fn a_missing_state_is_missing() {
        let project = tempfile::tempdir().unwrap();
        assert!(matches!(read_state(project.path()), StoredState::Missing));
        assert!(!state_exists(project.path()));
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
        std::os::unix::fs::symlink(outside.path(), linked_skills_dir(project.path())).unwrap();

        assert!(matches!(
            read_state(project.path()),
            StoredState::Unusable(_)
        ));
        assert!(create_root(project.path()).is_err());
    }
}
