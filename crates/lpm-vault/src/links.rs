//! Which folders on this machine may use a vault's local values.
//!
//! A project's `lpm.json` names its vault. Each vault keeps the folders that
//! may use it with the vault's own storage, never in a repository: a Keychain
//! item on macOS, an owner-only file beside the vault elsewhere. A folder
//! that isn't linked gets none of the vault's values until it's linked here.
//!
//! The list isn't a boundary against other code running as the user; CLI
//! approval, which asks the operating system for the user's presence, is.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use crate::storage_transaction::VaultStorageDirectory;

const LINKS_SCHEMA_VERSION: u8 = 1;
#[cfg(target_os = "macos")]
const LINKS_SERVICE: &str = "dev.lpm.vault.links";

#[derive(Debug, serde::Serialize, serde::Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LinkRecord {
    schema_version: u8,
    folders: BTreeSet<String>,
}

/// Whether a folder may use the vault its `lpm.json` names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FolderLink {
    Linked,
    Unlinked(UnlinkedFolder),
}

/// A folder that names a vault it isn't linked to, with what this machine
/// knows of the vault.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnlinkedFolder {
    pub vault_id: String,
    /// The folder, as the link list would record it.
    pub folder: PathBuf,
    /// The project's name as the vault records it, not as the folder says.
    pub project_name: Option<String>,
    /// The folders linked to the vault.
    pub linked_folders: Vec<PathBuf>,
}

/// How every refusal of an unlinked folder begins, so a caller that gets
/// storage errors as text can tell it from a storage failure.
const REFUSAL_PREFIX: &str = "This folder isn't linked to env project ";

impl UnlinkedFolder {
    /// The refusal an operation on the vault's values gives.
    pub fn refusal(&self) -> String {
        let project = match &self.project_name {
            Some(name) => format!("{name:?} ({})", self.vault_id),
            None => self.vault_id.clone(),
        };
        format!(
            "{REFUSAL_PREFIX}{project}, which its lpm.json names: {}. Run `lpm env link` in that \
             folder to let it use the project's values on this machine.",
            self.folder.display()
        )
    }
}

/// Whether `message` is an [`UnlinkedFolder::refusal`].
pub(crate) fn is_refusal(message: &str) -> bool {
    message.starts_with(REFUSAL_PREFIX)
}

/// The folder a link names: the project folder with symbolic links resolved,
/// so two spellings of one folder are one link. A folder that no longer
/// exists is resolved through its nearest existing ancestor, so a link made
/// under another spelling still matches it.
pub(crate) fn link_folder_path(project_dir: &Path) -> PathBuf {
    if let Ok(resolved) = project_dir.canonicalize() {
        return resolved;
    }
    let Ok(absolute) = std::path::absolute(project_dir) else {
        return project_dir.to_path_buf();
    };
    let mut missing = Vec::new();
    let mut current = absolute.as_path();
    while let (Some(parent), Some(name)) = (current.parent(), current.file_name()) {
        missing.push(name);
        if let Ok(mut resolved) = parent.canonicalize() {
            resolved.extend(missing.iter().rev());
            return resolved;
        }
        current = parent;
    }
    absolute
}

fn folder_key(folder: &Path) -> Option<&str> {
    folder.to_str()
}

/// The refusal for a folder a link can't name.
fn unlinkable(folder: &Path, vault_id: &str) -> String {
    format!(
        "{REFUSAL_PREFIX}{vault_id}, and can't be: a link names a folder by a UTF-8 path, and \
         {} isn't one",
        folder.display()
    )
}

/// Where a vault's link list lives.
trait LinkStore {
    fn read(&mut self, vault_id: &str) -> Result<Option<LinkRecord>, String>;
    fn write(&mut self, vault_id: &str, record: &LinkRecord) -> Result<(), String>;
    /// Whether this machine holds values for the vault, found without
    /// reading them, which could ask for the user's presence.
    fn holds_values(&mut self, vault_id: &str) -> Result<bool, String>;
    /// The project name and folder the vault's own records name, if any.
    fn recorded_project(&mut self, vault_id: &str) -> Result<Option<(String, String)>, String>;
    /// Called when `folder` may use the vault, before the command reads it.
    fn note_linked(&mut self, _vault_id: &str, _folder: &Path) {}
}

fn decode(bytes: &[u8], vault_id: &str) -> Result<LinkRecord, String> {
    let record: LinkRecord = serde_json::from_slice(bytes)
        .map_err(|error| format!("the folder links of vault {vault_id} are invalid: {error}"))?;
    if record.schema_version != LINKS_SCHEMA_VERSION {
        return Err(format!(
            "the folder links of vault {vault_id} have unsupported schema version {}",
            record.schema_version
        ));
    }
    Ok(record)
}

fn encode(record: &LinkRecord) -> Result<Vec<u8>, String> {
    serde_json::to_vec(record).map_err(|error| format!("failed to encode folder links: {error}"))
}

fn record_of(folders: BTreeSet<String>) -> LinkRecord {
    LinkRecord {
        schema_version: LINKS_SCHEMA_VERSION,
        folders,
    }
}

fn file_name(vault_id: &str) -> String {
    let vault_file = crate::fallback::vault_file_name(vault_id);
    let digest = vault_file.trim_end_matches(".vault");
    format!("{digest}.links")
}

/// The link list beside the vault's file, for the file backend.
struct FileLinkStore<'directory> {
    directory: &'directory VaultStorageDirectory,
}

impl LinkStore for FileLinkStore<'_> {
    fn read(&mut self, vault_id: &str) -> Result<Option<LinkRecord>, String> {
        let vaults = self.directory.open_or_create_directory("vaults")?;
        vaults
            .read_owner_only_file(&file_name(vault_id), "vault folder links")?
            .map(|bytes| decode(&bytes, vault_id))
            .transpose()
    }

    fn write(&mut self, vault_id: &str, record: &LinkRecord) -> Result<(), String> {
        let vaults = self.directory.open_or_create_directory("vaults")?;
        vaults.write_owner_only_file(&file_name(vault_id), &encode(record)?, "vault folder links")
    }

    fn holds_values(&mut self, vault_id: &str) -> Result<bool, String> {
        crate::fallback::vault_file_exists(self.directory, vault_id)
    }

    fn recorded_project(&mut self, _vault_id: &str) -> Result<Option<(String, String)>, String> {
        Ok(None)
    }
}

/// The link list as its own Keychain item, apart from the vault's items, for
/// the macOS Keychain backend. It needs no approval to read, so checking a
/// folder never asks for the user's presence.
#[cfg(target_os = "macos")]
struct KeychainLinkStore<'directory> {
    /// Where values the Keychain backend still reads from a file live.
    directory: &'directory VaultStorageDirectory,
}

#[cfg(target_os = "macos")]
impl LinkStore for KeychainLinkStore<'_> {
    fn read(&mut self, vault_id: &str) -> Result<Option<LinkRecord>, String> {
        crate::macos_keychain::read_bytes(&lpm_common::credential_service(LINKS_SERVICE), vault_id)?
            .map(|bytes| decode(&bytes, vault_id))
            .transpose()
    }

    fn write(&mut self, vault_id: &str, record: &LinkRecord) -> Result<(), String> {
        crate::macos_keychain::write_bytes(
            &lpm_common::credential_service(LINKS_SERVICE),
            vault_id,
            &encode(record)?,
        )
    }

    /// The Keychain backend falls back to a vault file it hasn't moved into
    /// the Keychain, so either holds the vault's values.
    fn holds_values(&mut self, vault_id: &str) -> Result<bool, String> {
        Ok(crate::keychain::holds_vault_values(vault_id)?
            || crate::fallback::vault_file_exists(self.directory, vault_id)?)
    }

    fn recorded_project(&mut self, vault_id: &str) -> Result<Option<(String, String)>, String> {
        crate::keychain::recorded_project(vault_id)
    }

    fn note_linked(&mut self, vault_id: &str, folder: &Path) {
        crate::macos_keychain::note_requester(vault_id, folder, || {
            // The name only labels the approval prompt, so a record that
            // can't be read leaves the prompt with the vault ID.
            crate::keychain::recorded_project(vault_id)
                .ok()
                .flatten()
                .map(|(name, _)| name)
        });
    }
}

/// Runs `operation` with the link store of the backend that holds the
/// vault's values.
fn with_store<T>(
    directory: &VaultStorageDirectory,
    operation: impl FnOnce(&mut dyn LinkStore) -> Result<T, String>,
) -> Result<T, String> {
    #[cfg(target_os = "macos")]
    if !crate::force_file_vault_backend() {
        return operation(&mut KeychainLinkStore { directory });
    }
    operation(&mut FileLinkStore { directory })
}

/// The folders a vault's link list names, and the project record read on
/// the way, if any.
struct Resolved {
    /// `None` for a vault with neither a list nor values on this machine,
    /// which keeps nothing from any folder.
    folders: Option<BTreeSet<String>>,
    recorded: Option<Option<(String, String)>>,
}

/// The vault's link list. A vault without one predates links: with no
/// values here it keeps nothing from any folder; otherwise the folder its
/// records name, when they name one by an absolute path, becomes its first
/// link, and the list is written so later changes start from it.
fn resolve(store: &mut dyn LinkStore, vault_id: &str) -> Result<Resolved, String> {
    if let Some(record) = store.read(vault_id)? {
        return Ok(Resolved {
            folders: Some(record.folders),
            recorded: None,
        });
    }
    if !store.holds_values(vault_id)? {
        return Ok(Resolved {
            folders: None,
            recorded: None,
        });
    }
    let recorded = store.recorded_project(vault_id)?;
    let first = recorded
        .as_ref()
        .map(|(_, path)| Path::new(path))
        .filter(|path| path.is_absolute())
        .map(link_folder_path)
        .and_then(|folder| folder_key(&folder).map(str::to_owned));
    let folders = BTreeSet::from_iter(first);
    if !folders.is_empty() {
        store.write(vault_id, &record_of(folders.clone()))?;
    }
    Ok(Resolved {
        folders: Some(folders),
        recorded: Some(recorded),
    })
}

/// Whether `project_dir` may use the vault `vault_id`.
pub(crate) fn check(
    directory: &VaultStorageDirectory,
    project_dir: &Path,
    vault_id: &str,
) -> Result<FolderLink, String> {
    with_store(directory, |store| {
        check_in(store, project_dir, vault_id).map(|(link, _)| link)
    })
}

/// [`check`] in `store`, with the vault's list when it has one. Reads the
/// project record only when the folder isn't linked or the vault predates
/// links, so a linked folder's check reads just the list.
fn check_in(
    store: &mut dyn LinkStore,
    project_dir: &Path,
    vault_id: &str,
) -> Result<(FolderLink, Option<BTreeSet<String>>), String> {
    let folder = link_folder_path(project_dir);
    let key = folder_key(&folder).ok_or_else(|| unlinkable(&folder, vault_id))?;
    let Resolved { folders, recorded } = resolve(store, vault_id)?;
    let Some(folders) = folders else {
        store.note_linked(vault_id, &folder);
        return Ok((FolderLink::Linked, None));
    };
    if folders.contains(key) {
        store.note_linked(vault_id, &folder);
        return Ok((FolderLink::Linked, Some(folders)));
    }
    let recorded = match recorded {
        Some(recorded) => recorded,
        None => store.recorded_project(vault_id)?,
    };
    Ok((unlinked(vault_id, folder, recorded, folders), None))
}

fn unlinked(
    vault_id: &str,
    folder: PathBuf,
    recorded: Option<(String, String)>,
    linked: BTreeSet<String>,
) -> FolderLink {
    FolderLink::Unlinked(UnlinkedFolder {
        vault_id: vault_id.to_owned(),
        folder,
        project_name: recorded
            .map(|(name, _)| name)
            .filter(|name| !name.is_empty()),
        linked_folders: linked.into_iter().map(PathBuf::from).collect(),
    })
}

/// Fails unless `project_dir` may use the vault `vault_id`.
pub(crate) fn require(
    directory: &VaultStorageDirectory,
    project_dir: &Path,
    vault_id: &str,
) -> Result<(), String> {
    match check(directory, project_dir, vault_id)? {
        FolderLink::Linked => Ok(()),
        FolderLink::Unlinked(unlinked) => Err(unlinked.refusal()),
    }
}

/// Fails unless `project_dir` may store values in the vault `vault_id`. The
/// first folder to store values in a vault with neither values nor links on
/// this machine is linked to it.
pub(crate) fn require_for_write(
    directory: &VaultStorageDirectory,
    project_dir: &Path,
    vault_id: &str,
) -> Result<(), String> {
    with_store(directory, |store| {
        match check_in(store, project_dir, vault_id)? {
            (FolderLink::Unlinked(unlinked), _) => Err(unlinked.refusal()),
            (FolderLink::Linked, Some(_)) => Ok(()),
            (FolderLink::Linked, None) => {
                insert(store, project_dir, vault_id, BTreeSet::new()).map(drop)
            }
        }
    })
}

/// Links `project_dir` to the vault `vault_id`; whether it wasn't listed
/// before.
pub(crate) fn add(
    directory: &VaultStorageDirectory,
    project_dir: &Path,
    vault_id: &str,
) -> Result<bool, String> {
    with_store(directory, |store| {
        let folders = resolve(store, vault_id)?.folders.unwrap_or_default();
        insert(store, project_dir, vault_id, folders)
    })
}

/// Writes `folders` with `project_dir` added; whether it was added.
fn insert(
    store: &mut dyn LinkStore,
    project_dir: &Path,
    vault_id: &str,
    mut folders: BTreeSet<String>,
) -> Result<bool, String> {
    let folder = link_folder_path(project_dir);
    let key = folder_key(&folder).ok_or_else(|| unlinkable(&folder, vault_id))?;
    let added = folders.insert(key.to_owned());
    if added {
        store.write(vault_id, &record_of(folders))?;
    }
    store.note_linked(vault_id, &folder);
    Ok(added)
}

/// Unlinks `folder` from the vault `vault_id`; whether it was linked. A
/// vault from before links is resolved first, and one that kept nothing
/// from any folder gets an empty list, so the folder stays unlinked.
pub(crate) fn remove(
    directory: &VaultStorageDirectory,
    folder: &Path,
    vault_id: &str,
) -> Result<bool, String> {
    with_store(directory, |store| remove_in(store, folder, vault_id))
}

fn remove_in(store: &mut dyn LinkStore, folder: &Path, vault_id: &str) -> Result<bool, String> {
    let Some(mut folders) = resolve(store, vault_id)?.folders else {
        store.write(vault_id, &record_of(BTreeSet::new()))?;
        return Ok(true);
    };
    let resolved = folder_key(&link_folder_path(folder)).is_some_and(|key| folders.remove(key));
    let given = folder_key(folder).is_some_and(|key| folders.remove(key));
    let removed = resolved || given;
    if removed {
        store.write(vault_id, &record_of(folders))?;
    }
    Ok(removed)
}

/// Removes the link list of the deleted file-backed vault `vault_id`.
pub(crate) fn forget_in_files(
    directory: &VaultStorageDirectory,
    vault_id: &str,
) -> Result<(), String> {
    if let Some(vaults) = directory.open_existing_directory("vaults")? {
        vaults.remove_file(&file_name(vault_id), "vault folder links")?;
    }
    Ok(())
}

/// Removes the link list of the deleted Keychain vault `vault_id`.
#[cfg(target_os = "macos")]
pub(crate) fn forget_in_keychain(vault_id: &str) -> Result<(), String> {
    crate::macos_keychain::delete(&lpm_common::credential_service(LINKS_SERVICE), vault_id)
        .map(drop)
}

/// The folders linked to the vault `vault_id`, and whether `project_dir`
/// may use it.
pub(crate) fn listing(
    directory: &VaultStorageDirectory,
    project_dir: &Path,
    vault_id: &str,
) -> Result<(Vec<PathBuf>, bool), String> {
    with_store(directory, |store| {
        let folders = resolve(store, vault_id)?.folders;
        let folder = link_folder_path(project_dir);
        let this_folder = folders
            .as_ref()
            .is_none_or(|folders| folder_key(&folder).is_some_and(|key| folders.contains(key)));
        let folders = folders
            .unwrap_or_default()
            .into_iter()
            .map(PathBuf::from)
            .collect();
        Ok((folders, this_folder))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[derive(Default)]
    struct MemoryLinkStore {
        records: HashMap<String, LinkRecord>,
        values: BTreeSet<String>,
        projects: HashMap<String, (String, String)>,
        writes: usize,
        reads: usize,
        project_reads: usize,
        noted: Vec<(String, PathBuf)>,
    }

    impl LinkStore for MemoryLinkStore {
        fn read(&mut self, vault_id: &str) -> Result<Option<LinkRecord>, String> {
            self.reads += 1;
            Ok(self.records.get(vault_id).map(|record| LinkRecord {
                schema_version: record.schema_version,
                folders: record.folders.clone(),
            }))
        }

        fn write(&mut self, vault_id: &str, record: &LinkRecord) -> Result<(), String> {
            self.writes += 1;
            self.records.insert(
                vault_id.to_owned(),
                LinkRecord {
                    schema_version: record.schema_version,
                    folders: record.folders.clone(),
                },
            );
            Ok(())
        }

        fn holds_values(&mut self, vault_id: &str) -> Result<bool, String> {
            Ok(self.values.contains(vault_id))
        }

        fn recorded_project(&mut self, vault_id: &str) -> Result<Option<(String, String)>, String> {
            self.project_reads += 1;
            Ok(self.projects.get(vault_id).cloned())
        }

        fn note_linked(&mut self, vault_id: &str, folder: &Path) {
            self.noted.push((vault_id.to_owned(), folder.to_path_buf()));
        }
    }

    fn make_folders(names: &[&str]) -> (tempfile::TempDir, Vec<PathBuf>) {
        let root = tempfile::tempdir().unwrap();
        let paths = names
            .iter()
            .map(|name| {
                let path = root.path().join(name);
                std::fs::create_dir_all(&path).unwrap();
                link_folder_path(&path)
            })
            .collect();
        (root, paths)
    }

    #[test]
    fn a_folder_the_link_list_names_is_linked_and_another_is_not() {
        let (_root, paths) = make_folders(&["own", "copy"]);
        let mut store = MemoryLinkStore::default();
        store.values.insert("vault".into());
        insert(&mut store, &paths[0], "vault", BTreeSet::new()).unwrap();

        assert_eq!(
            check_in(&mut store, &paths[0], "vault").unwrap().0,
            FolderLink::Linked
        );
        let (FolderLink::Unlinked(unlinked), _) = check_in(&mut store, &paths[1], "vault").unwrap()
        else {
            panic!("a copy that names the vault must not be linked");
        };
        assert_eq!(unlinked.linked_folders, [paths[0].clone()]);
        assert_eq!(unlinked.folder, paths[1]);
    }

    #[test]
    fn a_vault_without_links_or_values_keeps_nothing_from_a_folder() {
        let (_root, paths) = make_folders(&["any"]);
        let mut store = MemoryLinkStore::default();

        assert_eq!(
            check_in(&mut store, &paths[0], "vault").unwrap().0,
            FolderLink::Linked
        );
        assert_eq!(store.writes, 0);
    }

    #[test]
    fn a_vault_from_before_links_links_the_folder_its_records_name() {
        let (_root, paths) = make_folders(&["own", "copy"]);
        let mut store = MemoryLinkStore::default();
        store.values.insert("vault".into());
        store.projects.insert(
            "vault".into(),
            ("proj-a".into(), paths[0].display().to_string()),
        );

        let (FolderLink::Unlinked(unlinked), _) = check_in(&mut store, &paths[1], "vault").unwrap()
        else {
            panic!("only the recorded folder is linked");
        };
        assert_eq!(unlinked.project_name.as_deref(), Some("proj-a"));
        assert_eq!(unlinked.linked_folders, [paths[0].clone()]);
        assert_eq!(
            check_in(&mut store, &paths[0], "vault").unwrap().0,
            FolderLink::Linked
        );
    }

    #[test]
    fn a_vault_from_before_links_without_a_recorded_folder_links_none() {
        let (_root, paths) = make_folders(&["any"]);
        let mut store = MemoryLinkStore::default();
        store.values.insert("vault".into());

        let (FolderLink::Unlinked(unlinked), _) = check_in(&mut store, &paths[0], "vault").unwrap()
        else {
            panic!("a vault with values and no links links no folder");
        };
        assert!(unlinked.linked_folders.is_empty());
        assert!(
            unlinked.refusal().contains("lpm env link"),
            "{}",
            unlinked.refusal()
        );
    }

    #[test]
    fn an_unlinked_folder_s_refusal_is_an_env_project_refusal() {
        let (_root, paths) = make_folders(&["copy"]);
        let mut store = MemoryLinkStore::default();
        store.values.insert("vault".into());
        store
            .projects
            .insert("vault".into(), ("proj-a".into(), "/elsewhere".into()));

        let (FolderLink::Unlinked(unlinked), _) = check_in(&mut store, &paths[0], "vault").unwrap()
        else {
            panic!("a folder the vault doesn't record isn't linked");
        };

        assert!(
            crate::is_env_project_refusal(&unlinked.refusal()),
            "{}",
            unlinked.refusal()
        );
        assert!(!crate::is_env_project_refusal(&format!(
            "{} isn't linked",
            paths[0].display()
        )));
    }

    #[test]
    fn a_linked_folder_s_check_reads_no_project_record() {
        let (_root, paths) = make_folders(&["own"]);
        let mut store = MemoryLinkStore::default();
        store.values.insert("vault".into());
        store.projects.insert(
            "vault".into(),
            ("proj-a".into(), paths[0].display().to_string()),
        );
        insert(&mut store, &paths[0], "vault", BTreeSet::new()).unwrap();

        for _ in 0..3 {
            check_in(&mut store, &paths[0], "vault").unwrap();
        }

        assert_eq!(store.project_reads, 0);
    }

    #[test]
    fn only_a_folder_that_may_use_the_vault_is_noted_for_its_prompts() {
        let (_root, paths) = make_folders(&["own", "copy"]);
        let mut store = MemoryLinkStore::default();
        store.values.insert("vault".into());
        insert(&mut store, &paths[0], "vault", BTreeSet::new()).unwrap();

        store.noted.clear();
        check_in(&mut store, &paths[1], "vault").unwrap();
        check_in(&mut store, &paths[0], "vault").unwrap();

        assert_eq!(store.noted, [("vault".to_owned(), paths[0].clone())]);
    }

    #[test]
    fn two_spellings_of_one_folder_are_one_link() {
        let (root, paths) = make_folders(&["own"]);
        let mut store = MemoryLinkStore::default();
        store.values.insert("vault".into());
        insert(
            &mut store,
            &root.path().join("own/../own"),
            "vault",
            BTreeSet::new(),
        )
        .unwrap();

        assert_eq!(
            check_in(&mut store, &paths[0], "vault").unwrap().0,
            FolderLink::Linked
        );
    }

    fn legacy_store(recorded: &Path) -> MemoryLinkStore {
        let mut store = MemoryLinkStore::default();
        store.values.insert("vault".into());
        store.projects.insert(
            "vault".into(),
            ("proj-a".into(), recorded.display().to_string()),
        );
        store
    }

    #[test]
    fn unlinking_the_folder_a_vault_from_before_links_records_keeps_it_unlinked() {
        let (_root, paths) = make_folders(&["own"]);
        let mut store = legacy_store(&paths[0]);

        assert!(remove_in(&mut store, &paths[0], "vault").unwrap());

        assert!(matches!(
            check_in(&mut store, &paths[0], "vault").unwrap().0,
            FolderLink::Unlinked(_)
        ));
    }

    #[test]
    fn unlinking_a_folder_of_a_vault_that_kept_none_out_leaves_it_unlinked() {
        let (_root, paths) = make_folders(&["any"]);
        let mut store = MemoryLinkStore::default();

        assert!(remove_in(&mut store, &paths[0], "vault").unwrap());

        assert!(matches!(
            check_in(&mut store, &paths[0], "vault").unwrap().0,
            FolderLink::Unlinked(_)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn a_deleted_folder_is_unlinked_under_another_spelling_of_its_parent() {
        let (root, paths) = make_folders(&["parent/own"]);
        let alias = root.path().join("alias");
        std::os::unix::fs::symlink(root.path().join("parent"), &alias).unwrap();
        let mut store = MemoryLinkStore::default();
        insert(&mut store, &paths[0], "vault", BTreeSet::new()).unwrap();
        std::fs::remove_dir(&paths[0]).unwrap();

        assert!(remove_in(&mut store, &alias.join("own"), "vault").unwrap());

        assert!(store.records["vault"].folders.is_empty());
    }

    #[test]
    fn a_relative_folder_in_a_vault_s_records_links_no_folder() {
        let (_root, paths) = make_folders(&["own"]);
        let mut store = legacy_store(Path::new("."));

        assert!(matches!(
            check_in(&mut store, &paths[0], "vault").unwrap().0,
            FolderLink::Unlinked(_)
        ));
        assert_eq!(store.writes, 0);
    }

    #[test]
    fn linking_a_folder_names_it_in_the_approval_prompt() {
        let (_root, paths) = make_folders(&["own"]);
        let mut store = MemoryLinkStore::default();

        insert(&mut store, &paths[0], "vault", BTreeSet::new()).unwrap();

        assert_eq!(store.noted, [("vault".to_owned(), paths[0].clone())]);
    }

    #[test]
    fn a_linked_folder_s_check_before_a_write_reads_the_list_once() {
        let (_root, paths) = make_folders(&["own"]);
        let mut store = MemoryLinkStore::default();
        store.values.insert("vault".into());
        insert(&mut store, &paths[0], "vault", BTreeSet::new()).unwrap();
        store.reads = 0;

        let (link, folders) = check_in(&mut store, &paths[0], "vault").unwrap();

        assert_eq!(link, FolderLink::Linked);
        assert!(
            folders.is_some(),
            "a write that knows the list doesn't read it again"
        );
        assert_eq!(store.reads, 1);
    }

    #[test]
    fn every_folder_may_use_a_vault_that_keeps_none_out() {
        let (_root, paths) = make_folders(&["any"]);
        let mut store = MemoryLinkStore::default();

        let Resolved { folders, .. } = resolve(&mut store, "vault").unwrap();

        assert!(folders.is_none());
        assert_eq!(
            check_in(&mut store, &paths[0], "vault").unwrap().0,
            FolderLink::Linked
        );
    }
}
