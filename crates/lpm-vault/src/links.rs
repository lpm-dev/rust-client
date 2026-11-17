//! Which folders on this machine may use a vault's local values.
//!
//! A project's `lpm.json` names its vault. Each vault keeps the folders that
//! may use it with the vault's own storage, never in a repository: a Keychain
//! item on macOS, an owner-only file beside the vault elsewhere. A folder
//! that isn't linked gets none of the vault's values until it's linked here.
//!
//! Code already running as the user can change the list the way LPM CLI
//! does; only CLI approval, which asks the operating system for the user's
//! presence, holds against that.

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
/// so two spellings of one folder are one link.
pub(crate) fn link_folder_path(project_dir: &Path) -> PathBuf {
    project_dir
        .canonicalize()
        .unwrap_or_else(|_| project_dir.to_path_buf())
}

fn folder_key(folder: &Path) -> Result<String, String> {
    folder
        .to_str()
        .map(str::to_owned)
        .ok_or_else(|| format!("{} is not a UTF-8 path", folder.display()))
}

/// Where a vault's link list lives.
trait LinkStore {
    fn read(&mut self, vault_id: &str) -> Result<Option<LinkRecord>, String>;
    fn write(&mut self, vault_id: &str, record: &LinkRecord) -> Result<(), String>;
    fn delete(&mut self, vault_id: &str) -> Result<(), String>;
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

/// The link list beside the vault's file, for the file backend.
struct FileLinkStore<'directory> {
    directory: &'directory VaultStorageDirectory,
}

impl FileLinkStore<'_> {
    fn file_name(vault_id: &str) -> String {
        let vault_file = crate::fallback::vault_file_name(vault_id);
        let digest = vault_file.trim_end_matches(".vault");
        format!("{digest}.links")
    }
}

impl LinkStore for FileLinkStore<'_> {
    fn read(&mut self, vault_id: &str) -> Result<Option<LinkRecord>, String> {
        let vaults = self.directory.open_or_create_directory("vaults")?;
        vaults
            .read_owner_only_file(&Self::file_name(vault_id), "vault folder links")?
            .map(|bytes| decode(&bytes, vault_id))
            .transpose()
    }

    fn write(&mut self, vault_id: &str, record: &LinkRecord) -> Result<(), String> {
        let vaults = self.directory.open_or_create_directory("vaults")?;
        vaults.write_owner_only_file(
            &Self::file_name(vault_id),
            &encode(record)?,
            "vault folder links",
        )
    }

    fn delete(&mut self, vault_id: &str) -> Result<(), String> {
        if let Some(vaults) = self.directory.open_existing_directory("vaults")? {
            vaults.remove_file(&Self::file_name(vault_id), "vault folder links")?;
        }
        Ok(())
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
struct KeychainLinkStore;

#[cfg(target_os = "macos")]
impl LinkStore for KeychainLinkStore {
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

    fn delete(&mut self, vault_id: &str) -> Result<(), String> {
        crate::macos_keychain::delete(&lpm_common::credential_service(LINKS_SERVICE), vault_id)
            .map(drop)
    }

    fn holds_values(&mut self, vault_id: &str) -> Result<bool, String> {
        crate::keychain::holds_vault_values(vault_id)
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
        return operation(&mut KeychainLinkStore);
    }
    operation(&mut FileLinkStore { directory })
}

/// Whether `project_dir` may use the vault `vault_id`.
///
/// A vault with no link list predates links. When this machine holds none
/// of its values, there is nothing to keep from the folder. Otherwise the
/// folder the vault's records name is its first link, and any other folder
/// isn't linked yet.
pub(crate) fn check(
    directory: &VaultStorageDirectory,
    project_dir: &Path,
    vault_id: &str,
) -> Result<FolderLink, String> {
    with_store(directory, |store| check_in(store, project_dir, vault_id))
}

/// Reads the vault's project record only when the folder isn't linked or the
/// vault predates links, so a linked folder's check reads just the list.
fn check_in(
    store: &mut dyn LinkStore,
    project_dir: &Path,
    vault_id: &str,
) -> Result<FolderLink, String> {
    let folder = link_folder_path(project_dir);
    let key = folder_key(&folder)?;
    let (linked, recorded) = match store.read(vault_id)? {
        Some(record) => (record.folders, None),
        None if !store.holds_values(vault_id)? => (BTreeSet::from([key.clone()]), None),
        None => {
            let recorded = store.recorded_project(vault_id)?;
            let Some(path) = recorded
                .as_ref()
                .map(|(_, path)| path.as_str())
                .filter(|path| !path.is_empty())
            else {
                return Ok(unlinked(vault_id, folder, recorded, BTreeSet::new()));
            };
            let record = LinkRecord {
                schema_version: LINKS_SCHEMA_VERSION,
                folders: BTreeSet::from([folder_key(&link_folder_path(Path::new(path)))?]),
            };
            store.write(vault_id, &record)?;
            (record.folders, Some(recorded))
        }
    };
    if linked.contains(&key) {
        store.note_linked(vault_id, &folder);
        return Ok(FolderLink::Linked);
    }
    let recorded = match recorded {
        Some(recorded) => recorded,
        None => store.recorded_project(vault_id)?,
    };
    Ok(unlinked(vault_id, folder, recorded, linked))
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
            FolderLink::Unlinked(unlinked) => Err(unlinked.refusal()),
            FolderLink::Linked => {
                if store.read(vault_id)?.is_none() {
                    add_in(store, project_dir, vault_id)?;
                }
                Ok(())
            }
        }
    })
}

/// Links `project_dir` to the vault `vault_id`.
pub(crate) fn add(
    directory: &VaultStorageDirectory,
    project_dir: &Path,
    vault_id: &str,
) -> Result<(), String> {
    with_store(directory, |store| add_in(store, project_dir, vault_id))
}

fn add_in(store: &mut dyn LinkStore, project_dir: &Path, vault_id: &str) -> Result<(), String> {
    let mut record = store.read(vault_id)?.unwrap_or(LinkRecord {
        schema_version: LINKS_SCHEMA_VERSION,
        folders: BTreeSet::new(),
    });
    if record
        .folders
        .insert(folder_key(&link_folder_path(project_dir))?)
    {
        store.write(vault_id, &record)?;
    }
    Ok(())
}

/// Unlinks `folder` from the vault `vault_id`; whether it was linked.
pub(crate) fn remove(
    directory: &VaultStorageDirectory,
    folder: &Path,
    vault_id: &str,
) -> Result<bool, String> {
    with_store(directory, |store| {
        let Some(mut record) = store.read(vault_id)? else {
            return Ok(false);
        };
        // A folder that no longer exists can't be resolved, so it is also
        // matched as given.
        let resolved = record
            .folders
            .remove(&folder_key(&link_folder_path(folder))?);
        let removed = record.folders.remove(&folder_key(folder)?) || resolved;
        if removed {
            store.write(vault_id, &record)?;
        }
        Ok(removed)
    })
}

/// Removes the link list of the deleted file-backed vault `vault_id`.
pub(crate) fn forget_in_files(
    directory: &VaultStorageDirectory,
    vault_id: &str,
) -> Result<(), String> {
    FileLinkStore { directory }.delete(vault_id)
}

/// Removes the link list of the deleted Keychain vault `vault_id`.
#[cfg(target_os = "macos")]
pub(crate) fn forget_in_keychain(vault_id: &str) -> Result<(), String> {
    KeychainLinkStore.delete(vault_id)
}

/// The folders linked to the vault `vault_id`.
pub(crate) fn folders(
    directory: &VaultStorageDirectory,
    vault_id: &str,
) -> Result<Vec<PathBuf>, String> {
    with_store(directory, |store| {
        Ok(store
            .read(vault_id)?
            .map(|record| record.folders.into_iter().map(PathBuf::from).collect())
            .unwrap_or_default())
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
        project_reads: usize,
        noted: Vec<(String, PathBuf)>,
    }

    impl LinkStore for MemoryLinkStore {
        fn read(&mut self, vault_id: &str) -> Result<Option<LinkRecord>, String> {
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

        fn delete(&mut self, vault_id: &str) -> Result<(), String> {
            self.records.remove(vault_id);
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
        add_in(&mut store, &paths[0], "vault").unwrap();

        assert_eq!(
            check_in(&mut store, &paths[0], "vault").unwrap(),
            FolderLink::Linked
        );
        let FolderLink::Unlinked(unlinked) = check_in(&mut store, &paths[1], "vault").unwrap()
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
            check_in(&mut store, &paths[0], "vault").unwrap(),
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

        let FolderLink::Unlinked(unlinked) = check_in(&mut store, &paths[1], "vault").unwrap()
        else {
            panic!("only the recorded folder is linked");
        };
        assert_eq!(unlinked.project_name.as_deref(), Some("proj-a"));
        assert_eq!(unlinked.linked_folders, [paths[0].clone()]);
        assert_eq!(
            check_in(&mut store, &paths[0], "vault").unwrap(),
            FolderLink::Linked
        );
    }

    #[test]
    fn a_vault_from_before_links_without_a_recorded_folder_links_none() {
        let (_root, paths) = make_folders(&["any"]);
        let mut store = MemoryLinkStore::default();
        store.values.insert("vault".into());

        let FolderLink::Unlinked(unlinked) = check_in(&mut store, &paths[0], "vault").unwrap()
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

        let FolderLink::Unlinked(unlinked) = check_in(&mut store, &paths[0], "vault").unwrap()
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
        add_in(&mut store, &paths[0], "vault").unwrap();

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
        add_in(&mut store, &paths[0], "vault").unwrap();

        check_in(&mut store, &paths[1], "vault").unwrap();
        check_in(&mut store, &paths[0], "vault").unwrap();

        assert_eq!(store.noted, [("vault".to_owned(), paths[0].clone())]);
    }

    #[test]
    fn two_spellings_of_one_folder_are_one_link() {
        let (root, paths) = make_folders(&["own"]);
        let mut store = MemoryLinkStore::default();
        store.values.insert("vault".into());
        add_in(&mut store, &root.path().join("own/../own"), "vault").unwrap();

        assert_eq!(
            check_in(&mut store, &paths[0], "vault").unwrap(),
            FolderLink::Linked
        );
    }
}
