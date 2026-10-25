//! Companion storage in the Linux and Windows file store.
//!
//! Each project's companion records live in one owner-only folder,
//! `vaults/<vault digest>.companion/`, as entries named `features`,
//! `record.<kind>[.<part>]` or `staged.<kind>[.<part>]`. Windows reserves
//! device names such as `con` by the part before the first dot, whatever the
//! extension, so every record entry starts with a fixed word. Each entry is
//! sealed with AES-256-GCM under the data key, bound to its logical account
//! and vault ID.
//!
//! Changes that touch several files go through a journal, `vaults/.journal`,
//! with stages in `vaults/.stage/`:
//!
//! 1. Write every stage, each file synced, then sync `.stage/` once.
//! 2. Write the journal, `committed`, atomically.
//! 3. Rename each stage over its target, or delete the target.
//! 4. Sync each changed folder once.
//! 5. Delete the journal, sync `vaults/`, and remove `.stage/`.
//!
//! There's no `preparing` journal: stages found without a journal were never
//! committed, and recovery deletes them.

use std::collections::{BTreeMap, BTreeSet, HashSet};

use aes_gcm::aead::{AeadInPlace, generic_array::GenericArray};
use aes_gcm::{Aes256Gcm, KeyInit};
use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::companion::account::CompanionAccount;
use crate::companion::gate::{Operation, ProjectGate};
use crate::companion::lifecycle::{
    LifecycleStore, MAX_TRANSACTION_OPERATIONS, MAX_TRANSACTION_PAYLOAD_BYTES, Mutation,
};
use crate::companion::marker::{MAX_RECORD_BYTES, Marker};
use crate::companion::overrides::{OVERRIDES_KIND, PersonalOverrides};
use crate::companion::{CompanionBackend, damaged, evaluate_overrides};
use crate::storage_transaction::VaultStorageDirectory;

const VAULTS_FOLDER: &str = "vaults";
const JOURNAL: &str = ".journal";
const STAGE_FOLDER: &str = ".stage";
const MARKER_ENTRY: &str = "features";
const RECORD_ENTRY_PREFIX: &str = "record.";
const STAGED_ENTRY_PREFIX: &str = "staged.";
const ENTRY_AAD_DOMAIN: &[u8] = b"lpm-vault-companion\x01";
const NONCE_BYTES: usize = 12;
const TAG_BYTES: usize = 16;
const FILE_JOURNAL_SCHEMA_VERSION: u8 = 1;
const MAX_FILE_JOURNAL_BYTES: usize = 64 * 1024;

/// A project's companion folder: the digest that names its values file, with
/// a `.companion` extension.
pub(crate) fn companion_folder_name(vault_id: &str) -> String {
    let values = super::vault_file_name(vault_id);
    let digest = values.strip_suffix(".vault").unwrap_or(&values);
    format!("{digest}.companion")
}

fn entry_name(account: &CompanionAccount) -> String {
    let (prefix, kind, part) = match account {
        CompanionAccount::Marker { .. } => return MARKER_ENTRY.to_owned(),
        CompanionAccount::Record { kind, part, .. } => (RECORD_ENTRY_PREFIX, kind, part),
        CompanionAccount::Staged { kind, part, .. } => (STAGED_ENTRY_PREFIX, kind, part),
    };
    match part {
        Some(part) => format!("{prefix}{kind}.{part:03x}"),
        None => format!("{prefix}{kind}"),
    }
}

/// The account an entry of `vault_id`'s folder stores, when the entry is
/// named exactly as this module names it.
fn parse_entry_name(vault_id: &str, name: &str) -> Option<CompanionAccount> {
    if name == MARKER_ENTRY {
        return Some(CompanionAccount::Marker {
            vault_id: vault_id.to_owned(),
        });
    }
    let (staged, rest) = if let Some(rest) = name.strip_prefix(RECORD_ENTRY_PREFIX) {
        (false, rest)
    } else {
        (true, name.strip_prefix(STAGED_ENTRY_PREFIX)?)
    };
    let (kind, part) = match rest.split_once('.') {
        Some((kind, part)) => (kind, Some(part)),
        None => (rest, None),
    };
    let account = if staged {
        crate::companion::account::staged_account(kind, vault_id, None)
    } else {
        crate::companion::account::record_account(kind, vault_id, None)
    };
    let account = match part {
        Some(part) => format!("{account}:{part}"),
        None => account,
    };
    let parsed = CompanionAccount::parse(&account)?;
    (entry_name(&parsed) == name).then_some(parsed)
}

fn entry_associated_data(account: &CompanionAccount) -> Result<Vec<u8>, String> {
    let name = account.name();
    let vault_id = account.vault_id();
    let name_length = u16::try_from(name.len())
        .map_err(|_| "a companion account name is too long to seal".to_owned())?;
    let vault_length =
        u16::try_from(vault_id.len()).map_err(|_| "a vault ID is too long to seal".to_owned())?;
    let mut data = Vec::with_capacity(ENTRY_AAD_DOMAIN.len() + 4 + name.len() + vault_id.len());
    data.extend_from_slice(ENTRY_AAD_DOMAIN);
    data.extend_from_slice(&name_length.to_be_bytes());
    data.extend_from_slice(name.as_bytes());
    data.extend_from_slice(&vault_length.to_be_bytes());
    data.extend_from_slice(vault_id.as_bytes());
    Ok(data)
}

fn seal(key: &[u8; 32], account: &CompanionAccount, plaintext: &[u8]) -> Result<Vec<u8>, String> {
    let cipher =
        Aes256Gcm::new_from_slice(key).map_err(|error| format!("cipher init error: {error}"))?;
    let mut nonce = [0u8; NONCE_BYTES];
    rand::thread_rng().fill_bytes(&mut nonce);
    let mut sealed = Vec::with_capacity(NONCE_BYTES + plaintext.len() + TAG_BYTES);
    sealed.extend_from_slice(&nonce);
    sealed.extend_from_slice(plaintext);
    let tag = cipher
        .encrypt_in_place_detached(
            GenericArray::from_slice(&nonce),
            &entry_associated_data(account)?,
            &mut sealed[NONCE_BYTES..],
        )
        .map_err(|error| format!("encryption error: {error}"))?;
    sealed.extend_from_slice(&tag);
    Ok(sealed)
}

fn open(key: &[u8; 32], account: &CompanionAccount, sealed: &[u8]) -> Result<Vec<u8>, String> {
    if sealed.len() < NONCE_BYTES + TAG_BYTES {
        return Err(format!(
            "companion entry {} is truncated",
            entry_name(account)
        ));
    }
    let cipher =
        Aes256Gcm::new_from_slice(key).map_err(|error| format!("cipher init error: {error}"))?;
    let (nonce, rest) = sealed.split_at(NONCE_BYTES);
    let (ciphertext, tag) = rest.split_at(rest.len() - TAG_BYTES);
    let mut plaintext = ciphertext.to_vec();
    cipher
        .decrypt_in_place_detached(
            GenericArray::from_slice(nonce),
            &entry_associated_data(account)?,
            &mut plaintext,
            GenericArray::from_slice(tag),
        )
        .map_err(|_| {
            format!(
                "companion entry {} failed authentication (wrong key or corrupted data)",
                entry_name(account)
            )
        })?;
    Ok(plaintext)
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::Digest as _;
    hex::encode(sha2::Sha256::digest(bytes))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
enum FileAction {
    Replace,
    Delete,
}

/// Which file of a project's values an operation targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
enum ValuesFile {
    /// `<digest>.vault`.
    Digest,
    /// `<vault id>.enc`, the name before files were named by digest.
    Legacy,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct FileOperation {
    action: FileAction,
    /// A vault ID for a values file, or a companion account.
    target: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    values_file: Option<ValuesFile>,
    /// The target's SHA-256 before the transaction, or `None` when absent.
    before: Option<String>,
    /// The target's SHA-256 after it, or `None` when it's deleted.
    after: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct FileJournal {
    schema_version: u8,
    transaction_id: String,
    operations: Vec<FileOperation>,
}

/// Where an operation's target lives, derived from its logical name only.
enum PhysicalTarget {
    Values { name: String },
    Companion { folder: String, entry: String },
}

impl FileOperation {
    fn physical(&self) -> Result<PhysicalTarget, String> {
        match self.values_file {
            Some(file) => {
                if !lpm_common::stored_env::is_safe_vault_id(&self.target) {
                    return Err("the env file journal names an invalid env project".to_owned());
                }
                Ok(PhysicalTarget::Values {
                    name: match file {
                        ValuesFile::Digest => super::vault_file_name(&self.target),
                        ValuesFile::Legacy => format!("{}.enc", self.target),
                    },
                })
            }
            None => {
                let account = CompanionAccount::parse(&self.target).ok_or_else(|| {
                    "the env file journal names an invalid companion record".to_owned()
                })?;
                Ok(PhysicalTarget::Companion {
                    folder: companion_folder_name(account.vault_id()),
                    entry: entry_name(&account),
                })
            }
        }
    }
}

fn stage_name(transaction_id: &str, index: usize) -> String {
    format!("{transaction_id}.{index}")
}

fn is_hex_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

impl FileJournal {
    fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() > MAX_FILE_JOURNAL_BYTES {
            return Err("the env file journal is too large".to_owned());
        }
        let journal: Self = serde_json::from_slice(bytes)
            .map_err(|error| format!("the env file journal is malformed: {error}"))?;
        journal.validate()?;
        Ok(journal)
    }

    fn validate(&self) -> Result<(), String> {
        if self.schema_version != FILE_JOURNAL_SCHEMA_VERSION
            || !is_transaction_id(&self.transaction_id)
            || self.operations.is_empty()
            || self.operations.len() > MAX_TRANSACTION_OPERATIONS
        {
            return Err("the env file journal is invalid".to_owned());
        }
        let mut targets = HashSet::with_capacity(self.operations.len());
        for operation in &self.operations {
            let physical = operation.physical()?;
            let key = match physical {
                PhysicalTarget::Values { name } => name,
                PhysicalTarget::Companion { folder, entry } => format!("{folder}/{entry}"),
            };
            if !targets.insert(key) {
                return Err("the env file journal names a target twice".to_owned());
            }
            if operation
                .before
                .as_deref()
                .is_some_and(|digest| !is_hex_digest(digest))
                || operation
                    .after
                    .as_deref()
                    .is_some_and(|digest| !is_hex_digest(digest))
                || match operation.action {
                    FileAction::Replace => operation.after.is_none(),
                    FileAction::Delete => operation.after.is_some(),
                }
            {
                return Err("the env file journal has an invalid operation".to_owned());
            }
        }
        Ok(())
    }
}

fn is_transaction_id(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn new_transaction_id() -> String {
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// The file store's companion records, for one operation inside the lock.
pub(crate) struct FileCompanion<'directory> {
    directory: &'directory VaultStorageDirectory,
    vaults: VaultStorageDirectory,
}

impl<'directory> FileCompanion<'directory> {
    pub(crate) fn open(directory: &'directory VaultStorageDirectory) -> Result<Self, String> {
        Ok(Self {
            directory,
            vaults: directory.open_or_create_directory(VAULTS_FOLDER)?,
        })
    }

    fn data_key(&self) -> Result<[u8; 32], String> {
        super::load_data_key_with_store_unlocked(self.directory, &super::KeyringNativeDataKeyStore)
            .map(|key| key.bytes)
    }

    fn folder(&self, vault_id: &str) -> Result<Option<VaultStorageDirectory>, String> {
        self.vaults
            .open_existing_directory(&companion_folder_name(vault_id))
    }

    fn read_sealed(
        &self,
        folder: &VaultStorageDirectory,
        entry: &str,
    ) -> Result<Option<Vec<u8>>, String> {
        folder.read_owner_only_file(entry, "companion entry")
    }

    /// Recover an interrupted journal: replay it when it's committed, and
    /// remove stages no journal covers. Runs before every file-store
    /// operation that reads companion records.
    pub(crate) fn recover(&mut self) -> Result<(), String> {
        let Some(bytes) = self
            .vaults
            .read_owner_only_file(JOURNAL, "env file journal")?
        else {
            return self.remove_stage_folder();
        };
        let journal = FileJournal::parse(&bytes)?;
        self.check_journal_invariants(&journal)?;
        let stage = self.vaults.open_existing_directory(STAGE_FOLDER)?;
        let mut changed = BTreeSet::new();
        for (index, operation) in journal.operations.iter().enumerate() {
            let companion_folder = match operation.physical()? {
                PhysicalTarget::Values { .. } => None,
                PhysicalTarget::Companion { folder, .. } => {
                    Some(self.vaults.open_or_create_directory(&folder)?)
                }
            };
            let (folder, entry) = match (&companion_folder, operation.physical()?) {
                (Some(folder), PhysicalTarget::Companion { entry, .. }) => (folder, entry),
                (_, PhysicalTarget::Values { name }) => (&self.vaults, name),
                (None, PhysicalTarget::Companion { .. }) => {
                    return Err("a companion folder is missing".to_owned());
                }
            };
            let current = folder
                .sha256_owner_only_file(&entry, "env file journal target")?
                .map(hex::encode);
            if current == operation.after {
                continue;
            }
            if current != operation.before {
                if operation.values_file.is_some() {
                    // An older CLI rewrote these values after the crash; its
                    // write wins, as it would right after a finished transaction.
                    continue;
                }
                return Err(crate::companion::gate::GateError::Damaged(
                    crate::companion::gate::Damage::InvalidRecord {
                        kind: entry,
                        reason: "it changed outside the transaction that was writing it".to_owned(),
                    },
                )
                .to_string());
            }
            match operation.action {
                FileAction::Replace => {
                    let stage = stage.as_ref().ok_or_else(|| {
                        "the env file journal lost the stage of a change it hadn't applied"
                            .to_owned()
                    })?;
                    let name = stage_name(&journal.transaction_id, index);
                    let digest = stage
                        .sha256_owner_only_file(&name, "env file journal stage")?
                        .map(hex::encode);
                    if digest != operation.after {
                        return Err("an env file journal stage doesn't match its digest".to_owned());
                    }
                    stage.rename_to(&name, folder, &entry, "a journaled change")?;
                }
                FileAction::Delete => {
                    folder.remove_file_unsynced(&entry, "a journaled deletion")?;
                }
            }
            changed.insert(operation_folder_key(operation)?);
        }
        self.sync_folders(&changed)?;
        self.finish()
    }

    /// I1, I2 and I5 for the marker each touched project is left with.
    fn check_journal_invariants(&self, journal: &FileJournal) -> Result<(), String> {
        let mut projects: BTreeMap<String, Vec<(CompanionAccount, FileAction)>> = BTreeMap::new();
        for operation in &journal.operations {
            if operation.values_file.is_some() {
                continue;
            }
            let account = CompanionAccount::parse(&operation.target).ok_or_else(|| {
                "the env file journal names an invalid companion record".to_owned()
            })?;
            projects
                .entry(account.vault_id().to_owned())
                .or_default()
                .push((account, operation.action));
        }
        let stage = self.vaults.open_existing_directory(STAGE_FOLDER)?;
        for (vault_id, changes) in projects {
            let marker_index = journal.operations.iter().position(|operation| {
                operation.values_file.is_none()
                    && matches!(
                        CompanionAccount::parse(&operation.target),
                        Some(CompanionAccount::Marker { vault_id: ref id }) if *id == vault_id
                    )
            });
            let key = self.data_key()?;
            let marker_account = CompanionAccount::Marker {
                vault_id: vault_id.clone(),
            };
            let post_marker = match marker_index {
                Some(index) if journal.operations[index].action == FileAction::Delete => None,
                Some(index) => {
                    let name = stage_name(&journal.transaction_id, index);
                    let sealed = match stage
                        .as_ref()
                        .map(|stage| stage.read_owner_only_file(&name, "env file journal stage"))
                        .transpose()?
                        .flatten()
                    {
                        Some(sealed) => sealed,
                        None => self
                            .folder(&vault_id)?
                            .map(|folder| self.read_sealed(&folder, MARKER_ENTRY))
                            .transpose()?
                            .flatten()
                            .ok_or_else(|| {
                                "the env file journal lost a marker it wrote".to_owned()
                            })?,
                    };
                    Some(parse_marker(
                        &vault_id,
                        &open(&key, &marker_account, &sealed)?,
                    )?)
                }
                None => self.read_marker(&vault_id, &key)?,
            };
            let listed = |account: &CompanionAccount| match (account, &post_marker) {
                (CompanionAccount::Marker { .. }, _) => true,
                (CompanionAccount::Record { kind, .. }, Some(marker)) => {
                    marker.lists_kind(kind) || marker.restore_lists_kind(kind)
                }
                (CompanionAccount::Staged { kind, .. }, Some(marker)) => {
                    marker.restore_lists_kind(kind)
                }
                (_, None) => false,
            };
            let deleted: HashSet<&CompanionAccount> = changes
                .iter()
                .filter(|(_, action)| *action == FileAction::Delete)
                .map(|(account, _)| account)
                .collect();
            for (account, action) in &changes {
                if *action == FileAction::Replace && !listed(account) {
                    return Err(format!(
                        "the env file journal writes {} without a feature that lists it",
                        account.name()
                    ));
                }
            }
            for account in self.inventory_of(&vault_id)? {
                if !deleted.contains(&account) && !listed(&account) {
                    return Err(format!(
                        "the env file journal would leave {} without a feature that lists it",
                        account.name()
                    ));
                }
            }
        }
        Ok(())
    }

    fn read_marker(&self, vault_id: &str, key: &[u8; 32]) -> Result<Option<Marker>, String> {
        let Some(folder) = self.folder(vault_id)? else {
            return Ok(None);
        };
        let account = CompanionAccount::Marker {
            vault_id: vault_id.to_owned(),
        };
        self.read_sealed(&folder, MARKER_ENTRY)?
            .map(|sealed| parse_marker(vault_id, &open(key, &account, &sealed)?))
            .transpose()
    }

    fn sync_folders(&self, changed: &BTreeSet<String>) -> Result<(), String> {
        for key in changed {
            if key.is_empty() {
                self.vaults.sync("env files")?;
            } else if let Some(folder) = self.vaults.open_existing_directory(key)? {
                folder.sync("companion records")?;
            }
        }
        Ok(())
    }

    fn finish(&mut self) -> Result<(), String> {
        self.vaults.remove_file(JOURNAL, "env file journal")?;
        self.remove_stage_folder()
    }

    fn remove_stage_folder(&self) -> Result<(), String> {
        if !self.vaults.entry_exists(STAGE_FOLDER)? {
            return Ok(());
        }
        let stage = self.vaults.open_or_create_directory(STAGE_FOLDER)?;
        for name in stage.entry_names()? {
            stage.remove_file_unsynced(&name, "a stale env file journal stage")?;
        }
        self.vaults
            .remove_empty_directory(STAGE_FOLDER, "env file journal stages")?;
        Ok(())
    }

    fn inventory_of(&self, vault_id: &str) -> Result<Vec<CompanionAccount>, String> {
        let Some(folder) = self.folder(vault_id)? else {
            return Ok(Vec::new());
        };
        let mut accounts = Vec::new();
        for name in folder.entry_names()? {
            match parse_entry_name(vault_id, &name) {
                Some(CompanionAccount::Marker { .. }) => {}
                Some(account) => accounts.push(account),
                None => {
                    return Err(crate::companion::gate::GateError::Damaged(
                        crate::companion::gate::Damage::InvalidRecord {
                            kind: name,
                            reason: "its name isn't one LPM writes".to_owned(),
                        },
                    )
                    .to_string());
                }
            }
        }
        Ok(accounts)
    }
}

fn operation_folder_key(operation: &FileOperation) -> Result<String, String> {
    Ok(match operation.physical()? {
        PhysicalTarget::Values { .. } => String::new(),
        PhysicalTarget::Companion { folder, .. } => folder,
    })
}

fn parse_marker(vault_id: &str, bytes: &[u8]) -> Result<Marker, String> {
    Marker::parse(vault_id, bytes).map_err(|error| error.to_string())
}

impl LifecycleStore for FileCompanion<'_> {
    fn read(&mut self, account: &CompanionAccount) -> Result<Option<Vec<u8>>, String> {
        let Some(folder) = self.folder(account.vault_id())? else {
            return Ok(None);
        };
        let Some(sealed) = self.read_sealed(&folder, &entry_name(account))? else {
            return Ok(None);
        };
        let key = self.data_key()?;
        open(&key, account, &sealed).map(Some)
    }

    fn commit(&mut self, mutations: Vec<Mutation>) -> Result<(), String> {
        if mutations.is_empty() {
            return Ok(());
        }
        if mutations.len() > MAX_TRANSACTION_OPERATIONS {
            return Err("an env file transaction has too many operations".to_owned());
        }
        let payload: usize = mutations
            .iter()
            .map(|mutation| match mutation {
                Mutation::Write { value, .. } => value.len(),
                Mutation::Delete { .. } => 0,
            })
            .sum();
        if payload > MAX_TRANSACTION_PAYLOAD_BYTES {
            return Err("an env file transaction writes too many bytes".to_owned());
        }
        let key = self.data_key()?;
        let transaction_id = new_transaction_id();
        let stage = self.vaults.open_or_create_directory(STAGE_FOLDER)?;
        let mut operations = Vec::with_capacity(mutations.len());
        let mut staged_any = false;
        for (index, mutation) in mutations.iter().enumerate() {
            let (account, value) = match mutation {
                Mutation::Write { account, value } => (account, Some(value)),
                Mutation::Delete { account } => (account, None),
            };
            if value.is_some_and(|value| value.len() > MAX_RECORD_BYTES) {
                return Err("a companion record exceeds its size limit".to_owned());
            }
            let before = self
                .folder(account.vault_id())?
                .map(|folder| {
                    folder.sha256_owner_only_file(&entry_name(account), "companion entry")
                })
                .transpose()?
                .flatten()
                .map(hex::encode);
            let after = match value {
                Some(value) => {
                    let sealed = seal(&key, account, value)?;
                    stage.write_owner_only_file_unsynced(
                        &stage_name(&transaction_id, index),
                        &sealed,
                        "env file journal stage",
                    )?;
                    staged_any = true;
                    Some(sha256_hex(&sealed))
                }
                None => None,
            };
            operations.push(FileOperation {
                action: if after.is_some() {
                    FileAction::Replace
                } else {
                    FileAction::Delete
                },
                target: account.name(),
                values_file: None,
                before,
                after,
            });
        }
        if staged_any {
            stage.sync("env file journal stages")?;
        }
        let journal = FileJournal {
            schema_version: FILE_JOURNAL_SCHEMA_VERSION,
            transaction_id,
            operations,
        };
        journal.validate()?;
        let encoded = serde_json::to_vec(&journal)
            .map_err(|error| format!("failed to encode the env file journal: {error}"))?;
        if encoded.len() > MAX_FILE_JOURNAL_BYTES {
            return Err("the env file journal is too large".to_owned());
        }
        self.vaults
            .write_owner_only_file(JOURNAL, &encoded, "env file journal")?;

        let mut changed = BTreeSet::new();
        let mut created_folder = false;
        for (index, operation) in journal.operations.iter().enumerate() {
            let PhysicalTarget::Companion { folder, entry } = operation.physical()? else {
                return Err("an env file transaction may only change companion records".to_owned());
            };
            match operation.action {
                FileAction::Replace => {
                    created_folder |= !self.vaults.entry_exists(&folder)?;
                    let directory = self.vaults.open_or_create_directory(&folder)?;
                    stage.rename_to(
                        &stage_name(&journal.transaction_id, index),
                        &directory,
                        &entry,
                        "a companion record",
                    )?;
                }
                FileAction::Delete => {
                    if let Some(directory) = self.vaults.open_existing_directory(&folder)? {
                        directory.remove_file_unsynced(&entry, "a companion record")?;
                    }
                }
            }
            changed.insert(folder);
        }
        let mut removed_folder = false;
        for folder in &changed {
            if let Some(directory) = self.vaults.open_existing_directory(folder)?
                && directory.entry_names()?.is_empty()
            {
                drop(directory);
                removed_folder |= self
                    .vaults
                    .remove_empty_directory(folder, "a companion folder")?;
            }
        }
        if created_folder || removed_folder {
            changed.insert(String::new());
        }
        self.sync_folders(&changed)?;
        self.finish()
    }
}

impl CompanionBackend for FileCompanion<'_> {
    fn inventory(&mut self, vault_id: &str) -> Result<Vec<CompanionAccount>, String> {
        self.inventory_of(vault_id)
    }
}

/// Recover the file journal, then authorize `operation` on `vault_id`.
pub(crate) fn authorize_unlocked(
    directory: &VaultStorageDirectory,
    vault_id: &str,
    operation: Operation,
) -> Result<ProjectGate, String> {
    let mut companion = FileCompanion::open(directory)?;
    companion.recover()?;
    crate::companion::authorize(&mut companion, vault_id, operation)
}

/// The personal overrides record, read in the caller's lock after the Apply
/// gate, with the gate that decides what it means.
pub(crate) fn read_overrides_record_unlocked(
    directory: &VaultStorageDirectory,
    vault_id: &str,
) -> Result<(ProjectGate, Option<Vec<u8>>), String> {
    let gate = authorize_unlocked(directory, vault_id, Operation::ReadApplyingOverrides)?;
    let mut companion = FileCompanion::open(directory)?;
    let record = companion.read(&CompanionAccount::Record {
        kind: OVERRIDES_KIND.to_owned(),
        vault_id: vault_id.to_owned(),
        part: None,
    })?;
    Ok((gate, record))
}

/// The selected environment's personal overrides.
pub(crate) fn read_overrides_unlocked(
    directory: &VaultStorageDirectory,
    vault_id: &str,
    environment: &str,
) -> Result<PersonalOverrides, String> {
    let (gate, record) = read_overrides_record_unlocked(directory, vault_id)?;
    evaluate_overrides(&gate, vault_id, environment, record.as_deref()).map_err(damaged)
}

/// Remove every companion record of `vault_id` through the deletion protocol.
pub(crate) fn delete_project_unlocked(
    directory: &VaultStorageDirectory,
    vault_id: &str,
) -> Result<(), String> {
    let gate = authorize_unlocked(directory, vault_id, Operation::Maintenance)?;
    let mut companion = FileCompanion::open(directory)?;
    let inventory = companion.inventory(vault_id)?;
    if inventory.is_empty() && matches!(gate, ProjectGate::Plain) {
        return Ok(());
    }
    let deleting = crate::companion::deleting_marker(vault_id, gate.marker(), &inventory);
    companion.commit(vec![Mutation::Write {
        account: CompanionAccount::Marker {
            vault_id: vault_id.to_owned(),
        },
        value: deleting.encode().map_err(|error| error.to_string())?,
    }])?;
    crate::companion::lifecycle::resume(&mut companion, deleting, inventory)?;
    crate::companion::remember(vault_id, &ProjectGate::Plain);
    Ok(())
}

/// How many projects have companion folders, for storage status.
pub(crate) fn companion_folder_count(directory: &VaultStorageDirectory) -> Result<usize, String> {
    let Some(vaults) = directory.open_existing_directory(VAULTS_FOLDER)? else {
        return Ok(0);
    };
    Ok(vaults
        .entry_names()?
        .iter()
        .filter(|name| name.ends_with(".companion"))
        .count())
}

#[cfg(test)]
mod tests;
