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
//! Changes that touch several of a project's files go through its journal,
//! `vaults/<vault digest>.journal`, with stages in
//! `vaults/<vault digest>.stage/`, so an interrupted change holds up only its
//! own project:
//!
//! 1. Write every stage, each file synced, then sync the stage folder once.
//! 2. Write the journal, `committed`, atomically.
//! 3. Rename each stage over its target, or delete the target.
//! 4. Sync each changed folder once.
//! 5. Delete the journal, sync `vaults/`, and remove the stage folder.
//!
//! There's no `preparing` journal: stages found without a journal were never
//! committed, and recovery deletes them.

use std::collections::BTreeSet;

use aes_gcm::aead::{AeadInOut, Nonce, Tag};
use aes_gcm::{Aes256Gcm, KeyInit};
use rand::Rng;
use serde::{Deserialize, Serialize};

use crate::companion::account::CompanionAccount;
use crate::companion::gate::{Damage, GateError, Operation, ProjectGate};
use crate::companion::invariants::check_transaction;
use crate::companion::lifecycle::{
    FoundMarker, LifecycleStore, MAX_TRANSACTION_OPERATIONS, MAX_TRANSACTION_PAYLOAD_BYTES,
    Mutation, Plan,
};
use crate::companion::marker::MAX_RECORD_BYTES;
use crate::companion::overrides::change::InventoryNeed;
use crate::companion::overrides::{OVERRIDES_KIND, PersonalOverrides};
use crate::companion::repair::{CompanionRepair, CompanionReview};
use crate::companion::{Checked, CompanionBackend, damaged};
use crate::storage_transaction::VaultStorageDirectory;

const VAULTS_FOLDER: &str = "vaults";
const MARKER_ENTRY: &str = "features";
const RECORD_ENTRY_PREFIX: &str = "record.";
const STAGED_ENTRY_PREFIX: &str = "staged.";
const ENTRY_AAD_DOMAIN: &[u8] = b"lpm-vault-companion\x01";
const NONCE_BYTES: usize = 12;
const TAG_BYTES: usize = 16;
/// The largest sealed entry: a record at its limit with its nonce and tag.
const MAX_SEALED_ENTRY_BYTES: u64 = (MAX_RECORD_BYTES + NONCE_BYTES + TAG_BYTES) as u64;
const FILE_JOURNAL_SCHEMA_VERSION: u8 = 1;
const MAX_FILE_JOURNAL_BYTES: usize = 64 * 1024;
const CHANGED_OUTSIDE: &str = "changed outside LPM while LPM was changing it";

#[cfg(test)]
thread_local! {
    /// Fail the next commit once its journal is written and that many of its
    /// changes are applied, as a crash would leave it.
    pub(crate) static CRASH_AFTER_CHANGES: std::cell::Cell<Option<usize>> = const { std::cell::Cell::new(None) };
    /// How often this thread ran recovery.
    pub(crate) static RECOVERIES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// The digest that names a project's values file, companion folder, journal
/// and stage folder.
fn vault_digest(vault_id: &str) -> String {
    let mut name = super::vault_file_name(vault_id);
    if let Some(digest) = name.strip_suffix(".vault") {
        name.truncate(digest.len());
    }
    name
}

/// A project's companion folder: the digest that names its values file, with
/// a `.companion` extension.
pub(crate) fn companion_folder_name(vault_id: &str) -> String {
    format!("{}.companion", vault_digest(vault_id))
}

fn journal_name(vault_id: &str) -> String {
    format!("{}.journal", vault_digest(vault_id))
}

fn stage_folder_name(vault_id: &str) -> String {
    format!("{}.stage", vault_digest(vault_id))
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
    rand::rng().fill_bytes(&mut nonce);
    let mut sealed = Vec::with_capacity(NONCE_BYTES + plaintext.len() + TAG_BYTES);
    sealed.extend_from_slice(&nonce);
    sealed.extend_from_slice(plaintext);
    let tag = cipher
        .encrypt_inout_detached(
            <&Nonce<Aes256Gcm>>::from(&nonce),
            &entry_associated_data(account)?,
            (&mut sealed[NONCE_BYTES..]).into(),
        )
        .map_err(|error| format!("encryption error: {error}"))?;
    sealed.extend_from_slice(&tag);
    Ok(sealed)
}

/// Authenticate and decrypt `sealed` in place, so the plaintext reuses its
/// allocation.
fn open(
    key: &[u8; 32],
    account: &CompanionAccount,
    mut sealed: Vec<u8>,
) -> Result<Vec<u8>, String> {
    if sealed.len() < NONCE_BYTES + TAG_BYTES {
        return Err(format!(
            "companion entry {} is truncated",
            entry_name(account)
        ));
    }
    let cipher =
        Aes256Gcm::new_from_slice(key).map_err(|error| format!("cipher init error: {error}"))?;
    let tag_start = sealed.len() - TAG_BYTES;
    let (head, tag) = sealed
        .split_last_chunk_mut::<TAG_BYTES>()
        .expect("checked above: the entry holds a tag");
    let (nonce, ciphertext) = head
        .split_first_chunk_mut::<NONCE_BYTES>()
        .expect("checked above: the entry holds a nonce");
    cipher
        .decrypt_inout_detached(
            <&Nonce<Aes256Gcm>>::from(&*nonce),
            &entry_associated_data(account)?,
            ciphertext.into(),
            <&Tag<Aes256Gcm>>::from(&*tag),
        )
        .map_err(|_| {
            format!(
                "companion entry {} failed authentication (wrong key or corrupted data)",
                entry_name(account)
            )
        })?;
    sealed.truncate(tag_start);
    sealed.drain(..NONCE_BYTES);
    Ok(sealed)
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

impl ValuesFile {
    fn name(self, vault_id: &str) -> String {
        match self {
            Self::Digest => super::vault_file_name(vault_id),
            Self::Legacy => format!("{vault_id}.enc"),
        }
    }
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
    Values {
        name: String,
    },
    Companion {
        account: CompanionAccount,
        entry: String,
    },
}

impl FileOperation {
    /// The operation's target, which must be one of `vault_id`'s files.
    fn physical(&self, vault_id: &str) -> Result<PhysicalTarget, String> {
        match self.values_file {
            Some(file) => {
                if self.target != vault_id {
                    return Err("its journal names another project's values".to_owned());
                }
                Ok(PhysicalTarget::Values {
                    name: file.name(vault_id),
                })
            }
            None => {
                let account = CompanionAccount::parse(&self.target)
                    .filter(|account| account.vault_id() == vault_id)
                    .ok_or_else(|| {
                        "its journal names a record that isn't the project's".to_owned()
                    })?;
                Ok(PhysicalTarget::Companion {
                    entry: entry_name(&account),
                    account,
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
    fn parse(bytes: &[u8], vault_id: &str) -> Result<Self, String> {
        if bytes.len() > MAX_FILE_JOURNAL_BYTES {
            return Err("its journal is too large".to_owned());
        }
        let journal: Self = serde_json::from_slice(bytes).map_err(|error| {
            format!(
                "its journal is malformed: {}",
                crate::companion::marker::describe_json_error(&error)
            )
        })?;
        journal.validate(vault_id)?;
        Ok(journal)
    }

    fn validate(&self, vault_id: &str) -> Result<(), String> {
        if self.schema_version != FILE_JOURNAL_SCHEMA_VERSION
            || !is_transaction_id(&self.transaction_id)
            || self.operations.is_empty()
            || self.operations.len() > MAX_TRANSACTION_OPERATIONS
        {
            return Err("its journal is invalid".to_owned());
        }
        let mut targets = BTreeSet::new();
        for operation in &self.operations {
            let key = match operation.physical(vault_id)? {
                PhysicalTarget::Values { name } => name,
                PhysicalTarget::Companion { entry, .. } => format!("/{entry}"),
            };
            if !targets.insert(key) {
                return Err("its journal names a file twice".to_owned());
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
                return Err("its journal has an invalid change".to_owned());
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
    rand::rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// One change of a file-store transaction.
enum FileChange {
    Companion(Mutation),
    /// Delete one of the project's values files, as a deletion's first
    /// transaction does with the shared key and the single records.
    DeleteValues(ValuesFile),
    /// Replace the project's values file with these encrypted bytes, with
    /// the records that follow a values write.
    ReplaceValues(zeroize::Zeroizing<Vec<u8>>),
}

/// Why recovery couldn't finish a project's journal.
#[derive(Debug)]
pub(crate) enum RecoveryError {
    /// The journal or a file it names is in a state LPM never leaves it in,
    /// so only discarding the project's newer data gets past it.
    Stuck(String),
    /// Storage failed, so trying again may succeed.
    Failed(String),
}

impl From<String> for RecoveryError {
    fn from(error: String) -> Self {
        Self::Failed(error)
    }
}

impl RecoveryError {
    /// The error an operation on the project fails with: stuck recovery is
    /// damage, which `lpm env repair` discards.
    pub(crate) fn into_message(self) -> String {
        match self {
            Self::Stuck(reason) => GateError::Damaged(Damage::Unfinished(reason)).to_string(),
            Self::Failed(message) => message,
        }
    }
}

/// Who applies a journal: the commit that wrote it, which knows every target
/// is in its before-state, or recovery, which checks.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Replay {
    Commit,
    Recovery,
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
        folder.read_owner_only_file_capped(entry, "companion entry", MAX_SEALED_ENTRY_BYTES)
    }

    /// Recover `vault_id`'s interrupted journal: replay it when it's
    /// committed, and remove stages no journal covers. Runs before the first
    /// operation on the project in each lock.
    pub(crate) fn recover(&mut self, vault_id: &str) -> Result<(), RecoveryError> {
        #[cfg(test)]
        RECOVERIES.with(|recoveries| recoveries.set(recoveries.get() + 1));
        let Some(bytes) = self.vaults.read_owner_only_file_capped(
            &journal_name(vault_id),
            "env file journal",
            MAX_FILE_JOURNAL_BYTES as u64,
        )?
        else {
            return Ok(self.remove_stage_folder(vault_id)?);
        };
        let journal = FileJournal::parse(&bytes, vault_id).map_err(RecoveryError::Stuck)?;
        let stage = self
            .vaults
            .open_existing_directory(&stage_folder_name(vault_id))?;
        self.check_journal_invariants(vault_id, &journal, stage.as_ref())?;
        if journal.operations.iter().any(|operation| {
            matches!(
                operation.physical(vault_id),
                Ok(PhysicalTarget::Companion { account, .. })
                    if crate::companion::changes_overrides(&account)
            )
        }) {
            crate::companion::report_replayed_change(vault_id).map_err(RecoveryError::Failed)?;
        }
        self.replay(vault_id, &journal, stage.as_ref(), Replay::Recovery)?;
        drop(stage);
        Ok(self.finish(vault_id)?)
    }

    /// I1, I2 and I5 for the marker the journal leaves, as its commit
    /// checked them.
    fn check_journal_invariants(
        &self,
        vault_id: &str,
        journal: &FileJournal,
        stage: Option<&VaultStorageDirectory>,
    ) -> Result<(), RecoveryError> {
        let key = self.data_key()?;
        let mut changes: Vec<(String, Option<Vec<u8>>)> = Vec::new();
        for (index, operation) in journal.operations.iter().enumerate() {
            let PhysicalTarget::Companion { account, .. } =
                operation.physical(vault_id).map_err(RecoveryError::Stuck)?
            else {
                continue;
            };
            let value = match (&account, operation.action) {
                (_, FileAction::Delete) => None,
                (CompanionAccount::Marker { .. }, FileAction::Replace) => {
                    let name = stage_name(&journal.transaction_id, index);
                    let sealed = match stage
                        .map(|stage| {
                            stage.read_owner_only_file_capped(
                                &name,
                                "env file journal stage",
                                MAX_SEALED_ENTRY_BYTES,
                            )
                        })
                        .transpose()?
                        .flatten()
                    {
                        Some(sealed) => sealed,
                        None => self
                            .folder(vault_id)?
                            .map(|folder| self.read_sealed(&folder, MARKER_ENTRY))
                            .transpose()?
                            .flatten()
                            .ok_or_else(|| {
                                RecoveryError::Stuck(
                                    "its journal lost a feature marker it wrote".to_owned(),
                                )
                            })?,
                    };
                    Some(open(&key, &account, sealed).map_err(RecoveryError::Stuck)?)
                }
                (_, FileAction::Replace) => Some(Vec::new()),
            };
            changes.push((operation.target.clone(), value));
        }
        self.check_changes(&changes, &key)
            .map_err(|refusal| match refusal {
                crate::companion::invariants::Refusal::Storage(error) => {
                    RecoveryError::Failed(error)
                }
                refusal => RecoveryError::Stuck(refusal.describe("its journal")),
            })
    }

    /// The commit-time and recovery-time invariant check, over the names
    /// and marker bytes of a transaction's companion changes.
    fn check_changes(
        &self,
        changes: &[(String, Option<Vec<u8>>)],
        key: &[u8; 32],
    ) -> Result<(), crate::companion::invariants::Refusal> {
        let changes: Vec<(&str, Option<&[u8]>)> = changes
            .iter()
            .map(|(account, value)| (account.as_str(), value.as_deref()))
            .collect();
        check_transaction(
            &changes,
            |vault_id| self.read_marker_bytes(vault_id, key),
            |vault_id| self.listed_records(vault_id),
        )
    }

    fn read_marker_bytes(&self, vault_id: &str, key: &[u8; 32]) -> Result<Option<Vec<u8>>, String> {
        let Some(folder) = self.folder(vault_id)? else {
            return Ok(None);
        };
        let account = CompanionAccount::Marker {
            vault_id: vault_id.to_owned(),
        };
        self.read_sealed(&folder, MARKER_ENTRY)?
            .map(|sealed| open(key, &account, sealed))
            .transpose()
    }

    /// Apply `journal` in order, then sync every folder it touched: each
    /// target's folder whether this replay or the one before a crash changed
    /// it, and `vaults/` for values files and for companion folders it
    /// created or emptied.
    fn replay(
        &self,
        vault_id: &str,
        journal: &FileJournal,
        stage: Option<&VaultStorageDirectory>,
        replay: Replay,
    ) -> Result<(), RecoveryError> {
        let folder_name = companion_folder_name(vault_id);
        let mut companion_folder = self.vaults.open_existing_directory(&folder_name)?;
        let (mut sync_vaults, mut sync_folder) = (false, false);
        for (index, operation) in journal.operations.iter().enumerate() {
            #[cfg(test)]
            if replay == Replay::Commit
                && CRASH_AFTER_CHANGES.with(|crash| crash.get()) == Some(index)
            {
                CRASH_AFTER_CHANGES.with(|crash| crash.set(None));
                return Err(RecoveryError::Failed(
                    "simulated crash between changes".to_owned(),
                ));
            }
            let (folder, entry, account) =
                match operation.physical(vault_id).map_err(RecoveryError::Stuck)? {
                    PhysicalTarget::Values { name } => {
                        sync_vaults = true;
                        (&self.vaults, name, None)
                    }
                    PhysicalTarget::Companion { account, entry } => {
                        sync_folder = true;
                        if companion_folder.is_none() {
                            if operation.action == FileAction::Delete {
                                sync_vaults = true;
                                continue;
                            }
                            companion_folder =
                                Some(self.vaults.open_or_create_directory(&folder_name)?);
                            sync_vaults = true;
                        }
                        let Some(folder) = companion_folder.as_ref() else {
                            unreachable!("the companion folder was just opened");
                        };
                        (folder, entry, Some(account))
                    }
                };
            if replay == Replay::Recovery {
                let current = folder
                    .sha256_owner_only_file(&entry, "env file journal target")?
                    .map(hex::encode);
                if current == operation.after {
                    continue;
                }
                if current != operation.before {
                    let Some(account) = account else {
                        // An older CLI rewrote these values after the crash; its
                        // write wins, as it would right after a finished transaction.
                        continue;
                    };
                    return Err(RecoveryError::Stuck(changed_outside(&account)));
                }
            }
            match operation.action {
                FileAction::Replace => {
                    let stage = stage.ok_or_else(|| {
                        RecoveryError::Stuck(
                            "its journal lost the stage of a change it hadn't applied".to_owned(),
                        )
                    })?;
                    let name = stage_name(&journal.transaction_id, index);
                    if replay == Replay::Recovery
                        && stage
                            .sha256_owner_only_file(&name, "env file journal stage")?
                            .map(hex::encode)
                            != operation.after
                    {
                        return Err(RecoveryError::Stuck(
                            "a stage of its journal doesn't match its digest".to_owned(),
                        ));
                    }
                    stage.rename_to(&name, folder, &entry, "a journaled change")?;
                }
                FileAction::Delete => {
                    folder.remove_file_unsynced(&entry, "a journaled deletion")?;
                }
            }
        }
        #[cfg(test)]
        if replay == Replay::Commit
            && CRASH_AFTER_CHANGES.with(|crash| crash.get()) == Some(journal.operations.len())
        {
            CRASH_AFTER_CHANGES.with(|crash| crash.set(None));
            return Err(RecoveryError::Failed(
                "simulated crash after the last change".to_owned(),
            ));
        }
        if let Some(folder) = companion_folder.take()
            && folder.is_empty()?
        {
            drop(folder);
            sync_folder = false;
            sync_vaults |= self
                .vaults
                .remove_empty_directory(&folder_name, "a companion folder")?;
        }
        if sync_folder && let Some(folder) = self.vaults.open_existing_directory(&folder_name)? {
            folder.sync("companion records")?;
        }
        if sync_vaults {
            self.vaults.sync("env files")?;
        }
        Ok(())
    }

    /// Commit `changes` to `vault_id`'s files as one crash-atomic
    /// transaction. Companion changes are checked as recovery checks them,
    /// unless `checked` is false, which only seeds damage for tests.
    fn commit_changes(
        &mut self,
        vault_id: &str,
        changes: Vec<FileChange>,
        checked: bool,
    ) -> Result<(), String> {
        if changes.is_empty() {
            return Ok(());
        }
        if changes.len() > MAX_TRANSACTION_OPERATIONS {
            return Err("an env file transaction has too many changes".to_owned());
        }
        if let [FileChange::DeleteValues(file)] = changes[..] {
            self.vaults
                .remove_file(&file.name(vault_id), "encrypted vault")?;
            return Ok(());
        }
        // The budget is for the companion records a transaction writes;
        // values a journal carries have their own cap, which every values
        // write has and older recovery reads stages within.
        let payload: usize = changes
            .iter()
            .map(|change| match change {
                FileChange::Companion(mutation) => mutation.payload_bytes(),
                FileChange::DeleteValues(_) | FileChange::ReplaceValues(_) => 0,
            })
            .sum();
        if payload > MAX_TRANSACTION_PAYLOAD_BYTES {
            return Err("an env file transaction writes too many bytes".to_owned());
        }
        let key = self.data_key()?;
        if checked {
            let companion: Vec<(String, Option<Vec<u8>>)> = changes
                .iter()
                .filter_map(|change| match change {
                    FileChange::Companion(Mutation::Write { account, value }) => Some((
                        account.name(),
                        Some(match account {
                            CompanionAccount::Marker { .. } => value.to_vec(),
                            _ => Vec::new(),
                        }),
                    )),
                    FileChange::Companion(Mutation::Delete { account }) => {
                        Some((account.name(), None))
                    }
                    FileChange::DeleteValues(_) | FileChange::ReplaceValues(_) => None,
                })
                .collect();
            self.check_changes(&companion, &key)
                .map_err(|refusal| refusal.describe("an env file transaction"))?;
        }

        let transaction_id = new_transaction_id();
        let folder = self.folder(vault_id)?;
        let mut stage = None;
        let mut operations = Vec::with_capacity(changes.len());
        let mut staged = |index: usize, bytes: &[u8]| -> Result<String, String> {
            if stage.is_none() {
                stage = Some(
                    self.vaults
                        .open_or_create_directory(&stage_folder_name(vault_id))?,
                );
            }
            let Some(stage) = stage.as_ref() else {
                unreachable!("the stage folder was just opened");
            };
            stage.write_owner_only_file_unsynced(
                &stage_name(&transaction_id, index),
                bytes,
                "env file journal stage",
            )?;
            Ok(sha256_hex(bytes))
        };
        for (index, change) in changes.iter().enumerate() {
            let operation = match change {
                FileChange::ReplaceValues(bytes) => FileOperation {
                    action: FileAction::Replace,
                    target: vault_id.to_owned(),
                    values_file: Some(ValuesFile::Digest),
                    before: self
                        .vaults
                        .sha256_owner_only_file(
                            &ValuesFile::Digest.name(vault_id),
                            "encrypted vault",
                        )?
                        .map(hex::encode),
                    after: Some(staged(index, bytes)?),
                },
                FileChange::DeleteValues(file) => FileOperation {
                    action: FileAction::Delete,
                    target: vault_id.to_owned(),
                    values_file: Some(*file),
                    before: self
                        .vaults
                        .sha256_owner_only_file(&file.name(vault_id), "encrypted vault")?
                        .map(hex::encode),
                    after: None,
                },
                FileChange::Companion(mutation) => {
                    let (account, value) = match mutation {
                        Mutation::Write { account, value } => (account, Some(value)),
                        Mutation::Delete { account } => (account, None),
                    };
                    if account.vault_id() != vault_id {
                        return Err(
                            "an env file transaction may change only one env project".to_owned()
                        );
                    }
                    if value.is_some_and(|value| value.len() > MAX_RECORD_BYTES) {
                        return Err("a companion record exceeds its size limit".to_owned());
                    }
                    let before = folder
                        .as_ref()
                        .map(|folder| {
                            folder.sha256_owner_only_file(&entry_name(account), "companion entry")
                        })
                        .transpose()?
                        .flatten()
                        .map(hex::encode);
                    let after = match value {
                        Some(value) => Some(staged(index, &seal(&key, account, value)?)?),
                        None => None,
                    };
                    FileOperation {
                        action: if after.is_some() {
                            FileAction::Replace
                        } else {
                            FileAction::Delete
                        },
                        target: account.name(),
                        values_file: None,
                        before,
                        after,
                    }
                }
            };
            operations.push(operation);
        }
        drop(folder);
        if let Some(stage) = stage.as_ref() {
            stage.sync("env file journal stages")?;
        }
        let journal = FileJournal {
            schema_version: FILE_JOURNAL_SCHEMA_VERSION,
            transaction_id,
            operations,
        };
        journal.validate(vault_id)?;
        let encoded = serde_json::to_vec(&journal)
            .map_err(|error| format!("failed to encode the env file journal: {error}"))?;
        if encoded.len() > MAX_FILE_JOURNAL_BYTES {
            return Err("the env file journal is too large".to_owned());
        }
        if let Err(error) =
            self.vaults
                .write_owner_only_file(&journal_name(vault_id), &encoded, "env file journal")
        {
            // The journal's rename can land before its folder's sync fails,
            // so the next operation opens the project and finishes it.
            crate::companion::forget(vault_id);
            return Err(error);
        }
        let applied = (|| {
            #[cfg(test)]
            if CRASH_AFTER_CHANGES.with(|crash| crash.get()) == Some(0) {
                CRASH_AFTER_CHANGES.with(|crash| crash.set(None));
                return Err("simulated crash after the env file journal".to_owned());
            }
            self.replay(vault_id, &journal, stage.as_ref(), Replay::Commit)
                .map_err(RecoveryError::into_message)?;
            drop(stage);
            self.finish(vault_id)
        })();
        if applied.is_err() {
            crate::companion::forget(vault_id);
        }
        applied
    }

    fn finish(&mut self, vault_id: &str) -> Result<(), String> {
        self.vaults
            .remove_file(&journal_name(vault_id), "env file journal")?;
        self.remove_stage_folder(vault_id)
    }

    /// Windows refuses to remove a folder while any handle to it is open, so
    /// callers drop theirs first.
    fn remove_stage_folder(&self, vault_id: &str) -> Result<(), String> {
        let name = stage_folder_name(vault_id);
        if !self.vaults.entry_exists(&name)? {
            return Ok(());
        }
        {
            let stage = self.vaults.open_or_create_directory(&name)?;
            for entry in stage.entry_names()? {
                stage.remove_file_unsynced(&entry, "a stale env file journal stage")?;
            }
        }
        self.vaults
            .remove_empty_directory(&name, "env file journal stages")?;
        Ok(())
    }

    /// Whether `vault_id` has values, in either file name; anything but a
    /// regular file there is refused, as the values' read refuses it.
    fn has_values(&self, vault_id: &str) -> Result<bool, String> {
        if self
            .vaults
            .regular_file_exists(&ValuesFile::Digest.name(vault_id), "encrypted vault")?
        {
            return Ok(true);
        }
        match super::existing_legacy_vault_file_name(&self.vaults, vault_id)? {
            Some(legacy) => self.vaults.regular_file_exists(&legacy, "encrypted vault"),
            None => Ok(false),
        }
    }

    /// `vault_id`'s companion and staged records, failing on an entry whose
    /// name LPM doesn't write, which the gate reports as damage.
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
                    return Err(GateError::Damaged(Damage::InvalidRecord {
                        kind: name,
                        reason: "its name isn't one LPM writes".to_owned(),
                    })
                    .to_string());
                }
            }
        }
        Ok(accounts)
    }

    /// `vault_id`'s companion and staged records, skipping entries no
    /// marker can list, for the invariant check.
    fn listed_records(&self, vault_id: &str) -> Result<Vec<CompanionAccount>, String> {
        let Some(folder) = self.folder(vault_id)? else {
            return Ok(Vec::new());
        };
        Ok(folder
            .entry_names()?
            .iter()
            .filter_map(|name| parse_entry_name(vault_id, name))
            .filter(|account| !matches!(account, CompanionAccount::Marker { .. }))
            .collect())
    }
}

/// Why recovery stops at a companion entry a journal was changing that
/// something else changed.
fn changed_outside(account: &CompanionAccount) -> String {
    match account.kind() {
        Some(kind) => format!("record \"{kind}\" {CHANGED_OUTSIDE}"),
        None => format!("the feature marker {CHANGED_OUTSIDE}"),
    }
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
        open(&key, account, sealed).map(Some)
    }

    fn commit(&mut self, mutations: Vec<Mutation>) -> Result<(), String> {
        let Some(vault_id) = mutations
            .first()
            .map(|mutation| mutation.account().vault_id().to_owned())
        else {
            return Ok(());
        };
        self.commit_changes(
            &vault_id,
            mutations.into_iter().map(FileChange::Companion).collect(),
            true,
        )
    }
}

impl CompanionBackend for FileCompanion<'_> {
    fn inventory(&mut self, vault_id: &str) -> Result<Vec<CompanionAccount>, String> {
        self.inventory_of(vault_id)
    }

    fn read_overrides_beside_values(&mut self, vault_id: &str) -> Result<Option<Checked>, String> {
        if !self.has_values(vault_id)? {
            return Ok(None);
        }
        self.read_checked(&CompanionAccount::Record {
            kind: OVERRIDES_KIND.to_owned(),
            vault_id: vault_id.to_owned(),
            part: None,
        })
        .map(Some)
    }

    fn read_checked(&mut self, account: &CompanionAccount) -> Result<Checked, String> {
        let Some(folder) = self.folder(account.vault_id())? else {
            return Ok(Checked::Absent);
        };
        let sealed = match folder.read_owner_only_file_within(
            &entry_name(account),
            "companion entry",
            MAX_SEALED_ENTRY_BYTES,
        )? {
            None => return Ok(Checked::Absent),
            Some(Err(over)) => {
                return Ok(Checked::Unreadable(over.describe("companion entry")));
            }
            Some(Ok(sealed)) => sealed,
        };
        let key = self.data_key()?;
        Ok(match open(&key, account, sealed) {
            Ok(bytes) => Checked::Present(zeroize::Zeroizing::new(bytes)),
            Err(reason) => Checked::Unreadable(reason),
        })
    }
}

/// Recover `vault_id`'s file journal, unless this lock already opened the
/// project, then authorize `operation` on it.
pub(crate) fn authorize_unlocked(
    directory: &VaultStorageDirectory,
    vault_id: &str,
    operation: Operation,
) -> Result<ProjectGate, String> {
    authorize_with(&mut FileCompanion::open(directory)?, vault_id, operation)
}

fn authorize_with(
    companion: &mut FileCompanion<'_>,
    vault_id: &str,
    operation: Operation,
) -> Result<ProjectGate, String> {
    if !crate::companion::is_open(vault_id) {
        companion
            .recover(vault_id)
            .map_err(RecoveryError::into_message)?;
    }
    crate::companion::authorize(companion, vault_id, operation)
}

/// A record's bytes, wiped when dropped; `None` when it's absent.
pub(crate) type RecordBytes = Option<zeroize::Zeroizing<Vec<u8>>>;

#[cfg(test)]
thread_local! {
    pub(crate) static OVERRIDES_RECORD_READS: std::cell::Cell<usize> =
        const { std::cell::Cell::new(0) };
}

/// The personal overrides record. One that fails to decrypt is damage,
/// which says how to repair it.
fn read_overrides_record(
    companion: &mut FileCompanion<'_>,
    vault_id: &str,
) -> Result<RecordBytes, String> {
    #[cfg(test)]
    OVERRIDES_RECORD_READS.with(|reads| reads.set(reads.get() + 1));
    let account = CompanionAccount::Record {
        kind: OVERRIDES_KIND.to_owned(),
        vault_id: vault_id.to_owned(),
        part: None,
    };
    match companion.read_checked(&account)? {
        Checked::Present(bytes) => Ok(Some(bytes)),
        Checked::Absent => Ok(None),
        Checked::Unreadable(reason) => Err(damaged(Damage::InvalidRecord {
            kind: OVERRIDES_KIND.to_owned(),
            reason,
        })),
    }
}

/// The personal overrides record, read in the caller's lock after the Apply
/// gate, with the gate that decides what it means; `None` for a project
/// without values, which has no overrides: they live beside values, and a
/// record left without them is never applied.
fn read_overrides_record_unlocked(
    directory: &VaultStorageDirectory,
    vault_id: &str,
) -> Result<Option<(ProjectGate, RecordBytes)>, String> {
    let mut companion = FileCompanion::open(directory)?;
    let gate = authorize_with(&mut companion, vault_id, Operation::ReadApplyingOverrides)?;
    if !companion.has_values(vault_id)? {
        return Ok(None);
    }
    let record = read_overrides_record(&mut companion, vault_id)?;
    Ok(Some((gate, record)))
}

/// What a run reads in the caller's lock, after the Apply gate: the values
/// file's name and content, and the personal overrides record only when
/// there are values, which overrides need.
pub(crate) struct RunRead {
    pub(crate) values: Option<(String, Vec<u8>)>,
    /// The folder the values file is in, which names it in an error.
    pub(crate) vaults: VaultStorageDirectory,
    gate: ProjectGate,
    record: RecordBytes,
}

pub(crate) fn read_for_run_unlocked(
    directory: &VaultStorageDirectory,
    vault_id: &str,
) -> Result<RunRead, String> {
    let mut companion = FileCompanion::open(directory)?;
    let gate = authorize_with(&mut companion, vault_id, Operation::ReadApplyingOverrides)?;
    let values = super::read_vault_content(&companion.vaults, vault_id)?;
    let record = match values {
        Some(_) => read_overrides_record(&mut companion, vault_id)?,
        None => None,
    };
    Ok(RunRead {
        values,
        vaults: companion.vaults,
        gate,
        record,
    })
}

impl RunRead {
    /// What identifies the project's overrides in every environment, when
    /// they apply: there are values, and a record beside them.
    pub(crate) fn overrides_identity(&self) -> Option<crate::OverridesIdentity> {
        self.values.as_ref()?;
        self.record
            .as_deref()
            .map(|record| crate::OverridesIdentity::of(record))
    }

    /// `environment`'s personal overrides.
    pub(crate) fn overrides(
        &self,
        vault_id: &str,
        environment: &str,
    ) -> Result<PersonalOverrides, String> {
        if self.values.is_none() {
            return Ok(PersonalOverrides::default());
        }
        crate::companion::overrides::evaluate(
            &self.gate,
            vault_id,
            environment,
            self.record.as_ref().map(|bytes| bytes.as_slice()),
        )
        .map_err(damaged)
    }

    /// Every environment's personal overrides.
    pub(crate) fn all_overrides(
        &self,
        vault_id: &str,
    ) -> Result<std::collections::BTreeMap<String, PersonalOverrides>, String> {
        if self.values.is_none() {
            return Ok(std::collections::BTreeMap::new());
        }
        crate::companion::overrides::evaluate_all(
            &self.gate,
            vault_id,
            self.record.as_ref().map(|bytes| bytes.as_slice()),
        )
        .map_err(damaged)
    }
}

/// Every environment's personal overrides, read in the caller's lock after
/// the Apply gate.
pub(crate) fn read_all_overrides_unlocked(
    directory: &VaultStorageDirectory,
    vault_id: &str,
) -> Result<crate::overrides::AllOverrides, String> {
    let Some((gate, record)) = read_overrides_record_unlocked(directory, vault_id)? else {
        return Ok((std::collections::BTreeMap::new(), None));
    };
    let overrides = crate::companion::overrides::evaluate_all(
        &gate,
        vault_id,
        record.as_ref().map(|bytes| bytes.as_slice()),
    )
    .map_err(damaged)?;
    Ok((
        overrides,
        record.map(|record| crate::OverridesIdentity::of(&record)),
    ))
}

/// Refuse what `edits` to `vault_id`'s overrides are refused for whatever
/// their values, in the caller's lock: an interrupted step that can't be
/// finished, a gate that refuses writes, or no values, which overrides need.
/// No value or record is decrypted.
pub(crate) fn check_overrides_unlocked(
    directory: &VaultStorageDirectory,
    vault_id: &str,
    edits: &[crate::companion::overrides::change::Edit],
) -> Result<(), String> {
    let mut companion = FileCompanion::open(directory)?;
    let gate = authorize_with(&mut companion, vault_id, Operation::Write)?;
    if companion.has_values(vault_id)? {
        return Ok(());
    }
    crate::overrides::plan_without_values(&gate, edits, crate::overrides::Expect::Nothing).map(drop)
}

/// Plan `edits` against `vault_id`'s overrides, once they're as `expect`
/// says, and commit them in one journaled transaction, in the caller's lock
/// after the write gate.
pub(crate) fn change_overrides_unlocked(
    directory: &VaultStorageDirectory,
    vault_id: &str,
    edits: &[crate::companion::overrides::change::Edit],
    expect: crate::overrides::Expect<'_>,
) -> Result<crate::companion::overrides::change::ChangePlan, String> {
    let mut companion = FileCompanion::open(directory)?;
    let mut plan = plan_with(&mut companion, vault_id, edits, expect)?;
    commit_plan(&mut companion, vault_id, &mut plan)?;
    Ok(plan)
}

/// Write `environments` and carry `edits`, the environments the write
/// renames and removes, over to `vault_id`'s personal overrides, in the
/// caller's lock. The plan comes first, so a refusal leaves both as they
/// were; then one journal transaction replaces the values file, removes a
/// legacy one, and changes the records, as the journals of LPM CLI 0.82 and
/// later replay.
pub(crate) fn write_values_following_unlocked(
    directory: &VaultStorageDirectory,
    vault_id: &str,
    environments: &crate::EnvironmentMap,
    recording: &crate::history::scope::Recording,
    edits: &[crate::companion::overrides::change::Edit],
) -> Result<(), String> {
    let mut companion = FileCompanion::open(directory)?;
    let mut plan = plan_with(
        &mut companion,
        vault_id,
        edits,
        crate::overrides::Expect::Nothing,
    )?;
    if plan.mutations.is_empty() {
        drop(companion);
        return super::write_all_environments_unlocked(
            directory,
            vault_id,
            environments,
            recording,
        );
    }
    // History gets the values as they were, when its caller hasn't read
    // them, before the new ones are built; the plain text goes once it's
    // encrypted.
    crate::history::scope::observe_before(recording, || {
        super::read_environments_with_digest(directory, vault_id).map(|(before, _)| before)
    });
    let encrypted = {
        let json = crate::selected_environment::serialize(environments)?;
        zeroize::Zeroizing::new(
            super::encrypt_with_store_unlocked(
                directory,
                vault_id,
                &json,
                &super::KeyringNativeDataKeyStore,
            )?
            .into_bytes(),
        )
    };
    let mutations = std::mem::take(&mut plan.mutations);
    let mut changes = Vec::with_capacity(mutations.len() + 2);
    changes.push(FileChange::ReplaceValues(encrypted));
    if super::existing_legacy_vault_file_name(&companion.vaults, vault_id)?.is_some() {
        changes.push(FileChange::DeleteValues(ValuesFile::Legacy));
    }
    changes.extend(mutations.into_iter().map(FileChange::Companion));
    companion.commit_changes(vault_id, changes, true)?;
    crate::history::scope::committed(recording, std::borrow::Cow::Borrowed(environments));
    crate::companion::remember(vault_id, &plan.gate);
    Ok(())
}

fn plan_with(
    companion: &mut FileCompanion,
    vault_id: &str,
    edits: &[crate::companion::overrides::change::Edit],
    expect: crate::overrides::Expect<'_>,
) -> Result<crate::companion::overrides::change::ChangePlan, String> {
    let gate = authorize_with(companion, vault_id, Operation::Write)?;
    if !companion.has_values(vault_id)? {
        return crate::overrides::plan_without_values(&gate, edits, expect);
    }
    let record = read_overrides_record(companion, vault_id)?;
    crate::overrides::plan(
        vault_id,
        &gate,
        record.as_ref().map(|bytes| bytes.as_slice()),
        edits,
        expect,
        |need| {
            // Only creating the record counts every project's records.
            Ok(crate::companion::overrides::change::Inventory {
                project: companion.inventory_of(vault_id)?,
                service_records: match need {
                    InventoryNeed::Project => None,
                    InventoryNeed::ProjectAndService => Some(companion.record_count()?),
                },
            })
        },
    )
}

fn commit_plan(
    companion: &mut FileCompanion,
    vault_id: &str,
    plan: &mut crate::companion::overrides::change::ChangePlan,
) -> Result<(), String> {
    let mutations = std::mem::take(&mut plan.mutations);
    if !mutations.is_empty() {
        companion.commit(mutations)?;
        crate::companion::remember(vault_id, &plan.gate);
    }
    Ok(())
}

/// Delete `vault_id`'s values files and every companion record through the
/// deletion protocol. Its first transaction deletes the values with the
/// shared key and the single records, so no crash leaves values that run
/// without the records that change how they run.
pub(crate) fn delete_project_unlocked(
    directory: &VaultStorageDirectory,
    vault_id: &str,
) -> Result<(), String> {
    let gate = authorize_unlocked(directory, vault_id, Operation::Maintenance)?;
    let mut companion = FileCompanion::open(directory)?;
    let mut values = Vec::with_capacity(2);
    if companion
        .vaults
        .entry_exists(&ValuesFile::Digest.name(vault_id))?
    {
        values.push(ValuesFile::Digest);
    }
    if super::existing_legacy_vault_file_name(&companion.vaults, vault_id)?.is_some() {
        values.push(ValuesFile::Legacy);
    }
    let inventory = companion.inventory_of(vault_id)?;
    let found = FoundMarker::of(&gate);
    let plan =
        crate::companion::lifecycle::plan_deletion(vault_id, found, inventory, values.len())?;
    let mut transactions = plan.transactions.into_iter();
    let mut first: Vec<FileChange> = values.into_iter().map(FileChange::DeleteValues).collect();
    if let Some(transaction) = transactions.next() {
        first.extend(
            transaction
                .into_deletions(vault_id)?
                .into_iter()
                .map(FileChange::Companion),
        );
    }
    companion.commit_changes(vault_id, first, true)?;
    crate::companion::lifecycle::execute(
        &mut companion,
        Plan {
            vault_id: plan.vault_id,
            transactions: transactions.collect(),
            result: None,
        },
    )?;
    crate::companion::remember(vault_id, &ProjectGate::Plain);
    Ok(())
}

/// Review `vault_id`'s newer data on the file store. An interrupted change
/// recovery can't finish, a file LPM doesn't write and a marker that fails
/// authentication are each repaired only by discarding the newer data.
pub(crate) fn review_companion_data_unlocked(
    directory: &VaultStorageDirectory,
    vault_id: &str,
) -> Result<CompanionReview, String> {
    let mut companion = FileCompanion::open(directory)?;
    match companion.recover(vault_id) {
        Ok(()) => {}
        Err(RecoveryError::Stuck(reason)) => {
            return Ok(CompanionReview::discard(
                vault_id,
                Damage::Unfinished(reason).to_string(),
            ));
        }
        Err(RecoveryError::Failed(error)) => return Err(error),
    }
    let strays = companion.stray_entries(vault_id)?;
    if !strays.is_empty() {
        return Ok(CompanionReview::discard(
            vault_id,
            format!(
                "its folder holds files LPM doesn't write: {}",
                strays
                    .iter()
                    .map(|name| format!("{name:?}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        ));
    }
    // A marker that won't decrypt says nothing about what the project holds,
    // so only discarding everything repairs it. A record that won't decrypt
    // is judged by the review, which removes its feature alone.
    let marker = CompanionAccount::Marker {
        vault_id: vault_id.to_owned(),
    };
    if let Some(folder) = companion.folder(vault_id)? {
        let sealed = folder.read_owner_only_file_within(
            &entry_name(&marker),
            "companion entry",
            MAX_SEALED_ENTRY_BYTES,
        )?;
        let unreadable = match sealed {
            None => None,
            Some(Err(over)) => Some(over.describe("companion entry")),
            Some(Ok(sealed)) => open(&companion.data_key()?, &marker, sealed).err(),
        };
        if let Some(error) = unreadable {
            return Ok(CompanionReview::discard(vault_id, error));
        }
    }
    crate::companion::authorize(&mut companion, vault_id, Operation::Maintenance)?;
    crate::companion::repair::review(&mut companion, vault_id, None, None)
}

/// Run what `reviewed` lists on the file store, after checking `vault_id`
/// still shows exactly that.
pub(crate) fn repair_companion_data_unlocked(
    directory: &VaultStorageDirectory,
    vault_id: &str,
    reviewed: &CompanionReview,
) -> Result<Vec<CompanionRepair>, String> {
    if review_companion_data_unlocked(directory, vault_id)? != *reviewed {
        return Err(crate::companion::repair::CHANGED_SINCE_REVIEW.to_owned());
    }
    let mut companion = FileCompanion::open(directory)?;
    if reviewed.repairs() == [CompanionRepair::DiscardProject] {
        companion.discard_project(vault_id)?;
        return Ok(vec![CompanionRepair::DiscardProject]);
    }
    crate::companion::repair::repair(&mut companion, vault_id, None, None, reviewed)
}

/// The file store's records with commits that skip the invariant check, for
/// a discard of data that may not pass it: its plan is the engine's.
struct Discarding<'store, 'directory>(&'store mut FileCompanion<'directory>);

impl LifecycleStore for Discarding<'_, '_> {
    fn read(&mut self, account: &CompanionAccount) -> Result<Option<Vec<u8>>, String> {
        self.0.read(account)
    }

    fn commit(&mut self, mutations: Vec<Mutation>) -> Result<(), String> {
        let Some(vault_id) = mutations
            .first()
            .map(|mutation| mutation.account().vault_id().to_owned())
        else {
            return Ok(());
        };
        self.0.commit_changes(
            &vault_id,
            mutations.into_iter().map(FileChange::Companion).collect(),
            false,
        )
    }
}

impl FileCompanion<'_> {
    /// Names in `vault_id`'s folder that no account has.
    fn stray_entries(&self, vault_id: &str) -> Result<Vec<String>, String> {
        let Some(folder) = self.folder(vault_id)? else {
            return Ok(Vec::new());
        };
        Ok(folder
            .entry_names()?
            .into_iter()
            .filter(|name| parse_entry_name(vault_id, name).is_none())
            .collect())
    }

    /// Discard every companion record of `vault_id`, keeping its values:
    /// abandon an interrupted change that can't be finished, run the
    /// engine's discard, then remove files LPM doesn't write.
    fn discard_project(&mut self, vault_id: &str) -> Result<(), String> {
        self.vaults
            .remove_file(&journal_name(vault_id), "env file journal")?;
        self.remove_stage_folder(vault_id)?;
        let marker = match self.read(&CompanionAccount::Marker {
            vault_id: vault_id.to_owned(),
        }) {
            Ok(None) => None,
            Ok(Some(bytes)) => Some(crate::companion::marker::Marker::parse(vault_id, &bytes).ok()),
            // A marker that fails authentication is there, and invalid.
            Err(_) => Some(None),
        };
        let found = match &marker {
            None => FoundMarker::Absent,
            Some(None) => FoundMarker::Invalid,
            Some(Some(marker)) => FoundMarker::Valid(marker),
        };
        let inventory = self.listed_records(vault_id)?;
        let plan = crate::companion::lifecycle::plan_discard(vault_id, found, inventory)?;
        crate::companion::lifecycle::execute(&mut Discarding(self), plan)?;
        let strays = self.stray_entries(vault_id)?;
        if !strays.is_empty()
            && let Some(folder) = self.folder(vault_id)?
        {
            for name in &strays {
                folder.remove_file_unsynced(name, "a file LPM doesn't write")?;
            }
            folder.sync("companion records")?;
            drop(folder);
        }
        if let Some(folder) = self.folder(vault_id)?
            && folder.is_empty()?
        {
            drop(folder);
            self.vaults
                .remove_empty_directory(&companion_folder_name(vault_id), "a companion folder")?;
            self.vaults.sync("env files")?;
        }
        crate::companion::forget(vault_id);
        Ok(())
    }
}

/// Write `mutations` without the invariant check, as only damaged data
/// would be stored, for tests that read it.
#[cfg(any(test, feature = "acceptance-test-hooks"))]
pub(crate) fn commit_unchecked(
    directory: &VaultStorageDirectory,
    vault_id: &str,
    mutations: Vec<Mutation>,
) -> Result<(), String> {
    FileCompanion::open(directory)?.commit_changes(
        vault_id,
        mutations.into_iter().map(FileChange::Companion).collect(),
        false,
    )
}

/// Plant `state` for `vault_id` in the file store, past the gate and the
/// transaction check. Debug builds only.
#[cfg(debug_assertions)]
pub(crate) fn plant_debug_companion_state(
    directory: &VaultStorageDirectory,
    vault_id: &str,
    state: &crate::companion::debug_states::DebugCompanionState,
) -> Result<String, String> {
    let mut companion = FileCompanion::open(directory)?;
    let existing = companion.inventory_of(vault_id)?;
    let planting = crate::companion::debug_states::planting(vault_id, state, existing);
    if !planting.claims.is_empty() || planting.orphans.is_some() {
        return Err("only the macOS Keychain holds approval claims and orphans".to_owned());
    }
    companion.commit_changes(
        vault_id,
        planting
            .one_transaction()
            .into_iter()
            .map(FileChange::Companion)
            .collect(),
        false,
    )?;
    Ok(planting.description)
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

mod history;

pub(crate) use history::history_store;

#[cfg(test)]
mod tests;
