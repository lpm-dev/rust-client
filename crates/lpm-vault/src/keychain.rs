//! macOS Keychain integration shared with the native LPM Vault app.
//!
//! The signed CLI and app use the same Team-ID-scoped access group in the
//! Data Protection Keychain. Project discovery and sync metadata use the
//! current shared record contract, while vault payloads remain keyed by vault ID.

use std::collections::{HashMap, HashSet};

use lpm_common::stored_env::{
    is_canonical_registry_url, is_safe_vault_id, is_valid_environment_name, is_valid_org_slug,
};

use crate::companion::CompanionBackend as _;
use crate::companion::account::CompanionAccount;
use crate::companion::gate::{Operation, ProjectGate};
use crate::companion::graph::{AccessClass, record_access_class};
use crate::companion::marker::Marker;
use crate::macos_keychain::{
    ClaimedAccess, CliAccess, ProbeOutcome, delete as delete_keychain_password,
    read_string as try_read_keychain_password,
    with_keychain_transaction as with_raw_keychain_transaction,
    write_string as write_keychain_password,
};

mod companion_gate;

type SecretMap = HashMap<String, String>;
type EnvironmentMap = HashMap<String, SecretMap>;

#[cfg(test)]
thread_local! {
    static VAULT_PAYLOAD_PARSE_ATTEMPTS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static VAULT_PAYLOAD_PARSE_SUCCESSES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

const SERVICE: &str = "dev.lpm.vault";
const PROJECT_INDEX_MARKER_ACCOUNT: &str = "__vault_project_index_marker__";
const PROJECT_METADATA_PREFIX: &str = "__vault_project_metadata__:";
const PROJECT_DISCOVERY_PREFIX: &str = "__vault_project_discovery__:";
const PROJECT_INDEX_SCHEMA_VERSION: u8 = 3;
const PROJECT_DISCOVERY_SHARD_COUNT: usize = 1_024;
const MAX_PROJECT_DISCOVERY_SHARD_SIZE: usize = 128;
const MAX_VAULT_SIZE_WARNING: usize = 90 * 1024;
const TRANSACTION_MARKER_ACCOUNT: &str = "__vault_transaction_v3__";
const TRANSACTION_STAGE_PREFIX: &str = "__vault_transaction_stage_v3__:";
const TRANSACTION_SCHEMA_VERSION: u8 = 3;
const MAX_TRANSACTION_OPERATIONS: usize = 32;
const MAX_TRANSACTION_MARKER_BYTES: usize = 64 * 1024;
const MAX_TRANSACTION_VALUE_BYTES: usize = 100 * 1024;
const ORG_ASSOCIATIONS_ACCOUNT: &str = "__org_associations__";
const SYNC_METADATA_RECORD_PREFIX: &str = "__sync_metadata__:";
const SYNC_METADATA_SCHEMA_VERSION: u8 = 3;

fn service() -> String {
    lpm_common::credential_service(SERVICE)
}

#[derive(Debug, serde::Serialize, serde::Deserialize, Clone, PartialEq, Eq)]
pub struct IndexEntry {
    pub id: String,
    pub name: String,
    pub path: String,
}

#[derive(Debug, serde::Serialize, serde::Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProjectIndexMarker {
    schema_version: u8,
    storage_id: String,
    active_shards: Vec<usize>,
    writable_shard: Option<usize>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProjectMetadataRecord {
    schema_version: u8,
    storage_id: String,
    id: String,
    name: String,
    path: String,
    discovery_shard: usize,
    environment_summaries: Vec<ProjectEnvironmentSummary>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProjectEnvironmentSummary {
    name: String,
    key_count: usize,
}

mod validated_vault_payload {
    use super::ProjectEnvironmentSummary;

    #[derive(Clone)]
    pub(super) struct ValidatedVaultPayload {
        vault_id: String,
        encoded: String,
        environment_summaries: Vec<ProjectEnvironmentSummary>,
    }

    impl ValidatedVaultPayload {
        #[cfg(test)]
        pub(super) fn parse(vault_id: &str, encoded: &str) -> Result<Self, String> {
            super::validate_vault_id(vault_id)?;
            if encoded.len() > super::MAX_TRANSACTION_VALUE_BYTES {
                return Err("vault transaction value exceeds its size limit".to_owned());
            }
            let environment_summaries = super::project_environment_summaries(encoded)?;
            Ok(Self {
                vault_id: vault_id.to_owned(),
                encoded: encoded.to_owned(),
                environment_summaries,
            })
        }

        pub(super) fn from_serialized_environments(
            vault_id: &str,
            encoded: String,
            environments: &super::EnvironmentMap,
        ) -> Result<Self, String> {
            super::validate_vault_id(vault_id)?;
            if encoded.len() > super::MAX_TRANSACTION_VALUE_BYTES {
                return Err("vault transaction value exceeds its size limit".to_owned());
            }
            Ok(Self {
                vault_id: vault_id.to_owned(),
                encoded,
                environment_summaries: super::environment_summaries(environments),
            })
        }

        pub(super) fn vault_id(&self) -> &str {
            &self.vault_id
        }

        pub(super) fn encoded(&self) -> &str {
            &self.encoded
        }

        pub(super) fn environment_summaries(&self) -> &[ProjectEnvironmentSummary] {
            &self.environment_summaries
        }
    }
}

use validated_vault_payload::ValidatedVaultPayload;

#[derive(Debug, serde::Serialize, serde::Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProjectDiscoveryShard {
    schema_version: u8,
    storage_id: String,
    shard: usize,
    ids: Vec<String>,
}

struct ProjectIndexState {
    marker: ProjectIndexMarker,
}

struct ProjectMetadataSnapshot {
    record: ProjectMetadataRecord,
}

struct ProjectDiscoverySnapshot {
    envelope: ProjectDiscoveryShard,
}

#[derive(Clone)]
enum ProjectStorageMutation {
    Write { account: String, value: Vec<u8> },
    ValidatedVaultWrite(ValidatedVaultPayload),
    Delete { account: String },
}

impl ProjectStorageMutation {
    fn write(account: impl Into<String>, value: impl Into<Vec<u8>>) -> Self {
        Self::Write {
            account: account.into(),
            value: value.into(),
        }
    }

    fn validated_vault_write(payload: ValidatedVaultPayload) -> Self {
        Self::ValidatedVaultWrite(payload)
    }

    fn delete(account: impl Into<String>) -> Self {
        Self::Delete {
            account: account.into(),
        }
    }

    fn account(&self) -> &str {
        match self {
            Self::Write { account, .. } | Self::Delete { account } => account,
            Self::ValidatedVaultWrite(payload) => payload.vault_id(),
        }
    }

    fn value(&self) -> Option<&[u8]> {
        match self {
            Self::Write { value, .. } => Some(value),
            Self::ValidatedVaultWrite(payload) => Some(payload.encoded().as_bytes()),
            Self::Delete { .. } => None,
        }
    }
}

#[derive(Debug, serde::Serialize, serde::Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum TransactionState {
    Preparing,
    Committed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TransactionRecovery {
    None,
    DiscardedPreparing,
    RolledForwardCommitted,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TransactionJournal {
    schema_version: u8,
    transaction_id: String,
    state: TransactionState,
    operations: Vec<TransactionJournalOperation>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TransactionJournalOperation {
    action: String,
    target_account: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    staged_account: Option<String>,
    operation_sha256: String,
}

trait ProjectStorage {
    fn read(&mut self, account: &str) -> Result<Option<Vec<u8>>, String>;
    fn write(&mut self, account: &str, value: &[u8]) -> Result<(), String>;
    fn delete(&mut self, account: &str) -> Result<bool, String>;
    /// Every account name in the service, from attributes alone.
    fn account_names(&mut self) -> Result<Vec<String>, String>;
    /// An item's data with the CLI approval its attributes claim.
    fn read_with_access(
        &mut self,
        account: &str,
    ) -> Result<Option<(Vec<u8>, ClaimedAccess)>, String>;
    /// The CLI approval an item's attributes claim, without its data.
    fn claimed_access(&mut self, account: &str) -> Result<Option<ClaimedAccess>, String>;
    /// Whether an item demands user presence, learned without showing UI.
    fn probe(&mut self, account: &str, open_accounts: &[&str]) -> ProbeOutcome;
    /// Give an existing item CLI approval and confirm it by probing.
    fn require_approval(&mut self, account: &str, open_accounts: &[&str]) -> Result<(), String>;

    fn write_verified(&mut self, account: &str, value: &[u8]) -> Result<(), String> {
        self.write(account, value)?;
        if self.read(account)?.as_deref() != Some(value) {
            return Err(format!("vault transaction could not verify {account}"));
        }
        Ok(())
    }

    /// Write with the approval `source` claims.
    fn write_verified_with_access_from(
        &mut self,
        account: &str,
        value: &[u8],
        _source: &str,
    ) -> Result<(), String> {
        self.write_verified(account, value)
    }

    /// Write with `access` when the item is created.
    fn write_verified_with_access(
        &mut self,
        account: &str,
        value: &[u8],
        _access: CliAccess,
    ) -> Result<(), String> {
        self.write_verified(account, value)
    }
}

fn read_text(storage: &mut impl ProjectStorage, account: &str) -> Result<Option<String>, String> {
    storage
        .read(account)?
        .map(|bytes| String::from_utf8(bytes).map_err(|_| format!("{account} is not valid UTF-8")))
        .transpose()
}

fn with_keychain_transaction<T>(
    operation: impl FnOnce() -> Result<T, String>,
) -> Result<T, String> {
    with_raw_keychain_transaction(|| {
        recover_project_transaction_unlocked()?;
        operation()
    })
}

pub(crate) fn recover_project_transaction_unlocked() -> Result<(), String> {
    recover_project_transaction(&mut KeychainProjectStorage).map(|_| ())
}

struct KeychainProjectStorage;

impl ProjectStorage for KeychainProjectStorage {
    fn read(&mut self, account: &str) -> Result<Option<Vec<u8>>, String> {
        crate::macos_keychain::read_bytes(&service(), account)
    }

    fn write(&mut self, account: &str, value: &[u8]) -> Result<(), String> {
        crate::macos_keychain::write_bytes(&service(), account, value)
    }

    fn write_verified(&mut self, account: &str, value: &[u8]) -> Result<(), String> {
        crate::macos_keychain::write_bytes(&service(), account, value)
    }

    fn write_verified_with_access_from(
        &mut self,
        account: &str,
        value: &[u8],
        source: &str,
    ) -> Result<(), String> {
        if !carries_values_access(account) && !carries_values_access(source) {
            return crate::macos_keychain::write_bytes(&service(), account, value);
        }
        crate::macos_keychain::write_bytes_with_access_from(&service(), account, value, source)
    }

    fn write_verified_with_access(
        &mut self,
        account: &str,
        value: &[u8],
        access: CliAccess,
    ) -> Result<(), String> {
        crate::macos_keychain::write_bytes_with_access(&service(), account, value, access)
    }

    fn delete(&mut self, account: &str) -> Result<bool, String> {
        delete_keychain_password(&service(), account)
            .map(|outcome| outcome == crate::macos_keychain::KeychainDeleteOutcome::Deleted)
    }

    fn account_names(&mut self) -> Result<Vec<String>, String> {
        crate::macos_keychain::account_names(&service())
    }

    fn read_with_access(
        &mut self,
        account: &str,
    ) -> Result<Option<(Vec<u8>, ClaimedAccess)>, String> {
        crate::macos_keychain::read_bytes_with_access(&service(), account)
    }

    fn claimed_access(&mut self, account: &str) -> Result<Option<ClaimedAccess>, String> {
        crate::macos_keychain::claimed_access(&service(), account)
    }

    fn probe(&mut self, account: &str, open_accounts: &[&str]) -> ProbeOutcome {
        crate::macos_keychain::probe(&service(), account, open_accounts)
    }

    fn require_approval(&mut self, account: &str, open_accounts: &[&str]) -> Result<(), String> {
        crate::macos_keychain::require_approval(&service(), account, open_accounts)
    }
}

#[cfg(test)]
fn apply_project_transaction(
    storage: &mut impl ProjectStorage,
    mutations: Vec<ProjectStorageMutation>,
) -> Result<(), String> {
    recover_project_transaction(storage)?;
    apply_project_transaction_after_recovery(storage, mutations)
}

fn apply_project_transaction_after_recovery(
    storage: &mut impl ProjectStorage,
    mutations: Vec<ProjectStorageMutation>,
) -> Result<(), String> {
    if mutations.is_empty() {
        return Ok(());
    }
    if mutations.len() > MAX_TRANSACTION_OPERATIONS {
        return Err("vault transaction contains too many operations".to_owned());
    }
    let transaction_id = generate_project_storage_id();
    let mut targets = HashSet::with_capacity(mutations.len());
    let mut operations = Vec::with_capacity(mutations.len());
    for (index, mutation) in mutations.iter().enumerate() {
        if !targets.insert(mutation.account()) {
            return Err(format!(
                "vault transaction contains duplicate target {}",
                mutation.account()
            ));
        }
        match mutation {
            ProjectStorageMutation::Write { account, value } => {
                validate_transaction_target(account, Some(value))?;
                let staged_account = transaction_stage_account(&transaction_id, index);
                operations.push(TransactionJournalOperation {
                    action: "write".to_owned(),
                    target_account: account.clone(),
                    staged_account: Some(staged_account),
                    operation_sha256: transaction_operation_sha256("write", account, Some(value)),
                });
            }
            ProjectStorageMutation::ValidatedVaultWrite(payload) => {
                let staged_account = transaction_stage_account(&transaction_id, index);
                operations.push(TransactionJournalOperation {
                    action: "write".to_owned(),
                    target_account: payload.vault_id().to_owned(),
                    staged_account: Some(staged_account),
                    operation_sha256: transaction_operation_sha256(
                        "write",
                        payload.vault_id(),
                        Some(payload.encoded().as_bytes()),
                    ),
                });
            }
            ProjectStorageMutation::Delete { account } => {
                validate_transaction_target(account, None)?;
                operations.push(TransactionJournalOperation {
                    action: "delete".to_owned(),
                    target_account: account.clone(),
                    staged_account: None,
                    operation_sha256: transaction_operation_sha256("delete", account, None),
                });
            }
        }
    }
    let companion_changes: Vec<(&str, Option<&[u8]>)> = mutations
        .iter()
        .filter(|mutation| crate::companion::account::is_in_companion_namespace(mutation.account()))
        .map(|mutation| (mutation.account(), mutation.value()))
        .collect();
    if !companion_changes.is_empty() {
        check_companion_invariants(storage, &companion_changes, false)?;
    }

    let mut journal = TransactionJournal {
        schema_version: TRANSACTION_SCHEMA_VERSION,
        transaction_id,
        state: TransactionState::Preparing,
        operations,
    };
    let mut commit_was_verified = false;
    let result = (|| {
        write_journal(storage, &journal)?;
        let mut values_access = HashMap::new();
        for (mutation, operation) in mutations.iter().zip(&journal.operations) {
            if let Some(value) = mutation.value() {
                let staged_account = operation
                    .staged_account
                    .as_deref()
                    .ok_or_else(|| "vault transaction write stage is missing".to_owned())?;
                stage_write(
                    storage,
                    staged_account,
                    &operation.target_account,
                    value,
                    &mutations,
                    &mut values_access,
                )?;
            }
        }

        journal.state = TransactionState::Committed;
        write_journal(storage, &journal)?;
        commit_was_verified = true;
        roll_forward_prepared_project_transaction(storage, &journal, &mutations)
    })();

    if let Err(error) = result {
        return match recover_project_transaction(storage) {
            Ok(TransactionRecovery::RolledForwardCommitted) => Ok(()),
            Ok(TransactionRecovery::None)
                if commit_was_verified && transaction_is_fully_applied(storage, &journal)? =>
            {
                Ok(())
            }
            Ok(_) => Err(error),
            Err(recovery_error) => Err(format!(
                "{error}; vault transaction recovery failed: {recovery_error}"
            )),
        };
    }
    Ok(())
}

/// Whether `account` has the CLI approval of its project's values item: the
/// values item itself, and every companion record that follows values.
fn carries_values_access(account: &str) -> bool {
    validate_vault_id(account).is_ok()
        || CompanionAccount::parse(account).is_some_and(|parsed| follows_values(&parsed))
}

fn follows_values(account: &CompanionAccount) -> bool {
    match account {
        CompanionAccount::Marker { .. } => false,
        CompanionAccount::Record { kind, part, .. }
        | CompanionAccount::Staged { kind, part, .. } => {
            record_access_class(kind, *part) == AccessClass::FollowsValues
        }
    }
}

/// Write `target`'s stage. A values stage copies the values item's claimed
/// approval, as it always has. A companion record that follows values takes
/// the values item's approval as a probe verifies it, so a weak item
/// claiming approval can't pass a weaker one on.
fn stage_write(
    storage: &mut impl ProjectStorage,
    stage: &str,
    target: &str,
    value: &[u8],
    mutations: &[ProjectStorageMutation],
    values_access: &mut HashMap<String, CliAccess>,
) -> Result<(), String> {
    let companion = CompanionAccount::parse(target);
    if let Some(companion) = companion.as_ref().filter(|parsed| follows_values(parsed)) {
        let vault_id = companion.vault_id().to_owned();
        let access = match values_access.get(&vault_id) {
            Some(access) => *access,
            None => {
                let creates_values = mutations
                    .iter()
                    .any(|mutation| mutation.value().is_some() && mutation.account() == vault_id);
                let access = verified_values_access(storage, &vault_id, creates_values)?;
                values_access.insert(vault_id, access);
                access
            }
        };
        return storage.write_verified_with_access(stage, value, access);
    }
    storage.write_verified_with_access_from(stage, value, target)
}

/// The values item's CLI approval, verified by a probe rather than read
/// from its attributes.
fn verified_values_access(
    storage: &mut impl ProjectStorage,
    vault_id: &str,
    written_in_transaction: bool,
) -> Result<CliAccess, String> {
    let marker = crate::companion::account::marker_account(vault_id);
    match storage.probe(vault_id, &[PROJECT_INDEX_MARKER_ACCOUNT, &marker]) {
        // A weak item that claims approval passes approval on, not its weakness.
        ProbeOutcome::Automatic => match storage.claimed_access(vault_id)? {
            Some(ClaimedAccess::Automatic) | None => Ok(CliAccess::Automatic),
            Some(ClaimedAccess::RequireApproval | ClaimedAccess::Contradictory) => {
                Ok(CliAccess::RequireApproval)
            }
        },
        ProbeOutcome::Protected => Ok(CliAccess::RequireApproval),
        ProbeOutcome::Absent if written_in_transaction => Ok(CliAccess::Automatic),
        ProbeOutcome::Absent => Err(format!(
            "env project {vault_id} has no values, so its newer data can't be written"
        )),
        ProbeOutcome::Inconclusive => Err(
            "the macOS Keychain is unavailable, so env approval couldn't be confirmed; retry once the Mac is unlocked"
                .to_owned(),
        ),
    }
}

/// Check I1 and I5 for the companion records a transaction writes: each kind
/// is listed by the marker the transaction leaves. With `full`, also check
/// the project's other records against that marker, from a names-only
/// inventory: recovery does this, since it can't trust who wrote the journal.
fn check_companion_invariants(
    storage: &mut impl ProjectStorage,
    changes: &[(&str, Option<&[u8]>)],
    full: bool,
) -> Result<(), String> {
    let names = if full {
        Some(storage.account_names()?)
    } else {
        None
    };
    crate::companion::invariants::check_transaction(
        changes,
        |vault_id| storage.read(&crate::companion::account::marker_account(vault_id)),
        names.as_deref(),
    )
    .map_err(|refusal| refusal.describe("vault transaction"))
}

fn recover_project_transaction(
    storage: &mut impl ProjectStorage,
) -> Result<TransactionRecovery, String> {
    let Some(encoded) = storage.read(TRANSACTION_MARKER_ACCOUNT)? else {
        return Ok(TransactionRecovery::None);
    };
    if encoded.len() > MAX_TRANSACTION_MARKER_BYTES {
        return Err("vault transaction marker exceeds its size limit".to_owned());
    }
    let journal: TransactionJournal = serde_json::from_slice(&encoded)
        .map_err(|error| format!("vault transaction marker is not valid JSON: {error}"))?;
    validate_transaction_journal(&journal)?;
    match journal.state {
        TransactionState::Preparing => {
            discard_preparing_project_transaction(storage, &journal)?;
            Ok(TransactionRecovery::DiscardedPreparing)
        }
        TransactionState::Committed => {
            roll_forward_persisted_project_transaction(storage, &journal)?;
            Ok(TransactionRecovery::RolledForwardCommitted)
        }
    }
}

fn write_journal(
    storage: &mut impl ProjectStorage,
    journal: &TransactionJournal,
) -> Result<(), String> {
    let encoded = serde_json::to_vec(journal)
        .map_err(|error| format!("failed to serialize vault transaction marker: {error}"))?;
    if encoded.len() > MAX_TRANSACTION_MARKER_BYTES {
        return Err("vault transaction marker exceeds its size limit".to_owned());
    }
    write_verified(storage, TRANSACTION_MARKER_ACCOUNT, &encoded)
}

fn validate_transaction_journal(journal: &TransactionJournal) -> Result<(), String> {
    if journal.schema_version != TRANSACTION_SCHEMA_VERSION
        || !is_canonical_transaction_id(&journal.transaction_id)
        || journal.operations.is_empty()
        || journal.operations.len() > MAX_TRANSACTION_OPERATIONS
    {
        return Err("vault transaction marker is invalid".to_owned());
    }
    let mut targets = HashSet::with_capacity(journal.operations.len());
    for (index, operation) in journal.operations.iter().enumerate() {
        if !targets.insert(operation.target_account.as_str()) {
            return Err("vault transaction marker has duplicate targets".to_owned());
        }
        validate_transaction_target(&operation.target_account, None)?;
        match operation.action.as_str() {
            "write" => {
                let expected_stage = transaction_stage_account(&journal.transaction_id, index);
                if operation.staged_account.as_deref() != Some(expected_stage.as_str())
                    || !is_lower_hex_sha256(&operation.operation_sha256)
                {
                    return Err("vault transaction write operation is invalid".to_owned());
                }
            }
            "delete"
                if operation.staged_account.is_none()
                    && operation.operation_sha256
                        == transaction_operation_sha256(
                            "delete",
                            &operation.target_account,
                            None,
                        ) => {}
            _ => return Err("vault transaction operation is invalid".to_owned()),
        }
    }
    Ok(())
}

/// A `preparing` journal is discarded with whichever of its stages exist:
/// a crash can come before all of them are written, and the live records
/// were never touched, so no invariant applies.
fn discard_preparing_project_transaction(
    storage: &mut impl ProjectStorage,
    journal: &TransactionJournal,
) -> Result<(), String> {
    for operation in &journal.operations {
        if let Some(stage) = &operation.staged_account {
            delete_verified(storage, stage)?;
        }
    }
    delete_verified(storage, TRANSACTION_MARKER_ACCOUNT)
}

fn roll_forward_prepared_project_transaction(
    storage: &mut impl ProjectStorage,
    journal: &TransactionJournal,
    mutations: &[ProjectStorageMutation],
) -> Result<(), String> {
    if journal.operations.len() != mutations.len() {
        return Err("vault transaction mutation set changed after preparation".to_owned());
    }
    for (operation, mutation) in journal.operations.iter().zip(mutations) {
        if operation.target_account != mutation.account() {
            return Err("vault transaction mutation target changed after preparation".to_owned());
        }
        match (operation.action.as_str(), mutation.value()) {
            ("write", Some(value)) => {
                storage.write_verified_with_access_from(
                    &operation.target_account,
                    value,
                    operation
                        .staged_account
                        .as_deref()
                        .ok_or_else(|| "vault transaction stage is missing".to_owned())?,
                )?;
            }
            ("delete", None) => {
                delete_verified(storage, &operation.target_account)?;
            }
            _ => return Err("vault transaction mutation changed after preparation".to_owned()),
        }
    }
    finish_project_transaction(storage, journal)
}

/// Replay a `committed` journal. When it changes companion records, the
/// marker it leaves is checked against I1 and I5 first. A write whose stage
/// is gone already reached its target, since replay deletes stages only
/// after every target is written.
fn roll_forward_persisted_project_transaction(
    storage: &mut impl ProjectStorage,
    journal: &TransactionJournal,
) -> Result<(), String> {
    check_persisted_companion_invariants(storage, journal)?;
    for operation in &journal.operations {
        match operation.action.as_str() {
            "write" => {
                let stage = operation
                    .staged_account
                    .as_deref()
                    .ok_or_else(|| "vault transaction stage is missing".to_owned())?;
                if let Some(value) = read_validated_stage(storage, operation, stage)? {
                    storage.write_verified_with_access_from(
                        &operation.target_account,
                        &value,
                        stage,
                    )?;
                } else {
                    read_validated_applied_target(storage, operation)?;
                }
            }
            "delete" => {
                if transaction_operation_sha256("delete", &operation.target_account, None)
                    != operation.operation_sha256
                {
                    return Err("vault transaction delete operation is invalid".to_owned());
                }
                delete_verified(storage, &operation.target_account)?;
            }
            _ => return Err("vault transaction operation is invalid".to_owned()),
        }
    }
    finish_project_transaction(storage, journal)
}

fn read_validated_stage(
    storage: &mut impl ProjectStorage,
    operation: &TransactionJournalOperation,
    stage: &str,
) -> Result<Option<Vec<u8>>, String> {
    let Some(value) = storage.read(stage)? else {
        return Ok(None);
    };
    if value.len() > MAX_TRANSACTION_VALUE_BYTES
        || transaction_operation_sha256("write", &operation.target_account, Some(&value))
            != operation.operation_sha256
    {
        return Err("vault transaction stage is invalid".to_owned());
    }
    validate_transaction_target(&operation.target_account, Some(&value))?;
    Ok(Some(value))
}

fn read_validated_applied_target(
    storage: &mut impl ProjectStorage,
    operation: &TransactionJournalOperation,
) -> Result<Vec<u8>, String> {
    let target = storage
        .read(&operation.target_account)?
        .ok_or_else(|| "committed vault transaction lost both stage and target".to_owned())?;
    validate_transaction_target(&operation.target_account, Some(&target))?;
    if transaction_operation_sha256("write", &operation.target_account, Some(&target))
        != operation.operation_sha256
    {
        return Err("committed vault transaction target is invalid".to_owned());
    }
    Ok(target)
}

/// The invariant check needs only the marker each project is left with and
/// the names of the records written, so record bodies aren't held.
fn check_persisted_companion_invariants(
    storage: &mut impl ProjectStorage,
    journal: &TransactionJournal,
) -> Result<(), String> {
    let mut changes: Vec<(&str, Option<Vec<u8>>)> = Vec::new();
    for operation in &journal.operations {
        let account = operation.target_account.as_str();
        if !crate::companion::account::is_in_companion_namespace(account) {
            continue;
        }
        let value = match (operation.action.as_str(), &operation.staged_account) {
            ("write", Some(stage))
                if account.starts_with(crate::companion::account::MARKER_PREFIX) =>
            {
                Some(match read_validated_stage(storage, operation, stage)? {
                    Some(value) => value,
                    None => read_validated_applied_target(storage, operation)?,
                })
            }
            ("write", _) => Some(Vec::new()),
            _ => None,
        };
        changes.push((account, value));
    }
    if changes.is_empty() {
        return Ok(());
    }
    let changes: Vec<(&str, Option<&[u8]>)> = changes
        .iter()
        .map(|(account, value)| (*account, value.as_deref()))
        .collect();
    check_companion_invariants(storage, &changes, true)
}

fn finish_project_transaction(
    storage: &mut impl ProjectStorage,
    journal: &TransactionJournal,
) -> Result<(), String> {
    for operation in &journal.operations {
        if let Some(stage) = &operation.staged_account {
            delete_verified(storage, stage)?;
        }
    }
    delete_verified(storage, TRANSACTION_MARKER_ACCOUNT)
}

fn transaction_is_fully_applied(
    storage: &mut impl ProjectStorage,
    journal: &TransactionJournal,
) -> Result<bool, String> {
    if storage.read(TRANSACTION_MARKER_ACCOUNT)?.is_some() {
        return Ok(false);
    }
    for operation in &journal.operations {
        if let Some(stage) = &operation.staged_account
            && storage.read(stage)?.is_some()
        {
            return Ok(false);
        }
        match operation.action.as_str() {
            "write" => {
                let Some(target) = storage.read(&operation.target_account)? else {
                    return Ok(false);
                };
                if transaction_operation_sha256("write", &operation.target_account, Some(&target))
                    != operation.operation_sha256
                {
                    return Ok(false);
                }
            }
            "delete" => {
                if storage.read(&operation.target_account)?.is_some() {
                    return Ok(false);
                }
            }
            _ => return Ok(false),
        }
    }
    Ok(true)
}

fn write_verified(
    storage: &mut impl ProjectStorage,
    account: &str,
    value: &[u8],
) -> Result<(), String> {
    storage.write_verified(account, value)
}

fn delete_verified(storage: &mut impl ProjectStorage, account: &str) -> Result<(), String> {
    storage.delete(account)?;
    if storage.read(account)?.is_some() {
        return Err(format!("vault transaction could not delete {account}"));
    }
    Ok(())
}

fn validate_transaction_target(account: &str, value: Option<&[u8]>) -> Result<(), String> {
    if account.len() > 512
        || account == TRANSACTION_MARKER_ACCOUNT
        || account.starts_with(TRANSACTION_STAGE_PREFIX)
    {
        return Err("vault transaction target account is invalid".to_owned());
    }
    if let Some(value) = value
        && value.len() > MAX_TRANSACTION_VALUE_BYTES
    {
        return Err("vault transaction value exceeds its size limit".to_owned());
    }
    if crate::companion::account::is_in_companion_namespace(account) {
        let parsed = CompanionAccount::parse(account)
            .ok_or_else(|| "vault transaction companion account is invalid".to_owned())?;
        if let (CompanionAccount::Marker { vault_id }, Some(value)) = (&parsed, value) {
            Marker::parse(vault_id, value)
                .map_err(|error| format!("vault transaction feature marker is invalid: {error}"))?;
        }
        return Ok(());
    }
    let value = value
        .map(|value| {
            std::str::from_utf8(value)
                .map_err(|_| "vault transaction value is not valid UTF-8".to_owned())
        })
        .transpose()?;
    if validate_vault_id(account).is_ok() {
        if let Some(value) = value {
            parse_vault_environments(value)
                .map_err(|error| format!("vault transaction payload is invalid: {error}"))?;
        }
        return Ok(());
    }
    if account == PROJECT_INDEX_MARKER_ACCOUNT {
        if let Some(value) = value {
            decode_project_index_marker(value.to_owned())?;
        }
        return Ok(());
    }
    if account.starts_with(PROJECT_METADATA_PREFIX) {
        return validate_transaction_project_metadata(account, value);
    }
    if account.starts_with(PROJECT_DISCOVERY_PREFIX) {
        return validate_transaction_project_discovery(account, value);
    }
    if account == ORG_ASSOCIATIONS_ACCOUNT {
        if let Some(value) = value {
            let associations: HashMap<String, String> = serde_json::from_str(value)
                .map_err(|_| "vault organization associations are invalid".to_owned())?;
            if associations.iter().any(|(vault_id, slug)| {
                validate_vault_id(vault_id).is_err() || !is_valid_org_slug(slug)
            }) {
                return Err("vault organization associations are invalid".to_owned());
            }
        }
        return Ok(());
    }
    if account.starts_with(SYNC_METADATA_RECORD_PREFIX) {
        return validate_transaction_sync_metadata(account, value);
    }
    Err("vault transaction target account is not permitted".to_owned())
}

fn validate_transaction_project_metadata(account: &str, value: Option<&str>) -> Result<(), String> {
    let suffix = account
        .strip_prefix(PROJECT_METADATA_PREFIX)
        .ok_or_else(|| "vault project metadata account is invalid".to_owned())?;
    let (storage_id, encoded_id) = suffix
        .split_once(':')
        .ok_or_else(|| "vault project metadata account is invalid".to_owned())?;
    if !is_valid_project_storage_id(storage_id) {
        return Err("vault project metadata account is invalid".to_owned());
    }
    let decoded_id = decode_account_vault_id(encoded_id)?;
    if let Some(value) = value {
        let record: ProjectMetadataRecord = serde_json::from_str(value)
            .map_err(|_| "vault project metadata is invalid".to_owned())?;
        if record.schema_version != PROJECT_INDEX_SCHEMA_VERSION
            || record.storage_id != storage_id
            || record.id != decoded_id
            || record.discovery_shard >= PROJECT_DISCOVERY_SHARD_COUNT
            || !are_valid_environment_summaries(&record.environment_summaries)
            || account != project_metadata_account(storage_id, &record.id)
        {
            return Err("vault project metadata is invalid".to_owned());
        }
    }
    Ok(())
}

fn validate_transaction_project_discovery(
    account: &str,
    value: Option<&str>,
) -> Result<(), String> {
    let suffix = account
        .strip_prefix(PROJECT_DISCOVERY_PREFIX)
        .ok_or_else(|| "vault project discovery account is invalid".to_owned())?;
    let (storage_id, encoded_shard) = suffix
        .split_once(':')
        .ok_or_else(|| "vault project discovery account is invalid".to_owned())?;
    let shard = usize::from_str_radix(encoded_shard, 16)
        .map_err(|_| "vault project discovery account is invalid".to_owned())?;
    if !is_valid_project_storage_id(storage_id)
        || encoded_shard.len() != 3
        || shard >= PROJECT_DISCOVERY_SHARD_COUNT
    {
        return Err("vault project discovery account is invalid".to_owned());
    }
    if let Some(value) = value {
        let envelope: ProjectDiscoveryShard = serde_json::from_str(value)
            .map_err(|_| "vault project discovery is invalid".to_owned())?;
        if envelope.schema_version != PROJECT_INDEX_SCHEMA_VERSION
            || envelope.storage_id != storage_id
            || envelope.shard != shard
            || envelope.ids.len() > MAX_PROJECT_DISCOVERY_SHARD_SIZE
            || !envelope.ids.windows(2).all(|window| window[0] < window[1])
            || envelope
                .ids
                .iter()
                .any(|vault_id| validate_vault_id(vault_id).is_err())
            || account != project_discovery_account(storage_id, shard)
        {
            return Err("vault project discovery is invalid".to_owned());
        }
    }
    Ok(())
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SyncMetadataRecord {
    schema_version: u8,
    vault_id: String,
    metadata: CurrentSyncMetadata,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CurrentSyncMetadata {
    last_synced_at: Option<f64>,
    last_action: Option<String>,
    last_version: Option<i64>,
    #[serde(rename = "isDirty")]
    _is_dirty: bool,
    binding: Option<CurrentSyncBinding>,
    checkpoints: Vec<CurrentSyncCheckpoint>,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CurrentSyncCheckpoint {
    binding: CurrentSyncBinding,
    last_synced_at: f64,
    last_action: String,
    last_version: i64,
}

#[derive(Clone, PartialEq, Eq, Hash, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CurrentSyncBinding {
    #[serde(rename = "registryURL")]
    registry_url: String,
    #[serde(rename = "principalID")]
    principal_id: String,
    scope: String,
}

fn validate_transaction_sync_metadata(account: &str, value: Option<&str>) -> Result<(), String> {
    let encoded_id = account
        .strip_prefix(SYNC_METADATA_RECORD_PREFIX)
        .ok_or_else(|| "vault sync metadata account is invalid".to_owned())?;
    let vault_id = decode_account_vault_id(encoded_id)?;
    let canonical_account = format!(
        "{SYNC_METADATA_RECORD_PREFIX}{}",
        base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            vault_id.as_bytes()
        )
    );
    if account != canonical_account {
        return Err("vault sync metadata account is invalid".to_owned());
    }
    if let Some(value) = value {
        let record: SyncMetadataRecord = serde_json::from_str(value)
            .map_err(|_| "vault sync metadata record is invalid".to_owned())?;
        if record.schema_version != SYNC_METADATA_SCHEMA_VERSION
            || record.vault_id != vault_id
            || !is_valid_current_sync_metadata(&record.metadata)
        {
            return Err("vault sync metadata record is invalid".to_owned());
        }
    }
    Ok(())
}

fn is_valid_current_sync_metadata(metadata: &CurrentSyncMetadata) -> bool {
    if metadata.checkpoints.len() > 64 {
        return false;
    }
    let mut bindings = HashSet::with_capacity(metadata.checkpoints.len());
    let mut authorities = HashSet::with_capacity(metadata.checkpoints.len());
    for checkpoint in &metadata.checkpoints {
        if !is_valid_current_sync_binding(&checkpoint.binding)
            || !checkpoint.last_synced_at.is_finite()
            || !matches!(checkpoint.last_action.as_str(), "push" | "pull")
            || !(1..=i64::from(i32::MAX)).contains(&checkpoint.last_version)
            || !bindings.insert(checkpoint.binding.clone())
            || !authorities.insert((
                checkpoint.binding.registry_url.as_str(),
                checkpoint.binding.scope.as_str(),
            ))
        {
            return false;
        }
    }
    if metadata.checkpoints.is_empty() {
        return metadata.last_synced_at.is_none()
            && metadata.last_action.is_none()
            && metadata.last_version.is_none()
            && metadata.binding.is_none();
    }
    let (Some(last_synced_at), Some(last_action), Some(last_version), Some(binding)) = (
        metadata.last_synced_at,
        metadata.last_action.as_deref(),
        metadata.last_version,
        metadata.binding.as_ref(),
    ) else {
        return false;
    };
    if !last_synced_at.is_finite()
        || !matches!(last_action, "push" | "pull")
        || !(1..=i64::from(i32::MAX)).contains(&last_version)
        || !is_valid_current_sync_binding(binding)
    {
        return false;
    }
    metadata.checkpoints.iter().any(|checkpoint| {
        checkpoint.binding == *binding
            && checkpoint.last_synced_at == last_synced_at
            && checkpoint.last_action == last_action
            && checkpoint.last_version == last_version
    })
}

fn is_valid_current_sync_binding(binding: &CurrentSyncBinding) -> bool {
    matches!(binding.scope.as_str(), "personal" | "organization")
        && !binding.principal_id.is_empty()
        && binding.principal_id.len() <= 256
        && !binding.principal_id.chars().any(char::is_control)
        && is_canonical_registry_url(&binding.registry_url)
}

fn decode_account_vault_id(encoded: &str) -> Result<String, String> {
    use base64::Engine as _;

    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| "vault transaction account encoding is invalid".to_owned())?;
    let vault_id = String::from_utf8(bytes)
        .map_err(|_| "vault transaction account encoding is invalid".to_owned())?;
    validate_vault_id(&vault_id)?;
    Ok(vault_id)
}

fn transaction_stage_account(transaction_id: &str, index: usize) -> String {
    format!("{TRANSACTION_STAGE_PREFIX}{transaction_id}:{index}")
}

fn transaction_operation_sha256(
    action: &str,
    target_account: &str,
    value: Option<&[u8]>,
) -> String {
    use sha2::Digest as _;

    let mut hasher = sha2::Sha256::new();
    hasher.update(b"lpm-vault-transaction-operation\0");
    hasher.update(action.as_bytes());
    hasher.update([0]);
    hasher.update(target_account.as_bytes());
    hasher.update([0]);
    if let Some(value) = value {
        hasher.update(value);
    }
    hex::encode(hasher.finalize())
}

fn is_lower_hex_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_canonical_transaction_id(value: &str) -> bool {
    is_valid_project_storage_id(value) && value.bytes().all(|byte| !byte.is_ascii_uppercase())
}

#[cfg(test)]
#[derive(serde::Serialize, serde::Deserialize)]
struct EnvironmentsWrapper {
    environments: EnvironmentMap,
}

pub fn try_read_vault(vault_id: &str) -> Result<Option<SecretMap>, String> {
    try_read_vault_env(vault_id, "default")
}

pub fn try_read_vault_env(vault_id: &str, env: &str) -> Result<Option<SecretMap>, String> {
    with_keychain_transaction(|| try_read_vault_env_unlocked(vault_id, env))
}

fn try_read_vault_env_unlocked(vault_id: &str, env: &str) -> Result<Option<SecretMap>, String> {
    try_read_vault_env_unlocked_with_fallback(vault_id, env, false)
}

pub(crate) fn try_read_vault_env_with_default_fallback(
    vault_id: &str,
    env: &str,
) -> Result<Option<SecretMap>, String> {
    with_keychain_transaction(|| try_read_vault_env_unlocked_with_fallback(vault_id, env, true))
}

fn try_read_vault_env_unlocked_with_fallback(
    vault_id: &str,
    env: &str,
    default_fallback: bool,
) -> Result<Option<SecretMap>, String> {
    companion_gate::authorize(
        &mut KeychainProjectStorage,
        vault_id,
        Operation::ReadExcludingOverrides,
    )?;
    let Some(json) = try_read_keychain_password(&service(), vault_id)? else {
        return Ok(None);
    };

    let parsed = if default_fallback {
        crate::selected_environment::parse_with_default_fallback(&json, env)
    } else {
        crate::selected_environment::parse(&json, env)
    };
    parsed
        .map(crate::selected_environment::SelectedVaultPayload::into_selected)
        .map_err(|error| format!("vault keychain data is not valid JSON: {error}"))
}

#[cfg(test)]
fn take_environment(mut environments: EnvironmentMap, env: &str) -> Option<SecretMap> {
    environments.remove(env)
}

pub fn try_read_all_environments(vault_id: &str) -> Result<Option<EnvironmentMap>, String> {
    with_keychain_transaction(|| try_read_all_environments_unlocked(vault_id))
}

pub(crate) fn try_read_all_environments_unlocked(
    vault_id: &str,
) -> Result<Option<EnvironmentMap>, String> {
    try_read_all_environments_with_digest_unlocked(vault_id).map(|(environments, _)| environments)
}

pub(crate) fn try_read_all_environments_with_digest_unlocked(
    vault_id: &str,
) -> Result<(Option<EnvironmentMap>, Option<[u8; 32]>), String> {
    use sha2::Digest as _;

    companion_gate::authorize(
        &mut KeychainProjectStorage,
        vault_id,
        Operation::ReadExcludingOverrides,
    )?;
    let Some(json) = try_read_keychain_password(&service(), vault_id)? else {
        return Ok((None, None));
    };
    let digest = sha2::Sha256::digest(json.as_bytes()).into();

    let environments = crate::selected_environment::parse_all(&json)
        .map_err(|error| format!("vault keychain data is not valid JSON: {error}"))?;
    Ok((Some(environments), Some(digest)))
}

pub(crate) fn vault_payload_digest_unlocked(vault_id: &str) -> Result<Option<[u8; 32]>, String> {
    use sha2::Digest as _;

    companion_gate::authorize(
        &mut KeychainProjectStorage,
        vault_id,
        Operation::ReadExcludingOverrides,
    )?;
    try_read_keychain_password(&service(), vault_id)
        .map(|json| json.map(|json| sha2::Sha256::digest(json.as_bytes()).into()))
}

pub fn write_vault(
    vault_id: &str,
    project_name: &str,
    project_path: &str,
    secrets: &SecretMap,
) -> Result<(), String> {
    write_vault_env(vault_id, project_name, project_path, "default", secrets)
}

pub fn write_all_environments(
    vault_id: &str,
    project_name: &str,
    project_path: &str,
    environments: &EnvironmentMap,
) -> Result<(), String> {
    with_keychain_transaction(|| {
        write_all_environments_unlocked(vault_id, project_name, project_path, environments)
    })
}

pub(crate) fn write_all_environments_unlocked(
    vault_id: &str,
    project_name: &str,
    project_path: &str,
    environments: &EnvironmentMap,
) -> Result<(), String> {
    write_all_environments_with_storage_after_recovery(
        &mut KeychainProjectStorage,
        vault_id,
        project_name,
        project_path,
        environments,
    )
}

pub fn write_vault_env(
    vault_id: &str,
    project_name: &str,
    project_path: &str,
    env: &str,
    secrets: &SecretMap,
) -> Result<(), String> {
    with_keychain_transaction(|| {
        let mut environments = try_read_all_environments_unlocked(vault_id)?.unwrap_or_default();
        environments.insert(env.to_owned(), secrets.clone());

        write_all_environments_with_storage_after_recovery(
            &mut KeychainProjectStorage,
            vault_id,
            project_name,
            project_path,
            &environments,
        )
    })
}

pub(crate) fn mutate_vault_env<T>(
    vault_id: &str,
    project_name: &str,
    project_path: &str,
    env: &str,
    operation: impl FnOnce(&mut SecretMap) -> T,
) -> Result<T, String> {
    crate::storage_transaction::with_vault_transaction(|directory| {
        recover_project_transaction(&mut KeychainProjectStorage)?;
        let mut environments = match try_read_all_environments_unlocked(vault_id)? {
            Some(environments) => environments,
            None => crate::fallback::read_all_environments_unlocked(directory, vault_id)?
                .unwrap_or_default(),
        };
        let result = operation(environments.entry(env.to_owned()).or_default());
        write_all_environments_with_storage_after_recovery(
            &mut KeychainProjectStorage,
            vault_id,
            project_name,
            project_path,
            &environments,
        )?;
        Ok(result)
    })
}

fn warn_if_large(size: usize) {
    if let Some(warning) = large_env_warning(size) {
        tracing::warn!("{warning}");
    }
}

fn large_env_warning(size: usize) -> Option<String> {
    (size > MAX_VAULT_SIZE_WARNING).then(|| {
        format!(
            "env data is {} (approaching the Keychain's ~100 KiB limit)",
            lpm_common::format_bytes(size as u64)
        )
    })
}

fn write_all_environments_with_storage_after_recovery(
    storage: &mut impl ProjectStorage,
    vault_id: &str,
    project_name: &str,
    project_path: &str,
    environments: &EnvironmentMap,
) -> Result<(), String> {
    let encoded = crate::selected_environment::serialize(environments)?;
    warn_if_large(encoded.len());
    let payload =
        ValidatedVaultPayload::from_serialized_environments(vault_id, encoded, environments)?;
    save_validated_vault_data_with_storage_after_recovery(
        storage,
        project_name,
        project_path,
        payload,
    )
}

#[cfg(test)]
fn save_vault_data_with_storage(
    storage: &mut impl ProjectStorage,
    vault_id: &str,
    project_name: &str,
    project_path: &str,
    data: &str,
) -> Result<(), String> {
    recover_project_transaction(storage)?;
    save_vault_data_with_storage_after_recovery(storage, vault_id, project_name, project_path, data)
}

#[cfg(test)]
fn save_vault_data_with_storage_after_recovery(
    storage: &mut impl ProjectStorage,
    vault_id: &str,
    project_name: &str,
    project_path: &str,
    data: &str,
) -> Result<(), String> {
    let payload = ValidatedVaultPayload::parse(vault_id, data)?;
    save_validated_vault_data_with_storage_after_recovery(
        storage,
        project_name,
        project_path,
        payload,
    )
}

fn save_validated_vault_data_with_storage_after_recovery(
    storage: &mut impl ProjectStorage,
    project_name: &str,
    project_path: &str,
    payload: ValidatedVaultPayload,
) -> Result<(), String> {
    let vault_id = payload.vault_id().to_owned();
    companion_gate::authorize(storage, &vault_id, Operation::Write)?;
    let state = ensure_project_index_after_recovery(storage)?;
    if let Some(mut metadata) = read_project_metadata(storage, &vault_id, &state)? {
        if metadata.record.environment_summaries == payload.environment_summaries() {
            return apply_project_transaction_after_recovery(
                storage,
                vec![ProjectStorageMutation::validated_vault_write(payload)],
            );
        }
        storage
            .read(&vault_id)?
            .ok_or_else(|| format!("indexed vault payload {vault_id} is missing"))?;
        metadata.record.environment_summaries = payload.environment_summaries().to_vec();
        let metadata_data = serde_json::to_string(&metadata.record)
            .map_err(|error| format!("failed to serialize vault project metadata: {error}"))?;
        let metadata_account = project_metadata_account(&state.marker.storage_id, &vault_id);
        return apply_project_transaction_after_recovery(
            storage,
            vec![
                ProjectStorageMutation::validated_vault_write(payload),
                ProjectStorageMutation::write(metadata_account, metadata_data),
            ],
        );
    }
    create_project_records(storage, project_name, project_path, payload, state)
}

pub fn delete_vault(vault_id: &str) -> Result<(), String> {
    with_keychain_transaction(|| delete_vault_unlocked(vault_id))
}

fn delete_vault_unlocked(vault_id: &str) -> Result<(), String> {
    delete_vault_with_storage_after_recovery(&mut KeychainProjectStorage, vault_id)
}

pub fn list_vaults() -> Result<Vec<IndexEntry>, String> {
    with_keychain_transaction(|| {
        list_vaults_with_storage_after_recovery(&mut KeychainProjectStorage)
    })
}

/// The selected environment's values and personal overrides, read together
/// inside one lock on this thread, so one approval covers both. With
/// `default_fallback`, an environment without values of its own reads
/// `default`'s values; its overrides are always its own.
pub(crate) fn read_for_run_unlocked(
    vault_id: &str,
    env: &str,
    default_fallback: bool,
) -> Result<(Option<SecretMap>, crate::PersonalOverrides), String> {
    let read = companion_gate::read_for_run(&mut KeychainProjectStorage, vault_id)?;
    let overrides = crate::companion::overrides::evaluate(
        &read.gate,
        vault_id,
        env,
        read.overrides_record.as_deref(),
    )
    .map_err(crate::companion::damaged)?;
    let Some(bytes) = read.values else {
        return Ok((None, overrides));
    };
    let json = String::from_utf8(bytes)
        .map_err(|_| "vault keychain data is not valid UTF-8".to_owned())?;
    let parsed = if default_fallback {
        crate::selected_environment::parse_with_default_fallback(&json, env)
    } else {
        crate::selected_environment::parse(&json, env)
    };
    let values = parsed
        .map(crate::selected_environment::SelectedVaultPayload::into_selected)
        .map_err(|error| format!("vault keychain data is not valid JSON: {error}"))?;
    Ok((values, overrides))
}

/// Every environment's values and personal overrides, read together inside
/// one lock on this thread.
pub(crate) fn read_all_for_run_unlocked(
    vault_id: &str,
) -> Result<
    (
        Option<EnvironmentMap>,
        std::collections::BTreeMap<String, crate::PersonalOverrides>,
    ),
    String,
> {
    let read = companion_gate::read_for_run(&mut KeychainProjectStorage, vault_id)?;
    let overrides = crate::companion::overrides::evaluate_all(
        &read.gate,
        vault_id,
        read.overrides_record.as_deref(),
    )
    .map_err(crate::companion::damaged)?;
    let values = read
        .values
        .map(|bytes| {
            let json = String::from_utf8(bytes)
                .map_err(|_| "vault keychain data is not valid UTF-8".to_owned())?;
            crate::selected_environment::parse_all(&json)
                .map_err(|error| format!("vault keychain data is not valid JSON: {error}"))
        })
        .transpose()?;
    Ok((values, overrides))
}

/// Authorize `operation` on `vault_id` against its Keychain feature marker,
/// finishing any interrupted lifecycle step first.
pub(crate) fn authorize_unlocked(vault_id: &str, operation: Operation) -> Result<(), String> {
    companion_gate::authorize(&mut KeychainProjectStorage, vault_id, operation).map(|_| ())
}

fn try_read_x25519_private_key_for_account_unlocked(
    account: &str,
) -> Result<Option<[u8; 32]>, String> {
    let Some(encoded) = try_read_keychain_password(&service(), account)? else {
        return Ok(None);
    };
    decode_x25519_private_key(&encoded).map(Some)
}

pub(crate) fn try_read_x25519_private_key_for_account(
    account: &str,
) -> Result<Option<[u8; 32]>, String> {
    with_keychain_transaction(|| try_read_x25519_private_key_for_account_unlocked(account))
}

pub(crate) fn write_x25519_private_key_for_account(
    account: &str,
    private_key: &[u8; 32],
) -> Result<(), String> {
    with_keychain_transaction(|| {
        write_x25519_private_key_for_account_unlocked(account, private_key)
    })
}

fn write_x25519_private_key_for_account_unlocked(
    account: &str,
    private_key: &[u8; 32],
) -> Result<(), String> {
    let encoded = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, private_key);
    write_keychain_password(&service(), account, &encoded)
}

pub(crate) fn get_or_create_x25519_keypair_for_account(
    account: &str,
) -> Result<([u8; 32], [u8; 32]), String> {
    with_keychain_transaction(|| {
        if let Some(private) = try_read_x25519_private_key_for_account_unlocked(account)? {
            let public = crate::crypto::x25519_public_from_private(&private);
            return Ok((private, public));
        }

        let (candidate, _) = crate::crypto::generate_x25519_keypair();
        let encoded = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, candidate);
        let stored = crate::macos_keychain::get_or_insert_string(&service(), account, &encoded)?;
        let private = decode_x25519_private_key(&stored)?;
        let public = crate::crypto::x25519_public_from_private(&private);
        Ok((private, public))
    })
}

pub(crate) fn promote_x25519_private_key_accounts(
    pending_account: &str,
    live_account: &str,
) -> Result<(), String> {
    with_keychain_transaction(|| {
        promote_x25519_private_key_accounts_with_storage(
            &mut KeychainProjectStorage,
            pending_account,
            live_account,
        )
    })
}

fn promote_x25519_private_key_accounts_with_storage(
    storage: &mut impl ProjectStorage,
    pending_account: &str,
    live_account: &str,
) -> Result<(), String> {
    let encoded = read_text(storage, pending_account)?
        .ok_or_else(|| "no pending key to promote".to_owned())?;
    decode_x25519_private_key(&encoded)?;
    storage.write_verified(live_account, encoded.as_bytes())?;
    storage.delete(pending_account).map(|_| ())
}

pub(crate) fn delete_x25519_private_key_for_account(account: &str) -> Result<(), String> {
    with_keychain_transaction(|| delete_keychain_password(&service(), account).map(|_| ()))
}

fn decode_x25519_private_key(encoded: &str) -> Result<[u8; 32], String> {
    let bytes = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        encoded.as_bytes(),
    )
    .map_err(|_| "vault X25519 key is not valid base64".to_owned())?;
    bytes
        .try_into()
        .map_err(|_| "vault X25519 key must contain exactly 32 bytes".to_owned())
}

#[cfg(test)]
fn list_vaults_with_storage(storage: &mut impl ProjectStorage) -> Result<Vec<IndexEntry>, String> {
    recover_project_transaction(storage)?;
    list_vaults_with_storage_after_recovery(storage)
}

fn list_vaults_with_storage_after_recovery(
    storage: &mut impl ProjectStorage,
) -> Result<Vec<IndexEntry>, String> {
    let state = ensure_project_index_after_recovery(storage)?;
    let mut ids_by_shard = HashMap::new();
    for shard in &state.marker.active_shards {
        let snapshot = read_project_discovery(storage, *shard, &state)?
            .ok_or_else(|| format!("active vault project discovery shard {shard} is missing"))?;
        for vault_id in snapshot.envelope.ids {
            if ids_by_shard.insert(vault_id.clone(), *shard).is_some() {
                return Err(format!(
                    "vault project {vault_id} appears in multiple discovery shards"
                ));
            }
        }
    }

    let mut vault_ids: Vec<_> = ids_by_shard.keys().cloned().collect();
    vault_ids.sort_unstable();
    let mut entries = Vec::with_capacity(vault_ids.len());
    for vault_id in vault_ids {
        let metadata = read_project_metadata(storage, &vault_id, &state)?
            .ok_or_else(|| format!("vault project metadata for {vault_id} is missing"))?;
        if ids_by_shard.get(&vault_id) != Some(&metadata.record.discovery_shard) {
            return Err(format!(
                "vault project metadata for {vault_id} does not match discovery"
            ));
        }
        entries.push(IndexEntry {
            id: metadata.record.id,
            name: metadata.record.name,
            path: metadata.record.path,
        });
    }
    Ok(entries)
}

fn ensure_project_index_after_recovery(
    storage: &mut impl ProjectStorage,
) -> Result<ProjectIndexState, String> {
    if let Some(data) = read_text(storage, PROJECT_INDEX_MARKER_ACCOUNT)? {
        return decode_project_index_marker(data);
    }
    let marker = ProjectIndexMarker {
        schema_version: PROJECT_INDEX_SCHEMA_VERSION,
        storage_id: generate_project_storage_id(),
        active_shards: Vec::new(),
        writable_shard: None,
    };
    let marker_data = serde_json::to_string(&marker)
        .map_err(|error| format!("failed to serialize vault project-index marker: {error}"))?;
    apply_project_transaction_after_recovery(
        storage,
        vec![ProjectStorageMutation::write(
            PROJECT_INDEX_MARKER_ACCOUNT,
            marker_data,
        )],
    )?;
    Ok(ProjectIndexState { marker })
}

fn decode_project_index_marker(data: String) -> Result<ProjectIndexState, String> {
    let marker: ProjectIndexMarker = serde_json::from_str(&data)
        .map_err(|error| format!("vault project-index marker is not valid JSON: {error}"))?;
    let valid_shards = marker.active_shards.len() <= PROJECT_DISCOVERY_SHARD_COUNT
        && marker
            .active_shards
            .windows(2)
            .all(|window| window[0] < window[1])
        && marker
            .active_shards
            .iter()
            .all(|shard| *shard < PROJECT_DISCOVERY_SHARD_COUNT);
    if marker.schema_version != PROJECT_INDEX_SCHEMA_VERSION
        || !is_valid_project_storage_id(&marker.storage_id)
        || !valid_shards
        || marker
            .writable_shard
            .is_some_and(|shard| !marker.active_shards.contains(&shard))
    {
        return Err("vault project-index marker is invalid".to_owned());
    }
    Ok(ProjectIndexState { marker })
}

fn read_project_metadata(
    storage: &mut impl ProjectStorage,
    vault_id: &str,
    state: &ProjectIndexState,
) -> Result<Option<ProjectMetadataSnapshot>, String> {
    let account = project_metadata_account(&state.marker.storage_id, vault_id);
    let Some(data) = read_text(storage, &account)? else {
        return Ok(None);
    };
    let record: ProjectMetadataRecord = serde_json::from_str(&data)
        .map_err(|error| format!("vault project metadata is not valid JSON: {error}"))?;
    if record.schema_version != PROJECT_INDEX_SCHEMA_VERSION
        || record.storage_id != state.marker.storage_id
        || record.id != vault_id
        || record.discovery_shard >= PROJECT_DISCOVERY_SHARD_COUNT
        || !are_valid_environment_summaries(&record.environment_summaries)
        || account != project_metadata_account(&state.marker.storage_id, &record.id)
    {
        return Err(format!("vault project metadata for {vault_id} is invalid"));
    }
    validate_vault_id(&record.id)?;
    Ok(Some(ProjectMetadataSnapshot { record }))
}

fn read_project_discovery(
    storage: &mut impl ProjectStorage,
    shard: usize,
    state: &ProjectIndexState,
) -> Result<Option<ProjectDiscoverySnapshot>, String> {
    if !state.marker.active_shards.contains(&shard) {
        return Ok(None);
    }
    let account = project_discovery_account(&state.marker.storage_id, shard);
    let Some(data) = read_text(storage, &account)? else {
        return Err(format!("vault project discovery shard {shard} is missing"));
    };
    let envelope: ProjectDiscoveryShard = serde_json::from_str(&data)
        .map_err(|error| format!("vault project discovery is not valid JSON: {error}"))?;
    let ids_are_valid = envelope.ids.len() <= MAX_PROJECT_DISCOVERY_SHARD_SIZE
        && envelope.ids.windows(2).all(|window| window[0] < window[1])
        && envelope
            .ids
            .iter()
            .all(|vault_id| validate_vault_id(vault_id).is_ok());
    if envelope.schema_version != PROJECT_INDEX_SCHEMA_VERSION
        || envelope.storage_id != state.marker.storage_id
        || envelope.shard != shard
        || account != project_discovery_account(&state.marker.storage_id, envelope.shard)
        || !ids_are_valid
    {
        return Err(format!("vault project discovery shard {shard} is invalid"));
    }
    Ok(Some(ProjectDiscoverySnapshot { envelope }))
}

fn create_project_records(
    storage: &mut impl ProjectStorage,
    project_name: &str,
    project_path: &str,
    payload: ValidatedVaultPayload,
    mut state: ProjectIndexState,
) -> Result<(), String> {
    let vault_id = payload.vault_id();
    let metadata_account = project_metadata_account(&state.marker.storage_id, vault_id);
    if storage.read(&metadata_account)?.is_some() {
        return Err(format!(
            "vault project metadata for {vault_id} already exists"
        ));
    }
    let (shard, previous_shard) = select_project_discovery_shard(storage, vault_id, &state)?;
    let mut envelope = previous_shard
        .as_ref()
        .map(|snapshot| snapshot.envelope.clone())
        .unwrap_or(ProjectDiscoveryShard {
            schema_version: PROJECT_INDEX_SCHEMA_VERSION,
            storage_id: state.marker.storage_id.clone(),
            shard,
            ids: Vec::new(),
        });
    if envelope.ids.iter().any(|id| id == vault_id) {
        return Err(format!("vault project {vault_id} is already discoverable"));
    }
    envelope.ids.push(vault_id.to_owned());
    envelope.ids.sort_unstable();
    let metadata = ProjectMetadataRecord {
        schema_version: PROJECT_INDEX_SCHEMA_VERSION,
        storage_id: state.marker.storage_id.clone(),
        id: vault_id.to_owned(),
        name: project_name.to_owned(),
        path: project_path.to_owned(),
        discovery_shard: shard,
        environment_summaries: payload.environment_summaries().to_vec(),
    };
    let metadata_data = serde_json::to_string(&metadata)
        .map_err(|error| format!("failed to serialize vault project metadata: {error}"))?;
    let shard_data = serde_json::to_string(&envelope)
        .map_err(|error| format!("failed to serialize vault project discovery: {error}"))?;
    let shard_account = project_discovery_account(&state.marker.storage_id, shard);
    let activates_shard = previous_shard.is_none();
    if activates_shard {
        state.marker.active_shards.push(shard);
        state.marker.active_shards.sort_unstable();
    }
    let previous_writable_shard = state.marker.writable_shard;
    state.marker.writable_shard =
        (envelope.ids.len() < MAX_PROJECT_DISCOVERY_SHARD_SIZE).then_some(shard);
    let marker_changed = activates_shard || state.marker.writable_shard != previous_writable_shard;
    let updated_marker_data = marker_changed
        .then(|| {
            serde_json::to_string(&state.marker)
                .map_err(|error| format!("failed to serialize vault project-index marker: {error}"))
        })
        .transpose()?;

    let mut mutations = vec![
        ProjectStorageMutation::validated_vault_write(payload),
        ProjectStorageMutation::write(metadata_account, metadata_data),
        ProjectStorageMutation::write(shard_account, shard_data),
    ];
    if let Some(marker_data) = updated_marker_data {
        mutations.push(ProjectStorageMutation::write(
            PROJECT_INDEX_MARKER_ACCOUNT,
            marker_data,
        ));
    }
    apply_project_transaction_after_recovery(storage, mutations)
}

fn select_project_discovery_shard(
    storage: &mut impl ProjectStorage,
    vault_id: &str,
    state: &ProjectIndexState,
) -> Result<(usize, Option<ProjectDiscoverySnapshot>), String> {
    if let Some(writable_shard) = state.marker.writable_shard {
        let snapshot =
            read_project_discovery(storage, writable_shard, state)?.ok_or_else(|| {
                format!("writable vault project discovery shard {writable_shard} is missing")
            })?;
        if snapshot.envelope.ids.len() >= MAX_PROJECT_DISCOVERY_SHARD_SIZE {
            return Err(format!(
                "writable vault project discovery shard {writable_shard} is full"
            ));
        }
        return Ok((writable_shard, Some(snapshot)));
    }
    let active_shards: HashSet<_> = state.marker.active_shards.iter().copied().collect();
    let probe = project_discovery_probe(vault_id);
    for attempt in 0..PROJECT_DISCOVERY_SHARD_COUNT {
        let shard = project_discovery_shard(probe, attempt);
        if !active_shards.contains(&shard) {
            let account = project_discovery_account(&state.marker.storage_id, shard);
            if storage.read(&account)?.is_some() {
                return Err(format!(
                    "inactive vault project discovery shard {shard} unexpectedly exists"
                ));
            }
            return Ok((shard, None));
        }
    }
    Err("vault project discovery capacity is exhausted".to_owned())
}

#[cfg(test)]
fn delete_vault_with_storage(
    storage: &mut impl ProjectStorage,
    vault_id: &str,
) -> Result<(), String> {
    recover_project_transaction(storage)?;
    delete_vault_with_storage_after_recovery(storage, vault_id)
}

fn delete_vault_with_storage_after_recovery(
    storage: &mut impl ProjectStorage,
    vault_id: &str,
) -> Result<(), String> {
    validate_vault_id(vault_id)?;
    companion_gate::authorize(storage, vault_id, Operation::Maintenance)?;
    let inventory = companion_gate::KeychainCompanion(&mut *storage).inventory(vault_id)?;
    let marker_bytes = storage.read(&crate::companion::account::marker_account(vault_id))?;
    let mutations = project_deletion_mutations(storage, vault_id)?;
    if inventory.is_empty() && marker_bytes.is_none() {
        return match mutations {
            Some(mutations) => apply_project_transaction_after_recovery(storage, mutations),
            None => storage.delete(vault_id).map(|_| ()),
        };
    }
    delete_project_with_companion_records(storage, vault_id, mutations, marker_bytes, inventory)
}

/// Delete a project with companion records: the first transaction
/// removes the values item, the project's metadata, the shared key and the
/// single records, and either the marker or, when records remain, leaves a
/// `deleting` marker that later transactions finish.
fn delete_project_with_companion_records(
    storage: &mut impl ProjectStorage,
    vault_id: &str,
    project_mutations: Option<Vec<ProjectStorageMutation>>,
    marker_bytes: Option<Vec<u8>>,
    inventory: Vec<CompanionAccount>,
) -> Result<(), String> {
    use crate::companion::lifecycle::{FoundMarker, MarkerChange, Plan, PlannedChange};

    let current = marker_bytes
        .as_deref()
        .map(|bytes| Marker::parse(vault_id, bytes).ok());
    let found = match &current {
        None => FoundMarker::Absent,
        Some(None) => FoundMarker::Invalid,
        Some(Some(marker)) => FoundMarker::Valid(marker),
    };
    let mut mutations =
        project_mutations.unwrap_or_else(|| vec![ProjectStorageMutation::delete(vault_id)]);
    let plan =
        crate::companion::lifecycle::plan_deletion(vault_id, found, inventory, mutations.len())?;
    let mut transactions = plan.transactions.into_iter();
    if let Some(first) = transactions.next() {
        for change in first.changes {
            match change {
                PlannedChange::Delete(account) => {
                    mutations.push(ProjectStorageMutation::delete(account.name()));
                }
                PlannedChange::Move { .. } => {
                    return Err("a deletion plan moved a record".to_owned());
                }
            }
        }
        let marker_account = crate::companion::account::marker_account(vault_id);
        match first.marker {
            Some(MarkerChange::Write(marker)) => mutations.push(ProjectStorageMutation::write(
                marker_account,
                marker.encode().map_err(|error| error.to_string())?,
            )),
            Some(MarkerChange::Delete) => {
                mutations.push(ProjectStorageMutation::delete(marker_account));
            }
            None => {}
        }
    }
    apply_project_transaction_after_recovery(storage, mutations)?;
    crate::companion::lifecycle::execute(
        &mut companion_gate::KeychainCompanion(&mut *storage),
        Plan {
            vault_id: plan.vault_id,
            transactions: transactions.collect(),
            result: None,
        },
    )?;
    crate::companion::remember(vault_id, &ProjectGate::Plain);
    Ok(())
}

/// The mutations that delete a project's values item and discovery records,
/// or `None` when it has no metadata and only its values item goes.
fn project_deletion_mutations(
    storage: &mut impl ProjectStorage,
    vault_id: &str,
) -> Result<Option<Vec<ProjectStorageMutation>>, String> {
    let mut state = ensure_project_index_after_recovery(storage)?;
    let Some(metadata) = read_project_metadata(storage, vault_id, &state)? else {
        return Ok(None);
    };
    let shard = metadata.record.discovery_shard;
    let shard_snapshot = read_project_discovery(storage, shard, &state)?
        .ok_or_else(|| format!("vault project discovery shard {shard} is missing"))?;
    if shard_snapshot
        .envelope
        .ids
        .iter()
        .filter(|id| id.as_str() == vault_id)
        .count()
        != 1
    {
        return Err(format!(
            "vault project {vault_id} does not have exactly one discovery entry"
        ));
    }
    let metadata_account = project_metadata_account(&state.marker.storage_id, vault_id);
    let shard_account = project_discovery_account(&state.marker.storage_id, shard);
    let mut updated_shard = shard_snapshot.envelope.clone();
    updated_shard.ids.retain(|id| id != vault_id);
    let deactivates_shard = updated_shard.ids.is_empty();
    let previous_writable_shard = state.marker.writable_shard;
    if deactivates_shard {
        state
            .marker
            .active_shards
            .retain(|candidate| *candidate != shard);
        if state.marker.writable_shard == Some(shard) {
            state.marker.writable_shard = None;
        }
    } else if shard_snapshot.envelope.ids.len() == MAX_PROJECT_DISCOVERY_SHARD_SIZE
        && state.marker.writable_shard.is_none()
    {
        state.marker.writable_shard = Some(shard);
    }
    let marker_changed =
        deactivates_shard || state.marker.writable_shard != previous_writable_shard;

    let mut mutations = vec![
        ProjectStorageMutation::delete(vault_id),
        ProjectStorageMutation::delete(metadata_account),
    ];
    if deactivates_shard {
        mutations.push(ProjectStorageMutation::delete(shard_account));
    } else {
        let shard_data = serde_json::to_string(&updated_shard)
            .map_err(|error| format!("failed to serialize vault project discovery: {error}"))?;
        mutations.push(ProjectStorageMutation::write(shard_account, shard_data));
    }
    if marker_changed {
        let marker_data = serde_json::to_string(&state.marker)
            .map_err(|error| format!("failed to serialize vault project-index marker: {error}"))?;
        mutations.push(ProjectStorageMutation::write(
            PROJECT_INDEX_MARKER_ACCOUNT,
            marker_data,
        ));
    }
    Ok(Some(mutations))
}

#[cfg(test)]
fn project_environment_summaries(payload: &str) -> Result<Vec<ProjectEnvironmentSummary>, String> {
    let environments = parse_vault_environments(payload)
        .map_err(|error| format!("vault payload is not valid JSON: {error}"))?;
    Ok(environment_summaries(&environments))
}

fn environment_summaries(environments: &EnvironmentMap) -> Vec<ProjectEnvironmentSummary> {
    let mut summaries: Vec<_> = environments
        .iter()
        .map(|(name, secrets)| ProjectEnvironmentSummary {
            name: name.to_owned(),
            key_count: secrets.len(),
        })
        .collect();
    if summaries.is_empty() {
        summaries.push(ProjectEnvironmentSummary {
            name: "default".to_owned(),
            key_count: 0,
        });
    }
    summaries.sort_unstable_by(|left, right| left.name.cmp(&right.name));
    summaries
}

fn parse_vault_environments(payload: &str) -> Result<EnvironmentMap, String> {
    #[cfg(test)]
    VAULT_PAYLOAD_PARSE_ATTEMPTS.with(|count| count.set(count.get() + 1));
    let parsed = crate::selected_environment::parse_all(payload).map_err(|error| error.to_string());
    #[cfg(test)]
    if parsed.is_ok() {
        VAULT_PAYLOAD_PARSE_SUCCESSES.with(|count| count.set(count.get() + 1));
    }
    parsed
}

#[cfg(test)]
fn reset_vault_payload_parse_counts() {
    VAULT_PAYLOAD_PARSE_ATTEMPTS.with(|count| count.set(0));
    VAULT_PAYLOAD_PARSE_SUCCESSES.with(|count| count.set(0));
}

#[cfg(test)]
fn vault_payload_parse_counts() -> (usize, usize) {
    (
        VAULT_PAYLOAD_PARSE_ATTEMPTS.with(std::cell::Cell::get),
        VAULT_PAYLOAD_PARSE_SUCCESSES.with(std::cell::Cell::get),
    )
}

fn are_valid_environment_summaries(summaries: &[ProjectEnvironmentSummary]) -> bool {
    !summaries.is_empty()
        && summaries
            .windows(2)
            .all(|window| window[0].name < window[1].name)
        && summaries
            .iter()
            .all(|summary| is_valid_environment_name(&summary.name))
}

fn validate_vault_id(vault_id: &str) -> Result<(), String> {
    if is_safe_vault_id(vault_id) {
        Ok(())
    } else {
        Err("vault ID is not safe for protected storage".to_owned())
    }
}

fn generate_project_storage_id() -> String {
    let mut bytes = [0_u8; 16];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut bytes);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let encoded = hex::encode(bytes);
    format!(
        "{}-{}-{}-{}-{}",
        &encoded[0..8],
        &encoded[8..12],
        &encoded[12..16],
        &encoded[16..20],
        &encoded[20..32]
    )
}

fn is_valid_project_storage_id(storage_id: &str) -> bool {
    storage_id.len() == 36
        && storage_id.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        })
}

fn project_metadata_account(storage_id: &str, vault_id: &str) -> String {
    let encoded = base64::Engine::encode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        vault_id.as_bytes(),
    );
    format!("{PROJECT_METADATA_PREFIX}{storage_id}:{encoded}")
}

fn project_discovery_account(storage_id: &str, shard: usize) -> String {
    format!("{PROJECT_DISCOVERY_PREFIX}{storage_id}:{shard:03x}")
}

fn project_discovery_probe(vault_id: &str) -> (usize, usize) {
    use sha2::Digest as _;

    let digest = sha2::Sha256::digest(vault_id.as_bytes());
    let start =
        (usize::from(digest[0]) << 8 | usize::from(digest[1])) % PROJECT_DISCOVERY_SHARD_COUNT;
    let raw_step =
        (usize::from(digest[2]) << 8 | usize::from(digest[3])) % PROJECT_DISCOVERY_SHARD_COUNT;
    (start, raw_step | 1)
}

fn project_discovery_shard(probe: (usize, usize), attempt: usize) -> usize {
    (probe.0 + attempt * probe.1) % PROJECT_DISCOVERY_SHARD_COUNT
}

#[cfg(test)]
mod tests {
    use super::*;

    mod companion;

    #[test]
    fn large_env_data_is_warned_of_in_binary_units() {
        assert_eq!(
            large_env_warning(95 * 1024).as_deref(),
            Some("env data is 95 KiB (approaching the Keychain's ~100 KiB limit)")
        );
        assert_eq!(large_env_warning(MAX_VAULT_SIZE_WARNING), None);
    }

    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct ProjectIndexFixture {
        schema_version: u8,
        records: Vec<ProjectIndexFixtureRecord>,
        project: ProjectIndexFixtureProject,
    }

    #[derive(serde::Deserialize)]
    struct ProjectIndexFixtureRecord {
        account: String,
        value: String,
    }

    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct ProjectIndexFixtureProject {
        id: String,
        name: String,
        path: String,
        environment_summaries: Vec<ProjectEnvironmentSummary>,
    }

    /// Stored item data, readable as text where tests expect it.
    #[derive(Default)]
    struct TestValues(HashMap<String, Vec<u8>>);

    impl TestValues {
        fn insert(&mut self, account: impl Into<String>, value: impl Into<Vec<u8>>) {
            self.0.insert(account.into(), value.into());
        }

        fn extend<A: Into<String>, V: Into<Vec<u8>>>(
            &mut self,
            entries: impl IntoIterator<Item = (A, V)>,
        ) {
            for (account, value) in entries {
                self.insert(account, value);
            }
        }

        fn get(&self, account: &str) -> Option<&str> {
            self.0
                .get(account)
                .map(|value| std::str::from_utf8(value).expect("a text item"))
        }

        fn get_bytes(&self, account: &str) -> Option<&[u8]> {
            self.0.get(account).map(Vec::as_slice)
        }

        fn contains_key(&self, account: &str) -> bool {
            self.0.contains_key(account)
        }

        fn remove(&mut self, account: &str) -> Option<Vec<u8>> {
            self.0.remove(account)
        }

        fn keys(&self) -> impl Iterator<Item = &String> {
            self.0.keys()
        }

        fn as_text_map(&self) -> HashMap<String, String> {
            self.0
                .iter()
                .map(|(account, value)| {
                    (
                        account.clone(),
                        String::from_utf8(value.clone()).expect("a text item"),
                    )
                })
                .collect()
        }
    }

    #[derive(Default)]
    struct MemoryProjectStorage {
        access_sources: Vec<(String, String)>,
        rejected_access_sources: HashSet<String>,
        values: TestValues,
        /// The approval each item's attributes claim; absent means automatic.
        claims: HashMap<String, ClaimedAccess>,
        /// Items that really demand user presence, whatever they claim.
        protected: HashSet<String>,
        keychain_unavailable: bool,
        probes: Vec<String>,
        approvals_required: Vec<String>,
        listings: usize,
        reads: HashMap<String, usize>,
        writes: HashMap<String, usize>,
        deletes: HashMap<String, usize>,
        rejected_writes: HashSet<String>,
        ignored_writes: HashSet<String>,
        mutation_attempts: usize,
        fail_once_at_mutation: Option<usize>,
        injected_failure: bool,
        fail_committed_marker_verification_once: bool,
        fail_final_marker_delete_verification_once: bool,
        final_marker_was_deleted: bool,
    }

    impl ProjectStorage for MemoryProjectStorage {
        fn write_verified_with_access_from(
            &mut self,
            account: &str,
            value: &[u8],
            source: &str,
        ) -> Result<(), String> {
            if self.rejected_access_sources.contains(source) {
                return Err("env access approval was cancelled".to_owned());
            }
            self.access_sources
                .push((account.to_owned(), source.to_owned()));
            if !self.values.contains_key(account) {
                if let Some(claim) = self.claims.get(source).copied() {
                    self.claims.insert(account.to_owned(), claim);
                }
                if self.protected.contains(source) {
                    self.protected.insert(account.to_owned());
                }
            }
            self.write_verified(account, value)
        }

        fn write_verified_with_access(
            &mut self,
            account: &str,
            value: &[u8],
            access: CliAccess,
        ) -> Result<(), String> {
            if !self.values.contains_key(account) && access == CliAccess::RequireApproval {
                self.claims
                    .insert(account.to_owned(), ClaimedAccess::RequireApproval);
                self.protected.insert(account.to_owned());
            }
            self.write_verified(account, value)
        }

        fn read(&mut self, account: &str) -> Result<Option<Vec<u8>>, String> {
            *self.reads.entry(account.to_owned()).or_default() += 1;
            if account == TRANSACTION_MARKER_ACCOUNT
                && self.fail_committed_marker_verification_once
                && self
                    .values
                    .get(account)
                    .is_some_and(|value| value.contains(r#""state":"committed""#))
            {
                self.fail_committed_marker_verification_once = false;
                return Err("injected committed-marker verification failure".to_owned());
            }
            if account == TRANSACTION_MARKER_ACCOUNT
                && self.fail_final_marker_delete_verification_once
                && self.final_marker_was_deleted
                && !self.values.contains_key(account)
            {
                self.fail_final_marker_delete_verification_once = false;
                return Err("injected final-marker deletion verification failure".to_owned());
            }
            Ok(self.values.get_bytes(account).map(<[u8]>::to_vec))
        }

        fn write(&mut self, account: &str, value: &[u8]) -> Result<(), String> {
            *self.writes.entry(account.to_owned()).or_default() += 1;
            self.mutation_attempts += 1;
            if self.fail_once_at_mutation == Some(self.mutation_attempts) {
                self.injected_failure = true;
                return Err(format!("injected mutation failure for {account}"));
            }
            if self.rejected_writes.contains(account) {
                return Err(format!("injected write failure for {account}"));
            }
            if self.ignored_writes.contains(account) {
                return Ok(());
            }
            self.values.insert(account, value);
            Ok(())
        }

        fn delete(&mut self, account: &str) -> Result<bool, String> {
            *self.deletes.entry(account.to_owned()).or_default() += 1;
            self.mutation_attempts += 1;
            if self.fail_once_at_mutation == Some(self.mutation_attempts) {
                self.injected_failure = true;
                return Err(format!("injected mutation failure for {account}"));
            }
            let marker_was_committed = account == TRANSACTION_MARKER_ACCOUNT
                && self
                    .values
                    .get(account)
                    .is_some_and(|value| value.contains(r#""state":"committed""#));
            let deleted = self.values.remove(account).is_some();
            if deleted {
                self.claims.remove(account);
                self.protected.remove(account);
            }
            if marker_was_committed && deleted {
                self.final_marker_was_deleted = true;
            }
            Ok(deleted)
        }

        fn account_names(&mut self) -> Result<Vec<String>, String> {
            self.listings += 1;
            Ok(self.values.keys().cloned().collect())
        }

        fn read_with_access(
            &mut self,
            account: &str,
        ) -> Result<Option<(Vec<u8>, ClaimedAccess)>, String> {
            let claim = self
                .claims
                .get(account)
                .copied()
                .unwrap_or(ClaimedAccess::Automatic);
            Ok(self.read(account)?.map(|value| (value, claim)))
        }

        fn claimed_access(&mut self, account: &str) -> Result<Option<ClaimedAccess>, String> {
            Ok(self.values.contains_key(account).then(|| {
                self.claims
                    .get(account)
                    .copied()
                    .unwrap_or(ClaimedAccess::Automatic)
            }))
        }

        fn probe(&mut self, account: &str, open_accounts: &[&str]) -> ProbeOutcome {
            self.probes.push(account.to_owned());
            if !self.values.contains_key(account) {
                return ProbeOutcome::Absent;
            }
            if !self.protected.contains(account) {
                return if self.keychain_unavailable {
                    ProbeOutcome::Inconclusive
                } else {
                    ProbeOutcome::Automatic
                };
            }
            let open_item_reads = !self.keychain_unavailable
                && open_accounts
                    .iter()
                    .any(|open| self.values.contains_key(open));
            if open_item_reads {
                ProbeOutcome::Protected
            } else {
                ProbeOutcome::Inconclusive
            }
        }

        fn require_approval(
            &mut self,
            account: &str,
            open_accounts: &[&str],
        ) -> Result<(), String> {
            self.approvals_required.push(account.to_owned());
            self.claims
                .insert(account.to_owned(), ClaimedAccess::RequireApproval);
            self.protected.insert(account.to_owned());
            match self.probe(account, open_accounts) {
                ProbeOutcome::Protected => Ok(()),
                outcome => Err(format!("approval couldn't be confirmed: {outcome:?}")),
            }
        }
    }

    fn seed_committed_payload_recovery(
        storage: &mut MemoryProjectStorage,
        vault_id: &str,
        payload: &str,
    ) {
        let transaction_id = "00000000-0000-4000-8000-000000000001";
        let stage = transaction_stage_account(transaction_id, 0);
        let journal = TransactionJournal {
            schema_version: TRANSACTION_SCHEMA_VERSION,
            transaction_id: transaction_id.to_owned(),
            state: TransactionState::Committed,
            operations: vec![TransactionJournalOperation {
                action: "write".to_owned(),
                target_account: vault_id.to_owned(),
                staged_account: Some(stage.clone()),
                operation_sha256: transaction_operation_sha256(
                    "write",
                    vault_id,
                    Some(payload.as_bytes()),
                ),
            }],
        };
        storage.values.insert(
            TRANSACTION_MARKER_ACCOUNT.to_owned(),
            serde_json::to_string(&journal).expect("encode committed journal"),
        );
        storage.values.insert(stage, payload.to_owned());
    }

    #[test]
    fn committed_recovery_precedes_a_higher_level_payload_read() {
        let payload = r#"{"environments":{"default":{"RECOVERED":"yes"}}}"#;
        let mut storage = MemoryProjectStorage::default();
        storage.values.insert(
            "vault".to_owned(),
            r#"{"environments":{"default":{"STALE":"yes"}}}"#.to_owned(),
        );
        seed_committed_payload_recovery(&mut storage, "vault", payload);

        recover_project_transaction(&mut storage).expect("recover before read");
        let visible = storage.read("vault").expect("read recovered payload");

        assert_eq!(visible.as_deref(), Some(payload.as_bytes()));
    }

    #[test]
    fn committed_recovery_precedes_a_higher_level_read_modify_write() {
        let payload = r#"{"environments":{"default":{"RECOVERED":"yes"}}}"#;
        let mut storage = MemoryProjectStorage::default();
        storage.values.insert(
            "vault".to_owned(),
            r#"{"environments":{"default":{"STALE":"yes"}}}"#.to_owned(),
        );
        seed_committed_payload_recovery(&mut storage, "vault", payload);

        recover_project_transaction(&mut storage).expect("recover before mutation");
        let current = storage
            .read("vault")
            .expect("read recovered payload")
            .expect("recovered payload exists");
        let mut environments = crate::selected_environment::parse_all(
            std::str::from_utf8(&current).expect("text payload"),
        )
        .expect("parse recovered payload");
        environments
            .entry("default".to_owned())
            .or_default()
            .insert("LOCAL".to_owned(), "change".to_owned());
        let updated = crate::selected_environment::serialize(&environments)
            .expect("serialize updated payload");
        storage
            .write("vault", updated.as_bytes())
            .expect("write update");

        let final_payload = crate::selected_environment::parse_all(
            storage.values.get("vault").expect("final payload exists"),
        )
        .expect("parse final payload");
        assert_eq!(final_payload["default"].len(), 2);
        assert_eq!(final_payload["default"]["RECOVERED"], "yes");
        assert_eq!(final_payload["default"]["LOCAL"], "change");
    }

    #[test]
    fn swift_current_project_index_fixture_is_discoverable() {
        let fixture: ProjectIndexFixture =
            serde_json::from_str(include_str!("../tests/fixtures/project-index-v3.json"))
                .expect("shared project-index fixture should decode");
        assert_eq!(fixture.schema_version, 1);
        let mut storage = MemoryProjectStorage::default();
        storage.values.extend(
            fixture
                .records
                .into_iter()
                .map(|record| (record.account, record.value)),
        );

        assert_eq!(
            list_vaults_with_storage(&mut storage).expect("Swift fixture should decode"),
            [IndexEntry {
                id: fixture.project.id.clone(),
                name: fixture.project.name,
                path: fixture.project.path,
            }]
        );
        let state = ensure_project_index_after_recovery(&mut storage)
            .expect("project index should remain valid");
        let metadata = read_project_metadata(&mut storage, &fixture.project.id, &state)
            .expect("project metadata should decode")
            .expect("project metadata should exist");
        assert_eq!(
            metadata.record.environment_summaries,
            fixture.project.environment_summaries
        );
    }

    #[test]
    fn indexed_project_save_recovers_once_and_parses_the_payload_once() {
        let fixture: ProjectIndexFixture =
            serde_json::from_str(include_str!("../tests/fixtures/project-index-v3.json"))
                .expect("shared project-index fixture should decode");
        let vault_id = fixture.project.id.clone();
        let mut storage = MemoryProjectStorage::default();
        storage.values.extend(
            fixture
                .records
                .into_iter()
                .map(|record| (record.account, record.value)),
        );
        let payload = storage
            .values
            .get(&vault_id)
            .expect("fixture payload should exist")
            .to_owned();
        storage.reads.clear();
        reset_vault_payload_parse_counts();

        save_vault_data_with_storage(
            &mut storage,
            &vault_id,
            &fixture.project.name,
            &fixture.project.path,
            &payload,
        )
        .expect("indexed payload save should succeed");

        assert_eq!(storage.reads.get(TRANSACTION_MARKER_ACCOUNT), Some(&4));
        assert_eq!(vault_payload_parse_counts(), (1, 1));
    }

    #[test]
    fn new_project_save_recovers_once_and_parses_the_payload_once() {
        let mut storage = MemoryProjectStorage::default();
        let payload = r#"{"environments":{"default":{"TOKEN":"secret"}}}"#;
        reset_vault_payload_parse_counts();

        save_vault_data_with_storage(
            &mut storage,
            "new-vault",
            "New Vault",
            "/workspace/new",
            payload,
        )
        .expect("new project save should succeed");

        assert_eq!(storage.reads.get(TRANSACTION_MARKER_ACCOUNT), Some(&7));
        assert_eq!(vault_payload_parse_counts(), (1, 1));
        assert!(!storage.values.contains_key(TRANSACTION_MARKER_ACCOUNT));
        assert!(
            !storage
                .values
                .keys()
                .any(|account| account.starts_with(TRANSACTION_STAGE_PREFIX))
        );
    }

    #[test]
    fn locally_serialized_environments_move_into_storage_without_reparsing() {
        let mut storage = MemoryProjectStorage::default();
        let environments = HashMap::from([(
            "default".to_owned(),
            HashMap::from([("TOKEN".to_owned(), "secret".to_owned())]),
        )]);
        reset_vault_payload_parse_counts();

        write_all_environments_with_storage_after_recovery(
            &mut storage,
            "new-vault",
            "New Vault",
            "/workspace/new",
            &environments,
        )
        .expect("locally generated project save should succeed");

        assert_eq!(vault_payload_parse_counts(), (0, 0));
        assert_eq!(
            storage.values.get("new-vault"),
            Some(r#"{"environments":{"default":{"TOKEN":"secret"}}}"#)
        );
    }

    #[test]
    fn persisted_committed_transaction_reparses_the_staged_payload_once() {
        let payload = r#"{"environments":{"default":{"TOKEN":"secret"}}}"#;
        let mut storage = MemoryProjectStorage::default();
        seed_committed_payload_recovery(&mut storage, "vault", payload);
        reset_vault_payload_parse_counts();

        recover_project_transaction(&mut storage)
            .expect("persisted committed payload should recover");

        assert_eq!(vault_payload_parse_counts(), (1, 1));
        assert_eq!(storage.values.get("vault"), Some(payload));
    }

    #[test]
    fn project_updates_copy_access_control_to_staging_and_back_to_the_live_record() {
        let mut storage = MemoryProjectStorage::default();
        apply_project_transaction(
            &mut storage,
            vec![ProjectStorageMutation::Write {
                account: "vault".to_owned(),
                value: r#"{"environments":{"default":{"TOKEN":"fixture"}}}"#.to_owned().into(),
            }],
        )
        .expect("project update should succeed");
        let [(stage, source), (target, stage_source)] = storage.access_sources.as_slice() else {
            panic!("expected exactly one staged write and one live write");
        };
        assert!(stage.starts_with(TRANSACTION_STAGE_PREFIX));
        assert_eq!(source, "vault");
        assert_eq!(target, "vault");
        assert_eq!(stage_source, stage);
    }

    #[test]
    fn committed_recovery_restores_access_control_from_the_stage_when_the_target_is_absent() {
        let mut storage = MemoryProjectStorage::default();
        seed_committed_payload_recovery(
            &mut storage,
            "vault",
            r#"{"environments":{"default":{"TOKEN":"fixture"}}}"#,
        );
        recover_project_transaction(&mut storage).expect("committed update should recover");
        let [(target, source)] = storage.access_sources.as_slice() else {
            panic!("expected one recovered protected write");
        };
        assert_eq!(target, "vault");
        assert!(source.starts_with(TRANSACTION_STAGE_PREFIX));
    }

    #[test]
    fn denied_access_control_copy_leaves_the_original_project_and_no_staged_secret() {
        let original = r#"{"environments":{"default":{"TOKEN":"original"}}}"#;
        let mut storage = MemoryProjectStorage::default();
        storage
            .values
            .insert("vault".to_owned(), original.to_owned());
        storage.rejected_access_sources.insert("vault".to_owned());
        apply_project_transaction(
            &mut storage,
            vec![ProjectStorageMutation::Write {
                account: "vault".to_owned(),
                value: r#"{"environments":{"default":{"TOKEN":"replacement"}}}"#
                    .to_owned()
                    .into(),
            }],
        )
        .expect_err("cancelled approval must abort the update");
        assert_eq!(
            storage.values.as_text_map(),
            HashMap::from([("vault".to_owned(), original.to_owned())])
        );
    }

    #[test]
    fn persisted_committed_transaction_rejects_malformed_payload_before_target_write() {
        let malformed = r#"{"environments":{"default":{"TOKEN":"first","TOKEN":"second"}}}"#;
        let original = r#"{"environments":{"default":{"TOKEN":"original"}}}"#;
        let mut storage = MemoryProjectStorage::default();
        storage
            .values
            .insert("vault".to_owned(), original.to_owned());
        seed_committed_payload_recovery(&mut storage, "vault", malformed);
        reset_vault_payload_parse_counts();

        recover_project_transaction(&mut storage)
            .expect_err("malformed persisted payload must fail closed");

        assert_eq!(vault_payload_parse_counts(), (1, 0));
        assert_eq!(storage.values.get("vault"), Some(original));
        assert!(storage.values.contains_key(TRANSACTION_MARKER_ACCOUNT));
    }

    #[test]
    fn persisted_committed_transaction_checks_the_digest_before_parsing() {
        let payload = r#"{"environments":{"default":{"TOKEN":"secret"}}}"#;
        let mut storage = MemoryProjectStorage::default();
        seed_committed_payload_recovery(&mut storage, "vault", payload);
        let staged_account = storage
            .values
            .keys()
            .find(|account| account.starts_with(TRANSACTION_STAGE_PREFIX))
            .expect("staged payload should exist")
            .clone();
        storage.values.insert(
            staged_account,
            r#"{"environments":{"default":{"TOKEN":"tampered"}}}"#.to_owned(),
        );
        reset_vault_payload_parse_counts();

        recover_project_transaction(&mut storage)
            .expect_err("a digest mismatch must fail closed before parsing");

        assert_eq!(vault_payload_parse_counts(), (0, 0));
        assert!(!storage.values.contains_key("vault"));
    }

    #[test]
    fn failed_project_metadata_write_never_exposes_a_partial_vault_update() {
        let fixture: ProjectIndexFixture =
            serde_json::from_str(include_str!("../tests/fixtures/project-index-v3.json"))
                .expect("shared project-index fixture should decode");
        let vault_id = fixture.project.id.clone();
        let mut storage = MemoryProjectStorage::default();
        storage.values.extend(
            fixture
                .records
                .into_iter()
                .map(|record| (record.account, record.value)),
        );
        let state =
            ensure_project_index_after_recovery(&mut storage).expect("project index should decode");
        let metadata_account = project_metadata_account(&state.marker.storage_id, &vault_id);
        storage.rejected_writes.insert(metadata_account.clone());
        let updated_payload = r#"{"environments":{"default":{"ADDED":"value","TOKEN":"secret"}}}"#;

        save_vault_data_with_storage(
            &mut storage,
            &vault_id,
            &fixture.project.name,
            &fixture.project.path,
            updated_payload,
        )
        .expect_err("injected metadata failure should reject the update");
        storage.rejected_writes.clear();
        recover_project_transaction(&mut storage)
            .expect("the next process should roll the committed transaction forward");

        assert_eq!(storage.values.get(&vault_id), Some(updated_payload));
        let metadata: ProjectMetadataRecord = serde_json::from_str(
            storage
                .values
                .get(&metadata_account)
                .expect("metadata should survive recovery"),
        )
        .expect("metadata should decode after recovery");
        assert_eq!(metadata.environment_summaries[0].key_count, 2);
        assert!(!storage.values.contains_key(TRANSACTION_MARKER_ACCOUNT));
    }

    #[test]
    fn project_transaction_recovers_after_every_mutation_boundary() {
        let fixture_source = include_str!("../tests/fixtures/project-index-v3.json");
        let updated_payload = r#"{"environments":{"default":{"ADDED":"value","TOKEN":"secret"}}}"#;

        for failure_point in 1..=9 {
            let fixture: ProjectIndexFixture =
                serde_json::from_str(fixture_source).expect("shared fixture should decode");
            let vault_id = fixture.project.id.clone();
            let mut storage = MemoryProjectStorage::default();
            storage.values.extend(
                fixture
                    .records
                    .into_iter()
                    .map(|record| (record.account, record.value)),
            );
            storage.fail_once_at_mutation = Some(failure_point);

            let _ = save_vault_data_with_storage(
                &mut storage,
                &vault_id,
                &fixture.project.name,
                &fixture.project.path,
                updated_payload,
            );
            assert!(
                storage.injected_failure,
                "failure point {failure_point} was not reached"
            );
            storage.fail_once_at_mutation = None;
            recover_project_transaction(&mut storage)
                .expect("a restarted client should recover the transaction");

            let state = ensure_project_index_after_recovery(&mut storage)
                .expect("project index should decode");
            let metadata = read_project_metadata(&mut storage, &vault_id, &state)
                .expect("metadata should decode")
                .expect("metadata should remain present");
            let payload = storage
                .values
                .get(&vault_id)
                .expect("vault payload should remain present");
            assert_eq!(
                metadata.record.environment_summaries,
                project_environment_summaries(payload).expect("payload should decode"),
                "failure point {failure_point} left mismatched records"
            );
            assert!(!storage.values.contains_key(TRANSACTION_MARKER_ACCOUNT));
            assert!(
                !storage
                    .values
                    .keys()
                    .any(|account| account.starts_with(TRANSACTION_STAGE_PREFIX))
            );
        }
    }

    #[test]
    fn committed_marker_recovery_reports_transaction_success() {
        let mut storage = MemoryProjectStorage {
            fail_committed_marker_verification_once: true,
            ..MemoryProjectStorage::default()
        };
        let payload = r#"{"environments":{"default":{"TOKEN":"secret"}}}"#;

        apply_project_transaction(
            &mut storage,
            vec![ProjectStorageMutation::write("vault-id", payload)],
        )
        .expect("successful committed recovery must acknowledge the transaction");

        assert_eq!(storage.values.get("vault-id"), Some(payload));
        assert!(!storage.values.contains_key(TRANSACTION_MARKER_ACCOUNT));
    }

    #[test]
    fn final_marker_delete_verification_failure_reports_transaction_success() {
        let mut storage = MemoryProjectStorage {
            fail_final_marker_delete_verification_once: true,
            ..MemoryProjectStorage::default()
        };
        let payload = r#"{"environments":{"default":{"TOKEN":"secret"}}}"#;

        apply_project_transaction(
            &mut storage,
            vec![ProjectStorageMutation::write("vault-id", payload)],
        )
        .expect("a durable committed transaction must report success");

        assert_eq!(storage.values.get("vault-id"), Some(payload));
        assert!(!storage.values.contains_key(TRANSACTION_MARKER_ACCOUNT));
    }

    #[test]
    fn committed_journal_rejects_a_redirected_write_target() {
        let transaction_id = "00000000-0000-4000-8000-000000000001";
        let stage = transaction_stage_account(transaction_id, 0);
        let payload = r#"{"environments":{"default":{"TOKEN":"secret"}}}"#;
        let journal = TransactionJournal {
            schema_version: TRANSACTION_SCHEMA_VERSION,
            transaction_id: transaction_id.to_owned(),
            state: TransactionState::Committed,
            operations: vec![TransactionJournalOperation {
                action: "write".to_owned(),
                target_account: "redirected-vault".to_owned(),
                staged_account: Some(stage.clone()),
                operation_sha256: transaction_operation_sha256(
                    "write",
                    "original-vault",
                    Some(payload.as_bytes()),
                ),
            }],
        };
        let mut storage = MemoryProjectStorage::default();
        storage.values.insert(
            TRANSACTION_MARKER_ACCOUNT.to_owned(),
            serde_json::to_string(&journal).expect("journal should encode"),
        );
        storage.values.insert(stage, payload.to_owned());

        assert!(
            recover_project_transaction(&mut storage).is_err(),
            "a target not bound by the operation digest must be rejected"
        );

        assert!(!storage.values.contains_key("redirected-vault"));
    }

    #[test]
    fn committed_journal_rejects_a_redirected_delete_target() {
        let transaction_id = "00000000-0000-4000-8000-000000000001";
        let journal = TransactionJournal {
            schema_version: TRANSACTION_SCHEMA_VERSION,
            transaction_id: transaction_id.to_owned(),
            state: TransactionState::Committed,
            operations: vec![TransactionJournalOperation {
                action: "delete".to_owned(),
                target_account: "redirected-vault".to_owned(),
                staged_account: None,
                operation_sha256: transaction_operation_sha256("delete", "original-vault", None),
            }],
        };
        let mut storage = MemoryProjectStorage::default();
        storage.values.insert(
            TRANSACTION_MARKER_ACCOUNT.to_owned(),
            serde_json::to_string(&journal).expect("journal should encode"),
        );
        storage.values.insert(
            "redirected-vault".to_owned(),
            r#"{"environments":{"default":{}}}"#.to_owned(),
        );

        assert!(
            recover_project_transaction(&mut storage).is_err(),
            "a delete target not bound by the operation digest must be rejected"
        );

        assert!(storage.values.contains_key("redirected-vault"));
    }

    #[test]
    fn current_project_deletion_removes_its_discovery_records() {
        let fixture: ProjectIndexFixture =
            serde_json::from_str(include_str!("../tests/fixtures/project-index-v3.json"))
                .expect("shared project-index fixture should decode");
        let vault_id = fixture.project.id;
        let mut storage = MemoryProjectStorage::default();
        storage.values.extend(
            fixture
                .records
                .into_iter()
                .map(|record| (record.account, record.value)),
        );

        delete_vault_with_storage(&mut storage, &vault_id).expect("project should delete");

        assert!(
            list_vaults_with_storage(&mut storage)
                .expect("remaining index should decode")
                .is_empty()
        );
    }

    #[test]
    fn project_discovery_keeps_active_shards_densely_packed() {
        let mut storage = MemoryProjectStorage::default();
        let payload = r#"{"environments":{"default":{"TOKEN":"secret"}}}"#;

        for index in 0..1_000 {
            let vault_id = format!("vault-{index:04}");
            save_vault_data_with_storage(
                &mut storage,
                &vault_id,
                &format!("Project {index}"),
                &format!("/workspace/{vault_id}"),
                payload,
            )
            .expect("project should save");
        }

        let state =
            ensure_project_index_after_recovery(&mut storage).expect("project index should decode");
        storage.reads.clear();
        let project_count = list_vaults_with_storage(&mut storage)
            .expect("project index should remain discoverable")
            .len();
        let discovery_reads: usize = storage
            .reads
            .iter()
            .filter(|(account, _)| account.starts_with(PROJECT_DISCOVERY_PREFIX))
            .map(|(_, count)| count)
            .sum();

        assert_eq!(
            (
                state.marker.active_shards.len(),
                discovery_reads,
                project_count
            ),
            (8, 8, 1_000)
        );
    }

    #[test]
    fn project_deletion_reopens_a_full_discovery_shard() {
        let mut storage = MemoryProjectStorage::default();
        let payload = r#"{"environments":{"default":{"TOKEN":"secret"}}}"#;

        for index in 0..MAX_PROJECT_DISCOVERY_SHARD_SIZE {
            let vault_id = format!("vault-{index:04}");
            save_vault_data_with_storage(
                &mut storage,
                &vault_id,
                &format!("Project {index}"),
                &format!("/workspace/{vault_id}"),
                payload,
            )
            .expect("project should save");
        }
        delete_vault_with_storage(&mut storage, "vault-0000").expect("project should delete");
        save_vault_data_with_storage(
            &mut storage,
            "replacement",
            "Replacement",
            "/workspace/replacement",
            payload,
        )
        .expect("replacement project should save");

        let state =
            ensure_project_index_after_recovery(&mut storage).expect("project index should decode");
        let shard = state.marker.active_shards[0];
        let project_count = read_project_discovery(&mut storage, shard, &state)
            .expect("project discovery should decode")
            .expect("project discovery should exist")
            .envelope
            .ids
            .len();

        assert_eq!(
            (
                state.marker.active_shards.len(),
                state.marker.writable_shard,
                project_count,
            ),
            (1, None, MAX_PROJECT_DISCOVERY_SHARD_SIZE)
        );
    }

    #[test]
    fn environments_wrapper_round_trips_multiple_environments() {
        let environments = HashMap::from([
            (
                "default".to_owned(),
                HashMap::from([("TOKEN".to_owned(), "one".to_owned())]),
            ),
            (
                "staging".to_owned(),
                HashMap::from([("TOKEN".to_owned(), "two".to_owned())]),
            ),
        ]);

        let json = serde_json::to_string(&EnvironmentsWrapper {
            environments: environments.clone(),
        })
        .unwrap();
        let decoded: EnvironmentsWrapper = serde_json::from_str(&json).unwrap();

        assert_eq!(decoded.environments, environments);
    }

    #[test]
    fn selected_environment_transfers_owned_secret_values() {
        let value = "secret-value".to_owned();
        let value_pointer = value.as_ptr();
        let environments = HashMap::from([(
            "default".to_owned(),
            HashMap::from([("TOKEN".to_owned(), value)]),
        )]);

        let selected = take_environment(environments, "default").unwrap();

        assert_eq!(selected["TOKEN"].as_ptr(), value_pointer);
    }

    #[test]
    fn x25519_promotion_verifies_the_live_write_once_before_deleting_pending() {
        let pending_account = "pending-x25519";
        let live_account = "live-x25519";
        let encoded = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, [7u8; 32]);
        let mut storage = MemoryProjectStorage::default();
        storage
            .values
            .insert(pending_account.to_owned(), encoded.clone());

        promote_x25519_private_key_accounts_with_storage(
            &mut storage,
            pending_account,
            live_account,
        )
        .expect("verified promotion should succeed");

        assert_eq!(storage.writes.get(live_account), Some(&1));
        assert_eq!(storage.reads.get(live_account), Some(&1));
        assert_eq!(storage.values.get(live_account), Some(encoded.as_str()));
        assert!(!storage.values.contains_key(pending_account));
    }

    #[test]
    fn x25519_promotion_preserves_pending_when_live_verification_fails() {
        let pending_account = "pending-x25519";
        let live_account = "live-x25519";
        let encoded = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, [7u8; 32]);
        let mut storage = MemoryProjectStorage::default();
        storage
            .values
            .insert(pending_account.to_owned(), encoded.clone());
        storage.ignored_writes.insert(live_account.to_owned());

        promote_x25519_private_key_accounts_with_storage(
            &mut storage,
            pending_account,
            live_account,
        )
        .expect_err("an unverified live key must not be promoted");

        assert_eq!(storage.values.get(pending_account), Some(encoded.as_str()));
        assert!(!storage.values.contains_key(live_account));
        assert!(!storage.deletes.contains_key(pending_account));
    }

    #[test]
    fn shared_access_group_matches_the_native_app_contract() {
        assert_eq!(
            crate::macos_keychain::SHARED_ACCESS_GROUP,
            "823S8YKMRW.dev.lpm.vault.shared"
        );
    }

    #[test]
    fn keychain_delete_outcomes_remain_distinct() {
        assert_ne!(
            crate::macos_keychain::KeychainDeleteOutcome::Deleted,
            crate::macos_keychain::KeychainDeleteOutcome::NotFound
        );
    }

    #[test]
    fn organization_slug_validation_matches_the_current_portable_contract() {
        assert!(is_valid_org_slug("a"));
        assert!(is_valid_org_slug(&"a".repeat(120)));
        assert!(!is_valid_org_slug(&"a".repeat(121)));
        assert!(!is_valid_org_slug("-team"));
        assert!(!is_valid_org_slug("_team"));
        assert!(!is_valid_org_slug("téam"));
    }

    #[test]
    fn current_project_index_records_reject_unknown_fields() {
        assert!(serde_json::from_str::<ProjectIndexMarker>(
            r#"{"schemaVersion":3,"storageId":"00000000-0000-4000-8000-000000000001","activeShards":[],"extra":true}"#
        )
        .is_err());
        assert!(serde_json::from_str::<ProjectMetadataRecord>(
            r#"{"schemaVersion":3,"storageId":"00000000-0000-4000-8000-000000000001","id":"vault","name":"Vault","path":"/tmp/vault","discoveryShard":0,"environmentSummaries":[],"extra":true}"#
        )
        .is_err());
        assert!(serde_json::from_str::<ProjectDiscoveryShard>(
            r#"{"schemaVersion":3,"storageId":"00000000-0000-4000-8000-000000000001","shard":0,"ids":[],"extra":true}"#
        )
        .is_err());
    }

    #[test]
    fn sync_metadata_transaction_target_requires_the_current_wire_contract() {
        let account = "__sync_metadata__:dmF1bHQ";
        let valid = r#"{"schemaVersion":3,"vaultId":"vault","metadata":{"lastSyncedAt":1.5,"lastAction":"pull","lastVersion":2,"isDirty":false,"binding":{"registryURL":"https://lpm.dev","principalID":"user-1","scope":"personal"},"checkpoints":[{"binding":{"registryURL":"https://lpm.dev","principalID":"user-1","scope":"personal"},"lastSyncedAt":1.5,"lastAction":"pull","lastVersion":2}]}}"#;
        let result = validate_transaction_sync_metadata(account, Some(valid));
        assert!(result.is_ok(), "{result:?}");

        let arbitrary = r#"{"schemaVersion":3,"vaultId":"vault","metadata":{}}"#;
        assert!(validate_transaction_sync_metadata(account, Some(arbitrary)).is_err());
        assert!(
            validate_transaction_sync_metadata("__sync_metadata__:dmF1bHQ=", Some(valid)).is_err()
        );

        assert!(
            validate_transaction_target("__sync_metadata_v2__:dmF1bHQ", Some(valid.as_bytes()))
                .is_err()
        );
        assert!(validate_transaction_target("__sync_metadata_v2_marker__", None).is_err());

        for invalid in [
            valid.replace("https://lpm.dev", "https://LPM.dev/"),
            valid.replace("\"personal\"", "\"team\""),
            valid.replace("\"pull\"", "\"merge\""),
            valid.replacen("\"lastVersion\":2", "\"lastVersion\":0", 1),
            valid.replacen("\"lastVersion\":2", "\"lastVersion\":3", 1),
            valid.replace("\"isDirty\":false", "\"isDirty\":false,\"extra\":true"),
        ] {
            assert!(
                validate_transaction_sync_metadata(account, Some(&invalid)).is_err(),
                "accepted {invalid}"
            );
        }
    }
}
