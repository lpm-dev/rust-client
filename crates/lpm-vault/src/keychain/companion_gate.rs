//! Companion storage on the macOS Keychain: the gate, lifecycle resume
//! through the transaction journal, and the read that applies personal
//! overrides.

use crate::companion::account::{CompanionAccount, marker_account, record_account};
use crate::companion::gate::{Damage, Operation, ProjectGate};
use crate::companion::lifecycle::{LifecycleStore, Mutation};
use crate::companion::overrides::OVERRIDES_KIND;
use crate::companion::{CompanionBackend, damaged};
use crate::macos_keychain::{ClaimedAccess, ProbeOutcome};

use super::{
    PROJECT_INDEX_MARKER_ACCOUNT, ProjectStorage, ProjectStorageMutation,
    apply_project_transaction_after_recovery,
};

pub(super) struct KeychainCompanion<'storage, S: ProjectStorage>(pub(super) &'storage mut S);

impl<S: ProjectStorage> LifecycleStore for KeychainCompanion<'_, S> {
    fn read(&mut self, account: &CompanionAccount) -> Result<Option<Vec<u8>>, String> {
        self.0.read(&account.name())
    }

    fn commit(&mut self, mutations: Vec<Mutation>) -> Result<(), String> {
        apply_project_transaction_after_recovery(
            self.0,
            mutations.into_iter().map(storage_mutation).collect(),
        )
    }
}

impl<S: ProjectStorage> CompanionBackend for KeychainCompanion<'_, S> {
    fn inventory(&mut self, vault_id: &str) -> Result<Vec<CompanionAccount>, String> {
        Ok(self
            .0
            .account_names()?
            .iter()
            .filter_map(|name| CompanionAccount::parse(name))
            .filter(|account| {
                account.vault_id() == vault_id
                    && !matches!(account, CompanionAccount::Marker { .. })
            })
            .collect())
    }
}

pub(super) fn storage_mutation(mutation: Mutation) -> ProjectStorageMutation {
    match mutation {
        Mutation::Write { account, value } => ProjectStorageMutation::write(account.name(), value),
        Mutation::Delete { account } => ProjectStorageMutation::delete(account.name()),
    }
}

pub(super) fn authorize(
    storage: &mut impl ProjectStorage,
    vault_id: &str,
    operation: Operation,
) -> Result<ProjectGate, String> {
    crate::companion::authorize(
        &mut KeychainCompanion(&mut super::ListedStorage::new(storage)),
        vault_id,
        operation,
    )
}

/// The values item's bytes and the personal overrides record, read in one
/// lock scope on one thread, so one approval covers both, with the gate that
/// decides what the record means.
pub(super) struct RunRead {
    pub(super) values: Option<Vec<u8>>,
    pub(super) gate: ProjectGate,
    pub(super) overrides_record: Option<Vec<u8>>,
}

/// Why the values item damages a project's access, when its approval
/// attributes contradict each other.
pub(super) const CONTRADICTORY_VALUES: &str =
    "the values' approval attributes contradict each other";

/// The values item's bytes with the approval they claim, read in one call.
/// Approval attributes that contradict each other damage the project's
/// access, which refuses every read.
fn read_values(
    storage: &mut impl ProjectStorage,
    vault_id: &str,
) -> Result<Option<(Vec<u8>, ClaimedAccess)>, String> {
    match storage.read_with_access(vault_id)? {
        Some((_, ClaimedAccess::Contradictory)) => {
            Err(damaged(Damage::Access(CONTRADICTORY_VALUES.to_owned())))
        }
        read => Ok(read),
    }
}

/// The values item's payload for a read that excludes personal overrides.
pub(super) fn read_values_excluding_overrides(
    storage: &mut impl ProjectStorage,
    vault_id: &str,
) -> Result<Option<String>, String> {
    authorize(storage, vault_id, Operation::ReadExcludingOverrides)?;
    read_values(storage, vault_id)?
        .map(|(bytes, _)| {
            String::from_utf8(bytes).map_err(|_| "vault keychain data is not UTF-8".to_owned())
        })
        .transpose()
}

pub(super) fn read_for_run(
    storage: &mut impl ProjectStorage,
    vault_id: &str,
) -> Result<RunRead, String> {
    let gate = authorize(storage, vault_id, Operation::ReadApplyingOverrides)?;
    let (values, values_access) = match read_values(storage, vault_id)? {
        Some((bytes, access)) => (Some(bytes), Some(access)),
        None => (None, None),
    };
    let overrides_account = record_account(OVERRIDES_KIND, vault_id, None);
    let record = match storage.read_with_access(&overrides_account)? {
        Some((_, ClaimedAccess::Contradictory)) => {
            return Err(damaged(Damage::Access(
                "the personal overrides' approval attributes contradict each other".to_owned(),
            )));
        }
        Some((bytes, access)) => {
            if values_access == Some(ClaimedAccess::RequireApproval)
                && access == ClaimedAccess::Automatic
            {
                match_values_approval(storage, vault_id, &overrides_account)?;
            }
            Some(bytes)
        }
        None => None,
    };
    Ok(RunRead {
        values,
        gate,
        overrides_record: record,
    })
}

/// A record that follows values but claims no approval while the values item
/// requires it, as a client that predates this check leaves it after turning
/// approval on: strengthen it before its bytes are used.
fn match_values_approval(
    storage: &mut impl ProjectStorage,
    vault_id: &str,
    account: &str,
) -> Result<(), String> {
    let marker = marker_account(vault_id);
    let open = [PROJECT_INDEX_MARKER_ACCOUNT, marker.as_str()];
    match storage.probe(account, &open) {
        ProbeOutcome::Protected => Ok(()),
        ProbeOutcome::Automatic => storage.require_approval(account, &open),
        ProbeOutcome::Absent => Err(format!("{account} disappeared while it was read")),
        ProbeOutcome::Inconclusive => Err(
            "the macOS Keychain is unavailable, so env approval couldn't be confirmed; retry once the Mac is unlocked"
                .to_owned(),
        ),
    }
}
