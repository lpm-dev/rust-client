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
    /// Never read with less approval than the values demand.
    fn read_overrides_beside_values(
        &mut self,
        vault_id: &str,
    ) -> Result<Option<crate::companion::Checked>, String> {
        use crate::companion::Checked;
        let Some(protected) = values_demand_approval(self.0, vault_id)? else {
            return Ok(None);
        };
        Ok(Some(
            read_overrides_record(self.0, vault_id, protected)?
                .map_or(Checked::Absent, Checked::Present),
        ))
    }

    fn inventory(&mut self, vault_id: &str) -> Result<Vec<CompanionAccount>, String> {
        let encoded = lpm_env_companion::account::encode_vault_id(vault_id);
        Ok(self
            .0
            .account_names_containing(&encoded)?
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
        Mutation::Write { account, value } => ProjectStorageMutation::Write {
            account: account.name(),
            value,
        },
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
    pub(super) values: Option<zeroize::Zeroizing<Vec<u8>>>,
    pub(super) gate: ProjectGate,
    pub(super) overrides_record: Option<zeroize::Zeroizing<Vec<u8>>>,
}

impl RunRead {
    /// `environment`'s personal overrides for a run. A project without
    /// values has none: overrides live beside values, and a record left
    /// without them is one LPM Vault collects, never applies.
    pub(super) fn overrides(
        &self,
        vault_id: &str,
        environment: &str,
    ) -> Result<crate::PersonalOverrides, String> {
        if self.values.is_none() {
            return Ok(crate::PersonalOverrides::default());
        }
        crate::companion::overrides::evaluate(
            &self.gate,
            vault_id,
            environment,
            self.overrides_record.as_ref().map(|bytes| bytes.as_slice()),
        )
        .map_err(damaged)
    }

    /// The values item's payload as text, wiped when dropped.
    pub(super) fn into_values_text(self) -> Result<Option<zeroize::Zeroizing<String>>, String> {
        self.values
            .map(|mut bytes| {
                crate::zeroizing_text(std::mem::take(&mut *bytes))
                    .map_err(|_| "vault keychain data is not valid UTF-8".to_owned())
            })
            .transpose()
    }

    /// Every environment's personal overrides for a run, as
    /// [`overrides`](Self::overrides) gives one environment's.
    pub(super) fn all_overrides(
        &self,
        vault_id: &str,
    ) -> Result<std::collections::BTreeMap<String, crate::PersonalOverrides>, String> {
        if self.values.is_none() {
            return Ok(std::collections::BTreeMap::new());
        }
        crate::companion::overrides::evaluate_all(
            &self.gate,
            vault_id,
            self.overrides_record.as_ref().map(|bytes| bytes.as_slice()),
        )
        .map_err(damaged)
    }
}

/// Why the values item damages a project's access, when its approval
/// attributes contradict each other.
pub(super) const CONTRADICTORY_VALUES: &str =
    "the values' approval attributes contradict each other";

/// Why an approval couldn't be verified while the Keychain is locked.
pub(super) const APPROVAL_UNCONFIRMED: &str = "the macOS Keychain is unavailable, so env approval couldn't be confirmed; retry once the Mac is unlocked";

/// Why the overrides record damages a project's access, when its approval
/// attributes contradict each other.
pub(super) const CONTRADICTORY_RECORD: &str =
    "the personal overrides' approval attributes contradict each other";

pub(super) fn contradictory_record() -> String {
    damaged(Damage::Access(CONTRADICTORY_RECORD.to_owned()))
}

/// The values item's bytes, wiped when dropped, with the approval they claim.
type ValuesRead = (zeroize::Zeroizing<Vec<u8>>, ClaimedAccess);

/// The values item's bytes with the approval they claim, read in one call.
/// Approval attributes that contradict each other damage the project's
/// access, which refuses every read.
fn read_values(
    storage: &mut impl ProjectStorage,
    vault_id: &str,
) -> Result<Option<ValuesRead>, String> {
    match storage.read_with_access(vault_id)? {
        None => Ok(None),
        Some((bytes, access)) => {
            let bytes = zeroize::Zeroizing::new(bytes);
            if access == ClaimedAccess::Contradictory {
                return Err(damaged(Damage::Access(CONTRADICTORY_VALUES.to_owned())));
            }
            Ok(Some((bytes, access)))
        }
    }
}

/// The values item's payload for a read that excludes personal overrides,
/// wiped when dropped.
pub(super) fn read_values_excluding_overrides(
    storage: &mut impl ProjectStorage,
    vault_id: &str,
) -> Result<Option<zeroize::Zeroizing<String>>, String> {
    authorize(storage, vault_id, Operation::ReadExcludingOverrides)?;
    read_values(storage, vault_id)?
        .map(|(mut bytes, _)| {
            crate::zeroizing_text(std::mem::take(&mut *bytes))
                .map_err(|_| "vault keychain data is not UTF-8".to_owned())
        })
        .transpose()
}

pub(super) fn read_for_run(
    storage: &mut impl ProjectStorage,
    vault_id: &str,
) -> Result<RunRead, String> {
    let gate = authorize(storage, vault_id, Operation::ReadApplyingOverrides)?;
    let Some((values, values_access)) = read_values(storage, vault_id)? else {
        return Ok(RunRead {
            values: None,
            gate,
            overrides_record: None,
        });
    };
    let account = record_account(OVERRIDES_KIND, vault_id, None);
    let record = match storage.read_with_access(&account)? {
        None => None,
        Some((bytes, access)) => {
            let bytes = zeroize::Zeroizing::new(bytes);
            match access {
                ClaimedAccess::Contradictory => return Err(contradictory_record()),
                // The values were just read under their approval, in this
                // lock scope on this thread, so a weaker record's bytes
                // expose nothing more; it's strengthened before they're used,
                // and a failure returns none of them.
                ClaimedAccess::Automatic if values_access == ClaimedAccess::RequireApproval => {
                    match_values_approval(storage, vault_id, &account)?;
                }
                ClaimedAccess::Automatic | ClaimedAccess::RequireApproval => {}
            }
            Some(bytes)
        }
    };
    Ok(RunRead {
        values: Some(values),
        gate,
        overrides_record: record,
    })
}

/// Whether the values item demands approval, for a read of what follows it
/// that doesn't read the values themselves: as its attributes claim when
/// they claim approval, and as a probe verifies it when they claim none, so
/// a record never takes less approval than the values really demand. `None`
/// without values; attributes that contradict each other damage the
/// project's access.
pub(super) fn values_demand_approval(
    storage: &mut impl ProjectStorage,
    vault_id: &str,
) -> Result<Option<bool>, String> {
    match storage.claimed_access(vault_id)? {
        None => Ok(None),
        Some(ClaimedAccess::Contradictory) => {
            Err(damaged(Damage::Access(CONTRADICTORY_VALUES.to_owned())))
        }
        Some(ClaimedAccess::RequireApproval) => Ok(Some(true)),
        Some(ClaimedAccess::Automatic) => {
            let marker = marker_account(vault_id);
            match storage.probe(vault_id, &[PROJECT_INDEX_MARKER_ACCOUNT, marker.as_str()]) {
                ProbeOutcome::Automatic => Ok(Some(false)),
                ProbeOutcome::Protected => Ok(Some(true)),
                ProbeOutcome::Absent => Ok(None),
                ProbeOutcome::Inconclusive => Err(APPROVAL_UNCONFIRMED.to_owned()),
            }
        }
    }
}

/// The personal overrides record for a list or a change, its bytes never
/// read with less approval than the values demand when `protected_values`
/// (see [`values_demand_approval`]). An absent record or one whose
/// attributes contradict each other is settled from its attributes without
/// a read. Whatever a record claims, a probe verifies its approval, and it's
/// strengthened when it has none, before it's read: a claim can be wrong
/// either way. Bytes read from a record that claimed approval but reads as
/// claiming none, as another process could leave it in between, are refused.
pub(super) fn read_overrides_record(
    storage: &mut impl ProjectStorage,
    vault_id: &str,
    protected_values: bool,
) -> Result<Option<zeroize::Zeroizing<Vec<u8>>>, String> {
    let overrides_account = record_account(OVERRIDES_KIND, vault_id, None);
    let mut claimed = None;
    if protected_values {
        match storage.claimed_access(&overrides_account)? {
            None => return Ok(None),
            Some(ClaimedAccess::Contradictory) => return Err(contradictory_record()),
            Some(claim) => {
                // A record just strengthened claims approval, so a read that
                // finds it claiming none was weakened in between.
                let strengthened = match_values_approval(storage, vault_id, &overrides_account)?;
                claimed = Some(if strengthened {
                    ClaimedAccess::RequireApproval
                } else {
                    claim
                });
            }
        }
    }
    match storage.read_with_access(&overrides_account)? {
        None => Ok(None),
        Some((bytes, access)) => {
            let bytes = zeroize::Zeroizing::new(bytes);
            match access {
                ClaimedAccess::Contradictory => Err(contradictory_record()),
                ClaimedAccess::Automatic if claimed == Some(ClaimedAccess::RequireApproval) => Err(
                    "the personal overrides' approval changed while they were read; try again"
                        .to_owned(),
                ),
                ClaimedAccess::Automatic | ClaimedAccess::RequireApproval => Ok(Some(bytes)),
            }
        }
    }
}

/// A record that follows values but claims no approval while the values item
/// requires it, as a client that predates this check leaves it after turning
/// approval on: strengthen it before its bytes are used. True when it was
/// strengthened, rather than protected already.
pub(super) fn match_values_approval(
    storage: &mut impl ProjectStorage,
    vault_id: &str,
    account: &str,
) -> Result<bool, String> {
    let marker = marker_account(vault_id);
    let open = [PROJECT_INDEX_MARKER_ACCOUNT, marker.as_str()];
    match storage.probe(account, &open) {
        ProbeOutcome::Protected => Ok(false),
        ProbeOutcome::Automatic => storage.require_approval(account, &open).map(|()| true),
        ProbeOutcome::Absent => Err(format!("{account} disappeared while it was read")),
        ProbeOutcome::Inconclusive => Err(APPROVAL_UNCONFIRMED.to_owned()),
    }
}
