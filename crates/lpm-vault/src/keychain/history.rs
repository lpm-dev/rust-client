//! History's store on the macOS Keychain: records that follow values are
//! read with R2b parity and written with the values item's access; parts
//! are open.

use zeroize::Zeroizing;

use super::companion_gate::{KeychainCompanion, match_values_approval};
use super::{
    ClaimedAccess, KeychainProjectStorage, ListedStorage, PROJECT_INDEX_MARKER_ACCOUNT,
    ProjectStorage,
};
use crate::companion::CompanionBackend;
use crate::companion::account::{CompanionAccount, marker_account};
use crate::companion::graph::{AccessClass, record_access_class};
use crate::companion::lifecycle::{LifecycleStore, Mutation};
use crate::history::store::{AdmissionInventory, HistoryStore};
use crate::macos_keychain::ProbeOutcome;
use lpm_env_companion::history::admission;
use lpm_env_companion::keyring::Approval;

/// The Keychain as history's store, listing the service at most once.
pub(crate) struct KeychainHistory<'storage> {
    storage: ListedStorage<'storage, KeychainProjectStorage>,
}

/// Run `run` against the Keychain inside the caller's lock. It returns a
/// `Result` like the file store's, which can fail to open its folder.
#[allow(clippy::unnecessary_wraps)]
pub(crate) fn history_store<T>(
    run: impl FnOnce(&mut KeychainHistory<'_>) -> T,
) -> Result<T, String> {
    let mut storage = KeychainProjectStorage;
    let mut history = KeychainHistory {
        storage: ListedStorage::new(&mut storage),
    };
    Ok(run(&mut history))
}

impl LifecycleStore for KeychainHistory<'_> {
    fn read(&mut self, account: &CompanionAccount) -> Result<Option<Vec<u8>>, String> {
        KeychainCompanion(&mut self.storage).read(account)
    }

    fn commit(&mut self, mutations: Vec<Mutation>) -> Result<(), String> {
        KeychainCompanion(&mut self.storage).commit(mutations)
    }
}

impl CompanionBackend for KeychainHistory<'_> {
    fn inventory(&mut self, vault_id: &str) -> Result<Vec<CompanionAccount>, String> {
        KeychainCompanion(&mut self.storage).inventory(vault_id)
    }
}

impl HistoryStore for KeychainHistory<'_> {
    fn read_following_values(
        &mut self,
        account: &CompanionAccount,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, String> {
        read_following_values(&mut self.storage, account)
    }

    fn replace(&mut self, account: &CompanionAccount, bytes: &[u8]) -> Result<(), String> {
        replace(&mut self.storage, account, bytes)
    }

    fn delete(&mut self, account: &CompanionAccount) -> Result<(), String> {
        self.storage.delete(&account.name()).map(|_| ())
    }

    fn admission_inventory(&mut self, _vault_id: &str) -> Result<AdmissionInventory, String> {
        admission_inventory(&mut self.storage)
    }

    fn claimed_approval(&mut self, vault_id: &str) -> Result<Approval, String> {
        claimed_approval(&mut self.storage, vault_id)
    }

    fn verified_approval(&mut self, vault_id: &str) -> Result<Option<Approval>, String> {
        verified_approval(&mut self.storage, vault_id)
    }

    fn writes_without_prompt(&mut self, vault_id: &str) -> Result<bool, String> {
        Ok(claimed_approval(&mut self.storage, vault_id)? == Approval::Automatic)
    }
}

pub(super) fn read_following_values(
    storage: &mut impl ProjectStorage,
    account: &CompanionAccount,
) -> Result<Option<Zeroizing<Vec<u8>>>, String> {
    let name = account.name();
    let Some((bytes, access)) = storage.read_with_access(&name)? else {
        return Ok(None);
    };
    let bytes = Zeroizing::new(bytes);
    match access {
        ClaimedAccess::Contradictory => {
            return Err(format!(
                "local history's {} record has approval attributes that contradict each other",
                account.kind().unwrap_or("marker")
            ));
        }
        ClaimedAccess::Automatic
            if storage.claimed_access(account.vault_id())?
                == Some(ClaimedAccess::RequireApproval) =>
        {
            match_values_approval(storage, account.vault_id(), &name)?;
        }
        ClaimedAccess::Automatic | ClaimedAccess::RequireApproval => {}
    }
    Ok(Some(bytes))
}

pub(super) fn replace(
    storage: &mut impl ProjectStorage,
    account: &CompanionAccount,
    bytes: &[u8],
) -> Result<(), String> {
    let name = account.name();
    match account
        .kind()
        .map(|kind| record_access_class(kind, account.part()))
    {
        Some(AccessClass::FollowsValues) => {
            storage.write_verified_with_access_from(&name, bytes, account.vault_id())
        }
        Some(AccessClass::Open) | None => {
            storage.write(&name, bytes)?;
            if storage.read(&name)?.as_deref() != Some(bytes) {
                return Err(format!("local history couldn't verify {name}"));
            }
            Ok(())
        }
    }
}

pub(super) fn admission_inventory(
    storage: &mut impl ProjectStorage,
) -> Result<AdmissionInventory, String> {
    let accounts: Vec<CompanionAccount> = storage
        .account_names()?
        .iter()
        .filter_map(|name| CompanionAccount::parse(name))
        .filter(|account| !matches!(account, CompanionAccount::Marker { .. }))
        .collect();
    Ok(AdmissionInventory {
        count: accounts.len(),
        rings: admission::rings(&accounts),
    })
}

pub(super) fn claimed_approval(
    storage: &mut impl ProjectStorage,
    vault_id: &str,
) -> Result<Approval, String> {
    match storage.claimed_access(vault_id)? {
        Some(ClaimedAccess::RequireApproval) => Ok(Approval::Protected),
        Some(ClaimedAccess::Contradictory) => {
            Err(super::companion_gate::CONTRADICTORY_VALUES.to_owned())
        }
        Some(ClaimedAccess::Automatic) | None => Ok(Approval::Automatic),
    }
}

pub(super) fn verified_approval(
    storage: &mut impl ProjectStorage,
    vault_id: &str,
) -> Result<Option<Approval>, String> {
    let marker = marker_account(vault_id);
    match storage.probe(vault_id, &[PROJECT_INDEX_MARKER_ACCOUNT, marker.as_str()]) {
        ProbeOutcome::Automatic => Ok(Some(Approval::Automatic)),
        ProbeOutcome::Protected => Ok(Some(Approval::Protected)),
        ProbeOutcome::Absent => Err(format!("env project {vault_id} has no values item")),
        ProbeOutcome::Inconclusive => Ok(None),
    }
}
