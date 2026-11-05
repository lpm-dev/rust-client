//! History's store on the macOS Keychain: records that follow values are
//! read with R2b parity and written with the values item's access; parts
//! are open.

use zeroize::Zeroizing;

use super::companion_gate::{KeychainCompanion, match_values_approval};
use super::{ClaimedAccess, CliAccess, KeychainProjectStorage, ListedStorage, ProjectStorage};
use crate::companion::CompanionBackend;
use crate::companion::account::CompanionAccount;
use crate::companion::graph::{AccessClass, record_access_class};
use crate::companion::lifecycle::{LifecycleStore, Mutation};
use crate::history::store::{AdmissionInventory, HistoryStore, RecordError};
use lpm_env_companion::history::admission;
use lpm_env_companion::keyring::Approval;

/// The Keychain as history's store, listing the service, and learning each
/// item's claimed approval, at most once.
pub(crate) struct KeychainHistory<'storage, S: ProjectStorage = KeychainProjectStorage> {
    storage: ListedStorage<'storage, S>,
}

impl<'storage, S: ProjectStorage> KeychainHistory<'storage, S> {
    pub(super) fn new(storage: &'storage mut S) -> Self {
        Self {
            storage: ListedStorage::new(storage),
        }
    }
}

/// Run `run` against the Keychain inside the caller's lock. It returns a
/// `Result` like the file store's, which can fail to open its folder.
#[allow(clippy::unnecessary_wraps)]
pub(crate) fn history_store<T>(
    run: impl FnOnce(&mut KeychainHistory<'_>) -> T,
) -> Result<T, String> {
    let mut storage = KeychainProjectStorage;
    Ok(run(&mut KeychainHistory::new(&mut storage)))
}

impl<S: ProjectStorage> LifecycleStore for KeychainHistory<'_, S> {
    fn read(&mut self, account: &CompanionAccount) -> Result<Option<Vec<u8>>, String> {
        KeychainCompanion(&mut self.storage).read(account)
    }

    fn commit(&mut self, mutations: Vec<Mutation>) -> Result<(), String> {
        KeychainCompanion(&mut self.storage).commit(mutations)
    }
}

impl<S: ProjectStorage> CompanionBackend for KeychainHistory<'_, S> {
    fn inventory(&mut self, vault_id: &str) -> Result<Vec<CompanionAccount>, String> {
        KeychainCompanion(&mut self.storage).inventory(vault_id)
    }
}

impl<S: ProjectStorage> HistoryStore for KeychainHistory<'_, S> {
    fn read_following_values(
        &mut self,
        account: &CompanionAccount,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, RecordError> {
        read_following_values(&mut self.storage, account)
    }

    fn replace(&mut self, account: &CompanionAccount, bytes: &[u8]) -> Result<(), String> {
        replace(&mut self.storage, account, bytes)
    }

    fn delete(&mut self, account: &CompanionAccount) -> Result<(), String> {
        self.storage.delete(&account.name()).map(|_| ())
    }

    fn admission_inventory(&mut self, vault_id: &str) -> Result<AdmissionInventory, String> {
        admission_inventory(&mut self.storage, vault_id)
    }

    fn claimed_approval(&mut self, vault_id: &str) -> Result<Approval, String> {
        claimed_approval(&mut self.storage, vault_id)
    }

    fn verified_approval(&mut self, vault_id: &str) -> Result<Option<Approval>, String> {
        verified_approval(&mut self.storage, vault_id)
    }
}

pub(super) fn read_following_values(
    storage: &mut impl ProjectStorage,
    account: &CompanionAccount,
) -> Result<Option<Zeroizing<Vec<u8>>>, RecordError> {
    let name = account.name();
    let Some((bytes, access)) = storage.read_with_access(&name)? else {
        return Ok(None);
    };
    let bytes = Zeroizing::new(bytes);
    match access {
        ClaimedAccess::Contradictory => {
            return Err(RecordError::Damaged(format!(
                "local history's {} record has approval attributes that contradict each other",
                account.kind().unwrap_or("marker")
            )));
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
        // The storage verifies its own write: the Keychain's reads it back
        // below this boundary, so reading it here would verify it twice.
        Some(AccessClass::Open) | None => storage
            .write_verified(&name, bytes)
            .map_err(|error| format!("local history couldn't write {name}: {error}")),
    }
}

/// The service's records for admission, and which rings this client can
/// trim without a prompt: its own, and those whose values item claims no
/// approval, or is gone. One listing, with no read per project.
pub(super) fn admission_inventory(
    storage: &mut impl ProjectStorage,
    vault_id: &str,
) -> Result<AdmissionInventory, String> {
    let mut claims: std::collections::HashMap<String, ClaimedAccess> =
        std::collections::HashMap::new();
    let mut accounts: Vec<CompanionAccount> = Vec::new();
    storage.for_each_account(&mut |name, claim| match CompanionAccount::parse(name) {
        Some(CompanionAccount::Marker { .. }) => {}
        Some(account) => accounts.push(account),
        None => {
            if claim != ClaimedAccess::Automatic {
                claims.insert(name.to_owned(), claim);
            }
        }
    })?;
    let rings = admission::rings(&accounts);
    let trimmable = rings
        .iter()
        .filter(|ring| {
            ring.vault_id == vault_id
                || matches!(
                    claims.get(ring.vault_id.as_str()),
                    None | Some(ClaimedAccess::Automatic)
                )
        })
        .map(|ring| ring.vault_id.clone())
        .collect();
    Ok(AdmissionInventory {
        count: accounts.len(),
        rings,
        trimmable,
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

/// The values item's verified access, as the journal verifies it before
/// staging records that follow values, a weak item that claims approval
/// strengthened first, so the key records the access its records get.
pub(super) fn verified_approval(
    storage: &mut impl ProjectStorage,
    vault_id: &str,
) -> Result<Option<Approval>, String> {
    Ok(
        super::probe_values_access(storage, vault_id, false)?.map(|access| match access {
            CliAccess::Automatic => Approval::Automatic,
            CliAccess::RequireApproval => Approval::Protected,
        }),
    )
}
