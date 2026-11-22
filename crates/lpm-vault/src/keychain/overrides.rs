//! Personal overrides in the macOS Keychain: every environment's, read after
//! the Apply gate, and a batch of changes the engine plans and the
//! transaction journal commits, so the record takes the values item's
//! verified approval.

use std::collections::BTreeMap;

use crate::PersonalOverrides;
use crate::companion::gate::Operation;
use crate::companion::lifecycle::LifecycleStore as _;
use crate::companion::overrides::change::{ChangePlan, Edit, Inventory};
use crate::companion::{damaged, overrides};
use crate::macos_keychain::ClaimedAccess;

use super::ProjectStorage;
use super::companion_gate::{KeychainCompanion, authorize, read_overrides_record};

pub(crate) fn read_all_unlocked(
    vault_id: &str,
) -> Result<BTreeMap<String, PersonalOverrides>, String> {
    read_all_with_storage(&mut super::KeychainProjectStorage, vault_id)
}

pub(super) fn read_all_with_storage(
    storage: &mut impl ProjectStorage,
    vault_id: &str,
) -> Result<BTreeMap<String, PersonalOverrides>, String> {
    super::validate_vault_id(vault_id)?;
    let gate = authorize(storage, vault_id, Operation::ReadApplyingOverrides)?;
    let values_access = storage.claimed_access(vault_id)?;
    if values_access == Some(ClaimedAccess::Contradictory) {
        return Err(damaged(crate::companion::gate::Damage::Access(
            super::companion_gate::CONTRADICTORY_VALUES.to_owned(),
        )));
    }
    let record = read_overrides_record(storage, vault_id, values_access)?;
    overrides::evaluate_all(&gate, vault_id, record.as_deref()).map_err(damaged)
}

pub(crate) fn change_unlocked(vault_id: &str, edits: &[Edit]) -> Result<ChangePlan, String> {
    change_with_storage(&mut super::KeychainProjectStorage, vault_id, edits)
}

pub(super) fn change_with_storage(
    storage: &mut impl ProjectStorage,
    vault_id: &str,
    edits: &[Edit],
) -> Result<ChangePlan, String> {
    super::validate_vault_id(vault_id)?;
    let gate = authorize(storage, vault_id, Operation::Write)?;
    let values_access = match storage.claimed_access(vault_id)? {
        None => return Err(crate::overrides::no_values(vault_id)),
        Some(ClaimedAccess::Contradictory) => {
            return Err(damaged(crate::companion::gate::Damage::Access(
                super::companion_gate::CONTRADICTORY_VALUES.to_owned(),
            )));
        }
        access => access,
    };
    let record = read_overrides_record(storage, vault_id, values_access)?;
    let mut plan = crate::overrides::plan(vault_id, &gate, record.as_deref(), edits, || {
        let names = storage.account_names()?;
        Ok(Inventory::from_names(
            vault_id,
            names.iter().map(String::as_str),
        ))
    })?;
    let mutations = std::mem::take(&mut plan.mutations);
    if !mutations.is_empty() {
        if let Err(error) = KeychainCompanion(storage).commit(mutations) {
            crate::companion::forget(vault_id);
            return Err(error);
        }
        crate::companion::remember(vault_id, &plan.gate);
    }
    Ok(plan)
}
