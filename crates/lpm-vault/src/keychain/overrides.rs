//! Personal overrides in the macOS Keychain: every environment's, read after
//! the Apply gate, and a batch of changes the engine plans and the
//! transaction journal commits, so the record takes the values item's
//! verified approval.

use std::collections::BTreeMap;

use crate::companion::account::record_account;
use crate::companion::gate::{Operation, ProjectGate};
use crate::companion::lifecycle::LifecycleStore as _;
use crate::companion::overrides::change::{ChangePlan, Edit, Inventory, InventoryNeed};
use crate::companion::overrides::{self, OVERRIDES_KIND};
use crate::macos_keychain::ClaimedAccess;
use crate::overrides::Expect;

use super::companion_gate::{
    KeychainCompanion, authorize, contradictory_record, read_overrides_record,
    values_demand_approval,
};
use super::{ListedStorage, ProjectStorage};

pub(crate) fn read_all_unlocked(vault_id: &str) -> Result<crate::overrides::AllOverrides, String> {
    read_all_with_storage(&mut super::KeychainProjectStorage, vault_id)
}

pub(super) fn read_all_with_storage(
    storage: &mut impl ProjectStorage,
    vault_id: &str,
) -> Result<crate::overrides::AllOverrides, String> {
    super::validate_vault_id(vault_id)?;
    let gate = authorize(storage, vault_id, Operation::ReadApplyingOverrides)?;
    // Overrides live beside values: a project without them has none.
    let Some(protected_values) = values_demand_approval(storage, vault_id)? else {
        return Ok((BTreeMap::new(), None));
    };
    let record = read_overrides_record(storage, vault_id, protected_values)?;
    let overrides = overrides::evaluate_all(
        &gate,
        vault_id,
        record.as_ref().map(|bytes| bytes.as_slice()),
    )
    .map_err(crate::companion::damaged)?;
    Ok((
        overrides,
        record.map(|record| crate::OverridesIdentity::of(&record)),
    ))
}

/// Refuse what `edits` to `vault_id`'s overrides are refused for whatever
/// their values: an interrupted step that can't be finished, a gate that
/// refuses writes, no values, which overrides need, or a record whose
/// approval attributes contradict each other. It reads only the marker and
/// attributes; only finishing an interrupted step first can ask for approval.
pub(crate) fn check_unlocked(vault_id: &str, edits: &[Edit]) -> Result<(), String> {
    check_with_storage(&mut super::KeychainProjectStorage, vault_id, edits)
}

pub(super) fn check_with_storage(
    storage: &mut impl ProjectStorage,
    vault_id: &str,
    edits: &[Edit],
) -> Result<(), String> {
    super::validate_vault_id(vault_id)?;
    let mut listed = ListedStorage::new(storage);
    let gate = crate::companion::authorize(
        &mut KeychainCompanion(&mut listed),
        vault_id,
        Operation::Write,
    )?;
    // Whether values exist is all it needs, which their attributes say;
    // the change verifies their approval when it reads.
    match listed.claimed_access(vault_id)? {
        None => crate::overrides::plan_without_values(&gate, edits, Expect::Nothing).map(drop),
        Some(ClaimedAccess::Contradictory) => Err(crate::companion::damaged(
            crate::companion::gate::Damage::Access(
                super::companion_gate::CONTRADICTORY_VALUES.to_owned(),
            ),
        )),
        Some(_) => match listed.claimed_access(&record_account(OVERRIDES_KIND, vault_id, None))? {
            Some(ClaimedAccess::Contradictory) => Err(contradictory_record()),
            _ => Ok(()),
        },
    }
}

pub(crate) fn change_unlocked(
    vault_id: &str,
    edits: &[Edit],
    expect: Expect<'_>,
) -> Result<ChangePlan, String> {
    change_with_storage(&mut super::KeychainProjectStorage, vault_id, edits, expect)
}

/// Plan and commit `edits` through one listing of the service: the gate,
/// the inventory a plan asks for and the commit's own check all read it.
pub(super) fn change_with_storage(
    storage: &mut impl ProjectStorage,
    vault_id: &str,
    edits: &[Edit],
    expect: Expect<'_>,
) -> Result<ChangePlan, String> {
    super::validate_vault_id(vault_id)?;
    let mut listed = ListedStorage::new(storage);
    let mut plan = plan_listed(&mut listed, vault_id, edits, expect)?;
    let mutations = std::mem::take(&mut plan.mutations);
    if !mutations.is_empty() {
        if let Err(error) = KeychainCompanion(&mut listed).commit(mutations) {
            crate::companion::forget(vault_id);
            return Err(error);
        }
        crate::companion::remember(vault_id, &plan.gate);
    }
    Ok(plan)
}

/// Whether a change may write the project's overrides, and what it needs to.
enum Writable {
    WithoutValues(ProjectGate),
    WithValues {
        gate: ProjectGate,
        protected_values: bool,
    },
}

fn writable<S: ProjectStorage>(
    listed: &mut ListedStorage<'_, S>,
    vault_id: &str,
) -> Result<Writable, String> {
    let gate = crate::companion::authorize(
        &mut KeychainCompanion(&mut *listed),
        vault_id,
        Operation::Write,
    )?;
    Ok(match values_demand_approval(listed, vault_id)? {
        None => Writable::WithoutValues(gate),
        Some(protected_values) => Writable::WithValues {
            gate,
            protected_values,
        },
    })
}

/// Plan `edits` without committing them, through `listed`, which a values
/// write that commits them in its own transaction goes on to use.
pub(super) fn plan_listed<S: ProjectStorage>(
    listed: &mut ListedStorage<'_, S>,
    vault_id: &str,
    edits: &[Edit],
    expect: Expect<'_>,
) -> Result<ChangePlan, String> {
    let (gate, protected_values) = match writable(listed, vault_id)? {
        Writable::WithoutValues(gate) => {
            return crate::overrides::plan_without_values(&gate, edits, expect);
        }
        Writable::WithValues {
            gate,
            protected_values,
        } => (gate, protected_values),
    };
    let record = read_overrides_record(listed, vault_id, protected_values)?;
    crate::overrides::plan(
        vault_id,
        &gate,
        record.as_ref().map(|bytes| bytes.as_slice()),
        edits,
        expect,
        |need| {
            let names = listed.account_names()?;
            let names = names.iter().map(String::as_str);
            Ok(match need {
                InventoryNeed::Project => Inventory::project_from_names(vault_id, names),
                InventoryNeed::ProjectAndService => Inventory::from_names(vault_id, names),
            })
        },
    )
}
