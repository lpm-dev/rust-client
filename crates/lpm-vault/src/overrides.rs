//! Personal overrides on this computer: every environment's, and changes to
//! them, each in one lock. The engine plans every change, and the store
//! that holds the project's companion records commits it in one
//! transaction, after any interrupted step is finished. Overrides never
//! leave this computer and are never recorded in local history.

use std::collections::BTreeMap;
use std::path::Path;

pub use lpm_env_companion::overrides::change::{Edit, Effect, Previous};

use crate::PersonalOverrides;
use crate::companion::gate::ProjectGate;
use crate::companion::overrides::change::{ChangePlan, Inventory, PlanError, plan_change};
use crate::storage_transaction::VaultStorageDirectory;

/// What a batch of edits did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Change {
    pub effects: Vec<Effect>,
    /// The batch gave the project its first override, so an LPM CLI from
    /// before personal overrides would now run it differently.
    pub activated: bool,
    /// This computer's env storage holds more newer data than it should.
    pub over_admission_target: bool,
}

/// Every environment's personal overrides of the env project at
/// `project_dir`, by environment; empty when it has none or no env project.
pub fn read_all(project_dir: &Path) -> Result<BTreeMap<String, PersonalOverrides>, String> {
    let Some(vault_id) = crate::linked_vault_id(project_dir)? else {
        return Ok(BTreeMap::new());
    };
    in_overrides_lock(|directory| read_all_unlocked(directory, &vault_id))
}

/// Apply `edits` to the personal overrides of the env project at
/// `project_dir`, all of them or none. The project must have values: its
/// overrides take their approval and live beside them.
pub fn change(project_dir: &Path, edits: &[Edit]) -> Result<Change, String> {
    let Some(vault_id) = crate::linked_vault_id(project_dir)? else {
        return Err(
            "this directory has no env project yet; store a value first: lpm env set KEY"
                .to_owned(),
        );
    };
    in_overrides_lock(|directory| change_unlocked(directory, &vault_id, edits)).map(|plan| Change {
        effects: plan.effects,
        activated: plan.activated,
        over_admission_target: plan.over_admission_target,
    })
}

/// Plan `edits`, listing the store's companion records with `inventory`
/// only when the batch creates or deletes the record.
pub(crate) fn plan(
    vault_id: &str,
    gate: &ProjectGate,
    record: Option<&[u8]>,
    edits: &[Edit],
    inventory: impl FnOnce() -> Result<Inventory, String>,
) -> Result<ChangePlan, String> {
    match plan_change(vault_id, gate, record, edits, None) {
        Err(PlanError::NeedsInventory) => {
            let inventory = inventory()?;
            plan_change(vault_id, gate, record, edits, Some(&inventory))
        }
        planned => planned,
    }
    .map_err(|error| error.to_string())
}

pub(crate) fn no_values(vault_id: &str) -> String {
    format!(
        "env project {vault_id} has no values on this computer, so it can't have personal overrides; store a value first: lpm env set KEY"
    )
}

/// Run `operation` inside the values lock as an overrides command: on
/// macOS, its one approval prompt says it's for the personal overrides.
fn in_overrides_lock<T>(
    operation: impl FnOnce(&VaultStorageDirectory) -> Result<T, String>,
) -> Result<T, String> {
    #[cfg(target_os = "macos")]
    {
        crate::macos_keychain::prompting_for_personal_overrides(|| {
            crate::with_project_vault_transaction(operation)
        })
    }
    #[cfg(not(target_os = "macos"))]
    {
        crate::with_project_vault_transaction(operation)
    }
}

fn read_all_unlocked(
    directory: &VaultStorageDirectory,
    vault_id: &str,
) -> Result<BTreeMap<String, PersonalOverrides>, String> {
    if crate::force_file_vault_backend() {
        return crate::fallback::companion::read_all_overrides_unlocked(directory, vault_id);
    }
    #[cfg(target_os = "macos")]
    {
        let _ = directory;
        crate::keychain::overrides::read_all_unlocked(vault_id)
    }
    #[cfg(not(target_os = "macos"))]
    {
        crate::fallback::companion::read_all_overrides_unlocked(directory, vault_id)
    }
}

fn change_unlocked(
    directory: &VaultStorageDirectory,
    vault_id: &str,
    edits: &[Edit],
) -> Result<ChangePlan, String> {
    if crate::force_file_vault_backend() {
        return crate::fallback::companion::change_overrides_unlocked(directory, vault_id, edits);
    }
    #[cfg(target_os = "macos")]
    {
        let _ = directory;
        crate::keychain::overrides::change_unlocked(vault_id, edits)
    }
    #[cfg(not(target_os = "macos"))]
    {
        crate::fallback::companion::change_overrides_unlocked(directory, vault_id, edits)
    }
}
