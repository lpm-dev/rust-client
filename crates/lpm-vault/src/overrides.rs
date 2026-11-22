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
use crate::companion::overrides::change::{
    ChangePlan, Inventory, InventoryNeed, PlanError, effects_without_overrides, plan_change,
};

/// Why a directory without an env project can't have overrides.
const NO_PROJECT: &str =
    "this directory has no env project yet; store a value first: lpm env set KEY";
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

/// Every environment's personal overrides of one env project, as a review
/// read them, for a change to commit to that project alone.
#[derive(Debug)]
pub struct Reviewed {
    vault_id: String,
    pub overrides: BTreeMap<String, PersonalOverrides>,
}

/// Every environment's personal overrides of the env project at
/// `project_dir`, for a change reviewed against them (see
/// [`change_reviewed`]); `None` without an env project.
pub fn review_all(project_dir: &Path) -> Result<Option<Reviewed>, String> {
    let Some(vault_id) = crate::linked_vault_id(project_dir)? else {
        return Ok(None);
    };
    let overrides = in_overrides_lock(|directory| read_all_unlocked(directory, &vault_id))?;
    Ok(Some(Reviewed {
        vault_id,
        overrides,
    }))
}

/// [`change`] for edits made from `reviewed`, refused when `project_dir`
/// names another project than the one it read.
pub fn change_reviewed(
    project_dir: &Path,
    reviewed: &Reviewed,
    edits: &[Edit],
) -> Result<Change, String> {
    let vault_id = reviewed.vault_id.as_str();
    if crate::linked_vault_id(project_dir)?.as_deref() != Some(vault_id) {
        return Err(
            "this directory's env project changed since its personal overrides were read; nothing was changed"
                .to_owned(),
        );
    }
    in_overrides_lock(|directory| change_unlocked(directory, vault_id, edits)).map(|plan| Change {
        effects: plan.effects,
        activated: plan.activated,
        over_admission_target: plan.over_admission_target,
    })
}

/// Apply `edits` to the personal overrides of the env project at
/// `project_dir`, all of them or none. A project needs values to have
/// overrides, which take their approval and live beside them; without
/// either, edits that give no key an override remove nothing and say so.
pub fn change(project_dir: &Path, edits: &[Edit]) -> Result<Change, String> {
    let Some(vault_id) = crate::linked_vault_id(project_dir)? else {
        return match effects_without_overrides(edits).map_err(|error| error.to_string())? {
            Some(effects) => Ok(Change {
                effects,
                activated: false,
                over_admission_target: false,
            }),
            None => Err(NO_PROJECT.to_owned()),
        };
    };
    in_overrides_lock(|directory| change_unlocked(directory, &vault_id, edits)).map(|plan| Change {
        effects: plan.effects,
        activated: plan.activated,
        over_admission_target: plan.over_admission_target,
    })
}

/// Refuse what a set or unset of `keys` in `environment` is refused for
/// whatever their values, before any value is read or asked for: an invalid
/// environment or name, a name LPM never passes to a process, no env project
/// here or no values for it on this computer, an interrupted step that can't
/// be finished, or newer data that refuses the change. It reads only the
/// marker and attributes, so it never asks for approval.
pub fn check_before_values(
    project_dir: &Path,
    environment: &str,
    keys: &[&str],
) -> Result<(), String> {
    let edits: Vec<Edit> = keys
        .iter()
        .map(|key| Edit::Unset {
            environment: environment.to_owned(),
            key: (*key).to_owned(),
        })
        .collect();
    effects_without_overrides(&edits).map_err(|error| error.to_string())?;
    let Some(vault_id) = crate::linked_vault_id(project_dir)? else {
        return Err(NO_PROJECT.to_owned());
    };
    crate::with_project_vault_transaction(|directory| check_unlocked(directory, &vault_id, &edits))
}

/// Plan `edits`, listing the store's companion records with `inventory`
/// only when the batch creates or deletes the record, and only what that
/// needs.
pub(crate) fn plan(
    vault_id: &str,
    gate: &ProjectGate,
    record: Option<&[u8]>,
    edits: &[Edit],
    inventory: impl FnOnce(InventoryNeed) -> Result<Inventory, String>,
) -> Result<ChangePlan, String> {
    match plan_change(vault_id, gate, record, edits, None) {
        Err(PlanError::NeedsInventory { need, .. }) => {
            let inventory = inventory(need)?;
            plan_change(vault_id, gate, record, edits, Some(&inventory))
        }
        planned => planned,
    }
    .map_err(|error| error.to_string())
}

/// `edits` to a project without values, as the engine plans them: those
/// that give no key an override remove nothing and say so; any other is
/// refused, with the ways to get values.
pub(crate) fn plan_without_values(
    gate: &ProjectGate,
    edits: &[Edit],
) -> Result<ChangePlan, String> {
    crate::companion::overrides::change::plan_without_values(gate, edits).map_err(|error| {
        match error {
            PlanError::NoValues => format!(
                "{error}; get its values with lpm env pull, or store one with lpm env set KEY"
            ),
            error => error.to_string(),
        }
    })
}

/// Plan carrying the environments a values write renames and removes, all
/// at once as it makes them, over to the project's personal overrides, in
/// the caller's lock before the values are written, so a refusal leaves
/// both as they were. Commit it with
/// [`write_all_environments_following_unlocked`](crate::write_all_environments_following_unlocked).
pub(crate) fn plan_following_unlocked(
    directory: &VaultStorageDirectory,
    vault_id: &str,
    renamed: Vec<(String, String)>,
    removed: Vec<String>,
) -> Result<Option<ChangePlan>, String> {
    if renamed.is_empty() && removed.is_empty() {
        return Ok(None);
    }
    let edits = [Edit::EnvironmentsChanged { renamed, removed }];
    let plan = if crate::force_file_vault_backend() {
        crate::fallback::companion::plan_overrides_unlocked(directory, vault_id, &edits)
    } else {
        #[cfg(target_os = "macos")]
        {
            crate::keychain::overrides::plan_unlocked(vault_id, &edits)
        }
        #[cfg(not(target_os = "macos"))]
        {
            crate::fallback::companion::plan_overrides_unlocked(directory, vault_id, &edits)
        }
    }?;
    Ok((!plan.mutations.is_empty()).then_some(plan))
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

fn check_unlocked(
    directory: &VaultStorageDirectory,
    vault_id: &str,
    edits: &[Edit],
) -> Result<(), String> {
    if crate::force_file_vault_backend() {
        return crate::fallback::companion::check_overrides_unlocked(directory, vault_id, edits);
    }
    #[cfg(target_os = "macos")]
    {
        let _ = directory;
        crate::keychain::overrides::check_unlocked(vault_id, edits)
    }
    #[cfg(not(target_os = "macos"))]
    {
        crate::fallback::companion::check_overrides_unlocked(directory, vault_id, edits)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fallback::tests::{force_file_vault, with_temp_vault_home};
    use crate::history::{Action, Source};

    fn store_value_and_override(dir: &Path) {
        crate::set(dir, &[("A", "1")], &Source::new(Action::Set)).expect("a value");
        change(
            dir,
            &[Edit::Set {
                environment: "default".to_owned(),
                key: "A".to_owned(),
                value: zeroize::Zeroizing::new("mine".to_owned()),
            }],
        )
        .expect("an override");
    }

    #[test]
    fn a_reviewed_change_is_refused_once_the_directory_names_another_project() {
        with_temp_vault_home(|home| {
            force_file_vault();
            let dir = home.join("project");
            std::fs::create_dir_all(&dir).expect("project dir");
            store_value_and_override(&dir);
            let reviewed = review_all(&dir).expect("review").expect("a project");
            assert!(reviewed.overrides.contains_key("default"));
            std::fs::write(dir.join("lpm.json"), r#"{"vault":"another-project"}"#)
                .expect("another project takes the folder");
            store_value_and_override(&dir);

            let refused = change_reviewed(
                &dir,
                &reviewed,
                &[Edit::Remove {
                    environment: "default".to_owned(),
                    key: "A".to_owned(),
                }],
            )
            .expect_err("the review read another project");

            assert!(refused.contains("nothing was changed"), "{refused}");
            assert_eq!(read_all(&dir).expect("read")["default"].set["A"], "mine");
        });
    }
}
