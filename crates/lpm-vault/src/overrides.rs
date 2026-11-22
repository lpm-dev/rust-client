//! Personal overrides on this computer: every environment's, and changes to
//! them, each in one lock. The engine plans every change, and the store
//! that holds the project's companion records commits it in one
//! transaction, after any interrupted step is finished. Overrides never
//! leave this computer and are never recorded in local history.

use std::collections::BTreeMap;
use std::path::Path;

pub use lpm_env_companion::marker::MAX_RECORD_BYTES;
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

/// The env project a command checked or read before it asked for anything,
/// for a change committed to that project alone.
#[derive(Debug)]
pub struct Project {
    vault_id: String,
}

impl Project {
    /// The project `project_dir` names now, refused unless it's this one:
    /// the folder may name another since this one was checked.
    fn still_named(&self, project_dir: &Path, unchanged: &str) -> Result<&str, String> {
        if crate::linked_vault_id(project_dir)?.as_deref() == Some(self.vault_id.as_str()) {
            Ok(&self.vault_id)
        } else {
            Err(format!("this directory's env project changed {unchanged}"))
        }
    }
}

/// Every environment's personal overrides of one env project, as a review
/// read them, for removals to commit to that project alone, only while what
/// they remove is what it read.
#[derive(Debug)]
pub struct Reviewed {
    project: Project,
    pub overrides: BTreeMap<String, PersonalOverrides>,
}

/// Every environment's personal overrides of the env project at
/// `project_dir`, for removals reviewed against them (see
/// [`remove_reviewed`]); `None` without an env project.
pub fn review_all(project_dir: &Path) -> Result<Option<Reviewed>, String> {
    let Some(vault_id) = crate::linked_vault_id(project_dir)? else {
        return Ok(None);
    };
    let overrides = in_overrides_lock(|directory| read_all_unlocked(directory, &vault_id))?;
    Ok(Some(Reviewed {
        project: Project { vault_id },
        overrides,
    }))
}

/// Remove the overrides `removals` name, as [`change`] would, refused when
/// `project_dir` names another project than the one `reviewed` read, or when
/// an override it would remove changed since: set to another value, set where
/// it was unset or the reverse, or removed. An override another command added
/// meanwhile stays.
pub fn remove_reviewed(
    project_dir: &Path,
    reviewed: &Reviewed,
    removals: &[(String, String)],
) -> Result<Change, String> {
    const CHANGED: &str = "since its personal overrides were read; nothing was changed";
    let vault_id = reviewed.project.still_named(project_dir, CHANGED)?;
    let edits: Vec<Edit> = removals
        .iter()
        .map(|(environment, key)| Edit::Remove {
            environment: environment.clone(),
            key: key.clone(),
        })
        .collect();
    in_overrides_lock(|directory| {
        let current = read_all_unlocked(directory, vault_id)?;
        if removals.iter().any(|(environment, key)| {
            decision(&reviewed.overrides, environment, key) != decision(&current, environment, key)
        }) {
            return Err(
                "a personal override it asked about changed while it asked; nothing was changed"
                    .to_owned(),
            );
        }
        drop(current);
        change_unlocked(directory, vault_id, &edits)
    })
    .map(|plan| Change {
        effects: plan.effects,
        activated: plan.activated,
        over_admission_target: plan.over_admission_target,
    })
}

/// What `all` decides for `key` in `environment`: its value when set, and
/// whether it's unset; `None` without overrides there.
fn decision<'all>(
    all: &'all BTreeMap<String, PersonalOverrides>,
    environment: &str,
    key: &str,
) -> Option<(Option<&'all str>, bool)> {
    all.get(environment).map(|overrides| {
        (
            overrides.set.get(key).map(String::as_str),
            overrides.unset.iter().any(|unset| unset == key),
        )
    })
}

/// [`change`] for edits to `project`, the one [`check_before_values`]
/// checked, refused when `project_dir` names another project since.
pub fn change_checked(
    project_dir: &Path,
    project: &Project,
    edits: &[Edit],
) -> Result<Change, String> {
    let vault_id = project.still_named(
        project_dir,
        "while its values were asked for; nothing was stored",
    )?;
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
/// marker and attributes; only finishing an interrupted step can ask for
/// approval. The project it checked is the one [`change_checked`] commits
/// to.
pub fn check_before_values(
    project_dir: &Path,
    environment: &str,
    keys: &[&str],
) -> Result<Project, String> {
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
    crate::with_project_vault_transaction(|directory| {
        check_unlocked(directory, &vault_id, &edits)
    })?;
    Ok(Project { vault_id })
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
            let manifest = dir.join("lpm.json");
            let reviewed_manifest = std::fs::read(&manifest).expect("the reviewed project");
            std::fs::write(&manifest, r#"{"vault":"another-project"}"#)
                .expect("another project takes the folder");
            store_value_and_override(&dir);

            let refused =
                remove_reviewed(&dir, &reviewed, &[("default".to_owned(), "A".to_owned())])
                    .expect_err("the review read another project");

            assert!(refused.contains("nothing was changed"), "{refused}");
            assert_eq!(read_all(&dir).expect("read")["default"].set["A"], "mine");
            std::fs::write(&manifest, reviewed_manifest).expect("the reviewed project returns");
            assert_eq!(
                read_all(&dir).expect("read")["default"].set["A"],
                "mine",
                "the reviewed project keeps its override too"
            );
        });
    }
}
