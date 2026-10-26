//! Reviewing and repairing a project's damaged companion data from the CLI,
//! which is the only client on Linux, Windows and Macs without LPM Vault.
//! The engine decides what's damaged and how each damage is repaired; a
//! repair runs only against the state the person reviewed.

use super::CompanionBackend;
use super::account::CompanionAccount;
use super::assessment::{Observed, Repair, assess};
use super::lifecycle::{FoundMarker, execute, plan_discard};
use super::marker::Marker;
use super::overrides::OVERRIDES_KIND;

/// What's damaged in a project's newer data, and how each problem is
/// repaired, in the order the engine found them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CompanionReview {
    pub problems: Vec<CompanionProblem>,
    /// The repairs that set every problem right, as the engine decides them.
    repairs: Vec<CompanionRepair>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompanionProblem {
    /// What's damaged, without any record's contents.
    pub description: String,
    /// The repair, or `None` when only switching the project's CLI approval
    /// in LPM Vault sets it right.
    pub repair: Option<CompanionRepair>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompanionRepair {
    /// Delete every companion record of the project. Its values stay.
    DiscardProject,
    /// Remove one feature and the records only it lists.
    RemoveFeature(String),
    /// Delete the records no feature lists.
    RemoveUnlisted,
}

impl CompanionRepair {
    /// What the repair does, as an instruction.
    pub fn describe(&self) -> String {
        match self {
            Self::DiscardProject => {
                "discard this env project's newer data; its values stay".to_owned()
            }
            Self::RemoveFeature(feature) => format!(
                "remove {} and the records only it uses",
                super::gate::feature_description(feature)
            ),
            Self::RemoveUnlisted => "delete the records no feature lists".to_owned(),
        }
    }
}

impl From<Repair> for CompanionRepair {
    fn from(repair: Repair) -> Self {
        match repair {
            Repair::DiscardProject => Self::DiscardProject,
            Repair::RemoveFeature(feature) => Self::RemoveFeature(feature),
            Repair::RemoveUnlisted => Self::RemoveUnlisted,
        }
    }
}

impl CompanionReview {
    /// A review of one problem that only discarding the newer data repairs,
    /// such as an interrupted change that can't be finished.
    pub(crate) fn discard(description: String) -> Self {
        Self {
            problems: vec![CompanionProblem {
                description,
                repair: Some(CompanionRepair::DiscardProject),
            }],
            repairs: vec![CompanionRepair::DiscardProject],
        }
    }

    /// The distinct repairs to run, a project-wide discard alone when one
    /// is needed, since it removes everything the others would.
    pub fn repairs(&self) -> &[CompanionRepair] {
        &self.repairs
    }
}

pub(crate) const CHANGED_SINCE_REVIEW: &str =
    "this env project's newer data changed since you reviewed it; run lpm env repair again";

fn marker_account(vault_id: &str) -> CompanionAccount {
    CompanionAccount::Marker {
        vault_id: vault_id.to_owned(),
    }
}

/// Review `vault_id`'s companion data as the engine judges it, after its
/// interrupted steps were finished. `access` is why the store found the
/// project's access damaged, if it did, and `unfinished` why its interrupted
/// step can never be finished, if it can't; its records aren't read then.
pub(crate) fn review(
    backend: &mut impl CompanionBackend,
    vault_id: &str,
    access: Option<&str>,
    unfinished: Option<&str>,
) -> Result<CompanionReview, String> {
    let marker = backend.read(&marker_account(vault_id))?;
    let inventory = backend.inventory(vault_id)?;
    let overrides = match unfinished {
        Some(_) => None,
        None => Some(backend.read(&CompanionAccount::Record {
            kind: OVERRIDES_KIND.to_owned(),
            vault_id: vault_id.to_owned(),
            part: None,
        })?),
    };
    let assessment = assess(
        vault_id,
        Observed {
            marker: marker.as_deref(),
            inventory: Some(&inventory),
            overrides: overrides.as_ref().map(Option::as_deref),
            access,
            unfinished,
        },
    );
    Ok(CompanionReview {
        problems: assessment
            .every_damage()
            .map(|damage| CompanionProblem {
                description: damage.to_string(),
                repair: assessment.repair(damage).map(CompanionRepair::from),
            })
            .collect(),
        repairs: assessment
            .repairs()
            .into_iter()
            .map(CompanionRepair::from)
            .collect(),
    })
}

/// Run every repair `reviewed` lists, after checking `vault_id` still shows
/// exactly that damage. Returns the repairs it ran. A discard runs on the
/// marker as it stands, so it never needs the interrupted step finished.
pub(crate) fn repair(
    backend: &mut impl CompanionBackend,
    vault_id: &str,
    access: Option<&str>,
    unfinished: Option<&str>,
    reviewed: &CompanionReview,
) -> Result<Vec<CompanionRepair>, String> {
    if review(backend, vault_id, access, unfinished)? != *reviewed {
        return Err(CHANGED_SINCE_REVIEW.to_owned());
    }
    let repairs = reviewed.repairs().to_vec();
    for repair in &repairs {
        let marker = backend
            .read(&marker_account(vault_id))?
            .map(|bytes| Marker::parse(vault_id, &bytes));
        let inventory = backend.inventory(vault_id)?;
        let valid = || match &marker {
            Some(Ok(marker)) => Ok(marker),
            _ => Err(CHANGED_SINCE_REVIEW.to_owned()),
        };
        let plan = match repair {
            CompanionRepair::DiscardProject => {
                let found = match &marker {
                    None => FoundMarker::Absent,
                    Some(Err(_)) => FoundMarker::Invalid,
                    Some(Ok(marker)) => FoundMarker::Valid(marker),
                };
                plan_discard(vault_id, found, inventory)?
            }
            CompanionRepair::RemoveFeature(feature) => {
                super::lifecycle::plan_feature_removal(valid()?, feature, inventory)?
            }
            CompanionRepair::RemoveUnlisted => {
                super::lifecycle::plan_unlisted_removal(valid()?, inventory)?
            }
        };
        execute(backend, plan)?;
    }
    super::forget(vault_id);
    Ok(repairs)
}
