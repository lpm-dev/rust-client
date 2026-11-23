//! Reviewing and repairing a project's damaged companion data from the CLI,
//! which is the only client on Linux, Windows and Macs without LPM Vault.
//! The engine decides what's damaged and how each damage is repaired; a
//! repair runs only against the state the person reviewed.

use super::account::CompanionAccount;
use super::assessment::{Observed, Repair, assess_gate, gate_of, reads_overrides_record};
use super::lifecycle::{FoundMarker, execute, plan_discard};
use super::marker::Marker;
use super::overrides::OVERRIDES_KIND;
use super::{Checked, CompanionBackend};

/// What's damaged in one project's newer data, and how each problem is
/// repaired, in the order the engine found them. A repair runs it only on
/// the project it reviewed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompanionReview {
    vault_id: String,
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
    pub(crate) fn discard(vault_id: &str, description: String) -> Self {
        Self {
            vault_id: vault_id.to_owned(),
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

    /// The project this reviewed.
    pub(crate) fn vault_id(&self) -> &str {
        &self.vault_id
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
/// step can never be finished, if it can't; its records aren't read then,
/// since the approval that protects them can't be told, or what they hold
/// can't be trusted. Otherwise the overrides record is read only where the
/// listing shows it and the engine judges what it holds, and only beside
/// values.
pub(crate) fn review(
    backend: &mut impl CompanionBackend,
    vault_id: &str,
    access: Option<&str>,
    unfinished: Option<&str>,
) -> Result<CompanionReview, String> {
    let marker = backend.read(&marker_account(vault_id))?;
    let inventory = backend.inventory(vault_id)?;
    let gate = gate_of(vault_id, marker.as_deref());
    let contents_are_judged =
        reads_overrides_record(vault_id, &gate, Some(&inventory), access, unfinished);
    let mut unreadable_overrides = None;
    let overrides = if contents_are_judged {
        backend
            .read_overrides_beside_values(vault_id)?
            .map(|checked| match checked {
                Checked::Present(bytes) => Some(bytes),
                Checked::Absent => None,
                // Content that won't decrypt won't open as a record either, so
                // the engine judges it as it judges any record it can't open.
                Checked::Unreadable(reason) => {
                    unreadable_overrides = Some(reason);
                    Some(zeroize::Zeroizing::new(Vec::new()))
                }
            })
    } else {
        None
    };
    let history = match (unfinished, gate.marker()) {
        (None, Some(parsed)) => history_damage(backend, vault_id, parsed)?,
        _ => Vec::new(),
    };
    let assessment = assess_gate(
        vault_id,
        gate,
        Observed {
            marker: marker.as_deref(),
            inventory: Some(&inventory),
            overrides: overrides
                .as_ref()
                .map(|record| record.as_deref().map(Vec::as_slice)),
            access,
            unfinished,
            history: &history,
        },
    );
    let described = |damage: &super::gate::Damage| match (damage, &unreadable_overrides) {
        (super::gate::Damage::InvalidRecord { kind, .. }, Some(reason))
            if kind == OVERRIDES_KIND =>
        {
            super::gate::Damage::InvalidRecord {
                kind: kind.clone(),
                reason: format!("it can't be read: {reason}"),
            }
            .to_string()
        }
        _ => damage.to_string(),
    };
    Ok(CompanionReview {
        vault_id: vault_id.to_owned(),
        problems: assessment
            .every_damage()
            .map(|damage| CompanionProblem {
                description: described(damage),
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

/// What's wrong with local history's records beyond what the listing shows,
/// while the marker has history v1 on. A record the store holds but can't
/// read is damage; a store that failed fails the review, so a locked
/// Keychain or a cancelled prompt never offers to delete history.
fn history_damage(
    backend: &mut impl CompanionBackend,
    vault_id: &str,
    marker: &Marker,
) -> Result<Vec<super::gate::Damage>, String> {
    use lpm_env_companion::history::switch::MarkerHistory;
    use lpm_env_companion::history::{head_account, key_account, part_account};
    if MarkerHistory::of(Some(marker)) != MarkerHistory::On {
        return Ok(Vec::new());
    }
    let unreadable = |kind: &str, reason: String| super::gate::Damage::InvalidRecord {
        kind: kind.to_owned(),
        reason: format!("it can't be read: {reason}"),
    };
    let failed = |error: String| format!("local history couldn't be read: {error}");
    let head = match backend
        .read_checked(&head_account(vault_id))
        .map_err(failed)?
    {
        Checked::Present(head) => Some(head),
        Checked::Absent => None,
        Checked::Unreadable(reason) => return Ok(vec![unreadable("history-head", reason)]),
    };
    let key = match backend
        .read_checked(&key_account(vault_id))
        .map_err(failed)?
    {
        Checked::Present(key) => Some(key),
        Checked::Absent => None,
        Checked::Unreadable(reason) => return Ok(vec![unreadable("key", reason)]),
    };
    let mut failure = None;
    let damage = lpm_env_companion::history::read::check_records(
        vault_id,
        head.as_deref().map(Vec::as_slice),
        key.as_deref().map(Vec::as_slice),
        |part| match backend.read_checked(&part_account(vault_id, part)) {
            Ok(Checked::Present(mut sealed)) => {
                Some(std::borrow::Cow::Owned(std::mem::take(&mut *sealed)))
            }
            Ok(Checked::Absent) => None,
            // Content that won't decrypt won't open as a part either.
            Ok(Checked::Unreadable(_)) => Some(std::borrow::Cow::Owned(Vec::new())),
            Err(error) => {
                failure.get_or_insert(error);
                None
            }
        },
    );
    match failure {
        Some(error) => Err(failed(error)),
        None => Ok(damage),
    }
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
