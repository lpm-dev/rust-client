//! Changing personal overrides: one batch of edits, planned as one
//! transaction against the record and marker a client read inside its lock.
//!
//! The first override a project gets adds the `overrides` feature to its
//! marker, creating the marker when the project has none. Removing the last
//! one deletes the record and the feature entry together, and the marker
//! too when nothing else is left, so a project without overrides is exactly
//! as it was before it had any: no record a gate-aware client must read,
//! nothing the marker discloses, and no refusal an older client could meet.
//!
//! Environments: overrides are this computer's own, so only removing an
//! environment, or the person, removes them. A rename merges the
//! environment's overrides into its new name, each moved one replacing one
//! of the same name there; creating or duplicating an environment changes
//! none, and says how many the name already has, so a client can tell the
//! person about overrides it keeps.

use std::collections::BTreeMap;
use std::fmt;

use lpm_common::stored_env::{is_valid_environment_name, is_valid_variable_name};
use serde::Serialize;
use zeroize::Zeroizing;

use crate::account::{CompanionAccount, marker_account, record_account};
use crate::budgets::{self, Admission, OverBudget};
use crate::gate::{Damage, GateError, Operation, ProjectGate};
use crate::lifecycle::{Mutation, needs_resume, plan_feature_removal};
use crate::marker::{MAX_RECORD_BYTES, Marker, ProjectState};

use super::{OVERRIDES_KIND, OverridesRecord, VERSION, feature_entry};

/// One change to a project's personal overrides.
#[derive(Clone)]
pub enum Edit {
    /// Give `key` this computer's own value in `environment`; an empty
    /// string is a value.
    Set {
        environment: String,
        key: String,
        value: Zeroizing<String>,
    },
    /// Remove the project's value for `key` in `environment`, so a run gets
    /// none from the project.
    Unset { environment: String, key: String },
    /// Drop `key`'s override, set or unset, in `environment`.
    Remove { environment: String, key: String },
    /// Drop every override of `environment`.
    ClearEnvironment { environment: String },
    /// Drop every override of every environment.
    ClearAll,
    /// The project's environment `from` is now called `to`.
    EnvironmentRenamed { from: String, to: String },
    /// The project's environment was removed.
    EnvironmentRemoved { environment: String },
    /// The project's environment `from` was copied to `to`.
    EnvironmentDuplicated { from: String, to: String },
    /// The project has a new environment.
    EnvironmentCreated { environment: String },
}

impl fmt::Debug for Edit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Set {
                environment, key, ..
            } => formatter
                .debug_struct("Set")
                .field("environment", environment)
                .field("key", key)
                .finish_non_exhaustive(),
            Self::Unset { environment, key } => formatter
                .debug_struct("Unset")
                .field("environment", environment)
                .field("key", key)
                .finish(),
            Self::Remove { environment, key } => formatter
                .debug_struct("Remove")
                .field("environment", environment)
                .field("key", key)
                .finish(),
            Self::ClearEnvironment { environment } => formatter
                .debug_struct("ClearEnvironment")
                .field("environment", environment)
                .finish(),
            Self::ClearAll => formatter.write_str("ClearAll"),
            Self::EnvironmentRenamed { from, to } => formatter
                .debug_struct("EnvironmentRenamed")
                .field("from", from)
                .field("to", to)
                .finish(),
            Self::EnvironmentRemoved { environment } => formatter
                .debug_struct("EnvironmentRemoved")
                .field("environment", environment)
                .finish(),
            Self::EnvironmentDuplicated { from, to } => formatter
                .debug_struct("EnvironmentDuplicated")
                .field("from", from)
                .field("to", to)
                .finish(),
            Self::EnvironmentCreated { environment } => formatter
                .debug_struct("EnvironmentCreated")
                .field("environment", environment)
                .finish(),
        }
    }
}

/// What a key had before an edit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Previous {
    None,
    Set,
    Unset,
}

/// What one edit did, for the person: names and counts, never values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Effect {
    /// A set, unset or remove of one key. `changed` is false for a set to
    /// the value it had, an unset of a key already unset, and a remove of a
    /// key without an override.
    Key {
        environment: String,
        key: String,
        previous: Previous,
        changed: bool,
    },
    /// A clear of one environment, or of all of them when `None`.
    Cleared {
        environment: Option<String>,
        removed: usize,
    },
    EnvironmentRemoved {
        environment: String,
        removed: usize,
    },
    /// A rename moved `moved` overrides to the new name, where `replaced`
    /// of the same name gave way to them and `kept` others stayed.
    Moved {
        from: String,
        to: String,
        moved: usize,
        replaced: usize,
        kept: usize,
    },
    /// A duplicate copied none of `from`'s `count` overrides; `to` keeps
    /// the `existing` it had.
    NotCopied {
        from: String,
        to: String,
        count: usize,
        existing: usize,
    },
    /// A new environment keeps the `count` overrides its name already had.
    Existing {
        environment: String,
        count: usize,
    },
}

impl Effect {
    /// Whether the edit changed the overrides.
    fn changed(&self) -> bool {
        match self {
            Self::Key { changed, .. } => *changed,
            Self::Cleared { removed, .. } | Self::EnvironmentRemoved { removed, .. } => {
                *removed > 0
            }
            Self::Moved { moved, .. } => *moved > 0,
            Self::NotCopied { .. } | Self::Existing { .. } => false,
        }
    }
}

/// The names-only inventory a plan needs when it creates or deletes the
/// record: the project's companion records, markers excluded, and, to
/// create it, the service's count of companion and staged records.
#[derive(Debug, Clone, Default)]
pub struct Inventory {
    pub project: Vec<CompanionAccount>,
    pub service_records: Option<usize>,
}

/// What a plan asks an [`Inventory`] to hold.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum InventoryNeed {
    /// The project's records, to delete the record.
    Project,
    /// The project's records and the service's count, to create it.
    ProjectAndService,
}

impl Inventory {
    /// The inventory `names`, every account in the service, gives `vault_id`.
    pub fn from_names<'name>(
        vault_id: &str,
        names: impl IntoIterator<Item = &'name str> + Clone,
    ) -> Self {
        Self {
            service_records: Some(budgets::admission_count(names.clone())),
            ..Self::project_from_names(vault_id, names)
        }
    }

    /// The project's records among `names`, without the service's count.
    pub fn project_from_names<'name>(
        vault_id: &str,
        names: impl IntoIterator<Item = &'name str>,
    ) -> Self {
        Self {
            project: names
                .into_iter()
                .filter_map(CompanionAccount::parse)
                .filter(|account| {
                    account.vault_id() == vault_id
                        && !matches!(account, CompanionAccount::Marker { .. })
                })
                .collect(),
            service_records: None,
        }
    }
}

/// The transaction a batch of edits makes, empty when it changes nothing.
#[derive(Debug)]
pub struct ChangePlan {
    /// Commit these together, in one transaction.
    pub mutations: Vec<Mutation>,
    /// What the project's marker says once they're committed.
    pub gate: ProjectGate,
    pub effects: Vec<Effect>,
    /// The batch adds the `overrides` feature: the project had none before.
    pub activated: bool,
    /// The service holds more companion records than its target after the
    /// batch, which the person should hear about.
    pub over_admission_target: bool,
}

/// Why one edit can't be made.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EditError {
    InvalidEnvironment(String),
    /// A name that isn't a valid variable name, which is never repeated
    /// back: it may be a value typed in the wrong place.
    InvalidKey,
    DeniedName(String),
    NulValue(String),
    /// A rename, or a copy when `copy`, onto the environment itself.
    SameEnvironment {
        environment: String,
        copy: bool,
    },
}

impl EditError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidEnvironment(_) => "invalid_environment",
            Self::InvalidKey => "invalid_key",
            Self::DeniedName(_) => "denied_name",
            Self::NulValue(_) => "nul_value",
            Self::SameEnvironment { .. } => "same_environment",
        }
    }
}

impl fmt::Display for EditError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidEnvironment(name) => {
                write!(formatter, "{name:?} isn't a valid environment name")
            }
            Self::InvalidKey => {
                formatter.write_str("a personal override's name must match [A-Za-z_][A-Za-z0-9_]*")
            }
            Self::DeniedName(key) => write!(
                formatter,
                "LPM never passes a value for {key} to a process, so it can't be a personal override"
            ),
            Self::NulValue(key) => write!(
                formatter,
                "the personal override of {key} contains a NUL character, which no process environment can hold"
            ),
            Self::SameEnvironment { environment, copy } => write!(
                formatter,
                "environment {environment:?} can't be {} to itself",
                if *copy { "copied" } else { "renamed" }
            ),
        }
    }
}

/// Why a batch can't be planned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlanError {
    /// Edit `index` of the batch, counted from 0, can't be made.
    Edit {
        index: usize,
        reason: EditError,
    },
    TooLarge(usize),
    /// The gate refuses writes, for damage or a version this client
    /// doesn't support.
    Refused(GateError),
    NeedsResume,
    /// Ask again with an [`Inventory`] that holds what `need` names: the
    /// batch creates or deletes the record. `effects` are the edits' effects
    /// already, for a client that confirms before it lists the store.
    NeedsInventory {
        need: InventoryNeed,
        effects: Vec<Effect>,
    },
    OverBudget(OverBudget),
    AdmissionRefused(usize),
    /// Removing the last override takes more than the one transaction a
    /// client commits beside its own work, such as when interrupted steps
    /// left staged records; repairing the project removes them.
    RemovalNeedsRepair,
}

impl PlanError {
    /// A stable code for each kind of refusal.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Edit { reason, .. } => reason.code(),
            Self::TooLarge(_) => "too_large",
            Self::Refused(GateError::Damaged(_)) => "damaged",
            Self::Refused(GateError::Unsupported { .. }) => "unsupported",
            Self::NeedsResume => "needs_resume",
            Self::NeedsInventory { .. } => "needs_inventory",
            Self::OverBudget(_) => "over_budget",
            Self::AdmissionRefused(_) => "admission_refused",
            Self::RemovalNeedsRepair => "removal_needs_repair",
        }
    }
}

impl fmt::Display for PlanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Edit { reason, .. } => reason.fmt(formatter),
            Self::TooLarge(bytes) => {
                // Rounded up, so a size past the limit never reads as the limit.
                let tenths = bytes.saturating_mul(10).div_ceil(1024);
                write!(
                    formatter,
                    "the personal overrides would take {}.{} KiB, more than the {} KiB one record may hold",
                    tenths / 10,
                    tenths % 10,
                    MAX_RECORD_BYTES / 1024
                )
            }
            Self::Refused(error) => write!(formatter, "{error}"),
            Self::NeedsResume => {
                formatter.write_str("finish the env project's interrupted change first")
            }
            Self::NeedsInventory { .. } => formatter
                .write_str("the change creates or deletes a record, so it needs an inventory"),
            Self::OverBudget(over) => write!(formatter, "{over}"),
            Self::AdmissionRefused(count) => write!(
                formatter,
                "this computer's env storage holds {count} records of newer data, more than the {} it may; delete env projects you no longer use first",
                budgets::ADMISSION_CAP
            ),
            Self::RemovalNeedsRepair => formatter.write_str(
                "removing the last personal override needs the env project repaired first: run lpm env repair, then try again",
            ),
        }
    }
}

/// Plan `edits` for `vault_id`, given the gate and record read in the
/// caller's lock. An edit that changes nothing still reports its effect.
/// After [`PlanError::NeedsInventory`], plan the same edits again with one.
pub fn plan_change(
    vault_id: &str,
    gate: &ProjectGate,
    record: Option<&[u8]>,
    edits: &[Edit],
    inventory: Option<&Inventory>,
) -> Result<ChangePlan, PlanError> {
    plan_change_with_case_policy(vault_id, gate, record, edits, inventory, cfg!(windows))
}

pub(super) fn plan_change_with_case_policy(
    vault_id: &str,
    gate: &ProjectGate,
    record: Option<&[u8]>,
    edits: &[Edit],
    inventory: Option<&Inventory>,
    case_insensitive: bool,
) -> Result<ChangePlan, PlanError> {
    if gate.marker().is_some_and(needs_resume) {
        return Err(PlanError::NeedsResume);
    }
    gate.authorize(Operation::Write)
        .map_err(PlanError::Refused)?;
    let mut next = Overrides::stored(gate, vault_id, record, case_insensitive)?;
    let mut effects = Vec::with_capacity(edits.len());
    let mut changed = false;
    for (index, edit) in edits.iter().enumerate() {
        let effect = next
            .apply(edit)
            .map_err(|reason| PlanError::Edit { index, reason })?;
        changed |= effect.changed();
        effects.push(effect);
    }

    let unchanged = ChangePlan {
        mutations: Vec::new(),
        gate: gate.clone(),
        effects: Vec::new(),
        activated: false,
        over_admission_target: false,
    };
    let record_account = record_account(OVERRIDES_KIND, vault_id, None);
    let account = CompanionAccount::parse(&record_account)
        .expect("the overrides account is spelled the one valid way");
    match (record.is_some(), next.is_empty()) {
        (false, true) => {
            return Ok(ChangePlan {
                effects,
                ..unchanged
            });
        }
        // A record left with no overrides goes too, even one an edit didn't
        // empty, as another client may have written it.
        (true, true) => {
            let Some(inventory) = inventory else {
                return Err(PlanError::NeedsInventory {
                    need: InventoryNeed::Project,
                    effects,
                });
            };
            let (mutations, gate) = plan_record_removal(gate, vault_id, account, inventory)?;
            return Ok(ChangePlan {
                mutations,
                gate,
                effects,
                ..unchanged
            });
        }
        (_, false) if !changed => {
            return Ok(ChangePlan {
                effects,
                ..unchanged
            });
        }
        (true, false) | (false, false) => {}
    }

    let write = Mutation::Write {
        account: account.clone(),
        value: next.encode(vault_id)?,
    };
    if record.is_some() {
        return Ok(ChangePlan {
            mutations: vec![write],
            effects,
            ..unchanged
        });
    }

    let Some(Inventory {
        project,
        service_records: Some(service_records),
    }) = inventory
    else {
        return Err(PlanError::NeedsInventory {
            need: InventoryNeed::ProjectAndService,
            effects,
        });
    };
    budgets::check_project(project.iter().chain(std::iter::once(&account)))
        .map_err(PlanError::OverBudget)?;
    let over_admission_target = match budgets::admit(*service_records, 1) {
        Admission::Admitted => false,
        Admission::OverTarget => true,
        Admission::Refused => {
            return Err(PlanError::AdmissionRefused(*service_records));
        }
    };
    let mut marker = gate
        .marker()
        .cloned()
        .unwrap_or_else(|| Marker::empty(vault_id, ProjectState::Active));
    marker
        .features
        .insert(OVERRIDES_KIND.to_owned(), feature_entry());
    let marker_bytes = marker
        .encode()
        .map_err(|error| PlanError::Refused(GateError::Damaged(error.into())))?;
    Ok(ChangePlan {
        mutations: vec![
            Mutation::Write {
                account: CompanionAccount::parse(&marker_account(vault_id))
                    .expect("the marker account is spelled the one valid way"),
                value: Zeroizing::new(marker_bytes),
            },
            write,
        ],
        gate: ProjectGate::Marked(marker),
        effects,
        activated: true,
        over_admission_target,
    })
}

/// Delete the record and its feature entry, and the marker when nothing
/// else is left, in one transaction. The record is deleted whether or not
/// the inventory listed it, and a name listed twice is one record.
fn plan_record_removal(
    gate: &ProjectGate,
    vault_id: &str,
    record: CompanionAccount,
    inventory: &Inventory,
) -> Result<(Vec<Mutation>, ProjectGate), PlanError> {
    // A stored record that passed the gate is listed by the marker.
    let Some(marker) = gate.marker() else {
        return Err(PlanError::Refused(GateError::Damaged(
            Damage::UnlistedRecord {
                kind: OVERRIDES_KIND.to_owned(),
            },
        )));
    };
    let mut project = inventory.project.clone();
    project.push(record);
    project.sort_unstable_by_key(CompanionAccount::name);
    project.dedup();
    let mut plan = plan_feature_removal(marker, OVERRIDES_KIND, project)
        .map_err(|_| PlanError::RemovalNeedsRepair)?;
    if plan.transactions.len() > 1 {
        return Err(PlanError::RemovalNeedsRepair);
    }
    let mutations = match plan.transactions.pop() {
        Some(transaction) => transaction
            .into_deletions(vault_id)
            .map_err(|_| PlanError::RemovalNeedsRepair)?,
        None => Vec::new(),
    };
    Ok((
        mutations,
        plan.result.map_or(ProjectGate::Plain, ProjectGate::Marked),
    ))
}

/// What `edits` do to a project that has no overrides, such as one without
/// values beside which none can live: their effects when none of them gives
/// a key an override, so a removal of nothing succeeds and says so; `None`
/// when one does.
pub fn effects_without_overrides(edits: &[Edit]) -> Result<Option<Vec<Effect>>, PlanError> {
    let mut none = Overrides {
        case_insensitive: cfg!(windows),
        ..Overrides::default()
    };
    let mut effects = Vec::with_capacity(edits.len());
    for (index, edit) in edits.iter().enumerate() {
        effects.push(
            none.apply(edit)
                .map_err(|reason| PlanError::Edit { index, reason })?,
        );
    }
    Ok(none.is_empty().then_some(effects))
}

/// What an override decides for one name.
#[derive(Clone, PartialEq, Eq)]
enum Decision {
    Set(Zeroizing<String>),
    Unset,
}

/// One name's override, under the spelling it was given.
#[derive(Clone, PartialEq, Eq)]
struct Named {
    spelling: String,
    decision: Decision,
}

/// Each environment's overrides, keyed by the name the host compares: the
/// name itself, or its ASCII uppercase where the host ignores case.
#[derive(Default)]
struct Overrides {
    environments: BTreeMap<String, BTreeMap<String, Named>>,
    case_insensitive: bool,
}

impl Overrides {
    fn stored(
        gate: &ProjectGate,
        vault_id: &str,
        record: Option<&[u8]>,
        case_insensitive: bool,
    ) -> Result<Self, PlanError> {
        let mut stored = super::evaluate_with(gate, record, |bytes, version| {
            super::parse_record(bytes, vault_id, version, case_insensitive)
                .map(|record| Self::from_record(record, case_insensitive))
        })
        .map_err(|damage| PlanError::Refused(GateError::Damaged(damage)))?;
        stored.case_insensitive = case_insensitive;
        Ok(stored)
    }

    fn from_record(record: OverridesRecord, case_insensitive: bool) -> Self {
        let mut overrides = Self {
            environments: BTreeMap::new(),
            case_insensitive,
        };
        for (environment, entry) in record.environments {
            let names = overrides.environments.entry(environment).or_default();
            for (key, value) in entry.set {
                names.insert(
                    match_key(&key, case_insensitive),
                    Named {
                        spelling: key,
                        decision: Decision::Set(Zeroizing::new(value)),
                    },
                );
            }
            for key in entry.unset {
                names.insert(
                    match_key(&key, case_insensitive),
                    Named {
                        spelling: key,
                        decision: Decision::Unset,
                    },
                );
            }
        }
        overrides
    }

    fn is_empty(&self) -> bool {
        self.environments.is_empty()
    }

    fn count(&self, environment: &str) -> usize {
        self.environments.get(environment).map_or(0, BTreeMap::len)
    }

    fn apply(&mut self, edit: &Edit) -> Result<Effect, EditError> {
        match edit {
            Edit::Set {
                environment,
                key,
                value,
            } => {
                check_settable(environment, key)?;
                if value.contains('\0') {
                    return Err(EditError::NulValue(key.clone()));
                }
                Ok(self.decide(environment, key, Some(Decision::Set(value.clone()))))
            }
            Edit::Unset { environment, key } => {
                check_settable(environment, key)?;
                Ok(self.decide(environment, key, Some(Decision::Unset)))
            }
            Edit::Remove { environment, key } => {
                check_environment(environment)?;
                if !is_valid_variable_name(key) {
                    return Err(EditError::InvalidKey);
                }
                Ok(self.decide(environment, key, None))
            }
            Edit::ClearEnvironment { environment } => {
                check_environment(environment)?;
                Ok(Effect::Cleared {
                    environment: Some(environment.clone()),
                    removed: self.take(environment),
                })
            }
            Edit::ClearAll => {
                let removed = self.environments.values().map(BTreeMap::len).sum();
                self.environments.clear();
                Ok(Effect::Cleared {
                    environment: None,
                    removed,
                })
            }
            Edit::EnvironmentRenamed { from, to } => {
                check_two_environments(from, to, false)?;
                let names = self.environments.remove(from).unwrap_or_default();
                let moved = names.len();
                let target = self.environments.entry(to.clone()).or_default();
                let before = target.len();
                let mut replaced = 0;
                for (matched, named) in names {
                    replaced += usize::from(target.insert(matched, named).is_some());
                }
                let kept = before - replaced;
                if target.is_empty() {
                    self.environments.remove(to);
                }
                Ok(Effect::Moved {
                    from: from.clone(),
                    to: to.clone(),
                    moved,
                    replaced,
                    kept,
                })
            }
            Edit::EnvironmentRemoved { environment } => {
                check_environment(environment)?;
                Ok(Effect::EnvironmentRemoved {
                    environment: environment.clone(),
                    removed: self.take(environment),
                })
            }
            Edit::EnvironmentDuplicated { from, to } => {
                check_two_environments(from, to, true)?;
                Ok(Effect::NotCopied {
                    from: from.clone(),
                    to: to.clone(),
                    count: self.count(from),
                    existing: self.count(to),
                })
            }
            Edit::EnvironmentCreated { environment } => {
                check_environment(environment)?;
                Ok(Effect::Existing {
                    environment: environment.clone(),
                    count: self.count(environment),
                })
            }
        }
    }

    /// Drop every override of `environment`, and say how many it had.
    fn take(&mut self, environment: &str) -> usize {
        self.environments
            .remove(environment)
            .map_or(0, |names| names.len())
    }

    /// Give `key` `decision` in `environment`, or drop its override for
    /// `None`, replacing a name the host can't tell apart from it.
    fn decide(&mut self, environment: &str, key: &str, decision: Option<Decision>) -> Effect {
        let matched = match_key(key, self.case_insensitive);
        let names = self.environments.entry(environment.to_owned()).or_default();
        let previous = match names.get(&matched).map(|named| &named.decision) {
            None => Previous::None,
            Some(Decision::Set(_)) => Previous::Set,
            Some(Decision::Unset) => Previous::Unset,
        };
        let changed = match decision {
            Some(decision) => {
                let unchanged = names
                    .get(&matched)
                    .is_some_and(|named| named.spelling == key && named.decision == decision);
                if !unchanged {
                    names.insert(
                        matched,
                        Named {
                            spelling: key.to_owned(),
                            decision,
                        },
                    );
                }
                !unchanged
            }
            None => names.remove(&matched).is_some(),
        };
        if names.is_empty() {
            self.environments.remove(environment);
        }
        Effect::Key {
            environment: environment.to_owned(),
            key: key.to_owned(),
            previous,
            changed,
        }
    }

    /// The record's canonical bytes: environments, names and the unset list
    /// in order, so the same overrides always encode alike.
    fn encode(&self, vault_id: &str) -> Result<Zeroizing<Vec<u8>>, PlanError> {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Record<'a> {
            schema_version: u16,
            vault_id: &'a str,
            environments: BTreeMap<&'a str, Entry<'a>>,
        }
        #[derive(Serialize)]
        struct Entry<'a> {
            set: BTreeMap<&'a str, &'a str>,
            unset: Vec<&'a str>,
        }
        let environments = self
            .environments
            .iter()
            .map(|(environment, names)| {
                let mut entry = Entry {
                    set: BTreeMap::new(),
                    unset: Vec::new(),
                };
                for named in names.values() {
                    match &named.decision {
                        Decision::Set(value) => {
                            entry.set.insert(&named.spelling, value);
                        }
                        Decision::Unset => entry.unset.push(&named.spelling),
                    }
                }
                entry.unset.sort_unstable();
                (environment.as_str(), entry)
            })
            .collect();
        let record = Record {
            schema_version: VERSION,
            vault_id,
            environments,
        };
        // Measured first, so the buffer that holds the values never grows
        // and leaves an unwiped copy behind.
        let mut length = ByteCount(0);
        serde_json::to_writer(&mut length, &record)
            .map_err(|_| PlanError::TooLarge(MAX_RECORD_BYTES + 1))?;
        if length.0 > MAX_RECORD_BYTES {
            return Err(PlanError::TooLarge(length.0));
        }
        let mut bytes = Zeroizing::new(Vec::with_capacity(length.0));
        serde_json::to_writer(&mut *bytes, &record)
            .map_err(|_| PlanError::TooLarge(MAX_RECORD_BYTES + 1))?;
        Ok(bytes)
    }
}

/// Counts the bytes written to it.
struct ByteCount(usize);

impl std::io::Write for ByteCount {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0 += bytes.len();
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn match_key(key: &str, case_insensitive: bool) -> String {
    if case_insensitive {
        key.to_ascii_uppercase()
    } else {
        key.to_owned()
    }
}

fn check_two_environments(from: &str, to: &str, copy: bool) -> Result<(), EditError> {
    check_environment(from)?;
    check_environment(to)?;
    if from == to {
        return Err(EditError::SameEnvironment {
            environment: from.to_owned(),
            copy,
        });
    }
    Ok(())
}

fn check_environment(environment: &str) -> Result<(), EditError> {
    if is_valid_environment_name(environment) {
        Ok(())
    } else {
        Err(EditError::InvalidEnvironment(environment.to_owned()))
    }
}

/// A name a set or unset may give: valid, and one LPM passes to processes.
/// A remove takes any valid name, so an override a later deny list caught
/// can still be removed.
fn check_settable(environment: &str, key: &str) -> Result<(), EditError> {
    check_environment(environment)?;
    if !is_valid_variable_name(key) {
        return Err(EditError::InvalidKey);
    }
    if lpm_env::is_denied_env_var(key) {
        return Err(EditError::DeniedName(key.to_owned()));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
