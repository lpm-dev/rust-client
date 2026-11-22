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
//! Environments: a rename moves the environment's overrides to its new
//! name, replacing any left there by an environment of that name removed
//! earlier; removing an environment removes its overrides, so they never
//! come back to life on a new environment that takes the name; duplicating
//! one copies team values only, since overrides are this computer's own.

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
    /// A rename moved `moved` overrides and replaced `replaced` that an
    /// environment removed earlier left under the new name.
    Moved {
        from: String,
        to: String,
        moved: usize,
        replaced: usize,
    },
    /// A duplicate copied none of `from`'s `count` overrides.
    NotCopied {
        from: String,
        to: String,
        count: usize,
    },
}

/// The names-only inventory a plan needs when it creates or deletes the
/// record: the project's companion records and the service's count of
/// companion and staged records, markers excluded.
#[derive(Debug, Clone, Default)]
pub struct Inventory {
    pub project: Vec<CompanionAccount>,
    pub service_records: usize,
}

impl Inventory {
    /// The inventory `names`, every account in the service, gives `vault_id`.
    pub fn from_names<'name>(
        vault_id: &str,
        names: impl IntoIterator<Item = &'name str> + Clone,
    ) -> Self {
        Self {
            project: names
                .clone()
                .into_iter()
                .filter_map(CompanionAccount::parse)
                .filter(|account| {
                    account.vault_id() == vault_id
                        && !matches!(account, CompanionAccount::Marker { .. })
                })
                .collect(),
            service_records: budgets::admission_count(names),
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

/// Why a batch can't be planned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlanError {
    InvalidEnvironment(String),
    /// A name that isn't a valid variable name, which is never repeated
    /// back: it may be a value typed in the wrong place.
    InvalidKey,
    DeniedName(String),
    NulValue(String),
    TooLarge(usize),
    SameEnvironment(String),
    /// The gate refuses writes, for damage or a version this client
    /// doesn't support.
    Refused(GateError),
    NeedsResume,
    /// Ask again with [`Inventory`]: the batch creates or deletes the record.
    NeedsInventory,
    OverBudget(OverBudget),
    AdmissionRefused(usize),
}

impl PlanError {
    /// A stable code for each kind of refusal.
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidEnvironment(_) => "invalid_environment",
            Self::InvalidKey => "invalid_key",
            Self::DeniedName(_) => "denied_name",
            Self::NulValue(_) => "nul_value",
            Self::TooLarge(_) => "too_large",
            Self::SameEnvironment(_) => "same_environment",
            Self::Refused(GateError::Damaged(_)) => "damaged",
            Self::Refused(GateError::Unsupported { .. }) => "unsupported",
            Self::NeedsResume => "needs_resume",
            Self::NeedsInventory => "needs_inventory",
            Self::OverBudget(_) => "over_budget",
            Self::AdmissionRefused(_) => "admission_refused",
        }
    }
}

impl fmt::Display for PlanError {
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
            Self::TooLarge(bytes) => write!(
                formatter,
                "the personal overrides would take {bytes} bytes, more than the {MAX_RECORD_BYTES} one record may hold"
            ),
            Self::SameEnvironment(name) => {
                write!(formatter, "environment {name:?} can't be renamed to itself")
            }
            Self::Refused(error) => write!(formatter, "{error}"),
            Self::NeedsResume => {
                formatter.write_str("finish the env project's interrupted change first")
            }
            Self::NeedsInventory => formatter
                .write_str("the change creates or deletes a record, so it needs an inventory"),
            Self::OverBudget(over) => write!(formatter, "{over}"),
            Self::AdmissionRefused(count) => write!(
                formatter,
                "this computer's env storage holds {count} records of newer data, more than the {} it may; delete env projects you no longer use first",
                budgets::ADMISSION_CAP
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
    let stored = Overrides::stored(gate, vault_id, record, case_insensitive)?;
    let mut next = stored.clone();
    let mut effects = Vec::with_capacity(edits.len());
    for edit in edits {
        effects.push(next.apply(edit)?);
    }

    let unchanged = ChangePlan {
        mutations: Vec::new(),
        gate: gate.clone(),
        effects: Vec::new(),
        activated: false,
        over_admission_target: false,
    };
    if next == stored {
        return Ok(ChangePlan {
            effects,
            ..unchanged
        });
    }
    let record_account = record_account(OVERRIDES_KIND, vault_id, None);
    if next.is_empty() {
        // A stored record that passed the gate is listed by the marker.
        let Some(marker) = gate.marker() else {
            return Err(PlanError::Refused(GateError::Damaged(
                Damage::UnlistedRecord {
                    kind: OVERRIDES_KIND.to_owned(),
                },
            )));
        };
        let inventory = inventory.ok_or(PlanError::NeedsInventory)?;
        let mut plan = plan_feature_removal(marker, OVERRIDES_KIND, inventory.project.clone())
            .map_err(|_| PlanError::NeedsResume)?;
        let mut mutations = Vec::with_capacity(2);
        for transaction in plan.transactions.drain(..) {
            mutations.extend(
                transaction
                    .into_deletions(vault_id)
                    .map_err(|_| PlanError::NeedsResume)?,
            );
        }
        return Ok(ChangePlan {
            mutations,
            gate: plan.result.map_or(ProjectGate::Plain, ProjectGate::Marked),
            effects,
            ..unchanged
        });
    }

    let encoded = next.encode(vault_id)?;
    let account = CompanionAccount::parse(&record_account)
        .expect("the overrides account is spelled the one valid way");
    let write = Mutation::Write {
        account: account.clone(),
        value: encoded,
    };
    if record.is_some() {
        return Ok(ChangePlan {
            mutations: vec![write],
            effects,
            ..unchanged
        });
    }

    let inventory = inventory.ok_or(PlanError::NeedsInventory)?;
    budgets::check_project(inventory.project.iter().chain(std::iter::once(&account)))
        .map_err(PlanError::OverBudget)?;
    let over_admission_target = match budgets::admit(inventory.service_records, 1) {
        Admission::Admitted => false,
        Admission::OverTarget => true,
        Admission::Refused => {
            return Err(PlanError::AdmissionRefused(inventory.service_records));
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
#[derive(Clone, PartialEq, Eq, Default)]
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

    fn apply(&mut self, edit: &Edit) -> Result<Effect, PlanError> {
        match edit.clone() {
            Edit::Set {
                environment,
                key,
                value,
            } => {
                check_settable(&environment, &key)?;
                if value.contains('\0') {
                    return Err(PlanError::NulValue(key));
                }
                Ok(self.decide(environment, key, Some(Decision::Set(value))))
            }
            Edit::Unset { environment, key } => {
                check_settable(&environment, &key)?;
                Ok(self.decide(environment, key, Some(Decision::Unset)))
            }
            Edit::Remove { environment, key } => {
                check_environment(&environment)?;
                if !is_valid_variable_name(&key) {
                    return Err(PlanError::InvalidKey);
                }
                Ok(self.decide(environment, key, None))
            }
            Edit::ClearEnvironment { environment } => {
                check_environment(&environment)?;
                let removed = self
                    .environments
                    .remove(&environment)
                    .map_or(0, |names| names.len());
                Ok(Effect::Cleared {
                    environment: Some(environment),
                    removed,
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
                check_environment(&from)?;
                check_environment(&to)?;
                if from == to {
                    return Err(PlanError::SameEnvironment(from));
                }
                // What's left under `to` belongs to an environment removed
                // earlier; `to` is now `from`, whatever `from` had.
                let replaced = self.environments.remove(&to).map_or(0, |names| names.len());
                let moved = match self.environments.remove(&from) {
                    Some(names) => {
                        let moved = names.len();
                        self.environments.insert(to.clone(), names);
                        moved
                    }
                    None => 0,
                };
                Ok(Effect::Moved {
                    from,
                    to,
                    moved,
                    replaced,
                })
            }
            Edit::EnvironmentRemoved { environment } => {
                check_environment(&environment)?;
                let removed = self
                    .environments
                    .remove(&environment)
                    .map_or(0, |names| names.len());
                Ok(Effect::EnvironmentRemoved {
                    environment,
                    removed,
                })
            }
            Edit::EnvironmentDuplicated { from, to } => {
                check_environment(&from)?;
                check_environment(&to)?;
                if from == to {
                    return Err(PlanError::SameEnvironment(from));
                }
                Ok(Effect::NotCopied {
                    count: self.count(&from),
                    from,
                    to,
                })
            }
        }
    }

    /// Give `key` `decision` in `environment`, or drop its override for
    /// `None`, replacing a name the host can't tell apart from it.
    fn decide(&mut self, environment: String, key: String, decision: Option<Decision>) -> Effect {
        let matched = match_key(&key, self.case_insensitive);
        let names = self.environments.entry(environment.clone()).or_default();
        let before = names.get(&matched).cloned();
        let previous = match before.as_ref().map(|named| &named.decision) {
            None => Previous::None,
            Some(Decision::Set(_)) => Previous::Set,
            Some(Decision::Unset) => Previous::Unset,
        };
        let after = decision.map(|decision| Named {
            spelling: key.clone(),
            decision,
        });
        let changed = before != after;
        match after {
            Some(named) => {
                names.insert(matched, named);
            }
            None => {
                names.remove(&matched);
            }
        }
        if names.is_empty() {
            self.environments.remove(&environment);
        }
        Effect::Key {
            environment,
            key,
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

fn check_environment(environment: &str) -> Result<(), PlanError> {
    if is_valid_environment_name(environment) {
        Ok(())
    } else {
        Err(PlanError::InvalidEnvironment(environment.to_owned()))
    }
}

/// A name a set or unset may give: valid, and one LPM passes to processes.
/// A remove takes any valid name, so an override a later deny list caught
/// can still be removed.
fn check_settable(environment: &str, key: &str) -> Result<(), PlanError> {
    check_environment(environment)?;
    if !is_valid_variable_name(key) {
        return Err(PlanError::InvalidKey);
    }
    if lpm_env::is_denied_env_var(key) {
        return Err(PlanError::DeniedName(key.to_owned()));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
