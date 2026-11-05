//! What the CLI's history commands call: reading the timeline and an
//! entry, reviewing and committing rollbacks, removing one value, and
//! turning history off and on. Each runs inside one vault lock, so a
//! protected project asks for approval once, and finishes any rotation or
//! removal another client started before doing anything else.

use std::collections::BTreeSet;
use std::fmt;
use std::path::Path;

use lpm_env_companion::history::part_account;
use lpm_env_companion::history::read::{
    EntryLookup, Filter, Opened, PartSource, ReadError, RevealedEntry, Timeline, read_timeline,
    reveal_entries, reveal_entry,
};
use lpm_env_companion::history::rebuild::{
    Choices, PlanError, Point, Refusal, RollbackPlan, apply_rollback, plan_environment_rollback,
    plan_key_rollback, plan_undo,
};
use lpm_env_companion::history::removal::{
    Chosen, RemovalError, RemovalReview, review_removal, start_removal,
};
use lpm_env_companion::history::switch::{MarkerHistory, plan_off, plan_on};
use lpm_env_companion::keyring::SystemRandom;

use super::record::{commit, finish_running, open_maintained, read_head_and_key};
use super::store::HistoryStore;
use super::{Action, NotRecorded, RelatedSide, Source, SourceDetail, values_of};
use crate::EnvironmentMap;
use crate::companion::CompanionBackend as _;
use crate::companion::gate::{Operation, ProjectGate};
use crate::companion::lifecycle;

/// Why a history command couldn't do what it was asked. Each has a stable
/// code the CLI's JSON reports as `history.<code>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HistoryError {
    NoProject,
    Off,
    /// A newer LPM keeps this project's history.
    Unsupported,
    Damaged,
    EntryNotFound,
    AmbiguousEntry,
    /// The value is still current at every place chosen.
    ValueIsCurrent,
    ChangedSinceReview,
    /// No change is left to make once unknown values are left out.
    TargetUnknown,
    /// More places than one removal can name.
    Limit,
    /// Storage failed, or the project refused the operation.
    Storage(String),
}

impl HistoryError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::NoProject => "no_project",
            Self::Off => "off",
            Self::Unsupported => "unsupported",
            Self::Damaged => "damaged",
            Self::EntryNotFound => "entry_not_found",
            Self::AmbiguousEntry => "ambiguous_entry",
            Self::ValueIsCurrent => "value_is_current",
            Self::ChangedSinceReview => "changed_since_review",
            Self::TargetUnknown => "target_unknown",
            Self::Limit => "limit",
            Self::Storage(_) => "storage",
        }
    }
}

impl fmt::Display for HistoryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoProject => formatter.write_str("this directory has no env project"),
            Self::Off => formatter.write_str(
                "local history is off for this env project; turn it on with lpm env history on",
            ),
            Self::Unsupported => formatter.write_str(
                "a newer LPM keeps this env project's history; update the LPM CLI: lpm self-update",
            ),
            Self::Damaged => formatter.write_str(
                "this env project's local history is damaged; repair it with lpm env repair",
            ),
            Self::EntryNotFound => formatter.write_str("no entry in local history has that ID"),
            Self::AmbiguousEntry => formatter.write_str(
                "more than one entry in local history starts with that ID; give more of it",
            ),
            Self::ValueIsCurrent => formatter.write_str(
                "the value is still current at every place chosen; change it first, then remove the old value from history",
            ),
            Self::ChangedSinceReview => formatter.write_str(
                "this env project's values changed since the review, so nothing was changed; review it again",
            ),
            Self::TargetUnknown => formatter.write_str(
                "local history doesn't know the earlier values of every key that would change, so there's nothing to roll back",
            ),
            Self::Limit => formatter.write_str(
                "that's more places than one removal can name; remove the value in two passes",
            ),
            Self::Storage(error) => formatter.write_str(error),
        }
    }
}

impl From<NotRecorded> for HistoryError {
    fn from(reason: NotRecorded) -> Self {
        match reason {
            NotRecorded::Damaged => Self::Damaged,
            NotRecorded::NewerVersion => Self::Unsupported,
            other => Self::Storage(other.to_string()),
        }
    }
}

impl From<ReadError> for HistoryError {
    fn from(error: ReadError) -> Self {
        match error {
            ReadError::Damaged(_) => Self::Damaged,
            ReadError::Storage(error) => Self::Storage(error),
        }
    }
}

impl From<PlanError> for HistoryError {
    fn from(error: PlanError) -> Self {
        match error {
            PlanError::Read(error) => error.into(),
            PlanError::EntryNotFound => Self::EntryNotFound,
            PlanError::UnknownEnvironment => Self::Storage(error.to_string()),
        }
    }
}

impl From<RemovalError> for HistoryError {
    fn from(error: RemovalError) -> Self {
        match error {
            RemovalError::Read(error) => error.into(),
            RemovalError::NotFound => Self::EntryNotFound,
            RemovalError::ValueIsCurrent => Self::ValueIsCurrent,
            RemovalError::Limit => Self::Limit,
            RemovalError::ChangedSinceReview => Self::ChangedSinceReview,
            other => Self::Storage(other.to_string()),
        }
    }
}

/// History's state for one project.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HistoryState {
    /// On, with or without entries yet.
    On,
    Off,
    /// A newer LPM keeps it, or is removing it.
    Unsupported,
    Damaged,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoryStatus {
    pub state: HistoryState,
    /// Readable entries, when history can be read.
    pub retained: usize,
    pub oldest: Option<i64>,
    pub unreadable_parts: usize,
}

/// A project's parts, read from whichever store holds them.
struct Parts<'read> {
    read: &'read mut dyn FnMut(u16) -> Result<Option<Vec<u8>>, String>,
}

impl PartSource for Parts<'_> {
    fn part(&mut self, part: u16) -> Result<Option<Vec<u8>>, String> {
        (self.read)(part)
    }
}

type Run<'run, T> =
    dyn FnOnce(&mut Parts<'_>, &Opened, &EnvironmentMap) -> Result<T, HistoryError> + 'run;

/// Run `run` with history opened for reading or changing, inside the lock,
/// after the read gate, with the project's current values.
fn with_opened<T>(
    project_dir: &Path,
    operation: Operation,
    run: impl FnOnce(&mut Parts<'_>, &Opened, &EnvironmentMap) -> Result<T, HistoryError>,
) -> Result<Option<T>, HistoryError> {
    let run: Box<Run<'_, T>> = Box::new(run);
    let vault_id = project_vault_id(project_dir)?;
    let result = crate::with_project_vault_transaction(|directory| {
        crate::authorize_companion(directory, &vault_id, operation)?;
        let values =
            crate::read_all_environments_unlocked(directory, &vault_id)?.unwrap_or_default();
        with_history_store!(directory, |store| open_and_run(
            store, &vault_id, &values, run
        ))
    });
    match result {
        Ok(result) => result,
        Err(error) => Err(HistoryError::Storage(error)),
    }
}

fn open_and_run<T>(
    store: &mut impl HistoryStore,
    vault_id: &str,
    values: &EnvironmentMap,
    run: Box<Run<'_, T>>,
) -> Result<Option<T>, HistoryError> {
    match marker_history(store, vault_id)? {
        MarkerHistory::Default => return Ok(None),
        MarkerHistory::Off => return Err(HistoryError::Off),
        MarkerHistory::Removing | MarkerHistory::Unsupported { .. } => {
            return Err(HistoryError::Unsupported);
        }
        MarkerHistory::Both => return Err(HistoryError::Damaged),
        MarkerHistory::On => {}
    }
    let (head, key) = open_maintained(store, vault_id, &mut SystemRandom)?;
    let opened = Opened::open(vault_id, &head, &key)?;
    let mut read = |part: u16| store.read(&part_account(vault_id, part));
    run(&mut Parts { read: &mut read }, &opened, values).map(Some)
}

fn marker_history(
    store: &mut impl HistoryStore,
    vault_id: &str,
) -> Result<MarkerHistory, HistoryError> {
    match crate::companion::open_project(store, vault_id).map_err(HistoryError::Storage)? {
        ProjectGate::Plain => Ok(MarkerHistory::Default),
        ProjectGate::Marked(marker) => Ok(MarkerHistory::of(Some(&marker))),
        ProjectGate::Damaged(_) => Err(HistoryError::Damaged),
    }
}

fn project_vault_id(project_dir: &Path) -> Result<String, HistoryError> {
    crate::vault_id::read_vault_id(project_dir).ok_or(HistoryError::NoProject)
}

/// The timeline of the env project at `project_dir`, or `None` before its
/// first recorded change.
pub fn timeline(project_dir: &Path, filter: &Filter<'_>) -> Result<Option<Timeline>, HistoryError> {
    with_opened(
        project_dir,
        Operation::ReadExcludingOverrides,
        |parts, opened, values| Ok(read_timeline(opened, parts, &values_of(values), filter)?),
    )
}

/// History's state, and how much it holds.
pub fn status(project_dir: &Path) -> Result<HistoryStatus, HistoryError> {
    let empty = HistoryStatus {
        state: HistoryState::On,
        retained: 0,
        oldest: None,
        unreadable_parts: 0,
    };
    match timeline(project_dir, &Filter::default()) {
        Ok(None) => Ok(empty),
        Ok(Some(timeline)) => Ok(HistoryStatus {
            state: if timeline.damaged_tail {
                HistoryState::Damaged
            } else {
                HistoryState::On
            },
            retained: timeline.readable,
            oldest: timeline.oldest,
            unreadable_parts: timeline.unreadable_parts,
        }),
        Err(HistoryError::Off) => Ok(HistoryStatus {
            state: HistoryState::Off,
            ..empty
        }),
        Err(HistoryError::Unsupported) => Ok(HistoryStatus {
            state: HistoryState::Unsupported,
            ..empty
        }),
        Err(HistoryError::Damaged) => Ok(HistoryStatus {
            state: HistoryState::Damaged,
            ..empty
        }),
        Err(error) => Err(error),
    }
}

/// The full ID of the entry whose hex ID starts with `prefix`: the 8-digit
/// short ID, any unique prefix of at least 6 hex digits, or all 32.
pub fn resolve_entry(timeline: &Timeline, prefix: &str) -> Result<[u8; 16], HistoryError> {
    let prefix = prefix.to_ascii_lowercase();
    if prefix.len() < 6 || prefix.len() > 32 || !prefix.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(HistoryError::EntryNotFound);
    }
    let mut found: Option<[u8; 16]> = None;
    for row in &timeline.rows {
        let lpm_env_companion::history::read::TimelineRow::Entry(info) = row else {
            continue;
        };
        if hex::encode(info.id).starts_with(&prefix) {
            if found.is_some_and(|found| found != info.id) {
                return Err(HistoryError::AmbiguousEntry);
            }
            found = Some(info.id);
        }
    }
    found.ok_or(HistoryError::EntryNotFound)
}

/// One entry with its values.
pub fn show(project_dir: &Path, entry: [u8; 16]) -> Result<Option<EntryLookup>, HistoryError> {
    with_opened(
        project_dir,
        Operation::ReadExcludingOverrides,
        |parts, opened, _| Ok(reveal_entry(opened, parts, &entry)?),
    )
}

/// The entries `ids` names, with their values, in one read of history.
pub fn reveal(
    project_dir: &Path,
    ids: &BTreeSet<[u8; 16]>,
) -> Result<Vec<RevealedEntry>, HistoryError> {
    Ok(with_opened(
        project_dir,
        Operation::ReadExcludingOverrides,
        |parts, opened, _| Ok(reveal_entries(opened, parts, ids)?),
    )?
    .unwrap_or_default())
}

/// What a rollback goes back to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RollbackRequest {
    /// An environment, named as it was at the point, back to its state
    /// after or before an entry.
    Environment { environment: String, point: Point },
    /// One key, named as it is now, back to its value before an entry.
    Key {
        environment: String,
        key: String,
        entry: [u8; 16],
    },
    /// The keys an entry changed, in every environment it touched, back to
    /// their values before it.
    Undo { entry: [u8; 16] },
}

/// Plan a rollback for review.
pub fn review_rollback(
    project_dir: &Path,
    request: &RollbackRequest,
) -> Result<RollbackPlan, HistoryError> {
    with_opened(
        project_dir,
        Operation::ReadExcludingOverrides,
        |parts, opened, values| {
            let current = values_of(values);
            Ok(match request {
                RollbackRequest::Environment { environment, point } => {
                    plan_environment_rollback(opened, parts, &current, environment, *point)?
                }
                RollbackRequest::Key {
                    environment,
                    key,
                    entry,
                } => plan_key_rollback(opened, parts, &current, environment, key, *entry)?,
                RollbackRequest::Undo { entry } => plan_undo(opened, parts, &current, *entry)?,
            })
        },
    )?
    .ok_or(HistoryError::EntryNotFound)
}

/// Commit a reviewed rollback: one values write, bound to what the review
/// saw, recorded as a `rollback` entry. Returns the environments it wrote.
pub fn commit_rollback(
    project_dir: &Path,
    plan: &RollbackPlan,
    choices: &Choices,
) -> Result<Vec<String>, HistoryError> {
    let vault_id = project_vault_id(project_dir)?;
    let project_name = crate::vault_id::read_project_name(project_dir);
    let project_path = project_dir
        .canonicalize()
        .unwrap_or_else(|_| project_dir.to_path_buf())
        .display()
        .to_string();
    let source = Source::with_detail(
        Action::Rollback,
        SourceDetail {
            related: Some((
                plan.point.entry,
                match plan.kind {
                    lpm_env_companion::history::rebuild::RollbackKind::Undo => RelatedSide::Before,
                    _ => plan.point.side,
                },
                plan.point_time,
            )),
            ..SourceDetail::default()
        },
    );
    let result = crate::with_project_vault_transaction(|directory| {
        let recording = super::scope::begin(&vault_id, &source);
        crate::authorize_companion(directory, &vault_id, Operation::Write)?;
        let mut values =
            crate::read_all_environments_unlocked(directory, &vault_id)?.unwrap_or_default();
        let writes = match with_history_store!(directory, |store| {
            let generation = match marker_history(store, &vault_id) {
                Ok(MarkerHistory::On) => {
                    let opened = read_head_and_key(store, &vault_id)
                        .map_err(HistoryError::from)
                        .and_then(|(head, key)| {
                            Opened::open(&vault_id, &head, &key).map_err(HistoryError::from)
                        });
                    opened.map(|opened| (opened.record.current().generation(), opened.keys))
                }
                Ok(_) => Err(HistoryError::ChangedSinceReview),
                Err(error) => Err(error),
            };
            generation.and_then(|(generation, keys)| {
                apply_rollback(plan, choices, &values_of(&values), &keys, generation).map_err(
                    |refusal| match refusal {
                        Refusal::ChangedSinceReview => HistoryError::ChangedSinceReview,
                        Refusal::NothingToApply => HistoryError::TargetUnknown,
                    },
                )
            })
        })? {
            Ok(writes) => writes,
            Err(error) => return Ok(Err(error)),
        };
        let mut written = Vec::with_capacity(writes.len());
        for write in writes {
            if let Some(from) = &write.renamed_from {
                values.remove(from);
            }
            match write.values {
                Some(environment) => {
                    values.insert(
                        write.name.clone(),
                        environment
                            .into_iter()
                            .map(|(key, value)| (key, value.as_str().to_owned()))
                            .collect(),
                    );
                }
                None => {
                    values.remove(&write.name);
                }
            }
            written.push(write.name);
        }
        crate::write_all_environments_unlocked(
            directory,
            &vault_id,
            &project_name,
            &project_path,
            &values,
            &recording,
        )?;
        Ok(Ok(written))
    });
    match result {
        Ok(result) => result,
        Err(error) => Err(HistoryError::Storage(error)),
    }
}

/// The value a removal starts from: a key's value before or after an entry,
/// named as that entry names it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChosenValue {
    pub entry: [u8; 16],
    pub environment: String,
    pub key: String,
    pub side: RelatedSide,
}

/// Every place the chosen value appears, grouped, for review.
pub fn review_forget(
    project_dir: &Path,
    chosen: &ChosenValue,
) -> Result<RemovalReview, HistoryError> {
    with_opened(
        project_dir,
        Operation::ReadExcludingOverrides,
        |parts, opened, values| {
            Ok(review_removal(
                opened,
                parts,
                &values_of(values),
                Chosen {
                    entry: chosen.entry,
                    environment: &chosen.environment,
                    key: &chosen.key,
                    side: chosen.side,
                },
            )?)
        },
    )?
    .ok_or(HistoryError::EntryNotFound)
}

/// Remove the reviewed value from the selected places: the key rotates and
/// every part is rewritten, in one pass either client can resume.
pub fn forget(
    project_dir: &Path,
    review: &RemovalReview,
    selection: &BTreeSet<usize>,
) -> Result<(), HistoryError> {
    let vault_id = project_vault_id(project_dir)?;
    let result = crate::with_project_vault_transaction(|directory| {
        crate::authorize_companion(directory, &vault_id, Operation::Write)?;
        let values =
            crate::read_all_environments_unlocked(directory, &vault_id)?.unwrap_or_default();
        with_history_store!(directory, |store| {
            let mut random = SystemRandom;
            match marker_history(store, &vault_id)? {
                MarkerHistory::On => {}
                MarkerHistory::Off | MarkerHistory::Default => return Err(HistoryError::Off),
                MarkerHistory::Both => return Err(HistoryError::Damaged),
                MarkerHistory::Removing | MarkerHistory::Unsupported { .. } => {
                    return Err(HistoryError::Unsupported);
                }
            }
            let (head, key) = open_maintained(store, &vault_id, &mut random)?;
            let opened = Opened::open(&vault_id, &head, &key)?;
            let approval = store
                .claimed_approval(&vault_id)
                .map_err(HistoryError::Storage)?;
            let writes = start_removal(
                &opened,
                review,
                selection,
                &values_of(&values),
                approval,
                &mut random,
            )?;
            commit(store, writes)?;
            finish_running(store, &vault_id, &mut random)?;
            Ok(())
        })
    });
    match result {
        Ok(result) => result,
        Err(error) => Err(HistoryError::Storage(error)),
    }
}

/// Turn history off: delete the project's history and keep it off, in one
/// transaction. Works when history is damaged or newer than this client,
/// but not when the project itself is refused.
pub fn turn_off(project_dir: &Path) -> Result<(), HistoryError> {
    switch(project_dir, true)
}

/// Turn history back on; it starts empty at the next change.
pub fn turn_on(project_dir: &Path) -> Result<(), HistoryError> {
    switch(project_dir, false)
}

fn switch(project_dir: &Path, off: bool) -> Result<(), HistoryError> {
    let vault_id = project_vault_id(project_dir)?;
    let result = crate::with_project_vault_transaction(|directory| {
        crate::authorize_companion(directory, &vault_id, Operation::Write)?;
        with_history_store!(directory, |store| {
            let gate =
                crate::companion::open_project(store, &vault_id).map_err(HistoryError::Storage)?;
            let marker = gate.marker().cloned();
            let inventory = store.inventory(&vault_id).map_err(HistoryError::Storage)?;
            let plan = if off {
                plan_off(&vault_id, marker.as_ref(), inventory)
            } else {
                match &marker {
                    Some(marker) => plan_on(marker, &inventory),
                    None => return Ok(()),
                }
            }
            .map_err(HistoryError::Storage)?;
            let result = lifecycle::execute(store, plan).map_err(HistoryError::Storage)?;
            crate::companion::remember(
                &vault_id,
                &result.map_or(ProjectGate::Plain, ProjectGate::Marked),
            );
            Ok::<(), HistoryError>(())
        })
    });
    match result {
        Ok(result) => result,
        Err(error) => Err(HistoryError::Storage(error)),
    }
}

impl From<String> for HistoryError {
    fn from(error: String) -> Self {
        Self::Storage(error)
    }
}
