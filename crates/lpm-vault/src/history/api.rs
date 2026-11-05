//! What the CLI's history commands call: reading the timeline and an
//! entry, reviewing and committing rollbacks, removing one value, and
//! turning history off and on. Each runs inside one vault lock, so a
//! protected project asks for approval once, and finishes any rotation or
//! removal another client started before doing anything else.

use std::collections::BTreeSet;
use std::fmt;
use std::path::Path;

use lpm_env_companion::history::admission::{self, CreationAdmission};
use lpm_env_companion::history::append::too_many_values;
use lpm_env_companion::history::read::{
    EntryInfo, EntryLookup, Filter, IdPrefix, Opened, PartSource, ReadError, RevealedEntry,
    Timeline, find_entry, read_retained, read_timeline, reveal_entry,
};
use lpm_env_companion::history::rebuild::{
    Choices, PlanError, Refusal, RollbackKind, RollbackPlan, Target, apply_rollback, plan_rollback,
};
use lpm_env_companion::history::removal::{
    ChosenSide, RemovalError, RemovalReview, needs_finishing, review_removal_for, start_removal,
};
use lpm_env_companion::history::switch::{MarkerHistory, plan_off, plan_on};
use lpm_env_companion::keyring::SystemRandom;

use super::record::{
    MAX_TRIMS_PER_OPERATION, Maintained, commit, finish_running, open_maintained, read_head_and_key,
};
use super::store::{HistoryStore, read_part};
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
    /// The environment isn't in history at that point and doesn't exist now.
    UnknownEnvironment,
    /// The rollback would give an environment a name another holds now.
    NameTaken(String),
    /// The entry touched several environments, and the command acts on one.
    EnvironmentRequired,
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
            Self::UnknownEnvironment => "unknown_environment",
            Self::NameTaken(_) => "name_taken",
            Self::EnvironmentRequired => "environment_required",
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
            Self::UnknownEnvironment => formatter.write_str(
                "that environment isn't in local history at that point, and doesn't exist now",
            ),
            Self::NameTaken(name) => write!(
                formatter,
                "another environment is named {name} now, and a rollback never changes another environment; rename it first, then roll back"
            ),
            Self::EnvironmentRequired => {
                formatter.write_str("that entry touched several environments; choose one with --env")
            }
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
            PlanError::AmbiguousEntry => Self::AmbiguousEntry,
            PlanError::UnknownEnvironment => Self::UnknownEnvironment,
            PlanError::NameTaken(name) => Self::NameTaken(name),
        }
    }
}

impl From<RemovalError> for HistoryError {
    fn from(error: RemovalError) -> Self {
        match error {
            RemovalError::Read(error) => error.into(),
            RemovalError::NotFound => Self::EntryNotFound,
            RemovalError::AmbiguousEntry => Self::AmbiguousEntry,
            RemovalError::ValueIsCurrent => Self::ValueIsCurrent,
            RemovalError::Limit => Self::Limit,
            RemovalError::ChangedSinceReview => Self::ChangedSinceReview,
            other => Self::Storage(other.to_string()),
        }
    }
}

impl From<String> for HistoryError {
    fn from(error: String) -> Self {
        Self::Storage(error)
    }
}

fn lookup<T>(found: EntryLookup<T>) -> Result<T, HistoryError> {
    match found {
        EntryLookup::Found(found) => Ok(*found),
        EntryLookup::NotFound => Err(HistoryError::EntryNotFound),
        EntryLookup::Ambiguous => Err(HistoryError::AmbiguousEntry),
    }
}

fn prefix(text: &str) -> Result<IdPrefix, HistoryError> {
    IdPrefix::parse(text).ok_or(HistoryError::EntryNotFound)
}

/// Why history is paused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Paused {
    /// The Mac holds too much LPM data to start history for this project.
    Limit,
    Damaged,
    /// A newer LPM keeps it, or is removing it.
    NewerVersion,
    /// It can't be read right now: the Keychain is locked or unavailable.
    Unavailable(String),
    TooManyValues,
}

impl Paused {
    /// The stable code JSON output uses.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Limit => "limit",
            Self::Damaged => "damaged",
            Self::NewerVersion => "newer_version",
            Self::Unavailable(_) => "unavailable",
            Self::TooManyValues => "too_many_values",
        }
    }
}

/// History's state for one project.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HistoryState {
    /// On, with or without entries yet.
    On,
    Off,
    Paused(Paused),
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
    fn part(&mut self, part: u16) -> Result<Option<std::borrow::Cow<'_, [u8]>>, String> {
        (self.read)(part).map(|sealed| sealed.map(std::borrow::Cow::Owned))
    }
}

type Run<'run, T> =
    dyn FnOnce(&mut Parts<'_>, &Opened, &EnvironmentMap) -> Result<T, HistoryError> + 'run;

/// Whether a read needs the project's current values, which only rebuilding
/// a state, a live gap or a removal review does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Values {
    Needed,
    Unused,
}

/// Run `run` with history opened for reading or changing, inside the lock,
/// after the read gate, with the project's current values when needed.
/// `None` before the project's first recorded change.
fn with_opened<T>(
    project_dir: &Path,
    values: Values,
    run: impl FnOnce(&mut Parts<'_>, &Opened, &EnvironmentMap) -> Result<T, HistoryError>,
) -> Result<Option<T>, HistoryError> {
    let run: Box<Run<'_, T>> = Box::new(run);
    let vault_id = project_vault_id(project_dir)?;
    let result = crate::with_project_vault_transaction(|directory| {
        crate::authorize_companion(directory, &vault_id, Operation::ReadExcludingOverrides)?;
        let values = match values {
            Values::Needed => {
                crate::read_all_environments_unlocked(directory, &vault_id)?.unwrap_or_default()
            }
            Values::Unused => EnvironmentMap::new(),
        };
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
    let Maintained { opened, .. } = open_maintained(store, vault_id, &mut SystemRandom)?;
    let mut read = |part: u16| read_part(store, vault_id, part);
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

/// The timeline of the env project at `project_dir`, with the values of the
/// entries it shows when `reveal` is set, in one walk. `None` before its
/// first recorded change.
pub fn timeline(
    project_dir: &Path,
    filter: &Filter<'_>,
    reveal: bool,
) -> Result<Option<Timeline>, HistoryError> {
    with_opened(project_dir, Values::Needed, |parts, opened, values| {
        Ok(read_timeline(
            opened,
            parts,
            &values_of(values),
            filter,
            reveal,
        )?)
    })
}

/// History's state, and how much it holds, from entry headers alone. A
/// marker that can't be read is an error; history records that can't be
/// read right now pause it.
pub fn status(project_dir: &Path) -> Result<HistoryStatus, HistoryError> {
    let vault_id = project_vault_id(project_dir)?;
    let paused = |reason| HistoryStatus {
        state: HistoryState::Paused(reason),
        retained: 0,
        oldest: None,
        unreadable_parts: 0,
    };
    let result = crate::with_project_vault_transaction(|directory| {
        crate::authorize_companion(directory, &vault_id, Operation::ReadExcludingOverrides)?;
        let empty = HistoryStatus {
            state: HistoryState::On,
            retained: 0,
            oldest: None,
            unreadable_parts: 0,
        };
        let history =
            match with_history_store!(directory, |store| marker_history(store, &vault_id))? {
                Err(error) => return Ok(Err(error)),
                Ok(MarkerHistory::Off) => {
                    return Ok(Ok(HistoryStatus {
                        state: HistoryState::Off,
                        ..empty
                    }));
                }
                Ok(MarkerHistory::Removing | MarkerHistory::Unsupported { .. }) => {
                    return Ok(Ok(paused(Paused::NewerVersion)));
                }
                Ok(MarkerHistory::Both) => return Ok(Ok(paused(Paused::Damaged))),
                Ok(history) => history,
            };
        // Only a project history records, or will, needs its values here.
        let values =
            crate::read_all_environments_unlocked(directory, &vault_id)?.unwrap_or_default();
        let too_many = too_many_values(&values_of(&values));
        with_history_store!(directory, |store| {
            match history {
                MarkerHistory::Default | MarkerHistory::On if too_many => {
                    return Ok(paused(Paused::TooManyValues));
                }
                MarkerHistory::Default => {
                    let inventory = store
                        .admission_inventory(&vault_id)
                        .map_err(HistoryError::Storage)?;
                    let trims: usize = admission::plan_trims(
                        inventory.count + admission::CREATION_ACCOUNTS,
                        &inventory.rings,
                        MAX_TRIMS_PER_OPERATION,
                        |project| inventory.trimmable.contains(project),
                    )
                    .iter()
                    .map(|(_, count)| count)
                    .sum();
                    let refused = admission::admit_creation(inventory.count - trims)
                        == CreationAdmission::Refused;
                    return Ok(if refused {
                        paused(Paused::Limit)
                    } else {
                        empty
                    });
                }
                _ => {}
            }
            let opened = match open_maintained(store, &vault_id, &mut SystemRandom) {
                Ok(Maintained { opened, .. }) => opened,
                Err(NotRecorded::Damaged) => return Ok(paused(Paused::Damaged)),
                Err(NotRecorded::NewerVersion) => return Ok(paused(Paused::NewerVersion)),
                Err(other) => return Ok(paused(Paused::Unavailable(other.to_string()))),
            };
            let mut read = |part: u16| read_part(store, &vault_id, part);
            match read_retained(&opened, &mut read) {
                Ok(retained) => Ok(HistoryStatus {
                    state: if retained.damaged_tail {
                        HistoryState::Paused(Paused::Damaged)
                    } else {
                        HistoryState::On
                    },
                    retained: retained.readable,
                    oldest: retained.oldest,
                    unreadable_parts: retained.unreadable_parts,
                }),
                Err(ReadError::Damaged(_)) => Ok(paused(Paused::Damaged)),
                Err(ReadError::Storage(error)) => Ok(paused(Paused::Unavailable(error))),
            }
        })
    });
    match result {
        Ok(result) => result,
        Err(error) => Err(HistoryError::Storage(error)),
    }
}

/// One entry, found by its ID or a prefix of it, with its values when
/// asked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Shown {
    pub info: EntryInfo,
    pub revealed: Option<RevealedEntry>,
}

/// The entry whose ID starts with `prefix`, in one read of history.
pub fn show(project_dir: &Path, prefix_text: &str, reveal: bool) -> Result<Shown, HistoryError> {
    let prefix = prefix(prefix_text)?;
    with_opened(project_dir, Values::Unused, |parts, opened, _| {
        if reveal {
            let revealed = lookup(reveal_entry(opened, parts, &prefix)?)?;
            Ok(Shown {
                info: revealed.info.clone(),
                revealed: Some(revealed),
            })
        } else {
            Ok(Shown {
                info: lookup(find_entry(opened, parts, &prefix)?)?,
                revealed: None,
            })
        }
    })?
    .ok_or(HistoryError::EntryNotFound)
}

/// Find the entry whose ID starts with `prefix`, let `choose` say what to
/// roll back given that entry, and plan it for review, in one lock and one
/// walk.
pub fn review_rollback(
    project_dir: &Path,
    prefix_text: &str,
    choose: impl FnOnce(&EntryInfo) -> Result<Target, HistoryError>,
) -> Result<(EntryInfo, RollbackPlan), HistoryError> {
    let prefix = prefix(prefix_text)?;
    with_opened(project_dir, Values::Needed, |parts, opened, values| {
        plan_rollback(opened, parts, &values_of(values), &prefix, choose)
    })?
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
                    RollbackKind::Undo => RelatedSide::Before,
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
            match marker_history(store, &vault_id)? {
                MarkerHistory::On => {}
                _ => return Err(HistoryError::ChangedSinceReview),
            }
            let (head, key) = read_head_and_key(store, &vault_id)?;
            let opened = Opened::open(&vault_id, &head, &key)?;
            // A removal that started since the review may be taking out a
            // value the review would put back.
            if needs_finishing(&opened) {
                return Err(HistoryError::ChangedSinceReview);
            }
            apply_rollback(
                plan,
                choices,
                &values_of(&values),
                &opened.keys,
                opened.record.current().generation(),
            )
            .map_err(|refusal| match refusal {
                Refusal::ChangedSinceReview => HistoryError::ChangedSinceReview,
                Refusal::NothingToApply => HistoryError::TargetUnknown,
            })
        })? {
            Ok(writes) => writes,
            Err(error) => return Ok(Err(error)),
        };
        for write in &writes {
            match &write.renamed_from {
                Some(from) => {
                    values.remove(from);
                    super::scope::renamed_environment(&recording, from, &write.name);
                }
                None if write.values.is_none() => {
                    values.remove(&write.name);
                }
                None => {}
            }
        }
        let mut written = Vec::with_capacity(writes.len());
        for write in writes {
            if let Some(environment) = write.values {
                // The value moves out of its wiped buffer rather than being
                // copied; the map it joins is wiped once written.
                values.insert(
                    write.name.clone(),
                    environment
                        .into_iter()
                        .map(|(key, mut value)| (key, std::mem::take(&mut *value)))
                        .collect(),
                );
            }
            written.push(write.name);
        }
        let committed = crate::write_all_environments_unlocked(
            directory,
            &vault_id,
            &project_name,
            &project_path,
            &values,
            &recording,
        );
        super::wipe_values(&mut values);
        committed?;
        Ok(Ok(written))
    });
    match result {
        Ok(result) => result,
        Err(error) => Err(HistoryError::Storage(error)),
    }
}

/// Find the entry whose ID starts with `prefix`, let `choose` say which of
/// its values to remove, and list every place that value appears, grouped,
/// for review, in one lock and one walk.
pub fn review_forget(
    project_dir: &Path,
    prefix_text: &str,
    choose: impl FnOnce(&EntryInfo) -> Result<ChosenSide, HistoryError>,
) -> Result<(EntryInfo, RemovalReview), HistoryError> {
    let prefix = prefix(prefix_text)?;
    with_opened(project_dir, Values::Needed, |parts, opened, values| {
        review_removal_for(opened, parts, &values_of(values), &prefix, choose)
    })?
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
                MarkerHistory::Off => return Err(HistoryError::Off),
                // History was removed, or turned off and on, since the review.
                MarkerHistory::Default => return Err(HistoryError::ChangedSinceReview),
                MarkerHistory::Both => return Err(HistoryError::Damaged),
                MarkerHistory::Removing | MarkerHistory::Unsupported { .. } => {
                    return Err(HistoryError::Unsupported);
                }
            }
            let Maintained { opened, .. } = open_maintained(store, &vault_id, &mut random)?;
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
