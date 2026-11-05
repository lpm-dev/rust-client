//! Rebuilding a past state and planning rollbacks.
//!
//! The walk starts from the stored values and goes from the newest entry to
//! the oldest, undoing each change: a key takes its "before" side. At each
//! readable part's boundary the state derived so far is reconciled with
//! that part's summary, which makes keys a lost entry or an unreadable part
//! changed unknown. A key whose earlier value history didn't keep stays
//! unknown, with its digest when one is known; any kept value with the same
//! digest resolves it. Nothing unknown is ever guessed.

use std::collections::{BTreeMap, HashSet};
use std::fmt;

use zeroize::Zeroizing;

use crate::history::codec::{
    Action, Entry, EntryId, EnvironmentKind, KeyKind, Keys, Part, RelatedSide, Remote, Side, Slot,
    Summary, Unkept,
};
use crate::history::read::{Opened, PartRead, PartSource, ReadError};
use crate::history::values::Values;
use crate::keyring::{Digest, DigestKeys};

/// A point in history: right after an entry, or right before it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Point {
    pub entry: EntryId,
    pub side: RelatedSide,
}

/// Why a past value isn't known.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UnknownReason {
    /// It changed outside local history.
    NotRecorded,
    /// The change was too large to keep values.
    TooLarge,
    /// It was removed from history.
    Removed,
    /// Part of history couldn't be read.
    Unreadable,
}

/// A key's state at a point.
#[derive(Clone, PartialEq, Eq)]
pub enum TargetValue {
    Known(Zeroizing<String>),
    Absent,
    Unknown(UnknownReason),
}

impl fmt::Debug for TargetValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Known(_) => formatter.write_str("Known(..)"),
            Self::Absent => formatter.write_str("Absent"),
            Self::Unknown(reason) => write!(formatter, "Unknown({reason:?})"),
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
enum KeyState {
    Known(Zeroizing<String>),
    Unknown {
        digest: Option<Digest>,
        reason: UnknownReason,
    },
}

impl KeyState {
    fn from_side(side: &Side<'_>) -> Option<Self> {
        match side {
            Side::Absent => None,
            Side::Value { value, .. } => Some(Self::Known(Zeroizing::new((*value).to_owned()))),
            Side::DigestOnly { digest, reason } => Some(Self::Unknown {
                digest: Some(*digest),
                reason: match reason {
                    Unkept::NotRecorded => UnknownReason::NotRecorded,
                    Unkept::TooLarge => UnknownReason::TooLarge,
                },
            }),
            Side::Removed => Some(Self::Unknown {
                digest: None,
                reason: UnknownReason::Removed,
            }),
        }
    }

    fn target(&self) -> TargetValue {
        match self {
            Self::Known(value) => TargetValue::Known(value.clone()),
            Self::Unknown { reason, .. } => TargetValue::Unknown(*reason),
        }
    }
}

/// A key as the walk tracks it: its name now, if it exists now, and its
/// state at the point the walk reached.
#[derive(Clone)]
struct TrackedKey {
    current: Option<String>,
    state: KeyState,
}

#[derive(Clone, Default)]
struct TrackedEnvironment {
    current: Option<String>,
    exists: bool,
    keys: BTreeMap<String, TrackedKey>,
}

/// What the walk learns about a key from the entries newer than the point.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gap {
    /// The entry before the gap's time.
    pub since: Option<i64>,
    /// When it was found: the outside entry's time, or `None` for the live
    /// gap, which is still open.
    pub until: Option<i64>,
}

/// A pull that set a key's current value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pulled {
    pub remote: Option<RemoteName>,
    pub version: Option<u64>,
    pub time: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemoteName {
    Personal,
    Org(String),
}

/// The newest recorded change to a key after the change an undo reverts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangedAgain {
    pub time: i64,
    pub actor: crate::history::codec::Actor,
    pub action: Action,
}

#[derive(Default, Clone)]
struct Notes {
    gaps: Vec<Gap>,
    newest_touch_seen: bool,
    pulled: Option<Pulled>,
    changed_again: Option<ChangedAgain>,
}

/// The whole project as the walk tracks it, by the names it had at the
/// point reached.
#[derive(Default)]
struct State {
    environments: BTreeMap<String, TrackedEnvironment>,
    /// Notes per key, by (environment, key) as named now.
    notes: BTreeMap<(String, String), Notes>,
}

impl State {
    fn from_values(values: &Values<'_>) -> Self {
        Self {
            environments: values
                .environments()
                .iter()
                .map(|(name, keys)| {
                    (
                        (*name).to_owned(),
                        TrackedEnvironment {
                            current: Some((*name).to_owned()),
                            exists: true,
                            keys: keys
                                .iter()
                                .map(|(key, value)| {
                                    (
                                        (*key).to_owned(),
                                        TrackedKey {
                                            current: Some((*key).to_owned()),
                                            state: KeyState::Known(Zeroizing::new(
                                                (*value).to_owned(),
                                            )),
                                        },
                                    )
                                })
                                .collect(),
                        },
                    )
                })
                .collect(),
            notes: BTreeMap::new(),
        }
    }

    /// Make the derived state agree with `summary`, the state at this point
    /// as history recorded it: a key whose derived value doesn't match its
    /// digest becomes unknown with that digest, a key the summary doesn't
    /// list is absent, and a key only the summary lists is unknown.
    fn reconcile(&mut self, summary: &Summary<'_>, keys: &DigestKeys, reason: UnknownReason) {
        for (name, environment) in &mut self.environments {
            let Some(recorded) = summary.environments.get(name.as_str()) else {
                environment.exists = false;
                environment.keys.clear();
                continue;
            };
            environment.exists = true;
            environment
                .keys
                .retain(|key, _| recorded.contains_key(key.as_str()));
            for (key, slot) in recorded {
                let tracked = environment.keys.get_mut(*key);
                let matches = match (&tracked, slot) {
                    (
                        Some(TrackedKey {
                            state: KeyState::Known(value),
                            ..
                        }),
                        Slot::Digest(digest),
                    ) => keys.value(value.as_bytes()) == *digest,
                    (
                        Some(TrackedKey {
                            state: KeyState::Unknown { digest, .. },
                            ..
                        }),
                        Slot::Digest(recorded),
                    ) => *digest == Some(*recorded),
                    (
                        Some(TrackedKey {
                            state:
                                KeyState::Unknown {
                                    reason: UnknownReason::Removed,
                                    ..
                                },
                            ..
                        }),
                        Slot::Removed,
                    ) => true,
                    _ => false,
                };
                if matches {
                    continue;
                }
                let state = KeyState::Unknown {
                    digest: match slot {
                        Slot::Digest(digest) => Some(*digest),
                        Slot::Removed => None,
                    },
                    reason: match slot {
                        Slot::Removed => UnknownReason::Removed,
                        Slot::Digest(_) => reason,
                    },
                };
                match tracked {
                    Some(tracked) => tracked.state = state,
                    None => {
                        environment.keys.insert(
                            (*key).to_owned(),
                            TrackedKey {
                                current: None,
                                state,
                            },
                        );
                    }
                }
            }
        }
        for (name, recorded) in &summary.environments {
            if self.environments.contains_key(*name) {
                continue;
            }
            self.environments.insert(
                (*name).to_owned(),
                TrackedEnvironment {
                    current: None,
                    exists: true,
                    keys: recorded
                        .iter()
                        .map(|(key, slot)| {
                            (
                                (*key).to_owned(),
                                TrackedKey {
                                    current: None,
                                    state: KeyState::Unknown {
                                        digest: match slot {
                                            Slot::Digest(digest) => Some(*digest),
                                            Slot::Removed => None,
                                        },
                                        reason: match slot {
                                            Slot::Removed => UnknownReason::Removed,
                                            Slot::Digest(_) => reason,
                                        },
                                    },
                                },
                            )
                        })
                        .collect(),
                },
            );
        }
    }

    /// Note what `entry` tells about the keys it changed, by their names
    /// now: a gap it records, whether the key's current value came from a
    /// pull, and with `changed_again`, that the key changed after the point.
    fn note(&mut self, entry: &Entry<'_>, changed_again: bool) {
        let outside = entry.action == Action::Outside;
        let pulled = (entry.action == Action::Pull).then(|| Pulled {
            remote: entry.detail.remote.map(|remote| match remote {
                Remote::Personal => RemoteName::Personal,
                Remote::Org(slug) => RemoteName::Org(slug.to_owned()),
            }),
            version: entry.detail.remote_version,
            time: entry.time,
        });
        for change in &entry.environments {
            let Some(environment) = self.environments.get(change.name) else {
                continue;
            };
            let Some(environment_now) = &environment.current else {
                continue;
            };
            let Keys::Changes(key_changes) = &change.keys else {
                continue;
            };
            for key_change in key_changes {
                let Some(key_now) = environment
                    .keys
                    .get(key_change.key)
                    .and_then(|key| key.current.clone())
                else {
                    continue;
                };
                let notes = self
                    .notes
                    .entry((environment_now.clone(), key_now))
                    .or_default();
                if outside {
                    notes.gaps.push(Gap {
                        since: entry.since,
                        until: Some(entry.time),
                    });
                } else if changed_again && notes.changed_again.is_none() {
                    notes.changed_again = Some(ChangedAgain {
                        time: entry.time,
                        actor: entry.actor,
                        action: entry.action,
                    });
                }
                if !notes.newest_touch_seen {
                    notes.newest_touch_seen = true;
                    if notes.gaps.is_empty() {
                        notes.pulled = pulled.clone();
                    }
                }
            }
        }
    }

    /// Undo `entry`: every key it changed takes its "before" side.
    fn undo(&mut self, entry: &Entry<'_>) {
        for change in &entry.environments {
            let mut environment = self.environments.remove(change.name).unwrap_or_default();
            match &change.keys {
                Keys::Count(_) => {
                    for key in environment.keys.values_mut() {
                        key.state = KeyState::Unknown {
                            digest: None,
                            reason: UnknownReason::TooLarge,
                        };
                    }
                }
                Keys::Changes(key_changes) => {
                    for key_change in key_changes {
                        let mut tracked = environment.keys.remove(key_change.key);
                        let before = KeyState::from_side(&key_change.before);
                        let name = match key_change.kind {
                            KeyKind::RenamedFrom(from) => from,
                            _ => key_change.key,
                        };
                        match before {
                            None => {}
                            Some(state) => {
                                let current = tracked.take().and_then(|tracked| tracked.current);
                                environment
                                    .keys
                                    .insert(name.to_owned(), TrackedKey { current, state });
                            }
                        }
                    }
                }
            }
            let name = match change.kind {
                EnvironmentKind::Created => {
                    environment.exists = false;
                    environment.keys.clear();
                    change.name
                }
                EnvironmentKind::Removed => {
                    environment.exists = true;
                    change.name
                }
                EnvironmentKind::RenamedFrom(from) => {
                    environment.exists = true;
                    from
                }
                EnvironmentKind::Unchanged => {
                    environment.exists = true;
                    change.name
                }
            };
            self.environments.insert(name.to_owned(), environment);
        }
    }

    /// Resolve unknown keys whose digest matches a kept value in `entry`.
    fn resolve(&mut self, entry: &Entry<'_>) {
        let wanted: HashSet<Digest> =
            self.environments
                .values()
                .flat_map(|environment| environment.keys.values())
                .filter_map(|key| match key.state {
                    KeyState::Unknown {
                        digest: Some(digest),
                        reason:
                            UnknownReason::NotRecorded
                            | UnknownReason::TooLarge
                            | UnknownReason::Unreadable,
                    } => Some(digest),
                    _ => None,
                })
                .collect();
        if wanted.is_empty() {
            return;
        }
        for change in &entry.environments {
            let Keys::Changes(key_changes) = &change.keys else {
                continue;
            };
            for key_change in key_changes {
                for side in [&key_change.before, &key_change.after] {
                    let Side::Value { value, digest } = side else {
                        continue;
                    };
                    if !wanted.contains(digest) {
                        continue;
                    }
                    for environment in self.environments.values_mut() {
                        for key in environment.keys.values_mut() {
                            if matches!(key.state, KeyState::Unknown { digest: Some(unknown), .. } if unknown == *digest)
                            {
                                key.state = KeyState::Known(Zeroizing::new((*value).to_owned()));
                            }
                        }
                    }
                }
            }
        }
    }

    fn has_unresolved(&self) -> bool {
        self.environments.values().any(|environment| {
            environment.keys.values().any(|key| {
                matches!(
                    key.state,
                    KeyState::Unknown {
                        digest: Some(_),
                        ..
                    }
                )
            })
        })
    }

    fn note_live_gap(
        &mut self,
        summary: &Summary<'_>,
        current: &Values<'_>,
        keys: &DigestKeys,
        since: Option<i64>,
    ) {
        for (name, values) in current.environments() {
            let recorded = summary.environments.get(name);
            for (key, value) in values {
                let same = recorded
                    .and_then(|recorded| recorded.get(key))
                    .is_some_and(|slot| *slot == Slot::Digest(keys.value(value.as_bytes())));
                if !same {
                    self.notes
                        .entry(((*name).to_owned(), (*key).to_owned()))
                        .or_default()
                        .gaps
                        .push(Gap { since, until: None });
                }
            }
        }
    }
}

/// Why a rollback can't be planned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlanError {
    Read(ReadError),
    /// No readable entry has that ID.
    EntryNotFound,
    /// The environment didn't exist at the point and doesn't now.
    UnknownEnvironment,
}

impl fmt::Display for PlanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read(error) => write!(formatter, "{error}"),
            Self::EntryNotFound => formatter.write_str("no entry in local history has that ID"),
            Self::UnknownEnvironment => {
                formatter.write_str("that environment isn't in local history at that point")
            }
        }
    }
}

impl From<ReadError> for PlanError {
    fn from(error: ReadError) -> Self {
        Self::Read(error)
    }
}

struct Walked {
    state: State,
    /// The entry the walk stopped at, kept for undo plans.
    entry: Option<OwnedEntry>,
    target_time: i64,
}

/// The parts of an entry an undo needs once its part's plaintext is gone.
struct OwnedEntry {
    environments: Vec<OwnedEnvironmentChange>,
}

struct OwnedEnvironmentChange {
    name: String,
    kind: OwnedEnvironmentKind,
    keys: Vec<OwnedKeyChange>,
}

enum OwnedEnvironmentKind {
    Unchanged,
    Created,
    Removed,
    RenamedFrom(String),
}

struct OwnedKeyChange {
    key: String,
    renamed_from: Option<String>,
    before: Option<KeyState>,
}

fn owned(entry: &Entry<'_>) -> OwnedEntry {
    OwnedEntry {
        environments: entry
            .environments
            .iter()
            .map(|change| OwnedEnvironmentChange {
                name: change.name.to_owned(),
                kind: match change.kind {
                    EnvironmentKind::Unchanged => OwnedEnvironmentKind::Unchanged,
                    EnvironmentKind::Created => OwnedEnvironmentKind::Created,
                    EnvironmentKind::Removed => OwnedEnvironmentKind::Removed,
                    EnvironmentKind::RenamedFrom(from) => {
                        OwnedEnvironmentKind::RenamedFrom(from.to_owned())
                    }
                },
                keys: match &change.keys {
                    Keys::Count(_) => Vec::new(),
                    Keys::Changes(changes) => changes
                        .iter()
                        .map(|key_change| OwnedKeyChange {
                            key: key_change.key.to_owned(),
                            renamed_from: match key_change.kind {
                                KeyKind::RenamedFrom(from) => Some(from.to_owned()),
                                _ => None,
                            },
                            before: KeyState::from_side(&key_change.before),
                        })
                        .collect(),
                },
            })
            .collect(),
    }
}

/// Walk from `current` back to `stop`, then on while unknown digests may
/// still resolve.
fn walk(
    opened: &Opened,
    source: &mut impl PartSource,
    current: &Values<'_>,
    point: Point,
) -> Result<Walked, PlanError> {
    let mut state = State::from_values(current);
    let mut first_part = true;
    let mut skipped_unreadable = false;
    let mut reached = false;
    let mut walked_entry = None;
    let mut target_time = 0;
    opened.walk(source, |read| {
        let plaintext = match read {
            PartRead::Unreadable { .. } => {
                skipped_unreadable = true;
                return true;
            }
            PartRead::Readable { plaintext, .. } => plaintext,
        };
        let part = Part::decode(&plaintext).expect("walk decoded it");
        let summary = match opened.scrub() {
            Some(scrub) => scrub.summary(&part.summary).0,
            None => part.summary.clone(),
        };
        let reason = if skipped_unreadable {
            UnknownReason::Unreadable
        } else {
            UnknownReason::NotRecorded
        };
        if first_part {
            first_part = false;
            state.note_live_gap(
                &summary,
                current,
                &opened.keys,
                part.last_header().map(|header| header.time),
            );
            state.reconcile(&summary, &opened.keys, reason);
        } else if !reached {
            state.reconcile(&summary, &opened.keys, reason);
        }
        skipped_unreadable = false;
        for entry in part.decoded_entries().rev() {
            let entry = match opened.scrub() {
                Some(scrub) => scrub.entry(&entry).0,
                None => entry,
            };
            if reached {
                state.resolve(&entry);
                if !state.has_unresolved() {
                    return false;
                }
                continue;
            }
            if entry.id == point.entry {
                target_time = entry.time;
                walked_entry = Some(owned(&entry));
                state.note(&entry, false);
                if point.side == RelatedSide::Before {
                    state.undo(&entry);
                }
                reached = true;
                state.resolve(&entry);
                if !state.has_unresolved() {
                    return false;
                }
                continue;
            }
            state.note(&entry, true);
            state.undo(&entry);
            state.resolve(&entry);
        }
        true
    })?;
    if !reached {
        return Err(PlanError::EntryNotFound);
    }
    Ok(Walked {
        state,
        entry: walked_entry,
        target_time,
    })
}

/// How a reviewed rollback is bound to what the person saw.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Binding {
    /// The whole environment, byte for byte, or its absence.
    Environment(Option<Digest>),
    /// One key's value, or its absence.
    Key(Option<Digest>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RollbackKind {
    Environment,
    Key,
    Undo,
}

/// One key a rollback would change, or can't.
#[derive(Clone, PartialEq, Eq)]
pub struct Row {
    /// The key as the environment names it after the rollback; for a key
    /// that leaves, its name now.
    pub key: String,
    pub current: Option<Zeroizing<String>>,
    pub target: TargetValue,
    pub gaps: Vec<Gap>,
    pub pulled: Option<Pulled>,
    pub changed_again: Option<ChangedAgain>,
}

impl fmt::Debug for Row {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Row")
            .field("key", &self.key)
            .field("current", &self.current.as_ref().map(|_| ".."))
            .field("target", &self.target)
            .field("gaps", &self.gaps)
            .field("pulled", &self.pulled)
            .field("changed_again", &self.changed_again)
            .finish()
    }
}

impl Row {
    /// Whether applying the row changes the stored value.
    pub fn changes(&self) -> bool {
        match (&self.target, &self.current) {
            (TargetValue::Known(target), Some(current)) => target.as_str() != current.as_str(),
            (TargetValue::Known(_), None) => true,
            (TargetValue::Absent, current) => current.is_some(),
            (TargetValue::Unknown(_), _) => false,
        }
    }
}

/// One environment of a rollback.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvironmentPlan {
    /// Its name now, or `None` when the rollback recreates it.
    pub current: Option<String>,
    /// Its name at the point, or `None` when it didn't exist then, so the
    /// rollback can delete it.
    pub target: Option<String>,
    pub rows: Vec<Row>,
    pub binding: Binding,
}

impl EnvironmentPlan {
    /// Whether the rollback recreates an environment that doesn't exist now.
    pub fn recreates(&self) -> bool {
        self.current.is_none() && self.target.is_some()
    }

    /// Whether the environment didn't exist at the point, so the rollback
    /// can delete it once it's empty.
    pub fn offers_deletion(&self) -> bool {
        self.current.is_some() && self.target.is_none()
    }

    pub fn changing_rows(&self) -> usize {
        self.rows.iter().filter(|row| row.changes()).count()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RollbackPlan {
    pub kind: RollbackKind,
    pub point: Point,
    /// The point's entry's time.
    pub point_time: i64,
    /// The key's generation at review; a removal in between rotates it.
    pub generation: u32,
    pub environments: Vec<EnvironmentPlan>,
}

fn environment_binding(keys: &DigestKeys, values: Option<&BTreeMap<&str, &str>>) -> Option<Digest> {
    let values = values?;
    let mut encoded = Zeroizing::new(Vec::new());
    for (key, value) in values {
        encoded.extend_from_slice(&(key.len() as u64).to_be_bytes());
        encoded.extend_from_slice(key.as_bytes());
        encoded.extend_from_slice(&(value.len() as u64).to_be_bytes());
        encoded.extend_from_slice(value.as_bytes());
    }
    Some(keys.value(&encoded))
}

fn key_binding(keys: &DigestKeys, value: Option<&str>) -> Option<Digest> {
    value.map(|value| keys.value(value.as_bytes()))
}

fn notes_for(state: &State, environment: &str, key: &str) -> Notes {
    state
        .notes
        .get(&(environment.to_owned(), key.to_owned()))
        .cloned()
        .unwrap_or_default()
}

fn target_of(environment: &TrackedEnvironment, key: &str) -> TargetValue {
    if !environment.exists {
        return TargetValue::Absent;
    }
    environment
        .keys
        .get(key)
        .map_or(TargetValue::Absent, |tracked| tracked.state.target())
}

/// Plan rolling `environment`, as it was named at the point, back to its
/// whole state at `point`.
pub fn plan_environment_rollback(
    opened: &Opened,
    source: &mut impl PartSource,
    current: &Values<'_>,
    environment: &str,
    point: Point,
) -> Result<RollbackPlan, PlanError> {
    let walked = walk(opened, source, current, point)?;
    let tracked = walked
        .state
        .environments
        .get(environment)
        .ok_or(PlanError::UnknownEnvironment)?;
    let current_name = tracked
        .current
        .clone()
        .filter(|name| current.environment(name).is_some());
    let current_values = current_name
        .as_deref()
        .and_then(|name| current.environment(name));
    let target_name = tracked.exists.then(|| environment.to_owned());
    if current_name.is_none() && target_name.is_none() {
        return Err(PlanError::UnknownEnvironment);
    }
    let mut rows = Vec::new();
    let mut names: Vec<&str> = tracked
        .keys
        .keys()
        .map(String::as_str)
        .filter(|_| tracked.exists)
        .collect();
    if let Some(values) = current_values {
        names.extend(values.keys().copied());
    }
    names.sort_unstable();
    names.dedup();
    for name in names {
        let target = target_of(tracked, name);
        let current_value = current_values.and_then(|values| values.get(name)).copied();
        let notes = current_name
            .as_deref()
            .map(|environment| notes_for(&walked.state, environment, name))
            .unwrap_or_default();
        let row = Row {
            key: name.to_owned(),
            current: current_value.map(|value| Zeroizing::new(value.to_owned())),
            target,
            gaps: notes.gaps,
            pulled: notes.pulled,
            changed_again: None,
        };
        if row.changes() || matches!(row.target, TargetValue::Unknown(_)) {
            rows.push(row);
        }
    }
    Ok(RollbackPlan {
        kind: RollbackKind::Environment,
        point,
        point_time: walked.target_time,
        generation: opened.record.current().generation(),
        environments: vec![EnvironmentPlan {
            binding: Binding::Environment(environment_binding(&opened.keys, current_values)),
            current: current_name,
            target: target_name,
            rows,
        }],
    })
}

/// Plan rolling one key back to its value before `entry`, as the key
/// inspector's Roll Back… does, so it never does nothing even on the newest
/// change. `environment` and `key` name it now.
pub fn plan_key_rollback(
    opened: &Opened,
    source: &mut impl PartSource,
    current: &Values<'_>,
    environment: &str,
    key: &str,
    entry: EntryId,
) -> Result<RollbackPlan, PlanError> {
    let point = Point {
        entry,
        side: RelatedSide::Before,
    };
    let walked = walk(opened, source, current, point)?;
    let (target, notes) = walked
        .state
        .environments
        .values()
        .filter(|tracked| tracked.current.as_deref() == Some(environment))
        .map(|tracked| {
            if !tracked.exists {
                return TargetValue::Absent;
            }
            tracked
                .keys
                .values()
                .find(|tracked_key| tracked_key.current.as_deref() == Some(key))
                .map_or(TargetValue::Absent, |tracked_key| {
                    tracked_key.state.target()
                })
        })
        .next()
        .map(|target| (target, notes_for(&walked.state, environment, key)))
        .ok_or(PlanError::UnknownEnvironment)?;
    let current_value = current.get(environment, key);
    let row = Row {
        key: key.to_owned(),
        current: current_value.map(|value| Zeroizing::new(value.to_owned())),
        target,
        gaps: notes.gaps,
        pulled: notes.pulled,
        changed_again: None,
    };
    Ok(RollbackPlan {
        kind: RollbackKind::Key,
        point,
        point_time: walked.target_time,
        generation: opened.record.current().generation(),
        environments: vec![EnvironmentPlan {
            current: current
                .environment(environment)
                .map(|_| environment.to_owned()),
            target: Some(environment.to_owned()),
            rows: vec![row],
            binding: Binding::Key(key_binding(&opened.keys, current_value)),
        }],
    })
}

/// Plan undoing `entry`: every key it changed goes back to its value before
/// it, in every environment it touched.
pub fn plan_undo(
    opened: &Opened,
    source: &mut impl PartSource,
    current: &Values<'_>,
    entry: EntryId,
) -> Result<RollbackPlan, PlanError> {
    let point = Point {
        entry,
        side: RelatedSide::After,
    };
    let walked = walk(opened, source, current, point)?;
    let undone = walked.entry.as_ref().expect("the walk reached the entry");
    let mut environments = Vec::with_capacity(undone.environments.len());
    for change in &undone.environments {
        let tracked = walked.state.environments.get(&change.name);
        let current_name = tracked
            .and_then(|tracked| tracked.current.clone())
            .filter(|name| current.environment(name).is_some());
        let current_values = current_name
            .as_deref()
            .and_then(|name| current.environment(name));
        let target_name = match &change.kind {
            OwnedEnvironmentKind::Created => None,
            OwnedEnvironmentKind::RenamedFrom(from) => Some(from.clone()),
            OwnedEnvironmentKind::Unchanged | OwnedEnvironmentKind::Removed => {
                Some(change.name.clone())
            }
        };
        let mut rows = Vec::new();
        for key_change in &change.keys {
            let tracked_key = tracked.and_then(|tracked| tracked.keys.get(&key_change.key));
            let current_key = tracked_key
                .and_then(|tracked_key| tracked_key.current.clone())
                .filter(|name| {
                    current_values.is_some_and(|values| values.contains_key(name.as_str()))
                });
            let notes = match (&current_name, &current_key) {
                (Some(environment), Some(key)) => notes_for(&walked.state, environment, key),
                _ => Notes::default(),
            };
            let target = match &key_change.before {
                None => TargetValue::Absent,
                Some(state) => state.target(),
            };
            let target_key = key_change
                .renamed_from
                .clone()
                .unwrap_or_else(|| key_change.key.clone());
            if let (Some(_), Some(current_key)) = (&key_change.renamed_from, &current_key) {
                rows.push(Row {
                    key: current_key.clone(),
                    current: current_values
                        .and_then(|values| values.get(current_key.as_str()))
                        .map(|value| Zeroizing::new((*value).to_owned())),
                    target: TargetValue::Absent,
                    gaps: notes.gaps.clone(),
                    pulled: notes.pulled.clone(),
                    changed_again: notes.changed_again.clone(),
                });
            }
            let current_value = if key_change.renamed_from.is_some() {
                current_values.and_then(|values| values.get(target_key.as_str()))
            } else {
                current_key
                    .as_deref()
                    .and_then(|key| current_values.and_then(|values| values.get(key)))
            };
            let row = Row {
                key: if key_change.renamed_from.is_some() {
                    target_key
                } else {
                    current_key.clone().unwrap_or(target_key)
                },
                current: current_value.map(|value| Zeroizing::new((*value).to_owned())),
                target,
                gaps: notes.gaps,
                pulled: notes.pulled,
                changed_again: notes.changed_again,
            };
            if row.changes() || matches!(row.target, TargetValue::Unknown(_)) {
                rows.push(row);
            }
        }
        rows.sort_by(|left, right| left.key.cmp(&right.key));
        environments.push(EnvironmentPlan {
            binding: Binding::Environment(environment_binding(&opened.keys, current_values)),
            current: current_name,
            target: target_name,
            rows,
        });
    }
    Ok(RollbackPlan {
        kind: RollbackKind::Undo,
        point,
        point_time: walked.target_time,
        generation: opened.record.current().generation(),
        environments,
    })
}

/// What the person chose in the review.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Choices {
    /// Rows switched off, as (environment index, row index).
    pub skipped: HashSet<(usize, usize)>,
    /// Whether to keep an environment the rollback empties and that didn't
    /// exist at the point, by environment index. Deleting it is the default.
    pub keep_empty: HashSet<usize>,
}

/// Why a reviewed rollback was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// The values, or the history key, changed since the review.
    ChangedSinceReview,
    /// No row is switched on.
    NothingToApply,
}

/// One environment the values write sets.
#[derive(Clone, PartialEq, Eq)]
pub struct EnvironmentWrite {
    /// Its name after the write.
    pub name: String,
    /// Its name before, when the write renames it.
    pub renamed_from: Option<String>,
    /// Its values, or `None` to delete it.
    pub values: Option<BTreeMap<String, Zeroizing<String>>>,
}

impl fmt::Debug for EnvironmentWrite {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EnvironmentWrite")
            .field("name", &self.name)
            .field("renamed_from", &self.renamed_from)
            .field(
                "keys",
                &self
                    .values
                    .as_ref()
                    .map(|values| values.keys().collect::<Vec<_>>()),
            )
            .finish()
    }
}

/// The environments a reviewed rollback writes, if the stored values and
/// the history key are still what the review saw. Comparisons are exact.
pub fn apply_rollback(
    plan: &RollbackPlan,
    choices: &Choices,
    current: &Values<'_>,
    keys: &DigestKeys,
    generation: u32,
) -> Result<Vec<EnvironmentWrite>, Refusal> {
    if generation != plan.generation {
        return Err(Refusal::ChangedSinceReview);
    }
    let mut writes = Vec::with_capacity(plan.environments.len());
    let mut any = false;
    for (index, environment) in plan.environments.iter().enumerate() {
        let current_values = environment
            .current
            .as_deref()
            .and_then(|name| current.environment(name));
        if environment.current.is_some() && current_values.is_none() {
            return Err(Refusal::ChangedSinceReview);
        }
        let bound = match environment.binding {
            Binding::Environment(digest) => environment_binding(keys, current_values) == digest,
            Binding::Key(digest) => {
                let key = environment.rows.first().map(|row| row.key.as_str());
                key_binding(
                    keys,
                    key.and_then(|key| current_values.and_then(|values| values.get(key)).copied()),
                ) == digest
            }
        };
        if !bound {
            return Err(Refusal::ChangedSinceReview);
        }
        let mut values: BTreeMap<String, Zeroizing<String>> = current_values
            .map(|values| {
                values
                    .iter()
                    .map(|(key, value)| ((*key).to_owned(), Zeroizing::new((*value).to_owned())))
                    .collect()
            })
            .unwrap_or_default();
        let mut changed = false;
        for (row_index, row) in environment.rows.iter().enumerate() {
            if !row.changes() || choices.skipped.contains(&(index, row_index)) {
                continue;
            }
            match &row.target {
                TargetValue::Known(value) => {
                    values.insert(row.key.clone(), value.clone());
                }
                TargetValue::Absent => {
                    values.remove(&row.key);
                }
                TargetValue::Unknown(_) => continue,
            }
            changed = true;
        }
        if let Some(current_name) = environment.current.as_ref().filter(|_| {
            environment.offers_deletion()
                && values.is_empty()
                && !choices.keep_empty.contains(&index)
        }) {
            any = true;
            writes.push(EnvironmentWrite {
                name: current_name.clone(),
                renamed_from: None,
                values: None,
            });
            continue;
        }
        let renamed = environment.current.is_some()
            && environment.target.is_some()
            && environment.current != environment.target;
        if !changed && !renamed {
            continue;
        }
        any = true;
        writes.push(EnvironmentWrite {
            name: environment
                .target
                .clone()
                .or_else(|| environment.current.clone())
                .expect("an environment exists at one end"),
            renamed_from: renamed.then(|| environment.current.clone()).flatten(),
            values: Some(values),
        });
    }
    if !any {
        return Err(Refusal::NothingToApply);
    }
    Ok(writes)
}

#[cfg(test)]
mod tests;
