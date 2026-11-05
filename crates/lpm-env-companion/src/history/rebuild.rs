//! Rebuilding a past state and planning rollbacks.
//!
//! The walk starts from the stored values and goes from the newest entry to
//! the oldest, undoing each change: a key takes its "before" side. At each
//! readable part's boundary the state derived so far is reconciled with
//! that part's summary, which makes keys a lost entry or an unreadable part
//! changed unknown. A key whose earlier value history didn't keep stays
//! unknown, with its digest when one is known; any kept value with the same
//! digest resolves it. Nothing unknown is ever guessed.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fmt;

use zeroize::Zeroizing;

use crate::history::codec::{
    Action, Entry, EntryId, EnvironmentKind, KeyKind, Keys, RelatedSide, Remote, Side, Slot,
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
    Known {
        value: Zeroizing<String>,
        digest: Digest,
    },
    Absent,
    Unknown {
        digest: Option<Digest>,
        reason: UnknownReason,
    },
}

impl KeyState {
    fn from_side(side: &Side<'_>) -> Self {
        match side {
            Side::Absent => Self::Absent,
            Side::Value { value, digest } => Self::Known {
                value: Zeroizing::new((*value).to_owned()),
                digest: *digest,
            },
            Side::DigestOnly { digest, reason } => Self::Unknown {
                digest: Some(*digest),
                reason: match reason {
                    Unkept::NotRecorded => UnknownReason::NotRecorded,
                    Unkept::TooLarge => UnknownReason::TooLarge,
                },
            },
            Side::Removed => Self::Unknown {
                digest: None,
                reason: UnknownReason::Removed,
            },
        }
    }

    fn unknown(slot: Slot, reason: UnknownReason) -> Self {
        match slot {
            Slot::Digest(digest) => Self::Unknown {
                digest: Some(digest),
                reason,
            },
            Slot::Removed => Self::Unknown {
                digest: None,
                reason: UnknownReason::Removed,
            },
        }
    }

    fn target(&self) -> TargetValue {
        match self {
            Self::Known { value, .. } => TargetValue::Known(value.clone()),
            Self::Absent => TargetValue::Absent,
            Self::Unknown { reason, .. } => TargetValue::Unknown(*reason),
        }
    }

    fn is_absent(&self) -> bool {
        matches!(self, Self::Absent)
    }

    /// The digest a kept value elsewhere can resolve this state by. A
    /// removed value never resolves: removing it took its digest too.
    fn wanted(&self) -> Option<Digest> {
        match self {
            Self::Unknown {
                digest: Some(digest),
                reason:
                    UnknownReason::NotRecorded | UnknownReason::TooLarge | UnknownReason::Unreadable,
            } => Some(*digest),
            _ => None,
        }
    }

    /// Whether this state agrees with a summary slot.
    fn agrees_with(&self, slot: Slot) -> bool {
        match (self, slot) {
            (Self::Known { digest, .. }, Slot::Digest(recorded)) => *digest == recorded,
            (
                Self::Unknown {
                    digest: Some(digest),
                    ..
                },
                Slot::Digest(recorded),
            ) => *digest == recorded,
            (
                Self::Unknown {
                    reason: UnknownReason::Removed,
                    ..
                },
                Slot::Removed,
            ) => true,
            _ => false,
        }
    }
}

/// A key as the walk tracks it, one per identity: its name now, if it
/// exists now, and its state at the point the walk reached. A key keeps its
/// identity while it's absent, so a key removed and added back, or an
/// environment deleted and recreated, is still the key named now.
#[derive(Clone)]
struct TrackedKey {
    current: Option<String>,
    state: KeyState,
}

type KeyId = usize;

#[derive(Clone, Default)]
struct TrackedEnvironment {
    current: Option<String>,
    exists: bool,
    /// Set when an oversized entry hides which keys the environment had at
    /// this point: some may be missing from `keys`.
    unnamed: Option<UnknownReason>,
    /// Keys by their names at this point.
    keys: BTreeMap<String, KeyId>,
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
    keys: Vec<TrackedKey>,
    environments: BTreeMap<String, TrackedEnvironment>,
    /// Every key that exists now, by its environment's and its own name now.
    now: BTreeMap<String, BTreeMap<String, KeyId>>,
    /// Keys whose state a kept value with this digest can resolve. An ID
    /// stays listed after its state changes, so each use checks it.
    wanted: HashMap<Digest, Vec<KeyId>>,
    /// How many keys a kept value can still resolve.
    unresolved: usize,
    /// Notes per key that exists now.
    notes: HashMap<KeyId, Notes>,
}

impl State {
    fn from_values(values: &Values<'_>, digest_keys: &DigestKeys) -> Self {
        let mut state = Self::default();
        for (name, values) in values.environments() {
            let mut keys = BTreeMap::new();
            let mut now = BTreeMap::new();
            for (key, value) in values {
                let id = state.add_key(
                    Some((*key).to_owned()),
                    KeyState::Known {
                        value: Zeroizing::new((*value).to_owned()),
                        digest: digest_keys.value(value.as_bytes()),
                    },
                );
                keys.insert((*key).to_owned(), id);
                now.insert((*key).to_owned(), id);
            }
            state.environments.insert(
                (*name).to_owned(),
                TrackedEnvironment {
                    current: Some((*name).to_owned()),
                    exists: true,
                    unnamed: None,
                    keys,
                },
            );
            state.now.insert((*name).to_owned(), now);
        }
        state
    }

    fn add_key(&mut self, current: Option<String>, state: KeyState) -> KeyId {
        let id = self.keys.len();
        self.keys.push(TrackedKey {
            current,
            state: KeyState::Absent,
        });
        self.set_state(id, state);
        id
    }

    /// Every state change goes through here, which keeps `wanted` and
    /// `unresolved` true.
    fn set_state(&mut self, id: KeyId, state: KeyState) {
        if self.keys[id].state.wanted().is_some() {
            self.unresolved -= 1;
        }
        if let Some(digest) = state.wanted() {
            self.unresolved += 1;
            self.wanted.entry(digest).or_default().push(id);
        }
        self.keys[id].state = state;
    }

    fn state(&self, id: KeyId) -> &KeyState {
        &self.keys[id].state
    }

    /// Put key `id` at `name` in `environment`. A key absent at this point
    /// never displaces one that exists there.
    fn place_key(&self, environment: &mut TrackedEnvironment, name: &str, id: KeyId) {
        if let Some(existing) = environment.keys.get(name)
            && self.state(id).is_absent()
            && !self.state(*existing).is_absent()
        {
            return;
        }
        environment.keys.insert(name.to_owned(), id);
    }

    /// Put `environment` at `name`. One that didn't exist at this point
    /// never displaces one that did.
    fn place_environment(&mut self, name: &str, environment: TrackedEnvironment) {
        if let Some(existing) = self.environments.get(name)
            && !environment.exists
            && existing.exists
        {
            return;
        }
        self.environments.insert(name.to_owned(), environment);
    }

    /// The key that exists now as `key` in `environment`.
    fn now(&self, environment: &str, key: &str) -> Option<KeyId> {
        self.now.get(environment)?.get(key).copied()
    }

    /// Make the derived state agree with `summary`, the state at this point
    /// as history recorded it: a key whose derived value doesn't match its
    /// digest becomes unknown with that digest, a key the summary doesn't
    /// list is absent, and a key only the summary lists is unknown. The key
    /// set is complete again afterwards.
    fn reconcile(&mut self, summary: &Summary<'_>, reason: UnknownReason) {
        let names: Vec<String> = self.environments.keys().cloned().collect();
        for name in names {
            let mut environment = self
                .environments
                .remove(&name)
                .expect("the name came from the map");
            environment.unnamed = None;
            let recorded = summary.environments.get(name.as_str());
            environment.exists = recorded.is_some();
            for (key, id) in &environment.keys {
                crate::work::note(crate::work::Work::KeyVisit);
                match recorded.and_then(|recorded| recorded.get(key.as_str())) {
                    None => {
                        if !self.state(*id).is_absent() {
                            self.set_state(*id, KeyState::Absent);
                        }
                    }
                    Some(slot) => {
                        if !self.state(*id).agrees_with(*slot) {
                            self.set_state(*id, KeyState::unknown(*slot, reason));
                        }
                    }
                }
            }
            if let Some(recorded) = recorded {
                for (key, slot) in recorded {
                    if !environment.keys.contains_key(*key) {
                        let id = self.add_key(None, KeyState::unknown(*slot, reason));
                        environment.keys.insert((*key).to_owned(), id);
                    }
                }
            }
            self.environments.insert(name, environment);
        }
        for (name, recorded) in &summary.environments {
            if self.environments.contains_key(*name) {
                continue;
            }
            let mut environment = TrackedEnvironment {
                exists: true,
                ..TrackedEnvironment::default()
            };
            for (key, slot) in recorded {
                let id = self.add_key(None, KeyState::unknown(*slot, reason));
                environment.keys.insert((*key).to_owned(), id);
            }
            self.environments.insert((*name).to_owned(), environment);
        }
    }

    /// Note what `entry` tells about the keys it changed that exist now: a
    /// gap it records, whether the key's current value came from a pull,
    /// and with `changed_again`, that the key changed after the point.
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
            let Keys::Changes(key_changes) = &change.keys else {
                continue;
            };
            for key_change in key_changes {
                let Some(id) = environment
                    .keys
                    .get(key_change.key)
                    .copied()
                    .filter(|id| self.keys[*id].current.is_some())
                else {
                    continue;
                };
                let notes = self.notes.entry(id).or_default();
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

    /// Undo `entry`: every key it changed takes its "before" side, under
    /// the name it had before. Every changed environment and key is taken
    /// out before any is put back, so an entry that renamed one name to
    /// another and reused the first undoes in any order.
    fn undo(&mut self, entry: &Entry<'_>) {
        let taken: Vec<TrackedEnvironment> = entry
            .environments
            .iter()
            .map(|change| self.environments.remove(change.name).unwrap_or_default())
            .collect();
        for (change, mut environment) in entry.environments.iter().zip(taken) {
            match &change.keys {
                Keys::Count(_) => {
                    let ids: Vec<KeyId> = environment.keys.values().copied().collect();
                    for id in ids {
                        self.set_state(
                            id,
                            KeyState::Unknown {
                                digest: None,
                                reason: UnknownReason::TooLarge,
                            },
                        );
                    }
                    environment.unnamed = Some(UnknownReason::TooLarge);
                }
                Keys::Changes(key_changes) => {
                    let ids: Vec<Option<KeyId>> = key_changes
                        .iter()
                        .map(|key_change| environment.keys.remove(key_change.key))
                        .collect();
                    for (key_change, id) in key_changes.iter().zip(ids) {
                        let before = KeyState::from_side(&key_change.before);
                        let id = match id {
                            Some(id) => {
                                self.set_state(id, before);
                                id
                            }
                            None => self.add_key(None, before),
                        };
                        let name = match key_change.kind {
                            KeyKind::RenamedFrom(from) => from,
                            _ => key_change.key,
                        };
                        self.place_key(&mut environment, name, id);
                    }
                }
            }
            let name = match change.kind {
                EnvironmentKind::Created => {
                    environment.exists = false;
                    environment.unnamed = None;
                    let ids: Vec<KeyId> = environment.keys.values().copied().collect();
                    for id in ids {
                        if !self.state(id).is_absent() {
                            self.set_state(id, KeyState::Absent);
                        }
                    }
                    change.name
                }
                EnvironmentKind::Removed | EnvironmentKind::Unchanged => {
                    environment.exists = true;
                    change.name
                }
                EnvironmentKind::RenamedFrom(from) => {
                    environment.exists = true;
                    from
                }
            };
            self.place_environment(name, environment);
        }
    }

    /// Resolve unknown keys whose digest matches a kept value in `entry`.
    fn resolve(&mut self, entry: &Entry<'_>) {
        if self.unresolved == 0 {
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
                    let Some(ids) = self.wanted.remove(digest) else {
                        continue;
                    };
                    for id in ids {
                        crate::work::note(crate::work::Work::KeyVisit);
                        if self.state(id).wanted() == Some(*digest) {
                            self.set_state(
                                id,
                                KeyState::Known {
                                    value: Zeroizing::new((*value).to_owned()),
                                    digest: *digest,
                                },
                            );
                        }
                    }
                }
            }
        }
    }

    fn has_unresolved(&self) -> bool {
        self.unresolved > 0
    }

    /// Note a live gap on every key now whose value differs from the newest
    /// summary.
    fn note_live_gap(&mut self, summary: &Summary<'_>, since: Option<i64>) {
        let mut gaps = Vec::new();
        for (name, keys) in &self.now {
            let recorded = summary.environments.get(name.as_str());
            for (key, id) in keys {
                let same = recorded
                    .and_then(|recorded| recorded.get(key.as_str()))
                    .is_some_and(|slot| self.state(*id).agrees_with(*slot));
                if !same {
                    gaps.push(*id);
                }
            }
        }
        for id in gaps {
            self.notes
                .entry(id)
                .or_default()
                .gaps
                .push(Gap { since, until: None });
        }
    }

    fn notes(&self, id: Option<KeyId>) -> Notes {
        id.and_then(|id| self.notes.get(&id))
            .cloned()
            .unwrap_or_default()
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
    /// The rollback would give an environment back a name another
    /// environment holds now. A rollback never touches other environments.
    NameTaken(String),
}

impl fmt::Display for PlanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read(error) => write!(formatter, "{error}"),
            Self::EntryNotFound => formatter.write_str("no entry in local history has that ID"),
            Self::UnknownEnvironment => {
                formatter.write_str("that environment isn't in local history at that point")
            }
            Self::NameTaken(name) => write!(
                formatter,
                "another environment is named {name} now; rename it first, then roll back"
            ),
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
/// Each key's "before" state is a key in the walk's state, so a kept value
/// further back resolves it like any other.
struct OwnedEntry {
    environments: Vec<OwnedEnvironmentChange>,
}

struct OwnedEnvironmentChange {
    name: String,
    kind: OwnedEnvironmentKind,
    /// `None` when the entry was oversized and named no keys.
    keys: Option<Vec<OwnedKeyChange>>,
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
    before: KeyId,
}

fn owned(entry: &Entry<'_>, state: &mut State) -> OwnedEntry {
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
                    Keys::Count(_) => None,
                    Keys::Changes(changes) => Some(
                        changes
                            .iter()
                            .map(|key_change| OwnedKeyChange {
                                key: key_change.key.to_owned(),
                                renamed_from: match key_change.kind {
                                    KeyKind::RenamedFrom(from) => Some(from.to_owned()),
                                    _ => None,
                                },
                                before: state
                                    .add_key(None, KeyState::from_side(&key_change.before)),
                            })
                            .collect(),
                    ),
                },
            })
            .collect(),
    }
}

/// Walk from `current` back to `point`, then on while unknown digests may
/// still resolve.
fn walk(
    opened: &Opened,
    source: &mut impl PartSource,
    current: &Values<'_>,
    point: Point,
) -> Result<Walked, PlanError> {
    let mut state = State::from_values(current, &opened.keys);
    let mut first_part = true;
    let mut skipped_unreadable = false;
    let mut reached = false;
    // Set when the point is just before a part's oldest entry, so the next
    // part's summary is the state at the point itself.
    let mut point_at_boundary = false;
    let mut walked_entry = None;
    let mut target_time = 0;
    opened.walk(source, |read| {
        let decoded = match read {
            PartRead::Unreadable { .. } => {
                skipped_unreadable = true;
                point_at_boundary = false;
                return true;
            }
            PartRead::Readable { decoded, .. } => decoded,
        };
        let summary = opened.scrubbed_summary(&decoded.summary);
        let reason = if skipped_unreadable {
            UnknownReason::Unreadable
        } else {
            UnknownReason::NotRecorded
        };
        if first_part {
            first_part = false;
            state.note_live_gap(&summary, decoded.last_header().map(|header| header.time));
        }
        if !reached || point_at_boundary {
            state.reconcile(&summary, reason);
            point_at_boundary = false;
        }
        skipped_unreadable = false;
        let oldest = decoded.decoded_entries().next().map(|entry| entry.id);
        for entry in decoded.decoded_entries().rev() {
            let entry = opened.scrubbed(entry);
            if reached {
                state.resolve(&entry);
                if !state.has_unresolved() {
                    return false;
                }
                continue;
            }
            if entry.id == point.entry {
                target_time = entry.time;
                walked_entry = Some(owned(&entry, &mut state));
                state.note(&entry, false);
                if point.side == RelatedSide::Before {
                    state.undo(&entry);
                    point_at_boundary = oldest == Some(entry.id);
                }
                reached = true;
                state.resolve(&entry);
                if !state.has_unresolved() && !point_at_boundary {
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
    /// The other rows of a key renamed since the point: its name now leaves
    /// and its earlier name comes back. They apply together or not at all.
    pub linked: Vec<String>,
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
            .field("linked", &self.linked)
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

    fn shown(&self) -> bool {
        self.changes() || matches!(self.target, TargetValue::Unknown(_))
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
    /// Set when history can't name every key the environment had at the
    /// point, because an oversized change hid them: the review says so, and
    /// those keys are left as they are.
    pub unnamed_keys: Option<UnknownReason>,
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

    /// Whether the rollback gives the environment back its earlier name.
    pub fn renames(&self) -> bool {
        self.current.is_some() && self.target.is_some() && self.current != self.target
    }

    pub fn changing_rows(&self) -> usize {
        self.rows.iter().filter(|row| row.changes()).count()
    }

    /// Whether applying the plan as reviewed changes this environment.
    pub fn changes_anything(&self) -> bool {
        self.changing_rows() > 0 || self.recreates() || self.renames() || self.offers_deletion()
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

impl RollbackPlan {
    /// Whether applying the plan as reviewed changes anything.
    pub fn changes_anything(&self) -> bool {
        self.environments
            .iter()
            .any(EnvironmentPlan::changes_anything)
    }
}

fn environment_binding(keys: &DigestKeys, values: Option<&BTreeMap<&str, &str>>) -> Option<Digest> {
    let values = values?;
    let length = values
        .iter()
        .map(|(key, value)| 16 + key.len() + value.len())
        .sum();
    let mut encoded = Zeroizing::new(Vec::with_capacity(length));
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

/// Link the rows of each key renamed since the point, then make every row
/// of a group whose earlier value is unknown unknown too: half a rename
/// would lose the value or keep a copy.
fn link_rows(rows: &mut [Row], links: &[(String, String)]) {
    let index: HashMap<&str, usize> = rows
        .iter()
        .enumerate()
        .map(|(position, row)| (row.key.as_str(), position))
        .collect();
    let mut groups = Groups::new(rows.len());
    for (left, right) in links {
        if let (Some(left), Some(right)) = (index.get(left.as_str()), index.get(right.as_str())) {
            groups.join(*left, *right);
        }
    }
    let members = groups.members();
    for group in members.values().filter(|group| group.len() > 1) {
        let unknown = group
            .iter()
            .find_map(|position| match rows[*position].target {
                TargetValue::Unknown(reason) => Some(reason),
                _ => None,
            });
        for position in group {
            rows[*position].linked = group
                .iter()
                .filter(|other| *other != position)
                .map(|other| rows[*other].key.clone())
                .collect();
            if let Some(reason) = unknown {
                rows[*position].target = TargetValue::Unknown(reason);
            }
        }
    }
}

/// Disjoint sets over row positions.
struct Groups {
    parent: Vec<usize>,
}

impl Groups {
    fn new(size: usize) -> Self {
        Self {
            parent: (0..size).collect(),
        }
    }

    fn find(&mut self, mut position: usize) -> usize {
        while self.parent[position] != position {
            self.parent[position] = self.parent[self.parent[position]];
            position = self.parent[position];
        }
        position
    }

    fn join(&mut self, left: usize, right: usize) {
        let (left, right) = (self.find(left), self.find(right));
        if left != right {
            self.parent[left.max(right)] = left.min(right);
        }
    }

    fn members(&mut self) -> BTreeMap<usize, Vec<usize>> {
        let mut members: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
        for position in 0..self.parent.len() {
            let root = self.find(position);
            members.entry(root).or_default().push(position);
        }
        members
    }
}

/// Refuse a rollback that would give an environment a name another one
/// holds now, which the rollback would overwrite. `freed` are names this
/// rollback takes away.
fn check_target_name(
    current: &Values<'_>,
    current_name: Option<&str>,
    target_name: Option<&str>,
    freed: &BTreeSet<&str>,
) -> Result<(), PlanError> {
    match target_name {
        Some(target)
            if current_name != Some(target)
                && current.environment(target).is_some()
                && !freed.contains(target) =>
        {
            Err(PlanError::NameTaken(target.to_owned()))
        }
        _ => Ok(()),
    }
}

/// How a rollback names its environment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvironmentRef<'a> {
    /// As it's named now, as a person types it. A name no environment has
    /// now is taken as the name at the point, which names a deleted one.
    Now(&'a str),
    /// As it was named at the point, as the entry there names it.
    AtPoint(&'a str),
}

impl State {
    /// The environment `reference` names, with its name at the point.
    fn environment(&self, reference: EnvironmentRef<'_>) -> Option<(&str, &TrackedEnvironment)> {
        let at_point = |name: &str| {
            self.environments
                .get_key_value(name)
                .map(|(name, tracked)| (name.as_str(), tracked))
        };
        match reference {
            EnvironmentRef::Now(name) => self
                .environments
                .iter()
                .find(|(_, tracked)| tracked.current.as_deref() == Some(name))
                .map(|(name, tracked)| (name.as_str(), tracked))
                .or_else(|| at_point(name)),
            EnvironmentRef::AtPoint(name) => at_point(name),
        }
    }
}

/// Plan rolling an environment back to its whole state at `point`.
pub fn plan_environment_rollback(
    opened: &Opened,
    source: &mut impl PartSource,
    current: &Values<'_>,
    environment: EnvironmentRef<'_>,
    point: Point,
) -> Result<RollbackPlan, PlanError> {
    let walked = walk(opened, source, current, point)?;
    let state = &walked.state;
    let (environment, tracked) = state
        .environment(environment)
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
    check_target_name(
        current,
        current_name.as_deref(),
        target_name.as_deref(),
        &BTreeSet::new(),
    )?;
    let mut names: BTreeSet<&str> = BTreeSet::new();
    let mut links = Vec::new();
    if tracked.exists {
        for (name, id) in &tracked.keys {
            if state.state(*id).is_absent() {
                continue;
            }
            names.insert(name.as_str());
            if let Some(now) = state.keys[*id]
                .current
                .as_deref()
                .filter(|now| *now != name && current_name.is_some())
            {
                links.push((name.clone(), now.to_owned()));
            }
        }
    }
    if let Some(values) = current_values {
        names.extend(values.keys().copied());
    }
    let mut rows = Vec::with_capacity(names.len());
    for name in names {
        let target = if tracked.exists {
            tracked
                .keys
                .get(name)
                .map_or(TargetValue::Absent, |id| state.state(*id).target())
        } else {
            TargetValue::Absent
        };
        let current_value = current_values.and_then(|values| values.get(name)).copied();
        let notes = state.notes(
            current_name
                .as_deref()
                .and_then(|environment| state.now(environment, name)),
        );
        let row = Row {
            key: name.to_owned(),
            current: current_value.map(|value| Zeroizing::new(value.to_owned())),
            target,
            gaps: notes.gaps,
            pulled: notes.pulled,
            changed_again: None,
            linked: Vec::new(),
        };
        if row.shown() {
            rows.push(row);
        }
    }
    link_rows(&mut rows, &links);
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
            unnamed_keys: tracked.unnamed.filter(|_| tracked.exists),
        }],
    })
}

/// Plan rolling one key back to its value before `entry`, as the key
/// inspector's Roll Back… does, so it never does nothing even on the newest
/// change. `key` names it now; a key that doesn't exist now is the one its
/// name had at the point.
pub fn plan_key_rollback(
    opened: &Opened,
    source: &mut impl PartSource,
    current: &Values<'_>,
    environment: EnvironmentRef<'_>,
    key: &str,
    entry: EntryId,
) -> Result<RollbackPlan, PlanError> {
    let point = Point {
        entry,
        side: RelatedSide::Before,
    };
    let walked = walk(opened, source, current, point)?;
    let state = &walked.state;
    let (point_name, tracked) = state
        .environment(environment)
        .ok_or(PlanError::UnknownEnvironment)?;
    let environment = tracked
        .current
        .as_deref()
        .filter(|name| current.environment(name).is_some())
        .unwrap_or(point_name);
    let now = state.now(environment, key);
    let id = now.or_else(|| tracked.keys.get(key).copied());
    let target = id.map_or(TargetValue::Absent, |id| state.state(id).target());
    let notes = state.notes(now);
    let current_value = current.get(environment, key);
    let row = Row {
        key: key.to_owned(),
        current: current_value.map(|value| Zeroizing::new(value.to_owned())),
        target,
        gaps: notes.gaps,
        pulled: notes.pulled,
        changed_again: None,
        linked: Vec::new(),
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
            unnamed_keys: None,
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
    let state = &walked.state;
    let undone = walked.entry.as_ref().expect("the walk reached the entry");
    let mut names = Vec::with_capacity(undone.environments.len());
    for change in &undone.environments {
        let current_name = state
            .environments
            .get(&change.name)
            .and_then(|tracked| tracked.current.clone())
            .filter(|name| current.environment(name).is_some());
        let target_name = match &change.kind {
            OwnedEnvironmentKind::Created => None,
            OwnedEnvironmentKind::RenamedFrom(from) => Some(from.clone()),
            OwnedEnvironmentKind::Unchanged | OwnedEnvironmentKind::Removed => {
                Some(change.name.clone())
            }
        };
        names.push((current_name, target_name));
    }
    let freed: BTreeSet<&str> = names
        .iter()
        .filter_map(|(current_name, target_name)| match current_name {
            Some(current_name) if target_name.as_ref() != Some(current_name) => {
                Some(current_name.as_str())
            }
            _ => None,
        })
        .collect();
    for (current_name, target_name) in &names {
        check_target_name(
            current,
            current_name.as_deref(),
            target_name.as_deref(),
            &freed,
        )?;
    }
    let mut environments = Vec::with_capacity(undone.environments.len());
    for (change, (current_name, target_name)) in undone.environments.iter().zip(names) {
        let tracked = state.environments.get(&change.name);
        let current_values = current_name
            .as_deref()
            .and_then(|name| current.environment(name));
        let mut rows: BTreeMap<String, Row> = BTreeMap::new();
        let mut links = Vec::new();
        for key_change in change.keys.iter().flatten() {
            let id_now = tracked
                .and_then(|tracked| tracked.keys.get(&key_change.key))
                .copied()
                .filter(|id| state.keys[*id].current.is_some());
            let current_key = id_now
                .and_then(|id| state.keys[id].current.clone())
                .filter(|name| {
                    current_values.is_some_and(|values| values.contains_key(name.as_str()))
                });
            let notes = state.notes(id_now.filter(|_| current_key.is_some()));
            let target = state.state(key_change.before).target();
            let target_key = key_change
                .renamed_from
                .clone()
                .unwrap_or_else(|| key_change.key.clone());
            let row_key = if key_change.renamed_from.is_some() {
                target_key.clone()
            } else {
                current_key.clone().unwrap_or_else(|| target_key.clone())
            };
            if let Some(leaving) = current_key
                .as_ref()
                .filter(|leaving| key_change.renamed_from.is_some() && **leaving != row_key)
            {
                links.push((leaving.clone(), row_key.clone()));
                rows.entry(leaving.clone()).or_insert_with(|| Row {
                    key: leaving.clone(),
                    current: current_values
                        .and_then(|values| values.get(leaving.as_str()))
                        .map(|value| Zeroizing::new((*value).to_owned())),
                    target: TargetValue::Absent,
                    gaps: notes.gaps.clone(),
                    pulled: notes.pulled.clone(),
                    changed_again: notes.changed_again.clone(),
                    linked: Vec::new(),
                });
            }
            let row = Row {
                current: current_values
                    .and_then(|values| values.get(row_key.as_str()))
                    .map(|value| Zeroizing::new((*value).to_owned())),
                key: row_key.clone(),
                target,
                gaps: notes.gaps,
                pulled: notes.pulled,
                changed_again: notes.changed_again,
                linked: Vec::new(),
            };
            rows.insert(row_key, row);
        }
        let mut rows: Vec<Row> = rows.into_values().filter(Row::shown).collect();
        link_rows(&mut rows, &links);
        environments.push(EnvironmentPlan {
            binding: Binding::Environment(environment_binding(&opened.keys, current_values)),
            current: current_name,
            target: target_name,
            rows,
            unnamed_keys: change.keys.is_none().then_some(UnknownReason::TooLarge),
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
///
/// A client applies the writes as one values write: first it removes every
/// environment a write renames or deletes, then it stores every write's
/// values under its name, so writes that swap names apply in any order.
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
        let skipped: HashSet<&str> = environment
            .rows
            .iter()
            .enumerate()
            .filter(|(row_index, _)| choices.skipped.contains(&(index, *row_index)))
            .flat_map(|(_, row)| {
                std::iter::once(row.key.as_str()).chain(row.linked.iter().map(String::as_str))
            })
            .collect();
        let mut values: BTreeMap<String, Zeroizing<String>> = current_values
            .map(|values| {
                values
                    .iter()
                    .map(|(key, value)| ((*key).to_owned(), Zeroizing::new((*value).to_owned())))
                    .collect()
            })
            .unwrap_or_default();
        let mut changed = false;
        for row in &environment.rows {
            if !row.changes() || skipped.contains(row.key.as_str()) {
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
            writes.push(EnvironmentWrite {
                name: current_name.clone(),
                renamed_from: None,
                values: None,
            });
            continue;
        }
        if !changed && !environment.renames() && !environment.recreates() {
            continue;
        }
        writes.push(EnvironmentWrite {
            name: environment
                .target
                .clone()
                .or_else(|| environment.current.clone())
                .expect("an environment exists at one end"),
            renamed_from: environment
                .renames()
                .then(|| environment.current.clone())
                .flatten(),
            values: Some(values),
        });
    }
    if writes.is_empty() {
        return Err(Refusal::NothingToApply);
    }
    let freed: HashSet<&str> = writes
        .iter()
        .filter_map(|write| match (&write.renamed_from, &write.values) {
            (Some(from), _) => Some(from.as_str()),
            (None, None) => Some(write.name.as_str()),
            (None, Some(_)) => None,
        })
        .collect();
    let mut names = HashSet::with_capacity(writes.len());
    for write in &writes {
        if !names.insert(write.name.as_str()) {
            return Err(Refusal::ChangedSinceReview);
        }
        let takes_a_new_name = write.values.is_some()
            && plan.environments.iter().any(|environment| {
                environment.target.as_deref() == Some(write.name.as_str())
                    && environment.current.as_deref() != Some(write.name.as_str())
            });
        if takes_a_new_name
            && current.environment(&write.name).is_some()
            && !freed.contains(write.name.as_str())
        {
            return Err(Refusal::ChangedSinceReview);
        }
    }
    Ok(writes)
}

#[cfg(test)]
mod tests;
