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
use std::rc::Rc;

use zeroize::Zeroizing;

use crate::history::codec::{
    Action, Entry, EntryId, EnvironmentKind, KeyKind, Keys, RelatedSide, Remote, Side, Slot,
    Summary, Unkept,
};
use crate::history::read::{
    EntryInfo, IdPrefix, Opened, PartRead, PartSource, ReadError, entry_info,
};
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

/// A name the walk shares between the maps that hold it, so a key's name
/// is stored once.
type Name = Rc<str>;

/// A key as the walk tracks it, one per identity: its name now, if it
/// exists now, and its state at the point the walk reached. A key keeps its
/// identity while it's absent, so a key removed and added back, or an
/// environment deleted and recreated, is still the key named now.
#[derive(Clone)]
struct TrackedKey {
    current: Option<Name>,
    state: KeyState,
}

type KeyId = usize;

#[derive(Clone, Default)]
struct TrackedEnvironment {
    current: Option<Name>,
    exists: bool,
    /// Set when an oversized entry hides which keys the environment had at
    /// this point: some may be missing from `keys`.
    unnamed: Option<UnknownReason>,
    /// Keys by their names at this point.
    keys: BTreeMap<Name, KeyId>,
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
    environments: BTreeMap<Name, TrackedEnvironment>,
    /// Environments another one displaced at a name because it existed
    /// there at this point, kept so the name they have now still finds
    /// them.
    detached: Vec<TrackedEnvironment>,
    /// Every key that exists now, by its environment's and its own name now.
    now: BTreeMap<Name, BTreeMap<Name, KeyId>>,
    /// Keys whose state a kept value with this digest can resolve. An ID
    /// stays listed after its state changes, so each use checks it.
    wanted: HashMap<Digest, Vec<KeyId>>,
    /// How many keys the plan reads that a kept value can still resolve.
    unresolved: usize,
    /// The keys the plan reads, once the point is reached; every key
    /// before.
    focus: Option<HashSet<KeyId>>,
    /// Notes per key identity.
    notes: HashMap<KeyId, Notes>,
}

impl State {
    fn from_values(values: &Values<'_>, digest_keys: &DigestKeys) -> Self {
        let mut state = Self::default();
        for (name, values) in values.environments() {
            let environment_name: Name = Rc::from(*name);
            let mut keys = BTreeMap::new();
            let mut now = BTreeMap::new();
            for (key, value) in values {
                let key_name: Name = Rc::from(*key);
                let id = state.add_key(
                    Some(key_name.clone()),
                    KeyState::Known {
                        value: Zeroizing::new((*value).to_owned()),
                        digest: digest_keys.value(value.as_bytes()),
                    },
                );
                keys.insert(key_name.clone(), id);
                now.insert(key_name, id);
            }
            state.environments.insert(
                environment_name.clone(),
                TrackedEnvironment {
                    current: Some(environment_name.clone()),
                    exists: true,
                    unnamed: None,
                    keys,
                },
            );
            state.now.insert(environment_name, now);
        }
        state
    }

    fn add_key(&mut self, current: Option<Name>, state: KeyState) -> KeyId {
        let id = self.keys.len();
        self.keys.push(TrackedKey {
            current,
            state: KeyState::Absent,
        });
        self.set_state(id, state);
        id
    }

    fn counts(&self, id: KeyId) -> bool {
        self.focus.as_ref().is_none_or(|focus| focus.contains(&id))
    }

    /// Every state change goes through here, which keeps `wanted` and
    /// `unresolved` true.
    fn set_state(&mut self, id: KeyId, state: KeyState) {
        let counts = self.counts(id);
        if counts && self.keys[id].state.wanted().is_some() {
            self.unresolved -= 1;
        }
        if let Some(digest) = state.wanted() {
            if counts {
                self.unresolved += 1;
            }
            self.wanted.entry(digest).or_default().push(id);
        }
        self.keys[id].state = state;
    }

    /// From now on, wait only for the keys in `focus` to resolve.
    fn set_focus(&mut self, focus: HashSet<KeyId>) {
        self.unresolved = focus
            .iter()
            .filter(|id| self.state(**id).wanted().is_some())
            .count();
        self.focus = Some(focus);
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
        environment.keys.insert(Rc::from(name), id);
    }

    /// Put `environment` at `name`. One that didn't exist at this point
    /// never displaces one that did; the one left out is kept apart.
    fn place_environment(&mut self, name: &str, environment: TrackedEnvironment) {
        if let Some(existing) = self.environments.get(name)
            && !environment.exists
            && existing.exists
        {
            self.detached.push(environment);
            return;
        }
        if let Some(displaced) = self.environments.insert(Rc::from(name), environment) {
            self.detached.push(displaced);
        }
    }

    /// The key that exists now as `key` in `environment`.
    fn now(&self, environment: &str, key: &str) -> Option<KeyId> {
        self.now.get(environment)?.get(key).copied()
    }

    /// The environment `reference` names, with its name at the point.
    fn environment(&self, reference: EnvironmentRef<'_>) -> Option<(&str, &TrackedEnvironment)> {
        let at_point = |name: &str| {
            self.environments
                .get_key_value(name)
                .map(|(name, tracked)| (&**name, tracked))
        };
        match reference {
            EnvironmentRef::Now(name) => self
                .environments
                .iter()
                .find(|(_, tracked)| tracked.current.as_deref() == Some(name))
                .map(|(name, tracked)| (&**name, tracked))
                .or_else(|| {
                    self.detached.iter().find_map(|tracked| {
                        tracked
                            .current
                            .as_deref()
                            .filter(|current| *current == name)
                            .map(|current| (current, tracked))
                    })
                })
                .or_else(|| at_point(name)),
            EnvironmentRef::AtPoint(name) => at_point(name),
        }
    }

    /// The key a key rollback reads: the key named `key` now in the
    /// environment, or the key its name had at the point.
    fn key(
        &self,
        environment: EnvironmentRef<'_>,
        key: &str,
        current: &Values<'_>,
    ) -> Option<KeyId> {
        let (_, tracked) = self.environment(environment)?;
        tracked
            .current
            .as_deref()
            .filter(|name| current.environment(name).is_some())
            .and_then(|name| self.now(name, key))
            .or_else(|| tracked.keys.get(key).copied())
    }

    /// Make the derived state agree with `summary`, the state at this point
    /// as history recorded it: a key whose derived value doesn't match its
    /// digest becomes unknown with that digest, a key the summary doesn't
    /// list is absent, and a key only the summary lists is unknown. The key
    /// set is complete again afterwards.
    fn reconcile(&mut self, summary: &Summary<'_>, reason: UnknownReason) {
        let names: Vec<Name> = self.environments.keys().cloned().collect();
        for name in names {
            let mut environment = self
                .environments
                .remove(&name)
                .expect("the name came from the map");
            environment.unnamed = None;
            let recorded = summary.environments.get(&*name);
            environment.exists = recorded.is_some();
            for (key, id) in &environment.keys {
                crate::work::note(crate::work::Work::KeyVisit);
                match recorded.and_then(|recorded| recorded.get(&**key)) {
                    None => {
                        if !self.state(*id).is_absent() {
                            self.set_state(*id, KeyState::Absent);
                        }
                    }
                    Some(slot) => {
                        let state = self.state(*id);
                        if !state.agrees_with(*slot) {
                            // A key an oversized change hid learns its digest
                            // here and keeps its reason, unless an unreadable
                            // part came between.
                            let reason = match (state, reason) {
                                (
                                    KeyState::Unknown {
                                        digest: None,
                                        reason: hidden @ UnknownReason::TooLarge,
                                    },
                                    UnknownReason::NotRecorded,
                                ) => *hidden,
                                _ => reason,
                            };
                            self.set_state(*id, KeyState::unknown(*slot, reason));
                        }
                    }
                }
            }
            if let Some(recorded) = recorded {
                for (key, slot) in recorded {
                    if !environment.keys.contains_key(*key) {
                        let id = self.add_key(None, KeyState::unknown(*slot, reason));
                        environment.keys.insert(Rc::from(*key), id);
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
                environment.keys.insert(Rc::from(*key), id);
            }
            self.environments.insert(Rc::from(*name), environment);
        }
    }

    /// Note what `entry` tells about the keys it changed: a gap it records,
    /// whether the key's value after it came from a pull, and with
    /// `changed_again`, that the key changed after the point.
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
                let Some(id) = environment.keys.get(key_change.key).copied() else {
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

    /// Resolve wanted digests from `values`, the current ones: a value
    /// digests the same in any key.
    fn resolve_from_values(&mut self, values: &Values<'_>, digest_keys: &DigestKeys) {
        for keys in values.environments().values() {
            for value in keys.values() {
                if self.unresolved == 0 {
                    return;
                }
                let digest = digest_keys.value(value.as_bytes());
                let Some(ids) = self.wanted.remove(&digest) else {
                    continue;
                };
                for id in ids {
                    if self.state(id).wanted() == Some(digest) {
                        self.set_state(
                            id,
                            KeyState::Known {
                                value: Zeroizing::new((*value).to_owned()),
                                digest,
                            },
                        );
                    }
                }
            }
        }
    }

    /// The live gap against the newest summary: the keys now whose value
    /// differs from it, and the names of keys it lists that are gone now,
    /// which the summary's reconcile gives an identity.
    fn live_gap(&self, summary: &Summary<'_>) -> (Vec<KeyId>, Vec<(Name, Name)>) {
        let mut changed = Vec::new();
        for (name, keys) in &self.now {
            let recorded = summary.environments.get(&**name);
            for (key, id) in keys {
                let same = recorded
                    .and_then(|recorded| recorded.get(&**key))
                    .is_some_and(|slot| self.state(*id).agrees_with(*slot));
                if !same {
                    changed.push(*id);
                }
            }
        }
        let mut gone = Vec::new();
        for (name, recorded) in &summary.environments {
            let now = self.now.get(*name);
            for key in recorded.keys() {
                if now.is_none_or(|now| !now.contains_key(*key)) {
                    gone.push((Rc::from(*name), Rc::from(*key)));
                }
            }
        }
        (changed, gone)
    }

    fn note_gap(&mut self, id: KeyId, since: Option<i64>) {
        self.notes
            .entry(id)
            .or_default()
            .gaps
            .push(Gap { since, until: None });
    }

    fn take_notes(&mut self, id: Option<KeyId>) -> Notes {
        id.and_then(|id| self.notes.remove(&id)).unwrap_or_default()
    }

    /// Wait only for what `target` reads: the environment's keys at the
    /// point, the key, or the undone entry's "before" sides.
    fn focus_on(&mut self, target: &Target, undone: Option<&OwnedEntry>, current: &Values<'_>) {
        let focus: HashSet<KeyId> = match target {
            Target::Environment { environment, .. } => self
                .environment(environment.reference())
                .filter(|(_, tracked)| tracked.exists)
                .map(|(_, tracked)| tracked.keys.values().copied().collect())
                .unwrap_or_default(),
            Target::Key { environment, key } => self
                .key(environment.reference(), key, current)
                .into_iter()
                .collect(),
            Target::Undo { .. } => undone
                .iter()
                .flat_map(|undone| &undone.environments)
                .flat_map(|change| change.keys.iter().flatten())
                .map(|key_change| key_change.before)
                .collect(),
        };
        self.set_focus(focus);
    }
}

/// Why a rollback can't be planned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlanError {
    Read(ReadError),
    /// No readable entry has that ID.
    EntryNotFound,
    /// More than one entry starts with that ID.
    AmbiguousEntry,
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
            Self::AmbiguousEntry => {
                formatter.write_str("more than one entry in local history starts with that ID")
            }
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

/// How a rollback names its environment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvironmentRef<'a> {
    /// As it's named now, as a person types it. A name no environment has
    /// now is taken as the name at the point, which names a deleted one.
    Now(&'a str),
    /// As it was named at the point, as the entry there names it.
    AtPoint(&'a str),
}

/// An owned [`EnvironmentRef`], for a choice made once the entry is found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnvironmentName {
    Now(String),
    AtPoint(String),
}

impl EnvironmentName {
    pub fn reference(&self) -> EnvironmentRef<'_> {
        match self {
            Self::Now(name) => EnvironmentRef::Now(name),
            Self::AtPoint(name) => EnvironmentRef::AtPoint(name),
        }
    }
}

impl From<EnvironmentRef<'_>> for EnvironmentName {
    fn from(reference: EnvironmentRef<'_>) -> Self {
        match reference {
            EnvironmentRef::Now(name) => Self::Now(name.to_owned()),
            EnvironmentRef::AtPoint(name) => Self::AtPoint(name.to_owned()),
        }
    }
}

/// What a rollback goes back to, chosen once its entry is found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    /// An environment's whole state after or before the entry.
    Environment {
        environment: EnvironmentName,
        side: RelatedSide,
    },
    /// One key, named as it is now, back to its value before the entry.
    Key {
        environment: EnvironmentName,
        key: String,
    },
    /// The keys the entry changed back to their values before it, in every
    /// environment it touched, or in `only`.
    Undo { only: Option<EnvironmentName> },
}

impl Target {
    fn side(&self) -> RelatedSide {
        match self {
            Self::Environment { side, .. } => *side,
            Self::Key { .. } => RelatedSide::Before,
            Self::Undo { .. } => RelatedSide::After,
        }
    }
}

struct Walked {
    state: State,
    info: EntryInfo,
    target: Target,
    point: Point,
    point_time: i64,
    /// The entry an undo reverts.
    undone: Option<OwnedEntry>,
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

/// Walk from `current` back to the entry `entry` names, let `choose` say
/// what to roll back, then go on only while a key the plan reads may still
/// resolve. A prefix shorter than a whole ID makes the walk read every part,
/// so another entry starting the same way is found.
fn walk<E: From<PlanError>>(
    opened: &Opened,
    source: &mut impl PartSource,
    current: &Values<'_>,
    entry_id: &IdPrefix,
    choose: impl FnOnce(&EntryInfo) -> Result<Target, E>,
) -> Result<Walked, E> {
    let mut state = State::from_values(current, &opened.keys);
    let mut choose = Some(choose);
    let mut failure: Option<E> = None;
    let mut first_part = true;
    let mut skipped_unreadable = false;
    let mut found: Option<(EntryInfo, Target, Point, i64)> = None;
    let mut undone: Option<OwnedEntry> = None;
    // Set once the plan needs nothing more; the walk then only looks for
    // another entry the prefix matches.
    let mut done = false;
    let mut ambiguous = false;
    // Set when the point is just before a part's oldest entry, so the next
    // part's summary is the state at the point itself.
    let mut point_at_boundary = false;
    opened
        .walk(source, |read| {
            let decoded = match read {
                PartRead::Unreadable { .. } => {
                    skipped_unreadable = true;
                    point_at_boundary = false;
                    return true;
                }
                PartRead::Readable { decoded, .. } => decoded,
            };
            if !done {
                let summary = opened.scrubbed_summary(&decoded.summary);
                let reason = if skipped_unreadable {
                    UnknownReason::Unreadable
                } else {
                    UnknownReason::NotRecorded
                };
                if first_part {
                    first_part = false;
                    let since = decoded.last_header().map(|header| header.time);
                    let (changed, gone) = state.live_gap(&summary);
                    state.reconcile(&summary, reason);
                    for id in changed {
                        state.note_gap(id, since);
                    }
                    for (environment, key) in gone {
                        if let Some(id) = state
                            .environments
                            .get(&environment)
                            .and_then(|tracked| tracked.keys.get(&key))
                            .copied()
                        {
                            state.note_gap(id, since);
                        }
                    }
                } else if found.is_none() || point_at_boundary {
                    state.reconcile(&summary, reason);
                    if point_at_boundary {
                        point_at_boundary = false;
                        if let Some((_, target, ..)) = &found {
                            state.focus_on(target, undone.as_ref(), current);
                        }
                        done = !state.has_unresolved();
                    }
                }
            }
            skipped_unreadable = false;
            let oldest = decoded.decoded_entries().next().map(|entry| entry.id);
            for entry in decoded.decoded_entries().rev() {
                if let Some((_, _, point, _)) = &found {
                    if entry.id != point.entry && entry_id.matches(&entry.id) {
                        ambiguous = true;
                        return false;
                    }
                    if done {
                        continue;
                    }
                    state.resolve(&opened.scrubbed(entry));
                    if !state.has_unresolved() {
                        done = true;
                        if entry_id.is_whole() {
                            return false;
                        }
                    }
                    continue;
                }
                let entry = opened.scrubbed(entry);
                if !entry_id.matches(&entry.id) {
                    state.note(&entry, true);
                    state.undo(&entry);
                    state.resolve(&entry);
                    continue;
                }
                let info = entry_info(&entry);
                let chooser = choose.take().expect("one entry is chosen");
                let target = match chooser(&info) {
                    Ok(target) => target,
                    Err(error) => {
                        failure = Some(error);
                        return false;
                    }
                };
                let side = target.side();
                if matches!(target, Target::Undo { .. }) {
                    undone = Some(owned(&entry, &mut state));
                }
                // An "after" rollback keeps the point's own change, so only
                // a rollback to before it, or an undo, replaces it.
                if side == RelatedSide::Before || matches!(target, Target::Undo { .. }) {
                    state.note(&entry, false);
                }
                if side == RelatedSide::Before {
                    state.undo(&entry);
                    point_at_boundary = oldest == Some(entry.id);
                }
                state.focus_on(&target, undone.as_ref(), current);
                state.resolve(&entry);
                let point = Point {
                    entry: entry.id,
                    side,
                };
                found = Some((info, target, point, entry.time));
                if !state.has_unresolved() && !point_at_boundary {
                    done = true;
                    if entry_id.is_whole() {
                        return false;
                    }
                }
            }
            true
        })
        .map_err(|error| E::from(PlanError::from(error)))?;
    if let Some(failure) = failure {
        return Err(failure);
    }
    if ambiguous {
        return Err(E::from(PlanError::AmbiguousEntry));
    }
    let (info, target, point, point_time) =
        found.ok_or_else(|| E::from(PlanError::EntryNotFound))?;
    // The walk passed the current values and the newer entries before it
    // knew which digests it would want, so they resolve what's left.
    if state.has_unresolved() {
        state.resolve_from_values(current, &opened.keys);
    }
    if state.has_unresolved() {
        opened
            .walk(source, |read| {
                let PartRead::Readable { decoded, .. } = read else {
                    return true;
                };
                for entry in decoded.decoded_entries().rev() {
                    if entry.id == point.entry {
                        return false;
                    }
                    state.resolve(&opened.scrubbed(entry));
                    if !state.has_unresolved() {
                        return false;
                    }
                }
                true
            })
            .map_err(|error| E::from(PlanError::from(error)))?;
    }
    Ok(Walked {
        state,
        info,
        target,
        point,
        point_time,
        undone,
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

    fn new(key: &str, current: Option<&str>, target: TargetValue, notes: Notes) -> Self {
        Self {
            key: key.to_owned(),
            current: current.map(|value| Zeroizing::new(value.to_owned())),
            target,
            gaps: notes.gaps,
            pulled: notes.pulled,
            changed_again: notes.changed_again,
            linked: Vec::new(),
        }
    }
}

/// Whether a row from `target` to `current` would be shown, decided before
/// anything is copied.
fn shown(target: Option<&KeyState>, current: Option<&str>) -> bool {
    match target {
        Some(KeyState::Known { value, .. }) => current != Some(value.as_str()),
        Some(KeyState::Unknown { .. }) => true,
        Some(KeyState::Absent) | None => current.is_some(),
    }
}

/// One environment of a rollback.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvironmentPlan {
    /// Its name now, or `None` when the rollback recreates it.
    pub current: Option<String>,
    /// Its name after the rollback, or `None` when it didn't exist at the
    /// point, so the rollback can delete it.
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
    Some(keys.binding("environment", &encoded))
}

fn key_binding(keys: &DigestKeys, value: Option<&str>) -> Option<Digest> {
    value.map(|value| keys.value(value.as_bytes()))
}

/// Link the rows of each key renamed since the point, then make every row
/// of a group whose earlier value is unknown unknown too: half a rename
/// would lose the value or keep a copy.
fn link_rows(rows: &mut [Row], links: &[(String, String)]) {
    if links.is_empty() {
        return;
    }
    let index: HashMap<&str, usize> = rows
        .iter()
        .enumerate()
        .map(|(position, row)| (row.key.as_str(), position))
        .collect();
    let mut groups = Groups::default();
    for (left, right) in links {
        if let (Some(left), Some(right)) = (index.get(left.as_str()), index.get(right.as_str())) {
            groups.join(*left, *right);
        }
    }
    for group in groups.members() {
        let unknown = group
            .iter()
            .find_map(|position| match rows[*position].target {
                TargetValue::Unknown(reason) => Some(reason),
                _ => None,
            });
        for position in &group {
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

/// Disjoint sets over the row positions that links name.
#[derive(Default)]
struct Groups {
    parent: HashMap<usize, usize>,
}

impl Groups {
    fn find(&mut self, position: usize) -> usize {
        let parent = *self.parent.entry(position).or_insert(position);
        if parent == position {
            return position;
        }
        let root = self.find(parent);
        self.parent.insert(position, root);
        root
    }

    fn join(&mut self, left: usize, right: usize) {
        let (left, right) = (self.find(left), self.find(right));
        if left != right {
            self.parent.insert(left.max(right), left.min(right));
        }
    }

    /// Every group of two or more positions.
    fn members(&mut self) -> Vec<Vec<usize>> {
        let positions: Vec<usize> = self.parent.keys().copied().collect();
        let mut members: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
        for position in positions {
            let root = self.find(position);
            members.entry(root).or_default().push(position);
        }
        members
            .into_values()
            .filter(|group| group.len() > 1)
            .map(|mut group| {
                group.sort_unstable();
                group
            })
            .collect()
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

/// Find the entry `entry` names, let `choose` say what to roll back given
/// that entry, and plan it, in one walk.
pub fn plan_rollback<E: From<PlanError>>(
    opened: &Opened,
    source: &mut impl PartSource,
    current: &Values<'_>,
    entry: &IdPrefix,
    choose: impl FnOnce(&EntryInfo) -> Result<Target, E>,
) -> Result<(EntryInfo, RollbackPlan), E> {
    let mut walked = walk(opened, source, current, entry, choose)?;
    let generation = opened.record.current().generation();
    let target = walked.target.clone();
    let plan = match &target {
        Target::Environment { environment, .. } => {
            plan_environment(&mut walked, current, &opened.keys, generation, environment)
        }
        Target::Key { environment, key } => plan_key(
            &mut walked,
            current,
            &opened.keys,
            generation,
            environment,
            key,
        ),
        Target::Undo { only } => plan_undo_walked(
            &mut walked,
            current,
            &opened.keys,
            generation,
            only.as_ref(),
        ),
    }
    .map_err(E::from)?;
    Ok((walked.info, plan))
}

/// Plan rolling an environment back to its whole state at `point`.
pub fn plan_environment_rollback(
    opened: &Opened,
    source: &mut impl PartSource,
    current: &Values<'_>,
    environment: EnvironmentRef<'_>,
    point: Point,
) -> Result<RollbackPlan, PlanError> {
    plan_rollback(
        opened,
        source,
        current,
        &IdPrefix::whole(point.entry),
        |_| {
            Ok::<_, PlanError>(Target::Environment {
                environment: environment.into(),
                side: point.side,
            })
        },
    )
    .map(|(_, plan)| plan)
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
    plan_rollback(opened, source, current, &IdPrefix::whole(entry), |_| {
        Ok::<_, PlanError>(Target::Key {
            environment: environment.into(),
            key: key.to_owned(),
        })
    })
    .map(|(_, plan)| plan)
}

/// Plan undoing `entry`: every key it changed goes back to its value before
/// it, in every environment it touched.
pub fn plan_undo(
    opened: &Opened,
    source: &mut impl PartSource,
    current: &Values<'_>,
    entry: EntryId,
) -> Result<RollbackPlan, PlanError> {
    plan_rollback(opened, source, current, &IdPrefix::whole(entry), |_| {
        Ok::<_, PlanError>(Target::Undo { only: None })
    })
    .map(|(_, plan)| plan)
}

fn plan_environment(
    walked: &mut Walked,
    current: &Values<'_>,
    keys: &DigestKeys,
    generation: u32,
    environment: &EnvironmentName,
) -> Result<RollbackPlan, PlanError> {
    let state = &walked.state;
    let (point_name, tracked) = state
        .environment(environment.reference())
        .ok_or(PlanError::UnknownEnvironment)?;
    let current_name = tracked
        .current
        .as_deref()
        .filter(|name| current.environment(name).is_some())
        .map(str::to_owned);
    let current_values = current_name
        .as_deref()
        .and_then(|name| current.environment(name));
    let target_name = tracked.exists.then(|| point_name.to_owned());
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
            names.insert(name);
            if let Some(now) = state.keys[*id]
                .current
                .as_deref()
                .filter(|now| *now != &**name && current_name.is_some())
            {
                links.push((name.to_string(), now.to_owned()));
            }
        }
    }
    if let Some(values) = current_values {
        names.extend(values.keys().copied());
    }
    let mut chosen: Vec<(&str, Option<&str>, TargetValue, Option<KeyId>)> = Vec::new();
    for name in names {
        let target_id = tracked.keys.get(name).copied().filter(|_| tracked.exists);
        let target_state = target_id.map(|id| state.state(id));
        let current_value = current_values.and_then(|values| values.get(name)).copied();
        if !shown(target_state, current_value) {
            continue;
        }
        let notes_id = current_name
            .as_deref()
            .and_then(|environment| state.now(environment, name))
            .or(target_id);
        chosen.push((
            name,
            current_value,
            target_state.map_or(TargetValue::Absent, KeyState::target),
            notes_id,
        ));
    }
    let chosen: Vec<(String, Option<&str>, TargetValue, Option<KeyId>)> = chosen
        .into_iter()
        .map(|(name, current_value, target, id)| (name.to_owned(), current_value, target, id))
        .collect();
    let unnamed_keys = tracked.unnamed.filter(|_| tracked.exists);
    let mut rows: Vec<Row> = Vec::with_capacity(chosen.len());
    for (name, current_value, target, id) in chosen {
        let notes = walked.state.take_notes(id);
        let mut row = Row::new(&name, current_value, target, notes);
        row.changed_again = None;
        rows.push(row);
    }
    link_rows(&mut rows, &links);
    Ok(RollbackPlan {
        kind: RollbackKind::Environment,
        point: walked.point,
        point_time: walked.point_time,
        generation,
        environments: vec![EnvironmentPlan {
            binding: Binding::Environment(environment_binding(keys, current_values)),
            current: current_name,
            target: target_name,
            rows,
            unnamed_keys,
        }],
    })
}

fn plan_key(
    walked: &mut Walked,
    current: &Values<'_>,
    keys: &DigestKeys,
    generation: u32,
    environment: &EnvironmentName,
    key: &str,
) -> Result<RollbackPlan, PlanError> {
    let state = &walked.state;
    let (point_name, tracked) = state
        .environment(environment.reference())
        .ok_or(PlanError::UnknownEnvironment)?;
    let environment_now = tracked
        .current
        .as_deref()
        .filter(|name| current.environment(name).is_some());
    if environment_now.is_none() {
        check_target_name(current, None, Some(point_name), &BTreeSet::new())?;
    }
    let environment_name = environment_now.unwrap_or(point_name).to_owned();
    let id = state.key(environment.reference(), key, current);
    let key_now = id
        .and_then(|id| state.keys[id].current.as_deref())
        .filter(|name| current.get(&environment_name, name).is_some())
        .unwrap_or(key)
        .to_owned();
    let target = id.map_or(TargetValue::Absent, |id| state.state(id).target());
    let current_value = current.get(&environment_name, &key_now);
    let binding = Binding::Key(key_binding(keys, current_value));
    let environment_exists = current.environment(&environment_name).is_some();
    let notes = walked.state.take_notes(id);
    let mut row = Row::new(&key_now, current_value, target, notes);
    row.changed_again = None;
    Ok(RollbackPlan {
        kind: RollbackKind::Key,
        point: walked.point,
        point_time: walked.point_time,
        generation,
        environments: vec![EnvironmentPlan {
            current: environment_exists.then(|| environment_name.clone()),
            target: Some(environment_name),
            rows: vec![row],
            binding,
            unnamed_keys: None,
        }],
    })
}

fn plan_undo_walked(
    walked: &mut Walked,
    current: &Values<'_>,
    keys: &DigestKeys,
    generation: u32,
    only: Option<&EnvironmentName>,
) -> Result<RollbackPlan, PlanError> {
    let undone = walked
        .undone
        .take()
        .expect("an undo walk keeps the entry it reverts");
    let state = &walked.state;
    let mut chosen: Vec<(&OwnedEnvironmentChange, Option<String>, Option<String>)> =
        Vec::with_capacity(undone.environments.len());
    for change in &undone.environments {
        let current_name = state
            .environments
            .get(change.name.as_str())
            .and_then(|tracked| tracked.current.as_deref())
            .filter(|name| current.environment(name).is_some())
            .map(str::to_owned);
        let target_name = match &change.kind {
            OwnedEnvironmentKind::Created => None,
            OwnedEnvironmentKind::RenamedFrom(from) => Some(from.clone()),
            OwnedEnvironmentKind::Unchanged | OwnedEnvironmentKind::Removed => {
                Some(current_name.clone().unwrap_or_else(|| change.name.clone()))
            }
        };
        let wanted = only.is_none_or(|only| match only {
            EnvironmentName::Now(name) => current_name.as_deref() == Some(name.as_str()),
            EnvironmentName::AtPoint(name) => {
                change.name == *name || target_name.as_deref() == Some(name.as_str())
            }
        });
        if wanted {
            chosen.push((change, current_name, target_name));
        }
    }
    if chosen.is_empty() {
        return Err(PlanError::UnknownEnvironment);
    }
    let freed: BTreeSet<&str> = chosen
        .iter()
        .filter_map(
            |(_, current_name, target_name)| match (current_name, target_name) {
                (Some(current_name), Some(target_name)) if target_name != current_name => {
                    Some(current_name.as_str())
                }
                _ => None,
            },
        )
        .collect();
    for (_, current_name, target_name) in &chosen {
        check_target_name(
            current,
            current_name.as_deref(),
            target_name.as_deref(),
            &freed,
        )?;
    }
    /// One row before its notes: key, current value, target, the key whose
    /// notes it shows, and whether it's a renamed key's name leaving.
    type PlannedRow = (String, Option<String>, TargetValue, Option<KeyId>, bool);
    struct Planned {
        rows: Vec<PlannedRow>,
        links: Vec<(String, String)>,
    }
    let mut planned: Vec<Planned> = Vec::with_capacity(chosen.len());
    for (change, current_name, _) in &chosen {
        let tracked = state.environments.get(change.name.as_str());
        let current_values = current_name
            .as_deref()
            .and_then(|name| current.environment(name));
        let mut rows: BTreeMap<String, (Option<String>, TargetValue, Option<KeyId>, bool)> =
            BTreeMap::new();
        let mut links = Vec::new();
        for key_change in change.keys.iter().flatten() {
            let id_now = tracked
                .and_then(|tracked| tracked.keys.get(key_change.key.as_str()))
                .copied()
                .filter(|id| state.keys[*id].current.is_some());
            let current_key = id_now
                .and_then(|id| state.keys[id].current.as_deref())
                .filter(|name| current_values.is_some_and(|values| values.contains_key(name)))
                .map(str::to_owned);
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
            let notes_id = id_now.filter(|_| current_key.is_some());
            if let Some(leaving) = current_key
                .as_ref()
                .filter(|leaving| key_change.renamed_from.is_some() && **leaving != row_key)
            {
                links.push((leaving.clone(), row_key.clone()));
                rows.entry(leaving.clone()).or_insert_with(|| {
                    (
                        current_values
                            .and_then(|values| values.get(leaving.as_str()))
                            .map(|value| (*value).to_owned()),
                        TargetValue::Absent,
                        notes_id,
                        true,
                    )
                });
            }
            let current_value = current_values
                .and_then(|values| values.get(row_key.as_str()))
                .map(|value| (*value).to_owned());
            rows.insert(row_key, (current_value, target, notes_id, false));
        }
        planned.push(Planned {
            rows: rows
                .into_iter()
                .map(|(key, (current_value, target, id, leaving))| {
                    (key, current_value, target, id, leaving)
                })
                .collect(),
            links,
        });
    }
    let mut environments = Vec::with_capacity(chosen.len());
    let bindings: Vec<Option<Digest>> = chosen
        .iter()
        .map(|(_, current_name, _)| {
            environment_binding(
                keys,
                current_name
                    .as_deref()
                    .and_then(|name| current.environment(name)),
            )
        })
        .collect();
    let mut shared: HashMap<KeyId, Notes> = HashMap::new();
    for (((change, current_name, target_name), planned), binding) in
        chosen.into_iter().zip(planned).zip(bindings)
    {
        let mut rows: Vec<Row> = Vec::with_capacity(planned.rows.len());
        for (key, current_value, target, id, leaving) in planned.rows {
            // A rename's two rows share its key's notes.
            let notes = match id {
                Some(id) if leaving => shared
                    .entry(id)
                    .or_insert_with(|| walked.state.take_notes(Some(id)))
                    .clone(),
                Some(id) => shared
                    .remove(&id)
                    .unwrap_or_else(|| walked.state.take_notes(Some(id))),
                None => Notes::default(),
            };
            let row = Row::new(&key, current_value.as_deref(), target, notes);
            if row.shown() {
                rows.push(row);
            }
        }
        link_rows(&mut rows, &planned.links);
        environments.push(EnvironmentPlan {
            binding: Binding::Environment(binding),
            current: current_name,
            target: target_name,
            rows,
            unnamed_keys: change.keys.is_none().then_some(UnknownReason::TooLarge),
        });
    }
    Ok(RollbackPlan {
        kind: RollbackKind::Undo,
        point: walked.point,
        point_time: walked.point_time,
        generation,
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
