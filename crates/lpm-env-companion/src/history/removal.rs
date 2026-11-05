//! Removing one value from history, and rotating the key.
//!
//! A removal is a key rotation that also scrubs:
//! 1. The review reads every part and lists each place the value appears,
//!    grouped into the chosen key, in every environment and through its
//!    renames, and other keys that hold the same value.
//! 2. One journal transaction writes the head with `removing`, the value's
//!    digest and a digest of every name each checked place had, and the key
//!    as rotating, with a new pending key.
//! 3. Each part still under the old key is opened, scrubbed, sealed under
//!    the pending key and replaced, verified.
//! 4. One journal transaction makes the key stable with only the new key,
//!    which wipes the old one, and sets `removing` back to `null`.
//!
//! Steps 3 and 4 need nothing but the head, the key and the parts, so any
//! client finishes what another started. A rotation without a removal runs
//! the same steps with nothing to scrub.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fmt;

use crate::append_log::{HISTORY, Head, MAX_REMOVAL_PLACES, Removing};
use crate::history::codec::{
    Entry, EntryId, EnvironmentKind, KeyKind, Keys, Part, RelatedSide, Side, encode_part,
};
use crate::history::read::{
    EntryInfo, IdPrefix, Opened, PartRead, PartSource, ReadError, Scrub, entry_info,
};
use crate::history::values::Values;
use crate::history::{RecordWrite, head_account, key_account, part_account, part_identity};
use crate::keyring::{self, Approval, Digest, DigestKeys, KeyRecord, Random, RotationError};

/// The value a person chose on an entry: a key's value before or after it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Chosen<'a> {
    pub entry: EntryId,
    /// The environment and key as the entry names them.
    pub environment: &'a str,
    pub key: &'a str,
    pub side: RelatedSide,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum PlaceGroup {
    /// The chosen key, in every environment, through its renames: checked by
    /// default.
    ThisKey,
    /// Another key holding the same value, such as `true` under an unrelated
    /// key: unchecked by default.
    OtherKey,
}

/// When a value was set at a place and when it was replaced, as far as
/// history knows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Occurrence {
    pub set: Option<i64>,
    pub replaced: Option<i64>,
}

/// One key in one environment where the value appears, through its renames.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Place {
    /// The newest names it had.
    pub environment: String,
    pub key: String,
    /// The key's other names, sorted.
    pub renamed_from: Vec<String>,
    /// The environment's other names, sorted.
    pub renamed_environments: Vec<String>,
    pub group: PlaceGroup,
    /// Newest first.
    pub occurrences: Vec<Occurrence>,
    /// Whether the value is still the stored value there, so it can't be
    /// removed: the next change to that key would record it again.
    pub current: bool,
    /// A place digest for every name pair the place had.
    pub digests: Vec<Digest>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemovalReview {
    pub value: Digest,
    /// The key's generation at review.
    pub generation: u32,
    pub places: Vec<Place>,
}

impl RemovalReview {
    /// The places checked by default: the chosen key's, unless current.
    pub fn default_selection(&self) -> BTreeSet<usize> {
        self.places
            .iter()
            .enumerate()
            .filter(|(_, place)| place.group == PlaceGroup::ThisKey && !place.current)
            .map(|(index, _)| index)
            .collect()
    }
}

/// Why a removal can't start.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemovalError {
    Read(ReadError),
    /// No readable entry has that ID, or it didn't change that key.
    NotFound,
    /// The chosen side has no value to remove.
    NothingToRemove,
    /// Every checked place still holds the value, or none is checked.
    ValueIsCurrent,
    /// More than [`MAX_REMOVAL_PLACES`] name pairs: remove in two passes.
    Limit,
    /// The values or the key changed since the review.
    ChangedSinceReview,
    /// More than one entry starts with that ID.
    AmbiguousEntry,
    /// The key can't rotate again.
    GenerationExhausted,
    /// A rotation or removal is already running.
    Running,
    /// A readable part is still under the old key, so finishing would make
    /// it unreadable: rotate every part first.
    PartNotRotated(u16),
    /// A part opened but its scrubbed form wouldn't encode.
    Damaged(String),
    Random,
}

impl fmt::Display for RemovalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read(error) => write!(formatter, "{error}"),
            Self::NotFound => formatter.write_str("no entry in local history has that value"),
            Self::NothingToRemove => {
                formatter.write_str("that side of the change has no value to remove")
            }
            Self::ValueIsCurrent => formatter.write_str(
                "the value is still current at every place chosen; change it first, then remove the old value from history",
            ),
            Self::Limit => formatter.write_str(
                "that's more places than one removal can name; remove the value in two passes",
            ),
            Self::ChangedSinceReview => {
                formatter.write_str("the values changed since the removal was reviewed")
            }
            Self::AmbiguousEntry => {
                formatter.write_str("more than one entry in local history starts with that ID")
            }
            Self::GenerationExhausted => formatter.write_str(
                "local history's key can't rotate any more. Turn history off and on to start a new history",
            ),
            Self::Running => formatter.write_str("local history is finishing a key change"),
            Self::PartNotRotated(part) => write!(
                formatter,
                "part {part} of local history isn't under the new key yet; rotate every part before finishing"
            ),
            Self::Damaged(reason) => write!(formatter, "local history is damaged: {reason}"),
            Self::Random => formatter.write_str("the system's random number generator failed"),
        }
    }
}

impl From<ReadError> for RemovalError {
    fn from(error: ReadError) -> Self {
        Self::Read(error)
    }
}

/// Names linked by renames, so a place keeps one identity through them.
#[derive(Default)]
struct Aliases {
    parent: HashMap<String, String>,
}

impl Aliases {
    fn root(&mut self, name: &str) -> String {
        crate::work::note(crate::work::Work::AliasStep);
        let parent = self
            .parent
            .entry(name.to_owned())
            .or_insert_with(|| name.to_owned())
            .clone();
        if parent == name {
            return parent;
        }
        let root = self.root(&parent);
        self.parent.insert(name.to_owned(), root.clone());
        root
    }

    fn link(&mut self, left: &str, right: &str) {
        let (left, right) = (self.root(left), self.root(right));
        if left != right {
            self.parent.insert(left, right);
        }
    }

    /// Every name, by its group's root.
    fn groups(&mut self) -> HashMap<String, Vec<String>> {
        let names: Vec<String> = self.parent.keys().cloned().collect();
        let mut groups: HashMap<String, Vec<String>> = HashMap::new();
        for name in names {
            let root = self.root(&name);
            groups.entry(root).or_default().push(name);
        }
        groups
    }
}

/// A side holding some value, seen before the walk knew which value the
/// review is for.
struct Sighting {
    digest: Digest,
    environment: String,
    key: String,
    time: i64,
    set: bool,
    seq: u64,
}

/// What the review's walk collects, resolved into places once every rename
/// is known: renames can come in any order the parts are read in.
#[derive(Default)]
struct Found {
    environment_renames: Vec<(String, String)>,
    /// (environment after the entry, old key, new key).
    key_renames: Vec<(String, String, String)>,
    /// (time, set) events per (environment, key) as named at the entry.
    events: BTreeMap<(String, String), Vec<(i64, bool)>>,
    /// The newest entry each name pair appeared in, so places show their
    /// newest names.
    seen: BTreeMap<(String, String), u64>,
}

impl Found {
    fn add(&mut self, place: (String, String), time: i64, set: bool, seq: u64) {
        let seen = self.seen.entry(place.clone()).or_insert(seq);
        *seen = (*seen).max(seq);
        self.events.entry(place).or_default().push((time, set));
    }
}

/// The side a removal starts from, chosen once its entry is found: a key's
/// value before or after the entry, named as the entry names it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChosenSide {
    pub environment: String,
    pub key: String,
    pub side: RelatedSide,
}

/// The most sides a review holds, names and digests only, before it knows
/// which value it's for. Past it, it drops them and reads the parts newer
/// than the chosen entry again, so its memory stays bounded.
pub const MAX_SIGHTINGS: usize = 8 * 1024;

/// Review removing the value `chosen` names: every place it appears, in
/// every readable part, grouped and with its occurrences.
pub fn review_removal(
    opened: &Opened,
    source: &mut impl PartSource,
    current: &Values<'_>,
    chosen: Chosen<'_>,
) -> Result<RemovalReview, RemovalError> {
    review_removal_for(
        opened,
        source,
        current,
        &IdPrefix::whole(chosen.entry),
        |_| {
            Ok::<_, RemovalError>(ChosenSide {
                environment: chosen.environment.to_owned(),
                key: chosen.key.to_owned(),
                side: chosen.side,
            })
        },
    )
    .map(|(_, review)| review)
}

/// Find the entry `entry` names, let `choose` say which of its values to
/// remove, and review it, in one walk: sides read before the entry is
/// found are held, names and digests only, until its value is known.
pub fn review_removal_for<E: From<RemovalError>>(
    opened: &Opened,
    source: &mut impl PartSource,
    current: &Values<'_>,
    entry: &IdPrefix,
    choose: impl FnOnce(&EntryInfo) -> Result<ChosenSide, E>,
) -> Result<(EntryInfo, RemovalReview), E> {
    if opened.record.is_rotating() || opened.head.removing.is_some() {
        return Err(E::from(RemovalError::Running));
    }
    let mut choose = Some(choose);
    let mut failure: Option<E> = None;
    let mut chosen: Option<(EntryInfo, ChosenSide, EntryId)> = None;
    let mut value: Option<Option<Digest>> = None;
    let mut ambiguous = false;
    let mut found = Found::default();
    let mut sightings: Vec<Sighting> = Vec::new();
    let mut overflowed = false;
    // Entries read before the chosen one, which a second walk reads again
    // when the sightings overflowed.
    let mut before_chosen: HashSet<EntryId> = HashSet::new();
    let mut entries: HashSet<EntryId> = HashSet::new();
    opened
        .walk(source, |read| {
            let PartRead::Readable { decoded, .. } = read else {
                return true;
            };
            for candidate in decoded.decoded_entries() {
                if !entries.insert(candidate.id) {
                    continue;
                }
                if entry.matches(&candidate.id) {
                    if chosen.is_some() {
                        ambiguous = true;
                        return false;
                    }
                    let info = entry_info(&opened.scrubbed(candidate));
                    let side = match choose.take().expect("one entry is chosen")(&info) {
                        Ok(side) => side,
                        Err(error) => {
                            failure = Some(error);
                            return false;
                        }
                    };
                    let digest = side_of(candidate, &side).map(|side| side.digest());
                    let Some(digest) = digest else {
                        failure = Some(E::from(RemovalError::NotFound));
                        return false;
                    };
                    value = Some(digest);
                    let Some(digest) = digest else {
                        failure = Some(E::from(RemovalError::NothingToRemove));
                        return false;
                    };
                    chosen = Some((info, side, candidate.id));
                    for sighting in sightings.drain(..) {
                        if sighting.digest == digest {
                            found.add(
                                (sighting.environment, sighting.key),
                                sighting.time,
                                sighting.set,
                                sighting.seq,
                            );
                        }
                    }
                } else if chosen.is_none() {
                    before_chosen.insert(candidate.id);
                }
                let held = (!overflowed && chosen.is_none()).then_some(&mut sightings);
                collect(candidate, value.flatten(), &mut found, held);
                if sightings.len() > MAX_SIGHTINGS {
                    sightings = Vec::new();
                    overflowed = true;
                }
            }
            true
        })
        .map_err(|error| E::from(RemovalError::from(error)))?;
    if let Some(failure) = failure {
        return Err(failure);
    }
    if ambiguous {
        return Err(E::from(RemovalError::AmbiguousEntry));
    }
    let (info, side, _) = chosen.ok_or_else(|| E::from(RemovalError::NotFound))?;
    let value = value
        .flatten()
        .ok_or_else(|| E::from(RemovalError::NothingToRemove))?;
    drop(sightings);
    if overflowed {
        let mut again: HashSet<EntryId> = HashSet::new();
        opened
            .walk(source, |read| {
                let PartRead::Readable { decoded, .. } = read else {
                    return true;
                };
                for candidate in decoded.decoded_entries() {
                    if before_chosen.contains(&candidate.id) && again.insert(candidate.id) {
                        collect_sides(candidate, value, &mut found);
                    }
                }
                again.len() < before_chosen.len()
            })
            .map_err(|error| E::from(RemovalError::from(error)))?;
    }
    let review = places_of(opened, current, value, found, &side);
    Ok((info, review))
}

fn places_of(
    opened: &Opened,
    current: &Values<'_>,
    value: Digest,
    found: Found,
    chosen: &ChosenSide,
) -> RemovalReview {
    let mut environments = Aliases::default();
    for (from, to) in &found.environment_renames {
        environments.link(from, to);
    }
    let mut keys = Aliases::default();
    for (environment, from, to) in &found.key_renames {
        let root = environments.root(environment);
        keys.link(&key_identity(&root, from), &key_identity(&root, to));
    }
    let mut places: BTreeMap<(String, String), Place> = BTreeMap::new();
    let mut newest: BTreeMap<(String, String), u64> = BTreeMap::new();
    let chosen_identity = {
        let environment = environments.root(&chosen.environment);
        keys.root(&key_identity(&environment, &chosen.key))
    };
    for ((environment, key), events) in &found.events {
        let environment_root = environments.root(environment);
        let key_root = keys.root(&key_identity(&environment_root, key));
        let place_key = (environment_root, key_root);
        let order = found.seen[&(environment.clone(), key.clone())];
        let place = places.entry(place_key.clone()).or_insert_with(|| Place {
            environment: environment.clone(),
            key: key.clone(),
            renamed_from: Vec::new(),
            renamed_environments: Vec::new(),
            group: PlaceGroup::OtherKey,
            occurrences: Vec::new(),
            current: false,
            digests: Vec::new(),
        });
        if newest.get(&place_key).is_none_or(|seen| order > *seen) {
            newest.insert(place_key, order);
            place.environment = environment.clone();
            place.key = key.clone();
        }
        let mut sorted = events.clone();
        sorted.sort_unstable();
        place.occurrences.extend(pair(&sorted));
    }
    let environment_groups = environments.groups();
    let key_groups = keys.groups();
    let names_of = |identity: &str| -> BTreeSet<String> {
        key_groups
            .get(identity)
            .map_or_else(|| vec![identity.to_owned()], Clone::clone)
            .iter()
            .filter_map(|identity| identity.split_once('\u{0}').map(|(_, key)| key.to_owned()))
            .collect()
    };
    let chosen_names = names_of(&chosen_identity);
    let digest_keys = &opened.keys;
    let holding = current_places(digest_keys, current, value);
    let mut out: Vec<Place> = Vec::with_capacity(places.len());
    for ((environment_root, key_root), mut place) in places {
        let environment_names = environment_groups
            .get(&environment_root)
            .map_or_else(|| vec![environment_root.clone()], Clone::clone);
        let key_names = names_of(&key_root);
        place.renamed_from = key_names
            .iter()
            .filter(|name| **name != place.key)
            .cloned()
            .collect();
        place.renamed_environments = environment_names
            .iter()
            .filter(|name| **name != place.environment)
            .cloned()
            .collect();
        place.renamed_environments.sort_unstable();
        if !key_names.is_disjoint(&chosen_names) {
            place.group = PlaceGroup::ThisKey;
        }
        let mut digests: BTreeSet<Digest> = BTreeSet::new();
        for environment in &environment_names {
            for key in &key_names {
                digests.insert(digest_keys.place(environment, key));
            }
        }
        place.digests = digests.into_iter().collect();
        place.current = place.digests.iter().any(|digest| holding.contains(digest));
        place
            .occurrences
            .sort_by_key(|occurrence| std::cmp::Reverse(occurrence.set.or(occurrence.replaced)));
        out.push(place);
    }
    out.sort_by(|left, right| {
        (left.group, &left.key, &left.environment).cmp(&(
            right.group,
            &right.key,
            &right.environment,
        ))
    });
    RemovalReview {
        value,
        generation: opened.record.current().generation(),
        places: out,
    }
}

/// The place digest of every key that holds `value` now. A place is
/// current when any name it had is one of them: removing the value there
/// would last only until the next change recorded it again, since removal
/// scrubs by name.
fn current_places(keys: &DigestKeys, current: &Values<'_>, value: Digest) -> HashSet<Digest> {
    current
        .environments()
        .iter()
        .flat_map(|(environment, values)| {
            values
                .iter()
                .filter(|(_, stored)| keys.value(stored.as_bytes()) == value)
                .map(|(key, _)| keys.place(environment, key))
        })
        .collect()
}

/// A key's identity within an environment's alias group.
fn key_identity(environment_root: &str, key: &str) -> String {
    let mut identity = String::with_capacity(environment_root.len() + 1 + key.len());
    identity.push_str(environment_root);
    identity.push('\u{0}');
    identity.push_str(key);
    identity
}

fn side_of<'a>(entry: &Entry<'a>, chosen: &ChosenSide) -> Option<Side<'a>> {
    entry.environments.iter().find_map(|environment| {
        if environment.name != chosen.environment {
            return None;
        }
        let Keys::Changes(changes) = &environment.keys else {
            return None;
        };
        changes
            .iter()
            .find(|change| change.key == chosen.key)
            .map(|change| match chosen.side {
                RelatedSide::Before => change.before,
                RelatedSide::After => change.after,
            })
    })
}

/// Collect `entry`'s renames and its sides that hold `value`, or, before
/// the value is known, every side that holds some value into `sightings`
/// while they're held.
fn collect(
    entry: &Entry<'_>,
    value: Option<Digest>,
    found: &mut Found,
    sightings: Option<&mut Vec<Sighting>>,
) {
    for environment in &entry.environments {
        if let EnvironmentKind::RenamedFrom(from) = environment.kind {
            found
                .environment_renames
                .push((from.to_owned(), environment.name.to_owned()));
        }
        let Keys::Changes(changes) = &environment.keys else {
            continue;
        };
        for change in changes {
            if let KeyKind::RenamedFrom(from) = change.kind {
                found.key_renames.push((
                    environment.name.to_owned(),
                    from.to_owned(),
                    change.key.to_owned(),
                ));
            }
        }
    }
    match (value, sightings) {
        (Some(value), _) => collect_sides(entry, value, found),
        (None, Some(sightings)) => each_side(entry, |digest, environment, key, set| {
            sightings.push(Sighting {
                digest,
                environment: environment.to_owned(),
                key: key.to_owned(),
                time: entry.time,
                set,
                seq: entry.seq,
            });
        }),
        (None, None) => {}
    }
}

/// Collect `entry`'s sides that hold `value`.
fn collect_sides(entry: &Entry<'_>, value: Digest, found: &mut Found) {
    each_side(entry, |digest, environment, key, set| {
        if digest == value {
            found.add(
                (environment.to_owned(), key.to_owned()),
                entry.time,
                set,
                entry.seq,
            );
        }
    });
}

/// Every side of `entry` with a digest, under the names it had: a "before"
/// side under the names before the entry, an "after" side under the names
/// after it.
fn each_side(entry: &Entry<'_>, mut visit: impl FnMut(Digest, &str, &str, bool)) {
    for environment in &entry.environments {
        let before_environment = match environment.kind {
            EnvironmentKind::RenamedFrom(from) => from,
            _ => environment.name,
        };
        let Keys::Changes(changes) = &environment.keys else {
            continue;
        };
        for change in changes {
            let before_key = match change.kind {
                KeyKind::RenamedFrom(from) => from,
                _ => change.key,
            };
            if let Some(digest) = change.before.digest() {
                visit(digest, before_environment, before_key, false);
            }
            if let Some(digest) = change.after.digest() {
                visit(digest, environment.name, change.key, true);
            }
        }
    }
}

/// Pair "set" and "replaced" events, oldest first, into occurrences.
fn pair(events: &[(i64, bool)]) -> Vec<Occurrence> {
    let mut occurrences = Vec::new();
    let mut open: Option<i64> = None;
    for (time, set) in events {
        if *set {
            if let Some(previous) = open.replace(*time) {
                occurrences.push(Occurrence {
                    set: Some(previous),
                    replaced: None,
                });
            }
        } else {
            occurrences.push(Occurrence {
                set: open.take(),
                replaced: Some(*time),
            });
        }
    }
    if let Some(set) = open {
        occurrences.push(Occurrence {
            set: Some(set),
            replaced: None,
        });
    }
    occurrences
}

/// The first journal transaction of a removal: the head with `removing`
/// and the key rotating. Bound to the review: the same key generation, and
/// no checked place holding the value now.
pub fn start_removal(
    opened: &Opened,
    review: &RemovalReview,
    selection: &BTreeSet<usize>,
    current: &Values<'_>,
    approval: Approval,
    random: &mut impl Random,
) -> Result<Vec<RecordWrite>, RemovalError> {
    if opened.record.is_rotating() || opened.head.removing.is_some() {
        return Err(RemovalError::Running);
    }
    if opened.record.current().generation() != review.generation {
        return Err(RemovalError::ChangedSinceReview);
    }
    let holding = current_places(&opened.keys, current, review.value);
    let mut places: BTreeSet<Digest> = BTreeSet::new();
    let mut chosen = 0;
    for index in selection {
        let place = review
            .places
            .get(*index)
            .ok_or(RemovalError::ChangedSinceReview)?;
        if place.current {
            continue;
        }
        if place.digests.iter().any(|digest| holding.contains(digest)) {
            return Err(RemovalError::ChangedSinceReview);
        }
        chosen += 1;
        places.extend(place.digests.iter().copied());
    }
    if chosen == 0 {
        return Err(RemovalError::ValueIsCurrent);
    }
    if places.len() > MAX_REMOVAL_PLACES {
        return Err(RemovalError::Limit);
    }
    let mut head = opened.head.clone();
    head.removing = Some(Removing {
        value: review.value,
        places: places.into_iter().collect(),
    });
    begin(opened, head, approval, random)
}

/// The first step of a rotation without a removal, as raising approval
/// needs: the key rotating.
pub fn start_rotation(
    opened: &Opened,
    approval: Approval,
    random: &mut impl Random,
) -> Result<Vec<RecordWrite>, RemovalError> {
    if opened.record.is_rotating() || opened.head.removing.is_some() {
        return Err(RemovalError::Running);
    }
    let mut writes = begin(opened, opened.head.clone(), approval, random)?;
    writes.retain(|write| write.account == key_account(&opened.vault_id));
    Ok(writes)
}

fn begin(
    opened: &Opened,
    head: Head,
    approval: Approval,
    random: &mut impl Random,
) -> Result<Vec<RecordWrite>, RemovalError> {
    let mut record = KeyRecord::decode(&opened.record.encode()).expect("a decoded record encodes");
    record
        .begin_rotation(approval, random)
        .map_err(|error| match error {
            RotationError::GenerationExhausted => RemovalError::GenerationExhausted,
            RotationError::Random => RemovalError::Random,
            RotationError::AlreadyRotating | RotationError::NotRotating => RemovalError::Running,
        })?;
    let head = head.encode(HISTORY).map_err(|_| RemovalError::Limit)?;
    Ok(vec![
        RecordWrite::new(head_account(&opened.vault_id), head),
        RecordWrite {
            account: key_account(&opened.vault_id),
            bytes: record.encode(),
        },
    ])
}

/// What a client does with a key whose recorded approval doesn't match the
/// values item's verified access.
#[derive(Debug)]
pub enum KeyMaintenance {
    Nothing,
    /// Approval was raised after the key was made: rotate it.
    Rotate,
    /// Approval was lowered: record that without a new key, so raising it
    /// again rotates.
    Lower(RecordWrite),
}

pub fn key_maintenance(opened: &Opened, access: Approval) -> KeyMaintenance {
    match (opened.record.approval_at_generation(), access) {
        (Approval::Automatic, Approval::Protected) => KeyMaintenance::Rotate,
        (Approval::Protected, Approval::Automatic) => {
            let mut record =
                KeyRecord::decode(&opened.record.encode()).expect("a decoded record encodes");
            record.set_approval_at_generation(Approval::Automatic);
            KeyMaintenance::Lower(RecordWrite {
                account: key_account(&opened.vault_id),
                bytes: record.encode(),
            })
        }
        _ => KeyMaintenance::Nothing,
    }
}

/// Whether a rotation or a removal is running, which every history
/// operation finishes first.
pub fn needs_finishing(opened: &Opened) -> bool {
    opened.record.is_rotating() || opened.head.removing.is_some()
}

/// One part of a running rotation: opened, scrubbed when a removal runs,
/// and sealed under the pending key, or `None` when it's already under the
/// pending key, absent, or unreadable under every key, which a rotation
/// can't change.
pub fn rotate_part(
    opened: &Opened,
    part: u16,
    sealed: Option<&[u8]>,
    random: &mut impl Random,
) -> Result<Option<RecordWrite>, RemovalError> {
    let (Some(pending), Some(plaintext)) = (
        opened.record.pending(),
        plaintext_to_rotate(opened, part, sealed),
    ) else {
        return Ok(None);
    };
    let identity = part_identity(&opened.vault_id, part);
    let Ok(decoded) = Part::decode(&plaintext) else {
        return Ok(None);
    };
    let rewritten = match opened.scrub() {
        None => None,
        Some(scrub) => scrubbed_part(scrub, &decoded)?,
    };
    let rewritten = rewritten.as_deref().unwrap_or(&plaintext);
    let resealed =
        keyring::seal(pending, &identity, rewritten, random).map_err(|_| RemovalError::Random)?;
    Ok(Some(RecordWrite::new(
        part_account(&opened.vault_id, part),
        resealed,
    )))
}

/// The part's plaintext with the scrub applied, or `None` when nothing in it
/// matches.
fn scrubbed_part(
    scrub: &Scrub,
    part: &Part<'_>,
) -> Result<Option<zeroize::Zeroizing<Vec<u8>>>, RemovalError> {
    let (summary, mut changed) = scrub.summary(&part.summary);
    let entries: Vec<Entry<'_>> = part
        .decoded_entries()
        .map(|entry| {
            let (scrubbed, entry_changed) = scrub.entry(entry);
            changed |= entry_changed;
            scrubbed
        })
        .collect();
    if !changed {
        return Ok(None);
    }
    encode_part(part.epoch, &summary, &[], &entries)
        .map(Some)
        .map_err(|error| RemovalError::Damaged(error.to_string()))
}

/// The plaintext of a part a running rotation still has to seal under the
/// pending key: present, under another key, opening under the record and
/// decoding. `None` for a part already rotated, absent, or unreadable under
/// every key, which a rotation can't change.
fn plaintext_to_rotate(
    opened: &Opened,
    part: u16,
    sealed: Option<&[u8]>,
) -> Option<zeroize::Zeroizing<Vec<u8>>> {
    let pending = opened.record.pending()?;
    let sealed = sealed?;
    match keyring::sealed_key(sealed) {
        Ok((id, _)) if id != pending.id() => {}
        _ => return None,
    }
    let plaintext = keyring::open(
        &opened.record,
        &part_identity(&opened.vault_id, part),
        sealed,
    )
    .ok()?;
    Part::decode(&plaintext).ok()?;
    Some(plaintext)
}

/// The last journal transaction of a rotation: the key stable with only the
/// new key, and the head without `removing`. `part` gives each listed part
/// as stored now; finishing is refused while a readable one is still under
/// the old key, which finishing wipes.
pub fn finish_rotation<'p>(
    opened: &Opened,
    part: impl Fn(u16) -> Option<&'p [u8]>,
) -> Result<Vec<RecordWrite>, RemovalError> {
    if let Some(unrotated) = opened
        .head
        .parts
        .iter()
        .find(|&&listed| plaintext_to_rotate(opened, listed, part(listed)).is_some())
    {
        return Err(RemovalError::PartNotRotated(*unrotated));
    }
    let mut record = KeyRecord::decode(&opened.record.encode()).expect("a decoded record encodes");
    record
        .finish_rotation()
        .map_err(|_| RemovalError::Running)?;
    let mut writes = vec![RecordWrite {
        account: key_account(&opened.vault_id),
        bytes: record.encode(),
    }];
    if opened.head.removing.is_some() {
        let mut head = opened.head.clone();
        head.removing = None;
        writes.push(RecordWrite::new(
            head_account(&opened.vault_id),
            head.encode(HISTORY).map_err(|_| RemovalError::Limit)?,
        ));
    }
    Ok(writes)
}

#[cfg(test)]
mod tests;
