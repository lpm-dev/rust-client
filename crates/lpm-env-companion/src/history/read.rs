//! Reading history: the head and key, the parts newest first one at a time,
//! the timeline of what changed (names and kinds, never values), the live
//! gap between the newest summary and the stored values, and the scrub
//! readers apply while a removal runs.

use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fmt;

use zeroize::Zeroizing;

use crate::append_log::{self, HISTORY, Head};
use crate::history::codec::{
    Action, Actor, Detail, Entry, EntryId, EnvironmentChange, EnvironmentKind, Flags, KeyChange,
    KeyKind, Keys, Part, Platform, Related, Remote, Side, Slot, Summary, Unkept,
};
use crate::history::part_identity;
use crate::history::values::{Values, gap_changes};
use crate::keyring::{self, Digest, DigestKeys, KeyRecord};

/// Damage in history's records that a names-only listing can't see: a head
/// or key that won't parse, or a newest part an append can't build on. A
/// tail that's absent or from another epoch is a rollover a crash
/// interrupted, which the next append finishes from the part before it, so
/// it's damage only when that part is missing or won't read too. Repairing
/// any of these removes history; it stays on and restarts at the next
/// change. `part` reads one part's sealed bytes.
pub fn check_records<'p>(
    vault_id: &str,
    head: Option<&[u8]>,
    key: Option<&[u8]>,
    mut part: impl FnMut(u16) -> Option<Cow<'p, [u8]>>,
) -> Vec<crate::gate::Damage> {
    use crate::gate::Damage;
    let mut damage = Vec::new();
    let head = head.map(|bytes| Head::parse(HISTORY, vault_id, bytes));
    if let Some(Err(error)) = &head {
        damage.push(Damage::InvalidRecord {
            kind: HISTORY.head_kind.to_owned(),
            reason: error.to_string(),
        });
    }
    let record = key.map(KeyRecord::decode);
    if let Some(Err(error)) = &record {
        damage.push(Damage::InvalidRecord {
            kind: crate::graph::SHARED_KEY_KIND.to_owned(),
            reason: error.to_string(),
        });
    }
    let (Some(Ok(head)), Some(Ok(record))) = (head, record) else {
        return damage;
    };
    let epoch_of = |number: u16, sealed: &[u8]| {
        keyring::open(&record, &part_identity(vault_id, number), sealed)
            .map_err(|error| error.to_string())
            .and_then(|plaintext| {
                Part::decode(&plaintext)
                    .map(|decoded| decoded.epoch)
                    .map_err(|error| error.to_string())
            })
    };
    let tail = head.tail();
    let tail_epoch = match part(tail).map(|sealed| epoch_of(tail, &sealed)) {
        Some(Err(reason)) => {
            damage.push(Damage::InvalidRecord {
                kind: HISTORY.kind.to_owned(),
                reason: format!("the newest part won't read: {reason}"),
            });
            return damage;
        }
        Some(Ok(epoch)) => Some(epoch),
        None => None,
    };
    if append_log::tail_state(&head, tail_epoch) == append_log::TailState::Current {
        return damage;
    }
    let reason = match head.before_tail() {
        None => "the newest part is missing and no part comes before it".to_owned(),
        Some(previous) => match part(previous).map(|sealed| epoch_of(previous, &sealed)) {
            Some(Ok(_)) => return damage,
            Some(Err(reason)) => {
                format!("the newest part is missing and the part before it won't read: {reason}")
            }
            None => "the newest part and the part before it are missing".to_owned(),
        },
    };
    damage.push(Damage::InvalidRecord {
        kind: HISTORY.kind.to_owned(),
        reason,
    });
    damage
}

/// Where a reader gets parts from: the store, read one at a time inside the
/// client's lock, or the array the app passed, lent without a copy.
pub trait PartSource {
    /// The sealed bytes of `part`, or `None` when its account is absent.
    fn part(&mut self, part: u16) -> Result<Option<Cow<'_, [u8]>>, String>;
}

impl<F: FnMut(u16) -> Result<Option<Vec<u8>>, String>> PartSource for F {
    fn part(&mut self, part: u16) -> Result<Option<Cow<'_, [u8]>>, String> {
        self(part).map(|sealed| sealed.map(Cow::Owned))
    }
}

/// Why history can't be read at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReadError {
    /// The head or key won't read: Repair removes history.
    Damaged(String),
    /// The store failed; trying again may work.
    Storage(String),
}

impl fmt::Display for ReadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Damaged(reason) => write!(formatter, "local history is damaged: {reason}"),
            Self::Storage(error) => formatter.write_str(error),
        }
    }
}

/// A history whose head and key opened.
pub struct Opened {
    pub vault_id: String,
    pub head: Head,
    pub record: KeyRecord,
    pub keys: DigestKeys,
    scrub: Option<Scrub>,
}

impl fmt::Debug for Opened {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Opened")
            .field("vault_id", &self.vault_id)
            .field("head", &self.head)
            .finish_non_exhaustive()
    }
}

/// One part as a reader found it. A readable part is decoded once and lent
/// to the visitor; its plaintext is wiped when the visitor returns.
pub enum PartRead<'p> {
    Readable {
        part: u16,
        decoded: &'p Part<'p>,
    },
    /// Listed but absent, sealed under a key this history doesn't hold,
    /// changed, or not a valid part.
    Unreadable {
        part: u16,
        tail: bool,
    },
}

impl Opened {
    pub fn open(vault_id: &str, head: &[u8], key: &[u8]) -> Result<Self, ReadError> {
        let head = Head::parse(HISTORY, vault_id, head)
            .map_err(|error| ReadError::Damaged(error.to_string()))?;
        let record =
            KeyRecord::decode(key).map_err(|error| ReadError::Damaged(error.to_string()))?;
        let keys = record.digest_keys(vault_id);
        let scrub = head.removing.as_ref().map(|removing| Scrub {
            value: removing.value,
            places: removing.places.iter().copied().collect(),
            keys: keys.clone(),
        });
        Ok(Self {
            vault_id: vault_id.to_owned(),
            head,
            record,
            keys,
            scrub,
        })
    }

    /// The scrub of a running removal, which readers apply to what they
    /// return.
    pub fn scrub(&self) -> Option<&Scrub> {
        self.scrub.as_ref()
    }

    /// `entry` as readers may return it: scrubbed while a removal runs,
    /// borrowed otherwise.
    pub fn scrubbed<'e, 'a>(&self, entry: &'e Entry<'a>) -> Cow<'e, Entry<'a>> {
        match &self.scrub {
            Some(scrub) => Cow::Owned(scrub.entry(entry).0),
            None => Cow::Borrowed(entry),
        }
    }

    /// `summary` as readers may use it: scrubbed while a removal runs,
    /// borrowed otherwise.
    pub fn scrubbed_summary<'s, 'a>(&self, summary: &'s Summary<'a>) -> Cow<'s, Summary<'a>> {
        match &self.scrub {
            Some(scrub) => Cow::Owned(scrub.summary(summary).0),
            None => Cow::Borrowed(summary),
        }
    }

    /// Read each listed part, newest first, and hand it to `visit` until it
    /// returns `false`. A tail a rollover's crash left behind (absent, or
    /// from another epoch) holds nothing newer, so it's skipped; any other
    /// listed part that won't open or decode is unreadable.
    pub fn walk(
        &self,
        source: &mut impl PartSource,
        mut visit: impl FnMut(PartRead<'_>) -> bool,
    ) -> Result<(), ReadError> {
        let tail = self.head.tail();
        // After a skipped tail, the part before it is what the next append
        // recovers from, so it won't reading damages history as the tail
        // would; with no part before it, the skipped tail is damage itself.
        let mut recovering = false;
        for part in self.head.parts.iter().rev().copied() {
            let is_tail = part == tail;
            let unreadable = PartRead::Unreadable {
                part,
                tail: is_tail || recovering,
            };
            if !is_tail {
                recovering = false;
            }
            let skip_tail = |recovering: &mut bool| {
                *recovering = true;
                self.head.parts.len() == 1
            };
            let Some(sealed) = source.part(part).map_err(ReadError::Storage)? else {
                if is_tail {
                    if skip_tail(&mut recovering) && !visit(unreadable) {
                        break;
                    }
                    continue;
                }
                if !visit(unreadable) {
                    break;
                }
                continue;
            };
            let Ok(plaintext) =
                keyring::open(&self.record, &part_identity(&self.vault_id, part), &sealed)
            else {
                if !visit(unreadable) {
                    break;
                }
                continue;
            };
            drop(sealed);
            let Ok(decoded) = Part::decode(&plaintext) else {
                if !visit(unreadable) {
                    break;
                }
                continue;
            };
            if is_tail && decoded.epoch != self.head.tail_epoch {
                if skip_tail(&mut recovering) && !visit(PartRead::Unreadable { part, tail: true }) {
                    break;
                }
                continue;
            }
            if !visit(PartRead::Readable {
                part,
                decoded: &decoded,
            }) {
                break;
            }
        }
        Ok(())
    }
}

/// What a running removal takes out of what readers return.
#[derive(Clone)]
pub struct Scrub {
    pub value: Digest,
    pub places: HashSet<Digest>,
    keys: DigestKeys,
}

impl fmt::Debug for Scrub {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Scrub")
            .field("places", &self.places.len())
            .finish_non_exhaustive()
    }
}

impl Scrub {
    pub fn new(value: Digest, places: impl IntoIterator<Item = Digest>, keys: DigestKeys) -> Self {
        Self {
            value,
            places: places.into_iter().collect(),
            keys,
        }
    }

    /// Whether any name pair a side was recorded under is a removed place.
    fn matches(&self, environments: &[&str], keys: &[&str]) -> bool {
        environments.iter().any(|environment| {
            keys.iter()
                .any(|key| self.places.contains(&self.keys.place(environment, key)))
        })
    }

    fn side<'a>(&self, side: Side<'a>, environments: &[&str], keys: &[&str]) -> Side<'a> {
        match side.digest() {
            Some(digest) if digest == self.value && self.matches(environments, keys) => {
                Side::Removed
            }
            _ => side,
        }
    }

    /// The entry with every side at a removed place that holds the removed
    /// value replaced by `removed`, and whether anything changed.
    pub fn entry<'a>(&self, entry: &Entry<'a>) -> (Entry<'a>, bool) {
        let mut scrubbed = entry.clone();
        let mut changed = false;
        for environment in &mut scrubbed.environments {
            let names: Vec<&str> = match environment.kind {
                EnvironmentKind::RenamedFrom(from) => vec![environment.name, from],
                _ => vec![environment.name],
            };
            let Keys::Changes(changes) = &mut environment.keys else {
                continue;
            };
            for change in changes {
                let keys: Vec<&str> = match change.kind {
                    KeyKind::RenamedFrom(from) => vec![change.key, from],
                    _ => vec![change.key],
                };
                let before = self.side(change.before, &names, &keys);
                let after = self.side(change.after, &names, &keys);
                changed |= before != change.before || after != change.after;
                change.before = before;
                change.after = after;
            }
        }
        (scrubbed, changed)
    }

    /// The summary with every removed place holding the removed value
    /// replaced by `removed`, and whether anything changed.
    pub fn summary<'a>(&self, summary: &Summary<'a>) -> (Summary<'a>, bool) {
        let mut scrubbed = summary.clone();
        let mut changed = false;
        for (environment, keys) in &mut scrubbed.environments {
            for (key, slot) in keys.iter_mut() {
                if *slot == Slot::Digest(self.value) && self.matches(&[environment], &[key]) {
                    *slot = Slot::Removed;
                    changed = true;
                }
            }
        }
        (scrubbed, changed)
    }
}

/// One side as a listing shows it: whether its value is kept, never the
/// value itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SideInfo {
    Absent,
    Kept,
    NotRecorded,
    TooLarge,
    Removed,
}

impl From<&Side<'_>> for SideInfo {
    fn from(side: &Side<'_>) -> Self {
        match side {
            Side::Absent => Self::Absent,
            Side::Value { .. } => Self::Kept,
            Side::DigestOnly {
                reason: Unkept::NotRecorded,
                ..
            } => Self::NotRecorded,
            Side::DigestOnly {
                reason: Unkept::TooLarge,
                ..
            } => Self::TooLarge,
            Side::Removed => Self::Removed,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum KeyKindInfo {
    Added,
    Changed,
    Removed,
    RenamedFrom(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct KeyInfo {
    pub key: String,
    pub kind: KeyKindInfo,
    pub before: SideInfo,
    pub after: SideInfo,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum EnvironmentKindInfo {
    Unchanged,
    Created,
    Removed,
    RenamedFrom(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum KeysInfo {
    Changes(Vec<KeyInfo>),
    Count(u32),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EnvironmentInfo {
    pub name: String,
    pub kind: EnvironmentKindInfo,
    pub keys: KeysInfo,
}

impl EnvironmentInfo {
    pub fn key_count(&self) -> usize {
        match &self.keys {
            KeysInfo::Changes(keys) => keys.len(),
            KeysInfo::Count(count) => *count as usize,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum RemoteInfo {
    Personal,
    Org(String),
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct DetailInfo {
    pub file_name: Option<String>,
    pub pasted: bool,
    pub remote: Option<RemoteInfo>,
    pub remote_version: Option<u64>,
    pub platform: Option<Platform>,
    pub related: Option<Related>,
}

/// An entry as a listing shows it: names, kinds and times, never values.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EntryInfo {
    pub seq: u64,
    pub id: EntryId,
    pub time: i64,
    pub actor: Actor,
    pub action: Action,
    pub flags: Flags,
    pub since: Option<i64>,
    pub detail: DetailInfo,
    pub environments: Vec<EnvironmentInfo>,
}

impl EntryInfo {
    pub fn key_count(&self) -> usize {
        self.environments
            .iter()
            .map(EnvironmentInfo::key_count)
            .sum()
    }

    pub fn source(&self) -> SourceGroup {
        SourceGroup::of(self.actor, self.action)
    }
}

pub fn environments_info(environments: &[EnvironmentChange<'_>]) -> Vec<EnvironmentInfo> {
    environments
        .iter()
        .map(|environment| EnvironmentInfo {
            name: environment.name.to_owned(),
            kind: match environment.kind {
                EnvironmentKind::Unchanged => EnvironmentKindInfo::Unchanged,
                EnvironmentKind::Created => EnvironmentKindInfo::Created,
                EnvironmentKind::Removed => EnvironmentKindInfo::Removed,
                EnvironmentKind::RenamedFrom(from) => {
                    EnvironmentKindInfo::RenamedFrom(from.to_owned())
                }
            },
            keys: match &environment.keys {
                Keys::Count(count) => KeysInfo::Count(*count),
                Keys::Changes(changes) => KeysInfo::Changes(changes.iter().map(key_info).collect()),
            },
        })
        .collect()
}

fn key_info(change: &KeyChange<'_>) -> KeyInfo {
    KeyInfo {
        key: change.key.to_owned(),
        kind: match change.kind {
            KeyKind::Added => KeyKindInfo::Added,
            KeyKind::Changed => KeyKindInfo::Changed,
            KeyKind::Removed => KeyKindInfo::Removed,
            KeyKind::RenamedFrom(from) => KeyKindInfo::RenamedFrom(from.to_owned()),
        },
        before: SideInfo::from(&change.before),
        after: SideInfo::from(&change.after),
    }
}

fn detail_info(detail: &Detail<'_>) -> DetailInfo {
    DetailInfo {
        file_name: detail.file_name.map(str::to_owned),
        pasted: detail.pasted,
        remote: detail.remote.map(|remote| match remote {
            Remote::Personal => RemoteInfo::Personal,
            Remote::Org(slug) => RemoteInfo::Org(slug.to_owned()),
        }),
        remote_version: detail.remote_version,
        platform: detail.platform,
        related: detail.related,
    }
}

pub fn entry_info(entry: &Entry<'_>) -> EntryInfo {
    crate::work::note(crate::work::Work::Listed);
    EntryInfo {
        seq: entry.seq,
        id: entry.id,
        time: entry.time,
        actor: entry.actor,
        action: entry.action,
        flags: entry.flags,
        since: entry.since,
        detail: detail_info(&entry.detail),
        environments: environments_info(&entry.environments),
    }
}

/// The source filters, which partition every entry so their counts add up
/// to the total: edits by who made them, and every other action by kind,
/// whoever made it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum SourceGroup {
    App,
    Cli,
    Import,
    Restore,
    Pull,
    Rollback,
    Outside,
}

impl SourceGroup {
    pub const ALL: [Self; 7] = [
        Self::App,
        Self::Cli,
        Self::Import,
        Self::Restore,
        Self::Pull,
        Self::Rollback,
        Self::Outside,
    ];

    pub fn of(actor: Actor, action: Action) -> Self {
        match action {
            Action::Import => Self::Import,
            Action::Restore => Self::Restore,
            Action::Pull | Action::PlatformPull | Action::ProjectImport => Self::Pull,
            Action::Rollback | Action::Undo => Self::Rollback,
            Action::Outside => Self::Outside,
            _ if actor == Actor::App => Self::App,
            _ => Self::Cli,
        }
    }

    /// The name `--source` and JSON use.
    pub fn name(self) -> &'static str {
        match self {
            Self::App => "app",
            Self::Cli => "cli",
            Self::Import => "import",
            Self::Restore => "restore",
            Self::Pull => "pull",
            Self::Rollback => "rollback",
            Self::Outside => "outside",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|group| group.name() == name)
    }
}

/// How a listing matches keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyMatch<'a> {
    /// The key under its name now, and under every name it had before,
    /// following renames back.
    Exact(&'a str),
    /// Names containing the text, ignoring ASCII case, as a search box does.
    Contains(&'a str),
}

fn contains_ignoring_ascii_case(name: &str, text: &str) -> bool {
    text.is_empty()
        || name
            .as_bytes()
            .windows(text.len())
            .any(|window| window.eq_ignore_ascii_case(text.as_bytes()))
}

/// What a listing shows.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Filter<'a> {
    /// Entries touching this environment, named as it is now (or as it was
    /// when deleted), and under every name it had before, following renames
    /// back.
    pub environment: Option<&'a str>,
    pub key: Option<KeyMatch<'a>>,
    pub source: Option<SourceGroup>,
    /// The newest this many matching entries.
    pub limit: Option<usize>,
}

impl Filter<'_> {
    fn narrows(&self) -> bool {
        self.environment.is_some() || self.key.is_some()
    }
}

/// A filter's environment and exact key, followed back through renames as
/// a listing goes from the newest entry to the oldest. Where an entry
/// renames the name being followed away to another name, the entries before
/// it under that name are the other name's, so the match stops there.
struct Matcher<'f> {
    filter: &'f Filter<'f>,
    /// The filtered environment's name before the entries matched so far;
    /// `None` once its history ended.
    environment: Option<Option<String>>,
    /// An exact key's name before the entries matched so far, by the name
    /// its environment had then, where it differs from the filter's.
    renamed_keys: HashMap<String, String>,
    /// Environments, by their name then, where the exact key's history
    /// ended.
    ended_keys: HashSet<String>,
}

impl<'f> Matcher<'f> {
    fn new(filter: &'f Filter<'f>) -> Self {
        Self {
            filter,
            environment: filter.environment.map(|name| Some(name.to_owned())),
            renamed_keys: HashMap::new(),
            ended_keys: HashSet::new(),
        }
    }

    fn exact_key(&self) -> Option<&'f str> {
        match self.filter.key {
            Some(KeyMatch::Exact(key)) => Some(key),
            _ => None,
        }
    }

    /// Whether `environments`, one entry's changes, touch what the filter
    /// follows; then step back across the renames they record.
    fn matches(&mut self, environments: &[EnvironmentChange<'_>]) -> bool {
        let wanted = match &self.environment {
            Some(None) => return false,
            Some(Some(name)) => Some(name.clone()),
            None => None,
        };
        let mut matched = false;
        let mut environment_step: Option<Option<String>> = None;
        let mut key_steps: Vec<(String, String, KeyStep)> = Vec::new();
        for environment in environments {
            let earlier_name = match environment.kind {
                EnvironmentKind::RenamedFrom(from) => Some(from),
                _ => None,
            };
            if let Some(wanted) = &wanted {
                if environment.name != wanted {
                    if earlier_name == Some(wanted.as_str()) {
                        // The followed name became this environment's here.
                        environment_step = Some(None);
                    }
                    continue;
                }
                if let Some(from) = earlier_name {
                    environment_step = Some(Some(from.to_owned()));
                }
            }
            let earlier = earlier_name.unwrap_or(environment.name);
            let key_matches = match self.filter.key {
                None => true,
                Some(KeyMatch::Contains(text)) => match &environment.keys {
                    Keys::Count(_) => false,
                    Keys::Changes(changes) => changes.iter().any(|change| {
                        contains_ignoring_ascii_case(change.key, text)
                            || matches!(change.kind, KeyKind::RenamedFrom(from)
                                if contains_ignoring_ascii_case(from, text))
                    }),
                },
                Some(KeyMatch::Exact(wanted_key)) => {
                    if self.ended_keys.contains(environment.name) {
                        if earlier_name.is_some() {
                            key_steps.push((
                                environment.name.to_owned(),
                                earlier.to_owned(),
                                KeyStep::Ended,
                            ));
                        }
                        false
                    } else {
                        let name = self
                            .renamed_keys
                            .get(environment.name)
                            .map_or(wanted_key, String::as_str);
                        let changes = match &environment.keys {
                            Keys::Count(_) => &[][..],
                            Keys::Changes(changes) => changes.as_slice(),
                        };
                        let change = changes.iter().find(|change| change.key == name);
                        let step = match change.map(|change| change.kind) {
                            Some(KeyKind::RenamedFrom(from)) => KeyStep::Named(from.to_owned()),
                            Some(_) => KeyStep::Named(name.to_owned()),
                            None if changes.iter().any(|change| {
                                matches!(change.kind, KeyKind::RenamedFrom(from) if from == name)
                            }) =>
                            {
                                KeyStep::Ended
                            }
                            None => KeyStep::Named(name.to_owned()),
                        };
                        let moved = earlier_name.is_some()
                            || !matches!(&step, KeyStep::Named(next) if next == name);
                        if moved {
                            key_steps.push((environment.name.to_owned(), earlier.to_owned(), step));
                        }
                        change.is_some()
                    }
                }
            };
            matched |= key_matches;
        }
        if let Some(step) = environment_step {
            self.environment = Some(step);
        }
        for (name, earlier, step) in key_steps {
            self.renamed_keys.remove(&name);
            self.ended_keys.remove(&name);
            match step {
                KeyStep::Ended => {
                    self.renamed_keys.remove(&earlier);
                    self.ended_keys.insert(earlier);
                }
                KeyStep::Named(key) if Some(key.as_str()) != self.exact_key() => {
                    self.ended_keys.remove(&earlier);
                    self.renamed_keys.insert(earlier, key);
                }
                KeyStep::Named(_) => {
                    self.ended_keys.remove(&earlier);
                    self.renamed_keys.remove(&earlier);
                }
            }
        }
        matched
    }
}

/// What an exact key's name is before one entry, in one environment.
enum KeyStep {
    Named(String),
    /// The name was renamed away to another key here.
    Ended,
}

/// One timeline row, newest first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TimelineRow {
    Entry(EntryInfo),
    /// A listed part that won't read, between the readable entries around
    /// it, whose times bound it.
    Unreadable {
        part: u16,
        after: Option<i64>,
        before: Option<i64>,
    },
}

/// Changes to the stored values that the newest summary doesn't have.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveGap {
    /// The newest readable entry's time.
    pub since: Option<i64>,
    pub environments: Vec<EnvironmentInfo>,
}

/// An environment the timeline names, current or deleted. A name an
/// environment had before a rename isn't listed: its entries are the
/// renamed environment's, which a filter on its name follows back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvironmentName {
    pub name: String,
    /// When an entry removed it, if it doesn't exist now.
    pub deleted_at: Option<i64>,
}

#[derive(Clone, PartialEq, Eq)]
pub struct Timeline {
    pub rows: Vec<TimelineRow>,
    /// The shown entries' kept values, by entry ID, each environment's key
    /// changes in the order their entry lists them; empty unless revealed.
    pub values: HashMap<EntryId, Vec<Vec<RevealedValues>>>,
    pub live_gap: Option<LiveGap>,
    /// Readable entries matching the filter's environment and key, before
    /// its source and limit.
    pub readable: usize,
    pub counts: BTreeMap<SourceGroup, usize>,
    pub oldest: Option<i64>,
    /// Whether the tail won't read, which damages history.
    pub damaged_tail: bool,
    pub unreadable_parts: usize,
    pub environments: Vec<EnvironmentName>,
}

/// The environments a timeline names, gathered from the newest entry to
/// the oldest.
struct Names {
    names: BTreeMap<String, Option<i64>>,
    /// Names environments had before a rename seen so far.
    earlier: HashSet<String>,
}

impl Names {
    fn new(current: &Values<'_>) -> Self {
        Self {
            names: current
                .environments()
                .keys()
                .map(|name| ((*name).to_owned(), None))
                .collect(),
            earlier: HashSet::new(),
        }
    }

    fn note(&mut self, entry: &Entry<'_>) {
        for environment in &entry.environments {
            if !self.names.contains_key(environment.name)
                && !self.earlier.contains(environment.name)
            {
                let deleted_at =
                    (environment.kind == EnvironmentKind::Removed).then_some(entry.time);
                self.names.insert(environment.name.to_owned(), deleted_at);
            }
            if let EnvironmentKind::RenamedFrom(from) = environment.kind
                && !self.names.contains_key(from)
            {
                self.earlier.insert(from.to_owned());
            }
        }
    }
}

impl fmt::Debug for Timeline {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Timeline")
            .field("rows", &self.rows)
            .field("values", &self.values.len())
            .field("live_gap", &self.live_gap)
            .field("readable", &self.readable)
            .field("counts", &self.counts)
            .field("oldest", &self.oldest)
            .field("damaged_tail", &self.damaged_tail)
            .field("unreadable_parts", &self.unreadable_parts)
            .field("environments", &self.environments)
            .finish()
    }
}

/// A timeline row as the walk builds it. A repeated entry's row moves to
/// its oldest copy's place and leaves a gap behind.
enum Building {
    Row(TimelineRow),
    Moved,
}

/// Read the timeline: entries newest first, each repeated entry ID once
/// (the oldest copy, as a retry after someone else's rollover stores it
/// twice), unreadable parts at their place, and the live gap against
/// `current`. Only the rows shown are built, with their values when
/// `reveal` is set, in the same walk.
pub fn read_timeline(
    opened: &Opened,
    source: &mut impl PartSource,
    current: &Values<'_>,
    filter: &Filter<'_>,
    reveal: bool,
) -> Result<Timeline, ReadError> {
    let mut rows: Vec<Building> = Vec::new();
    let mut values: HashMap<EntryId, Vec<Vec<RevealedValues>>> = HashMap::new();
    // Each entry ID seen, with its row's place when it's shown.
    let mut seen: HashMap<EntryId, Option<usize>> = HashMap::new();
    let mut live_gap = None;
    let mut newest_summary_seen = false;
    let mut damaged_tail = false;
    let mut unreadable_parts = 0;
    let mut names = Names::new(current);
    let mut matcher = Matcher::new(filter);
    let mut counts: BTreeMap<SourceGroup, usize> = SourceGroup::ALL
        .into_iter()
        .map(|group| (group, 0))
        .collect();
    let mut readable = 0;
    let mut oldest = None;
    let mut shown = 0;
    let mut newer_time = None;
    let mut open_unreadable: Vec<usize> = Vec::new();
    let gap_shown = filter
        .source
        .is_none_or(|group| group == SourceGroup::Outside);
    opened.walk(source, |read| {
        match read {
            PartRead::Unreadable { part, tail } => {
                damaged_tail |= tail;
                unreadable_parts += 1;
                if filter.limit.is_none_or(|limit| shown < limit) {
                    open_unreadable.push(rows.len());
                    rows.push(Building::Row(TimelineRow::Unreadable {
                        part,
                        after: None,
                        before: newer_time,
                    }));
                }
            }
            PartRead::Readable { decoded, .. } => {
                if !newest_summary_seen {
                    newest_summary_seen = true;
                    if gap_shown {
                        let summary = opened.scrubbed_summary(&decoded.summary);
                        let current_summary = current.summary(&opened.keys);
                        let gaps = gap_changes(&summary, current, &current_summary);
                        if !gaps.is_empty()
                            && (!filter.narrows() || Matcher::new(filter).matches(&gaps))
                        {
                            live_gap = Some(LiveGap {
                                since: decoded.last_header().map(|header| header.time),
                                environments: environments_info(&gaps),
                            });
                        }
                    }
                }
                for entry in decoded.decoded_entries().rev() {
                    let time = entry.time;
                    for index in open_unreadable.drain(..) {
                        if let Building::Row(TimelineRow::Unreadable { after, .. }) =
                            &mut rows[index]
                        {
                            *after = Some(time);
                        }
                    }
                    newer_time = Some(time);
                    let entry = opened.scrubbed(entry);
                    names.note(&entry);
                    if let Some(place) = seen.get(&entry.id) {
                        if let Some(place) = *place {
                            let row = std::mem::replace(&mut rows[place], Building::Moved);
                            seen.insert(entry.id, Some(rows.len()));
                            rows.push(row);
                        }
                        continue;
                    }
                    if filter.narrows() && !matcher.matches(&entry.environments) {
                        seen.insert(entry.id, None);
                        continue;
                    }
                    readable += 1;
                    let group = SourceGroup::of(entry.actor, entry.action);
                    *counts.entry(group).or_default() += 1;
                    oldest = Some(time);
                    if filter.source.is_some_and(|wanted| wanted != group)
                        || filter.limit.is_some_and(|limit| shown >= limit)
                    {
                        seen.insert(entry.id, None);
                        continue;
                    }
                    shown += 1;
                    if reveal {
                        values.insert(entry.id, revealed_values(&entry));
                    }
                    seen.insert(entry.id, Some(rows.len()));
                    rows.push(Building::Row(TimelineRow::Entry(entry_info(&entry))));
                }
            }
        }
        true
    })?;
    Ok(Timeline {
        rows: rows
            .into_iter()
            .filter_map(|row| match row {
                Building::Row(row) => Some(row),
                Building::Moved => None,
            })
            .collect(),
        values,
        live_gap,
        readable,
        counts,
        oldest,
        damaged_tail,
        unreadable_parts,
        environments: names
            .names
            .into_iter()
            .map(|(name, deleted_at)| EnvironmentName { name, deleted_at })
            .collect(),
    })
}

/// How much history holds, from entry headers alone.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Retained {
    /// Readable entries, each repeated ID once.
    pub readable: usize,
    pub oldest: Option<i64>,
    pub unreadable_parts: usize,
    /// Whether the tail won't read, which damages history.
    pub damaged_tail: bool,
}

/// Count what history holds without building any listing.
pub fn read_retained(opened: &Opened, source: &mut impl PartSource) -> Result<Retained, ReadError> {
    let mut retained = Retained::default();
    let mut ids: HashSet<EntryId> = HashSet::new();
    opened.walk(source, |read| {
        match read {
            PartRead::Unreadable { tail, .. } => {
                retained.damaged_tail |= tail;
                retained.unreadable_parts += 1;
            }
            PartRead::Readable { decoded, .. } => {
                for entry in decoded.decoded_entries() {
                    if ids.insert(entry.id) {
                        retained.readable += 1;
                    }
                }
                if let Some(first) = decoded.decoded_entries().next() {
                    retained.oldest = Some(first.time);
                }
            }
        }
        true
    })?;
    Ok(retained)
}

/// A key change's kept values, before and after.
#[derive(Clone, PartialEq, Eq)]
pub struct RevealedValues {
    pub before: Option<Zeroizing<String>>,
    pub after: Option<Zeroizing<String>>,
}

/// One entry with its values, for reveal and copy. The values are copied
/// into wiped buffers, which the caller drops as soon as it's shown them.
#[derive(Clone, PartialEq, Eq)]
pub struct RevealedEntry {
    pub info: EntryInfo,
    /// Each environment's key changes, in the order `info` lists them.
    pub values: Vec<Vec<RevealedValues>>,
}

impl fmt::Debug for RevealedEntry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RevealedEntry")
            .field("info", &self.info)
            .finish_non_exhaustive()
    }
}

/// An entry ID, or the start of one, as the hex digits a person types: the
/// 8-digit short ID, any prefix of at least [`IdPrefix::MIN_DIGITS`], or
/// all 32.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IdPrefix {
    bytes: EntryId,
    digits: usize,
}

impl IdPrefix {
    pub const MIN_DIGITS: usize = 6;

    /// The prefix `text` spells, in either case, or `None` when it's too
    /// short, too long or not hex.
    pub fn parse(text: &str) -> Option<Self> {
        let digits = text.len();
        if !(Self::MIN_DIGITS..=32).contains(&digits) {
            return None;
        }
        let mut bytes = [0_u8; 16];
        for (index, digit) in text.bytes().enumerate() {
            let nibble = char::from(digit).to_digit(16)? as u8;
            bytes[index / 2] |= if index % 2 == 0 { nibble << 4 } else { nibble };
        }
        Some(Self { bytes, digits })
    }

    pub fn whole(id: EntryId) -> Self {
        Self {
            bytes: id,
            digits: 32,
        }
    }

    pub fn is_whole(&self) -> bool {
        self.digits == 32
    }

    pub fn matches(&self, id: &EntryId) -> bool {
        let full = self.digits / 2;
        id[..full] == self.bytes[..full]
            && (self.digits.is_multiple_of(2) || id[full] >> 4 == self.bytes[full] >> 4)
    }
}

/// What looking an entry up by a prefix of its ID found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntryLookup<T = RevealedEntry> {
    NotFound,
    /// More than one entry starts with the prefix.
    Ambiguous,
    Found(Box<T>),
}

/// Find the one entry whose ID starts with `prefix`, and make `found` of
/// it. A whole ID stops at its entry; a shorter prefix reads every part, so
/// another entry starting the same way makes the lookup ambiguous.
fn lookup<T>(
    opened: &Opened,
    source: &mut impl PartSource,
    prefix: &IdPrefix,
    found: impl Fn(&Entry<'_>) -> T,
) -> Result<EntryLookup<T>, ReadError> {
    let mut result: Option<(EntryId, T)> = None;
    let mut ambiguous = false;
    opened.walk(source, |read| {
        let PartRead::Readable { decoded, .. } = read else {
            return true;
        };
        for entry in decoded.decoded_entries() {
            if !prefix.matches(&entry.id) {
                continue;
            }
            match &result {
                Some((id, _)) if *id != entry.id => {
                    ambiguous = true;
                    return false;
                }
                Some(_) => continue,
                None => {
                    result = Some((entry.id, found(&opened.scrubbed(entry))));
                    if prefix.is_whole() {
                        return false;
                    }
                }
            }
        }
        true
    })?;
    Ok(match (ambiguous, result) {
        (true, _) => EntryLookup::Ambiguous,
        (false, None) => EntryLookup::NotFound,
        (false, Some((_, found))) => EntryLookup::Found(Box::new(found)),
    })
}

/// Find the entry whose ID starts with `prefix`, names and kinds only.
pub fn find_entry(
    opened: &Opened,
    source: &mut impl PartSource,
    prefix: &IdPrefix,
) -> Result<EntryLookup<EntryInfo>, ReadError> {
    lookup(opened, source, prefix, entry_info)
}

/// Find the entry whose ID starts with `prefix` and return it with its
/// values.
pub fn reveal_entry(
    opened: &Opened,
    source: &mut impl PartSource,
    prefix: &IdPrefix,
) -> Result<EntryLookup, ReadError> {
    lookup(opened, source, prefix, revealed)
}

/// The entries whose IDs are in `ids`, with their values, in one walk.
pub fn reveal_entries(
    opened: &Opened,
    source: &mut impl PartSource,
    ids: &BTreeSet<EntryId>,
) -> Result<Vec<RevealedEntry>, ReadError> {
    let mut found: BTreeMap<EntryId, RevealedEntry> = BTreeMap::new();
    opened.walk(source, |read| {
        let PartRead::Readable { decoded, .. } = read else {
            return true;
        };
        for entry in decoded.decoded_entries() {
            if !ids.contains(&entry.id) || found.contains_key(&entry.id) {
                continue;
            }
            found.insert(entry.id, revealed(&opened.scrubbed(entry)));
        }
        found.len() < ids.len()
    })?;
    Ok(found.into_values().collect())
}

fn revealed(entry: &Entry<'_>) -> RevealedEntry {
    RevealedEntry {
        info: entry_info(entry),
        values: revealed_values(entry),
    }
}

/// An entry's kept values, each environment's key changes in order.
fn revealed_values(entry: &Entry<'_>) -> Vec<Vec<RevealedValues>> {
    entry
        .environments
        .iter()
        .map(|environment| match &environment.keys {
            Keys::Count(_) => Vec::new(),
            Keys::Changes(changes) => changes
                .iter()
                .map(|change| RevealedValues {
                    before: kept(&change.before),
                    after: kept(&change.after),
                })
                .collect(),
        })
        .collect()
}

fn kept(side: &Side<'_>) -> Option<Zeroizing<String>> {
    match side {
        Side::Value { value, .. } => Some(Zeroizing::new((*value).to_owned())),
        _ => None,
    }
}
