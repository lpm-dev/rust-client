//! Reading history: the head and key, the parts newest first one at a time,
//! the timeline of what changed (names and kinds, never values), the live
//! gap between the newest summary and the stored values, and the scrub
//! readers apply while a removal runs.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fmt;

use zeroize::Zeroizing;

use crate::append_log::{HISTORY, Head};
use crate::history::codec::{
    Action, Actor, Detail, Entry, EntryId, EnvironmentChange, EnvironmentKind, Flags, KeyChange,
    KeyKind, Keys, Part, Platform, Related, Remote, Side, Slot, Summary, Unkept,
};
use crate::history::part_identity;
use crate::history::values::{Values, gap_changes};
use crate::keyring::{self, Digest, DigestKeys, KeyRecord};

/// Where a reader gets parts from: the store, read one at a time inside the
/// client's lock, or the array the app passed.
pub trait PartSource {
    /// The sealed bytes of `part`, or `None` when its account is absent.
    fn part(&mut self, part: u16) -> Result<Option<Vec<u8>>, String>;
}

impl<F: FnMut(u16) -> Result<Option<Vec<u8>>, String>> PartSource for F {
    fn part(&mut self, part: u16) -> Result<Option<Vec<u8>>, String> {
        self(part)
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

/// One part as a reader found it.
pub enum PartRead {
    Readable {
        part: u16,
        plaintext: Zeroizing<Vec<u8>>,
    },
    /// Listed but absent, sealed under a key this history doesn't hold,
    /// changed, or not a valid part.
    Unreadable { part: u16, tail: bool },
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

    /// Read each listed part, newest first, and hand it to `visit` until it
    /// returns `false`. A tail a rollover's crash left behind (absent, or
    /// from another epoch) holds nothing newer, so it's skipped; any other
    /// listed part that won't open or decode is unreadable.
    pub fn walk(
        &self,
        source: &mut impl PartSource,
        mut visit: impl FnMut(PartRead) -> bool,
    ) -> Result<(), ReadError> {
        let tail = self.head.tail();
        for part in self.head.parts.iter().rev().copied() {
            let is_tail = part == tail;
            let Some(sealed) = source.part(part).map_err(ReadError::Storage)? else {
                if is_tail {
                    continue;
                }
                if !visit(PartRead::Unreadable { part, tail: false }) {
                    break;
                }
                continue;
            };
            let read =
                match keyring::open(&self.record, &part_identity(&self.vault_id, part), &sealed) {
                    Err(_) => PartRead::Unreadable {
                        part,
                        tail: is_tail,
                    },
                    Ok(plaintext) => match Part::decode(&plaintext).map(|decoded| decoded.epoch) {
                        Err(_) => PartRead::Unreadable {
                            part,
                            tail: is_tail,
                        },
                        Ok(epoch) if is_tail && epoch != self.head.tail_epoch => continue,
                        Ok(_) => PartRead::Readable { part, plaintext },
                    },
                };
            if !visit(read) {
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
    /// The key's name, or a name it was renamed from, exactly.
    Exact(&'a str),
    /// Names containing the text, ignoring ASCII case, as a search box does.
    Contains(&'a str),
}

impl KeyMatch<'_> {
    fn matches(&self, name: &str) -> bool {
        match self {
            Self::Exact(wanted) => name == *wanted,
            Self::Contains(text) => name
                .to_ascii_lowercase()
                .contains(&text.to_ascii_lowercase()),
        }
    }
}

/// What a listing shows.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Filter<'a> {
    /// Entries touching this environment, under this name or a name it was
    /// renamed from.
    pub environment: Option<&'a str>,
    pub key: Option<KeyMatch<'a>>,
    pub source: Option<SourceGroup>,
    /// The newest this many matching entries.
    pub limit: Option<usize>,
}

impl Filter<'_> {
    fn touches(&self, environments: &[EnvironmentInfo]) -> bool {
        environments.iter().any(|environment| {
            let environment_matches = self.environment.is_none_or(|wanted| {
                environment.name == wanted
                    || matches!(&environment.kind, EnvironmentKindInfo::RenamedFrom(from) if from == wanted)
            });
            let key_matches = self.key.is_none_or(|key| match &environment.keys {
                KeysInfo::Count(_) => false,
                KeysInfo::Changes(changes) => changes.iter().any(|change| {
                    key.matches(&change.key)
                        || matches!(&change.kind, KeyKindInfo::RenamedFrom(from) if key.matches(from))
                }),
            });
            environment_matches && key_matches
        })
    }
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

/// An environment the timeline names, current or deleted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvironmentName {
    pub name: String,
    /// When an entry removed it, if it doesn't exist now.
    pub deleted_at: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Timeline {
    pub rows: Vec<TimelineRow>,
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

/// Read the timeline: entries newest first, each repeated entry ID once
/// (the oldest copy, as a retry after someone else's rollover stores it
/// twice), unreadable parts at their place, and the live gap against
/// `current`.
pub fn read_timeline(
    opened: &Opened,
    source: &mut impl PartSource,
    current: &Values<'_>,
    filter: &Filter<'_>,
) -> Result<Timeline, ReadError> {
    let mut rows: Vec<TimelineRow> = Vec::new();
    let mut live_gap = None;
    let mut newest_summary_seen = false;
    let mut damaged_tail = false;
    let mut unreadable_parts = 0;
    let mut names: BTreeMap<String, Option<i64>> = current
        .environments()
        .keys()
        .map(|name| ((*name).to_owned(), None))
        .collect();
    let current_summary = current.summary(&opened.keys);
    opened.walk(source, |read| {
        match read {
            PartRead::Unreadable { part, tail } => {
                damaged_tail |= tail;
                unreadable_parts += 1;
                rows.push(TimelineRow::Unreadable {
                    part,
                    after: None,
                    before: None,
                });
            }
            PartRead::Readable { plaintext, .. } => {
                let part = Part::decode(&plaintext).expect("walk decoded it");
                if !newest_summary_seen {
                    newest_summary_seen = true;
                    let summary = scrubbed_summary(opened, &part.summary);
                    let gaps = gap_changes(&summary, current, &current_summary);
                    if !gaps.is_empty() {
                        live_gap = Some(LiveGap {
                            since: part.last_header().map(|header| header.time),
                            environments: environments_info(&gaps),
                        });
                    }
                }
                for entry in part.decoded_entries().rev() {
                    let entry = match opened.scrub() {
                        Some(scrub) => scrub.entry(&entry).0,
                        None => entry,
                    };
                    for environment in &entry.environments {
                        if environment.kind == EnvironmentKind::Removed {
                            names
                                .entry(environment.name.to_owned())
                                .or_insert(Some(entry.time));
                        } else {
                            names.entry(environment.name.to_owned()).or_insert(None);
                        }
                    }
                    rows.push(TimelineRow::Entry(entry_info(&entry)));
                }
            }
        }
        true
    })?;
    // A retry after someone else's rollover can store an entry twice; the
    // oldest copy stays, in its place.
    let mut deduplicated: Vec<TimelineRow> = Vec::with_capacity(rows.len());
    let mut kept_ids: BTreeSet<EntryId> = BTreeSet::new();
    for row in rows.into_iter().rev() {
        if let TimelineRow::Entry(info) = &row
            && !kept_ids.insert(info.id)
        {
            continue;
        }
        deduplicated.push(row);
    }
    deduplicated.reverse();

    let mut counts: BTreeMap<SourceGroup, usize> = SourceGroup::ALL
        .into_iter()
        .map(|group| (group, 0))
        .collect();
    let mut readable = 0;
    let mut oldest = None;
    let mut matched: Vec<TimelineRow> = Vec::with_capacity(deduplicated.len());
    let mut shown = 0;
    for (index, row) in deduplicated.iter().enumerate() {
        match row {
            TimelineRow::Entry(info) => {
                let filtered = filter.environment.is_some() || filter.key.is_some();
                if filtered && !filter.touches(&info.environments) {
                    continue;
                }
                readable += 1;
                *counts.entry(info.source()).or_default() += 1;
                oldest = Some(info.time);
                if filter.source.is_some_and(|group| group != info.source())
                    || filter.limit.is_some_and(|limit| shown >= limit)
                {
                    continue;
                }
                shown += 1;
                matched.push(row.clone());
            }
            TimelineRow::Unreadable { part, .. } => {
                let newer = deduplicated[..index].iter().rev().find_map(row_time);
                let older = deduplicated[index + 1..].iter().find_map(row_time);
                if filter.limit.is_none_or(|limit| shown < limit) {
                    matched.push(TimelineRow::Unreadable {
                        part: *part,
                        after: older,
                        before: newer,
                    });
                }
            }
        }
    }
    let live_gap = live_gap.filter(|gap: &LiveGap| {
        filter
            .source
            .is_none_or(|group| group == SourceGroup::Outside)
            && (filter.environment.is_none() && filter.key.is_none()
                || filter.touches(&gap.environments))
    });
    Ok(Timeline {
        rows: matched,
        live_gap,
        readable,
        counts,
        oldest,
        damaged_tail,
        unreadable_parts,
        environments: names
            .into_iter()
            .map(|(name, deleted_at)| EnvironmentName { name, deleted_at })
            .collect(),
    })
}

fn row_time(row: &TimelineRow) -> Option<i64> {
    match row {
        TimelineRow::Entry(info) => Some(info.time),
        TimelineRow::Unreadable { .. } => None,
    }
}

fn scrubbed_summary<'a>(opened: &Opened, summary: &Summary<'a>) -> Summary<'a> {
    match opened.scrub() {
        Some(scrub) => scrub.summary(summary).0,
        None => summary.clone(),
    }
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

/// What looking an entry up by a prefix of its ID found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntryLookup {
    NotFound,
    /// More than one entry starts with the prefix.
    Ambiguous,
    Found(Box<RevealedEntry>),
}

/// Find the entry whose ID starts with `prefix` and return it with its
/// values.
pub fn reveal_entry(
    opened: &Opened,
    source: &mut impl PartSource,
    prefix: &[u8],
) -> Result<EntryLookup, ReadError> {
    let mut found: Option<RevealedEntry> = None;
    let mut ambiguous = false;
    opened.walk(source, |read| {
        let PartRead::Readable { plaintext, .. } = read else {
            return true;
        };
        let part = Part::decode(&plaintext).expect("walk decoded it");
        for entry in part.decoded_entries() {
            if !entry.id.starts_with(prefix) {
                continue;
            }
            if found
                .as_ref()
                .is_some_and(|found| found.info.id != entry.id)
            {
                ambiguous = true;
                return false;
            }
            let entry = match opened.scrub() {
                Some(scrub) => scrub.entry(&entry).0,
                None => entry,
            };
            found = Some(revealed(&entry));
        }
        true
    })?;
    Ok(match (ambiguous, found) {
        (true, _) => EntryLookup::Ambiguous,
        (false, None) => EntryLookup::NotFound,
        (false, Some(found)) => EntryLookup::Found(Box::new(found)),
    })
}

/// The entries whose IDs are in `ids`, with their values, in one walk.
pub fn reveal_entries(
    opened: &Opened,
    source: &mut impl PartSource,
    ids: &BTreeSet<EntryId>,
) -> Result<Vec<RevealedEntry>, ReadError> {
    let mut found: BTreeMap<EntryId, RevealedEntry> = BTreeMap::new();
    opened.walk(source, |read| {
        let PartRead::Readable { plaintext, .. } = read else {
            return true;
        };
        let part = Part::decode(&plaintext).expect("walk decoded it");
        for entry in part.decoded_entries() {
            if !ids.contains(&entry.id) || found.contains_key(&entry.id) {
                continue;
            }
            let entry = match opened.scrub() {
                Some(scrub) => scrub.entry(&entry).0,
                None => entry,
            };
            found.insert(entry.id, revealed(&entry));
        }
        found.len() < ids.len()
    })?;
    Ok(found.into_values().collect())
}

fn revealed(entry: &Entry<'_>) -> RevealedEntry {
    RevealedEntry {
        info: entry_info(entry),
        values: entry
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
            .collect(),
    }
}

fn kept(side: &Side<'_>) -> Option<Zeroizing<String>> {
    match side {
        Side::Value { value, .. } => Some(Zeroizing::new((*value).to_owned())),
        _ => None,
    }
}
