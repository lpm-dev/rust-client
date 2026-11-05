//! Recording one change: creating history at the first change that touches
//! a key, and appending to it afterwards.
//!
//! An append runs after the values commit, in the same lock. It compares
//! the stored "before" state with the tail's summary and records any
//! difference as an `outside` entry first, then the change's own entry,
//! and replaces the tail's summary with the "after" state. The tail is
//! replaced when everything fits the part target. Otherwise a ring limited
//! to one part drops its oldest entries, and any other ring rolls over: the
//! head first, then the next part.

use std::fmt;

use crate::account::CompanionAccount;
use crate::append_log::{self, HISTORY, Head, TailState};
use crate::history::codec::{
    Action, Actor, Detail, Entry, EntryHeader, EntryId, Flags, InvalidPart, Part, Summary,
    encode_part, fits_str16, part_len,
};
use crate::history::values::{Rename, Values, gap_changes, net_change};
use crate::history::{RecordWrite, feature_entry, part_identity};
use crate::keyring::{self, Approval, KeyRecord, PART_CAPACITY, Random};
use crate::marker::{Marker, ProjectState};

/// The size at which a part rolls over, unless its summary needs more room.
pub const PART_TARGET: usize = 32 * 1024;
/// The room every part leaves for entries beside its summary.
pub const ENTRY_ROOM: usize = 16 * 1024;
/// A sliding ring slides at every append once it's full, so it asks
/// admission whether it may grow again only at every this many entries,
/// about as often as a shrunk ring rolls over.
pub const REGROW_CHECK_INTERVAL: u64 = 64;

/// The part target for a summary of `summary_len` bytes: the larger of
/// [`PART_TARGET`] and the summary plus [`ENTRY_ROOM`], never more than a
/// part's capacity. A writer's rule only: readers accept any part up to
/// capacity, so the target can rise without a migration.
pub fn part_target(summary_len: usize) -> usize {
    PART_TARGET
        .max(summary_len.saturating_add(ENTRY_ROOM))
        .min(PART_CAPACITY)
}

/// One change, as the operation that made it describes it.
#[derive(Debug, Clone, Copy)]
pub struct Change<'c, 'v> {
    /// Random per user action; a retry reuses it.
    pub id: EntryId,
    /// The writer's clock, in milliseconds since the Unix epoch.
    pub time: i64,
    pub actor: Actor,
    pub action: Action,
    pub detail: Detail<'c>,
    pub before: &'c Values<'v>,
    pub after: &'c Values<'v>,
    pub renames: &'c [Rename<'c>],
}

impl Change<'_, '_> {
    /// Whether the stored values differ at all, which recording needs.
    pub fn changes_values(&self) -> bool {
        self.before != self.after
    }

    /// Whether the change adds, changes, removes or renames a key, which
    /// creating history needs, told from the values alone, without digests:
    /// the same answer the entry's key count gives.
    pub fn changes_keys(&self) -> bool {
        let origins = environment_origins(self.before, self.after, self.renames);
        let renamed_away: Vec<&str> = origins.iter().map(|(_, from)| *from).collect();
        for (name, after_values) in self.after.environments() {
            let origin = origins
                .iter()
                .find(|(to, _)| to == name)
                .map(|(_, from)| *from)
                .or_else(|| self.before.environment(name).map(|_| *name));
            match origin.and_then(|origin| self.before.environment(origin)) {
                None if !after_values.is_empty() => return true,
                None => {}
                Some(before_values) if before_values != after_values => return true,
                Some(_) => {}
            }
        }
        self.before.environments().iter().any(|(name, values)| {
            !values.is_empty()
                && self.after.environment(name).is_none()
                && !renamed_away.contains(name)
        })
    }
}

/// The environment renames `renames` hints that the net change applies,
/// as (new name, old name).
fn environment_origins<'a>(
    before: &Values<'a>,
    after: &Values<'a>,
    renames: &[Rename<'a>],
) -> Vec<(&'a str, &'a str)> {
    let mut origins: Vec<(&'a str, &'a str)> = Vec::new();
    for rename in renames {
        if let Rename::Environment { from, to } = *rename
            && from != to
            && before.environment(from).is_some()
            && before.environment(to).is_none()
            && after.environment(to).is_some()
            && after.environment(from).is_none()
            && !origins.iter().any(|(new, old)| *old == from || *new == to)
        {
            origins.push((to, from));
        }
    }
    origins
}

/// Whether `values` are too many for history: a summary that leaves no
/// room for entries in a part, or a name too long to encode. Told from the
/// names alone, so a client can stop before reading history.
pub fn too_many_values(values: &Values<'_>) -> bool {
    let environments = values.environments();
    if environments.len() > usize::from(u16::MAX) {
        return true;
    }
    let mut length = 2_usize;
    for (name, keys) in environments {
        if !fits_str16(name) {
            return true;
        }
        length += 2 + name.len() + 4;
        for key in keys.keys() {
            if !fits_str16(key) {
                return true;
            }
            length += 2 + key.len() + 1 + 16;
        }
    }
    length + ENTRY_ROOM > PART_CAPACITY
}

/// What the plans of one append share while the client answers their
/// requests for another read or for admission, so a plan made again
/// doesn't digest every value again. One cache serves one append.
#[derive(Debug, Default)]
pub struct AppendCache<'v> {
    before_summary: Option<Summary<'v>>,
}

/// Why a change wasn't recorded, which the values write it follows never
/// depends on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NotRecorded {
    /// The head, the key or the tail won't read; Repair removes history.
    Damaged(String),
    /// The key is rotating or a removal is running: finish it first.
    NeedsMaintenance,
    /// The project's summary leaves no room for entries in a part.
    TooManyValues,
    Random,
}

impl fmt::Display for NotRecorded {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Damaged(reason) => write!(formatter, "local history is damaged: {reason}"),
            Self::NeedsMaintenance => {
                formatter.write_str("local history is finishing a key change")
            }
            Self::TooManyValues => {
                formatter.write_str("this env project has too many values to keep history")
            }
            Self::Random => formatter.write_str("the system's random number generator failed"),
        }
    }
}

impl From<keyring::RandomError> for NotRecorded {
    fn from(_: keyring::RandomError) -> Self {
        Self::Random
    }
}

/// What creating history writes, as one journal transaction: the marker
/// with the history entry, the key, the head and part 0.
#[derive(Debug)]
pub struct Creation {
    pub writes: Vec<RecordWrite>,
    pub entry: EntryId,
    pub values_kept: bool,
}

#[derive(Debug)]
pub enum CreationPlan {
    /// The change touches no key, so history isn't created for it.
    NoKeyChanges,
    Create(Creation),
}

/// Plan creating history for `change`, under `marker` (none yet, or one
/// without a history entry), with the ring limit admission chose.
/// `approval` is the values item's verified access, which the key records.
pub fn plan_creation(
    vault_id: &str,
    marker: Option<&Marker>,
    change: &Change<'_, '_>,
    approval: Approval,
    ring_limit: u16,
    random: &mut impl Random,
) -> Result<CreationPlan, NotRecorded> {
    let record = KeyRecord::generate(approval, random)?;
    let keys = record.digest_keys(vault_id);
    let before_summary = change.before.summary(&keys);
    let changes = net_change(
        change.before,
        &before_summary,
        change.after,
        change.renames,
        &keys,
    );
    let entry = Entry {
        seq: 1,
        id: change.id,
        time: change.time,
        actor: change.actor,
        action: change.action,
        flags: Flags::default(),
        since: None,
        detail: change.detail,
        environments: changes,
    };
    if !entry.changes_keys() {
        return Ok(CreationPlan::NoKeyChanges);
    }
    let mut summary = before_summary;
    summary.apply(&entry.environments);
    check_summary(&summary)?;
    let entries = fit(summary.encoded_len(), &[], vec![entry], PART_CAPACITY)?;
    let values_kept = !entries[0].flags.values_not_kept;
    let plaintext = encode_part(1, &summary, &[], &entries).map_err(damaged)?;
    let part = keyring::seal(
        record.current(),
        &part_identity(vault_id, 0),
        &plaintext,
        random,
    )
    .map_err(|_| NotRecorded::Random)?;
    let head = Head::new(vault_id, ring_limit)
        .encode(HISTORY)
        .map_err(|error| NotRecorded::Damaged(error.to_string()))?;
    let mut next_marker = marker
        .cloned()
        .unwrap_or_else(|| Marker::empty(vault_id, ProjectState::Active));
    next_marker
        .features
        .insert(super::FEATURE.to_owned(), feature_entry());
    let marker_bytes = next_marker
        .encode()
        .map_err(|error| NotRecorded::Damaged(error.to_string()))?;
    Ok(CreationPlan::Create(Creation {
        writes: vec![
            RecordWrite::new(
                CompanionAccount::Marker {
                    vault_id: vault_id.to_owned(),
                },
                marker_bytes,
            ),
            RecordWrite {
                account: super::key_account(vault_id),
                bytes: record.encode(),
            },
            RecordWrite::new(super::head_account(vault_id), head),
            RecordWrite::new(super::part_account(vault_id, 0), part),
        ],
        entry: change.id,
        values_kept,
    }))
}

/// What a client read for an append, inside its lock.
#[derive(Debug, Clone, Copy, Default)]
pub struct Stored<'a> {
    pub head: &'a [u8],
    pub key: &'a [u8],
    /// The tail part, `None` when its account is absent.
    pub tail: Option<&'a [u8]>,
    /// The part before the tail, once the plan asked for it.
    pub previous: Option<&'a [u8]>,
}

/// Whether a rollover may add a part, which only admission decides: a
/// ring below its limit grows, and a ring shrunk to fewer parts than a full
/// one grows again once the service has room ([`admission::admit_growth_of`]).
///
/// [`admission::admit_growth_of`]: crate::history::admission::admit_growth_of
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Growth {
    /// Admission hasn't been asked; a plan that would grow asks for it.
    Unasked,
    Allowed,
    Refused,
}

#[derive(Debug)]
pub enum AppendPlan {
    /// The stored values didn't change.
    Unchanged,
    /// The tail already holds the entry: a retry.
    AlreadyRecorded,
    /// A rollover was interrupted: read this part, the one before the tail,
    /// and plan again.
    NeedsPrevious {
        part: u16,
    },
    /// The rollover would add a part: ask admission and plan again.
    NeedsGrowthAdmission,
    Write(AppendWrite),
}

/// What an append writes. A rollover's head is written and verified first,
/// then the part; any other append writes the part alone, outside the
/// journal.
#[derive(Debug)]
pub struct AppendWrite {
    pub head: Option<RecordWrite>,
    pub part: RecordWrite,
    pub entry: EntryId,
    pub gap: bool,
    pub values_kept: bool,
    pub shape: AppendShape,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppendShape {
    Steady,
    /// A one-part ring dropped this many of its oldest entries.
    Slid {
        dropped: usize,
    },
    Rollover {
        grew: bool,
    },
    /// The tail was rewritten after a crash between a rollover's head and
    /// part.
    Recovered,
}

/// Plan appending `change` to the history `stored` holds. `cache` carries
/// work from an earlier plan of the same append.
pub fn plan_append<'v>(
    vault_id: &str,
    stored: &Stored<'_>,
    change: &Change<'_, 'v>,
    growth: Growth,
    cache: &mut AppendCache<'v>,
    random: &mut impl Random,
) -> Result<AppendPlan, NotRecorded> {
    if !change.changes_values() {
        return Ok(AppendPlan::Unchanged);
    }
    let head = Head::parse(HISTORY, vault_id, stored.head)
        .map_err(|error| NotRecorded::Damaged(error.to_string()))?;
    let record =
        KeyRecord::decode(stored.key).map_err(|error| NotRecorded::Damaged(error.to_string()))?;
    if record.is_rotating() || head.removing.is_some() {
        return Err(NotRecorded::NeedsMaintenance);
    }
    let tail_part = head.tail();
    let tail_plaintext = stored
        .tail
        .map(|sealed| keyring::open(&record, &part_identity(vault_id, tail_part), sealed))
        .transpose()
        .map_err(|error| NotRecorded::Damaged(format!("the tail won't open: {error}")))?;
    let tail = tail_plaintext
        .as_deref()
        .map(|plaintext| Part::decode(plaintext))
        .transpose()
        .map_err(damaged)?;
    if let (TailState::Current, Some(tail)) = (
        append_log::tail_state(&head, tail.as_ref().map(|part| part.epoch)),
        &tail,
    ) {
        if tail.contains_id(&change.id) {
            return Ok(AppendPlan::AlreadyRecorded);
        }
        let shape = if head.slides() {
            Shape::SteadyOrSlide(growth)
        } else {
            Shape::SteadyOrRollover(growth)
        };
        return finish(
            vault_id,
            &head,
            &record,
            change,
            &tail.summary,
            &tail.entries,
            tail.last_header(),
            shape,
            cache,
            random,
        );
    }
    let Some(part) = head.before_tail() else {
        return Err(NotRecorded::Damaged(
            "the tail is missing and no part comes before it".to_owned(),
        ));
    };
    let Some(sealed) = stored.previous else {
        return Ok(AppendPlan::NeedsPrevious { part });
    };
    let previous_plaintext = keyring::open(&record, &part_identity(vault_id, part), sealed)
        .map_err(|error| {
            NotRecorded::Damaged(format!(
                "the part before an interrupted rollover won't open: {error}"
            ))
        })?;
    let previous = Part::decode(&previous_plaintext).map_err(damaged)?;
    finish(
        vault_id,
        &head,
        &record,
        change,
        &previous.summary,
        &[],
        previous.last_header(),
        Shape::Recover,
        cache,
        random,
    )
}

#[derive(Debug, Clone, Copy)]
enum Shape {
    SteadyOrSlide(Growth),
    SteadyOrRollover(Growth),
    Recover,
}

#[allow(clippy::too_many_arguments)]
fn finish<'v>(
    vault_id: &str,
    head: &Head,
    record: &KeyRecord,
    change: &Change<'_, 'v>,
    baseline: &Summary<'_>,
    existing: &[&[u8]],
    last: Option<EntryHeader>,
    shape: Shape,
    cache: &mut AppendCache<'v>,
    random: &mut impl Random,
) -> Result<AppendPlan, NotRecorded> {
    let keys = record.digest_keys(vault_id);
    let before_summary = cache
        .before_summary
        .get_or_insert_with(|| change.before.summary(&keys))
        .clone();
    let gaps = gap_changes(baseline, change.before, &before_summary);
    let changes = net_change(
        change.before,
        &before_summary,
        change.after,
        change.renames,
        &keys,
    );
    if changes.is_empty() {
        return Ok(AppendPlan::Unchanged);
    }
    let mut summary = before_summary;
    summary.apply(&changes);
    check_summary(&summary)?;
    let recovering = matches!(shape, Shape::Recover);
    let mut seq = last.map_or(0, |header| header.seq);
    let mut entries = Vec::with_capacity(2);
    let gap = !gaps.is_empty();
    if gap {
        seq += 1;
        let mut id = [0_u8; 16];
        random.fill(&mut id)?;
        entries.push(Entry {
            seq,
            id,
            time: change.time,
            actor: Actor::Outside,
            action: Action::Outside,
            flags: Flags {
                interrupted_rollover: recovering,
                ..Flags::default()
            },
            since: Some(last.map_or(change.time, |header| header.time)),
            detail: Detail::default(),
            environments: gaps,
        });
    }
    seq += 1;
    entries.push(Entry {
        seq,
        id: change.id,
        time: change.time,
        actor: change.actor,
        action: change.action,
        flags: Flags {
            interrupted_rollover: recovering && !gap,
            ..Flags::default()
        },
        since: None,
        detail: change.detail,
        environments: changes,
    });

    let summary_len = summary.encoded_len();
    let target = part_target(summary_len);
    let new_len: usize = entries.iter().map(Entry::encoded_len).sum();
    let fits_with = |kept: &[&[u8]]| {
        part_len(summary_len, kept.iter().map(|bytes| bytes.len())) + 4 * entries.len() + new_len
            <= target
    };
    let slide = |next_head: Option<Head>| {
        let dropped = oldest_to_drop(summary_len, existing, entries.len(), new_len, target);
        (
            head.tail(),
            head.tail_epoch,
            &existing[dropped..],
            next_head,
            AppendShape::Slid { dropped },
        )
    };
    let (part, epoch, kept, next_head, shape_out) = match shape {
        Shape::Recover => (
            head.tail(),
            head.tail_epoch,
            &existing[..0],
            None,
            AppendShape::Recovered,
        ),
        _ if fits_with(existing) => (
            head.tail(),
            head.tail_epoch,
            existing,
            None,
            AppendShape::Steady,
        ),
        Shape::SteadyOrSlide(growth) => match growth {
            _ if !head.may_regrow(HISTORY) || !seq.is_multiple_of(REGROW_CHECK_INTERVAL) => {
                slide(None)
            }
            Growth::Unasked => return Ok(AppendPlan::NeedsGrowthAdmission),
            Growth::Allowed => rollover(head, true),
            Growth::Refused => slide(None),
        },
        Shape::SteadyOrRollover(growth) => {
            let may_grow = match growth {
                _ if !head.would_grow() && !head.may_regrow(HISTORY) => false,
                Growth::Unasked => return Ok(AppendPlan::NeedsGrowthAdmission),
                Growth::Allowed => true,
                Growth::Refused => false,
            };
            if !may_grow && head.parts.len() == 1 {
                // Reusing a ring's only part would drop history to one entry,
                // so a ring that can't grow past one part slides, and keeps
                // one part as its limit so later appends don't ask again.
                let mut sliding = head.clone();
                sliding.ring_limit = 1;
                slide(Some(sliding))
            } else {
                rollover(head, may_grow)
            }
        }
    };
    let entries = fit(summary_len, kept, entries, PART_CAPACITY)?;
    let values_kept = entries.iter().all(|entry| !entry.flags.values_not_kept);
    let plaintext = encode_part(epoch, &summary, kept, &entries).map_err(damaged)?;
    let sealed = keyring::seal(
        record.sealing_key(),
        &part_identity(vault_id, part),
        &plaintext,
        random,
    )
    .map_err(|_| NotRecorded::Random)?;
    let head_write = next_head
        .map(|next| {
            next.encode(HISTORY)
                .map(|bytes| RecordWrite::new(super::head_account(vault_id), bytes))
                .map_err(|error| NotRecorded::Damaged(error.to_string()))
        })
        .transpose()?;
    Ok(AppendPlan::Write(AppendWrite {
        head: head_write,
        part: RecordWrite::new(super::part_account(vault_id, part), sealed),
        entry: change.id,
        gap,
        values_kept,
        shape: shape_out,
    }))
}

/// A rollover's place, epoch, entries kept and head. A ring shrunk below
/// a full ring that may grow takes a full limit again first.
fn rollover<'k>(
    head: &Head,
    may_grow: bool,
) -> (u16, u64, &'k [&'k [u8]], Option<Head>, AppendShape) {
    let regrown;
    let from = if may_grow && !head.would_grow() {
        let mut full = head.clone();
        full.ring_limit = HISTORY.max_parts;
        regrown = full;
        &regrown
    } else {
        head
    };
    let rollover = from.rollover(HISTORY, may_grow);
    (
        rollover.part,
        rollover.head.tail_epoch,
        &[],
        Some(rollover.head),
        AppendShape::Rollover {
            grew: !rollover.reused,
        },
    )
}

/// How many of the oldest `existing` entries a sliding tail drops so the
/// rest fit beside `new_count` new entries of `new_len` bytes; all of them
/// when even the new entries alone don't fit the target. One pass.
fn oldest_to_drop(
    summary_len: usize,
    existing: &[&[u8]],
    new_count: usize,
    new_len: usize,
    target: usize,
) -> usize {
    let mut length =
        part_len(summary_len, existing.iter().map(|bytes| bytes.len())) + 4 * new_count + new_len;
    for (dropped, bytes) in existing.iter().enumerate() {
        if length <= target {
            return dropped;
        }
        length -= 4 + bytes.len();
    }
    existing.len()
}

/// `entries` as they fit beside `kept` within `limit`: as they are, then
/// without values, then oversized.
fn fit<'e>(
    summary_len: usize,
    kept: &[&[u8]],
    entries: Vec<Entry<'e>>,
    limit: usize,
) -> Result<Vec<Entry<'e>>, NotRecorded> {
    let kept_len = part_len(summary_len, kept.iter().map(|bytes| bytes.len()));
    let length = |entries: &[Entry<'_>]| {
        kept_len
            + entries
                .iter()
                .map(|entry| 4 + entry.encoded_len())
                .sum::<usize>()
    };
    if length(&entries) <= limit {
        return Ok(entries);
    }
    let without: Vec<Entry<'e>> = entries.iter().map(Entry::without_values).collect();
    if length(&without) <= limit {
        return Ok(without);
    }
    let oversized: Vec<Entry<'e>> = entries.iter().map(Entry::oversized).collect();
    if length(&oversized) <= limit {
        return Ok(oversized);
    }
    Err(NotRecorded::TooManyValues)
}

/// A summary too large to leave [`ENTRY_ROOM`] in a part, or with a name
/// too long to encode, means history can't record this project.
fn check_summary(summary: &Summary<'_>) -> Result<(), NotRecorded> {
    if summary.is_encodable() && summary.encoded_len() + ENTRY_ROOM <= PART_CAPACITY {
        Ok(())
    } else {
        Err(NotRecorded::TooManyValues)
    }
}

fn damaged(error: InvalidPart) -> NotRecorded {
    NotRecorded::Damaged(error.to_string())
}

#[cfg(test)]
mod tests;
