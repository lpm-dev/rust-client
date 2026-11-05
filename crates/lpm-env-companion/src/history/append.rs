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
    encode_part, part_len,
};
use crate::history::values::{Rename, Values, gap_changes, net_change};
use crate::history::{RecordWrite, feature_entry, part_identity};
use crate::keyring::{self, Approval, KeyRecord, PART_CAPACITY, Random};
use crate::marker::{Marker, ProjectState};

/// The size at which a part rolls over, unless its summary needs more room.
pub const PART_TARGET: usize = 32 * 1024;
/// The room every part leaves for entries beside its summary.
pub const ENTRY_ROOM: usize = 16 * 1024;

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
    let entries = fit(&summary, &[], vec![entry], PART_CAPACITY)?;
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

/// Whether a rollover may add a part, which only admission decides.
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

/// Plan appending `change` to the history `stored` holds.
pub fn plan_append(
    vault_id: &str,
    stored: &Stored<'_>,
    change: &Change<'_, '_>,
    growth: Growth,
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
            Shape::SteadyOrSlide
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
        random,
    )
}

#[derive(Debug, Clone, Copy)]
enum Shape {
    SteadyOrSlide,
    SteadyOrRollover(Growth),
    Recover,
}

#[allow(clippy::too_many_arguments)]
fn finish(
    vault_id: &str,
    head: &Head,
    record: &KeyRecord,
    change: &Change<'_, '_>,
    baseline: &Summary<'_>,
    existing: &[&[u8]],
    last: Option<EntryHeader>,
    shape: Shape,
    random: &mut impl Random,
) -> Result<AppendPlan, NotRecorded> {
    let keys = record.digest_keys(vault_id);
    let before_summary = change.before.summary(&keys);
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

    let target = part_target(summary.encoded_len());
    let fits_with = |kept: &[&[u8]]| {
        part_len(
            summary.encoded_len(),
            kept.iter()
                .map(|bytes| bytes.len())
                .chain(entries.iter().map(Entry::encoded_len)),
        ) <= target
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
        Shape::SteadyOrSlide => {
            let dropped = oldest_to_drop(existing, &fits_with);
            (
                head.tail(),
                head.tail_epoch,
                &existing[dropped..],
                None,
                AppendShape::Slid { dropped },
            )
        }
        Shape::SteadyOrRollover(growth) => {
            let may_grow = match growth {
                _ if !head.would_grow() => false,
                Growth::Unasked => return Ok(AppendPlan::NeedsGrowthAdmission),
                Growth::Allowed => true,
                Growth::Refused => false,
            };
            if !may_grow && head.parts.len() == 1 {
                // Reusing a ring's only part would drop history to one entry,
                // so a ring that can't grow past one part slides, and keeps
                // one part as its limit so later appends don't ask again.
                let dropped = oldest_to_drop(existing, &fits_with);
                let mut sliding = head.clone();
                sliding.ring_limit = 1;
                (
                    head.tail(),
                    head.tail_epoch,
                    &existing[dropped..],
                    Some(sliding),
                    AppendShape::Slid { dropped },
                )
            } else {
                let rollover = head.rollover(HISTORY, may_grow);
                (
                    rollover.part,
                    rollover.head.tail_epoch,
                    &existing[..0],
                    Some(rollover.head),
                    AppendShape::Rollover {
                        grew: !rollover.reused,
                    },
                )
            }
        }
    };
    let entries = fit(&summary, kept, entries, PART_CAPACITY)?;
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

/// How many of the oldest `existing` entries a sliding tail drops so the
/// rest fit beside the new entries; all of them when even the new entries
/// alone don't fit the target.
fn oldest_to_drop(existing: &[&[u8]], fits_with: &impl Fn(&[&[u8]]) -> bool) -> usize {
    (0..existing.len())
        .find(|dropped| fits_with(&existing[*dropped..]))
        .unwrap_or(existing.len())
}

/// `entries` as they fit beside `kept` within `limit`: as they are, then
/// without values, then oversized.
fn fit<'e>(
    summary: &Summary<'_>,
    kept: &[&[u8]],
    entries: Vec<Entry<'e>>,
    limit: usize,
) -> Result<Vec<Entry<'e>>, NotRecorded> {
    let length = |entries: &[Entry<'_>]| {
        part_len(
            summary.encoded_len(),
            kept.iter()
                .map(|bytes| bytes.len())
                .chain(entries.iter().map(Entry::encoded_len)),
        )
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
