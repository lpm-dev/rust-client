//! Recording one project's change when the outermost lock ends: creating
//! history at the first change that touches a key, appending afterwards,
//! and finishing any key rotation or removal first. Nothing here changes
//! the values write it follows; every failure becomes an outcome.

use lpm_env_companion::append_log::{HISTORY, Head};
use lpm_env_companion::budgets::ADMISSION_TARGET;
use lpm_env_companion::history::admission::{self, CreationAdmission, TrimStep, TrimTail};
use lpm_env_companion::history::append::{
    AppendCache, AppendPlan, Change, CreationPlan, Growth, NotRecorded as PlanNotRecorded, Stored,
    plan_append, plan_creation, too_many_values,
};
use lpm_env_companion::history::codec::Actor;
use lpm_env_companion::history::read::Opened;
use lpm_env_companion::history::removal::{
    KeyMaintenance, finish_rotation, key_maintenance, needs_finishing, rotate_part, start_rotation,
};
use lpm_env_companion::history::switch::MarkerHistory;
use lpm_env_companion::history::values::Rename;
use lpm_env_companion::history::{RecordWrite, head_account, key_account};
use lpm_env_companion::keyring::{Random, SystemRandom};

use super::scope::Tracked;
use super::store::{HistoryStore, RecordError, read_part};
use super::{NotRecorded, Outcome, values_of};
use crate::companion::gate::ProjectGate;
use crate::companion::lifecycle::Mutation;

/// Trims one operation may make before creating history or growing a ring.
pub(super) const MAX_TRIMS_PER_OPERATION: usize = 16;

/// Record `tracked`, the change one lock scope made to `vault_id`.
pub(crate) fn record(store: &mut impl HistoryStore, vault_id: &str, tracked: &Tracked) -> Outcome {
    let (Some(before), Some(after)) = (&tracked.before, &tracked.after) else {
        return Outcome::Nothing;
    };
    let before = values_of(before);
    let after = values_of(after);
    if before == after {
        return Outcome::Nothing;
    }
    let gate = match crate::companion::open_project(store, vault_id) {
        Ok(gate) => gate,
        Err(error) => return Outcome::NotRecorded(NotRecorded::Failed(error)),
    };
    let marker = match &gate {
        ProjectGate::Plain => None,
        ProjectGate::Marked(marker) => Some(marker),
        ProjectGate::Damaged(_) => return Outcome::NotRecorded(NotRecorded::Damaged),
    };
    let renames: Vec<Rename<'_>> = tracked
        .environment_renames
        .iter()
        .map(|(from, to)| Rename::Environment { from, to })
        .collect();
    let detail = tracked.source.detail.borrowed();
    let change = Change {
        id: tracked.source.id,
        time: now_ms(),
        actor: Actor::Cli,
        action: tracked.source.action,
        detail,
        before: &before,
        after: &after,
        renames: &renames,
    };
    let mut random = SystemRandom;
    match MarkerHistory::of(marker) {
        MarkerHistory::Off => Outcome::Off,
        MarkerHistory::Removing | MarkerHistory::Unsupported { .. } => {
            Outcome::NotRecorded(NotRecorded::NewerVersion)
        }
        MarkerHistory::Both => Outcome::NotRecorded(NotRecorded::Damaged),
        MarkerHistory::Default if !change.changes_keys() => Outcome::Nothing,
        MarkerHistory::Default | MarkerHistory::On if too_many_values(&after) => {
            Outcome::NotRecorded(NotRecorded::TooManyValues)
        }
        MarkerHistory::Default => create(store, vault_id, marker, &change, &mut random)
            .unwrap_or_else(Outcome::NotRecorded),
        MarkerHistory::On => append(store, vault_id, marker, &change, &mut random)
            .unwrap_or_else(Outcome::NotRecorded),
    }
}

fn create(
    store: &mut impl HistoryStore,
    vault_id: &str,
    marker: Option<&crate::companion::marker::Marker>,
    change: &Change<'_, '_>,
    random: &mut impl Random,
) -> Result<Outcome, NotRecorded> {
    let existing = admit(store, vault_id, admission::CREATION_ACCOUNTS, None)?.existing;
    let admission = admission::admit_creation(existing);
    let Some(ring_limit) = admission.ring_limit() else {
        return Err(NotRecorded::Limit);
    };
    let approval = store
        .verified_approval(vault_id)
        .map_err(NotRecorded::Failed)?
        .ok_or(NotRecorded::Unavailable)?;
    let creation = match plan_creation(vault_id, marker, change, approval, ring_limit, random)
        .map_err(NotRecorded::from)?
    {
        CreationPlan::NoKeyChanges => return Ok(Outcome::Nothing),
        CreationPlan::Create(creation) => creation,
    };
    let next_marker = creation
        .writes
        .iter()
        .find(|write| {
            matches!(
                write.account,
                crate::companion::account::CompanionAccount::Marker { .. }
            )
        })
        .and_then(|write| crate::companion::marker::Marker::parse(vault_id, &write.bytes).ok());
    commit(store, creation.writes)?;
    if let Some(next_marker) = next_marker {
        crate::companion::remember(vault_id, &ProjectGate::Marked(next_marker));
    }
    Ok(Outcome::Recorded {
        crowded: (admission == CreationAdmission::Reduced).then_some(existing),
        gap: false,
    })
}

fn append(
    store: &mut impl HistoryStore,
    vault_id: &str,
    marker: Option<&crate::companion::marker::Marker>,
    change: &Change<'_, '_>,
    random: &mut impl Random,
) -> Result<Outcome, NotRecorded> {
    let Maintained {
        mut head,
        key,
        mut opened,
    } = open_maintained(store, vault_id, random)?;
    let mut growth = Growth::Unasked;
    let mut crowded = None;
    let mut cache = AppendCache::default();
    'read: loop {
        let tail = read_part(store, vault_id, opened.head.tail()).map_err(NotRecorded::Failed)?;
        let mut previous: Option<Vec<u8>> = None;
        loop {
            let stored = Stored {
                head: &head,
                key: &key,
                tail: tail.as_deref(),
                previous: previous.as_deref(),
            };
            match plan_append(
                vault_id, marker, &stored, change, growth, &mut cache, random,
            )
            .map_err(NotRecorded::from)?
            {
                AppendPlan::Unchanged => return Ok(Outcome::Nothing),
                AppendPlan::AlreadyRecorded => {
                    return Ok(Outcome::Recorded {
                        crowded: None,
                        gap: false,
                    });
                }
                AppendPlan::NeedsPrevious { part } => {
                    previous = Some(
                        read_part(store, vault_id, part)
                            .map_err(NotRecorded::Failed)?
                            .ok_or(NotRecorded::Damaged)?,
                    );
                }
                AppendPlan::NeedsGrowthAdmission => {
                    let admitted = admit(store, vault_id, 1, Some(&opened.head))?;
                    if admitted.trimmed_own {
                        // A trim rewrote this project's head: plan again on
                        // the head as it is now.
                        head = store
                            .read_following_values(&head_account(vault_id))?
                            .ok_or(NotRecorded::Damaged)?;
                        opened = Opened::open(vault_id, &head, &key)
                            .map_err(|_| NotRecorded::Damaged)?;
                    }
                    growth = if admission::admit_growth_of(&opened.head, admitted.existing) {
                        Growth::Allowed
                    } else {
                        if opened.head.would_grow() {
                            crowded = Some(admitted.existing);
                        }
                        Growth::Refused
                    };
                    if admitted.trimmed_own {
                        continue 'read;
                    }
                }
                AppendPlan::Write(write) => {
                    if let Some(head) = write.head {
                        store
                            .replace(&head.account, &head.bytes)
                            .map_err(NotRecorded::Failed)?;
                    }
                    store
                        .replace(&write.part.account, &write.part.bytes)
                        .map_err(NotRecorded::Failed)?;
                    return Ok(Outcome::Recorded {
                        crowded,
                        gap: write.gap,
                    });
                }
            }
        }
    }
}

type Secret = zeroize::Zeroizing<Vec<u8>>;

impl From<RecordError> for NotRecorded {
    fn from(error: RecordError) -> Self {
        match error {
            RecordError::Damaged(_) => Self::Damaged,
            RecordError::Store(error) => Self::Failed(error),
        }
    }
}

/// The head and key, read with their access.
pub(super) fn read_head_and_key(
    store: &mut impl HistoryStore,
    vault_id: &str,
) -> Result<(Secret, Secret), NotRecorded> {
    let head = store
        .read_following_values(&head_account(vault_id))?
        .ok_or(NotRecorded::Damaged)?;
    let key = store
        .read_following_values(&key_account(vault_id))?
        .ok_or(NotRecorded::Damaged)?;
    Ok((head, key))
}

/// History's head and key after any upkeep they needed, as read and as
/// opened.
pub(super) struct Maintained {
    pub(super) head: Secret,
    pub(super) key: Secret,
    pub(super) opened: Opened,
}

/// The head and key, read once, after any key upkeep they need: an append
/// or a read reads them again only when a rotation ran or an approval
/// change was recorded.
pub(super) fn open_maintained(
    store: &mut impl HistoryStore,
    vault_id: &str,
    random: &mut impl Random,
) -> Result<Maintained, NotRecorded> {
    let (head, key) = read_head_and_key(store, vault_id)?;
    let opened = Opened::open(vault_id, &head, &key).map_err(|_| NotRecorded::Damaged)?;
    let claimed = store
        .claimed_approval(vault_id)
        .map_err(NotRecorded::Failed)?;
    if !needs_finishing(&opened)
        && matches!(key_maintenance(&opened, claimed), KeyMaintenance::Nothing)
    {
        return Ok(Maintained { head, key, opened });
    }
    maintain_key(store, vault_id, random)?;
    let (head, key) = read_head_and_key(store, vault_id)?;
    let opened = Opened::open(vault_id, &head, &key).map_err(|_| NotRecorded::Damaged)?;
    Ok(Maintained { head, key, opened })
}

fn opened(store: &mut impl HistoryStore, vault_id: &str) -> Result<Opened, NotRecorded> {
    let (head, key) = read_head_and_key(store, vault_id)?;
    Opened::open(vault_id, &head, &key).map_err(|_| NotRecorded::Damaged)
}

/// Rotate a key made while approval was off once approval is on, record a
/// lowered approval, and finish any rotation or removal another client
/// started: every history operation does this first.
pub(super) fn maintain_key(
    store: &mut impl HistoryStore,
    vault_id: &str,
    random: &mut impl Random,
) -> Result<(), NotRecorded> {
    finish_running(store, vault_id, random)?;
    let opened = opened(store, vault_id)?;
    let claimed = store
        .claimed_approval(vault_id)
        .map_err(NotRecorded::Failed)?;
    match key_maintenance(&opened, claimed) {
        KeyMaintenance::Nothing => Ok(()),
        KeyMaintenance::Lower(write) => store
            .replace(&write.account, &write.bytes)
            .map_err(NotRecorded::Failed),
        KeyMaintenance::Rotate => {
            let writes = start_rotation(&opened, claimed, random)
                .map_err(|error| NotRecorded::Failed(error.to_string()))?;
            commit(store, writes)?;
            finish_running(store, vault_id, random)
        }
    }
}

/// Finish a rotation or removal: every part still under the old key is
/// sealed under the new one, then the key keeps only the new key.
pub(super) fn finish_running(
    store: &mut impl HistoryStore,
    vault_id: &str,
    random: &mut impl Random,
) -> Result<(), NotRecorded> {
    let opened = opened(store, vault_id)?;
    if !needs_finishing(&opened) {
        return Ok(());
    }
    // Each part as stored once it's rotated, so finishing checks them
    // without reading them again.
    let mut stored: Vec<(u16, Option<Vec<u8>>)> = Vec::with_capacity(opened.head.parts.len());
    for part in opened.head.parts.clone() {
        let sealed = read_part(store, vault_id, part).map_err(NotRecorded::Failed)?;
        let now = match rotate_part(&opened, part, sealed.as_deref(), random)
            .map_err(|error| NotRecorded::Failed(error.to_string()))?
        {
            Some(write) => {
                store
                    .replace(&write.account, &write.bytes)
                    .map_err(NotRecorded::Failed)?;
                Some(write.bytes.to_vec())
            }
            None => sealed,
        };
        stored.push((part, now));
    }
    let parts = |part| {
        stored
            .iter()
            .find(|(listed, _)| *listed == part)
            .and_then(|(_, bytes)| bytes.as_deref())
    };
    let writes = finish_rotation(&opened, parts).map_err(|_| NotRecorded::Damaged)?;
    commit(store, writes)
}

/// What admission found, after its trims.
struct Admitted {
    /// The service's record count.
    existing: usize,
    /// Whether a trim rewrote this project's own head.
    trimmed_own: bool,
}

/// The service's record count for an operation that adds `adding`
/// accounts, after trimming the largest rings this client may write when
/// it would pass the target. With `own`, this project's head, the parts it
/// doesn't list, left by a trim that crashed before its deletion, are
/// deleted too.
fn admit(
    store: &mut impl HistoryStore,
    vault_id: &str,
    adding: usize,
    own: Option<&Head>,
) -> Result<Admitted, NotRecorded> {
    let mut inventory = store
        .admission_inventory(vault_id)
        .map_err(NotRecorded::Failed)?;
    let mut existing = inventory.count;
    if let Some(head) = own
        && let Some(ring) = inventory
            .rings
            .iter_mut()
            .find(|ring| ring.vault_id == vault_id && ring.parts > head.parts.len())
    {
        let accounts = store.inventory(vault_id).map_err(NotRecorded::Failed)?;
        for orphan in admission::orphan_parts(head, &accounts) {
            store.delete(&orphan).map_err(NotRecorded::Failed)?;
            existing -= 1;
            ring.parts -= 1;
        }
    }
    let mut trimmed_own = false;
    if existing + adding <= ADMISSION_TARGET {
        return Ok(Admitted {
            existing,
            trimmed_own,
        });
    }
    for planned in admission::plan_trims(
        existing + adding,
        &inventory.rings,
        MAX_TRIMS_PER_OPERATION,
        |project| inventory.trimmable.contains(project),
    ) {
        let project = planned.vault_id;
        for _ in 0..planned.count {
            let head = match store.read_following_values(&head_account(&project)) {
                Ok(Some(head)) => head,
                // Another project's damaged history is its own to repair.
                Ok(None) | Err(RecordError::Damaged(_)) => break,
                Err(RecordError::Store(error)) => return Err(NotRecorded::Failed(error)),
            };
            let Ok(head) = Head::parse(HISTORY, &project, &head) else {
                break;
            };
            let step = match admission::trim_oldest(&head, planned.floor, TrimTail::Unread) {
                TrimStep::NeedsTail => {
                    let key = match store.read_following_values(&key_account(&project)) {
                        Ok(Some(key)) => key,
                        Ok(None) | Err(RecordError::Damaged(_)) => break,
                        Err(RecordError::Store(error)) => {
                            return Err(NotRecorded::Failed(error));
                        }
                    };
                    let tail =
                        read_part(store, &project, head.tail()).map_err(NotRecorded::Failed)?;
                    admission::trim_oldest(
                        &head,
                        planned.floor,
                        TrimTail::Read {
                            key: &key,
                            tail: tail.as_deref(),
                        },
                    )
                }
                step => step,
            };
            let TrimStep::Trim(trim) = step else {
                break;
            };
            store
                .replace(&trim.head.account, &trim.head.bytes)
                .map_err(NotRecorded::Failed)?;
            store.delete(&trim.delete).map_err(NotRecorded::Failed)?;
            existing -= 1;
            trimmed_own |= project == vault_id;
        }
    }
    Ok(Admitted {
        existing,
        trimmed_own,
    })
}

/// Commit `writes` as one journal transaction.
pub(super) fn commit(
    store: &mut impl HistoryStore,
    writes: Vec<RecordWrite>,
) -> Result<(), NotRecorded> {
    store
        .commit(
            writes
                .into_iter()
                .map(|write| Mutation::Write {
                    account: write.account,
                    value: write.bytes,
                })
                .collect(),
        )
        .map_err(NotRecorded::Failed)
}

impl From<PlanNotRecorded> for NotRecorded {
    fn from(reason: PlanNotRecorded) -> Self {
        match reason {
            PlanNotRecorded::Marker(MarkerHistory::Both) | PlanNotRecorded::Damaged(_) => {
                Self::Damaged
            }
            PlanNotRecorded::Marker(
                MarkerHistory::Unsupported { .. } | MarkerHistory::Removing,
            ) => Self::NewerVersion,
            refused @ PlanNotRecorded::Marker(
                MarkerHistory::Default | MarkerHistory::On | MarkerHistory::Off,
            ) => Self::Failed(refused.to_string()),
            PlanNotRecorded::NeedsMaintenance => {
                Self::Failed("local history is finishing a key change".to_owned())
            }
            PlanNotRecorded::TooManyValues => Self::TooManyValues,
            PlanNotRecorded::Random => {
                Self::Failed("the system's random number generator failed".to_owned())
            }
        }
    }
}

pub(crate) fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| {
            i64::try_from(elapsed.as_millis()).unwrap_or(i64::MAX)
        })
}
