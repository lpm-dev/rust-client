//! Recording one project's change when the outermost lock ends: creating
//! history at the first change that touches a key, appending afterwards,
//! and finishing any key rotation or removal first. Nothing here changes
//! the values write it follows; every failure becomes an outcome.

use lpm_env_companion::append_log::{HISTORY, Head};
use lpm_env_companion::budgets::ADMISSION_TARGET;
use lpm_env_companion::history::admission::{self, CreationAdmission};
use lpm_env_companion::history::append::{
    AppendPlan, Change, CreationPlan, Growth, NotRecorded as PlanNotRecorded, Stored, plan_append,
    plan_creation,
};
use lpm_env_companion::history::codec::Actor;
use lpm_env_companion::history::read::Opened;
use lpm_env_companion::history::removal::{
    KeyMaintenance, finish_rotation, key_maintenance, needs_finishing, rotate_part, start_rotation,
};
use lpm_env_companion::history::switch::MarkerHistory;
use lpm_env_companion::history::{RecordWrite, head_account, key_account, part_account};
use lpm_env_companion::keyring::{Random, SystemRandom};

use super::scope::Tracked;
use super::store::HistoryStore;
use super::{NotRecorded, Outcome, values_of};
use crate::companion::gate::ProjectGate;
use crate::companion::lifecycle::Mutation;

/// Trims one operation may make before creating history or growing a ring.
const MAX_TRIMS_PER_OPERATION: usize = 16;

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
    let detail = tracked.source.detail.borrowed();
    let change = Change {
        id: tracked.source.id,
        time: now_ms(),
        actor: Actor::Cli,
        action: tracked.source.action,
        detail,
        before: &before,
        after: &after,
        renames: &[],
    };
    let mut random = SystemRandom;
    match MarkerHistory::of(marker) {
        MarkerHistory::Off => Outcome::Off,
        MarkerHistory::Removing | MarkerHistory::Unsupported { .. } => {
            Outcome::NotRecorded(NotRecorded::NewerVersion)
        }
        MarkerHistory::Both => Outcome::NotRecorded(NotRecorded::Damaged),
        MarkerHistory::Default => create(store, vault_id, marker, &change, &mut random)
            .unwrap_or_else(Outcome::NotRecorded),
        MarkerHistory::On => {
            append(store, vault_id, &change, &mut random).unwrap_or_else(Outcome::NotRecorded)
        }
    }
}

fn create(
    store: &mut impl HistoryStore,
    vault_id: &str,
    marker: Option<&crate::companion::marker::Marker>,
    change: &Change<'_, '_>,
    random: &mut impl Random,
) -> Result<Outcome, NotRecorded> {
    let existing = admit(store, vault_id, admission::CREATION_ACCOUNTS)?;
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
    change: &Change<'_, '_>,
    random: &mut impl Random,
) -> Result<Outcome, NotRecorded> {
    let (head, key) = open_maintained(store, vault_id, random)?;
    let mut growth = Growth::Unasked;
    let mut previous: Option<Vec<u8>> = None;
    let mut crowded = None;
    let parsed_head = Head::parse(HISTORY, vault_id, &head).map_err(|_| NotRecorded::Damaged)?;
    let tail = store
        .read(&part_account(vault_id, parsed_head.tail()))
        .map_err(NotRecorded::Failed)?;
    loop {
        let stored = Stored {
            head: &head,
            key: &key,
            tail: tail.as_deref(),
            previous: previous.as_deref(),
        };
        match plan_append(vault_id, &stored, change, growth, random).map_err(NotRecorded::from)? {
            AppendPlan::Unchanged => return Ok(Outcome::Nothing),
            AppendPlan::AlreadyRecorded => {
                return Ok(Outcome::Recorded {
                    crowded: None,
                    gap: false,
                });
            }
            AppendPlan::NeedsPrevious { part } => {
                previous = Some(
                    store
                        .read(&part_account(vault_id, part))
                        .map_err(NotRecorded::Failed)?
                        .ok_or(NotRecorded::Damaged)?,
                );
            }
            AppendPlan::NeedsGrowthAdmission => {
                let existing = admit(store, vault_id, 1)?;
                growth = if admission::admit_growth(existing) {
                    Growth::Allowed
                } else {
                    crowded = Some(existing);
                    Growth::Refused
                };
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

type Secret = zeroize::Zeroizing<Vec<u8>>;

/// The head and key, read with their access.
pub(super) fn read_head_and_key(
    store: &mut impl HistoryStore,
    vault_id: &str,
) -> Result<(Secret, Secret), NotRecorded> {
    let head = store
        .read_following_values(&head_account(vault_id))
        .map_err(NotRecorded::Failed)?
        .ok_or(NotRecorded::Damaged)?;
    let key = store
        .read_following_values(&key_account(vault_id))
        .map_err(NotRecorded::Failed)?
        .ok_or(NotRecorded::Damaged)?;
    Ok((head, key))
}

/// The head and key, read once, after any key upkeep they need: an append
/// or a read reads them again only when a rotation ran or an approval
/// change was recorded.
pub(super) fn open_maintained(
    store: &mut impl HistoryStore,
    vault_id: &str,
    random: &mut impl Random,
) -> Result<(Secret, Secret), NotRecorded> {
    let (head, key) = read_head_and_key(store, vault_id)?;
    let opened = Opened::open(vault_id, &head, &key).map_err(|_| NotRecorded::Damaged)?;
    let claimed = store
        .claimed_approval(vault_id)
        .map_err(NotRecorded::Failed)?;
    if !needs_finishing(&opened)
        && matches!(key_maintenance(&opened, claimed), KeyMaintenance::Nothing)
    {
        return Ok((head, key));
    }
    maintain_key(store, vault_id, random)?;
    read_head_and_key(store, vault_id)
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
    for part in opened.head.parts.clone() {
        let account = part_account(vault_id, part);
        let sealed = store.read(&account).map_err(NotRecorded::Failed)?;
        if let Some(write) = rotate_part(&opened, part, sealed.as_deref(), random)
            .map_err(|error| NotRecorded::Failed(error.to_string()))?
        {
            store
                .replace(&write.account, &write.bytes)
                .map_err(NotRecorded::Failed)?;
        }
    }
    let writes = finish_rotation(&opened).map_err(|_| NotRecorded::Damaged)?;
    commit(store, writes)
}

/// The service's record count for an operation that adds `adding`
/// accounts, after trimming the largest rings this client may write when
/// it would pass the target.
fn admit(
    store: &mut impl HistoryStore,
    vault_id: &str,
    adding: usize,
) -> Result<usize, NotRecorded> {
    let inventory = store
        .admission_inventory(vault_id)
        .map_err(NotRecorded::Failed)?;
    let mut existing = inventory.count;
    if existing + adding <= ADMISSION_TARGET {
        return Ok(existing);
    }
    let rings = inventory.rings;
    let mut trimmable = std::collections::BTreeSet::new();
    for ring in &rings {
        if ring.vault_id == vault_id
            || store
                .writes_without_prompt(&ring.vault_id)
                .map_err(NotRecorded::Failed)?
        {
            trimmable.insert(ring.vault_id.clone());
        }
    }
    for (project, count) in admission::plan_trims(
        existing + adding,
        &rings,
        MAX_TRIMS_PER_OPERATION,
        |project| trimmable.contains(project),
    ) {
        for _ in 0..count {
            let Some(head) = store
                .read_following_values(&head_account(&project))
                .map_err(NotRecorded::Failed)?
            else {
                break;
            };
            let Ok(head) = Head::parse(HISTORY, &project, &head) else {
                break;
            };
            let Some(trim) = admission::trim_oldest(&head) else {
                break;
            };
            store
                .replace(&trim.head.account, &trim.head.bytes)
                .map_err(NotRecorded::Failed)?;
            store.delete(&trim.delete).map_err(NotRecorded::Failed)?;
            existing -= 1;
        }
    }
    Ok(existing)
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
            PlanNotRecorded::Damaged(_) => Self::Damaged,
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
