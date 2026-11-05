//! How much history the service-wide record budget allows: whether a new
//! history starts and with how many parts, whether a ring grows, and which
//! rings shrink when the service holds too many records.
//!
//! N counts companion and staged records, orphans included and markers not,
//! from the names-only inventory the operation already takes.
//!
//! | N after the change | Creation              | Growth  | Shrinking                         |
//! |--------------------|-----------------------|---------|-----------------------------------|
//! | ≤ 4,096            | 16 parts              | allowed |                                   |
//! | > 4,096            | 2 parts, with a note  | refused | largest rings down to 2 parts     |
//! | > 8,192            | refused               | refused | largest rings down to 1 part      |

use std::cmp::Reverse;
use std::collections::{BTreeMap, BinaryHeap};

use crate::account::CompanionAccount;
use crate::append_log::{HISTORY, Head};
use crate::budgets::{ADMISSION_CAP, ADMISSION_TARGET};
use crate::history::{RecordWrite, head_account};

/// Accounts creating history adds: the head, the key and part 0.
pub const CREATION_ACCOUNTS: usize = 3;
/// Below this many records, shrunk rings may grow again: 7/8 of the target,
/// so rings don't flap around it.
pub const REGROW_BELOW: usize = ADMISSION_TARGET / 8 * 7;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CreationAdmission {
    /// A full ring.
    Full,
    /// Past the target: two parts, and the person hears why.
    Reduced,
    /// Past the cap: history doesn't start, "Paused: limit".
    Refused,
}

impl CreationAdmission {
    /// The ring limit a new history gets, or `None` when refused.
    pub fn ring_limit(self) -> Option<u16> {
        match self {
            Self::Full => Some(HISTORY.max_parts),
            Self::Reduced => Some(2),
            Self::Refused => None,
        }
    }
}

/// Admission for creating history in a service holding `existing` records.
pub fn admit_creation(existing: usize) -> CreationAdmission {
    let after = existing.saturating_add(CREATION_ACCOUNTS);
    if after <= ADMISSION_TARGET {
        CreationAdmission::Full
    } else if after <= ADMISSION_CAP {
        CreationAdmission::Reduced
    } else {
        CreationAdmission::Refused
    }
}

/// Whether a ring may add a part to a service holding `existing` records.
pub fn admit_growth(existing: usize) -> bool {
    existing.saturating_add(1) <= ADMISSION_TARGET
}

/// Whether the ring `head` describes may add a part: a ring below its limit
/// while the service stays within its target, and a ring shrunk below a
/// full one once the service is back below [`REGROW_BELOW`], so rings
/// don't flap around the target.
pub fn admit_growth_of(head: &Head, existing: usize) -> bool {
    if head.would_grow() {
        admit_growth(existing)
    } else {
        head.may_regrow(HISTORY) && existing.saturating_add(1) < REGROW_BELOW
    }
}

/// One project's ring, from the names-only inventory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ring {
    pub vault_id: String,
    pub parts: usize,
}

/// The history rings in `accounts`, a names-only inventory of the service:
/// how many history parts each project holds, the head's listing aside.
pub fn rings<'a>(accounts: impl IntoIterator<Item = &'a CompanionAccount>) -> Vec<Ring> {
    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    for account in accounts {
        if let CompanionAccount::Record {
            kind,
            vault_id,
            part: Some(_),
        } = account
            && kind == HISTORY.kind
        {
            *counts.entry(vault_id.as_str()).or_default() += 1;
        }
    }
    counts
        .into_iter()
        .map(|(vault_id, parts)| Ring {
            vault_id: vault_id.to_owned(),
            parts,
        })
        .collect()
}

/// Trims that bring a service holding `existing` records back within its
/// budget, at most `max` of them: the largest rings first, ties by vault
/// ID, down to 2 parts each while past the target and 1 part each while
/// past the cap. `trimmable` says which projects this client may write
/// without a prompt. Returns how many parts to trim from each project.
pub fn plan_trims(
    existing: usize,
    rings: &[Ring],
    max: usize,
    trimmable: impl Fn(&str) -> bool,
) -> Vec<(String, usize)> {
    let mut remaining = existing;
    let mut heap: BinaryHeap<(usize, Reverse<&str>)> = rings
        .iter()
        .filter(|ring| trimmable(&ring.vault_id))
        .map(|ring| (ring.parts, Reverse(ring.vault_id.as_str())))
        .collect();
    let mut trims: BTreeMap<&str, usize> = BTreeMap::new();
    let mut made = 0;
    while made < max && remaining > ADMISSION_TARGET {
        let floor = if remaining > ADMISSION_CAP { 1 } else { 2 };
        let Some((parts, Reverse(vault_id))) = heap.pop() else {
            break;
        };
        if parts <= floor {
            break;
        }
        *trims.entry(vault_id).or_default() += 1;
        made += 1;
        remaining -= 1;
        heap.push((parts - 1, Reverse(vault_id)));
    }
    trims
        .into_iter()
        .map(|(vault_id, count)| (vault_id.to_owned(), count))
        .collect()
}

/// One trim of a ring: the head without its oldest part, written and
/// verified first, then that part deleted. `None` when one part is left.
#[derive(Debug)]
pub struct Trim {
    pub head: RecordWrite,
    pub delete: CompanionAccount,
}

pub fn trim_oldest(head: &Head) -> Option<Trim> {
    let (next, oldest) = head.trim_oldest()?;
    Some(Trim {
        head: RecordWrite::new(head_account(&head.vault_id), next.encode(HISTORY).ok()?),
        delete: crate::history::part_account(&head.vault_id, oldest),
    })
}

/// The head with a full ring limit again, for a ring shrunk while the
/// service was past its target, once it's back below [`REGROW_BELOW`].
pub fn raise_limit(head: &Head, existing: usize) -> Option<RecordWrite> {
    if existing >= REGROW_BELOW || head.ring_limit >= HISTORY.max_parts {
        return None;
    }
    let mut next = head.clone();
    next.ring_limit = HISTORY.max_parts;
    Some(RecordWrite::new(
        head_account(&head.vault_id),
        next.encode(HISTORY).ok()?,
    ))
}

/// History parts of `head`'s project that the head doesn't list: left by a
/// trim that crashed before its deletion, and collected by the next
/// operation that holds an inventory.
pub fn orphan_parts<'a>(
    head: &Head,
    inventory: impl IntoIterator<Item = &'a CompanionAccount>,
) -> Vec<CompanionAccount> {
    inventory
        .into_iter()
        .filter(|account| {
            matches!(account, CompanionAccount::Record { kind, vault_id, part: Some(part) }
                if kind == HISTORY.kind && *vault_id == head.vault_id && !head.lists(*part))
        })
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creation_at_the_target_and_the_cap_and_one_past_each() {
        assert_eq!(admit_creation(4_093), CreationAdmission::Full);
        assert_eq!(admit_creation(4_094), CreationAdmission::Reduced);
        assert_eq!(admit_creation(4_097), CreationAdmission::Reduced);
        assert_eq!(admit_creation(8_189), CreationAdmission::Reduced);
        assert_eq!(admit_creation(8_190), CreationAdmission::Refused);
        assert_eq!(admit_creation(8_193), CreationAdmission::Refused);
        assert_eq!(CreationAdmission::Full.ring_limit(), Some(16));
        assert_eq!(CreationAdmission::Reduced.ring_limit(), Some(2));
        assert_eq!(CreationAdmission::Refused.ring_limit(), None);
    }

    #[test]
    fn growth_at_the_target_and_one_past_it() {
        assert!(admit_growth(4_095));
        assert!(!admit_growth(4_096));
        assert!(!admit_growth(4_097));
    }

    fn ring(vault_id: &str, parts: usize) -> Ring {
        Ring {
            vault_id: vault_id.to_owned(),
            parts,
        }
    }

    #[test]
    fn trims_take_the_largest_rings_first_down_to_their_floor() {
        let rings = [ring("a", 16), ring("b", 16), ring("c", 3), ring("d", 2)];
        assert_eq!(plan_trims(4_096, &rings, 64, |_| true), vec![]);
        assert_eq!(
            plan_trims(4_100, &rings, 64, |_| true),
            vec![("a".to_owned(), 2), ("b".to_owned(), 2)],
            "largest first, ties by vault ID, alternating as they shrink"
        );
        let trims = plan_trims(4_200, &rings, 64, |_| true);
        assert_eq!(
            trims,
            vec![
                ("a".to_owned(), 14),
                ("b".to_owned(), 14),
                ("c".to_owned(), 1)
            ],
            "rings stop at 2 parts while past the target"
        );
        assert_eq!(
            plan_trims(4_200, &rings, 5, |_| true)
                .iter()
                .map(|(_, count)| count)
                .sum::<usize>(),
            5,
            "at most the given number per pass"
        );
        assert_eq!(
            plan_trims(4_100, &rings, 64, |vault_id| vault_id != "a"),
            vec![("b".to_owned(), 4)],
            "only projects the client may write"
        );
    }

    #[test]
    fn past_the_cap_rings_shrink_to_one_part_and_then_to_two() {
        let rings = [ring("a", 2), ring("b", 2), ring("c", 2)];
        assert_eq!(
            plan_trims(8_194, &rings, 64, |_| true),
            vec![("a".to_owned(), 1), ("b".to_owned(), 1)],
            "down to one part until the cap is met, then two is the floor"
        );
    }

    #[test]
    fn rings_count_parts_per_project_and_orphans_are_parts_the_head_doesnt_list() {
        let accounts = [
            crate::history::part_account("a", 0),
            crate::history::part_account("a", 1),
            crate::history::part_account("b", 4),
            crate::history::head_account("a"),
            crate::history::key_account("a"),
        ];
        assert_eq!(rings(&accounts), vec![ring("a", 2), ring("b", 1)]);
        let head = Head::new("a", 16);
        assert_eq!(
            orphan_parts(&head, &accounts),
            vec![crate::history::part_account("a", 1)]
        );
    }

    #[test]
    fn a_shrunk_ring_grows_again_only_well_below_the_target() {
        let mut head = Head::new("a", 2);
        head.parts = vec![0, 1];
        assert!(raise_limit(&head, REGROW_BELOW).is_none());
        assert_eq!(REGROW_BELOW, 3_584);
        let raised = raise_limit(&head, REGROW_BELOW - 1).expect("raised");
        let parsed = Head::parse(HISTORY, "a", &raised.bytes).expect("head");
        assert_eq!(parsed.ring_limit, 16);
        let trim = trim_oldest(&head).expect("trim");
        assert_eq!(trim.delete, crate::history::part_account("a", 0));
        assert_eq!(
            Head::parse(HISTORY, "a", &trim.head.bytes)
                .expect("head")
                .parts,
            vec![1]
        );
    }
}
