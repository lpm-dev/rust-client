//! What the marker says about history, and turning history off and on.
//!
//! "Off" is an entry of its own, `history-off`, with no records: clients
//! that don't know it read it as an unknown feature at `ignore`, allow
//! every operation, and keep it when they rewrite the marker.

use crate::account::CompanionAccount;
use crate::graph::{HISTORY, HISTORY_OFF};
use crate::history::{FEATURE, OFF_FEATURE, VERSION, off_entry};
use crate::lifecycle::{self, MarkerChange, Plan, Transaction, needs_resume};
use crate::marker::{FeatureState, Marker, ProjectState};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MarkerHistory {
    /// No history entry yet: on by default, created at the next change.
    Default,
    On,
    /// A removal of the history feature is running, finished before
    /// anything else.
    Removing,
    /// A newer version this client neither records nor reads.
    Unsupported {
        version: u16,
    },
    Off,
    /// Both on and off: history damage, repaired by removing history.
    Both,
}

impl MarkerHistory {
    pub fn of(marker: Option<&Marker>) -> Self {
        let Some(marker) = marker else {
            return Self::Default;
        };
        let off = marker.feature(OFF_FEATURE).is_some();
        match marker.feature(FEATURE) {
            Some(entry) if entry.state == FeatureState::Removing => Self::Removing,
            Some(_) if off => Self::Both,
            Some(entry) if entry.version == VERSION => Self::On,
            Some(entry) => Self::Unsupported {
                version: entry.version,
            },
            None if off => Self::Off,
            None => Self::Default,
        }
    }

    /// Whether a change may be recorded: on, or on by default.
    pub fn records(self) -> bool {
        matches!(self, Self::On | Self::Default)
    }
}

/// Plan turning history off for `marker`'s project, given a names-only
/// inventory of its records: delete the key unless another feature lists
/// it, the head and every history part, listed or not, and leave
/// `history-off` in the marker. One transaction when it fits; otherwise the
/// first marks history `removing` and adds `history-off`, so an
/// interruption still ends off. Turning off doesn't depend on history's
/// content, so it works when history is damaged or newer than this client.
pub fn plan_off(
    vault_id: &str,
    marker: Option<&Marker>,
    inventory: Vec<CompanionAccount>,
) -> Result<Plan, String> {
    if marker.is_some_and(needs_resume) {
        return Err("finish the env project's interrupted change first".to_owned());
    }
    let mut next = marker
        .cloned()
        .unwrap_or_else(|| Marker::empty(vault_id, ProjectState::Active));
    next.features
        .entry(OFF_FEATURE.to_owned())
        .or_insert_with(off_entry);
    let Some(entry) = next.features.get_mut(FEATURE) else {
        let transactions = if marker == Some(&next) {
            Vec::new()
        } else {
            vec![Transaction {
                changes: Vec::new(),
                marker: Some(MarkerChange::Write(next.clone())),
            }]
        };
        return Ok(Plan {
            vault_id: vault_id.to_owned(),
            transactions,
            result: Some(next),
        });
    };
    entry.state = FeatureState::Removing;
    let mut plan = lifecycle::plan_resume(next.clone(), inventory)?;
    if plan.transactions.len() > 1 {
        plan.transactions.insert(
            0,
            Transaction {
                changes: Vec::new(),
                marker: Some(MarkerChange::Write(next)),
            },
        );
    }
    Ok(plan)
}

/// Plan turning history back on: one transaction that removes
/// `history-off`, deleting the marker when nothing else is left. History
/// starts empty at the next change.
pub fn plan_on(marker: &Marker, inventory: &[CompanionAccount]) -> Result<Plan, String> {
    if needs_resume(marker) {
        return Err("finish the env project's interrupted change first".to_owned());
    }
    // Removing `history-off` would leave the old history's records live.
    if MarkerHistory::of(Some(marker)) == MarkerHistory::Both {
        return Err(
            "local history is damaged: it's both on and off. Repair it first: lpm env repair"
                .to_owned(),
        );
    }
    let mut next = marker.clone();
    if next.features.remove(OFF_FEATURE).is_none() {
        return Ok(Plan {
            vault_id: marker.vault_id.clone(),
            transactions: Vec::new(),
            result: Some(next),
        });
    }
    let leaves_records = inventory
        .iter()
        .any(|account| !matches!(account, CompanionAccount::Marker { .. }));
    let (change, result) = if next.features.is_empty() && !leaves_records {
        (MarkerChange::Delete, None)
    } else {
        (MarkerChange::Write(next.clone()), Some(next))
    };
    Ok(Plan {
        vault_id: marker.vault_id.clone(),
        transactions: vec![Transaction {
            changes: Vec::new(),
            marker: Some(change),
        }],
        result,
    })
}

const _: () = assert!(HISTORY.supported_versions[0] == VERSION);
const _: () = assert!(HISTORY_OFF.supported_versions[0] == 1);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lifecycle::PlannedChange;
    use crate::marker::{FeatureEntry, Level};

    fn history_marker(version: u16) -> Marker {
        let mut marker = Marker::empty("proj", ProjectState::Active);
        let mut entry = crate::history::feature_entry();
        entry.version = version;
        marker.features.insert(FEATURE.to_owned(), entry);
        marker
    }

    fn inventory(parts: u16) -> Vec<CompanionAccount> {
        let mut accounts = vec![
            crate::history::key_account("proj"),
            crate::history::head_account("proj"),
        ];
        accounts.extend((0..parts).map(|part| crate::history::part_account("proj", part)));
        accounts
    }

    #[test]
    fn the_marker_says_whether_history_is_on_off_newer_or_both() {
        assert_eq!(MarkerHistory::of(None), MarkerHistory::Default);
        let mut marker = history_marker(1);
        assert_eq!(MarkerHistory::of(Some(&marker)), MarkerHistory::On);
        assert!(MarkerHistory::of(Some(&marker)).records());
        assert_eq!(
            MarkerHistory::of(Some(&history_marker(2))),
            MarkerHistory::Unsupported { version: 2 }
        );
        marker.features.insert(OFF_FEATURE.to_owned(), off_entry());
        assert_eq!(MarkerHistory::of(Some(&marker)), MarkerHistory::Both);
        marker.features.remove(FEATURE);
        assert_eq!(MarkerHistory::of(Some(&marker)), MarkerHistory::Off);
        assert!(!MarkerHistory::Off.records());
    }

    #[test]
    fn turning_off_full_history_is_one_transaction_of_nineteen_operations() {
        let plan = plan_off("proj", Some(&history_marker(1)), inventory(16)).expect("plan");
        assert_eq!(plan.transactions.len(), 1);
        let transaction = &plan.transactions[0];
        assert_eq!(transaction.changes.len(), 18);
        assert!(
            transaction
                .changes
                .iter()
                .all(|change| matches!(change, PlannedChange::Delete(_)))
        );
        let Some(MarkerChange::Write(result)) = &transaction.marker else {
            panic!("the marker stays, with history off");
        };
        assert!(result.feature(OFF_FEATURE).is_some());
        assert!(result.feature(FEATURE).is_none());
        assert_eq!(plan.result.as_ref(), Some(result));
    }

    #[test]
    fn turning_off_keeps_a_key_another_feature_lists() {
        let mut marker = history_marker(1);
        marker.features.insert(
            "future".to_owned(),
            FeatureEntry {
                version: 1,
                if_unsupported: Level::Ignore,
                kinds: vec!["future-log".to_owned(), "key".to_owned()],
                state: FeatureState::Active,
            },
        );
        let plan = plan_off("proj", Some(&marker), inventory(2)).expect("plan");
        let deleted: Vec<&PlannedChange> = plan.transactions[0].changes.iter().collect();
        assert!(!deleted.contains(&&PlannedChange::Delete(crate::history::key_account("proj"))));
        assert_eq!(deleted.len(), 3);
    }

    #[test]
    fn turning_off_before_any_history_writes_only_the_entry_and_a_newer_history_batches() {
        let plan = plan_off("proj", None, Vec::new()).expect("plan");
        assert_eq!(plan.transactions.len(), 1);
        assert!(plan.transactions[0].changes.is_empty());
        let off = plan.result.expect("a marker");
        assert_eq!(MarkerHistory::of(Some(&off)), MarkerHistory::Off);
        assert!(
            plan_off("proj", Some(&off), Vec::new())
                .expect("plan")
                .transactions
                .is_empty(),
            "already off"
        );

        let mut many = inventory(0);
        many.extend((0..40).map(|part| crate::history::part_account("proj", part)));
        let plan = plan_off("proj", Some(&history_marker(2)), many).expect("plan");
        assert!(plan.transactions.len() > 1);
        let Some(MarkerChange::Write(first)) = &plan.transactions[0].marker else {
            panic!("the first transaction marks the removal");
        };
        assert_eq!(first.features[FEATURE].state, FeatureState::Removing);
        assert!(
            first.feature(OFF_FEATURE).is_some(),
            "off from the first transaction"
        );
        let result = plan.result.expect("a marker");
        assert_eq!(MarkerHistory::of(Some(&result)), MarkerHistory::Off);
    }

    #[test]
    fn turning_on_is_refused_while_history_is_both_on_and_off() {
        let mut both = history_marker(VERSION);
        both.features
            .insert(OFF_FEATURE.to_owned(), crate::history::off_entry());
        assert_eq!(MarkerHistory::of(Some(&both)), MarkerHistory::Both);
        let refused = plan_on(&both, &[crate::history::head_account("proj")]);
        assert!(
            refused
                .as_ref()
                .is_err_and(|error| error.contains("lpm env repair")),
            "{refused:?}"
        );
    }

    #[test]
    fn turning_on_removes_the_entry_and_the_marker_when_nothing_else_is_left() {
        let off = plan_off("proj", None, Vec::new())
            .expect("plan")
            .result
            .expect("marker");
        let plan = plan_on(&off, &[]).expect("plan");
        assert_eq!(plan.transactions[0].marker, Some(MarkerChange::Delete));
        assert_eq!(plan.result, None);

        let mut with_overrides = off;
        with_overrides.features.insert(
            "overrides".to_owned(),
            FeatureEntry {
                version: 1,
                if_unsupported: Level::Refuse,
                kinds: vec!["overrides".to_owned()],
                state: FeatureState::Active,
            },
        );
        let plan = plan_on(&with_overrides, &[]).expect("plan");
        let Some(MarkerChange::Write(result)) = &plan.transactions[0].marker else {
            panic!("the marker stays for overrides");
        };
        assert_eq!(MarkerHistory::of(Some(result)), MarkerHistory::Default);
    }
}
