//! Finishing what a deletion, a discard, a feature removal or a restore
//! started. Every step is content-agnostic: it moves and deletes opaque
//! records, so a client finishes what a later client began.
//!
//! Each step is one journaled transaction of at most
//! [`MAX_TRANSACTION_OPERATIONS`] operations and [`MAX_TRANSACTION_PAYLOAD_BYTES`]
//! of written bytes. The marker changes in the last transaction of a step,
//! so a crash leaves a state the next client resumes.

use std::collections::{BTreeSet, HashSet};

use super::account::CompanionAccount;
use super::graph::SHARED_KEY_KIND;
use super::marker::{FeatureState, Marker, ProjectState, RestorePhase};

pub(crate) const MAX_TRANSACTION_OPERATIONS: usize = 32;
pub(crate) const MAX_TRANSACTION_PAYLOAD_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Mutation {
    Write {
        account: CompanionAccount,
        value: Vec<u8>,
    },
    Delete {
        account: CompanionAccount,
    },
}

impl Mutation {
    fn payload_bytes(&self) -> usize {
        match self {
            Self::Write { value, .. } => value.len(),
            Self::Delete { .. } => 0,
        }
    }
}

/// The storage a resume runs against, inside the caller's lock.
pub(crate) trait LifecycleStore {
    fn read(&mut self, account: &CompanionAccount) -> Result<Option<Vec<u8>>, String>;
    /// Apply `mutations` as one crash-atomic transaction.
    fn commit(&mut self, mutations: Vec<Mutation>) -> Result<(), String>;
}

/// Whether `marker` describes work a client must finish before anything else.
pub(crate) fn needs_resume(marker: &Marker) -> bool {
    marker.state != ProjectState::Active
        || marker
            .features
            .values()
            .any(|entry| entry.state == FeatureState::Removing)
}

/// Finish every lifecycle step `marker` describes, given the project's
/// companion accounts from one names-only inventory. Returns the marker
/// left afterwards, or `None` when the marker is gone.
pub(crate) fn resume(
    store: &mut impl LifecycleStore,
    mut marker: Marker,
    mut inventory: Vec<CompanionAccount>,
) -> Result<Option<Marker>, String> {
    loop {
        match marker.state {
            ProjectState::Deleting | ProjectState::Discarding => {
                remove_everything(store, &marker, &inventory)?;
                return Ok(None);
            }
            ProjectState::Restoring => {
                let restore = marker.restore.clone().ok_or_else(|| {
                    "a restoring feature marker must describe the restore".to_owned()
                })?;
                let next = match restore.phase {
                    RestorePhase::Staging => roll_back_restore(store, &marker, &mut inventory)?,
                    RestorePhase::Activating => {
                        roll_forward_restore(store, &marker, &mut inventory)?
                    }
                };
                match next {
                    Some(next) => marker = next,
                    None => return Ok(None),
                }
            }
            ProjectState::Active => {
                let Some(name) = marker
                    .features
                    .iter()
                    .find(|(_, entry)| entry.state == FeatureState::Removing)
                    .map(|(name, _)| name.clone())
                else {
                    return Ok(Some(marker));
                };
                match remove_feature(store, &marker, &name, &mut inventory)? {
                    Some(next) => marker = next,
                    None => return Ok(None),
                }
            }
        }
    }
}

/// Deletes in key-first order: the shared key, then single records, then parts.
fn deletion_order(account: &CompanionAccount) -> (u8, Option<u16>) {
    let rank = match (account.kind(), account.part()) {
        (Some(SHARED_KEY_KIND), _) => 0,
        (_, None) => 1,
        (_, Some(_)) => 2,
    };
    (rank, account.part())
}

fn remove_everything(
    store: &mut impl LifecycleStore,
    marker: &Marker,
    inventory: &[CompanionAccount],
) -> Result<(), String> {
    let mut accounts: Vec<&CompanionAccount> = inventory.iter().collect();
    accounts.sort_by_key(|account| deletion_order(account));
    let mut batches = Batches::default();
    for account in accounts {
        batches.push(
            store,
            Mutation::Delete {
                account: account.clone(),
            },
        )?;
    }
    batches.finish(store, marker_delete(marker))
}

fn remove_feature(
    store: &mut impl LifecycleStore,
    marker: &Marker,
    name: &str,
    inventory: &mut Vec<CompanionAccount>,
) -> Result<Option<Marker>, String> {
    let entry = marker
        .features
        .get(name)
        .ok_or_else(|| format!("feature {name:?} isn't in the feature marker"))?;
    let still_listed: HashSet<&str> = marker
        .features
        .iter()
        .filter(|(other, _)| other.as_str() != name)
        .flat_map(|(_, other)| other.kinds.iter().map(String::as_str))
        .collect();
    let owned: HashSet<&str> = entry
        .kinds
        .iter()
        .map(String::as_str)
        .filter(|kind| !still_listed.contains(kind))
        .collect();
    let mut doomed: Vec<CompanionAccount> = inventory
        .iter()
        .filter(|account| {
            matches!(account, CompanionAccount::Record { kind, .. } if owned.contains(kind.as_str()))
        })
        .cloned()
        .collect();
    doomed.sort_by_key(deletion_order);

    let mut next = marker.clone();
    next.features.remove(name);
    let final_mutation = if next.features.is_empty() && inventory.len() == doomed.len() {
        marker_delete(marker)
    } else {
        marker_write(&next)?
    };
    let mut batches = Batches::default();
    for account in &doomed {
        batches.push(
            store,
            Mutation::Delete {
                account: account.clone(),
            },
        )?;
    }
    let removes_marker = matches!(final_mutation, Mutation::Delete { .. });
    batches.finish(store, final_mutation)?;
    let doomed: HashSet<CompanionAccount> = doomed.into_iter().collect();
    inventory.retain(|account| !doomed.contains(account));
    Ok((!removes_marker).then_some(next))
}

fn roll_back_restore(
    store: &mut impl LifecycleStore,
    marker: &Marker,
    inventory: &mut Vec<CompanionAccount>,
) -> Result<Option<Marker>, String> {
    let mut staged: Vec<CompanionAccount> = inventory
        .iter()
        .filter(|account| matches!(account, CompanionAccount::Staged { .. }))
        .cloned()
        .collect();
    staged.sort_by_key(deletion_order);
    let mut next = marker.clone();
    next.state = ProjectState::Active;
    next.restore = None;
    let leaves_records = inventory.len() > staged.len();
    let final_mutation = if next.features.is_empty() && !leaves_records {
        marker_delete(marker)
    } else {
        marker_write(&next)?
    };
    let mut batches = Batches::default();
    for account in &staged {
        batches.push(
            store,
            Mutation::Delete {
                account: account.clone(),
            },
        )?;
    }
    let removes_marker = matches!(final_mutation, Mutation::Delete { .. });
    batches.finish(store, final_mutation)?;
    inventory.retain(|account| !matches!(account, CompanionAccount::Staged { .. }));
    Ok((!removes_marker).then_some(next))
}

/// Activate a restore in two steps a resume can tell apart. First the live
/// records of replaced features that no staged record replaces are deleted;
/// the transaction that finishes this drops the replaced features from the
/// marker and empties `replaces`. Then each staged record moves to its live
/// account, and the last move writes the post-state marker. Splitting the
/// steps matters: once moves begin, a moved record can't be told from a
/// stale one by looking at the records alone.
fn roll_forward_restore(
    store: &mut impl LifecycleStore,
    marker: &Marker,
    inventory: &mut Vec<CompanionAccount>,
) -> Result<Option<Marker>, String> {
    let mut marker = marker.clone();
    if marker
        .restore
        .as_ref()
        .is_some_and(|restore| !restore.replaces.is_empty())
    {
        marker = remove_replaced_records(store, &marker, inventory)?;
    }
    move_staged_records(store, &marker, inventory)
}

fn remove_replaced_records(
    store: &mut impl LifecycleStore,
    marker: &Marker,
    inventory: &mut Vec<CompanionAccount>,
) -> Result<Marker, String> {
    let restore = marker
        .restore
        .as_ref()
        .ok_or_else(|| "a restoring feature marker must describe the restore".to_owned())?;
    let replaced: BTreeSet<&str> = restore.replaces.iter().map(String::as_str).collect();
    let kept_kinds: HashSet<&str> = marker
        .features
        .iter()
        .filter(|(name, _)| !replaced.contains(name.as_str()))
        .flat_map(|(_, entry)| entry.kinds.iter().map(String::as_str))
        .collect();
    let replaced_kinds: HashSet<&str> = marker
        .features
        .iter()
        .filter(|(name, _)| replaced.contains(name.as_str()))
        .flat_map(|(_, entry)| entry.kinds.iter().map(String::as_str))
        .filter(|kind| !kept_kinds.contains(kind))
        .collect();
    let incoming: HashSet<CompanionAccount> = inventory
        .iter()
        .filter_map(CompanionAccount::activated)
        .collect();
    let mut stale: Vec<CompanionAccount> = inventory
        .iter()
        .filter(|account| match account {
            CompanionAccount::Record { kind, .. } => {
                replaced_kinds.contains(kind.as_str()) && !incoming.contains(account)
            }
            CompanionAccount::Marker { .. } | CompanionAccount::Staged { .. } => false,
        })
        .cloned()
        .collect();
    stale.sort_by_key(deletion_order);

    let mut next = marker.clone();
    for name in &replaced {
        next.features.remove(*name);
    }
    if let Some(restore) = next.restore.as_mut() {
        restore.replaces.clear();
    }
    let mut batches = Batches::default();
    for account in &stale {
        batches.push(
            store,
            Mutation::Delete {
                account: account.clone(),
            },
        )?;
    }
    batches.finish(store, marker_write(&next)?)?;
    let stale: HashSet<CompanionAccount> = stale.into_iter().collect();
    inventory.retain(|account| !stale.contains(account));
    Ok(next)
}

fn move_staged_records(
    store: &mut impl LifecycleStore,
    marker: &Marker,
    inventory: &mut Vec<CompanionAccount>,
) -> Result<Option<Marker>, String> {
    let restore = marker
        .restore
        .as_ref()
        .ok_or_else(|| "a restoring feature marker must describe the restore".to_owned())?;
    let mut staged: Vec<CompanionAccount> = inventory
        .iter()
        .filter(|account| matches!(account, CompanionAccount::Staged { .. }))
        .cloned()
        .collect();
    staged.sort_by_key(deletion_order);

    let mut next = marker.clone();
    next.features = marker.post_restore_features(restore);
    next.state = ProjectState::Active;
    next.restore = None;
    let final_mutation = marker_write(&next)?;

    let mut batches = Batches::default();
    let mut moved = Vec::with_capacity(staged.len());
    for account in &staged {
        let value = store
            .read(account)?
            .ok_or_else(|| "a restore lost a staged record before it was activated".to_owned())?;
        let live = account
            .activated()
            .ok_or_else(|| "a staged record has no live account".to_owned())?;
        batches.push_pair(
            store,
            Mutation::Write {
                account: live.clone(),
                value,
            },
            Mutation::Delete {
                account: account.clone(),
            },
        )?;
        moved.push(live);
    }
    batches.finish(store, final_mutation)?;

    inventory.retain(|account| !matches!(account, CompanionAccount::Staged { .. }));
    for live in moved {
        if !inventory.contains(&live) {
            inventory.push(live);
        }
    }
    Ok(Some(next))
}

fn marker_write(marker: &Marker) -> Result<Mutation, String> {
    Ok(Mutation::Write {
        account: CompanionAccount::Marker {
            vault_id: marker.vault_id.clone(),
        },
        value: marker.encode().map_err(|error| error.to_string())?,
    })
}

fn marker_delete(marker: &Marker) -> Mutation {
    Mutation::Delete {
        account: CompanionAccount::Marker {
            vault_id: marker.vault_id.clone(),
        },
    }
}

/// Mutations grouped into transactions within the operation and byte limits.
#[derive(Default)]
struct Batches {
    pending: Vec<Mutation>,
    payload: usize,
}

impl Batches {
    fn fits(&self, operations: usize, payload: usize) -> bool {
        self.pending.len() + operations <= MAX_TRANSACTION_OPERATIONS
            && self.payload + payload <= MAX_TRANSACTION_PAYLOAD_BYTES
    }

    fn flush(&mut self, store: &mut impl LifecycleStore) -> Result<(), String> {
        if self.pending.is_empty() {
            return Ok(());
        }
        self.payload = 0;
        store.commit(std::mem::take(&mut self.pending))
    }

    fn push(&mut self, store: &mut impl LifecycleStore, mutation: Mutation) -> Result<(), String> {
        let payload = mutation.payload_bytes();
        if !self.fits(1, payload) {
            self.flush(store)?;
        }
        self.payload += payload;
        self.pending.push(mutation);
        Ok(())
    }

    /// Two mutations that belong in the same transaction, such as writing a
    /// live record and deleting the staged record it came from.
    fn push_pair(
        &mut self,
        store: &mut impl LifecycleStore,
        first: Mutation,
        second: Mutation,
    ) -> Result<(), String> {
        let payload = first.payload_bytes() + second.payload_bytes();
        if !self.fits(2, payload) {
            self.flush(store)?;
        }
        self.payload += payload;
        self.pending.push(first);
        self.pending.push(second);
        Ok(())
    }

    /// Commit what's left with the marker's change, in one last transaction.
    fn finish(mut self, store: &mut impl LifecycleStore, marker: Mutation) -> Result<(), String> {
        let payload = marker.payload_bytes();
        if !self.fits(1, payload) {
            self.flush(store)?;
        }
        self.pending.push(marker);
        store.commit(self.pending)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::collections::BTreeMap;

    use super::super::marker::{FeatureEntry, Level, Restore};
    use super::*;

    /// Committed records, and how many more commits succeed before a crash.
    #[derive(Default)]
    pub(crate) struct MemoryStore {
        pub(crate) records: BTreeMap<CompanionAccount, Vec<u8>>,
        pub(crate) commits: usize,
        pub(crate) crash_after: Option<usize>,
        pub(crate) largest_transaction: usize,
    }

    impl LifecycleStore for MemoryStore {
        fn read(&mut self, account: &CompanionAccount) -> Result<Option<Vec<u8>>, String> {
            Ok(self.records.get(account).cloned())
        }

        fn commit(&mut self, mutations: Vec<Mutation>) -> Result<(), String> {
            if self.crash_after == Some(self.commits) {
                return Err("simulated crash".to_owned());
            }
            assert!(mutations.len() <= MAX_TRANSACTION_OPERATIONS);
            assert!(
                mutations.iter().map(Mutation::payload_bytes).sum::<usize>()
                    <= MAX_TRANSACTION_PAYLOAD_BYTES
            );
            self.largest_transaction = self.largest_transaction.max(mutations.len());
            for mutation in mutations {
                match mutation {
                    Mutation::Write { account, value } => {
                        self.records.insert(account, value);
                    }
                    Mutation::Delete { account } => {
                        self.records.remove(&account);
                    }
                }
            }
            self.commits += 1;
            Ok(())
        }
    }

    impl MemoryStore {
        fn marker(&self) -> Option<Marker> {
            let account = CompanionAccount::Marker {
                vault_id: "proj".to_owned(),
            };
            self.records
                .get(&account)
                .map(|bytes| Marker::parse("proj", bytes).expect("stored markers stay valid"))
        }

        fn inventory(&self) -> Vec<CompanionAccount> {
            self.records
                .keys()
                .filter(|account| !matches!(account, CompanionAccount::Marker { .. }))
                .cloned()
                .collect()
        }

        fn store_marker(&mut self, marker: &Marker) {
            self.records.insert(
                CompanionAccount::Marker {
                    vault_id: "proj".to_owned(),
                },
                marker.encode().expect("valid marker"),
            );
        }

        /// Resume until done, crashing after every commit once, the way a
        /// sequence of interrupted clients would.
        fn resume_through_crashes(&mut self) -> Option<Marker> {
            let mut crash_point = self.commits;
            loop {
                let marker = self.marker()?;
                if !needs_resume(&marker) {
                    return Some(marker);
                }
                self.crash_after = Some(crash_point);
                let inventory = self.inventory();
                match resume(self, marker, inventory) {
                    Ok(result) => {
                        self.crash_after = None;
                        return result;
                    }
                    Err(_) => crash_point = self.commits + 1,
                }
            }
        }
    }

    fn record(kind: &str, part: Option<u16>) -> CompanionAccount {
        CompanionAccount::Record {
            kind: kind.to_owned(),
            vault_id: "proj".to_owned(),
            part,
        }
    }

    fn staged(kind: &str, part: Option<u16>) -> CompanionAccount {
        CompanionAccount::Staged {
            kind: kind.to_owned(),
            vault_id: "proj".to_owned(),
            part,
        }
    }

    fn entry(kinds: &[&str], state: FeatureState) -> FeatureEntry {
        FeatureEntry {
            version: 1,
            if_unsupported: Level::Ignore,
            kinds: kinds.iter().map(|kind| (*kind).to_owned()).collect(),
            state,
        }
    }

    fn history_store(parts: u16) -> MemoryStore {
        let mut store = MemoryStore::default();
        let mut marker = Marker::empty("proj", ProjectState::Active);
        marker.features.insert(
            "history".to_owned(),
            entry(&["history-head", "history", "key"], FeatureState::Active),
        );
        marker.features.insert(
            "releases".to_owned(),
            entry(&["releases-head", "releases", "key"], FeatureState::Active),
        );
        marker.features.insert(
            "overrides".to_owned(),
            entry(&["overrides"], FeatureState::Active),
        );
        store.store_marker(&marker);
        store
            .records
            .insert(record("key", None), b"old-key".to_vec());
        store
            .records
            .insert(record("history-head", None), b"head".to_vec());
        store
            .records
            .insert(record("releases-head", None), b"head".to_vec());
        store
            .records
            .insert(record("overrides", None), b"mine".to_vec());
        for part in 0..parts {
            store
                .records
                .insert(record("history", Some(part)), vec![b'h'; 90 * 1024]);
            store
                .records
                .insert(record("releases", Some(part % 8)), b"r".to_vec());
        }
        store
    }

    #[test]
    fn a_deletion_interrupted_after_any_commit_ends_with_nothing_left() {
        for crash in 0..4 {
            let mut store = history_store(16);
            let mut marker = store.marker().expect("marker");
            marker.state = ProjectState::Deleting;
            store.store_marker(&marker);
            store.crash_after = Some(crash);
            let inventory = store.inventory();
            let _ = resume(&mut store, marker, inventory);
            store.crash_after = None;
            assert_eq!(store.resume_through_crashes(), None, "crash {crash}");
            assert!(store.records.is_empty(), "crash {crash}");
        }
    }

    #[test]
    fn deletion_removes_the_shared_key_in_its_first_transaction() {
        struct FirstCommit(MemoryStore, Option<Vec<Mutation>>);
        impl LifecycleStore for FirstCommit {
            fn read(&mut self, account: &CompanionAccount) -> Result<Option<Vec<u8>>, String> {
                self.0.read(account)
            }
            fn commit(&mut self, mutations: Vec<Mutation>) -> Result<(), String> {
                if self.1.is_none() {
                    self.1 = Some(mutations.clone());
                }
                self.0.commit(mutations)
            }
        }
        let mut store = history_store(16);
        let mut marker = store.marker().expect("marker");
        marker.state = ProjectState::Deleting;
        let inventory = store.inventory();
        let mut first = FirstCommit(std::mem::take(&mut store), None);
        resume(&mut first, marker, inventory).expect("deletion finishes");
        let first_batch = first.1.expect("a first transaction");
        assert_eq!(
            first_batch.first(),
            Some(&Mutation::Delete {
                account: record("key", None)
            })
        );
    }

    #[test]
    fn removing_a_feature_keeps_the_key_another_feature_lists() {
        let mut store = history_store(4);
        let mut marker = store.marker().expect("marker");
        marker.features.get_mut("history").unwrap().state = FeatureState::Removing;
        store.store_marker(&marker);
        let result = store.resume_through_crashes().expect("marker remains");
        assert!(!result.features.contains_key("history"));
        assert!(store.records.contains_key(&record("key", None)));
        assert!(!store.records.contains_key(&record("history-head", None)));
        assert!(
            !store
                .records
                .keys()
                .any(|account| account.kind() == Some("history"))
        );
        assert!(store.records.contains_key(&record("releases-head", None)));
    }

    #[test]
    fn removing_the_last_feature_removes_the_marker_with_its_records() {
        let mut store = MemoryStore::default();
        let mut marker = Marker::empty("proj", ProjectState::Active);
        marker.features.insert(
            "overrides".to_owned(),
            entry(&["overrides"], FeatureState::Removing),
        );
        store.store_marker(&marker);
        store
            .records
            .insert(record("overrides", None), b"x".to_vec());
        assert_eq!(store.resume_through_crashes(), None);
        assert!(store.records.is_empty());
    }

    fn restoring_store(phase: RestorePhase) -> (MemoryStore, BTreeMap<CompanionAccount, Vec<u8>>) {
        let mut store = history_store(16);
        let before = store.records.clone();
        let mut marker = store.marker().expect("marker");
        marker.state = ProjectState::Restoring;
        marker.restore = Some(Restore {
            phase,
            replaces: vec![
                "history".to_owned(),
                "releases".to_owned(),
                "overrides".to_owned(),
            ],
            features: [
                (
                    "history".to_owned(),
                    entry(&["history-head", "history", "key"], FeatureState::Active),
                ),
                (
                    "overrides".to_owned(),
                    entry(&["overrides"], FeatureState::Active),
                ),
            ]
            .into(),
        });
        store.store_marker(&marker);
        store
            .records
            .insert(staged("key", None), b"new-key".to_vec());
        store
            .records
            .insert(staged("history-head", None), b"new-head".to_vec());
        store
            .records
            .insert(staged("overrides", None), b"theirs".to_vec());
        for part in 0..3 {
            store
                .records
                .insert(staged("history", Some(part)), vec![b'n'; 100 * 1024]);
        }
        (store, before)
    }

    #[test]
    fn an_interrupted_staging_rolls_back_to_exactly_the_records_before_it() {
        for crash in 0..3 {
            let (mut store, before) = restoring_store(RestorePhase::Staging);
            store.crash_after = Some(crash);
            let marker = store.marker().expect("marker");
            let inventory = store.inventory();
            let _ = resume(&mut store, marker, inventory);
            store.crash_after = None;
            let result = store.resume_through_crashes().expect("marker remains");
            assert_eq!(result.state, ProjectState::Active);
            assert!(result.restore.is_none());
            let mut expected = before.clone();
            expected.insert(
                CompanionAccount::Marker {
                    vault_id: "proj".to_owned(),
                },
                result.encode().unwrap(),
            );
            assert_eq!(store.records, expected, "crash {crash}");
        }
    }

    #[test]
    fn an_interrupted_activation_finishes_exactly_the_reviewed_post_state() {
        for crash in 0..6 {
            let (mut store, _) = restoring_store(RestorePhase::Activating);
            store.crash_after = Some(crash);
            let marker = store.marker().expect("marker");
            let inventory = store.inventory();
            let _ = resume(&mut store, marker, inventory);
            store.crash_after = None;
            let result = store.resume_through_crashes().expect("marker remains");
            assert_eq!(result.state, ProjectState::Active);
            assert_eq!(
                result.features.keys().collect::<Vec<_>>(),
                ["history", "overrides"]
            );
            let accounts: Vec<_> = store.records.keys().cloned().collect();
            let mut expected = vec![
                CompanionAccount::Marker {
                    vault_id: "proj".to_owned(),
                },
                record("history", Some(0)),
                record("history", Some(1)),
                record("history", Some(2)),
                record("history-head", None),
                record("key", None),
                record("overrides", None),
            ];
            expected.sort();
            assert_eq!(accounts, expected, "crash {crash}");
            assert_eq!(store.records[&record("key", None)], b"new-key");
            assert_eq!(store.records[&record("overrides", None)], b"theirs");
            assert_eq!(
                store.records[&record("history", Some(2))],
                vec![b'n'; 100 * 1024]
            );
        }
    }

    #[test]
    fn large_activations_split_by_bytes_and_operations() {
        let (mut store, _) = restoring_store(RestorePhase::Activating);
        for part in 3..16 {
            store
                .records
                .insert(staged("history", Some(part)), vec![b'n'; 100 * 1024]);
        }
        let marker = store.marker().expect("marker");
        let inventory = store.inventory();
        resume(&mut store, marker, inventory).expect("activation finishes");
        assert!(store.commits >= 2);
        assert!(store.largest_transaction <= MAX_TRANSACTION_OPERATIONS);
    }
}
