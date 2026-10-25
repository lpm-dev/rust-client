//! Finishing what a deletion, a discard, a feature removal or a restore
//! started, as a plan of transactions each client commits to its own
//! storage. Planning is content-agnostic: it deletes records and moves
//! staged records to their live accounts, so a client finishes what a later
//! client began.
//!
//! A step's marker change is in its last transaction, so a crash between
//! transactions leaves a state the next client plans again. Every
//! transaction stays within [`MAX_TRANSACTION_OPERATIONS`] operations and
//! [`MAX_TRANSACTION_PAYLOAD_BYTES`] of written bytes, counting a move as
//! the largest record a store accepts, since a names-only inventory doesn't
//! say how large a record is.

use std::collections::{BTreeSet, HashSet};

use crate::account::CompanionAccount;
use crate::graph::SHARED_KEY_KIND;
use crate::invariants::is_listed;
use crate::marker::{FeatureState, MAX_RECORD_BYTES, Marker, ProjectState, RestorePhase};

pub const MAX_TRANSACTION_OPERATIONS: usize = 32;
pub const MAX_TRANSACTION_PAYLOAD_BYTES: usize = 1024 * 1024;

/// A change one transaction makes to a store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mutation {
    Write {
        account: CompanionAccount,
        value: Vec<u8>,
    },
    Delete {
        account: CompanionAccount,
    },
}

impl Mutation {
    pub fn payload_bytes(&self) -> usize {
        match self {
            Self::Write { value, .. } => value.len(),
            Self::Delete { .. } => 0,
        }
    }
}

/// The storage a plan runs against, inside the caller's lock.
pub trait LifecycleStore {
    fn read(&mut self, account: &CompanionAccount) -> Result<Option<Vec<u8>>, String>;
    /// Apply `mutations` as one crash-atomic transaction.
    fn commit(&mut self, mutations: Vec<Mutation>) -> Result<(), String>;
}

/// One change a planned transaction makes besides the marker's.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum PlannedChange {
    /// Delete a companion or staged record.
    Delete(CompanionAccount),
    /// Write a staged record's bytes to its live account and delete the
    /// staged record, in the same transaction.
    Move {
        staged: CompanionAccount,
        live: CompanionAccount,
    },
}

impl PlannedChange {
    fn operations(&self) -> usize {
        match self {
            Self::Delete(_) => 1,
            Self::Move { .. } => 2,
        }
    }

    fn payload_bound(&self) -> usize {
        match self {
            Self::Delete(_) => 0,
            Self::Move { .. } => MAX_RECORD_BYTES,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MarkerChange {
    Write(Marker),
    Delete,
}

/// One crash-atomic transaction: its changes, then the marker's change, if
/// it ends a step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transaction {
    pub changes: Vec<PlannedChange>,
    pub marker: Option<MarkerChange>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    pub vault_id: String,
    pub transactions: Vec<Transaction>,
    /// The marker the project is left with, or `None` when it's gone.
    pub result: Option<Marker>,
}

/// Whether `marker` describes work a client must finish before anything else.
pub fn needs_resume(marker: &Marker) -> bool {
    marker.state != ProjectState::Active
        || marker
            .features
            .values()
            .any(|entry| entry.state == FeatureState::Removing)
}

/// Every transaction that finishes the lifecycle work `marker` describes,
/// given the project's companion and staged records from one names-only
/// inventory.
pub fn plan_resume(
    mut marker: Marker,
    mut inventory: Vec<CompanionAccount>,
) -> Result<Plan, String> {
    let mut plan = Plan {
        vault_id: marker.vault_id.clone(),
        transactions: Vec::new(),
        result: None,
    };
    loop {
        let step = match marker.state {
            ProjectState::Deleting | ProjectState::Discarding => remove_everything(&inventory),
            ProjectState::Restoring => {
                let phase = marker
                    .restore
                    .as_ref()
                    .map(|restore| restore.phase)
                    .ok_or_else(|| {
                        "a restoring feature marker must describe the restore".to_owned()
                    })?;
                let replaces_features = marker
                    .restore
                    .as_ref()
                    .is_some_and(|restore| !restore.replaces.is_empty());
                match phase {
                    RestorePhase::Staging => roll_back_restore(&marker, &mut inventory),
                    RestorePhase::Activating if replaces_features => {
                        remove_replaced_records(&marker, &mut inventory)?
                    }
                    RestorePhase::Activating => move_staged_records(&marker, &mut inventory)?,
                }
            }
            ProjectState::Active => {
                let Some(name) = marker
                    .features
                    .iter()
                    .find(|(_, entry)| entry.state == FeatureState::Removing)
                    .map(|(name, _)| name.clone())
                else {
                    plan.result = Some(marker);
                    return Ok(plan);
                };
                remove_feature(&marker, &name, &mut inventory)?
            }
        };
        let next = match &step.marker {
            MarkerChange::Write(next) => Some(next.clone()),
            MarkerChange::Delete => None,
        };
        pack(step, &mut plan.transactions)?;
        match next {
            Some(next) => marker = next,
            None => return Ok(plan),
        }
    }
}

/// Commit every transaction of `plan`, reading each staged record a move
/// needs just before its transaction, and return the marker it leaves.
pub fn execute(store: &mut impl LifecycleStore, plan: Plan) -> Result<Option<Marker>, String> {
    let marker_account = CompanionAccount::Marker {
        vault_id: plan.vault_id,
    };
    for transaction in plan.transactions {
        let mut mutations = Vec::with_capacity(
            transaction
                .changes
                .iter()
                .map(PlannedChange::operations)
                .sum::<usize>()
                + 1,
        );
        for change in transaction.changes {
            match change {
                PlannedChange::Delete(account) => mutations.push(Mutation::Delete { account }),
                PlannedChange::Move { staged, live } => {
                    let value = store.read(&staged)?.ok_or_else(|| {
                        "a restore lost a staged record before it was activated".to_owned()
                    })?;
                    mutations.push(Mutation::Write {
                        account: live,
                        value,
                    });
                    mutations.push(Mutation::Delete { account: staged });
                }
            }
        }
        match transaction.marker {
            Some(MarkerChange::Write(marker)) => mutations.push(Mutation::Write {
                account: marker_account.clone(),
                value: marker.encode().map_err(|error| error.to_string())?,
            }),
            Some(MarkerChange::Delete) => mutations.push(Mutation::Delete {
                account: marker_account.clone(),
            }),
            None => {}
        }
        store.commit(mutations)?;
    }
    Ok(plan.result)
}

/// [`plan_resume`], then [`execute`].
pub fn resume(
    store: &mut impl LifecycleStore,
    marker: Marker,
    inventory: Vec<CompanionAccount>,
) -> Result<Option<Marker>, String> {
    execute(store, plan_resume(marker, inventory)?)
}

/// What a client found at a project's marker account.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FoundMarker<'marker> {
    Absent,
    Invalid,
    Valid(&'marker Marker),
}

/// Plan deleting `vault_id`'s companion records with its project, given a
/// names-only inventory taken after any resume. The first transaction
/// leaves room for `own_operations` of the client's own, which it commits
/// with it: deleting the values item and the project's metadata. It deletes
/// the shared key first, then as many single records as fit, and then
/// either deletes the marker, when nothing is left, or writes a `deleting`
/// marker that later transactions finish.
pub fn plan_deletion(
    vault_id: &str,
    found: FoundMarker<'_>,
    inventory: Vec<CompanionAccount>,
    own_operations: usize,
) -> Result<Plan, String> {
    plan_removal(
        ProjectState::Deleting,
        vault_id,
        found,
        inventory,
        own_operations,
    )
}

/// Plan discarding a damaged project's companion data, project-wide, as a
/// project whose marker is invalid or whose records have no marker needs.
/// The values item stays.
pub fn plan_discard(
    vault_id: &str,
    found: FoundMarker<'_>,
    inventory: Vec<CompanionAccount>,
) -> Result<Plan, String> {
    plan_removal(ProjectState::Discarding, vault_id, found, inventory, 0)
}

/// Plan removing `feature` and the records only it lists, as discarding a
/// damaged feature of a valid marker does. More than one transaction first
/// marks the feature `removing`, so an interruption finishes the removal.
pub fn plan_feature_removal(
    marker: &Marker,
    feature: &str,
    inventory: Vec<CompanionAccount>,
) -> Result<Plan, String> {
    if needs_resume(marker) {
        return Err("finish the env project's interrupted change first".to_owned());
    }
    let mut removing = marker.clone();
    removing
        .features
        .get_mut(feature)
        .ok_or_else(|| format!("feature {feature:?} isn't in the feature marker"))?
        .state = FeatureState::Removing;
    let mut plan = plan_resume(removing.clone(), inventory)?;
    if plan.transactions.len() > 1 {
        plan.transactions.insert(
            0,
            Transaction {
                changes: Vec::new(),
                marker: Some(MarkerChange::Write(removing)),
            },
        );
    }
    Ok(plan)
}

/// Plan deleting the records of `marker`'s project that no feature lists, as
/// repairing that damage does. The marker stays as it is.
pub fn plan_unlisted_removal(
    marker: &Marker,
    inventory: Vec<CompanionAccount>,
) -> Result<Plan, String> {
    if needs_resume(marker) {
        return Err("finish the env project's interrupted change first".to_owned());
    }
    let unlisted = inventory
        .into_iter()
        .filter(|account| !is_listed(Some(marker), account))
        .collect();
    let mut plan = Plan {
        vault_id: marker.vault_id.clone(),
        transactions: Vec::new(),
        result: Some(marker.clone()),
    };
    pack_changes(deletions(unlisted), None, &mut plan.transactions)?;
    Ok(plan)
}

/// A deletion or a discard. A `deleting` or `discarding` marker covers every
/// record of its project, listed or not, since none is read for its content
/// again, so it keeps the current marker's features as they are.
fn plan_removal(
    state: ProjectState,
    vault_id: &str,
    found: FoundMarker<'_>,
    mut inventory: Vec<CompanionAccount>,
    own_operations: usize,
) -> Result<Plan, String> {
    inventory.sort_by_key(deletion_order);
    let room = MAX_TRANSACTION_OPERATIONS.saturating_sub(own_operations + 1);
    let first = inventory
        .iter()
        .take_while(|account| account.part().is_none())
        .take(room)
        .count();
    let rest = inventory.split_off(first);
    let first: Vec<PlannedChange> = inventory.into_iter().map(PlannedChange::Delete).collect();
    if rest.is_empty() {
        let marker = (found != FoundMarker::Absent).then_some(MarkerChange::Delete);
        return Ok(Plan {
            vault_id: vault_id.to_owned(),
            transactions: if marker.is_none() && first.is_empty() {
                Vec::new()
            } else {
                vec![Transaction {
                    changes: first,
                    marker,
                }]
            },
            result: None,
        });
    }
    let mut marker = match found {
        FoundMarker::Valid(current) => current.clone(),
        FoundMarker::Absent | FoundMarker::Invalid => Marker::empty(vault_id, state),
    };
    marker.state = state;
    marker.restore = None;
    let mut plan = plan_resume(marker.clone(), rest)?;
    plan.transactions.insert(
        0,
        Transaction {
            changes: first,
            marker: Some(MarkerChange::Write(marker)),
        },
    );
    Ok(plan)
}

/// One lifecycle step before it's split into transactions: its changes,
/// then the marker change that ends it.
struct Step {
    changes: Vec<PlannedChange>,
    marker: MarkerChange,
}

/// Split `step` into transactions within the limits, the marker's change in
/// the last.
fn pack(step: Step, transactions: &mut Vec<Transaction>) -> Result<(), String> {
    pack_changes(step.changes, Some(step.marker), transactions)
}

/// Split `changes` into transactions within the limits, with `marker`'s
/// change, if any, in the last.
fn pack_changes(
    changes: Vec<PlannedChange>,
    marker: Option<MarkerChange>,
    transactions: &mut Vec<Transaction>,
) -> Result<(), String> {
    let (marker_operations, marker_bytes) = match &marker {
        Some(MarkerChange::Write(marker)) => {
            (1, marker.encode().map_err(|error| error.to_string())?.len())
        }
        Some(MarkerChange::Delete) => (1, 0),
        None => (0, 0),
    };
    let mut current = Vec::new();
    let (mut operations, mut payload) = (0, 0);
    for change in changes {
        let (more_operations, more_payload) = (change.operations(), change.payload_bound());
        if !current.is_empty()
            && (operations + more_operations > MAX_TRANSACTION_OPERATIONS
                || payload + more_payload > MAX_TRANSACTION_PAYLOAD_BYTES)
        {
            transactions.push(Transaction {
                changes: std::mem::take(&mut current),
                marker: None,
            });
            (operations, payload) = (0, 0);
        }
        operations += more_operations;
        payload += more_payload;
        current.push(change);
    }
    if !current.is_empty()
        && (operations + marker_operations > MAX_TRANSACTION_OPERATIONS
            || payload + marker_bytes > MAX_TRANSACTION_PAYLOAD_BYTES)
    {
        transactions.push(Transaction {
            changes: std::mem::take(&mut current),
            marker: None,
        });
    }
    if !current.is_empty() || marker.is_some() {
        transactions.push(Transaction {
            changes: current,
            marker,
        });
    }
    Ok(())
}

/// Deletions in key-first order: the shared key, then single records, then parts.
fn deletion_order(account: &CompanionAccount) -> (u8, Option<u16>) {
    let rank = match (account.kind(), account.part()) {
        (Some(SHARED_KEY_KIND), _) => 0,
        (_, None) => 1,
        (_, Some(_)) => 2,
    };
    (rank, account.part())
}

fn deletions(mut accounts: Vec<CompanionAccount>) -> Vec<PlannedChange> {
    accounts.sort_by_key(deletion_order);
    accounts.into_iter().map(PlannedChange::Delete).collect()
}

/// A step that removes the marker when it leaves no feature and no record,
/// and otherwise writes `next`.
fn ending(next: Marker, leaves_records: bool) -> MarkerChange {
    if next.features.is_empty() && !leaves_records {
        MarkerChange::Delete
    } else {
        MarkerChange::Write(next)
    }
}

fn remove_everything(inventory: &[CompanionAccount]) -> Step {
    Step {
        changes: deletions(inventory.to_vec()),
        marker: MarkerChange::Delete,
    }
}

fn remove_feature(
    marker: &Marker,
    name: &str,
    inventory: &mut Vec<CompanionAccount>,
) -> Result<Step, String> {
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
    let (doomed, kept): (Vec<CompanionAccount>, Vec<CompanionAccount>) =
        std::mem::take(inventory).into_iter().partition(|account| {
            matches!(account, CompanionAccount::Record { kind, .. } if owned.contains(kind.as_str()))
        });
    *inventory = kept;
    let mut next = marker.clone();
    next.features.remove(name);
    Ok(Step {
        changes: deletions(doomed),
        marker: ending(next, !inventory.is_empty()),
    })
}

fn roll_back_restore(marker: &Marker, inventory: &mut Vec<CompanionAccount>) -> Step {
    let (staged, kept): (Vec<CompanionAccount>, Vec<CompanionAccount>) = std::mem::take(inventory)
        .into_iter()
        .partition(|account| matches!(account, CompanionAccount::Staged { .. }));
    *inventory = kept;
    let mut next = marker.clone();
    next.state = ProjectState::Active;
    next.restore = None;
    Step {
        changes: deletions(staged),
        marker: ending(next, !inventory.is_empty()),
    }
}

/// The first activation step: delete the live records of replaced features
/// that no staged record replaces, and drop the replaced features from the
/// marker with `replaces` emptied. Once moves begin, a moved record can't be
/// told from a stale one by the records alone, so the steps stay apart.
fn remove_replaced_records(
    marker: &Marker,
    inventory: &mut Vec<CompanionAccount>,
) -> Result<Step, String> {
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
    let (stale, kept): (Vec<CompanionAccount>, Vec<CompanionAccount>) =
        std::mem::take(inventory).into_iter().partition(|account| {
            matches!(account, CompanionAccount::Record { kind, .. } if replaced_kinds.contains(kind.as_str()))
                && !incoming.contains(account)
        });
    *inventory = kept;
    let mut next = marker.clone();
    for name in &replaced {
        next.features.remove(*name);
    }
    if let Some(restore) = next.restore.as_mut() {
        restore.replaces.clear();
    }
    Ok(Step {
        changes: deletions(stale),
        marker: MarkerChange::Write(next),
    })
}

/// The second activation step: move every staged record to its live
/// account, `key` first, and write the post-state marker.
fn move_staged_records(
    marker: &Marker,
    inventory: &mut Vec<CompanionAccount>,
) -> Result<Step, String> {
    let restore = marker
        .restore
        .as_ref()
        .ok_or_else(|| "a restoring feature marker must describe the restore".to_owned())?;
    let (mut staged, mut kept): (Vec<CompanionAccount>, Vec<CompanionAccount>) =
        std::mem::take(inventory)
            .into_iter()
            .partition(|account| matches!(account, CompanionAccount::Staged { .. }));
    staged.sort_by_key(deletion_order);
    let mut changes = Vec::with_capacity(staged.len());
    let mut live_accounts: HashSet<CompanionAccount> = kept.iter().cloned().collect();
    for account in staged {
        let live = account
            .activated()
            .ok_or_else(|| "a staged record has no live account".to_owned())?;
        if live_accounts.insert(live.clone()) {
            kept.push(live.clone());
        }
        changes.push(PlannedChange::Move {
            staged: account,
            live,
        });
    }
    *inventory = kept;
    let mut next = marker.clone();
    next.features = marker.post_restore_features(restore);
    next.state = ProjectState::Active;
    next.restore = None;
    Ok(Step {
        changes,
        marker: MarkerChange::Write(next),
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::marker::{FeatureEntry, Level, Restore};

    /// Committed records, and how many more commits succeed before a crash.
    #[derive(Default)]
    struct MemoryStore {
        records: BTreeMap<CompanionAccount, Vec<u8>>,
        commits: usize,
        crash_after: Option<usize>,
        largest_transaction: usize,
        transactions: Vec<Vec<Mutation>>,
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
            self.transactions.push(mutations.clone());
            let unlisted_before: Vec<CompanionAccount> = self.unlisted();
            let written: Vec<CompanionAccount> = mutations
                .iter()
                .filter_map(|mutation| match mutation {
                    Mutation::Write { account, .. } => Some(account.clone()),
                    Mutation::Delete { .. } => None,
                })
                .collect();
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
            crate::invariants::check_written(self.marker().as_ref(), &written)
                .expect("every record a commit writes is listed");
            for account in self.unlisted() {
                assert!(
                    unlisted_before.contains(&account),
                    "a commit left {} without a feature that lists it",
                    account.name()
                );
            }
            Ok(())
        }
    }

    impl MemoryStore {
        /// The stored marker, or `None` when it's absent or invalid, which
        /// lists nothing either way.
        fn marker(&self) -> Option<Marker> {
            self.records
                .get(&marker_account())
                .and_then(|bytes| Marker::parse("proj", bytes).ok())
        }

        fn unlisted(&self) -> Vec<CompanionAccount> {
            let marker = self.marker();
            self.records
                .keys()
                .filter(|account| !crate::invariants::is_listed(marker.as_ref(), account))
                .cloned()
                .collect()
        }

        fn inventory(&self) -> Vec<CompanionAccount> {
            self.records
                .keys()
                .filter(|account| !matches!(account, CompanionAccount::Marker { .. }))
                .cloned()
                .collect()
        }

        fn store_marker(&mut self, marker: &Marker) {
            self.records
                .insert(marker_account(), marker.encode().expect("valid marker"));
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

    fn marker_account() -> CompanionAccount {
        CompanionAccount::Marker {
            vault_id: "proj".to_owned(),
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
            let mut store = history_store(40);
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
        let mut store = history_store(16);
        let mut marker = store.marker().expect("marker");
        marker.state = ProjectState::Deleting;
        let inventory = store.inventory();
        resume(&mut store, marker, inventory).expect("deletion finishes");
        assert_eq!(
            store.transactions[0].first(),
            Some(&Mutation::Delete {
                account: record("key", None)
            })
        );
    }

    /// The first transaction of a deletion plan, with `own` deletions of the
    /// client's in front, as a client commits it.
    fn first_with_own(plan: &Plan, own: usize) -> Vec<Mutation> {
        let first = &plan.transactions[0];
        let mut mutations: Vec<Mutation> = (0..own)
            .map(|index| Mutation::Delete {
                account: record(&format!("own{index}"), None),
            })
            .collect();
        mutations.extend(first.changes.iter().map(|change| match change {
            PlannedChange::Delete(account) => Mutation::Delete {
                account: account.clone(),
            },
            PlannedChange::Move { .. } => panic!("a deletion moves nothing"),
        }));
        match &first.marker {
            Some(MarkerChange::Write(marker)) => mutations.push(Mutation::Write {
                account: marker_account(),
                value: marker.encode().expect("valid marker"),
            }),
            Some(MarkerChange::Delete) => mutations.push(Mutation::Delete {
                account: marker_account(),
            }),
            None => {}
        }
        mutations
    }

    #[test]
    fn a_planned_deletion_shreds_the_key_with_the_project_and_finishes_through_crashes() {
        let store = history_store(40);
        let current = store.marker().expect("marker");
        let plan = plan_deletion("proj", FoundMarker::Valid(&current), store.inventory(), 3)
            .expect("a plan");
        let first = &plan.transactions[0];
        assert_eq!(
            first.changes.first(),
            Some(&PlannedChange::Delete(record("key", None)))
        );
        assert!(first.changes.iter().all(
            |change| matches!(change, PlannedChange::Delete(account) if account.part().is_none())
        ));
        assert!(first.changes.len() <= MAX_TRANSACTION_OPERATIONS - 4);
        assert!(matches!(
            &first.marker,
            Some(MarkerChange::Write(marker)) if marker.state == ProjectState::Deleting
                && marker.features == current.features
        ));
        assert_eq!(plan.result, None);
        for crash in 0..4 {
            let mut store = history_store(40);
            store.crash_after = Some(crash);
            let mut transactions = plan.transactions.clone();
            transactions.remove(0);
            if store.commit(first_with_own(&plan, 0)).is_err() {
                assert_eq!(store.marker(), Some(current.clone()), "crash {crash}");
                continue;
            }
            let _ = execute(
                &mut store,
                Plan {
                    transactions,
                    ..plan.clone()
                },
            );
            store.crash_after = None;
            assert_eq!(store.resume_through_crashes(), None, "crash {crash}");
            assert!(store.records.is_empty(), "crash {crash}");
        }
    }

    #[test]
    fn a_deletion_that_fits_deletes_the_marker_in_its_only_transaction() {
        let mut store = MemoryStore::default();
        let mut marker = Marker::empty("proj", ProjectState::Active);
        marker.features.insert(
            "overrides".to_owned(),
            entry(&["overrides"], FeatureState::Active),
        );
        store.store_marker(&marker);
        store
            .records
            .insert(record("overrides", None), b"mine".to_vec());
        let plan = plan_deletion("proj", FoundMarker::Valid(&marker), store.inventory(), 2)
            .expect("a plan");
        assert_eq!(
            plan.transactions,
            [Transaction {
                changes: vec![PlannedChange::Delete(record("overrides", None))],
                marker: Some(MarkerChange::Delete),
            }]
        );
        store
            .commit(first_with_own(&plan, 2))
            .expect("one transaction");
        assert!(store.records.is_empty());
    }

    #[test]
    fn a_deletion_without_a_marker_writes_none_unless_records_outlast_the_first_transaction() {
        let single = vec![record("future-kind", None)];
        let plan = plan_deletion("proj", FoundMarker::Absent, single.clone(), 1).expect("a plan");
        assert_eq!(
            plan.transactions,
            [Transaction {
                changes: vec![PlannedChange::Delete(record("future-kind", None))],
                marker: None,
            }]
        );
        assert!(
            plan_deletion("proj", FoundMarker::Absent, Vec::new(), 1)
                .expect("a plan")
                .transactions
                .is_empty()
        );
        assert_eq!(
            plan_deletion("proj", FoundMarker::Invalid, Vec::new(), 1)
                .expect("a plan")
                .transactions,
            [Transaction {
                changes: Vec::new(),
                marker: Some(MarkerChange::Delete),
            }]
        );
        let mut with_parts = single;
        with_parts.push(record("future-log", Some(3)));
        let plan = plan_deletion("proj", FoundMarker::Invalid, with_parts, 1).expect("a plan");
        assert_eq!(plan.transactions.len(), 2);
        let Some(MarkerChange::Write(deleting)) = &plan.transactions[0].marker else {
            panic!("a deleting marker first");
        };
        assert_eq!(deleting.state, ProjectState::Deleting);
        assert!(deleting.features.is_empty());
        deleting.validate().expect("the deleting marker validates");
        assert_eq!(
            plan.transactions[1],
            Transaction {
                changes: vec![PlannedChange::Delete(record("future-log", Some(3)))],
                marker: Some(MarkerChange::Delete),
            }
        );
    }

    #[test]
    fn a_project_wide_discard_keeps_nothing_but_the_values_through_crashes() {
        for crash in 0..4 {
            let mut store = history_store(40);
            store
                .records
                .insert(marker_account(), b"not a marker".to_vec());
            store.crash_after = Some(crash);
            let plan =
                plan_discard("proj", FoundMarker::Invalid, store.inventory()).expect("a plan");
            assert!(matches!(
                &plan.transactions[0].marker,
                Some(MarkerChange::Write(marker)) if marker.state == ProjectState::Discarding
            ));
            let _ = execute(&mut store, plan);
            store.crash_after = None;
            if crash > 0 {
                assert_eq!(store.resume_through_crashes(), None, "crash {crash}");
                assert!(store.records.is_empty(), "crash {crash}");
            }
        }
    }

    #[test]
    fn removing_one_feature_marks_it_removing_only_when_it_takes_more_than_one_transaction() {
        let store = history_store(2);
        let marker = store.marker().expect("marker");
        let small = plan_feature_removal(&marker, "overrides", store.inventory()).expect("a plan");
        assert_eq!(small.transactions.len(), 1);
        assert_eq!(
            small.transactions[0].changes,
            [PlannedChange::Delete(record("overrides", None))]
        );
        assert!(
            small
                .result
                .as_ref()
                .is_some_and(|result| !result.features.contains_key("overrides"))
        );

        for crash in 0..4 {
            let mut store = history_store(40);
            let marker = store.marker().expect("marker");
            let large =
                plan_feature_removal(&marker, "history", store.inventory()).expect("a plan");
            assert!(matches!(
                &large.transactions[0],
                Transaction { changes, marker: Some(MarkerChange::Write(removing)) }
                    if changes.is_empty()
                        && removing.features["history"].state == FeatureState::Removing
            ));
            store.crash_after = Some(crash);
            let _ = execute(&mut store, large);
            store.crash_after = None;
            let result = store.resume_through_crashes().expect("marker remains");
            if crash > 0 {
                assert!(!result.features.contains_key("history"), "crash {crash}");
                assert!(
                    !store
                        .records
                        .keys()
                        .any(|account| account.kind() == Some("history")),
                    "crash {crash}"
                );
            }
            assert!(
                store.records.contains_key(&record("key", None)),
                "crash {crash}"
            );
        }
    }

    #[test]
    fn removing_unlisted_records_keeps_every_listed_one_and_the_marker() {
        let mut store = history_store(2);
        store
            .records
            .insert(record("notes", None), b"stray".to_vec());
        store
            .records
            .insert(staged("overrides", None), b"stray".to_vec());
        for part in 0..40 {
            store
                .records
                .insert(record("future-log", Some(part)), b"stray".to_vec());
        }
        let marker = store.marker().expect("marker");
        let listed = history_store(2).records;
        let plan = plan_unlisted_removal(&marker, store.inventory()).expect("a plan");
        assert!(plan.transactions.len() >= 2);
        assert!(
            plan.transactions
                .iter()
                .all(|transaction| transaction.marker.is_none())
        );
        assert_eq!(plan.result.as_ref(), Some(&marker));
        assert_eq!(execute(&mut store, plan), Ok(Some(marker)));
        assert_eq!(store.records, listed);
        let nothing =
            plan_unlisted_removal(&store.marker().unwrap(), store.inventory()).expect("a plan");
        assert!(nothing.transactions.is_empty());
    }

    #[test]
    fn a_feature_removal_waits_for_an_interrupted_change() {
        let store = history_store(2);
        let mut marker = store.marker().expect("marker");
        marker.state = ProjectState::Deleting;
        assert!(plan_feature_removal(&marker, "overrides", store.inventory()).is_err());
        let active = store.marker().expect("marker");
        assert!(plan_feature_removal(&active, "details", store.inventory()).is_err());
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

    fn restoring_store(
        phase: RestorePhase,
        staged_parts: u16,
    ) -> (MemoryStore, BTreeMap<CompanionAccount, Vec<u8>>) {
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
        for part in 0..staged_parts {
            store
                .records
                .insert(staged("history", Some(part)), vec![b'n'; 100 * 1024]);
        }
        (store, before)
    }

    #[test]
    fn an_interrupted_staging_rolls_back_to_exactly_the_records_before_it() {
        for crash in 0..3 {
            let (mut store, before) = restoring_store(RestorePhase::Staging, 3);
            store.crash_after = Some(crash);
            let marker = store.marker().expect("marker");
            let inventory = store.inventory();
            let _ = resume(&mut store, marker, inventory);
            store.crash_after = None;
            let result = store.resume_through_crashes().expect("marker remains");
            assert_eq!(result.state, ProjectState::Active);
            assert!(result.restore.is_none());
            let mut expected = before.clone();
            expected.insert(marker_account(), result.encode().unwrap());
            assert_eq!(store.records, expected, "crash {crash}");
        }
    }

    #[test]
    fn an_interrupted_activation_finishes_exactly_the_reviewed_post_state() {
        for crash in 0..8 {
            let (mut store, _) = restoring_store(RestorePhase::Activating, 14);
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
                marker_account(),
                record("history-head", None),
                record("key", None),
                record("overrides", None),
            ];
            expected.extend((0..14).map(|part| record("history", Some(part))));
            expected.sort();
            assert_eq!(accounts, expected, "crash {crash}");
            assert_eq!(store.records[&record("key", None)], b"new-key");
            assert_eq!(store.records[&record("overrides", None)], b"theirs");
            assert_eq!(
                store.records[&record("history", Some(13))],
                vec![b'n'; 100 * 1024]
            );
        }
    }

    #[test]
    fn activations_split_by_the_largest_record_and_keep_moves_whole() {
        let (store, _) = restoring_store(RestorePhase::Activating, 30);
        let marker = store.marker().expect("marker");
        let plan = plan_resume(marker, store.inventory()).expect("a plan");
        let moves: usize = plan
            .transactions
            .iter()
            .flat_map(|transaction| &transaction.changes)
            .filter(|change| matches!(change, PlannedChange::Move { .. }))
            .count();
        assert_eq!(moves, 33);
        for transaction in &plan.transactions {
            let operations: usize = transaction
                .changes
                .iter()
                .map(PlannedChange::operations)
                .sum::<usize>()
                + usize::from(transaction.marker.is_some());
            let bound: usize = transaction
                .changes
                .iter()
                .map(PlannedChange::payload_bound)
                .sum();
            assert!(operations <= MAX_TRANSACTION_OPERATIONS);
            assert!(bound <= MAX_TRANSACTION_PAYLOAD_BYTES);
        }
        let marker_changes = plan
            .transactions
            .iter()
            .filter(|transaction| transaction.marker.is_some())
            .count();
        assert_eq!(marker_changes, 2, "one marker change per activation step");
        assert!(plan.transactions.last().unwrap().marker.is_some());
    }

    #[test]
    fn a_marker_with_nothing_to_finish_plans_nothing() {
        let store = history_store(2);
        let marker = store.marker().expect("marker");
        let plan = plan_resume(marker.clone(), store.inventory()).expect("a plan");
        assert!(plan.transactions.is_empty());
        assert_eq!(plan.result, Some(marker));
    }
}
