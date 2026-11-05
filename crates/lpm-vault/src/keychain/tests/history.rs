//! Local history on the Keychain: what recording costs, counted by account,
//! with the in-memory Keychain.

use super::*;
use crate::companion::CompanionBackend;
use crate::companion::lifecycle::LifecycleStore;
use crate::history::record::record;
use crate::history::scope::Tracked;
use crate::history::store::{AdmissionInventory, HistoryStore};
use crate::history::{Action, Outcome, Source};
use lpm_env_companion::keyring::Approval;

const VAULT: &str = "proj";

/// The in-memory Keychain as history's store, through the same helpers the
/// real one uses.
struct TestHistory<'storage>(&'storage mut MemoryProjectStorage);

impl LifecycleStore for TestHistory<'_> {
    fn read(&mut self, account: &CompanionAccount) -> Result<Option<Vec<u8>>, String> {
        companion_gate::KeychainCompanion(&mut *self.0).read(account)
    }

    fn commit(
        &mut self,
        mutations: Vec<crate::companion::lifecycle::Mutation>,
    ) -> Result<(), String> {
        companion_gate::KeychainCompanion(&mut *self.0).commit(mutations)
    }
}

impl CompanionBackend for TestHistory<'_> {
    fn inventory(&mut self, vault_id: &str) -> Result<Vec<CompanionAccount>, String> {
        companion_gate::KeychainCompanion(&mut *self.0).inventory(vault_id)
    }
}

impl HistoryStore for TestHistory<'_> {
    fn read_following_values(
        &mut self,
        account: &CompanionAccount,
    ) -> Result<Option<zeroize::Zeroizing<Vec<u8>>>, String> {
        crate::keychain::history::read_following_values(&mut *self.0, account)
    }

    fn replace(&mut self, account: &CompanionAccount, bytes: &[u8]) -> Result<(), String> {
        crate::keychain::history::replace(&mut *self.0, account, bytes)
    }

    fn delete(&mut self, account: &CompanionAccount) -> Result<(), String> {
        self.0.delete(&account.name()).map(|_| ())
    }

    fn admission_inventory(&mut self, _vault_id: &str) -> Result<AdmissionInventory, String> {
        crate::keychain::history::admission_inventory(&mut *self.0)
    }

    fn claimed_approval(&mut self, vault_id: &str) -> Result<Approval, String> {
        crate::keychain::history::claimed_approval(&mut *self.0, vault_id)
    }

    fn verified_approval(&mut self, vault_id: &str) -> Result<Option<Approval>, String> {
        crate::keychain::history::verified_approval(&mut *self.0, vault_id)
    }

    fn writes_without_prompt(&mut self, vault_id: &str) -> Result<bool, String> {
        Ok(
            crate::keychain::history::claimed_approval(&mut *self.0, vault_id)?
                == Approval::Automatic,
        )
    }
}

fn environments(token: &str) -> EnvironmentMap {
    HashMap::from([(
        "default".to_owned(),
        HashMap::from([("TOKEN".to_owned(), token.to_owned())]),
    )])
}

fn change(before: &str, after: &str) -> Tracked {
    Tracked {
        source: Source::new(Action::Set),
        before: Some(environments(before)),
        after: Some(environments(after)),
    }
}

fn reads(storage: &MemoryProjectStorage, account: &CompanionAccount) -> usize {
    storage
        .reads
        .get(&account.name())
        .copied()
        .unwrap_or_default()
}

fn writes(storage: &MemoryProjectStorage, account: &CompanionAccount) -> usize {
    storage
        .writes
        .get(&account.name())
        .copied()
        .unwrap_or_default()
}

#[test]
fn a_steady_append_reads_the_head_key_and_tail_once_and_writes_the_tail_once() {
    let mut storage = MemoryProjectStorage::default();
    save_vault_data_with_storage(
        &mut storage,
        VAULT,
        "Project",
        "/project",
        r#"{"environments":{"default":{"TOKEN":"one"}}}"#,
    )
    .expect("create the project");

    let created = record(
        &mut TestHistory(&mut storage),
        VAULT,
        &change("zero", "one"),
    );
    assert!(matches!(created, Outcome::Recorded { .. }), "{created:?}");
    assert_eq!(
        storage.listings, 1,
        "creation lists the service once, for admission"
    );
    assert_eq!(
        storage.probes.len(),
        2,
        "creation probes the values item to record the key's approval, and the journal again to stage"
    );

    storage.reads.clear();
    storage.writes.clear();
    storage.listings = 0;
    storage.probes.clear();
    let appended = record(&mut TestHistory(&mut storage), VAULT, &change("one", "two"));
    assert!(matches!(appended, Outcome::Recorded { .. }), "{appended:?}");

    let head = lpm_env_companion::history::head_account(VAULT);
    let key = lpm_env_companion::history::key_account(VAULT);
    let tail = lpm_env_companion::history::part_account(VAULT, 0);
    assert_eq!(reads(&storage, &head), 1, "the head is read once");
    assert_eq!(reads(&storage, &key), 1, "the key is read once");
    assert_eq!(reads(&storage, &tail), 2, "the tail is read, then verified");
    assert_eq!(writes(&storage, &tail), 1, "the tail is written once");
    let payload_reads: usize = [&head, &key, &tail]
        .iter()
        .map(|account| reads(&storage, account))
        .sum();
    let payload_writes: usize = storage.writes.values().sum();
    assert_eq!(
        (payload_reads, payload_writes),
        (4, 1),
        "4R + 1W of payload work"
    );
    assert_eq!(storage.listings, 0, "no listing");
    assert!(storage.probes.is_empty(), "no probe");
}

#[test]
fn a_record_that_follows_values_is_strengthened_before_its_bytes_are_used() {
    let mut storage = MemoryProjectStorage::default();
    save_vault_data_with_storage(
        &mut storage,
        VAULT,
        "Project",
        "/project",
        r#"{"environments":{"default":{"TOKEN":"one"}}}"#,
    )
    .expect("create the project");
    record(
        &mut TestHistory(&mut storage),
        VAULT,
        &change("zero", "one"),
    );
    // Approval was turned on by a client that didn't protect the head.
    storage
        .claims
        .insert(VAULT.to_owned(), ClaimedAccess::RequireApproval);
    storage.protected.insert(VAULT.to_owned());
    let head = lpm_env_companion::history::head_account(VAULT);
    storage.claims.insert(head.name(), ClaimedAccess::Automatic);
    crate::keychain::history::read_following_values(&mut storage, &head).expect("read with parity");
    assert!(
        storage.approvals_required.contains(&head.name()),
        "the head was given the values item's approval"
    );
}
