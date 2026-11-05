//! Local history on the Keychain: what recording costs, counted by account,
//! with the in-memory Keychain.

use super::*;
use crate::history::record::record;
use crate::history::scope::Tracked;
use crate::history::{Action, Outcome, Source};

const VAULT: &str = "proj";

/// The in-memory Keychain as history's store: the store the CLI uses, over
/// the in-memory storage.
type TestHistory<'storage> =
    crate::keychain::history::KeychainHistory<'storage, MemoryProjectStorage>;

fn test_history(storage: &mut MemoryProjectStorage) -> TestHistory<'_> {
    crate::keychain::history::KeychainHistory::new(storage)
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
        environment_renames: Vec::new(),
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
        &mut test_history(&mut storage),
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
    storage.attribute_reads.clear();
    storage.listings = 0;
    storage.probes.clear();
    let appended = record(
        &mut test_history(&mut storage),
        VAULT,
        &change("one", "two"),
    );
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
    let attribute_reads: usize = storage.attribute_reads.values().sum();
    assert!(
        attribute_reads <= 1,
        "the values item's attributes are read at most once: {:?}",
        storage.attribute_reads
    );
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
        &mut test_history(&mut storage),
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

fn created_storage() -> MemoryProjectStorage {
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
        &mut test_history(&mut storage),
        VAULT,
        &change("zero", "one"),
    );
    assert!(matches!(created, Outcome::Recorded { .. }), "{created:?}");
    storage
}

fn head_of(storage: &MemoryProjectStorage) -> lpm_env_companion::append_log::Head {
    let account = lpm_env_companion::history::head_account(VAULT).name();
    lpm_env_companion::append_log::Head::parse(
        lpm_env_companion::append_log::HISTORY,
        VAULT,
        storage.values.get_bytes(&account).expect("head"),
    )
    .expect("a valid head")
}

/// Record large changes until the ring holds `parts` parts. Returns the
/// value last stored.
fn grow_to(storage: &mut MemoryProjectStorage, parts: usize, mut previous: String) -> String {
    let mut round = 0;
    while head_of(storage).parts.len() < parts {
        round += 1;
        assert!(round < 64, "the ring grows within a few large changes");
        let next = format!("{round}{}", "x".repeat(6 * 1024));
        let outcome = record(&mut test_history(storage), VAULT, &change(&previous, &next));
        assert!(matches!(outcome, Outcome::Recorded { .. }), "{outcome:?}");
        previous = next;
    }
    previous
}

/// Fill the service with other projects' records until it holds `total`.
fn fill_service(storage: &mut MemoryProjectStorage, total: usize) {
    let existing = storage
        .values
        .keys()
        .filter(|name| {
            CompanionAccount::parse(name)
                .is_some_and(|account| !matches!(account, CompanionAccount::Marker { .. }))
        })
        .count();
    for index in 0..total.saturating_sub(existing) {
        storage.values.insert(
            CompanionAccount::Record {
                kind: "overrides".to_owned(),
                vault_id: format!("other{index:05}"),
                part: None,
            }
            .name(),
            b"x".to_vec(),
        );
    }
}

#[test]
fn trimming_its_own_ring_for_growth_plans_again_on_the_head_as_it_is_now() {
    let mut storage = created_storage();
    let previous = grow_to(&mut storage, 3, "one".to_owned());
    fill_service(&mut storage, lpm_env_companion::budgets::ADMISSION_TARGET);
    let mut previous = previous;
    let parts_before = head_of(&storage).parts;
    for round in 0..64 {
        let next = format!("again {round}{}", "y".repeat(6 * 1024));
        record(
            &mut test_history(&mut storage),
            VAULT,
            &change(&previous, &next),
        );
        previous = next;
        if head_of(&storage).parts != parts_before {
            break;
        }
    }
    let head = head_of(&storage);
    for part in &head.parts {
        let account = lpm_env_companion::history::part_account(VAULT, *part).name();
        assert!(
            storage.values.contains_key(&account),
            "the head lists part {part}, which exists: {head:?}"
        );
    }
    assert_eq!(
        head.ring_limit as usize,
        head.parts.len(),
        "the ring shrank and couldn't grow: {head:?}"
    );
}

#[test]
fn admission_learns_every_project_s_approval_from_the_listing() {
    let mut storage = MemoryProjectStorage::default();
    save_vault_data_with_storage(
        &mut storage,
        VAULT,
        "Project",
        "/project",
        r#"{"environments":{"default":{"TOKEN":"one"}}}"#,
    )
    .expect("create the project");
    for index in 0..2_100 {
        let vault = format!("ring{index:05}");
        for part in 0..2 {
            storage.values.insert(
                lpm_env_companion::history::part_account(&vault, part).name(),
                b"x".to_vec(),
            );
        }
        storage.values.insert(vault.clone(), b"{}".to_vec());
        if index % 2 == 0 {
            storage.claims.insert(vault, ClaimedAccess::RequireApproval);
        }
    }
    storage.attribute_reads.clear();
    let created = record(
        &mut test_history(&mut storage),
        VAULT,
        &change("zero", "one"),
    );
    assert!(matches!(created, Outcome::Recorded { .. }), "{created:?}");
    let other_reads: usize = storage
        .attribute_reads
        .iter()
        .filter(|(account, _)| account.as_str() != VAULT)
        .map(|(_, count)| count)
        .sum();
    assert_eq!(
        other_reads, 0,
        "no project's attributes are read one by one"
    );
    assert_eq!(storage.listings, 1);
}

#[test]
fn a_change_history_cant_record_costs_no_listing_or_probe() {
    let mut storage = MemoryProjectStorage::default();
    save_vault_data_with_storage(
        &mut storage,
        VAULT,
        "Project",
        "/project",
        r#"{"environments":{"default":{"TOKEN":"one"}}}"#,
    )
    .expect("create the project");
    let mut many = HashMap::new();
    for index in 0..3_000 {
        many.insert(format!("A_RATHER_LONG_KEY_NAME_{index:08}"), "v".to_owned());
    }
    let too_many = Tracked {
        source: Source::new(Action::Import),
        before: Some(environments("one")),
        after: Some(HashMap::from([("default".to_owned(), many)])),
        environment_renames: Vec::new(),
    };
    assert_eq!(
        record(&mut test_history(&mut storage), VAULT, &too_many),
        Outcome::NotRecorded(crate::history::NotRecorded::TooManyValues)
    );
    let environment_only = Tracked {
        source: Source::new(Action::CreateEnvironment),
        before: Some(environments("one")),
        after: Some(HashMap::from([
            (
                "default".to_owned(),
                HashMap::from([("TOKEN".to_owned(), "one".to_owned())]),
            ),
            ("preview".to_owned(), HashMap::new()),
        ])),
        environment_renames: Vec::new(),
    };
    assert_eq!(
        record(&mut test_history(&mut storage), VAULT, &environment_only),
        Outcome::Nothing
    );
    assert_eq!(storage.listings, 0, "no listing");
    assert!(storage.probes.is_empty(), "no probe");
}

#[test]
fn a_locked_keychain_fails_the_repair_review_instead_of_offering_to_delete_history() {
    let mut storage = created_storage();
    storage
        .failing_reads
        .insert(lpm_env_companion::history::head_account(VAULT).name());
    let review = review_companion_data_with_storage(&mut storage, VAULT);
    assert!(
        matches!(&review, Err(error) if error.contains("couldn't be read")),
        "{review:?}"
    );
}

#[test]
fn growth_admission_collects_the_parts_its_own_head_no_longer_lists() {
    let mut storage = created_storage();
    let previous = grow_to(&mut storage, 2, "one".to_owned());
    let orphan = lpm_env_companion::history::part_account(VAULT, 9).name();
    storage
        .values
        .insert(orphan.clone(), b"left by a crashed trim".to_vec());
    grow_to(&mut storage, 3, previous);
    assert!(
        !storage.values.contains_key(&orphan),
        "the growth's admission deleted the orphan part"
    );
}

#[test]
fn a_change_built_on_the_file_store_s_values_records_them_as_its_before() {
    crate::fallback::tests::with_temp_vault_home(|_| {
        crate::fallback::tests::force_file_vault();
        let stored = HashMap::from([(
            "default".to_owned(),
            HashMap::from([
                ("A".to_owned(), "1".to_owned()),
                ("B".to_owned(), "2".to_owned()),
            ]),
        )]);
        crate::fallback::write_all_environments(VAULT, &stored, &Source::new(Action::Set))
            .expect("file-store values");
        crate::history::take_outcomes();
        crate::storage_transaction::with_vault_transaction(|directory| {
            crate::history::scope::begin(VAULT, &Source::new(Action::Set));
            let mut keychain = MemoryProjectStorage::default();
            let base = read_mutation_base(&mut keychain, directory, VAULT)?;
            assert_eq!(base, stored);
            assert_eq!(
                crate::history::scope::tracked(VAULT).and_then(|tracked| tracked.before),
                Some(stored.clone()),
                "the change read the file store's values, so they're its before"
            );
            crate::history::scope::forget(VAULT);
            Ok(())
        })
        .expect("transaction");
    });
}
