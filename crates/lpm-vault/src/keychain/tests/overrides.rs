//! Personal override writes through the Keychain journal: the record takes
//! the values item's verified approval, an interrupted step is finished
//! first, and the marker comes and goes with the last override.

use super::*;
use crate::companion::account::{marker_account, record_account};
use crate::companion::overrides::change::Edit;
use zeroize::Zeroizing;

const VAULT: &str = "proj";
const VALUES: &str = r#"{"environments":{"default":{"TOKEN":"team"}}}"#;

fn storage_with_values() -> MemoryProjectStorage {
    let mut storage = MemoryProjectStorage::default();
    save_vault_data_with_storage(&mut storage, VAULT, "Project", "/project", VALUES)
        .expect("create the project");
    storage
}

fn set(key: &str, value: &str) -> Edit {
    Edit::Set {
        environment: "default".to_owned(),
        key: key.to_owned(),
        value: Zeroizing::new(value.to_owned()),
    }
}

fn remove(key: &str) -> Edit {
    Edit::Remove {
        environment: "default".to_owned(),
        key: key.to_owned(),
    }
}

/// A change as the CLI makes one: in a lock scope that first recovers any
/// journal an earlier run left.
fn change(storage: &mut MemoryProjectStorage, edits: &[Edit]) -> Result<(), String> {
    let _scope = crate::companion::LockScope::enter();
    recover_project_transaction(storage)?;
    crate::keychain::overrides::change_with_storage(storage, VAULT, edits).map(|_| ())
}

fn read_all(
    storage: &mut MemoryProjectStorage,
) -> Result<std::collections::BTreeMap<String, crate::PersonalOverrides>, String> {
    let _scope = crate::companion::LockScope::enter();
    recover_project_transaction(storage)?;
    crate::keychain::overrides::read_all_with_storage(storage, VAULT)
}

fn overrides_account() -> String {
    record_account("overrides", VAULT, None)
}

#[test]
fn the_first_override_is_journaled_with_its_marker_and_reads_back() {
    let mut storage = storage_with_values();
    change(&mut storage, &[set("API_URL", "http://localhost:4000")]).expect("set");

    let read = read_all(&mut storage).expect("read");
    assert_eq!(read["default"].set["API_URL"], "http://localhost:4000");
    let marker = storage
        .values
        .get(&marker_account(VAULT))
        .expect("the marker lists overrides");
    assert!(marker.contains(r#""overrides":{"version":1,"ifUnsupported":"refuse""#));
    assert!(
        !storage.values.contains_key(TRANSACTION_MARKER_ACCOUNT),
        "the journal is gone once the change is applied"
    );
}

#[test]
fn an_override_takes_the_values_verified_approval() {
    let mut storage = storage_with_values();
    storage
        .claims
        .insert(VAULT.to_owned(), ClaimedAccess::RequireApproval);
    storage.protected.insert(VAULT.to_owned());

    change(&mut storage, &[set("API_URL", "mine")]).expect("set");

    assert!(
        storage.protected.contains(&overrides_account()),
        "a record that follows values is as protected as they are"
    );
    assert!(
        !storage.protected.contains(&marker_account(VAULT)),
        "the marker is open"
    );
}

#[test]
fn an_override_of_values_without_approval_stays_automatic() {
    let mut storage = storage_with_values();
    change(&mut storage, &[set("API_URL", "mine")]).expect("set");
    assert!(!storage.protected.contains(&overrides_account()));
}

#[test]
fn a_weaker_record_under_approved_values_is_strengthened_before_it_is_read_or_changed() {
    let mut storage = storage_with_values();
    change(&mut storage, &[set("API_URL", "mine")]).expect("set");
    storage
        .claims
        .insert(VAULT.to_owned(), ClaimedAccess::RequireApproval);
    storage.protected.insert(VAULT.to_owned());

    read_all(&mut storage).expect("read");
    assert_eq!(storage.approvals_required, [overrides_account()]);
    assert!(storage.protected.contains(&overrides_account()));
}

#[test]
fn removing_the_last_override_deletes_the_record_and_the_marker() {
    let mut storage = storage_with_values();
    change(&mut storage, &[set("API_URL", "mine")]).expect("set");
    change(&mut storage, &[remove("API_URL")]).expect("remove");

    assert!(!storage.values.contains_key(&overrides_account()));
    assert!(!storage.values.contains_key(&marker_account(VAULT)));
    assert!(read_all(&mut storage).expect("read").is_empty());
}

#[test]
fn a_project_without_values_cant_have_overrides() {
    let mut storage = MemoryProjectStorage::default();
    let error = change(&mut storage, &[set("API_URL", "mine")]).expect_err("no values");
    assert!(error.contains("has no values on this computer"), "{error}");
    assert_eq!(storage.values.keys().count(), 0);
}

#[test]
fn an_override_change_interrupted_after_its_journal_is_finished_by_the_next_operation() {
    let mut storage = storage_with_values();
    change(&mut storage, &[set("FIRST", "1")]).expect("set");
    let record = storage
        .values
        .get(&overrides_account())
        .expect("the record")
        .replace(r#""FIRST":"1""#, r#""FIRST":"1","INTERRUPTED":"2""#);
    super::companion::committed_journal(
        &mut storage,
        &[(overrides_account().as_str(), Some(record.as_bytes()))],
    );

    change(&mut storage, &[set("THIRD", "3")]).expect("set after recovery");

    assert!(!storage.values.contains_key(TRANSACTION_MARKER_ACCOUNT));
    let read = read_all(&mut storage).expect("read");
    assert_eq!(read["default"].set["FIRST"], "1");
    assert_eq!(read["default"].set["INTERRUPTED"], "2");
    assert_eq!(read["default"].set["THIRD"], "3");
}

#[test]
fn a_damaged_record_refuses_changes_and_writes_nothing() {
    let mut storage = storage_with_values();
    change(&mut storage, &[set("API_URL", "mine")]).expect("set");
    storage
        .values
        .insert(overrides_account(), b"{not json".to_vec());
    let before = storage.values.as_text_map();

    let error = change(&mut storage, &[set("OTHER", "x")]).expect_err("damage refuses");
    assert!(
        error.starts_with("This env project's newer data is damaged"),
        "{error}"
    );
    assert!(crate::is_env_project_refusal(&error));
    assert_eq!(storage.values.as_text_map(), before);
}

#[test]
fn a_change_to_existing_overrides_lists_nothing_and_a_first_one_lists_once() {
    let mut storage = storage_with_values();
    let listings = storage.listings;
    change(&mut storage, &[set("API_URL", "mine")]).expect("set");
    let first = storage.listings - listings;
    assert!(
        first >= 1,
        "creating the record takes the names-only inventory"
    );

    let listings = storage.listings;
    change(&mut storage, &[set("API_URL", "yours")]).expect("replace");
    assert_eq!(
        storage.listings, listings,
        "replacing the record needs neither an inventory nor an invariant listing"
    );
}

#[test]
fn a_change_whose_last_step_failed_is_finished_by_the_next_operation() {
    let mut storage = storage_with_values();
    change(&mut storage, &[set("API_URL", "mine")]).expect("set");
    storage.rejected_writes.insert(overrides_account());

    change(&mut storage, &[set("API_URL", "yours")]).expect_err("the write fails");
    assert!(
        storage.values.contains_key(TRANSACTION_MARKER_ACCOUNT),
        "the committed journal stays for the next operation"
    );
    storage.rejected_writes.clear();

    let read = read_all(&mut storage).expect("read");
    assert_eq!(read["default"].set["API_URL"], "yours");
    assert!(!storage.values.contains_key(TRANSACTION_MARKER_ACCOUNT));
}

#[test]
fn a_change_that_fails_before_its_journal_commits_leaves_the_overrides_as_they_were() {
    let mut storage = storage_with_values();
    change(&mut storage, &[set("API_URL", "mine")]).expect("set");
    storage.keychain_unavailable = true;
    storage
        .claims
        .insert(VAULT.to_owned(), ClaimedAccess::RequireApproval);
    storage.protected.insert(VAULT.to_owned());

    let error = change(&mut storage, &[set("API_URL", "yours")]).expect_err("no probe");
    assert!(error.contains("retry once the Mac is unlocked"), "{error}");
    storage.keychain_unavailable = false;

    let read = read_all(&mut storage).expect("read");
    assert_eq!(read["default"].set["API_URL"], "mine");
    assert!(!storage.values.contains_key(TRANSACTION_MARKER_ACCOUNT));
}
