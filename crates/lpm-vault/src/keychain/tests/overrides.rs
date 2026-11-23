//! Personal override writes through the Keychain journal: the record takes
//! the values item's verified approval, an interrupted step is finished
//! first, and the marker comes and goes with the last override.

use super::*;
use crate::companion::account::{marker_account, record_account};
use crate::companion::overrides::change::Edit;
use crate::companion::repair::CompanionRepair;
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
    crate::keychain::overrides::change_with_storage(
        storage,
        VAULT,
        edits,
        crate::overrides::Expect::Nothing,
    )
    .map(|_| ())
}

fn read_all(
    storage: &mut MemoryProjectStorage,
) -> Result<std::collections::BTreeMap<String, crate::PersonalOverrides>, String> {
    let _scope = crate::companion::LockScope::enter();
    recover_project_transaction(storage)?;
    crate::keychain::overrides::read_all_with_storage(storage, VAULT)
        .map(|(overrides, _)| overrides)
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
    assert!(marker.contains(r#""overrides":{"version":2,"ifUnsupported":"refuse""#));
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
fn a_first_override_whose_approval_is_cancelled_leaves_the_project_as_it_was() {
    let mut storage = storage_with_values();
    storage
        .claims
        .insert(VAULT.to_owned(), ClaimedAccess::RequireApproval);
    storage.protected.insert(VAULT.to_owned());
    storage.approval_cancelled = true;

    let error = change(&mut storage, &[set("API_URL", "fixture-mine")])
        .expect_err("verifying the protected stage asks for the approval");
    assert!(error.contains("cancelled"), "{error}");

    storage.approval_cancelled = false;
    assert!(read_all(&mut storage).expect("read").is_empty());
    for account in [
        overrides_account(),
        marker_account(VAULT),
        TRANSACTION_MARKER_ACCOUNT.to_owned(),
    ] {
        assert!(
            !storage.values.contains_key(&account),
            "{account} is left after the cancelled write is finished"
        );
    }
    assert_eq!(storage.values.get_bytes(VAULT), Some(VALUES.as_bytes()));
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
fn a_committed_override_change_is_replayed_only_by_an_lpm_that_can_report_it() {
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
    let root = tempfile::tempdir().expect("temporary folder");
    let not_a_marker = root.path().join("not-a-marker");
    std::fs::write(&not_a_marker, "").expect("a file where a marker would be");

    let refused =
        crate::override_marker::reporting_to(vec![not_a_marker], || read_all(&mut storage))
            .expect_err("the replay couldn't be reported");

    assert!(crate::override_marker::describes(&refused), "{refused}");
    assert!(
        storage.values.contains_key(TRANSACTION_MARKER_ACCOUNT),
        "the journal waits for an lpm that can report it"
    );
    assert_eq!(
        read_all(&mut storage).expect("read")["default"].set["INTERRUPTED"],
        "2"
    );
}

#[test]
fn a_committed_journal_of_values_alone_is_replayed_without_a_report() {
    let mut storage = storage_with_values();
    change(&mut storage, &[set("FIRST", "1")]).expect("set");
    let replayed = VALUES.replace("team", "replayed");
    super::companion::committed_journal(&mut storage, &[(VAULT, Some(replayed.as_bytes()))]);
    let root = tempfile::tempdir().expect("temporary folder");
    let not_a_marker = root.path().join("not-a-marker");
    std::fs::write(&not_a_marker, "").expect("a file where a marker would be");

    let values = crate::override_marker::reporting_to(vec![not_a_marker], || {
        let _scope = crate::companion::LockScope::enter();
        recover_project_transaction(&mut storage)?;
        companion_gate::read_values_excluding_overrides(&mut storage, VAULT)
    })
    .expect("a journal that changes values alone has nothing to report")
    .expect("values");

    assert!(values.contains("replayed"));
    assert!(!storage.values.contains_key(TRANSACTION_MARKER_ACCOUNT));
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
fn a_change_lists_the_service_at_most_once_and_a_replacement_never() {
    let mut storage = storage_with_values();
    let listings = storage.listings;
    change(&mut storage, &[set("API_URL", "mine")]).expect("set");
    assert_eq!(
        storage.listings - listings,
        1,
        "creating the record and its marker takes one names-only listing"
    );

    let listings = storage.listings;
    change(&mut storage, &[set("API_URL", "yours")]).expect("replace");
    assert_eq!(
        storage.listings, listings,
        "replacing the record needs neither an inventory nor an invariant listing"
    );

    let listings = storage.listings;
    change(&mut storage, &[remove("API_URL")]).expect("remove");
    assert_eq!(
        storage.listings - listings,
        1,
        "deleting the record and its marker takes one listing"
    );
}

#[test]
fn a_first_override_beside_a_marker_lists_the_service_once() {
    let mut storage = storage_with_values();
    storage.values.insert(
        marker_account(VAULT),
        r#"{"schemaVersion":1,"vaultId":"proj","state":"active","features":{"history-off":{"version":1,"ifUnsupported":"ignore","kinds":["history-off"],"state":"active"}}}"#.to_owned(),
    );
    let listings = storage.listings;
    change(&mut storage, &[set("API_URL", "mine")]).expect("set");
    assert_eq!(storage.listings - listings, 1);
}

#[test]
fn a_weaker_record_under_approved_values_is_never_read_without_their_approval() {
    let mut storage = storage_with_values();
    change(&mut storage, &[set("API_URL", "fixture-mine")]).expect("set");
    storage
        .claims
        .insert(VAULT.to_owned(), ClaimedAccess::RequireApproval);
    storage.protected.insert(VAULT.to_owned());
    storage.approval_cancelled = true;

    let error = read_all(&mut storage).expect_err("the approval was cancelled");
    assert!(error.contains("cancelled"), "{error}");
    assert!(storage.protected.contains(&overrides_account()));
}

#[test]
fn a_repair_review_never_reads_a_weaker_record_without_the_values_approval() {
    let mut storage = storage_with_values();
    change(&mut storage, &[set("API_URL", "fixture-mine")]).expect("set");
    storage
        .values
        .insert(overrides_account(), "fixture-damaged-record");
    storage
        .claims
        .insert(VAULT.to_owned(), ClaimedAccess::RequireApproval);
    storage.protected.insert(VAULT.to_owned());
    storage.approval_cancelled = true;

    let error = review_companion_data_with_storage(&mut storage, VAULT)
        .expect_err("no review, and no removal, from a record read without approval");

    assert!(error.contains("cancelled"), "{error}");
    assert!(!error.contains("malformed"), "{error}");
}

#[test]
fn a_repair_review_never_reads_a_record_whose_contents_decide_nothing() {
    const SUPPORTED: &str = r#"{"schemaVersion":1,"vaultId":"proj","state":"active","features":{"overrides":{"version":1,"ifUnsupported":"refuse","kinds":["overrides"],"state":"active"}}}"#;
    const NEWER: &str = r#"{"schemaVersion":1,"vaultId":"proj","state":"active","features":{"overrides":{"version":9,"ifUnsupported":"refuse","kinds":["overrides"],"state":"active"}}}"#;
    for (case, values, marker, repairs) in [
        (
            "an invalid marker",
            true,
            Some("not a marker"),
            vec![CompanionRepair::DiscardProject],
        ),
        (
            "a version this client doesn't support",
            true,
            Some(NEWER),
            Vec::new(),
        ),
        (
            "a record no marker lists",
            true,
            None,
            vec![CompanionRepair::DiscardProject],
        ),
        (
            "a project without values",
            false,
            Some(SUPPORTED),
            Vec::new(),
        ),
    ] {
        let mut storage = if values {
            storage_with_values()
        } else {
            MemoryProjectStorage::default()
        };
        if let Some(marker) = marker {
            storage.values.insert(marker_account(VAULT), marker);
        }
        storage
            .values
            .insert(overrides_account(), "fixture-damaged-record");
        storage
            .claims
            .insert(overrides_account(), ClaimedAccess::RequireApproval);
        storage.protected.insert(overrides_account());
        storage.reads.clear();

        let reviewed = review_companion_data_with_storage(&mut storage, VAULT)
            .unwrap_or_else(|error| panic!("{case}: {error}"));

        assert_eq!(reviewed.repairs(), repairs, "{case}: {reviewed:?}");
        assert_eq!(
            storage.reads.get(&overrides_account()),
            None,
            "{case}: the record's contents are never read"
        );
        assert!(
            !storage.probes.contains(&overrides_account())
                && !storage.approvals_required.contains(&overrides_account()),
            "{case}: nor is its approval asked about or changed"
        );
    }
}

#[test]
fn a_repair_review_shows_a_record_whose_approval_contradicts_itself_as_damage_only_lpm_vault_repairs()
 {
    const MARKER: &str = r#"{"schemaVersion":1,"vaultId":"proj","state":"active","features":{"overrides":{"version":1,"ifUnsupported":"refuse","kinds":["overrides"],"state":"active"}}}"#;
    for values in [true, false] {
        let mut storage = if values {
            storage_with_values()
        } else {
            MemoryProjectStorage::default()
        };
        storage.values.insert(marker_account(VAULT), MARKER);
        storage
            .values
            .insert(overrides_account(), "fixture-damaged-record");
        storage
            .claims
            .insert(overrides_account(), ClaimedAccess::Contradictory);
        storage
            .values
            .insert(record_account("notes", VAULT, None), "fixture-stray");
        storage.reads.clear();

        let reviewed = review_companion_data_with_storage(&mut storage, VAULT)
            .unwrap_or_else(|error| panic!("values {values}: {error}"));

        let contradiction = reviewed
            .problems
            .iter()
            .find(|problem| problem.description.contains("contradict"));
        if values {
            assert_eq!(
                contradiction.map(|problem| &problem.repair),
                Some(&None),
                "only LPM Vault sets approval again: {reviewed:?}"
            );
        } else {
            assert!(
                contradiction.is_none(),
                "a record left without values is never read: {reviewed:?}"
            );
        }
        assert!(
            reviewed
                .repairs()
                .contains(&CompanionRepair::RemoveUnlisted),
            "values {values}: the other damage is still repaired: {reviewed:?}"
        );
        assert_eq!(storage.reads.get(&overrides_account()), None);
    }
}

#[test]
fn a_record_weakened_while_it_is_read_is_refused_rather_than_used() {
    let mut storage = storage_with_values();
    change(&mut storage, &[set("API_URL", "fixture-mine")]).expect("set");
    for account in [VAULT.to_owned(), overrides_account()] {
        storage
            .claims
            .insert(account.clone(), ClaimedAccess::RequireApproval);
        storage.protected.insert(account);
    }
    storage.weakened_before_read.insert(overrides_account());

    let error = read_all(&mut storage).expect_err("weakened during the read");
    assert!(error.contains("approval"), "{error}");
    assert!(!error.contains("fixture-mine"), "{error}");
}

#[test]
fn a_record_weakened_again_after_it_was_strengthened_is_refused_rather_than_used() {
    let mut storage = storage_with_values();
    change(&mut storage, &[set("API_URL", "fixture-mine")]).expect("set");
    storage
        .claims
        .insert(VAULT.to_owned(), ClaimedAccess::RequireApproval);
    storage.protected.insert(VAULT.to_owned());
    storage.weakened_before_read.insert(overrides_account());

    let error = read_all(&mut storage).expect_err("weakened after the strengthening");
    assert!(error.contains("approval"), "{error}");
    assert!(!error.contains("fixture-mine"), "{error}");
}

#[test]
fn values_that_demand_approval_they_dont_claim_keep_their_overrides_behind_it() {
    let mut storage = storage_with_values();
    change(&mut storage, &[set("API_URL", "fixture-mine")]).expect("set");
    storage.protected.insert(VAULT.to_owned());
    storage.approval_cancelled = true;

    let error = read_all(&mut storage).expect_err("the values' approval was cancelled");
    assert!(error.contains("cancelled"), "{error}");
    assert!(!error.contains("fixture-mine"), "{error}");
    let error = change(&mut storage, &[remove("API_URL")]).expect_err("cancelled again");
    assert!(error.contains("cancelled"), "{error}");
    assert!(
        storage.values.contains_key(&overrides_account()),
        "nothing was removed without the values' approval"
    );
    assert!(storage.protected.contains(&overrides_account()));
}

#[test]
fn a_protected_record_that_claims_no_approval_is_read_once_a_probe_verifies_it() {
    let mut storage = storage_with_values();
    change(&mut storage, &[set("API_URL", "mine")]).expect("set");
    storage
        .claims
        .insert(VAULT.to_owned(), ClaimedAccess::RequireApproval);
    storage.protected.insert(VAULT.to_owned());
    storage.protected.insert(overrides_account());

    let read = read_all(&mut storage).expect("its approval is verified");
    assert_eq!(read["default"].set["API_URL"], "mine");
    assert!(storage.approvals_required.is_empty());
}

#[test]
fn a_record_that_claims_approval_it_lacks_is_strengthened_before_it_is_read() {
    let mut storage = storage_with_values();
    change(&mut storage, &[set("API_URL", "fixture-mine")]).expect("set");
    for account in [VAULT.to_owned(), overrides_account()] {
        storage
            .claims
            .insert(account, ClaimedAccess::RequireApproval);
    }
    storage.protected.insert(VAULT.to_owned());
    storage.approval_cancelled = true;

    let error = read_all(&mut storage).expect_err("the approval was cancelled");
    assert!(error.contains("cancelled"), "{error}");
    let error = change(&mut storage, &[Edit::ClearAll]).expect_err("cancelled again");
    assert!(error.contains("cancelled"), "{error}");
    assert!(
        storage.values.contains_key(&overrides_account()),
        "nothing was cleared without the values' approval"
    );
    assert!(storage.protected.contains(&overrides_account()));
}

#[test]
fn a_record_left_without_values_is_never_listed() {
    let mut storage = storage_with_values();
    change(&mut storage, &[set("API_URL", "fixture-mine")]).expect("set");
    storage.values.remove(VAULT);
    storage.reads.clear();

    assert!(read_all(&mut storage).expect("no overrides").is_empty());
    assert_eq!(storage.reads.get(&overrides_account()).copied(), None);
}

#[test]
fn approved_values_settle_an_absent_or_contradictory_record_without_reading_it() {
    let mut storage = storage_with_values();
    storage
        .claims
        .insert(VAULT.to_owned(), ClaimedAccess::RequireApproval);
    storage.protected.insert(VAULT.to_owned());
    storage.reads.clear();
    assert!(read_all(&mut storage).expect("no overrides").is_empty());
    assert_eq!(storage.reads.get(&overrides_account()).copied(), None);

    change(&mut storage, &[set("API_URL", "fixture-mine")]).expect("set");
    storage
        .claims
        .insert(overrides_account(), ClaimedAccess::Contradictory);
    storage.reads.clear();
    let error = read_all(&mut storage).expect_err("contradictory");
    assert!(error.contains("contradict"), "{error}");
    assert_eq!(storage.reads.get(&overrides_account()).copied(), None);
}

#[test]
fn a_change_probes_the_values_once_for_its_read_and_its_journal() {
    let mut storage = storage_with_values();
    change(&mut storage, &[set("API_URL", "mine")]).expect("set");
    storage.probes.clear();

    change(&mut storage, &[set("API_URL", "yours")]).expect("replace");

    assert_eq!(
        storage
            .probes
            .iter()
            .filter(|account| *account == VAULT)
            .count(),
        1
    );
}

#[test]
fn a_reviewed_removal_reads_the_record_once_and_is_refused_once_it_changed() {
    let mut storage = storage_with_values();
    change(&mut storage, &[set("API_URL", "mine"), set("LOG", "debug")]).expect("set");
    let reviewed = read_all(&mut storage).expect("review");
    let removals = [("default".to_owned(), "API_URL".to_owned())];
    let reviewed_removal = |storage: &mut MemoryProjectStorage| {
        let _scope = crate::companion::LockScope::enter();
        crate::keychain::overrides::change_with_storage(
            storage,
            VAULT,
            &[remove("API_URL")],
            crate::overrides::Expect::Reviewed {
                overrides: &reviewed,
                removals: &removals,
            },
        )
        .map(drop)
    };

    change(&mut storage, &[set("API_URL", "yours")]).expect("another command changes it");
    storage.reads.clear();
    let refused = reviewed_removal(&mut storage).expect_err("API_URL changed");
    assert!(refused.contains("changed while it asked"), "{refused}");
    assert_eq!(
        read_all(&mut storage).expect("read")["default"].set["API_URL"],
        "yours"
    );

    let cost = |storage: &mut MemoryProjectStorage| {
        (
            storage.reads.get(&overrides_account()).copied(),
            storage
                .probes
                .iter()
                .filter(|account| *account == VAULT)
                .count(),
        )
    };
    change(&mut storage, &[set("API_URL", "mine"), remove("LOG")]).expect("as reviewed");
    storage.reads.clear();
    storage.probes.clear();
    change(&mut storage, &[remove("API_URL")]).expect("a plain removal");
    let plain = cost(&mut storage);
    change(&mut storage, &[set("API_URL", "mine")]).expect("as reviewed again");
    storage.reads.clear();
    storage.probes.clear();
    reviewed_removal(&mut storage).expect("what it removes is as reviewed");
    assert_eq!(
        cost(&mut storage),
        plain,
        "the review is checked against the record the plan reads"
    );
    assert!(read_all(&mut storage).expect("read").is_empty());
}

/// A rollback's write that renames `default` to `prod`, its overrides
/// following.
fn rename_default_to_prod(storage: &mut MemoryProjectStorage) -> Result<(), String> {
    let _scope = crate::companion::LockScope::enter();
    recover_project_transaction(storage)?;
    let renamed = HashMap::from([(
        "prod".to_owned(),
        HashMap::from([("TOKEN".to_owned(), "team".to_owned())]),
    )]);
    write_all_environments_following_with_storage(
        storage,
        VAULT,
        "Project",
        "/project",
        &renamed,
        &crate::history::scope::begin(
            VAULT,
            &crate::history::Source::new(crate::history::Action::Rollback),
        ),
        &[Edit::EnvironmentsChanged {
            renamed: vec![("default".to_owned(), "prod".to_owned())],
            removed: Vec::new(),
        }],
    )
}

#[test]
fn a_write_its_overrides_follow_probes_the_values_once_for_its_plan_and_its_journal() {
    let mut storage = storage_with_values();
    change(&mut storage, &[set("TOKEN", "mine")]).expect("set");
    storage.probes.clear();

    rename_default_to_prod(&mut storage).expect("renamed");

    assert_eq!(
        storage
            .probes
            .iter()
            .filter(|account| *account == VAULT)
            .count(),
        1
    );
    assert!(read_all(&mut storage).expect("read").contains_key("prod"));
}

#[test]
fn a_write_its_overrides_follow_stages_the_values_with_their_verified_approval() {
    let mut storage = storage_with_values();
    change(&mut storage, &[set("TOKEN", "mine")]).expect("set");
    // The values demand approval their attributes don't claim, as a client
    // that predates the check can leave them.
    storage.protected.insert(VAULT.to_owned());
    storage.access_sources.clear();

    rename_default_to_prod(&mut storage).expect("renamed");

    assert!(
        storage
            .access_sources
            .iter()
            .all(|(_, source)| source != VAULT),
        "no stage copied the values' claim: {:?}",
        storage.access_sources
    );
}

#[test]
fn values_and_the_overrides_that_follow_them_land_together_or_not_at_all() {
    let storage = || {
        let mut storage = storage_with_values();
        change(&mut storage, &[set("TOKEN", "mine")]).expect("set");
        storage.mutation_attempts = 0;
        storage
    };
    let rename = rename_default_to_prod;
    let mut uninterrupted = storage();
    rename(&mut uninterrupted).expect("renamed");
    assert!(
        read_all(&mut uninterrupted)
            .expect("read")
            .contains_key("prod")
    );
    let mutations = uninterrupted.mutation_attempts;
    assert!(mutations > 0);

    for failure_point in 1..=mutations {
        let mut storage = storage();
        storage.fail_once_at_mutation = Some(failure_point);
        let _ = rename(&mut storage);
        assert!(storage.injected_failure, "{failure_point}");
        storage.fail_once_at_mutation = None;

        let overrides =
            read_all(&mut storage).unwrap_or_else(|error| panic!("{failure_point}: {error}"));
        let values_moved = storage
            .values
            .get(VAULT)
            .expect("the values")
            .contains(r#""prod""#);
        assert_eq!(
            overrides.contains_key("prod"),
            values_moved,
            "{failure_point}: {:?}",
            overrides.keys().collect::<Vec<_>>()
        );
        assert_eq!(overrides.len(), 1, "{failure_point}");
    }
}

#[test]
fn the_check_before_values_neither_probes_nor_reads_the_values() {
    let mut storage = storage_with_values();
    storage.reads.clear();
    storage.probes.clear();
    {
        let _scope = crate::companion::LockScope::enter();
        crate::keychain::overrides::check_with_storage(&mut storage, VAULT, &[remove("API_URL")])
            .expect("a project that can have overrides");
    }
    assert!(storage.probes.is_empty(), "{:?}", storage.probes);
    assert_eq!(storage.reads.get(VAULT).copied(), None);
}

#[test]
fn the_check_before_values_refuses_a_record_whose_approval_attributes_contradict() {
    let mut storage = storage_with_values();
    change(&mut storage, &[set("API_URL", "fixture-mine")]).expect("set");
    storage
        .claims
        .insert(overrides_account(), ClaimedAccess::Contradictory);
    storage.reads.clear();

    let refused = {
        let _scope = crate::companion::LockScope::enter();
        crate::keychain::overrides::check_with_storage(
            &mut storage,
            VAULT,
            &[set("API_URL", "fixture-yours")],
        )
        .expect_err("damaged")
    };

    assert!(refused.contains("contradict"), "{refused}");
    assert_eq!(storage.reads.get(&overrides_account()).copied(), None);
}

#[test]
fn removing_overrides_from_a_project_without_values_changes_nothing_and_says_so() {
    let mut storage = MemoryProjectStorage::default();
    let _scope = crate::companion::LockScope::enter();
    let plan = crate::keychain::overrides::change_with_storage(
        &mut storage,
        VAULT,
        &[remove("API_URL"), Edit::ClearAll],
        crate::overrides::Expect::Nothing,
    )
    .expect("nothing to remove");
    assert!(plan.mutations.is_empty());
    assert!(matches!(
        plan.effects[..],
        [
            crate::companion::overrides::change::Effect::Key { changed: false, .. },
            crate::companion::overrides::change::Effect::Cleared { removed: 0, .. }
        ]
    ));
    assert_eq!(storage.values.keys().count(), 0);
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

/// A first override under values that need approval, on this Mac's own
/// Keychain. How many times macOS asks is what a person counts, which no
/// memory store shows. Run it with an empty LPM home, so it touches none of
/// this Mac's env projects:
///
/// ```text
/// LPM_HOME="$(mktemp -d)" LPM_RUN_KEYCHAIN_TESTS=1 scripts/build-signed-macos.sh --vault-tests -- \
///     keychain::tests::overrides::a_first_override_under_values_that_need_approval_asks_once_on_this_macs_keychain \
///     --ignored --exact --nocapture
/// ```
#[test]
#[ignore = "requires a signed macOS test bundle with the shared Keychain entitlement, an empty LPM_HOME and a person to approve"]
fn a_first_override_under_values_that_need_approval_asks_once_on_this_macs_keychain() {
    assert_eq!(std::env::var("LPM_RUN_KEYCHAIN_TESTS").as_deref(), Ok("1"));
    assert_ne!(
        service(),
        SERVICE,
        "set LPM_HOME to an empty folder, so the test touches none of this Mac's env projects"
    );
    struct RemoveEverything;
    impl Drop for RemoveEverything {
        fn drop(&mut self) {
            let service = service();
            if let Ok(accounts) = crate::macos_keychain::accounts_with_access(&service) {
                for (account, _) in accounts {
                    let _ = crate::macos_keychain::delete(&service, &account);
                }
            }
        }
    }
    let _cleanup = RemoveEverything;
    let mut storage = KeychainProjectStorage;
    save_vault_data_with_storage(&mut storage, VAULT, "Project", "/project", VALUES)
        .expect("create the project");
    storage
        .require_approval(VAULT, &[PROJECT_INDEX_MARKER_ACCOUNT])
        .expect("the values need approval");

    eprintln!(
        "\nmacOS asks to approve the first override now. Approve every prompt and count them: one is expected.\n"
    );
    let planned = {
        let _scope = crate::companion::LockScope::enter();
        crate::macos_keychain::prompting_for_personal_overrides(|| {
            recover_project_transaction(&mut storage)?;
            crate::keychain::overrides::change_with_storage(
                &mut storage,
                VAULT,
                &[set("API_URL", "fixture-mine")],
                crate::overrides::Expect::Nothing,
            )
        })
    }
    .expect("set the first override");
    assert!(planned.activated);
    assert_eq!(
        storage.probe(&overrides_account(), &[PROJECT_INDEX_MARKER_ACCOUNT]),
        ProbeOutcome::Protected,
        "the record takes the values' approval"
    );
    let read = {
        let _scope = crate::companion::LockScope::enter();
        crate::keychain::overrides::read_all_with_storage(&mut storage, VAULT)
    }
    .expect("read the overrides back without another approval");
    assert_eq!(read.0["default"].set["API_URL"], "fixture-mine");
}
