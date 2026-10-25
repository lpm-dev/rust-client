//! Companion storage through the Keychain journal, the gate and the read
//! that applies personal overrides.

use super::*;
use crate::companion::account::{marker_account, record_account, staged_account};
use crate::companion::gate::Operation;

fn run_read(storage: &mut MemoryProjectStorage) -> Result<companion_gate::RunRead, String> {
    companion_gate::read_for_run(storage, VAULT)
}

fn run_overrides(storage: &mut MemoryProjectStorage) -> Result<crate::PersonalOverrides, String> {
    let read = run_read(storage)?;
    crate::companion::overrides::evaluate(
        &read.gate,
        VAULT,
        "default",
        read.overrides_record.as_deref(),
    )
    .map_err(crate::companion::damaged)
}

const VAULT: &str = "proj";
const VALUES: &str = r#"{"environments":{"default":{"TOKEN":"team"}}}"#;

fn marker(features: &str, state: &str) -> String {
    format!(r#"{{"schemaVersion":1,"vaultId":"proj","state":"{state}","features":{{{features}}}}}"#)
}

const OVERRIDES_FEATURE: &str =
    r#""overrides":{"version":1,"ifUnsupported":"refuse","kinds":["overrides"],"state":"active"}"#;

fn overrides_record(set: &str) -> String {
    format!(
        r#"{{"schemaVersion":1,"vaultId":"proj","environments":{{"default":{{"set":{{{set}}},"unset":[]}}}}}}"#
    )
}

fn storage_with_values() -> MemoryProjectStorage {
    let mut storage = MemoryProjectStorage::default();
    save_vault_data_with_storage(&mut storage, VAULT, "Project", "/project", VALUES)
        .expect("create the project");
    storage
}

fn committed_journal(storage: &mut MemoryProjectStorage, operations: &[(&str, Option<&[u8]>)]) {
    let transaction_id = "00000000-0000-4000-8000-0000000000aa";
    let mut journal_operations = Vec::new();
    for (index, (target, value)) in operations.iter().enumerate() {
        match value {
            Some(value) => {
                let stage = transaction_stage_account(transaction_id, index);
                storage.values.insert(stage.clone(), value.to_vec());
                journal_operations.push(TransactionJournalOperation {
                    action: "write".to_owned(),
                    target_account: (*target).to_owned(),
                    staged_account: Some(stage),
                    operation_sha256: transaction_operation_sha256("write", target, Some(value)),
                });
            }
            None => journal_operations.push(TransactionJournalOperation {
                action: "delete".to_owned(),
                target_account: (*target).to_owned(),
                staged_account: None,
                operation_sha256: transaction_operation_sha256("delete", target, None),
            }),
        }
    }
    let journal = TransactionJournal {
        schema_version: TRANSACTION_SCHEMA_VERSION,
        transaction_id: transaction_id.to_owned(),
        state: TransactionState::Committed,
        operations: journal_operations,
    };
    storage.values.insert(
        TRANSACTION_MARKER_ACCOUNT,
        serde_json::to_vec(&journal).expect("encode the journal"),
    );
}

#[test]
fn committed_recovery_replays_binary_companion_records_byte_for_byte() {
    let mut storage = MemoryProjectStorage::default();
    let binary = [0_u8, 0xff, b'L', 0, 0xfe];
    let record = record_account("future-log", VAULT, Some(1));
    let marker = marker(
        r#""future":{"version":1,"ifUnsupported":"ignore","kinds":["future-log"],"state":"active"}"#,
        "active",
    );
    committed_journal(
        &mut storage,
        &[
            (&marker_account(VAULT), Some(marker.as_bytes())),
            (&record, Some(&binary)),
        ],
    );

    recover_project_transaction(&mut storage).expect("a committed companion journal recovers");

    assert_eq!(storage.values.get_bytes(&record), Some(&binary[..]));
    assert_eq!(
        storage.values.get(&marker_account(VAULT)),
        Some(marker.as_str())
    );
    assert!(!storage.values.contains_key(TRANSACTION_MARKER_ACCOUNT));
    assert!(
        !storage
            .values
            .keys()
            .any(|account| account.starts_with(TRANSACTION_STAGE_PREFIX))
    );
}

#[test]
fn committed_recovery_refuses_a_record_no_feature_lists() {
    let mut storage = MemoryProjectStorage::default();
    let record = record_account("future-log", VAULT, None);
    committed_journal(&mut storage, &[(&record, Some(b"orphan"))]);

    let error = recover_project_transaction(&mut storage).expect_err("I1 fails closed");

    assert!(error.contains("without a feature that lists it"), "{error}");
    assert!(!storage.values.contains_key(&record));
}

#[test]
fn committed_recovery_refuses_to_leave_records_without_their_marker() {
    let mut storage = MemoryProjectStorage::default();
    storage
        .values
        .insert(marker_account(VAULT), marker(OVERRIDES_FEATURE, "active"));
    storage.values.insert(
        record_account("overrides", VAULT, None),
        overrides_record(r#""A":"1""#),
    );
    committed_journal(&mut storage, &[(&marker_account(VAULT), None)]);

    let error = recover_project_transaction(&mut storage).expect_err("I2 fails closed");

    assert!(error.contains("would leave"), "{error}");
    assert!(storage.values.contains_key(&marker_account(VAULT)));
}

#[test]
fn committed_recovery_replays_over_a_stray_record_it_doesnt_touch() {
    let mut storage = MemoryProjectStorage::default();
    storage
        .values
        .insert(marker_account(VAULT), marker(OVERRIDES_FEATURE, "active"));
    let stray = record_account("future-kind", VAULT, None);
    storage.values.insert(stray.clone(), b"stray".to_vec());
    let overrides = record_account("overrides", VAULT, None);
    let record = overrides_record(r#""A":"1""#);
    committed_journal(&mut storage, &[(&overrides, Some(record.as_bytes()))]);

    recover_project_transaction(&mut storage).expect("damage it didn't cause doesn't block");

    assert_eq!(storage.values.get(&overrides), Some(record.as_str()));
    assert!(storage.values.contains_key(&stray));
    assert!(!storage.values.contains_key(TRANSACTION_MARKER_ACCOUNT));
}

#[test]
fn committed_recovery_finishes_a_marker_deletion_it_already_replayed() {
    let mut storage = MemoryProjectStorage::default();
    let overrides = record_account("overrides", VAULT, None);
    storage
        .values
        .insert(overrides.clone(), overrides_record(r#""A":"1""#));
    committed_journal(&mut storage, &[(&marker_account(VAULT), None)]);

    recover_project_transaction(&mut storage)
        .expect("refusing can't bring back a marker that's gone");

    assert!(!storage.values.contains_key(TRANSACTION_MARKER_ACCOUNT));
    assert!(storage.values.contains_key(&overrides));
}

#[test]
fn committed_recovery_deletes_a_marker_over_strays_it_didnt_list() {
    let mut storage = MemoryProjectStorage::default();
    storage
        .values
        .insert(marker_account(VAULT), marker(OVERRIDES_FEATURE, "active"));
    let overrides = record_account("overrides", VAULT, None);
    storage
        .values
        .insert(overrides.clone(), overrides_record(r#""A":"1""#));
    let stray = record_account("future-kind", VAULT, None);
    storage.values.insert(stray.clone(), b"stray".to_vec());
    committed_journal(
        &mut storage,
        &[(&overrides, None), (&marker_account(VAULT), None)],
    );

    recover_project_transaction(&mut storage).expect("the stray was unlisted before");

    assert!(!storage.values.contains_key(&marker_account(VAULT)));
    assert!(!storage.values.contains_key(&overrides));
    assert!(storage.values.contains_key(&stray));
}

#[test]
fn a_preparing_journal_without_all_its_stages_is_discarded_untouched() {
    let mut storage = MemoryProjectStorage::default();
    let record = record_account("overrides", VAULT, None);
    storage.values.insert(record.clone(), b"live".to_vec());
    let transaction_id = "00000000-0000-4000-8000-0000000000bb";
    let journal = TransactionJournal {
        schema_version: TRANSACTION_SCHEMA_VERSION,
        transaction_id: transaction_id.to_owned(),
        state: TransactionState::Preparing,
        operations: vec![
            TransactionJournalOperation {
                action: "write".to_owned(),
                target_account: marker_account(VAULT),
                staged_account: Some(transaction_stage_account(transaction_id, 0)),
                operation_sha256: transaction_operation_sha256(
                    "write",
                    &marker_account(VAULT),
                    Some(b"m"),
                ),
            },
            TransactionJournalOperation {
                action: "write".to_owned(),
                target_account: record.clone(),
                staged_account: Some(transaction_stage_account(transaction_id, 1)),
                operation_sha256: transaction_operation_sha256("write", &record, Some(b"new")),
            },
        ],
    };
    storage.values.insert(
        TRANSACTION_MARKER_ACCOUNT,
        serde_json::to_vec(&journal).expect("encode the journal"),
    );
    storage
        .values
        .insert(transaction_stage_account(transaction_id, 0), b"m".to_vec());

    assert_eq!(
        recover_project_transaction(&mut storage),
        Ok(TransactionRecovery::DiscardedPreparing)
    );
    assert_eq!(storage.values.get_bytes(&record), Some(&b"live"[..]));
    assert!(!storage.values.contains_key(&marker_account(VAULT)));
}

#[test]
fn writes_are_refused_while_a_feature_needs_a_newer_client() {
    let mut storage = storage_with_values();
    storage.values.insert(
        marker_account(VAULT),
        marker(
            r#""overrides":{"version":2,"ifUnsupported":"ignore","kinds":["overrides"],"state":"active"}"#,
            "active",
        ),
    );

    let error = save_vault_data_with_storage(
        &mut storage,
        VAULT,
        "Project",
        "/project",
        r#"{"environments":{"default":{"TOKEN":"changed"}}}"#,
    )
    .expect_err("an unsupported override version refuses");

    assert!(error.contains("doesn't support"), "{error}");
    assert_eq!(storage.values.get(VAULT), Some(VALUES));
}

#[test]
fn read_only_features_allow_reads_and_refuse_writes() {
    let mut storage = storage_with_values();
    storage.values.insert(
        marker_account(VAULT),
        marker(
            r#""future":{"version":1,"ifUnsupported":"readOnly","kinds":["future-log"],"state":"active"}"#,
            "active",
        ),
    );

    assert!(
        companion_gate::authorize(&mut storage, VAULT, Operation::ReadExcludingOverrides).is_ok()
    );
    assert!(run_overrides(&mut storage).is_ok());
    let error = companion_gate::authorize(&mut storage, VAULT, Operation::Write)
        .expect_err("read-only refuses writes");
    assert!(error.contains("can only read"), "{error}");
}

#[test]
fn a_damaged_marker_blocks_reads_and_writes_but_not_maintenance() {
    let mut storage = storage_with_values();
    storage
        .values
        .insert(marker_account(VAULT), r#"{"schemaVersion":1}"#);

    for operation in [
        Operation::ReadExcludingOverrides,
        Operation::ReadApplyingOverrides,
        Operation::Write,
    ] {
        let error = companion_gate::authorize(&mut storage, VAULT, operation)
            .expect_err("a damaged marker blocks");
        assert!(error.contains("damaged"), "{operation:?}: {error}");
    }
    assert!(companion_gate::authorize(&mut storage, VAULT, Operation::Maintenance).is_ok());
}

#[test]
fn a_deletion_left_unfinished_is_finished_before_a_write_and_keeps_the_new_values() {
    let mut storage = storage_with_values();
    storage
        .values
        .insert(marker_account(VAULT), marker(OVERRIDES_FEATURE, "deleting"));
    storage.values.insert(
        record_account("overrides", VAULT, None),
        overrides_record(r#""A":"1""#),
    );
    let changed = r#"{"environments":{"default":{"TOKEN":"recreated"}}}"#;

    save_vault_data_with_storage(&mut storage, VAULT, "Project", "/project", changed)
        .expect("the write finishes the deletion first");

    assert!(!storage.values.contains_key(&marker_account(VAULT)));
    assert!(
        !storage
            .values
            .contains_key(&record_account("overrides", VAULT, None))
    );
    assert_eq!(storage.values.get(VAULT), Some(changed));
}

#[test]
fn deleting_a_project_removes_its_companion_records_with_the_key_first() {
    let mut storage = storage_with_values();
    storage.values.insert(
        marker_account(VAULT),
        marker(
            &format!(
                r#"{OVERRIDES_FEATURE},"history":{{"version":1,"ifUnsupported":"ignore","kinds":["history-head","history","key"],"state":"active"}}"#
            ),
            "active",
        ),
    );
    storage.values.insert(
        record_account("overrides", VAULT, None),
        overrides_record(r#""A":"1""#),
    );
    storage
        .values
        .insert(record_account("key", VAULT, None), vec![7_u8; 58]);
    storage.values.insert(
        record_account("history-head", VAULT, None),
        b"head".to_vec(),
    );
    for part in 0..16 {
        storage.values.insert(
            record_account("history", VAULT, Some(part)),
            vec![part as u8; 64],
        );
    }
    storage.deletes.clear();

    delete_vault_with_storage(&mut storage, VAULT).expect("delete the project");

    assert!(!storage.values.contains_key(VAULT));
    assert!(
        !storage
            .values
            .keys()
            .any(|account| crate::companion::account::is_in_companion_namespace(account)),
        "{:?}",
        storage.values.keys().collect::<Vec<_>>()
    );
    assert_eq!(
        storage.deletes.get(&record_account("key", VAULT, None)),
        Some(&1)
    );
}

#[test]
fn deleting_a_project_whose_records_fit_one_transaction_writes_no_deleting_marker() {
    let mut storage = storage_with_values();
    storage
        .values
        .insert(marker_account(VAULT), marker(OVERRIDES_FEATURE, "active"));
    storage.values.insert(
        record_account("overrides", VAULT, None),
        overrides_record(r#""A":"1""#),
    );
    storage.writes.clear();

    delete_vault_with_storage(&mut storage, VAULT).expect("delete the project");

    assert!(!storage.values.contains_key(VAULT));
    assert!(!storage.values.contains_key(&marker_account(VAULT)));
    assert!(
        !storage
            .values
            .contains_key(&record_account("overrides", VAULT, None))
    );
    assert_eq!(storage.writes.get(&marker_account(VAULT)), None);
}

#[test]
fn deleting_a_project_with_parts_and_no_valid_marker_finishes() {
    for marker_value in [None, Some(r#"{"schemaVersion":1}"#)] {
        let mut storage = storage_with_values();
        if let Some(marker_value) = marker_value {
            storage.values.insert(marker_account(VAULT), marker_value);
        }
        storage
            .values
            .insert(record_account("future-kind", VAULT, None), b"x".to_vec());
        for part in 0..40 {
            storage.values.insert(
                record_account("future-log", VAULT, Some(part)),
                vec![part as u8; 64],
            );
        }

        delete_vault_with_storage(&mut storage, VAULT).expect("delete the project");

        assert!(!storage.values.contains_key(VAULT));
        assert!(
            !storage
                .values
                .keys()
                .any(|account| crate::companion::account::is_in_companion_namespace(account)),
            "{marker_value:?}: {:?}",
            storage.values.keys().collect::<Vec<_>>()
        );
    }
}

#[test]
fn applying_overrides_reads_the_record_even_without_a_marker() {
    let mut storage = storage_with_values();
    storage.values.insert(
        record_account("overrides", VAULT, None),
        overrides_record(r#""A":"1""#),
    );

    let error = run_overrides(&mut storage).expect_err("markerless overrides are damage");

    assert!(error.contains("belongs to no feature"), "{error}");
    assert!(
        companion_gate::authorize(&mut storage, VAULT, Operation::ReadExcludingOverrides).is_ok()
    );
}

#[test]
fn applying_overrides_fails_when_the_marker_lists_a_missing_record() {
    let mut storage = storage_with_values();
    storage
        .values
        .insert(marker_account(VAULT), marker(OVERRIDES_FEATURE, "active"));

    let error = run_overrides(&mut storage).expect_err("a missing required record is damage");

    assert!(error.contains(r#"missing record "overrides""#), "{error}");
}

#[test]
fn applying_overrides_returns_the_selected_environment_with_the_values() {
    let mut storage = storage_with_values();
    storage
        .values
        .insert(marker_account(VAULT), marker(OVERRIDES_FEATURE, "active"));
    storage.values.insert(
        record_account("overrides", VAULT, None),
        overrides_record(r#""TOKEN":"mine""#),
    );

    let values = run_read(&mut storage).expect("apply read").values;
    let overrides = run_overrides(&mut storage).expect("apply read");

    assert_eq!(values.as_deref(), Some(VALUES.as_bytes()));
    assert_eq!(overrides.set["TOKEN"], "mine");
}

#[test]
fn weaker_overrides_under_approved_values_are_strengthened_before_use() {
    let mut storage = storage_with_values();
    let overrides = record_account("overrides", VAULT, None);
    storage
        .values
        .insert(marker_account(VAULT), marker(OVERRIDES_FEATURE, "active"));
    storage
        .values
        .insert(overrides.clone(), overrides_record(r#""TOKEN":"mine""#));
    storage
        .claims
        .insert(VAULT.to_owned(), ClaimedAccess::RequireApproval);
    storage.protected.insert(VAULT.to_owned());

    run_overrides(&mut storage).expect("apply read");

    assert_eq!(storage.approvals_required, std::slice::from_ref(&overrides));
    assert!(storage.protected.contains(&overrides));
}

#[test]
fn an_unavailable_keychain_returns_no_override_bytes_and_records_nothing() {
    let mut storage = storage_with_values();
    storage
        .values
        .insert(marker_account(VAULT), marker(OVERRIDES_FEATURE, "active"));
    storage.values.insert(
        record_account("overrides", VAULT, None),
        overrides_record(r#""TOKEN":"mine""#),
    );
    storage
        .claims
        .insert(VAULT.to_owned(), ClaimedAccess::RequireApproval);
    storage.protected.insert(VAULT.to_owned());
    storage.keychain_unavailable = true;

    let error = run_overrides(&mut storage).expect_err("an inconclusive probe fails");

    assert!(error.contains("retry once the Mac is unlocked"), "{error}");
    assert!(storage.approvals_required.is_empty());
}

#[test]
fn contradictory_override_approval_is_damage() {
    let mut storage = storage_with_values();
    let overrides = record_account("overrides", VAULT, None);
    storage
        .values
        .insert(marker_account(VAULT), marker(OVERRIDES_FEATURE, "active"));
    storage
        .values
        .insert(overrides.clone(), overrides_record(r#""TOKEN":"mine""#));
    storage
        .claims
        .insert(overrides, ClaimedAccess::Contradictory);

    let error =
        run_overrides(&mut storage).expect_err("contradictory approval attributes are damage");

    assert!(error.contains("contradict"), "{error}");
}

fn activating_restore(storage: &mut MemoryProjectStorage) {
    let restore = r#""restore":{"phase":"activating","replaces":[],"features":{"overrides":{"version":1,"ifUnsupported":"refuse","kinds":["overrides"],"state":"active"}}}"#;
    storage.values.insert(
        marker_account(VAULT),
        format!(
            r#"{{"schemaVersion":1,"vaultId":"proj","state":"restoring","features":{{}},{restore}}}"#
        ),
    );
    storage.values.insert(
        staged_account("overrides", VAULT, None),
        overrides_record(r#""TOKEN":"restored""#),
    );
}

#[test]
fn restored_records_that_follow_values_take_the_values_verified_approval() {
    let mut storage = storage_with_values();
    activating_restore(&mut storage);
    storage
        .claims
        .insert(VAULT.to_owned(), ClaimedAccess::RequireApproval);
    storage.protected.insert(VAULT.to_owned());

    companion_gate::authorize(&mut storage, VAULT, Operation::Maintenance)
        .expect("the restore finishes");

    let live = record_account("overrides", VAULT, None);
    assert!(storage.protected.contains(&live));
    assert!(storage.values.contains_key(&live));
    assert!(
        !storage
            .values
            .contains_key(&staged_account("overrides", VAULT, None))
    );
}

#[test]
fn values_that_claim_approval_without_it_get_it_before_their_records_are_staged() {
    let mut storage = storage_with_values();
    activating_restore(&mut storage);
    storage
        .claims
        .insert(VAULT.to_owned(), ClaimedAccess::RequireApproval);

    companion_gate::authorize(&mut storage, VAULT, Operation::Maintenance)
        .expect("the restore finishes");

    assert!(
        storage.protected.contains(VAULT),
        "the values get the approval they claim"
    );
    assert!(
        storage
            .protected
            .contains(&record_account("overrides", VAULT, None))
    );
}

#[test]
fn values_whose_approval_attributes_contradict_each_other_are_reported() {
    let mut storage = storage_with_values();
    activating_restore(&mut storage);
    storage
        .claims
        .insert(VAULT.to_owned(), ClaimedAccess::Contradictory);

    let warnings = crate::test_tracing::warnings(|| {
        companion_gate::authorize(&mut storage, VAULT, Operation::Maintenance)
            .expect("the restore finishes");
    });

    assert!(
        warnings.contains(
            "this env project's values have approval attributes that contradict each other"
        ),
        "{warnings}"
    );
    assert!(
        !storage.protected.contains(VAULT),
        "an unclear claim isn't enforced"
    );
    assert!(
        storage
            .protected
            .contains(&record_account("overrides", VAULT, None))
    );
}

#[test]
fn records_that_follow_values_cant_be_written_for_a_project_without_values() {
    let mut storage = MemoryProjectStorage::default();
    activating_restore(&mut storage);

    let error = companion_gate::authorize(&mut storage, VAULT, Operation::Maintenance)
        .expect_err("no values item to follow");

    assert!(error.contains("has no values"), "{error}");
}

#[test]
fn one_lock_scope_reads_a_project_marker_once() {
    let mut storage = storage_with_values();
    storage
        .values
        .insert(marker_account(VAULT), marker(OVERRIDES_FEATURE, "active"));
    storage.values.insert(
        record_account("overrides", VAULT, None),
        overrides_record(r#""A":"1""#),
    );
    storage.reads.clear();

    {
        let _scope = crate::companion::LockScope::enter();
        companion_gate::authorize(&mut storage, VAULT, Operation::ReadExcludingOverrides)
            .expect("read");
        companion_gate::authorize(&mut storage, VAULT, Operation::Write).expect("write");
    }

    assert_eq!(storage.reads.get(&marker_account(VAULT)), Some(&1));
}

#[test]
fn a_healthy_apply_read_reads_the_marker_values_and_overrides_once_each_and_never_probes() {
    let mut storage = storage_with_values();
    storage
        .values
        .insert(marker_account(VAULT), marker(OVERRIDES_FEATURE, "active"));
    storage.values.insert(
        record_account("overrides", VAULT, None),
        overrides_record(r#""A":"1""#),
    );
    storage.reads.clear();

    run_overrides(&mut storage).expect("apply read");

    let reads = |account: &str| storage.reads.get(account).copied().unwrap_or(0);
    assert_eq!(reads(&marker_account(VAULT)), 1);
    assert_eq!(reads(VAULT), 1);
    assert_eq!(reads(&record_account("overrides", VAULT, None)), 1);
    assert_eq!(storage.reads.values().sum::<usize>(), 3);
    assert!(storage.probes.is_empty());
    assert_eq!(storage.listings, 0);
}

#[test]
fn an_apply_read_without_overrides_still_reads_their_account_once() {
    let mut storage = storage_with_values();
    storage.reads.clear();

    run_overrides(&mut storage).expect("apply read");

    assert_eq!(
        storage
            .reads
            .get(&record_account("overrides", VAULT, None))
            .copied(),
        Some(1)
    );
    assert_eq!(storage.reads.values().sum::<usize>(), 3);
}

#[test]
fn a_values_write_adds_one_marker_read_and_no_probe_or_listing() {
    let mut storage = storage_with_values();
    storage.reads.clear();

    save_vault_data_with_storage(
        &mut storage,
        VAULT,
        "Project",
        "/project",
        r#"{"environments":{"default":{"TOKEN":"changed"}}}"#,
    )
    .expect("write values");

    assert_eq!(storage.reads.get(&marker_account(VAULT)).copied(), Some(1));
    assert!(storage.probes.is_empty());
    assert_eq!(storage.listings, 0);
}

#[test]
fn a_commit_refuses_to_leave_records_without_their_marker() {
    let mut storage = storage_with_values();
    storage
        .values
        .insert(marker_account(VAULT), marker(OVERRIDES_FEATURE, "active"));
    storage.values.insert(
        record_account("overrides", VAULT, None),
        overrides_record(r#""A":"1""#),
    );

    let error = apply_project_transaction(
        &mut storage,
        vec![ProjectStorageMutation::delete(marker_account(VAULT))],
    )
    .expect_err("a commit is checked as recovery would check it");

    assert!(error.contains("would leave"), "{error}");
    assert!(storage.values.contains_key(&marker_account(VAULT)));
    assert!(!storage.values.contains_key(TRANSACTION_MARKER_ACCOUNT));
}

#[test]
fn committed_recovery_reads_a_staged_marker_no_more_than_a_staged_record() {
    let mut storage = MemoryProjectStorage::default();
    let marker = marker(OVERRIDES_FEATURE, "active");
    let overrides = overrides_record(r#""A":"1""#);
    committed_journal(
        &mut storage,
        &[
            (&marker_account(VAULT), Some(marker.as_bytes())),
            (
                &record_account("overrides", VAULT, None),
                Some(overrides.as_bytes()),
            ),
        ],
    );
    let stage = |index| transaction_stage_account("00000000-0000-4000-8000-0000000000aa", index);

    recover_project_transaction(&mut storage).expect("a committed journal recovers");

    assert_eq!(
        storage.reads.get(&stage(0)),
        storage.reads.get(&stage(1)),
        "each stage is read for its bytes, then to confirm it's gone"
    );
}

#[test]
fn a_transaction_writes_no_more_than_its_payload_limit() {
    let mut storage = storage_with_values();
    let marker = marker(
        r#""future":{"version":1,"ifUnsupported":"ignore","kinds":["future-log"],"state":"active"}"#,
        "active",
    );
    let mut mutations = vec![ProjectStorageMutation::write(
        marker_account(VAULT),
        marker.into_bytes(),
    )];
    mutations.extend((0..11).map(|part| {
        ProjectStorageMutation::write(
            record_account("future-log", VAULT, Some(part)),
            vec![b'x'; 100 * 1024],
        )
    }));

    let error = apply_project_transaction(&mut storage, mutations)
        .expect_err("1,126,400 bytes is too many");

    assert!(error.contains("too many bytes"), "{error}");
    assert!(!storage.values.contains_key(&marker_account(VAULT)));
    assert!(!storage.values.contains_key(TRANSACTION_MARKER_ACCOUNT));
}

#[test]
fn every_read_refuses_values_whose_approval_contradicts_itself() {
    let mut storage = storage_with_values();
    storage
        .claims
        .insert(VAULT.to_owned(), ClaimedAccess::Contradictory);

    for error in [
        companion_gate::read_values_excluding_overrides(&mut storage, VAULT)
            .map(|_| ())
            .expect_err("an Exclude read"),
        run_read(&mut storage)
            .map(|_| ())
            .expect_err("an Apply read"),
    ] {
        assert!(error.contains("CLI approval is damaged"), "{error}");
    }
}

#[test]
fn deleting_a_project_lists_the_service_once_however_many_transactions_it_takes() {
    let mut storage = storage_with_values();
    storage.values.insert(
        marker_account(VAULT),
        marker(
            r#""future":{"version":1,"ifUnsupported":"ignore","kinds":["future-log"],"state":"active"}"#,
            "active",
        ),
    );
    for part in 0..80 {
        storage.values.insert(
            record_account("future-log", VAULT, Some(part)),
            vec![part as u8; 64],
        );
    }
    storage.listings = 0;

    delete_vault_with_storage(&mut storage, VAULT).expect("delete the project");

    assert!(
        !storage
            .values
            .keys()
            .any(|account| crate::companion::account::is_in_companion_namespace(account))
    );
    assert_eq!(storage.listings, 1);
}

#[test]
fn a_missing_record_is_reviewed_and_repaired_by_removing_its_feature() {
    use crate::companion::repair::CompanionRepair;
    let mut storage = storage_with_values();
    storage
        .values
        .insert(marker_account(VAULT), marker(OVERRIDES_FEATURE, "active"));

    let review = review_companion_data_with_storage(&mut storage, VAULT).expect("a review");
    assert_eq!(review.problems.len(), 1);
    assert_eq!(
        review.problems[0].description,
        "missing record \"overrides\""
    );
    assert_eq!(
        review.problems[0].repair,
        Some(CompanionRepair::RemoveFeature("overrides".to_owned()))
    );

    let repaired =
        repair_companion_data_with_storage(&mut storage, VAULT, &review).expect("the repair");

    assert_eq!(
        repaired,
        [CompanionRepair::RemoveFeature("overrides".to_owned())]
    );
    assert!(!storage.values.contains_key(&marker_account(VAULT)));
    assert!(
        review_companion_data_with_storage(&mut storage, VAULT)
            .expect("a review")
            .problems
            .is_empty()
    );
    run_overrides(&mut storage).expect("overrides apply again");
}

#[test]
fn a_repair_refuses_a_project_that_changed_since_its_review() {
    let mut storage = storage_with_values();
    storage
        .values
        .insert(marker_account(VAULT), marker(OVERRIDES_FEATURE, "active"));
    let review = review_companion_data_with_storage(&mut storage, VAULT).expect("a review");
    let overrides = record_account("overrides", VAULT, None);
    storage
        .values
        .insert(overrides.clone(), overrides_record(r#""A":"1""#));

    let error = repair_companion_data_with_storage(&mut storage, VAULT, &review)
        .expect_err("the reviewed damage is gone");

    assert!(error.contains("changed since you reviewed it"), "{error}");
    assert!(storage.values.contains_key(&overrides));
    assert!(storage.values.contains_key(&marker_account(VAULT)));
}

#[test]
fn damaged_access_is_reviewed_with_no_repair_here() {
    let mut storage = storage_with_values();
    storage
        .claims
        .insert(VAULT.to_owned(), ClaimedAccess::Contradictory);

    let review = review_companion_data_with_storage(&mut storage, VAULT).expect("a review");

    assert_eq!(review.problems.len(), 1);
    assert_eq!(review.problems[0].repair, None);
    assert!(review.repairs().is_empty());
    assert_eq!(
        repair_companion_data_with_storage(&mut storage, VAULT, &review).expect("nothing to run"),
        []
    );
}

#[test]
fn every_journal_fixture_recovers_as_recorded() {
    use base64::Engine as _;
    use std::collections::BTreeMap;

    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Fixture {
        journal_account: String,
        cases: Vec<Case>,
    }
    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Case {
        name: String,
        before: BTreeMap<String, String>,
        journal: serde_json::Value,
        outcome: String,
        #[serde(default)]
        after: BTreeMap<String, String>,
        #[serde(default)]
        refusal: Option<String>,
    }
    let decode = |value: &str| {
        base64::engine::general_purpose::STANDARD
            .decode(value)
            .expect("fixture bytes are base64")
    };
    let fixture: Fixture = serde_json::from_str(include_str!(
        "../../../../lpm-env-companion/tests/fixtures/journals.json"
    ))
    .expect("the journal fixture decodes");
    assert_eq!(fixture.journal_account, TRANSACTION_MARKER_ACCOUNT);
    for case in fixture.cases {
        let mut storage = MemoryProjectStorage::default();
        for (account, value) in &case.before {
            storage.values.insert(account.clone(), decode(value));
        }
        storage.values.insert(
            TRANSACTION_MARKER_ACCOUNT,
            serde_json::to_vec(&case.journal).expect("encode the journal"),
        );

        let result = recover_project_transaction(&mut storage);

        match case.outcome.as_str() {
            "recovers" => {
                result.unwrap_or_else(|error| panic!("{}: {error}", case.name));
                let left: BTreeMap<String, Vec<u8>> = storage
                    .values
                    .keys()
                    .map(|account| {
                        (
                            account.to_owned(),
                            storage
                                .values
                                .get_bytes(account)
                                .unwrap_or_default()
                                .to_vec(),
                        )
                    })
                    .collect();
                let expected: BTreeMap<String, Vec<u8>> = case
                    .after
                    .iter()
                    .map(|(account, value)| (account.clone(), decode(value)))
                    .collect();
                assert_eq!(left, expected, "{}", case.name);
            }
            "refuses" => {
                let error = result.map(|_| ()).expect_err(&case.name);
                let refusal = case.refusal.as_deref().unwrap_or_default();
                assert!(error.contains(refusal), "{}: {error}", case.name);
                assert!(
                    storage.values.contains_key(TRANSACTION_MARKER_ACCOUNT),
                    "{}",
                    case.name
                );
            }
            other => panic!("{}: unknown outcome {other}", case.name),
        }
    }
}

#[test]
fn a_deletion_that_fails_after_any_mutation_finishes_on_the_next_one() {
    let storage = || {
        let mut storage = storage_with_values();
        storage.values.insert(
            marker_account(VAULT),
            marker(
                &format!(
                    r#"{OVERRIDES_FEATURE},"future":{{"version":1,"ifUnsupported":"ignore","kinds":["future-log"],"state":"active"}}"#
                ),
                "active",
            ),
        );
        storage.values.insert(
            record_account("overrides", VAULT, None),
            overrides_record(r#""A":"1""#),
        );
        for part in 0..40 {
            storage.values.insert(
                record_account("future-log", VAULT, Some(part)),
                vec![part as u8; 64],
            );
        }
        storage.mutation_attempts = 0;
        storage
    };
    let mut uninterrupted = storage();
    delete_vault_with_storage(&mut uninterrupted, VAULT).expect("delete the project");
    let mutations = uninterrupted.mutation_attempts;
    assert!(mutations > 0);

    for failure_point in 1..=mutations {
        let mut storage = storage();
        storage.fail_once_at_mutation = Some(failure_point);
        let _ = delete_vault_with_storage(&mut storage, VAULT);
        assert!(storage.injected_failure, "{failure_point}");
        storage.fail_once_at_mutation = None;

        delete_vault_with_storage(&mut storage, VAULT)
            .unwrap_or_else(|error| panic!("{failure_point}: {error}"));

        assert!(!storage.values.contains_key(VAULT), "{failure_point}");
        assert!(
            !storage.values.keys().any(|account| {
                crate::companion::account::is_in_companion_namespace(account)
                    || account.starts_with(TRANSACTION_STAGE_PREFIX)
                    || account == TRANSACTION_MARKER_ACCOUNT
            }),
            "{failure_point}: {:?}",
            storage.values.keys().collect::<Vec<_>>()
        );
    }
}
