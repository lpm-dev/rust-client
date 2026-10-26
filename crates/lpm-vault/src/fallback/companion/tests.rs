use std::collections::HashMap;

use super::*;
use crate::fallback::tests::{force_file_vault, with_temp_vault_home};
use crate::storage_transaction::{DIRECTORY_SYNCS, with_vault_transaction};

const VAULT: &str = "proj";

fn marker_with_overrides() -> Vec<u8> {
    br#"{"schemaVersion":1,"vaultId":"proj","state":"active","features":{"overrides":{"version":1,"ifUnsupported":"refuse","kinds":["overrides"],"state":"active"}}}"#.to_vec()
}

fn overrides(set: &str) -> Vec<u8> {
    format!(
        r#"{{"schemaVersion":1,"vaultId":"proj","environments":{{"default":{{"set":{{{set}}},"unset":[]}}}}}}"#
    )
    .into_bytes()
}

fn marker_account() -> CompanionAccount {
    CompanionAccount::Marker {
        vault_id: VAULT.to_owned(),
    }
}

fn record(kind: &str, part: Option<u16>) -> CompanionAccount {
    CompanionAccount::Record {
        kind: kind.to_owned(),
        vault_id: VAULT.to_owned(),
        part,
    }
}

fn commit(mutations: Vec<Mutation>) {
    with_vault_transaction(|directory| FileCompanion::open(directory)?.commit(mutations))
        .expect("commit companion records");
}

fn write(account: CompanionAccount, value: Vec<u8>) -> Mutation {
    Mutation::Write { account, value }
}

fn seed_values() {
    crate::fallback::write_all_environments(
        VAULT,
        &HashMap::from([(
            "default".to_owned(),
            HashMap::from([("TOKEN".to_owned(), "team".to_owned())]),
        )]),
    )
    .expect("write values");
}

fn vaults_path(home: &std::path::Path) -> std::path::PathBuf {
    home.join(".lpm").join("vaults")
}

#[test]
fn entry_names_stay_clear_of_windows_device_names_and_round_trip() {
    for (account, name) in [
        (marker_account(), "features"),
        (record("con", None), "record.con"),
        (record("nul", Some(0)), "record.nul.000"),
        (
            CompanionAccount::Staged {
                kind: "com1".to_owned(),
                vault_id: VAULT.to_owned(),
                part: Some(0xabc),
            },
            "staged.com1.abc",
        ),
    ] {
        assert_eq!(entry_name(&account), name);
        assert_eq!(parse_entry_name(VAULT, name), Some(account));
    }
    for invalid in [
        "con",
        "record.",
        "record.Con",
        "record.con.0",
        "record.con.ABC",
        "record.features",
        "staged.history.000.001",
        "other.thing",
    ] {
        assert_eq!(parse_entry_name(VAULT, invalid), None, "{invalid}");
    }
}

#[test]
fn sealed_entries_open_only_as_the_account_they_were_sealed_for() {
    let key = [9_u8; 32];
    let sealed = seal(&key, &record("overrides", None), b"secret").expect("seal");
    assert_eq!(
        open(&key, &record("overrides", None), sealed.clone()).expect("open"),
        b"secret"
    );
    assert!(open(&key, &record("notes", None), sealed.clone()).is_err());
    assert!(open(&[8_u8; 32], &record("overrides", None), sealed.clone()).is_err());
    let other_project = CompanionAccount::Record {
        kind: "overrides".to_owned(),
        vault_id: "other".to_owned(),
        part: None,
    };
    assert!(open(&key, &other_project, sealed).is_err());
}

#[test]
fn a_run_read_applies_overrides_from_the_file_store() {
    with_temp_vault_home(|_| {
        force_file_vault();
        seed_values();
        commit(vec![
            write(marker_account(), marker_with_overrides()),
            write(record("overrides", None), overrides(r#""TOKEN":"mine""#)),
        ]);

        let run = crate::try_get_run_environment_for_vault_id(VAULT, None).expect("run read");

        assert_eq!(run.values["TOKEN"], "team");
        assert_eq!(run.overrides.set["TOKEN"], "mine");
    });
}

#[test]
fn overrides_without_a_marker_fail_a_run_read_but_not_a_plain_read() {
    with_temp_vault_home(|_| {
        force_file_vault();
        seed_values();
        with_vault_transaction(|directory| {
            commit_unchecked(
                directory,
                VAULT,
                vec![write(record("overrides", None), overrides(r#""A":"1""#))],
            )
        })
        .expect("seed a markerless record");

        let error = crate::try_get_run_environment_for_vault_id(VAULT, None)
            .expect_err("markerless overrides are damage");
        assert!(error.contains("belongs to no feature"), "{error}");
        assert_eq!(
            crate::try_get_all_env_for_vault_id(VAULT, "default").expect("plain read")["TOKEN"],
            "team"
        );
    });
}

#[test]
fn one_run_read_loads_the_data_key_once() {
    with_temp_vault_home(|_| {
        force_file_vault();
        seed_values();
        commit(vec![
            write(marker_account(), marker_with_overrides()),
            write(record("overrides", None), overrides(r#""TOKEN":"mine""#)),
        ]);
        crate::fallback::DATA_KEY_LOADS.with(|loads| loads.set(0));

        crate::try_get_run_environment_for_vault_id(VAULT, None).expect("run read");

        assert_eq!(
            crate::fallback::DATA_KEY_LOADS.with(std::cell::Cell::get),
            1
        );
    });
}

#[test]
fn a_commit_syncs_each_changed_folder_once_and_leaves_no_journal() {
    with_temp_vault_home(|home| {
        force_file_vault();
        seed_values();
        DIRECTORY_SYNCS.with(|syncs| syncs.borrow_mut().clear());

        commit(vec![
            write(marker_account(), marker_with_overrides()),
            write(record("overrides", None), overrides(r#""A":"1""#)),
        ]);

        let vaults = vaults_path(home);
        let folder = vaults.join(companion_folder_name(VAULT));
        let syncs = DIRECTORY_SYNCS.with(|syncs| syncs.borrow().clone());
        let stage_syncs = syncs
            .iter()
            .filter(|path| path.ends_with(stage_folder_name(VAULT)))
            .count();
        let folder_syncs = syncs.iter().filter(|path| **path == folder).count();
        let vaults_syncs = syncs.iter().filter(|path| **path == vaults).count();
        assert_eq!(
            (stage_syncs, folder_syncs, vaults_syncs),
            (1, 1, 3),
            "{syncs:?}"
        );
        assert!(!vaults.join(journal_name(VAULT)).exists());
        assert!(!vaults.join(stage_folder_name(VAULT)).exists());
    });
}

fn journal_path(home: &std::path::Path, vault_id: &str) -> std::path::PathBuf {
    vaults_path(home).join(journal_name(vault_id))
}

fn write_journal(home: &std::path::Path, journal: &FileJournal) {
    write_project_journal(home, VAULT, journal);
}

fn write_project_journal(home: &std::path::Path, vault_id: &str, journal: &FileJournal) {
    let path = journal_path(home, vault_id);
    std::fs::write(&path, serde_json::to_vec(journal).expect("encode journal"))
        .expect("write journal");
    set_owner_only(&path);
}

fn marker_of(vault_id: &str, features: &str) -> Vec<u8> {
    format!(
        r#"{{"schemaVersion":1,"vaultId":"{vault_id}","state":"active","features":{{{features}}}}}"#
    )
    .into_bytes()
}

const OVERRIDES_FEATURE: &str =
    r#""overrides":{"version":1,"ifUnsupported":"refuse","kinds":["overrides"],"state":"active"}"#;

fn set_owner_only(path: &std::path::Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).expect("chmod");
    }
    #[cfg(not(unix))]
    let _ = path;
}

fn digest_of(path: &std::path::Path) -> Option<String> {
    std::fs::read(path).ok().map(|bytes| sha256_hex(&bytes))
}

#[test]
fn recovery_finishes_a_deletion_of_both_value_files_after_a_crash_between_them() {
    with_temp_vault_home(|home| {
        force_file_vault();
        seed_values();
        let vaults = vaults_path(home);
        let digest_file = vaults.join(crate::fallback::vault_file_name(VAULT));
        let legacy_file = vaults.join(format!("{VAULT}.enc"));
        std::fs::copy(&digest_file, &legacy_file).expect("seed a legacy copy");
        set_owner_only(&legacy_file);
        let journal = FileJournal {
            schema_version: FILE_JOURNAL_SCHEMA_VERSION,
            transaction_id: "0123456789abcdef0123456789abcdef".to_owned(),
            operations: vec![
                FileOperation {
                    action: FileAction::Delete,
                    target: VAULT.to_owned(),
                    values_file: Some(ValuesFile::Digest),
                    before: digest_of(&digest_file),
                    after: None,
                },
                FileOperation {
                    action: FileAction::Delete,
                    target: VAULT.to_owned(),
                    values_file: Some(ValuesFile::Legacy),
                    before: digest_of(&legacy_file),
                    after: None,
                },
            ],
        };
        write_journal(home, &journal);
        std::fs::remove_file(&digest_file).expect("crash after the first removal");

        assert_eq!(
            crate::try_get_all_env_for_vault_id(VAULT, "default").expect("recovered read"),
            HashMap::new()
        );
        assert!(!legacy_file.exists(), "deleted values must not come back");
        assert!(!journal_path(home, VAULT).exists());
    });
}

#[test]
fn recovery_keeps_values_an_older_cli_rewrote_after_the_crash() {
    with_temp_vault_home(|home| {
        force_file_vault();
        seed_values();
        let vaults = vaults_path(home);
        let digest_file = vaults.join(crate::fallback::vault_file_name(VAULT));
        let journal = FileJournal {
            schema_version: FILE_JOURNAL_SCHEMA_VERSION,
            transaction_id: "0123456789abcdef0123456789abcdee".to_owned(),
            operations: vec![FileOperation {
                action: FileAction::Delete,
                target: VAULT.to_owned(),
                values_file: Some(ValuesFile::Digest),
                before: Some("0".repeat(64)),
                after: None,
            }],
        };
        write_journal(home, &journal);

        assert_eq!(
            crate::try_get_all_env_for_vault_id(VAULT, "default").expect("recovered read")["TOKEN"],
            "team"
        );
        assert!(digest_file.exists());
    });
}

#[test]
fn recovery_fails_closed_when_a_companion_entry_changed_outside_the_journal() {
    with_temp_vault_home(|home| {
        force_file_vault();
        seed_values();
        commit(vec![
            write(marker_account(), marker_with_overrides()),
            write(record("overrides", None), overrides(r#""A":"1""#)),
        ]);
        let journal = FileJournal {
            schema_version: FILE_JOURNAL_SCHEMA_VERSION,
            transaction_id: "0123456789abcdef0123456789abcded".to_owned(),
            operations: vec![FileOperation {
                action: FileAction::Delete,
                target: record("overrides", None).name(),
                values_file: None,
                before: Some("0".repeat(64)),
                after: None,
            }],
        };
        write_journal(home, &journal);

        let error = crate::try_get_all_env_for_vault_id(VAULT, "default")
            .expect_err("a foreign companion change is damage");
        assert!(error.contains("changed outside"), "{error}");
        assert!(journal_path(home, VAULT).exists());
    });
}

#[test]
fn recovery_replays_over_a_stray_record_it_doesnt_touch() {
    with_temp_vault_home(|home| {
        force_file_vault();
        seed_values();
        commit(vec![
            write(
                marker_account(),
                br#"{"schemaVersion":1,"vaultId":"proj","state":"active","features":{"overrides":{"version":1,"ifUnsupported":"refuse","kinds":["overrides"],"state":"active"},"future":{"version":1,"ifUnsupported":"ignore","kinds":["future-kind"],"state":"active"}}}"#.to_vec(),
            ),
            write(record("overrides", None), overrides(r#""A":"1""#)),
            write(record("future-kind", None), b"stray".to_vec()),
        ]);
        with_vault_transaction(|directory| {
            commit_unchecked(
                directory,
                VAULT,
                vec![write(marker_account(), marker_with_overrides())],
            )
        })
        .expect("leave the future record without its feature");
        let folder = vaults_path(home).join(companion_folder_name(VAULT));
        let overrides_entry = folder.join(entry_name(&record("overrides", None)));
        let journal = FileJournal {
            schema_version: FILE_JOURNAL_SCHEMA_VERSION,
            transaction_id: "0123456789abcdef0123456789abcdec".to_owned(),
            operations: vec![FileOperation {
                action: FileAction::Delete,
                target: record("overrides", None).name(),
                values_file: None,
                before: digest_of(&overrides_entry),
                after: None,
            }],
        };
        write_journal(home, &journal);

        with_vault_transaction(|directory| {
            FileCompanion::open(directory)?
                .recover(VAULT)
                .map_err(RecoveryError::into_message)
        })
        .expect("damage the journal didn't cause doesn't block");

        assert!(!overrides_entry.exists());
        assert!(
            folder
                .join(entry_name(&record("future-kind", None)))
                .exists()
        );
        assert!(!journal_path(home, VAULT).exists());
    });
}

#[test]
fn stages_without_a_journal_are_swept() {
    with_temp_vault_home(|home| {
        force_file_vault();
        seed_values();
        let stage = vaults_path(home).join(stage_folder_name(VAULT));
        std::fs::create_dir(&stage).expect("create stage folder");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&stage, std::fs::Permissions::from_mode(0o700))
                .expect("chmod");
        }
        std::fs::write(
            stage.join("0123456789abcdef0123456789abcdef.0"),
            b"left over",
        )
        .expect("write a stray stage");
        set_owner_only(&stage.join("0123456789abcdef0123456789abcdef.0"));

        crate::try_get_all_env_for_vault_id(VAULT, "default").expect("read after sweep");

        assert!(!stage.exists());
    });
}

#[test]
fn hostile_journals_are_refused() {
    let valid = FileOperation {
        action: FileAction::Delete,
        target: record("overrides", None).name(),
        values_file: None,
        before: None,
        after: None,
    };
    let journal = |operations: Vec<FileOperation>| FileJournal {
        schema_version: FILE_JOURNAL_SCHEMA_VERSION,
        transaction_id: "0123456789abcdef0123456789abcdef".to_owned(),
        operations,
    };
    let encode = |journal: &FileJournal| serde_json::to_vec(journal).expect("encode");
    assert!(FileJournal::parse(&encode(&journal(vec![valid.clone()])), VAULT).is_ok());

    let mut traversal = valid.clone();
    traversal.target = "../escape".to_owned();
    traversal.values_file = Some(ValuesFile::Legacy);
    let mut not_companion = valid.clone();
    not_companion.target = "__vault_project_index_marker__".to_owned();
    let mut bad_digest = valid.clone();
    bad_digest.before = Some("XYZ".to_owned());
    let mut replace_without_after = valid.clone();
    replace_without_after.action = FileAction::Replace;
    let mut another_project = valid.clone();
    another_project.target = CompanionAccount::Record {
        kind: "overrides".to_owned(),
        vault_id: "other".to_owned(),
        part: None,
    }
    .name();
    let mut another_projects_values = valid.clone();
    another_projects_values.target = "other".to_owned();
    another_projects_values.values_file = Some(ValuesFile::Digest);
    for operations in [
        vec![traversal],
        vec![not_companion],
        vec![another_project],
        vec![another_projects_values],
        vec![bad_digest],
        vec![replace_without_after],
        vec![valid.clone(), valid.clone()],
        vec![valid; MAX_TRANSACTION_OPERATIONS + 1],
        Vec::new(),
    ] {
        assert!(FileJournal::parse(&encode(&journal(operations)), VAULT).is_err());
    }
    let repeated = br#"{"schemaVersion":1,"schemaVersion":1,"transactionId":"0123456789abcdef0123456789abcdef","operations":[]}"#;
    assert!(FileJournal::parse(repeated, VAULT).is_err());
    assert!(FileJournal::parse(&vec![b' '; MAX_FILE_JOURNAL_BYTES + 1], VAULT).is_err());
}

#[test]
fn deleting_a_project_removes_its_companion_folder() {
    with_temp_vault_home(|home| {
        force_file_vault();
        seed_values();
        commit(vec![
            write(marker_account(), marker_with_overrides()),
            write(record("overrides", None), overrides(r#""A":"1""#)),
        ]);

        crate::fallback::delete_vault_file(VAULT).expect("delete the project");

        assert!(
            !vaults_path(home)
                .join(companion_folder_name(VAULT))
                .exists()
        );
        assert!(
            !vaults_path(home)
                .join(crate::fallback::vault_file_name(VAULT))
                .exists()
        );
    });
}

#[test]
fn a_clean_values_write_syncs_one_folder_and_stages_nothing() {
    with_temp_vault_home(|home| {
        force_file_vault();
        seed_values();
        DIRECTORY_SYNCS.with(|syncs| syncs.borrow_mut().clear());
        crate::fallback::DATA_KEY_LOADS.with(|loads| loads.set(0));

        seed_values();

        let syncs = DIRECTORY_SYNCS.with(|syncs| syncs.borrow().clone());
        assert_eq!(syncs, [vaults_path(home)]);
        assert!(!vaults_path(home).join(stage_folder_name(VAULT)).exists());
        assert_eq!(
            crate::fallback::DATA_KEY_LOADS.with(std::cell::Cell::get),
            1
        );
    });
}

#[test]
fn another_projects_stuck_journal_leaves_this_project_usable() {
    with_temp_vault_home(|home| {
        force_file_vault();
        seed_values();
        let other = |part| CompanionAccount::Record {
            kind: "overrides".to_owned(),
            vault_id: "other".to_owned(),
            part,
        };
        commit(vec![
            write(
                CompanionAccount::Marker {
                    vault_id: "other".to_owned(),
                },
                marker_of("other", OVERRIDES_FEATURE),
            ),
            write(other(None), b"{}".to_vec()),
        ]);
        let journal = FileJournal {
            schema_version: FILE_JOURNAL_SCHEMA_VERSION,
            transaction_id: "0123456789abcdef0123456789abcde0".to_owned(),
            operations: vec![FileOperation {
                action: FileAction::Delete,
                target: other(None).name(),
                values_file: None,
                before: Some("0".repeat(64)),
                after: None,
            }],
        };
        write_project_journal(home, "other", &journal);

        assert_eq!(
            crate::try_get_all_env_for_vault_id(VAULT, "default")
                .expect("another project's journal doesn't block this one")["TOKEN"],
            "team"
        );
        let error = crate::try_get_all_env_for_vault_id("other", "default")
            .expect_err("the stuck project fails closed");
        assert!(error.contains("changed outside"), "{error}");
    });
}

#[test]
fn recovery_syncs_the_folder_of_a_change_that_reached_its_target_before_the_crash() {
    with_temp_vault_home(|home| {
        force_file_vault();
        seed_values();
        commit(vec![
            write(marker_account(), marker_with_overrides()),
            write(record("overrides", None), overrides(r#""A":"1""#)),
        ]);
        let folder = vaults_path(home).join(companion_folder_name(VAULT));
        let entry = folder.join(entry_name(&record("overrides", None)));
        let journal = FileJournal {
            schema_version: FILE_JOURNAL_SCHEMA_VERSION,
            transaction_id: "0123456789abcdef0123456789abcde1".to_owned(),
            operations: vec![FileOperation {
                action: FileAction::Replace,
                target: record("overrides", None).name(),
                values_file: None,
                before: Some("1".repeat(64)),
                after: digest_of(&entry),
            }],
        };
        write_journal(home, &journal);
        DIRECTORY_SYNCS.with(|syncs| syncs.borrow_mut().clear());

        crate::try_get_all_env_for_vault_id(VAULT, "default").expect("recovered read");

        let syncs = DIRECTORY_SYNCS.with(|syncs| syncs.borrow().clone());
        assert!(syncs.contains(&folder), "{syncs:?}");
        assert!(!journal_path(home, VAULT).exists());
    });
}

#[test]
fn a_deletion_interrupted_at_any_step_never_leaves_values_without_their_companion_data() {
    // The first transaction deletes the digest and legacy values files, the
    // overrides record and the marker: a crash can come before or after any.
    for applied in 0..=4 {
        with_temp_vault_home(|home| {
            force_file_vault();
            seed_values();
            let vaults = vaults_path(home);
            std::fs::copy(
                vaults.join(crate::fallback::vault_file_name(VAULT)),
                vaults.join(format!("{VAULT}.enc")),
            )
            .expect("seed a legacy copy");
            set_owner_only(&vaults.join(format!("{VAULT}.enc")));
            commit(vec![
                write(marker_account(), marker_with_overrides()),
                write(record("overrides", None), overrides(r#""A":"1""#)),
            ]);
            CRASH_AFTER_CHANGES.with(|crash| crash.set(Some(applied)));

            crate::fallback::delete_vault_file(VAULT).expect_err("the simulated crash");

            assert_eq!(
                crate::try_get_all_env_for_vault_id(VAULT, "default").expect("recovered read"),
                HashMap::new(),
                "after {applied} changes, recovery finishes the deletion with the values"
            );
            assert!(
                !vaults.join(companion_folder_name(VAULT)).exists(),
                "{applied}"
            );
            assert!(!vaults.join(format!("{VAULT}.enc")).exists(), "{applied}");
            assert!(!journal_path(home, VAULT).exists(), "{applied}");
        });
    }
}

#[test]
fn a_commit_keeps_every_record_listed_by_a_feature() {
    with_temp_vault_home(|home| {
        force_file_vault();
        seed_values();
        let error = with_vault_transaction(|directory| {
            FileCompanion::open(directory)?.commit(vec![write(
                record("overrides", None),
                overrides(r#""A":"1""#),
            )])
        })
        .expect_err("a record no feature lists");
        assert!(error.contains("without a feature that lists it"), "{error}");

        commit(vec![
            write(marker_account(), marker_with_overrides()),
            write(record("overrides", None), overrides(r#""A":"1""#)),
        ]);
        let error = with_vault_transaction(|directory| {
            FileCompanion::open(directory)?.commit(vec![Mutation::Delete {
                account: marker_account(),
            }])
        })
        .expect_err("a marker deletion that orphans its records");
        assert!(error.contains("would leave"), "{error}");
        assert!(
            vaults_path(home)
                .join(companion_folder_name(VAULT))
                .join(MARKER_ENTRY)
                .exists()
        );
    });
}

#[test]
fn an_oversized_entry_is_refused_by_its_size() {
    with_temp_vault_home(|home| {
        force_file_vault();
        seed_values();
        commit(vec![
            write(marker_account(), marker_with_overrides()),
            write(record("overrides", None), overrides(r#""A":"1""#)),
        ]);
        let entry = vaults_path(home)
            .join(companion_folder_name(VAULT))
            .join(entry_name(&record("overrides", None)));
        std::fs::write(&entry, vec![0_u8; 2 * MAX_RECORD_BYTES]).expect("grow the entry");
        set_owner_only(&entry);

        let error = crate::try_get_run_environment_for_vault_id(VAULT, None)
            .expect_err("an entry larger than any record");
        assert!(error.contains("limit"), "{error}");
    });
}

#[test]
fn a_deletion_lists_its_records_a_bounded_number_of_times() {
    const PARTS: u16 = 256;
    with_temp_vault_home(|_| {
        force_file_vault();
        seed_values();
        commit(vec![write(
            marker_account(),
            marker_of(
                VAULT,
                r#""future":{"version":1,"ifUnsupported":"ignore","kinds":["future-log"],"state":"active"}"#,
            ),
        )]);
        for batch in 0..PARTS / 32 {
            commit(
                (batch * 32..(batch + 1) * 32)
                    .map(|part| write(record("future-log", Some(part)), b"x".to_vec()))
                    .collect(),
            );
        }
        crate::storage_transaction::ENTRIES_VISITED.with(|visited| visited.set(0));

        crate::fallback::delete_vault_file(VAULT).expect("delete the project");

        let visited = crate::storage_transaction::ENTRIES_VISITED.with(std::cell::Cell::get);
        assert!(visited < 3 * usize::from(PARTS), "{visited}");
    });
}

#[test]
fn one_run_read_recovers_once() {
    with_temp_vault_home(|_| {
        force_file_vault();
        seed_values();
        commit(vec![
            write(marker_account(), marker_with_overrides()),
            write(record("overrides", None), overrides(r#""TOKEN":"mine""#)),
        ]);
        RECOVERIES.with(|recoveries| recoveries.set(0));

        crate::try_get_run_environment_for_vault_id(VAULT, None).expect("run read");

        assert_eq!(RECOVERIES.with(std::cell::Cell::get), 1);
    });
}

fn review() -> CompanionReview {
    with_vault_transaction(|directory| review_companion_data_unlocked(directory, VAULT))
        .expect("a review")
}

fn repair(reviewed: &CompanionReview) -> Result<Vec<CompanionRepair>, String> {
    with_vault_transaction(|directory| repair_companion_data_unlocked(directory, VAULT, reviewed))
}

fn assert_discarded_with_values_kept(home: &std::path::Path) {
    assert!(!journal_path(home, VAULT).exists());
    assert!(!vaults_path(home).join(stage_folder_name(VAULT)).exists());
    assert!(
        !vaults_path(home)
            .join(companion_folder_name(VAULT))
            .exists()
    );
    assert_eq!(
        crate::try_get_run_environment_for_vault_id(VAULT, None)
            .expect("the project runs again")
            .values["TOKEN"],
        "team"
    );
}

#[test]
fn an_interrupted_change_that_cant_be_finished_is_repaired_by_a_discard() {
    with_temp_vault_home(|home| {
        force_file_vault();
        seed_values();
        commit(vec![
            write(marker_account(), marker_with_overrides()),
            write(record("overrides", None), overrides(r#""A":"1""#)),
        ]);
        write_journal(
            home,
            &FileJournal {
                schema_version: FILE_JOURNAL_SCHEMA_VERSION,
                transaction_id: "0123456789abcdef0123456789abcde2".to_owned(),
                operations: vec![FileOperation {
                    action: FileAction::Delete,
                    target: record("overrides", None).name(),
                    values_file: None,
                    before: Some("0".repeat(64)),
                    after: None,
                }],
            },
        );
        let error = crate::try_get_run_environment_for_vault_id(VAULT, None)
            .expect_err("the stuck project fails closed");
        assert!(
            error.contains("an interrupted change can't be finished"),
            "{error}"
        );
        assert!(error.contains("lpm env repair"), "{error}");

        let reviewed = review();
        assert_eq!(reviewed.repairs(), [CompanionRepair::DiscardProject]);
        assert!(
            reviewed.problems[0]
                .description
                .contains("record \"overrides\" changed outside LPM"),
            "{reviewed:?}"
        );

        assert_eq!(
            repair(&reviewed).expect("the discard"),
            [CompanionRepair::DiscardProject]
        );
        assert_discarded_with_values_kept(home);
    });
}

#[test]
fn files_lpm_doesnt_write_and_an_unreadable_marker_are_repaired_by_a_discard() {
    for damage in ["stray", "unreadable marker"] {
        with_temp_vault_home(|home| {
            force_file_vault();
            seed_values();
            commit(vec![
                write(marker_account(), marker_with_overrides()),
                write(record("overrides", None), overrides(r#""A":"1""#)),
            ]);
            let folder = vaults_path(home).join(companion_folder_name(VAULT));
            let path = match damage {
                "stray" => folder.join("notes.txt"),
                _ => folder.join(MARKER_ENTRY),
            };
            std::fs::write(&path, b"not sealed by LPM").expect("damage the folder");
            set_owner_only(&path);

            let reviewed = review();
            assert_eq!(
                reviewed.repairs(),
                [CompanionRepair::DiscardProject],
                "{damage}"
            );
            repair(&reviewed).expect("the discard");
            assert_discarded_with_values_kept(home);
        });
    }
}

#[test]
fn an_invalid_marker_is_repaired_by_a_discard() {
    with_temp_vault_home(|home| {
        force_file_vault();
        seed_values();
        commit(vec![
            write(marker_account(), marker_with_overrides()),
            write(record("overrides", None), overrides(r#""A":"1""#)),
        ]);
        with_vault_transaction(|directory| {
            commit_unchecked(
                directory,
                VAULT,
                vec![write(marker_account(), b"{}".to_vec())],
            )
        })
        .expect("seed an invalid marker");

        let reviewed = review();
        assert_eq!(reviewed.repairs(), [CompanionRepair::DiscardProject]);
        repair(&reviewed).expect("the discard");
        assert_discarded_with_values_kept(home);
    });
}

#[test]
fn a_healthy_project_has_nothing_to_review() {
    with_temp_vault_home(|_| {
        force_file_vault();
        seed_values();
        commit(vec![
            write(marker_account(), marker_with_overrides()),
            write(record("overrides", None), overrides(r#""A":"1""#)),
        ]);
        let reviewed = review();
        assert!(reviewed.problems.is_empty(), "{reviewed:?}");
        assert!(repair(&reviewed).expect("nothing to run").is_empty());
    });
}

#[test]
fn every_file_journal_fixture_validates_as_recorded() {
    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Fixture {
        vault_id: String,
        cases: Vec<Case>,
    }
    #[derive(serde::Deserialize)]
    struct Case {
        name: String,
        text: String,
        valid: bool,
    }
    let fixture: Fixture = serde_json::from_str(include_str!(
        "../../../../lpm-env-companion/tests/fixtures/file-journals.json"
    ))
    .expect("the file journal fixture decodes");
    for case in fixture.cases {
        let parsed = FileJournal::parse(case.text.as_bytes(), &fixture.vault_id);
        assert_eq!(parsed.is_ok(), case.valid, "{}: {parsed:?}", case.name);
    }
}
