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
        open(&key, &record("overrides", None), &sealed).expect("open"),
        b"secret"
    );
    assert!(open(&key, &record("notes", None), &sealed).is_err());
    assert!(open(&[8_u8; 32], &record("overrides", None), &sealed).is_err());
    let other_project = CompanionAccount::Record {
        kind: "overrides".to_owned(),
        vault_id: "other".to_owned(),
        part: None,
    };
    assert!(open(&key, &other_project, &sealed).is_err());
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
            let mut companion = FileCompanion::open(directory)?;
            companion.commit(vec![write(marker_account(), marker_with_overrides())])?;
            companion.commit(vec![write(
                record("overrides", None),
                overrides(r#""A":"1""#),
            )])?;
            companion.commit(vec![Mutation::Delete {
                account: marker_account(),
            }])
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
            .filter(|path| path.ends_with(STAGE_FOLDER))
            .count();
        let folder_syncs = syncs.iter().filter(|path| **path == folder).count();
        let vaults_syncs = syncs.iter().filter(|path| **path == vaults).count();
        assert_eq!(
            (stage_syncs, folder_syncs, vaults_syncs),
            (1, 1, 3),
            "{syncs:?}"
        );
        assert!(!vaults.join(JOURNAL).exists());
        assert!(!vaults.join(STAGE_FOLDER).exists());
    });
}

fn write_journal(home: &std::path::Path, journal: &FileJournal) {
    std::fs::write(
        vaults_path(home).join(JOURNAL),
        serde_json::to_vec(journal).expect("encode journal"),
    )
    .expect("write journal");
    set_owner_only(&vaults_path(home).join(JOURNAL));
}

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
        assert!(!vaults.join(JOURNAL).exists());
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
        assert!(vaults_path(home).join(JOURNAL).exists());
    });
}

#[test]
fn stages_without_a_journal_are_swept() {
    with_temp_vault_home(|home| {
        force_file_vault();
        seed_values();
        let stage = vaults_path(home).join(STAGE_FOLDER);
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
    assert!(FileJournal::parse(&encode(&journal(vec![valid.clone()]))).is_ok());

    let mut traversal = valid.clone();
    traversal.target = "../escape".to_owned();
    traversal.values_file = Some(ValuesFile::Legacy);
    let mut not_companion = valid.clone();
    not_companion.target = "__vault_project_index_marker__".to_owned();
    let mut bad_digest = valid.clone();
    bad_digest.before = Some("XYZ".to_owned());
    let mut replace_without_after = valid.clone();
    replace_without_after.action = FileAction::Replace;
    for operations in [
        vec![traversal],
        vec![not_companion],
        vec![bad_digest],
        vec![replace_without_after],
        vec![valid.clone(), valid.clone()],
        vec![valid; MAX_TRANSACTION_OPERATIONS + 1],
        Vec::new(),
    ] {
        assert!(FileJournal::parse(&encode(&journal(operations))).is_err());
    }
    let repeated = br#"{"schemaVersion":1,"schemaVersion":1,"transactionId":"0123456789abcdef0123456789abcdef","operations":[]}"#;
    assert!(FileJournal::parse(repeated).is_err());
    assert!(FileJournal::parse(&vec![b' '; MAX_FILE_JOURNAL_BYTES + 1]).is_err());
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
        assert!(!vaults_path(home).join(STAGE_FOLDER).exists());
        assert_eq!(
            crate::fallback::DATA_KEY_LOADS.with(std::cell::Cell::get),
            1
        );
    });
}
