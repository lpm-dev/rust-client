use lpm_runner::local_domains::{
    HostsFileCleanPlan, HostsFilePlan, ManagedHostsFile, apply_hosts_file_clean_plan,
    clean_hosts_file_without_backup, ensure_hosts_file_backup,
    remove_hosts_file_block_without_backup,
};

#[test]
fn releasing_malformed_hosts_blocks_preserves_every_original_byte() {
    for newline in ["\n", "\r\n"] {
        for malformed in [
            "# >>> lpm:owned >>>\n127.0.0.1 app.test\n10.0.0.1 router",
            "# >>> lpm:owned >>>\n# >>> lpm:other >>>\n10.0.0.1 router\n# <<< lpm:owned <<<\n",
        ] {
            for without_backup in [false, true] {
                let dir = tempfile::tempdir().unwrap();
                let path = dir.path().join("hosts");
                let original = format!("127.0.0.1 localhost\n{malformed}").replace('\n', newline);
                std::fs::write(&path, &original).unwrap();
                let plan = HostsFilePlan {
                    path: path.clone(),
                    backup_path: dir.path().join("hosts.bak"),
                    block_id: "owned".into(),
                    hosts: vec!["app.test".into()],
                };
                let result = if without_backup {
                    remove_hosts_file_block_without_backup(&path, "owned")
                } else {
                    ManagedHostsFile::from_plan(&plan, true).release()
                };
                assert!(result.is_err(), "malformed block must fail: {result:?}");
                assert_eq!(std::fs::read(&path).unwrap(), original.as_bytes());
                assert!(!plan.backup_path.exists());
            }
        }
    }
}

#[cfg(unix)]
#[test]
fn hosts_backup_rejects_a_dangling_symlink_without_creating_its_target() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("hosts");
    let backup = dir.path().join("hosts.bak");
    let target = dir.path().join("unrelated");
    std::fs::write(&path, "127.0.0.1 localhost\n").unwrap();
    std::os::unix::fs::symlink(&target, &backup).unwrap();
    assert!(ensure_hosts_file_backup(&path, &backup).is_err());
    assert!(!target.exists());
    assert!(std::fs::symlink_metadata(&backup).unwrap().is_symlink());
}

#[test]
fn cleanup_rejects_changed_block_counts_before_backup_or_mutation() {
    assert_cleanup_count_changed(false);
}

#[test]
fn elevated_cleanup_rejects_changed_block_counts_before_mutation() {
    assert_cleanup_count_changed(true);
}

fn assert_cleanup_count_changed(without_backup: bool) {
    for actual in [0, 1, 3] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hosts");
        let backup = dir.path().join("hosts.bak");
        let mut original = "127.0.0.1 localhost\n".to_string();
        for index in 0..actual {
            original.push_str(&format!("# >>> lpm:block-{index} >>>\n127.0.0.1 app-{index}.test\n# <<< lpm:block-{index} <<<\n"));
        }
        std::fs::write(&path, &original).unwrap();
        let result = if without_backup {
            clean_hosts_file_without_backup(&path, 2)
        } else {
            apply_hosts_file_clean_plan(&HostsFileCleanPlan {
                path: path.clone(),
                backup_path: backup.clone(),
                block_count: 2,
            })
        };
        let error = result.unwrap_err();
        assert!(error.to_string().contains("count changed"), "{error}");
        assert_eq!(std::fs::read(&path).unwrap(), original.as_bytes());
        assert!(!backup.exists());
    }
}

#[test]
fn cleanup_with_matching_count_preserves_new_unmanaged_entries() {
    for without_backup in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hosts");
        let backup = dir.path().join("hosts.bak");
        let original = "127.0.0.1 localhost\n# >>> lpm:owned >>>\n127.0.0.1 app.test\n# <<< lpm:owned <<<\n10.0.0.1 newly-added\n";
        std::fs::write(&path, original).unwrap();
        let outcome = if without_backup {
            clean_hosts_file_without_backup(&path, 1)
        } else {
            apply_hosts_file_clean_plan(&HostsFileCleanPlan {
                path: path.clone(),
                backup_path: backup.clone(),
                block_count: 1,
            })
        }
        .unwrap();
        assert_eq!(outcome.removed_blocks, 1);
        assert!(outcome.changed);
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "127.0.0.1 localhost\n10.0.0.1 newly-added\n"
        );
        assert_eq!(backup.exists(), !without_backup);
    }
}

#[test]
fn hosts_backup_preserves_regular_files_and_rejects_directories() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("hosts");
    let backup = dir.path().join("hosts.bak");
    std::fs::write(&path, "current hosts").unwrap();
    std::fs::write(&backup, "first backup").unwrap();
    ensure_hosts_file_backup(&path, &backup).unwrap();
    assert_eq!(std::fs::read_to_string(&backup).unwrap(), "first backup");
    std::fs::remove_file(&backup).unwrap();
    std::fs::create_dir(&backup).unwrap();
    assert!(ensure_hosts_file_backup(&path, &backup).is_err());
}
