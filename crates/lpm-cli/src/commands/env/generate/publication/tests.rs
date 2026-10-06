use super::*;
use lpm_env_codegen::{Adapter, Options};
use std::cell::Cell;

fn generated(value: &str) -> Generated {
    let schema =
        serde_json::from_value(serde_json::json!({"vars":{"VALUE":{"default":value}}})).unwrap();
    lpm_env_codegen::generate(
        &schema,
        Options {
            adapter: Adapter::Default,
            context: Default::default(),
        },
    )
    .unwrap()
}

#[test]
fn generation_replaces_owned_output_and_preserves_the_published_directory() {
    let project = tempfile::tempdir().unwrap();
    let path = Path::new("env.generated");
    write(project.path(), path, &generated("before"), false, || Ok(())).unwrap();
    let after = generated("after");
    write(project.path(), path, &after, false, || Ok(())).unwrap();
    write(project.path(), path, &after, true, || Ok(())).unwrap();
    for (name, bytes) in &after.files {
        assert_eq!(
            std::fs::read(project.path().join(path).join(name)).unwrap(),
            *bytes
        );
    }
    assert_eq!(std::fs::read_dir(project.path()).unwrap().count(), 2);
}

#[test]
fn checks_of_missing_output_do_not_create_locks_or_directories() {
    let project = tempfile::tempdir().unwrap();
    assert!(
        write(
            project.path(),
            Path::new("env.generated"),
            &generated("value"),
            true,
            || Ok(())
        )
        .is_err()
    );
    assert_eq!(std::fs::read_dir(project.path()).unwrap().count(), 0);
}

#[test]
fn generation_preserves_changed_files_within_a_previous_owned_inventory() {
    let project = tempfile::tempdir().unwrap();
    let path = Path::new("env.generated");
    write(project.path(), path, &generated("before"), false, || Ok(())).unwrap();
    std::fs::write(
        project.path().join(path).join("server.js"),
        b"user edited contents",
    )
    .unwrap();
    assert!(write(project.path(), path, &generated("after"), false, || Ok(())).is_err());
    assert_eq!(
        std::fs::read(project.path().join(path).join("server.js")).unwrap(),
        b"user edited contents"
    );
}

#[test]
fn a_target_replaced_after_admission_is_restored_without_deleting_user_files() {
    let project = tempfile::tempdir().unwrap();
    let path = Path::new("env.generated");
    write(project.path(), path, &generated("before"), false, || Ok(())).unwrap();
    let result = write(project.path(), path, &generated("after"), false, || {
        std::fs::rename(
            project.path().join(path),
            project.path().join("original-output"),
        )
        .unwrap();
        std::fs::create_dir(project.path().join(path)).unwrap();
        std::fs::write(project.path().join(path).join("user-file"), b"preserve").unwrap();
        Ok(())
    });
    assert!(result.is_err());
    assert_eq!(
        std::fs::read(project.path().join(path).join("user-file")).unwrap(),
        b"preserve"
    );
}

#[test]
fn output_changed_during_quarantine_admission_is_restored_without_publishing() {
    let project = tempfile::tempdir().unwrap();
    let path = Path::new("env.generated");
    write(project.path(), path, &generated("before"), false, || Ok(())).unwrap();
    let result = write(project.path(), path, &generated("after"), false, || {
        std::fs::write(
            project.path().join(path).join("server.js"),
            b"preserve raced contents",
        )
        .unwrap();
        Ok(())
    });
    assert!(result.is_err());
    assert_eq!(
        std::fs::read(project.path().join(path).join("server.js")).unwrap(),
        b"preserve raced contents"
    );
}

#[test]
fn unowned_inventory_and_stale_sources_preserve_existing_outputs() {
    let project = tempfile::tempdir().unwrap();
    let path = Path::new("env.generated");
    let before = generated("before");
    write(project.path(), path, &before, false, || Ok(())).unwrap();
    std::fs::write(project.path().join(path).join("user-file"), b"preserve").unwrap();
    assert!(write(project.path(), path, &generated("after"), false, || Ok(())).is_err());
    assert_eq!(
        std::fs::read(project.path().join(path).join("user-file")).unwrap(),
        b"preserve"
    );
    std::fs::remove_file(project.path().join(path).join("user-file")).unwrap();
    assert!(
        write(project.path(), path, &generated("after"), false, || Err(
            Error::Code("env.source_changed")
        ))
        .is_err()
    );
    write(project.path(), path, &before, true, || Ok(())).unwrap();
}

#[test]
fn sources_changed_after_quarantine_restore_the_previous_output() {
    let project = tempfile::tempdir().unwrap();
    let path = Path::new("env.generated");
    let before = generated("before");
    write(project.path(), path, &before, false, || Ok(())).unwrap();
    let checks = Cell::new(0);
    let result = write(project.path(), path, &generated("after"), false, || {
        checks.set(checks.get() + 1);
        if checks.get() == 2 {
            assert!(!project.path().join(path).exists());
            Err(Error::Code("env.source_changed"))
        } else {
            Ok(())
        }
    });
    assert!(matches!(result, Err(Error::Code("env.source_changed"))));
    write(project.path(), path, &before, true, || Ok(())).unwrap();
}

#[test]
fn rollback_collisions_preserve_racing_files_and_report_retained_output() {
    let project = tempfile::tempdir().unwrap();
    let path = Path::new("env.generated");
    let before = generated("before");
    write(project.path(), path, &before, false, || Ok(())).unwrap();
    let checks = Cell::new(0);
    let result = write(project.path(), path, &generated("after"), false, || {
        checks.set(checks.get() + 1);
        if checks.get() == 2 {
            std::fs::create_dir(project.path().join(path)).unwrap();
            std::fs::write(project.path().join(path).join("user-file"), b"preserve").unwrap();
            Err(Error::Code("env.source_changed"))
        } else {
            Ok(())
        }
    });
    let Err(Error::Recovery { directory }) = result else {
        panic!("expected retained recovery directory")
    };
    assert_eq!(
        std::fs::read(project.path().join(path).join("user-file")).unwrap(),
        b"preserve"
    );
    for (name, bytes) in &before.files {
        assert_eq!(
            std::fs::read(directory.join("previous").join(name)).unwrap(),
            *bytes
        );
    }
}

#[test]
fn failed_identity_reads_never_admit_a_directory_match() {
    struct Unreadable;
    impl PublicationIo for Unreadable {
        fn identity(&self, _: &Dir) -> std::io::Result<DirectoryIdentity> {
            Err(std::io::Error::other("injected identity failure"))
        }
    }
    let project = tempfile::tempdir().unwrap();
    let root = Dir::open_ambient_dir(project.path(), cap_std::ambient_authority()).unwrap();
    root.create_dir("output").unwrap();
    let output = root.open_dir("output").unwrap();
    assert!(!identity_matches(
        &root,
        OsStr::new("output"),
        &output,
        &Unreadable
    ));
}

#[test]
fn identity_read_failure_after_quarantine_restores_the_previous_output() {
    struct FailAfterMove(Cell<bool>);
    impl PublicationIo for FailAfterMove {
        fn identity(&self, directory: &Dir) -> std::io::Result<DirectoryIdentity> {
            if self.0.get() {
                Err(std::io::Error::other("injected identity failure"))
            } else {
                transaction::directory_identity(directory)
            }
        }
        fn rename_noreplace(
            &self,
            source: &Dir,
            directory: &Dir,
            name: &OsStr,
            destination: &Dir,
            target: &OsStr,
        ) -> std::io::Result<()> {
            transaction::publish_directory_noreplace(source, directory, name, destination, target)?;
            self.0.set(true);
            Ok(())
        }
    }
    let project = tempfile::tempdir().unwrap();
    let path = Path::new("env.generated");
    let before = generated("before");
    write(project.path(), path, &before, false, || Ok(())).unwrap();
    let destination = Destination::open(project.path(), path).unwrap();
    assert!(
        publish_with(
            &destination,
            project.path(),
            &generated("after"),
            &|| Ok(()),
            &FailAfterMove(Cell::new(false))
        )
        .is_err()
    );
    write(project.path(), path, &before, true, || Ok(())).unwrap();
}

#[test]
fn a_post_rename_error_restores_output_and_removes_staging() {
    struct FailFirstMove(Cell<bool>);
    impl PublicationIo for FailFirstMove {
        fn rename_noreplace(
            &self,
            source: &Dir,
            directory: &Dir,
            name: &OsStr,
            destination: &Dir,
            target: &OsStr,
        ) -> std::io::Result<()> {
            transaction::publish_directory_noreplace(source, directory, name, destination, target)?;
            if self.0.replace(false) {
                Err(std::io::Error::other("injected post-rename failure"))
            } else {
                Ok(())
            }
        }
    }
    let project = tempfile::tempdir().unwrap();
    let path = Path::new("env.generated");
    let before = generated("before");
    write(project.path(), path, &before, false, || Ok(())).unwrap();
    let destination = Destination::open(project.path(), path).unwrap();
    assert!(
        publish_with(
            &destination,
            project.path(),
            &generated("after"),
            &|| Ok(()),
            &FailFirstMove(Cell::new(true))
        )
        .is_err()
    );
    write(project.path(), path, &before, true, || Ok(())).unwrap();
    assert_eq!(std::fs::read_dir(project.path()).unwrap().count(), 2);
}

#[test]
fn staging_initialization_failures_remove_empty_owned_residue() {
    struct FailInitialization(bool);
    impl PublicationIo for FailInitialization {
        fn create_stage(&self, private: &Dir) -> std::io::Result<Dir> {
            if self.0 {
                private.create_dir("next")?;
            }
            Err(std::io::Error::other(
                "injected staging initialization failure",
            ))
        }
    }
    for created in [false, true] {
        let project = tempfile::tempdir().unwrap();
        let path = Path::new("env.generated");
        let before = generated("before");
        write(project.path(), path, &before, false, || Ok(())).unwrap();
        let destination = Destination::open(project.path(), path).unwrap();
        assert!(
            publish_with(
                &destination,
                project.path(),
                &generated("after"),
                &|| Ok(()),
                &FailInitialization(created)
            )
            .is_err()
        );
        write(project.path(), path, &before, true, || Ok(())).unwrap();
        assert_eq!(std::fs::read_dir(project.path()).unwrap().count(), 2);
    }
}

#[test]
fn parent_replacement_after_quarantine_preserves_the_previous_output() {
    let project = tempfile::tempdir().unwrap();
    std::fs::create_dir(project.path().join("out")).unwrap();
    let path = Path::new("out/env.generated");
    let before = generated("before");
    write(project.path(), path, &before, false, || Ok(())).unwrap();
    let checks = Cell::new(0);
    let result = write(project.path(), path, &generated("after"), false, || {
        checks.set(checks.get() + 1);
        if checks.get() == 2 {
            std::fs::rename(
                project.path().join("out"),
                project.path().join("displaced-out"),
            )
            .unwrap();
            std::fs::create_dir(project.path().join("out")).unwrap();
            std::fs::write(project.path().join("out/user-file"), b"preserve").unwrap();
        }
        Ok(())
    });
    assert!(result.is_err());
    assert_eq!(
        std::fs::read(project.path().join("out/user-file")).unwrap(),
        b"preserve"
    );
    write(
        project.path(),
        Path::new("displaced-out/env.generated"),
        &before,
        true,
        || Ok(()),
    )
    .unwrap();
}

#[test]
fn recovery_reports_the_current_location_after_a_parent_is_renamed() {
    struct MoveParent<'a>(&'a Path, Cell<usize>);
    impl PublicationIo for MoveParent<'_> {
        fn rename_noreplace(
            &self,
            source: &Dir,
            directory: &Dir,
            name: &OsStr,
            destination: &Dir,
            target: &OsStr,
        ) -> std::io::Result<()> {
            transaction::publish_directory_noreplace(source, directory, name, destination, target)?;
            self.1.set(self.1.get() + 1);
            if self.1.get() == 2 {
                std::fs::rename(self.0.join("out"), self.0.join("displaced-out"))?;
                std::fs::create_dir(self.0.join("out"))?;
            }
            Ok(())
        }
    }
    let project = tempfile::tempdir().unwrap();
    std::fs::create_dir(project.path().join("out")).unwrap();
    let path = Path::new("out/env.generated");
    let before = generated("before");
    write(project.path(), path, &before, false, || Ok(())).unwrap();
    let destination = Destination::open(project.path(), path).unwrap();
    let result = publish_with(
        &destination,
        project.path(),
        &generated("after"),
        &|| Ok(()),
        &MoveParent(project.path(), Cell::new(0)),
    );
    let Err(Error::Recovery { directory }) = result else {
        panic!("expected retained output")
    };
    assert!(
        directory.is_dir(),
        "recovery path must remain usable after parent replacement: {}",
        directory.display()
    );
    for (name, bytes) in &before.files {
        assert_eq!(
            std::fs::read(directory.join("previous").join(name)).unwrap(),
            *bytes
        );
    }
}

#[test]
fn a_replaced_staging_name_preserves_unadmitted_files() {
    let project = tempfile::tempdir().unwrap();
    let path = Path::new("env.generated");
    let result = write(project.path(), path, &generated("value"), false, || {
        let transaction = std::fs::read_dir(project.path())
            .unwrap()
            .map(Result::unwrap)
            .find(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".lpm-env-generated-")
            })
            .unwrap()
            .path();
        std::fs::rename(transaction.join("next"), transaction.join("displaced-next")).unwrap();
        std::fs::create_dir(transaction.join("next")).unwrap();
        std::fs::write(transaction.join("next/user-file"), b"preserve").unwrap();
        Ok(())
    });
    let Err(Error::Recovery { directory }) = result else {
        panic!("expected retained staging race")
    };
    assert_eq!(
        std::fs::read(directory.join("next/user-file")).unwrap(),
        b"preserve"
    );
    assert!(!project.path().join(path).exists());
}

#[test]
fn recovery_follows_a_renamed_transaction_and_preserves_its_replacement() {
    let project = tempfile::tempdir().unwrap();
    let path = Path::new("env.generated");
    let before = generated("before");
    write(project.path(), path, &before, false, || Ok(())).unwrap();
    let checks = Cell::new(0);
    let result = write(project.path(), path, &generated("after"), false, || {
        checks.set(checks.get() + 1);
        if checks.get() == 2 {
            let transaction = std::fs::read_dir(project.path())
                .unwrap()
                .map(Result::unwrap)
                .find(|entry| {
                    entry
                        .file_name()
                        .to_string_lossy()
                        .starts_with(".lpm-env-generated-")
                })
                .unwrap()
                .path();
            std::fs::rename(&transaction, project.path().join("moved-transaction")).unwrap();
            std::fs::create_dir(&transaction).unwrap();
            std::fs::write(
                transaction.join("user-file"),
                b"preserve transaction replacement",
            )
            .unwrap();
            std::fs::create_dir(project.path().join(path)).unwrap();
            Err(Error::Code("env.source_changed"))
        } else {
            Ok(())
        }
    });
    let Err(Error::Recovery { directory }) = result else {
        panic!("expected retained transaction")
    };
    for (name, bytes) in &before.files {
        assert_eq!(
            std::fs::read(directory.join("previous").join(name)).unwrap(),
            *bytes
        );
    }
    let replacement = std::fs::read_dir(project.path())
        .unwrap()
        .map(Result::unwrap)
        .find(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .starts_with(".lpm-env-generated-")
        })
        .unwrap()
        .path();
    assert_eq!(
        std::fs::read(replacement.join("user-file")).unwrap(),
        b"preserve transaction replacement"
    );
}

#[cfg(unix)]
#[test]
fn linked_output_parents_and_files_are_rejected_without_following_them() {
    let project = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    std::os::unix::fs::symlink(outside.path(), project.path().join("alias")).unwrap();
    assert!(
        write(
            project.path(),
            Path::new("alias/output"),
            &generated("value"),
            false,
            || Ok(())
        )
        .is_err()
    );
    assert_eq!(std::fs::read_dir(outside.path()).unwrap().count(), 0);
    write(
        project.path(),
        Path::new("env.generated"),
        &generated("value"),
        false,
        || Ok(()),
    )
    .unwrap();
    std::fs::remove_file(project.path().join("env.generated/server.js")).unwrap();
    std::os::unix::fs::symlink(
        outside.path().join("keep"),
        project.path().join("env.generated/server.js"),
    )
    .unwrap();
    assert!(
        write(
            project.path(),
            Path::new("env.generated"),
            &generated("value"),
            true,
            || Ok(())
        )
        .is_err()
    );
}
