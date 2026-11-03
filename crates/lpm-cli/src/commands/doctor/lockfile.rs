use std::path::Path;

use crate::doctor_catalog;

use super::check::Check;

pub(super) enum DiagnosticLockfile {
    Loaded(Box<lpm_lockfile::ProjectLockfile>),
    Missing,
    Invalid(String),
}

impl DiagnosticLockfile {
    pub(super) fn load(project_dir: &Path) -> Self {
        match lpm_lockfile::Lockfile::read_for_project(project_dir) {
            Ok(mut project) => {
                project.content = String::new();
                Self::Loaded(Box::new(project))
            }
            Err(lpm_lockfile::LockfileError::NotFound(_)) => Self::Missing,
            Err(error) => Self::Invalid(error.to_string()),
        }
    }
}

pub(super) fn check_lockfile_state(lockfile: &DiagnosticLockfile) -> Vec<Check> {
    let mut checks = Vec::new();

    match lockfile {
        DiagnosticLockfile::Loaded(project) => {
            checks.push(Check::pass(&doctor_catalog::LOCKFILE_PRESENT, "lpm.lock"));
            let binary_path = project
                .path
                .with_file_name(lpm_lockfile::OBSOLETE_BINARY_LOCKFILE_NAME);
            if std::fs::symlink_metadata(&binary_path).is_ok() {
                checks.push(Check::warn(
                    &doctor_catalog::LOCKFILE_BINARY_OBSOLETE,
                    "lpm.lockb is no longer used — run lpm doctor --fix to remove it",
                ));
            }
        }
        DiagnosticLockfile::Missing => checks.push(Check::warn(
            &doctor_catalog::LOCKFILE_MISSING,
            "not found — run: lpm install to generate",
        )),
        DiagnosticLockfile::Invalid(error) => {
            checks.push(Check::fail(&doctor_catalog::LOCKFILE_CORRUPT, error))
        }
    }

    checks
}

/// Fix: remove the obsolete `lpm.lockb` beside the project's `lpm.lock`.
pub(super) fn fix_obsolete_binary_lockfile(project_dir: &Path) -> Result<(), String> {
    let expected_lock_path = lpm_lockfile::Lockfile::read_for_project(project_dir)
        .map_err(|_| "lpm.lock not found — cannot locate lpm.lockb".to_string())?
        .path;
    let lock_root = expected_lock_path.parent().ok_or_else(|| {
        format!(
            "cannot determine the project root for {}",
            expected_lock_path.display()
        )
    })?;
    lpm_common::with_exclusive_lock(lpm_common::project_install_lock(lock_root), || {
        let lock_path = lpm_lockfile::Lockfile::read_for_project(project_dir)
            .map_err(|error| lpm_common::LpmError::Script(format!("read lpm.lock failed: {error}")))?
            .path;
        if lock_path != expected_lock_path {
            return Err(lpm_common::LpmError::Script(format!(
                "the owning lockfile changed from {} to {} while waiting for the install transaction; retry lpm doctor --fix",
                expected_lock_path.display(),
                lock_path.display(),
            )));
        }
        lpm_lockfile::remove_obsolete_binary_lockfile(&lock_path)
            .map_err(|error| lpm_common::LpmError::Script(error.to_string()))
    })
    .map_err(|error| error.to_string())
}

pub(super) fn check_deps_in_sync(
    package: &lpm_workspace::PackageJson,
    lockfile: &DiagnosticLockfile,
) -> Option<Check> {
    let DiagnosticLockfile::Loaded(project) = lockfile else {
        return None;
    };
    let expected = [
        ("dependencies", &package.dependencies),
        ("devDependencies", &package.dev_dependencies),
        ("optionalDependencies", &package.optional_dependencies),
        ("peerDependencies", &package.peer_dependencies),
    ];
    let Some(snapshot) = project.lockfile.importers.get(".") else {
        if expected
            .iter()
            .all(|(_, dependencies)| dependencies.is_empty())
        {
            return Some(Check::pass(
                &doctor_catalog::DEPS_SYNC_CLEAN,
                "lockfile matches package.json",
            ));
        }
        return Some(Check::warn(
            &doctor_catalog::DEPS_SYNC_DRIFT,
            "lockfile has no direct-dependency importer snapshot — run: lpm install",
        ));
    };
    let actual = [
        ("dependencies", &snapshot.dependencies),
        ("devDependencies", &snapshot.dev_dependencies),
        ("optionalDependencies", &snapshot.optional_dependencies),
        ("peerDependencies", &snapshot.peer_dependencies),
    ];
    let changed: Vec<_> = expected
        .iter()
        .zip(actual.iter())
        .filter_map(|((name, expected), (_, actual))| {
            (!maps_match(expected, actual)).then_some(*name)
        })
        .collect();

    if changed.is_empty() {
        Some(Check::pass(
            &doctor_catalog::DEPS_SYNC_CLEAN,
            "lockfile matches package.json",
        ))
    } else {
        Some(Check::warn(
            &doctor_catalog::DEPS_SYNC_DRIFT,
            &format!(
                "lockfile importer differs in {} — run: lpm install",
                changed.join(", ")
            ),
        ))
    }
}

fn maps_match(
    expected: &std::collections::HashMap<String, String>,
    actual: &std::collections::BTreeMap<String, String>,
) -> bool {
    expected.len() == actual.len()
        && expected
            .iter()
            .all(|(name, spec)| actual.get(name) == Some(spec))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::doctor_catalog::Severity;

    fn structured_peers_lockfile() -> lpm_lockfile::Lockfile {
        let mut lockfile = lpm_lockfile::Lockfile::new();
        lockfile.metadata.lockfile_version = lpm_lockfile::LOCKFILE_VERSION_WITH_STRUCTURED_PEERS;
        lockfile
    }

    fn check_deps_in_sync_at(project_dir: &Path) -> Option<Check> {
        let package = lpm_workspace::read_package_json(&project_dir.join("package.json")).ok()?;
        let lockfile = DiagnosticLockfile::load(project_dir);
        check_deps_in_sync(&package, &lockfile)
    }

    fn check_lockfile_state_at(project_dir: &Path) -> Vec<Check> {
        check_lockfile_state(&DiagnosticLockfile::load(project_dir))
    }

    #[test]
    fn deps_sync_uses_exact_name_matching() {
        // Bug: naive string search with `contains("name = \"a\"")` would match
        // a package named "react" if we searched for "a" because "a" appears inside "react".
        // The old code used `lock_content.contains(...)` which is too loose.
        // With proper lockfile parsing via find_package(), only exact matches work.
        let dir = tempfile::tempdir().unwrap();

        // Create package.json with dep "a"
        let pkg_json = serde_json::json!({
            "dependencies": {
                "a": "^1.0.0"
            }
        });
        std::fs::write(
            dir.path().join("package.json"),
            serde_json::to_string_pretty(&pkg_json).unwrap(),
        )
        .unwrap();

        // Create lockfile with "react" but NOT "a"
        let mut lockfile = structured_peers_lockfile();
        lockfile.importers.insert(
            ".".to_string(),
            lpm_lockfile::ImporterSnapshot {
                dependencies: std::collections::BTreeMap::from([(
                    "react".to_string(),
                    "18.0.0".to_string(),
                )]),
                ..Default::default()
            },
        );
        lockfile.add_package(lpm_lockfile::LockedPackage {
            instance_id: None,
            dependency_targets: std::collections::BTreeMap::new(),
            peer_targets: std::collections::BTreeMap::new(),
            name: "react".to_string(),
            version: "18.0.0".to_string(),
            source: None,
            integrity: None,
            unpacked_size: None,
            manifest_fingerprint: None,
            registry_signatures: Vec::new(),
            registry_published_at: None,
            os: Vec::new(),
            cpu: Vec::new(),
            libc: Vec::new(),
            node_engine: None,
            optional: false,
            dependencies: vec![],
            alias_dependencies: vec![],
            peers: vec![],
            peer_edges: Vec::new(),
            tarball: None,
        });
        lockfile
            .write_to_file(&dir.path().join("lpm.lock"))
            .unwrap();

        let result = check_deps_in_sync_at(dir.path());
        let check = result.expect("should return a check");
        // "a" should be reported as missing — it is NOT in the lockfile
        assert!(
            matches!(check.severity, Severity::Warn),
            "dep 'a' should be missing from lockfile"
        );
        assert!(check.detail.contains("dependencies"), "{}", check.detail);
    }

    #[test]
    fn deps_sync_finds_exact_match() {
        let dir = tempfile::tempdir().unwrap();

        let pkg_json = serde_json::json!({
            "dependencies": {
                "react": "^18.0.0"
            }
        });
        std::fs::write(
            dir.path().join("package.json"),
            serde_json::to_string_pretty(&pkg_json).unwrap(),
        )
        .unwrap();

        let mut lockfile = structured_peers_lockfile();
        lockfile.importers.insert(
            ".".to_string(),
            lpm_lockfile::ImporterSnapshot {
                dependencies: std::collections::BTreeMap::from([(
                    "react".to_string(),
                    "^18.0.0".to_string(),
                )]),
                ..Default::default()
            },
        );
        lockfile.add_package(lpm_lockfile::LockedPackage {
            instance_id: None,
            dependency_targets: std::collections::BTreeMap::new(),
            peer_targets: std::collections::BTreeMap::new(),
            name: "react".to_string(),
            version: "18.0.0".to_string(),
            source: None,
            integrity: None,
            unpacked_size: None,
            manifest_fingerprint: None,
            registry_signatures: Vec::new(),
            registry_published_at: None,
            os: Vec::new(),
            cpu: Vec::new(),
            libc: Vec::new(),
            node_engine: None,
            optional: false,
            dependencies: vec![],
            alias_dependencies: vec![],
            peers: vec![],
            peer_edges: Vec::new(),
            tarball: None,
        });
        lockfile
            .write_to_file(&dir.path().join("lpm.lock"))
            .unwrap();

        let result = check_deps_in_sync_at(dir.path());
        let check = result.expect("should return a check");
        assert!(
            matches!(check.severity, Severity::Pass),
            "react should be found in lockfile"
        );
    }

    fn write_lockfile_with_importer(
        directory: &Path,
        snapshot: lpm_lockfile::ImporterSnapshot,
        packages: Vec<lpm_lockfile::LockedPackage>,
    ) {
        let mut lockfile = structured_peers_lockfile();
        lockfile.importers.insert(".".to_string(), snapshot);
        lockfile.packages = packages;
        lockfile.write_to_file(&directory.join("lpm.lock")).unwrap();
    }

    #[test]
    fn deps_sync_detects_changed_requested_range() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("package.json"),
            r#"{"dependencies":{"react":"^18.0.0"}}"#,
        )
        .unwrap();
        write_lockfile_with_importer(
            dir.path(),
            lpm_lockfile::ImporterSnapshot {
                dependencies: std::collections::BTreeMap::from([(
                    "react".to_string(),
                    "^17.0.0".to_string(),
                )]),
                ..Default::default()
            },
            Vec::new(),
        );

        let check = check_deps_in_sync_at(dir.path()).expect("dependency sync check");
        assert!(matches!(check.severity, Severity::Warn), "{}", check.detail);
        assert!(check.detail.contains("dependencies"), "{}", check.detail);
    }

    #[test]
    fn deps_sync_detects_removed_direct_dependency() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("package.json"), r#"{"name":"empty"}"#).unwrap();
        write_lockfile_with_importer(
            dir.path(),
            lpm_lockfile::ImporterSnapshot {
                dependencies: std::collections::BTreeMap::from([(
                    "removed".to_string(),
                    "^1.0.0".to_string(),
                )]),
                ..Default::default()
            },
            Vec::new(),
        );

        let check = check_deps_in_sync_at(dir.path()).expect("dependency sync check");
        assert!(matches!(check.severity, Severity::Warn), "{}", check.detail);
    }

    #[test]
    fn deps_sync_does_not_treat_a_transitive_package_as_a_direct_binding() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("package.json"),
            r#"{"dependencies":{"react":"^18.0.0"}}"#,
        )
        .unwrap();
        let mut transitive = structured_peers_lockfile();
        transitive.add_package(lpm_lockfile::LockedPackage {
            name: "react".to_string(),
            version: "18.0.0".to_string(),
            ..Default::default()
        });
        write_lockfile_with_importer(
            dir.path(),
            lpm_lockfile::ImporterSnapshot::default(),
            transitive.packages,
        );

        let check = check_deps_in_sync_at(dir.path()).expect("dependency sync check");
        assert!(matches!(check.severity, Severity::Warn), "{}", check.detail);
    }

    #[test]
    fn deps_sync_detects_optional_dependency_drift() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("package.json"),
            r#"{"optionalDependencies":{"fsevents":"^2.3.3"}}"#,
        )
        .unwrap();
        write_lockfile_with_importer(
            dir.path(),
            lpm_lockfile::ImporterSnapshot::default(),
            Vec::new(),
        );

        let check = check_deps_in_sync_at(dir.path()).expect("dependency sync check");
        assert!(matches!(check.severity, Severity::Warn), "{}", check.detail);
        assert!(
            check.detail.contains("optionalDependencies"),
            "{}",
            check.detail
        );
    }

    // ── Lockfile state checks ───────────────────────────────────────────

    #[test]
    fn lockfile_check_no_lockfile_warns() {
        let dir = tempfile::tempdir().unwrap();
        let checks = check_lockfile_state_at(dir.path());
        assert_eq!(checks.len(), 1);
        assert_eq!(checks[0].name(), "Lockfile");
        assert!(matches!(checks[0].severity, Severity::Warn));
        assert!(checks[0].detail.contains("not found"));
    }

    #[test]
    fn lockfile_check_existing_corrupt_toml_is_not_reported_as_missing() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("lpm.lock"), b"not = [valid").unwrap();

        let checks = check_lockfile_state_at(dir.path());
        assert_eq!(checks.len(), 1);
        assert_eq!(checks[0].code(), "lockfile_corrupt");
        assert!(
            checks[0].detail.contains("failed to parse"),
            "{}",
            checks[0].detail
        );
    }

    #[test]
    fn lockfile_check_without_a_binary_lockfile_reports_only_the_lockfile() {
        let dir = tempfile::tempdir().unwrap();
        lpm_lockfile::Lockfile::new()
            .write_to_file(&dir.path().join("lpm.lock"))
            .unwrap();

        let checks = check_lockfile_state_at(dir.path());
        assert_eq!(checks.len(), 1);
        assert_eq!(checks[0].code(), "lockfile_present");
        assert!(matches!(checks[0].severity, Severity::Pass));
    }

    #[test]
    fn lockfile_check_warns_about_a_leftover_binary_lockfile() {
        let dir = tempfile::tempdir().unwrap();
        lpm_lockfile::Lockfile::new()
            .write_to_file(&dir.path().join("lpm.lock"))
            .unwrap();
        std::fs::write(dir.path().join("lpm.lockb"), b"LPMB leftover").unwrap();

        let checks = check_lockfile_state_at(dir.path());
        assert_eq!(checks.len(), 2);
        assert_eq!(checks[1].code(), "lockfile_binary_obsolete");
        assert!(matches!(checks[1].severity, Severity::Warn));
    }

    // ── Fix execution tests ─────────────────────────────────────────────

    #[test]
    fn fix_obsolete_binary_lockfile_removes_it_and_leaves_the_lockfile() {
        let dir = tempfile::tempdir().unwrap();
        let lockfile_path = dir.path().join("lpm.lock");
        lpm_lockfile::Lockfile::new()
            .write_to_file(&lockfile_path)
            .unwrap();
        let lockfile_bytes = std::fs::read(&lockfile_path).unwrap();
        std::fs::write(dir.path().join("lpm.lockb"), b"LPMB leftover").unwrap();

        fix_obsolete_binary_lockfile(dir.path()).unwrap();

        assert!(!dir.path().join("lpm.lockb").exists());
        assert_eq!(std::fs::read(&lockfile_path).unwrap(), lockfile_bytes);
    }

    #[test]
    fn fix_obsolete_binary_lockfile_waits_for_the_install_transaction() {
        let dir = tempfile::tempdir().unwrap();
        lpm_lockfile::Lockfile::new()
            .write_to_file(&dir.path().join("lpm.lock"))
            .unwrap();
        let project_dir = dir.path().to_path_buf();
        let binary_path = project_dir.join(lpm_lockfile::OBSOLETE_BINARY_LOCKFILE_NAME);
        std::fs::write(&binary_path, b"LPMB leftover").unwrap();
        let lock_path = lpm_common::project_install_lock(&project_dir);
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (finished_tx, finished_rx) = std::sync::mpsc::channel();

        lpm_common::with_exclusive_lock(&lock_path, || {
            let repair_project_dir = project_dir.clone();
            std::thread::spawn(move || {
                started_tx.send(()).unwrap();
                finished_tx
                    .send(fix_obsolete_binary_lockfile(&repair_project_dir))
                    .unwrap();
            });
            started_rx.recv().unwrap();
            assert!(
                finished_rx
                    .recv_timeout(std::time::Duration::from_millis(200))
                    .is_err(),
                "the removal must wait for the active install transaction"
            );
            assert!(binary_path.exists());
            Ok::<_, lpm_common::LpmError>(())
        })
        .unwrap();

        finished_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("the removal must finish after the install transaction releases its lock")
            .unwrap();
        assert!(!binary_path.exists());
    }

    #[test]
    fn fix_obsolete_binary_lockfile_fails_without_a_lockfile() {
        let dir = tempfile::tempdir().unwrap();

        let result = fix_obsolete_binary_lockfile(dir.path());

        assert!(result.unwrap_err().contains("not found"));
    }
}
