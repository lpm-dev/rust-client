use std::path::Path;

use crate::doctor_catalog;

use super::check::Check;

pub(super) fn check_lockfile_state(project_dir: &Path) -> Vec<Check> {
    let mut checks = Vec::new();

    if let Ok(project) = lpm_lockfile::Lockfile::read_for_project(project_dir) {
        let lockfile = project.path;
        let lockb_path = lockfile.with_extension("lockb");
        checks.push(Check::pass(&doctor_catalog::LOCKFILE_PRESENT, "lpm.lock"));

        let lockfile_data = lpm_lockfile::Lockfile::read_from_file(&lockfile).ok();
        let binary_supported = match lockfile_data.as_ref() {
            Some(lockfile_data) => lpm_lockfile::binary::binary_format_supports(lockfile_data),
            None => true,
        };

        if lockb_path.exists() {
            if !binary_supported {
                checks.push(Check::warn(
                    &doctor_catalog::LOCKFILE_BINARY_STALE,
                    "lpm.lockb is stale for TOML-only lockfile metadata — run lpm install to remove",
                ));
                return checks;
            }

            // Binary exists — check if in sync
            let toml_mtime = lockfile.metadata().and_then(|m| m.modified()).ok();
            let bin_mtime = lockb_path.metadata().and_then(|m| m.modified()).ok();

            let is_stale = match (toml_mtime, bin_mtime) {
                (Some(t), Some(b)) => b < t,
                _ => false,
            };

            if is_stale {
                checks.push(Check::warn(
                    &doctor_catalog::LOCKFILE_BINARY_STALE,
                    "lpm.lockb is stale — run lpm install to regenerate",
                ));
            } else {
                // Validate header
                match lpm_lockfile::binary::BinaryLockfileReader::open(&lockb_path) {
                    Ok(Some(_)) => checks.push(Check::pass(
                        &doctor_catalog::LOCKFILE_BINARY_VALID,
                        "lpm.lockb (in sync, valid)",
                    )),
                    Ok(None) => {} // shouldn't happen since we checked exists
                    Err(_) => {
                        checks.push(Check::warn(
                            &doctor_catalog::LOCKFILE_BINARY_CORRUPT,
                            "lpm.lockb is corrupt — run lpm install to regenerate",
                        ));
                    }
                }
            }
        } else if binary_supported {
            checks.push(Check::warn(
                &doctor_catalog::LOCKFILE_BINARY_MISSING,
                "lpm.lockb missing — run lpm install to generate",
            ));
        }
    } else {
        checks.push(Check::warn(
            &doctor_catalog::LOCKFILE_MISSING,
            "not found — run: lpm install to generate",
        ));
    }

    checks
}

/// Check .gitattributes state: exists and has lpm.lockb binary marker.
pub(super) fn check_gitattributes_state(project_dir: &Path) -> Vec<Check> {
    let mut checks = Vec::new();
    let Ok(project) = lpm_lockfile::Lockfile::read_for_project(project_dir) else {
        return checks;
    };
    let lockfile = project.path;
    let lockb_path = lockfile.with_extension("lockb");
    let ga_path = lockfile
        .parent()
        .unwrap_or(project_dir)
        .join(".gitattributes");

    if lockb_path.exists() || lockfile.exists() {
        if ga_path.exists() {
            let ga_content =
                lpm_common::read_text_file_capped(&ga_path, lpm_common::CONFIG_FILE_SIZE_CAP_BYTES)
                    .unwrap_or_default();
            if ga_content.lines().any(|l| l.trim() == "lpm.lockb binary") {
                checks.push(Check::pass(
                    &doctor_catalog::GITATTRIBUTES_LOCKB_MARKED,
                    "lpm.lockb marked as binary",
                ));
            } else {
                checks.push(Check::warn(
                    &doctor_catalog::GITATTRIBUTES_LOCKB_UNMARKED,
                    "lpm.lockb not marked as binary — run lpm install to fix",
                ));
            }
        } else {
            checks.push(Check::warn(
                &doctor_catalog::GITATTRIBUTES_MISSING,
                "missing — run lpm install to create (marks lpm.lockb as binary)",
            ));
        }
    }

    checks
}

/// Fix: reconcile `lpm.lockb` with `lpm.lock`.
pub(super) fn fix_binary_lockfile(project_dir: &Path) -> Result<(), String> {
    let expected_lock_path = lpm_lockfile::Lockfile::read_for_project(project_dir)
        .map_err(|_| "lpm.lock not found — cannot reconcile lpm.lockb".to_string())?
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
        let lockfile = lpm_lockfile::Lockfile::read_from_file(&lock_path).map_err(|error| {
            lpm_common::LpmError::Script(format!("read lpm.lock failed: {error}"))
        })?;
        lockfile.write_all(&lock_path).map_err(|error| {
            lpm_common::LpmError::Script(format!("write lockfiles failed: {error}"))
        })
    })
    .map_err(|error| error.to_string())
}

/// Fix: ensure `.gitattributes` marks `lpm.lockb` as binary.
pub(super) fn fix_gitattributes(project_dir: &Path) -> Result<(), String> {
    let root = lpm_lockfile::Lockfile::read_for_project(project_dir)
        .ok()
        .and_then(|project| project.path.parent().map(Path::to_path_buf))
        .unwrap_or_else(|| project_dir.to_path_buf());
    lpm_lockfile::ensure_gitattributes(&root)
        .map_err(|e| format!(".gitattributes update failed: {e}"))
}

/// Check if lockfile dependencies match package.json dependencies.
///
/// Reads dep names from package.json and checks if they all appear in lpm.lock.
/// Detects "lockfile out of date" drift.
pub(super) fn check_deps_in_sync(project_dir: &Path) -> Option<Check> {
    let pkg_json_path = project_dir.join("package.json");
    let pkg_content =
        lpm_common::read_text_file_capped(&pkg_json_path, lpm_common::CONFIG_FILE_SIZE_CAP_BYTES)
            .ok()?;
    let pkg: serde_json::Value = serde_json::from_str(&pkg_content).ok()?;

    let lockfile = lpm_lockfile::Lockfile::read_for_project(project_dir)
        .ok()?
        .lockfile;

    // Collect all dep names from package.json
    let mut declared_deps: Vec<String> = Vec::new();
    if let Some(deps) = pkg.get("dependencies").and_then(|d| d.as_object()) {
        for key in deps.keys() {
            declared_deps.push(key.clone());
        }
    }
    if let Some(deps) = pkg.get("devDependencies").and_then(|d| d.as_object()) {
        for key in deps.keys() {
            declared_deps.push(key.clone());
        }
    }

    if declared_deps.is_empty() {
        return None; // No deps to check
    }

    // Check which deps are missing from lockfile using proper lockfile parsing
    let mut missing: Vec<&str> = Vec::new();
    for dep in &declared_deps {
        if lockfile.find_package(dep).is_none() {
            missing.push(dep);
        }
    }

    if missing.is_empty() {
        Some(Check::pass(
            &doctor_catalog::DEPS_SYNC_CLEAN,
            "lockfile matches package.json",
        ))
    } else if missing.len() <= 3 {
        Some(Check::warn(
            &doctor_catalog::DEPS_SYNC_DRIFT,
            &format!(
                "lockfile missing: {} — run: lpm install",
                missing.join(", ")
            ),
        ))
    } else {
        Some(Check::warn(
            &doctor_catalog::DEPS_SYNC_DRIFT,
            &format!(
                "{} deps not in lockfile ({}, ...) — run: lpm install",
                missing.len(),
                missing[..2].join(", ")
            ),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::doctor_catalog::Severity;

    fn binary_representable_lockfile() -> lpm_lockfile::Lockfile {
        let mut lockfile = lpm_lockfile::Lockfile::new();
        lockfile.metadata.lockfile_version = lpm_lockfile::LOCKFILE_VERSION_WITH_STRUCTURED_PEERS;
        lockfile
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
        let mut lockfile = binary_representable_lockfile();
        lockfile.add_package(lpm_lockfile::LockedPackage {
            instance_id: None,
            dependency_targets: std::collections::BTreeMap::new(),
            peer_targets: std::collections::BTreeMap::new(),
            name: "react".to_string(),
            version: "18.0.0".to_string(),
            source: None,
            integrity: None,
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

        let result = check_deps_in_sync(dir.path());
        let check = result.expect("should return a check");
        // "a" should be reported as missing — it is NOT in the lockfile
        assert!(
            matches!(check.severity, Severity::Warn),
            "dep 'a' should be missing from lockfile"
        );
        assert!(
            check.detail.contains("a"),
            "detail should mention missing dep 'a'"
        );
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

        let mut lockfile = binary_representable_lockfile();
        lockfile.add_package(lpm_lockfile::LockedPackage {
            instance_id: None,
            dependency_targets: std::collections::BTreeMap::new(),
            peer_targets: std::collections::BTreeMap::new(),
            name: "react".to_string(),
            version: "18.0.0".to_string(),
            source: None,
            integrity: None,
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

        let result = check_deps_in_sync(dir.path());
        let check = result.expect("should return a check");
        assert!(
            matches!(check.severity, Severity::Pass),
            "react should be found in lockfile"
        );
    }

    // ── Lockfile state checks ───────────────────────────────────────────

    #[test]
    fn lockfile_check_no_lockfile_warns() {
        let dir = tempfile::tempdir().unwrap();
        let checks = check_lockfile_state(dir.path());
        assert_eq!(checks.len(), 1);
        assert_eq!(checks[0].name(), "Lockfile");
        assert!(matches!(checks[0].severity, Severity::Warn));
        assert!(checks[0].detail.contains("not found"));
    }

    #[test]
    fn lockfile_check_representable_toml_warns_missing_binary() {
        let dir = tempfile::tempdir().unwrap();
        let lf = binary_representable_lockfile();
        lf.write_to_file(&dir.path().join("lpm.lock")).unwrap();

        let checks = check_lockfile_state(dir.path());
        assert_eq!(checks.len(), 2);
        assert_eq!(checks[0].name(), "Lockfile");
        assert!(matches!(checks[0].severity, Severity::Pass));
        assert_eq!(checks[1].name(), "Binary lockfile");
        assert!(matches!(checks[1].severity, Severity::Warn));
        assert!(checks[1].detail.contains("missing"));
    }

    fn lockfile_with_platform_metadata() -> lpm_lockfile::Lockfile {
        let mut lf = binary_representable_lockfile();
        lf.add_package(lpm_lockfile::LockedPackage {
            instance_id: None,
            dependency_targets: std::collections::BTreeMap::new(),
            peer_targets: std::collections::BTreeMap::new(),
            name: "native-pkg".to_string(),
            version: "1.0.0".to_string(),
            source: Some("registry+https://registry.npmjs.org".to_string()),
            integrity: None,
            manifest_fingerprint: None,
            registry_signatures: Vec::new(),
            registry_published_at: None,
            os: vec!["darwin".to_string()],
            cpu: Vec::new(),
            libc: Vec::new(),
            node_engine: None,
            optional: true,
            dependencies: vec![],
            alias_dependencies: vec![],
            peers: vec![],
            peer_edges: Vec::new(),
            tarball: None,
        });
        lf
    }

    #[test]
    fn lockfile_check_toml_only_metadata_allows_missing_binary() {
        let dir = tempfile::tempdir().unwrap();
        let lf = lockfile_with_platform_metadata();
        lf.write_to_file(&dir.path().join("lpm.lock")).unwrap();

        let checks = check_lockfile_state(dir.path());
        assert_eq!(checks.len(), 1);
        assert_eq!(checks[0].name(), "Lockfile");
        assert!(matches!(checks[0].severity, Severity::Pass));
    }

    #[test]
    fn lockfile_check_toml_only_metadata_warns_on_stale_binary() {
        let dir = tempfile::tempdir().unwrap();
        let representable = binary_representable_lockfile();
        lpm_lockfile::binary::write_binary(&representable, &dir.path().join("lpm.lockb")).unwrap();

        let lf = lockfile_with_platform_metadata();
        std::thread::sleep(std::time::Duration::from_millis(50));
        lf.write_to_file(&dir.path().join("lpm.lock")).unwrap();

        let checks = check_lockfile_state(dir.path());
        assert_eq!(checks.len(), 2);
        assert_eq!(checks[1].name(), "Binary lockfile");
        assert!(matches!(checks[1].severity, Severity::Warn));
        assert!(checks[1].detail.contains("TOML-only"));
    }

    #[test]
    fn lockfile_check_both_in_sync_passes() {
        let dir = tempfile::tempdir().unwrap();
        let lf = binary_representable_lockfile();
        // Write TOML first, then binary (so binary is newer)
        lf.write_to_file(&dir.path().join("lpm.lock")).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(50));
        lpm_lockfile::binary::write_binary(&lf, &dir.path().join("lpm.lockb")).unwrap();

        let checks = check_lockfile_state(dir.path());
        assert_eq!(checks.len(), 2);
        assert!(matches!(checks[0].severity, Severity::Pass));
        assert_eq!(checks[1].name(), "Binary lockfile");
        assert!(matches!(checks[1].severity, Severity::Pass));
        assert!(checks[1].detail.contains("in sync, valid"));
    }

    #[test]
    fn lockfile_check_stale_binary_warns() {
        let dir = tempfile::tempdir().unwrap();
        let lf = binary_representable_lockfile();
        // Write binary first (older), then TOML (newer)
        lpm_lockfile::binary::write_binary(&lf, &dir.path().join("lpm.lockb")).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(50));
        lf.write_to_file(&dir.path().join("lpm.lock")).unwrap();

        let checks = check_lockfile_state(dir.path());
        assert_eq!(checks.len(), 2);
        assert_eq!(checks[1].name(), "Binary lockfile");
        assert!(matches!(checks[1].severity, Severity::Warn));
        assert!(checks[1].detail.contains("stale"));
    }

    #[test]
    fn lockfile_check_corrupt_binary_warns() {
        let dir = tempfile::tempdir().unwrap();
        let lf = binary_representable_lockfile();
        lf.write_to_file(&dir.path().join("lpm.lock")).unwrap();
        // Write corrupt binary (newer than TOML)
        std::thread::sleep(std::time::Duration::from_millis(50));
        std::fs::write(dir.path().join("lpm.lockb"), b"BADMxxxxxxxxxxxxxxxxx").unwrap();

        let checks = check_lockfile_state(dir.path());
        assert_eq!(checks.len(), 2);
        assert_eq!(checks[1].name(), "Binary lockfile");
        assert!(matches!(checks[1].severity, Severity::Warn));
        assert!(checks[1].detail.contains("corrupt"));
    }

    // ── .gitattributes state checks ─────────────────────────────────────

    #[test]
    fn gitattributes_check_skipped_without_lockfiles() {
        let dir = tempfile::tempdir().unwrap();
        // No lpm.lock or lpm.lockb — should produce no checks
        let checks = check_gitattributes_state(dir.path());
        assert!(checks.is_empty());
    }

    #[test]
    fn gitattributes_check_missing_warns() {
        let dir = tempfile::tempdir().unwrap();
        let lf = binary_representable_lockfile();
        lf.write_to_file(&dir.path().join("lpm.lock")).unwrap();
        // No .gitattributes file

        let checks = check_gitattributes_state(dir.path());
        assert_eq!(checks.len(), 1);
        assert!(matches!(checks[0].severity, Severity::Warn));
        assert!(checks[0].detail.contains("missing"));
    }

    #[test]
    fn gitattributes_check_without_marker_warns() {
        let dir = tempfile::tempdir().unwrap();
        let lf = binary_representable_lockfile();
        lf.write_to_file(&dir.path().join("lpm.lock")).unwrap();
        std::fs::write(dir.path().join(".gitattributes"), "*.png binary\n").unwrap();

        let checks = check_gitattributes_state(dir.path());
        assert_eq!(checks.len(), 1);
        assert!(matches!(checks[0].severity, Severity::Warn));
        assert!(checks[0].detail.contains("not marked as binary"));
    }

    #[test]
    fn gitattributes_check_with_marker_passes() {
        let dir = tempfile::tempdir().unwrap();
        let lf = binary_representable_lockfile();
        lf.write_to_file(&dir.path().join("lpm.lock")).unwrap();
        std::fs::write(
            dir.path().join(".gitattributes"),
            "# lpm\nlpm.lockb binary\n",
        )
        .unwrap();

        let checks = check_gitattributes_state(dir.path());
        assert_eq!(checks.len(), 1);
        assert!(matches!(checks[0].severity, Severity::Pass));
        assert!(checks[0].detail.contains("marked as binary"));
    }

    // ── Fix execution tests ─────────────────────────────────────────────

    #[test]
    fn fix_binary_lockfile_regenerates_from_toml() {
        let dir = tempfile::tempdir().unwrap();
        let mut lf = binary_representable_lockfile();
        lf.add_package(lpm_lockfile::LockedPackage {
            instance_id: None,
            dependency_targets: std::collections::BTreeMap::new(),
            peer_targets: std::collections::BTreeMap::new(),
            name: "react".to_string(),
            version: "18.0.0".to_string(),
            source: Some("registry+https://registry.npmjs.org".to_string()),
            integrity: None,
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
        lf.write_to_file(&dir.path().join("lpm.lock")).unwrap();

        // No lpm.lockb exists yet
        assert!(!dir.path().join("lpm.lockb").exists());

        // Fix should create it
        fix_binary_lockfile(dir.path()).unwrap();
        assert!(dir.path().join("lpm.lockb").exists());

        // The regenerated binary should be valid and contain the same data
        let reader =
            lpm_lockfile::binary::BinaryLockfileReader::open(&dir.path().join("lpm.lockb"))
                .unwrap()
                .unwrap();
        assert_eq!(reader.package_count(), 1);
        let pkg = reader.find_package("react").unwrap();
        assert_eq!(pkg.version(), "18.0.0");
    }

    #[test]
    fn fix_binary_lockfile_overwrites_corrupt() {
        let dir = tempfile::tempdir().unwrap();
        let lf = binary_representable_lockfile();
        lf.write_to_file(&dir.path().join("lpm.lock")).unwrap();

        // Write corrupt binary
        std::fs::write(dir.path().join("lpm.lockb"), b"GARBAGE_DATA").unwrap();

        // Fix should overwrite with valid binary
        fix_binary_lockfile(dir.path()).unwrap();

        let reader =
            lpm_lockfile::binary::BinaryLockfileReader::open(&dir.path().join("lpm.lockb"))
                .unwrap()
                .unwrap();
        assert_eq!(reader.package_count(), 0);
    }

    #[test]
    fn fix_binary_lockfile_waits_for_install_transaction_and_uses_latest_toml() {
        let dir = tempfile::tempdir().unwrap();
        let initial = binary_representable_lockfile();
        initial.write_to_file(&dir.path().join("lpm.lock")).unwrap();
        let project_dir = dir.path().to_path_buf();
        let lock_path = lpm_common::project_install_lock(&project_dir);
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (finished_tx, finished_rx) = std::sync::mpsc::channel();

        lpm_common::with_exclusive_lock(&lock_path, || {
            let repair_project_dir = project_dir.clone();
            std::thread::spawn(move || {
                started_tx.send(()).unwrap();
                finished_tx
                    .send(fix_binary_lockfile(&repair_project_dir))
                    .unwrap();
            });
            started_rx.recv().unwrap();
            assert!(
                finished_rx
                    .recv_timeout(std::time::Duration::from_millis(200))
                    .is_err(),
                "lockfile repair must wait for the active install transaction"
            );

            let mut updated = binary_representable_lockfile();
            updated.add_package(lpm_lockfile::LockedPackage {
                name: "latest".to_string(),
                version: "2.0.0".to_string(),
                source: Some("registry+https://registry.npmjs.org".to_string()),
                ..Default::default()
            });
            updated
                .write_to_file(&project_dir.join("lpm.lock"))
                .unwrap();
            Ok::<_, lpm_common::LpmError>(())
        })
        .unwrap();

        finished_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("repair must finish after the install transaction releases its lock")
            .unwrap();
        let reader = lpm_lockfile::binary::BinaryLockfileReader::open(
            &project_dir.join(lpm_lockfile::BINARY_LOCKFILE_NAME),
        )
        .unwrap()
        .unwrap();
        assert!(reader.find_package("latest").is_some());
    }

    #[test]
    fn fix_binary_lockfile_removes_stale_binary_for_toml_only_metadata() {
        let dir = tempfile::tempdir().unwrap();
        let lf = lockfile_with_platform_metadata();
        lf.write_to_file(&dir.path().join("lpm.lock")).unwrap();
        std::fs::write(dir.path().join("lpm.lockb"), b"GARBAGE_DATA").unwrap();

        fix_binary_lockfile(dir.path()).unwrap();

        assert!(!dir.path().join("lpm.lockb").exists());
    }

    #[test]
    fn fix_binary_lockfile_fails_without_toml() {
        let dir = tempfile::tempdir().unwrap();
        // No lpm.lock
        let result = fix_binary_lockfile(dir.path());
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not found"));
    }

    #[test]
    fn fix_gitattributes_creates_file() {
        let dir = tempfile::tempdir().unwrap();
        assert!(!dir.path().join(".gitattributes").exists());

        fix_gitattributes(dir.path()).unwrap();

        let content = std::fs::read_to_string(dir.path().join(".gitattributes")).unwrap();
        assert!(content.contains("lpm.lockb binary"));
    }

    #[test]
    fn fix_gitattributes_appends_to_existing() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(".gitattributes"), "*.png binary\n").unwrap();

        fix_gitattributes(dir.path()).unwrap();

        let content = std::fs::read_to_string(dir.path().join(".gitattributes")).unwrap();
        assert!(content.contains("*.png binary"));
        assert!(content.contains("lpm.lockb binary"));
    }
}
