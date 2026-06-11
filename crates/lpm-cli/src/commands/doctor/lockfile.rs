use std::path::Path;

use crate::doctor_catalog;

use super::check::Check;

pub(super) fn check_lockfile_state(project_dir: &Path) -> Vec<Check> {
    let lockfile = project_dir.join("lpm.lock");
    let lockb_path = project_dir.join("lpm.lockb");
    let mut checks = Vec::new();

    if lockfile.exists() {
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
    let lockfile = project_dir.join("lpm.lock");
    let lockb_path = project_dir.join("lpm.lockb");
    let ga_path = project_dir.join(".gitattributes");
    let mut checks = Vec::new();

    if lockb_path.exists() || lockfile.exists() {
        if ga_path.exists() {
            let ga_content = std::fs::read_to_string(&ga_path).unwrap_or_default();
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
    let lock_path = project_dir.join("lpm.lock");
    if !lock_path.exists() {
        return Err("lpm.lock not found — cannot reconcile lpm.lockb".into());
    }
    let lf = lpm_lockfile::Lockfile::read_from_file(&lock_path)
        .map_err(|e| format!("read lpm.lock failed: {e}"))?;
    lf.write_all(&lock_path)
        .map_err(|e| format!("write lockfiles failed: {e}"))
}

/// Fix: ensure `.gitattributes` marks `lpm.lockb` as binary.
pub(super) fn fix_gitattributes(project_dir: &Path) -> Result<(), String> {
    lpm_lockfile::ensure_gitattributes(project_dir)
        .map_err(|e| format!(".gitattributes update failed: {e}"))
}

/// Check if lockfile dependencies match package.json dependencies.
///
/// Reads dep names from package.json and checks if they all appear in lpm.lock.
/// Detects "lockfile out of date" drift.
pub(super) fn check_deps_in_sync(project_dir: &Path) -> Option<Check> {
    let pkg_json_path = project_dir.join("package.json");
    let lockfile_path = project_dir.join("lpm.lock");

    let pkg_content = std::fs::read_to_string(&pkg_json_path).ok()?;
    let pkg: serde_json::Value = serde_json::from_str(&pkg_content).ok()?;

    let lockfile = lpm_lockfile::Lockfile::read_from_file(&lockfile_path).ok()?;

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
        let mut lockfile = lpm_lockfile::Lockfile::new();
        lockfile.add_package(lpm_lockfile::LockedPackage {
            name: "react".to_string(),
            version: "18.0.0".to_string(),
            source: None,
            integrity: None,
            registry_signatures: Vec::new(),
            registry_published_at: None,
            os: Vec::new(),
            cpu: Vec::new(),
            libc: Vec::new(),
            optional: false,
            dependencies: vec![],
            alias_dependencies: vec![],
            peers: vec![],
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

        let mut lockfile = lpm_lockfile::Lockfile::new();
        lockfile.add_package(lpm_lockfile::LockedPackage {
            name: "react".to_string(),
            version: "18.0.0".to_string(),
            source: None,
            integrity: None,
            registry_signatures: Vec::new(),
            registry_published_at: None,
            os: Vec::new(),
            cpu: Vec::new(),
            libc: Vec::new(),
            optional: false,
            dependencies: vec![],
            alias_dependencies: vec![],
            peers: vec![],
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
        let lf = lpm_lockfile::Lockfile::new();
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
        let mut lf = lpm_lockfile::Lockfile::new();
        lf.add_package(lpm_lockfile::LockedPackage {
            name: "native-pkg".to_string(),
            version: "1.0.0".to_string(),
            source: Some("registry+https://registry.npmjs.org".to_string()),
            integrity: None,
            registry_signatures: Vec::new(),
            registry_published_at: None,
            os: vec!["darwin".to_string()],
            cpu: Vec::new(),
            libc: Vec::new(),
            optional: true,
            dependencies: vec![],
            alias_dependencies: vec![],
            peers: vec![],
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
        let representable = lpm_lockfile::Lockfile::new();
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
        let lf = lpm_lockfile::Lockfile::new();
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
        let lf = lpm_lockfile::Lockfile::new();
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
        let lf = lpm_lockfile::Lockfile::new();
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
        let lf = lpm_lockfile::Lockfile::new();
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
        let lf = lpm_lockfile::Lockfile::new();
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
        let lf = lpm_lockfile::Lockfile::new();
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
        let mut lf = lpm_lockfile::Lockfile::new();
        lf.add_package(lpm_lockfile::LockedPackage {
            name: "react".to_string(),
            version: "18.0.0".to_string(),
            source: Some("registry+https://registry.npmjs.org".to_string()),
            integrity: None,
            registry_signatures: Vec::new(),
            registry_published_at: None,
            os: Vec::new(),
            cpu: Vec::new(),
            libc: Vec::new(),
            optional: false,
            dependencies: vec![],
            alias_dependencies: vec![],
            peers: vec![],
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
        let lf = lpm_lockfile::Lockfile::new();
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
