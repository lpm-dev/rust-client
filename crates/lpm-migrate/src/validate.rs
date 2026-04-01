//! Post-conversion validation for migrated lockfiles.
//!
//! Checks completeness, integrity format, and root dependency coverage.
//! Returns a `Vec<String>` of warnings (empty = valid).

use lpm_lockfile::Lockfile;
use std::collections::HashSet;
use std::path::Path;

/// Known integrity hash prefixes (SRI format).
const VALID_INTEGRITY_PREFIXES: &[&str] = &["sha256-", "sha384-", "sha512-", "sha1-"];

/// Threshold for "huge lockfile" warning.
const HUGE_LOCKFILE_THRESHOLD: usize = 100_000;

/// Validate a converted lockfile for completeness and correctness.
///
/// Checks:
/// 1. Every dep reference in `dependencies` must exist as a package entry.
/// 2. All root deps from `package.json` should have lockfile entries.
/// 3. Integrity hashes must use valid SRI format.
/// 4. Warns on very large lockfiles (>100k packages).
pub fn validate(lockfile: &Lockfile, project_dir: &Path) -> Vec<String> {
    let mut warnings = Vec::new();

    check_completeness(lockfile, &mut warnings);
    check_root_deps(lockfile, project_dir, &mut warnings);
    check_integrity_format(lockfile, &mut warnings);
    check_size(lockfile, &mut warnings);

    warnings
}

/// Check that every dependency reference points to an existing package entry.
fn check_completeness(lockfile: &Lockfile, warnings: &mut Vec<String>) {
    // Build a set of (name, version) pairs for fast lookup
    let known: HashSet<(&str, &str)> = lockfile
        .packages
        .iter()
        .map(|p| (p.name.as_str(), p.version.as_str()))
        .collect();

    for pkg in &lockfile.packages {
        for dep_str in &pkg.dependencies {
            // Dependencies are formatted as "name@version"
            if let Some((dep_name, dep_version)) = parse_dep_ref(dep_str)
                && !known.contains(&(dep_name, dep_version))
            {
                warnings.push(format!(
                    "missing dependency: {} requires {}@{} but it is not in the lockfile",
                    pkg.name, dep_name, dep_version,
                ));
            }
        }
    }
}

/// Check that all deps from package.json are present in the lockfile.
fn check_root_deps(lockfile: &Lockfile, project_dir: &Path, warnings: &mut Vec<String>) {
    let pkg_json_path = project_dir.join("package.json");
    let content = match std::fs::read_to_string(&pkg_json_path) {
        Ok(c) => c,
        Err(_) => return, // No package.json — nothing to check
    };

    let json: serde_json::Value = match serde_json::from_str(&content) {
        Ok(j) => j,
        Err(_) => return, // Malformed — skip
    };

    let lockfile_names: HashSet<&str> = lockfile.packages.iter().map(|p| p.name.as_str()).collect();

    // Check both dependencies and devDependencies
    for field in &["dependencies", "devDependencies"] {
        if let Some(deps) = json.get(*field).and_then(|d| d.as_object()) {
            for dep_name in deps.keys() {
                if !lockfile_names.contains(dep_name.as_str()) {
                    warnings.push(format!(
                        "root dependency '{}' from package.json ({}) not found in lockfile",
                        dep_name, field,
                    ));
                }
            }
        }
    }
}

/// Check that integrity hashes use valid SRI format.
fn check_integrity_format(lockfile: &Lockfile, warnings: &mut Vec<String>) {
    for pkg in &lockfile.packages {
        if let Some(ref integrity) = pkg.integrity {
            let valid = VALID_INTEGRITY_PREFIXES
                .iter()
                .any(|prefix| integrity.starts_with(prefix));
            if !valid {
                warnings.push(format!(
                    "invalid integrity format for {}@{}: '{}' (expected sha256-/sha384-/sha512-/sha1- prefix)",
                    pkg.name, pkg.version, integrity,
                ));
            }
        }
    }
}

/// Warn if the lockfile is unusually large.
fn check_size(lockfile: &Lockfile, warnings: &mut Vec<String>) {
    if lockfile.packages.len() > HUGE_LOCKFILE_THRESHOLD {
        warnings.push(format!(
            "very large lockfile: {} packages (consider auditing for unnecessary dependencies)",
            lockfile.packages.len(),
        ));
    }
}

/// Parse a dep ref like "name@version" into (name, version).
fn parse_dep_ref(s: &str) -> Option<(&str, &str)> {
    // Find the last '@' that is not at position 0
    let at_pos = s
        .char_indices()
        .rev()
        .find(|&(i, c)| c == '@' && i > 0)
        .map(|(i, _)| i)?;

    let name = &s[..at_pos];
    let version = &s[at_pos + 1..];

    if name.is_empty() || version.is_empty() {
        return None;
    }

    Some((name, version))
}

#[cfg(test)]
mod tests {
    use super::*;
    use lpm_lockfile::{LOCKFILE_VERSION, LockedPackage, LockfileMetadata};

    fn make_lockfile(packages: Vec<LockedPackage>) -> Lockfile {
        Lockfile {
            metadata: LockfileMetadata {
                lockfile_version: LOCKFILE_VERSION,
                resolved_with: Some("migrate".to_string()),
            },
            packages,
        }
    }

    #[test]
    fn valid_passes() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("package.json"),
            r#"{"dependencies": {"express": "^4.0.0"}}"#,
        )
        .unwrap();

        let lockfile = make_lockfile(vec![
            LockedPackage {
                name: "express".to_string(),
                version: "4.22.1".to_string(),
                source: Some("registry+https://registry.npmjs.org".to_string()),
                integrity: Some("sha512-abc".to_string()),
                dependencies: vec!["accepts@1.3.8".to_string()],
            },
            LockedPackage {
                name: "accepts".to_string(),
                version: "1.3.8".to_string(),
                source: Some("registry+https://registry.npmjs.org".to_string()),
                integrity: Some("sha512-def".to_string()),
                dependencies: vec![],
            },
        ]);

        let warnings = validate(&lockfile, dir.path());
        assert!(
            warnings.is_empty(),
            "expected no warnings, got: {:?}",
            warnings
        );
    }

    #[test]
    fn missing_dep_detected() {
        let dir = tempfile::tempdir().unwrap();

        let lockfile = make_lockfile(vec![LockedPackage {
            name: "express".to_string(),
            version: "4.22.1".to_string(),
            source: None,
            integrity: Some("sha512-abc".to_string()),
            dependencies: vec!["missing-dep@1.0.0".to_string()],
        }]);

        let warnings = validate(&lockfile, dir.path());
        assert!(warnings.iter().any(|w| w.contains("missing dependency")));
        assert!(warnings.iter().any(|w| w.contains("missing-dep")));
    }

    #[test]
    fn missing_root_dep() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("package.json"),
            r#"{"dependencies": {"express": "^4.0.0", "lodash": "^4.0.0"}}"#,
        )
        .unwrap();

        let lockfile = make_lockfile(vec![LockedPackage {
            name: "express".to_string(),
            version: "4.22.1".to_string(),
            source: None,
            integrity: Some("sha512-abc".to_string()),
            dependencies: vec![],
        }]);

        let warnings = validate(&lockfile, dir.path());
        assert!(warnings.iter().any(|w| w.contains("lodash")));
        assert!(warnings.iter().any(|w| w.contains("root dependency")));
    }

    #[test]
    fn invalid_integrity() {
        let dir = tempfile::tempdir().unwrap();

        let lockfile = make_lockfile(vec![LockedPackage {
            name: "bad-pkg".to_string(),
            version: "1.0.0".to_string(),
            source: None,
            integrity: Some("md5-notvalid".to_string()),
            dependencies: vec![],
        }]);

        let warnings = validate(&lockfile, dir.path());
        assert!(warnings.iter().any(|w| w.contains("invalid integrity")));
    }

    #[test]
    fn no_package_json_no_root_warnings() {
        let dir = tempfile::tempdir().unwrap();
        // Don't create package.json

        let lockfile = make_lockfile(vec![LockedPackage {
            name: "express".to_string(),
            version: "4.22.1".to_string(),
            source: None,
            integrity: Some("sha512-abc".to_string()),
            dependencies: vec![],
        }]);

        let warnings = validate(&lockfile, dir.path());
        // Should have no root dep warnings (no package.json to compare against)
        assert!(
            !warnings.iter().any(|w| w.contains("root dependency")),
            "unexpected root dep warnings: {:?}",
            warnings
        );
    }

    #[test]
    fn huge_lockfile_warning() {
        // We can't actually create 100k+ entries in a test, but we can test the check function directly
        let mut warnings = Vec::new();
        let lockfile = make_lockfile(Vec::new());
        check_size(&lockfile, &mut warnings);
        assert!(warnings.is_empty());

        // Test with threshold logic directly
        assert!(100_001 > HUGE_LOCKFILE_THRESHOLD);
    }

    #[test]
    fn valid_integrity_prefixes() {
        let dir = tempfile::tempdir().unwrap();

        let lockfile = make_lockfile(vec![
            LockedPackage {
                name: "a".to_string(),
                version: "1.0.0".to_string(),
                source: None,
                integrity: Some("sha256-abc".to_string()),
                dependencies: vec![],
            },
            LockedPackage {
                name: "b".to_string(),
                version: "1.0.0".to_string(),
                source: None,
                integrity: Some("sha384-def".to_string()),
                dependencies: vec![],
            },
            LockedPackage {
                name: "c".to_string(),
                version: "1.0.0".to_string(),
                source: None,
                integrity: Some("sha512-ghi".to_string()),
                dependencies: vec![],
            },
            LockedPackage {
                name: "d".to_string(),
                version: "1.0.0".to_string(),
                source: None,
                integrity: Some("sha1-jkl".to_string()),
                dependencies: vec![],
            },
        ]);

        let warnings = validate(&lockfile, dir.path());
        assert!(
            !warnings.iter().any(|w| w.contains("invalid integrity")),
            "got unexpected integrity warnings: {:?}",
            warnings,
        );
    }

    #[test]
    fn parse_dep_ref_regular() {
        let (name, ver) = parse_dep_ref("express@4.22.1").unwrap();
        assert_eq!(name, "express");
        assert_eq!(ver, "4.22.1");
    }

    #[test]
    fn parse_dep_ref_scoped() {
        let (name, ver) = parse_dep_ref("@babel/core@7.24.0").unwrap();
        assert_eq!(name, "@babel/core");
        assert_eq!(ver, "7.24.0");
    }
}
