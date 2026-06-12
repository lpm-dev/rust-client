use crate::output;
use lpm_common::color::Painted;
use std::path::Path;

/// Print security warnings for a single package version.
pub fn print_security_warnings(
    name: &str,
    version: &str,
    ver_meta: &lpm_registry::VersionMetadata,
) {
    let mut warnings: Vec<String> = Vec::new();

    if let Some(findings) = &ver_meta.security_findings {
        for finding in findings {
            let severity = finding.severity.as_deref().unwrap_or("info");
            let desc = finding
                .description
                .as_deref()
                .unwrap_or("security concern detected");
            warnings.push(format!("[{}] {}", severity, desc));
        }
    }

    if let Some(tags) = &ver_meta.behavioral_tags {
        let mut dangerous = Vec::new();
        if tags.eval {
            dangerous.push("eval()");
        }
        if tags.child_process {
            dangerous.push("child_process");
        }
        if tags.shell {
            dangerous.push("shell exec");
        }
        if tags.dynamic_require {
            dangerous.push("dynamic require");
        }
        if !dangerous.is_empty() {
            warnings.push(format!("uses {}", dangerous.join(", ")));
        }
    }

    if let Some(scripts) = &ver_meta.lifecycle_scripts {
        let script_names: Vec<&str> = scripts.keys().map(|s| s.as_str()).collect();
        if !script_names.is_empty() {
            warnings.push(format!(
                "has lifecycle scripts: {}",
                script_names.join(", ")
            ));
        }
    }

    if warnings.is_empty() {
        return;
    }

    println!();
    output::warn(&format!(
        "{} ({}) has {} issue(s):",
        name.bold(),
        version,
        warnings.len()
    ));
    for warning in &warnings {
        println!("    {} {}", "\u{26a0}".yellow(), warning);
    }
    println!("  Run {} for details", "lpm audit".bold());
}

/// Typosquatting warning returned when a package name is suspiciously similar to a popular package.
pub(super) struct TyposquatWarning {
    /// The bare name the user typed.
    pub(super) input: String,
    /// The popular package it's similar to.
    pub(super) similar: String,
}

/// Check if a package name should trigger a typosquatting warning.
///
/// Returns `None` (no warning) if:
/// - The name is an exact match for a popular package
/// - The name is not similar to any popular package
/// - The exact package name is already present in the lockfile (user accepted it before)
/// - The lockfile doesn't exist or can't be read (fail-open: skip lockfile check, still warn)
pub(super) fn should_warn_typosquatting(
    pkg_ref: &str,
    project_dir: &Path,
) -> Option<TyposquatWarning> {
    let bare_name = pkg_ref.strip_prefix("@lpm.dev/").unwrap_or(pkg_ref);

    // If the name is in the lockfile, the user has already accepted it — skip the warning.
    let in_lockfile =
        lpm_lockfile::Lockfile::read_fast(&project_dir.join(lpm_lockfile::LOCKFILE_NAME))
            .is_ok_and(|lf| lf.packages.iter().any(|p| p.name == pkg_ref));

    if in_lockfile {
        return None;
    }

    lpm_security::typosquatting::check_typosquatting(bare_name).map(|similar| TyposquatWarning {
        input: bare_name.to_string(),
        similar: similar.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// Create a minimal lockfile with the given package names.
    fn write_lockfile(dir: &Path, package_names: &[&str]) {
        let mut lockfile = lpm_lockfile::Lockfile::new();
        for name in package_names {
            lockfile.add_package(lpm_lockfile::LockedPackage {
                name: name.to_string(),
                version: "1.0.0".to_string(),
                source: None,
                integrity: None,
                registry_signatures: Vec::new(),
                registry_published_at: None,
                os: Vec::new(),
                cpu: Vec::new(),
                libc: Vec::new(),
                optional: false,
                dependencies: Vec::new(),
                alias_dependencies: vec![],
                peers: vec![],
                tarball: None,
            });
        }
        let path = dir.join(lpm_lockfile::LOCKFILE_NAME);
        let toml = toml::to_string_pretty(&lockfile).unwrap();
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(toml.as_bytes()).unwrap();
    }

    #[test]
    fn typosquatting_warns_when_not_in_lockfile() {
        let dir = tempfile::tempdir().unwrap();
        // No lockfile — "loadash" should warn (similar to "lodash")
        let result = should_warn_typosquatting("loadash", dir.path());
        assert!(result.is_some(), "should warn when no lockfile exists");
        assert_eq!(result.unwrap().similar, "lodash");
    }

    #[test]
    fn typosquatting_warns_when_lockfile_exists_but_package_absent() {
        let dir = tempfile::tempdir().unwrap();
        write_lockfile(dir.path(), &["react", "express"]);
        // "loadash" is NOT in lockfile — should warn
        let result = should_warn_typosquatting("loadash", dir.path());
        assert!(result.is_some(), "should warn when package not in lockfile");
        assert_eq!(result.unwrap().similar, "lodash");
    }

    #[test]
    fn typosquatting_skips_when_package_in_lockfile() {
        let dir = tempfile::tempdir().unwrap();
        // "loadash" is IN the lockfile — the user has accepted it, no warning
        write_lockfile(dir.path(), &["loadash"]);
        let result = should_warn_typosquatting("loadash", dir.path());
        assert!(
            result.is_none(),
            "should NOT warn when package is in lockfile"
        );
    }

    #[test]
    fn typosquatting_skips_exact_match() {
        let dir = tempfile::tempdir().unwrap();
        // "lodash" is an exact match — not a typosquat
        let result = should_warn_typosquatting("lodash", dir.path());
        assert!(result.is_none(), "exact match should not warn");
    }

    #[test]
    fn typosquatting_lockfile_skip_works_for_scoped_packages() {
        let dir = tempfile::tempdir().unwrap();
        // Scoped LPM package in lockfile
        write_lockfile(dir.path(), &["@lpm.dev/owner.loadash"]);
        let result = should_warn_typosquatting("@lpm.dev/owner.loadash", dir.path());
        assert!(
            result.is_none(),
            "scoped package in lockfile should not warn"
        );
    }

    #[test]
    fn typosquatting_lockfile_skip_does_not_cross_match() {
        let dir = tempfile::tempdir().unwrap();
        // "lodash" is in lockfile but "loadash" is NOT — should still warn
        write_lockfile(dir.path(), &["lodash"]);
        let result = should_warn_typosquatting("loadash", dir.path());
        assert!(
            result.is_some(),
            "different package name should still warn even if lockfile has the real one"
        );
    }
}
