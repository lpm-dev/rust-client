use std::collections::{HashMap, HashSet};

use lpm_security::query::{PseudoClass, Severity, TagGroup, behavioral_tag_policies};

use super::discovery::{DiscoveredPackage, DiscoveryResult, ManagerKind, ScanMode};
use super::inventory;
use super::policy::{AuditLevel, min_severity_level, severity_level};
use super::types::{AuditIssue, AuditResult};

/// Behavioral summary stats returned for the final output.
pub(super) struct BehavioralSummary {
    pub(super) packages_scanned: usize,
    pub(super) packages_with_actionable_findings: usize,
}

/// Run behavioral analysis on all scannable packages.
///
pub(super) fn run_behavioral_analysis(
    discovery: &DiscoveryResult,
    results: &mut Vec<AuditResult>,
    lpm_packages: &[(String, String)],
    _json_output: bool,
    level: Option<AuditLevel>,
    store_version: lpm_store::StoreVersion,
) -> BehavioralSummary {
    let scannable_count = discovery
        .packages
        .iter()
        .filter(|package| {
            matches!(
                package.scan_mode,
                ScanMode::FullLocal | ScanMode::RegistryAndStore
            )
        })
        .count();

    if scannable_count == 0 {
        return BehavioralSummary {
            packages_scanned: 0,
            packages_with_actionable_findings: 0,
        };
    }

    let lpm_names: HashSet<&str> = lpm_packages.iter().map(|(n, _)| n.as_str()).collect();

    let mut results_by_key: HashMap<String, usize> = results
        .iter()
        .enumerate()
        .map(|(index, result)| {
            let key = audit_result_key(result);
            (key, index)
        })
        .collect();

    let (analyses, source_paths) = inventory::load_behavioral_analyses(discovery, store_version);

    let mut scanned = 0usize;
    let mut with_actionable_findings = 0usize;

    for ((pkg, analysis), source_path) in discovery.packages.iter().zip(analyses).zip(source_paths)
    {
        let Some(analysis) = analysis else {
            continue;
        };
        let source = if lpm_names.contains(pkg.name.as_str()) {
            "combined"
        } else {
            "local"
        };
        scanned += 1;

        let resolved_path = source_path.map_or_else(
            || pkg.path.clone(),
            |path| path.to_string_lossy().into_owned(),
        );
        let merge_key = package_result_key(discovery.manager, pkg);
        let existing_result = results_by_key.get(&merge_key).copied();
        if let Some(index) = existing_result {
            results[index].path = Some(resolved_path.clone());
        }

        let mut issues = analysis_to_issues(&analysis, source);

        // Apply --level filter
        if let Some(lvl) = level {
            let min_lvl = min_severity_level(lvl);
            issues.retain(|issue| severity_level(&issue.severity) >= min_lvl);
            if issues.is_empty() {
                continue;
            }
        }
        if issues.iter().any(|issue| issue.severity != "info") {
            with_actionable_findings += 1;
        }

        if issues.is_empty() {
            continue;
        }

        // Merge into an exact registry result or create a local result.
        if let Some(idx) = existing_result {
            // Dedup: don't add issues with the same message already present from registry
            let existing_messages: HashSet<String> = results[idx]
                .issues
                .iter()
                .map(|i| i.message.clone())
                .collect();
            for issue in issues {
                if !existing_messages.contains(&issue.message) {
                    results[idx].issues.push(issue);
                }
            }
        } else {
            let idx = results.len();
            results.push(AuditResult {
                identity: merge_key.clone(),
                name: pkg.name.clone(),
                version: pkg.version.clone(),
                instance_id: pkg.instance_id,
                path: Some(resolved_path),
                quality_score: None,
                issues,
            });
            results_by_key.insert(merge_key, idx);
        }
    }

    // Re-filter merged results by --level if provided
    if let Some(lvl) = level {
        let min_lvl = min_severity_level(lvl);
        for result in results.iter_mut() {
            result
                .issues
                .retain(|issue| severity_level(&issue.severity) >= min_lvl);
        }
    }

    BehavioralSummary {
        packages_scanned: scanned,
        packages_with_actionable_findings: with_actionable_findings,
    }
}

fn audit_result_key(result: &AuditResult) -> String {
    result.identity.clone()
}

pub(super) fn package_result_key(manager: ManagerKind, package: &DiscoveredPackage) -> String {
    if package.instance_id.is_some() || manager != ManagerKind::Lpm {
        package.analysis_key()
    } else {
        format!("{}@{}", package.name, package.version)
    }
}

/// Convert a PackageAnalysis into AuditIssues.
pub(super) fn analysis_to_issues(
    analysis: &lpm_security::behavioral::PackageAnalysis,
    source: &str,
) -> Vec<AuditIssue> {
    behavioral_tag_policies()
        .iter()
        .filter(|policy| policy.tag.matches_analysis(analysis))
        .filter_map(|policy| behavioral_issue(policy.tag, source))
        .collect()
}

pub(super) fn behavioral_issue(tag: PseudoClass, source: &str) -> Option<AuditIssue> {
    let policy = tag.behavioral_policy()?;
    let category = match policy.group {
        TagGroup::SupplyChain => "supply-chain",
        TagGroup::Source | TagGroup::Manifest => "behavior",
    };
    let severity = match policy.severity {
        Severity::Critical => "critical",
        Severity::High => "high",
        Severity::Medium => "moderate",
        Severity::Info => "info",
    };
    Some(AuditIssue {
        severity: severity.to_string(),
        message: policy.label.to_string(),
        category: category.to_string(),
        source: source.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::audit::discovery::{DiscoveredPackage, ManagerKind, ScanMode};

    #[test]
    fn behavioral_summary_counts_only_actionable_findings_that_survive_level_filter() {
        let project = tempfile::tempdir().unwrap();
        let package_dir = project.path().join("node_modules/info-only");
        std::fs::create_dir_all(&package_dir).unwrap();
        std::fs::write(
            package_dir.join("package.json"),
            r#"{"name":"info-only","version":"1.0.0"}"#,
        )
        .unwrap();
        std::fs::write(package_dir.join("index.js"), "module.exports = 1;\n").unwrap();
        let discovery = DiscoveryResult {
            manager: ManagerKind::FallbackNodeModules,
            lockfile_path: None,
            project_root: project.path().to_path_buf(),
            is_degraded: true,
            is_yarn_pnp: false,
            packages: vec![DiscoveredPackage {
                name: "info-only".to_string(),
                version: "1.0.0".to_string(),
                instance_id: None,
                path: "node_modules/info-only".to_string(),
                integrity: None,
                patch_sha256: None,
                resolved_url: None,
                local_source_dir: None,
                scan_mode: ScanMode::FullLocal,
                is_dev: false,
                is_optional: false,
                dependencies: Vec::new(),
            }],
            lpm_lockfile: None,
            lpm_lockfile_content: None,
            workspace_root: None,
        };
        let mut results = Vec::new();

        let summary = run_behavioral_analysis(
            &discovery,
            &mut results,
            &[],
            false,
            Some(AuditLevel::High),
            lpm_store::StoreVersion::V2,
        );

        assert_eq!(summary.packages_scanned, 1);
        assert_eq!(summary.packages_with_actionable_findings, 0);
        assert!(results.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn behavioral_scan_does_not_follow_a_replaced_package_root() {
        use std::os::unix::fs::symlink;

        let project = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let package_dir = project.path().join("node_modules/replaced");
        std::fs::create_dir_all(&package_dir).unwrap();
        std::fs::write(
            package_dir.join("package.json"),
            r#"{"name":"replaced","version":"1.0.0"}"#,
        )
        .unwrap();
        std::fs::write(package_dir.join("index.js"), "module.exports = 1;\n").unwrap();
        std::fs::write(
            outside.path().join("package.json"),
            r#"{"name":"outside","version":"9.0.0"}"#,
        )
        .unwrap();
        std::fs::write(outside.path().join("index.js"), "eval('outside')\n").unwrap();
        let discovery = DiscoveryResult {
            manager: ManagerKind::Npm,
            lockfile_path: None,
            project_root: project.path().to_path_buf(),
            is_degraded: false,
            is_yarn_pnp: false,
            packages: vec![DiscoveredPackage {
                name: "replaced".to_string(),
                version: "1.0.0".to_string(),
                instance_id: None,
                path: "node_modules/replaced".to_string(),
                integrity: Some("sha512-replaced".to_string()),
                patch_sha256: None,
                resolved_url: None,
                local_source_dir: None,
                scan_mode: ScanMode::FullLocal,
                is_dev: false,
                is_optional: false,
                dependencies: Vec::new(),
            }],
            lpm_lockfile: None,
            lpm_lockfile_content: None,
            workspace_root: None,
        };
        std::fs::rename(&package_dir, project.path().join("detached-package")).unwrap();
        symlink(outside.path(), &package_dir).unwrap();
        let mut results = Vec::new();

        let summary = run_behavioral_analysis(
            &discovery,
            &mut results,
            &[],
            false,
            None,
            lpm_store::StoreVersion::V2,
        );

        assert_eq!(summary.packages_scanned, 0);
        assert!(results.is_empty());
    }
}
