use std::collections::{HashMap, HashSet};

use lpm_security::query::{PseudoClass, Severity, TagGroup, behavioral_tag_policies};
use rayon::prelude::*;

use super::cache::ProjectAuditCache;
use super::discovery::{DiscoveredPackage, DiscoveryResult, ScanMode};
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
/// For LPM store packages: reads existing `.lpm-security.json` from the store.
/// For node_modules packages: scans source code, caches in `.lpm/audit-cache.json`.
pub(super) fn run_behavioral_analysis(
    discovery: &DiscoveryResult,
    results: &mut Vec<AuditResult>,
    lpm_packages: &[(String, String)],
    _json_output: bool,
    level: Option<AuditLevel>,
    store_version: lpm_store::StoreVersion,
) -> BehavioralSummary {
    struct LoadedBehavioralAnalysis {
        name: String,
        version: String,
        source: &'static str,
        analysis: lpm_security::behavioral::PackageAnalysis,
        cache_update: Option<BehavioralCacheUpdate>,
    }

    struct BehavioralCacheUpdate {
        path: String,
        name: String,
        version: String,
        integrity: Option<String>,
        analysis: lpm_security::behavioral::PackageAnalysis,
        dependencies: Vec<(String, String)>,
    }

    let scannable: Vec<&DiscoveredPackage> = discovery
        .packages
        .iter()
        .filter(|p| {
            matches!(
                p.scan_mode,
                ScanMode::FullLocal | ScanMode::RegistryAndStore
            )
        })
        .collect();

    if scannable.is_empty() {
        return BehavioralSummary {
            packages_scanned: 0,
            packages_with_actionable_findings: 0,
        };
    }

    let lpm_names: HashSet<&str> = lpm_packages.iter().map(|(n, _)| n.as_str()).collect();

    // Build index of existing results for O(1) merge.
    // Key by "name@version" to handle multiple instances of the same package
    // at different versions (e.g., qs@6.5.3 nested under express vs qs@6.14.0 hoisted).
    let mut results_by_key: HashMap<String, usize> = results
        .iter()
        .enumerate()
        .map(|(i, r)| (format!("{}@{}", r.name, r.version), i))
        .collect();

    // Load project-level audit cache. Used by all project types:
    // - npm/pnpm/yarn/bun: primary cache for node_modules scans
    // - lpm: fallback cache when store entries are missing
    let mut project_cache = ProjectAuditCache::read(&discovery.project_root);

    let lpm_root = lpm_common::LpmRoot::from_env().ok();
    let baseline_index = lpm_root.as_ref().map(|root| {
        inventory::build_project_v2_baseline_index(&discovery.project_root, root, store_version)
    });

    let mut scanned = 0usize;
    let mut with_actionable_findings = 0usize;

    let project_cache_ref = project_cache.as_ref();
    let project_root_directory = open_project_root(&discovery.project_root).ok();
    let loaded: Vec<LoadedBehavioralAnalysis> = scannable
        .par_iter()
        .filter_map(|pkg| {
            let source = if lpm_names.contains(pkg.name.as_str()) {
                "combined"
            } else {
                "local"
            };
            let cache_integrity = inventory::audit_cache_integrity(pkg);
            let store_baseline = if pkg.scan_mode == ScanMode::RegistryAndStore {
                lpm_root.as_ref().and_then(|root| {
                    inventory::find_project_baseline(
                        baseline_index.as_ref(),
                        root,
                        &pkg.name,
                        &pkg.version,
                    )
                })
            } else {
                None
            };
            let cached_analysis = if pkg.scan_mode == ScanMode::RegistryAndStore {
                let store_analysis = if inventory::can_reuse_lpm_store_analysis(pkg) {
                    store_baseline.as_ref().and_then(|baseline| {
                        lpm_security::behavioral::read_cached_analysis(&baseline.package_dir)
                    })
                } else {
                    None
                };
                store_analysis.or_else(|| {
                    project_cache_ref
                        .and_then(|c| c.get(&pkg.path, cache_integrity))
                        .cloned()
                })
            } else {
                project_cache_ref
                    .and_then(|c| c.get(&pkg.path, cache_integrity))
                    .cloned()
            };

            let (analysis, cache_update) = if let Some(analysis) = cached_analysis {
                (analysis, None)
            } else if let Some(package_directory) = store_baseline
                .as_ref()
                .and_then(|baseline| open_project_root(&baseline.package_dir).ok())
                .or_else(|| {
                    project_root_directory
                        .as_ref()
                        .and_then(|root| open_relative_directory_nofollow(root, &pkg.path).ok())
                })
            {
                let analysis =
                    lpm_security::behavioral::analyze_package_from_open_dir(&package_directory);
                let cache_update = BehavioralCacheUpdate {
                    path: pkg.path.clone(),
                    name: pkg.name.clone(),
                    version: pkg.version.clone(),
                    integrity: pkg.patch_sha256.clone().or_else(|| pkg.integrity.clone()),
                    analysis: analysis.clone(),
                    dependencies: pkg.dependencies.clone(),
                };
                (analysis, Some(cache_update))
            } else {
                return None;
            };

            Some(LoadedBehavioralAnalysis {
                name: pkg.name.clone(),
                version: pkg.version.clone(),
                source,
                analysis,
                cache_update,
            })
        })
        .collect();

    for loaded in loaded {
        if let Some(update) = loaded.cache_update {
            if project_cache.is_none() {
                project_cache = Some(ProjectAuditCache::new(&discovery.manager.to_string()));
            }
            if let Some(ref mut cache) = project_cache {
                cache.insert(
                    update.path,
                    update.name,
                    update.version,
                    update.integrity,
                    update.analysis,
                    update.dependencies,
                );
            }
        }

        scanned += 1;

        let mut issues = analysis_to_issues(&loaded.analysis, loaded.source);
        if issues.is_empty() {
            continue;
        }

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

        // Merge into existing result (for @lpm.dev) or create new entry (npm).
        // Key by "name@version" so different versions of the same package stay separate.
        let merge_key = format!("{}@{}", loaded.name, loaded.version);
        if let Some(&idx) = results_by_key.get(&merge_key) {
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
                name: loaded.name,
                version: loaded.version,
                quality_score: None,
                issues,
            });
            results_by_key.insert(merge_key, idx);
        }
    }

    // Write project cache back to disk
    if let Some(ref cache) = project_cache
        && let Err(e) = cache.write(&discovery.project_root)
    {
        tracing::debug!("failed to write audit cache: {e}");
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

fn open_project_root(path: &std::path::Path) -> std::io::Result<cap_std::fs::Dir> {
    if !path.is_absolute() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "audit project root must be absolute",
        ));
    }
    cap_std::fs::Dir::open_ambient_dir(path, cap_std::ambient_authority())
}

fn open_relative_directory_nofollow(
    root: &cap_std::fs::Dir,
    relative: &str,
) -> std::io::Result<cap_std::fs::Dir> {
    use cap_fs_ext::DirExt as _;

    let mut directory = root.try_clone()?;
    for component in std::path::Path::new(relative).components() {
        let std::path::Component::Normal(name) = component else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "audit package path contains an unsafe component",
            ));
        };
        directory = directory.open_dir_nofollow(name)?;
    }
    Ok(directory)
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
    use crate::commands::audit::discovery::{ManagerKind, ScanMode};

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
                path: "node_modules/info-only".to_string(),
                integrity: None,
                patch_sha256: None,
                resolved_url: None,
                scan_mode: ScanMode::FullLocal,
                is_dev: false,
                is_optional: false,
                dependencies: Vec::new(),
            }],
            lpm_lockfile: None,
            lpm_lockfile_content: None,
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
                path: "node_modules/replaced".to_string(),
                integrity: Some("sha512-replaced".to_string()),
                patch_sha256: None,
                resolved_url: None,
                scan_mode: ScanMode::FullLocal,
                is_dev: false,
                is_optional: false,
                dependencies: Vec::new(),
            }],
            lpm_lockfile: None,
            lpm_lockfile_content: None,
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
