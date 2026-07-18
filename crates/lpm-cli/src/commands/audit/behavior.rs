use std::collections::{HashMap, HashSet};

use rayon::prelude::*;

use super::cache::ProjectAuditCache;
use super::discovery::{DiscoveredPackage, DiscoveryResult, ScanMode};
use super::inventory;
use super::policy::{AuditLevel, min_severity_level, severity_level};
use super::types::{AuditIssue, AuditResult};

/// Behavioral summary stats returned for the final output.
pub(super) struct BehavioralSummary {
    pub(super) packages_scanned: usize,
    pub(super) packages_with_findings: usize,
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
            packages_with_findings: 0,
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
    let baseline_index = lpm_root
        .as_ref()
        .and_then(|root| inventory::build_project_v2_baseline_index(&discovery.project_root, root));

    let mut scanned = 0usize;
    let mut with_findings = 0usize;

    let project_cache_ref = project_cache.as_ref();
    let loaded: Vec<LoadedBehavioralAnalysis> = scannable
        .par_iter()
        .filter_map(|pkg| {
            let source = if lpm_names.contains(pkg.name.as_str()) {
                "combined"
            } else {
                "local"
            };
            let cache_integrity = inventory::audit_cache_integrity(pkg);
            let cached_analysis = if pkg.scan_mode == ScanMode::RegistryAndStore {
                let store_analysis = if inventory::can_reuse_lpm_store_analysis(pkg) {
                    lpm_root
                        .as_ref()
                        .and_then(|root| {
                            inventory::find_project_baseline(
                                baseline_index.as_ref(),
                                root,
                                &pkg.name,
                                &pkg.version,
                            )
                        })
                        .and_then(|baseline| {
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

            let abs_path = discovery.project_root.join(&pkg.path);
            let (analysis, cache_update) = if let Some(analysis) = cached_analysis {
                (analysis, None)
            } else if abs_path.is_dir() {
                let analysis = lpm_security::behavioral::analyze_package(&abs_path);
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
        with_findings += 1;

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
        packages_with_findings: with_findings,
    }
}

/// Convert a PackageAnalysis into AuditIssues.
pub(super) fn analysis_to_issues(
    analysis: &lpm_security::behavioral::PackageAnalysis,
    source: &str,
) -> Vec<AuditIssue> {
    let mut issues = Vec::new();

    // Critical: obfuscated, protestware, high entropy
    if analysis.supply_chain.obfuscated {
        issues.push(AuditIssue {
            severity: "critical".into(),
            message: "obfuscated code detected".into(),
            category: "supply-chain".into(),
            source: source.into(),
        });
    }
    if analysis.supply_chain.protestware {
        issues.push(AuditIssue {
            severity: "critical".into(),
            message: "protestware patterns detected".into(),
            category: "supply-chain".into(),
            source: source.into(),
        });
    }
    // high_entropy_strings is informational, not critical. It fires on any package
    // with string literals above Shannon entropy 4.5, which includes legitimate
    // Base64 data, URL-encoded strings, hash constants, and bundled assets.
    // Only obfuscated + protestware are true critical supply-chain signals.
    if analysis.supply_chain.high_entropy_strings {
        issues.push(AuditIssue {
            severity: "info".into(),
            message: "high-entropy strings detected".into(),
            category: "supply-chain".into(),
            source: source.into(),
        });
    }

    // High: eval, child_process, shell, dynamic_require
    let s = &analysis.source;
    let mut dangerous = Vec::new();
    if s.eval {
        dangerous.push("eval()");
    }
    if s.child_process {
        dangerous.push("child_process");
    }
    if s.shell {
        dangerous.push("shell exec");
    }
    if s.dynamic_require {
        dangerous.push("dynamic require");
    }
    if !dangerous.is_empty() {
        issues.push(AuditIssue {
            severity: "high".into(),
            message: format!("uses {}", dangerous.join(", ")),
            category: "behavior".into(),
            source: source.into(),
        });
    }

    // Medium: network, native bindings, git/http/wildcard deps, no license
    let mut medium = Vec::new();
    if s.network {
        medium.push("network");
    }
    if s.native_bindings {
        medium.push("native bindings");
    }
    if analysis.manifest.git_dependency {
        medium.push("git dependency");
    }
    if analysis.manifest.http_dependency {
        medium.push("http dependency");
    }
    if analysis.manifest.wildcard_dependency {
        medium.push("wildcard dep");
    }
    if analysis.manifest.no_license {
        medium.push("no license");
    }
    if !medium.is_empty() {
        issues.push(AuditIssue {
            severity: "info".into(),
            message: format!("flags: {}", medium.join(", ")),
            category: "behavior".into(),
            source: source.into(),
        });
    }

    issues
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::audit::discovery::{ManagerKind, ScanMode};

    #[test]
    fn behavioral_summary_counts_only_findings_that_survive_level_filter() {
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
        };
        let mut results = Vec::new();

        let summary =
            run_behavioral_analysis(&discovery, &mut results, &[], false, Some(AuditLevel::High));

        assert_eq!(summary.packages_scanned, 1);
        assert_eq!(summary.packages_with_findings, 0);
        assert!(results.is_empty());
    }
}
