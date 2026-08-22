use std::path::Path;

use lpm_common::LpmError;
use lpm_registry::RegistryClient;

use super::behavior::{BehavioralSummary, package_result_key, run_behavioral_analysis};
use super::discovery::{self, DiscoveryResult, ScanMode};
use super::osv::{OsvVulnerability, collect_osv_queries, run_osv_queries};
use super::policy::{AuditLevel, min_severity_level, severity_level};
use super::registry::registry_audit_result;
use super::types::AuditResult;

pub(super) struct AuditScan {
    pub(super) discovery: DiscoveryResult,
    pub(super) lpm_packages: Vec<(String, String)>,
    pub(super) results: Vec<AuditResult>,
    pub(super) behavioral: BehavioralSummary,
    pub(super) osv_vulnerabilities: Vec<OsvVulnerability>,
    pub(super) osv_degraded_reason: Option<String>,
    pub(super) checked_lpm: usize,
}

pub(super) async fn run_scan(
    client: &RegistryClient,
    project_dir: &Path,
    store_version: lpm_store::StoreVersion,
    json_output: bool,
    level: Option<AuditLevel>,
) -> Result<AuditScan, LpmError> {
    let discovery = discovery::discover_packages_retaining_parsed_lpm_lockfile(project_dir)?;
    let lpm_packages: Vec<(String, String)> = discovery
        .packages
        .iter()
        .filter(|package| package.name.starts_with("@lpm.dev/"))
        .map(|package| (package.name.clone(), package.version.clone()))
        .collect();
    let needs_store_lock = discovery
        .packages
        .iter()
        .any(|package| matches!(package.scan_mode, ScanMode::RegistryAndStore));
    let store_lock = if needs_store_lock {
        Some(lpm_common::LpmRoot::from_env()?.store_lock())
    } else {
        None
    };

    let registry_task = if lpm_packages.is_empty() {
        None
    } else {
        let names: Vec<String> = lpm_packages.iter().map(|(name, _)| name.clone()).collect();
        let client = client.clone_with_config();
        Some(tokio::spawn(async move {
            client.batch_metadata(&names).await.map_err(|error| {
                LpmError::Registry(format!(
                    "LPM registry metadata lookup failed during audit: {error}"
                ))
            })
        }))
    };
    let osv_task = tokio::spawn(run_osv_queries(
        collect_osv_queries(&discovery.packages),
        json_output,
        level,
    ));

    let mut behavioral_results = Vec::with_capacity(discovery.packages.len());

    let behavioral = if let Some(lock_path) = store_lock {
        let mut summary = None;
        lpm_common::with_shared_lock(lock_path, || {
            summary = Some(run_behavioral_analysis(
                &discovery,
                &mut behavioral_results,
                &lpm_packages,
                json_output,
                level,
                store_version,
            ));
            Ok(())
        })
        .map(|()| summary.expect("behavioral summary is set while the shared lock is held"))
    } else {
        Ok(run_behavioral_analysis(
            &discovery,
            &mut behavioral_results,
            &lpm_packages,
            json_output,
            level,
            store_version,
        ))
    };

    let registry_result = async {
        match registry_task {
            Some(task) => task
                .await
                .map_err(|error| LpmError::Script(format!("audit registry task failed: {error}")))?
                .map(Some),
            None => Ok(None),
        }
    };
    let (metadata_map, osv_outcome) = tokio::join!(registry_result, osv_task);
    let metadata_map = metadata_map?;
    let osv_outcome =
        osv_outcome.map_err(|error| LpmError::Script(format!("audit OSV task failed: {error}")))?;
    let behavioral = behavioral?;

    let mut results = Vec::with_capacity(lpm_packages.len() + behavioral_results.len());
    let mut checked_lpm = 0usize;
    if let Some(metadata_map) = metadata_map {
        for package in discovery
            .packages
            .iter()
            .filter(|package| package.name.starts_with("@lpm.dev/"))
        {
            let metadata = metadata_map.get(&package.name).ok_or_else(|| {
                LpmError::Registry(format!(
                    "LPM registry returned no metadata for installed package {}@{}",
                    package.name, package.version,
                ))
            })?;
            let version_metadata = metadata.version(&package.version).ok_or_else(|| {
                LpmError::Registry(format!(
                    "LPM registry metadata omitted installed version {}@{}",
                    package.name, package.version,
                ))
            })?;
            checked_lpm += 1;

            let mut result =
                registry_audit_result(&package.name, &package.version, version_metadata);
            result.identity = package_result_key(discovery.manager, package);
            result.instance_id = package.instance_id;
            result.path = Some(package.path.clone());
            results.push(result);
        }
    }
    merge_behavioral_results(&mut results, behavioral_results);
    if let Some(level) = level {
        let minimum = min_severity_level(level);
        for result in &mut results {
            result
                .issues
                .retain(|issue| severity_level(&issue.severity) >= minimum);
        }
    }

    Ok(AuditScan {
        discovery,
        lpm_packages,
        results,
        behavioral,
        osv_vulnerabilities: osv_outcome.vulns,
        osv_degraded_reason: osv_outcome.degraded_reason,
        checked_lpm,
    })
}

fn merge_behavioral_results(results: &mut Vec<AuditResult>, behavioral: Vec<AuditResult>) {
    let mut result_indexes = std::collections::HashMap::with_capacity(results.len());
    for (index, result) in results.iter().enumerate() {
        result_indexes.insert(result.identity.clone(), index);
    }

    for mut local_result in behavioral {
        let Some(index) = result_indexes.get(&local_result.identity).copied() else {
            result_indexes.insert(local_result.identity.clone(), results.len());
            results.push(local_result);
            continue;
        };
        let result = &mut results[index];
        if local_result.path.is_some() {
            result.path = local_result.path.take();
        }
        let existing_messages: std::collections::HashSet<&str> = result
            .issues
            .iter()
            .map(|issue| issue.message.as_str())
            .collect();
        local_result
            .issues
            .retain(|issue| !existing_messages.contains(issue.message.as_str()));
        drop(existing_messages);
        result.issues.extend(local_result.issues);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::audit::types::AuditIssue;

    fn result(identity: &str, path: &str, quality_score: Option<u32>, issue: &str) -> AuditResult {
        AuditResult {
            identity: identity.to_string(),
            name: "package".to_string(),
            version: "1.0.0".to_string(),
            instance_id: None,
            path: Some(path.to_string()),
            quality_score,
            issues: vec![AuditIssue {
                severity: "high".to_string(),
                message: issue.to_string(),
                category: "behavior".to_string(),
                source: "test".to_string(),
            }],
        }
    }

    #[test]
    fn concurrent_scan_merge_preserves_registry_data_and_deduplicates_behavior() {
        let mut results = vec![result("same", "registry", Some(90), "duplicate")];
        let mut local = result("same", "local", None, "duplicate");
        local.issues.push(AuditIssue {
            severity: "critical".to_string(),
            message: "local-only".to_string(),
            category: "behavior".to_string(),
            source: "local".to_string(),
        });

        merge_behavioral_results(&mut results, vec![local]);

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].quality_score, Some(90));
        assert_eq!(results[0].path.as_deref(), Some("local"));
        assert_eq!(results[0].issues.len(), 2);
    }
}
