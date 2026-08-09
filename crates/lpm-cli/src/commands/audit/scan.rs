use std::path::Path;

use lpm_common::LpmError;
use lpm_registry::RegistryClient;

use super::behavior::{BehavioralSummary, run_behavioral_analysis};
use super::discovery::{self, DiscoveryResult, ScanMode};
use super::osv::{OsvVulnerability, run_osv_scan};
use super::policy::AuditLevel;
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
    let discovery = discovery::discover_packages(project_dir)?;
    let lpm_packages: Vec<(String, String)> = discovery
        .packages
        .iter()
        .filter(|package| package.name.starts_with("@lpm.dev/"))
        .map(|package| (package.name.clone(), package.version.clone()))
        .collect();

    let mut results = Vec::with_capacity(lpm_packages.len());
    let mut checked_lpm = 0usize;

    if !lpm_packages.is_empty() {
        let names: Vec<String> = lpm_packages.iter().map(|(name, _)| name.clone()).collect();
        let metadata_map = client.batch_metadata(&names).await.map_err(|error| {
            LpmError::Registry(format!(
                "LPM registry metadata lookup failed during audit: {error}"
            ))
        })?;

        for (name, version) in &lpm_packages {
            let metadata = metadata_map.get(name).ok_or_else(|| {
                LpmError::Registry(format!(
                    "LPM registry returned no metadata for installed package {name}@{version}"
                ))
            })?;
            let version_metadata = metadata.version(version).ok_or_else(|| {
                LpmError::Registry(format!(
                    "LPM registry metadata omitted installed version {name}@{version}"
                ))
            })?;
            checked_lpm += 1;

            results.push(registry_audit_result(name, version, version_metadata));
        }
    }

    let needs_store_lock = discovery
        .packages
        .iter()
        .any(|package| matches!(package.scan_mode, ScanMode::RegistryAndStore));
    let behavioral = if needs_store_lock {
        let lock_path = lpm_common::LpmRoot::from_env()?.store_lock();
        let mut summary = None;
        lpm_common::with_shared_lock(lock_path, || {
            summary = Some(run_behavioral_analysis(
                &discovery,
                &mut results,
                &lpm_packages,
                json_output,
                level,
                store_version,
            ));
            Ok(())
        })?;
        summary.expect("behavioral summary is set while the shared lock is held")
    } else {
        run_behavioral_analysis(
            &discovery,
            &mut results,
            &lpm_packages,
            json_output,
            level,
            store_version,
        )
    };

    let osv_outcome = run_osv_scan(&discovery.packages, json_output, level).await;

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
