use std::path::Path;

use lpm_common::LpmError;
use lpm_registry::RegistryClient;

use super::scan::run_scan;
use super::types::{AuditCounts, summarize_findings};

/// Run the same audit scan as `lpm audit` without printing its report.
///
/// Returns `Ok(None)` when there are no installed packages. An incomplete
/// OSV scan is returned as an error so install never presents partial counts
/// as a completed audit. The install itself treats this hook as informational.
pub async fn run_install_summary(
    client: &RegistryClient,
    project_dir: &Path,
    store_version: lpm_store::StoreVersion,
) -> Result<Option<AuditCounts>, LpmError> {
    let started = std::time::Instant::now();
    let scan = run_scan(
        client,
        project_dir,
        store_version,
        /* json_output */ true,
        /* level */ None,
    )
    .await?;

    if scan.discovery.packages.is_empty() {
        return Ok(None);
    }
    if let Some(reason) = scan.osv_degraded_reason {
        return Err(LpmError::Network(format!(
            "audit-after-install OSV scan did not complete: {reason}"
        )));
    }

    let registry_vulnerabilities = scan
        .results
        .iter()
        .flat_map(|result| &result.issues)
        .filter(|issue| issue.category == "vulnerability")
        .count();
    let vulnerabilities = scan.osv_vulnerabilities.len() + registry_vulnerabilities;
    let (severity_counts, critical_findings) =
        summarize_findings(&scan.results, &scan.osv_vulnerabilities);

    Ok(Some(AuditCounts {
        packages_audited: scan.discovery.packages.len(),
        vulnerabilities,
        suspicious: scan.behavioral.packages_with_actionable_findings,
        severity_counts,
        critical_findings,
        elapsed_ms: started.elapsed().as_millis(),
    }))
}
