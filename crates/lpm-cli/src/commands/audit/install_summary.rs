use std::path::Path;

use lpm_common::LpmError;
use lpm_registry::RegistryClient;

use super::registry::registry_audit_result;
use super::scan::run_scan;
use super::types::{AuditCounts, summarize_findings};

pub fn summarize_registry_install(
    name: &str,
    version: &str,
    ver_meta: &lpm_registry::VersionMetadata,
) -> AuditCounts {
    let started = std::time::Instant::now();
    let result = registry_audit_result(name, version, ver_meta);
    let vulnerabilities = result
        .issues
        .iter()
        .filter(|issue| issue.category == "vulnerability")
        .count();
    let (severity_counts, critical_findings) =
        summarize_findings(std::slice::from_ref(&result), &[]);

    AuditCounts {
        packages_audited: 1,
        vulnerabilities,
        suspicious: 0,
        severity_counts,
        critical_findings,
        elapsed_ms: started.elapsed().as_millis(),
    }
}

pub fn print_install_summary(counts: &AuditCounts, show_audit_follow_up: bool) {
    crate::install_ui::warn_line(crate::install_ui::format_audit_advisory(
        counts.packages_audited,
        counts.vulnerabilities,
        counts.suspicious,
        counts.severity_counts.critical,
        counts.elapsed_ms,
        show_audit_follow_up,
    ));
    if counts.critical_findings.is_empty() {
        return;
    }

    crate::install_ui::detail_line(crate::install_ui::terminal_line!(
        "  {}",
        crate::install_ui::red("Critical")
    ));
    for finding in &counts.critical_findings {
        let package = lpm_common::sanitize_terminal_inline(&finding.package);
        let version = lpm_common::sanitize_terminal_inline(&finding.version);
        let message = lpm_common::sanitize_terminal_inline(&finding.message);
        let source = lpm_common::sanitize_terminal_inline(&finding.source);
        let category = lpm_common::sanitize_terminal_inline(&finding.category);
        crate::install_ui::detail_line(crate::install_ui::terminal_line!(
            "    {} {} {}",
            crate::install_ui::yellow(&format!("{package}@{version}")),
            message,
            crate::install_ui::dim(&format!("[{source}/{category}]")),
        ));
    }
}

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
