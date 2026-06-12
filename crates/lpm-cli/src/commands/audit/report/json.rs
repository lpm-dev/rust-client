use crate::commands::audit::discovery::DiscoveryResult;
use crate::commands::audit::osv::OsvVulnerability;
use crate::commands::audit::types::AuditResult;

/// Print JSON output for machine consumption.
pub(in crate::commands::audit) fn print_json_report(
    results: &[AuditResult],
    osv_vulns: &[OsvVulnerability],
    osv_degraded_reason: Option<&str>,
    discovery: &DiscoveryResult,
    checked_lpm: usize,
) {
    let mut critical_count = 0usize;
    let mut high_count = 0usize;
    let mut moderate_count = 0usize;
    let mut low_count = 0usize;
    let mut info_count = 0usize;

    for r in results {
        for issue in &r.issues {
            match issue.severity.to_lowercase().as_str() {
                "critical" => critical_count += 1,
                "high" => high_count += 1,
                "moderate" | "medium" => moderate_count += 1,
                "low" => low_count += 1,
                "info" => info_count += 1,
                _ => {}
            }
        }
    }
    for v in osv_vulns {
        match v.severity.to_uppercase().as_str() {
            "CRITICAL" => critical_count += 1,
            "HIGH" => high_count += 1,
            "MODERATE" | "MEDIUM" => moderate_count += 1,
            "LOW" => low_count += 1,
            _ => info_count += 1,
        }
    }

    let json = serde_json::json!({
        "success": true,
        "manager": discovery.manager.to_string(),
        "degraded": discovery.is_degraded,
        // `osv_degraded` is true when the OSV advisory database was
        // unreachable; `osv_vulnerabilities: 0` in that state is the
        // best LPM could say, NOT a confirmation that no CVEs exist.
        // CI gates that use this envelope must treat
        // `osv_degraded == true` as a fail-on-pipeline-issue, not a
        // clean scan.
        "osv_degraded": osv_degraded_reason.is_some(),
        "osv_degraded_reason": osv_degraded_reason,
        "scanned": discovery.packages.len(),
        "checked_lpm": checked_lpm,
        "packages_with_issues": results.iter().filter(|r| !r.issues.is_empty()).count(),
        "total_issues": results.iter().map(|r| r.issues.len()).sum::<usize>(),
        "osv_vulnerabilities": osv_vulns.len(),
        "counts": {
            "critical": critical_count,
            "high": high_count,
            "moderate": moderate_count,
            "low": low_count,
            "info": info_count,
        },
        "packages": results.iter().map(|r| {
            serde_json::json!({
                "name": r.name,
                "version": r.version,
                "quality_score": r.quality_score,
                "issues": r.issues.iter().map(|i| {
                    serde_json::json!({
                        "severity": i.severity,
                        "category": i.category,
                        "message": i.message,
                        "source": i.source,
                    })
                }).collect::<Vec<_>>(),
            })
        }).collect::<Vec<_>>(),
        "vulnerabilities": osv_vulns.iter().map(|v| {
            serde_json::json!({
                "package": v.package,
                "version": v.version,
                "id": v.id,
                "summary": v.summary,
                "severity": v.severity,
            })
        }).collect::<Vec<_>>(),
    });
    println!("{}", serde_json::to_string_pretty(&json).unwrap());
}
