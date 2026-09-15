use crate::commands::audit::discovery::DiscoveryResult;
use crate::commands::audit::osv::OsvVulnerability;
use crate::commands::audit::types::{AuditResult, summarize_findings};

/// Print JSON output for machine consumption.
pub(in crate::commands::audit) fn print_json_report(
    results: &[AuditResult],
    osv_vulns: &[OsvVulnerability],
    osv_degraded_reason: Option<&str>,
    discovery: &DiscoveryResult,
    checked_lpm: usize,
    behavioral: &super::super::behavior::BehavioralSummary,
) {
    let (counts, _) = summarize_findings(results, osv_vulns);

    let json = serde_json::json!({
        "success": osv_degraded_reason.is_none() && behavioral.coverage.complete,
        "behavioral_coverage": behavioral.coverage,
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
        "packages_with_issues": results.iter().filter(|r| r.issues.iter().any(|i| !i.is_capability())).count(),
        "total_issues": results.iter().flat_map(|r| &r.issues).filter(|i| !i.is_capability()).count(),
        "total_capabilities": results.iter().flat_map(|r| &r.issues).filter(|i| i.is_capability()).count(),
        "osv_vulnerabilities": osv_vulns.len(),
        "counts": {
            "critical": counts.critical,
            "high": counts.high,
            "moderate": counts.moderate,
            "low": counts.low,
            "info": counts.info,
        },
        "packages": results.iter().map(|r| {
            serde_json::json!({
                "name": r.name,
                "version": r.version,
                "instance_id": r.instance_id.map(|instance_id| instance_id.to_string()),
                "path": r.path,
                "quality_score": r.quality_score,
                "capabilities": r.issues.iter().filter(|i| i.is_capability()).map(|i| {
                    serde_json::json!({
                        "rule_id": i.rule_id,
                        "name": i.message,
                        "policy_severity": i.severity,
                        "source": i.source,
                        "evidence": i.evidence,
                    })
                }).collect::<Vec<_>>(),
                "issues": r.issues.iter().filter(|i| !i.is_capability()).map(|i| {
                    let mut issue = serde_json::json!({
                        "severity": i.severity,
                        "category": i.category,
                        "message": i.message,
                        "source": i.source,
                    });
                    if let Some(rule_id) = i.rule_id {
                        issue["rule_id"] = serde_json::json!(rule_id);
                        issue["evidence"] = serde_json::json!(i.evidence);
                    }
                    issue
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
