use super::osv::OsvVulnerability;

/// Audit result attached to an opted-in install report.
#[derive(Debug, Clone, serde::Serialize)]
pub struct AuditCounts {
    /// Total packages discovered + checked in this run.
    pub packages_audited: usize,
    /// OSV and LPM registry vulnerabilities across the discovered tree.
    pub vulnerabilities: usize,
    /// Packages flagged by client-side behavioral analysis
    /// (eval / child_process / dynamic require / etc.).
    pub suspicious: usize,
    /// Finding counts by normalized audit severity.
    pub severity_counts: AuditSeverityCounts,
    /// Every Critical finding, retained individually for human and JSON details.
    pub critical_findings: Vec<AuditCriticalFinding>,
    /// Wall-clock spent inside `run_install_summary`.
    pub elapsed_ms: u128,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
pub struct AuditSeverityCounts {
    pub critical: usize,
    pub high: usize,
    pub moderate: usize,
    pub low: usize,
    pub info: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct AuditCriticalFinding {
    pub package: String,
    pub version: String,
    pub message: String,
    pub category: String,
    pub source: String,
}

pub(super) fn summarize_findings(
    results: &[AuditResult],
    osv_vulnerabilities: &[OsvVulnerability],
) -> (AuditSeverityCounts, Vec<AuditCriticalFinding>) {
    let mut counts = AuditSeverityCounts::default();
    let mut critical_findings = Vec::new();

    for result in results {
        for issue in &result.issues {
            let _ = increment_severity(&mut counts, &issue.severity);
            if issue.severity.eq_ignore_ascii_case("critical") {
                critical_findings.push(AuditCriticalFinding {
                    package: result.name.clone(),
                    version: result.version.clone(),
                    message: issue.message.clone(),
                    category: issue.category.clone(),
                    source: issue.source.clone(),
                });
            }
        }
    }

    for vulnerability in osv_vulnerabilities {
        if !increment_severity(&mut counts, &vulnerability.severity) {
            counts.info += 1;
        }
        if vulnerability.severity.eq_ignore_ascii_case("critical") {
            let message = if vulnerability.summary.is_empty() {
                vulnerability.id.clone()
            } else {
                format!("{} — {}", vulnerability.id, vulnerability.summary)
            };
            critical_findings.push(AuditCriticalFinding {
                package: vulnerability.package.clone(),
                version: vulnerability.version.clone(),
                message,
                category: "vulnerability".to_string(),
                source: "osv".to_string(),
            });
        }
    }

    (counts, critical_findings)
}

fn increment_severity(counts: &mut AuditSeverityCounts, severity: &str) -> bool {
    if severity.eq_ignore_ascii_case("critical") {
        counts.critical += 1;
    } else if severity.eq_ignore_ascii_case("high") {
        counts.high += 1;
    } else if severity.eq_ignore_ascii_case("moderate") || severity.eq_ignore_ascii_case("medium") {
        counts.moderate += 1;
    } else if severity.eq_ignore_ascii_case("low") {
        counts.low += 1;
    } else if severity.eq_ignore_ascii_case("info") {
        counts.info += 1;
    } else {
        return false;
    }
    true
}

#[derive(Debug)]
pub(super) struct AuditResult {
    pub(super) identity: String,
    pub(super) name: String,
    pub(super) version: String,
    pub(super) instance_id: Option<lpm_common::PackageInstanceId>,
    pub(super) path: Option<String>,
    pub(super) quality_score: Option<u32>,
    pub(super) issues: Vec<AuditIssue>,
}

#[derive(Debug)]
pub(super) struct AuditIssue {
    pub(super) severity: String,
    pub(super) message: String,
    pub(super) category: String,
    /// Where the issue was detected: "registry", "local", or "combined".
    pub(super) source: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_summary_preserves_each_critical_registry_finding() {
        let results = [AuditResult {
            identity: "@lpm.dev/test.package@1.0.0".to_string(),
            name: "@lpm.dev/test.package".to_string(),
            version: "1.0.0".to_string(),
            instance_id: None,
            path: None,
            quality_score: None,
            issues: vec![
                AuditIssue {
                    severity: "Critical".to_string(),
                    message: "LPM-ADV-A".to_string(),
                    category: "vulnerability".to_string(),
                    source: "registry".to_string(),
                },
                AuditIssue {
                    severity: "critical".to_string(),
                    message: "LPM-ADV-B".to_string(),
                    category: "vulnerability".to_string(),
                    source: "registry".to_string(),
                },
                AuditIssue {
                    severity: "critical".to_string(),
                    message: "registry analysis finding".to_string(),
                    category: "security".to_string(),
                    source: "registry".to_string(),
                },
            ],
        }];

        let (counts, critical_findings) = summarize_findings(&results, &[]);

        assert_eq!(counts.critical, 3);
        assert_eq!(critical_findings.len(), 3);
        assert_eq!(critical_findings[0].message, "LPM-ADV-A");
        assert_eq!(critical_findings[1].message, "LPM-ADV-B");
        assert_eq!(critical_findings[2].message, "registry analysis finding");
    }
}
