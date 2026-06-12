use super::types::AuditIssue;

pub(super) fn collect_registry_issues(
    ver_meta: &lpm_registry::VersionMetadata,
    issues: &mut Vec<AuditIssue>,
) {
    // AI security findings
    if let Some(findings) = &ver_meta.security_findings {
        for finding in findings {
            let severity = finding.severity.as_deref().unwrap_or("moderate");
            let desc = finding
                .description
                .as_deref()
                .unwrap_or("security concern detected");
            issues.push(AuditIssue {
                severity: severity.to_string(),
                message: desc.to_string(),
                category: "security".to_string(),
                source: "registry".to_string(),
            });
        }
    }

    // Behavioral tags from registry (all 22 tags)
    if let Some(tags) = &ver_meta.behavioral_tags {
        let mut critical = Vec::new();
        if tags.obfuscated {
            critical.push("obfuscated code");
        }
        if tags.protestware {
            critical.push("protestware");
        }
        if tags.high_entropy_strings {
            critical.push("high-entropy strings");
        }
        if !critical.is_empty() {
            issues.push(AuditIssue {
                severity: "critical".to_string(),
                message: format!("detected {}", critical.join(", ")),
                category: "supply-chain".to_string(),
                source: "registry".to_string(),
            });
        }

        let mut dangerous = Vec::new();
        if tags.eval {
            dangerous.push("eval()");
        }
        if tags.child_process {
            dangerous.push("child_process");
        }
        if tags.shell {
            dangerous.push("shell exec");
        }
        if tags.dynamic_require {
            dangerous.push("dynamic require");
        }
        if !dangerous.is_empty() {
            issues.push(AuditIssue {
                severity: "high".to_string(),
                message: format!("uses {}", dangerous.join(", ")),
                category: "behavior".to_string(),
                source: "registry".to_string(),
            });
        }

        let mut medium = Vec::new();
        if tags.network {
            medium.push("network");
        }
        if tags.native_bindings {
            medium.push("native bindings");
        }
        if tags.git_dependency {
            medium.push("git dependency");
        }
        if tags.http_dependency {
            medium.push("http dependency");
        }
        if tags.wildcard_dependency {
            medium.push("wildcard dep");
        }
        if tags.no_license {
            medium.push("no license");
        }
        if !medium.is_empty() {
            issues.push(AuditIssue {
                severity: "info".to_string(),
                message: format!("flags: {}", medium.join(", ")),
                category: "behavior".to_string(),
                source: "registry".to_string(),
            });
        }

        let mut notable = Vec::new();
        if tags.filesystem {
            notable.push("filesystem");
        }
        if tags.environment_vars {
            notable.push("env vars");
        }
        if tags.crypto {
            notable.push("crypto");
        }
        if tags.web_socket {
            notable.push("websocket");
        }
        if tags.telemetry {
            notable.push("telemetry");
        }
        if tags.minified {
            notable.push("minified");
        }
        if tags.url_strings {
            notable.push("url strings");
        }
        if tags.trivial {
            notable.push("trivial");
        }
        if tags.copyleft_license {
            notable.push("copyleft");
        }
        if !notable.is_empty() {
            issues.push(AuditIssue {
                severity: "info".to_string(),
                message: format!("accesses {}", notable.join(", ")),
                category: "behavior".to_string(),
                source: "registry".to_string(),
            });
        }
    }

    // Lifecycle scripts
    if let Some(scripts) = &ver_meta.lifecycle_scripts
        && !scripts.is_empty()
    {
        let names: Vec<&str> = scripts.keys().map(|s| s.as_str()).collect();
        issues.push(AuditIssue {
            severity: "moderate".to_string(),
            message: format!("lifecycle scripts: {}", names.join(", ")),
            category: "scripts".to_string(),
            source: "registry".to_string(),
        });
    }

    // Registry-provided vulnerabilities
    if let Some(vulns) = &ver_meta.vulnerabilities {
        for vuln in vulns {
            let id = vuln.id.as_deref().unwrap_or("unknown");
            let summary = vuln.summary.as_deref().unwrap_or("");
            let severity = vuln.severity.as_deref().unwrap_or("moderate");
            issues.push(AuditIssue {
                severity: severity.to_lowercase(),
                message: format!(
                    "{id}{}",
                    if summary.is_empty() {
                        String::new()
                    } else {
                        format!(" — {summary}")
                    }
                ),
                category: "vulnerability".to_string(),
                source: "registry".to_string(),
            });
        }
    }
}
