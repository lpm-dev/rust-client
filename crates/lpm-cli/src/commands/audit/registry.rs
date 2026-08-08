use lpm_security::query::PseudoClass;

use super::behavior::behavioral_issue;
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

    if let Some(tags) = &ver_meta.behavioral_tags {
        for (tag, present) in [
            (PseudoClass::Eval, tags.eval),
            (PseudoClass::Network, tags.network),
            (PseudoClass::Fs, tags.filesystem),
            (PseudoClass::Shell, tags.shell),
            (PseudoClass::ChildProcess, tags.child_process),
            (PseudoClass::Native, tags.native_bindings),
            (PseudoClass::Crypto, tags.crypto),
            (PseudoClass::DynamicRequire, tags.dynamic_require),
            (PseudoClass::Env, tags.environment_vars),
            (PseudoClass::Ws, tags.web_socket),
            (PseudoClass::Obfuscated, tags.obfuscated),
            (PseudoClass::HighEntropy, tags.high_entropy_strings),
            (PseudoClass::Minified, tags.minified),
            (PseudoClass::Telemetry, tags.telemetry),
            (PseudoClass::UrlStrings, tags.url_strings),
            (PseudoClass::Trivial, tags.trivial),
            (PseudoClass::Protestware, tags.protestware),
            (PseudoClass::GitDep, tags.git_dependency),
            (PseudoClass::HttpDep, tags.http_dependency),
            (PseudoClass::WildcardDep, tags.wildcard_dependency),
            (PseudoClass::Copyleft, tags.copyleft_license),
            (PseudoClass::NoLicense, tags.no_license),
        ] {
            if present && let Some(issue) = behavioral_issue(tag, "registry") {
                issues.push(issue);
            }
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
