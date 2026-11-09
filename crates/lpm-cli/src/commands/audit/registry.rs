use lpm_security::query::PseudoClass;

use super::behavior::behavioral_issue;
use super::types::{AuditIssue, AuditResult};

pub(super) fn validate_registry_version(
    name: &str,
    version: &str,
    metadata: &lpm_registry::VersionMetadata,
) -> Result<(), lpm_common::LpmError> {
    if metadata.version != version {
        return Err(lpm_common::LpmError::Registry(format!(
            "inconsistent version metadata for {name}@{version}: entry declares {}",
            metadata.version
        )));
    }
    let severities = metadata
        .security_findings
        .iter()
        .flatten()
        .filter_map(|finding| finding.severity.as_deref());
    for severity in severities {
        if super::policy::severity_level(severity.trim()) == 0 {
            return Err(lpm_common::LpmError::Registry(format!(
                "unsupported audit severity {severity:?} for {name}@{version}"
            )));
        }
    }
    Ok(())
}

pub(super) fn registry_audit_result(
    name: &str,
    version: &str,
    ver_meta: &lpm_registry::VersionMetadata,
) -> AuditResult {
    let mut issues = Vec::new();
    collect_registry_issues(ver_meta, &mut issues);

    let quality_score = ver_meta.quality_score;
    if let Some(score) = quality_score
        && score < 40
    {
        issues.push(AuditIssue {
            severity: if score < 20 { "high" } else { "moderate" }.to_string(),
            message: format!("low quality score: {score}/100"),
            category: "quality".to_string(),
            source: "registry".to_string(),
            ..AuditIssue::default()
        });
    }

    AuditResult {
        identity: format!("{name}@{version}"),
        name: name.to_string(),
        version: version.to_string(),
        instance_id: None,
        path: None,
        quality_score,
        issues,
    }
}

pub(super) fn collect_registry_issues(
    ver_meta: &lpm_registry::VersionMetadata,
    issues: &mut Vec<AuditIssue>,
) {
    // AI security findings
    if let Some(findings) = &ver_meta.security_findings {
        for finding in findings {
            let severity = finding
                .severity
                .as_deref()
                .unwrap_or("moderate")
                .trim()
                .to_ascii_lowercase();
            let desc = finding
                .description
                .as_deref()
                .unwrap_or("security concern detected");
            issues.push(AuditIssue {
                severity,
                message: desc.to_string(),
                category: "security".to_string(),
                source: "registry".to_string(),
                ..AuditIssue::default()
            });
        }
    }

    if let Some(tags) = &ver_meta.behavioral_tags {
        let test_only = ver_meta.test_only_tags.as_deref().unwrap_or_default();
        // The third value is the tag's registry key, as `_testOnlyTags` names it.
        for (tag, present, key) in [
            (PseudoClass::Eval, tags.eval, "eval"),
            (PseudoClass::Network, tags.network, "network"),
            (PseudoClass::Fs, tags.filesystem, "filesystem"),
            (PseudoClass::Shell, tags.shell, "shell"),
            (
                PseudoClass::ChildProcess,
                tags.child_process,
                "childProcess",
            ),
            (PseudoClass::Native, tags.native_bindings, "nativeBindings"),
            (PseudoClass::Crypto, tags.crypto, "crypto"),
            (
                PseudoClass::DynamicRequire,
                tags.dynamic_require,
                "dynamicRequire",
            ),
            (PseudoClass::Env, tags.environment_vars, "environmentVars"),
            (PseudoClass::Ws, tags.web_socket, "webSocket"),
            (PseudoClass::Obfuscated, tags.obfuscated, "obfuscated"),
            (
                PseudoClass::HighEntropy,
                tags.high_entropy_strings,
                "highEntropyStrings",
            ),
            (PseudoClass::Minified, tags.minified, "minified"),
            (PseudoClass::Telemetry, tags.telemetry, "telemetry"),
            (PseudoClass::UrlStrings, tags.url_strings, "urlStrings"),
            (PseudoClass::Trivial, tags.trivial, "trivial"),
            (PseudoClass::Protestware, tags.protestware, "protestware"),
            (PseudoClass::GitDep, tags.git_dependency, "gitDependency"),
            (PseudoClass::HttpDep, tags.http_dependency, "httpDependency"),
            (
                PseudoClass::WildcardDep,
                tags.wildcard_dependency,
                "wildcardDependency",
            ),
            (
                PseudoClass::Copyleft,
                tags.copyleft_license,
                "copyleftLicense",
            ),
            (PseudoClass::NoLicense, tags.no_license, "noLicense"),
            (
                PseudoClass::CustomLicense,
                tags.custom_license,
                "customLicense",
            ),
        ] {
            if present && let Some(mut issue) = behavioral_issue(tag, "registry") {
                if test_only.iter().any(|only| only == key) {
                    issue.tests_only = true;
                    issue.severity = "info".to_string();
                }
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
            ..AuditIssue::default()
        });
    }
}
