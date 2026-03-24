//! Post-install security warnings.
//!
//! After `lpm install` or `lpm add`, checks installed LPM packages for:
//! - AI-detected security findings
//! - Dangerous behavioral tags (eval, childProcess, shell, dynamicRequire)
//! - Lifecycle scripts (postinstall, etc.)
//!
//! Uses batch metadata endpoint for efficiency (1 request for all packages).

use crate::output;
use lpm_registry::RegistryClient;
use owo_colors::OwoColorize;
use std::collections::HashMap;

/// Check installed LPM packages for security issues and print warnings.
///
/// Fetches security metadata via batch endpoint (single HTTP request).
pub async fn check_installed_packages(
    client: &RegistryClient,
    lpm_packages: &HashMap<String, String>, // name → version
    json_output: bool,
) {
    if lpm_packages.is_empty() {
        return;
    }

    // Batch fetch all metadata in one request
    let names: Vec<String> = lpm_packages.keys().cloned().collect();
    let metadata_map = match client.batch_metadata(&names).await {
        Ok(m) => m,
        Err(_) => return, // Silently skip if batch fails
    };

    let mut issues: Vec<PackageIssue> = Vec::new();

    for (name, version) in lpm_packages {
        let metadata = match metadata_map.get(name) {
            Some(m) => m,
            None => continue,
        };

        let ver_meta = match metadata.version(version) {
            Some(v) => v,
            None => match metadata.latest() {
                Some(v) => v,
                None => continue,
            },
        };

        if !ver_meta.has_security_issues() {
            continue;
        }

        let warnings = collect_warnings(ver_meta);
        if !warnings.is_empty() {
            issues.push(PackageIssue {
                name: name.clone(),
                version: version.clone(),
                warnings,
            });
        }
    }

    if issues.is_empty() {
        return;
    }

    if json_output {
        let json = serde_json::json!({
            "security_warnings": issues.iter().map(|i| {
                serde_json::json!({
                    "package": i.name,
                    "version": i.version,
                    "warnings": i.warnings,
                })
            }).collect::<Vec<_>>(),
        });
        println!("{}", serde_json::to_string_pretty(&json).unwrap());
        return;
    }

    let total_warnings: usize = issues.iter().map(|i| i.warnings.len()).sum();
    println!();
    output::warn(&format!(
        "{} package(s) with {} issue(s):",
        issues.len(),
        total_warnings
    ));
    for issue in &issues {
        println!(
            "  {} {}",
            issue.name.bold(),
            format!("({})", issue.version).dimmed()
        );
        for warning in &issue.warnings {
            println!("    {} {}", "⚠".yellow(), warning);
        }
    }
    println!(
        "\n  Run {} for details\n",
        "lpm audit".bold()
    );
}

/// Collect warning strings from version metadata.
pub fn collect_warnings(ver_meta: &lpm_registry::VersionMetadata) -> Vec<String> {
    let mut warnings: Vec<String> = Vec::new();

    if let Some(findings) = &ver_meta.security_findings {
        for finding in findings {
            let severity = finding.severity.as_deref().unwrap_or("info");
            let desc = finding
                .description
                .as_deref()
                .unwrap_or("security concern detected");
            warnings.push(format!("[{}] {}", severity, desc));
        }
    }

    if let Some(tags) = &ver_meta.behavioral_tags {
        let mut dangerous = Vec::new();
        if tags.eval { dangerous.push("eval()"); }
        if tags.child_process { dangerous.push("child_process"); }
        if tags.shell { dangerous.push("shell exec"); }
        if tags.dynamic_require { dangerous.push("dynamic require"); }
        if !dangerous.is_empty() {
            warnings.push(format!("uses {}", dangerous.join(", ")));
        }
    }

    if let Some(scripts) = &ver_meta.lifecycle_scripts {
        let script_names: Vec<&str> = scripts.keys().map(|s| s.as_str()).collect();
        if !script_names.is_empty() {
            warnings.push(format!("has lifecycle scripts: {}", script_names.join(", ")));
        }
    }

    warnings
}

struct PackageIssue {
    name: String,
    version: String,
    warnings: Vec<String>,
}
