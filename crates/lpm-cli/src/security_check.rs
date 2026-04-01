//! Post-install security warnings.
//!
//! Two layers of security checking:
//!
//! 1. **Client-side analysis** (all packages): Reads `.lpm-security.json` from
//!    the store for every installed package (npm + @lpm.dev). Produces a
//!    severity-tiered summary of 22 behavioral tags.
//!
//! 2. **Registry-side analysis** (@lpm.dev only): Fetches AI security findings,
//!    behavioral tags, and lifecycle scripts from the registry metadata.
//!    Merges with client-side tags.
//!
//! Uses batch metadata endpoint for @lpm.dev packages (1 request for all).

use crate::output;
use lpm_registry::RegistryClient;
use lpm_security::behavioral::{self, PackageAnalysis};
use lpm_store::PackageStore;
use owo_colors::OwoColorize;
use std::collections::HashMap;

/// Severity tier for the post-install summary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Info,
}

/// A tagged issue found in a package.
struct TagIssue {
    tag_label: &'static str,
    severity: Severity,
    packages: Vec<String>, // "name@version"
}

/// Run the full post-install security summary.
///
/// Reads `.lpm-security.json` from the store for ALL packages, then
/// optionally fetches registry metadata for @lpm.dev packages.
pub async fn post_install_security_summary(
    client: &RegistryClient,
    store: &PackageStore,
    packages: &[(String, String, bool)], // (name, version, is_lpm)
    json_output: bool,
    quiet: bool,
) {
    if packages.is_empty() {
        return;
    }

    // ── Phase 1: Client-side analysis (all packages) ──────────

    let show_progress = !json_output && packages.len() > 50;
    let spinner = if show_progress {
        let s = cliclack::spinner();
        s.start(format!("Analyzing {} packages...", packages.len()));
        Some(s)
    } else {
        None
    };

    let mut tag_counts: HashMap<&'static str, Vec<String>> = HashMap::new();

    for (i, (name, version, _is_lpm)) in packages.iter().enumerate() {
        if show_progress
            && i % 50 == 0
            && i > 0
            && let Some(ref s) = spinner
        {
            s.start(format!("Analyzing... {}/{}", i, packages.len()));
        }

        let pkg_dir = store.package_dir(name, version);
        let analysis = match behavioral::read_cached_analysis(&pkg_dir) {
            Some(a) => a,
            None => continue,
        };

        let pkg_id = format!("{name}@{version}");
        collect_tags_from_analysis(&analysis, &pkg_id, &mut tag_counts);
    }

    if let Some(s) = spinner {
        s.stop(format!("Analyzed {} packages", packages.len()));
    }

    // ── Phase 2: Registry-side enrichment (@lpm.dev only) ─────

    let lpm_packages: HashMap<String, String> = packages
        .iter()
        .filter(|(_, _, is_lpm)| *is_lpm)
        .map(|(n, v, _)| (n.clone(), v.clone()))
        .collect();

    if !lpm_packages.is_empty() {
        let names: Vec<String> = lpm_packages.keys().cloned().collect();
        if let Ok(metadata_map) = client.batch_metadata(&names).await {
            for (name, version) in &lpm_packages {
                if let Some(metadata) = metadata_map.get(name) {
                    let ver_meta = metadata.version(version).or_else(|| metadata.latest());
                    if let Some(vm) = ver_meta {
                        let pkg_id = format!("{name}@{version}");
                        collect_registry_warnings(vm, &pkg_id, &mut tag_counts);
                    }
                }
            }
        }
    }

    // ── Build severity-grouped output ─────────────────────────

    let issues = build_severity_groups(&tag_counts);

    if issues.is_empty() {
        return;
    }

    let critical_count: usize = issues
        .iter()
        .filter(|i| i.severity == Severity::Critical)
        .map(|i| i.packages.len())
        .sum();
    let high_count: usize = issues
        .iter()
        .filter(|i| i.severity == Severity::High)
        .map(|i| i.packages.len())
        .sum();

    // Skip output if only Info-level tags and in quiet mode
    if quiet && critical_count == 0 && high_count == 0 {
        return;
    }

    if json_output {
        let json_issues: Vec<serde_json::Value> = issues
            .iter()
            .map(|i| {
                serde_json::json!({
                    "tag": i.tag_label,
                    "severity": format!("{:?}", i.severity).to_lowercase(),
                    "count": i.packages.len(),
                    "packages": i.packages,
                })
            })
            .collect();
        let json = serde_json::json!({ "security_summary": json_issues });
        println!("{}", serde_json::to_string_pretty(&json).unwrap());
        return;
    }

    // ── Human-readable output ─────────────────────────────────

    println!();
    let total: usize = tag_counts.values().map(|v| v.len()).sum();
    output::info(&format!(
        "Security summary ({} packages, {} findings):",
        packages.len(),
        total,
    ));

    for severity in [
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Info,
    ] {
        let tier_issues: Vec<&TagIssue> =
            issues.iter().filter(|i| i.severity == severity).collect();

        if tier_issues.is_empty() {
            continue;
        }

        // Skip Info tier unless verbose (not quiet)
        if severity == Severity::Info && quiet {
            continue;
        }
        // Skip Medium tier in quiet mode
        if severity == Severity::Medium && quiet {
            continue;
        }

        let (label, color) = match severity {
            Severity::Critical => ("Critical", "\x1b[31m"), // red
            Severity::High => ("High", "\x1b[33m"),         // yellow
            Severity::Medium => ("Medium", "\x1b[36m"),     // cyan
            Severity::Info => ("Info", "\x1b[2m"),          // dim
        };
        let reset = "\x1b[0m";

        println!("\n  {color}● {label}{reset}");

        for issue in tier_issues {
            let count = issue.packages.len();
            let preview: Vec<&str> = issue.packages.iter().take(3).map(|s| s.as_str()).collect();
            let preview_str = preview.join(", ");
            let suffix = if count > 3 {
                format!(", ... (+{})", count - 3)
            } else {
                String::new()
            };

            println!(
                "    {count} {:<20} {color}→{reset} {preview_str}{suffix}",
                issue.tag_label,
            );
        }
    }

    println!("\n  Run {} for full details.", "lpm audit".bold());
    println!(
        "  Run {} to inspect specific tags.\n",
        "lpm query \":critical\"".bold()
    );
}

/// Collect tags from a client-side PackageAnalysis into the tag_counts map.
fn collect_tags_from_analysis(
    analysis: &PackageAnalysis,
    pkg_id: &str,
    counts: &mut HashMap<&'static str, Vec<String>>,
) {
    let s = &analysis.source;
    let sc = &analysis.supply_chain;
    let m = &analysis.manifest;

    // Source tags
    if s.filesystem {
        counts
            .entry("filesystem")
            .or_default()
            .push(pkg_id.to_string());
    }
    if s.network {
        counts
            .entry("network")
            .or_default()
            .push(pkg_id.to_string());
    }
    if s.child_process {
        counts
            .entry("child_process")
            .or_default()
            .push(pkg_id.to_string());
    }
    if s.environment_vars {
        counts
            .entry("environment_vars")
            .or_default()
            .push(pkg_id.to_string());
    }
    if s.eval {
        counts.entry("eval").or_default().push(pkg_id.to_string());
    }
    if s.native_bindings {
        counts
            .entry("native_bindings")
            .or_default()
            .push(pkg_id.to_string());
    }
    if s.crypto {
        counts.entry("crypto").or_default().push(pkg_id.to_string());
    }
    if s.shell {
        counts.entry("shell").or_default().push(pkg_id.to_string());
    }
    if s.web_socket {
        counts
            .entry("web_socket")
            .or_default()
            .push(pkg_id.to_string());
    }
    if s.dynamic_require {
        counts
            .entry("dynamic_require")
            .or_default()
            .push(pkg_id.to_string());
    }

    // Supply chain tags
    if sc.obfuscated {
        counts
            .entry("obfuscated")
            .or_default()
            .push(pkg_id.to_string());
    }
    if sc.high_entropy_strings {
        counts
            .entry("high_entropy")
            .or_default()
            .push(pkg_id.to_string());
    }
    if sc.minified {
        counts
            .entry("minified")
            .or_default()
            .push(pkg_id.to_string());
    }
    if sc.telemetry {
        counts
            .entry("telemetry")
            .or_default()
            .push(pkg_id.to_string());
    }
    if sc.url_strings {
        counts
            .entry("url_strings")
            .or_default()
            .push(pkg_id.to_string());
    }
    if sc.trivial {
        counts
            .entry("trivial")
            .or_default()
            .push(pkg_id.to_string());
    }
    if sc.protestware {
        counts
            .entry("protestware")
            .or_default()
            .push(pkg_id.to_string());
    }

    // Manifest tags
    if m.git_dependency {
        counts
            .entry("git_dependency")
            .or_default()
            .push(pkg_id.to_string());
    }
    if m.http_dependency {
        counts
            .entry("http_dependency")
            .or_default()
            .push(pkg_id.to_string());
    }
    if m.wildcard_dependency {
        counts
            .entry("wildcard_dependency")
            .or_default()
            .push(pkg_id.to_string());
    }
    if m.copyleft_license {
        counts
            .entry("copyleft_license")
            .or_default()
            .push(pkg_id.to_string());
    }
    if m.no_license {
        counts
            .entry("no_license")
            .or_default()
            .push(pkg_id.to_string());
    }
}

/// Collect additional warnings from registry metadata (@lpm.dev packages only).
fn collect_registry_warnings(
    ver_meta: &lpm_registry::VersionMetadata,
    pkg_id: &str,
    counts: &mut HashMap<&'static str, Vec<String>>,
) {
    // AI security findings
    if let Some(findings) = &ver_meta.security_findings {
        for finding in findings {
            let severity = finding.severity.as_deref().unwrap_or("info");
            if severity == "critical" || severity == "high" {
                // Avoid double-counting if client-side already detected it
                let key = "ai_security_finding";
                let entry = counts.entry(key).or_default();
                if !entry.contains(&pkg_id.to_string()) {
                    entry.push(pkg_id.to_string());
                }
            }
        }
    }

    // Lifecycle scripts (already blocked by default, but show in summary)
    if let Some(scripts) = &ver_meta.lifecycle_scripts
        && !scripts.is_empty()
    {
        let entry = counts.entry("lifecycle_scripts").or_default();
        if !entry.contains(&pkg_id.to_string()) {
            entry.push(pkg_id.to_string());
        }
    }
}

/// Map tag names to severity tiers and build sorted issue list.
fn build_severity_groups(counts: &HashMap<&'static str, Vec<String>>) -> Vec<TagIssue> {
    let tag_severity: &[(&str, &str, Severity)] = &[
        // Critical
        ("obfuscated", "obfuscated code", Severity::Critical),
        ("protestware", "protestware", Severity::Critical),
        ("high_entropy", "high entropy strings", Severity::Critical),
        // High
        ("eval", "eval()", Severity::High),
        ("child_process", "child_process", Severity::High),
        ("shell", "shell exec", Severity::High),
        ("dynamic_require", "dynamic require", Severity::High),
        ("lifecycle_scripts", "install scripts", Severity::High),
        ("ai_security_finding", "AI security finding", Severity::High),
        // Medium
        ("network", "network access", Severity::Medium),
        ("native_bindings", "native bindings", Severity::Medium),
        ("git_dependency", "git dependency", Severity::Medium),
        ("http_dependency", "http dependency", Severity::Medium),
        ("wildcard_dependency", "wildcard dep", Severity::Medium),
        ("no_license", "no license", Severity::Medium),
        // Info
        ("filesystem", "filesystem", Severity::Info),
        ("crypto", "crypto", Severity::Info),
        ("environment_vars", "env vars", Severity::Info),
        ("web_socket", "websocket", Severity::Info),
        ("telemetry", "telemetry", Severity::Info),
        ("trivial", "trivial package", Severity::Info),
        ("copyleft_license", "copyleft", Severity::Info),
        ("minified", "minified", Severity::Info),
        ("url_strings", "url strings", Severity::Info),
    ];

    let mut issues = Vec::new();

    for (key, label, severity) in tag_severity {
        if let Some(pkgs) = counts.get(key)
            && !pkgs.is_empty()
        {
            issues.push(TagIssue {
                tag_label: label,
                severity: *severity,
                packages: pkgs.clone(),
            });
        }
    }

    issues
}

/// Legacy function: Check installed LPM packages for security issues.
///
/// Fetches security metadata via batch endpoint (single HTTP request).
/// DEPRECATED in favor of `post_install_security_summary()` which covers
/// ALL packages (npm + @lpm.dev) via client-side analysis.
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
    println!("\n  Run {} for details\n", "lpm audit".bold());
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
            warnings.push(format!("uses {}", dangerous.join(", ")));
        }
    }

    if let Some(scripts) = &ver_meta.lifecycle_scripts {
        let script_names: Vec<&str> = scripts.keys().map(|s| s.as_str()).collect();
        if !script_names.is_empty() {
            warnings.push(format!(
                "has lifecycle scripts: {}",
                script_names.join(", ")
            ));
        }
    }

    warnings
}

struct PackageIssue {
    name: String,
    version: String,
    warnings: Vec<String>,
}
