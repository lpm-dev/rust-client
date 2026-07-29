//! Post-install security warnings.
//!
//! Two layers of security checking:
//!
//! 1. **Client-side analysis** (all packages): Reads `.lpm-security.json` from
//!    the store for every installed package (npm + @lpm.dev). Produces a
//!    severity-tiered summary of 22 behavioral tags.
//!
//! 2. **Registry-side analysis** (@lpm.dev only): Fetches AI security findings,
//!    behavioral tags, vulnerabilities, and lifecycle scripts from the registry
//!    metadata. Merges registry behavioral tags with client-side tags via OR.
//!
//! Uses batch metadata endpoint for @lpm.dev packages (1 request for all).

use crate::install_ui;
use lpm_registry::RegistryClient;
use lpm_security::behavioral::{self, PackageAnalysis};
use lpm_store::V2BaselineIndex;
use std::collections::{HashMap, HashSet};

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

#[derive(Debug, Eq, PartialEq)]
enum SecuritySummaryLine {
    Warn(install_ui::TerminalLine),
    Detail(install_ui::TerminalLine),
}

/// Run the full post-install security summary.
///
/// Reads `.lpm-security.json` from the store for ALL packages, then
/// fetches registry metadata for @lpm.dev packages to merge behavioral
/// tags, vulnerabilities, AI findings, and lifecycle scripts.
pub async fn post_install_security_summary(
    client: &RegistryClient,
    lpm_root: &lpm_common::LpmRoot,
    baseline_index: Option<&V2BaselineIndex>,
    packages: &[(String, String, bool)], // (name, version, is_lpm)
    json_output: bool,
    quiet: bool,
) {
    if packages.is_empty() {
        return;
    }

    // ── Client-side analysis (all packages) ──────────

    let empty_baseline_index = V2BaselineIndex::default();
    let baseline_index = baseline_index.unwrap_or(&empty_baseline_index);
    let show_progress = !json_output && packages.len() > 50;
    if show_progress {
        install_ui::phase_untrusted(&format!(
            "Checking cached security results for {} packages",
            packages.len()
        ));
    }

    let mut tag_counts: HashMap<&'static str, HashSet<String>> = HashMap::new();

    for (i, (name, version, _is_lpm)) in packages.iter().enumerate() {
        if show_progress && i % 50 == 0 && i > 0 {
            install_ui::phase_untrusted(&format!(
                "Checked cached security results for {i}/{} packages",
                packages.len()
            ));
        }

        let analysis = match lpm_store::find_installed_package_baseline_indexed(
            baseline_index,
            lpm_root,
            name,
            version,
        )
        .and_then(|baseline| behavioral::read_cached_analysis(&baseline.pristine_dir))
        {
            Some(a) => a,
            None => continue,
        };

        let pkg_id = format!("{name}@{version}");
        collect_tags_from_analysis(&analysis, &pkg_id, &mut tag_counts);
    }

    if show_progress {
        install_ui::done_untrusted(&format!(
            "Checked cached security results for {} packages",
            packages.len()
        ));
    }

    // ── Registry-side enrichment (@lpm.dev only) ─────

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

    let total: usize = tag_counts.values().map(|v| v.len()).sum();
    emit_human_security_summary(packages.len(), total, &issues, quiet);
}

fn emit_human_security_summary(
    package_count: usize,
    finding_count: usize,
    issues: &[TagIssue],
    quiet: bool,
) {
    for line in format_human_security_summary(package_count, finding_count, issues, quiet) {
        match line {
            SecuritySummaryLine::Warn(message) => install_ui::warn_line(message),
            SecuritySummaryLine::Detail(message) => install_ui::detail_line(message),
        }
    }
}

fn format_human_security_summary(
    package_count: usize,
    finding_count: usize,
    issues: &[TagIssue],
    quiet: bool,
) -> Vec<SecuritySummaryLine> {
    let mut lines = Vec::new();
    lines.push(SecuritySummaryLine::Warn(install_ui::terminal_line!(
        "Security summary · {} · {}",
        install_ui::status_ok(&format!(
            "{} {}",
            package_count,
            install_ui::packages_word(package_count)
        )),
        install_ui::status_ok(&format!(
            "{finding_count} {}",
            if finding_count == 1 {
                "finding"
            } else {
                "findings"
            }
        )),
    )));

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

        lines.push(SecuritySummaryLine::Detail(install_ui::terminal_line!(
            "  {}",
            format_security_severity(severity)
        )));

        for issue in tier_issues {
            let count = issue.packages.len();
            let preview_str = preview_packages(&issue.packages, 3);
            let suffix = if count > 3 {
                install_ui::dim(&format!(", ... (+{})", count - 3))
            } else {
                install_ui::dim("")
            };

            lines.push(SecuritySummaryLine::Detail(install_ui::terminal_line!(
                "    {} {:<20} {} {}{}",
                install_ui::status_ok(&count.to_string()),
                install_ui::cyan(issue.tag_label),
                install_ui::dim("→"),
                install_ui::dim(&preview_str),
                suffix,
            )));
        }
    }

    lines.push(SecuritySummaryLine::Detail(install_ui::terminal_line!(
        "  {} Run {} for full details.",
        install_ui::dim("hint"),
        install_ui::yellow("lpm audit"),
    )));
    lines.push(SecuritySummaryLine::Detail(install_ui::terminal_line!(
        "  {} Run {} to inspect specific tags.",
        install_ui::dim("hint"),
        install_ui::yellow("lpm query \":critical\""),
    )));
    lines
}

fn format_security_severity(severity: Severity) -> install_ui::TerminalFragment {
    match severity {
        Severity::Critical => install_ui::red("Critical"),
        Severity::High => install_ui::yellow("High"),
        Severity::Medium => install_ui::cyan("Medium"),
        Severity::Info => install_ui::dim("Info"),
    }
}

fn preview_packages(packages: &[String], limit: usize) -> String {
    packages
        .iter()
        .take(limit)
        .map(|pkg| lpm_common::sanitize_for_terminal(pkg))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Collect tags from a client-side PackageAnalysis into the tag_counts map.
fn collect_tags_from_analysis(
    analysis: &PackageAnalysis,
    pkg_id: &str,
    counts: &mut HashMap<&'static str, HashSet<String>>,
) {
    let s = &analysis.source;
    let sc = &analysis.supply_chain;
    let m = &analysis.manifest;

    // Source tags
    if s.filesystem {
        counts
            .entry("filesystem")
            .or_default()
            .insert(pkg_id.to_string());
    }
    if s.network {
        counts
            .entry("network")
            .or_default()
            .insert(pkg_id.to_string());
    }
    if s.child_process {
        counts
            .entry("child_process")
            .or_default()
            .insert(pkg_id.to_string());
    }
    if s.environment_vars {
        counts
            .entry("environment_vars")
            .or_default()
            .insert(pkg_id.to_string());
    }
    if s.eval {
        counts.entry("eval").or_default().insert(pkg_id.to_string());
    }
    if s.native_bindings {
        counts
            .entry("native_bindings")
            .or_default()
            .insert(pkg_id.to_string());
    }
    if s.crypto {
        counts
            .entry("crypto")
            .or_default()
            .insert(pkg_id.to_string());
    }
    if s.shell {
        counts
            .entry("shell")
            .or_default()
            .insert(pkg_id.to_string());
    }
    if s.web_socket {
        counts
            .entry("web_socket")
            .or_default()
            .insert(pkg_id.to_string());
    }
    if s.dynamic_require {
        counts
            .entry("dynamic_require")
            .or_default()
            .insert(pkg_id.to_string());
    }

    // Supply chain tags
    if sc.obfuscated {
        counts
            .entry("obfuscated")
            .or_default()
            .insert(pkg_id.to_string());
    }
    if sc.high_entropy_strings {
        counts
            .entry("high_entropy")
            .or_default()
            .insert(pkg_id.to_string());
    }
    if sc.minified {
        counts
            .entry("minified")
            .or_default()
            .insert(pkg_id.to_string());
    }
    if sc.telemetry {
        counts
            .entry("telemetry")
            .or_default()
            .insert(pkg_id.to_string());
    }
    if sc.url_strings {
        counts
            .entry("url_strings")
            .or_default()
            .insert(pkg_id.to_string());
    }
    if sc.trivial {
        counts
            .entry("trivial")
            .or_default()
            .insert(pkg_id.to_string());
    }
    if sc.protestware {
        counts
            .entry("protestware")
            .or_default()
            .insert(pkg_id.to_string());
    }

    // Manifest tags
    if m.git_dependency {
        counts
            .entry("git_dependency")
            .or_default()
            .insert(pkg_id.to_string());
    }
    if m.http_dependency {
        counts
            .entry("http_dependency")
            .or_default()
            .insert(pkg_id.to_string());
    }
    if m.wildcard_dependency {
        counts
            .entry("wildcard_dependency")
            .or_default()
            .insert(pkg_id.to_string());
    }
    if m.copyleft_license {
        counts
            .entry("copyleft_license")
            .or_default()
            .insert(pkg_id.to_string());
    }
    if m.no_license {
        counts
            .entry("no_license")
            .or_default()
            .insert(pkg_id.to_string());
    }
}

/// Collect additional warnings from registry metadata (@lpm.dev packages only).
///
/// Merges registry behavioral tags (OR with client-side), vulnerabilities,
/// AI security findings, and lifecycle scripts into the tag counts.
fn collect_registry_warnings(
    ver_meta: &lpm_registry::VersionMetadata,
    pkg_id: &str,
    counts: &mut HashMap<&'static str, HashSet<String>>,
) {
    // Registry behavioral tags — OR merge with client-side
    if let Some(tags) = &ver_meta.behavioral_tags {
        // Source tags
        if tags.eval {
            counts.entry("eval").or_default().insert(pkg_id.to_string());
        }
        if tags.child_process {
            counts
                .entry("child_process")
                .or_default()
                .insert(pkg_id.to_string());
        }
        if tags.shell {
            counts
                .entry("shell")
                .or_default()
                .insert(pkg_id.to_string());
        }
        if tags.network {
            counts
                .entry("network")
                .or_default()
                .insert(pkg_id.to_string());
        }
        if tags.filesystem {
            counts
                .entry("filesystem")
                .or_default()
                .insert(pkg_id.to_string());
        }
        if tags.crypto {
            counts
                .entry("crypto")
                .or_default()
                .insert(pkg_id.to_string());
        }
        if tags.dynamic_require {
            counts
                .entry("dynamic_require")
                .or_default()
                .insert(pkg_id.to_string());
        }
        if tags.native_bindings {
            counts
                .entry("native_bindings")
                .or_default()
                .insert(pkg_id.to_string());
        }
        if tags.environment_vars {
            counts
                .entry("environment_vars")
                .or_default()
                .insert(pkg_id.to_string());
        }
        if tags.web_socket {
            counts
                .entry("web_socket")
                .or_default()
                .insert(pkg_id.to_string());
        }
        // Supply chain tags
        if tags.obfuscated {
            counts
                .entry("obfuscated")
                .or_default()
                .insert(pkg_id.to_string());
        }
        if tags.high_entropy_strings {
            counts
                .entry("high_entropy")
                .or_default()
                .insert(pkg_id.to_string());
        }
        if tags.minified {
            counts
                .entry("minified")
                .or_default()
                .insert(pkg_id.to_string());
        }
        if tags.telemetry {
            counts
                .entry("telemetry")
                .or_default()
                .insert(pkg_id.to_string());
        }
        if tags.url_strings {
            counts
                .entry("url_strings")
                .or_default()
                .insert(pkg_id.to_string());
        }
        if tags.trivial {
            counts
                .entry("trivial")
                .or_default()
                .insert(pkg_id.to_string());
        }
        if tags.protestware {
            counts
                .entry("protestware")
                .or_default()
                .insert(pkg_id.to_string());
        }
        // Manifest tags
        if tags.git_dependency {
            counts
                .entry("git_dependency")
                .or_default()
                .insert(pkg_id.to_string());
        }
        if tags.http_dependency {
            counts
                .entry("http_dependency")
                .or_default()
                .insert(pkg_id.to_string());
        }
        if tags.wildcard_dependency {
            counts
                .entry("wildcard_dependency")
                .or_default()
                .insert(pkg_id.to_string());
        }
        if tags.copyleft_license {
            counts
                .entry("copyleft_license")
                .or_default()
                .insert(pkg_id.to_string());
        }
        if tags.no_license {
            counts
                .entry("no_license")
                .or_default()
                .insert(pkg_id.to_string());
        }
    }

    // Registry-provided vulnerabilities (from server-side OSV scan)
    if let Some(vulns) = &ver_meta.vulnerabilities {
        for vuln in vulns {
            let severity = vuln.severity.as_deref().unwrap_or("unknown").to_lowercase();
            let key = match severity.as_str() {
                "critical" => "vulnerability_critical",
                "high" => "vulnerability_high",
                _ => "vulnerability",
            };
            counts.entry(key).or_default().insert(pkg_id.to_string());
        }
    }

    // AI security findings
    if let Some(findings) = &ver_meta.security_findings {
        for finding in findings {
            let severity = finding.severity.as_deref().unwrap_or("info");
            if severity == "critical" || severity == "high" {
                counts
                    .entry("ai_security_finding")
                    .or_default()
                    .insert(pkg_id.to_string());
            }
        }
    }

    // Lifecycle scripts (already blocked by default, but show in summary)
    if let Some(scripts) = &ver_meta.lifecycle_scripts
        && !scripts.is_empty()
    {
        counts
            .entry("lifecycle_scripts")
            .or_default()
            .insert(pkg_id.to_string());
    }
}

/// Map tag names to severity tiers and build sorted issue list.
fn build_severity_groups(counts: &HashMap<&'static str, HashSet<String>>) -> Vec<TagIssue> {
    let tag_severity: &[(&str, &str, Severity)] = &[
        // Critical
        ("obfuscated", "obfuscated code", Severity::Critical),
        ("protestware", "protestware", Severity::Critical),
        (
            "vulnerability_critical",
            "critical vulnerability",
            Severity::Critical,
        ),
        // High
        ("eval", "eval()", Severity::High),
        ("child_process", "child_process", Severity::High),
        ("shell", "shell exec", Severity::High),
        ("dynamic_require", "dynamic require", Severity::High),
        ("lifecycle_scripts", "install scripts", Severity::High),
        ("ai_security_finding", "AI security finding", Severity::High),
        ("vulnerability_high", "high vulnerability", Severity::High),
        ("vulnerability", "vulnerability", Severity::High),
        // Medium
        ("network", "network access", Severity::Medium),
        ("native_bindings", "native bindings", Severity::Medium),
        ("git_dependency", "git dependency", Severity::Medium),
        ("http_dependency", "http dependency", Severity::Medium),
        ("wildcard_dependency", "wildcard dep", Severity::Medium),
        ("no_license", "no license", Severity::Medium),
        // Info
        ("high_entropy", "high entropy strings", Severity::Info),
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
            let mut sorted_pkgs: Vec<String> = pkgs.iter().cloned().collect();
            sorted_pkgs.sort();
            issues.push(TagIssue {
                tag_label: label,
                severity: *severity,
                packages: sorted_pkgs,
            });
        }
    }

    issues
}

#[cfg(test)]
mod tests {
    use super::*;
    use lpm_security::behavioral::manifest::ManifestTags;
    use lpm_security::behavioral::source::SourceTags;
    use lpm_security::behavioral::supply_chain::SupplyChainTags;
    use lpm_security::behavioral::{AnalysisMeta, PackageAnalysis};

    fn make_analysis(
        source: SourceTags,
        supply_chain: SupplyChainTags,
        manifest: ManifestTags,
    ) -> PackageAnalysis {
        PackageAnalysis {
            version: lpm_security::behavioral::SCHEMA_VERSION,
            analyzed_at: "T00:00:00Z".into(),
            source,
            supply_chain,
            manifest,
            meta: AnalysisMeta {
                files_scanned: 1,
                bytes_scanned: 100,
                limit_reached: false,
                url_domains: vec![],
                oversized_source_files: vec![],
            },
        }
    }

    // ── collect_tags_from_analysis tests ──────────────────────────────

    #[test]
    fn collect_tags_eval_and_shell() {
        let analysis = make_analysis(
            SourceTags {
                eval: true,
                shell: true,
                ..Default::default()
            },
            SupplyChainTags::default(),
            ManifestTags::default(),
        );
        let mut counts: HashMap<&'static str, HashSet<String>> = HashMap::new();
        collect_tags_from_analysis(&analysis, "test@1.0.0", &mut counts);

        assert!(counts.get("eval").unwrap().contains("test@1.0.0"));
        assert!(counts.get("shell").unwrap().contains("test@1.0.0"));
        assert!(!counts.contains_key("network"));
    }

    #[test]
    fn collect_tags_supply_chain() {
        let analysis = make_analysis(
            SourceTags::default(),
            SupplyChainTags {
                obfuscated: true,
                protestware: true,
                ..Default::default()
            },
            ManifestTags::default(),
        );
        let mut counts: HashMap<&'static str, HashSet<String>> = HashMap::new();
        collect_tags_from_analysis(&analysis, "evil@0.1.0", &mut counts);

        assert!(counts.get("obfuscated").unwrap().contains("evil@0.1.0"));
        assert!(counts.get("protestware").unwrap().contains("evil@0.1.0"));
    }

    #[test]
    fn collect_tags_manifest() {
        let analysis = make_analysis(
            SourceTags::default(),
            SupplyChainTags::default(),
            ManifestTags {
                no_license: true,
                copyleft_license: true,
                ..Default::default()
            },
        );
        let mut counts: HashMap<&'static str, HashSet<String>> = HashMap::new();
        collect_tags_from_analysis(&analysis, "pkg@2.0.0", &mut counts);

        assert!(counts.get("no_license").unwrap().contains("pkg@2.0.0"));
        assert!(
            counts
                .get("copyleft_license")
                .unwrap()
                .contains("pkg@2.0.0")
        );
    }

    #[test]
    fn human_security_summary_uses_slim_lines_with_expected_content() {
        let issues = vec![
            TagIssue {
                tag_label: "lifecycle script",
                severity: Severity::Critical,
                packages: vec!["evil@1.0.0".to_string(), "risky@2.0.0".to_string()],
            },
            TagIssue {
                tag_label: "network access",
                severity: Severity::Medium,
                packages: vec!["net@3.0.0".to_string()],
            },
        ];

        let lines = format_human_security_summary(3, 3, &issues, false);
        let joined = lines
            .iter()
            .map(|line| match line {
                SecuritySummaryLine::Warn(message) | SecuritySummaryLine::Detail(message) => {
                    message.as_ref()
                }
            })
            .collect::<Vec<_>>()
            .join("\n");
        let joined = console::strip_ansi_codes(&joined).into_owned();

        assert!(
            matches!(lines.first(), Some(SecuritySummaryLine::Warn(_))),
            "security summary headline should render through install_ui::warn"
        );
        assert!(
            joined.contains("Security summary · 3 packages · 3 findings"),
            "summary headline missing: {joined}"
        );
        assert!(
            joined.contains("2 lifecycle script") && joined.contains("→ evil@1.0.0, risky@2.0.0"),
            "critical issue detail missing: {joined}"
        );
        assert!(
            joined.contains("Run lpm audit for full details."),
            "hint detail missing: {joined}"
        );
    }

    #[test]
    fn human_security_summary_quiet_mode_keeps_high_signal_tiers_only() {
        let issues = vec![
            TagIssue {
                tag_label: "network access",
                severity: Severity::Medium,
                packages: vec!["net@3.0.0".to_string()],
            },
            TagIssue {
                tag_label: "lifecycle script",
                severity: Severity::High,
                packages: vec!["risky@2.0.0".to_string()],
            },
        ];

        let lines = format_human_security_summary(2, 2, &issues, true);
        let joined = lines
            .iter()
            .map(|line| match line {
                SecuritySummaryLine::Warn(message) | SecuritySummaryLine::Detail(message) => {
                    message.as_ref()
                }
            })
            .collect::<Vec<_>>()
            .join("\n");
        let joined = console::strip_ansi_codes(&joined).into_owned();

        assert!(
            joined.contains("lifecycle script"),
            "high-severity issue should stay visible: {joined}"
        );
        assert!(
            !joined.contains("network access"),
            "medium-severity issue should be suppressed in quiet mode: {joined}"
        );
    }

    #[test]
    fn collect_tags_dedup_same_package() {
        let analysis = make_analysis(
            SourceTags {
                eval: true,
                ..Default::default()
            },
            SupplyChainTags::default(),
            ManifestTags::default(),
        );
        let mut counts: HashMap<&'static str, HashSet<String>> = HashMap::new();
        collect_tags_from_analysis(&analysis, "pkg@1.0.0", &mut counts);
        collect_tags_from_analysis(&analysis, "pkg@1.0.0", &mut counts);

        // HashSet deduplicates automatically
        assert_eq!(counts.get("eval").unwrap().len(), 1);
    }

    #[test]
    fn collect_tags_empty_analysis() {
        let analysis = make_analysis(
            SourceTags::default(),
            SupplyChainTags::default(),
            ManifestTags::default(),
        );
        let mut counts: HashMap<&'static str, HashSet<String>> = HashMap::new();
        collect_tags_from_analysis(&analysis, "clean@1.0.0", &mut counts);

        assert!(counts.is_empty());
    }

    // ── collect_registry_warnings tests ──────────────────────────────

    #[test]
    fn registry_warnings_collects_vulnerabilities() {
        let ver_meta = lpm_registry::VersionMetadata {
            vulnerabilities: Some(vec![
                lpm_registry::Vulnerability {
                    id: Some("CVE-2021-1234".into()),
                    summary: Some("test vuln".into()),
                    severity: Some("critical".into()),
                    aliases: None,
                },
                lpm_registry::Vulnerability {
                    id: Some("CVE-2021-5678".into()),
                    summary: Some("another vuln".into()),
                    severity: Some("high".into()),
                    aliases: None,
                },
            ]),
            ..Default::default()
        };
        let mut counts: HashMap<&'static str, HashSet<String>> = HashMap::new();
        collect_registry_warnings(&ver_meta, "pkg@1.0.0", &mut counts);

        assert!(
            counts
                .get("vulnerability_critical")
                .unwrap()
                .contains("pkg@1.0.0")
        );
        assert!(
            counts
                .get("vulnerability_high")
                .unwrap()
                .contains("pkg@1.0.0")
        );
    }

    #[test]
    fn registry_warnings_merges_behavioral_tags() {
        let ver_meta = lpm_registry::VersionMetadata {
            behavioral_tags: Some(lpm_registry::BehavioralTags {
                eval: true,
                obfuscated: true,
                no_license: true,
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut counts: HashMap<&'static str, HashSet<String>> = HashMap::new();
        collect_registry_warnings(&ver_meta, "pkg@1.0.0", &mut counts);

        assert!(counts.get("eval").unwrap().contains("pkg@1.0.0"));
        assert!(counts.get("obfuscated").unwrap().contains("pkg@1.0.0"));
        assert!(counts.get("no_license").unwrap().contains("pkg@1.0.0"));
    }

    #[test]
    fn registry_warnings_or_merges_with_client_side() {
        // Simulate client-side already found eval
        let mut counts: HashMap<&'static str, HashSet<String>> = HashMap::new();
        counts
            .entry("eval")
            .or_default()
            .insert("pkg@1.0.0".to_string());

        // Registry also finds eval + network
        let ver_meta = lpm_registry::VersionMetadata {
            behavioral_tags: Some(lpm_registry::BehavioralTags {
                eval: true,
                network: true,
                ..Default::default()
            }),
            ..Default::default()
        };
        collect_registry_warnings(&ver_meta, "pkg@1.0.0", &mut counts);

        // eval: still 1 entry (HashSet dedup), network: added
        assert_eq!(counts.get("eval").unwrap().len(), 1);
        assert!(counts.get("network").unwrap().contains("pkg@1.0.0"));
    }

    #[test]
    fn registry_warnings_ai_findings() {
        let ver_meta = lpm_registry::VersionMetadata {
            security_findings: Some(vec![lpm_registry::SecurityFinding {
                severity: Some("critical".into()),
                description: Some("suspicious code".into()),
                file: None,
            }]),
            ..Default::default()
        };
        let mut counts: HashMap<&'static str, HashSet<String>> = HashMap::new();
        collect_registry_warnings(&ver_meta, "pkg@1.0.0", &mut counts);

        assert!(
            counts
                .get("ai_security_finding")
                .unwrap()
                .contains("pkg@1.0.0")
        );
    }

    #[test]
    fn registry_warnings_lifecycle_scripts() {
        let mut scripts = HashMap::new();
        scripts.insert("postinstall".to_string(), "node setup.js".to_string());

        let ver_meta = lpm_registry::VersionMetadata {
            lifecycle_scripts: Some(scripts),
            ..Default::default()
        };
        let mut counts: HashMap<&'static str, HashSet<String>> = HashMap::new();
        collect_registry_warnings(&ver_meta, "pkg@1.0.0", &mut counts);

        assert!(
            counts
                .get("lifecycle_scripts")
                .unwrap()
                .contains("pkg@1.0.0")
        );
    }

    #[test]
    fn registry_warnings_empty_metadata() {
        let ver_meta = lpm_registry::VersionMetadata::default();
        let mut counts: HashMap<&'static str, HashSet<String>> = HashMap::new();
        collect_registry_warnings(&ver_meta, "pkg@1.0.0", &mut counts);

        assert!(counts.is_empty());
    }

    // ── build_severity_groups tests ──────────────────────────────────

    #[test]
    fn severity_groups_critical_first() {
        let mut counts: HashMap<&'static str, HashSet<String>> = HashMap::new();
        counts
            .entry("eval")
            .or_default()
            .insert("a@1.0.0".to_string());
        counts
            .entry("obfuscated")
            .or_default()
            .insert("b@1.0.0".to_string());
        counts
            .entry("filesystem")
            .or_default()
            .insert("c@1.0.0".to_string());

        let issues = build_severity_groups(&counts);

        assert_eq!(issues[0].severity, Severity::Critical); // obfuscated
        assert_eq!(issues[1].severity, Severity::High); // eval
        assert_eq!(issues[2].severity, Severity::Info); // filesystem
    }

    #[test]
    fn severity_groups_vulnerability_tiers() {
        let mut counts: HashMap<&'static str, HashSet<String>> = HashMap::new();
        counts
            .entry("vulnerability_critical")
            .or_default()
            .insert("a@1.0.0".to_string());
        counts
            .entry("vulnerability_high")
            .or_default()
            .insert("b@1.0.0".to_string());
        counts
            .entry("vulnerability")
            .or_default()
            .insert("c@1.0.0".to_string());

        let issues = build_severity_groups(&counts);

        assert_eq!(issues.len(), 3);
        assert_eq!(issues[0].severity, Severity::Critical);
        assert_eq!(issues[0].tag_label, "critical vulnerability");
        assert_eq!(issues[1].severity, Severity::High);
        assert_eq!(issues[1].tag_label, "high vulnerability");
        assert_eq!(issues[2].severity, Severity::High);
        assert_eq!(issues[2].tag_label, "vulnerability");
    }

    #[test]
    fn severity_groups_empty_counts() {
        let counts: HashMap<&'static str, HashSet<String>> = HashMap::new();
        let issues = build_severity_groups(&counts);
        assert!(issues.is_empty());
    }

    #[test]
    fn severity_groups_packages_sorted() {
        let mut counts: HashMap<&'static str, HashSet<String>> = HashMap::new();
        let set = counts.entry("eval").or_default();
        set.insert("z-pkg@1.0.0".to_string());
        set.insert("a-pkg@1.0.0".to_string());
        set.insert("m-pkg@1.0.0".to_string());

        let issues = build_severity_groups(&counts);
        assert_eq!(
            issues[0].packages,
            vec!["a-pkg@1.0.0", "m-pkg@1.0.0", "z-pkg@1.0.0"]
        );
    }
}
