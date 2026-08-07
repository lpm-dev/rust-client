use std::collections::{HashMap, HashSet};

use lpm_common::color::Painted;

use crate::install_ui;

use super::format::{
    count_phrase, format_behavior_message, format_osv_severity, format_severity, info_tag_phrase,
    preview_package_names, preview_versioned_packages,
};
use crate::commands::audit::behavior::BehavioralSummary;
use crate::commands::audit::discovery::DiscoveryResult;
use crate::commands::audit::osv::OsvVulnerability;
use crate::commands::audit::types::{AuditIssue, AuditResult};

pub(in crate::commands::audit) fn print_discovery_summary(discovery: &DiscoveryResult) {
    let total = discovery.packages.len();
    let mut message = format!("Analyzed {total} {}", install_ui::packages_word(total));
    if let Some(ref lockfile_path) = discovery.lockfile_path {
        if let Some(lockfile_name) = lockfile_path
            .file_name()
            .and_then(|f| f.to_str())
            .filter(|name| !name.is_empty())
        {
            message.push_str(" · ");
            message.push_str(&install_ui::dim(lockfile_name));
        }
    } else {
        message.push_str(" · ");
        message.push_str(&install_ui::dim("node_modules"));
    }

    install_ui::done_untrusted(&message);

    if discovery.lockfile_path.is_none() {
        install_ui::warn("No lockfile found; scanning node_modules directly");
    }
    if discovery.is_yarn_pnp {
        install_ui::warn("Yarn PnP detected; source scanning unavailable");
    }
}

pub(in crate::commands::audit) fn print_osv_status(osv_degraded_reason: Option<&str>) {
    if let Some(reason) = osv_degraded_reason {
        install_ui::warn_line(crate::install_ui::terminal_line!(
            "{} database unavailable; vulnerability scan incomplete",
            install_ui::yellow("OSV")
        ));
        eprintln!(
            "  {} {}",
            install_ui::dim("reason:"),
            lpm_common::sanitize_terminal_inline(reason)
        );
    } else {
        install_ui::done_line(crate::install_ui::terminal_line!(
            "Checked against {} database",
            install_ui::yellow("OSV")
        ));
    }
}

/// Print LPM package quality scores and registry-only issues.
pub(in crate::commands::audit) fn print_lpm_results(
    results: &[AuditResult],
    lpm_packages: &[(String, String)],
) {
    if lpm_packages.is_empty() {
        return;
    }

    let lpm_names: HashSet<&str> = lpm_packages.iter().map(|(n, _)| n.as_str()).collect();

    for result in results {
        if !lpm_names.contains(result.name.as_str()) {
            continue;
        }

        let score_str = result
            .quality_score
            .map(|s| format!(" quality: {s}/100"))
            .unwrap_or_default();

        let registry_issues: Vec<&AuditIssue> = result
            .issues
            .iter()
            .filter(|i| i.source == "registry")
            .collect();

        if registry_issues.is_empty() {
            let name = lpm_common::sanitize_terminal_inline(&result.name);
            let version = lpm_common::sanitize_terminal_inline(&result.version);
            eprintln!(
                "  {} {}{}",
                "✓".green(),
                format!("{name}@{version}").dimmed(),
                score_str.dimmed(),
            );
            continue;
        }

        let name = lpm_common::sanitize_terminal_inline(&result.name);
        let version = lpm_common::sanitize_terminal_inline(&result.version);
        eprintln!(
            "\n  {} {}",
            install_ui::yellow(&name),
            format!("({version}){score_str}").dimmed(),
        );

        for issue in registry_issues {
            let icon = match issue.severity.as_str() {
                "high" | "critical" => "✗".red().to_string(),
                "moderate" => "!".yellow().to_string(),
                _ => "ℹ".blue().to_string(),
            };
            eprintln!(
                "    {icon} {} {} {}",
                format_severity(&issue.severity),
                lpm_common::sanitize_terminal_inline(&issue.message),
                format!("[{}]", lpm_common::sanitize_terminal_inline(&issue.source)).dimmed()
            );
        }
    }
}

/// Print OSV vulnerability results.
pub(in crate::commands::audit) fn print_osv_results(osv_vulns: &[OsvVulnerability]) {
    if osv_vulns.is_empty() {
        return;
    }

    eprintln!();
    eprintln!("  {}", install_ui::section("Vulnerabilities"));

    for vuln in osv_vulns {
        let package_safe = lpm_common::sanitize_for_terminal(&vuln.package);
        let version_safe = lpm_common::sanitize_for_terminal(&vuln.version);
        let id_safe = lpm_common::sanitize_for_terminal(&vuln.id);
        eprintln!(
            "  {} {}@{}  {}  {}",
            "!".yellow(),
            package_safe,
            version_safe,
            install_ui::cyan(&id_safe),
            format_osv_severity(&vuln.severity),
        );
    }
}

/// Print behavioral analysis findings grouped by severity tier.
///
/// Instead of listing every package individually (which can be thousands of lines),
/// groups findings by tag with counts and shows only a few example packages per tag.
pub(in crate::commands::audit) fn print_behavioral_results(
    results: &[AuditResult],
    lpm_packages: &[(String, String)],
) {
    let lpm_names: HashSet<&str> = lpm_packages.iter().map(|(n, _)| n.as_str()).collect();

    // Collect tag → packages mapping grouped by severity
    let mut critical_tags: HashMap<String, Vec<String>> = HashMap::new();
    let mut moderate_tags: HashMap<String, Vec<String>> = HashMap::new();
    let mut info_tags: HashMap<String, Vec<String>> = HashMap::new();

    for result in results {
        if lpm_names.contains(result.name.as_str()) {
            continue;
        }
        let pkg_id = format!("{}@{}", result.name, result.version);

        for issue in &result.issues {
            let sev = issue.severity.to_lowercase();
            let tags = match sev.as_str() {
                "critical" => &mut critical_tags,
                "high" | "moderate" => &mut moderate_tags,
                "info" => &mut info_tags,
                _ => &mut info_tags,
            };
            tags.entry(issue.message.clone())
                .or_default()
                .push(pkg_id.clone());
        }
    }

    let has_critical = !critical_tags.is_empty();
    let has_moderate = !moderate_tags.is_empty();
    let has_info = !info_tags.is_empty();

    if !has_critical && !has_moderate && !has_info {
        return;
    }

    eprintln!();

    // Critical tier — show individual packages (these are truly suspicious)
    if has_critical {
        eprintln!("  {}", install_ui::section("Suspicious packages"));
        let mut sorted: Vec<(&String, &Vec<String>)> = critical_tags.iter().collect();
        sorted.sort_by(|a, b| b.1.len().cmp(&a.1.len()).then_with(|| a.0.cmp(b.0)));
        for (message, packages) in sorted {
            eprintln!(
                "  {} {}  {}",
                "✗".red(),
                "CRITICAL".red().bold(),
                lpm_common::sanitize_terminal_inline(message),
            );
            eprintln!("              {}", preview_versioned_packages(packages, 4),);
        }
        eprintln!();
    }

    // Moderate tier — show counts with a few examples
    if has_moderate {
        eprintln!("  {}", install_ui::section("Behavioral flags"));
        // Sort by count descending
        let mut sorted: Vec<(&String, &Vec<String>)> = moderate_tags.iter().collect();
        sorted.sort_by(|a, b| b.1.len().cmp(&a.1.len()).then_with(|| a.0.cmp(b.0)));
        for (message, packages) in sorted {
            let count = packages.len();
            eprintln!(
                "  {} {count:<3} {}  {}",
                "!".yellow(),
                format_behavior_message(message),
                preview_package_names(packages, 2),
            );
        }
        eprintln!();
    }

    // Info tier — aggregate counts only, no package names
    if has_info {
        // Parse "flags: network, native bindings" → individual tags
        let mut tag_counts: HashMap<&str, usize> = HashMap::new();
        for (message, packages) in &info_tags {
            if let Some(flags) = message.strip_prefix("flags: ") {
                for flag in flags.split(", ") {
                    *tag_counts.entry(flag).or_default() += packages.len();
                }
            } else {
                // Non-flags info message (e.g., "high-entropy strings detected")
                tag_counts.insert(message.as_str(), packages.len());
            }
        }
        if !tag_counts.is_empty() {
            let mut sorted: Vec<(&&str, &usize)> = tag_counts.iter().collect();
            sorted.sort_by(|a, b| b.1.cmp(a.1).then_with(|| a.0.cmp(b.0)));
            let signal_count = tag_counts.values().sum();
            let summary_parts: Vec<String> = sorted
                .into_iter()
                .map(|(tag, count)| info_tag_phrase(tag, *count))
                .collect();
            let separator = format!(" {} ", install_ui::dim("·"));
            eprintln!(
                "  {} · {}",
                install_ui::section("Behavioral metadata"),
                count_phrase(signal_count, "signal", "signals")
            );
            eprintln!(
                "  {} {}",
                install_ui::dim("signals:"),
                summary_parts.join(&separator),
            );
        }
    }
}

/// Print final summary line.
pub(in crate::commands::audit) fn print_summary(
    results: &[AuditResult],
    osv_vulns: &[OsvVulnerability],
    behavioral: &BehavioralSummary,
    discovery: &DiscoveryResult,
    checked_lpm: usize,
    osv_degraded: bool,
) {
    eprintln!();

    let total_scanned = discovery.packages.len();
    let vuln_count = osv_vulns.len();
    let lpm_actionable_issues: usize = results
        .iter()
        .filter(|r| r.name.starts_with("@lpm.dev/"))
        .flat_map(|result| &result.issues)
        .filter(|issue| issue.severity != "info")
        .count();
    let metadata_signals = results
        .iter()
        .flat_map(|result| &result.issues)
        .filter(|issue| issue.severity == "info")
        .count();

    if osv_degraded {
        install_ui::warn_untrusted(&format!(
            "Audit incomplete · {total_scanned} {} scanned",
            install_ui::packages_word(total_scanned)
        ));
    } else if vuln_count == 0
        && lpm_actionable_issues == 0
        && behavioral.packages_with_actionable_findings == 0
    {
        let mut parts = vec![format!("{total_scanned} scanned")];
        if checked_lpm > 0 {
            parts.push(format!("{checked_lpm} LPM audited"));
        }
        if behavioral.packages_scanned > 0 {
            parts.push(format!("{} analyzed", behavioral.packages_scanned));
        }
        if metadata_signals > 0 {
            parts.push(format!(
                "{metadata_signals} metadata signal{}",
                if metadata_signals == 1 { "" } else { "s" }
            ));
        }
        install_ui::done_untrusted(&format!("No security issues found · {}", parts.join(" · ")));
    } else {
        let mut parts = Vec::new();
        if vuln_count > 0 {
            parts.push(count_phrase(vuln_count, "vulnerability", "vulnerabilities"));
        }
        if behavioral.packages_with_actionable_findings > 0 {
            parts.push(count_phrase(
                behavioral.packages_with_actionable_findings,
                "suspicious",
                "suspicious",
            ));
        }
        if lpm_actionable_issues > 0 {
            parts.push(count_phrase(
                lpm_actionable_issues,
                "LPM issue",
                "LPM issues",
            ));
        }
        parts.push(format!("{total_scanned} scanned"));

        install_ui::warn_untrusted(&parts.join(" · "));
    }
}
