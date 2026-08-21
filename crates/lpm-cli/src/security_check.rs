//! Post-install security warnings.
//!
//! Two layers of security checking:
//!
//! 1. **Client-side analysis** (all packages): Scans each installed package's
//!    live materialization (npm + @lpm.dev). Produces a severity-tiered summary
//!    of behavioral tags.
//!
//! 2. **Registry-side analysis** (@lpm.dev only): Fetches behavioral tags and
//!    lifecycle scripts from registry metadata, then merges behavioral tags
//!    with client-side tags via OR.
//!
//! Uses batch metadata endpoint for @lpm.dev packages (1 request for all).

use crate::install_ui;
use lpm_linker::MaterializedPackage;
use lpm_registry::RegistryClient;
use lpm_security::behavioral::{self, PackageAnalysis};
use lpm_security::query::{InstallVisibility, PseudoClass, Severity, behavioral_tag_policies};
use rayon::prelude::*;
use std::collections::{HashMap, HashSet};
use std::path::Path;

/// A tagged issue found in a package.
struct TagIssue {
    tag_label: &'static str,
    severity: Severity,
    install_visibility: InstallVisibility,
    selector: Option<&'static str>,
    packages: Vec<String>, // "name@version"
}

#[derive(Default)]
struct SummaryCounts {
    behavioral: HashMap<PseudoClass, HashSet<String>>,
    lifecycle_scripts: HashSet<String>,
}

impl SummaryCounts {
    fn insert_behavioral(&mut self, tag: PseudoClass, package: &str) {
        self.behavioral
            .entry(tag)
            .or_default()
            .insert(package.to_string());
    }

    fn insert_lifecycle_scripts(&mut self, package: &str) {
        self.lifecycle_scripts.insert(package.to_string());
    }
}

#[derive(Debug, Clone)]
pub(crate) struct SecuritySummaryPackage {
    pub(crate) instance_id: Option<lpm_common::PackageInstanceId>,
    pub(crate) name: String,
    pub(crate) version: String,
    pub(crate) source: String,
    pub(crate) integrity: Option<String>,
    pub(crate) is_lpm: bool,
}

impl SecuritySummaryPackage {
    fn finding_key(&self) -> String {
        let integrity = self.integrity.as_deref().unwrap_or("");
        let mut key = String::with_capacity(
            self.name.len() + self.version.len() + self.source.len() + integrity.len() + 3,
        );
        key.push_str(&self.name);
        key.push('@');
        key.push_str(&self.version);
        key.push('\u{1f}');
        key.push_str(&self.source);
        key.push('\u{1f}');
        key.push_str(integrity);
        if let Some(instance_id) = self.instance_id {
            key.push('\u{1f}');
            key.push_str(&instance_id.to_string());
        }
        key
    }
}

#[derive(Debug, Eq, PartialEq)]
enum SecuritySummaryLine {
    Warn(install_ui::TerminalLine),
    Detail(install_ui::TerminalLine),
}

/// Run the full post-install security summary.
///
/// Scans every live package materialization, then fetches registry metadata for
/// @lpm.dev packages to merge behavioral tags and lifecycle scripts.
/// Vulnerabilities and registry security findings are available only through
/// `lpm audit` or audit-after-install.
pub(crate) async fn post_install_security_summary(
    client: &RegistryClient,
    packages: &[SecuritySummaryPackage],
    materialized: &[MaterializedPackage],
    json_output: bool,
    verbose: bool,
    fetch_lpm_security_insights: bool,
) {
    if packages.is_empty() {
        return;
    }

    // ── Client-side analysis (all packages) ──────────

    let show_progress = !json_output && packages.len() > 50;
    if show_progress {
        install_ui::phase_untrusted(&format!(
            "Scanning security behavior for {} installed packages",
            packages.len()
        ));
    }

    let analyses: Vec<_> = packages
        .par_iter()
        .filter_map(|package| {
            analyze_live_package(package, materialized).map(|analysis| (package, analysis))
        })
        .collect();
    let mut tag_counts = SummaryCounts::default();
    for (package, analysis) in analyses {
        let pkg_id = package.finding_key();
        collect_tags_from_analysis(&analysis, &pkg_id, &mut tag_counts);
    }

    if show_progress {
        install_ui::done_untrusted(&format!(
            "Scanned security behavior for {} installed packages",
            packages.len()
        ));
    }

    // ── Registry-side enrichment (@lpm.dev only) ─────

    let lpm_packages = lpm_packages_for_enrichment(packages, fetch_lpm_security_insights);

    if !lpm_packages.is_empty() {
        let names: Vec<String> = lpm_packages
            .iter()
            .map(|package| package.name.clone())
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();
        if let Ok(metadata_map) = client.batch_metadata(&names).await {
            for package in &lpm_packages {
                if let Some(metadata) = metadata_map.get(&package.name) {
                    let ver_meta = metadata
                        .version(&package.version)
                        .or_else(|| metadata.latest());
                    if let Some(vm) = ver_meta {
                        let pkg_id = package.finding_key();
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

    emit_human_security_summary(packages.len(), &issues, verbose);
}

fn analyze_live_package(
    package: &SecuritySummaryPackage,
    materialized: &[MaterializedPackage],
) -> Option<PackageAnalysis> {
    let exact = package.instance_id.and_then(|instance_id| {
        materialized
            .iter()
            .find(|candidate| candidate.instance_id == Some(instance_id))
    });
    let selected = exact.or_else(|| {
        let mut candidates = materialized.iter().filter(|candidate| {
            candidate.instance_id.is_none()
                && candidate.name == package.name
                && candidate.version == package.version
        });
        candidates.next().map(|first| {
            candidates.fold(first, |selected, candidate| {
                if candidate.destination < selected.destination {
                    candidate
                } else {
                    selected
                }
            })
        })
    })?;
    let source = selected
        .analysis_source
        .as_deref()
        .unwrap_or(&selected.destination);
    let directory = open_materialized_package(source).ok()?;
    Some(behavioral::analyze_package_from_open_dir(&directory))
}

fn open_materialized_package(path: &Path) -> std::io::Result<cap_std::fs::Dir> {
    let parent = path.parent().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "materialized package path has no parent",
        )
    })?;
    let name = path.file_name().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "materialized package path has no final component",
        )
    })?;
    let parent = cap_std::fs::Dir::open_ambient_dir(parent, cap_std::ambient_authority())?;
    cap_fs_ext::DirExt::open_dir_nofollow(&parent, name)
}

fn lpm_packages_for_enrichment(
    packages: &[SecuritySummaryPackage],
    enabled: bool,
) -> Vec<&SecuritySummaryPackage> {
    if !enabled {
        return Vec::new();
    }
    packages.iter().filter(|package| package.is_lpm).collect()
}

fn emit_human_security_summary(package_count: usize, issues: &[TagIssue], verbose: bool) {
    for line in format_human_security_summary(package_count, issues, verbose) {
        match line {
            SecuritySummaryLine::Warn(message) => install_ui::warn_line(message),
            SecuritySummaryLine::Detail(message) => install_ui::detail_line(message),
        }
    }
}

fn format_human_security_summary(
    package_count: usize,
    issues: &[TagIssue],
    verbose: bool,
) -> Vec<SecuritySummaryLine> {
    let mut lines = Vec::new();
    let actionable: Vec<&TagIssue> = issues
        .iter()
        .filter(|issue| {
            issue.severity != Severity::Info && issue.install_visibility.is_visible(verbose)
        })
        .collect();
    let metadata: Vec<&TagIssue> = issues
        .iter()
        .filter(|issue| {
            issue.severity == Severity::Info && issue.install_visibility.is_visible(verbose)
        })
        .collect();

    if !actionable.is_empty() {
        let finding_count = issue_count(&actionable);
        lines.push(SecuritySummaryLine::Warn(summary_heading(
            "Security summary",
            package_count,
            finding_count,
            "finding",
        )));
        if verbose {
            append_issue_tiers(
                &mut lines,
                &actionable,
                &[Severity::Critical, Severity::High, Severity::Medium],
            );
        } else {
            append_severity_rollup(&mut lines, &actionable);
            append_issue_tiers(&mut lines, &actionable, &[Severity::Critical]);
        }
        lines.push(SecuritySummaryLine::Detail(install_ui::terminal_line!(
            "  {} Run {} for full details.",
            install_ui::dim("hint"),
            install_ui::yellow("lpm audit"),
        )));
        if verbose {
            append_query_hint(&mut lines, &actionable, "findings");
        }
    }

    if !metadata.is_empty() {
        let signal_count = issue_count(&metadata);
        lines.push(SecuritySummaryLine::Detail(install_ui::terminal_line!(
            "{} {}",
            install_ui::cyan("ℹ"),
            summary_heading("Behavioral metadata", package_count, signal_count, "signal")
        )));
        append_issue_tiers(&mut lines, &metadata, &[Severity::Info]);
        append_query_hint(&mut lines, &metadata, "signals");
    }

    lines
}

fn summary_heading(
    title: &'static str,
    package_count: usize,
    item_count: usize,
    item_name: &'static str,
) -> install_ui::TerminalLine {
    install_ui::terminal_line!(
        "{} · {} · {}",
        title,
        install_ui::status_ok(&format!(
            "{} {}",
            package_count,
            install_ui::packages_word(package_count)
        )),
        install_ui::status_ok(&format!(
            "{item_count} {item_name}{}",
            if item_count == 1 { "" } else { "s" }
        )),
    )
}

fn issue_count(issues: &[&TagIssue]) -> usize {
    issues.iter().map(|issue| issue.packages.len()).sum()
}

fn append_severity_rollup(lines: &mut Vec<SecuritySummaryLine>, issues: &[&TagIssue]) {
    let count = |severity| {
        issues
            .iter()
            .filter(|issue| issue.severity == severity)
            .map(|issue| issue.packages.len())
            .sum::<usize>()
    };
    let critical = count(Severity::Critical);
    let high = count(Severity::High);
    let medium = count(Severity::Medium);

    lines.push(SecuritySummaryLine::Detail(install_ui::terminal_line!(
        "  {} {} {} {} {} {} {} {}",
        install_ui::status_ok(&critical.to_string()),
        format_security_severity(Severity::Critical),
        install_ui::dim("·"),
        install_ui::status_ok(&high.to_string()),
        format_security_severity(Severity::High),
        install_ui::dim("·"),
        install_ui::status_ok(&medium.to_string()),
        format_security_severity(Severity::Medium),
    )));
}

fn append_issue_tiers(
    lines: &mut Vec<SecuritySummaryLine>,
    issues: &[&TagIssue],
    severities: &[Severity],
) {
    for &severity in severities {
        let tier_issues: Vec<&TagIssue> = issues
            .iter()
            .copied()
            .filter(|issue| issue.severity == severity)
            .collect();
        if tier_issues.is_empty() {
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
                "    {} {:<27} {} {}{}",
                install_ui::status_ok(&count.to_string()),
                install_ui::cyan(issue.tag_label),
                install_ui::dim("→"),
                install_ui::dim(&preview_str),
                suffix,
            )));
        }
    }
}

fn append_query_hint(
    lines: &mut Vec<SecuritySummaryLine>,
    issues: &[&TagIssue],
    item_name: &'static str,
) {
    let selectors: Vec<&str> = issues
        .iter()
        .filter_map(|issue| issue.selector)
        .collect::<HashSet<_>>()
        .into_iter()
        .collect();
    if selectors.is_empty() {
        return;
    }
    let selector = behavioral_tag_policies()
        .iter()
        .filter_map(|policy| selectors.contains(&policy.token).then_some(policy.token))
        .chain(
            [":scripts"]
                .into_iter()
                .filter(|selector| selectors.contains(selector)),
        )
        .collect::<Vec<_>>()
        .join(",");
    lines.push(SecuritySummaryLine::Detail(install_ui::terminal_line!(
        "  {} Run {} to inspect these {}.",
        install_ui::dim("hint"),
        install_ui::yellow(&format!("lpm query \"{selector}\"")),
        item_name,
    )));
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
    counts: &mut SummaryCounts,
) {
    for policy in behavioral_tag_policies() {
        if policy.tag.matches_analysis(analysis) {
            counts.insert_behavioral(policy.tag, pkg_id);
        }
    }
}

/// Collect registry metadata used by the normal install summary.
///
/// Merges registry behavioral tags (OR with client-side) and lifecycle scripts.
fn collect_registry_warnings(
    ver_meta: &lpm_registry::VersionMetadata,
    pkg_id: &str,
    counts: &mut SummaryCounts,
) {
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
            if present {
                counts.insert_behavioral(tag, pkg_id);
            }
        }
    }

    if let Some(scripts) = &ver_meta.lifecycle_scripts
        && !scripts.is_empty()
    {
        counts.insert_lifecycle_scripts(pkg_id);
    }
}

fn build_severity_groups(counts: &SummaryCounts) -> Vec<TagIssue> {
    let mut issues = Vec::new();
    for severity in [
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Info,
    ] {
        for policy in behavioral_tag_policies()
            .iter()
            .filter(|policy| policy.severity == severity)
        {
            if let Some(packages) = counts.behavioral.get(&policy.tag)
                && !packages.is_empty()
            {
                issues.push(TagIssue {
                    tag_label: policy.label,
                    severity: policy.severity,
                    install_visibility: policy.install_visibility,
                    selector: Some(policy.token),
                    packages: sorted_package_labels(packages),
                });
            }
        }
    }
    if !counts.lifecycle_scripts.is_empty() {
        issues.push(TagIssue {
            tag_label: "install scripts",
            severity: Severity::High,
            install_visibility: InstallVisibility::Default,
            selector: Some(":scripts"),
            packages: sorted_package_labels(&counts.lifecycle_scripts),
        });
    }
    issues
}

fn sorted_package_labels(packages: &HashSet<String>) -> Vec<String> {
    let mut coordinate_counts: HashMap<&str, usize> = HashMap::new();
    for package in packages {
        *coordinate_counts
            .entry(package.split('\u{1f}').next().unwrap_or(package))
            .or_default() += 1;
    }
    let mut labels: Vec<String> = packages
        .iter()
        .map(|package| {
            let mut fields = package.split('\u{1f}');
            let coordinate = fields.next().unwrap_or(package);
            if coordinate_counts.get(coordinate).copied().unwrap_or(0) < 2 {
                return coordinate.to_string();
            }
            let source = fields.next().unwrap_or("");
            let integrity = fields.next().unwrap_or("");
            let source = install_ui::safe_package_source_identity(source);
            let integrity_preview: String = integrity.chars().take(20).collect();
            if integrity_preview.is_empty() {
                format!("{coordinate} ({source})")
            } else {
                format!("{coordinate} ({source}, {integrity_preview}…)")
            }
        })
        .collect();
    labels.sort();
    labels
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use lpm_security::behavioral::manifest::ManifestTags;
    use lpm_security::behavioral::source::SourceTags;
    use lpm_security::behavioral::supply_chain::SupplyChainTags;
    use lpm_security::behavioral::{AnalysisMeta, PackageAnalysis};
    use lpm_store::V2BaselineIndex;
    use lpm_store::v2::link_meta::{LinkMeta, LinkMetaPlatform};
    use std::sync::Arc;

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

    fn summary_package(name: &str, is_lpm: bool) -> SecuritySummaryPackage {
        SecuritySummaryPackage {
            instance_id: None,
            name: name.to_string(),
            version: "1.0.0".to_string(),
            source: "https://registry.example.test".to_string(),
            integrity: None,
            is_lpm,
        }
    }

    #[test]
    fn disabled_lpm_security_insights_schedules_no_registry_enrichment() {
        let packages = [
            summary_package("@lpm.dev/secure", true),
            summary_package("ordinary", false),
        ];

        assert!(lpm_packages_for_enrichment(&packages, false).is_empty());
        assert_eq!(
            lpm_packages_for_enrichment(&packages, true)
                .iter()
                .map(|package| package.name.as_str())
                .collect::<Vec<_>>(),
            ["@lpm.dev/secure"]
        );
    }

    #[test]
    fn live_security_analysis_selects_the_exact_materialized_instance() {
        let root = tempfile::tempdir().unwrap();
        let first_dir = root.path().join("first");
        let second_dir = root.path().join("second");
        for (directory, source) in [
            (&first_dir, "module.exports = () => eval('first')\n"),
            (
                &second_dir,
                "require('child_process').exec('echo second')\n",
            ),
        ] {
            std::fs::create_dir_all(directory).unwrap();
            std::fs::write(
                directory.join("package.json"),
                r#"{"name":"duplicate","version":"1.0.0","license":"MIT"}"#,
            )
            .unwrap();
            std::fs::write(directory.join("index.js"), source).unwrap();
        }
        let first_id =
            lpm_common::PackageInstanceId::derive("duplicate", "1.0.0", "registry+first", "first");
        let second_id = lpm_common::PackageInstanceId::derive(
            "duplicate",
            "1.0.0",
            "registry+second",
            "second",
        );
        let materialized = [
            MaterializedPackage {
                instance_id: Some(first_id),
                name: "duplicate".to_string(),
                version: "1.0.0".to_string(),
                analysis_source: None,
                destination: first_dir,
            },
            MaterializedPackage {
                instance_id: Some(second_id),
                name: "duplicate".to_string(),
                version: "1.0.0".to_string(),
                analysis_source: None,
                destination: second_dir,
            },
        ];
        let package = SecuritySummaryPackage {
            instance_id: Some(second_id),
            name: "duplicate".to_string(),
            version: "1.0.0".to_string(),
            source: "registry+second".to_string(),
            integrity: Some("sha512-shared".to_string()),
            is_lpm: false,
        };

        let analysis = analyze_live_package(&package, &materialized).unwrap();

        assert!(!analysis.source.eval);
        assert!(analysis.source.child_process);
    }

    #[test]
    fn live_security_analysis_reads_the_original_directory_source() {
        let root = tempfile::tempdir().unwrap();
        let wrapper = root.path().join("wrapper");
        let source = root.path().join("source");
        for directory in [&wrapper, &source] {
            std::fs::create_dir_all(directory).unwrap();
            std::fs::write(
                directory.join("package.json"),
                r#"{"name":"local","version":"1.0.0","license":"MIT"}"#,
            )
            .unwrap();
        }
        std::fs::write(wrapper.join("index.js"), "module.exports = 1\n").unwrap();
        std::fs::write(
            source.join("index.js"),
            "module.exports = () => eval('live')\n",
        )
        .unwrap();
        let materialized = [MaterializedPackage {
            instance_id: None,
            name: "local".to_string(),
            version: "1.0.0".to_string(),
            analysis_source: Some(source),
            destination: wrapper,
        }];
        let package = summary_package("local", false);

        let analysis = analyze_live_package(&package, &materialized).unwrap();

        assert!(analysis.source.eval);
    }

    fn write_cached_analysis_link(
        lpm_root: &lpm_common::LpmRoot,
        store_version: lpm_store::StoreVersion,
        suffix: &str,
        source_sri: &str,
        analysis: &PackageAnalysis,
    ) {
        let link_dir = lpm_store::v2::Store::from_lpm_root_for_version(lpm_root, store_version)
            .paths()
            .links_root()
            .join(format!("duplicate@1.0.0+{suffix}"));
        let package_dir = link_dir.join("node_modules").join("duplicate");
        std::fs::create_dir_all(&package_dir).unwrap();
        behavioral::write_cached_analysis(&package_dir, analysis).unwrap();
        std::fs::write(
            package_dir.join("package.json"),
            r#"{"name":"duplicate","version":"1.0.0"}"#,
        )
        .unwrap();
        LinkMeta {
            schema: 1,
            graph_key: format!("duplicate@1.0.0+{suffix}"),
            graph_key_digest_hex: suffix.repeat(4),
            name: "duplicate".to_string(),
            version: "1.0.0".to_string(),
            source_sri: source_sri.to_string(),
            object_path: format!("objects/{source_sri}"),
            tree_digest: None,
            deps: Vec::new(),
            platform: Arc::new(LinkMetaPlatform {
                os: "darwin".to_string(),
                cpu: "arm64".to_string(),
                libc: None,
            }),
            created_at: Utc::now(),
            last_referenced_at: Utc::now(),
        }
        .write_to(&link_dir)
        .unwrap();
    }

    #[test]
    fn cached_security_lookup_distinguishes_sources_across_v2_and_v3() {
        let dir = tempfile::tempdir().unwrap();
        let lpm_root = lpm_common::LpmRoot::from_dir(dir.path());
        write_cached_analysis_link(
            &lpm_root,
            lpm_store::StoreVersion::V3,
            "aaaaaaaaaaaaaaaa",
            "sha512-source-a",
            &make_analysis(
                SourceTags {
                    eval: true,
                    ..Default::default()
                },
                SupplyChainTags::default(),
                ManifestTags::default(),
            ),
        );
        write_cached_analysis_link(
            &lpm_root,
            lpm_store::StoreVersion::V2,
            "bbbbbbbbbbbbbbbb",
            "sha512-source-b",
            &make_analysis(
                SourceTags {
                    shell: true,
                    ..Default::default()
                },
                SupplyChainTags::default(),
                ManifestTags::default(),
            ),
        );
        let index = V2BaselineIndex::build(&lpm_root).unwrap();
        let packages = [
            (
                "duplicate",
                "1.0.0",
                "registry+https://registry.npmjs.org",
                "sha512-source-a",
            ),
            (
                "duplicate",
                "1.0.0",
                "registry+https://registry.example.com",
                "sha512-source-b",
            ),
        ];
        let mut observed_tags = HashSet::new();

        for (name, version, _source, integrity) in packages {
            let analysis = lpm_store::find_installed_package_baseline_by_identity_indexed(
                &index,
                &lpm_root,
                name,
                version,
                Some(integrity),
            )
            .and_then(|baseline| behavioral::read_cached_analysis(&baseline.pristine_dir))
            .unwrap();
            if analysis.source.eval {
                observed_tags.insert("eval");
            }
            if analysis.source.shell {
                observed_tags.insert("shell");
            }
        }

        assert_eq!(observed_tags, HashSet::from(["eval", "shell"]));
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
        let mut counts = SummaryCounts::default();
        collect_tags_from_analysis(&analysis, "test@1.0.0", &mut counts);

        assert!(
            counts
                .behavioral
                .get(&PseudoClass::Eval)
                .unwrap()
                .contains("test@1.0.0")
        );
        assert!(
            counts
                .behavioral
                .get(&PseudoClass::Shell)
                .unwrap()
                .contains("test@1.0.0")
        );
        assert!(!counts.behavioral.contains_key(&PseudoClass::Network));
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
        let mut counts = SummaryCounts::default();
        collect_tags_from_analysis(&analysis, "evil@0.1.0", &mut counts);

        assert!(
            counts
                .behavioral
                .get(&PseudoClass::Obfuscated)
                .unwrap()
                .contains("evil@0.1.0")
        );
        assert!(
            counts
                .behavioral
                .get(&PseudoClass::Protestware)
                .unwrap()
                .contains("evil@0.1.0")
        );
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
        let mut counts = SummaryCounts::default();
        collect_tags_from_analysis(&analysis, "pkg@2.0.0", &mut counts);

        assert!(
            counts
                .behavioral
                .get(&PseudoClass::NoLicense)
                .unwrap()
                .contains("pkg@2.0.0")
        );
        assert!(
            counts
                .behavioral
                .get(&PseudoClass::Copyleft)
                .unwrap()
                .contains("pkg@2.0.0")
        );
    }

    #[test]
    fn human_security_summary_rolls_up_severities_and_details_only_critical_by_default() {
        let issues = vec![
            TagIssue {
                tag_label: "obfuscated code",
                severity: Severity::Critical,
                install_visibility: InstallVisibility::Default,
                selector: Some(":obfuscated"),
                packages: vec!["evil@1.0.0".to_string()],
            },
            TagIssue {
                tag_label: "shell execution",
                severity: Severity::High,
                install_visibility: InstallVisibility::Default,
                selector: Some(":shell"),
                packages: vec![
                    "runner-a@1.0.0".to_string(),
                    "runner-b@1.0.0".to_string(),
                    "runner-c@1.0.0".to_string(),
                ],
            },
            TagIssue {
                tag_label: "network access",
                severity: Severity::Medium,
                install_visibility: InstallVisibility::Default,
                selector: Some(":network"),
                packages: vec![
                    "net-a@1.0.0".to_string(),
                    "net-b@1.0.0".to_string(),
                    "net-c@1.0.0".to_string(),
                    "net-d@1.0.0".to_string(),
                    "net-e@1.0.0".to_string(),
                ],
            },
        ];

        let lines = format_human_security_summary(9, &issues, false);
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
            joined.contains("Security summary · 9 packages · 9 findings"),
            "summary headline missing: {joined}"
        );
        assert!(
            joined.contains("1 Critical")
                && joined.contains("3 High")
                && joined.contains("5 Medium"),
            "severity roll-up missing: {joined}"
        );
        assert!(
            joined.contains("1 obfuscated code") && joined.contains("→ evil@1.0.0"),
            "critical issue detail missing: {joined}"
        );
        assert!(
            !joined.contains("shell execution") && !joined.contains("network access"),
            "normal output must hide High and Medium details: {joined}"
        );
        assert!(
            joined.contains("Run lpm audit for full details."),
            "hint detail missing: {joined}"
        );
        assert!(
            !joined.contains("lpm query"),
            "normal output should use one full-details command: {joined}"
        );
    }

    #[test]
    fn human_security_summary_verbose_output_shows_all_actionable_tiers() {
        let issues = vec![
            TagIssue {
                tag_label: "network access",
                severity: Severity::Medium,
                install_visibility: InstallVisibility::Default,
                selector: Some(":network"),
                packages: vec!["net@3.0.0".to_string()],
            },
            TagIssue {
                tag_label: "lifecycle script",
                severity: Severity::High,
                install_visibility: InstallVisibility::Default,
                selector: Some(":scripts"),
                packages: vec!["risky@2.0.0".to_string()],
            },
        ];

        let lines = format_human_security_summary(2, &issues, true);
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
            joined.contains("network access"),
            "medium-severity issue should stay visible: {joined}"
        );
        assert!(
            joined.contains("lpm query \":network,:scripts\""),
            "verbose output should include exact selectors: {joined}"
        );
    }

    #[test]
    fn human_security_summary_hides_info_only_signals_without_verbose_output() {
        let issues = vec![
            TagIssue {
                tag_label: "environment-variable access",
                severity: Severity::Info,
                install_visibility: InstallVisibility::VerboseOnly,
                selector: Some(":env"),
                packages: vec!["react@19.2.8".to_string()],
            },
            TagIssue {
                tag_label: "URL literals",
                severity: Severity::Info,
                install_visibility: InstallVisibility::VerboseOnly,
                selector: Some(":url-strings"),
                packages: vec!["react@19.2.8".to_string()],
            },
        ];

        assert!(format_human_security_summary(1, &issues, false).is_empty());
    }

    #[test]
    fn human_security_summary_verbose_output_names_metadata_and_uses_matching_selectors() {
        let issues = vec![
            TagIssue {
                tag_label: "environment-variable access",
                severity: Severity::Info,
                install_visibility: InstallVisibility::VerboseOnly,
                selector: Some(":env"),
                packages: vec!["react@19.2.8".to_string()],
            },
            TagIssue {
                tag_label: "URL literals",
                severity: Severity::Info,
                install_visibility: InstallVisibility::VerboseOnly,
                selector: Some(":url-strings"),
                packages: vec!["react@19.2.8".to_string()],
            },
        ];

        let lines = format_human_security_summary(1, &issues, true);
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

        assert!(joined.contains("Behavioral metadata · 1 package · 2 signals"));
        assert!(joined.contains("lpm query \":env,:url-strings\""));
        assert!(!joined.contains(":critical"));
        assert!(!joined.contains("Security summary"));
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
        let mut counts = SummaryCounts::default();
        collect_tags_from_analysis(&analysis, "pkg@1.0.0", &mut counts);
        collect_tags_from_analysis(&analysis, "pkg@1.0.0", &mut counts);

        assert_eq!(counts.behavioral.get(&PseudoClass::Eval).unwrap().len(), 1);
    }

    #[test]
    fn severity_groups_keep_same_coordinates_from_distinct_sources() {
        let npm = SecuritySummaryPackage {
            instance_id: None,
            name: "duplicate".to_string(),
            version: "1.0.0".to_string(),
            source: "registry+https://registry.npmjs.org".to_string(),
            integrity: Some("sha512-source-a".to_string()),
            is_lpm: false,
        };
        let custom = SecuritySummaryPackage {
            instance_id: None,
            name: "duplicate".to_string(),
            version: "1.0.0".to_string(),
            source: "registry+https://registry.example.com".to_string(),
            integrity: Some("sha512-source-b".to_string()),
            is_lpm: false,
        };
        let counts = SummaryCounts {
            behavioral: HashMap::from([(
                PseudoClass::Eval,
                HashSet::from([npm.finding_key(), custom.finding_key()]),
            )]),
            lifecycle_scripts: HashSet::new(),
        };

        let issues = build_severity_groups(&counts);

        assert_eq!(issues[0].packages.len(), 2);
        assert!(
            issues[0]
                .packages
                .iter()
                .any(|package| package.contains("registry.npmjs.org"))
        );
        assert!(
            issues[0]
                .packages
                .iter()
                .any(|package| package.contains("registry.example.com"))
        );
    }

    #[test]
    fn severity_groups_redact_registry_credentials_and_url_components() {
        let package = SecuritySummaryPackage {
            instance_id: None,
            name: "duplicate".to_string(),
            version: "1.0.0".to_string(),
            source: "registry+https://user:password@example.test/private?token=query-secret"
                .to_string(),
            integrity: Some("sha512-source-a".to_string()),
            is_lpm: false,
        };
        let sibling = SecuritySummaryPackage {
            instance_id: None,
            name: "duplicate".to_string(),
            version: "1.0.0".to_string(),
            source: "registry+https://registry.npmjs.org".to_string(),
            integrity: Some("sha512-source-b".to_string()),
            is_lpm: false,
        };
        let counts = SummaryCounts {
            behavioral: HashMap::from([(
                PseudoClass::Eval,
                HashSet::from([package.finding_key(), sibling.finding_key()]),
            )]),
            lifecycle_scripts: HashSet::new(),
        };

        let issues = build_severity_groups(&counts);

        assert_eq!(
            issues[0].packages,
            [
                "duplicate@1.0.0 (registry+https://example.test, sha512-source-a…)",
                "duplicate@1.0.0 (registry+https://registry.npmjs.org, sha512-source-b…)",
            ]
        );
    }

    #[test]
    fn collect_tags_empty_analysis() {
        let analysis = make_analysis(
            SourceTags::default(),
            SupplyChainTags::default(),
            ManifestTags::default(),
        );
        let mut counts = SummaryCounts::default();
        collect_tags_from_analysis(&analysis, "clean@1.0.0", &mut counts);

        assert!(counts.behavioral.is_empty());
        assert!(counts.lifecycle_scripts.is_empty());
    }

    // ── collect_registry_warnings tests ──────────────────────────────

    #[test]
    fn ordinary_install_registry_warnings_ignore_vulnerability_advisories() {
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
        let mut counts = SummaryCounts::default();
        collect_registry_warnings(&ver_meta, "pkg@1.0.0", &mut counts);

        assert!(
            counts.lifecycle_scripts.is_empty(),
            "ordinary install must leave vulnerability advisories to audit-after-install"
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
        let mut counts = SummaryCounts::default();
        collect_registry_warnings(&ver_meta, "pkg@1.0.0", &mut counts);

        for tag in [
            PseudoClass::Eval,
            PseudoClass::Obfuscated,
            PseudoClass::NoLicense,
        ] {
            assert!(counts.behavioral.get(&tag).unwrap().contains("pkg@1.0.0"));
        }
    }

    #[test]
    fn registry_warnings_or_merges_with_client_side() {
        let mut counts = SummaryCounts::default();
        counts.insert_behavioral(PseudoClass::Eval, "pkg@1.0.0");

        let ver_meta = lpm_registry::VersionMetadata {
            behavioral_tags: Some(lpm_registry::BehavioralTags {
                eval: true,
                network: true,
                ..Default::default()
            }),
            ..Default::default()
        };
        collect_registry_warnings(&ver_meta, "pkg@1.0.0", &mut counts);

        assert_eq!(counts.behavioral.get(&PseudoClass::Eval).unwrap().len(), 1);
        assert!(
            counts
                .behavioral
                .get(&PseudoClass::Network)
                .unwrap()
                .contains("pkg@1.0.0")
        );
    }

    #[test]
    fn ordinary_install_registry_warnings_ignore_ai_security_findings() {
        let ver_meta = lpm_registry::VersionMetadata {
            security_findings: Some(vec![lpm_registry::SecurityFinding {
                severity: Some("critical".into()),
                description: Some("suspicious code".into()),
                file: None,
            }]),
            ..Default::default()
        };
        let mut counts = SummaryCounts::default();
        collect_registry_warnings(&ver_meta, "pkg@1.0.0", &mut counts);

        assert!(
            counts.lifecycle_scripts.is_empty(),
            "ordinary install must leave AI security findings to audit-after-install"
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
        let mut counts = SummaryCounts::default();
        collect_registry_warnings(&ver_meta, "pkg@1.0.0", &mut counts);

        assert!(counts.lifecycle_scripts.contains("pkg@1.0.0"));
    }

    #[test]
    fn registry_warnings_empty_metadata() {
        let ver_meta = lpm_registry::VersionMetadata::default();
        let mut counts = SummaryCounts::default();
        collect_registry_warnings(&ver_meta, "pkg@1.0.0", &mut counts);

        assert!(counts.behavioral.is_empty());
        assert!(counts.lifecycle_scripts.is_empty());
    }

    // ── build_severity_groups tests ──────────────────────────────────

    #[test]
    fn severity_groups_critical_first() {
        let mut counts = SummaryCounts::default();
        counts.insert_behavioral(PseudoClass::Eval, "a@1.0.0");
        counts.insert_behavioral(PseudoClass::Obfuscated, "b@1.0.0");
        counts.insert_behavioral(PseudoClass::Fs, "c@1.0.0");

        let issues = build_severity_groups(&counts);

        assert_eq!(issues[0].severity, Severity::Critical); // obfuscated
        assert_eq!(issues[1].severity, Severity::High); // eval
        assert_eq!(issues[2].severity, Severity::Info); // filesystem
    }

    #[test]
    fn severity_groups_empty_counts() {
        let counts = SummaryCounts::default();
        let issues = build_severity_groups(&counts);
        assert!(issues.is_empty());
    }

    #[test]
    fn severity_groups_packages_sorted() {
        let mut counts = SummaryCounts::default();
        counts.insert_behavioral(PseudoClass::Eval, "z-pkg@1.0.0");
        counts.insert_behavioral(PseudoClass::Eval, "a-pkg@1.0.0");
        counts.insert_behavioral(PseudoClass::Eval, "m-pkg@1.0.0");

        let issues = build_severity_groups(&counts);
        assert_eq!(
            issues[0].packages,
            vec!["a-pkg@1.0.0", "m-pkg@1.0.0", "z-pkg@1.0.0"]
        );
    }
}
