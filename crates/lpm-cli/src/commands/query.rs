//! `lpm query` — CSS-like dependency tree inspection.
//!
//! Queries installed packages using a selector syntax that targets
//! behavioral tags, state, and dependency relationships.
//!
//! ## Examples
//!
//! ```bash
//! lpm query ":eval"                   # All packages using eval
//! lpm query ":scripts:not(:built)"    # Unbuilt packages with scripts
//! lpm query ":root > :network"        # Direct deps that access network
//! lpm query ":eval:child-process"     # Packages with eval AND child_process
//! lpm query ":eval,:network"          # Packages with eval OR network
//! lpm query "#express"                # Package by exact name
//! lpm query --count                   # Tag counts grouped by severity
//! lpm query ":eval" --assert-none     # CI gate: exit 1 if any match
//! ```

use crate::output;
use lpm_common::LpmError;
use lpm_registry::RegistryClient;
use lpm_security::behavioral::{self, PackageAnalysis};
use lpm_security::query::{
    self, DepGraph, PackageContext, Severity, count_all_tags, parse_selector,
};
use lpm_store::PackageStore;
use owo_colors::OwoColorize;
use std::collections::{HashMap, HashSet};
use std::path::Path;

/// Lifecycle script phases to check for `has_scripts`.
const LIFECYCLE_SCRIPTS: &[&str] = &["preinstall", "install", "postinstall", "prepare"];

/// Build state marker filename (must match build.rs).
const BUILD_MARKER: &str = ".lpm-built";

#[allow(clippy::too_many_arguments)]
pub async fn run(
    client: &RegistryClient,
    project_dir: &Path,
    selector_str: Option<&str>,
    count_mode: bool,
    json_output: bool,
    verbose: bool,
    assert_none: bool,
    format: &str,
) -> Result<(), LpmError> {
    // Load lockfile
    let lockfile_path = project_dir.join("lpm.lock");
    if !lockfile_path.exists() {
        return Err(LpmError::NotFound(
            "No lpm.lock found. Run `lpm install` first.".into(),
        ));
    }

    let lockfile = lpm_lockfile::Lockfile::read_fast(&lockfile_path)
        .map_err(|e| LpmError::Registry(format!("failed to read lockfile: {e}")))?;

    if lockfile.packages.is_empty() {
        if json_output {
            println!("[]");
        } else {
            output::info("No packages installed.");
        }
        return Ok(());
    }

    let store = PackageStore::default_location()?;

    // Read root package.json for direct dependencies
    let root_dep_names = read_root_dependencies(project_dir);

    // Build analysis + metadata for every package
    let mut analyses: HashMap<String, PackageAnalysis> = HashMap::new();
    let mut has_scripts_map: HashMap<String, bool> = HashMap::new();
    let mut is_built_map: HashMap<String, bool> = HashMap::new();

    let show_progress = !json_output && lockfile.packages.len() > 50;
    let spinner = if show_progress {
        let s = cliclack::spinner();
        s.start(format!("Loading {} packages...", lockfile.packages.len()));
        Some(s)
    } else {
        None
    };

    for (i, pkg) in lockfile.packages.iter().enumerate() {
        if show_progress
            && i % 50 == 0
            && i > 0
            && let Some(ref s) = spinner
        {
            s.start(format!("Analyzing... {}/{}", i, lockfile.packages.len()));
        }

        let pkg_dir = store.package_dir(&pkg.name, &pkg.version);

        // Load behavioral analysis (cached)
        if let Some(analysis) = behavioral::read_cached_analysis(&pkg_dir) {
            analyses.insert(pkg.name.clone(), analysis);
        } else if pkg_dir.exists() {
            // Not cached yet — run analysis now (e.g., package installed by older lpm)
            let analysis = behavioral::analyze_package_cached(&pkg_dir);
            analyses.insert(pkg.name.clone(), analysis);
        }

        // Check for lifecycle scripts
        let has_scripts = check_has_lifecycle_scripts(&pkg_dir);
        has_scripts_map.insert(pkg.name.clone(), has_scripts);

        // Check build state
        let is_built = pkg_dir.join(BUILD_MARKER).exists();
        is_built_map.insert(pkg.name.clone(), is_built);
    }

    if let Some(s) = spinner {
        s.stop(format!("Loaded {} packages", lockfile.packages.len()));
    }

    // Fetch vulnerability state for all packages
    let mut vulnerable_set: HashSet<String> = HashSet::new();
    let deprecated_set: HashSet<String> = HashSet::new();

    // @lpm.dev packages: check registry metadata for server-side vulnerabilities
    let lpm_names: Vec<String> = lockfile
        .packages
        .iter()
        .filter(|p| p.name.starts_with("@lpm.dev/"))
        .map(|p| p.name.clone())
        .collect();

    if !lpm_names.is_empty()
        && let Ok(metadata_map) = client.batch_metadata(&lpm_names).await
    {
        for pkg in &lockfile.packages {
            if !pkg.name.starts_with("@lpm.dev/") {
                continue;
            }
            if let Some(metadata) = metadata_map.get(&pkg.name)
                && let Some(vm) = metadata.version(&pkg.version).or_else(|| metadata.latest())
                && vm.vulnerabilities.as_ref().is_some_and(|v| !v.is_empty())
            {
                vulnerable_set.insert(pkg.name.clone());
            }
        }
    }

    // All packages (npm + @lpm.dev): check OSV database for known vulnerabilities
    let osv_vulns = query_osv_vulnerable_packages(&lockfile.packages).await;
    vulnerable_set.extend(osv_vulns);

    // Build PackageContexts
    let pkg_contexts: Vec<PackageContext<'_>> = lockfile
        .packages
        .iter()
        .map(|p| PackageContext {
            name: &p.name,
            version: &p.version,
            analysis: analyses.get(&p.name),
            has_scripts: has_scripts_map.get(&p.name).copied().unwrap_or(false),
            is_built: is_built_map.get(&p.name).copied().unwrap_or(false),
            is_vulnerable: vulnerable_set.contains(&p.name),
            is_deprecated: deprecated_set.contains(&p.name),
            is_root: false,
        })
        .collect();

    // Count mode — show tag counts grouped by severity
    if count_mode {
        return run_count_mode(&pkg_contexts, json_output);
    }

    // Selector mode — filter packages by selector
    let selector_str = selector_str.ok_or_else(|| {
        LpmError::Registry(
            "No selector provided. Usage: lpm query \":eval\" or lpm query --count".into(),
        )
    })?;

    let selector = parse_selector(selector_str)
        .map_err(|e| LpmError::Registry(format!("Invalid selector: {e}")))?;

    // Build dependency graph for `>` combinators
    let dep_graph = DepGraph::from_lockfile(&lockfile.packages, &root_dep_names);

    // Build all_packages map for combinator matching
    let all_packages: HashMap<&str, PackageContext<'_>> = pkg_contexts
        .iter()
        .map(|p| {
            (
                p.name,
                PackageContext {
                    name: p.name,
                    version: p.version,
                    analysis: p.analysis,
                    has_scripts: p.has_scripts,
                    is_built: p.is_built,
                    is_vulnerable: p.is_vulnerable,
                    is_deprecated: p.is_deprecated,
                    is_root: p.is_root,
                },
            )
        })
        .collect();

    // Match packages
    let matched: Vec<&PackageContext<'_>> = pkg_contexts
        .iter()
        .filter(|pkg| query::matches(&selector, pkg, &dep_graph, &all_packages))
        .collect();

    // Output — Mermaid format
    if format == "mermaid" {
        return output_mermaid(&matched, &lockfile.packages, selector_str);
    }

    // Output — list (default) or JSON
    if json_output {
        let json_results: Vec<serde_json::Value> = matched
            .iter()
            .map(|pkg| {
                let mut obj = serde_json::json!({
                    "name": pkg.name,
                    "version": pkg.version,
                });
                if verbose {
                    if let Some(analysis) = pkg.analysis {
                        obj["analysis"] = serde_json::to_value(analysis).unwrap_or_default();
                    }
                    obj["hasScripts"] = serde_json::json!(pkg.has_scripts);
                    obj["isBuilt"] = serde_json::json!(pkg.is_built);
                }
                obj
            })
            .collect();

        println!(
            "{}",
            serde_json::to_string_pretty(&json_results).unwrap_or_else(|_| "[]".into())
        );
    } else if matched.is_empty() {
        println!(
            "  {} No packages match {}",
            "·".dimmed(),
            selector_str.bold()
        );
    } else {
        println!(
            "  {} {} matching {}",
            "●".green(),
            format!(
                "{} package{}",
                matched.len(),
                if matched.len() == 1 { "" } else { "s" }
            )
            .bold(),
            selector_str.bold()
        );
        println!();

        for pkg in &matched {
            let mut extras = Vec::new();

            if pkg.has_scripts {
                extras.push("scripts".to_string());
            }
            if pkg.is_built {
                extras.push("built".to_string());
            }

            if verbose && let Some(analysis) = pkg.analysis {
                let tags = collect_active_tags(analysis);
                if !tags.is_empty() {
                    extras.push(tags.join(", "));
                }
            }

            let extra_str = if extras.is_empty() {
                String::new()
            } else {
                format!(" {}", format!("({})", extras.join(", ")).dimmed())
            };

            println!("    {}@{}{extra_str}", pkg.name, pkg.version);
        }
    }

    // --assert-none: exit 1 if ANY packages matched (CI gate)
    if assert_none && !matched.is_empty() {
        return Err(LpmError::Registry(format!(
            "assertion failed: {} package{} matched selector '{selector_str}'",
            matched.len(),
            if matched.len() == 1 { "" } else { "s" }
        )));
    }

    Ok(())
}

/// Count mode: show tag counts for all packages, grouped by severity tier.
fn run_count_mode(packages: &[PackageContext<'_>], json_output: bool) -> Result<(), LpmError> {
    let counts = count_all_tags(packages);

    if json_output {
        let mut json_obj = serde_json::Map::new();
        for tc in &counts {
            json_obj.insert(
                tc.pseudo_class
                    .display_name()
                    .trim_start_matches(':')
                    .to_string(),
                serde_json::json!(tc.count),
            );
        }
        json_obj.insert("total".to_string(), serde_json::json!(packages.len()));
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::Value::Object(json_obj))
                .unwrap_or_else(|_| "{}".into())
        );
        return Ok(());
    }

    println!(
        "  {} across {} packages\n",
        "Tag counts".bold(),
        packages.len().to_string().bold()
    );

    // Group by severity
    #[allow(clippy::type_complexity)]
    let tiers: [(Severity, &str, fn(&str) -> String); 4] = [
        (Severity::Critical, "Critical", |s: &str| {
            s.red().bold().to_string()
        }),
        (Severity::High, "High", |s: &str| {
            s.yellow().bold().to_string()
        }),
        (Severity::Medium, "Medium", |s: &str| {
            s.cyan().bold().to_string()
        }),
        (Severity::Info, "Info", |s: &str| s.dimmed().to_string()),
    ];

    for (severity, label, colorize) in &tiers {
        let tier_counts: Vec<_> = counts
            .iter()
            .filter(|tc| tc.pseudo_class.severity() == *severity)
            .collect();

        if tier_counts.is_empty() {
            continue;
        }

        println!("  ● {}", colorize(label));

        // Find max label length for alignment
        let max_label_len = tier_counts
            .iter()
            .map(|tc| tc.pseudo_class.display_name().len())
            .max()
            .unwrap_or(0);

        for tc in &tier_counts {
            let display = tc.pseudo_class.display_name();
            let padding = max_label_len - display.len();
            let count_str = if tc.count > 0 {
                tc.count.to_string().bold().to_string()
            } else {
                "0".dimmed().to_string()
            };
            println!("    {}{:padding$}  {count_str}", display.dimmed(), "",);
        }
        println!();
    }

    Ok(())
}

/// Collect active tag names from a package analysis (for verbose output).
fn collect_active_tags(analysis: &PackageAnalysis) -> Vec<String> {
    let mut tags = Vec::new();

    // Source tags
    if analysis.source.eval {
        tags.push("eval".into());
    }
    if analysis.source.network {
        tags.push("network".into());
    }
    if analysis.source.filesystem {
        tags.push("fs".into());
    }
    if analysis.source.shell {
        tags.push("shell".into());
    }
    if analysis.source.child_process {
        tags.push("child-process".into());
    }
    if analysis.source.native_bindings {
        tags.push("native".into());
    }
    if analysis.source.crypto {
        tags.push("crypto".into());
    }
    if analysis.source.dynamic_require {
        tags.push("dynamic-require".into());
    }
    if analysis.source.environment_vars {
        tags.push("env".into());
    }
    if analysis.source.web_socket {
        tags.push("ws".into());
    }

    // Supply chain tags
    if analysis.supply_chain.obfuscated {
        tags.push("obfuscated".into());
    }
    if analysis.supply_chain.high_entropy_strings {
        tags.push("high-entropy".into());
    }
    if analysis.supply_chain.minified {
        tags.push("minified".into());
    }
    if analysis.supply_chain.telemetry {
        tags.push("telemetry".into());
    }
    if analysis.supply_chain.url_strings {
        tags.push("url-strings".into());
    }
    if analysis.supply_chain.trivial {
        tags.push("trivial".into());
    }
    if analysis.supply_chain.protestware {
        tags.push("protestware".into());
    }

    // Manifest tags
    if analysis.manifest.git_dependency {
        tags.push("git-dep".into());
    }
    if analysis.manifest.http_dependency {
        tags.push("http-dep".into());
    }
    if analysis.manifest.wildcard_dependency {
        tags.push("wildcard-dep".into());
    }
    if analysis.manifest.copyleft_license {
        tags.push("copyleft".into());
    }
    if analysis.manifest.no_license {
        tags.push("no-license".into());
    }

    tags
}

/// Read direct dependencies from the root package.json.
fn read_root_dependencies(project_dir: &Path) -> HashSet<String> {
    let pkg_json_path = project_dir.join("package.json");
    let content = match std::fs::read_to_string(&pkg_json_path) {
        Ok(c) => c,
        Err(_) => return HashSet::new(),
    };
    let parsed: serde_json::Value = match serde_json::from_str(&content) {
        Ok(v) => v,
        Err(_) => return HashSet::new(),
    };

    let mut deps = HashSet::new();

    if let Some(d) = parsed.get("dependencies").and_then(|d| d.as_object()) {
        for key in d.keys() {
            deps.insert(key.clone());
        }
    }
    if let Some(d) = parsed.get("devDependencies").and_then(|d| d.as_object()) {
        for key in d.keys() {
            deps.insert(key.clone());
        }
    }

    deps
}

/// Check if a package has lifecycle scripts by reading its package.json in the store.
fn check_has_lifecycle_scripts(pkg_dir: &Path) -> bool {
    let pkg_json_path = pkg_dir.join("package.json");
    let content = match std::fs::read_to_string(&pkg_json_path) {
        Ok(c) => c,
        Err(_) => return false,
    };
    let parsed: serde_json::Value = match serde_json::from_str(&content) {
        Ok(v) => v,
        Err(_) => return false,
    };

    let scripts = match parsed.get("scripts").and_then(|s| s.as_object()) {
        Some(s) => s,
        None => return false,
    };

    LIFECYCLE_SCRIPTS
        .iter()
        .any(|phase| scripts.contains_key(*phase))
}

/// Output matching packages as a Mermaid dependency subgraph.
fn output_mermaid(
    matched: &[&PackageContext<'_>],
    all_packages: &[lpm_lockfile::LockedPackage],
    selector_str: &str,
) -> Result<(), LpmError> {
    use std::collections::HashSet;

    let matched_names: HashSet<&str> = matched.iter().map(|p| p.name).collect();

    // Build edge list: only edges where at least one end is in the matched set
    let mut edges: Vec<(String, String)> = Vec::new();
    for pkg in all_packages {
        for dep_ref in &pkg.dependencies {
            if let Some(at) = dep_ref.rfind('@') {
                let dep_name = &dep_ref[..at];
                let pkg_in = matched_names.contains(pkg.name.as_str());
                let dep_in = matched_names.contains(dep_name);
                if pkg_in || dep_in {
                    edges.push((pkg.name.clone(), dep_name.to_string()));
                }
            }
        }
    }

    // Sanitize names for Mermaid (replace @, /, . with _)
    let sanitize = |s: &str| -> String { s.replace('@', "").replace(['/', '.'], "_") };

    println!("graph TD");
    println!("    %% lpm query \"{}\"", selector_str);

    // Declare matched nodes with highlight style
    for pkg in matched {
        let id = sanitize(pkg.name);
        println!("    {id}[\"{}@{}\"]", pkg.name, pkg.version);
    }

    // Edges
    for (from, to) in &edges {
        println!("    {} --> {}", sanitize(from), sanitize(to));
    }

    // Style matched nodes
    if !matched.is_empty() {
        let ids: Vec<String> = matched.iter().map(|p| sanitize(p.name)).collect();
        println!("    style {} fill:#f96,stroke:#333", ids.join(","));
    }

    Ok(())
}

/// Query OSV.dev batch endpoint to find which packages have known vulnerabilities.
/// Returns a set of package names that are vulnerable.
/// Gracefully returns empty set on any network/parse failure.
async fn query_osv_vulnerable_packages(
    packages: &[lpm_lockfile::LockedPackage],
) -> HashSet<String> {
    if packages.is_empty() {
        return HashSet::new();
    }

    let client = reqwest::Client::new();

    let queries: Vec<serde_json::Value> = packages
        .iter()
        .map(|p| {
            serde_json::json!({
                "package": { "name": &p.name, "ecosystem": "npm" },
                "version": &p.version,
            })
        })
        .collect();

    let body = serde_json::json!({ "queries": queries });

    let response = match client
        .post("https://api.osv.dev/v1/querybatch")
        .json(&body)
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await
    {
        Ok(r) if r.status().is_success() => r,
        _ => return HashSet::new(),
    };

    #[derive(serde::Deserialize)]
    struct OsvBatchResponse {
        results: Vec<OsvQueryResult>,
    }
    #[derive(serde::Deserialize)]
    struct OsvQueryResult {
        #[serde(default)]
        vulns: Vec<serde_json::Value>,
    }

    let result: OsvBatchResponse = match response.json().await {
        Ok(r) => r,
        Err(_) => return HashSet::new(),
    };

    let mut vulnerable = HashSet::new();
    for (i, query_result) in result.results.into_iter().enumerate() {
        if i >= packages.len() {
            break;
        }
        if !query_result.vulns.is_empty() {
            vulnerable.insert(packages[i].name.clone());
        }
    }

    vulnerable
}

#[cfg(test)]
mod tests {
    use super::*;
    use lpm_security::behavioral::manifest::ManifestTags;
    use lpm_security::behavioral::source::SourceTags;
    use lpm_security::behavioral::supply_chain::SupplyChainTags;
    use lpm_security::behavioral::{AnalysisMeta, PackageAnalysis};

    fn make_analysis(source: SourceTags) -> PackageAnalysis {
        PackageAnalysis {
            version: 2,
            analyzed_at: "2026-04-04T00:00:00Z".into(),
            source,
            supply_chain: SupplyChainTags::default(),
            manifest: ManifestTags::default(),
            meta: AnalysisMeta::default(),
        }
    }

    #[test]
    fn collect_active_tags_from_eval_network() {
        let analysis = make_analysis(SourceTags {
            eval: true,
            network: true,
            ..Default::default()
        });
        let tags = collect_active_tags(&analysis);
        assert!(tags.contains(&"eval".to_string()));
        assert!(tags.contains(&"network".to_string()));
        assert!(!tags.contains(&"shell".to_string()));
    }

    #[test]
    fn collect_active_tags_empty_analysis() {
        let analysis = make_analysis(SourceTags::default());
        let tags = collect_active_tags(&analysis);
        assert!(tags.is_empty());
    }

    #[test]
    fn collect_active_tags_all_source_tags() {
        let analysis = make_analysis(SourceTags {
            eval: true,
            network: true,
            filesystem: true,
            shell: true,
            child_process: true,
            native_bindings: true,
            crypto: true,
            dynamic_require: true,
            environment_vars: true,
            web_socket: true,
        });
        let tags = collect_active_tags(&analysis);
        assert_eq!(tags.len(), 10);
    }

    #[test]
    fn read_root_deps_from_package_json() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("package.json"),
            r#"{"dependencies":{"react":"^18.0.0","lodash":"^4.17.0"},"devDependencies":{"jest":"^29.0.0"}}"#,
        )
        .unwrap();

        let deps = read_root_dependencies(dir.path());
        assert!(deps.contains("react"));
        assert!(deps.contains("lodash"));
        assert!(deps.contains("jest"));
        assert_eq!(deps.len(), 3);
    }

    #[test]
    fn read_root_deps_missing_package_json() {
        let dir = tempfile::tempdir().unwrap();
        let deps = read_root_dependencies(dir.path());
        assert!(deps.is_empty());
    }

    #[test]
    fn check_lifecycle_scripts_detects_postinstall() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("package.json"),
            r#"{"scripts":{"postinstall":"node setup.js","test":"jest"}}"#,
        )
        .unwrap();

        assert!(check_has_lifecycle_scripts(dir.path()));
    }

    #[test]
    fn check_lifecycle_scripts_no_lifecycle() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("package.json"),
            r#"{"scripts":{"test":"jest","start":"node ."}}"#,
        )
        .unwrap();

        assert!(!check_has_lifecycle_scripts(dir.path()));
    }

    #[test]
    fn check_lifecycle_scripts_missing_file() {
        let dir = tempfile::tempdir().unwrap();
        assert!(!check_has_lifecycle_scripts(dir.path()));
    }
}
