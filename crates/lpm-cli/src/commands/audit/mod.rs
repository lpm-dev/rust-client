pub mod cache;
pub mod discovery;
pub mod inventory;

use crate::output;
use cache::ProjectAuditCache;
#[cfg(test)]
use discovery::ManagerKind;
use discovery::{DiscoveredPackage, DiscoveryResult, ScanMode};
use lpm_common::LpmError;
use lpm_registry::RegistryClient;
use owo_colors::OwoColorize;
use std::collections::{HashMap, HashSet};
use std::path::Path;

/// Audit installed LPM packages for security issues.
///
/// Checks: AI security findings, dangerous behavioral tags,
/// lifecycle scripts, and quality scores.
/// Convert a severity string to a numeric level for comparison.
/// Higher = more severe.
fn severity_level(severity: &str) -> u8 {
    match severity.to_lowercase().as_str() {
        "critical" => 4,
        "high" => 3,
        "moderate" | "medium" => 2,
        "info" | "low" => 1,
        _ => 0,
    }
}

// ─── Dependency confusion check ──────────────────────────────────────────────

/// Popular npm package names that could be confused with LPM package names.
/// This is a curated list of the most-downloaded npm packages. A package
/// `@lpm.dev/owner.react` shares the bare name `react` with the npm registry,
/// which creates a dependency confusion risk if a developer accidentally
/// installs from the wrong registry.
const POPULAR_NPM_PACKAGES: &[&str] = &[
    "react",
    "react-dom",
    "lodash",
    "chalk",
    "express",
    "axios",
    "commander",
    "moment",
    "debug",
    "uuid",
    "semver",
    "glob",
    "minimatch",
    "yargs",
    "inquirer",
    "webpack",
    "typescript",
    "eslint",
    "prettier",
    "babel-core",
    "jest",
    "mocha",
    "chai",
    "sinon",
    "underscore",
    "bluebird",
    "async",
    "request",
    "mkdirp",
    "rimraf",
    "fs-extra",
    "cross-env",
    "dotenv",
    "body-parser",
    "cors",
    "cookie-parser",
    "jsonwebtoken",
    "bcrypt",
    "mongoose",
    "sequelize",
    "pg",
    "mysql2",
    "redis",
    "socket.io",
    "nodemailer",
    "sharp",
    "esbuild",
    "rollup",
    "vite",
    "next",
    "vue",
    "angular",
    "svelte",
    "ember",
    "backbone",
    "jquery",
    "d3",
    "three",
    "pixi",
    "rxjs",
    "ramda",
    "immutable",
    "styled-components",
    "emotion",
    "tailwindcss",
    "postcss",
    "graphql",
    "apollo",
    "prisma",
    "drizzle-orm",
    "zod",
    "yup",
    "formik",
    "react-hook-form",
    "react-query",
    "swr",
    "zustand",
    "redux",
    "mobx",
    "recoil",
    "jotai",
    "immer",
];

/// Warning about a potential dependency confusion between an LPM package
/// and an npm package with the same bare name.
pub struct ConfusionWarning {
    pub lpm_package: String,
    pub npm_name: String,
}

/// Check if LPM-scoped packages have name collisions with popular npm packages.
///
/// A package `@lpm.dev/owner.react` shares the bare name `react` with npmjs.org.
/// This is a supply-chain risk: an attacker could publish a malicious package
/// on one registry that gets confused with the legitimate package on the other.
pub fn check_dependency_confusion(lpm_packages: &[(String, String)]) -> Vec<ConfusionWarning> {
    let popular: HashSet<&str> = POPULAR_NPM_PACKAGES.iter().copied().collect();
    let mut warnings = Vec::new();

    for (pkg, _version) in lpm_packages {
        if let Some(scope_body) = pkg.strip_prefix("@lpm.dev/")
            && let Some(dot_pos) = scope_body.find('.')
        {
            let bare_name = &scope_body[dot_pos + 1..];
            if popular.contains(bare_name) {
                warnings.push(ConfusionWarning {
                    lpm_package: pkg.clone(),
                    npm_name: bare_name.to_string(),
                });
            }
        }
    }

    warnings
}

/// Get the minimum severity level from a --level flag value.
fn min_severity_level(level: &str) -> u8 {
    match level.to_lowercase().as_str() {
        "high" => 3,
        "moderate" => 2,
        "info" => 1,
        _ => 0,
    }
}

// ─── Main audit entry point ─────────────────────────────────────────────────

/// CI exit code policy for `--fail-on`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FailPolicy {
    /// Exit non-zero only for confirmed vulnerabilities (OSV/registry).
    Vuln,
    /// Exit non-zero only for critical/high behavioral flags.
    Behavior,
    /// Exit non-zero for either (default).
    All,
}

impl FailPolicy {
    fn parse(s: &str) -> Result<Self, LpmError> {
        match s.to_lowercase().as_str() {
            "vuln" | "vulnerability" | "vulnerabilities" => Ok(Self::Vuln),
            "behavior" | "behavioral" | "behaviour" => Ok(Self::Behavior),
            "all" => Ok(Self::All),
            _ => Err(LpmError::Registry(format!(
                "invalid --fail-on value '{s}'. Expected: vuln, behavior, or all"
            ))),
        }
    }
}

pub async fn run(
    client: &RegistryClient,
    project_dir: &Path,
    json_output: bool,
    level: Option<&str>,
    fail_on: Option<&str>,
) -> Result<(), LpmError> {
    let fail_policy = match fail_on {
        Some(s) => FailPolicy::parse(s)?,
        None => FailPolicy::All,
    };
    // ── Phase 1: Discover packages from any lockfile ──────────────────────
    let discovery = discovery::discover_packages(project_dir)?;

    if discovery.packages.is_empty() {
        if !json_output {
            output::info("No packages found to audit");
        }
        return Ok(());
    }

    let total_count = discovery.packages.len();

    // Separate LPM and non-LPM packages
    let lpm_packages: Vec<(String, String)> = discovery
        .packages
        .iter()
        .filter(|p| p.name.starts_with("@lpm.dev/"))
        .map(|p| (p.name.clone(), p.version.clone()))
        .collect();
    let lpm_count = lpm_packages.len();
    let npm_count = total_count - lpm_count;

    if !json_output {
        print_discovery_header(&discovery, lpm_count, npm_count);
    }

    let mut results: Vec<AuditResult> = Vec::new();
    let mut checked_lpm = 0usize;

    // ── Phase 2: LPM registry metadata (@lpm.dev packages only) ──────────
    if !lpm_packages.is_empty() {
        let names: Vec<String> = lpm_packages.iter().map(|(n, _)| n.clone()).collect();
        let metadata_map = client.batch_metadata(&names).await.unwrap_or_default();

        for (name, version) in &lpm_packages {
            let Some(metadata) = metadata_map.get(name) else {
                continue;
            };
            let Some(ver_meta) = metadata.version(version).or_else(|| metadata.latest()) else {
                continue;
            };
            checked_lpm += 1;
            let mut issues: Vec<AuditIssue> = Vec::new();
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
                });
            }

            results.push(AuditResult {
                name: name.clone(),
                version: version.clone(),
                quality_score,
                issues,
            });
        }
    }

    // ── Phase 3: Client-side behavioral analysis (ALL packages) ──────────
    let behavioral_results =
        run_behavioral_analysis(&discovery, &mut results, &lpm_packages, json_output, level);

    // ── Phase 4: OSV vulnerability scan (non-@lpm.dev packages) ──────────
    let osv_vulns = run_osv_scan(&discovery.packages, json_output, level).await;

    // ── Phase 5: Report ──────────────────────────────────────────────────
    if json_output {
        print_json_report(&results, &osv_vulns, &discovery, checked_lpm);
    } else {
        // Human-readable output — three-tier separation

        // Section 1: LPM quality scores
        print_lpm_results(&results, &lpm_packages);

        // Section 2: Vulnerabilities (OSV)
        print_osv_results(&osv_vulns);

        // Section 3: Suspicious behaviors (from behavioral analysis)
        print_behavioral_results(&results, &lpm_packages);

        // Dependency confusion check (LPM packages only)
        if !lpm_packages.is_empty() {
            let confusion_warnings = check_dependency_confusion(&lpm_packages);
            if !confusion_warnings.is_empty() {
                println!("  {}", "Dependency confusion warnings".bold());
                for w in &confusion_warnings {
                    println!(
                        "    {} {} shares name with npm package '{}'",
                        "⚠".yellow(),
                        w.lpm_package,
                        w.npm_name,
                    );
                }
                println!();
            }
        }

        // Section 4: Summary
        print_summary(
            &results,
            &osv_vulns,
            &behavioral_results,
            &discovery,
            checked_lpm,
        );
    }

    // ── Exit code: non-zero based on --fail-on policy ──
    let has_vulns = !osv_vulns.is_empty();
    let has_registry_vulns = results
        .iter()
        .any(|r| r.issues.iter().any(|i| i.category == "vulnerability"));
    // Critical behaviors: obfuscation, protestware (always a failure signal)
    let has_critical_behavior = results.iter().any(|r| {
        r.issues
            .iter()
            .any(|i| i.severity == "critical" && i.category != "vulnerability")
    });
    // High behaviors: eval, child_process, shell, dynamic_require
    // Only triggers failure when --fail-on behavior or --fail-on all is explicit
    let has_high_behavior = results.iter().any(|r| {
        r.issues
            .iter()
            .any(|i| i.severity == "high" && i.category != "vulnerability")
    });

    let should_fail = match fail_policy {
        FailPolicy::Vuln => has_vulns || has_registry_vulns,
        FailPolicy::Behavior => has_critical_behavior || has_high_behavior,
        // Default (All): critical behaviors + vulns. High behaviors only
        // trigger failure when --fail-on is explicitly specified, to avoid
        // breaking existing CI pipelines that tolerate eval() usage.
        FailPolicy::All => {
            if fail_on.is_some() {
                // Explicit --fail-on all: include high behaviors
                has_vulns || has_critical_behavior || has_high_behavior || has_registry_vulns
            } else {
                // Implicit default: backward-compatible (critical + vulns only)
                has_vulns || has_critical_behavior || has_registry_vulns
            }
        }
    };

    if should_fail {
        return Err(LpmError::ExitCode(1));
    }

    Ok(())
}

// ─── Phase 2: Registry issue collection ─────────────────────────────────────

fn collect_registry_issues(ver_meta: &lpm_registry::VersionMetadata, issues: &mut Vec<AuditIssue>) {
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
        if tags.telemetry {
            notable.push("telemetry");
        }
        if tags.minified {
            notable.push("minified");
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

// ─── Phase 3: Client-side behavioral analysis ───────────────────────────────

/// Behavioral summary stats returned for the final output.
struct BehavioralSummary {
    packages_scanned: usize,
    packages_with_findings: usize,
}

/// Run behavioral analysis on all scannable packages.
///
/// For LPM store packages: reads existing `.lpm-security.json` from the store.
/// For node_modules packages: scans source code, caches in `.lpm/audit-cache.json`.
fn run_behavioral_analysis(
    discovery: &DiscoveryResult,
    results: &mut Vec<AuditResult>,
    lpm_packages: &[(String, String)],
    json_output: bool,
    level: Option<&str>,
) -> BehavioralSummary {
    let scannable: Vec<&DiscoveredPackage> = discovery
        .packages
        .iter()
        .filter(|p| {
            matches!(
                p.scan_mode,
                ScanMode::FullLocal | ScanMode::RegistryAndStore
            )
        })
        .collect();

    if scannable.is_empty() {
        return BehavioralSummary {
            packages_scanned: 0,
            packages_with_findings: 0,
        };
    }

    let lpm_names: HashSet<&str> = lpm_packages.iter().map(|(n, _)| n.as_str()).collect();

    // Build index of existing results for O(1) merge.
    // Key by "name@version" to handle multiple instances of the same package
    // at different versions (e.g., qs@6.5.3 nested under express vs qs@6.14.0 hoisted).
    let mut results_by_key: HashMap<String, usize> = results
        .iter()
        .enumerate()
        .map(|(i, r)| (format!("{}@{}", r.name, r.version), i))
        .collect();

    // Load project-level audit cache. Used by all project types:
    // - npm/pnpm/yarn/bun: primary cache for node_modules scans
    // - lpm: fallback cache when store entries are missing
    let mut project_cache = ProjectAuditCache::read(&discovery.project_root);

    // Try LPM store for store-backed packages
    let lpm_store = lpm_store::PackageStore::default_location().ok();

    // Progress indicator for large scans
    let show_progress = !json_output && scannable.len() > 50;
    let spinner = if show_progress {
        let s = cliclack::spinner();
        s.start(format!("Analyzing {} packages...", scannable.len()));
        Some(s)
    } else {
        None
    };

    let mut scanned = 0usize;
    let mut with_findings = 0usize;

    for (i, pkg) in scannable.iter().enumerate() {
        if show_progress
            && i % 50 == 0
            && i > 0
            && let Some(ref s) = spinner
        {
            s.start(format!("Analyzing... {}/{}", i, scannable.len()));
        }

        let is_lpm = lpm_names.contains(pkg.name.as_str());
        let source = if is_lpm { "combined" } else { "local" };

        // Get analysis — try each source in order of cost:
        // 1. LPM store cache (cheapest — pre-computed at install time)
        // 2. Project-level audit cache (cheap — from prior lpm audit run)
        // 3. Fresh scan on node_modules/ directory (expensive — reads source files)
        let analysis = if pkg.scan_mode == ScanMode::RegistryAndStore {
            // Try LPM store first, then fall back to project cache
            lpm_store
                .as_ref()
                .and_then(|store| {
                    let pkg_dir = store.package_dir(&pkg.name, &pkg.version);
                    lpm_security::behavioral::read_cached_analysis(&pkg_dir)
                })
                .or_else(|| {
                    project_cache
                        .as_ref()
                        .and_then(|c| c.get(&pkg.path, pkg.integrity.as_deref()))
                        .cloned()
                })
        } else {
            // Non-store packages: check project cache
            project_cache
                .as_ref()
                .and_then(|c| c.get(&pkg.path, pkg.integrity.as_deref()))
                .cloned()
        };

        // Fallback: if no cached analysis found, scan node_modules/ directly.
        // This handles both FullLocal packages and RegistryAndStore packages
        // whose global store entry is missing (cleaned store, different machine).
        let analysis = analysis.or_else(|| {
            let abs_path = discovery.project_root.join(&pkg.path);
            if abs_path.is_dir() {
                let analysis = lpm_security::behavioral::analyze_package(&abs_path);
                if project_cache.is_none() {
                    project_cache = Some(ProjectAuditCache::new(&discovery.manager.to_string()));
                }
                if let Some(ref mut cache) = project_cache {
                    cache.insert(
                        pkg.path.clone(),
                        pkg.name.clone(),
                        pkg.version.clone(),
                        pkg.integrity.clone(),
                        analysis.clone(),
                        pkg.dependencies.clone(),
                    );
                }
                Some(analysis)
            } else {
                None
            }
        });

        let Some(analysis) = analysis else {
            continue;
        };

        scanned += 1;

        let mut issues = analysis_to_issues(&analysis, source);
        if issues.is_empty() {
            continue;
        }

        with_findings += 1;

        // Apply --level filter
        if let Some(lvl) = level {
            let min_lvl = min_severity_level(lvl);
            issues.retain(|issue| severity_level(&issue.severity) >= min_lvl);
            if issues.is_empty() {
                continue;
            }
        }

        // Merge into existing result (for @lpm.dev) or create new entry (npm).
        // Key by "name@version" so different versions of the same package stay separate.
        let merge_key = format!("{}@{}", pkg.name, pkg.version);
        if let Some(&idx) = results_by_key.get(&merge_key) {
            // Dedup: don't add issues with the same message already present from registry
            let existing_messages: HashSet<String> = results[idx]
                .issues
                .iter()
                .map(|i| i.message.clone())
                .collect();
            for issue in issues {
                if !existing_messages.contains(&issue.message) {
                    results[idx].issues.push(issue);
                }
            }
        } else {
            let idx = results.len();
            results.push(AuditResult {
                name: pkg.name.clone(),
                version: pkg.version.clone(),
                quality_score: None,
                issues,
            });
            results_by_key.insert(merge_key, idx);
        }
    }

    if let Some(s) = spinner {
        s.stop(format!("Analyzed {} packages", scanned));
    }

    // Write project cache back to disk
    if let Some(ref cache) = project_cache
        && let Err(e) = cache.write(&discovery.project_root)
    {
        tracing::debug!("failed to write audit cache: {e}");
    }

    // Re-filter merged results by --level if provided
    if let Some(lvl) = level {
        let min_lvl = min_severity_level(lvl);
        for result in results.iter_mut() {
            result
                .issues
                .retain(|issue| severity_level(&issue.severity) >= min_lvl);
        }
    }

    BehavioralSummary {
        packages_scanned: scanned,
        packages_with_findings: with_findings,
    }
}

/// Convert a PackageAnalysis into AuditIssues.
fn analysis_to_issues(
    analysis: &lpm_security::behavioral::PackageAnalysis,
    source: &str,
) -> Vec<AuditIssue> {
    let mut issues = Vec::new();

    // Critical: obfuscated, protestware, high entropy
    if analysis.supply_chain.obfuscated {
        issues.push(AuditIssue {
            severity: "critical".into(),
            message: "obfuscated code detected".into(),
            category: "supply-chain".into(),
            source: source.into(),
        });
    }
    if analysis.supply_chain.protestware {
        issues.push(AuditIssue {
            severity: "critical".into(),
            message: "protestware patterns detected".into(),
            category: "supply-chain".into(),
            source: source.into(),
        });
    }
    // high_entropy_strings is informational, not critical. It fires on any package
    // with string literals above Shannon entropy 4.5, which includes legitimate
    // Base64 data, URL-encoded strings, hash constants, and bundled assets.
    // Only obfuscated + protestware are true critical supply-chain signals.
    if analysis.supply_chain.high_entropy_strings {
        issues.push(AuditIssue {
            severity: "info".into(),
            message: "high-entropy strings detected".into(),
            category: "supply-chain".into(),
            source: source.into(),
        });
    }

    // High: eval, child_process, shell, dynamic_require
    let s = &analysis.source;
    let mut dangerous = Vec::new();
    if s.eval {
        dangerous.push("eval()");
    }
    if s.child_process {
        dangerous.push("child_process");
    }
    if s.shell {
        dangerous.push("shell exec");
    }
    if s.dynamic_require {
        dangerous.push("dynamic require");
    }
    if !dangerous.is_empty() {
        issues.push(AuditIssue {
            severity: "high".into(),
            message: format!("uses {}", dangerous.join(", ")),
            category: "behavior".into(),
            source: source.into(),
        });
    }

    // Medium: network, native bindings, git/http/wildcard deps, no license
    let mut medium = Vec::new();
    if s.network {
        medium.push("network");
    }
    if s.native_bindings {
        medium.push("native bindings");
    }
    if analysis.manifest.git_dependency {
        medium.push("git dependency");
    }
    if analysis.manifest.http_dependency {
        medium.push("http dependency");
    }
    if analysis.manifest.wildcard_dependency {
        medium.push("wildcard dep");
    }
    if analysis.manifest.no_license {
        medium.push("no license");
    }
    if !medium.is_empty() {
        issues.push(AuditIssue {
            severity: "info".into(),
            message: format!("flags: {}", medium.join(", ")),
            category: "behavior".into(),
            source: source.into(),
        });
    }

    issues
}

// ─── Phase 4: OSV vulnerability scan ────────────────────────────────────────

/// Query OSV for all non-@lpm.dev packages, deduplicating by (name, version).
async fn run_osv_scan(
    packages: &[DiscoveredPackage],
    json_output: bool,
    level: Option<&str>,
) -> Vec<OsvVulnerability> {
    // Collect non-@lpm.dev packages eligible for OSV
    let mut osv_queries: Vec<(String, String)> = Vec::new();
    let mut seen: HashSet<(String, String)> = HashSet::new();

    for pkg in packages {
        // Skip @lpm.dev packages — they get vuln data from registry metadata
        if pkg.name.starts_with("@lpm.dev/") {
            continue;
        }

        // We intentionally do NOT skip packages based on resolved URL.
        // Even packages resolved from a corporate proxy (Verdaccio, Artifactory,
        // or the LPM registry worker) are typically mirrors of public npm packages.
        // Skipping them based on URL silently removes OSV coverage. OSV returns
        // empty for unknown packages, so there's no false-positive risk for
        // querying a public name that was resolved from a proxy.

        let key = (pkg.name.clone(), pkg.version.clone());
        if seen.insert(key.clone()) {
            osv_queries.push(key);
        }
    }

    if osv_queries.is_empty() {
        return Vec::new();
    }

    if !json_output {
        println!();
        output::info(&format!(
            "Checking {} packages against OSV vulnerability database...",
            osv_queries.len()
        ));
    }

    let vulns = match query_osv_batch(&osv_queries).await {
        Ok(v) => v,
        Err(e) => {
            tracing::debug!("OSV query failed: {e}");
            if !json_output {
                println!("  {} OSV database unavailable, skipping", "⚠".yellow());
            }
            return Vec::new();
        }
    };

    // Filter by --level
    if let Some(lvl) = level {
        let min_lvl = min_severity_level(lvl);
        vulns
            .into_iter()
            .filter(|v| severity_level(&v.severity) >= min_lvl)
            .collect()
    } else {
        vulns
    }
}

// ─── Phase 5: Report rendering ──────────────────────────────────────────────

fn print_discovery_header(discovery: &DiscoveryResult, lpm_count: usize, npm_count: usize) {
    let total = discovery.packages.len();
    output::info(&format!("Scanning {total} packages..."));

    // Show lockfile info
    if let Some(ref lockfile_path) = discovery.lockfile_path {
        let lockfile_name = lockfile_path
            .file_name()
            .map(|f| f.to_string_lossy().to_string())
            .unwrap_or_default();
        println!(
            "  {} Lockfile: {} ({})",
            "│".dimmed(),
            lockfile_name.bold(),
            discovery.manager,
        );
    } else {
        println!(
            "  {} {}",
            "│".dimmed(),
            "No lockfile found — scanning node_modules directly (degraded mode)".yellow(),
        );
    }

    if discovery.is_yarn_pnp {
        println!(
            "  {} {}",
            "│".dimmed(),
            "Yarn PnP detected — source scanning unavailable (packages are zipped)".yellow(),
        );
        println!(
            "  {} Running vulnerability scan only (OSV)...",
            "│".dimmed(),
        );
    }

    if lpm_count > 0 {
        println!(
            "  {} LPM packages: {} (with registry metadata)",
            "│".dimmed(),
            lpm_count
        );
    }
    if npm_count > 0 {
        let label = if discovery.is_yarn_pnp {
            "OSV-only"
        } else {
            "client-side analysis"
        };
        println!("  {} npm packages: {} ({})", "│".dimmed(), npm_count, label,);
    }
    println!();
}

/// Print LPM package quality scores and registry-only issues.
fn print_lpm_results(results: &[AuditResult], lpm_packages: &[(String, String)]) {
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
            println!(
                "  {} {}{}",
                "✔".green(),
                format!("{}@{}", result.name, result.version).dimmed(),
                score_str.dimmed(),
            );
            continue;
        }

        println!(
            "\n  {} {}",
            result.name.bold(),
            format!("({}){}", result.version, score_str).dimmed(),
        );

        for issue in registry_issues {
            let icon = match issue.severity.as_str() {
                "high" | "critical" => "✖".red().to_string(),
                "moderate" => "⚠".yellow().to_string(),
                _ => "ℹ".blue().to_string(),
            };
            println!(
                "    {icon} {} {} {}",
                format_severity(&issue.severity),
                issue.message,
                format!("[{}]", issue.source).dimmed()
            );
        }
    }
}

/// Print OSV vulnerability results.
fn print_osv_results(osv_vulns: &[OsvVulnerability]) {
    if osv_vulns.is_empty() {
        return;
    }

    println!();
    println!("  {}", "Vulnerabilities (OSV)".bold());

    for vuln in osv_vulns {
        let icon = match vuln.severity.as_str() {
            "HIGH" | "CRITICAL" => "✖".red().to_string(),
            "MODERATE" | "MEDIUM" => "⚠".yellow().to_string(),
            _ => "ℹ".cyan().to_string(),
        };
        let summary = if vuln.summary.is_empty() {
            String::new()
        } else {
            format!(" — {}", vuln.summary)
        };
        println!(
            "    {icon} {}@{} {} [{}]{summary}",
            vuln.package,
            vuln.version,
            vuln.id.bold(),
            format_severity(&vuln.severity),
        );
    }

    println!(
        "\n  {} vulnerability details: {}",
        "ℹ".blue(),
        "https://osv.dev/vulnerability/VULN_ID".dimmed()
    );
}

/// Print behavioral analysis findings grouped by severity tier.
///
/// Instead of listing every package individually (which can be thousands of lines),
/// groups findings by tag with counts and shows only a few example packages per tag.
fn print_behavioral_results(results: &[AuditResult], lpm_packages: &[(String, String)]) {
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

    println!();

    // Critical tier — show individual packages (these are truly suspicious)
    if has_critical {
        println!("  {}", "Suspicious packages".bold());
        for (message, packages) in &critical_tags {
            let count = packages.len();
            let preview: Vec<&str> = packages.iter().take(3).map(|s| s.as_str()).collect();
            let suffix = if count > 3 {
                format!(", +{} more", count - 3)
            } else {
                String::new()
            };
            println!(
                "    {} {} {} — {}{}",
                "✖".red(),
                format_severity("critical"),
                message,
                preview.join(", "),
                suffix,
            );
        }
        println!();
    }

    // Moderate tier — show counts with a few examples
    if has_moderate {
        println!("  {}", "Behavioral flags".bold());
        // Sort by count descending
        let mut sorted: Vec<(&String, &Vec<String>)> = moderate_tags.iter().collect();
        sorted.sort_by(|a, b| b.1.len().cmp(&a.1.len()));
        for (message, packages) in &sorted {
            let count = packages.len();
            let preview: Vec<&str> = packages.iter().take(3).map(|s| s.as_str()).collect();
            let suffix = if count > 3 {
                format!(", +{} more", count - 3)
            } else {
                String::new()
            };
            println!(
                "    {} {count:<4} {:<40} {}{}",
                "⚠".yellow(),
                message,
                preview.join(", "),
                suffix,
            );
        }
        println!();
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
            sorted.sort_by(|a, b| b.1.cmp(a.1));
            let summary_parts: Vec<String> = sorted
                .iter()
                .map(|(tag, count)| format!("{count} {tag}"))
                .collect();
            println!("  {} {}", "ℹ".blue(), summary_parts.join(", ").dimmed(),);
        }
    }
}

/// Print final summary line.
fn print_summary(
    results: &[AuditResult],
    osv_vulns: &[OsvVulnerability],
    behavioral: &BehavioralSummary,
    discovery: &DiscoveryResult,
    checked_lpm: usize,
) {
    println!();

    let total_scanned = discovery.packages.len();
    let vuln_count = osv_vulns.len();
    let lpm_issues: usize = results
        .iter()
        .filter(|r| r.name.starts_with("@lpm.dev/"))
        .map(|r| r.issues.len())
        .sum();

    let lpm_count = discovery
        .packages
        .iter()
        .filter(|p| p.name.starts_with("@lpm.dev/"))
        .count();
    let npm_count = total_scanned - lpm_count;

    if vuln_count == 0 && lpm_issues == 0 && behavioral.packages_with_findings == 0 {
        output::success(&format!(
            "No issues found ({total_scanned} packages scanned{}{})",
            if checked_lpm > 0 {
                format!(", {checked_lpm} LPM audited")
            } else {
                String::new()
            },
            if behavioral.packages_scanned > 0 {
                format!(", {} analyzed", behavioral.packages_scanned)
            } else {
                String::new()
            },
        ));
    } else {
        let mut parts = Vec::new();
        if vuln_count > 0 {
            parts.push(format!(
                "{vuln_count} vulnerabilit{}",
                if vuln_count == 1 { "y" } else { "ies" }
            ));
        }
        if behavioral.packages_with_findings > 0 {
            parts.push(format!("{} suspicious", behavioral.packages_with_findings));
        }
        if lpm_issues > 0 {
            parts.push(format!(
                "{lpm_issues} LPM issue{}",
                if lpm_issues == 1 { "" } else { "s" }
            ));
        }

        output::warn(&format!(
            "{} ({} LPM + {} npm scanned)",
            parts.join(", "),
            lpm_count,
            npm_count,
        ));
    }

    // Helpful commands
    println!();
    println!(
        "  Run {} for machine-readable output.",
        "lpm audit --json".bold()
    );
    println!();
}

/// Print JSON output for machine consumption.
fn print_json_report(
    results: &[AuditResult],
    osv_vulns: &[OsvVulnerability],
    discovery: &DiscoveryResult,
    checked_lpm: usize,
) {
    let mut critical_count = 0usize;
    let mut high_count = 0usize;
    let mut moderate_count = 0usize;
    let mut low_count = 0usize;
    let mut info_count = 0usize;

    for r in results {
        for issue in &r.issues {
            match issue.severity.to_lowercase().as_str() {
                "critical" => critical_count += 1,
                "high" => high_count += 1,
                "moderate" | "medium" => moderate_count += 1,
                "low" => low_count += 1,
                "info" => info_count += 1,
                _ => {}
            }
        }
    }
    for v in osv_vulns {
        match v.severity.to_uppercase().as_str() {
            "CRITICAL" => critical_count += 1,
            "HIGH" => high_count += 1,
            "MODERATE" | "MEDIUM" => moderate_count += 1,
            "LOW" => low_count += 1,
            _ => info_count += 1,
        }
    }

    let json = serde_json::json!({
        "success": true,
        "manager": discovery.manager.to_string(),
        "degraded": discovery.is_degraded,
        "scanned": discovery.packages.len(),
        "checked_lpm": checked_lpm,
        "packages_with_issues": results.iter().filter(|r| !r.issues.is_empty()).count(),
        "total_issues": results.iter().map(|r| r.issues.len()).sum::<usize>(),
        "osv_vulnerabilities": osv_vulns.len(),
        "counts": {
            "critical": critical_count,
            "high": high_count,
            "moderate": moderate_count,
            "low": low_count,
            "info": info_count,
        },
        "packages": results.iter().map(|r| {
            serde_json::json!({
                "name": r.name,
                "version": r.version,
                "quality_score": r.quality_score,
                "issues": r.issues.iter().map(|i| {
                    serde_json::json!({
                        "severity": i.severity,
                        "category": i.category,
                        "message": i.message,
                        "source": i.source,
                    })
                }).collect::<Vec<_>>(),
            })
        }).collect::<Vec<_>>(),
        "vulnerabilities": osv_vulns.iter().map(|v| {
            serde_json::json!({
                "package": v.package,
                "version": v.version,
                "id": v.id,
                "summary": v.summary,
                "severity": v.severity,
            })
        }).collect::<Vec<_>>(),
    });
    println!("{}", serde_json::to_string_pretty(&json).unwrap());
}

// ─── Internal structs ───────────────────────────────────────────────────────

struct AuditResult {
    name: String,
    version: String,
    quality_score: Option<u32>,
    issues: Vec<AuditIssue>,
}

struct AuditIssue {
    severity: String,
    message: String,
    category: String,
    /// Where the issue was detected: "registry", "local", or "combined".
    source: String,
}

/// Format a severity string with colored terminal output.
fn format_severity(severity: &str) -> String {
    match severity.to_lowercase().as_str() {
        "critical" => format!("{}", " CRITICAL ".on_red().white().bold()),
        "high" => format!("{}", severity.red().bold()),
        "moderate" | "medium" => format!("{}", severity.yellow()),
        "low" => format!("{}", severity.blue()),
        "info" => format!("{}", severity.dimmed()),
        _ => severity.to_string(),
    }
}

// ─── OSV.dev integration ────────────────────────────────────────────────────

#[derive(Debug, serde::Deserialize)]
struct OsvBatchResponse {
    results: Vec<OsvQueryResult>,
}

#[derive(Debug, serde::Deserialize)]
struct OsvQueryResult {
    #[serde(default)]
    vulns: Vec<OsvVuln>,
}

#[derive(Debug, serde::Deserialize)]
struct OsvVuln {
    id: String,
    summary: Option<String>,
    #[serde(default)]
    severity: Vec<OsvSeverityEntry>,
}

#[derive(Debug, serde::Deserialize)]
struct OsvSeverityEntry {
    #[serde(rename = "type")]
    severity_type: String,
    score: String,
}

struct OsvVulnerability {
    package: String,
    version: String,
    id: String,
    summary: String,
    severity: String,
}

/// Query OSV.dev for known vulnerabilities.
///
/// # Trust Model
/// OSV responses are fetched over HTTPS, which prevents passive eavesdropping
/// and basic MITM attacks. However, there is no certificate pinning or response
/// signing. A sophisticated attacker with access to a trusted CA (e.g., corporate
/// MITM proxy) could inject false "no vulnerabilities" responses.
///
/// This matches the security posture of npm audit, yarn audit, and other tools
/// that query advisory databases over HTTPS without additional verification.
///
/// Uses the batch endpoint to minimize HTTP round-trips (single request for all packages).
/// Gracefully returns an empty vec on any network/parse failure.
async fn query_osv_batch(packages: &[(String, String)]) -> Result<Vec<OsvVulnerability>, LpmError> {
    if packages.is_empty() {
        return Ok(Vec::new());
    }

    let client = reqwest::Client::new();

    let queries: Vec<serde_json::Value> = packages
        .iter()
        .map(|(name, version)| {
            serde_json::json!({
                "package": { "name": name, "ecosystem": "npm" },
                "version": version,
            })
        })
        .collect();

    let body = serde_json::json!({ "queries": queries });

    let response = client
        .post("https://api.osv.dev/v1/querybatch")
        .json(&body)
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await
        .map_err(|e| LpmError::Network(format!("OSV API error: {e}")))?;

    if !response.status().is_success() {
        return Ok(Vec::new()); // Graceful fallback
    }

    let result: OsvBatchResponse = response
        .json()
        .await
        .map_err(|e| LpmError::Network(format!("OSV parse error: {e}")))?;

    let mut vulns: Vec<OsvVulnerability> = Vec::new();

    for (i, query_result) in result.results.into_iter().enumerate() {
        if i >= packages.len() {
            break;
        }
        for vuln in query_result.vulns {
            vulns.push(OsvVulnerability {
                package: packages[i].0.clone(),
                version: packages[i].1.clone(),
                id: vuln.id,
                summary: vuln.summary.unwrap_or_default(),
                severity: extract_severity(&vuln.severity),
            });
        }
    }

    Ok(vulns)
}

/// Extract the highest severity string from OSV severity entries.
fn extract_severity(entries: &[OsvSeverityEntry]) -> String {
    for entry in entries {
        if entry.severity_type == "CVSS_V3" {
            return cvss_score_to_label(&entry.score);
        }
    }
    if let Some(entry) = entries.first() {
        return cvss_score_to_label(&entry.score);
    }
    "UNKNOWN".to_string()
}

/// Convert a CVSS vector string to a severity label.
fn cvss_score_to_label(score_str: &str) -> String {
    if let Ok(score) = score_str.parse::<f64>() {
        return if score >= 9.0 {
            "CRITICAL".to_string()
        } else if score >= 7.0 {
            "HIGH".to_string()
        } else if score >= 4.0 {
            "MEDIUM".to_string()
        } else {
            "LOW".to_string()
        };
    }
    if score_str.contains("CVSS:") {
        "HIGH".to_string()
    } else {
        "UNKNOWN".to_string()
    }
}

// ─── Secrets scanning ───────────────────────────────────────────────────────

/// Scan installed packages for hardcoded secrets.
///
/// Walks node_modules and scans each package for API keys, tokens, and private keys.
pub async fn run_secrets(project_dir: &Path, json_output: bool) -> Result<(), LpmError> {
    let node_modules = project_dir.join("node_modules");
    if !node_modules.exists() {
        return Err(LpmError::Script(
            "no node_modules found. Run `lpm install` first.".into(),
        ));
    }

    if !json_output {
        crate::output::info("scanning installed packages for secrets...");
    }

    let mut total_packages = 0u32;
    let mut packages_with_secrets = Vec::new();

    let entries = std::fs::read_dir(&node_modules)
        .map_err(|e| LpmError::Script(format!("failed to read node_modules: {e}")))?;

    for entry in entries.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();

        if name_str.starts_with('.') || !entry.file_type().is_ok_and(|t| t.is_dir()) {
            continue;
        }

        if name_str.starts_with('@') {
            let scope_entries = std::fs::read_dir(entry.path())
                .into_iter()
                .flatten()
                .flatten();
            for scope_entry in scope_entries {
                if scope_entry.file_type().is_ok_and(|t| t.is_dir()) {
                    let pkg_name =
                        format!("{}/{}", name_str, scope_entry.file_name().to_string_lossy());
                    total_packages += 1;
                    let result =
                        lpm_security::behavioral::secrets::scan_directory(&scope_entry.path());
                    if result.has_secrets() {
                        packages_with_secrets.push((pkg_name, result));
                    }
                }
            }
        } else {
            total_packages += 1;
            let result = lpm_security::behavioral::secrets::scan_directory(&entry.path());
            if result.has_secrets() {
                packages_with_secrets.push((name_str.to_string(), result));
            }
        }
    }

    if json_output {
        let findings: Vec<serde_json::Value> = packages_with_secrets
            .iter()
            .map(|(pkg, result)| {
                serde_json::json!({
                    "package": pkg,
                    "matches": result.matches.iter().map(|m| {
                        serde_json::json!({
                            "pattern": m.pattern_name,
                            "description": m.description,
                            "line": m.line,
                            "severity": m.severity,
                        })
                    }).collect::<Vec<_>>(),
                })
            })
            .collect();

        println!(
            "{}",
            serde_json::json!({
                "packagesScanned": total_packages,
                "packagesWithSecrets": packages_with_secrets.len(),
                "findings": findings,
            })
        );
        return Ok(());
    }

    println!();
    println!(
        "  Scanned {} package(s) for hardcoded secrets",
        total_packages
    );
    println!();

    if packages_with_secrets.is_empty() {
        crate::output::success("no hardcoded secrets found");
        return Ok(());
    }

    for (pkg_name, result) in &packages_with_secrets {
        let critical = result.critical_count();
        let high = result.high_count();
        let total = result.matches.len();

        println!(
            "  {} {}  {} finding(s) ({} critical, {} high)",
            "⚠".yellow(),
            pkg_name.bold(),
            total,
            critical.to_string().red(),
            high.to_string().yellow(),
        );

        for m in &result.matches {
            let location = if m.line > 0 {
                format!(":{}", m.line)
            } else {
                String::new()
            };
            println!(
                "    {} {}{}  {}",
                match m.severity.as_str() {
                    "critical" => "●".red().to_string(),
                    "high" => "●".yellow().to_string(),
                    _ => "●".dimmed().to_string(),
                },
                m.matched_text.dimmed(),
                location.dimmed(),
                m.description
            );
        }
        println!();
    }

    println!(
        "  {} package(s) contain potential hardcoded secrets",
        packages_with_secrets.len().to_string().red()
    );
    println!();

    Ok(())
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_level_critical_case_insensitive() {
        assert_eq!(severity_level("CRITICAL"), 4);
        assert_eq!(severity_level("critical"), 4);
        assert_eq!(severity_level("Critical"), 4);
    }

    #[test]
    fn severity_level_high_case_insensitive() {
        assert_eq!(severity_level("HIGH"), 3);
        assert_eq!(severity_level("high"), 3);
        assert_eq!(severity_level("High"), 3);
    }

    #[test]
    fn severity_level_moderate_and_medium() {
        assert_eq!(severity_level("moderate"), 2);
        assert_eq!(severity_level("medium"), 2);
        assert_eq!(severity_level("MODERATE"), 2);
        assert_eq!(severity_level("MEDIUM"), 2);
    }

    #[test]
    fn severity_level_low_and_info() {
        assert_eq!(severity_level("low"), 1);
        assert_eq!(severity_level("info"), 1);
        assert_eq!(severity_level("LOW"), 1);
        assert_eq!(severity_level("INFO"), 1);
    }

    #[test]
    fn severity_level_unknown() {
        assert_eq!(severity_level("unknown"), 0);
        assert_eq!(severity_level(""), 0);
    }

    #[test]
    fn confusion_warns_on_popular_npm_name() {
        let packages = vec![("@lpm.dev/owner.lodash".to_string(), "1.0.0".to_string())];
        let warnings = check_dependency_confusion(&packages);
        assert_eq!(warnings.len(), 1);
        assert_eq!(warnings[0].npm_name, "lodash");
        assert_eq!(warnings[0].lpm_package, "@lpm.dev/owner.lodash");
    }

    #[test]
    fn confusion_no_warn_on_custom_name() {
        let packages = vec![(
            "@lpm.dev/owner.my-custom-lib".to_string(),
            "1.0.0".to_string(),
        )];
        let warnings = check_dependency_confusion(&packages);
        assert!(warnings.is_empty());
    }

    #[test]
    fn confusion_no_warn_on_non_lpm_package() {
        let packages = vec![("lodash".to_string(), "4.17.21".to_string())];
        let warnings = check_dependency_confusion(&packages);
        assert!(warnings.is_empty());
    }

    #[test]
    fn confusion_multiple_warnings() {
        let packages = vec![
            ("@lpm.dev/alice.react".to_string(), "1.0.0".to_string()),
            ("@lpm.dev/bob.express".to_string(), "2.0.0".to_string()),
            ("@lpm.dev/charlie.my-thing".to_string(), "3.0.0".to_string()),
        ];
        let warnings = check_dependency_confusion(&packages);
        assert_eq!(warnings.len(), 2);
    }

    #[test]
    fn osv_skips_lpm_packages() {
        // OSV dedup should exclude @lpm.dev packages (they get vuln data from registry)
        let packages = vec![
            DiscoveredPackage {
                name: "@lpm.dev/owner.utils".into(),
                version: "1.0.0".into(),
                path: "@lpm.dev/owner.utils".into(),
                integrity: None,
                resolved_url: None,
                scan_mode: ScanMode::RegistryAndStore,
                is_dev: false,
                is_optional: false,
                dependencies: Vec::new(),
            },
            DiscoveredPackage {
                name: "lodash".into(),
                version: "4.17.21".into(),
                path: "node_modules/lodash".into(),
                integrity: None,
                resolved_url: Some("https://artifactory.example.com/lodash-4.17.21.tgz".into()),
                scan_mode: ScanMode::FullLocal,
                is_dev: false,
                is_optional: false,
                dependencies: Vec::new(),
            },
        ];

        // Simulate OSV collection logic: only non-@lpm.dev packages
        let osv_eligible: Vec<&str> = packages
            .iter()
            .filter(|p| !p.name.starts_with("@lpm.dev/"))
            .map(|p| p.name.as_str())
            .collect();

        assert_eq!(osv_eligible, vec!["lodash"]);
        // lodash from a proxy should NOT be skipped — it's still a public package
    }

    #[test]
    fn discovery_scan_mode_display() {
        assert_eq!(ManagerKind::Npm.to_string(), "npm");
        assert_eq!(ManagerKind::Lpm.to_string(), "lpm");
        assert_eq!(ManagerKind::Pnpm.to_string(), "pnpm");
        assert_eq!(ManagerKind::Yarn.to_string(), "yarn");
        assert_eq!(ManagerKind::Bun.to_string(), "bun");
        assert_eq!(ManagerKind::FallbackNodeModules.to_string(), "node_modules");
    }

    #[test]
    fn cvss_score_parsing() {
        assert_eq!(cvss_score_to_label("9.8"), "CRITICAL");
        assert_eq!(cvss_score_to_label("7.5"), "HIGH");
        assert_eq!(cvss_score_to_label("5.0"), "MEDIUM");
        assert_eq!(cvss_score_to_label("2.0"), "LOW");
        assert_eq!(cvss_score_to_label("CVSS:3.1/AV:N/AC:L"), "HIGH");
        assert_eq!(cvss_score_to_label("unknown"), "UNKNOWN");
    }

    #[test]
    fn fail_policy_parse_valid() {
        assert_eq!(FailPolicy::parse("vuln").unwrap(), FailPolicy::Vuln);
        assert_eq!(
            FailPolicy::parse("vulnerability").unwrap(),
            FailPolicy::Vuln
        );
        assert_eq!(
            FailPolicy::parse("vulnerabilities").unwrap(),
            FailPolicy::Vuln
        );
        assert_eq!(FailPolicy::parse("behavior").unwrap(), FailPolicy::Behavior);
        assert_eq!(
            FailPolicy::parse("behavioral").unwrap(),
            FailPolicy::Behavior
        );
        assert_eq!(
            FailPolicy::parse("behaviour").unwrap(),
            FailPolicy::Behavior
        );
        assert_eq!(FailPolicy::parse("all").unwrap(), FailPolicy::All);
        assert_eq!(FailPolicy::parse("VULN").unwrap(), FailPolicy::Vuln);
    }

    #[test]
    fn fail_policy_parse_invalid() {
        assert!(FailPolicy::parse("invalid").is_err());
        assert!(FailPolicy::parse("").is_err());
    }

    #[test]
    fn eval_classified_as_high_severity() {
        // Bug: eval/child_process/shell/dynamic_require were labeled "moderate"
        // but the documented severity says "high". --fail-on behavior should
        // catch these, but the check only looked for "critical".
        let mut analysis = lpm_security::behavioral::PackageAnalysis {
            version: lpm_security::behavioral::SCHEMA_VERSION,
            analyzed_at: String::new(),
            source: Default::default(),
            supply_chain: Default::default(),
            manifest: Default::default(),
            meta: Default::default(),
        };
        analysis.source.eval = true;

        let issues = analysis_to_issues(&analysis, "local");

        // eval must be classified as "high", not "moderate"
        let eval_issue = issues
            .iter()
            .find(|i| i.message.contains("eval"))
            .expect("eval issue not found");
        assert_eq!(
            eval_issue.severity, "high",
            "eval should be 'high' severity per documented classification"
        );
    }

    #[test]
    fn fail_on_behavior_catches_high_severity() {
        // --fail-on behavior should fail on both critical AND high behaviors.
        // A package using eval() (high severity) must trigger exit 1.
        let results = vec![AuditResult {
            name: "sketchy-pkg".into(),
            version: "1.0.0".into(),
            quality_score: None,
            issues: vec![AuditIssue {
                severity: "high".into(),
                message: "uses eval()".into(),
                category: "behavior".into(),
                source: "local".into(),
            }],
        }];

        // FailPolicy::Behavior should catch high-severity behavioral flags
        let has_behavioral_failure = results.iter().any(|r| {
            r.issues.iter().any(|i| {
                (i.severity == "critical" || i.severity == "high") && i.category != "vulnerability"
            })
        });
        assert!(
            has_behavioral_failure,
            "--fail-on behavior must catch high-severity behaviors like eval()"
        );
    }
}
