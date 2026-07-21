pub mod cache;
pub mod discovery;
pub mod inventory;

mod behavior;
mod fix;
mod install_summary;
mod osv;
mod policy;
mod registry;
mod report;
mod secrets;
mod signatures;
mod types;

#[cfg(test)]
mod tests;

use std::collections::HashSet;
use std::path::Path;

use lpm_common::LpmError;
use lpm_common::color::Painted;
use lpm_registry::RegistryClient;

use crate::install_ui;

use behavior::run_behavioral_analysis;
use discovery::ScanMode;
use osv::run_osv_scan;
use policy::FailPolicy;
use registry::collect_registry_issues;
use report::{
    print_behavioral_results, print_discovery_summary, print_json_report, print_lpm_results,
    print_osv_results, print_osv_status, print_summary,
};
use types::{AuditIssue, AuditResult};

pub use fix::run_fix;
pub(crate) use install_summary::run_install_summary;
pub(crate) use policy::AuditLevel;
pub use secrets::run_secrets;
pub use signatures::run_signatures;
pub use types::AuditCounts;

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

#[derive(Debug, clap::Subcommand)]
pub enum AuditCmd {
    /// Update vulnerable direct dependencies to patched versions.
    Fix {
        /// Show the fixes that would be applied without changing files.
        #[arg(long)]
        dry_run: bool,
    },
    /// Verify npm registry package signatures for installed packages.
    Signatures,
}

pub async fn run(
    client: &RegistryClient,
    project_dir: &Path,
    json_output: bool,
    level: Option<AuditLevel>,
    fail_on: Option<&str>,
) -> Result<(), LpmError> {
    let fail_policy = match fail_on {
        Some(s) => FailPolicy::parse(s)?,
        None => FailPolicy::All,
    };
    // ── Discover packages from any lockfile ──────────────────────
    //
    // Discovery only reads the project's lockfile — no LPM-store
    // touch — so it runs unlocked. The store-touching slice is
    // [`run_behavioral_analysis`] below, and only when at least one
    // discovered package has `ScanMode::RegistryAndStore`.
    let discovery = discovery::discover_packages(project_dir)?;

    if discovery.packages.is_empty() {
        if json_output {
            print_json_report(&[], &[], None, &discovery, 0);
        } else {
            install_ui::warn("No packages found to audit");
        }
        return Ok(());
    }

    // Separate LPM and non-LPM packages
    let lpm_packages: Vec<(String, String)> = discovery
        .packages
        .iter()
        .filter(|p| p.name.starts_with("@lpm.dev/"))
        .map(|p| (p.name.clone(), p.version.clone()))
        .collect();

    let mut results: Vec<AuditResult> = Vec::new();
    let mut checked_lpm = 0usize;

    // ── LPM registry metadata (@lpm.dev packages only) ──────────
    if !lpm_packages.is_empty() {
        let names: Vec<String> = lpm_packages.iter().map(|(n, _)| n.clone()).collect();
        let metadata_map = client.batch_metadata(&names).await.map_err(|error| {
            LpmError::Registry(format!(
                "LPM registry metadata lookup failed during audit: {error}"
            ))
        })?;

        for (name, version) in &lpm_packages {
            let metadata = metadata_map.get(name).ok_or_else(|| {
                LpmError::Registry(format!(
                    "LPM registry returned no metadata for installed package {name}@{version}"
                ))
            })?;
            let ver_meta = metadata.version(version).ok_or_else(|| {
                LpmError::Registry(format!(
                    "LPM registry metadata omitted installed version {name}@{version}"
                ))
            })?;
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

    // ── Client-side behavioral analysis (ALL packages) ──────────
    //
    // Only `RegistryAndStore` packages (i.e., LPM store-backed packages)
    // touch `~/.lpm/store/`. If none are present — pure npm / pnpm /
    // yarn / bun project — we skip the store lock entirely. Otherwise
    // we hold the shared store lock for the duration of the scan so
    // it can't race a concurrent `lpm cache prune --apply` / `lpm store clean`.
    let needs_store_lock = discovery
        .packages
        .iter()
        .any(|p| matches!(p.scan_mode, ScanMode::RegistryAndStore));

    let behavioral_results = if needs_store_lock {
        let lock_path = lpm_common::LpmRoot::from_env()?.store_lock();
        let mut summary = None;
        lpm_common::with_shared_lock(lock_path, || {
            summary = Some(run_behavioral_analysis(
                &discovery,
                &mut results,
                &lpm_packages,
                json_output,
                level,
            ));
            Ok(())
        })?;
        summary.expect("set inside the closure body")
    } else {
        run_behavioral_analysis(&discovery, &mut results, &lpm_packages, json_output, level)
    };

    // ── OSV vulnerability scan (non-@lpm.dev packages) ──────────
    let osv_outcome = run_osv_scan(&discovery.packages, json_output, level).await;
    let osv_vulns = osv_outcome.vulns;
    let osv_degraded_reason = osv_outcome.degraded_reason;

    // ── Report ──────────────────────────────────────────────────
    if json_output {
        print_json_report(
            &results,
            &osv_vulns,
            osv_degraded_reason.as_deref(),
            &discovery,
            checked_lpm,
        );
    } else {
        // Human-readable output — three-tier separation
        print_discovery_summary(&discovery);
        print_osv_status(osv_degraded_reason.as_deref());

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
                eprintln!();
                eprintln!("  {}", install_ui::section("Dependency confusion warnings"));
                for w in &confusion_warnings {
                    eprintln!(
                        "  {} {} shares name with npm package {}",
                        "!".yellow(),
                        install_ui::yellow(&w.lpm_package),
                        install_ui::cyan(&w.npm_name),
                    );
                }
            }
        }

        // Section 4: Summary
        print_summary(
            &results,
            &osv_vulns,
            &behavioral_results,
            &discovery,
            checked_lpm,
            osv_degraded_reason.is_some(),
        );
    }

    if osv_degraded_reason.is_some() {
        return Err(LpmError::ExitCode(1));
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
        FailPolicy::Secrets => false,
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
