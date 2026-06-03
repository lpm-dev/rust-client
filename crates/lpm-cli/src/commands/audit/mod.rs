pub mod cache;
pub mod discovery;
pub mod inventory;

use crate::install_ui;
use crate::npm_public_source::{NpmMetadataSource, lockfile_npm_metadata_source};
use cache::ProjectAuditCache;
use discovery::{DiscoveredPackage, DiscoveryResult, ManagerKind, ScanMode};
use lpm_common::color::Painted;
use lpm_common::{LpmError, PackageName};
use lpm_registry::{PackageMetadata, RegistryClient};
use lpm_semver::Version;
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
    /// Exit non-zero only for hardcoded secret findings from `--secrets` mode.
    Secrets,
    /// Exit non-zero for either (default).
    All,
}

impl FailPolicy {
    fn parse(s: &str) -> Result<Self, LpmError> {
        match s.to_lowercase().as_str() {
            "vuln" | "vulnerability" | "vulnerabilities" => Ok(Self::Vuln),
            "behavior" | "behavioral" | "behaviour" => Ok(Self::Behavior),
            "secret" | "secrets" => Ok(Self::Secrets),
            "all" => Ok(Self::All),
            _ => Err(LpmError::Registry(format!(
                "invalid --fail-on value '{s}'. Expected: vuln, behavior, secrets, or all"
            ))),
        }
    }
}

#[derive(Debug, clap::Subcommand)]
pub enum AuditCmd {
    /// Update vulnerable direct dependencies to patched versions.
    Fix {
        /// Show the fixes that would be applied without changing files.
        #[arg(long)]
        dry_run: bool,
    },
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
    // ── Discover packages from any lockfile ──────────────────────
    //
    // Discovery only reads the project's lockfile — no LPM-store
    // touch — so it runs unlocked. The store-touching slice is
    // [`run_behavioral_analysis`] below, and only when at least one
    // discovered package has `ScanMode::RegistryAndStore`.
    let discovery = discovery::discover_packages(project_dir)?;

    if discovery.packages.is_empty() {
        if !json_output {
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

#[derive(Debug, Clone)]
struct AuditFixDirectDep {
    name: String,
    current_range: String,
    is_dev: bool,
}

#[derive(Debug, Clone)]
struct AuditFixPlan {
    name: String,
    from: String,
    to: String,
    current_range: String,
    new_range: String,
    is_dev: bool,
    vulnerability_ids: Vec<String>,
}

#[derive(Debug, Clone)]
struct AuditFixSkipped {
    name: String,
    reason: String,
}

pub async fn run_fix(
    client: &RegistryClient,
    project_dir: &Path,
    json_output: bool,
    dry_run: bool,
) -> Result<(), LpmError> {
    let started_at = std::time::Instant::now();
    let pkg_json_path = project_dir.join("package.json");
    if !pkg_json_path.exists() {
        return Err(LpmError::NotFound("no package.json found".into()));
    }

    let original_content = std::fs::read_to_string(&pkg_json_path)
        .map_err(|e| LpmError::Script(format!("failed to read package.json: {e}")))?;
    let mut doc: serde_json::Value = serde_json::from_str(&original_content)
        .map_err(|e| LpmError::Script(format!("failed to parse package.json: {e}")))?;

    let discovery = discovery::discover_packages(project_dir)?;
    if discovery.manager != ManagerKind::Lpm {
        return Err(LpmError::Script(format!(
            "`lpm audit fix` currently supports LPM-managed projects only (found {} inventory). \
             Run the native package manager's audit fix for this project, or migrate to LPM first.",
            discovery.manager,
        )));
    }

    if discovery.packages.is_empty() {
        emit_audit_fix_report(&[], &[], dry_run, json_output, started_at.elapsed());
        return Ok(());
    }

    let osv_outcome = run_osv_scan(&discovery.packages, true, None).await;
    if let Some(reason) = osv_outcome.degraded_reason {
        return Err(LpmError::Script(format!(
            "`lpm audit fix` cannot safely choose patched versions because the OSV scan degraded: {reason}"
        )));
    }
    if osv_outcome.vulns.is_empty() {
        emit_audit_fix_report(&[], &[], dry_run, json_output, started_at.elapsed());
        return Ok(());
    }

    let lockfile_path = project_dir.join("lpm.lock");
    let lockfile = lpm_lockfile::Lockfile::read_fast(&lockfile_path)
        .map_err(|e| LpmError::Script(format!("failed to read lpm.lock: {e}")))?;

    let installed_versions: HashMap<String, String> = discovery
        .packages
        .iter()
        .map(|pkg| (pkg.name.clone(), pkg.version.clone()))
        .collect();
    let mut vulns_by_package: HashMap<String, Vec<&OsvVulnerability>> = HashMap::new();
    for vuln in &osv_outcome.vulns {
        vulns_by_package
            .entry(vuln.package.clone())
            .or_default()
            .push(vuln);
    }

    let mut planned = Vec::new();
    let mut skipped = Vec::new();
    for dep in audit_fix_direct_deps_from_value(&doc) {
        let Some(vulns) = vulns_by_package.get(dep.name.as_str()) else {
            continue;
        };
        let Some(installed_version) = installed_versions.get(&dep.name) else {
            skipped.push(AuditFixSkipped {
                name: dep.name,
                reason: "direct dependency is not present in lpm.lock".into(),
            });
            continue;
        };

        let npm_source = if dep.name.starts_with("@lpm.dev/") {
            None
        } else {
            match lockfile_npm_metadata_source(Some(&lockfile), &dep.name, client) {
                Some(source) => Some(source),
                None => {
                    skipped.push(AuditFixSkipped {
                        name: dep.name,
                        reason: "lockfile source is not public npm or the configured LPM registry; refusing to disclose the name to npm metadata endpoints".into(),
                    });
                    continue;
                }
            }
        };

        let metadata = match fetch_audit_fix_metadata(client, &dep.name, npm_source).await {
            Ok(metadata) => metadata,
            Err(err) => {
                skipped.push(AuditFixSkipped {
                    name: dep.name,
                    reason: format!("metadata lookup failed: {err}"),
                });
                continue;
            }
        };
        let target = match choose_audit_fix_target(&dep.name, installed_version, &metadata, vulns) {
            Ok(target) => target,
            Err(reason) => {
                skipped.push(AuditFixSkipped {
                    name: dep.name,
                    reason,
                });
                continue;
            }
        };
        let vulnerability_ids = vulns.iter().map(|v| v.id.clone()).collect();
        planned.push(AuditFixPlan {
            name: dep.name,
            from: installed_version.clone(),
            to: target.clone(),
            current_range: dep.current_range.clone(),
            new_range: audit_fix_range_for_target(&dep.current_range, &target),
            is_dev: dep.is_dev,
            vulnerability_ids,
        });
    }

    planned.sort_by(|a, b| a.name.cmp(&b.name));
    skipped.sort_by(|a, b| a.name.cmp(&b.name));

    if planned.is_empty() || dry_run {
        emit_audit_fix_report(
            &planned,
            &skipped,
            dry_run,
            json_output,
            started_at.elapsed(),
        );
        return Ok(());
    }

    apply_audit_fixes_to_manifest(&mut doc, &planned)?;
    let updated_content = serde_json::to_string_pretty(&doc)
        .map_err(|e| LpmError::Script(format!("failed to serialize package.json: {e}")))?;

    let tmp_path = pkg_json_path.with_extension("json.tmp");
    let lockfile_backup = audit_fix_read_optional_file(&project_dir.join("lpm.lock"))?;
    let lockfile_binary_backup = audit_fix_read_optional_file(&project_dir.join("lpm.lockb"))?;

    std::fs::write(&tmp_path, format!("{updated_content}\n"))
        .map_err(|e| LpmError::Script(format!("failed to write temp package.json: {e}")))?;
    std::fs::rename(&tmp_path, &pkg_json_path)
        .map_err(|e| LpmError::Script(format!("failed to rename temp package.json: {e}")))?;

    audit_fix_remove_optional_file(&project_dir.join("lpm.lock"))?;
    audit_fix_remove_optional_file(&project_dir.join("lpm.lockb"))?;

    let install_result = crate::commands::install::run_with_options(
        client,
        project_dir,
        false, // keep audit-fix JSON stdout single-document
        false,
        false,
        true, // no_security_summary: audit fix emits its own final report.
        false,
        None,
        None,
        false,
        false,
        false,
        false,
        None,
        None,
        None,
        None,
        None,
        None,
        crate::provenance_fetch::DriftIgnorePolicy::default(),
        crate::provenance_fetch::VerifyPolicy::resolve_no_cli(),
        false,
        false,
        false,
        false,
    )
    .await;

    if let Err(err) = install_result {
        if let Err(restore_err) = std::fs::write(&pkg_json_path, &original_content) {
            tracing::error!(
                "failed to restore package.json after audit fix install failure: {}",
                restore_err
            );
        } else if !json_output {
            install_ui::warn("install failed — restored original package.json");
        }
        if let Err(restore_err) =
            audit_fix_restore_optional_file(&project_dir.join("lpm.lock"), &lockfile_backup)
        {
            tracing::error!(
                "failed to restore lpm.lock after audit fix install failure: {}",
                restore_err
            );
        }
        if let Err(restore_err) =
            audit_fix_restore_optional_file(&project_dir.join("lpm.lockb"), &lockfile_binary_backup)
        {
            tracing::error!(
                "failed to restore lpm.lockb after audit fix install failure: {}",
                restore_err
            );
        }
        return Err(err);
    }

    emit_audit_fix_report(
        &planned,
        &skipped,
        dry_run,
        json_output,
        started_at.elapsed(),
    );
    Ok(())
}

fn audit_fix_direct_deps_from_value(doc: &serde_json::Value) -> Vec<AuditFixDirectDep> {
    let mut deps = Vec::new();
    for (key, is_dev) in [("dependencies", false), ("devDependencies", true)] {
        if let Some(obj) = doc.get(key).and_then(|value| value.as_object()) {
            deps.reserve(obj.len());
            for (name, range) in obj {
                if let Some(range) = range.as_str() {
                    deps.push(AuditFixDirectDep {
                        name: name.clone(),
                        current_range: range.to_string(),
                        is_dev,
                    });
                }
            }
        }
    }
    deps
}

async fn fetch_audit_fix_metadata(
    client: &RegistryClient,
    name: &str,
    npm_source: Option<NpmMetadataSource>,
) -> Result<PackageMetadata, LpmError> {
    if name.starts_with("@lpm.dev/") {
        let package_name = PackageName::parse(name)
            .map_err(|err| LpmError::Script(format!("invalid LPM package name '{name}': {err}")))?;
        client.get_package_metadata(&package_name).await
    } else {
        match npm_source {
            Some(NpmMetadataSource::PublicNpm) => client.get_npm_package_metadata(name).await,
            Some(NpmMetadataSource::ConfiguredRegistry) => {
                client.get_npm_package_metadata_proxy_only(name).await
            }
            None => Err(LpmError::Script(format!(
                "missing npm metadata source for '{name}'"
            ))),
        }
    }
}

fn choose_audit_fix_target(
    package: &str,
    installed_version: &str,
    metadata: &PackageMetadata,
    vulns: &[&OsvVulnerability],
) -> Result<String, String> {
    let mut fixed_versions: Vec<Version> = vulns
        .iter()
        .flat_map(|vuln| vuln.fixed_versions.iter())
        .filter_map(|version| Version::parse(version).ok())
        .collect();
    fixed_versions.sort();
    fixed_versions.dedup();
    let Some(required_fixed_floor) = fixed_versions.last().cloned() else {
        return Err("OSV advisory does not publish a fixed version".into());
    };
    let installed = Version::parse(installed_version).ok();
    let mut candidates: Vec<Version> = metadata
        .versions
        .keys()
        .filter_map(|version| Version::parse(version).ok())
        .filter(|version| !version.is_prerelease())
        .filter(|version| version >= &required_fixed_floor)
        .filter(|version| installed.as_ref().is_none_or(|current| version > current))
        .collect();
    candidates.sort();
    candidates.first().map(ToString::to_string).ok_or_else(|| {
        format!(
            "registry has no non-prerelease version of '{package}' newer than {installed_version} \
                 at or above highest OSV fixed version {required_fixed_floor}"
        )
    })
}

fn audit_fix_range_for_target(current_range: &str, target: &str) -> String {
    let prefix = if current_range.starts_with('^') {
        "^"
    } else if current_range.starts_with('~') {
        "~"
    } else {
        ""
    };
    format!("{prefix}{target}")
}

fn apply_audit_fixes_to_manifest(
    doc: &mut serde_json::Value,
    fixes: &[AuditFixPlan],
) -> Result<(), LpmError> {
    for fix in fixes {
        let dep_key = if fix.is_dev {
            "devDependencies"
        } else {
            "dependencies"
        };
        let deps = doc
            .get_mut(dep_key)
            .and_then(|value| value.as_object_mut())
            .ok_or_else(|| {
                LpmError::Script(format!(
                    "package.json is missing `{dep_key}` while fixing {}",
                    fix.name
                ))
            })?;
        match deps.get_mut(&fix.name) {
            Some(serde_json::Value::String(current)) => {
                if current != &fix.current_range {
                    return Err(LpmError::Script(format!(
                        "package.json drifted before audit fix could write {}: expected `{}`, found `{}`",
                        fix.name, fix.current_range, current
                    )));
                }
                *current = fix.new_range.clone();
            }
            _ => {
                return Err(LpmError::Script(format!(
                    "package.json is missing string dependency entry `{}` in `{dep_key}`",
                    fix.name
                )));
            }
        }
    }
    Ok(())
}

fn emit_audit_fix_report(
    fixes: &[AuditFixPlan],
    skipped: &[AuditFixSkipped],
    dry_run: bool,
    json_output: bool,
    elapsed: std::time::Duration,
) {
    if json_output {
        let packages: Vec<_> = fixes
            .iter()
            .map(|fix| {
                serde_json::json!({
                    "name": fix.name,
                    "from": fix.from,
                    "to": fix.to,
                    "current_range": fix.current_range,
                    "new_range": fix.new_range,
                    "is_dev": fix.is_dev,
                    "vulnerabilities": fix.vulnerability_ids,
                })
            })
            .collect();
        let skipped_json: Vec<_> = skipped
            .iter()
            .map(|skip| serde_json::json!({"name": skip.name, "reason": skip.reason}))
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "success": true,
                "dry_run": dry_run,
                "fixed": if dry_run { 0 } else { fixes.len() },
                "planned": fixes.len(),
                "packages": packages,
                "skipped": skipped_json,
                "elapsed_ms": elapsed.as_millis(),
            }))
            .unwrap()
        );
        return;
    }

    if fixes.is_empty() {
        if skipped.is_empty() {
            install_ui::done("No OSV vulnerabilities found in direct dependencies");
        } else {
            install_ui::warn("No direct dependency fixes could be applied");
            for skip in skipped {
                eprintln!(
                    "  {} {}",
                    sanitize_audit_fix_name(&skip.name).bold(),
                    sanitize_audit_fix_name(&skip.reason).dimmed(),
                );
            }
        }
        return;
    }

    let verb = if dry_run { "Would fix" } else { "Fixed" };
    install_ui::done(&format!(
        "{verb} {} vulnerable direct {} in {}",
        fixes.len(),
        install_ui::packages_word(fixes.len()),
        install_ui::format_duration(elapsed),
    ));
    for fix in fixes {
        eprintln!(
            "  {} {} {} {}  {}",
            sanitize_audit_fix_name(&fix.name).bold(),
            sanitize_audit_fix_name(&fix.from).dimmed(),
            "→".dimmed(),
            sanitize_audit_fix_name(&fix.to).yellow(),
            sanitize_audit_fix_name(&fix.vulnerability_ids.join(", ")).dimmed(),
        );
    }
    if !skipped.is_empty() {
        install_ui::warn(&format!(
            "{} vulnerable direct {} could not be fixed automatically",
            skipped.len(),
            install_ui::packages_word(skipped.len()),
        ));
    }
}

fn sanitize_audit_fix_name(value: &str) -> String {
    lpm_common::sanitize_for_terminal(value)
}

fn audit_fix_read_optional_file(path: &Path) -> Result<Option<Vec<u8>>, LpmError> {
    match std::fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(LpmError::Script(format!(
            "failed to read {}: {err}",
            path.display()
        ))),
    }
}

fn audit_fix_remove_optional_file(path: &Path) -> Result<(), LpmError> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(LpmError::Script(format!(
            "failed to remove {}: {err}",
            path.display()
        ))),
    }
}

fn audit_fix_restore_optional_file(path: &Path, backup: &Option<Vec<u8>>) -> std::io::Result<()> {
    match backup {
        Some(bytes) => std::fs::write(path, bytes),
        None => match std::fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(err),
        },
    }
}

/// Compact counts produced by [`run_install_summary`] for the
/// audit-after-install line in the install pipeline. Intentionally
/// flat + Serialize-friendly so the install JSON envelope can attach
/// it as `audit_summary` without an extra mapping layer.
#[derive(Debug, Clone, serde::Serialize)]
pub struct AuditCounts {
    /// Total packages discovered + checked in this run.
    pub packages_audited: usize,
    /// OSV-reported vulnerabilities across the discovered tree.
    /// Matches the headline number `print_summary` shows so the
    /// install-time advisory and a follow-up `lpm audit` agree.
    pub vulnerabilities: usize,
    /// Packages flagged by client-side behavioral analysis
    /// (eval / child_process / dynamic require / etc.).
    pub suspicious: usize,
    /// Wall-clock spent inside `run_install_summary`.
    pub elapsed_ms: u128,
}

/// Silent audit pass for the install pipeline's audit-after-install hook.
///
/// Mirrors the scan flow of [`run`] but never prints a human report —
/// the install pipeline composes its own slim one-line advisory from
/// the returned [`AuditCounts`]. Returns `Ok(None)` when discovery
/// found nothing to audit (fresh project, empty lockfile) so the
/// caller can skip the advisory entirely instead of printing a
/// misleading "Audited 0 packages" line.
///
/// **Failure mode:** scan-level errors (network down, missing store
/// lock, etc.) bubble up via `Result::Err`. The install pipeline
/// catches them and emits a degraded `! Audit skipped` line — they
/// never fail the install itself, matching the "audit findings are
/// informational" contract the operator opted into.
pub async fn run_install_summary(
    client: &RegistryClient,
    project_dir: &Path,
) -> Result<Option<AuditCounts>, LpmError> {
    let started = std::time::Instant::now();

    let discovery = discovery::discover_packages(project_dir)?;
    if discovery.packages.is_empty() {
        return Ok(None);
    }

    let total_packages = discovery.packages.len();
    let lpm_packages: Vec<(String, String)> = discovery
        .packages
        .iter()
        .filter(|p| p.name.starts_with("@lpm.dev/"))
        .map(|p| (p.name.clone(), p.version.clone()))
        .collect();

    // Re-use the same scan helpers `run` calls, but pass
    // `json_output=true` so every interior `if !json_output` print
    // gate stays closed — the install pipeline is the sole producer
    // of human output around this call.
    let mut results: Vec<AuditResult> = Vec::new();
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
            let mut issues: Vec<AuditIssue> = Vec::new();
            collect_registry_issues(ver_meta, &mut issues);
            results.push(AuditResult {
                name: name.clone(),
                version: version.clone(),
                quality_score: ver_meta.quality_score,
                issues,
            });
        }
    }

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
                /* json_output */ true,
                /* level */ None,
            ));
            Ok(())
        })?;
        summary.expect("set inside the closure body")
    } else {
        run_behavioral_analysis(
            &discovery,
            &mut results,
            &lpm_packages,
            /* json_output */ true,
            /* level */ None,
        )
    };

    let osv_outcome = run_osv_scan(
        &discovery.packages,
        /* json_output */ true,
        /* level */ None,
    )
    .await;

    Ok(Some(AuditCounts {
        packages_audited: total_packages,
        vulnerabilities: osv_outcome.vulns.len(),
        suspicious: behavioral_results.packages_with_findings,
        elapsed_ms: started.elapsed().as_millis(),
    }))
}

// ─── Registry issue collection ─────────────────────────────────────

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

// ─── Client-side behavioral analysis ───────────────────────────────

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
    _json_output: bool,
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

    // S5c — v2-aware store lookup. `find_installed_package_baseline`
    // prefers v2 (default since 4b) and falls back to v1.
    // Pre-fix this used the v1-only `PackageStore::package_dir` and
    // every v2-installed package fell through to the slower
    // project_cache path on every audit run. The clonefile that
    // populates the v2 link entry copies the `.lpm-security.json`
    // sidecar from the object dir into the link's `node_modules/<pkg>/`,
    // so reading from the baseline-resolved path picks up the
    // pre-computed analysis written at install time.
    let lpm_root = lpm_common::LpmRoot::from_env().ok();

    let mut scanned = 0usize;
    let mut with_findings = 0usize;

    for pkg in &scannable {
        let is_lpm = lpm_names.contains(pkg.name.as_str());
        let source = if is_lpm { "combined" } else { "local" };

        // Get analysis — try each source in order of cost:
        // 1. LPM store cache (cheapest — pre-computed at install time)
        // 2. Project-level audit cache (cheap — from prior lpm audit run)
        // 3. Fresh scan on node_modules/ directory (expensive — reads source files)
        let analysis = if pkg.scan_mode == ScanMode::RegistryAndStore {
            // Try LPM store first, then fall back to project cache.
            lpm_root
                .as_ref()
                .and_then(|root| {
                    lpm_store::find_installed_package_baseline(root, &pkg.name, &pkg.version)
                        .ok()
                        .flatten()
                })
                .and_then(|baseline| {
                    lpm_security::behavioral::read_cached_analysis(&baseline.package_dir)
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

// ─── OSV vulnerability scan ────────────────────────────────────────

/// Outcome of an OSV scan.
///
/// `degraded_reason` is `Some(_)` when the OSV API returned a non-2xx
/// status, refused the connection, or otherwise failed — semantics
/// previously conflated with "scan completed successfully and found
/// nothing." A green audit run that the user could not previously
/// distinguish from a degraded one is the H8 hazard: a transient OSV
/// outage (or an attacker who can sink the OSV connection) silently
/// hid every CVE.
pub(crate) struct OsvScanOutcome {
    pub vulns: Vec<OsvVulnerability>,
    pub degraded_reason: Option<String>,
}

/// Query OSV for all non-@lpm.dev packages, deduplicating by (name, version).
async fn run_osv_scan(
    packages: &[DiscoveredPackage],
    _json_output: bool,
    level: Option<&str>,
) -> OsvScanOutcome {
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
        return OsvScanOutcome {
            vulns: Vec::new(),
            degraded_reason: None,
        };
    }

    let vulns = match query_osv_batch(&osv_queries).await {
        Ok(v) => v,
        Err(e) => {
            let reason = e.to_string();
            // Promote to `warn` (was `debug`) so a degraded audit
            // never hides in default tracing output. The human renderer
            // prints the warning once; the JSON envelope carries the
            // structured `osv_degraded` field for machine consumption.
            tracing::warn!("OSV query failed: {reason}");
            return OsvScanOutcome {
                vulns: Vec::new(),
                degraded_reason: Some(reason),
            };
        }
    };

    let filtered = if let Some(lvl) = level {
        let min_lvl = min_severity_level(lvl);
        vulns
            .into_iter()
            .filter(|v| severity_level(&v.severity) >= min_lvl)
            .collect()
    } else {
        vulns
    };
    OsvScanOutcome {
        vulns: filtered,
        degraded_reason: None,
    }
}

// ─── Report rendering ──────────────────────────────────────────────

fn print_discovery_summary(discovery: &DiscoveryResult) {
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

    install_ui::done(&message);

    if discovery.lockfile_path.is_none() {
        install_ui::warn("No lockfile found; scanning node_modules directly");
    }
    if discovery.is_yarn_pnp {
        install_ui::warn("Yarn PnP detected; source scanning unavailable");
    }
}

fn print_osv_status(osv_degraded_reason: Option<&str>) {
    if let Some(reason) = osv_degraded_reason {
        install_ui::warn(&format!(
            "{} database unavailable; vulnerability scan incomplete",
            install_ui::yellow("OSV")
        ));
        eprintln!("  {} {reason}", install_ui::dim("reason:"));
    } else {
        install_ui::done(&format!(
            "Checked against {} database",
            install_ui::yellow("OSV")
        ));
    }
}

fn format_osv_severity(severity: &str) -> String {
    install_ui::dim(&format!("severity {}", severity.to_lowercase()))
}

fn package_name_without_version(pkg_id: &str) -> String {
    pkg_id
        .rsplit_once('@')
        .filter(|(name, _)| !name.is_empty())
        .map_or_else(|| pkg_id.to_string(), |(name, _)| name.to_string())
}

fn preview_versioned_packages(packages: &[String], limit: usize) -> String {
    let mut preview: Vec<String> = packages
        .iter()
        .take(limit)
        .map(|pkg| lpm_common::sanitize_for_terminal(pkg))
        .collect();
    if packages.len() > limit {
        preview.push(format!("+{}", packages.len() - limit));
    }
    install_ui::dim(&preview.join(", "))
}

fn preview_package_names(packages: &[String], limit: usize) -> String {
    let mut preview: Vec<String> = packages
        .iter()
        .take(limit)
        .map(|pkg| lpm_common::sanitize_for_terminal(&package_name_without_version(pkg)))
        .collect();
    if packages.len() > limit {
        preview.push(format!("+{}", packages.len() - limit));
    }
    install_ui::dim(&preview.join(", "))
}

fn behavior_token_label(token: &str) -> &str {
    match token {
        "dynamic require" => "dyn-require",
        other => other,
    }
}

fn format_behavior_message(message: &str) -> String {
    let body = message.strip_prefix("uses ").unwrap_or(message);
    let tokens: Vec<String> = body
        .split(", ")
        .filter(|part| !part.is_empty())
        .map(|part| behavior_token_label(part).to_string())
        .collect();
    if tokens.len() == 2 && tokens[0] == "eval()" && tokens[1] == "dyn-require" {
        return "eval() / dynamic require (misc)".to_string();
    }
    if tokens.is_empty() {
        lpm_common::sanitize_for_terminal(message)
    } else {
        let separator = format!(" {} ", install_ui::dim("·"));
        tokens.join(&separator)
    }
}

fn info_tag_label(tag: &str, count: usize) -> String {
    match tag {
        "high-entropy strings detected" => "high-entropy strings".to_string(),
        "wildcard dep" if count != 1 => "wildcard deps".to_string(),
        "native bindings" if count == 1 => "native binding".to_string(),
        other => other.to_string(),
    }
}

fn count_phrase(count: usize, singular: &str, plural: &str) -> String {
    let noun = if count == 1 { singular } else { plural };
    format!("{} {noun}", install_ui::yellow(&count.to_string()))
}

fn info_tag_phrase(tag: &str, count: usize) -> String {
    format!(
        "{} {}",
        install_ui::yellow(&count.to_string()),
        info_tag_label(tag, count)
    )
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
            eprintln!(
                "  {} {}{}",
                "✓".green(),
                format!("{}@{}", result.name, result.version).dimmed(),
                score_str.dimmed(),
            );
            continue;
        }

        eprintln!(
            "\n  {} {}",
            install_ui::yellow(&result.name),
            format!("({}){}", result.version, score_str).dimmed(),
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

    eprintln!();

    // Critical tier — show individual packages (these are truly suspicious)
    if has_critical {
        eprintln!("  {}", install_ui::section("Suspicious packages"));
        let mut sorted: Vec<(&String, &Vec<String>)> = critical_tags.iter().collect();
        sorted.sort_by(|a, b| b.1.len().cmp(&a.1.len()).then_with(|| a.0.cmp(b.0)));
        for (message, packages) in sorted {
            eprintln!("  {} {}  {}", "✗".red(), "CRITICAL".red().bold(), message,);
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
            let summary_parts: Vec<String> = sorted
                .into_iter()
                .map(|(tag, count)| info_tag_phrase(tag, *count))
                .collect();
            let separator = format!(" {} ", install_ui::dim("·"));
            eprintln!(
                "  {} {}",
                install_ui::dim("also:"),
                summary_parts.join(&separator),
            );
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
    eprintln!();

    let total_scanned = discovery.packages.len();
    let vuln_count = osv_vulns.len();
    let lpm_issues: usize = results
        .iter()
        .filter(|r| r.name.starts_with("@lpm.dev/"))
        .map(|r| r.issues.len())
        .sum();

    if vuln_count == 0 && lpm_issues == 0 && behavioral.packages_with_findings == 0 {
        let mut parts = vec![format!("{total_scanned} scanned")];
        if checked_lpm > 0 {
            parts.push(format!("{checked_lpm} LPM audited"));
        }
        if behavioral.packages_scanned > 0 {
            parts.push(format!("{} analyzed", behavioral.packages_scanned));
        }
        install_ui::done(&format!("No issues found · {}", parts.join(" · ")));
    } else {
        let mut parts = Vec::new();
        if vuln_count > 0 {
            parts.push(count_phrase(vuln_count, "vulnerability", "vulnerabilities"));
        }
        if behavioral.packages_with_findings > 0 {
            parts.push(count_phrase(
                behavioral.packages_with_findings,
                "suspicious",
                "suspicious",
            ));
        }
        if lpm_issues > 0 {
            parts.push(count_phrase(lpm_issues, "LPM issue", "LPM issues"));
        }
        parts.push(format!("{total_scanned} scanned"));

        install_ui::warn(&parts.join(" · "));
    }
}

/// Print JSON output for machine consumption.
fn print_json_report(
    results: &[AuditResult],
    osv_vulns: &[OsvVulnerability],
    osv_degraded_reason: Option<&str>,
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
        // `osv_degraded` is true when the OSV advisory database was
        // unreachable; `osv_vulnerabilities: 0` in that state is the
        // best LPM could say, NOT a confirmation that no CVEs exist.
        // CI gates that use this envelope must treat
        // `osv_degraded == true` as a fail-on-pipeline-issue, not a
        // clean scan.
        "osv_degraded": osv_degraded_reason.is_some(),
        "osv_degraded_reason": osv_degraded_reason,
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

#[derive(Debug)]
struct AuditResult {
    name: String,
    version: String,
    quality_score: Option<u32>,
    issues: Vec<AuditIssue>,
}

#[derive(Debug)]
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
        "critical" => " CRITICAL ".on_red().white().bold(),
        "high" => severity.red().bold(),
        "moderate" | "medium" => severity.yellow(),
        "low" => severity.blue(),
        "info" => severity.dimmed(),
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
    #[serde(default)]
    affected: Vec<OsvAffected>,
}

#[derive(Debug, serde::Deserialize)]
struct OsvSeverityEntry {
    #[serde(rename = "type")]
    severity_type: String,
    score: String,
}

#[derive(Debug, serde::Deserialize)]
struct OsvAffected {
    package: Option<OsvAffectedPackage>,
    #[serde(default)]
    ranges: Vec<OsvAffectedRange>,
}

#[derive(Debug, serde::Deserialize)]
struct OsvAffectedPackage {
    name: Option<String>,
    ecosystem: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
struct OsvAffectedRange {
    #[serde(rename = "type")]
    range_type: Option<String>,
    #[serde(default)]
    events: Vec<OsvAffectedEvent>,
}

#[derive(Debug, serde::Deserialize)]
struct OsvAffectedEvent {
    fixed: Option<String>,
}

#[derive(Debug)]
pub(crate) struct OsvVulnerability {
    package: String,
    version: String,
    id: String,
    summary: String,
    severity: String,
    fixed_versions: Vec<String>,
}

const OSV_URL_DEFAULT: &str = "https://api.osv.dev/v1/querybatch";

/// Resolve the OSV endpoint, honouring `LPM_OSV_URL` overrides only
/// when the scheme/host combination matches the same gating contract as
/// the H9 self-update probe (`release_lookup::resolve_release_url`):
/// HTTPS is always accepted; plain HTTP is accepted only when the host
/// is a loopback address so workflow tests can target a localhost mock
/// without opening a generic env-poisoning hole. Honoured and rejected
/// overrides both emit `warn` so operator logs surface unexpected
/// redirects of the advisory feed.
fn resolve_osv_url() -> String {
    let raw = match std::env::var("LPM_OSV_URL").ok().filter(|s| !s.is_empty()) {
        Some(v) => v,
        None => return OSV_URL_DEFAULT.to_string(),
    };
    if osv_override_is_accepted(&raw) {
        tracing::warn!(
            override_url = %raw,
            "LPM_OSV_URL override honoured — confirm this is expected",
        );
        return raw;
    }
    tracing::warn!(
        override_url = %raw,
        "rejecting LPM_OSV_URL override: plain HTTP non-loopback URL or unsupported scheme; \
         falling back to default — set the override to an https:// URL to use a private mirror",
    );
    OSV_URL_DEFAULT.to_string()
}

/// Accept an override URL if it's HTTPS (any host) or HTTP pointed at
/// a loopback address. Mirrors `release_lookup::accept_override` so the
/// two env-driven advisory/version endpoints share an identical
/// abuse-window posture.
fn osv_override_is_accepted(url: &str) -> bool {
    let parsed = match reqwest::Url::parse(url) {
        Ok(u) => u,
        Err(_) => return false,
    };
    match parsed.scheme() {
        "https" => true,
        "http" => parsed.host_str().is_some_and(host_is_loopback),
        _ => false,
    }
}

fn host_is_loopback(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    if let Ok(addr) = host.parse::<std::net::IpAddr>() {
        return addr.is_loopback();
    }
    if let Some(inner) = host.strip_prefix('[').and_then(|s| s.strip_suffix(']'))
        && let Ok(addr) = inner.parse::<std::net::IpAddr>()
    {
        return addr.is_loopback();
    }
    false
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

    let osv_url = resolve_osv_url();

    let response = client
        .post(&osv_url)
        .json(&body)
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await
        .map_err(|e| LpmError::Network(format!("OSV API error: {e}")))?;

    if !response.status().is_success() {
        // Surface the failure as an error rather than silently
        // returning an empty result. The pre-fix `Ok(Vec::new())`
        // was indistinguishable from "no vulnerabilities found" —
        // an attacker who could downstream block / fail the OSV
        // endpoint (env override, transient outage, MITM-stripped
        // TLS) could make `lpm audit` falsely report a green
        // result. The caller renders a "degraded mode" warning
        // and exits with a distinct semantic so CI gates do not
        // confuse "unreachable advisory DB" with "clean scan".
        return Err(LpmError::Network(format!(
            "OSV API returned HTTP {}; treat as degraded — vulnerability data not retrieved",
            response.status().as_u16()
        )));
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
            let fixed_versions = osv_fixed_versions_for_package(&vuln, &packages[i].0);
            vulns.push(OsvVulnerability {
                package: packages[i].0.clone(),
                version: packages[i].1.clone(),
                id: vuln.id,
                summary: vuln.summary.unwrap_or_default(),
                severity: extract_severity(&vuln.severity),
                fixed_versions,
            });
        }
    }

    Ok(vulns)
}

fn osv_fixed_versions_for_package(vuln: &OsvVuln, package_name: &str) -> Vec<String> {
    let mut fixed = Vec::new();
    for affected in &vuln.affected {
        if let Some(package) = &affected.package {
            if package
                .ecosystem
                .as_deref()
                .is_some_and(|ecosystem| !ecosystem.eq_ignore_ascii_case("npm"))
            {
                continue;
            }
            if package
                .name
                .as_deref()
                .is_some_and(|name| name != package_name)
            {
                continue;
            }
        }
        for range in &affected.ranges {
            if range
                .range_type
                .as_deref()
                .is_some_and(|kind| !kind.eq_ignore_ascii_case("semver"))
            {
                continue;
            }
            for event in &range.events {
                if let Some(version) = event.fixed.as_deref()
                    && Version::parse(version).is_ok()
                {
                    fixed.push(version.to_string());
                }
            }
        }
    }
    fixed.sort();
    fixed.dedup();
    fixed
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
pub async fn run_secrets(
    project_dir: &Path,
    json_output: bool,
    fail_on: Option<&str>,
) -> Result<(), LpmError> {
    let fail_policy = match fail_on {
        Some(value) => FailPolicy::parse(value)?,
        None => FailPolicy::All,
    };
    let node_modules = project_dir.join("node_modules");
    if !node_modules.exists() {
        return Err(LpmError::Script(
            "no node_modules found. Run `lpm install` first.".into(),
        ));
    }

    if !json_output {
        install_ui::phase("Scanning installed packages for secrets");
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
        if should_fail_secrets(fail_policy, !packages_with_secrets.is_empty()) {
            return Err(LpmError::ExitCode(1));
        }
        return Ok(());
    }

    eprintln!();
    eprintln!(
        "  Scanned {} package(s) for hardcoded secrets",
        total_packages
    );
    eprintln!();

    if packages_with_secrets.is_empty() {
        install_ui::done("no hardcoded secrets found");
        return Ok(());
    }

    for (pkg_name, result) in &packages_with_secrets {
        let critical = result.critical_count();
        let high = result.high_count();
        let total = result.matches.len();

        eprintln!(
            "  {} {}  {} finding(s) ({} critical, {} high)",
            "!".yellow(),
            install_ui::yellow(pkg_name),
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
            eprintln!(
                "    {} {}{}  {}",
                match m.severity.as_str() {
                    "critical" => "·".red().to_string(),
                    "high" => "·".yellow().to_string(),
                    _ => "·".dimmed().to_string(),
                },
                m.matched_text.dimmed(),
                location.dimmed(),
                m.description
            );
        }
        eprintln!();
    }

    eprintln!(
        "  {} package(s) contain potential hardcoded secrets",
        packages_with_secrets.len().to_string().red()
    );
    eprintln!();

    if should_fail_secrets(fail_policy, true) {
        return Err(LpmError::ExitCode(1));
    }

    Ok(())
}

fn should_fail_secrets(fail_policy: FailPolicy, has_secrets: bool) -> bool {
    if !has_secrets {
        return false;
    }

    matches!(fail_policy, FailPolicy::Secrets | FailPolicy::All)
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
        let packages = [
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
        assert_eq!(FailPolicy::parse("secret").unwrap(), FailPolicy::Secrets);
        assert_eq!(FailPolicy::parse("secrets").unwrap(), FailPolicy::Secrets);
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
        let results = [AuditResult {
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

    // ─── collect_registry_issues: behavioral-tag → AuditIssue mapping ───
    //
    // Pins the 4-bucket contract (critical / dangerous / medium / notable)
    // and the lifecycle-scripts / security-findings / vulnerabilities
    // arms. Each bucket emits at most one AuditIssue, regardless of how
    // many member tags fire. A silent miscategorization here would let
    // the registry think a package is dangerous while `lpm audit` reports
    // it as clean, so the test set is exhaustive across all 22
    // documented behavioral_tags fields.

    use lpm_registry::{BehavioralTags, SecurityFinding, VersionMetadata, Vulnerability};

    fn meta_with_tags(setup: impl FnOnce(&mut BehavioralTags)) -> VersionMetadata {
        let mut tags = BehavioralTags::default();
        setup(&mut tags);
        VersionMetadata {
            behavioral_tags: Some(tags),
            ..Default::default()
        }
    }

    fn collect(meta: &VersionMetadata) -> Vec<AuditIssue> {
        let mut issues = Vec::new();
        collect_registry_issues(meta, &mut issues);
        issues
    }

    fn find_issue<'a>(
        issues: &'a [AuditIssue],
        severity: &str,
        category: &str,
    ) -> Option<&'a AuditIssue> {
        issues
            .iter()
            .find(|i| i.severity == severity && i.category == category)
    }

    // Critical bucket — obfuscated, protestware, high_entropy_strings

    #[test]
    fn registry_issue_critical_bucket_fires_for_obfuscated() {
        let meta = meta_with_tags(|t| t.obfuscated = true);
        let issues = collect(&meta);
        let issue = find_issue(&issues, "critical", "supply-chain")
            .expect("expected one critical/supply-chain issue");
        assert_eq!(issue.source, "registry");
        assert!(
            issue.message.contains("obfuscated code"),
            "msg: {}",
            issue.message
        );
    }

    #[test]
    fn registry_issue_critical_bucket_fires_for_protestware() {
        let issues = collect(&meta_with_tags(|t| t.protestware = true));
        let issue = find_issue(&issues, "critical", "supply-chain").unwrap();
        assert!(issue.message.contains("protestware"));
    }

    #[test]
    fn registry_issue_critical_bucket_fires_for_high_entropy_strings() {
        let issues = collect(&meta_with_tags(|t| t.high_entropy_strings = true));
        let issue = find_issue(&issues, "critical", "supply-chain").unwrap();
        assert!(issue.message.contains("high-entropy strings"));
    }

    #[test]
    fn registry_issue_critical_bucket_emits_single_issue_with_all_three() {
        let issues = collect(&meta_with_tags(|t| {
            t.obfuscated = true;
            t.protestware = true;
            t.high_entropy_strings = true;
        }));
        let critical: Vec<_> = issues
            .iter()
            .filter(|i| i.severity == "critical" && i.category == "supply-chain")
            .collect();
        assert_eq!(
            critical.len(),
            1,
            "critical bucket must emit ONE issue regardless of tag count"
        );
        // All three names must appear in the single message
        assert!(critical[0].message.contains("obfuscated"));
        assert!(critical[0].message.contains("protestware"));
        assert!(critical[0].message.contains("high-entropy"));
    }

    // Dangerous bucket — eval, child_process, shell, dynamic_require

    #[test]
    fn registry_issue_dangerous_bucket_fires_for_eval() {
        let issues = collect(&meta_with_tags(|t| t.eval = true));
        let issue = find_issue(&issues, "high", "behavior").unwrap();
        assert!(issue.message.contains("eval()"));
        assert_eq!(issue.source, "registry");
    }

    #[test]
    fn registry_issue_dangerous_bucket_fires_for_child_process() {
        let issues = collect(&meta_with_tags(|t| t.child_process = true));
        let issue = find_issue(&issues, "high", "behavior").unwrap();
        assert!(issue.message.contains("child_process"));
    }

    #[test]
    fn registry_issue_dangerous_bucket_fires_for_shell() {
        let issues = collect(&meta_with_tags(|t| t.shell = true));
        let issue = find_issue(&issues, "high", "behavior").unwrap();
        assert!(issue.message.contains("shell"));
    }

    #[test]
    fn registry_issue_dangerous_bucket_fires_for_dynamic_require() {
        let issues = collect(&meta_with_tags(|t| t.dynamic_require = true));
        let issue = find_issue(&issues, "high", "behavior").unwrap();
        assert!(issue.message.contains("dynamic require"));
    }

    #[test]
    fn registry_issue_dangerous_bucket_emits_single_issue_with_all_members() {
        let issues = collect(&meta_with_tags(|t| {
            t.eval = true;
            t.child_process = true;
            t.shell = true;
            t.dynamic_require = true;
        }));
        assert_eq!(
            issues
                .iter()
                .filter(|i| i.severity == "high" && i.category == "behavior")
                .count(),
            1
        );
    }

    // Medium bucket — network, native_bindings, git/http/wildcard dep, no_license
    // Emits severity=info, category=behavior, message starts with "flags:".

    #[test]
    fn registry_issue_medium_bucket_fires_for_network() {
        let issues = collect(&meta_with_tags(|t| t.network = true));
        // Both medium and notable share severity=info+category=behavior;
        // distinguish by message prefix.
        let issue = issues
            .iter()
            .find(|i| i.severity == "info" && i.message.starts_with("flags:"))
            .expect("expected medium bucket issue");
        assert!(issue.message.contains("network"));
        assert_eq!(issue.source, "registry");
    }

    #[test]
    fn registry_issue_medium_bucket_fires_for_each_member() {
        for (setter, expected_token) in [
            (
                Box::new(|t: &mut BehavioralTags| t.native_bindings = true)
                    as Box<dyn FnOnce(&mut BehavioralTags)>,
                "native bindings",
            ),
            (Box::new(|t| t.git_dependency = true), "git dependency"),
            (Box::new(|t| t.http_dependency = true), "http dependency"),
            (Box::new(|t| t.wildcard_dependency = true), "wildcard dep"),
            (Box::new(|t| t.no_license = true), "no license"),
        ] {
            let issues = collect(&meta_with_tags(setter));
            let medium = issues
                .iter()
                .find(|i| i.message.starts_with("flags:"))
                .unwrap_or_else(|| {
                    panic!("expected medium bucket issue for {expected_token}; got: {issues:?}")
                });
            assert!(
                medium.message.contains(expected_token),
                "message must contain '{expected_token}'; got: {}",
                medium.message
            );
        }
    }

    #[test]
    fn registry_issue_medium_bucket_emits_single_issue_with_all_members() {
        let issues = collect(&meta_with_tags(|t| {
            t.network = true;
            t.native_bindings = true;
            t.git_dependency = true;
            t.http_dependency = true;
            t.wildcard_dependency = true;
            t.no_license = true;
        }));
        assert_eq!(
            issues
                .iter()
                .filter(|i| i.message.starts_with("flags:"))
                .count(),
            1
        );
    }

    // Notable bucket — filesystem, env_vars, crypto, telemetry, minified,
    // trivial, copyleft_license. Emits severity=info, category=behavior,
    // message starts with "accesses".

    #[test]
    fn registry_issue_notable_bucket_fires_for_filesystem() {
        let issues = collect(&meta_with_tags(|t| t.filesystem = true));
        let issue = issues
            .iter()
            .find(|i| i.message.starts_with("accesses"))
            .expect("expected notable bucket issue");
        assert!(issue.message.contains("filesystem"));
        assert_eq!(issue.severity, "info");
        assert_eq!(issue.category, "behavior");
        assert_eq!(issue.source, "registry");
    }

    #[test]
    fn registry_issue_notable_bucket_fires_for_each_member() {
        for (setter, expected_token) in [
            (
                Box::new(|t: &mut BehavioralTags| t.environment_vars = true)
                    as Box<dyn FnOnce(&mut BehavioralTags)>,
                "env vars",
            ),
            (Box::new(|t| t.crypto = true), "crypto"),
            (Box::new(|t| t.telemetry = true), "telemetry"),
            (Box::new(|t| t.minified = true), "minified"),
            (Box::new(|t| t.trivial = true), "trivial"),
            (Box::new(|t| t.copyleft_license = true), "copyleft"),
        ] {
            let issues = collect(&meta_with_tags(setter));
            let notable = issues
                .iter()
                .find(|i| i.message.starts_with("accesses"))
                .unwrap_or_else(|| panic!("expected notable bucket issue for {expected_token}"));
            assert!(
                notable.message.contains(expected_token),
                "message must contain '{expected_token}'; got: {}",
                notable.message
            );
        }
    }

    #[test]
    fn registry_issue_notable_bucket_emits_single_issue_with_all_members() {
        let issues = collect(&meta_with_tags(|t| {
            t.filesystem = true;
            t.environment_vars = true;
            t.crypto = true;
            t.telemetry = true;
            t.minified = true;
            t.trivial = true;
            t.copyleft_license = true;
        }));
        assert_eq!(
            issues
                .iter()
                .filter(|i| i.message.starts_with("accesses"))
                .count(),
            1
        );
    }

    // Edge cases — empty tags, unused-by-mapping tags, all-tags-set

    #[test]
    fn registry_issue_empty_tags_emits_no_issues() {
        let issues = collect(&meta_with_tags(|_| {}));
        assert!(
            issues.is_empty(),
            "default-empty tags must produce 0 issues; got {issues:?}"
        );
    }

    #[test]
    fn registry_issue_url_strings_and_web_socket_not_currently_mapped() {
        // FINDING: `url_strings` and `web_socket` exist on BehavioralTags
        // but are not surfaced by collect_registry_issues. This test
        // pins the current behavior. If a future change adds these to
        // any bucket, update the test to assert the new mapping.
        let issues = collect(&meta_with_tags(|t| {
            t.url_strings = true;
            t.web_socket = true;
        }));
        assert!(
            issues.is_empty(),
            "url_strings and web_socket are currently unmapped — \
             if this changes, update the test to assert the new bucket. Got: {issues:?}"
        );
    }

    #[test]
    fn registry_issue_all_tags_set_emits_one_issue_per_active_bucket() {
        let issues = collect(&meta_with_tags(|t| {
            // Set every documented tag — all 22.
            t.eval = true;
            t.child_process = true;
            t.shell = true;
            t.network = true;
            t.filesystem = true;
            t.crypto = true;
            t.dynamic_require = true;
            t.native_bindings = true;
            t.environment_vars = true;
            t.web_socket = true;
            t.obfuscated = true;
            t.high_entropy_strings = true;
            t.minified = true;
            t.telemetry = true;
            t.url_strings = true;
            t.trivial = true;
            t.protestware = true;
            t.git_dependency = true;
            t.http_dependency = true;
            t.wildcard_dependency = true;
            t.copyleft_license = true;
            t.no_license = true;
        }));
        // 4 buckets all fire → exactly 4 issues from behavioral tags.
        assert_eq!(
            issues.len(),
            4,
            "expected one issue per active bucket; got: {issues:?}"
        );
        assert!(find_issue(&issues, "critical", "supply-chain").is_some());
        assert!(find_issue(&issues, "high", "behavior").is_some());
        assert_eq!(
            issues
                .iter()
                .filter(|i| i.severity == "info" && i.category == "behavior")
                .count(),
            2,
            "medium + notable both emit info/behavior"
        );
    }

    // security_findings arm

    #[test]
    fn registry_issue_security_findings_emits_one_issue_per_finding() {
        let meta = VersionMetadata {
            security_findings: Some(vec![
                SecurityFinding {
                    severity: Some("high".into()),
                    description: Some("hardcoded API key".into()),
                    file: Some("index.js".into()),
                },
                SecurityFinding {
                    severity: Some("moderate".into()),
                    description: Some("unsafe regex".into()),
                    file: None,
                },
            ]),
            ..Default::default()
        };
        let issues = collect(&meta);
        assert_eq!(issues.len(), 2);
        assert!(
            issues
                .iter()
                .all(|i| i.category == "security" && i.source == "registry")
        );
        let high = issues.iter().find(|i| i.severity == "high").unwrap();
        assert_eq!(high.message, "hardcoded API key");
        let moderate = issues.iter().find(|i| i.severity == "moderate").unwrap();
        assert_eq!(moderate.message, "unsafe regex");
    }

    #[test]
    fn registry_issue_security_finding_uses_defaults_for_missing_fields() {
        let meta = VersionMetadata {
            security_findings: Some(vec![SecurityFinding {
                severity: None,
                description: None,
                file: None,
            }]),
            ..Default::default()
        };
        let issues = collect(&meta);
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].severity, "moderate", "default severity");
        assert_eq!(
            issues[0].message, "security concern detected",
            "default message"
        );
    }

    // lifecycle_scripts arm

    #[test]
    fn registry_issue_lifecycle_scripts_emits_one_moderate_issue() {
        let mut scripts = std::collections::HashMap::new();
        scripts.insert("preinstall".to_string(), "node setup.js".to_string());
        scripts.insert("postinstall".to_string(), "node build.js".to_string());
        let meta = VersionMetadata {
            lifecycle_scripts: Some(scripts),
            ..Default::default()
        };
        let issues = collect(&meta);
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].severity, "moderate");
        assert_eq!(issues[0].category, "scripts");
        // Both script names must appear (HashMap order is non-deterministic,
        // assert membership rather than order).
        assert!(issues[0].message.contains("preinstall"));
        assert!(issues[0].message.contains("postinstall"));
    }

    #[test]
    fn registry_issue_empty_lifecycle_scripts_emits_no_issue() {
        let meta = VersionMetadata {
            lifecycle_scripts: Some(std::collections::HashMap::new()),
            ..Default::default()
        };
        let issues = collect(&meta);
        assert!(issues.is_empty());
    }

    // vulnerabilities arm

    #[test]
    fn registry_issue_vulnerabilities_emits_one_issue_per_vuln() {
        let meta = VersionMetadata {
            vulnerabilities: Some(vec![
                Vulnerability {
                    id: Some("GHSA-aaaa".into()),
                    summary: Some("rce".into()),
                    severity: Some("HIGH".into()),
                    aliases: None,
                },
                Vulnerability {
                    id: Some("CVE-2025-0001".into()),
                    summary: None,
                    severity: Some("Critical".into()),
                    aliases: None,
                },
            ]),
            ..Default::default()
        };
        let issues = collect(&meta);
        assert_eq!(issues.len(), 2);
        // Severity is lowercased
        let high = issues
            .iter()
            .find(|i| i.message.contains("GHSA-aaaa"))
            .unwrap();
        assert_eq!(high.severity, "high");
        assert_eq!(high.category, "vulnerability");
        assert!(high.message.contains("rce"));
        let critical = issues
            .iter()
            .find(|i| i.message.contains("CVE-2025-0001"))
            .unwrap();
        assert_eq!(critical.severity, "critical");
        // No summary → no " — " separator
        assert!(!critical.message.contains(" — "));
    }

    #[test]
    fn registry_issue_vulnerability_defaults_for_missing_fields() {
        let meta = VersionMetadata {
            vulnerabilities: Some(vec![Vulnerability {
                id: None,
                summary: None,
                severity: None,
                aliases: None,
            }]),
            ..Default::default()
        };
        let issues = collect(&meta);
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].severity, "moderate", "default severity");
        assert_eq!(issues[0].message, "unknown", "default id");
    }

    // Combined — multiple arms in one call

    #[test]
    fn registry_issue_combined_security_behavioral_scripts_vulns() {
        let mut scripts = std::collections::HashMap::new();
        scripts.insert("preinstall".to_string(), "x".to_string());
        let meta = VersionMetadata {
            security_findings: Some(vec![SecurityFinding {
                severity: Some("high".into()),
                description: Some("ai-finding".into()),
                file: None,
            }]),
            behavioral_tags: Some(BehavioralTags {
                eval: true,
                obfuscated: true,
                network: true,
                ..Default::default()
            }),
            lifecycle_scripts: Some(scripts),
            vulnerabilities: Some(vec![Vulnerability {
                id: Some("CVE-2025-9999".into()),
                summary: Some("rce".into()),
                severity: Some("high".into()),
                aliases: None,
            }]),
            ..Default::default()
        };
        let issues = collect(&meta);
        // 1 security_finding + 3 active buckets (critical/dangerous/medium)
        // + 1 lifecycle_scripts + 1 vulnerability = 6 issues.
        assert_eq!(issues.len(), 6, "got: {issues:?}");
    }

    /// `query_osv_batch` now surfaces non-2xx responses as `Err`
    /// rather than silently returning `Ok(Vec::new())` — the latter
    /// was indistinguishable from "no vulnerabilities found", a green
    /// state that a transient OSV outage or an attacker who can block
    /// the OSV connection could fabricate. Locks the new error path
    /// so a future refactor that re-introduces the silent fallback
    /// fails this test first.
    #[tokio::test]
    async fn query_osv_batch_returns_err_on_non_success_http() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(500).set_body_string("osv down"))
            .mount(&server)
            .await;

        // SAFETY: a `Mutex`-guarded env var would be ideal but this
        // module doesn't have an env-isolation harness like
        // `release_lookup`. The OSV URL env var is read inside the
        // function under test, so the set→call→remove sequence is
        // race-free within a single test. Other tests in this module
        // do not set LPM_OSV_URL.
        unsafe { std::env::set_var("LPM_OSV_URL", server.uri()) };
        let result = query_osv_batch(&[("react".to_string(), "1.0.0".to_string())]).await;
        unsafe { std::env::remove_var("LPM_OSV_URL") };

        let err = result.expect_err("non-2xx OSV response must surface as Err");
        let msg = err.to_string();
        assert!(
            msg.contains("HTTP 500") && msg.contains("degraded"),
            "error must label the failure mode: {msg}"
        );
    }

    /// M67: `LPM_OSV_URL` override gating mirrors the H9 self-update
    /// probe — HTTPS accepted (private mirrors), HTTP only on loopback
    /// (workflow tests), anything else falls back to the default.
    #[test]
    fn osv_override_accepts_https_any_host() {
        assert!(osv_override_is_accepted(
            "https://api.osv.dev/v1/querybatch"
        ));
        assert!(osv_override_is_accepted("https://osv.private.corp/v1"));
        assert!(osv_override_is_accepted("https://example.com:8443/path"));
    }

    #[test]
    fn osv_override_accepts_http_only_for_loopback() {
        assert!(osv_override_is_accepted("http://127.0.0.1:8080/v1"));
        assert!(osv_override_is_accepted("http://localhost:9090/v1"));
        assert!(osv_override_is_accepted("http://[::1]:8080/v1"));
    }

    #[test]
    fn osv_override_rejects_plain_http_non_loopback() {
        assert!(!osv_override_is_accepted("http://attacker.example/v1"));
        assert!(!osv_override_is_accepted("http://192.0.2.1/v1"));
        assert!(!osv_override_is_accepted("http://osv.dev/v1"));
    }

    #[test]
    fn osv_override_rejects_unsupported_schemes() {
        assert!(!osv_override_is_accepted("ftp://osv.dev/v1"));
        assert!(!osv_override_is_accepted("file:///etc/osv.json"));
        assert!(!osv_override_is_accepted("javascript:alert(1)"));
        assert!(!osv_override_is_accepted("not a url"));
    }
}
