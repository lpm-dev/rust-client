use std::collections::HashMap;
use std::path::Path;

use lpm_common::color::Painted;
use lpm_common::{LpmError, PackageName};
use lpm_registry::{PackageMetadata, RegistryClient};
use lpm_semver::Version;

use crate::install_ui;
use crate::npm_public_source::{NpmMetadataSource, lockfile_npm_metadata_source};

use super::discovery::{self, ManagerKind};
use super::osv::{OsvVulnerability, run_osv_scan};

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
        false, // offline
        crate::commands::install::FrozenLockfileMode::Never,
        false, // force
        false, // allow_new
        false, // strict_integrity
        None,  // strict_peer_dependencies_override
        None,  // linker_override
        false, // no_skills
        false, // no_editor_setup
        true,  // no_security_summary: audit fix emits its own final report.
        false, // auto_build
        None,  // target_set
        None,  // direct_versions_out
        None,  // requested_add_count
        None,  // script_policy_override
        None,  // advisor_override
        None,  // min_release_age_override
        &[],
        crate::provenance_fetch::DriftIgnorePolicy::default(),
        crate::provenance_fetch::VerifyPolicy::resolve_no_cli(),
        crate::commands::install::InstallOmitPolicy::default(),
        false, // strict_sandbox
        false, // no_sandbox
        false, // verbose
        false, // audit_after_install
        &[],
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
