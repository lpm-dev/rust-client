use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use lpm_common::{LpmError, PackageName};
use lpm_registry::{PackageMetadata, RegistryClient};
use lpm_semver::Version;

use crate::install_ui;
use crate::npm_public_source::{NpmMetadataSource, locked_package_npm_metadata_source};

use super::discovery::{self, ManagerKind};
use super::osv::{OsvVulnerability, run_osv_scan};

#[derive(Debug, Clone)]
struct AuditFixDirectDep {
    local_name: String,
    target_name: String,
    current_range: String,
    dependency_key: &'static str,
    is_dev: bool,
    is_optional: bool,
    unsupported_reason: Option<String>,
}

#[derive(Debug, Clone)]
struct AuditFixPlan {
    name: String,
    target_name: String,
    from: String,
    to: String,
    current_range: String,
    new_range: String,
    dependency_key: &'static str,
    is_dev: bool,
    is_optional: bool,
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
    lpm_common::with_exclusive_lock_async(
        lpm_common::project_install_lock(project_dir),
        run_fix_under_project_lock(client, project_dir, json_output, dry_run),
    )
    .await
}

async fn run_fix_under_project_lock(
    client: &RegistryClient,
    project_dir: &Path,
    json_output: bool,
    dry_run: bool,
) -> Result<(), LpmError> {
    let started_at = std::time::Instant::now();
    let pkg_json_path = project_dir.join("package.json");
    let original_content = match lpm_common::read_file_capped(
        &pkg_json_path,
        lpm_common::CONFIG_FILE_SIZE_CAP_BYTES,
    ) {
        Ok(content) => content,
        Err(lpm_common::BoundedReadError::NotFound { .. }) => {
            return Err(LpmError::NotFound("no package.json found".into()));
        }
        Err(error) => {
            return Err(LpmError::Script(format!(
                "failed to read package.json: {error}"
            )));
        }
    };
    let mut doc: serde_json::Value = serde_json::from_slice(&original_content)
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
    let lockfile_path = project_dir.join("lpm.lock");
    let lockfile = lpm_lockfile::Lockfile::read_fast(&lockfile_path)
        .map_err(|e| LpmError::Script(format!("failed to read lpm.lock: {e}")))?;

    let mut vulns_by_instance: HashMap<(String, String), Vec<&OsvVulnerability>> = HashMap::new();
    for vuln in &osv_outcome.vulns {
        vulns_by_instance
            .entry((vuln.package.clone(), vuln.version.clone()))
            .or_default()
            .push(vuln);
    }

    let mut planned = Vec::new();
    let mut skipped = Vec::new();
    for dep in audit_fix_direct_deps_from_value(&doc) {
        let target_name = dep.target_name.as_str();
        let locked_package = match select_installed_direct_locked_package(
            project_dir,
            &lockfile,
            &dep.local_name,
            target_name,
        ) {
            Ok(package) => package,
            Err(reason) => {
                skipped.push(AuditFixSkipped {
                    name: dep.local_name,
                    reason,
                });
                continue;
            }
        };
        let installed_version = &locked_package.version;
        let is_lpm_package = target_name.starts_with("@lpm.dev/");
        let npm_vulns = if is_lpm_package {
            None
        } else {
            let Some(vulns) =
                vulns_by_instance.get(&(target_name.to_string(), installed_version.clone()))
            else {
                continue;
            };
            Some(vulns)
        };

        let npm_source = if is_lpm_package {
            None
        } else {
            match locked_package_npm_metadata_source(locked_package, client) {
                Some(source) => Some(source),
                None => {
                    skipped.push(AuditFixSkipped {
                        name: dep.local_name,
                        reason: "lockfile source is not public npm or the configured LPM registry; refusing to disclose the name to npm metadata endpoints".into(),
                    });
                    continue;
                }
            }
        };

        let metadata = match fetch_audit_fix_metadata(client, target_name, npm_source).await {
            Ok(metadata) => metadata,
            Err(err) => {
                skipped.push(AuditFixSkipped {
                    name: dep.local_name,
                    reason: format!("metadata lookup failed: {err}"),
                });
                continue;
            }
        };

        let (target, vulnerability_ids) = if is_lpm_package {
            let Some(version_metadata) = metadata.version(installed_version) else {
                skipped.push(AuditFixSkipped {
                    name: dep.local_name,
                    reason: format!(
                        "registry metadata omitted installed version {target_name}@{installed_version}"
                    ),
                });
                continue;
            };
            let vulnerability_ids = lpm_vulnerability_ids(version_metadata);
            if vulnerability_ids.is_empty() {
                continue;
            }
            if let Some(reason) = dep.unsupported_reason.clone() {
                skipped.push(AuditFixSkipped {
                    name: dep.local_name,
                    reason,
                });
                continue;
            }
            match choose_lpm_audit_fix_target(target_name, installed_version, &metadata) {
                Ok(target) => (target, vulnerability_ids),
                Err(reason) => {
                    skipped.push(AuditFixSkipped {
                        name: dep.local_name,
                        reason,
                    });
                    continue;
                }
            }
        } else {
            let vulns = npm_vulns.expect("set for npm packages");
            if let Some(reason) = dep.unsupported_reason.clone() {
                skipped.push(AuditFixSkipped {
                    name: dep.local_name,
                    reason,
                });
                continue;
            }
            match choose_audit_fix_target(target_name, installed_version, &metadata, vulns) {
                Ok(target) => (
                    target,
                    vulns
                        .iter()
                        .map(|vulnerability| vulnerability.id.clone())
                        .collect(),
                ),
                Err(reason) => {
                    skipped.push(AuditFixSkipped {
                        name: dep.local_name,
                        reason,
                    });
                    continue;
                }
            }
        };
        let new_range = match audit_fix_range_for_target(&dep.current_range, &target) {
            Ok(range) => range,
            Err(reason) => {
                skipped.push(AuditFixSkipped {
                    name: dep.local_name,
                    reason,
                });
                continue;
            }
        };
        planned.push(AuditFixPlan {
            name: dep.local_name,
            target_name: target_name.to_string(),
            from: installed_version.clone(),
            to: target.clone(),
            current_range: dep.current_range.clone(),
            new_range,
            dependency_key: dep.dependency_key,
            is_dev: dep.is_dev,
            is_optional: dep.is_optional,
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

    let lockfile_binary_path = project_dir.join("lpm.lockb");
    let install_hash_path = project_dir.join(".lpm").join("install-hash");
    apply_audit_fixes_to_manifest(&mut doc, &planned)?;
    let updated_content = serde_json::to_string_pretty(&doc)
        .map_err(|e| LpmError::Script(format!("failed to serialize package.json: {e}")))?;

    let tx = crate::manifest_tx::ManifestTransaction::snapshot_install_state_if_unchanged(
        &[(pkg_json_path.as_path(), original_content.as_slice())],
        &[lockfile_path.as_path(), lockfile_binary_path.as_path()],
        &[install_hash_path.as_path()],
    )
    .map_err(|error| {
        LpmError::Script(format!(
            "package.json changed while audit fix was planning; no changes were applied: {error}"
        ))
    })?;

    lpm_common::write_file_atomic(&pkg_json_path, format!("{updated_content}\n"))
        .map_err(LpmError::Io)?;

    audit_fix_remove_optional_file(&lockfile_path)?;
    audit_fix_remove_optional_file(&lockfile_binary_path)?;

    let install_result =
        crate::commands::install::run_silent_for_audit_fix(client, project_dir).await;

    if let Err(err) = install_result {
        if !json_output {
            install_ui::warn("install failed — restored original package.json");
        }
        return Err(err);
    }

    verify_audit_fixes(client, project_dir, &planned).await?;
    tx.commit();

    emit_audit_fix_report(
        &planned,
        &skipped,
        dry_run,
        json_output,
        started_at.elapsed(),
    );
    Ok(())
}

fn select_installed_direct_locked_package<'a>(
    project_dir: &Path,
    lockfile: &'a lpm_lockfile::Lockfile,
    local_name: &str,
    target_name: &str,
) -> Result<&'a lpm_lockfile::LockedPackage, String> {
    let manifest_path = installed_direct_manifest_path(project_dir, local_name)?;
    let content =
        lpm_common::read_file_capped(&manifest_path, lpm_common::CONFIG_FILE_SIZE_CAP_BYTES)
            .map_err(|error| {
                format!(
                    "cannot read installed direct dependency {}: {error}",
                    manifest_path.display()
                )
            })?;
    let manifest: serde_json::Value = serde_json::from_slice(&content).map_err(|error| {
        format!(
            "installed direct dependency {} has invalid package.json: {error}",
            manifest_path.display()
        )
    })?;
    let installed_name = manifest
        .get("name")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            format!(
                "installed direct dependency {} is missing its package name",
                manifest_path.display()
            )
        })?;
    if installed_name != target_name {
        return Err(format!(
            "installed direct dependency '{local_name}' resolves to '{installed_name}', expected '{target_name}'"
        ));
    }
    let installed_version = manifest
        .get("version")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            format!(
                "installed direct dependency {} is missing its version",
                manifest_path.display()
            )
        })?;

    let start = lockfile
        .packages
        .partition_point(|package| package.name.as_str() < target_name);
    let end = start
        + lockfile.packages[start..]
            .partition_point(|package| package.name.as_str() == target_name);
    let mut matches = lockfile.packages[start..end]
        .iter()
        .filter(|package| package.version == installed_version);
    let Some(installed) = matches.next() else {
        return Err(format!(
            "installed direct dependency {target_name}@{installed_version} is not present in lpm.lock"
        ));
    };
    if matches.next().is_some() {
        return Err(format!(
            "installed direct dependency {target_name}@{installed_version} has ambiguous lockfile instances from multiple sources"
        ));
    }
    Ok(installed)
}

fn installed_direct_manifest_path(project_dir: &Path, local_name: &str) -> Result<PathBuf, String> {
    if local_name.contains('\\') {
        return Err(format!(
            "dependency name '{local_name}' is not safe to resolve on disk"
        ));
    }
    let parts: Vec<&str> = local_name.split('/').collect();
    let valid_part = |part: &str| !part.is_empty() && part != "." && part != "..";
    let valid = match parts.as_slice() {
        [name] => valid_part(name) && !name.starts_with('@'),
        [scope, name] => {
            scope.starts_with('@')
                && scope.len() > 1
                && valid_part(scope)
                && valid_part(name)
                && !name.starts_with('@')
        }
        _ => false,
    };
    if !valid {
        return Err(format!(
            "dependency name '{local_name}' is not safe to resolve on disk"
        ));
    }

    let mut path = project_dir.to_path_buf();
    path.push("node_modules");
    for part in parts {
        path.push(part);
    }
    path.push("package.json");
    Ok(path)
}

fn audit_fix_direct_deps_from_value(doc: &serde_json::Value) -> Vec<AuditFixDirectDep> {
    let mut deps = Vec::new();
    let mut seen = HashSet::new();
    for (key, is_dev, is_optional) in [
        ("optionalDependencies", false, true),
        ("dependencies", false, false),
        ("devDependencies", true, false),
    ] {
        if let Some(obj) = doc.get(key).and_then(|value| value.as_object()) {
            deps.reserve(obj.len());
            for (name, range) in obj {
                let Some(range) = range.as_str() else {
                    continue;
                };
                if !seen.insert(name.clone()) {
                    continue;
                }
                let (target_name, unsupported_reason) = match lpm_resolver::Specifier::parse(range)
                {
                    Ok(lpm_resolver::Specifier::SemverRange(_)) => (name.clone(), None),
                    Ok(lpm_resolver::Specifier::NpmAlias { target, .. })
                        if range.starts_with("npm:") =>
                    {
                        (target, None)
                    }
                    Ok(_) | Err(_) => (
                        name.clone(),
                        Some(format!(
                            "dependency specifier '{range}' cannot be updated automatically without changing its source protocol"
                        )),
                    ),
                };
                deps.push(AuditFixDirectDep {
                    local_name: name.clone(),
                    target_name,
                    current_range: range.to_string(),
                    dependency_key: key,
                    is_dev,
                    is_optional,
                    unsupported_reason,
                });
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
    let installed = Version::parse(installed_version)
        .map_err(|error| format!("installed version '{installed_version}' is invalid: {error}"))?;
    let mut candidates: Vec<Version> = metadata
        .versions
        .keys()
        .filter_map(|version| Version::parse(version).ok())
        .filter(|version| !version.is_prerelease())
        .filter(|version| version > &installed)
        .collect();
    candidates.sort();
    for candidate in candidates {
        let candidate_text = candidate.to_string();
        let mut safe = true;
        for vulnerability in vulns {
            match vulnerability.affects_version(&candidate_text) {
                Ok(false) => {}
                Ok(true) => {
                    safe = false;
                    break;
                }
                Err(reason) => return Err(reason),
            }
        }
        if safe {
            return Ok(candidate_text);
        }
    }
    Err(format!(
        "registry has no verified non-vulnerable version of '{package}' newer than {installed_version}"
    ))
}

fn choose_lpm_audit_fix_target(
    package: &str,
    installed_version: &str,
    metadata: &PackageMetadata,
) -> Result<String, String> {
    let installed = Version::parse(installed_version)
        .map_err(|error| format!("installed version '{installed_version}' is invalid: {error}"))?;
    let mut candidates: Vec<Version> = metadata
        .versions
        .keys()
        .filter_map(|version| Version::parse(version).ok())
        .filter(|version| !version.is_prerelease() && version > &installed)
        .collect();
    candidates.sort();
    candidates
        .into_iter()
        .find(|candidate| {
            metadata
                .version(&candidate.to_string())
                .is_some_and(|version| lpm_vulnerability_ids(version).is_empty())
        })
        .map(|version| version.to_string())
        .ok_or_else(|| {
            format!(
                "registry has no verified non-vulnerable version of '{package}' newer than {installed_version}"
            )
        })
}

fn lpm_vulnerability_ids(metadata: &lpm_registry::VersionMetadata) -> Vec<String> {
    metadata
        .vulnerabilities
        .as_deref()
        .unwrap_or_default()
        .iter()
        .enumerate()
        .map(|(index, vulnerability)| {
            vulnerability
                .id
                .clone()
                .unwrap_or_else(|| format!("unknown-{}", index + 1))
        })
        .collect()
}

fn audit_fix_range_for_target(current_range: &str, target: &str) -> Result<String, String> {
    if current_range.starts_with("catalog:") {
        return Err(format!(
            "dependency specifier '{current_range}' cannot be updated automatically without changing its source protocol"
        ));
    }
    match lpm_resolver::Specifier::parse(current_range) {
        Ok(lpm_resolver::Specifier::SemverRange(_)) => update_semver_range(current_range, target),
        Ok(lpm_resolver::Specifier::NpmAlias {
            target: alias_target,
            range,
        }) if current_range.starts_with("npm:") => Ok(format!(
            "npm:{alias_target}@{}",
            update_semver_range(&range, target)?
        )),
        Ok(_) | Err(_) => Err(format!(
            "dependency specifier '{current_range}' cannot be updated automatically without changing its source protocol"
        )),
    }
}

fn update_semver_range(_current_range: &str, target: &str) -> Result<String, String> {
    Version::parse(target)
        .map_err(|error| format!("candidate version '{target}' is invalid: {error}"))?;
    Ok(target.to_string())
}

fn apply_audit_fixes_to_manifest(
    doc: &mut serde_json::Value,
    fixes: &[AuditFixPlan],
) -> Result<(), LpmError> {
    for fix in fixes {
        let dep_key = fix.dependency_key;
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
        if fix.is_optional
            && let Some(serde_json::Value::String(duplicate_range)) = doc
                .get_mut("dependencies")
                .and_then(|value| value.as_object_mut())
                .and_then(|dependencies| dependencies.get_mut(&fix.name))
        {
            *duplicate_range =
                audit_fix_range_for_target(duplicate_range, &fix.to).map_err(LpmError::Script)?;
        }
    }
    Ok(())
}

async fn verify_audit_fixes(
    client: &RegistryClient,
    project_dir: &Path,
    fixes: &[AuditFixPlan],
) -> Result<(), LpmError> {
    let lockfile_path = project_dir.join("lpm.lock");
    let lockfile = lpm_lockfile::Lockfile::read_fast(&lockfile_path)
        .map_err(|error| LpmError::Script(format!("failed to verify updated lpm.lock: {error}")))?;

    for fix in fixes.iter() {
        let installed = select_installed_direct_locked_package(
            project_dir,
            &lockfile,
            &fix.name,
            &fix.target_name,
        )
        .map_err(|reason| {
            LpmError::Script(format!(
                "audit fix verification could not identify direct dependency {}: {reason}",
                fix.name
            ))
        })?;
        if installed.version != fix.to {
            return Err(LpmError::Script(format!(
                "audit fix verification expected {} at planned version {}, found {}",
                fix.name, fix.to, installed.version
            )));
        }
    }

    let discovery = discovery::discover_packages(project_dir)?;
    let osv_outcome = run_osv_scan(&discovery.packages, true, None).await;
    if let Some(reason) = osv_outcome.degraded_reason {
        return Err(LpmError::Script(format!(
            "audit fix verification could not query OSV: {reason}"
        )));
    }
    let remaining_osv: HashSet<(&str, &str)> = osv_outcome
        .vulns
        .iter()
        .map(|vulnerability| {
            (
                vulnerability.package.as_str(),
                vulnerability.version.as_str(),
            )
        })
        .collect();

    for fix in fixes {
        if fix.target_name.starts_with("@lpm.dev/") {
            let metadata = fetch_audit_fix_metadata(client, &fix.target_name, None).await?;
            let version = metadata.version(&fix.to).ok_or_else(|| {
                LpmError::Script(format!(
                    "audit fix verification metadata omitted {}@{}",
                    fix.target_name, fix.to
                ))
            })?;
            let remaining = lpm_vulnerability_ids(version);
            if !remaining.is_empty() {
                return Err(LpmError::Script(format!(
                    "audit fix verification found {}@{} still vulnerable: {}",
                    fix.target_name,
                    fix.to,
                    remaining.join(", ")
                )));
            }
        } else if remaining_osv.contains(&(fix.target_name.as_str(), fix.to.as_str())) {
            return Err(LpmError::Script(format!(
                "audit fix verification found {}@{} still vulnerable according to OSV",
                fix.target_name, fix.to
            )));
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
                    "is_optional": fix.is_optional,
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
                install_ui::detail_line(crate::install_ui::terminal_line!(
                    "  {} {}",
                    install_ui::bold(&skip.name),
                    install_ui::dim(&skip.reason),
                ));
            }
        }
        return;
    }

    let verb = if dry_run { "Would fix" } else { "Fixed" };
    install_ui::done_line(crate::install_ui::terminal_line!(
        "{} {} vulnerable direct {} in {}",
        verb,
        fixes.len(),
        install_ui::packages_word(fixes.len()),
        install_ui::format_duration(elapsed),
    ));
    for fix in fixes {
        install_ui::detail_line(crate::install_ui::terminal_line!(
            "  {} {} {} {}  {}",
            install_ui::bold(&fix.name),
            install_ui::dim(&fix.from),
            install_ui::dim("→"),
            install_ui::yellow(&fix.to),
            install_ui::dim(&fix.vulnerability_ids.join(", ")),
        ));
    }
    if !skipped.is_empty() {
        install_ui::warn_untrusted(&format!(
            "{} vulnerable direct {} could not be fixed automatically",
            skipped.len(),
            install_ui::packages_word(skipped.len()),
        ));
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_fix_range_pins_npm_alias_to_planned_target() {
        assert_eq!(
            audit_fix_range_for_target("npm:lodash@^4.17.0", "4.17.21").unwrap(),
            "npm:lodash@4.17.21"
        );
    }

    #[test]
    fn audit_fix_range_refuses_non_registry_source_protocol_rewrites() {
        for specifier in [
            "catalog:",
            "workspace:^",
            "file:../local-package",
            "git+https://github.com/example/package.git",
            "jsr:@scope/package@^1.0.0",
        ] {
            let error = audit_fix_range_for_target(specifier, "4.17.21").unwrap_err();
            assert!(
                error.contains("source protocol"),
                "unexpected error for {specifier}: {error}"
            );
        }
    }

    #[test]
    fn direct_dependency_inventory_applies_optional_precedence() {
        let document = serde_json::json!({
            "dependencies": {"shared": "1.0.0"},
            "optionalDependencies": {"shared": "1.0.1", "optional": "2.0.0"},
            "devDependencies": {"dev": "3.0.0"}
        });
        let dependencies = audit_fix_direct_deps_from_value(&document);
        assert_eq!(dependencies.len(), 3);
        let shared = dependencies
            .iter()
            .find(|dependency| dependency.local_name == "shared")
            .unwrap();
        assert_eq!(shared.current_range, "1.0.1");
        assert_eq!(shared.dependency_key, "optionalDependencies");
        assert!(shared.is_optional);
    }
}
