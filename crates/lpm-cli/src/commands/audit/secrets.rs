use std::collections::{HashSet, VecDeque};
use std::path::{Path, PathBuf};

use lpm_common::LpmError;
use lpm_common::color::Painted;
use lpm_security::behavioral::secrets::{
    SecretScanBudget, SecretScanLimit, SecretScanResult, scan_directory_with_budget,
};

use crate::install_ui;

use super::policy::FailPolicy;

/// Scan installed packages for hardcoded secrets.
///
/// Walks the installed package graph and scans each package for API keys, tokens,
/// and private keys.
pub async fn run_secrets(
    project_dir: &Path,
    json_output: bool,
    fail_on: Option<&str>,
) -> Result<(), LpmError> {
    let fail_policy = match fail_on {
        Some(value) => FailPolicy::parse(value)?,
        None => FailPolicy::All,
    };
    if !json_output {
        install_ui::phase("Scanning installed packages for secrets");
    }

    let lpm_root = lpm_common::LpmRoot::from_env()?;
    let (total_packages, packages_with_secrets) =
        lpm_common::with_shared_lock(lpm_root.store_lock(), || {
            scan_installed_packages(project_dir, &lpm_root)
        })?;

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
            serde_json::to_string_pretty(&serde_json::json!({
                "success": true,
                "packagesScanned": total_packages,
                "packagesWithSecrets": packages_with_secrets.len(),
                "findings": findings,
            }))
            .unwrap()
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
            install_ui::yellow(&lpm_common::sanitize_terminal_inline(pkg_name)),
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
                "    {}{}  {}",
                match m.severity.as_str() {
                    "critical" => "·".red().to_string(),
                    "high" => "·".yellow().to_string(),
                    _ => "·".dimmed().to_string(),
                },
                location.dimmed(),
                lpm_common::sanitize_terminal_inline(&m.description)
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

const AUDIT_SECRET_SCAN_MAX_PACKAGES: usize = 100_000;

struct InstalledPackage {
    name: String,
    directory: PathBuf,
}

struct PackageRoots {
    project: PathBuf,
    allowed: Vec<PathBuf>,
}

fn scan_installed_packages(
    project_dir: &Path,
    lpm_root: &lpm_common::LpmRoot,
) -> Result<(usize, Vec<(String, SecretScanResult)>), LpmError> {
    let packages = discover_installed_packages(project_dir, lpm_root)?;
    let total_packages = packages.len();
    let mut budget = SecretScanBudget::for_operation();
    let mut packages_with_secrets = Vec::with_capacity(total_packages.min(128));

    for package in packages {
        let result = scan_directory_with_budget(&package.directory, &mut budget);
        if let Some(limit) = result.limit_exceeded.or_else(|| budget.exceeded()) {
            return Err(secret_scan_limit_error(limit));
        }
        if result.has_secrets() {
            packages_with_secrets.push((package.name, result));
        }
    }

    Ok((total_packages, packages_with_secrets))
}

fn secret_scan_limit_error(limit: SecretScanLimit) -> LpmError {
    let maximum = match limit {
        SecretScanLimit::Files => {
            lpm_security::behavioral::secrets::SECRET_SCAN_MAX_FILES.to_string()
        }
        SecretScanLimit::Bytes => format!(
            "{} MiB",
            lpm_security::behavioral::secrets::SECRET_SCAN_MAX_BYTES / (1024 * 1024)
        ),
        SecretScanLimit::Findings => {
            lpm_security::behavioral::secrets::SECRET_SCAN_MAX_FINDINGS.to_string()
        }
    };
    LpmError::Script(format!(
        "secret scan stopped at the {maximum} {limit} limit; no clean result was reported"
    ))
}

fn discover_installed_packages(
    project_dir: &Path,
    lpm_root: &lpm_common::LpmRoot,
) -> Result<Vec<InstalledPackage>, LpmError> {
    let node_modules = project_dir.join("node_modules");
    let metadata = std::fs::symlink_metadata(&node_modules).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            LpmError::Script("no node_modules found. Run `lpm install` first.".into())
        } else {
            LpmError::Script(format!("failed to inspect node_modules: {error}"))
        }
    })?;
    if !metadata.is_dir() || lpm_common::is_symlink_or_junction(&metadata) {
        return Err(LpmError::Script(
            "project node_modules must be a real directory before secrets can be audited".into(),
        ));
    }

    let project = project_dir.canonicalize().map_err(LpmError::Io)?;
    let canonical_node_modules = node_modules.canonicalize().map_err(LpmError::Io)?;
    let mut roots = PackageRoots {
        project,
        allowed: vec![canonical_node_modules.clone()],
    };
    for root in [
        project_dir.join(".lpm/wrappers"),
        project_dir.join(".lpm/hoisted"),
        lpm_root.store_root(),
    ] {
        if let Ok(canonical) = root.canonicalize()
            && !roots.allowed.contains(&canonical)
        {
            roots.allowed.push(canonical);
        }
    }

    let mut node_modules_queue = VecDeque::from([canonical_node_modules]);
    let mut visited_node_modules = HashSet::new();
    let mut visited_packages = HashSet::new();
    let mut packages = Vec::new();

    while let Some(directory) = node_modules_queue.pop_front() {
        let Some(directory) = canonicalize_scannable_directory(&directory, &roots)? else {
            continue;
        };
        if !visited_node_modules.insert(directory.clone()) {
            continue;
        }
        let entries = std::fs::read_dir(&directory).map_err(|error| {
            LpmError::Script(format!(
                "failed to read installed package directory {}: {error}",
                directory.display()
            ))
        })?;
        for entry in entries {
            let entry = entry.map_err(|error| {
                LpmError::Script(format!(
                    "failed to enumerate installed packages in {}: {error}",
                    lpm_common::sanitize_terminal_inline(&directory.display().to_string())
                ))
            })?;
            let entry_name = entry.file_name().to_string_lossy().to_string();
            if entry_name.starts_with('.') {
                continue;
            }
            if entry_name.starts_with('@') {
                collect_scope_packages(
                    &entry.path(),
                    &entry_name,
                    &roots,
                    &mut visited_packages,
                    &mut node_modules_queue,
                    &mut packages,
                )?;
            } else {
                collect_package(
                    &entry.path(),
                    &entry_name,
                    &roots,
                    &mut visited_packages,
                    &mut node_modules_queue,
                    &mut packages,
                )?;
            }
        }
    }

    Ok(packages)
}

fn collect_scope_packages(
    scope: &Path,
    scope_name: &str,
    roots: &PackageRoots,
    visited_packages: &mut HashSet<PathBuf>,
    node_modules_queue: &mut VecDeque<PathBuf>,
    packages: &mut Vec<InstalledPackage>,
) -> Result<(), LpmError> {
    let Some(scope) = canonicalize_scannable_directory(scope, roots)? else {
        return Ok(());
    };
    let entries = std::fs::read_dir(&scope).map_err(|error| {
        LpmError::Script(format!(
            "failed to read installed package scope {}: {error}",
            scope.display()
        ))
    })?;
    for entry in entries {
        let entry = entry.map_err(|error| {
            LpmError::Script(format!(
                "failed to enumerate installed package scope {}: {error}",
                lpm_common::sanitize_terminal_inline(&scope.display().to_string())
            ))
        })?;
        let package_name = format!("{scope_name}/{}", entry.file_name().to_string_lossy());
        collect_package(
            &entry.path(),
            &package_name,
            roots,
            visited_packages,
            node_modules_queue,
            packages,
        )?;
    }
    Ok(())
}

fn collect_package(
    package: &Path,
    fallback_name: &str,
    roots: &PackageRoots,
    visited_packages: &mut HashSet<PathBuf>,
    node_modules_queue: &mut VecDeque<PathBuf>,
    packages: &mut Vec<InstalledPackage>,
) -> Result<(), LpmError> {
    let Some(package) = canonicalize_scannable_directory(package, roots)? else {
        return Ok(());
    };
    if !visited_packages.insert(package.clone()) {
        return Ok(());
    }
    if packages.len() == AUDIT_SECRET_SCAN_MAX_PACKAGES {
        return Err(LpmError::Script(format!(
            "secret scan stopped at the {AUDIT_SECRET_SCAN_MAX_PACKAGES} package limit; no clean result was reported"
        )));
    }

    let name = package_display_name(&package).unwrap_or_else(|| fallback_name.to_string());
    packages.push(InstalledPackage {
        name,
        directory: package.clone(),
    });
    node_modules_queue.push_back(package.join("node_modules"));
    if let Some(containing_node_modules) = package.ancestors().skip(1).find(|ancestor| {
        ancestor
            .file_name()
            .is_some_and(|name| name == "node_modules")
    }) {
        node_modules_queue.push_back(containing_node_modules.to_path_buf());
    }
    Ok(())
}

fn canonicalize_scannable_directory(
    directory: &Path,
    roots: &PackageRoots,
) -> Result<Option<PathBuf>, LpmError> {
    let canonical = match directory.canonicalize() {
        Ok(canonical) => canonical,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(LpmError::Script(format!(
                "failed to resolve installed package path {}: {error}",
                lpm_common::sanitize_terminal_inline(&directory.display().to_string())
            )));
        }
    };
    if !canonical.is_dir() {
        return Ok(None);
    }
    if roots.allowed.iter().any(|root| canonical.starts_with(root)) {
        return Ok(Some(canonical));
    }
    if canonical.starts_with(&roots.project) {
        return Ok(None);
    }
    Err(LpmError::Script(format!(
        "refusing to scan an installed package link outside approved package roots: {}",
        lpm_common::sanitize_terminal_inline(&directory.display().to_string())
    )))
}

fn package_display_name(package: &Path) -> Option<String> {
    let manifest = lpm_common::read_text_file_capped(
        &package.join("package.json"),
        lpm_common::CONFIG_FILE_SIZE_CAP_BYTES,
    )
    .ok()?;
    serde_json::from_str::<serde_json::Value>(&manifest)
        .ok()?
        .get("name")?
        .as_str()
        .map(str::to_string)
}
