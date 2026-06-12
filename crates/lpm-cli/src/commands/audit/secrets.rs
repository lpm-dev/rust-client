use std::path::Path;

use lpm_common::LpmError;
use lpm_common::color::Painted;

use crate::install_ui;

use super::policy::FailPolicy;

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
