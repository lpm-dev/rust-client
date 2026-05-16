use crate::output;
use lpm_common::color::Painted;
use lpm_common::{LpmError, PackageName};
use lpm_registry::RegistryClient;
use std::path::Path;

/// Check for newer versions of installed dependencies.
pub async fn run(
    client: &RegistryClient,
    project_dir: &Path,
    json_output: bool,
    include_npm: bool,
) -> Result<(), LpmError> {
    let pkg_json_path = project_dir.join("package.json");
    if !pkg_json_path.exists() {
        return Err(LpmError::NotFound("no package.json found".into()));
    }

    let pkg = lpm_workspace::read_package_json(&pkg_json_path)
        .map_err(|e| LpmError::Registry(format!("failed to read package.json: {e}")))?;

    let deps = pkg.dependencies;
    if deps.is_empty() {
        if json_output {
            let json = serde_json::json!({
                "success": true,
                "packages": [],
                "count": 0,
                "outdated_count": 0,
            });
            println!("{}", serde_json::to_string_pretty(&json).unwrap());
        } else {
            output::info("No dependencies to check.");
        }
        return Ok(());
    }

    let lockfile_path = project_dir.join("lpm.lock");
    let lockfile = if lockfile_path.exists() {
        lpm_lockfile::Lockfile::read_fast(&lockfile_path).ok()
    } else {
        None
    };

    let mut dep_entries: Vec<_> = deps.iter().collect();
    dep_entries.sort_by(|(left, _), (right, _)| left.cmp(right));

    let mut results = Vec::new();

    for (name, range) in dep_entries {
        let metadata = if name.starts_with("@lpm.dev/") {
            let pkg_name = match PackageName::parse(name) {
                Ok(n) => n,
                Err(_) => continue,
            };
            client.get_package_metadata(&pkg_name).await
        } else if include_npm {
            client.get_npm_package_metadata(name).await
        } else {
            continue;
        };

        match metadata {
            Ok(metadata) => {
                let latest = metadata
                    .latest_version_tag()
                    .unwrap_or("unknown")
                    .to_string();

                let installed = lockfile
                    .as_ref()
                    .and_then(|lf| lf.find_package(name).map(|p| p.version.clone()));

                let installed_str = installed.as_deref().unwrap_or("?");
                let is_outdated = installed.as_deref() != Some(latest.as_str());

                results.push(serde_json::json!({
                    "name": name,
                    "current": installed_str,
                    "wanted": range,
                    "latest": latest,
                    "outdated": is_outdated,
                }));
            }
            Err(_) => continue,
        }
    }

    if json_output {
        let outdated_count = results.iter().filter(|r| r["outdated"] == true).count();
        let json = serde_json::json!({
            "success": true,
            "packages": results,
            "count": results.len(),
            "outdated_count": outdated_count,
        });
        println!("{}", serde_json::to_string_pretty(&json).unwrap());
    } else {
        let outdated: Vec<_> = results.iter().filter(|r| r["outdated"] == true).collect();
        if outdated.is_empty() {
            let message = if include_npm {
                "All checked package.json dependencies are up to date"
            } else {
                "All checked LPM dependencies are up to date"
            };
            output::success(message);
        } else {
            println!();
            println!(
                "  {:<40} {:<12} {:<12}",
                "Package".bold(),
                "Current".bold(),
                "Latest".bold()
            );
            for r in &outdated {
                println!(
                    "  {:<40} {:<12} {}",
                    r["name"].as_str().unwrap_or(""),
                    r["current"].as_str().unwrap_or("?").dimmed(),
                    r["latest"].as_str().unwrap_or("?").green(),
                );
            }
            println!();
            output::info(&format!("{} package(s) can be updated", outdated.len()));
        }
        println!();
    }

    Ok(())
}
