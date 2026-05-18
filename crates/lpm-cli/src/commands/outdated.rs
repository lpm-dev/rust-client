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
    let mut skipped_private: Vec<String> = Vec::new();

    for (name, range) in dep_entries {
        let metadata = if name.starts_with("@lpm.dev/") {
            let pkg_name = match PackageName::parse(name) {
                Ok(n) => n,
                Err(_) => continue,
            };
            client.get_package_metadata(&pkg_name).await
        } else if include_npm {
            // M15: only query the public npm registry for packages
            // whose lockfile source ALREADY routes through an npm
            // registry. Querying the public npm registry for a
            // package whose source is a workspace member, a `file:`
            // dir, a `link:` dep, a private git URL, or a custom
            // registry would leak the private package name to a
            // public service — a free dependency-confusion oracle
            // for typosquatters.
            //
            // No lockfile entry → no source attribution → refuse to
            // leak the name. The operator should run `lpm install`
            // first so the source is recorded, then re-run
            // `lpm outdated --include-npm`.
            if !lockfile_source_is_npm_public(lockfile.as_ref(), name) {
                skipped_private.push(name.clone());
                continue;
            }
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
        let mut json = serde_json::json!({
            "success": true,
            "packages": results,
            "count": results.len(),
            "outdated_count": outdated_count,
        });
        if !skipped_private.is_empty() {
            json.as_object_mut()
                .unwrap()
                .insert("skipped_private".into(), serde_json::json!(skipped_private));
            json.as_object_mut().unwrap().insert(
                "skipped_private_reason".into(),
                serde_json::json!(
                    "Packages without a recorded npm-public source were skipped to avoid leaking private names to registry.npmjs.org. Run `lpm install` to resolve sources, then re-run."
                ),
            );
        }
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
        if !skipped_private.is_empty() {
            output::warn(&format!(
                "skipped {} package(s) without a recorded npm-public source to avoid leaking private names to registry.npmjs.org: {}",
                skipped_private.len(),
                skipped_private.join(", "),
            ));
            output::info("run `lpm install` first to record sources in lpm.lock, then re-run.");
        }
        println!();
    }

    Ok(())
}

/// M15: returns `true` only when the lockfile entry for `name` exists
/// AND records a `registry+https://registry.npmjs.org` (or
/// `registry+https://registry.npmjs.com`) source. Used by the
/// `--include-npm` gate to refuse leaking private package names to
/// the public npm registry.
///
/// Private mirrors (Verdaccio, GitHub Packages, self-hosted Nexus,
/// etc.) explicitly do NOT count as "npm-public" here — those mirrors
/// host private code, so a name resolved against them shouldn't be
/// re-queried against the public npm. Only the actual public npm
/// origins pass this gate.
fn lockfile_source_is_npm_public(lockfile: Option<&lpm_lockfile::Lockfile>, name: &str) -> bool {
    let Some(lf) = lockfile else {
        return false;
    };
    let Some(pkg) = lf.find_package(name) else {
        return false;
    };
    match pkg.source_kind() {
        Some(Ok(lpm_lockfile::Source::Registry { url })) => is_public_npm_origin(&url),
        _ => false,
    }
}

fn is_public_npm_origin(url: &str) -> bool {
    let lower = url.trim_end_matches('/').to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "https://registry.npmjs.org" | "https://registry.npmjs.com"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// M15: every shape that resolves to the canonical public npm
    /// origin (with or without trailing slash, with the `.com` alias)
    /// passes the gate.
    #[test]
    fn public_npm_origin_recognises_canonical_shapes() {
        assert!(is_public_npm_origin("https://registry.npmjs.org"));
        assert!(is_public_npm_origin("https://registry.npmjs.org/"));
        assert!(is_public_npm_origin("https://registry.npmjs.com"));
        assert!(is_public_npm_origin("https://REGISTRY.NPMJS.ORG"));
    }

    /// M15: every other origin — private mirrors, GitHub Packages,
    /// self-hosted — is treated as "not public npm" so the
    /// `--include-npm` gate refuses to send the package name to the
    /// public registry.
    #[test]
    fn public_npm_origin_rejects_private_mirrors() {
        assert!(!is_public_npm_origin("https://npm.internal.example.com"));
        assert!(!is_public_npm_origin("https://npm.pkg.github.com"));
        assert!(!is_public_npm_origin("https://verdaccio.local"));
        assert!(!is_public_npm_origin("http://localhost:4873"));
        assert!(!is_public_npm_origin(""));
    }
}
