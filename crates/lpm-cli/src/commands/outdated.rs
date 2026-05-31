use crate::install_ui;
use crate::npm_public_source::lockfile_source_is_npm_public;
use lpm_common::color::Painted;
use lpm_common::{LpmError, PackageName};
use lpm_registry::RegistryClient;
use std::collections::BTreeSet;
use std::path::Path;

const OUTDATED_JSON_SCHEMA_VERSION: u32 = 2;

struct DependencyEntry {
    name: String,
    range: String,
    section: &'static str,
}

struct OutdatedResult {
    name: String,
    current: String,
    wanted: Option<String>,
    wanted_range: String,
    latest: String,
    section: &'static str,
    outdated: bool,
}

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

    let mut dep_entries = Vec::with_capacity(pkg.dependencies.len() + pkg.dev_dependencies.len());
    for (name, range) in pkg.dependencies {
        dep_entries.push(DependencyEntry {
            name,
            range,
            section: "dependencies",
        });
    }
    for (name, range) in pkg.dev_dependencies {
        dep_entries.push(DependencyEntry {
            name,
            range,
            section: "devDependencies",
        });
    }

    if dep_entries.is_empty() {
        if json_output {
            let json = serde_json::json!({
                "schema_version": OUTDATED_JSON_SCHEMA_VERSION,
                "success": true,
                "packages": [],
                "count": 0,
                "outdated_count": 0,
            });
            println!("{}", serde_json::to_string_pretty(&json).unwrap());
        } else {
            install_ui::warn("No dependencies to check");
        }
        return Ok(());
    }

    let lockfile_path = project_dir.join("lpm.lock");
    let lockfile = if lockfile_path.exists() {
        lpm_lockfile::Lockfile::read_fast(&lockfile_path).ok()
    } else {
        None
    };

    dep_entries.sort_by(|left, right| {
        left.name
            .cmp(&right.name)
            .then_with(|| left.section.cmp(right.section))
    });

    let mut results = Vec::new();
    let mut skipped_private: BTreeSet<String> = BTreeSet::new();

    for dep in dep_entries {
        let metadata = if dep.name.starts_with("@lpm.dev/") {
            let pkg_name = match PackageName::parse(&dep.name) {
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
            if !lockfile_source_is_npm_public(lockfile.as_ref(), &dep.name) {
                skipped_private.insert(dep.name.clone());
                continue;
            }
            client.get_npm_package_metadata(&dep.name).await
        } else {
            continue;
        };

        match metadata {
            Ok(metadata) => {
                let latest = metadata
                    .latest_version_tag()
                    .unwrap_or("unknown")
                    .to_string();
                let wanted = metadata.resolve_version_spec(&dep.range).ok();

                let installed = lockfile
                    .as_ref()
                    .and_then(|lf| lf.find_package(&dep.name).map(|p| p.version.clone()));

                let installed_str = installed.as_deref().unwrap_or("?");
                let is_outdated = installed.as_deref() != Some(latest.as_str());

                results.push(OutdatedResult {
                    name: dep.name,
                    current: installed_str.to_string(),
                    wanted,
                    wanted_range: dep.range,
                    latest,
                    section: dep.section,
                    outdated: is_outdated,
                });
            }
            Err(_) => continue,
        }
    }

    if json_output {
        let outdated_count = results.iter().filter(|result| result.outdated).count();
        let package_json: Vec<_> = results
            .iter()
            .map(|result| {
                serde_json::json!({
                    "name": result.name,
                    "current": result.current,
                    "wanted": result.wanted,
                    "wanted_range": result.wanted_range,
                    "latest": result.latest,
                    "section": result.section,
                    "outdated": result.outdated,
                })
            })
            .collect();
        let mut json = serde_json::json!({
            "schema_version": OUTDATED_JSON_SCHEMA_VERSION,
            "success": true,
            "packages": package_json,
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
        let outdated: Vec<_> = results.iter().filter(|result| result.outdated).collect();
        if outdated.is_empty() {
            let message = if include_npm {
                "All checked package.json dependency entries are up to date"
            } else {
                "All checked LPM dependency entries are up to date"
            };
            install_ui::done(message);
        } else {
            let section_width = outdated
                .iter()
                .map(|result| result.section.len())
                .max()
                .unwrap_or(0)
                .max("Section".len());
            let package_width = outdated
                .iter()
                .map(|result| result.name.len())
                .max()
                .unwrap_or(0)
                .max("Package".len());
            let current_width = outdated
                .iter()
                .map(|result| result.current.len())
                .max()
                .unwrap_or(0)
                .max("Current".len());
            let wanted_width = outdated
                .iter()
                .map(|result| result.wanted.as_deref().unwrap_or("?").len())
                .max()
                .unwrap_or(0)
                .max("Wanted".len());

            println!(
                "{:<section_width$}  {:<package_width$}  {:<current_width$}  {:<wanted_width$}  {}",
                "Section".dimmed(),
                "Package".dimmed(),
                "Current".dimmed(),
                "Wanted".dimmed(),
                "Latest".dimmed()
            );
            for result in &outdated {
                let wanted = result.wanted.as_deref().unwrap_or("?");
                println!(
                    "{:<section_width$}  {:<package_width$}  {:<current_width$}  {:<wanted_width$}  {}",
                    result.section.dimmed(),
                    result.name,
                    result.current.dimmed(),
                    install_ui::status_ok(wanted),
                    style_latest_version(&result.latest, wanted),
                );
            }
            println!();
            install_ui::done(&format!(
                "Found {} outdated {}",
                outdated.len(),
                install_ui::packages_word(outdated.len()),
            ));
        }
        if !skipped_private.is_empty() {
            let skipped_private_list = skipped_private.iter().cloned().collect::<Vec<_>>();
            install_ui::warn(&format!(
                "skipped {} package(s) without a recorded npm-public source to avoid leaking private names to registry.npmjs.org: {}",
                skipped_private.len(),
                skipped_private_list.join(", "),
            ));
            install_ui::phase("run `lpm install` first to record sources in lpm.lock, then re-run");
        }
    }

    Ok(())
}

fn style_latest_version(latest: &str, wanted: &str) -> String {
    let latest_major = lpm_semver::Version::parse(latest).ok().map(|v| v.major());
    let wanted_major = lpm_semver::Version::parse(wanted).ok().map(|v| v.major());
    if matches!((wanted_major, latest_major), (Some(wanted), Some(latest)) if latest > wanted) {
        latest.red()
    } else {
        latest.yellow()
    }
}
