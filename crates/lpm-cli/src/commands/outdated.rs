use crate::install_ui;
use crate::manifest_dependency::ManifestDependencySpec;
use crate::npm_public_source::{NpmMetadataSource, lockfile_npm_metadata_source};
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

struct LookupFailure {
    name: String,
    section: &'static str,
    reason: String,
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

    let lockfile = lpm_lockfile::Lockfile::read_for_project(project_dir)
        .ok()
        .map(|project| project.lockfile);
    let release_age_policy = crate::release_age_selection::resolver_policy_for_project(
        project_dir,
        None,
        false,
        json_output,
    )?;

    dep_entries.sort_by(|left, right| {
        left.name
            .cmp(&right.name)
            .then_with(|| left.section.cmp(right.section))
    });

    let mut results = Vec::new();
    let mut lookup_failures = Vec::new();
    let mut skipped_private: BTreeSet<String> = BTreeSet::new();

    for dep in dep_entries {
        let (manifest_spec, version_range) =
            ManifestDependencySpec::from_manifest_value(&dep.name, &dep.range)?;
        let lookup_name = manifest_spec.lookup_name(&dep.name, lockfile.as_ref());
        let metadata = if lookup_name.starts_with("@lpm.dev/") {
            let pkg_name = PackageName::parse(&lookup_name).map_err(|error| {
                LpmError::Script(format!(
                    "invalid LPM dependency name `{}` (registry name `{lookup_name}`): {error}",
                    dep.name
                ))
            })?;
            client.get_package_metadata(&pkg_name).await
        } else if include_npm {
            // Only query metadata endpoints that the lockfile already
            // proves saw this package name: public npm directly, or the
            // configured LPM registry worker. Unknown/custom sources are
            // skipped so private package names are not disclosed to a new
            // service.
            match lockfile_npm_metadata_source(lockfile.as_ref(), &lookup_name, client) {
                Some(NpmMetadataSource::PublicNpm) => {
                    client.get_npm_package_metadata(&lookup_name).await
                }
                Some(NpmMetadataSource::ConfiguredRegistry) => {
                    client
                        .get_npm_package_metadata_proxy_only(&lookup_name)
                        .await
                }
                None => {
                    skipped_private.insert(dep.name.clone());
                    continue;
                }
            }
        } else {
            continue;
        };

        match metadata {
            Ok(metadata) => {
                let installed = lockfile.as_ref().and_then(|lockfile| {
                    lockfile
                        .find_package(&lookup_name)
                        .map(|package| package.version.clone())
                });
                let latest = crate::release_age_selection::latest_allowed_version(
                    &metadata,
                    &release_age_policy,
                )
                .or_else(|| installed.clone())
                .unwrap_or_else(|| {
                    metadata
                        .latest_version_tag()
                        .unwrap_or("unknown")
                        .to_string()
                });
                let wanted = crate::release_age_selection::resolve_version_spec_with_policy(
                    &metadata,
                    &version_range,
                    &release_age_policy,
                )
                .ok();

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
            Err(e) => {
                lookup_failures.push(LookupFailure {
                    name: dep.name,
                    section: dep.section,
                    reason: e.to_string(),
                });
            }
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
            "success": lookup_failures.is_empty(),
            "packages": package_json,
            "count": results.len(),
            "outdated_count": outdated_count,
        });
        if !lookup_failures.is_empty() {
            let unresolved_json: Vec<_> = lookup_failures
                .iter()
                .map(|failure| {
                    serde_json::json!({
                        "name": failure.name,
                        "section": failure.section,
                        "reason": failure.reason,
                    })
                })
                .collect();
            json.as_object_mut()
                .unwrap()
                .insert("unresolved".into(), serde_json::json!(unresolved_json));
            json.as_object_mut().unwrap().insert(
                "unresolved_count".into(),
                serde_json::json!(lookup_failures.len()),
            );
        }
        if !skipped_private.is_empty() {
            json.as_object_mut()
                .unwrap()
                .insert("skipped_private".into(), serde_json::json!(skipped_private));
            json.as_object_mut().unwrap().insert(
                "skipped_private_reason".into(),
                serde_json::json!(
                    "Packages without a recorded public npm or LPM-registry source were skipped to avoid leaking private names to registry.npmjs.org. Run `lpm install` to resolve sources, then re-run."
                ),
            );
        }
        println!("{}", serde_json::to_string_pretty(&json).unwrap());
        if !lookup_failures.is_empty() {
            return Err(LpmError::ExitCode(1));
        }
    } else {
        let outdated: Vec<_> = results.iter().filter(|result| result.outdated).collect();
        if outdated.is_empty() {
            let message = if include_npm {
                "All checked package.json dependency entries are up to date"
            } else {
                "All checked LPM dependency entries are up to date"
            };
            install_ui::done_untrusted(message);
        } else {
            let rendered = outdated
                .iter()
                .map(|result| {
                    let wanted = result.wanted.as_deref().unwrap_or("?");
                    (
                        *result,
                        lpm_common::sanitize_terminal_inline(&result.name),
                        lpm_common::sanitize_terminal_inline(&result.current),
                        lpm_common::sanitize_terminal_inline(wanted),
                    )
                })
                .collect::<Vec<_>>();
            let section_width = outdated
                .iter()
                .map(|result| result.section.len())
                .max()
                .unwrap_or(0)
                .max("Section".len());
            let package_width = rendered
                .iter()
                .map(|(_, name, _, _)| name.len())
                .max()
                .unwrap_or(0)
                .max("Package".len());
            let current_width = rendered
                .iter()
                .map(|(_, _, current, _)| current.len())
                .max()
                .unwrap_or(0)
                .max("Current".len());
            let wanted_width = rendered
                .iter()
                .map(|(_, _, _, wanted)| wanted.len())
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
            for (result, name, current, wanted) in rendered {
                println!(
                    "{:<section_width$}  {:<package_width$}  {:<current_width$}  {:<wanted_width$}  {}",
                    result.section.dimmed(),
                    name,
                    current.dimmed(),
                    install_ui::status_ok(&wanted),
                    style_latest_version(&result.latest, &wanted),
                );
            }
            println!();
            install_ui::done_untrusted(&format!(
                "Found {} outdated {}",
                outdated.len(),
                install_ui::packages_word(outdated.len()),
            ));
        }
        if !skipped_private.is_empty() {
            let skipped_private_list = skipped_private
                .iter()
                .map(|name| lpm_common::sanitize_terminal_inline(name).into_owned())
                .collect::<Vec<_>>();
            install_ui::warn_untrusted(&format!(
                "skipped {} package(s) without a recorded public npm or LPM-registry source to avoid leaking private names to registry.npmjs.org: {}",
                skipped_private.len(),
                skipped_private_list.join(", "),
            ));
            install_ui::phase("run `lpm install` first to record sources in lpm.lock, then re-run");
        }
        if !lookup_failures.is_empty() {
            install_ui::warn_untrusted(&format!(
                "could not check {} package(s) due to registry lookup failures",
                lookup_failures.len(),
            ));
            for failure in &lookup_failures {
                install_ui::detail_line(crate::install_ui::terminal_line!(
                    "  {} {}: {}",
                    install_ui::dim(failure.section),
                    lpm_common::sanitize_terminal_inline(&failure.name),
                    lpm_common::sanitize_terminal_inline(&failure.reason),
                ));
            }
            return Err(LpmError::ExitCode(1));
        }
    }

    Ok(())
}

fn style_latest_version(latest: &str, wanted: &str) -> String {
    let latest_major = lpm_semver::Version::parse(latest).ok().map(|v| v.major());
    let wanted_major = lpm_semver::Version::parse(wanted).ok().map(|v| v.major());
    let latest = lpm_common::sanitize_terminal_inline(latest);
    if matches!((wanted_major, latest_major), (Some(wanted), Some(latest)) if latest > wanted) {
        latest.red()
    } else {
        latest.yellow()
    }
}
