use crate::install_ui;
use crate::manifest_dependency::ManifestDependencySpec;
use crate::npm_public_source::{
    LockfileRootIndex, NpmMetadataSource, lockfile_npm_metadata_source,
    read_optional_project_lockfile,
};
use futures::StreamExt;
use lpm_common::color::Painted;
use lpm_common::{LpmError, PackageName};
use lpm_registry::{PackageMetadata, RegistryClient};
use lpm_semver::Version;
use std::collections::{BTreeSet, HashMap};
use std::path::Path;

const OUTDATED_JSON_SCHEMA_VERSION: u32 = 2;
const OUTDATED_METADATA_CONCURRENCY: usize = 4;

struct ManifestDependencyEntry {
    name: String,
    range: String,
    section: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum MetadataRoute {
    Lpm,
    PublicNpm,
    ConfiguredRegistry,
}

struct DependencyEntry {
    name: String,
    lookup_name: String,
    version_range: String,
    manifest_range: String,
    section: &'static str,
    route: MetadataRoute,
}

struct MetadataJob {
    lookup_name: String,
    route: MetadataRoute,
    dependency_indices: Vec<usize>,
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
        dep_entries.push(ManifestDependencyEntry {
            name,
            range,
            section: "dependencies",
        });
    }
    for (name, range) in pkg.dev_dependencies {
        dep_entries.push(ManifestDependencyEntry {
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

    let lockfile = read_optional_project_lockfile(project_dir)?;
    let roots = LockfileRootIndex::new(lockfile.as_ref());
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

    let mut dependencies = Vec::with_capacity(dep_entries.len());
    let mut skipped_private: BTreeSet<String> = BTreeSet::new();
    for dependency in dep_entries {
        let (manifest_spec, version_range) =
            ManifestDependencySpec::from_manifest_value(&dependency.name, &dependency.range)?;
        let lookup_name = manifest_spec.lookup_name(&dependency.name, lockfile.as_ref());
        let route = if lookup_name.starts_with("@lpm.dev/") {
            PackageName::parse(&lookup_name).map_err(|error| {
                LpmError::Script(format!(
                    "invalid LPM dependency name `{}` (registry name `{lookup_name}`): {error}",
                    dependency.name
                ))
            })?;
            MetadataRoute::Lpm
        } else if include_npm {
            match lockfile_npm_metadata_source(&roots, &dependency.name, &lookup_name, client) {
                Some(NpmMetadataSource::PublicNpm) => MetadataRoute::PublicNpm,
                Some(NpmMetadataSource::ConfiguredRegistry) => MetadataRoute::ConfiguredRegistry,
                None => {
                    skipped_private.insert(dependency.name);
                    continue;
                }
            }
        } else {
            continue;
        };
        dependencies.push(DependencyEntry {
            name: dependency.name,
            lookup_name,
            version_range,
            manifest_range: dependency.range,
            section: dependency.section,
            route,
        });
    }

    let mut job_indices: HashMap<(MetadataRoute, String), usize> =
        HashMap::with_capacity(dependencies.len());
    let mut jobs: Vec<MetadataJob> = Vec::with_capacity(dependencies.len());
    for (dependency_index, dependency) in dependencies.iter().enumerate() {
        let key = (dependency.route, dependency.lookup_name.clone());
        if let Some(job_index) = job_indices.get(&key).copied() {
            jobs[job_index].dependency_indices.push(dependency_index);
        } else {
            let job_index = jobs.len();
            job_indices.insert(key, job_index);
            jobs.push(MetadataJob {
                lookup_name: dependency.lookup_name.clone(),
                route: dependency.route,
                dependency_indices: vec![dependency_index],
            });
        }
    }

    let fetches = futures::stream::iter(jobs.into_iter().map(|job| async move {
        let result = fetch_metadata(client, job.route, &job.lookup_name).await;
        (job, result)
    }))
    .buffer_unordered(OUTDATED_METADATA_CONCURRENCY);
    futures::pin_mut!(fetches);

    let mut indexed_results = Vec::with_capacity(dependencies.len());
    let mut lookup_failures = Vec::new();
    while let Some((job, metadata_result)) = fetches.next().await {
        let mut metadata = match metadata_result {
            Ok(metadata) => metadata,
            Err(error) => {
                for dependency_index in job.dependency_indices {
                    let dependency = &dependencies[dependency_index];
                    lookup_failures.push((
                        dependency_index,
                        LookupFailure {
                            name: dependency.name.clone(),
                            section: dependency.section,
                            reason: error.to_string(),
                        },
                    ));
                }
                continue;
            }
        };
        let release_time_source = match job.route {
            MetadataRoute::PublicNpm => {
                crate::release_age_selection::ReleaseTimeMetadataSource::NpmDirect
            }
            MetadataRoute::Lpm | MetadataRoute::ConfiguredRegistry => {
                crate::release_age_selection::ReleaseTimeMetadataSource::WorkerOnly
            }
        };
        if let Err(error) = crate::release_age_selection::hydrate_release_times_if_needed(
            client,
            &mut metadata,
            &release_age_policy,
            release_time_source,
        )
        .await
        {
            for dependency_index in job.dependency_indices {
                let dependency = &dependencies[dependency_index];
                lookup_failures.push((
                    dependency_index,
                    LookupFailure {
                        name: dependency.name.clone(),
                        section: dependency.section,
                        reason: error.to_string(),
                    },
                ));
            }
            continue;
        }

        for dependency_index in job.dependency_indices {
            let dependency = &dependencies[dependency_index];
            match plan_outdated_result(dependency, &metadata, &roots, &release_age_policy) {
                Ok(result) => indexed_results.push((dependency_index, result)),
                Err(error) => lookup_failures.push((
                    dependency_index,
                    LookupFailure {
                        name: dependency.name.clone(),
                        section: dependency.section,
                        reason: error.to_string(),
                    },
                )),
            }
        }
    }

    indexed_results.sort_by_key(|(dependency_index, _)| *dependency_index);
    let results = indexed_results
        .into_iter()
        .map(|(_, result)| result)
        .collect::<Vec<_>>();
    lookup_failures.sort_by_key(|(dependency_index, _)| *dependency_index);
    let lookup_failures = lookup_failures
        .into_iter()
        .map(|(_, failure)| failure)
        .collect::<Vec<_>>();

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

async fn fetch_metadata(
    client: &RegistryClient,
    route: MetadataRoute,
    name: &str,
) -> Result<PackageMetadata, LpmError> {
    match route {
        MetadataRoute::Lpm => {
            let package = PackageName::parse(name).map_err(|error| {
                LpmError::Script(format!("invalid LPM dependency name `{name}`: {error}"))
            })?;
            client.get_package_metadata(&package).await
        }
        MetadataRoute::PublicNpm => client.get_npm_metadata_direct(name).await,
        MetadataRoute::ConfiguredRegistry => client.get_npm_package_metadata_proxy_only(name).await,
    }
}

fn plan_outdated_result(
    dependency: &DependencyEntry,
    metadata: &PackageMetadata,
    roots: &LockfileRootIndex<'_>,
    release_age_policy: &lpm_resolver::ResolverPolicy,
) -> Result<OutdatedResult, LpmError> {
    let installed = roots
        .root_package(&dependency.name, &dependency.lookup_name)
        .map(|package| package.version.clone());
    let allowed_versions =
        crate::release_age_selection::allowed_version_index(metadata, release_age_policy)?;
    let latest = allowed_versions.latest.clone();
    let wanted = allowed_versions
        .resolve_spec(metadata, &dependency.version_range, release_age_policy)
        .ok();
    let outdated = installed
        .as_deref()
        .is_some_and(|current| version_is_newer(current, &latest));

    Ok(OutdatedResult {
        name: dependency.name.clone(),
        current: installed.unwrap_or_else(|| "?".to_string()),
        wanted,
        wanted_range: dependency.manifest_range.clone(),
        latest,
        section: dependency.section,
        outdated,
    })
}

fn version_is_newer(current: &str, candidate: &str) -> bool {
    matches!(
        (Version::parse(current), Version::parse(candidate)),
        (Ok(current), Ok(candidate)) if candidate > current
    )
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
