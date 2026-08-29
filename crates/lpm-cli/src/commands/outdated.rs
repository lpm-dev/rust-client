use crate::install_ui;
use crate::npm_public_source::{
    LockfileRootIndex, NpmMetadataSource, lockfile_npm_metadata_source,
    read_optional_project_lockfile,
};
use futures::StreamExt;
use lpm_common::color::Painted;
use lpm_common::{LpmError, PackageName};
use lpm_registry::{PackageMetadata, RegistryClient};
use lpm_resolver::specifier::Specifier;
use lpm_semver::Version;
use std::collections::{BTreeSet, HashMap};
use std::path::Path;
use std::sync::Arc;

const OUTDATED_JSON_SCHEMA_VERSION: u32 = 2;
const OUTDATED_METADATA_CONCURRENCY: usize = 4;
const MAX_LOOKUP_FAILURE_DETAIL_BYTES: usize = 2 * 1024;

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
    reason: Arc<str>,
}

type LookupOutcome = Result<OutdatedResult, LookupFailure>;

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
    let mut dep_entries = effective_manifest_dependencies(&pkg);

    if dep_entries.is_empty() {
        if json_output {
            let json = serde_json::json!({
                "schema_version": OUTDATED_JSON_SCHEMA_VERSION,
                "success": true,
                "packages": [],
                "count": 0,
                "outdated_count": 0,
            });
            println!("{}", serde_json::to_string_pretty(&json)?);
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
    let mut resolved_ranges = resolve_catalog_ranges(project_dir, &pkg, &dep_entries)?;

    let mut dependencies = Vec::with_capacity(dep_entries.len());
    let mut skipped_private: BTreeSet<String> = BTreeSet::new();
    let mut skipped_non_registry: BTreeSet<String> = BTreeSet::new();
    for dependency in dep_entries {
        let resolved_range = resolved_ranges.remove(&dependency.name).ok_or_else(|| {
            LpmError::Script(format!(
                "internal outdated planner error: no resolved manifest range for {}",
                dependency.name
            ))
        })?;
        if resolved_range.trim_start().starts_with("jsr:") {
            skipped_non_registry.insert(dependency.name);
            continue;
        }
        let parsed_specifier = Specifier::parse(&resolved_range).map_err(|error| {
            LpmError::Script(format!(
                "dependency `{}` uses invalid package specifier `{}`: {error}",
                dependency.name, dependency.range
            ))
        })?;
        let (lookup_name, version_range) = match parsed_specifier {
            Specifier::SemverRange(range) => (dependency.name.clone(), range),
            Specifier::NpmAlias { target, range } => (target, range),
            Specifier::Workspace(_)
            | Specifier::Tarball { .. }
            | Specifier::File { .. }
            | Specifier::Link { .. }
            | Specifier::Git { .. } => {
                skipped_non_registry.insert(dependency.name);
                continue;
            }
        };
        let route = if lookup_name.starts_with("@lpm.dev/") {
            PackageName::parse(&lookup_name).map_err(|error| {
                LpmError::InvalidPackageName(format!(
                    "invalid LPM dependency name `{}` (registry name `{lookup_name}`): {error}",
                    dependency.name
                ))
            })?;
            MetadataRoute::Lpm
        } else if include_npm {
            validate_registry_lookup_name(&dependency.name, &lookup_name)?;
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

    let mut job_indices: HashMap<(MetadataRoute, &str), usize> =
        HashMap::with_capacity(dependencies.len());
    let mut jobs: Vec<MetadataJob> = Vec::with_capacity(dependencies.len());
    for (dependency_index, dependency) in dependencies.iter().enumerate() {
        let key = (dependency.route, dependency.lookup_name.as_str());
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

    let mut outcomes: Vec<Option<LookupOutcome>> = std::iter::repeat_with(|| None)
        .take(dependencies.len())
        .collect();
    {
        let release_age_policy_ref = &release_age_policy;
        let fetches = futures::stream::iter(jobs.into_iter().map(|job| async move {
            let result = async {
                let mut metadata = fetch_metadata(client, job.route, &job.lookup_name).await?;
                let release_time_source = match job.route {
                    MetadataRoute::PublicNpm => {
                        crate::release_age_selection::ReleaseTimeMetadataSource::NpmDirect
                    }
                    MetadataRoute::Lpm | MetadataRoute::ConfiguredRegistry => {
                        crate::release_age_selection::ReleaseTimeMetadataSource::WorkerOnly
                    }
                };
                crate::release_age_selection::hydrate_release_times_if_needed(
                    client,
                    &mut metadata,
                    release_age_policy_ref,
                    release_time_source,
                )
                .await?;
                let allowed_versions = crate::release_age_selection::allowed_version_index(
                    &metadata,
                    release_age_policy_ref,
                )?;
                Ok::<_, LpmError>((metadata, allowed_versions))
            }
            .await;
            (job, result)
        }))
        .buffer_unordered(OUTDATED_METADATA_CONCURRENCY);
        futures::pin_mut!(fetches);

        while let Some((job, metadata_result)) = fetches.next().await {
            let (metadata, allowed_versions) = match metadata_result {
                Ok(result) => result,
                Err(error) => {
                    let reason: Arc<str> =
                        truncate_lookup_failure_detail(&error.to_string()).into();
                    for dependency_index in job.dependency_indices {
                        let dependency = &dependencies[dependency_index];
                        outcomes[dependency_index] = Some(Err(LookupFailure {
                            name: dependency.name.clone(),
                            section: dependency.section,
                            reason: Arc::clone(&reason),
                        }));
                    }
                    continue;
                }
            };

            for dependency_index in job.dependency_indices {
                let dependency = &dependencies[dependency_index];
                outcomes[dependency_index] = Some(
                    plan_outdated_result(
                        dependency,
                        &metadata,
                        &allowed_versions,
                        &roots,
                        &release_age_policy,
                    )
                    .map_err(|error| LookupFailure {
                        name: dependency.name.clone(),
                        section: dependency.section,
                        reason: truncate_lookup_failure_detail(&error.to_string()).into(),
                    }),
                );
            }
        }
    }

    let mut results = Vec::with_capacity(dependencies.len());
    let mut lookup_failures = Vec::new();
    for (dependency_index, outcome) in outcomes.into_iter().enumerate() {
        let outcome = outcome.ok_or_else(|| {
            LpmError::Registry(format!(
                "internal outdated planner error: no lookup outcome for {}",
                dependencies[dependency_index].name
            ))
        })?;
        match outcome {
            Ok(result) => results.push(result),
            Err(failure) => lookup_failures.push(failure),
        }
    }
    drop(job_indices);
    drop(roots);
    drop(lockfile);
    drop(dependencies);
    drop(release_age_policy);

    if json_output {
        let outdated_count = results.iter().filter(|result| result.outdated).count();
        let result_count = results.len();
        let package_json: Vec<_> = results
            .into_iter()
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
            "count": result_count,
            "outdated_count": outdated_count,
        });
        let lookup_failure_count = lookup_failures.len();
        let lookup_failed = lookup_failure_count != 0;
        let object = json.as_object_mut().ok_or_else(|| {
            LpmError::Json(serde_json::Error::io(std::io::Error::other(
                "outdated JSON envelope is not an object",
            )))
        })?;
        if lookup_failed {
            let unresolved_json: Vec<_> = lookup_failures
                .into_iter()
                .map(|failure| {
                    serde_json::json!({
                        "name": failure.name,
                        "section": failure.section,
                        "reason": failure.reason.as_ref(),
                    })
                })
                .collect();
            object.insert("unresolved".into(), serde_json::json!(unresolved_json));
            object.insert(
                "unresolved_count".into(),
                serde_json::json!(lookup_failure_count),
            );
            object.insert(
                "error".into(),
                serde_json::json!(format!(
                    "could not check {lookup_failure_count} package(s) due to registry lookup failures"
                )),
            );
            object.insert("error_code".into(), serde_json::json!("registry"));
        }
        if !skipped_private.is_empty() {
            object.insert(
                "skipped_private_count".into(),
                serde_json::json!(skipped_private.len()),
            );
            object.insert("skipped_private".into(), serde_json::json!(skipped_private));
            object.insert(
                "skipped_private_reason".into(),
                serde_json::json!(
                    "Packages without a recorded public npm or LPM-registry source were skipped to avoid leaking private names to registry.npmjs.org. Run `lpm install` to resolve sources, then re-run."
                ),
            );
        }
        if !skipped_non_registry.is_empty() {
            object.insert(
                "skipped_non_registry_count".into(),
                serde_json::json!(skipped_non_registry.len()),
            );
            object.insert(
                "skipped_non_registry".into(),
                serde_json::json!(skipped_non_registry),
            );
            object.insert(
                "skipped_non_registry_reason".into(),
                serde_json::json!(
                    "Local, workspace, Git, tarball, and JSR dependencies do not use registry version metadata and were skipped."
                ),
            );
        }
        println!("{}", serde_json::to_string_pretty(&json)?);
        if lookup_failed {
            return Err(LpmError::ExitCode(1));
        }
    } else {
        let outdated: Vec<_> = results.iter().filter(|result| result.outdated).collect();
        if outdated.is_empty() && lookup_failures.is_empty() {
            let message = if include_npm {
                "All checked package.json dependency entries are up to date"
            } else {
                "All checked LPM dependency entries are up to date"
            };
            install_ui::done_untrusted(message);
        } else if !outdated.is_empty() {
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
        if !skipped_non_registry.is_empty() {
            let skipped_non_registry_list = skipped_non_registry
                .iter()
                .map(|name| lpm_common::sanitize_terminal_inline(name).into_owned())
                .collect::<Vec<_>>();
            install_ui::warn_untrusted(&format!(
                "skipped {} local, workspace, Git, tarball, or JSR package(s): {}",
                skipped_non_registry.len(),
                skipped_non_registry_list.join(", "),
            ));
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

fn effective_manifest_dependencies(
    package: &lpm_workspace::PackageJson,
) -> Vec<ManifestDependencyEntry> {
    let capacity = package.dependencies.len()
        + package.dev_dependencies.len()
        + package.optional_dependencies.len();
    let mut entries = HashMap::with_capacity(capacity);
    entries.extend(package.dependencies.iter().map(|(name, range)| {
        (
            name.clone(),
            ManifestDependencyEntry {
                name: name.clone(),
                range: range.clone(),
                section: "dependencies",
            },
        )
    }));
    for (name, range) in &package.dev_dependencies {
        entries
            .entry(name.clone())
            .or_insert_with(|| ManifestDependencyEntry {
                name: name.clone(),
                range: range.clone(),
                section: "devDependencies",
            });
    }
    entries.extend(package.optional_dependencies.iter().map(|(name, range)| {
        (
            name.clone(),
            ManifestDependencyEntry {
                name: name.clone(),
                range: range.clone(),
                section: "optionalDependencies",
            },
        )
    }));
    entries.into_values().collect()
}

fn resolve_catalog_ranges(
    project_dir: &Path,
    package: &lpm_workspace::PackageJson,
    dependencies: &[ManifestDependencyEntry],
) -> Result<HashMap<String, String>, LpmError> {
    let mut ranges = dependencies
        .iter()
        .map(|dependency| (dependency.name.clone(), dependency.range.clone()))
        .collect::<HashMap<_, _>>();
    if !dependencies
        .iter()
        .any(|dependency| dependency.range.starts_with("catalog:"))
    {
        return Ok(ranges);
    }

    let workspace = crate::workspace_discovery_cache::discover_workspace(project_dir)
        .map_err(|error| LpmError::Workspace(format!("failed to discover catalogs: {error}")))?;
    let catalogs = workspace.as_deref().map_or(&package.catalogs, |workspace| {
        &workspace.root_package.catalogs
    });
    lpm_workspace::resolve_catalog_protocol(&mut ranges, catalogs)
        .map_err(|error| LpmError::Workspace(error.to_string()))?;
    Ok(ranges)
}

fn validate_registry_lookup_name(local_name: &str, lookup_name: &str) -> Result<(), LpmError> {
    lpm_lockfile::Lockfile::validate_package_name_and_version(lookup_name, "0.0.0").map_err(
        |error| {
            LpmError::InvalidPackageName(format!(
                "invalid npm dependency name `{lookup_name}` for `{local_name}`: {error}"
            ))
        },
    )
}

fn truncate_lookup_failure_detail(detail: &str) -> String {
    if detail.len() <= MAX_LOOKUP_FAILURE_DETAIL_BYTES {
        return detail.to_string();
    }
    let mut end = MAX_LOOKUP_FAILURE_DETAIL_BYTES;
    while !detail.is_char_boundary(end) {
        end -= 1;
    }
    let mut truncated = String::with_capacity(end + 32);
    truncated.push_str(&detail[..end]);
    truncated.push_str("… [remote detail truncated]");
    truncated
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
    allowed_versions: &crate::release_age_selection::AllowedVersionIndex,
    roots: &LockfileRootIndex<'_>,
    release_age_policy: &lpm_resolver::ResolverPolicy,
) -> Result<OutdatedResult, LpmError> {
    let installed = roots
        .root_package(&dependency.name, &dependency.lookup_name)
        .ok_or_else(|| {
            LpmError::Script(format!(
                "no installed root resolution for '{}' targeting '{}'; run `lpm install`, then re-run `lpm outdated`",
                dependency.name, dependency.lookup_name
            ))
        })?;
    let current = Version::parse(&installed.version).map_err(|error| {
        LpmError::Script(format!(
            "installed root '{}' has invalid version '{}': {error}",
            dependency.name, installed.version
        ))
    })?;
    let latest = allowed_versions.latest.clone();
    let latest_version = Version::parse(&latest).map_err(|error| {
        LpmError::Registry(format!(
            "registry selected invalid latest version '{}@{latest}': {error}",
            metadata.name
        ))
    })?;
    let wanted = match allowed_versions.resolve_spec(
        metadata,
        &dependency.version_range,
        release_age_policy,
    ) {
        Ok(wanted) => Some(wanted),
        Err(_)
            if Version::parse(&dependency.version_range).is_err()
                && latest_version < current
                && lpm_semver::VersionReq::parse(&dependency.version_range)
                    .is_ok_and(|requirement| requirement.matches(&current)) =>
        {
            Some(installed.version.clone())
        }
        Err(error) => return Err(error),
    };
    let outdated = latest_version > current;

    Ok(OutdatedResult {
        name: dependency.name.clone(),
        current: installed.version.clone(),
        wanted,
        wanted_range: dependency.manifest_range.clone(),
        latest,
        section: dependency.section,
        outdated,
    })
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
