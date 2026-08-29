use crate::install_ui;
use crate::manifest_dependency::ManifestDependencySpec;
use crate::npm_public_source::{
    LockfileRootIndex, NpmMetadataSource, lockfile_npm_metadata_source,
    read_optional_project_lockfile,
};
use crate::prompt::prompt_err;
#[cfg(test)]
use crate::upgrade_engine::PeerViolation;
use crate::upgrade_engine::{self, PatchInvalidation, PeerImpact, SemverClass};
use futures::StreamExt;
use lpm_common::color::Painted;
use lpm_common::{LpmError, PackageName};
use lpm_registry::PackageMetadata;
use lpm_registry::RegistryClient;
use lpm_resolver::specifier::Specifier;
use lpm_semver::{Version, VersionReq};
use std::collections::{BTreeSet, HashMap};
use std::io::IsTerminal;
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

const METADATA_PLANNING_CONCURRENCY: usize = 4;
const MAX_METADATA_FAILURE_DETAIL_BYTES: usize = 2 * 1024;
const MAX_METADATA_FAILURE_NAMES: usize = 8;
const MAX_METADATA_FAILURES_MESSAGE_BYTES: usize = 16 * 1024;

// ── Mode resolution ─────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ResolvedMode {
    Interactive,
    NonInteractive,
}

fn resolve_mode(
    interactive: bool,
    yes: bool,
    json_output: bool,
    is_tty: bool,
) -> Result<ResolvedMode, LpmError> {
    if interactive && yes {
        return Err(LpmError::Script(
            "`-i` and `-y` are mutually exclusive \
			 (one forces interactive, the other forces non-interactive)"
                .into(),
        ));
    }
    if interactive && json_output {
        return Err(LpmError::Script(
            "`-i` cannot be combined with `--json` — \
			 interactive prompts cannot render structured output"
                .into(),
        ));
    }
    if yes || json_output {
        return Ok(ResolvedMode::NonInteractive);
    }
    if interactive {
        return Ok(ResolvedMode::Interactive);
    }
    if is_tty {
        Ok(ResolvedMode::Interactive)
    } else {
        Ok(ResolvedMode::NonInteractive)
    }
}

fn validate_major_for_mode(major: bool, mode: ResolvedMode) -> Result<(), LpmError> {
    if major && mode == ResolvedMode::Interactive {
        return Err(LpmError::Script(
            "`--major` cannot be combined with interactive mode. \
			 In interactive mode, major upgrades appear as separate rows \
			 alongside the safe within-major option — toggle them on individually. \
			 Pass `-y --major` for batch behavior, or just `lpm upgrade` \
			 and select the MAJOR rows you want."
                .into(),
        ));
    }
    Ok(())
}

// ── Candidate types ─────────────────────────────────────────────────

/// Distinguishes the two rows a single package can produce in interactive
/// mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TargetKind {
    WithinMajor,
    AbsoluteLatest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum MetadataRoute {
    Lpm,
    PublicNpm,
    ConfiguredRegistry,
}

impl MetadataRoute {
    fn upstream_route(self) -> lpm_registry::UpstreamRoute {
        match self {
            Self::PublicNpm => lpm_registry::UpstreamRoute::NpmDirect,
            Self::Lpm | Self::ConfiguredRegistry => lpm_registry::UpstreamRoute::LpmWorker,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum DependencyKind {
    Runtime,
    Development,
    Optional,
}

impl DependencyKind {
    fn manifest_key(self) -> &'static str {
        match self {
            Self::Runtime => "dependencies",
            Self::Development => "devDependencies",
            Self::Optional => "optionalDependencies",
        }
    }

    fn is_dev(self) -> bool {
        self == Self::Development
    }
}

#[derive(Debug, Clone)]
struct UpgradeDependency {
    name: String,
    lookup_name: String,
    range: String,
    manifest_value: String,
    dependency_kind: DependencyKind,
    route: MetadataRoute,
    manifest_spec: ManifestDependencySpec,
}

struct MetadataJob {
    route: MetadataRoute,
    lookup_name: String,
    dependency_indices: Vec<usize>,
}

/// enriched candidate — drives both the interactive multiselect
/// and the JSON output.
#[derive(Clone)]
struct EnrichedCandidate {
    name: String,
    from: String,
    current_range: String,
    new_range: String,
    to: String,
    dependency_kind: DependencyKind,
    target_kind: TargetKind,
    semver_class: SemverClass,
    has_install_scripts: bool,
    peer_impact: PeerImpact,
    patch_invalidation: Option<PatchInvalidation>,
    lookup_name: String,
    route: MetadataRoute,
    selected_metadata: Arc<PackageMetadata>,
}

// ── Entry point ─────────────────────────────────────────────────────

/// Upgrade outdated LPM dependencies to their latest versions.
///
/// TTY-aware interactive mode with enrichment.
#[allow(clippy::too_many_arguments)]
pub async fn run(
    client: &RegistryClient,
    project_dir: &Path,
    requested_packages: &[String],
    major: bool,
    dry_run: bool,
    interactive: bool,
    yes: bool,
    json_output: bool,
) -> Result<(), LpmError> {
    let started_at = Instant::now();
    let pkg_json_path = project_dir.join("package.json");
    let original_content = match lpm_common::read_text_file_capped(
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
    let mut doc: serde_json::Value =
        serde_json::from_str(lpm_common::strip_utf8_bom_str(&original_content))
            .map_err(|e| LpmError::Script(format!("failed to parse package.json: {e}")))?;
    let package_json = lpm_workspace::package_json_from_value(&doc)
        .map_err(|error| LpmError::Script(format!("failed to parse package.json: {error}")))?;
    let patched_deps = package_json
        .lpm
        .as_ref()
        .map(|config| config.patched_dependencies.clone())
        .unwrap_or_default();
    let empty_overrides = HashMap::new();
    let overrides = lpm_resolver::OverrideSet::parse(
        package_json
            .lpm
            .as_ref()
            .map_or(&empty_overrides, |config| &config.overrides),
        &package_json.overrides,
        &package_json.resolutions,
    )
    .map_err(|error| LpmError::Script(format!("failed to parse package overrides: {error}")))?;

    // Resolve mode + validate flag combinations
    let is_tty = std::io::stdin().is_terminal() && std::io::stdout().is_terminal();
    let mode = resolve_mode(interactive, yes, json_output, is_tty)?;
    validate_major_for_mode(major, mode)?;
    let release_age_policy = crate::release_age_selection::resolver_policy_for_project(
        project_dir,
        None,
        false,
        json_output,
    )?;
    let planning_client = client.clone_with_config().without_metadata_memory_cache();
    let install_client = client.clone_with_metadata_memory_cache();

    // Read lockfile ONCE
    let lockfile = read_optional_project_lockfile(project_dir)?;
    let roots = LockfileRootIndex::new(lockfile.as_ref());

    let mut skipped_private: Vec<String> = Vec::new();
    let mut skipped_non_registry: Vec<String> = Vec::new();
    let all_deps = filter_requested_deps(extract_deps_from_value(&doc), requested_packages)?;
    let mut upgradeable_deps = Vec::with_capacity(all_deps.len());
    for (name, manifest_value, dependency_kind) in all_deps {
        let parsed_specifier = Specifier::parse(&manifest_value).map_err(|error| {
            LpmError::Script(format!(
                "dependency `{name}` uses invalid package specifier `{manifest_value}`: {error}"
            ))
        })?;
        if manifest_value.trim_start().starts_with("jsr:")
            || matches!(
                parsed_specifier,
                Specifier::Workspace(_)
                    | Specifier::Tarball { .. }
                    | Specifier::File { .. }
                    | Specifier::Link { .. }
                    | Specifier::Git { .. }
            )
        {
            skipped_non_registry.push(name);
            continue;
        }
        let (manifest_spec, range) =
            ManifestDependencySpec::from_manifest_value(&name, &manifest_value)?;
        let range = range.trim().to_string();
        let lookup_name = match &manifest_spec {
            ManifestDependencySpec::Plain => name.clone(),
            ManifestDependencySpec::NpmAlias { target } => target.clone(),
        };

        if lookup_name.starts_with("@lpm.dev/") {
            PackageName::parse(&lookup_name).map_err(|error| {
                LpmError::Script(format!(
                    "invalid LPM dependency name `{name}` (registry name `{lookup_name}`): {error}"
                ))
            })?;
            upgradeable_deps.push(UpgradeDependency {
                name,
                lookup_name,
                range,
                manifest_value,
                dependency_kind,
                route: MetadataRoute::Lpm,
                manifest_spec,
            });
            continue;
        }

        if let Some(source) = lockfile_npm_metadata_source(&roots, &name, &lookup_name, client) {
            upgradeable_deps.push(UpgradeDependency {
                name,
                lookup_name,
                range,
                manifest_value,
                dependency_kind,
                route: match source {
                    NpmMetadataSource::PublicNpm => MetadataRoute::PublicNpm,
                    NpmMetadataSource::ConfiguredRegistry => MetadataRoute::ConfiguredRegistry,
                },
                manifest_spec,
            });
            continue;
        }

        skipped_private.push(name);
    }
    skipped_private.sort();
    skipped_non_registry.sort();

    if !requested_packages.is_empty() && !skipped_non_registry.is_empty() {
        return Err(LpmError::Script(format!(
            "cannot upgrade requested non-registry package(s): {}. Update the local, git, tarball, workspace, or JSR spec directly in package.json.",
            skipped_non_registry.join(", ")
        )));
    }
    if !requested_packages.is_empty() && !skipped_private.is_empty() {
        return Err(LpmError::Script(format!(
            "cannot upgrade requested package(s) without a recorded public npm or LPM-registry source: {}. Run `lpm install` to record sources in lpm.lock, then re-run.",
            skipped_private.join(", ")
        )));
    }

    if !json_output {
        install_ui::phase("Checking dependencies for newer matching versions");
    }

    let mut job_indices: HashMap<(MetadataRoute, String), usize> =
        HashMap::with_capacity(upgradeable_deps.len());
    let mut jobs: Vec<MetadataJob> = Vec::with_capacity(upgradeable_deps.len());
    for (dependency_index, dependency) in upgradeable_deps.iter().enumerate() {
        let key = (dependency.route, dependency.lookup_name.clone());
        if let Some(job_index) = job_indices.get(&key).copied() {
            jobs[job_index].dependency_indices.push(dependency_index);
        } else {
            let job_index = jobs.len();
            job_indices.insert(key, job_index);
            jobs.push(MetadataJob {
                route: dependency.route,
                lookup_name: dependency.lookup_name.clone(),
                dependency_indices: vec![dependency_index],
            });
        }
    }

    let planning_client_ref = &planning_client;
    let release_age_policy_ref = &release_age_policy;
    let fetches = futures::stream::iter(jobs.into_iter().map(move |job| async move {
        let result = async {
            let mut metadata =
                fetch_metadata(planning_client_ref, job.route, &job.lookup_name).await?;
            let release_time_source = match job.route {
                MetadataRoute::PublicNpm => {
                    crate::release_age_selection::ReleaseTimeMetadataSource::NpmDirect
                }
                MetadataRoute::Lpm | MetadataRoute::ConfiguredRegistry => {
                    crate::release_age_selection::ReleaseTimeMetadataSource::WorkerOnly
                }
            };
            crate::release_age_selection::hydrate_release_times_if_needed(
                planning_client_ref,
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
    .buffer_unordered(METADATA_PLANNING_CONCURRENCY);
    futures::pin_mut!(fetches);

    let mut candidates = Vec::with_capacity(upgradeable_deps.len());
    let mut fetch_failures: Vec<(usize, usize, String)> = Vec::new();
    while let Some((job, metadata_result)) = fetches.next().await {
        let (metadata, allowed_versions) = match metadata_result {
            Ok(result) => result,
            Err(error) => {
                let Some(&first_dependency_index) = job.dependency_indices.first() else {
                    return Err(LpmError::Registry(format!(
                        "internal upgrade planner error: metadata job for {} has no dependencies",
                        job.lookup_name
                    )));
                };
                let affected_count = job.dependency_indices.len();
                let package_names =
                    bounded_dependency_name_list(&job.dependency_indices, &upgradeable_deps);
                let detail = truncate_metadata_failure_detail(&error.to_string());
                tracing::warn!(
                    "failed to fetch metadata for {} via {}: {}",
                    package_names,
                    job.lookup_name,
                    detail
                );
                fetch_failures.push((
                    first_dependency_index,
                    affected_count,
                    format!("{package_names}: {detail}"),
                ));
                continue;
            }
        };

        for dependency_index in job.dependency_indices {
            let dependency = &upgradeable_deps[dependency_index];
            match plan_upgrade_dependency(
                dependency,
                &metadata,
                &allowed_versions,
                mode,
                major,
                &release_age_policy,
                &roots,
                &patched_deps,
                &overrides,
            ) {
                Ok(planned) => candidates.extend(planned),
                Err(error) => fetch_failures.push((
                    dependency_index,
                    1,
                    format!(
                        "{}: {}",
                        dependency.name,
                        truncate_metadata_failure_detail(&error.to_string())
                    ),
                )),
            }
        }
    }

    if !fetch_failures.is_empty() {
        fetch_failures.sort_by_key(|(dependency_index, _, _)| *dependency_index);
        let affected_count = fetch_failures
            .iter()
            .map(|(_, affected_count, _)| affected_count)
            .sum::<usize>();
        let messages = join_bounded_metadata_failures(&fetch_failures);
        return Err(LpmError::Registry(format!(
            "could not determine upgrade status for {} package(s): {}",
            affected_count, messages
        )));
    }
    let fetch_errors = 0;

    // Sort for deterministic output
    candidates.sort_by(|a, b| {
        a.name.cmp(&b.name).then(a.to.cmp(&b.to)) // within-major first since it's lower
    });

    if candidates.is_empty() {
        if json_output {
            emit_upgrade_json(
                &[],
                dry_run,
                fetch_errors,
                &skipped_private,
                &skipped_non_registry,
            )?;
        } else {
            let message = if requested_packages.is_empty() {
                "All checked package.json dependencies are up to date"
            } else {
                "All requested package.json dependencies are up to date"
            };
            install_ui::done_untrusted(message);
            warn_skipped_private(&skipped_private);
            warn_skipped_non_registry(&skipped_non_registry);
        }
        return Ok(());
    }

    // ── Selection ───────────────────────────────────────────────────

    let selected = match mode {
        ResolvedMode::NonInteractive => candidates,
        ResolvedMode::Interactive => {
            let selection = select_candidates_interactively(&candidates)?;
            if selection.is_empty() {
                install_ui::phase("No packages selected. package.json is unchanged.");
                return Ok(());
            }
            selection
        }
    };

    // Deduplicate: if both within-major and absolute-latest rows were
    // selected for the same package, take the highest target version.
    let deduped = deduplicate_by_highest_target(selected);

    // ── Display + dry-run gate ──────────────────────────────────────

    if json_output {
        if dry_run {
            emit_upgrade_json(
                &deduped,
                true,
                fetch_errors,
                &skipped_private,
                &skipped_non_registry,
            )?;
            return Ok(());
        }
    } else {
        install_ui::phase_untrusted(&format!(
            "Upgrading {} {}",
            deduped.len(),
            install_ui::packages_word(deduped.len())
        ));
        for u in &deduped {
            let dev_tag = match u.dependency_kind {
                DependencyKind::Development => " (dev)",
                DependencyKind::Optional => " (optional)",
                DependencyKind::Runtime => "",
            };
            let glyph = format_upgrade_glyph(u.semver_class);
            let safe_name = lpm_common::sanitize_terminal_inline(&u.name);
            let safe_from = lpm_common::sanitize_terminal_inline(&u.from);
            let safe_to = lpm_common::sanitize_terminal_inline(&u.to);
            let name = format!("{safe_name:<24}").bold();
            let from = format!("{safe_from:>8}").dimmed();
            let arrow = "→".dimmed();
            let to = format!("{safe_to:<8}").yellow();
            let class_label = format_class_label(u.semver_class);
            let hint = format_candidate_hint(u);
            let hint_suffix = if hint.is_empty() {
                String::new()
            } else {
                format!("  {}", hint.dimmed())
            };
            eprintln!(
                "{glyph} {name} {from} {arrow} {to} {class_label}{}{}",
                dev_tag.dimmed(),
                hint_suffix,
            );
        }

        if dry_run {
            install_ui::done_untrusted(&format!(
                "Done · would upgrade {} {} (dry run)",
                deduped.len(),
                install_ui::packages_word(deduped.len())
            ));
            warn_skipped_private(&skipped_private);
            warn_skipped_non_registry(&skipped_non_registry);
            return Ok(());
        }
    }

    seed_selected_metadata_for_install(&install_client, &deduped)?;

    // ── Mutate package.json ─────────────────────────────────────────

    apply_upgrades_to_manifest(&mut doc, &deduped)?;
    let mut updated_content = serde_json::to_string_pretty(&doc)
        .map_err(|e| LpmError::Script(format!("failed to serialize package.json: {e}")))?;
    updated_content.push('\n');
    let project_dirs = [project_dir.to_path_buf()];
    let install_result =
        crate::commands::install::workspace_lockfile::scope_workspace_mutation_if_present(
            project_dir,
            &project_dirs,
            async {
                if !crate::commands::install::workspace_lockfile::project_lockfile_unchanged(
                    project_dir,
                    lockfile.as_ref(),
                )
                .map_err(|error| {
                    LpmError::Script(format!(
                        "failed to re-read lpm.lock before applying upgrades: {error}"
                    ))
                })? {
                    return Err(LpmError::Script(
                        "lpm.lock changed while upgrades were being planned; no changes were applied"
                            .into(),
                    ));
                }

                let lockfile_path =
                    crate::commands::install::workspace_lockfile::active_lockfile_path(project_dir);
                let lockfile_binary_path = lockfile_path.with_extension("lockb");
                let install_hash_path = project_dir.join(".lpm").join("install-hash");
                let mut transaction =
                    crate::manifest_tx::ManifestTransaction::snapshot_install_state_if_unchanged(
                        &[(pkg_json_path.as_path(), original_content.as_bytes())],
                        &[lockfile_path.as_path(), lockfile_binary_path.as_path()],
                        &[install_hash_path.as_path()],
                    )
                    .map_err(|error| {
                        LpmError::Script(format!(
                            "package.json changed while upgrades were being planned; no changes were applied: {error}"
                        ))
                    })?;
                transaction
                    .restore_only_if_unchanged(&pkg_json_path, updated_content.as_bytes())
                    .map_err(|error| {
                        LpmError::Script(format!(
                            "failed to protect package.json from concurrent edits: {error}"
                        ))
                    })?;

                lpm_common::write_file_atomic(&pkg_json_path, &updated_content)
                    .map_err(|e| LpmError::Script(format!("failed to write package.json: {e}")))?;

                crate::commands::root_lifecycle::RootProjectLifecycle::load(project_dir)?
                    .run_dev_preinstall(project_dir, json_output)?;

                if !json_output {
                    install_ui::phase("Installing upgraded dependencies");
                }

                if !crate::commands::install::workspace_lockfile::mutation_active() {
                    remove_optional_file(&lockfile_path)?;
                    remove_optional_file(&lockfile_binary_path)?;
                }

                let lpm_root = lpm_common::LpmRoot::from_env()?;
                let install_result = crate::commands::install::run_with_options_with_lpm_root(
                    &install_client,
                    project_dir,
                    json_output,
                    false, // offline
                    crate::commands::install::FrozenLockfileMode::Never,
                    false, // force
                    false, // allow_new
                    false, // strict_integrity
                    false, // no_engine_strict
                    None,  // strict_peer_dependencies_override
                    None,  // linker_override
                    crate::lpm_skills_config::LpmSkillsPreference::Config,
                    false, // no_editor_setup
                    false, // no_security_summary
                    false, // auto_build
                    None,  // target_set
                    None,  // direct_versions_out
                    None,  // requested_add_count: upgrade is not an add-path install
                    None,  // script_policy_override: `lpm upgrade` does not expose policy flags
                    None,  // advisor_override: `lpm upgrade` does not expose `--advisor`
                    None,  // min_release_age_override: `lpm upgrade` uses the chain
                    &[],
                    crate::provenance_fetch::DriftIgnorePolicy::default(),
                    crate::provenance_fetch::VerifyPolicy::resolve_no_cli(),
                    crate::commands::install::InstallOmitPolicy::default(),
                    false, // strict_sandbox
                    false, // no_sandbox
                    false, // verbose: internal pipeline, no user-facing Done footer
                    false, // audit_after_install: internal pipeline never runs audit
                    false, // timing: upgrade does not expose install's --timing flag
                    &[],
                    !json_output,
                    false,
                    None,
                    lpm_root,
                )
                .await;
                if let Err(error) = install_result {
                    if !json_output {
                        install_ui::warn("install failed — restored original package.json");
                    }
                    return Err(error);
                }

                crate::commands::root_lifecycle::RootProjectLifecycle::load(project_dir)?
                    .run_after_successful_install(project_dir, json_output)?;

                crate::commands::install::workspace_lockfile::commit_manifest_transaction_checked(
                    transaction,
                )?;
                Ok(())
            },
        )
        .await;

    install_result?;

    if json_output {
        emit_upgrade_json(
            &deduped,
            false,
            fetch_errors,
            &skipped_private,
            &skipped_non_registry,
        )?;
    } else {
        install_ui::done("Updated package.json, lpm.lock, node_modules");
        install_ui::done_untrusted(&format!(
            "Done · upgraded {} {} in {}",
            deduped.len(),
            install_ui::packages_word(deduped.len()),
            install_ui::format_duration(started_at.elapsed())
        ));
        warn_skipped_private(&skipped_private);
        warn_skipped_non_registry(&skipped_non_registry);
    }

    Ok(())
}

fn seed_selected_metadata_for_install(
    client: &RegistryClient,
    candidates: &[EnrichedCandidate],
) -> Result<(), LpmError> {
    let mut metadata_by_route: HashMap<(MetadataRoute, String), Arc<PackageMetadata>> =
        HashMap::with_capacity(candidates.len());
    for candidate in candidates {
        let key = (candidate.route, candidate.lookup_name.clone());
        match metadata_by_route.entry(key) {
            std::collections::hash_map::Entry::Vacant(entry) => {
                entry.insert(Arc::clone(&candidate.selected_metadata));
            }
            std::collections::hash_map::Entry::Occupied(mut entry) => {
                if !Arc::ptr_eq(entry.get(), &candidate.selected_metadata) {
                    merge_selected_metadata(
                        Arc::make_mut(entry.get_mut()),
                        &candidate.selected_metadata,
                    );
                }
            }
        }
    }

    for ((route, name), metadata) in metadata_by_route {
        if !client.seed_metadata_for_command(&name, &route.upstream_route(), metadata) {
            return Err(LpmError::Registry(format!(
                "failed to retain validated upgrade metadata for '{name}'"
            )));
        }
    }
    Ok(())
}

fn merge_selected_metadata(existing: &mut PackageMetadata, incoming: &PackageMetadata) {
    existing.versions.extend(incoming.versions.clone());
    existing.time.extend(incoming.time.clone());
    for (tag, version) in &incoming.dist_tags {
        let replace = existing.dist_tags.get(tag).is_none_or(|current| {
            match (Version::parse(version), Version::parse(current)) {
                (Ok(candidate), Ok(current)) => candidate > current,
                _ => version > current,
            }
        });
        if replace {
            existing.dist_tags.insert(tag.clone(), version.clone());
        }
    }
    existing.latest_version = existing.dist_tags.get("latest").cloned();
}

fn remove_optional_file(path: &Path) -> Result<(), LpmError> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(LpmError::Script(format!(
            "failed to remove {}: {err}",
            path.display()
        ))),
    }
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
            client
                .revalidate_package_metadata_with_timings(&package)
                .await
                .map(|result| result.metadata)
        }
        MetadataRoute::PublicNpm => client
            .revalidate_npm_metadata_direct_with_timings(name)
            .await
            .map(|result| result.metadata),
        MetadataRoute::ConfiguredRegistry => {
            client
                .revalidate_npm_package_metadata_proxy_only(name)
                .await
        }
    }
}

fn bounded_dependency_name_list(
    dependency_indices: &[usize],
    dependencies: &[UpgradeDependency],
) -> String {
    let shown = dependency_indices.len().min(MAX_METADATA_FAILURE_NAMES);
    let mut names = dependency_indices[..shown]
        .iter()
        .map(|index| dependencies[*index].name.as_str())
        .collect::<Vec<_>>()
        .join(", ");
    let omitted = dependency_indices.len() - shown;
    if omitted != 0 {
        names.push_str(&format!(", … and {omitted} more"));
    }
    names
}

fn truncate_metadata_failure_detail(detail: &str) -> String {
    if detail.len() <= MAX_METADATA_FAILURE_DETAIL_BYTES {
        return detail.to_string();
    }
    let mut end = MAX_METADATA_FAILURE_DETAIL_BYTES;
    while !detail.is_char_boundary(end) {
        end -= 1;
    }
    let mut truncated = String::with_capacity(end + 32);
    truncated.push_str(&detail[..end]);
    truncated.push_str("… [remote detail truncated]");
    truncated
}

fn join_bounded_metadata_failures(failures: &[(usize, usize, String)]) -> String {
    let mut joined = String::with_capacity(MAX_METADATA_FAILURES_MESSAGE_BYTES);
    for (position, (_, _, message)) in failures.iter().enumerate() {
        let separator_len = usize::from(position != 0) * 2;
        if joined
            .len()
            .saturating_add(separator_len)
            .saturating_add(message.len())
            > MAX_METADATA_FAILURES_MESSAGE_BYTES.saturating_sub(64)
        {
            let omitted = failures.len() - position;
            joined.push_str(&format!(
                "; … {omitted} additional metadata failure(s) omitted"
            ));
            break;
        }
        if position != 0 {
            joined.push_str("; ");
        }
        joined.push_str(message);
    }
    joined
}

#[allow(clippy::too_many_arguments)]
fn plan_upgrade_dependency(
    dependency: &UpgradeDependency,
    metadata: &PackageMetadata,
    allowed_versions: &crate::release_age_selection::AllowedVersionIndex,
    mode: ResolvedMode,
    major: bool,
    release_age_policy: &lpm_resolver::ResolverPolicy,
    roots: &LockfileRootIndex<'_>,
    patched_dependencies: &HashMap<String, lpm_workspace::PatchedDependencyEntry>,
    overrides: &lpm_resolver::OverrideSet,
) -> Result<Vec<EnrichedCandidate>, LpmError> {
    let latest = &allowed_versions.latest;
    if !is_valid_version_string(latest) {
        return Err(LpmError::Registry(format!(
            "registry returned invalid version string {latest:?} for '{}'",
            dependency.lookup_name
        )));
    }

    let installed_version = roots
        .root_package(&dependency.name, &dependency.lookup_name)
        .map(|package| package.version.as_str());
    let from =
        installed_version.map_or_else(|| version_from_range(&dependency.range), str::to_string);

    let build_candidate = |target_version: String,
                           new_range: String,
                           target_kind: TargetKind,
                           required_dist_tag: Option<&str>|
     -> Result<Option<EnrichedCandidate>, LpmError> {
        let natural_version =
            lpm_resolver::NpmVersion::parse(&target_version).map_err(|error| {
                LpmError::Registry(format!(
                    "registry selected invalid version '{}@{target_version}': {error}",
                    metadata.name
                ))
            })?;
        if overrides
            .find_match(&dependency.lookup_name, &natural_version, None)
            .is_some()
        {
            return Ok(None);
        }
        let target = metadata.version(&target_version).ok_or_else(|| {
            LpmError::Registry(format!(
                "registry selected missing version '{}@{target_version}'",
                metadata.name
            ))
        })?;
        let peer_impact = upgrade_engine::compute_peer_impact(
            &target.peer_dependencies,
            &target.peer_dependencies_meta,
            |peer_name| {
                roots
                    .root_package(peer_name, peer_name)
                    .map(|package| package.version.as_str())
            },
        );
        let patch_invalidation = upgrade_engine::detect_patch_invalidation(
            patched_dependencies,
            &dependency.lookup_name,
            installed_version.unwrap_or("0.0.0"),
            &target_version,
        );
        let selected_metadata = Arc::new(compact_metadata_for_version(
            metadata,
            &target_version,
            required_dist_tag,
        )?);
        Ok(Some(EnrichedCandidate {
            name: dependency.name.clone(),
            from: from.clone(),
            current_range: dependency.manifest_value.clone(),
            new_range: if required_dist_tag.is_some() {
                dependency.manifest_value.clone()
            } else {
                dependency.manifest_spec.render_new_value(&new_range)
            },
            to: target_version.clone(),
            dependency_kind: dependency.dependency_kind,
            target_kind,
            semver_class: upgrade_engine::classify_semver_change(&from, &target_version),
            has_install_scripts: upgrade_engine::target_has_install_scripts(target),
            peer_impact,
            patch_invalidation,
            lookup_name: dependency.lookup_name.clone(),
            route: dependency.route,
            selected_metadata,
        }))
    };

    let mut planned = Vec::with_capacity(if mode == ResolvedMode::Interactive {
        2
    } else {
        1
    });
    if metadata.dist_tags.contains_key(&dependency.range) {
        let target =
            allowed_versions.resolve_spec(metadata, &dependency.range, release_age_policy)?;
        if installed_version.is_none_or(|installed| installed != target)
            && let Some(candidate) = build_candidate(
                target,
                dependency.range.clone(),
                TargetKind::WithinMajor,
                Some(&dependency.range),
            )?
        {
            planned.push(candidate);
        }
        return Ok(planned);
    }
    match mode {
        ResolvedMode::NonInteractive => {
            let (target, new_range) = compute_upgrade(
                &dependency.range,
                installed_version,
                latest,
                &allowed_versions.versions,
                major,
            );
            if let Some(target) = target
                && installed_version.is_none_or(|installed| installed != target)
                && (installed_version.is_some() || dependency.range != new_range)
                && let Some(candidate) = build_candidate(
                    target,
                    new_range,
                    if major {
                        TargetKind::AbsoluteLatest
                    } else {
                        TargetKind::WithinMajor
                    },
                    None,
                )?
            {
                planned.push(candidate);
            }
        }
        ResolvedMode::Interactive => {
            let (within_target, within_range) = compute_upgrade(
                &dependency.range,
                installed_version,
                latest,
                &allowed_versions.versions,
                false,
            );
            let (absolute_target, absolute_range) = compute_upgrade(
                &dependency.range,
                installed_version,
                latest,
                &allowed_versions.versions,
                true,
            );
            if let Some(target) = within_target.as_ref()
                && installed_version.is_none_or(|installed| installed != target)
                && (installed_version.is_some() || dependency.range != within_range)
                && let Some(candidate) =
                    build_candidate(target.clone(), within_range, TargetKind::WithinMajor, None)?
            {
                planned.push(candidate);
            }
            if let Some(target) = absolute_target
                && within_target.as_deref() != Some(target.as_str())
                && installed_version.is_none_or(|installed| installed != target)
                && (installed_version.is_some() || dependency.range != absolute_range)
                && let Some(candidate) =
                    build_candidate(target, absolute_range, TargetKind::AbsoluteLatest, None)?
            {
                planned.push(candidate);
            }
        }
    }
    Ok(planned)
}

fn compact_metadata_for_version(
    metadata: &PackageMetadata,
    version: &str,
    required_dist_tag: Option<&str>,
) -> Result<PackageMetadata, LpmError> {
    let selected = metadata.version(version).cloned().ok_or_else(|| {
        LpmError::Registry(format!(
            "registry selected missing version '{}@{version}'",
            metadata.name
        ))
    })?;
    let mut dist_tags = HashMap::with_capacity(1 + usize::from(required_dist_tag.is_some()));
    dist_tags.insert("latest".to_string(), version.to_string());
    if let Some(tag) = required_dist_tag {
        dist_tags.insert(tag.to_string(), version.to_string());
    }
    let mut versions = HashMap::with_capacity(1);
    versions.insert(version.to_string(), selected);
    let mut time = HashMap::with_capacity(1);
    if let Some(published_at) = metadata.time.get(version) {
        time.insert(version.to_string(), published_at.clone());
    }
    Ok(PackageMetadata {
        name: metadata.name.clone(),
        description: None,
        modified: metadata.modified.clone(),
        dist_tags,
        versions,
        time,
        downloads: None,
        distribution_mode: metadata.distribution_mode.clone(),
        package_type: metadata.package_type.clone(),
        latest_version: Some(version.to_string()),
        ecosystem: metadata.ecosystem.clone(),
    })
}

fn emit_upgrade_json(
    candidates: &[EnrichedCandidate],
    dry_run: bool,
    fetch_errors: usize,
    skipped_private: &[String],
    skipped_non_registry: &[String],
) -> Result<(), LpmError> {
    let packages: Vec<_> = candidates.iter().map(candidate_to_json).collect();
    let mut json = serde_json::json!({
        "success": true,
        "dry_run": dry_run,
        "upgraded": candidates.len(),
        "packages": packages,
        "fetch_errors": fetch_errors,
    });
    attach_skipped_private(&mut json, skipped_private);
    if !skipped_non_registry.is_empty() {
        json.as_object_mut()
            .expect("upgrade JSON envelope is an object")
            .insert(
                "skipped_non_registry".to_string(),
                serde_json::json!(skipped_non_registry),
            );
    }
    let encoded = serde_json::to_string_pretty(&json).map_err(|error| {
        LpmError::Script(format!("failed to serialize upgrade result: {error}"))
    })?;
    println!("{encoded}");
    Ok(())
}

fn attach_skipped_private(json: &mut serde_json::Value, skipped_private: &[String]) {
    if skipped_private.is_empty() {
        return;
    }

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

fn warn_skipped_private(skipped_private: &[String]) {
    if skipped_private.is_empty() {
        return;
    }

    let names = skipped_private
        .iter()
        .map(|name| lpm_common::sanitize_terminal_inline(name).into_owned())
        .collect::<Vec<_>>();
    install_ui::warn_untrusted(&format!(
        "skipped {} package(s) without a recorded public npm or LPM-registry source to avoid leaking private names to registry.npmjs.org: {}",
        skipped_private.len(),
        names.join(", "),
    ));
    install_ui::phase("run `lpm install` first to record sources in lpm.lock, then re-run.");
}

fn warn_skipped_non_registry(skipped_non_registry: &[String]) {
    if skipped_non_registry.is_empty() {
        return;
    }

    let names = skipped_non_registry
        .iter()
        .map(|name| lpm_common::sanitize_terminal_inline(name).into_owned())
        .collect::<Vec<_>>();
    install_ui::warn_untrusted(&format!(
        "skipped {} non-registry package(s): {}",
        skipped_non_registry.len(),
        names.join(", "),
    ));
}

// ── Interactive multiselect ─────────────────────────────────────────

fn select_candidates_interactively(
    candidates: &[EnrichedCandidate],
) -> Result<Vec<EnrichedCandidate>, LpmError> {
    let pkg_count = {
        let mut names: Vec<&str> = candidates.iter().map(|c| c.name.as_str()).collect();
        names.dedup();
        names.len()
    };
    let target_count = candidates.len();
    if target_count == pkg_count {
        install_ui::phase_untrusted(&format!("{pkg_count} package(s) can be upgraded."));
    } else {
        install_ui::phase_untrusted(&format!(
            "{target_count} upgrade targets across {pkg_count} packages."
        ));
    }

    let mut ms =
        cliclack::multiselect("Select packages to upgrade  (space=toggle  a=all  enter=confirm)");

    let initial_indices: Vec<usize> = candidates
        .iter()
        .enumerate()
        .filter(|(_, c)| {
            upgrade_engine::default_pre_check(
                c.semver_class,
                c.has_install_scripts,
                &c.peer_impact,
                c.patch_invalidation.as_ref(),
            )
        })
        .map(|(i, _)| i)
        .collect();

    for (i, c) in candidates.iter().enumerate() {
        let label = format_candidate_row_for_tui(c);
        let hint = format_candidate_hint(c);
        ms = ms.item(i, label, hint);
    }
    ms = ms.initial_values(initial_indices);

    let chosen_indices: Vec<usize> = ms.interact().map_err(prompt_err)?;

    let selected: Vec<EnrichedCandidate> = chosen_indices
        .into_iter()
        .filter_map(|i| candidates.get(i).cloned())
        .collect();
    Ok(selected)
}

// ── Deduplication ───────────────────────────────────────────────────

/// When both the within-major and absolute-latest rows are selected for
/// the same package, keep only the one with the higher target version.
fn deduplicate_by_highest_target(mut selected: Vec<EnrichedCandidate>) -> Vec<EnrichedCandidate> {
    selected.sort_unstable_by(|left, right| {
        left.name
            .cmp(&right.name)
            .then_with(|| left.current_range.cmp(&right.current_range))
            .then_with(|| left.dependency_kind.cmp(&right.dependency_kind))
            .then_with(
                || match (Version::parse(&left.to), Version::parse(&right.to)) {
                    (Ok(left), Ok(right)) => right.cmp(&left),
                    _ => right.to.cmp(&left.to),
                },
            )
    });
    selected.dedup_by(|next, current| {
        next.name == current.name
            && next.current_range == current.current_range
            && next.dependency_kind == current.dependency_kind
    });
    selected.sort_unstable_by(|left, right| {
        left.name
            .cmp(&right.name)
            .then_with(|| left.dependency_kind.cmp(&right.dependency_kind))
    });
    selected
}

// ── Formatting helpers ──────────────────────────────────────────────

fn format_candidate_row_for_tui(c: &EnrichedCandidate) -> String {
    let dev_tag = match c.dependency_kind {
        DependencyKind::Development => " (dev)",
        DependencyKind::Optional => " (optional)",
        DependencyKind::Runtime => "",
    };
    let class_label = format_class_label(c.semver_class);
    let kind_tag = match c.target_kind {
        TargetKind::AbsoluteLatest => " (latest)",
        TargetKind::WithinMajor => "",
    };
    let name = lpm_common::sanitize_terminal_inline(&c.name);
    let from = lpm_common::sanitize_terminal_inline(&c.from);
    let to = lpm_common::sanitize_terminal_inline(&c.to);
    format!(
        "{:<40} {} → {} {}{}{}",
        name, from, to, class_label, kind_tag, dev_tag,
    )
}

fn format_candidate_hint(c: &EnrichedCandidate) -> String {
    let mut parts: Vec<String> = Vec::new();

    if c.has_install_scripts {
        parts.push("[!] install scripts (will need approve-scripts)".into());
    }

    if !c.peer_impact.ok {
        let mut peer_parts: Vec<String> = Vec::new();
        for v in &c.peer_impact.violations {
            peer_parts.push(format!(
                "{}={}≠{}",
                lpm_common::sanitize_terminal_inline(&v.name),
                lpm_common::sanitize_terminal_inline(&v.have),
                lpm_common::sanitize_terminal_inline(&v.want)
            ));
        }
        for m in &c.peer_impact.missing {
            peer_parts.push(format!(
                "{} missing",
                lpm_common::sanitize_terminal_inline(m)
            ));
        }
        if !peer_parts.is_empty() {
            parts.push(format!(
                "peer: {} (current lockfile)",
                peer_parts.join(", ")
            ));
        }
    }

    if let Some(ref inv) = c.patch_invalidation {
        parts.push(format!(
            "orphans patch {}",
            lpm_common::sanitize_terminal_inline(&inv.key)
        ));
    }

    parts.join("  •  ")
}

fn format_class_label(class: SemverClass) -> String {
    match class {
        SemverClass::Patch => "patch".green(),
        SemverClass::Minor => "minor".yellow(),
        SemverClass::Major => "MAJOR".red(),
        SemverClass::Prerelease => "pre".dimmed(),
        SemverClass::Unknown => "?".dimmed(),
    }
}

fn format_upgrade_glyph(class: SemverClass) -> String {
    match class {
        SemverClass::Patch => "↑".green(),
        SemverClass::Minor => "↑".yellow(),
        SemverClass::Major => "↑".red(),
        SemverClass::Prerelease | SemverClass::Unknown => "↑".dimmed(),
    }
}

fn candidate_to_json(c: &EnrichedCandidate) -> serde_json::Value {
    let mut value = serde_json::json!({
        "name": c.name,
        "from": c.from,
        "to": c.to,
        "new_range": c.new_range,
        "is_dev": c.dependency_kind.is_dev(),
        "semver_class": c.semver_class,
        "has_install_scripts": c.has_install_scripts,
        "peer_impact": c.peer_impact,
        "patch_invalidation": c.patch_invalidation,
    });
    if c.dependency_kind == DependencyKind::Optional {
        value
            .as_object_mut()
            .expect("upgrade candidate JSON is an object")
            .insert("is_optional".to_string(), serde_json::Value::Bool(true));
    }
    value
}

fn apply_upgrades_to_manifest(
    doc: &mut serde_json::Value,
    upgrades: &[EnrichedCandidate],
) -> Result<(), LpmError> {
    for upgrade in upgrades {
        let dep_key = upgrade.dependency_kind.manifest_key();

        let deps = doc
            .get_mut(dep_key)
            .and_then(|value| value.as_object_mut())
            .ok_or_else(|| {
                LpmError::Script(format!(
                    "package.json is missing `{dep_key}` while upgrading {}",
                    upgrade.name
                ))
            })?;

        match deps.get_mut(&upgrade.name) {
            Some(serde_json::Value::String(current)) => {
                if current != &upgrade.current_range {
                    return Err(LpmError::Script(format!(
                        "package.json drifted before upgrade could write {}: expected `{}`, found `{}`",
                        upgrade.name, upgrade.current_range, current
                    )));
                }
                *current = upgrade.new_range.clone();
            }
            _ => {
                return Err(LpmError::Script(format!(
                    "package.json is missing string dependency entry `{}` in `{dep_key}`",
                    upgrade.name
                )));
            }
        }
    }

    Ok(())
}

// ── Preserved helpers from the original upgrade.rs ──────────────────

fn extract_deps_from_value(doc: &serde_json::Value) -> Vec<(String, String, DependencyKind)> {
    let optional = doc
        .get("optionalDependencies")
        .and_then(serde_json::Value::as_object);
    let capacity = doc
        .get("dependencies")
        .and_then(serde_json::Value::as_object)
        .map_or(0, serde_json::Map::len)
        + doc
            .get("devDependencies")
            .and_then(serde_json::Value::as_object)
            .map_or(0, serde_json::Map::len)
        + optional.map_or(0, serde_json::Map::len);
    let mut deps = Vec::with_capacity(capacity);
    if let Some(obj) = doc.get("dependencies").and_then(|d| d.as_object()) {
        for (k, v) in obj {
            if optional.is_some_and(|optional| optional.contains_key(k)) {
                continue;
            }
            if let Some(range) = v.as_str() {
                deps.push((k.clone(), range.to_string(), DependencyKind::Runtime));
            }
        }
    }
    if let Some(obj) = doc.get("devDependencies").and_then(|d| d.as_object()) {
        for (k, v) in obj {
            if let Some(range) = v.as_str() {
                deps.push((k.clone(), range.to_string(), DependencyKind::Development));
            }
        }
    }
    if let Some(obj) = optional {
        for (k, v) in obj {
            if let Some(range) = v.as_str() {
                deps.push((k.clone(), range.to_string(), DependencyKind::Optional));
            }
        }
    }
    deps
}

fn filter_requested_deps(
    deps: Vec<(String, String, DependencyKind)>,
    requested_packages: &[String],
) -> Result<Vec<(String, String, DependencyKind)>, LpmError> {
    if requested_packages.is_empty() {
        return Ok(deps);
    }

    let requested = requested_packages.iter().cloned().collect::<BTreeSet<_>>();
    let available = deps
        .iter()
        .map(|(name, _, _)| name.clone())
        .collect::<BTreeSet<_>>();
    let missing = requested
        .difference(&available)
        .cloned()
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        return Err(LpmError::Script(format!(
            "package(s) not found in package.json dependencies, devDependencies, or optionalDependencies: {}",
            missing.join(", ")
        )));
    }

    Ok(deps
        .into_iter()
        .filter(|(name, _, _)| requested.contains(name))
        .collect())
}

/// Compute the upgrade target version and new range.
///
/// In default (non-major) mode, stays within the current major version.
/// In major mode, uses the absolute latest.
fn compute_upgrade(
    current_range: &str,
    installed_version: Option<&str>,
    latest: &str,
    available_versions: &[Version],
    major: bool,
) -> (Option<String>, String) {
    let simple_range = simple_version_range(current_range);
    let requirement = VersionReq::parse(current_range).ok();

    if major {
        if installed_version
            .and_then(|version| Version::parse(version).ok())
            .zip(Version::parse(latest).ok())
            .is_some_and(|(installed, target)| target <= installed)
        {
            return (None, current_range.to_string());
        }
        let prefix = simple_range.map_or("", |(prefix, _)| prefix);
        let new_range = format!("{prefix}{latest}");
        return (Some(latest.to_string()), new_range);
    }

    let installed = installed_version.and_then(|version| Version::parse(version).ok());
    let installed_matches_manifest = installed.as_ref().is_some_and(|version| {
        requirement
            .as_ref()
            .is_none_or(|requirement| requirement.matches(version))
    });
    let prerelease_allowed = |version: &Version| {
        !version.is_prerelease()
            || requirement
                .as_ref()
                .is_some_and(|requirement| requirement.matches(version))
    };
    let current_major = installed
        .as_ref()
        .filter(|_| installed_matches_manifest)
        .map(|version| version.major())
        .or_else(|| {
            let requirement = requirement.as_ref()?;
            available_versions
                .iter()
                .filter(|version| prerelease_allowed(version) && requirement.matches(version))
                .max()
                .map(|version| version.major())
        })
        .or_else(|| {
            simple_range
                .and_then(|(_, version)| Version::parse(version).ok())
                .map(|version| version.major())
        });

    let current_major = match current_major {
        Some(m) => m,
        None => {
            return (Some(latest.to_string()), current_range.to_string());
        }
    };

    let Some(best) = available_versions.iter().rev().find(|version| {
        version.major() == current_major
            && prerelease_allowed(version)
            && (simple_range.is_some()
                || requirement
                    .as_ref()
                    .is_none_or(|requirement| requirement.matches(version)))
    }) else {
        return (None, current_range.to_string());
    };
    if installed
        .as_ref()
        .is_some_and(|installed| best <= installed)
    {
        return (None, current_range.to_string());
    }
    let best_str = best.to_string();
    let new_range = simple_range.map_or_else(
        || current_range.to_string(),
        |(prefix, _)| format!("{prefix}{best_str}"),
    );

    (Some(best_str), new_range)
}

fn simple_version_range(range: &str) -> Option<(&str, &str)> {
    let trimmed = range.trim();
    let (prefix, version) = if let Some(version) = trimmed.strip_prefix('^') {
        ("^", version)
    } else if let Some(version) = trimmed.strip_prefix('~') {
        ("~", version)
    } else {
        ("", trimmed)
    };
    Version::parse(version).ok().map(|_| (prefix, version))
}

/// Extract a best-effort version string from a range like `"^1.2.0"`.
/// Strips `^`, `~`, `>=`, `=` prefixes and returns the body. If the
/// body doesn't look like a version (e.g., `"*"`), returns it as-is
/// — the caller's `classify_semver_change` will return `Unknown`.
///
/// When no lockfile exists, `installed_ver` is `None` and the old code
/// used `"?"` as the "from" version, which
/// `classify_semver_change` can't parse → `Unknown` → patches/minors
/// don't get pre-checked. This helper extracts a real version from
/// the manifest range so classification works correctly even without
/// a lockfile.
fn version_from_range(range: &str) -> String {
    range
        .trim_start_matches(['^', '~', '>', '<', '='])
        .trim()
        .to_string()
}

fn is_valid_version_string(v: &str) -> bool {
    if v.is_empty() {
        return false;
    }
    v.chars()
        .all(|c| c.is_alphanumeric() || c == '.' || c == '-' || c == '+')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filter_requested_deps_keeps_only_named_manifest_dependencies() {
        let deps = vec![
            (
                "zod".to_string(),
                "^3.0.0".to_string(),
                DependencyKind::Runtime,
            ),
            (
                "typescript".to_string(),
                "^5.0.0".to_string(),
                DependencyKind::Development,
            ),
            (
                "react".to_string(),
                "^18.0.0".to_string(),
                DependencyKind::Runtime,
            ),
        ];

        let filtered = filter_requested_deps(deps, &["typescript".to_string()]).unwrap();

        assert_eq!(
            filtered,
            vec![(
                "typescript".to_string(),
                "^5.0.0".to_string(),
                DependencyKind::Development
            )]
        );
    }

    #[test]
    fn filter_requested_deps_errors_when_package_is_not_manifest_dependency() {
        let deps = vec![(
            "zod".to_string(),
            "^3.0.0".to_string(),
            DependencyKind::Runtime,
        )];

        let err = filter_requested_deps(deps, &["react".to_string()]).unwrap_err();

        assert!(
            err.to_string().contains("react"),
            "missing package error should name the requested dependency: {err}"
        );
    }

    #[test]
    fn manifest_dependency_spec_parses_unscoped_npm_alias() {
        let (spec, range) =
            ManifestDependencySpec::from_manifest_value("strip-ansi-cjs", "npm:strip-ansi@^6")
                .unwrap();

        assert!(matches!(
            &spec,
            ManifestDependencySpec::NpmAlias { target } if target == "strip-ansi"
        ));
        assert_eq!(range, "^6");
        assert_eq!(spec.render_new_value("^6.1.0"), "npm:strip-ansi@^6.1.0");
    }

    #[test]
    fn manifest_dependency_spec_parses_scoped_npm_alias() {
        let (spec, range) =
            ManifestDependencySpec::from_manifest_value("node-types", "npm:@types/node@^20")
                .unwrap();

        assert!(matches!(
            &spec,
            ManifestDependencySpec::NpmAlias { target } if target == "@types/node"
        ));
        assert_eq!(range, "^20");
        assert_eq!(spec.render_new_value("^20.1.0"), "npm:@types/node@^20.1.0");
    }

    #[test]
    fn plain_manifest_dependency_does_not_inherit_a_stale_lockfile_alias() {
        let mut lockfile = lpm_lockfile::Lockfile::new();
        lockfile
            .root_aliases
            .insert("tool".to_string(), "old-public-tool".to_string());

        let lookup_name = ManifestDependencySpec::Plain.lookup_name("tool", Some(&lockfile));

        assert_eq!(lookup_name, "tool");
    }

    // ── compute_upgrade (preserved from original) ───────────────────

    fn parsed_versions(versions: &[&str]) -> Vec<Version> {
        let mut parsed = versions
            .iter()
            .map(|version| Version::parse(version).unwrap())
            .collect::<Vec<_>>();
        parsed.sort();
        parsed
    }

    #[test]
    fn default_mode_stays_within_major() {
        let available = parsed_versions(&["1.2.0", "1.5.0", "2.0.0"]);
        let (target, new_range) = compute_upgrade("^1.2.0", None, "2.0.0", &available, false);
        assert_eq!(target, Some("1.5.0".to_string()));
        assert_eq!(new_range, "^1.5.0");
    }

    #[test]
    fn major_mode_jumps_to_latest() {
        let available = parsed_versions(&["1.2.0", "1.5.0", "2.0.0"]);
        let (target, new_range) = compute_upgrade("^1.2.0", None, "2.0.0", &available, true);
        assert_eq!(target, Some("2.0.0".to_string()));
        assert_eq!(new_range, "^2.0.0");
    }

    #[test]
    fn default_mode_same_major_as_latest() {
        let available = parsed_versions(&["2.0.0", "2.1.0", "2.3.0"]);
        let (target, new_range) = compute_upgrade("^2.0.0", None, "2.3.0", &available, false);
        assert_eq!(target, Some("2.3.0".to_string()));
        assert_eq!(new_range, "^2.3.0");
    }

    #[test]
    fn default_mode_tilde_prefix_preserved() {
        let available = parsed_versions(&["1.2.0", "1.5.0", "2.0.0"]);
        let (target, new_range) = compute_upgrade("~1.2.0", None, "2.0.0", &available, false);
        assert_eq!(target, Some("1.5.0".to_string()));
        assert_eq!(new_range, "~1.5.0");
    }

    #[test]
    fn default_mode_no_prefix() {
        let available = parsed_versions(&["1.2.0", "1.5.0", "2.0.0"]);
        let (target, new_range) = compute_upgrade("1.2.0", None, "2.0.0", &available, false);
        assert_eq!(target, Some("1.5.0".to_string()));
        assert_eq!(new_range, "1.5.0");
    }

    #[test]
    fn default_mode_skips_prereleases() {
        let available = parsed_versions(&["1.2.0", "1.6.0-beta.1", "1.5.0", "2.0.0"]);
        let (target, _) = compute_upgrade("^1.2.0", None, "2.0.0", &available, false);
        assert_eq!(target, Some("1.5.0".to_string()));
    }

    #[test]
    fn default_mode_keeps_complex_ranges_within_the_current_major() {
        let available = parsed_versions(&["1.9.0", "1.9.1", "2.0.0"]);

        let result = compute_upgrade(">=1.0.0 <2.0.0", Some("1.9.0"), "2.0.0", &available, false);

        assert_eq!(
            result,
            (Some("1.9.1".to_string()), ">=1.0.0 <2.0.0".to_string())
        );
    }

    #[test]
    fn default_mode_respects_every_bound_in_a_complex_range() {
        let available = parsed_versions(&["1.2.0", "1.4.0", "1.9.0"]);

        let result = compute_upgrade(">=1.0.0 <1.5.0", Some("1.2.0"), "1.9.0", &available, false);

        assert_eq!(
            result,
            (Some("1.4.0".to_string()), ">=1.0.0 <1.5.0".to_string())
        );
    }

    #[test]
    fn default_mode_uses_manifest_intent_when_installed_version_is_stale() {
        let available = parsed_versions(&["1.5.0", "1.9.0", "2.0.0", "2.1.0"]);

        let result = compute_upgrade("^2.0.0", Some("1.5.0"), "2.1.0", &available, false);

        assert_eq!(result, (Some("2.1.0".to_string()), "^2.1.0".to_string()));
    }

    #[test]
    fn default_mode_advances_an_explicit_prerelease_range() {
        let available = parsed_versions(&["2.0.0-beta.1", "2.0.0-beta.2"]);

        let result = compute_upgrade(
            "^2.0.0-beta.1",
            Some("2.0.0-beta.1"),
            "2.0.0-beta.2",
            &available,
            false,
        );

        assert_eq!(
            result,
            (
                Some("2.0.0-beta.2".to_string()),
                "^2.0.0-beta.2".to_string()
            )
        );
    }

    #[test]
    fn compute_upgrade_does_not_turn_a_registry_rollback_into_a_downgrade() {
        let available = parsed_versions(&["2.3.0", "2.4.0"]);

        let result = compute_upgrade("^2.0.0", Some("2.5.0"), "2.4.0", &available, false);

        assert_eq!(result, (None, "^2.0.0".to_string()));
    }

    // ── resolve_mode ────────────────────────────────────────────────

    #[test]
    fn resolve_mode_default_tty_is_interactive() {
        assert_eq!(
            resolve_mode(false, false, false, true).unwrap(),
            ResolvedMode::Interactive
        );
    }

    #[test]
    fn resolve_mode_default_no_tty_is_non_interactive() {
        assert_eq!(
            resolve_mode(false, false, false, false).unwrap(),
            ResolvedMode::NonInteractive
        );
    }

    #[test]
    fn resolve_mode_yes_forces_non_interactive_in_tty() {
        assert_eq!(
            resolve_mode(false, true, false, true).unwrap(),
            ResolvedMode::NonInteractive
        );
    }

    #[test]
    fn resolve_mode_interactive_forces_interactive_no_tty() {
        assert_eq!(
            resolve_mode(true, false, false, false).unwrap(),
            ResolvedMode::Interactive
        );
    }

    #[test]
    fn resolve_mode_json_forces_non_interactive() {
        assert_eq!(
            resolve_mode(false, false, true, true).unwrap(),
            ResolvedMode::NonInteractive
        );
    }

    #[test]
    fn resolve_mode_interactive_and_yes_is_hard_error() {
        assert!(resolve_mode(true, true, false, true).is_err());
    }

    #[test]
    fn resolve_mode_interactive_and_json_is_hard_error() {
        assert!(resolve_mode(true, false, true, false).is_err());
    }

    #[test]
    fn validate_major_for_mode_rejects_major_in_interactive() {
        assert!(validate_major_for_mode(true, ResolvedMode::Interactive).is_err());
    }

    #[test]
    fn validate_major_for_mode_accepts_major_in_non_interactive() {
        assert!(validate_major_for_mode(true, ResolvedMode::NonInteractive).is_ok());
    }

    #[test]
    fn validate_major_for_mode_accepts_no_major_in_either() {
        assert!(validate_major_for_mode(false, ResolvedMode::Interactive).is_ok());
        assert!(validate_major_for_mode(false, ResolvedMode::NonInteractive).is_ok());
    }

    // ── formatting helpers ──────────────────────────────────────────

    fn make_candidate(
        class: SemverClass,
        has_scripts: bool,
        peer_ok: bool,
        has_patch_inv: bool,
    ) -> EnrichedCandidate {
        let peer_impact = if peer_ok {
            PeerImpact {
                ok: true,
                basis: "current_lockfile".into(),
                missing: vec![],
                violations: vec![],
            }
        } else {
            PeerImpact {
                ok: false,
                basis: "current_lockfile".into(),
                missing: vec![],
                violations: vec![PeerViolation {
                    name: "react".into(),
                    have: "17.0.2".into(),
                    want: "^18.0.0".into(),
                }],
            }
        };
        let patch_invalidation = if has_patch_inv {
            Some(PatchInvalidation {
                key: "lodash@4.17.20".into(),
                patch_path: "patches/lodash.patch".into(),
                from_version: "4.17.20".into(),
                to_version: "4.17.21".into(),
            })
        } else {
            None
        };
        let selected_metadata = Arc::new(PackageMetadata {
            name: "@lpm.dev/test.pkg".into(),
            description: None,
            modified: None,
            dist_tags: HashMap::new(),
            versions: HashMap::new(),
            time: HashMap::new(),
            downloads: None,
            distribution_mode: None,
            package_type: None,
            latest_version: None,
            ecosystem: None,
        });
        EnrichedCandidate {
            name: "@lpm.dev/test.pkg".into(),
            from: "1.2.0".into(),
            current_range: "^1.2.0".into(),
            new_range: "^1.2.4".into(),
            to: "1.2.4".into(),
            dependency_kind: DependencyKind::Runtime,
            target_kind: TargetKind::WithinMajor,
            semver_class: class,
            has_install_scripts: has_scripts,
            peer_impact,
            patch_invalidation,
            lookup_name: "@lpm.dev/test.pkg".into(),
            route: MetadataRoute::Lpm,
            selected_metadata,
        }
    }

    #[test]
    fn format_row_includes_class_label() {
        let c = make_candidate(SemverClass::Patch, false, true, false);
        let row = format_candidate_row_for_tui(&c);
        assert!(row.contains("1.2.0"));
        assert!(row.contains("1.2.4"));
    }

    #[test]
    fn format_hint_marks_install_scripts() {
        let c = make_candidate(SemverClass::Patch, true, true, false);
        let hint = format_candidate_hint(&c);
        assert!(hint.contains("[!]"));
        assert!(hint.contains("install scripts"));
    }

    #[test]
    fn format_hint_marks_peer_violation() {
        let c = make_candidate(SemverClass::Minor, false, false, false);
        let hint = format_candidate_hint(&c);
        assert!(hint.contains("react"));
        assert!(hint.contains("current lockfile"));
    }

    #[test]
    fn format_hint_marks_patch_invalidation() {
        let c = make_candidate(SemverClass::Minor, false, true, true);
        let hint = format_candidate_hint(&c);
        assert!(hint.contains("orphans patch"));
        assert!(hint.contains("lodash@4.17.20"));
    }

    #[test]
    fn format_hint_is_empty_when_clean() {
        let c = make_candidate(SemverClass::Patch, false, true, false);
        let hint = format_candidate_hint(&c);
        assert!(hint.is_empty());
    }

    // ── Dual-row model ──────────────────────────────────────────────

    #[test]
    fn deduplicate_takes_major_when_both_selected() {
        let minor = EnrichedCandidate {
            name: "pkg".into(),
            from: "3.4.0".into(),
            current_range: "^3.4.0".into(),
            new_range: "^3.9.0".into(),
            to: "3.9.0".into(),
            dependency_kind: DependencyKind::Runtime,
            target_kind: TargetKind::WithinMajor,
            semver_class: SemverClass::Minor,
            has_install_scripts: false,
            peer_impact: PeerImpact {
                ok: true,
                basis: "current_lockfile".into(),
                missing: vec![],
                violations: vec![],
            },
            patch_invalidation: None,
            lookup_name: "pkg".into(),
            route: MetadataRoute::PublicNpm,
            selected_metadata: Arc::new(PackageMetadata {
                name: "pkg".into(),
                description: None,
                modified: None,
                dist_tags: HashMap::new(),
                versions: HashMap::new(),
                time: HashMap::new(),
                downloads: None,
                distribution_mode: None,
                package_type: None,
                latest_version: None,
                ecosystem: None,
            }),
        };
        let major = EnrichedCandidate {
            to: "4.0.0".into(),
            new_range: "^4.0.0".into(),
            target_kind: TargetKind::AbsoluteLatest,
            semver_class: SemverClass::Major,
            ..minor.clone()
        };
        let deduped = deduplicate_by_highest_target(vec![minor, major]);
        assert_eq!(deduped.len(), 1);
        assert_eq!(deduped[0].to, "4.0.0");
    }

    #[test]
    fn deduplicate_keeps_minor_when_only_minor_selected() {
        let minor = EnrichedCandidate {
            name: "pkg".into(),
            from: "3.4.0".into(),
            current_range: "^3.4.0".into(),
            new_range: "^3.9.0".into(),
            to: "3.9.0".into(),
            dependency_kind: DependencyKind::Runtime,
            target_kind: TargetKind::WithinMajor,
            semver_class: SemverClass::Minor,
            has_install_scripts: false,
            peer_impact: PeerImpact {
                ok: true,
                basis: "current_lockfile".into(),
                missing: vec![],
                violations: vec![],
            },
            patch_invalidation: None,
            lookup_name: "pkg".into(),
            route: MetadataRoute::PublicNpm,
            selected_metadata: Arc::new(PackageMetadata {
                name: "pkg".into(),
                description: None,
                modified: None,
                dist_tags: HashMap::new(),
                versions: HashMap::new(),
                time: HashMap::new(),
                downloads: None,
                distribution_mode: None,
                package_type: None,
                latest_version: None,
                ecosystem: None,
            }),
        };
        let deduped = deduplicate_by_highest_target(vec![minor]);
        assert_eq!(deduped.len(), 1);
        assert_eq!(deduped[0].to, "3.9.0");
    }

    #[test]
    fn deduplicate_keeps_identical_declarations_from_both_dependency_sections() {
        let runtime = make_candidate(SemverClass::Patch, false, true, false);
        let development = EnrichedCandidate {
            dependency_kind: DependencyKind::Development,
            ..runtime.clone()
        };

        let deduped = deduplicate_by_highest_target(vec![runtime, development]);

        assert_eq!(deduped.len(), 2);
        assert!(
            deduped
                .iter()
                .any(|candidate| candidate.dependency_kind == DependencyKind::Runtime)
        );
        assert!(
            deduped
                .iter()
                .any(|candidate| candidate.dependency_kind == DependencyKind::Development)
        );
    }

    // ── extract_deps_from_value (preserved) ─────────────────────────

    #[test]
    fn extract_deps_from_json_value() {
        let doc: serde_json::Value = serde_json::from_str(
            r#"{"dependencies":{"foo":"^1.0.0"},"devDependencies":{"bar":"~2.0.0"}}"#,
        )
        .unwrap();
        let deps = extract_deps_from_value(&doc);
        assert_eq!(deps.len(), 2);
        assert!(
            deps.iter().any(|(n, r, kind)| n == "foo"
                && r == "^1.0.0"
                && *kind == DependencyKind::Runtime)
        );
        assert!(deps.iter().any(|(n, r, kind)| n == "bar"
            && r == "~2.0.0"
            && *kind == DependencyKind::Development));
    }

    #[test]
    fn extract_deps_includes_optional_dependencies() {
        let doc: serde_json::Value =
            serde_json::from_str(r#"{"optionalDependencies":{"optional-pkg":"^1.0.0"}}"#).unwrap();

        let deps = extract_deps_from_value(&doc);

        assert!(deps.iter().any(|(name, range, kind)| name == "optional-pkg"
            && range == "^1.0.0"
            && *kind == DependencyKind::Optional));
    }

    // ── version validation (preserved) ──────────────────────────────

    #[test]
    fn valid_version_strings() {
        assert!(is_valid_version_string("1.5.0"));
        assert!(is_valid_version_string("2.0.0-rc.1"));
        assert!(is_valid_version_string("1.0.0-beta.2"));
        assert!(is_valid_version_string("1.0.0+build.123"));
    }

    #[test]
    fn invalid_version_strings() {
        assert!(!is_valid_version_string(""));
        assert!(!is_valid_version_string("1.0.0 && rm -rf /"));
        assert!(!is_valid_version_string("1.0.0; echo pwned"));
        assert!(!is_valid_version_string("$(whoami)"));
    }

    // ── no-lockfile classification regression ─────────────
    // Bug: when no lockfile exists, `from` was "?" → classify returned
    // Unknown → patches/minors not pre-checked. Contract: the class
    // must be derived from the range body, not from "?".

    #[test]
    fn version_from_range_strips_caret() {
        assert_eq!(version_from_range("^1.2.0"), "1.2.0");
    }

    #[test]
    fn version_from_range_strips_tilde() {
        assert_eq!(version_from_range("~1.2.0"), "1.2.0");
    }

    #[test]
    fn version_from_range_strips_gte() {
        assert_eq!(version_from_range(">=1.0.0"), "1.0.0");
    }

    #[test]
    fn version_from_range_no_prefix() {
        assert_eq!(version_from_range("1.2.0"), "1.2.0");
    }

    #[test]
    fn no_lockfile_patch_upgrade_classifies_as_patch_not_unknown() {
        // The user-visible contract: ^1.0.0 → 1.0.1 is a patch upgrade
        // even when no lockfile is present. The "from" should be derived
        // from the range body "1.0.0", not "?".
        let from = version_from_range("^1.0.0");
        let class = upgrade_engine::classify_semver_change(&from, "1.0.1");
        assert_eq!(
            class,
            SemverClass::Patch,
            "no-lockfile ^1.0.0 → 1.0.1 must classify as Patch, not Unknown"
        );
        assert!(
            class.default_checked(),
            "Patch must be default-checked in the multiselect"
        );
    }

    #[test]
    fn no_lockfile_minor_upgrade_classifies_as_minor_not_unknown() {
        let from = version_from_range("^1.0.0");
        let class = upgrade_engine::classify_semver_change(&from, "1.5.0");
        assert_eq!(
            class,
            SemverClass::Minor,
            "no-lockfile ^1.0.0 → 1.5.0 must classify as Minor, not Unknown"
        );
        assert!(class.default_checked());
    }

    #[test]
    fn no_lockfile_major_upgrade_classifies_as_major() {
        let from = version_from_range("^1.0.0");
        let class = upgrade_engine::classify_semver_change(&from, "2.0.0");
        assert_eq!(class, SemverClass::Major);
        assert!(!class.default_checked());
    }
}
