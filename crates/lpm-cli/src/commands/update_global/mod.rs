//! `lpm global update [pkg|pkg@spec]`.
//!
//! Three-phase upgrade tx, structurally similar to the install
//! pipeline but with three differences:
//!
//! 1. **Existing-row required.** prepare errors if `[packages.<pkg>]`
//!    is absent — upgrade is for installs that already exist.
//! 2. **Snapshot prior state in the WAL Intent.**
//!    `prior_active_row_json` + `prior_command_ownership_json` carry
//!    the data recovery's `roll_back` needs to restore on failure
//!    (re-emit shims pointing at the old install root, restore prior
//!    alias rows).
//! 3. **Atomic shim swap at commit.** Same command names, new install
//!    root — `emit_shim` does the rename-over-existing dance. Old
//!    install root goes onto `manifest.tombstones` for `store gc`.
//!    Slow install work is covered by the same tx-local in-flight lock
//!    as `install -g`, so startup recovery never rolls back a live
//!    update while unrelated global installs can still overlap fetches.
//!
//! `lpm global update` (no arg) iterates every package and re-resolves
//! against its persisted `saved_spec`. `lpm global update <pkg>` does
//! the same scoped to one package. `lpm global update <pkg>@<spec>`
//! rewrites the saved_spec via the `decide_saved_dependency_spec`
//! before resolving.
//!
//! `--dry-run` runs every step up to `prepare_locked` but releases
//! the lock without writing anything; the upgrade plan is printed.

mod commit;
mod inner;
mod prepare;
mod rollback;
#[cfg(test)]
mod test_support;

use self::commit::{UpgradeOutput, commit_upgrade_batch_locked, commit_upgrade_locked};
use self::inner::do_install_upgrade;
use self::prepare::{
    StagedUpgrade, UpgradePrep, active_matches_planned_snapshot, prepare_upgrade_batch_locked,
    prepare_upgrade_locked,
};
use super::global_util::{discover_bin_commands, mk_tx_id, pick_version_with_policy};
use crate::save_spec::{
    SaveConfig, SaveFlags, UserSaveIntent, decide_saved_dependency_spec, parse_user_save_intent,
};
use crate::{install_ui, output};
use futures::StreamExt;
use lpm_common::color::Painted;
use lpm_common::{
    ExclusiveLockHandle, LpmError, LpmRoot, acquire_exclusive_lock, sanitize_for_terminal,
    with_exclusive_lock, with_exclusive_lock_async,
};
use lpm_global::{
    GlobalManifest, InstallReadyMarker, PackageSource, read_for, write_for, write_marker,
};
use lpm_registry::{PackageMetadata, RegistryClient, UpstreamRoute};
use lpm_semver::Version;
use std::collections::HashMap;
use std::sync::Arc;

const GLOBAL_UPDATE_PLANNING_CONCURRENCY: usize = 4;
const GLOBAL_UPDATE_INSTALL_CONCURRENCY: usize = 4;
const GLOBAL_UPDATE_TRANSACTION_BATCH_SIZE: usize = 16;

fn bounded_install_stream<I, F>(futures: I) -> impl futures::Stream<Item = F::Output>
where
    I: IntoIterator<Item = F>,
    F: std::future::Future,
{
    futures::stream::iter(futures).buffer_unordered(GLOBAL_UPDATE_INSTALL_CONCURRENCY)
}

fn update_failure_reason(error: &LpmError) -> String {
    let LpmError::NotFound(detail) = error else {
        return error.to_string();
    };
    let detail = detail.trim();
    if detail.is_empty() {
        return "Not found".to_string();
    }
    if let Some(suffix) = detail.get("not found".len()..)
        && detail
            .get(.."not found".len())
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("not found"))
    {
        return format!("Not found{suffix}");
    }
    format!("Not found: {detail}")
}

pub async fn run(
    client: &RegistryClient,
    package: Option<&str>,
    dry_run: bool,
    json_output: bool,
) -> Result<(), LpmError> {
    let root = LpmRoot::from_env()?;
    let planning_registry = client.clone_with_config().without_metadata_memory_cache();
    let install_registry = client.clone_with_metadata_memory_cache();
    let manifest = read_for(&root)?;

    let targets = match package {
        Some(spec) => vec![parse_target(spec)?],
        None => collect_all_targets(&manifest),
    };

    if targets.is_empty() {
        if json_output {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "success": true,
                    "updated": [],
                    "skipped": [],
                    "dry_run": dry_run,
                }))
                .unwrap()
            );
        } else {
            output::info("No globally-installed packages to update.");
        }
        return Ok(());
    }

    let release_age_policy = crate::release_age_selection::resolver_policy_for_project(
        &root.global_root(),
        None,
        false,
        json_output,
    )?;
    let aliases_by_package = index_aliases_by_package(&manifest);
    let manifest_ref = &manifest;
    let planning_registry_ref = &planning_registry;
    let release_age_policy_ref = &release_age_policy;
    let aliases_by_package_ref = &aliases_by_package;
    let planning = futures::stream::iter(targets.into_iter().enumerate().map(
        move |(target_index, target)| async move {
            let result = plan_upgrade(
                manifest_ref,
                planning_registry_ref,
                &target,
                release_age_policy_ref,
                aliases_by_package_ref,
            )
            .await;
            (target_index, target, result)
        },
    ))
    .buffer_unordered(GLOBAL_UPDATE_PLANNING_CONCURRENCY);
    futures::pin_mut!(planning);
    let mut planned = Vec::with_capacity(manifest.packages.len());
    while let Some(result) = planning.next().await {
        planned.push(result);
    }
    planned.sort_by_key(|(target_index, _, _)| *target_index);

    let mut plans = Vec::with_capacity(planned.len());
    for (_, target, result) in planned {
        match result {
            Ok(plan) => plans.push(plan),
            Err(error) => {
                let reason = update_failure_reason(&error);
                if !json_output {
                    let name_safe = sanitize_for_terminal(&target.name);
                    let reason_safe = sanitize_for_terminal(&reason);
                    output::warn_line(install_ui::terminal_line!(
                        "planning {}: {}",
                        install_ui::bold(&name_safe),
                        reason_safe,
                    ));
                }
                // Continue planning other targets — one bad spec doesn't
                // block the bulk update.
                plans.push(UpgradePlan::PlanError {
                    package: target.name,
                    reason,
                });
            }
        }
    }

    if dry_run {
        emit_dry_run(&plans, json_output);
        // A dry run that found planning errors must fail after emitting
        // the diagnostic plan, so automation can trust the exit status.
        let any_plan_error = plans
            .iter()
            .any(|p| matches!(p, UpgradePlan::PlanError { .. }));
        if any_plan_error {
            return Err(LpmError::ExitCode(1));
        }
        return Ok(());
    }

    let mut ordered_results: Vec<Option<UpgradeResult>> =
        std::iter::repeat_with(|| None).take(plans.len()).collect();
    let mut upgrades = Vec::new();
    for (index, plan) in plans.into_iter().enumerate() {
        match plan {
            UpgradePlan::Upgrade {
                prep,
                metadata,
                route,
            } => {
                if !install_registry.seed_metadata_for_command(
                    &prep.name,
                    &route.upstream_route(),
                    metadata,
                ) {
                    ordered_results[index] = Some(UpgradeResult::Failed {
                        package: prep.name.clone(),
                        reason: "failed to retain validated global-update metadata".to_string(),
                    });
                    continue;
                }
                upgrades.push((index, prep));
            }
            UpgradePlan::SaveSpecRewrite {
                package,
                version,
                old_saved_spec,
                new_saved_spec,
                prior_snapshot,
            } => {
                match execute_saved_spec_rewrite(
                    &root,
                    &package,
                    &old_saved_spec,
                    &new_saved_spec,
                    &prior_snapshot,
                ) {
                    Ok(()) => {
                        ordered_results[index] = Some(UpgradeResult::SaveSpecRewritten {
                            package,
                            version,
                            old_saved_spec,
                            new_saved_spec,
                        })
                    }
                    Err(e) => {
                        ordered_results[index] = Some(UpgradeResult::Failed {
                            package,
                            reason: e.to_string(),
                        })
                    }
                }
            }
            UpgradePlan::AlreadyCurrent { package, version } => {
                ordered_results[index] = Some(UpgradeResult::AlreadyCurrent { package, version });
            }
            UpgradePlan::PlanError { package, reason } => {
                ordered_results[index] = Some(UpgradeResult::Failed { package, reason });
            }
        }
    }

    if upgrades.len() == 1 {
        let (index, prep) = upgrades.pop().expect("one queued global upgrade");
        ordered_results[index] = Some(
            match execute_upgrade(&root, &install_registry, prep, json_output).await {
                Ok(output) => UpgradeResult::Upgraded(output),
                Err((package, error)) => UpgradeResult::Failed {
                    package,
                    reason: error.to_string(),
                },
            },
        );
    } else {
        let mut queued_upgrades = upgrades.into_iter();
        loop {
            let batch = queued_upgrades
                .by_ref()
                .take(GLOBAL_UPDATE_TRANSACTION_BATCH_SIZE)
                .collect::<Vec<_>>();
            if batch.is_empty() {
                break;
            }
            for (index, result) in
                execute_upgrade_batch(&root, &install_registry, batch, true).await
            {
                ordered_results[index] = Some(result);
            }
        }
    }
    let results: Vec<UpgradeResult> = ordered_results
        .into_iter()
        .map(|result| result.expect("every global update plan produces one result"))
        .collect();

    // Opportunistic tombstone sweep. Each successful
    // upgrade pushed the prior install root onto `manifest.tombstones`;
    // run one non-blocking sweep after the bulk loop (rather than one
    // per package) so a 50-package bulk update doesn't serialise 50
    // lock acquires. Bulk updates are the common case where this
    // matters. Best-effort — never fails the caller.
    crate::commands::global::run_opportunistic_sweep(&root);

    emit_results(&results, json_output);

    // Exit non-zero on any failure so shell automation can detect partial
    // or total bulk-update failures. In JSON mode, `emit_results` already
    // wrote the structured envelope, so return `ExitCode` to avoid a second
    // top-level JSON document.
    let failed: Vec<&str> = results
        .iter()
        .filter_map(|r| match r {
            UpgradeResult::Failed { package, .. } => Some(package.as_str()),
            _ => None,
        })
        .collect();
    if !failed.is_empty() {
        if json_output {
            return Err(LpmError::ExitCode(1));
        }
        return Err(LpmError::Script(format!(
            "{} package(s) failed to update: {}",
            failed.len(),
            failed.join(", ")
        )));
    }
    Ok(())
}

// ─── Target parsing ──────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct Target {
    /// Package name as keyed in `[packages.*]`.
    name: String,
    /// `Some(intent)` when the user typed `pkg@spec` — decides
    /// the new saved_spec from this. `None` means "re-resolve against
    /// the existing saved_spec," which is the bulk-update default and
    /// the `lpm global update <pkg>` (no version) shape.
    new_intent: Option<UserSaveIntent>,
}

fn parse_target(spec: &str) -> Result<Target, LpmError> {
    let (name, intent) = parse_user_save_intent(spec)?;
    let new_intent = if matches!(&intent, UserSaveIntent::Bare) {
        None
    } else {
        Some(intent)
    };
    Ok(Target { name, new_intent })
}

fn collect_all_targets(manifest: &GlobalManifest) -> Vec<Target> {
    manifest
        .packages
        .iter()
        .filter(|(_, entry)| entry.source != PackageSource::LocalLink)
        .map(|(name, _)| Target {
            name: name.clone(),
            new_intent: None,
        })
        .collect()
}

fn index_aliases_by_package(manifest: &GlobalManifest) -> HashMap<String, serde_json::Value> {
    let mut aliases_by_package: HashMap<String, serde_json::Map<String, serde_json::Value>> =
        HashMap::with_capacity(manifest.packages.len());
    for (alias, entry) in &manifest.aliases {
        aliases_by_package
            .entry(entry.package.clone())
            .or_default()
            .insert(
                alias.clone(),
                serde_json::json!({"package": entry.package, "bin": entry.bin}),
            );
    }
    aliases_by_package
        .into_iter()
        .map(|(package, aliases)| (package, serde_json::Value::Object(aliases)))
        .collect()
}

// ─── Planning ────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
enum UpgradePlan {
    /// Resolved version differs from the active one — full upgrade tx.
    Upgrade {
        prep: Box<UpgradePrep>,
        metadata: Arc<PackageMetadata>,
        route: MetadataRoute,
    },
    /// Resolved version is unchanged but the user typed a `<pkg>@<spec>`
    /// that produces a different `saved_spec` — manifest-only mutation
    /// that retunes the bulk-update tracking policy without touching
    /// the install root.
    ///
    /// `prior_snapshot` carries the full pre-rewrite row (same shape
    /// as Upgrade's `prior_active_row_json`). The execute step
    /// re-validates the WHOLE row under the lock — not just
    /// `saved_spec` — so a concurrent upgrade that landed between
    /// planning and rewrite can't "retune" the new active row with a
    /// stale plan. For example, a rewrite planned against 3.8.3 must not
    /// retune a concurrent 3.8.4 upgrade that landed before execution.
    SaveSpecRewrite {
        package: String,
        version: String,
        old_saved_spec: String,
        new_saved_spec: String,
        prior_snapshot: Box<serde_json::Value>,
    },
    /// No version change AND no saved_spec change.
    AlreadyCurrent {
        package: String,
        version: String,
    },
    PlanError {
        package: String,
        reason: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MetadataRoute {
    Lpm,
    PublicNpm,
}

impl MetadataRoute {
    fn upstream_route(self) -> UpstreamRoute {
        match self {
            Self::Lpm => UpstreamRoute::LpmWorker,
            Self::PublicNpm => UpstreamRoute::NpmDirect,
        }
    }

    fn release_time_source(self) -> crate::release_age_selection::ReleaseTimeMetadataSource {
        match self {
            Self::Lpm => crate::release_age_selection::ReleaseTimeMetadataSource::WorkerOnly,
            Self::PublicNpm => crate::release_age_selection::ReleaseTimeMetadataSource::NpmDirect,
        }
    }
}

async fn plan_upgrade(
    manifest: &GlobalManifest,
    registry: &RegistryClient,
    target: &Target,
    release_age_policy: &lpm_resolver::ResolverPolicy,
    aliases_by_package: &HashMap<String, serde_json::Value>,
) -> Result<UpgradePlan, LpmError> {
    let active = manifest.packages.get(&target.name).ok_or_else(|| {
        LpmError::Script(format!(
            "'{}' is not globally installed. Run `lpm install -g {}` first.",
            target.name, target.name
        ))
    })?;
    if active.source == PackageSource::LocalLink {
        return Err(LpmError::Script(format!(
            "'{}' is a local global link. Edit the linked checkout directly, or run \
             `lpm global unlink {}` and `lpm global link <path>` if the package metadata changed.",
            target.name, target.name
        )));
    }

    // `decide_saved_dependency_spec` needs a UserSaveIntent. For bulk
    // update / `lpm global update <pkg>`, we re-resolve against the
    // existing saved_spec — i.e. treat the persisted spec as a Range
    // and look for the highest matching newer version. For the
    // `pkg@spec` form, the user-typed intent overrides.
    let intent = match &target.new_intent {
        Some(i) => i.clone(),
        None => infer_intent_from_saved_spec(&active.saved_spec),
    };

    // Dispatch by name shape — same as install_global.
    let route = match active.source {
        PackageSource::LpmDev => MetadataRoute::Lpm,
        PackageSource::UpstreamNpm => MetadataRoute::PublicNpm,
        PackageSource::LocalLink => unreachable!("local links returned above"),
    };
    let mut metadata = match route {
        MetadataRoute::Lpm => {
            let package = lpm_common::PackageName::parse(&target.name).map_err(|error| {
                LpmError::Script(format!(
                    "invalid LPM package name '{}': {error}",
                    target.name
                ))
            })?;
            registry
                .revalidate_package_metadata_with_timings(&package)
                .await?
                .metadata
        }
        MetadataRoute::PublicNpm => {
            registry
                .revalidate_npm_metadata_direct_with_timings(&target.name)
                .await?
                .metadata
        }
    };
    crate::release_age_selection::hydrate_release_times_if_needed(
        registry,
        &mut metadata,
        release_age_policy,
        route.release_time_source(),
    )
    .await?;
    let new_version_str =
        pick_version_with_policy(&metadata, &intent, "global update", release_age_policy)?;
    let new_version = Version::parse(&new_version_str).map_err(|e| {
        LpmError::Script(format!(
            "registry returned unparseable version '{new_version_str}' for '{}': {e}",
            target.name
        ))
    })?;
    ensure_registry_serves_version(&metadata, &new_version_str)?;
    let current_version = Version::parse(&active.resolved).map_err(|error| {
        LpmError::Script(format!(
            "global manifest contains invalid resolved version '{}' for '{}': {error}",
            active.resolved, target.name
        ))
    })?;
    if target.new_intent.is_none() && new_version <= current_version {
        return Ok(UpgradePlan::AlreadyCurrent {
            package: target.name.clone(),
            version: active.resolved.clone(),
        });
    }

    // Compute the new saved_spec before the already-current check; an
    // unchanged version can still need a manifest-only tracking rewrite.
    let new_saved_spec = decide_saved_dependency_spec(
        &intent,
        &new_version,
        SaveFlags::default(),
        SaveConfig::default(),
    )
    .spec_to_write;

    // Snapshot the active row up-front. Both the Upgrade and
    // SaveSpecRewrite branches need it for the under-lock match
    // check that prevents stale-plan lost updates.
    let prior_active_row_json = serde_json::json!({
        "saved_spec": active.saved_spec,
        "resolved": active.resolved,
        "integrity": active.integrity,
        "source": serde_json::to_value(active.source).unwrap(),
        "installed_at": active.installed_at.to_rfc3339(),
        "root": active.root,
        "commands": active.commands,
    });

    // Three-way classification:
    //   resolved differs            → Upgrade
    //   resolved same, saved_spec differs → SaveSpecRewrite
    //   both unchanged              → AlreadyCurrent
    if new_version.to_string() == active.resolved {
        if new_saved_spec != active.saved_spec {
            return Ok(UpgradePlan::SaveSpecRewrite {
                package: target.name.clone(),
                version: active.resolved.clone(),
                old_saved_spec: active.saved_spec.clone(),
                new_saved_spec,
                prior_snapshot: Box::new(prior_active_row_json),
            });
        }
        return Ok(UpgradePlan::AlreadyCurrent {
            package: target.name.clone(),
            version: active.resolved.clone(),
        });
    }

    let version_meta = metadata.versions.get(&new_version_str).ok_or_else(|| {
        LpmError::Script(format!(
            "version '{new_version_str}' missing from metadata for '{}'",
            target.name
        ))
    })?;
    let new_integrity = version_meta
        .dist
        .as_ref()
        .and_then(|d| d.integrity.clone())
        .ok_or_else(|| {
            LpmError::Script(format!(
                "version '{new_version_str}' of '{}' has no integrity hash in registry metadata",
                target.name
            ))
        })?;

    let source = active.source;

    let selected_metadata = Arc::new(compact_metadata_for_version(&metadata, &new_version_str)?);
    Ok(UpgradePlan::Upgrade {
        prep: Box::new(UpgradePrep {
            name: target.name.clone(),
            current_version: active.resolved.clone(),
            new_version,
            new_saved_spec,
            new_integrity,
            source,
            prior_active_row_json,
            prior_aliases_json: aliases_by_package
                .get(&target.name)
                .cloned()
                .unwrap_or_else(|| serde_json::Value::Object(serde_json::Map::new())),
        }),
        metadata: selected_metadata,
        route,
    })
}

fn compact_metadata_for_version(
    metadata: &PackageMetadata,
    version: &str,
) -> Result<PackageMetadata, LpmError> {
    let selected = metadata.version(version).cloned().ok_or_else(|| {
        LpmError::Registry(format!(
            "registry selected missing version '{}@{version}'",
            metadata.name
        ))
    })?;
    let mut dist_tags = HashMap::with_capacity(1);
    dist_tags.insert("latest".to_string(), version.to_string());
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

/// Infer a UserSaveIntent from a persisted saved_spec string. The
/// saved_spec was already produced by `decide_saved_dependency_spec`
/// at install time, so it's always a valid range / exact / wildcard
/// spec. For bulk-update we treat it as a Range so the next call to
/// `decide_saved_dependency_spec` preserves the user's original
/// shape (caret stays caret, tilde stays tilde, exact stays exact).
fn infer_intent_from_saved_spec(saved_spec: &str) -> UserSaveIntent {
    if saved_spec == "*" {
        return UserSaveIntent::Wildcard;
    }
    if saved_spec.starts_with("workspace:") {
        return UserSaveIntent::Workspace(saved_spec.to_string());
    }
    if Version::parse(saved_spec).is_ok() {
        return UserSaveIntent::Exact(saved_spec.to_string());
    }
    UserSaveIntent::Range(saved_spec.to_string())
}

fn ensure_registry_serves_version(
    metadata: &lpm_registry::PackageMetadata,
    version: &str,
) -> Result<(), LpmError> {
    if metadata.versions.contains_key(version) {
        return Ok(());
    }
    Err(LpmError::Script(format!(
        "registry no longer serves version '{version}' for '{}' - the version may have been yanked or deleted upstream",
        metadata.name
    )))
}

// ─── Execution ───────────────────────────────────────────────────────

#[derive(Debug, Clone)]
enum UpgradeResult {
    Upgraded(UpgradeOutput),
    /// Manifest-only mutation outcome (no version change). Same shape
    /// as `UpgradePlan::SaveSpecRewrite`. Output emitter renders this
    /// distinctly so users can see "spec retuned, version stayed."
    SaveSpecRewritten {
        package: String,
        version: String,
        old_saved_spec: String,
        new_saved_spec: String,
    },
    AlreadyCurrent {
        package: String,
        version: String,
    },
    Failed {
        package: String,
        reason: String,
    },
}

struct BatchUpgrade {
    index: usize,
    prep: Box<UpgradePrep>,
    tx_id: String,
    _inflight_lock: ExclusiveLockHandle,
}

struct PreparedBatchUpgrade {
    index: usize,
    prep: Box<UpgradePrep>,
    staged: StagedUpgrade,
    _inflight_lock: ExclusiveLockHandle,
}

async fn execute_upgrade_batch(
    root: &LpmRoot,
    registry: &RegistryClient,
    upgrades: Vec<(usize, Box<UpgradePrep>)>,
    suppress_nested_output: bool,
) -> Vec<(usize, UpgradeResult)> {
    let upgrade_count = upgrades.len();
    let mut results = Vec::with_capacity(upgrade_count);
    let mut locked = Vec::with_capacity(upgrade_count);
    for (index, prep) in upgrades {
        let tx_id = mk_tx_id();
        match acquire_exclusive_lock(lpm_global::inflight_tx_lock(root, &tx_id)) {
            Ok(inflight_lock) => locked.push(BatchUpgrade {
                index,
                prep,
                tx_id,
                _inflight_lock: inflight_lock,
            }),
            Err(error) => results.push((
                index,
                UpgradeResult::Failed {
                    package: prep.name.clone(),
                    reason: error.to_string(),
                },
            )),
        }
    }
    if locked.is_empty() {
        return results;
    }

    let prepare_inputs = locked
        .iter()
        .map(|upgrade| (upgrade.prep.as_ref(), upgrade.tx_id.clone()))
        .collect::<Vec<_>>();
    let prepared = match with_exclusive_lock(root.global_tx_lock(), || {
        prepare_upgrade_batch_locked(root, &prepare_inputs)
    }) {
        Ok(prepared) => prepared,
        Err(error) => {
            let reason = error.to_string();
            results.extend(locked.into_iter().map(|upgrade| {
                (
                    upgrade.index,
                    UpgradeResult::Failed {
                        package: upgrade.prep.name.clone(),
                        reason: reason.clone(),
                    },
                )
            }));
            return results;
        }
    };

    let mut ready = Vec::with_capacity(locked.len());
    for (upgrade, prepared) in locked.into_iter().zip(prepared) {
        match prepared {
            Ok(staged) => ready.push(PreparedBatchUpgrade {
                index: upgrade.index,
                prep: upgrade.prep,
                staged,
                _inflight_lock: upgrade._inflight_lock,
            }),
            Err(error) => results.push((
                upgrade.index,
                UpgradeResult::Failed {
                    package: upgrade.prep.name.clone(),
                    reason: error.to_string(),
                },
            )),
        }
    }

    let installs = bounded_install_stream(ready.into_iter().map(|upgrade| async move {
        let install_result = async {
            do_install_upgrade(
                root,
                registry,
                &upgrade.prep,
                &upgrade.staged,
                suppress_nested_output,
            )
            .await?;
            let commands = discover_bin_commands(&upgrade.staged.install_root, &upgrade.prep.name)?;
            if commands.is_empty() {
                return Err(LpmError::Script(format!(
                    "package '{}' exposes no bin entries — refusing to upgrade",
                    upgrade.prep.name
                )));
            }
            write_marker(
                &upgrade.staged.install_root,
                &InstallReadyMarker::new(commands),
            )?;
            Ok(())
        }
        .await;
        (upgrade, install_result)
    }));
    futures::pin_mut!(installs);
    let mut commit_ready = Vec::with_capacity(upgrade_count);
    while let Some((upgrade, install_result)) = installs.next().await {
        match install_result {
            Ok(()) => commit_ready.push(upgrade),
            Err(error) => results.push((
                upgrade.index,
                UpgradeResult::Failed {
                    package: upgrade.prep.name.clone(),
                    reason: error.to_string(),
                },
            )),
        }
    }

    if !commit_ready.is_empty() {
        commit_ready.sort_by_key(|upgrade| upgrade.index);
        let commit_inputs = commit_ready
            .iter()
            .map(|upgrade| (upgrade.prep.as_ref(), &upgrade.staged))
            .collect::<Vec<_>>();
        match with_exclusive_lock(root.global_tx_lock(), || {
            commit_upgrade_batch_locked(root, &commit_inputs)
        }) {
            Ok(commit_results) => {
                for (upgrade, commit_result) in commit_ready.into_iter().zip(commit_results) {
                    let result = match commit_result {
                        Ok(output) => UpgradeResult::Upgraded(output),
                        Err(error) => UpgradeResult::Failed {
                            package: upgrade.prep.name.clone(),
                            reason: error.to_string(),
                        },
                    };
                    results.push((upgrade.index, result));
                }
            }
            Err(error) => {
                let reason = error.to_string();
                results.extend(commit_ready.into_iter().map(|upgrade| {
                    (
                        upgrade.index,
                        UpgradeResult::Failed {
                            package: upgrade.prep.name.clone(),
                            reason: reason.clone(),
                        },
                    )
                }));
            }
        }
    }

    results
}

async fn execute_upgrade(
    root: &LpmRoot,
    registry: &RegistryClient,
    prep: Box<UpgradePrep>,
    suppress_nested_output: bool,
) -> Result<UpgradeOutput, (String, LpmError)> {
    let package_name = prep.name.clone();
    let tx_id = mk_tx_id();
    let inflight_lock = lpm_global::inflight_tx_lock(root, &tx_id);
    with_exclusive_lock_async(inflight_lock, async {
        let staged = with_exclusive_lock(root.global_tx_lock(), || {
            prepare_upgrade_locked(root, &prep, tx_id)
        })?;

        do_install_upgrade(root, registry, &prep, &staged, suppress_nested_output).await?;
        let commands = discover_bin_commands(&staged.install_root, &prep.name)?;
        if commands.is_empty() {
            return Err(LpmError::Script(format!(
                "package '{}' exposes no bin entries — refusing to upgrade",
                prep.name
            )));
        }
        let marker = InstallReadyMarker::new(commands);
        write_marker(&staged.install_root, &marker)?;

        with_exclusive_lock(root.global_tx_lock(), || {
            commit_upgrade_locked(root, &prep, &staged)
        })
    })
    .await
    .map_err(|e| (package_name, e))
}

// ─── Output ──────────────────────────────────────────────────────────

fn emit_dry_run(plans: &[UpgradePlan], json_output: bool) {
    let any_plan_error = plans
        .iter()
        .any(|p| matches!(p, UpgradePlan::PlanError { .. }));
    if json_output {
        let entries: Vec<_> = plans
            .iter()
            .map(|p| match p {
                UpgradePlan::Upgrade { prep, .. } => serde_json::json!({
                    "package": prep.name,
                    "action": "upgrade",
                    "from": prep.current_version,
                    "to": prep.new_version.to_string(),
                    "saved_spec": prep.new_saved_spec,
                }),
                UpgradePlan::SaveSpecRewrite {
                    package,
                    version,
                    old_saved_spec,
                    new_saved_spec,
                    ..
                } => serde_json::json!({
                    "package": package,
                    "action": "saved_spec_rewrite",
                    "current": version,
                    "from_saved_spec": old_saved_spec,
                    "to_saved_spec": new_saved_spec,
                }),
                UpgradePlan::AlreadyCurrent { package, version } => serde_json::json!({
                    "package": package,
                    "action": "skip",
                    "current": version,
                }),
                UpgradePlan::PlanError { package, reason } => serde_json::json!({
                    "package": package,
                    "action": "plan_error",
                    "reason": reason,
                }),
            })
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "success": !any_plan_error,
                "dry_run": true,
                "plans": entries,
            }))
            .unwrap()
        );
        return;
    }
    let mut any_action = false;
    for plan in plans {
        match plan {
            UpgradePlan::Upgrade { prep, .. } => {
                any_action = true;
                let name_safe = sanitize_for_terminal(&prep.name);
                let current_safe = sanitize_for_terminal(&prep.current_version);
                let new_safe = sanitize_for_terminal(&prep.new_version.to_string());
                eprintln!(
                    "  {} {} \u{2192} {}",
                    name_safe.bold(),
                    current_safe.dimmed(),
                    new_safe.green()
                );
            }
            UpgradePlan::SaveSpecRewrite {
                package,
                version,
                old_saved_spec,
                new_saved_spec,
                ..
            } => {
                any_action = true;
                let package_safe = sanitize_for_terminal(package);
                let version_safe = sanitize_for_terminal(version);
                let old_safe = sanitize_for_terminal(old_saved_spec);
                let new_safe = sanitize_for_terminal(new_saved_spec);
                eprintln!(
                    "  {} {} (saved_spec {} \u{2192} {})",
                    package_safe.bold(),
                    format!("@{version_safe}").dimmed(),
                    old_safe.dimmed(),
                    new_safe.green()
                );
            }
            UpgradePlan::AlreadyCurrent { package, version } => {
                let package_safe = sanitize_for_terminal(package);
                let version_safe = sanitize_for_terminal(version);
                eprintln!(
                    "  {} {} (already current)",
                    package_safe.dimmed(),
                    format!("@{version_safe}").dimmed()
                );
            }
            UpgradePlan::PlanError { package, reason } => {
                let package_safe = sanitize_for_terminal(package);
                let reason_safe = sanitize_for_terminal(reason);
                eprintln!(
                    "  {} {} {}",
                    package_safe.bold(),
                    "could not plan:".red(),
                    reason_safe
                );
            }
        }
    }
    if !any_action {
        output::info("Nothing to update.");
    }
}

fn emit_results(results: &[UpgradeResult], json_output: bool) {
    if json_output {
        let entries: Vec<_> = results
            .iter()
            .map(|r| match r {
                UpgradeResult::Upgraded(out) => serde_json::json!({
                    "package": out.name,
                    "action": "upgraded",
                    "from": out.from_version,
                    "to": out.to_version,
                    "saved_spec": out.saved_spec,
                    "commands": out.commands,
                }),
                UpgradeResult::SaveSpecRewritten {
                    package,
                    version,
                    old_saved_spec,
                    new_saved_spec,
                } => serde_json::json!({
                    "package": package,
                    "action": "saved_spec_rewritten",
                    "current": version,
                    "from_saved_spec": old_saved_spec,
                    "to_saved_spec": new_saved_spec,
                }),
                UpgradeResult::AlreadyCurrent { package, version } => serde_json::json!({
                    "package": package,
                    "action": "skip",
                    "current": version,
                }),
                UpgradeResult::Failed { package, reason } => serde_json::json!({
                    "package": package,
                    "action": "failed",
                    "reason": reason,
                }),
            })
            .collect();
        let any_failure = results
            .iter()
            .any(|r| matches!(r, UpgradeResult::Failed { .. }));
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "success": !any_failure,
                "dry_run": false,
                "results": entries,
            }))
            .unwrap()
        );
        return;
    }
    for r in results {
        match r {
            UpgradeResult::Upgraded(out) => {
                let name_safe = sanitize_for_terminal(&out.name);
                let from_safe = sanitize_for_terminal(&out.from_version);
                let to_safe = sanitize_for_terminal(&out.to_version);
                output::success_line(install_ui::terminal_line!(
                    "Upgraded {} {} \u{2192} {}",
                    install_ui::bold(&name_safe),
                    install_ui::dim(&from_safe),
                    install_ui::green(&to_safe),
                ));
            }
            UpgradeResult::SaveSpecRewritten {
                package,
                version,
                old_saved_spec,
                new_saved_spec,
            } => {
                let package_safe = sanitize_for_terminal(package);
                let version_safe = sanitize_for_terminal(version);
                let old_safe = sanitize_for_terminal(old_saved_spec);
                let new_safe = sanitize_for_terminal(new_saved_spec);
                output::success_line(install_ui::terminal_line!(
                    "Retuned {} {} (saved_spec {} \u{2192} {})",
                    install_ui::bold(&package_safe),
                    install_ui::dim(&format!("@{version_safe}")),
                    install_ui::dim(&old_safe),
                    install_ui::green(&new_safe),
                ));
            }
            UpgradeResult::AlreadyCurrent { package, version } => {
                let package_safe = sanitize_for_terminal(package);
                let version_safe = sanitize_for_terminal(version);
                output::info_line(install_ui::terminal_line!(
                    "{} {} already current",
                    install_ui::dim(&package_safe),
                    install_ui::dim(&format!("@{version_safe}")),
                ));
            }
            UpgradeResult::Failed { package, reason } => {
                let package_safe = sanitize_for_terminal(package);
                let reason_safe = sanitize_for_terminal(reason);
                output::warn_line(install_ui::terminal_line!(
                    "{}: {}",
                    install_ui::bold(&package_safe),
                    reason_safe,
                ));
            }
        }
    }
}

/// Manifest-only mutation: change `[packages.<pkg>].saved_spec` to
/// `new_saved_spec`. No install root work, no shim swap. Used when
/// the user's `<pkg>@<spec>` resolves to the same version that's
/// already active but expresses different tracking intent (e.g.
/// going from exact-pinned `3.8.3` to range `^3.8.3` so future bulk
/// updates pick up patches).
///
/// Atomic via the manifest writer's tempfile + rename. Re-validates
/// the WHOLE active row against the planned snapshot under the lock
/// so a concurrent upgrade cannot be retuned by a stale plan.
///
/// `old_saved_spec` is kept as a separate parameter only so the
/// "you tried to retune from X to Y but X isn't current" error
/// message names what the user typed; the actual safety check is
/// `active_matches_planned_snapshot`.
fn execute_saved_spec_rewrite(
    root: &LpmRoot,
    package: &str,
    old_saved_spec: &str,
    new_saved_spec: &str,
    prior_snapshot: &serde_json::Value,
) -> Result<(), LpmError> {
    with_exclusive_lock(root.global_tx_lock(), || {
        let mut manifest = read_for(root)?;
        let active = manifest.packages.get(package).ok_or_else(|| {
            let package_safe = sanitize_for_terminal(package);
            LpmError::Script(format!(
                "'{package_safe}' is no longer installed. Aborting saved_spec rewrite."
            ))
        })?;
        if let Err(diff) = active_matches_planned_snapshot(active, prior_snapshot) {
            let package_safe = sanitize_for_terminal(package);
            let diff_safe = sanitize_for_terminal(&diff);
            let old_safe = sanitize_for_terminal(old_saved_spec);
            let new_safe = sanitize_for_terminal(new_saved_spec);
            return Err(LpmError::Script(format!(
                "'{package_safe}' was modified by another process between planning and rewrite \
                 ({diff_safe}). The retune from {old_safe:?} to {new_safe:?} no longer \
                 applies. Re-run `lpm global update {package_safe}@<spec>` to plan against the \
                 current state."
            )));
        }
        let active_mut = manifest
            .packages
            .get_mut(package)
            .expect("just checked it exists");
        active_mut.saved_spec = new_saved_spec.to_string();
        write_for(root, &manifest)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scoped_update_env(
        path: &std::path::Path,
        registry_url: Option<&str>,
    ) -> crate::test_env::ScopedEnv {
        let mut vars = vec![("LPM_HOME", Some(path.as_os_str().to_owned()))];
        if let Some(registry_url) = registry_url {
            vars.push(("LPM_REGISTRY_URL", Some(registry_url.into())));
        }
        crate::test_env::ScopedEnv::update(vars)
    }

    #[tokio::test]
    async fn install_scheduler_never_exceeds_four_in_flight_upgrades() {
        async fn wait_for_count(
            counter: &std::sync::atomic::AtomicUsize,
            notification: &tokio::sync::Notify,
            expected: usize,
        ) {
            tokio::time::timeout(std::time::Duration::from_secs(5), async {
                while counter.load(std::sync::atomic::Ordering::SeqCst) < expected {
                    notification.notified().await;
                }
            })
            .await
            .expect("bounded install scheduler stopped making progress");
        }

        let permits = Arc::new(tokio::sync::Semaphore::new(0));
        let current = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let maximum = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let started = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let notification = Arc::new(tokio::sync::Notify::new());
        let future_permits = Arc::clone(&permits);
        let future_current = Arc::clone(&current);
        let future_maximum = Arc::clone(&maximum);
        let future_started = Arc::clone(&started);
        let future_notification = Arc::clone(&notification);
        let install_futures = (0..8).map(move |_| {
            let permits = Arc::clone(&future_permits);
            let current = Arc::clone(&future_current);
            let maximum = Arc::clone(&future_maximum);
            let started = Arc::clone(&future_started);
            let notification = Arc::clone(&future_notification);
            async move {
                let active = current.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
                maximum.fetch_max(active, std::sync::atomic::Ordering::SeqCst);
                started.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                notification.notify_waiters();
                permits
                    .acquire()
                    .await
                    .expect("test semaphore stays open")
                    .forget();
                current.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
            }
        });
        let scheduler = tokio::spawn(async move {
            bounded_install_stream(install_futures)
                .collect::<Vec<_>>()
                .await
        });

        wait_for_count(&started, &notification, 4).await;
        assert_eq!(started.load(std::sync::atomic::Ordering::SeqCst), 4);
        assert_eq!(current.load(std::sync::atomic::Ordering::SeqCst), 4);
        assert_eq!(maximum.load(std::sync::atomic::Ordering::SeqCst), 4);

        permits.add_permits(4);
        wait_for_count(&started, &notification, 8).await;
        assert_eq!(started.load(std::sync::atomic::Ordering::SeqCst), 8);
        assert_eq!(current.load(std::sync::atomic::Ordering::SeqCst), 4);
        assert_eq!(maximum.load(std::sync::atomic::Ordering::SeqCst), 4);

        permits.add_permits(4);
        scheduler.await.expect("join bounded install scheduler");
        assert_eq!(current.load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    #[test]
    fn parse_target_pkg_only_has_no_intent_override() {
        let t = parse_target("eslint").unwrap();
        assert_eq!(t.name, "eslint");
        assert!(t.new_intent.is_none());
    }

    #[test]
    fn parse_target_pkg_at_version_carries_exact_intent() {
        let t = parse_target("eslint@10.0.0").unwrap();
        assert_eq!(t.name, "eslint");
        assert!(matches!(t.new_intent, Some(UserSaveIntent::Exact(v)) if v == "10.0.0"));
    }

    #[test]
    fn parse_target_pkg_at_range_carries_range_intent() {
        let t = parse_target("eslint@^10").unwrap();
        assert_eq!(t.name, "eslint");
        assert!(matches!(t.new_intent, Some(UserSaveIntent::Range(v)) if v == "^10"));
    }

    #[test]
    fn parse_target_pkg_at_dist_tag_carries_disttag_intent() {
        let t = parse_target("eslint@latest").unwrap();
        assert_eq!(t.name, "eslint");
        assert!(matches!(t.new_intent, Some(UserSaveIntent::DistTag(v)) if v == "latest"));
    }

    #[test]
    fn infer_intent_caret_range_stays_range() {
        let intent = infer_intent_from_saved_spec("^9");
        assert!(matches!(intent, UserSaveIntent::Range(v) if v == "^9"));
    }

    #[test]
    fn infer_intent_exact_version_stays_exact() {
        let intent = infer_intent_from_saved_spec("9.24.0");
        assert!(matches!(intent, UserSaveIntent::Exact(v) if v == "9.24.0"));
    }

    #[test]
    fn infer_intent_wildcard_stays_wildcard() {
        let intent = infer_intent_from_saved_spec("*");
        assert!(matches!(intent, UserSaveIntent::Wildcard));
    }

    /// Build a snapshot JSON that matches the provided PackageEntry
    /// on every load-bearing field. Used by the SaveSpecRewrite tests
    /// so they only have to describe the pre-plan state once.
    fn snapshot_of(entry: &lpm_global::PackageEntry) -> serde_json::Value {
        serde_json::json!({
            "saved_spec": entry.saved_spec,
            "resolved": entry.resolved,
            "integrity": entry.integrity,
            "source": serde_json::to_value(entry.source).unwrap(),
            "installed_at": entry.installed_at.to_rfc3339(),
            "root": entry.root,
            "commands": entry.commands,
        })
    }

    /// saved_spec rewrite must succeed even when the resolved version is unchanged.
    #[test]
    fn execute_saved_spec_rewrite_changes_persisted_saved_spec_under_lock() {
        let tmp = tempfile::tempdir().unwrap();
        let root = lpm_common::LpmRoot::from_dir(tmp.path());
        let entry = lpm_global::PackageEntry {
            saved_spec: "3.8.3".into(),
            resolved: "3.8.3".into(),
            integrity: "sha512-x".into(),
            source: lpm_global::PackageSource::UpstreamNpm,
            installed_at: chrono::Utc::now(),
            root: "installs/prettier@3.8.3".into(),
            commands: vec!["prettier".into()],
        };
        let snapshot = snapshot_of(&entry);
        let mut manifest = lpm_global::GlobalManifest::default();
        manifest.packages.insert("prettier".into(), entry);
        lpm_global::write_for(&root, &manifest).unwrap();

        execute_saved_spec_rewrite(&root, "prettier", "3.8.3", "^3", &snapshot).unwrap();

        let read_back = lpm_global::read_for(&root).unwrap();
        assert_eq!(
            read_back.packages.get("prettier").unwrap().saved_spec,
            "^3",
            "saved_spec should be rewritten without a version change"
        );
        // The resolved version stays the same — this is a manifest-only
        // mutation, not a real upgrade.
        assert_eq!(
            read_back.packages.get("prettier").unwrap().resolved,
            "3.8.3"
        );
    }

    #[test]
    fn execute_saved_spec_rewrite_refuses_when_old_spec_does_not_match() {
        let tmp = tempfile::tempdir().unwrap();
        let root = lpm_common::LpmRoot::from_dir(tmp.path());
        // Planned-against snapshot: saved_spec was "3.8.3"
        let planned = lpm_global::PackageEntry {
            saved_spec: "3.8.3".into(),
            resolved: "3.8.3".into(),
            integrity: "sha512-x".into(),
            source: lpm_global::PackageSource::UpstreamNpm,
            installed_at: chrono::Utc::now(),
            root: "installs/prettier@3.8.3".into(),
            commands: vec!["prettier".into()],
        };
        let snapshot = snapshot_of(&planned);

        // On-disk reality: someone else already retuned the saved_spec.
        let mut manifest = lpm_global::GlobalManifest::default();
        manifest.packages.insert(
            "prettier".into(),
            lpm_global::PackageEntry {
                saved_spec: "^4".into(),
                resolved: "4.0.0".into(),
                integrity: "sha512-x".into(),
                source: lpm_global::PackageSource::UpstreamNpm,
                installed_at: chrono::Utc::now(),
                root: "installs/prettier@4.0.0".into(),
                commands: vec!["prettier".into()],
            },
        );
        lpm_global::write_for(&root, &manifest).unwrap();

        let err =
            execute_saved_spec_rewrite(&root, "prettier", "3.8.3", "^3", &snapshot).unwrap_err();
        assert!(format!("{err}").contains("modified by another process"));
        assert!(format!("{err}").contains("saved_spec changed"));
    }

    /// The SaveSpecRewrite prior_snapshot guards the whole row, not just saved_spec.
    ///
    /// Scenario encoded below:
    ///   plan   : active = prettier 3.8.3, saved_spec ^3; user typed `pkg@3.8.3`
    ///   disk   : concurrent bulk update landed — resolved is now 3.8.4
    ///            (saved_spec stays ^3)
    ///   expect : rewrite refuses; the now-3.8.4 row is untouched.
    #[test]
    fn execute_saved_spec_rewrite_refuses_when_resolved_changed_under_us() {
        let tmp = tempfile::tempdir().unwrap();
        let root = lpm_common::LpmRoot::from_dir(tmp.path());

        let planned = lpm_global::PackageEntry {
            saved_spec: "^3".into(),
            resolved: "3.8.3".into(),
            integrity: "sha512-old".into(),
            source: lpm_global::PackageSource::UpstreamNpm,
            installed_at: chrono::Utc::now(),
            root: "installs/prettier@3.8.3".into(),
            commands: vec!["prettier".into()],
        };
        let snapshot = snapshot_of(&planned);

        // On-disk reality: concurrent upgrade landed 3.8.3 → 3.8.4
        // while saved_spec stayed "^3".
        let upgraded = lpm_global::PackageEntry {
            saved_spec: "^3".into(),
            resolved: "3.8.4".into(),
            integrity: "sha512-new".into(),
            source: lpm_global::PackageSource::UpstreamNpm,
            installed_at: chrono::Utc::now(),
            root: "installs/prettier@3.8.4".into(),
            commands: vec!["prettier".into()],
        };
        let mut manifest = lpm_global::GlobalManifest::default();
        manifest.packages.insert("prettier".into(), upgraded);
        lpm_global::write_for(&root, &manifest).unwrap();

        // User typed `lpm global update prettier@3.8.3` to pin to exact.
        let err =
            execute_saved_spec_rewrite(&root, "prettier", "^3", "3.8.3", &snapshot).unwrap_err();
        assert!(
            format!("{err}").contains("modified by another process"),
            "expected lost-update error, got: {err}"
        );
        assert!(
            format!("{err}").contains("resolved version changed"),
            "error must name the specific field that drifted: {err}"
        );

        // The now-3.8.4 row must be untouched — no "retune" applied.
        let read_back = lpm_global::read_for(&root).unwrap();
        let row = read_back.packages.get("prettier").unwrap();
        assert_eq!(row.saved_spec, "^3");
        assert_eq!(row.resolved, "3.8.4");
        assert_eq!(row.integrity, "sha512-new");
    }

    #[test]
    fn execute_saved_spec_rewrite_errors_when_package_uninstalled() {
        let tmp = tempfile::tempdir().unwrap();
        let root = lpm_common::LpmRoot::from_dir(tmp.path());
        lpm_global::write_for(&root, &lpm_global::GlobalManifest::default()).unwrap();
        // Any snapshot — the existence check runs first.
        let snapshot = serde_json::json!({});
        let err = execute_saved_spec_rewrite(&root, "ghost", "x", "y", &snapshot).unwrap_err();
        assert!(format!("{err}").contains("no longer installed"));
    }

    /// In --json mode the failure path
    /// must return `LpmError::ExitCode(_)` rather than `LpmError::Script(_)`.
    /// `emit_results` has already written a structured failure JSON
    /// document to stdout; `LpmError::Script` causes main.rs to emit a
    /// second top-level `{"success": false, "error": ...}` document,
    /// breaking the single-JSON-document contract. ExitCode is the
    /// explicit "I've already emitted my own output, just propagate
    /// status" signal the top-level handler honours.
    #[tokio::test]
    async fn run_json_failure_returns_exit_code_not_script_error() {
        let tmp = tempfile::tempdir().unwrap();
        let _env = scoped_update_env(tmp.path(), Some("http://127.0.0.1:1"));
        // Seed a manifest with a package whose saved_spec is unparseable
        // by the registry. `plan_upgrade` will fetch metadata for it —
        // we don't have a mock registry here, so registry failure
        // becomes a PlanError, which emit_results maps to a Failed
        // result. That's enough to exercise the failure-exit path.
        let root = lpm_common::LpmRoot::from_dir(tmp.path());
        let mut manifest = lpm_global::GlobalManifest::default();
        manifest.packages.insert(
            "this-package-should-not-exist-on-any-registry-xyz123".into(),
            lpm_global::PackageEntry {
                saved_spec: "^1".into(),
                resolved: "1.0.0".into(),
                integrity: "sha512-x".into(),
                source: lpm_global::PackageSource::UpstreamNpm,
                installed_at: chrono::Utc::now(),
                root: "installs/ghost@1.0.0".into(),
                commands: vec![],
            },
        );
        lpm_global::write_for(&root, &manifest).unwrap();

        // Point registry at an unreachable host so the metadata fetch
        // fails quickly without hitting the real registry in CI.
        let r = run(&RegistryClient::new(), None, false, true).await;

        let err = r.expect_err("json failure path must return Err");
        assert!(
            matches!(err, LpmError::ExitCode(1)),
            "json-mode failure must surface as ExitCode(1) to preserve \
             single-JSON-document contract, got: {err:?}"
        );
    }
}
