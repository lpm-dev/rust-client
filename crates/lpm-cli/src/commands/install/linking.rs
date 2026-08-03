use lpm_linker::{LinkResult, MaterializedPackage};

use super::*;

#[derive(Debug, Clone)]
pub(super) struct LinkDependencyTarget {
    pub(super) name: String,
    pub(super) version: String,
    pub(super) wrapper_id: String,
}

pub(super) fn looks_like_source_dependency_key(value: &str) -> bool {
    matches!(value.as_bytes(), [b'f' | b'l' | b't' | b'g', b'-', ..])
}

pub(super) fn source_dependency_index(
    packages: &[InstallPackage],
) -> HashMap<String, LinkDependencyTarget> {
    let mut index = HashMap::with_capacity(packages.len());
    for package in packages {
        if let Some(wrapper_id) = package.wrapper_id_for_source() {
            index
                .entry(wrapper_id.clone())
                .or_insert(LinkDependencyTarget {
                    name: package.name.clone(),
                    version: package.version.clone(),
                    wrapper_id,
                });
        }
    }
    index
}

pub(super) fn link_dependencies_for_package(
    package: &InstallPackage,
    source_index: &HashMap<String, LinkDependencyTarget>,
) -> Result<Vec<lpm_linker::LinkDependency>, LpmError> {
    let mut deps = Vec::with_capacity(package.dependencies.len());
    for (local, value) in &package.dependencies {
        if let Some(target) = source_index.get(value) {
            deps.push(lpm_linker::LinkDependency::new(
                local.clone(),
                target.name.clone(),
                target.version.clone(),
                Some(target.wrapper_id.clone()),
            ));
            continue;
        }
        if looks_like_source_dependency_key(value) {
            return Err(LpmError::Registry(format!(
                "source dependency edge {local}@{value} of {}@{} has no matching package identity",
                package.name, package.version
            )));
        }
        let target_name = package
            .aliases
            .get(local)
            .cloned()
            .unwrap_or_else(|| local.clone());
        deps.push(lpm_linker::LinkDependency::new(
            local.clone(),
            target_name,
            value.clone(),
            None,
        ));
    }
    Ok(deps)
}

pub(super) fn link_target_lookup_key(name: &str, version: &str) -> String {
    let mut k = String::with_capacity(name.len() + 1 + version.len());
    k.push_str(name);
    k.push('\x00');
    k.push_str(version);
    k
}

pub(super) fn local_source_sri_for_target(target: &LinkTarget) -> String {
    local_source_sri(
        &target.name,
        &target.version,
        target.wrapper_id.as_deref(),
        &target.store_path,
    )
}

pub(super) fn local_source_sri(
    name: &str,
    version: &str,
    wrapper_id: Option<&str>,
    store_path: &Path,
) -> String {
    let seed = format!(
        "lpm-v2-local-source\0{}\0{}\0{}\0{}",
        name,
        version,
        wrapper_id.unwrap_or(""),
        store_path.display()
    );
    lpm_store::compute_sri_hash(seed.as_bytes())
}

pub(super) fn build_v2_targets(
    packages: &[InstallPackage],
    link_targets: &[LinkTarget],
) -> Result<Vec<lpm_linker::v2::V2Target>, LpmError> {
    let sri_by_pkg: HashMap<String, String> = packages
        .iter()
        .filter_map(|p| {
            p.integrity
                .clone()
                .map(|sri| (link_target_lookup_key(&p.name, &p.version), sri))
        })
        .collect();

    let mut v2_targets: Vec<lpm_linker::v2::V2Target> = Vec::with_capacity(link_targets.len());
    for target in link_targets {
        let lookup_key = link_target_lookup_key(&target.name, &target.version);
        let sri = match target.materialization {
            lpm_linker::Materialization::CasBacked => sri_by_pkg.get(&lookup_key).cloned(),
            lpm_linker::Materialization::DirectorySource => {
                Some(local_source_sri_for_target(target))
            }
        }
        .ok_or_else(|| {
            LpmError::Registry(format!(
                "v2 install: missing source SRI for {}@{}",
                target.name, target.version
            ))
        })?;
        v2_targets.push(lpm_linker::v2::V2Target {
            target: Arc::new(target.clone()),
            source_sri: sri,
            verified_object_integrity: None,
            fresh_object: None,
        });
    }

    Ok(v2_targets)
}

#[allow(clippy::too_many_arguments)]
pub(super) fn relink_bins_after_lifecycle_build(
    project_dir: &Path,
    packages: &[InstallPackage],
    link_targets: &[LinkTarget],
    linker_mode: lpm_linker::LinkerMode,
    lpm_root: &lpm_common::LpmRoot,
    object_integrity_policy: lpm_store::v2::ObjectIntegrityPolicy,
    self_package_name: Option<&str>,
    compatibility_bin_names: &[String],
    store_version: lpm_store::StoreVersion,
) -> Result<usize, LpmError> {
    let result = if store_version.is_v2() {
        let store_v2 = lpm_store::v2::Store::from_lpm_root_with_object_integrity_policy(
            lpm_root,
            object_integrity_policy,
        );
        let v2_targets = build_v2_targets(packages, link_targets)?;
        lpm_linker::v2::finalize_existing_link_entries_with_compatibility_bin_names(
            project_dir,
            v2_targets,
            &store_v2,
            linker_mode,
            self_package_name,
            compatibility_bin_names,
        )?
    } else {
        match linker_mode {
            lpm_linker::LinkerMode::Hoisted => lpm_linker::link_packages_hoisted(
                project_dir,
                link_targets,
                false,
                self_package_name,
            )?,
            lpm_linker::LinkerMode::Isolated => {
                lpm_linker::link_packages(project_dir, link_targets, false, self_package_name)?
            }
        }
    };
    Ok(result.bin_linked)
}

pub(super) struct OnlineLinkPhaseInput<'a> {
    pub(super) start: Instant,
    pub(super) project_dir: &'a Path,
    pub(super) package_name: Option<&'a str>,
    pub(super) packages: &'a [InstallPackage],
    pub(super) link_targets: &'a [LinkTarget],
    pub(super) event_driven_link: bool,
    pub(super) event_link_handles: Vec<LinkHandle>,
    pub(super) v2_mode: bool,
    pub(super) store_v2: Option<&'a lpm_store::v2::Store>,
    pub(super) v2_event_driven: bool,
    pub(super) v2_plan: Option<&'a lpm_linker::v2::LinkPlanV2>,
    pub(super) v2_event_link_handles: Vec<V2LinkHandle>,
    pub(super) prepared_v2_link_tasks: Option<PreparedV2LinkTasks>,
    pub(super) v2_link_task_timings: &'a mut V2LinkTaskTimings,
    pub(super) slow_package_timings: &'a mut SlowPackageTimings,
    pub(super) timing_detail_mode: TimingDetailMode,
    pub(super) linker_mode: lpm_linker::LinkerMode,
    pub(super) force: bool,
    pub(super) compatibility_bin_names: &'a [String],
}

pub(super) struct OnlineLinkPhaseResult {
    pub(super) link_result: LinkResult,
    pub(super) link_ms: u128,
    pub(super) waterfall_start_ms: u128,
    pub(super) waterfall_end_ms: u128,
    pub(super) await_ms: u128,
    pub(super) finalize_ms: u128,
    pub(super) reconcile_ms: u128,
    pub(super) root_symlinks_ms: u128,
    pub(super) compatibility_ms: u128,
    pub(super) bin_shims_ms: u128,
}

pub(super) struct PreparedV2LinkTasks {
    materialized: Vec<MaterializedPackage>,
    linked_count: usize,
    await_ms: u128,
}

pub(super) async fn prepare_v2_link_tasks(
    handles: Vec<V2LinkHandle>,
    v2_link_task_timings: &mut V2LinkTaskTimings,
    slow_package_timings: &mut SlowPackageTimings,
    timing_detail_mode: TimingDetailMode,
) -> Result<PreparedV2LinkTasks, LpmError> {
    let mut materialized = Vec::with_capacity(handles.len());
    let mut linked_count = 0usize;
    let started = Instant::now();
    for handle in handles {
        let task = handle.wait().await?;
        let package_display = timing_detail_mode
            .trace()
            .then(|| format!("{}@{}", task.materialized.name, task.materialized.version));
        v2_link_task_timings.record(task.ms, task.freshly_populated);
        if let Some(package_display) = package_display.as_deref() {
            slow_package_timings.record_link_v2_one(package_display, task.ms, task.timings);
        }
        if task.freshly_populated {
            linked_count += 1;
        }
        materialized.push(task.materialized);
    }
    Ok(PreparedV2LinkTasks {
        materialized,
        linked_count,
        await_ms: started.elapsed().as_millis(),
    })
}

pub(super) async fn run_online_link_phase(
    input: OnlineLinkPhaseInput<'_>,
) -> Result<OnlineLinkPhaseResult, LpmError> {
    let OnlineLinkPhaseInput {
        start,
        project_dir,
        package_name,
        packages,
        link_targets,
        event_driven_link,
        mut event_link_handles,
        v2_mode,
        store_v2,
        v2_event_driven,
        v2_plan,
        v2_event_link_handles,
        prepared_v2_link_tasks,
        v2_link_task_timings,
        slow_package_timings,
        timing_detail_mode,
        linker_mode,
        force,
        compatibility_bin_names,
    } = input;

    let waterfall_start_ms = start.elapsed().as_millis();
    let link_start = Instant::now();
    let mut await_ms = 0u128;
    let mut finalize_ms = 0u128;
    let mut reconcile_ms = 0u128;
    let mut root_symlinks_ms = 0u128;
    let mut compatibility_ms = 0u128;
    let mut bin_shims_ms = 0u128;

    let link_result = if event_driven_link {
        let mut linked_count = 0usize;
        let mut skipped_count = 0usize;
        let mut symlinked_count = 0usize;
        let mut materialized_all: Vec<MaterializedPackage> =
            Vec::with_capacity(event_link_handles.len());

        for handle in event_link_handles.drain(..) {
            let (materialized, result) = handle
                .await
                .map_err(|e| LpmError::Registry(format!("link task panicked: {e}")))??;
            materialized_all.push(materialized);
            if result.linked {
                linked_count += 1;
            } else {
                skipped_count += 1;
            }
            symlinked_count += result.symlinks_created;
        }

        let finalize = lpm_linker::link_finalize(project_dir, link_targets, package_name)?;
        symlinked_count += finalize.symlinks_created;

        LinkResult {
            linked: linked_count,
            symlinked: symlinked_count,
            bin_linked: finalize.bin_count,
            skipped: skipped_count,
            self_referenced: finalize.self_referenced,
            materialized: materialized_all,
        }
    } else if v2_mode {
        let store_v2 = store_v2.expect("v2_mode implies v2 store handle is available");
        let v2_targets = build_v2_targets(packages, link_targets)?;

        if v2_event_driven {
            let plan = v2_plan.expect("v2_event_driven implies v2_plan is Some");
            let prepared = match prepared_v2_link_tasks {
                Some(prepared) => prepared,
                None => {
                    prepare_v2_link_tasks(
                        v2_event_link_handles,
                        v2_link_task_timings,
                        slow_package_timings,
                        timing_detail_mode,
                    )
                    .await?
                }
            };
            await_ms = prepared.await_ms;
            let link_finalize_start = Instant::now();
            let finalize =
                lpm_linker::v2::link_v2_finalize(project_dir, plan, store_v2, package_name)?;
            finalize_ms = link_finalize_start.elapsed().as_millis();
            reconcile_ms = finalize.reconcile_ms;
            root_symlinks_ms = finalize.root_symlinks_ms;
            compatibility_ms = finalize.compatibility_ms;
            bin_shims_ms = finalize.bin_shims_ms;
            let target_total = plan.augmented_targets.len();
            LinkResult {
                linked: prepared.linked_count,
                symlinked: finalize.symlinked,
                bin_linked: finalize.bin_count,
                skipped: target_total.saturating_sub(prepared.linked_count),
                self_referenced: finalize.self_referenced,
                materialized: prepared.materialized,
            }
        } else {
            lpm_linker::v2::link_packages_v2_with_compatibility_bin_names(
                project_dir,
                v2_targets,
                store_v2,
                linker_mode,
                package_name,
                compatibility_bin_names,
            )?
        }
    } else {
        match linker_mode {
            lpm_linker::LinkerMode::Hoisted => {
                lpm_linker::link_packages_hoisted(project_dir, link_targets, force, package_name)?
            }
            lpm_linker::LinkerMode::Isolated => {
                lpm_linker::link_packages(project_dir, link_targets, force, package_name)?
            }
        }
    };

    Ok(OnlineLinkPhaseResult {
        link_result,
        link_ms: link_start.elapsed().as_millis(),
        waterfall_start_ms,
        waterfall_end_ms: start.elapsed().as_millis(),
        await_ms,
        finalize_ms,
        reconcile_ms,
        root_symlinks_ms,
        compatibility_ms,
        bin_shims_ms,
    })
}

/// Offline/shared path: link packages from store, write lockfile, print output.
#[allow(clippy::too_many_arguments)]
pub(super) async fn run_link_and_finish(
    _client: &RegistryClient,
    project_dir: &Path,
    _deps: &HashMap<String, String>,
    pkg: &lpm_workspace::PackageJson,
    packages: Vec<InstallPackage>,
    ephemeral_packages: &[InstallPackage],
    ephemeral_source_deps: &HashMap<String, Vec<SourceDep>>,
    downloaded: usize,
    cached: usize,
    used_lockfile: bool,
    npm_firewall_stats: NpmFirewallPreflightStats,
    policy_extension_stats: PolicyExtensionStats,
    json_output: bool,
    start: Instant,
    linker_mode: lpm_linker::LinkerMode,
    force: bool,
    workspace_member_deps: &[WorkspaceMemberLink],
    // same CLI-side policy override as
    // [`run_with_options`]. Reached via the lockfile fast path when
    // `run_with_options` short-circuits resolution; both paths must
    // render the same triage summary line when the effective policy
    // is `triage`.
    script_policy_override: Option<crate::script_policy_config::ScriptPolicy>,
    lpm_root: &lpm_common::LpmRoot,
    global_config: &crate::commands::config::GlobalConfig,
    object_integrity_policy: lpm_store::v2::ObjectIntegrityPolicy,
    auto_build: bool,
    no_sandbox: bool,
    strict_sandbox: bool,
    emit_timing: bool,
    compatibility_bin_names: &[String],
    store_version: lpm_store::StoreVersion,
    emit_install_report: bool,
) -> Result<(), LpmError> {
    crate::security_floor::clear_recorded_suppressions();
    let force_security_floor = crate::security_floor::force_security_floor_enabled(global_config);
    let mut packages = packages;
    if !ephemeral_packages.is_empty() {
        packages.extend(ephemeral_packages.iter().cloned());
        apply_post_resolve_directory_link_fixup(&mut packages, ephemeral_source_deps);
    }
    dedupe_install_packages_by_identity(&mut packages);
    let store = PackageStore::from_root(lpm_root);

    // Mirror of the online-arm
    // hoist: pre-resolve the per-target patch fingerprint map before
    // building LinkTargets so v2's GraphKey can fold patch identity
    // into the link-entry directory. The drift gate in
    // `run_with_options` already validated that `current_patches`
    // matches the persisted fingerprint by the time we reach here, so
    // any read failures are an integrity bug rather than user-visible
    // drift.
    let current_patches_for_link: HashMap<String, PatchedDependencyEntry> = pkg
        .lpm
        .as_ref()
        .map(|l| l.patched_dependencies.clone())
        .unwrap_or_default();
    let patch_fingerprints = compute_patch_fingerprints(&current_patches_for_link, project_dir)?;

    let source_index = source_dependency_index(&packages);
    let link_targets: Vec<LinkTarget> = packages
        .iter()
        .map(|p| -> Result<LinkTarget, LpmError> {
            // Typed-error path for the source-aware store path. See
            // `run_with_options` for the same conversion in the
            // cold-resolve link batch.
            Ok(LinkTarget {
                name: p.name.clone(),
                version: p.version.clone(),
                store_path: p.store_path_or_err(&store, project_dir, None)?,
                dependencies: link_dependencies_for_package(p, &source_index)?,
                aliases: p.aliases.clone(),
                is_direct: p.is_direct,
                root_link_names: p.root_link_names.clone(),
                wrapper_id: p.wrapper_id_for_source(),
                materialization: p.materialization_for_source(),
                peers: p.peers.clone(),
                patch_fingerprint: patch_fingerprints
                    .get(&(p.name.clone(), p.version.clone()))
                    .cloned(),
            })
        })
        .collect::<Result<_, _>>()?;

    let link_start = Instant::now();
    let mut link_result = if store_version.is_v2() {
        let store_v2 = lpm_store::v2::Store::from_lpm_root_with_object_integrity_policy(
            lpm_root,
            object_integrity_policy,
        );
        let v2_targets = build_v2_targets(&packages, &link_targets)?;
        lpm_linker::v2::link_packages_v2(
            project_dir,
            v2_targets,
            &store_v2,
            linker_mode,
            pkg.name.as_deref(),
        )?
    } else {
        match linker_mode {
            lpm_linker::LinkerMode::Hoisted => lpm_linker::link_packages_hoisted(
                project_dir,
                &link_targets,
                force,
                pkg.name.as_deref(),
            )?,
            lpm_linker::LinkerMode::Isolated => {
                lpm_linker::link_packages(project_dir, &link_targets, force, pkg.name.as_deref())?
            }
        }
    };
    let link_ms = link_start.elapsed().as_millis();

    // invariant: link workspace member dependencies AFTER
    // the regular linker run. Same rationale as the online path — see
    // `run_with_options`. Offline mode does not write a lockfile entry for
    // workspace members because they're never resolved through the registry.
    let workspace_links_created = link_workspace_members(project_dir, workspace_member_deps)?;
    if workspace_links_created > 0 && !json_output {
        output::info_line(crate::install_ui::terminal_line!(
            "Linked {} workspace member(s)",
            install_ui::bold(&workspace_links_created.to_string())
        ));
    }

    //
    // Mirror of the online path. The drift gate already ran in
    // `run_with_options` BEFORE this function was reached, so any
    // declared patch is guaranteed to match the previously-recorded
    // fingerprint at this point. The apply pass enforces store
    // integrity binding per-package and is safe to run offline because
    // the store baseline is local-only and the linker has just
    // materialized everything.
    //
    // ** follow-up:** the `current_patches` map was already read
    // above into `current_patches_for_link` to feed
    // `compute_patch_fingerprints`. Re-bind here under the original
    // name so the rest of the function (state-file persist, JSON
    // envelope writes) keeps the symmetric naming with the online
    // path; the underlying clone is one HashMap and patches are rare,
    // so the cost is negligible.
    let current_patches = current_patches_for_link;
    let applied_patches = apply_patches_for_install(
        &current_patches,
        &link_result,
        &store,
        project_dir,
        json_output,
    )?;

    let policy = lpm_security::SecurityPolicy::from_package_json(&project_dir.join("package.json"));
    let script_policy_cfg =
        crate::script_policy_config::ScriptPolicyConfig::try_from_package_json(project_dir)?;
    let effective_policy = crate::script_policy_config::resolve_script_policy_with_security(
        project_dir,
        script_policy_override,
        &script_policy_cfg,
        json_output,
    )?;

    // capture the install-time blocked set into
    // build-state.json. Same wiring as the online path — see comment there.
    let installed_with_integrity: Vec<(String, String, Option<String>)> = packages
        .iter()
        .map(|p| (p.name.clone(), p.version.clone(), p.integrity.clone()))
        .collect();
    // Parse the project
    // capability request + user bound so the offline / lockfile-
    // fast-path install also catches capability-widening packages.
    // The online path above does the same at install.rs:2369;
    // without this, the shared `run_link_and_finish` path would
    // silently omit capability-widened packages from build-state.json
    // and leave approve-scripts with nothing actionable.
    let offline_requested_capabilities =
        crate::capability::CapabilitySet::from_package_json(&project_dir.join("package.json"))
            .map_err(|e| LpmError::Registry(format!("{e}")))?;
    let offline_user_bound = crate::security_approval::authorized_capability_user_bound();
    let all_trusted_for_auto_build = crate::commands::rebuild::all_scripted_packages_trusted(
        lpm_root,
        &installed_with_integrity,
        &policy,
        project_dir,
        effective_policy,
        force_security_floor,
        &offline_requested_capabilities,
        &offline_user_bound,
        None,
    );
    let auto_build_attempted = should_auto_build(
        auto_build,
        script_policy_cfg.auto_build,
        all_trusted_for_auto_build,
        effective_policy,
    );
    let baseline_index = if store_version == lpm_store::StoreVersion::V2 {
        Some(lpm_store::V2BaselineIndex::for_project(
            project_dir,
            lpm_root,
        )?)
    } else {
        None
    };

    let mut blocked_capture = crate::build_state::capture_blocked_set_after_install_with_options(
        project_dir,
        &store,
        &installed_with_integrity,
        &policy,
        &crate::build_state::BlockedSetMetadata::default(),
        &offline_requested_capabilities,
        &offline_user_bound,
        crate::build_state::BlockedSetCaptureOptions {
            advisor_approvals: None,
            execution_exclusions: None,
            baseline_index: baseline_index.as_ref(),
        },
    )?;

    let mut auto_build_report = crate::commands::rebuild::RebuildRunReport::default();
    if auto_build_attempted {
        match crate::commands::rebuild::run_with_report(
            project_dir,
            &[],
            false,
            false,
            false,
            None,
            json_output,
            false,
            no_sandbox,
            strict_sandbox,
            false,
            effective_policy,
            None,
        )
        .await
        {
            Ok(report) => {
                auto_build_report = report;
            }
            Err(e) => {
                if !json_output {
                    output::warn(&format!(
                        "Auto-build failed: {}",
                        lpm_common::sanitize_terminal_inline(&e.to_string())
                    ));
                }
                return Err(e);
            }
        }
    }

    if auto_build_report.covered_any_packages() || auto_build_report.built_any_packages() {
        let execution_exclusions = auto_build_report
            .covered_packages
            .iter()
            .cloned()
            .collect::<HashSet<_>>();
        blocked_capture = crate::build_state::capture_blocked_set_after_install_with_options(
            project_dir,
            &store,
            &installed_with_integrity,
            &policy,
            &crate::build_state::BlockedSetMetadata::default(),
            &offline_requested_capabilities,
            &offline_user_bound,
            crate::build_state::BlockedSetCaptureOptions {
                advisor_approvals: None,
                execution_exclusions: Some(&execution_exclusions),
                baseline_index: baseline_index.as_ref(),
            },
        )?;

        let relinked_bins = relink_bins_after_lifecycle_build(
            project_dir,
            &packages,
            &link_targets,
            linker_mode,
            lpm_root,
            object_integrity_policy,
            pkg.name.as_deref(),
            compatibility_bin_names,
            store_version,
        )?;
        link_result.bin_linked = relinked_bins;
    }

    maybe_emit_post_auto_build_triage_pointer(
        auto_build_attempted,
        effective_policy,
        &blocked_capture,
        json_output,
    );

    //: snapshot write on the fast path too — a warm
    // install that only changed `trustedDependencies` (not deps)
    // would otherwise skip the update and leave the next install
    // comparing against stale state. Non-fatal on failure.
    {
        let trust_snap_start = std::time::Instant::now();
        let snap = crate::trust_snapshot::TrustSnapshot::capture_current(pkg.lpm.as_ref().map_or(
            &lpm_workspace::TrustedDependencies::Legacy(Vec::new()),
            |l| &l.trusted_dependencies,
        ));
        if let Err(e) = crate::trust_snapshot::write_snapshot(project_dir, &snap) {
            tracing::warn!("failed to write trust-snapshot.json: {e}");
        }
        tracing::debug!(
            "perf.trust_snapshot ms={}",
            trust_snap_start.elapsed().as_millis()
        );
    }

    let elapsed = start.elapsed();

    // persist patch state in offline mode too.
    // The drift gate already ran in `run_with_options`, so reaching
    // this point means the on-disk state file (if any) matches the
    // current parsed map fingerprint, OR both sides are empty.
    //
    // **invariant :** re-read the prior state here so the
    // persist helper can preserve the prior `applied` trace on
    // idempotent reruns (the alternative — passing it down from
    // `run_with_options` — would require threading the value through
    // the offline early-return). The cost is one extra `read` of a
    // ~few-KB JSON file.
    let prior_patch_state_for_offline = patch_state::read_state(project_dir);
    persist_patch_state(
        project_dir,
        &current_patches,
        &prior_patch_state_for_offline,
        &applied_patches,
    );

    // Compute the filtered summary once; reuse for JSON + human output.
    let applied_patches_summary: Vec<&patch_engine::AppliedPatch> = applied_patches
        .iter()
        .filter(|a| a.touched_anything())
        .collect();

    if emit_install_report && json_output {
        let pkg_list: Vec<serde_json::Value> = packages
            .iter()
            .map(|p| {
                serde_json::json!({
                    "name": p.name,
                    "version": p.version,
                    "source": p.source,
                    "direct": p.is_direct,
                })
            })
            .collect();

        let mut json = serde_json::json!({
            "schema_version": crate::json_contract::INSTALL_JSON_SCHEMA_VERSION,
            "success": true,
            "packages": pkg_list,
            "count": packages.len(),
            "downloaded": downloaded,
            "cached": cached,
            "linked": link_result.linked,
            "symlinked": link_result.symlinked,
            "counts": InstallCountSemantics {
                resolved_package_row_count: packages.len(),
                authoritative_fetch_candidate_count: downloaded,
                store_reuse_observation_count: cached,
                linker_entry_created_count: link_result.linked,
                linker_entry_reused_count: link_result.skipped,
                project_root_symlink_created_count: link_result.symlinked,
                bin_link_created_count: link_result.bin_linked,
            }.to_json(),
            "used_lockfile": used_lockfile,
            "offline": true,
            "duration_ms": elapsed.as_millis() as u64,
            "timing": {
                "firewall_batch_ms": npm_firewall_stats.batch_ms,
                "firewall": npm_firewall_stats.to_json(),
                "policy_extensions": policy_extension_stats.to_json(),
                "link_ms": link_ms,
                "total_ms": elapsed.as_millis(),
            },
            "security": {
                "firewall": npm_firewall_stats.to_json(),
                "policy_extensions": policy_extension_stats.to_json(),
            },
            "warnings": [],
            "errors": [],
        });
        attach_target_timing_semantics(&mut json["timing"]);
        if !emit_timing && let Some(obj) = json.as_object_mut() {
            obj.remove("timing");
        }
        // invariant: surface workspace member deps that
        // were linked locally instead of going through the registry.
        if !workspace_member_deps.is_empty() {
            json["workspace_members"] = serde_json::Value::Array(
                workspace_member_deps
                    .iter()
                    .map(|m| {
                        serde_json::json!({
                            "name": m.name,
                            "version": m.version,
                            "source_dir": m.source_dir.display().to_string(),
                        })
                    })
                    .collect(),
            );
        }
        // surface applied_patches in offline mode.
        // invariant : use the filtered summary so a no-op
        // idempotent rerun reports an empty array.
        json["applied_patches"] = applied_patches_to_json(&applied_patches_summary, project_dir);
        json["patches_count"] = serde_json::json!(current_patches.len());
        json["patches_fingerprint"] = fingerprint_json_value(
            current_patches.len(),
            patch_state::compute_fingerprint(&current_patches),
        );
        // surface the install-time blocked set so
        // agents and CI can drive `lpm approve-scripts` without re-scanning.
        // Mirrors the online path.
        json["blocked_count"] = serde_json::json!(blocked_capture.state.blocked_packages.len());
        json["blocked_set_changed"] = serde_json::json!(blocked_capture.should_emit_warning);
        json["blocked_set_fingerprint"] = fingerprint_json_value(
            blocked_capture.state.blocked_packages.len(),
            blocked_capture.state.blocked_set_fingerprint.clone(),
        );
        // + per-entry shape now
        // includes `static_tier` () and `version_diff` () via
        // the shared `version_diff::blocked_to_json` helper —
        // mirrors the run_with_options site above. See that site's
        // comment block for the wire-shape rationale.
        let trusted_for_json = read_trusted_deps_from_manifest(project_dir).unwrap_or_default();
        json["blocked_packages"] = serde_json::Value::Array(
            blocked_capture
                .state
                .blocked_packages
                .iter()
                .map(|bp| crate::version_diff::blocked_to_json(bp, &trusted_for_json))
                .collect(),
        );
        crate::security_floor::attach_security_posture(&mut json, force_security_floor);
        report_capture::emit_install_json(&json);
    } else if emit_install_report {
        // patch summary in human mode.
        // invariant : use the filtered summary so a no-op
        // idempotent rerun does NOT print "Applied 1 patch" with zero
        // files.
        if !applied_patches_summary.is_empty() {
            println!();
            output::info_line(crate::install_ui::terminal_line!(
                "Applied {} patch{}:",
                install_ui::bold(&applied_patches_summary.len().to_string()),
                if applied_patches_summary.len() == 1 {
                    ""
                } else {
                    "es"
                }
            ));
            for a in &applied_patches_summary {
                let rel_patch = a
                    .patch_path
                    .strip_prefix(project_dir)
                    .unwrap_or(&a.patch_path);
                let total = a.files_modified + a.files_added + a.files_deleted;
                println!(
                    "{}",
                    crate::install_ui::terminal_line!(
                        "   {}@{} ({}, {} file{})",
                        install_ui::bold(&a.name),
                        install_ui::dim(&a.version),
                        install_ui::dim(&rel_patch.display().to_string()),
                        total,
                        if total == 1 { "" } else { "s" },
                    )
                );
            }
        }
        println!();
        output::success_line(crate::install_ui::terminal_line!(
            "{} packages installed in {}s",
            install_ui::bold(&packages.len().to_string()),
            format!("{:.1}", elapsed.as_secs_f64())
        ));
        println!(
            "  {} linked, {} symlinked",
            link_result.linked.to_string().dimmed(),
            link_result.symlinked.to_string().dimmed(),
        );
        println!();
    }

    maybe_emit_post_install_lifecycle_hint(
        lpm_root,
        &packages,
        &policy,
        project_dir,
        script_policy_override,
        &offline_requested_capabilities,
        &offline_user_bound,
        &blocked_capture,
        json_output,
    )?;

    Ok(())
}
