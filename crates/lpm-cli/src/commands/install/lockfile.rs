use super::*;

/// Try to use the lockfile as a fast path.
///
/// Returns `Some(LockfileFastPath { packages, lockfile,
/// needs_binary_upgrade })` if the lockfile exists AND every declared
/// dependency in package.json has a matching entry in the lockfile.
/// Otherwise returns `None` to signal that fresh resolution is needed.
///
/// The parsed `Lockfile` is returned alongside the install packages so
/// the install driver can patch `LockedPackage.tarball` and re-emit
/// the lockfile on the generalized-writeback path (
/// Change 3) without re-parsing. The `needs_binary_upgrade` flag
/// tells the driver whether a rewrite is needed even when no URL
/// diverged (e.g., pre-existing v1 `lpm.lockb` on disk, or missing
/// entirely — migration completes on first fast-path install
/// instead of being deferred to the next fresh resolve).
/// Return type for [`try_lockfile_fast_path`]. Carries the parsed
/// lockfile back to the install driver (so it can be patched + re-
/// written on the generalized-writeback path) alongside the install
/// packages derived from it, plus a `needs_binary_upgrade` flag
/// indicating that the binary lockfile is missing or out-of-version
/// and should be re-emitted at install-end (the fast-path install
/// itself doesn't normally write the lockfile).
pub(super) struct LockfileFastPath {
    pub(super) packages: Vec<InstallPackage>,
    /// Parsed lockfile. Owned by the caller so
    /// `LockedPackage.tarball` fields can be patched with post-fetch
    /// URLs before `write_all` is called on the writeback path.
    pub(super) lockfile: lpm_lockfile::Lockfile,
    /// True when the v2 `lpm.lockb` was missing or opened with
    /// `UnsupportedVersion`. Triggers a writeback even when no URL
    /// diverged — otherwise the migration from a v1 binary (or no
    /// binary at all) would never complete on fast-path-only runs.
    pub(super) needs_binary_upgrade: bool,
}

pub(super) const MIN_LOCKFILE_VERSION_WITH_AUTHORITATIVE_PEER_STATE: u32 = 2;

pub(super) fn lockfile_needs_peer_state_repair(
    lockfile: &lpm_lockfile::Lockfile,
    auto_install_peers: bool,
) -> bool {
    auto_install_peers
        && lockfile.metadata.lockfile_version < MIN_LOCKFILE_VERSION_WITH_AUTHORITATIVE_PEER_STATE
}

pub(super) struct LockfileSelectionInput<'a> {
    pub(super) lockfile_path: &'a Path,
    pub(super) deps: &'a HashMap<String, String>,
    pub(super) catalog_resolutions: &'a [lpm_workspace::CatalogProtocolResolution],
    pub(super) client: &'a RegistryClient,
    pub(super) gate_stats: &'a GateStats,
    pub(super) frozen_lockfile_active: bool,
    pub(super) force: bool,
    pub(super) overrides_changed: bool,
    pub(super) patches_changed: bool,
    pub(super) is_add_invocation: bool,
    pub(super) auto_install_peers: bool,
    pub(super) json_output: bool,
}

pub(super) fn select_lockfile_install_plan(
    input: LockfileSelectionInput<'_>,
) -> Result<Option<LockfileFastPath>, LpmError> {
    if input.frozen_lockfile_active {
        let candidate = try_lockfile_fast_path(
            input.lockfile_path,
            input.deps,
            input.catalog_resolutions,
            input.client,
            input.gate_stats,
            false,
        )
        .ok_or_else(|| {
            LpmError::Registry(
                "Frozen lockfile mismatch\n  lockfile    lpm.lock\n  hint        lockfile cannot satisfy the current manifest; run `lpm install` locally and commit lpm.lock, or pass --no-frozen-lockfile"
                    .into(),
            )
        })?;
        if lockfile_needs_peer_state_repair(&candidate.lockfile, input.auto_install_peers) {
            return Err(LpmError::Registry(format!(
                "Frozen lockfile mismatch\n  lockfile    v{}\n  required    v{}\n  hint        run `lpm install` locally and commit the upgraded lpm.lock",
                candidate.lockfile.metadata.lockfile_version,
                lpm_lockfile::LOCKFILE_VERSION,
            )));
        }
        return Ok(Some(candidate));
    }

    if input.force || input.overrides_changed || input.patches_changed || input.is_add_invocation {
        return Ok(None);
    }

    let candidate = try_lockfile_fast_path(
        input.lockfile_path,
        input.deps,
        input.catalog_resolutions,
        input.client,
        input.gate_stats,
        false,
    );
    match candidate {
        Some(fast)
            if lockfile_needs_peer_state_repair(&fast.lockfile, input.auto_install_peers) =>
        {
            if !input.json_output {
                output::info(
                    "Lockfile is in an older format; rebuilding to capture \
                     peer auto-install state. Subsequent installs will be fast.",
                );
            }
            Ok(None)
        }
        other => Ok(other),
    }
}

pub(super) struct EmptyDependencyInstallInput<'a> {
    pub(super) project_dir: &'a Path,
    pub(super) policy_extension_configs: &'a [policy_extensions::PolicyExtensionConfig],
    pub(super) cleanup_catalogs_in_pipeline: bool,
    pub(super) json_output: bool,
    pub(super) start: Instant,
    pub(super) timing_detail_mode: TimingDetailMode,
    pub(super) setup_install_state_ms: u128,
    pub(super) setup_route_table_ms: u128,
    pub(super) emit_timing: bool,
    pub(super) target_set: Option<&'a [String]>,
    pub(super) force_security_floor: bool,
    pub(super) override_set: &'a OverrideSet,
    pub(super) linker_mode: lpm_linker::LinkerMode,
    pub(super) object_integrity_policy: lpm_store::v2::ObjectIntegrityPolicy,
}

pub(super) async fn run_empty_dependency_install_phase(
    input: EmptyDependencyInstallInput<'_>,
) -> Result<(), LpmError> {
    let EmptyDependencyInstallInput {
        project_dir,
        policy_extension_configs,
        cleanup_catalogs_in_pipeline,
        json_output,
        start,
        timing_detail_mode,
        setup_install_state_ms,
        setup_route_table_ms,
        emit_timing,
        target_set,
        force_security_floor,
        override_set,
        linker_mode,
        object_integrity_policy,
    } = input;

    if cleanup_catalogs_in_pipeline {
        cleanup_unused_catalogs_after_install(project_dir)?;
    }
    let policy_extension_stats =
        run_policy_extensions(policy_extension_configs, project_dir, &[], json_output).await?;
    let elapsed = start.elapsed();
    let total_ms = elapsed.as_millis();
    if json_output {
        let mut json = serde_json::json!({
            "schema_version": crate::json_contract::INSTALL_JSON_SCHEMA_VERSION,
            "success": true,
            "no_dependencies": true,
            "duration_ms": total_ms as u64,
            "timing": {
                "resolve_ms": 0u128,
                "fetch_ms": 0u128,
                "link_ms": 0u128,
                "total_ms": total_ms,
                "waterfall": {
                    "setup_ms": total_ms,
                    "resolve_ms": 0u128,
                    "pre_fetch_ms": 0u128,
                    "fetch_ms": 0u128,
                    "pre_link_ms": 0u128,
                    "link_ms": 0u128,
                    "link_await_ms": 0u128,
                    "link_finalize_ms": 0u128,
                    "tail_ms": 0u128,
                    "total_ms": total_ms,
                },
            },
            "peer_conflicts": [],
            "peer_issues": peer_issues_json_value(&[], &[]),
            "security": {
                "policy_extensions": policy_extension_stats.to_json(),
            },
        });
        json["timing"]["policy_extensions"] = policy_extension_stats.to_json();
        if timing_detail_mode.enabled() {
            json["timing"]["detail"] = setup_only_timing_detail_json(
                timing_detail_mode,
                total_ms,
                setup_install_state_ms,
                setup_route_table_ms,
            );
        }
        if !emit_timing && let Some(obj) = json.as_object_mut() {
            obj.remove("timing");
        }
        if let Some(targets) = target_set {
            json["target_set"] =
                serde_json::Value::Array(targets.iter().map(|s| serde_json::json!(s)).collect());
        }
        crate::security_floor::attach_security_posture(&mut json, force_security_floor);
        println!("{}", serde_json::to_string_pretty(&json).unwrap());
    } else {
        output::success("No dependencies to install");
    }

    if override_set.is_empty()
        && overrides_state::read_state(project_dir).is_some()
        && let Err(e) = overrides_state::delete_state(project_dir)
    {
        tracing::warn!("failed to delete stale overrides-state.json: {e}");
    }
    materialize_empty_install_artifacts(project_dir)?;
    write_post_install_hash(project_dir, linker_mode, object_integrity_policy);
    Ok(())
}

pub(super) struct LockfileDriftInput<'a> {
    pub(super) project_dir: &'a Path,
    pub(super) lockfile_path: &'a Path,
    pub(super) pkg: &'a lpm_workspace::PackageJson,
    pub(super) override_set: &'a OverrideSet,
    pub(super) current_patches: &'a HashMap<String, PatchedDependencyEntry>,
    pub(super) current_patch_fingerprint: &'a str,
}

pub(super) struct LockfileDriftState {
    pub(super) prior_overrides_state: Option<overrides_state::OverridesState>,
    pub(super) overrides_changed: bool,
    pub(super) prior_patch_state: Option<patch_state::PatchState>,
    pub(super) patches_changed: bool,
    pub(super) pre_install_direct_versions: HashMap<String, String>,
}

pub(super) fn prepare_lockfile_drift_state(input: LockfileDriftInput<'_>) -> LockfileDriftState {
    let LockfileDriftInput {
        project_dir,
        lockfile_path,
        pkg,
        override_set,
        current_patches,
        current_patch_fingerprint,
    } = input;

    let prior_overrides_state = overrides_state::read_state(project_dir);
    let overrides_changed = prior_overrides_state
        .as_ref()
        .map_or(!override_set.is_empty(), |s| {
            s.fingerprint != override_set.fingerprint()
        });
    if overrides_changed {
        tracing::debug!(
            "overrides changed since last install (fingerprint drift) - \
             invalidating lockfile fast path"
        );
    }

    let prior_patch_state = patch_state::read_state(project_dir);
    let patches_changed = prior_patch_state
        .as_ref()
        .map_or(!current_patches.is_empty(), |s| {
            s.fingerprint != current_patch_fingerprint
        });
    if patches_changed {
        tracing::debug!(
            "patches changed since last install (fingerprint drift) - \
             invalidating lockfile fast path"
        );
    }

    let pre_install_direct_versions = if lockfile_path.exists() {
        lpm_lockfile::Lockfile::read_fast(lockfile_path)
            .ok()
            .map(|lf| collect_locked_direct_versions(pkg, &lf))
            .unwrap_or_default()
    } else {
        HashMap::new()
    };

    LockfileDriftState {
        prior_overrides_state,
        overrides_changed,
        prior_patch_state,
        patches_changed,
        pre_install_direct_versions,
    }
}

pub(super) struct OfflineInstallInput<'a> {
    pub(super) client: &'a RegistryClient,
    pub(super) project_dir: &'a Path,
    pub(super) deps: &'a HashMap<String, String>,
    pub(super) pkg: &'a lpm_workspace::PackageJson,
    pub(super) lockfile_path: &'a Path,
    pub(super) catalog_resolutions: &'a [lpm_workspace::CatalogProtocolResolution],
    pub(super) gate_stats: &'a GateStats,
    pub(super) override_set: &'a OverrideSet,
    pub(super) prior_overrides_state: Option<&'a crate::overrides_state::OverridesState>,
    pub(super) overrides_changed: bool,
    pub(super) current_patches: &'a HashMap<String, PatchedDependencyEntry>,
    pub(super) current_patch_fingerprint: &'a str,
    pub(super) prior_patch_state: Option<&'a crate::patch_state::PatchState>,
    pub(super) patches_changed: bool,
    pub(super) auto_install_peers: bool,
    pub(super) omit_policy: InstallOmitPolicy,
    pub(super) production_dependency_names: &'a HashSet<String>,
    pub(super) requested_v2_mode: bool,
    pub(super) object_integrity_policy: lpm_store::v2::ObjectIntegrityPolicy,
    pub(super) lpm_root: &'a lpm_common::LpmRoot,
    pub(super) json_output: bool,
    pub(super) verify_registry_signatures: bool,
    pub(super) registry_signature_timings:
        Option<Arc<crate::registry_signatures::RegistrySignatureTimings>>,
    pub(super) arc_client: &'a Arc<RegistryClient>,
    pub(super) route_table: &'a RouteTable,
    pub(super) npm_firewall_mode: crate::npm_firewall_config::NpmFirewallMode,
    pub(super) npm_firewall_lookup_mode: NpmFirewallLookupMode,
    pub(super) policy_extension_configs: &'a [policy_extensions::PolicyExtensionConfig],
    pub(super) workspace_member_deps: &'a mut Vec<WorkspaceMemberLink>,
    pub(super) all_workspace_members: &'a [WorkspaceMemberLink],
    pub(super) v2_workspace_root_pre_resolve: &'a V2WorkspaceRootPreResolveResult,
    pub(super) start: Instant,
    pub(super) linker_mode: lpm_linker::LinkerMode,
    pub(super) force: bool,
    pub(super) script_policy_override: Option<crate::script_policy_config::ScriptPolicy>,
    pub(super) global_config: &'a crate::commands::config::GlobalConfig,
    pub(super) auto_build: bool,
    pub(super) no_sandbox: bool,
    pub(super) strict_sandbox: bool,
    pub(super) emit_timing: bool,
    pub(super) strict_integrity: bool,
    pub(super) compatibility_bin_names: &'a [String],
}

pub(super) async fn run_offline_install_phase(
    input: OfflineInstallInput<'_>,
) -> Result<(), LpmError> {
    let OfflineInstallInput {
        client,
        project_dir,
        deps,
        pkg,
        lockfile_path,
        catalog_resolutions,
        gate_stats,
        override_set,
        prior_overrides_state,
        overrides_changed,
        current_patches,
        current_patch_fingerprint,
        prior_patch_state,
        patches_changed,
        auto_install_peers,
        omit_policy,
        production_dependency_names,
        requested_v2_mode,
        object_integrity_policy,
        lpm_root,
        json_output,
        verify_registry_signatures,
        registry_signature_timings,
        arc_client,
        route_table,
        npm_firewall_mode,
        npm_firewall_lookup_mode,
        policy_extension_configs,
        workspace_member_deps,
        all_workspace_members,
        v2_workspace_root_pre_resolve,
        start,
        linker_mode,
        force,
        script_policy_override,
        global_config,
        auto_build,
        no_sandbox,
        strict_sandbox,
        emit_timing,
        strict_integrity,
        compatibility_bin_names,
    } = input;

    if overrides_changed {
        let detail = match prior_overrides_state {
            Some(prior) => format!(
                "previous fingerprint {} differs from current {}",
                prior.fingerprint,
                override_set.fingerprint()
            ),
            None if !override_set.is_empty() => {
                "no previously-recorded override fingerprint; the lockfile may have \
                 been generated without these overrides"
                    .to_string()
            }
            None => "override state inconsistency".to_string(),
        };
        return Err(LpmError::Registry(format!(
            "--offline: override set differs from the lockfile's recorded set ({detail}). \
             Run `lpm install` (online) to re-resolve, then retry --offline."
        )));
    }

    if patches_changed {
        let detail = match prior_patch_state {
            Some(prior) => format!(
                "previous fingerprint {} differs from current {}",
                prior.fingerprint, current_patch_fingerprint
            ),
            None if !current_patches.is_empty() => {
                "no previously-recorded patch fingerprint; the lockfile may have \
                 been written without these patches"
                    .to_string()
            }
            None => "patch state inconsistency".to_string(),
        };
        return Err(LpmError::Registry(format!(
            "--offline: lpm.patchedDependencies differs from the previously-recorded \
             patch set ({detail}). Run `lpm install` (online) to re-resolve, then retry \
             --offline."
        )));
    }

    // Offline replay cannot fresh-resolve, so it trusts lockfile-local source entries.
    let fast = try_lockfile_fast_path(
        lockfile_path,
        deps,
        catalog_resolutions,
        client,
        gate_stats,
        true,
    )
    .ok_or_else(|| {
        LpmError::Registry(
            "--offline could not load the lockfile. Possible causes: (1) lpm.lock is \
                     missing — run `lpm install` online first; (2) lpm.lock is corrupted — \
                     delete it and re-run online; (3) a root dependency in package.json is \
                     absent from the lockfile (e.g., declared but never installed online). \
                     Run `lpm install` online to reconcile."
                .into(),
        )
    })?;

    if lockfile_needs_peer_state_repair(&fast.lockfile, auto_install_peers) {
        return Err(LpmError::Registry(
            "--offline cannot use a pre-R2.5 lockfile under \
             `lpm.autoInstallPeers = true`: the lockfile may be missing \
             ambient-peer-install state. Run \
             `lpm install` (online) once to re-derive and upgrade the \
             lockfile to v2, then retry --offline. To bypass this check \
             and accept warn-only peer semantics, set \
             `lpm.autoInstallPeers = false` in package.json."
                .into(),
        ));
    }

    let mut locked = fast.packages;
    if omit_policy.dev {
        filter_dev_packages(&mut locked, production_dependency_names);
    }
    let _platform_skipped = filter_platform_packages(&mut locked)?;
    if !json_output {
        output::info(&format!(
            "Offline: using lockfile ({} packages)",
            locked.len().to_string().bold()
        ));
    }

    let store = PackageStore::from_root(lpm_root);
    let store_v2 = requested_v2_mode.then(|| {
        lpm_store::v2::Store::from_lpm_root_with_object_integrity_policy(
            lpm_root,
            object_integrity_policy,
        )
    });
    let mut missing = Vec::new();
    for p in &locked {
        // Source-aware lookup prevents registry cache hits from satisfying local/tarball entries.
        if !p.store_has_for_install_layout(&store, store_v2.as_ref(), project_dir) {
            missing.push(format!("{}@{}", p.name, p.version));
        }
    }
    if !missing.is_empty() {
        return Err(LpmError::Registry(format!(
            "--offline: {} package(s) not in global store: {}",
            missing.len(),
            missing[..missing.len().min(5)].join(", ")
        )));
    }

    merge_workspace_member_links(
        workspace_member_deps,
        v2_workspace_root_pre_resolve
            .additional_workspace_links
            .iter()
            .cloned(),
    );
    expand_workspace_member_deps_with_transitives(workspace_member_deps, all_workspace_members)?;
    enforce_registry_integrity_policy(&locked, strict_integrity, json_output)?;
    if verify_registry_signatures {
        enforce_registry_signature_policy(
            Arc::clone(arc_client),
            route_table,
            &locked,
            json_output,
            false,
            registry_signature_timings,
        )
        .await?;
    }
    let npm_firewall_stats = run_npm_firewall_preflight(
        npm_firewall_mode,
        npm_firewall_lookup_mode,
        arc_client,
        route_table,
        &locked,
        true,
        json_output,
    )
    .await?;
    let policy_extension_stats =
        run_policy_extensions(policy_extension_configs, project_dir, &locked, json_output).await?;

    run_link_and_finish(
        client,
        project_dir,
        deps,
        pkg,
        locked,
        &v2_workspace_root_pre_resolve.install_pkgs,
        &v2_workspace_root_pre_resolve.source_deps,
        0,
        0,
        true,
        npm_firewall_stats,
        policy_extension_stats,
        json_output,
        start,
        linker_mode,
        force,
        workspace_member_deps,
        script_policy_override,
        lpm_root,
        global_config,
        object_integrity_policy,
        auto_build,
        no_sandbox,
        strict_sandbox,
        emit_timing,
        compatibility_bin_names,
    )
    .await
}

pub(super) fn catalog_protocol_error_to_lpm(
    error: lpm_workspace::CatalogProtocolError,
) -> LpmError {
    match error {
        lpm_workspace::CatalogProtocolError::RecursiveDefinition {
            dependency,
            catalog,
            specifier,
        } => LpmError::CatalogEntryInvalidRecursiveDefinition {
            dependency,
            catalog,
            specifier,
        },
        other => LpmError::Registry(format!("catalog resolution failed: {other}")),
    }
}

pub(super) type OverrideCatalogResolution<'a> = (
    Cow<'a, HashMap<String, String>>,
    Vec<lpm_workspace::CatalogProtocolResolution>,
);

pub(super) fn resolve_catalog_protocol_in_override_map<'a>(
    overrides: &'a HashMap<String, String>,
    catalogs: &HashMap<String, HashMap<String, String>>,
) -> Result<OverrideCatalogResolution<'a>, LpmError> {
    if !overrides
        .values()
        .any(|target| target.starts_with("catalog:"))
    {
        return Ok((Cow::Borrowed(overrides), Vec::new()));
    }

    let mut resolved_overrides = HashMap::with_capacity(overrides.len());
    let mut catalog_resolutions = Vec::new();

    for (raw_key, raw_target) in overrides {
        if !raw_target.starts_with("catalog:") {
            resolved_overrides.insert(raw_key.clone(), raw_target.clone());
            continue;
        }

        let target_name =
            lpm_resolver::override_selector_target_name(raw_key).map_err(|error| {
                LpmError::Script(format!("invalid override in package.json: {error}"))
            })?;
        let mut catalog_dep = HashMap::with_capacity(1);
        catalog_dep.insert(target_name.clone(), raw_target.clone());
        let resolved = lpm_workspace::resolve_catalog_protocol(&mut catalog_dep, catalogs)
            .map_err(catalog_protocol_error_to_lpm)?;
        let resolved_target = catalog_dep.remove(&target_name).ok_or_else(|| {
            LpmError::Registry(format!(
                "catalog resolution failed: override target `{target_name}` was not resolved"
            ))
        })?;
        resolved_overrides.insert(raw_key.clone(), resolved_target);
        catalog_resolutions.extend(resolved);
    }

    Ok((Cow::Owned(resolved_overrides), catalog_resolutions))
}

pub(super) fn extend_catalog_resolutions(
    catalog_resolutions: &mut Vec<lpm_workspace::CatalogProtocolResolution>,
    incoming: Vec<lpm_workspace::CatalogProtocolResolution>,
) {
    for resolution in incoming {
        push_catalog_resolution(catalog_resolutions, resolution);
    }
}

pub(super) fn push_catalog_resolution(
    catalog_resolutions: &mut Vec<lpm_workspace::CatalogProtocolResolution>,
    resolution: lpm_workspace::CatalogProtocolResolution,
) {
    if catalog_resolutions.iter().any(|existing| {
        existing.catalog_name == resolution.catalog_name
            && existing.package_name == resolution.package_name
    }) {
        return;
    }
    catalog_resolutions.push(resolution);
}

pub(super) fn catalog_resolutions_for_lockfile(
    dependency_catalog_resolutions: &[lpm_workspace::CatalogProtocolResolution],
    override_catalog_resolutions: &[lpm_workspace::CatalogProtocolResolution],
    applied_overrides: &[OverrideHit],
) -> Vec<lpm_workspace::CatalogProtocolResolution> {
    let mut catalog_resolutions = Vec::with_capacity(
        dependency_catalog_resolutions.len() + override_catalog_resolutions.len(),
    );
    catalog_resolutions.extend_from_slice(dependency_catalog_resolutions);

    for resolution in override_catalog_resolutions {
        if applied_overrides
            .iter()
            .any(|hit| hit.package == resolution.package_name)
        {
            push_catalog_resolution(&mut catalog_resolutions, resolution.clone());
        }
    }

    catalog_resolutions
}

pub(super) fn catalog_snapshot_from_install_packages(
    catalog_resolutions: &[lpm_workspace::CatalogProtocolResolution],
    packages: &[InstallPackage],
) -> Result<lpm_lockfile::CatalogSnapshots, LpmError> {
    if catalog_resolutions.is_empty() {
        return Ok(lpm_lockfile::CatalogSnapshots::new());
    }

    let mut snapshots = lpm_lockfile::CatalogSnapshots::new();
    for resolution in catalog_resolutions {
        let resolved_version = resolved_catalog_version_from_install_packages(resolution, packages)
            .ok_or_else(|| {
                LpmError::Registry(format!(
                    "catalog snapshot: resolver did not report a concrete version for `{}`",
                    resolution.package_name
                ))
            })?;
        snapshots
            .entry(resolution.catalog_name.clone())
            .or_default()
            .insert(
                resolution.package_name.clone(),
                lpm_lockfile::CatalogSnapshotEntry {
                    specifier: resolution.specifier.clone(),
                    version: resolved_version,
                    reference: resolution.reference.clone(),
                },
            );
    }

    Ok(snapshots)
}

pub(super) fn resolved_catalog_version_from_install_packages(
    resolution: &lpm_workspace::CatalogProtocolResolution,
    packages: &[InstallPackage],
) -> Option<String> {
    let requested_range = lpm_resolver::NpmRange::parse(&resolution.specifier).ok();
    let mut first_match: Option<&InstallPackage> = None;
    let mut best_satisfying: Option<(lpm_resolver::NpmVersion, &InstallPackage)> = None;
    let mut best_any: Option<(lpm_resolver::NpmVersion, &InstallPackage)> = None;

    for package in packages
        .iter()
        .filter(|package| package_matches_catalog_resolution(package, &resolution.package_name))
    {
        if first_match.is_none() {
            first_match = Some(package);
        }

        let Ok(version) = lpm_resolver::NpmVersion::parse(&package.version) else {
            continue;
        };

        let better_any = best_any.as_ref().is_none_or(|(best, _)| version > *best);
        if better_any {
            best_any = Some((version.clone(), package));
        }

        if let Some(range) = requested_range.as_ref()
            && range.satisfies(&version)
        {
            let better_satisfying = best_satisfying
                .as_ref()
                .is_none_or(|(best, _)| version > *best);
            if better_satisfying {
                best_satisfying = Some((version, package));
            }
        }
    }

    best_satisfying
        .map(|(_, package)| package.version.clone())
        .or_else(|| best_any.map(|(_, package)| package.version.clone()))
        .or_else(|| first_match.map(|package| package.version.clone()))
}

pub(super) fn package_matches_catalog_resolution(
    package: &InstallPackage,
    package_name: &str,
) -> bool {
    package.name == package_name
        || package
            .root_link_names
            .as_ref()
            .is_some_and(|names| names.iter().any(|name| name == package_name))
}

pub(super) fn catalog_snapshot_entry_count(snapshots: &lpm_lockfile::CatalogSnapshots) -> usize {
    snapshots.values().map(BTreeMap::len).sum()
}

pub(super) fn lockfile_catalog_snapshots_match_current(
    lockfile: &lpm_lockfile::Lockfile,
    deps: &HashMap<String, String>,
    catalog_resolutions: &[lpm_workspace::CatalogProtocolResolution],
) -> bool {
    if catalog_snapshot_entry_count(&lockfile.catalogs) != catalog_resolutions.len() {
        return false;
    }

    for resolution in catalog_resolutions {
        let Some(entry) = lockfile
            .catalogs
            .get(&resolution.catalog_name)
            .and_then(|catalog| catalog.get(&resolution.package_name))
        else {
            return false;
        };
        if entry.specifier != resolution.specifier || entry.reference != resolution.reference {
            return false;
        }

        let target = lockfile
            .root_aliases
            .get(&resolution.package_name)
            .map_or(resolution.package_name.as_str(), String::as_str);
        let requested_spec = deps
            .get(&resolution.package_name)
            .map_or(resolution.specifier.as_str(), String::as_str);
        let Some(locked_package) =
            select_locked_package_for_requested_spec(lockfile, target, requested_spec)
        else {
            return false;
        };
        if locked_package.version != entry.version {
            return false;
        }
    }

    true
}

pub(crate) fn requested_range_for_locked_lookup(requested_spec: &str) -> Option<String> {
    match lpm_resolver::Specifier::parse(requested_spec).ok()? {
        lpm_resolver::Specifier::SemverRange(range) => Some(range),
        lpm_resolver::Specifier::NpmAlias { range, .. } => Some(range),
        _ => None,
    }
}

pub(crate) fn select_locked_package_for_requested_spec<'a>(
    lockfile: &'a lpm_lockfile::Lockfile,
    target: &str,
    requested_spec: &str,
) -> Option<&'a lpm_lockfile::LockedPackage> {
    let requested_range = requested_range_for_locked_lookup(requested_spec)
        .and_then(|range| lpm_resolver::NpmRange::parse(&range).ok());
    let mut first_match: Option<&lpm_lockfile::LockedPackage> = None;
    let mut best_satisfying: Option<(lpm_resolver::NpmVersion, &lpm_lockfile::LockedPackage)> =
        None;
    let mut best_any: Option<(lpm_resolver::NpmVersion, &lpm_lockfile::LockedPackage)> = None;

    let start = lockfile
        .packages
        .partition_point(|pkg| pkg.name.as_str() < target);
    let end = start + lockfile.packages[start..].partition_point(|pkg| pkg.name.as_str() == target);

    for candidate in &lockfile.packages[start..end] {
        if first_match.is_none() {
            first_match = Some(candidate);
        }

        let Ok(version) = lpm_resolver::NpmVersion::parse(&candidate.version) else {
            continue;
        };

        let better_any = best_any.as_ref().is_none_or(|(best, _)| version > *best);
        if better_any {
            best_any = Some((version.clone(), candidate));
        }

        if let Some(range) = requested_range.as_ref()
            && range.satisfies(&version)
        {
            let better_satisfying = best_satisfying
                .as_ref()
                .is_none_or(|(best, _)| version > *best);
            if better_satisfying {
                best_satisfying = Some((version, candidate));
            }
        }
    }

    best_satisfying
        .map(|(_, candidate)| candidate)
        .or_else(|| best_any.map(|(_, candidate)| candidate))
        .or(first_match)
}

fn select_resolved_package_for_requested_spec<'a>(
    resolved: &'a [ResolvedPackage],
    target: &str,
    requested_spec: &str,
) -> Option<&'a ResolvedPackage> {
    let requested_range = requested_range_for_locked_lookup(requested_spec)
        .and_then(|range| lpm_resolver::NpmRange::parse(&range).ok());
    let mut first_match: Option<&ResolvedPackage> = None;
    let mut first_unscoped: Option<&ResolvedPackage> = None;
    let mut best_satisfying_unscoped: Option<(lpm_resolver::NpmVersion, &ResolvedPackage)> = None;
    let mut best_satisfying: Option<(lpm_resolver::NpmVersion, &ResolvedPackage)> = None;
    let mut best_any_unscoped: Option<(lpm_resolver::NpmVersion, &ResolvedPackage)> = None;
    let mut best_any: Option<(lpm_resolver::NpmVersion, &ResolvedPackage)> = None;

    for candidate in resolved {
        if candidate.package.canonical_name() != target {
            continue;
        }
        if first_match.is_none() {
            first_match = Some(candidate);
        }
        let is_unscoped = candidate.package.context().is_none();
        if is_unscoped && first_unscoped.is_none() {
            first_unscoped = Some(candidate);
        }

        let version = candidate.version.clone();
        let better_any = best_any.as_ref().is_none_or(|(best, _)| version > *best);
        if better_any {
            best_any = Some((version.clone(), candidate));
        }
        if is_unscoped
            && best_any_unscoped
                .as_ref()
                .is_none_or(|(best, _)| version > *best)
        {
            best_any_unscoped = Some((version.clone(), candidate));
        }

        if let Some(range) = requested_range.as_ref()
            && range.satisfies(&version)
        {
            let better_satisfying = best_satisfying
                .as_ref()
                .is_none_or(|(best, _)| version > *best);
            if better_satisfying {
                best_satisfying = Some((version.clone(), candidate));
            }
            if is_unscoped
                && best_satisfying_unscoped
                    .as_ref()
                    .is_none_or(|(best, _)| version > *best)
            {
                best_satisfying_unscoped = Some((version, candidate));
            }
        }
    }

    best_satisfying_unscoped
        .map(|(_, candidate)| candidate)
        .or_else(|| best_satisfying.map(|(_, candidate)| candidate))
        .or_else(|| best_any_unscoped.map(|(_, candidate)| candidate))
        .or(first_unscoped)
        .or_else(|| best_any.map(|(_, candidate)| candidate))
        .or(first_match)
}

pub(super) fn collect_locked_direct_versions(
    pkg: &lpm_workspace::PackageJson,
    lockfile: &lpm_lockfile::Lockfile,
) -> HashMap<String, String> {
    let mut versions = HashMap::with_capacity(pkg.dependencies.len() + pkg.dev_dependencies.len());

    for (local, requested_spec) in pkg.dependencies.iter().chain(pkg.dev_dependencies.iter()) {
        let target = lockfile
            .root_aliases
            .get(local)
            .cloned()
            .unwrap_or_else(|| local.clone());
        if let Some(candidate) =
            select_locked_package_for_requested_spec(lockfile, &target, requested_spec)
        {
            versions
                .entry(target)
                .or_insert_with(|| candidate.version.clone());
        }
    }

    versions
}

pub(super) fn install_package_is_direct(
    root_link_names: Option<&[String]>,
    deps: &HashMap<String, String>,
) -> bool {
    root_link_names.is_some_and(|names| names.iter().any(|local| deps.contains_key(local)))
}

pub(super) fn platform_meta_from_lockfile(
    lp: &lpm_lockfile::LockedPackage,
) -> Option<lpm_resolver::PlatformMeta> {
    if lp.os.is_empty() && lp.cpu.is_empty() && lp.libc.is_empty() {
        return None;
    }
    Some(lpm_resolver::PlatformMeta {
        os: lp.os.clone(),
        cpu: lp.cpu.clone(),
        libc: lp.libc.clone(),
    })
}

pub(super) fn package_platform_compatible(package: &InstallPackage) -> bool {
    package
        .platform
        .as_ref()
        .is_none_or(lpm_resolver::is_platform_compatible)
}

pub(super) fn package_reference_keys(package: &InstallPackage) -> Vec<String> {
    let mut keys = Vec::with_capacity(2);
    keys.push(link_target_lookup_key(&package.name, &package.version));
    if let Some(source_id) = package.wrapper_id_for_source() {
        keys.push(link_target_lookup_key(&package.name, &source_id));
    }
    keys
}

pub(super) fn filter_dev_packages(
    packages: &mut Vec<InstallPackage>,
    production_roots: &HashSet<String>,
) -> usize {
    if packages.is_empty() {
        return 0;
    }

    let mut key_to_index = HashMap::with_capacity(packages.len() * 2);
    for (idx, package) in packages.iter().enumerate() {
        for key in package_reference_keys(package) {
            key_to_index.entry(key).or_insert(idx);
        }
    }

    let mut retained = HashSet::with_capacity(packages.len());
    let mut queue = VecDeque::new();
    for (idx, package) in packages.iter().enumerate() {
        let is_prod_root = package
            .root_link_names
            .as_ref()
            .is_some_and(|names| names.iter().any(|name| production_roots.contains(name)));
        if is_prod_root && retained.insert(idx) {
            queue.push_back(idx);
        }
    }

    while let Some(idx) = queue.pop_front() {
        let package = &packages[idx];
        for (local_name, version) in &package.dependencies {
            let target = package
                .aliases
                .get(local_name)
                .map_or(local_name.as_str(), String::as_str);
            if let Some(next_idx) = key_to_index.get(&link_target_lookup_key(target, version))
                && retained.insert(*next_idx)
            {
                queue.push_back(*next_idx);
            }
        }
        for (peer_name, version) in &package.peers {
            if let Some(next_idx) = key_to_index.get(&link_target_lookup_key(peer_name, version))
                && retained.insert(*next_idx)
            {
                queue.push_back(*next_idx);
            }
        }
    }

    let mut retained_keys = HashSet::with_capacity(retained.len() * 2);
    let mut peer_root_names = HashSet::new();
    for idx in &retained {
        let package = &packages[*idx];
        for key in package_reference_keys(package) {
            retained_keys.insert(key);
        }
        for (peer_name, _) in &package.peers {
            peer_root_names.insert(peer_name.clone());
        }
    }

    let mut kept = Vec::with_capacity(retained.len());
    let mut skipped = 0usize;
    for (idx, mut package) in packages.drain(..).enumerate() {
        if !retained.contains(&idx) {
            skipped += 1;
            continue;
        }

        if let Some(root_link_names) = &mut package.root_link_names {
            root_link_names
                .retain(|name| production_roots.contains(name) || peer_root_names.contains(name));
            if root_link_names.is_empty() {
                package.root_link_names = None;
            }
        }

        package.dependencies.retain(|(local_name, version)| {
            let target = package
                .aliases
                .get(local_name)
                .map_or(local_name.as_str(), String::as_str);
            retained_keys.contains(&link_target_lookup_key(target, version))
        });
        package.peers.retain(|(name, version)| {
            retained_keys.contains(&link_target_lookup_key(name, version))
        });
        kept.push(package);
    }

    *packages = kept;
    skipped
}

pub(super) fn filter_platform_packages(
    packages: &mut Vec<InstallPackage>,
) -> Result<usize, LpmError> {
    let mut skipped: HashSet<(String, String)> = HashSet::new();
    let mut kept = Vec::with_capacity(packages.len());

    for package in packages.drain(..) {
        if package_platform_compatible(&package) {
            kept.push(package);
            continue;
        }
        if package.optional {
            skipped.insert((package.name.clone(), package.version.clone()));
            continue;
        }
        return Err(LpmError::Registry(format!(
            "{}@{} is incompatible with this platform",
            package.name, package.version
        )));
    }

    if !skipped.is_empty() {
        for package in &mut kept {
            package.dependencies.retain(|(local, version)| {
                let target = package
                    .aliases
                    .get(local)
                    .map_or(local.as_str(), String::as_str);
                !skipped.contains(&(target.to_string(), version.clone()))
            });
            package
                .peers
                .retain(|(name, version)| !skipped.contains(&(name.clone(), version.clone())));
        }
    }

    *packages = kept;
    Ok(skipped.len())
}

pub(super) fn try_lockfile_fast_path(
    lockfile_path: &Path,
    deps: &HashMap<String, String>,
    catalog_resolutions: &[lpm_workspace::CatalogProtocolResolution],
    // — the URL-reuse gate needs the client to check
    // origin (`is_configured_origin`) and the shared `GateStats`
    // to bump mismatch counters. Both passed by ref; the fast
    // path runs synchronously so no Arc is needed here.
    client: &RegistryClient,
    gate_stats: &GateStats,
    // when `true`, the
    // `is_safe_source` check is downgraded from "skip fast path"
    // to "warn and accept" for non-registry sources. Online installs
    // MUST keep the safety gate strict because the fast-path bypasses
    // the integrity / URL-reuse re-checks that fresh resolve runs;
    // OFFLINE mode trusts the lockfile by definition, so a
    // `directory+`/`link+`/`tarball+local` entry is admissible. See
    // the offline lockfile invariant: previously, an offline
    // install of a project with a `file:` dep crashed with the
    // misleading "—offline requires a lockfile" message even when
    // the lockfile existed and was fresh, because `is_safe_source`
    // unconditionally rejected the lockfile entry.
    accept_unsafe_sources: bool,
) -> Option<LockfileFastPath> {
    if !lpm_lockfile::Lockfile::exists(lockfile_path) {
        return None;
    }

    let lockfile = lpm_lockfile::Lockfile::read_fast(lockfile_path).ok()?;

    let needs_binary_upgrade = binary_lockfile_needs_writeback(lockfile_path, &lockfile);

    // Scan the lockfile for entries with `http://` sources and
    // emit a single aggregate warn so re-installs against a lockfile
    // captured under `--insecure` don't proceed silently. The
    // per-fetch source-safety check still fires later; this one is
    // about pre-install visibility — operators using
    // `lpm install` in CI without `--insecure` should see that the
    // lockfile carries insecure entries before the install runs.
    let insecure_count = lockfile
        .packages
        .iter()
        .filter(|p| {
            p.source
                .as_deref()
                .is_some_and(|s| s.contains("+http://") || s.starts_with("http://"))
        })
        .count();
    if insecure_count > 0 {
        tracing::warn!(
            insecure_count,
            "lpm.lock contains {insecure_count} package(s) with insecure http:// sources \
             (recorded by an earlier `--insecure` install); re-installs honour these without \
             re-prompting. Re-resolve the affected entries against an https:// mirror to \
             remove the insecure source from the lockfile.",
        );
    }

    // Validate all package sources are safe (HTTPS registries or
    // localhost). **Invariant:** in offline mode (`accept_unsafe_sources
    // = true`) we trust the lockfile and admit non-registry sources —
    // the fresh-resolve fallback isn't available offline, so bailing
    // here would surface a misleading "—offline requires a lockfile"
    // error. The link-target construction handles every source kind
    // post-rounds-1-5, so the warm path produces a correct install.
    for lp in &lockfile.packages {
        if let Some(ref source) = lp.source
            && !lpm_lockfile::is_safe_source(source)
        {
            if accept_unsafe_sources {
                tracing::debug!(
                    "package {}@{} non-registry source {} accepted in offline mode",
                    lp.name,
                    lp.version,
                    source
                );
                continue;
            }
            tracing::warn!(
                "package {}@{} has unsafe source URL: {} — skipping lockfile fast path",
                lp.name,
                lp.version,
                source
            );
            return None; // Force re-resolution from trusted registries
        }
    }

    if !lockfile_catalog_snapshots_match_current(&lockfile, deps, catalog_resolutions) {
        tracing::debug!("catalog snapshot drift detected — invalidating lockfile fast path");
        return None;
    }

    // — verify every declared root dep has a lockfile
    // entry. For aliased roots, check the ALIAS TARGET (looked up via
    // `lockfile.root_aliases`) rather than the alias key, since the
    // lockfile is keyed by canonical registry names.
    for (local, requested_spec) in deps {
        let target = lockfile
            .root_aliases
            .get(local)
            .map_or(local.as_str(), String::as_str);
        if select_locked_package_for_requested_spec(&lockfile, target, requested_spec).is_none() {
            tracing::debug!(
                "lockfile miss: {local} (resolved target {target}) not found, re-resolving"
            );
            return None;
        }
    }

    // Rebuild per-package root_link_names from root_aliases + deps,
    // using the same algorithm as `resolved_to_install_packages` so
    // the warm-install layout matches the fresh-install layout
    // byte-for-byte.
    //
    // keyed by PackageKey
    // (name, version, source_id) to match the fresh-resolve loop's
    // bookkeeping. This map is defensively future-proofed:
    // the warm-install path only fires when `is_safe_source` accepts
    // every package — and `is_safe_source` rejects `tarball+...`
    // sources today (see [`lpm_lockfile::is_safe_source`] + the
    // gate at ~line 4488), so any lockfile containing a tarball-URL
    // entry falls back to fresh-resolve. Once `is_safe_source` is
    // taught about non-Registry sources, the
    // PackageKey-based lookups in this loop are already correct.
    //
    // Key is "name\x00version" (compound string) to avoid allocating a
    // PackageKey (SHA-256 source_id + 2 String clones) on every build
    // AND every lookup — the root symlink slot is unambiguous for
    // (name, version) since the lockfile rejects same-name-same-version
    // cross-source collisions during resolution.
    let root_link_key = |name: &str, version: &str| -> String {
        let mut k = String::with_capacity(name.len() + 1 + version.len());
        k.push_str(name);
        k.push('\x00');
        k.push_str(version);
        k
    };
    let mut root_link_map: HashMap<String, Vec<String>> = HashMap::new();
    for (local, requested_spec) in deps {
        let target = lockfile
            .root_aliases
            .get(local)
            .cloned()
            .unwrap_or_else(|| local.clone());
        if let Some(lp) =
            select_locked_package_for_requested_spec(&lockfile, &target, requested_spec)
        {
            root_link_map
                .entry(root_link_key(&lp.name, &lp.version))
                .or_default()
                .push(local.clone());
        }
    }
    // surface lockfile-recorded ambient peer installs
    // (auto-installed peers from the cold resolve) at the project's
    // top-level `node_modules/<peer>/`. Without this, a warm install
    // from an older lockfile without peer tracking would skip
    // the auto-installed peer entirely (it's not in
    // `pkg.dependencies` so `deps.keys()` above never visits it),
    // leaving react-redux unable to resolve its `react` peer at
    // runtime. Mirrors the cold-resolve surface logic in
    // `resolved_to_install_packages` (install.rs:7942-7971).
    //
    // Dedup against `deps.keys()` matches the cold-resolve writer:
    // if the user later moves the auto-installed peer into their
    // `dependencies`, we don't want a double-link entry.
    for ambient in &lockfile.ambient_peer_installs {
        if let Some(lp) = lockfile.find_package(ambient) {
            let entry = root_link_map
                .entry(root_link_key(&lp.name, &lp.version))
                .or_default();
            if !entry.iter().any(|l| l == ambient) {
                entry.push(ambient.clone());
            }
        }
    }
    for locals in root_link_map.values_mut() {
        locals.sort();
    }

    // Convert locked packages to InstallPackage
    let packages: Vec<InstallPackage> = lockfile
        .packages
        .iter()
        .map(|lp| {
            let is_lpm = lp.name.starts_with("@lpm.dev/");

            // Parse dependency strings back to (name, version) tuples
            let dependencies: Vec<(String, String)> = lp
                .dependencies
                .iter()
                .filter_map(|dep_str| {
                    // Format: "name@version"
                    dep_str
                        .rfind('@')
                        .map(|at| (dep_str[..at].to_string(), dep_str[at + 1..].to_string()))
                })
                .collect();

            // — restore per-package alias map from the
            // lockfile's `alias-dependencies` entries.
            let aliases: HashMap<String, String> = lp
                .alias_dependencies
                .iter()
                .map(|pair| (pair[0].clone(), pair[1].clone()))
                .collect();

            // restore per-package peer pinning from the
            // lockfile. Same string shape as `dependencies`:
            // `<peer_name>@<version>`. Empty for packages without
            // peer dependencies (most of the tree). Load-bearing for
            // v2 graph-key reproducibility — the v2 linker hashes
            // peer pinning into the link-entry identity, so a warm
            // install that forgets peer state computes a different
            // graph key than the cold install and silently
            // materializes a separate link entry (worst case: shares
            // an entry with an unrelated project that happens to
            // have matching dep edges + empty peers).
            //
            // Older lockfiles have no `peers = [...]` field; serde
            // defaults to empty Vec. The first warm install on such
            // a lockfile reconstructs with empty peers, which
            // happens to match what the v2 linker would have
            // produced under the empty-peer-context graph key — same
            // wrong-but-self-consistent shape as before.
            // Re-running a fresh resolve writes the peers field and
            // upgrades the project to the correct shape.
            let peers: Vec<(String, String)> = lp
                .peers
                .iter()
                .filter_map(|s| {
                    s.rfind('@')
                        .map(|at| (s[..at].to_string(), s[at + 1..].to_string()))
                })
                .collect();

            let root_link_names = root_link_map
                .get(&root_link_key(&lp.name, &lp.version))
                .cloned();
            let is_direct = install_package_is_direct(root_link_names.as_deref(), deps);

            InstallPackage {
                name: lp.name.clone(),
                version: lp.version.clone(),
                source: lp
                    .source
                    .clone()
                    .unwrap_or_else(|| "registry+https://registry.npmjs.org".to_string()),
                dependencies,
                aliases,
                // `root_link_names` restored from the lockfile's
                // `root-aliases` map. `None` for transitive packages
                // (no root symlink); `Some(vec)` for direct deps,
                // including aliased ones.
                root_link_names,
                is_direct,
                is_lpm,
                peers,
                integrity: lp.integrity.clone(),
                registry_signatures: install_registry_signatures(&lp.registry_signatures),
                registry_published_at: lp.registry_published_at.clone(),
                platform: platform_meta_from_lockfile(lp),
                optional: lp.optional,
                // — gate a stored URL against scheme/shape/
                // origin before reusing it. Any rejection downgrades
                // to `None`, which forces on-demand lookup against
                // the current registry.
                tarball_url: lp.tarball.as_deref().and_then(|url| {
                    match evaluate_cached_url(url, client) {
                        GateDecision::Accepted => Some(url.to_string()),
                        GateDecision::RejectedScheme => {
                            // Writer never emits scheme-unsafe URLs,
                            // so this path signals a corrupt lockfile.
                            // Counter-bumped for telemetry symmetry
                            // with shape/origin — makes corrupt-
                            // lockfile signals observable instead of
                            // trace-log-only.
                            gate_stats
                                .scheme_mismatch
                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            tracing::warn!(
                                "cached tarball URL for {}@{} has unsafe scheme; \
                                 falling back to on-demand lookup",
                                lp.name,
                                lp.version,
                            );
                            None
                        }
                        GateDecision::RejectedShape => {
                            gate_stats
                                .shape_mismatch
                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            tracing::warn!(
                                "cached tarball URL for {}@{} failed shape check; \
                                 falling back to on-demand lookup",
                                lp.name,
                                lp.version,
                            );
                            None
                        }
                        GateDecision::RejectedOrigin => {
                            // Expected after `LPM_REGISTRY_URL` switch:
                            // stored `@lpm.dev/*` URLs mismatch the new
                            // origin and fall through to on-demand
                            // lookup against the mirror. The writeback
                            // trigger ( Change 3) will persist the
                            // rebased URLs on the next install.
                            gate_stats
                                .origin_mismatch
                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            None
                        }
                    }
                }),
                metadata_checked_for_tarball: false,
            }
        })
        .collect();

    Some(LockfileFastPath {
        packages,
        lockfile,
        needs_binary_upgrade,
    })
}

/// — rebuild the root-level alias map from `packages`
/// for lockfile persistence. Walks each package's `root_link_names`;
/// any local name that differs from the package's canonical name is
/// an alias declaration (e.g., `strip-ansi-cjs` on a `strip-ansi`
/// InstallPackage). Returns a `BTreeMap` so serialized TOML has
/// deterministic order across runs.
pub(super) fn root_aliases_for_lockfile(
    packages: &[InstallPackage],
    _deps: &HashMap<String, String>,
) -> std::collections::BTreeMap<String, String> {
    let mut aliases = std::collections::BTreeMap::new();
    for pkg in packages {
        if let Some(link_names) = &pkg.root_link_names {
            for local in link_names {
                if local != &pkg.name {
                    aliases.insert(local.clone(), pkg.name.clone());
                }
            }
        }
    }
    aliases
}

/// Convert resolver output to InstallPackage list.
///
/// — the `root_aliases` map (from the resolver's
/// `ResolveResult`) is used to (1) compute `is_direct` for aliased
/// root deps whose canonical name does NOT appear in `deps.keys()`
/// (the pre- `deps.contains_key(&name)` missed these) and (2)
/// copy the per-package transitive alias map from
/// `ResolvedPackage.aliases`. Root-level `root_link_names` are
/// filled in later in the install pipeline, since they require
/// matching resolved versions against the root `deps` map.
///
/// `ambient_peer_installs` carries the canonical
/// names the resolver synthesized as ambient root-scoped installs to
/// satisfy unmet required peers (auto-install). They are NOT in
/// `deps` (the user's `package.json > dependencies`), but they MUST
/// surface at the project's top-level `node_modules/<name>/` so
/// runtime `require()` from peer-declaring consumers resolves
/// correctly. This function unions them with `deps.keys()` when
/// computing both `direct_target_names` (for `is_direct`/script
/// gating) and `root_link_map` (for top-level node_modules symlinks).
/// Ambient installs are NOT marked `is_direct = true` because they
/// aren't user-declared — they shouldn't trigger scripts that the
/// user didn't opt into. They DO get root-link entries so the
/// linker exposes them at the canonical module-resolution path.
///
/// Compute a `canonical_name → highest-stable-version` map from the
/// resolver's metadata cache. Used by the post-install `+` list to
/// annotate direct deps with `(vX.Y.Z available)` when the registry
/// has a newer stable release than the resolver picked.
///
/// "Stable" excludes pre-releases (anything carrying a `-alpha` /
/// `-beta` / `-rc` / etc. tag in the semver). `versions` is sorted
/// descending in [`lpm_resolver::CachedPackageInfo`], so we scan from
/// the top and pick the first stable. Returns no entry when the cache
/// has no stable version at all (rare — usually a private one-off pkg).
pub(super) fn build_latest_stable_versions(
    cache: &HashMap<lpm_resolver::CanonicalKey, std::sync::Arc<lpm_resolver::CachedPackageInfo>>,
) -> HashMap<String, String> {
    let mut out = HashMap::with_capacity(cache.len());
    for (key, info) in cache {
        let name = match key {
            lpm_resolver::CanonicalKey::Root => continue,
            lpm_resolver::CanonicalKey::Lpm { owner, name } => format!("@lpm.dev/{owner}.{name}"),
            lpm_resolver::CanonicalKey::Npm { name } => name.clone(),
        };
        if let Some(latest) = info.versions.iter().find(|v| !v.is_prerelease()) {
            out.insert(name, latest.to_string());
        }
    }
    out
}

pub(super) fn resolved_to_install_packages(
    resolved: &[ResolvedPackage],
    deps: &HashMap<String, String>,
    root_aliases: &HashMap<String, String>,
    // (see function doc)
    ambient_peer_installs: &[String],
    resolver_cache: &HashMap<CanonicalKey, Arc<CachedPackageInfo>>,
    // (reviewed) — supplied so the source string
    // reflects the actual registry the package was fetched from
    // (`.npmrc`-mapped private mirrors, etc.) rather than a
    // hardcoded npmjs.org. motivated source_id by URL for
    // exactly this reason; without route-awareness here, the type
    // system's granularity wasn't reaching the install pipeline.
    route_table: &RouteTable,
) -> Vec<InstallPackage> {
    // Targets the root either declares directly OR reaches via an
    // npm-alias: each such target's (any version's) resolved package
    // is considered a direct dep for scripts/display.
    //
    // **Note:** ambient_peer_installs are intentionally NOT folded
    // into `direct_target_names` — they aren't user-declared, so
    // they don't get `is_direct = true` (which gates script
    // execution + display). They DO get root_link entries below.
    // For each resolved direct package, capture its resolved
    // version. Keyed by canonical_name. Used below to compute the
    // `(name, version, source_id)` triple under which the package
    // will be filed in the lockfile.
    // "name\x00version" compound key — avoids allocating a PackageKey
    // (SHA-256 source_id + 2 String clones) per entry and per lookup.
    // Safe because same-name-same-version cross-source packages collapse
    // to one row via the dedup filter below.
    let rlk = |name: &str, version: &str| -> String {
        let mut k = String::with_capacity(name.len() + 1 + version.len());
        k.push_str(name);
        k.push('\x00');
        k.push_str(version);
        k
    };
    let mut root_link_map: HashMap<String, Vec<String>> = HashMap::new();
    for (local, requested_spec) in deps {
        let target = root_aliases
            .get(local)
            .cloned()
            .unwrap_or_else(|| local.clone());
        if let Some(package) =
            select_resolved_package_for_requested_spec(resolved, &target, requested_spec)
        {
            root_link_map
                .entry(rlk(&target, &package.version.to_string()))
                .or_default()
                .push(local.clone());
        }
    }
    // Ambient peer installs also need top-level link
    // entries so `node_modules/<peer>/` resolves at runtime. Unioned
    // here rather than in `deps` so `is_direct` (above) stays false
    // for them — same key shape, separate provenance.
    for ambient in ambient_peer_installs {
        if deps.contains_key(ambient) {
            continue;
        }
        if let Some(package) = resolved
            .iter()
            .filter(|package| package.package.canonical_name() == *ambient)
            .max_by(|a, b| a.version.cmp(&b.version))
        {
            // Avoid duplicate locals if the user ALSO listed the peer
            // in their `dependencies` (in which case `deps.keys()`
            // already covered it; we shouldn't double-link).
            let entry = root_link_map
                .entry(rlk(ambient, &package.version.to_string()))
                .or_default();
            if !entry.iter().any(|l| l == ambient) {
                entry.push(ambient.clone());
            }
        }
    }
    // Stable ordering so snapshot tests and binary round-trips don't
    // flap on HashMap iteration order.
    for locals in root_link_map.values_mut() {
        locals.sort();
    }

    // The resolver can emit multiple `ResolvedPackage`
    // rows for the same `(canonical_name, version)` tuple when // splits a subtree for multi-version peer-dep resolution: each
    // split scope produces its own row differing only in
    // `ResolverPackage::context`. `canonical_name()` strips that context,
    // so every split collapses to the same `InstallPackage`. Without
    // this dedup, downstream stages receive N identical rows for one
    // physical package, which in turn produced N concurrent // root-symlink creations in `link_finalize` and raced on
    // `std::os::unix::fs::symlink` — leaving whichever thread lost to
    // abort the install with `EEXIST`.
    //
    // First-seen wins. The resolver guarantees that all rows with the
    // same `(canonical_name, version)` agree on everything observable
    // to the install pipeline — same tarball URL, same integrity, same
    // dependency set, same aliases — because they represent the same
    // physical package. Split contexts are a resolver-internal scoping
    // device that doesn't change the store's view of the package.
    //
    // Preserving the resolver's input order keeps lockfile and JSON
    // output deterministic across runs.
    let mut seen: std::collections::HashSet<String> =
        std::collections::HashSet::with_capacity(resolved.len());
    resolved
        .iter()
        .filter_map(|r| {
            let name = r.package.canonical_name();
            let version = r.version.to_string();
            if !seen.insert(rlk(&name, &version)) {
                return None;
            }
            let canonical = CanonicalKey::from(&r.package);
            let (registry_signatures, registry_published_at) = resolver_cache
                .get(&canonical)
                .and_then(|info| info.dist.get(&version))
                .map(|dist| (dist.signatures.clone(), dist.published_at.clone()))
                .unwrap_or_default();
            let is_lpm = r.package.is_lpm();
            // (reviewed): derive the wire-format source
            // string from the active route table, so a `.npmrc`-mapped
            // private mirror gets filed under its real URL.
            let registry_url = registry_source_url_for(&name, route_table);
            let source = format!("registry+{registry_url}");
            let root_link_names = root_link_map.get(&rlk(&name, &version)).cloned();
            let is_direct = install_package_is_direct(root_link_names.as_deref(), deps);

            Some(InstallPackage {
                name,
                version,
                source,
                dependencies: r.dependencies.clone(),
                aliases: r.aliases.clone(),
                root_link_names,
                is_direct,
                is_lpm,
                // — peer-context threading. The resolver
                // intersected this package's declared peers against
                // the install set; carry the resulting
                // `(peer_name, version)` list straight through.
                peers: r.peers.clone(),
                integrity: r.integrity.clone(),
                registry_signatures,
                registry_published_at,
                platform: r.platform.clone(),
                optional: r.optional,
                tarball_url: r.tarball_url.clone(),
                metadata_checked_for_tarball: true,
            })
        })
        .collect()
}

#[allow(clippy::too_many_arguments)]
pub(super) fn resolved_to_install_packages_with_workspace_members(
    resolved: &[ResolvedPackage],
    deps: &HashMap<String, String>,
    root_aliases: &HashMap<String, String>,
    ambient_peer_installs: &[String],
    resolver_cache: &HashMap<CanonicalKey, Arc<CachedPackageInfo>>,
    route_table: &RouteTable,
    all_workspace_members: &[WorkspaceMemberLink],
    project_dir: &Path,
) -> Vec<InstallPackage> {
    let mut packages = resolved_to_install_packages(
        resolved,
        deps,
        root_aliases,
        ambient_peer_installs,
        resolver_cache,
        route_table,
    );
    rewrite_workspace_resolved_sources(&mut packages, all_workspace_members, project_dir);
    packages
}
