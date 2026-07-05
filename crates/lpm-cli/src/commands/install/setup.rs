use super::*;

pub(super) struct InstallSetupInput<'a> {
    pub(super) project_dir: &'a Path,
    pub(super) json_output: bool,
    pub(super) frozen_lockfile: FrozenLockfileMode,
    pub(super) allow_new: bool,
    pub(super) strict_peer_dependencies_override: Option<bool>,
    pub(super) linker_override: Option<lpm_linker::LinkerMode>,
    pub(super) min_release_age_override: Option<u64>,
    pub(super) min_release_age_exclude: &'a [String],
    pub(super) timing: bool,
}

pub(super) struct InstallSetupContext {
    pub(super) timing_detail_mode: TimingDetailMode,
    pub(super) emit_timing: bool,
    pub(super) global_config: crate::commands::config::GlobalConfig,
    pub(super) object_integrity_policy: lpm_store::v2::ObjectIntegrityPolicy,
    pub(super) verify_registry_signatures: bool,
    pub(super) registry_signature_timings:
        Option<Arc<crate::registry_signatures::RegistrySignatureTimings>>,
    pub(super) provenance_timings: Option<crate::provenance_fetch::ProvenanceTimings>,
    pub(super) npm_firewall_lookup_mode: NpmFirewallLookupMode,
    pub(super) npm_firewall_chunk_size: usize,
    pub(super) policy_extension_configs: Vec<policy_extensions::PolicyExtensionConfig>,
    pub(super) force_security_floor: bool,
    pub(super) pkg_json_path: PathBuf,
    pub(super) lockfile_path: PathBuf,
    pub(super) frozen_lockfile_active: bool,
    pub(super) pkg: lpm_workspace::PackageJson,
    pub(super) npm_firewall_mode: crate::npm_firewall_config::NpmFirewallMode,
    pub(super) effective_min_age_secs: u64,
    pub(super) resolver_min_age_secs: u64,
    pub(super) release_age_policy: crate::release_age_config::ReleaseAgePolicy,
    pub(super) resolver_trust_policy: lpm_resolver::TrustPolicyMode,
    pub(super) minimum_release_age_exclude: Vec<String>,
    pub(super) auto_install_peers: bool,
    pub(super) strict_peer_dependencies: bool,
    pub(super) pubgrub_opt_out: bool,
    pub(super) configured_linker_mode: lpm_linker::LinkerMode,
    pub(super) peer_conflict_auto_isolation_allowed: bool,
    pub(super) auto_isolated_peer_conflicts: bool,
    pub(super) linker_mode: lpm_linker::LinkerMode,
    pub(super) requested_v2_mode: bool,
    pub(super) manifest_deps: HashMap<String, String>,
    pub(super) production_dependency_names: HashSet<String>,
}

pub(super) fn prepare_install_setup_context(
    input: InstallSetupInput<'_>,
) -> Result<InstallSetupContext, LpmError> {
    lpm_registry::timing::reset_metadata_http_versions();
    lpm_registry::timing::reset_metadata_detail();
    crate::build_state::reset_write_timing();
    crate::security_floor::clear_recorded_suppressions();

    let timing_detail_mode = TimingDetailMode::from_env();
    let emit_timing = crate::json_contract::install_timing_requested(input.timing);
    let global_config = crate::commands::config::GlobalConfig::load_checked()?;
    let object_integrity_policy =
        crate::commands::config::resolve_object_integrity_policy(&global_config)?;
    let verify_registry_signatures = registry_signature_verification_enabled(&global_config);
    let registry_signature_timings = timing_detail_mode
        .enabled()
        .then(|| Arc::new(crate::registry_signatures::RegistrySignatureTimings::default()));
    let provenance_timings = timing_detail_mode
        .enabled()
        .then(crate::provenance_fetch::ProvenanceTimings::default);
    let npm_firewall_lookup_mode = NpmFirewallLookupMode::from_env();
    let npm_firewall_chunk_size = npm_firewall_chunk_size_from_env();
    let policy_extension_configs = load_policy_extension_configs(&global_config)?;
    let force_security_floor = crate::security_floor::force_security_floor_enabled(&global_config);

    let pkg_json_path = input.project_dir.join("package.json");
    let lockfile_path = input.project_dir.join(lpm_lockfile::LOCKFILE_NAME);
    let frozen_lockfile_active = input.frozen_lockfile.is_active(&lockfile_path);
    if !pkg_json_path.exists() {
        return Err(LpmError::NotFound(
            "no package.json found in current directory or any parent. \
             Run `lpm init` to create one, or `lpm install <pkg>` to auto-create."
                .to_string(),
        ));
    }

    let pkg = lpm_workspace::read_package_json(&pkg_json_path)
        .map_err(|e| LpmError::Registry(format!("failed to read package.json: {e}")))?;

    crate::security_approval::ensure_project_policy_authorized(
        input.project_dir,
        input.json_output,
        crate::security_approval::ApprovalSource::ProjectConfig,
    )?;
    let npm_firewall_mode = crate::npm_firewall_config::resolve_runtime_mode(
        &global_config,
        input.project_dir,
        input.json_output,
    )?;
    crate::typosquat_guard::guard_manifest_direct_dependencies(
        input.project_dir,
        &pkg_json_path,
        &pkg,
        input.json_output,
    )?;

    let release_age_config = crate::release_age_config::ReleaseAgeResolver::resolve_config(
        input.project_dir,
        input.min_release_age_override,
        input.min_release_age_exclude,
        input.json_output,
    )?;
    let effective_min_age_secs = release_age_config.minimum_release_age_secs;
    if input.allow_new && effective_min_age_secs > 0 {
        crate::security_approval::approve_project_runtime_override(
            crate::security_approval::ApprovalScope::CooldownBypass,
            input.project_dir,
            input.json_output,
            crate::security_approval::ApprovalSource::CliFlag,
            "This install bypasses the minimum release age for this project.",
            &[],
        )?;
    }
    let resolver_min_age_secs = if input.allow_new {
        0
    } else {
        effective_min_age_secs
    };
    let release_age_policy = release_age_config.minimum_release_age_policy;
    let resolver_trust_policy = match global_config.get_trust_policy().as_deref() {
        Some("no-downgrade") => lpm_resolver::TrustPolicyMode::NoDowngrade,
        _ => lpm_resolver::TrustPolicyMode::Off,
    };
    let minimum_release_age_exclude = release_age_config.minimum_release_age_exclude;

    let auto_install_peers: bool = pkg
        .lpm
        .as_ref()
        .and_then(|l| l.auto_install_peers)
        .or_else(|| global_config.get_bool("auto-install-peers"))
        .unwrap_or(true);
    let strict_peer_dependencies = resolve_strict_peer_dependencies(
        input.strict_peer_dependencies_override,
        &pkg,
        &global_config,
    );
    let pubgrub_opt_out = std::env::var("LPM_RESOLVER").as_deref() == Ok("pubgrub");
    if pubgrub_opt_out && auto_install_peers {
        output::warn(
            "LPM_RESOLVER=pubgrub does not support eager peer auto-install \
             (lpm.autoInstallPeers = true). Missing peers will surface as \
             warnings only — the install tree will differ from the default \
             greedy-fusion resolver. To silence this warning, either unset \
             LPM_RESOLVER or set `lpm.autoInstallPeers = false` in package.json.",
        );
    }

    let (configured_linker_mode, linker_source) =
        crate::linker_config::resolve_effective_linker_with_source(
            input.linker_override,
            &pkg,
            &global_config,
            input.project_dir,
        )
        .map_err(|e| {
            LpmError::Script(format!(
                "{e} \
             Update the offending surface or override with \
             `--linker=<isolated|hoisted>`."
            ))
        })?;
    let peer_conflict_auto_isolation_allowed = matches!(
        linker_source,
        crate::linker_config::LinkerModeSource::Default
    );
    let auto_isolated_peer_conflicts = peer_conflict_auto_isolation_allowed
        && lockfile_has_auto_isolated_peer_conflicts(&lockfile_path);
    let linker_mode = if auto_isolated_peer_conflicts {
        lpm_linker::LinkerMode::Isolated
    } else {
        configured_linker_mode
    };
    let requested_v2_mode = lpm_store::StoreVersion::from_env().is_v2();
    let mut manifest_deps = manifest_install_deps(&pkg);
    normalize_jsr_manifest_deps(&mut manifest_deps)?;
    let production_dependency_names: HashSet<String> = pkg.dependencies.keys().cloned().collect();
    reject_remote_tarball_url_deps_with_policy_extensions(
        &policy_extension_configs,
        &manifest_deps,
    )?;

    Ok(InstallSetupContext {
        timing_detail_mode,
        emit_timing,
        global_config,
        object_integrity_policy,
        verify_registry_signatures,
        registry_signature_timings,
        provenance_timings,
        npm_firewall_lookup_mode,
        npm_firewall_chunk_size,
        policy_extension_configs,
        force_security_floor,
        pkg_json_path,
        lockfile_path,
        frozen_lockfile_active,
        pkg,
        npm_firewall_mode,
        effective_min_age_secs,
        resolver_min_age_secs,
        release_age_policy,
        resolver_trust_policy,
        minimum_release_age_exclude,
        auto_install_peers,
        strict_peer_dependencies,
        pubgrub_opt_out,
        configured_linker_mode,
        peer_conflict_auto_isolation_allowed,
        auto_isolated_peer_conflicts,
        linker_mode,
        requested_v2_mode,
        manifest_deps,
        production_dependency_names,
    })
}
