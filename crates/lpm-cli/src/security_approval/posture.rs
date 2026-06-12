use super::prelude::*;

pub fn load_authorized_posture() -> Result<AuthorizedPosture, LpmError> {
    Ok(read_signed_json(&approved_posture_path()?)?.unwrap_or_default())
}

pub fn load_effective_authorized_posture() -> Result<EffectiveAuthorizedPosture, LpmError> {
    let approved_path = approved_posture_path()?;
    let approved_posture_source = if approved_path.exists() {
        PostureSourceKind::ApprovedStore
    } else {
        PostureSourceKind::BuiltinDefault
    };
    let mut posture = load_authorized_posture()?;
    let mut sources = EffectivePostureSources::new(approved_posture_source);
    let managed_policy = load_managed_policy()?;

    if let Some(policy) = managed_policy.as_ref() {
        if let Some(script_policy) = policy.script_policy {
            posture.script_policy = script_policy.as_str().to_string();
            sources.script_policy = PostureSourceKind::ManagedPolicy;
        }
        if let Some(minimum_release_age_secs) = policy.minimum_release_age_secs {
            posture.minimum_release_age_secs = minimum_release_age_secs;
            sources.minimum_release_age_secs = PostureSourceKind::ManagedPolicy;
        }
        if let Some(sandbox_mode) = policy.sandbox_mode {
            posture.sandbox_mode = sandbox_mode.as_str().to_string();
            sources.sandbox_mode = PostureSourceKind::ManagedPolicy;
        }
        if let Some(sandbox_allow_degraded) = policy.sandbox_allow_degraded {
            posture.sandbox_allow_degraded = sandbox_allow_degraded;
            sources.sandbox_allow_degraded = PostureSourceKind::ManagedPolicy;
        }
        if let Some(sigstore_verify) = policy.sigstore_verify {
            posture.sigstore_verify =
                crate::security_floor::sigstore_mode_name(sigstore_verify).to_string();
            sources.sigstore_verify = PostureSourceKind::ManagedPolicy;
        }
    }

    Ok(EffectiveAuthorizedPosture {
        posture,
        sources,
        approved_posture_path: approved_path.display().to_string(),
        approved_posture_source,
        managed_policy: managed_policy.map(|policy| policy.status),
    })
}

pub fn persist_authorized_posture(posture: &AuthorizedPosture) -> Result<(), LpmError> {
    let mut normalized = posture.clone();
    normalized.schema_version = APPROVED_POSTURE_SCHEMA_VERSION;
    normalized.updated_at = Utc::now();
    write_signed_json(&approved_posture_path()?, &normalized)
}

fn active_runtime_overrides(effective: &EffectiveAuthorizedPosture) -> Vec<RuntimeOverride> {
    let env_value = std::env::var("LPM_PROVENANCE_ENFORCE").ok();
    let global = crate::commands::config::GlobalConfig::load();
    let (mode, source) =
        EnforceMode::resolve_from_chain(env_value.as_deref(), || global.get_sigstore_verify());
    let effective_mode = effective.posture.sigstore_verify();
    if matches!(
        source,
        crate::provenance_fetch::EnforceModeSource::Env
            | crate::provenance_fetch::EnforceModeSource::Config
    ) && mode != effective_mode
    {
        return vec![RuntimeOverride {
            control: "sigstore.verify".to_string(),
            value: crate::security_floor::sigstore_mode_name(mode).to_string(),
            source: match source {
                crate::provenance_fetch::EnforceModeSource::Env => {
                    "LPM_PROVENANCE_ENFORCE".to_string()
                }
                crate::provenance_fetch::EnforceModeSource::Config => {
                    "~/.lpm/config.toml [sigstore].verify".to_string()
                }
                crate::provenance_fetch::EnforceModeSource::Default => unreachable!(),
            },
        }];
    }
    Vec::new()
}

pub fn load_security_status(
    project_dir: Option<&Path>,
    global: bool,
) -> Result<SecurityStatus, LpmError> {
    let effective = load_effective_authorized_posture()?;
    let active_runtime_overrides = active_runtime_overrides(&effective);
    let (target, project_root, active_unlocks) = if global {
        (
            UnlockTargetKind::Global,
            Some(canonical_global_root()?),
            list_active_global_unlocks()?,
        )
    } else {
        match project_dir {
            Some(dir) => (
                UnlockTargetKind::Project,
                Some(canonical_project_root(dir)),
                list_active_project_unlocks(dir)?,
            ),
            None => (UnlockTargetKind::Project, None, list_active_unlocks()?),
        }
    };

    Ok(SecurityStatus {
        target,
        project_root,
        effective_floor: effective.posture.to_view(),
        floor_sources: effective.sources,
        approved_posture_path: effective.approved_posture_path,
        approved_posture_source: effective.approved_posture_source,
        managed_policy: effective.managed_policy,
        active_runtime_overrides,
        active_unlocks,
    })
}
