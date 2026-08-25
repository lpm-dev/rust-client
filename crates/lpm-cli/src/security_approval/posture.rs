use super::prelude::*;

struct AuthorizedPostureTransactionState {
    original: Option<AuthorizedPosture>,
    pending: Option<AuthorizedPosture>,
}

thread_local! {
    static AUTHORIZED_POSTURE_TRANSACTION: std::cell::RefCell<Option<AuthorizedPostureTransactionState>> = const { std::cell::RefCell::new(None) };
}

pub(crate) struct AuthorizedPostureTransaction {
    active: bool,
}

impl AuthorizedPostureTransaction {
    pub(crate) fn commit(mut self) -> Result<(), LpmError> {
        let state =
            AUTHORIZED_POSTURE_TRANSACTION.with(|transaction| transaction.borrow_mut().take());
        self.active = false;
        let Some(state) = state else {
            return Err(LpmError::SecurityApprovalStore(
                "authorized posture transaction was not active".to_string(),
            ));
        };
        let Some(pending) = state.pending else {
            return Ok(());
        };
        if state.original.as_ref() == Some(&pending) {
            return Ok(());
        }
        persist_authorized_posture_immediately(&pending)
    }
}

impl Drop for AuthorizedPostureTransaction {
    fn drop(&mut self) {
        if self.active {
            AUTHORIZED_POSTURE_TRANSACTION.with(|transaction| {
                transaction.borrow_mut().take();
            });
        }
    }
}

pub(crate) fn begin_authorized_posture_transaction()
-> Result<AuthorizedPostureTransaction, LpmError> {
    AUTHORIZED_POSTURE_TRANSACTION.with(|transaction| {
        let mut transaction = transaction.borrow_mut();
        if transaction.is_some() {
            return Err(LpmError::SecurityApprovalStore(
                "nested authorized posture transactions are not supported".to_string(),
            ));
        }
        *transaction = Some(AuthorizedPostureTransactionState {
            original: None,
            pending: None,
        });
        Ok(AuthorizedPostureTransaction { active: true })
    })
}

pub fn load_authorized_posture() -> Result<AuthorizedPosture, LpmError> {
    if let Some(posture) = AUTHORIZED_POSTURE_TRANSACTION.with(|transaction| {
        transaction
            .borrow()
            .as_ref()
            .and_then(|state| state.pending.clone())
    }) {
        return Ok(posture);
    }
    let posture = load_authorized_posture_immediately()?;
    AUTHORIZED_POSTURE_TRANSACTION.with(|transaction| {
        if let Some(state) = transaction.borrow_mut().as_mut()
            && state.original.is_none()
        {
            state.original = Some(posture.clone());
        }
    });
    Ok(posture)
}

fn load_authorized_posture_immediately() -> Result<AuthorizedPosture, LpmError> {
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
        if let Some(release_age_policy) = policy.release_age_policy {
            posture.release_age_policy = release_age_policy.as_str().to_string();
            sources.release_age_policy = PostureSourceKind::ManagedPolicy;
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
        if let Some(typosquat_guard) = policy.typosquat_guard {
            posture.typosquat_guard = typosquat_guard.as_str().to_string();
            sources.typosquat_guard = PostureSourceKind::ManagedPolicy;
        }
        if let Some(firewall_mode) = policy.firewall_mode {
            posture.firewall_mode = firewall_mode.as_str().to_string();
            sources.firewall_mode = PostureSourceKind::ManagedPolicy;
        }
        if let Some(install_time_source_analysis) = policy.install_time_source_analysis {
            posture.install_time_source_analysis = install_time_source_analysis;
            sources.install_time_source_analysis = PostureSourceKind::ManagedPolicy;
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
    let transaction_active =
        AUTHORIZED_POSTURE_TRANSACTION.with(|transaction| transaction.borrow().is_some());
    if !transaction_active {
        return persist_authorized_posture_immediately(&normalized);
    }
    let needs_original = AUTHORIZED_POSTURE_TRANSACTION.with(|transaction| {
        transaction
            .borrow()
            .as_ref()
            .is_some_and(|state| state.original.is_none())
    });
    let original = needs_original
        .then(load_authorized_posture_immediately)
        .transpose()?;
    AUTHORIZED_POSTURE_TRANSACTION.with(|transaction| {
        let mut transaction = transaction.borrow_mut();
        let state = transaction
            .as_mut()
            .expect("active posture transaction disappeared before staging");
        if state.original.is_none() {
            state.original = original;
        }
        state.pending = Some(normalized.clone());
    });
    Ok(())
}

fn persist_authorized_posture_immediately(posture: &AuthorizedPosture) -> Result<(), LpmError> {
    write_signed_json(&approved_posture_path()?, posture)
}

fn active_runtime_overrides(
    effective: &EffectiveAuthorizedPosture,
) -> Result<Vec<RuntimeOverride>, LpmError> {
    let env_value = std::env::var("LPM_PROVENANCE_ENFORCE").ok();
    let global = crate::commands::config::GlobalConfig::load_checked()?;
    let mut overrides = Vec::new();
    let (mode, source) =
        EnforceMode::resolve_from_chain(env_value.as_deref(), || global.get_sigstore_verify());
    let effective_mode = effective.posture.sigstore_verify();
    if matches!(
        source,
        crate::provenance_fetch::EnforceModeSource::Env
            | crate::provenance_fetch::EnforceModeSource::Config
    ) && mode != effective_mode
    {
        overrides.push(RuntimeOverride {
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
        });
    }
    let effective_typosquat = effective.posture.typosquat_guard();
    if let Some(config_typosquat) = global.get_typosquat_guard_mode()
        && config_typosquat != effective_typosquat
    {
        overrides.push(RuntimeOverride {
            control: crate::commands::config::TYPOSQUAT_GUARD_KEY.to_string(),
            value: config_typosquat.as_str().to_string(),
            source: "~/.lpm/config.toml typosquat-guard".to_string(),
        });
    }
    let effective_firewall = effective.posture.firewall_mode();
    if let Some(request_firewall) = crate::npm_firewall_config::runtime_request_mode(&global)?
        && request_firewall.mode() != effective_firewall
    {
        overrides.push(RuntimeOverride {
            control: crate::npm_firewall_config::FIREWALL_CONFIG_PATH.to_string(),
            value: request_firewall.mode().as_str().to_string(),
            source: request_firewall.source_label().to_string(),
        });
    }
    let requested_source_analysis =
        crate::source_analysis_config::read_install_time_source_analysis(&global)?;
    if requested_source_analysis != effective.posture.install_time_source_analysis() {
        overrides.push(RuntimeOverride {
            control: crate::source_analysis_config::INSTALL_TIME_SOURCE_ANALYSIS_KEY.to_string(),
            value: requested_source_analysis.to_string(),
            source: "~/.lpm/config.toml install-time-source-analysis".to_string(),
        });
    }
    Ok(overrides)
}

pub fn load_security_status(
    project_dir: Option<&Path>,
    global: bool,
) -> Result<SecurityStatus, LpmError> {
    let effective = load_effective_authorized_posture()?;
    let active_runtime_overrides = active_runtime_overrides(&effective)?;
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
