use super::prelude::*;

fn managed_policy_write_error(
    managed_policy: &ManagedPolicyStatus,
    knob: &str,
    requested: impl AsRef<str>,
    enforced: impl AsRef<str>,
) -> LpmError {
    LpmError::SecurityFloor(format!(
        "managed security policy `{}` keeps `{knob}` at `{}`. Update that higher-authority policy before setting `{knob}` to `{}` here.",
        managed_policy.path,
        enforced.as_ref(),
        requested.as_ref(),
    ))
}

fn managed_policy_scope_error(
    managed_policy: &ManagedPolicyStatus,
    scope: ApprovalScope,
    control: &str,
) -> LpmError {
    LpmError::SecurityFloor(format!(
        "managed security policy `{}` owns `{control}`, so `{}` cannot be unlocked here. Update that higher-authority policy before weakening this control.",
        managed_policy.path,
        scope.as_str(),
    ))
}

pub(super) fn managed_policy_blocks_scope(
    effective: &EffectiveAuthorizedPosture,
    scope: ApprovalScope,
) -> Option<LpmError> {
    let managed_policy = effective.managed_policy.as_ref()?;
    let blocked_control = match scope {
        ApprovalScope::ScriptsAllow | ApprovalScope::ScriptsTriage
            if matches!(
                effective.sources.script_policy,
                PostureSourceKind::ManagedPolicy
            ) =>
        {
            Some("script-policy")
        }
        ApprovalScope::CooldownBypass | ApprovalScope::CooldownWindow
            if matches!(
                effective.sources.minimum_release_age_secs,
                PostureSourceKind::ManagedPolicy
            ) || matches!(
                effective.sources.release_age_policy,
                PostureSourceKind::ManagedPolicy
            ) =>
        {
            Some("minimum-release-age")
        }
        ApprovalScope::SandboxDefault | ApprovalScope::SandboxNone
            if matches!(
                effective.sources.sandbox_mode,
                PostureSourceKind::ManagedPolicy
            ) =>
        {
            Some("sandbox.mode")
        }
        ApprovalScope::SandboxAllowDegraded
            if matches!(
                effective.sources.sandbox_allow_degraded,
                PostureSourceKind::ManagedPolicy
            ) =>
        {
            Some("sandbox.allow-degraded")
        }
        ApprovalScope::ProvenanceUnverified | ApprovalScope::ProvenanceIgnoreDrift
            if matches!(
                effective.sources.sigstore_verify,
                PostureSourceKind::ManagedPolicy
            ) =>
        {
            Some("sigstore.verify")
        }
        _ => None,
    }?;
    Some(managed_policy_scope_error(
        managed_policy,
        scope,
        blocked_control,
    ))
}

fn approval_source_for_enforce_source(
    source: crate::provenance_fetch::EnforceModeSource,
) -> ApprovalSource {
    match source {
        crate::provenance_fetch::EnforceModeSource::Env => ApprovalSource::EnvVar,
        crate::provenance_fetch::EnforceModeSource::Config => ApprovalSource::GlobalConfig,
        crate::provenance_fetch::EnforceModeSource::Default => ApprovalSource::SecurityCommand,
    }
}

pub fn approval_required_error(
    message: impl Into<String>,
    requested_scopes: Vec<String>,
    project_root: Option<String>,
    suggested_command: Option<String>,
) -> LpmError {
    LpmError::SecurityApprovalRequired {
        message: message.into(),
        requested_scopes,
        project_root,
        suggested_command,
    }
}

fn approval_required_for_scopes(
    message: impl Into<String>,
    scopes: &[ApprovalScope],
    project_root: Option<String>,
) -> LpmError {
    let requested_scopes: Vec<_> = scopes
        .iter()
        .map(|scope| scope.as_str().to_string())
        .collect();
    let suggested_command = scopes
        .first()
        .map(|scope| suggested_unlock_command(scope.as_str(), UnlockTargetKind::Project, &[]));
    approval_required_error(message, requested_scopes, project_root, suggested_command)
}

fn ensure_project_policy_candidate_authorized(
    project_dir: &Path,
    current: &ApprovedProjectPolicyState,
    json_output: bool,
    source: ApprovalSource,
) -> Result<(), LpmError> {
    let approved = load_approved_project_policy_state(project_dir)?;
    let required_scopes = project_policy_required_scopes(current, &approved);
    if required_scopes.is_empty() {
        if !same_project_policy_shape(current, &approved) {
            persist_project_policy_state(project_dir, current)?;
        }
        return Ok(());
    }

    let mut missing_scopes = Vec::new();
    for scope in &required_scopes {
        if !has_active_project_unlock(*scope, project_dir, None, &[])? {
            missing_scopes.push(*scope);
        }
    }
    if !missing_scopes.is_empty() {
        let message =
            "project trust or capability state changed outside an LPM-managed approval flow";
        record_audit_event(
            AuditRecord::new(
                "guarded-attempt",
                false,
                missing_scopes
                    .iter()
                    .map(|scope| scope.as_str().to_string())
                    .collect(),
            )
            .project_root(canonical_project_root(project_dir))
            .source(source)
            .detail(message),
        );
        if matches!(source, ApprovalSource::CliFlag) && !is_automation(json_output) {
            for scope in &missing_scopes {
                prompt_for_unlock(
                    *scope,
                    project_dir,
                    DEFAULT_UNLOCK_TTL_SECS,
                    None,
                    &[],
                    message,
                )?;
            }
        } else {
            return Err(approval_required_for_scopes(
                message,
                &missing_scopes,
                Some(canonical_project_root(project_dir)),
            ));
        }
    }

    persist_project_policy_state(project_dir, current)?;
    record_audit_event(
        AuditRecord::new(
            "project-policy-authorized",
            true,
            required_scopes
                .iter()
                .map(|scope| scope.as_str().to_string())
                .collect(),
        )
        .project_root(canonical_project_root(project_dir))
        .source(source)
        .detail("persisted approved project trust/capability state"),
    );
    Ok(())
}

pub fn ensure_project_policy_authorized(
    project_dir: &Path,
    json_output: bool,
    source: ApprovalSource,
) -> Result<(), LpmError> {
    let current = current_project_policy_state(project_dir)?;
    ensure_project_policy_candidate_authorized(project_dir, &current, json_output, source)
}

pub fn ensure_project_trust_candidate_authorized(
    project_dir: &Path,
    trusted: &lpm_workspace::TrustedDependencies,
    json_output: bool,
    source: ApprovalSource,
) -> Result<(), LpmError> {
    let current = candidate_project_policy_state(project_dir, trusted)?;
    ensure_project_policy_candidate_authorized(project_dir, &current, json_output, source)
}

pub(crate) fn record_project_trust_candidate_authorized_from_managed_flow(
    project_dir: &Path,
    trusted: &lpm_workspace::TrustedDependencies,
    source: ApprovalSource,
) -> Result<(), LpmError> {
    let current = candidate_project_policy_state(project_dir, trusted)?;
    let approved = load_approved_project_policy_state(project_dir)?;
    let required_scopes = project_policy_required_scopes(&current, &approved);

    persist_project_policy_state(project_dir, &current)?;
    record_audit_event(
        AuditRecord::new(
            "project-policy-authorized",
            true,
            required_scopes
                .iter()
                .map(|scope| scope.as_str().to_string())
                .collect(),
        )
        .project_root(canonical_project_root(project_dir))
        .source(source)
        .detail("persisted approved project trust/capability state from managed approval flow"),
    );
    Ok(())
}

pub fn ensure_global_trust_authorized(
    root: &lpm_common::LpmRoot,
    json_output: bool,
    source: ApprovalSource,
) -> Result<(), LpmError> {
    let current = current_global_trust_state(root)?;
    ensure_global_trust_candidate_authorized(&current, json_output, source)
}

fn ensure_global_trust_candidate_authorized(
    current: &ApprovedGlobalTrustState,
    json_output: bool,
    source: ApprovalSource,
) -> Result<(), LpmError> {
    let approved = load_approved_global_trust_state()?;
    if !global_trust_widened(
        &current.trusted_dependencies,
        &approved.trusted_dependencies,
    ) {
        if !same_global_trust_shape(current, &approved) {
            persist_global_trust_state(current)?;
        }
        return Ok(());
    }

    ensure_global_unlock(
        ApprovalScope::TrustBulkApprove,
        json_output,
        source,
        "global trust approvals changed outside an LPM-managed approval flow",
        &[],
    )?;
    persist_global_trust_state(current)?;
    record_audit_event(
        AuditRecord::new(
            "global-trust-authorized",
            true,
            vec![ApprovalScope::TrustBulkApprove.as_str().to_string()],
        )
        .source(source)
        .detail("persisted approved global trust state"),
    );
    Ok(())
}

pub fn ensure_global_trust_candidate_authorized_from_trust(
    root: &lpm_common::LpmRoot,
    trust: &lpm_global::GlobalTrustedDependencies,
    json_output: bool,
    source: ApprovalSource,
) -> Result<(), LpmError> {
    let current = candidate_global_trust_state(trust);
    let _ = root;
    ensure_global_trust_candidate_authorized(&current, json_output, source)
}

fn confirm_persistent_weakening(
    scope: ApprovalScope,
    json_output: bool,
    command_hint: &str,
    message: &str,
) -> Result<(), LpmError> {
    if is_automation(json_output) {
        record_persistent_guarded_attempt(scope, false, message);
        return Err(approval_required_error(
            message,
            vec![scope.as_str().to_string()],
            None,
            Some(command_hint.to_string()),
        ));
    }

    crate::output::warn(message);
    let confirmed =
        request_native_approval("Approve this persistent machine-level security change now?")?;
    if !confirmed {
        record_persistent_guarded_attempt(scope, false, message);
        return Err(approval_required_error(
            message,
            vec![scope.as_str().to_string()],
            None,
            Some(command_hint.to_string()),
        ));
    }
    record_persistent_guarded_attempt(scope, true, message);
    Ok(())
}

fn record_persistent_guarded_attempt(scope: ApprovalScope, allowed: bool, detail: &str) {
    record_audit_event(
        AuditRecord::new(
            "persistent-guarded-attempt",
            allowed,
            vec![scope.as_str().to_string()],
        )
        .source(ApprovalSource::ConfigMutation)
        .detail(detail),
    );
}

fn approval_scope_for_script_policy(requested: ScriptPolicy) -> ApprovalScope {
    match requested {
        ScriptPolicy::Allow => ApprovalScope::ScriptsAllow,
        ScriptPolicy::Triage | ScriptPolicy::Deny => ApprovalScope::ScriptsTriage,
    }
}

fn approval_scope_for_sandbox_mode(requested: ResolvedSandboxMode) -> ApprovalScope {
    match requested {
        ResolvedSandboxMode::None => ApprovalScope::SandboxNone,
        ResolvedSandboxMode::Default | ResolvedSandboxMode::Strict => ApprovalScope::SandboxDefault,
    }
}

pub fn authorize_persistent_script_policy(
    requested: ScriptPolicy,
    json_output: bool,
    command_hint: &str,
) -> Result<(), LpmError> {
    let effective = load_effective_authorized_posture()?;
    let current = effective.posture.script_policy();
    let weakens_current = requested.loosens(current);
    if requested.loosens(current)
        && matches!(
            effective.sources.script_policy,
            PostureSourceKind::ManagedPolicy
        )
    {
        let managed_policy = effective
            .managed_policy
            .as_ref()
            .expect("managed policy source must include status metadata");
        let err = managed_policy_write_error(
            managed_policy,
            "script-policy",
            requested.as_str(),
            current.as_str(),
        );
        record_persistent_guarded_attempt(
            approval_scope_for_script_policy(requested),
            false,
            &err.to_string(),
        );
        return Err(err);
    }

    let mut posture = load_authorized_posture()?;
    if weakens_current {
        confirm_persistent_weakening(
            approval_scope_for_script_policy(requested),
            json_output,
            command_hint,
            &format!(
                "Persisting `script-policy = {}` weakens the approved machine posture.",
                requested.as_str()
            ),
        )?;
    } else if !matches!(
        effective.approved_posture_source,
        PostureSourceKind::ApprovedStore
    ) {
        return Ok(());
    } else {
        let approved = posture.script_policy();
        if requested == approved || requested.loosens(approved) {
            return Ok(());
        }
    }
    posture.script_policy = requested.as_str().to_string();
    persist_authorized_posture(&posture)
}

pub fn authorize_persistent_release_age(
    requested_secs: u64,
    json_output: bool,
    command_hint: &str,
) -> Result<(), LpmError> {
    let effective = load_effective_authorized_posture()?;
    let current = effective.posture.minimum_release_age_secs();
    let weakens_current = requested_secs < current;
    if requested_secs < current
        && matches!(
            effective.sources.minimum_release_age_secs,
            PostureSourceKind::ManagedPolicy
        )
    {
        let managed_policy = effective
            .managed_policy
            .as_ref()
            .expect("managed policy source must include status metadata");
        let err = managed_policy_write_error(
            managed_policy,
            "minimum-release-age-secs",
            requested_secs.to_string(),
            current.to_string(),
        );
        record_persistent_guarded_attempt(ApprovalScope::CooldownBypass, false, &err.to_string());
        return Err(err);
    }

    let mut posture = load_authorized_posture()?;
    if weakens_current {
        confirm_persistent_weakening(
            ApprovalScope::CooldownBypass,
            json_output,
            command_hint,
            &format!(
                "Persisting `minimum-release-age-secs = {requested_secs}` weakens the approved machine posture."
            ),
        )?;
    } else if !matches!(
        effective.approved_posture_source,
        PostureSourceKind::ApprovedStore
    ) {
        return Ok(());
    } else {
        let approved = posture.minimum_release_age_secs();
        if requested_secs <= approved {
            return Ok(());
        }
    }
    posture.minimum_release_age_secs = requested_secs;
    persist_authorized_posture(&posture)
}

pub fn authorize_persistent_release_age_policy(
    requested: ReleaseAgePolicy,
    json_output: bool,
    command_hint: &str,
) -> Result<(), LpmError> {
    let effective = load_effective_authorized_posture()?;
    let current = effective.posture.release_age_policy();
    let weakens_current = requested.loosens(current);
    if weakens_current
        && matches!(
            effective.sources.release_age_policy,
            PostureSourceKind::ManagedPolicy
        )
    {
        let managed_policy = effective
            .managed_policy
            .as_ref()
            .expect("managed policy source must include status metadata");
        let err = managed_policy_write_error(
            managed_policy,
            crate::release_age_config::GLOBAL_POLICY_KEY,
            requested.as_str(),
            current.as_str(),
        );
        record_persistent_guarded_attempt(ApprovalScope::CooldownWindow, false, &err.to_string());
        return Err(err);
    }

    let mut posture = load_authorized_posture()?;
    if weakens_current {
        confirm_persistent_weakening(
            ApprovalScope::CooldownWindow,
            json_output,
            command_hint,
            &format!(
                "Persisting `release-age-policy = {}` weakens the approved machine posture.",
                requested.as_str()
            ),
        )?;
    } else if !matches!(
        effective.approved_posture_source,
        PostureSourceKind::ApprovedStore
    ) && requested == current
    {
        return Ok(());
    } else {
        let approved = posture.release_age_policy();
        if requested == approved || requested.loosens(approved) {
            return Ok(());
        }
    }
    posture.release_age_policy = requested.as_str().to_string();
    persist_authorized_posture(&posture)
}

pub fn authorize_persistent_sandbox_mode(
    requested: ResolvedSandboxMode,
    json_output: bool,
    command_hint: &str,
) -> Result<(), LpmError> {
    let effective = load_effective_authorized_posture()?;
    let current = effective.posture.sandbox_mode();
    let weakens_current = requested.loosens(current);
    if requested.loosens(current)
        && matches!(
            effective.sources.sandbox_mode,
            PostureSourceKind::ManagedPolicy
        )
    {
        let managed_policy = effective
            .managed_policy
            .as_ref()
            .expect("managed policy source must include status metadata");
        let err = managed_policy_write_error(
            managed_policy,
            "[sandbox].mode",
            requested.as_str(),
            current.as_str(),
        );
        record_persistent_guarded_attempt(
            approval_scope_for_sandbox_mode(requested),
            false,
            &err.to_string(),
        );
        return Err(err);
    }

    let mut posture = load_authorized_posture()?;
    if weakens_current {
        confirm_persistent_weakening(
            approval_scope_for_sandbox_mode(requested),
            json_output,
            command_hint,
            &format!(
                "Persisting `[sandbox] mode = \"{}\"` weakens the approved machine posture.",
                requested.as_str()
            ),
        )?;
    } else if !matches!(
        effective.approved_posture_source,
        PostureSourceKind::ApprovedStore
    ) {
        return Ok(());
    } else {
        let approved = posture.sandbox_mode();
        if requested == approved || requested.loosens(approved) {
            return Ok(());
        }
    }
    posture.sandbox_mode = requested.as_str().to_string();
    persist_authorized_posture(&posture)
}

pub fn authorize_persistent_sigstore(
    requested: EnforceMode,
    json_output: bool,
    command_hint: &str,
) -> Result<(), LpmError> {
    let effective = load_effective_authorized_posture()?;
    let current = effective.posture.sigstore_verify();
    let weakens_current = crate::security_floor::sigstore_loosens(requested, current);
    if weakens_current
        && matches!(
            effective.sources.sigstore_verify,
            PostureSourceKind::ManagedPolicy
        )
    {
        let managed_policy = effective
            .managed_policy
            .as_ref()
            .expect("managed policy source must include status metadata");
        let err = managed_policy_write_error(
            managed_policy,
            "[sigstore].verify",
            crate::security_floor::sigstore_mode_name(requested),
            crate::security_floor::sigstore_mode_name(current),
        );
        record_persistent_guarded_attempt(
            ApprovalScope::ProvenanceUnverified,
            false,
            &err.to_string(),
        );
        return Err(err);
    }

    let mut posture = load_authorized_posture()?;
    if weakens_current {
        confirm_persistent_weakening(
            ApprovalScope::ProvenanceUnverified,
            json_output,
            command_hint,
            &format!(
                "Persisting `[sigstore] verify = \"{}\"` weakens the approved machine posture.",
                crate::security_floor::sigstore_mode_name(requested)
            ),
        )?;
    } else if !matches!(
        effective.approved_posture_source,
        PostureSourceKind::ApprovedStore
    ) {
        return Ok(());
    } else {
        let approved = posture.sigstore_verify();
        if requested == approved || crate::security_floor::sigstore_loosens(requested, approved) {
            return Ok(());
        }
    }
    posture.sigstore_verify = crate::security_floor::sigstore_mode_name(requested).to_string();
    persist_authorized_posture(&posture)
}

pub fn ensure_runtime_sigstore_posture(
    project_dir: &Path,
    json_output: bool,
    requested: EnforceMode,
    source: crate::provenance_fetch::EnforceModeSource,
) -> Result<(), LpmError> {
    let effective = load_effective_authorized_posture()?;
    let approved = effective.posture.sigstore_verify();
    if !crate::security_floor::sigstore_loosens(requested, approved) {
        return Ok(());
    }
    if matches!(
        source,
        crate::provenance_fetch::EnforceModeSource::Env
            | crate::provenance_fetch::EnforceModeSource::Config
    ) {
        if let Some(err) =
            managed_policy_blocks_scope(&effective, ApprovalScope::ProvenanceUnverified)
        {
            record_audit_event(
                AuditRecord::new(
                    "guarded-attempt",
                    false,
                    vec![ApprovalScope::ProvenanceUnverified.as_str().to_string()],
                )
                .project_root(canonical_project_root(project_dir))
                .source(approval_source_for_enforce_source(source))
                .detail(
                    "runtime Sigstore verification posture is weaker than managed policy"
                        .to_string(),
                ),
            );
            return Err(err);
        }
        ensure_project_unlock(
            ApprovalScope::ProvenanceUnverified,
            project_dir,
            json_output,
            approval_source_for_enforce_source(source),
            match source {
                crate::provenance_fetch::EnforceModeSource::Env => {
                    "This command weakens Sigstore verification via LPM_PROVENANCE_ENFORCE for this project."
                }
                crate::provenance_fetch::EnforceModeSource::Config => {
                    "The persisted global [sigstore].verify setting weakens Sigstore verification for this project."
                }
                crate::provenance_fetch::EnforceModeSource::Default => unreachable!(),
            },
            None,
            &[],
        )?;
    }
    Ok(())
}

pub fn ensure_runtime_sigstore_posture_for_global(
    json_output: bool,
    requested: EnforceMode,
    source: crate::provenance_fetch::EnforceModeSource,
) -> Result<(), LpmError> {
    let effective = load_effective_authorized_posture()?;
    let approved = effective.posture.sigstore_verify();
    if !crate::security_floor::sigstore_loosens(requested, approved) {
        return Ok(());
    }
    if matches!(
        source,
        crate::provenance_fetch::EnforceModeSource::Env
            | crate::provenance_fetch::EnforceModeSource::Config
    ) {
        if let Some(err) =
            managed_policy_blocks_scope(&effective, ApprovalScope::ProvenanceUnverified)
        {
            record_audit_event(
                AuditRecord::new(
                    "guarded-attempt",
                    false,
                    vec![ApprovalScope::ProvenanceUnverified.as_str().to_string()],
                )
                .source(approval_source_for_enforce_source(source))
                .detail(
                    "runtime Sigstore verification posture is weaker than managed policy"
                        .to_string(),
                ),
            );
            return Err(err);
        }
        ensure_global_unlock(
            ApprovalScope::ProvenanceUnverified,
            json_output,
            approval_source_for_enforce_source(source),
            match source {
                crate::provenance_fetch::EnforceModeSource::Env => {
                    "This command weakens Sigstore verification via LPM_PROVENANCE_ENFORCE globally."
                }
                crate::provenance_fetch::EnforceModeSource::Config => {
                    "The persisted global [sigstore].verify setting weakens Sigstore verification globally."
                }
                crate::provenance_fetch::EnforceModeSource::Default => unreachable!(),
            },
            &[],
        )?;
    }
    Ok(())
}
