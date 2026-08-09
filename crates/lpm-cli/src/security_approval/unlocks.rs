use super::prelude::*;

pub(super) fn create_unlock_grant_for_scopes(
    scopes: &[ApprovalScope],
    project_dir: &Path,
    ttl_secs: u64,
    min_release_age_secs: Option<u64>,
    packages: &[String],
) -> UnlockGrant {
    let now = Utc::now();
    UnlockGrant {
        schema_version: UNLOCK_SCHEMA_VERSION,
        id: format!("unl_{}", now.timestamp_nanos_opt().unwrap_or_default()),
        target: UnlockTargetKind::Project,
        project_root: Some(canonical_project_root(project_dir)),
        scopes: normalized_scopes(scopes),
        packages: normalized_packages(packages),
        limits: UnlockLimits {
            min_release_age_secs,
        },
        issued_at: now,
        expires_at: now + chrono::Duration::seconds(ttl_secs as i64),
        issuer: "user-presence".to_string(),
    }
}

pub(super) fn create_unlock_grant(
    scope: ApprovalScope,
    project_dir: &Path,
    ttl_secs: u64,
    min_release_age_secs: Option<u64>,
    packages: &[String],
) -> UnlockGrant {
    create_unlock_grant_for_scopes(
        &[scope],
        project_dir,
        ttl_secs,
        min_release_age_secs,
        packages,
    )
}

pub(super) fn create_global_unlock_grant_for_scopes(
    scopes: &[ApprovalScope],
    ttl_secs: u64,
    packages: &[String],
) -> UnlockGrant {
    let now = Utc::now();
    UnlockGrant {
        schema_version: UNLOCK_SCHEMA_VERSION,
        id: format!("unl_{}", now.timestamp_nanos_opt().unwrap_or_default()),
        target: UnlockTargetKind::Global,
        project_root: None,
        scopes: normalized_scopes(scopes),
        packages: normalized_packages(packages),
        limits: UnlockLimits::default(),
        issued_at: now,
        expires_at: now + chrono::Duration::seconds(ttl_secs as i64),
        issuer: "user-presence".to_string(),
    }
}

pub(super) fn create_global_unlock_grant(
    scope: ApprovalScope,
    ttl_secs: u64,
    packages: &[String],
) -> UnlockGrant {
    create_global_unlock_grant_for_scopes(&[scope], ttl_secs, packages)
}

pub(super) fn persist_unlock_grant(grant: &UnlockGrant) -> Result<(), LpmError> {
    let path = unlocks_dir()?.join(format!("{}.json", grant.id));
    write_signed_json(&path, grant)
}

fn read_active_unlock_entries() -> Result<Vec<StoredUnlockGrant>, LpmError> {
    let dir = unlocks_dir()?;
    if !dir.exists() {
        return Ok(Vec::new());
    }

    let mut grants = Vec::new();
    let now = Utc::now();
    for entry in std::fs::read_dir(&dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
            continue;
        }
        match read_signed_json::<UnlockGrant>(&path) {
            Ok(Some(grant)) if grant.expires_at > now => {
                grants.push(StoredUnlockGrant { path, grant })
            }
            Ok(Some(_expired)) => {
                let _ = std::fs::remove_file(&path);
            }
            Ok(None) => {}
            Err(err) => return Err(err),
        }
    }
    Ok(grants)
}

pub(super) fn read_active_unlocks() -> Result<Vec<UnlockGrant>, LpmError> {
    Ok(read_active_unlock_entries()?
        .into_iter()
        .map(|entry| entry.grant)
        .collect())
}

pub fn list_active_unlocks() -> Result<Vec<UnlockGrant>, LpmError> {
    let mut grants = read_active_unlocks()?;
    grants.sort_by_key(|left| left.expires_at);
    Ok(grants)
}

pub fn list_active_global_unlocks() -> Result<Vec<UnlockGrant>, LpmError> {
    let mut grants: Vec<_> = read_active_unlocks()?
        .into_iter()
        .filter(|grant| grant.target == UnlockTargetKind::Global)
        .collect();
    grants.sort_by_key(|left| left.expires_at);
    Ok(grants)
}

pub fn list_active_project_unlocks(project_dir: &Path) -> Result<Vec<UnlockGrant>, LpmError> {
    let root = canonical_project_root(project_dir);
    let mut grants: Vec<_> = read_active_unlocks()?
        .into_iter()
        .filter(|grant| {
            grant.target == UnlockTargetKind::Project
                && grant.project_root.as_deref() == Some(root.as_str())
        })
        .collect();
    grants.sort_by_key(|left| left.expires_at);
    Ok(grants)
}

fn grant_matches_lock_request(
    grant: &UnlockGrant,
    target: UnlockTargetKind,
    project_root: Option<&str>,
    scopes: &[ApprovalScope],
    packages: &[String],
) -> bool {
    if grant.target != target {
        return false;
    }
    if target == UnlockTargetKind::Project && grant.project_root.as_deref() != project_root {
        return false;
    }
    if !grant.scopes.iter().any(|scope| scopes.contains(scope)) {
        return false;
    }
    packages.is_empty() || grant.packages == packages
}

fn revoke_unlocks(
    selector: &str,
    target: UnlockTargetKind,
    project_root: Option<&Path>,
    scopes: &[ApprovalScope],
    packages: &[String],
    source: ApprovalSource,
) -> Result<Vec<UnlockRevocation>, LpmError> {
    let requested_scopes = normalized_scopes(scopes);
    if requested_scopes.is_empty() {
        return Err(LpmError::Registry(
            "at least one unlock scope is required".into(),
        ));
    }

    let requested_packages = normalized_packages(packages);
    let project_root = project_root.map(canonical_project_root);
    let mut revocations = Vec::new();

    for entry in read_active_unlock_entries()? {
        if !grant_matches_lock_request(
            &entry.grant,
            target,
            project_root.as_deref(),
            &requested_scopes,
            &requested_packages,
        ) {
            continue;
        }

        let revoked_scopes: Vec<_> = entry
            .grant
            .scopes
            .iter()
            .copied()
            .filter(|scope| requested_scopes.contains(scope))
            .collect();
        let remaining_scopes: Vec<_> = entry
            .grant
            .scopes
            .iter()
            .copied()
            .filter(|scope| !requested_scopes.contains(scope))
            .collect();
        let revoked_scopes = normalized_scopes(&revoked_scopes);
        let remaining_scopes = normalized_scopes(&remaining_scopes);

        if remaining_scopes.is_empty() {
            std::fs::remove_file(&entry.path)?;
        } else {
            let mut updated = entry.grant.clone();
            updated.scopes = remaining_scopes.clone();
            write_signed_json(&entry.path, &updated)?;
        }

        let mut audit = AuditRecord::new("unlock-revoked", true, scope_names(&revoked_scopes))
            .packages(entry.grant.packages.clone())
            .source(source)
            .unlock_id(entry.grant.id.clone());
        if let Some(root) = entry.grant.project_root.clone() {
            audit = audit.project_root(root);
        }
        let detail = if remaining_scopes.is_empty() {
            format!("temporary unlock revoked for {selector}")
        } else {
            format!(
                "temporary unlock narrowed for {selector}; remaining scopes: {}",
                format_scope_list(&remaining_scopes)
            )
        };
        record_audit_event(audit.detail(detail));

        revocations.push(UnlockRevocation {
            id: entry.grant.id,
            target: entry.grant.target,
            project_root: entry.grant.project_root,
            revoked_scopes,
            remaining_scopes,
            packages: entry.grant.packages,
            expires_at: entry.grant.expires_at,
        });
    }

    Ok(revocations)
}

pub fn lock_project_scopes_command(
    selector: &str,
    scopes: &[ApprovalScope],
    project_dir: &Path,
    packages: &[String],
) -> Result<Vec<UnlockRevocation>, LpmError> {
    revoke_unlocks(
        selector,
        UnlockTargetKind::Project,
        Some(project_dir),
        scopes,
        packages,
        ApprovalSource::SecurityCommand,
    )
}

pub fn lock_global_scopes_command(
    selector: &str,
    scopes: &[ApprovalScope],
    packages: &[String],
) -> Result<Vec<UnlockRevocation>, LpmError> {
    revoke_unlocks(
        selector,
        UnlockTargetKind::Global,
        None,
        scopes,
        packages,
        ApprovalSource::SecurityCommand,
    )
}

pub(super) fn revoke_project_policy_unlocks(
    selector: &str,
    project_dir: &Path,
    scopes: &[ApprovalScope],
    source: ApprovalSource,
) -> Result<Vec<UnlockRevocation>, LpmError> {
    revoke_unlocks(
        selector,
        UnlockTargetKind::Project,
        Some(project_dir),
        scopes,
        &[],
        source,
    )
}

pub(super) fn find_active_project_unlock(
    scope: ApprovalScope,
    project_dir: &Path,
    min_release_age_secs: Option<u64>,
    packages: &[String],
) -> Result<Option<UnlockGrant>, LpmError> {
    let root = canonical_project_root(project_dir);
    for grant in read_active_unlocks()? {
        if grant.target != UnlockTargetKind::Project {
            continue;
        }
        if grant.project_root.as_deref() != Some(root.as_str()) {
            continue;
        }
        if !grant.scopes.contains(&scope) {
            continue;
        }
        if let Some(requested_secs) = min_release_age_secs
            && let Some(limit) = grant.limits.min_release_age_secs
            && requested_secs < limit
        {
            continue;
        }
        if !unlock_grant_covers_packages(&grant, packages) {
            continue;
        }
        return Ok(Some(grant));
    }
    Ok(None)
}

pub fn has_active_project_unlock(
    scope: ApprovalScope,
    project_dir: &Path,
    min_release_age_secs: Option<u64>,
    packages: &[String],
) -> Result<bool, LpmError> {
    Ok(find_active_project_unlock(scope, project_dir, min_release_age_secs, packages)?.is_some())
}

fn find_active_global_unlock(
    scope: ApprovalScope,
    packages: &[String],
) -> Result<Option<UnlockGrant>, LpmError> {
    for grant in read_active_unlocks()? {
        if grant.target != UnlockTargetKind::Global {
            continue;
        }
        if !grant.scopes.contains(&scope) {
            continue;
        }
        if !unlock_grant_covers_packages(&grant, packages) {
            continue;
        }
        return Ok(Some(grant));
    }
    Ok(None)
}

pub(super) fn prompt_for_unlock(
    scope: ApprovalScope,
    project_dir: &Path,
    ttl_secs: u64,
    min_release_age_secs: Option<u64>,
    packages: &[String],
    message: &str,
) -> Result<(), LpmError> {
    crate::output::warn(message);
    let prompt = format!(
        "Approve {} for this project for {}?",
        scope.as_str(),
        format_unlock_duration(ttl_secs),
    );
    let confirmed = request_native_approval(&prompt)?;

    if !confirmed {
        record_audit_event(
            AuditRecord::new("guarded-attempt", false, vec![scope.as_str().to_string()])
                .project_root(canonical_project_root(project_dir))
                .packages(packages.to_vec())
                .source(ApprovalSource::CliFlag)
                .detail(format!("user declined {}", scope.as_str())),
        );
        return Err(approval_required_error(
            format!("{} requires explicit approval", scope.as_str()),
            vec![scope.as_str().to_string()],
            Some(canonical_project_root(project_dir)),
            Some(suggested_unlock_command(
                scope.as_str(),
                UnlockTargetKind::Project,
                packages,
            )),
        ));
    }

    let grant = create_unlock_grant(scope, project_dir, ttl_secs, min_release_age_secs, packages);
    persist_unlock_grant(&grant)?;
    record_audit_event(
        AuditRecord::new("unlock-granted", true, vec![scope.as_str().to_string()])
            .project_root(canonical_project_root(project_dir))
            .packages(packages.to_vec())
            .source(ApprovalSource::CliFlag)
            .unlock_id(grant.id)
            .detail(format!("temporary unlock granted for {}", scope.as_str())),
    );
    crate::output::success(&format!(
        "Approved {} for this project for {}.",
        scope.as_str(),
        format_unlock_duration(ttl_secs),
    ));
    Ok(())
}

pub fn approve_project_runtime_override(
    scope: ApprovalScope,
    project_dir: &Path,
    json_output: bool,
    source: ApprovalSource,
    message: &str,
    packages: &[String],
) -> Result<(), LpmError> {
    if let Some(policy) = load_managed_policy()?
        && let Some(err) = managed_policy_blocks_scope_direct(&policy, scope)
    {
        return Err(err);
    }

    let target = if project_dir_is_global_install(project_dir) {
        UnlockTargetKind::Global
    } else {
        UnlockTargetKind::Project
    };

    if !matches!(source, ApprovalSource::CliFlag | ApprovalSource::EnvVar)
        || is_automation(json_output)
    {
        return Err(runtime_override_approval_required(
            scope,
            target,
            project_dir,
            packages,
        ));
    }

    crate::output::warn(message);
    let prompt = if target == UnlockTargetKind::Global {
        format!("Approve {} for this global install?", scope.as_str())
    } else {
        format!("Approve {} for this install?", scope.as_str())
    };
    let confirmed = request_native_approval(&prompt)?;
    if !confirmed {
        return Err(runtime_override_approval_required(
            scope,
            target,
            project_dir,
            packages,
        ));
    }

    let target_label = if target == UnlockTargetKind::Global {
        "this global install"
    } else {
        "this install"
    };
    crate::output::success(&format!("Approved {} for {target_label}.", scope.as_str(),));
    Ok(())
}

fn runtime_override_approval_required(
    scope: ApprovalScope,
    target: UnlockTargetKind,
    project_dir: &Path,
    packages: &[String],
) -> LpmError {
    let project_root = if target == UnlockTargetKind::Global {
        None
    } else {
        Some(canonical_project_root(project_dir))
    };
    approval_required_error(
        format!("{} requires explicit approval", scope.as_str()),
        vec![scope.as_str().to_string()],
        project_root,
        Some(suggested_unlock_command(scope.as_str(), target, packages)),
    )
}

pub fn ensure_project_unlock(
    scope: ApprovalScope,
    project_dir: &Path,
    json_output: bool,
    source: ApprovalSource,
    message: &str,
    min_release_age_secs: Option<u64>,
    packages: &[String],
) -> Result<(), LpmError> {
    let effective = load_effective_authorized_posture()?;
    if let Some(err) = managed_policy_blocks_scope(&effective, scope) {
        record_audit_event(
            AuditRecord::new("guarded-attempt", false, vec![scope.as_str().to_string()])
                .project_root(canonical_project_root(project_dir))
                .packages(packages.to_vec())
                .source(source)
                .detail(message),
        );
        return Err(err);
    }
    if project_dir_is_global_install(project_dir) {
        return ensure_global_unlock(scope, json_output, source, message, packages);
    }
    if let Some(grant) =
        find_active_project_unlock(scope, project_dir, min_release_age_secs, packages)?
    {
        record_audit_event(
            AuditRecord::new("guarded-attempt", true, vec![scope.as_str().to_string()])
                .project_root(canonical_project_root(project_dir))
                .packages(packages.to_vec())
                .source(source)
                .unlock_id(grant.id)
                .detail(message),
        );
        return Ok(());
    }

    if matches!(source, ApprovalSource::CliFlag | ApprovalSource::EnvVar)
        && !is_automation(json_output)
    {
        return prompt_for_unlock(
            scope,
            project_dir,
            DEFAULT_UNLOCK_TTL_SECS,
            min_release_age_secs,
            packages,
            message,
        );
    }

    record_audit_event(
        AuditRecord::new("guarded-attempt", false, vec![scope.as_str().to_string()])
            .project_root(canonical_project_root(project_dir))
            .packages(packages.to_vec())
            .source(source)
            .detail(message),
    );
    Err(approval_required_error(
        format!("{} requires explicit approval", scope.as_str()),
        vec![scope.as_str().to_string()],
        Some(canonical_project_root(project_dir)),
        Some(suggested_unlock_command(
            scope.as_str(),
            UnlockTargetKind::Project,
            packages,
        )),
    ))
}

fn prompt_for_global_unlock(
    scope: ApprovalScope,
    ttl_secs: u64,
    packages: &[String],
    message: &str,
) -> Result<(), LpmError> {
    crate::output::warn(message);
    let prompt = format!(
        "Approve {} globally for {}?",
        scope.as_str(),
        format_unlock_duration(ttl_secs),
    );
    let confirmed = request_native_approval(&prompt)?;

    if !confirmed {
        record_audit_event(
            AuditRecord::new("guarded-attempt", false, vec![scope.as_str().to_string()])
                .packages(packages.to_vec())
                .source(ApprovalSource::CliFlag)
                .detail(format!("user declined {}", scope.as_str())),
        );
        return Err(approval_required_error(
            format!("{} requires explicit approval", scope.as_str()),
            vec![scope.as_str().to_string()],
            None,
            Some(suggested_unlock_command(
                scope.as_str(),
                UnlockTargetKind::Global,
                packages,
            )),
        ));
    }

    let grant = create_global_unlock_grant(scope, ttl_secs, packages);
    persist_unlock_grant(&grant)?;
    record_audit_event(
        AuditRecord::new("unlock-granted", true, vec![scope.as_str().to_string()])
            .packages(packages.to_vec())
            .source(ApprovalSource::CliFlag)
            .unlock_id(grant.id)
            .detail(format!(
                "temporary global unlock granted for {}",
                scope.as_str()
            )),
    );
    crate::output::success(&format!(
        "Approved {} globally for {}.",
        scope.as_str(),
        format_unlock_duration(ttl_secs),
    ));
    Ok(())
}

pub fn ensure_global_unlock(
    scope: ApprovalScope,
    json_output: bool,
    source: ApprovalSource,
    message: &str,
    packages: &[String],
) -> Result<(), LpmError> {
    let effective = load_effective_authorized_posture()?;
    if let Some(err) = managed_policy_blocks_scope(&effective, scope) {
        record_audit_event(
            AuditRecord::new("guarded-attempt", false, vec![scope.as_str().to_string()])
                .packages(packages.to_vec())
                .source(source)
                .detail(message),
        );
        return Err(err);
    }
    if let Some(grant) = find_active_global_unlock(scope, packages)? {
        record_audit_event(
            AuditRecord::new("guarded-attempt", true, vec![scope.as_str().to_string()])
                .packages(packages.to_vec())
                .source(source)
                .unlock_id(grant.id)
                .detail(message),
        );
        return Ok(());
    }

    if matches!(source, ApprovalSource::CliFlag | ApprovalSource::EnvVar)
        && !is_automation(json_output)
    {
        return prompt_for_global_unlock(scope, DEFAULT_UNLOCK_TTL_SECS, packages, message);
    }

    record_audit_event(
        AuditRecord::new("guarded-attempt", false, vec![scope.as_str().to_string()])
            .packages(packages.to_vec())
            .source(source)
            .detail(message),
    );
    Err(approval_required_error(
        format!("{} requires explicit approval", scope.as_str()),
        vec![scope.as_str().to_string()],
        None,
        Some(suggested_unlock_command(
            scope.as_str(),
            UnlockTargetKind::Global,
            packages,
        )),
    ))
}

pub fn unlock_scopes_command(
    selector: &str,
    scopes: &[ApprovalScope],
    project_dir: &Path,
    ttl_secs: u64,
    json_output: bool,
    min_release_age_secs: Option<u64>,
    packages: &[String],
) -> Result<UnlockGrant, LpmError> {
    let requested_scopes = normalized_scopes(scopes);
    if requested_scopes.is_empty() {
        return Err(LpmError::Registry(
            "at least one unlock scope is required".into(),
        ));
    }
    if !(1..=MAX_UNLOCK_TTL_SECS).contains(&ttl_secs) {
        return Err(LpmError::Registry(format!(
            "unlock ttl must be between 1 and {MAX_UNLOCK_TTL_SECS} seconds"
        )));
    }
    let effective = load_effective_authorized_posture()?;
    for scope in &requested_scopes {
        if let Some(err) = managed_policy_blocks_scope(&effective, *scope) {
            return Err(err);
        }
    }
    if is_automation(json_output) {
        return Err(approval_required_error(
            format!("{selector} requires an interactive approval terminal"),
            scope_names(&requested_scopes),
            Some(canonical_project_root(project_dir)),
            Some(suggested_unlock_command(
                selector,
                UnlockTargetKind::Project,
                packages,
            )),
        ));
    }

    crate::output::warn(&format!(
        "{selector} will be allowed for this project for {} if you approve.",
        format_unlock_duration(ttl_secs),
    ));
    let confirmed = request_native_approval("Approve this temporary security unlock now?")?;
    if !confirmed {
        record_audit_event(
            AuditRecord::new("unlock-granted", false, scope_names(&requested_scopes))
                .project_root(canonical_project_root(project_dir))
                .packages(packages.to_vec())
                .source(ApprovalSource::SecurityCommand)
                .detail(format!("user declined {selector}")),
        );
        return Err(approval_required_error(
            format!("{selector} requires explicit approval"),
            scope_names(&requested_scopes),
            Some(canonical_project_root(project_dir)),
            Some(suggested_unlock_command(
                selector,
                UnlockTargetKind::Project,
                packages,
            )),
        ));
    }
    let grant = create_unlock_grant_for_scopes(
        &requested_scopes,
        project_dir,
        ttl_secs,
        min_release_age_secs,
        packages,
    );
    persist_unlock_grant(&grant)?;
    record_audit_event(
        AuditRecord::new("unlock-granted", true, scope_names(&requested_scopes))
            .project_root(canonical_project_root(project_dir))
            .packages(packages.to_vec())
            .source(ApprovalSource::SecurityCommand)
            .unlock_id(grant.id.clone())
            .detail(format!("temporary unlock granted for {selector}")),
    );
    Ok(grant)
}

pub fn unlock_global_scopes_command(
    selector: &str,
    scopes: &[ApprovalScope],
    ttl_secs: u64,
    json_output: bool,
    packages: &[String],
) -> Result<UnlockGrant, LpmError> {
    let requested_scopes = normalized_scopes(scopes);
    if requested_scopes.is_empty() {
        return Err(LpmError::Registry(
            "at least one unlock scope is required".into(),
        ));
    }
    if !(1..=MAX_UNLOCK_TTL_SECS).contains(&ttl_secs) {
        return Err(LpmError::Registry(format!(
            "unlock ttl must be between 1 and {MAX_UNLOCK_TTL_SECS} seconds"
        )));
    }
    let effective = load_effective_authorized_posture()?;
    for scope in &requested_scopes {
        if let Some(err) = managed_policy_blocks_scope(&effective, *scope) {
            return Err(err);
        }
    }
    if is_automation(json_output) {
        return Err(approval_required_error(
            format!("{selector} requires an interactive approval terminal"),
            scope_names(&requested_scopes),
            None,
            Some(suggested_unlock_command(
                selector,
                UnlockTargetKind::Global,
                packages,
            )),
        ));
    }

    crate::output::warn(&format!(
        "{selector} will be allowed globally for {} if you approve.",
        format_unlock_duration(ttl_secs),
    ));
    let confirmed = request_native_approval("Approve this temporary global security unlock now?")?;
    if !confirmed {
        record_audit_event(
            AuditRecord::new("unlock-granted", false, scope_names(&requested_scopes))
                .packages(packages.to_vec())
                .source(ApprovalSource::SecurityCommand)
                .detail(format!("user declined {selector}")),
        );
        return Err(approval_required_error(
            format!("{selector} requires explicit approval"),
            scope_names(&requested_scopes),
            None,
            Some(suggested_unlock_command(
                selector,
                UnlockTargetKind::Global,
                packages,
            )),
        ));
    }
    let grant = create_global_unlock_grant_for_scopes(&requested_scopes, ttl_secs, packages);
    persist_unlock_grant(&grant)?;
    record_audit_event(
        AuditRecord::new("unlock-granted", true, scope_names(&requested_scopes))
            .packages(packages.to_vec())
            .source(ApprovalSource::SecurityCommand)
            .unlock_id(grant.id.clone())
            .detail(format!("temporary global unlock granted for {selector}")),
    );
    Ok(grant)
}
