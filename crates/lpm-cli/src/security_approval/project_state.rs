use super::prelude::*;

fn project_policy_state_path(project_dir: &Path) -> Result<PathBuf, LpmError> {
    let root = canonical_project_root(project_dir);
    let id = hex::encode(Sha256::digest(root.as_bytes()));
    Ok(approved_projects_dir()?.join(format!("{id}.json")))
}

fn read_project_trusted_dependencies(
    project_dir: &Path,
) -> Result<lpm_workspace::TrustedDependencies, LpmError> {
    let pkg_json_path = project_dir.join("package.json");
    if !pkg_json_path.exists() {
        return Ok(lpm_workspace::TrustedDependencies::default());
    }
    let pkg = lpm_workspace::read_package_json(&pkg_json_path)
        .map_err(|e| LpmError::Registry(format!("failed to read package.json: {e}")))?;
    Ok(pkg
        .lpm
        .map(|lpm| lpm.trusted_dependencies)
        .unwrap_or_default())
}

fn trusted_dependencies_snapshot(
    trusted: &lpm_workspace::TrustedDependencies,
) -> BTreeMap<String, crate::trust_snapshot::SnapshotEntry> {
    crate::trust_snapshot::TrustSnapshot::capture_current(trusted).bindings
}

fn current_trusted_scopes(project_dir: &Path) -> Result<BTreeSet<String>, LpmError> {
    Ok(
        crate::script_policy_config::ScriptPolicyConfig::try_from_package_json(project_dir)?
            .trusted_scopes
            .into_iter()
            .collect(),
    )
}

pub fn authorized_capability_user_bound() -> crate::capability::UserBound {
    // Raw `[sandbox.limits]` in `~/.lpm/config.toml` is only a proposal layer.
    // Until LPM has an authenticated write path for capability ceilings, runtime
    // capability enforcement must fail closed rather than trust hand-edited user config.
    crate::capability::UserBound::default()
}

fn current_capability_request_hash(project_dir: &Path) -> Result<Option<String>, LpmError> {
    let user_bound = authorized_capability_user_bound();
    let capability_set =
        crate::capability::CapabilitySet::from_package_json(&project_dir.join("package.json"))
            .map_err(|e| LpmError::Registry(format!("{e}")))?;
    Ok(if capability_set.loosens_beyond(&user_bound) {
        Some(capability_set.canonical_hash())
    } else {
        None
    })
}

pub(super) fn current_project_policy_state(
    project_dir: &Path,
) -> Result<ApprovedProjectPolicyState, LpmError> {
    let trusted = read_project_trusted_dependencies(project_dir)?;
    candidate_project_policy_state(project_dir, &trusted)
}

pub(super) fn candidate_project_policy_state(
    project_dir: &Path,
    trusted: &lpm_workspace::TrustedDependencies,
) -> Result<ApprovedProjectPolicyState, LpmError> {
    let mut trusted_scopes: Vec<_> = current_trusted_scopes(project_dir)?.into_iter().collect();
    trusted_scopes.sort();
    Ok(ApprovedProjectPolicyState {
        schema_version: APPROVED_PROJECT_STATE_SCHEMA_VERSION,
        updated_at: Utc::now(),
        project_root: canonical_project_root(project_dir),
        trusted_dependencies: trusted_dependencies_snapshot(trusted),
        trusted_scopes,
        capability_request_hash: current_capability_request_hash(project_dir)?,
    })
}

pub(super) fn load_approved_project_policy_state(
    project_dir: &Path,
) -> Result<ApprovedProjectPolicyState, LpmError> {
    Ok(
        read_signed_json(&project_policy_state_path(project_dir)?)?.unwrap_or_else(|| {
            ApprovedProjectPolicyState {
                schema_version: APPROVED_PROJECT_STATE_SCHEMA_VERSION,
                updated_at: Utc::now(),
                project_root: canonical_project_root(project_dir),
                trusted_dependencies: BTreeMap::new(),
                trusted_scopes: Vec::new(),
                capability_request_hash: None,
            }
        }),
    )
}

pub(super) fn persist_project_policy_state(
    project_dir: &Path,
    state: &ApprovedProjectPolicyState,
) -> Result<(), LpmError> {
    let mut normalized = state.clone();
    normalized.schema_version = APPROVED_PROJECT_STATE_SCHEMA_VERSION;
    normalized.updated_at = Utc::now();
    normalized.project_root = canonical_project_root(project_dir);
    normalized.trusted_scopes.sort();
    normalized.trusted_scopes.dedup();
    write_signed_json(&project_policy_state_path(project_dir)?, &normalized)
}

pub(super) fn current_global_trust_state(
    root: &lpm_common::LpmRoot,
) -> Result<ApprovedGlobalTrustState, LpmError> {
    let trust = lpm_global::trusted_deps::read_for(root)?;
    Ok(candidate_global_trust_state(&trust))
}

pub(super) fn candidate_global_trust_state(
    trust: &lpm_global::GlobalTrustedDependencies,
) -> ApprovedGlobalTrustState {
    ApprovedGlobalTrustState {
        schema_version: APPROVED_GLOBAL_TRUST_STATE_SCHEMA_VERSION,
        updated_at: Utc::now(),
        trusted_dependencies: trust.trusted.clone(),
    }
}

pub(super) fn load_approved_global_trust_state() -> Result<ApprovedGlobalTrustState, LpmError> {
    Ok(
        read_signed_json(&approved_global_trust_path()?)?.unwrap_or(ApprovedGlobalTrustState {
            schema_version: APPROVED_GLOBAL_TRUST_STATE_SCHEMA_VERSION,
            updated_at: Utc::now(),
            trusted_dependencies: BTreeMap::new(),
        }),
    )
}

pub(super) fn persist_global_trust_state(state: &ApprovedGlobalTrustState) -> Result<(), LpmError> {
    let mut normalized = state.clone();
    normalized.schema_version = APPROVED_GLOBAL_TRUST_STATE_SCHEMA_VERSION;
    normalized.updated_at = Utc::now();
    write_signed_json(&approved_global_trust_path()?, &normalized)
}

fn trusted_dependencies_widened(
    current: &BTreeMap<String, crate::trust_snapshot::SnapshotEntry>,
    approved: &BTreeMap<String, crate::trust_snapshot::SnapshotEntry>,
) -> bool {
    current
        .iter()
        .any(|(key, value)| approved.get(key) != Some(value))
}

fn trusted_scopes_widened(current: &[String], approved: &[String]) -> bool {
    let approved_set: BTreeSet<_> = approved.iter().map(String::as_str).collect();
    current
        .iter()
        .any(|scope| !approved_set.contains(scope.as_str()))
}

fn capability_request_widened(current: Option<&String>, approved: Option<&String>) -> bool {
    match current {
        Some(hash) => approved != Some(hash),
        None => false,
    }
}

pub(super) fn project_policy_required_scopes(
    current: &ApprovedProjectPolicyState,
    approved: &ApprovedProjectPolicyState,
) -> Vec<ApprovalScope> {
    let mut scopes = Vec::new();
    if trusted_dependencies_widened(
        &current.trusted_dependencies,
        &approved.trusted_dependencies,
    ) {
        scopes.push(ApprovalScope::TrustBulkApprove);
    }
    if trusted_scopes_widened(&current.trusted_scopes, &approved.trusted_scopes) {
        scopes.push(ApprovalScope::TrustScopeWiden);
    }
    if capability_request_widened(
        current.capability_request_hash.as_ref(),
        approved.capability_request_hash.as_ref(),
    ) {
        scopes.push(ApprovalScope::CapabilityWiden);
    }
    scopes
}

pub(super) fn same_project_policy_shape(
    current: &ApprovedProjectPolicyState,
    approved: &ApprovedProjectPolicyState,
) -> bool {
    current.project_root == approved.project_root
        && current.trusted_dependencies == approved.trusted_dependencies
        && current.trusted_scopes == approved.trusted_scopes
        && current.capability_request_hash == approved.capability_request_hash
}

pub(super) fn global_trust_widened(
    current: &BTreeMap<String, lpm_global::TrustedDependencyBinding>,
    approved: &BTreeMap<String, lpm_global::TrustedDependencyBinding>,
) -> bool {
    current
        .iter()
        .any(|(key, value)| approved.get(key) != Some(value))
}

pub(super) fn unlock_grant_covers_packages(grant: &UnlockGrant, packages: &[String]) -> bool {
    let requested_packages = normalized_packages(packages);
    match (grant.packages.is_empty(), requested_packages.is_empty()) {
        (true, _) => true,
        (false, true) => false,
        (false, false) => {
            let granted: BTreeSet<_> = grant.packages.iter().map(String::as_str).collect();
            requested_packages
                .iter()
                .all(|package| granted.contains(package.as_str()))
        }
    }
}

pub(super) fn same_global_trust_shape(
    current: &ApprovedGlobalTrustState,
    approved: &ApprovedGlobalTrustState,
) -> bool {
    current.trusted_dependencies == approved.trusted_dependencies
}
