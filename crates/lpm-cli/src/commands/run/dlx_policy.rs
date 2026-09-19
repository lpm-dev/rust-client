use super::dlx::DlxOptions;
use crate::commands::config::GlobalConfig;
use crate::security_approval::{self, ApprovalScope, ApprovalSource};
use lpm_common::{CONFIG_FILE_SIZE_CAP_BYTES, LpmError};
use lpm_registry::{RegistryClient, RouteTable};
use sha2::{Digest, Sha256};

pub(super) struct CallerPolicy {
    pub(super) routes: RouteTable,
    pub(super) receipt: Option<String>,
    snapshot: String,
}

impl CallerPolicy {
    pub(super) fn recheck(
        &self,
        client: &RegistryClient,
        project_dir: &std::path::Path,
    ) -> Result<(), LpmError> {
        if caller_snapshot(client, project_dir)? != self.snapshot {
            return Err(LpmError::Script(
                "dlx caller policy or authorization changed while waiting; retry the command"
                    .into(),
            ));
        }
        Ok(())
    }
}

fn caller_snapshot(
    client: &RegistryClient,
    project_dir: &std::path::Path,
) -> Result<String, LpmError> {
    let mut routes = RouteTable::from_env_and_filesystem(project_dir)
        .map_err(|error| LpmError::Registry(format!("npmrc: {error}")))?;
    if let Some(overrides) = client.metadata_route_overrides() {
        routes = routes.with_package_route_overrides(overrides);
    }
    let mut posture =
        serde_json::to_value(security_approval::load_effective_authorized_posture()?)?;
    if let Some(object) = posture
        .get_mut("posture")
        .and_then(serde_json::Value::as_object_mut)
    {
        object.remove("updated_at");
    }
    let inputs = serde_json::json!({
        "manifest": optional_config(&project_dir.join("package.json"))?,
        "toml": optional_config(&project_dir.join("lpm.toml"))?,
        "global": GlobalConfig::load_checked()?.table(),
        "posture": posture,
        "status": security_approval::load_security_status(Some(project_dir), false)?,
        "routing": format!("{:?}", routes.workspace_resolution_key()),
    });
    Ok(hex::encode(Sha256::digest(serde_json::to_vec(&inputs)?)))
}

fn optional_config(path: &std::path::Path) -> Result<Option<String>, LpmError> {
    match lpm_common::read_text_file_capped(path, CONFIG_FILE_SIZE_CAP_BYTES) {
        Ok(text) => Ok(Some(text)),
        Err(lpm_common::BoundedReadError::NotFound { .. }) => Ok(None),
        Err(error) => Err(LpmError::Script(format!(
            "failed to read dlx caller configuration: {error}"
        ))),
    }
}

pub(super) fn authorize(
    client: &RegistryClient,
    project_dir: &std::path::Path,
    options: &DlxOptions<'_>,
) -> Result<CallerPolicy, LpmError> {
    let global = GlobalConfig::load_checked()?;
    let mut routes = RouteTable::from_env_and_filesystem(project_dir)
        .map_err(|error| LpmError::Registry(format!("npmrc: {error}")))?;
    if let Some(overrides) = client.metadata_route_overrides() {
        routes = routes.with_package_route_overrides(overrides);
    }
    security_approval::ensure_project_policy_authorized(
        project_dir,
        options.reserve_stdout,
        ApprovalSource::ProjectConfig,
    )?;
    let release = crate::release_age_config::ReleaseAgeResolver::resolve_config(
        project_dir,
        options.min_release_age_override,
        options.min_release_age_exclude,
        options.reserve_stdout,
    )?;
    if options.allow_new && release.minimum_release_age_secs > 0 {
        security_approval::approve_project_runtime_override(
            ApprovalScope::CooldownBypass,
            project_dir,
            options.reserve_stdout,
            ApprovalSource::CliFlag,
            "This invocation bypasses the minimum release age for this project.",
            &[],
        )?;
    }
    let scripts =
        crate::script_policy_config::ScriptPolicyConfig::try_from_package_json(project_dir)?;
    crate::script_policy_config::resolve_script_policy_with_security(
        project_dir,
        None,
        &scripts,
        options.reserve_stdout,
    )?;
    crate::npm_firewall_config::resolve_runtime_mode(&global, project_dir, options.reserve_stdout)?;
    crate::source_analysis_config::resolve_install_time_source_analysis(
        &global,
        project_dir,
        options.reserve_stdout,
    )?;
    crate::sandbox_config::resolve_sandbox_mode_from_chain(
        project_dir,
        false,
        false,
        options.reserve_stdout,
    )?;
    let (verify, source) = crate::provenance_fetch::EnforceMode::resolve_from_chain(
        std::env::var("LPM_PROVENANCE_ENFORCE").ok().as_deref(),
        || global.get_sigstore_verify(),
    );
    security_approval::ensure_runtime_sigstore_posture(
        project_dir,
        options.reserve_stdout,
        verify,
        source,
    )?;
    let capabilities =
        crate::capability::CapabilitySet::from_project(&project_dir.join("package.json"))
            .map_err(|error| LpmError::Registry(error.to_string()))?;
    let mut posture =
        serde_json::to_value(security_approval::load_effective_authorized_posture()?)?;
    if let Some(object) = posture
        .get_mut("posture")
        .and_then(serde_json::Value::as_object_mut)
    {
        object.remove("updated_at");
    }
    let status = security_approval::load_security_status(Some(project_dir), false)?;
    let environment: std::collections::BTreeMap<_, _> = std::env::vars()
        .filter(|(key, _)| {
            key.starts_with("LPM_") || key.to_ascii_lowercase().starts_with("npm_config_")
        })
        .collect();
    // External policy programs and custom TLS inputs require a fresh installation.
    // A receipt is never an authorization: every invocation checks the live grants above.
    let reusable = global.get_value("policy").is_none()
        && scripts
            .triage_advisor
            .as_deref()
            .is_none_or(|value| value == "none")
        && global
            .get_str("triage-advisor")
            .is_none_or(|value| value == "none");
    let worker_principal = client.routed_cache_identity(
        "@lpm.dev/__dlx_cache_context",
        &lpm_registry::UpstreamRoute::LpmWorker,
    );
    let receipt = routes
        .workspace_resolution_key()
        .filter(|_| reusable && worker_principal.is_some())
        .map(|routing| {
            let inputs = serde_json::json!({
                "schema": 1,
                "cli": env!("CARGO_PKG_VERSION"),
                "project": project_dir,
                "manifest": optional_config(&project_dir.join("package.json"))?,
                "toml": optional_config(&project_dir.join("lpm.toml"))?,
                "global": global.table(),
                "posture": posture,
                "status": status,
                "capabilities": capabilities.canonical_hash(),
                "environment": environment,
                "routing": format!("{routing:?}"),
                "worker_principal": worker_principal,
                "registry": client.base_url(),
                "npm_registry": client.npm_registry_url(),
                "allow_new": options.allow_new,
                "strict_integrity": options.strict_integrity,
                "release_age": release.minimum_release_age_secs,
                "release_policy": release.minimum_release_age_policy.as_str(),
                "exclusions": release.minimum_release_age_exclude,
            });
            Ok::<_, LpmError>(hex::encode(Sha256::digest(serde_json::to_vec(&inputs)?)))
        })
        .transpose()?;
    Ok(CallerPolicy {
        routes,
        receipt,
        snapshot: caller_snapshot(client, project_dir)?,
    })
}
