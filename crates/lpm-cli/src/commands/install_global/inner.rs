use super::super::global_util::{
    InnerGlobalInstallOptions, SyntheticProjectJsonFormat, run_inner_global_install,
};
use super::prepare::PrepResult;
use lpm_common::{LpmError, LpmRoot};
use lpm_registry::RegistryClient;

/// per-invocation install policy overrides forwarded from `lpm install -g`.
/// Keeps the `do_install` boundary clear as the global command grows
/// flags that need to affect the inner project-shaped install.
#[derive(Debug, Clone, Default)]
pub struct InstallGlobalOverrides {
    pub allow_new: bool,
    pub strict_peer_dependencies_override: Option<bool>,
    pub min_release_age_override: Option<u64>,
    pub min_release_age_exclude: Vec<String>,
    pub drift_ignore_policy: crate::provenance_fetch::DriftIgnorePolicy,
    /// Composed `(EnforceMode, SkipPolicy)` for the install-time
    /// Sigstore verifier. Canonicalized from the
    /// `--unverified-provenance{,-all}` flags +
    /// `LPM_PROVENANCE_ENFORCE` env + `[sigstore] verify` config.
    pub verify_policy: crate::provenance_fetch::VerifyPolicy,
    pub script_policy_override: Option<crate::script_policy_config::ScriptPolicy>,
    pub auto_build: bool,
}

pub(super) async fn do_install(
    root: &LpmRoot,
    registry: &RegistryClient,
    prep: &PrepResult,
    suppress_nested_output: bool,
    overrides: &InstallGlobalOverrides,
) -> Result<(), LpmError> {
    let version = prep.version.to_string();
    run_inner_global_install(
        registry,
        InnerGlobalInstallOptions {
            install_root: &prep.install_root,
            package_name: &prep.name,
            package_version: &version,
            synthetic_project_scope: "@lpm-global",
            trust_root: Some(root),
            json_format: SyntheticProjectJsonFormat::Pretty,
            suppress_nested_output,
            allow_new: overrides.allow_new,
            strict_peer_dependencies_override: overrides.strict_peer_dependencies_override,
            auto_build: overrides.auto_build,
            script_policy_override: overrides.script_policy_override,
            min_release_age_override: overrides.min_release_age_override,
            min_release_age_exclude: &overrides.min_release_age_exclude,
            drift_ignore_policy: overrides.drift_ignore_policy.clone(),
            verify_policy: overrides.verify_policy.clone(),
        },
    )
    .await
}
