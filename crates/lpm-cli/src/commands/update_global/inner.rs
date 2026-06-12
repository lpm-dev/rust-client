use super::super::global_util::{
    InnerGlobalInstallOptions, SyntheticProjectJsonFormat, run_inner_global_install,
};
use super::prepare::{StagedUpgrade, UpgradePrep};
use lpm_common::LpmError;
use lpm_registry::RegistryClient;

pub(super) async fn do_install_upgrade(
    registry: &RegistryClient,
    prep: &UpgradePrep,
    staged: &StagedUpgrade,
    suppress_nested_output: bool,
) -> Result<(), LpmError> {
    let new_version = prep.new_version.to_string();
    run_inner_global_install(
        registry,
        InnerGlobalInstallOptions {
            install_root: &staged.install_root,
            package_name: &prep.name,
            package_version: &new_version,
            synthetic_project_scope: "@lpm-global-upgrade",
            trust_root: None,
            json_format: SyntheticProjectJsonFormat::Compact,
            suppress_nested_output,
            allow_new: false,
            strict_peer_dependencies_override: None,
            auto_build: false,
            script_policy_override: None,
            min_release_age_override: None,
            drift_ignore_policy: crate::provenance_fetch::DriftIgnorePolicy::default(),
            verify_policy: crate::provenance_fetch::VerifyPolicy::resolve_no_cli(),
        },
    )
    .await
}
