use std::path::Path;

use lpm_common::LpmError;
use lpm_registry::RegistryClient;

/// Run `lpm install` with doctor-appropriate defaults (no security summary, no JSON output).
pub(super) async fn run_doctor_install(
    client: &RegistryClient,
    project_dir: &Path,
) -> Result<(), LpmError> {
    crate::commands::install::run_with_options(
        client,
        project_dir,
        false, // json_output
        false, // offline
        crate::commands::install::FrozenLockfileMode::Never,
        false, // force
        false, // allow_new
        false, // strict_integrity
        false, // no_engine_strict
        None,  // strict_peer_dependencies_override
        None,  // linker_override
        crate::lpm_skills_config::LpmSkillsPreference::Config,
        false, // no_editor_setup
        true,  // no_security_summary
        false, // auto_build
        None,  // target_set: doctor is single-project
        None,  // direct_versions_out: doctor does not finalize placeholders
        None,  // requested_add_count: doctor auto-fix install is not an add-path install
        None,  // script_policy_override: `lpm doctor` does not expose policy flags
        None,  // advisor_override: `lpm doctor` does not expose `--advisor`
        None,  // min_release_age_override: `lpm doctor` uses the package.json/global/default chain
        &[],
        crate::provenance_fetch::DriftIgnorePolicy::default(), // drift-ignore: `lpm doctor` enforces drift like a normal install
        crate::provenance_fetch::VerifyPolicy::resolve_no_cli(), // verify-policy: doctor's auto-fix install honors env + config posture chain
        crate::commands::install::InstallOmitPolicy::default(),
        // doctor's auto-fix install does not
        // surface its own sandbox-mode flags. Falls through the
        // env / config / default chain.
        false, // strict_sandbox
        false, // no_sandbox
        false, // verbose: internal pipeline, no user-facing Done footer
        false, // audit_after_install: internal pipeline never runs audit
        false, // timing: doctor does not expose install's --timing flag
        &[],
    )
    .await
}
