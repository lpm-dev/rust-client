use super::super::super::*;
use super::super::ExperimentalResolverParityMode;
use super::super::experimental::{
    DEFAULT_EXPERIMENTAL_RESOLVER_METADATA_CONCURRENCY, ExperimentalResolverAdmission,
    ExperimentalResolverGraphSource, unsupported_admission_reasons,
};

fn benchmark_admission() -> ExperimentalResolverAdmission {
    ExperimentalResolverAdmission {
        json_output: true,
        frozen_lockfile_active: true,
        omit_policy: InstallOmitPolicy::default(),
        has_workspace_member_deps: false,
        has_v2_workspace_member_deps: false,
        has_tarball_source_deps: false,
        verify_registry_signatures: false,
        strict_integrity: false,
        force_security_floor: false,
        npm_firewall_enabled: false,
        policy_extensions_enabled: false,
        auto_build: false,
        script_policy_override: None,
        script_policy_is_default: true,
        has_trusted_dependencies: false,
        strict_release_age_replay: false,
        allow_new: false,
        is_add_invocation: false,
        has_direct_versions_out: false,
        has_target_set: false,
        audit_after_install: false,
        no_skills: true,
        no_security_summary: true,
        verbose: false,
        drift_ignore_policy_is_default: true,
        verify_policy_is_default: true,
    }
}

#[test]
fn metadata_concurrency_default_uses_measured_stable_value() {
    assert_eq!(DEFAULT_EXPERIMENTAL_RESOLVER_METADATA_CONCURRENCY, 192);
}

#[test]
fn parity_mode_parses_lockfile_deny_without_environment_mutation() {
    assert_eq!(
        ExperimentalResolverParityMode::from_value(Some("lockfile-deny")),
        ExperimentalResolverParityMode::Lockfile { deny: true }
    );
}

#[test]
fn graph_source_parses_lockfile_without_environment_mutation() {
    assert_eq!(
        ExperimentalResolverGraphSource::from_value(Some("lockfile")),
        ExperimentalResolverGraphSource::Lockfile
    );
}

#[test]
fn graph_source_defaults_to_resolve_worklist_when_unset() {
    assert_eq!(
        ExperimentalResolverGraphSource::from_value(None),
        ExperimentalResolverGraphSource::ResolveWorklist
    );
}

#[test]
fn graph_source_parses_explicit_resolve_worklist_without_environment_mutation() {
    assert_eq!(
        ExperimentalResolverGraphSource::from_value(Some("resolve-worklist")),
        ExperimentalResolverGraphSource::ResolveWorklist
    );
}

#[test]
fn graph_source_rejects_unknown_explicit_value() {
    assert_eq!(
        ExperimentalResolverGraphSource::from_value(Some("unexpected")),
        ExperimentalResolverGraphSource::Invalid
    );
}

#[test]
fn admission_accepts_frozen_lockfile_benchmark_shape() {
    let reasons = unsupported_admission_reasons(
        benchmark_admission(),
        ExperimentalResolverGraphSource::Lockfile,
        ExperimentalResolverParityMode::Disabled,
        true,
    );

    assert!(reasons.is_empty(), "unexpected reasons: {reasons:?}");
}

#[test]
fn admission_accepts_live_resolve_worklist_benchmark_shape() {
    let mut admission = benchmark_admission();
    admission.frozen_lockfile_active = false;

    let reasons = unsupported_admission_reasons(
        admission,
        ExperimentalResolverGraphSource::ResolveWorklist,
        ExperimentalResolverParityMode::FreshResolve { deny: true },
        true,
    );

    assert!(reasons.is_empty(), "unexpected reasons: {reasons:?}");
}

#[test]
fn admission_rejects_live_resolve_worklist_without_deny_parity() {
    let mut admission = benchmark_admission();
    admission.frozen_lockfile_active = false;

    let reasons = unsupported_admission_reasons(
        admission,
        ExperimentalResolverGraphSource::ResolveWorklist,
        ExperimentalResolverParityMode::Disabled,
        true,
    );

    assert_eq!(
        reasons,
        vec!["set LPM_INSTALLER_SPIKE_PARITY=deny for live graph parity"]
    );
}

#[test]
fn admission_rejects_unknown_explicit_graph_value() {
    let reasons = unsupported_admission_reasons(
        benchmark_admission(),
        ExperimentalResolverGraphSource::Invalid,
        ExperimentalResolverParityMode::FreshResolve { deny: true },
        true,
    );

    assert_eq!(
        reasons,
        vec!["set LPM_INSTALLER_SPIKE_GRAPH=resolve-worklist or lockfile"]
    );
}

#[test]
fn admission_rejects_live_resolve_worklist_for_frozen_installs() {
    let reasons = unsupported_admission_reasons(
        benchmark_admission(),
        ExperimentalResolverGraphSource::ResolveWorklist,
        ExperimentalResolverParityMode::FreshResolve { deny: true },
        true,
    );

    assert_eq!(
        reasons,
        vec!["set LPM_INSTALLER_SPIKE_GRAPH=lockfile for frozen installs"]
    );
}

#[test]
fn admission_requires_benchmark_ack_and_frozen_lockfile_for_lockfile_graph() {
    let mut admission = benchmark_admission();
    admission.frozen_lockfile_active = false;

    let reasons = unsupported_admission_reasons(
        admission,
        ExperimentalResolverGraphSource::Lockfile,
        ExperimentalResolverParityMode::FreshResolve { deny: false },
        false,
    );

    assert!(reasons.contains(&"set LPM_INSTALLER_SPIKE_BENCHMARK_ONLY=1"));
    assert!(reasons.contains(&"use lockfile parity or disable parity"));
    assert!(reasons.contains(&"use a frozen lockfile install"));
}

#[test]
fn admission_rejects_unsupported_install_contracts() {
    let mut admission = benchmark_admission();
    admission.omit_policy.dev = true;
    admission.has_workspace_member_deps = true;
    admission.verify_registry_signatures = true;
    admission.npm_firewall_enabled = true;
    admission.audit_after_install = true;
    admission.script_policy_is_default = false;
    admission.has_trusted_dependencies = true;
    admission.strict_release_age_replay = true;

    let reasons = unsupported_admission_reasons(
        admission,
        ExperimentalResolverGraphSource::Lockfile,
        ExperimentalResolverParityMode::Lockfile { deny: true },
        true,
    );

    assert!(reasons.contains(&"--prod/--omit=dev is not supported"));
    assert!(reasons.contains(&"workspace member links require resolve-worklist graph mode"));
    assert!(!reasons.contains(&"overrides are not supported"));
    assert!(!reasons.contains(&"patches are not supported"));
    assert!(reasons.contains(&"registry signature verification is not supported"));
    assert!(reasons.contains(&"npm firewall is not supported"));
    assert!(reasons.contains(&"audit-after-install is not supported"));
    assert!(reasons.contains(&"script policy/build execution options are not supported"));
    assert!(reasons.contains(&"strict minimumReleaseAge lockfile replay is not supported"));
}

#[test]
fn admission_accepts_workspace_member_links_for_live_resolve_worklist() {
    let mut admission = benchmark_admission();
    admission.frozen_lockfile_active = false;
    admission.has_workspace_member_deps = true;
    admission.has_v2_workspace_member_deps = true;

    let reasons = unsupported_admission_reasons(
        admission,
        ExperimentalResolverGraphSource::ResolveWorklist,
        ExperimentalResolverParityMode::FreshResolve { deny: true },
        true,
    );

    assert!(reasons.is_empty(), "unexpected reasons: {reasons:?}");
}

#[test]
fn admission_rejects_tarball_source_deps() {
    let mut admission = benchmark_admission();
    admission.has_tarball_source_deps = true;

    let reasons = unsupported_admission_reasons(
        admission,
        ExperimentalResolverGraphSource::Lockfile,
        ExperimentalResolverParityMode::Disabled,
        true,
    );

    assert_eq!(reasons, vec!["tarball source deps are not supported"]);
}

#[test]
fn admission_rejects_policy_extensions() {
    let mut admission = benchmark_admission();
    admission.policy_extensions_enabled = true;

    let reasons = unsupported_admission_reasons(
        admission,
        ExperimentalResolverGraphSource::Lockfile,
        ExperimentalResolverParityMode::Disabled,
        true,
    );

    assert_eq!(reasons, vec!["policy extensions are not supported"]);
}

#[test]
fn admission_rejects_trusted_dependencies_without_other_script_policy_changes() {
    let mut admission = benchmark_admission();
    admission.has_trusted_dependencies = true;

    let reasons = unsupported_admission_reasons(
        admission,
        ExperimentalResolverGraphSource::Lockfile,
        ExperimentalResolverParityMode::Disabled,
        true,
    );

    assert_eq!(
        reasons,
        vec!["script policy/build execution options are not supported"]
    );
}
