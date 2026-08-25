use super::super::super::*;
use super::super::ExperimentalResolverParityMode;
use super::super::experimental::{
    DEFAULT_EXPERIMENTAL_RESOLVER_METADATA_CONCURRENCY, ExperimentalResolverAdmission,
    ExperimentalResolverGraphSource, apply_computed_sri_to_artifact, index_v2_targets_by_artifact,
    unsupported_admission_reasons,
};
use super::super::peer::{attach_peer_edges_to_drafts, collect_peer_requirements};
use super::common::{fake_draft, info_with_peers};

fn contextual_v2_target(
    package: &InstallPackage,
    instance_id: lpm_common::PackageInstanceId,
) -> Arc<lpm_linker::v2::V2Target> {
    Arc::new(lpm_linker::v2::V2Target {
        instance_id,
        target: Arc::new(lpm_linker::LinkTarget {
            name: package.name.clone(),
            version: package.version.clone(),
            store_path: PathBuf::from("/unused"),
            dependencies: Vec::new(),
            aliases: HashMap::new(),
            is_direct: false,
            root_link_names: None,
            wrapper_id: None,
            materialization: lpm_linker::Materialization::CasBacked,
            peers: Vec::new(),
            patch_fingerprint: None,
        }),
        dependency_targets: HashMap::new(),
        peer_targets: HashMap::new(),
        source_sri: package.integrity.clone().unwrap(),
        verified_object_integrity: None,
        fresh_object: None,
    })
}

#[test]
fn event_dispatch_indexes_every_contextual_instance_of_one_artifact() {
    let mut first = super::common::fake_package("plugin", "1.0.0", &[]);
    let mut second = first.clone();
    let first_id = lpm_common::PackageInstanceId::derive(
        &first.name,
        &first.version,
        &first.source,
        "root/first/plugin",
    );
    let second_id = lpm_common::PackageInstanceId::derive(
        &second.name,
        &second.version,
        &second.source,
        "root/second/plugin",
    );
    first.instance_id = Some(first_id);
    second.instance_id = Some(second_id);
    let targets = vec![
        contextual_v2_target(&first, first_id),
        contextual_v2_target(&second, second_id),
    ];

    let index = index_v2_targets_by_artifact(&[first, second], &targets).unwrap();

    assert_eq!(
        index
            .values()
            .flat_map(|targets| targets.iter())
            .map(|target| target.instance_id)
            .collect::<HashSet<_>>(),
        HashSet::from([first_id, second_id])
    );
}

#[test]
fn computed_sri_updates_only_matching_source_instances() {
    let registry = super::common::fake_package("plugin", "1.0.0", &[]);
    let mut tarball = registry.clone();
    tarball.source = "tarball+https://example.test/plugin.tgz".to_string();
    tarball.integrity = None;
    let tarball_key = install_pkg_key(&tarball);
    let computed_sri = "sha512-computed".to_string();
    let mut packages = vec![registry.clone(), tarball];

    apply_computed_sri_to_artifact(&mut packages, &tarball_key, computed_sri.clone());

    assert_eq!(
        packages
            .iter()
            .map(|package| package.integrity.clone())
            .collect::<Vec<_>>(),
        vec![registry.integrity, Some(computed_sri)]
    );
}

#[test]
fn computed_sri_updates_every_contextual_instance_of_matching_artifact() {
    let mut first = super::common::fake_package("plugin", "1.0.0", &[]);
    first.integrity = None;
    let mut second = first.clone();
    first.instance_id = Some(lpm_common::PackageInstanceId::derive(
        &first.name,
        &first.version,
        &first.source,
        "root/first/plugin",
    ));
    second.instance_id = Some(lpm_common::PackageInstanceId::derive(
        &second.name,
        &second.version,
        &second.source,
        "root/second/plugin",
    ));
    let artifact_key = install_pkg_key(&first);
    let computed_sri = "sha512-computed".to_string();
    let mut packages = vec![first, second];

    apply_computed_sri_to_artifact(&mut packages, &artifact_key, computed_sri.clone());

    assert_eq!(
        packages
            .iter()
            .map(|package| package.integrity.as_deref())
            .collect::<Vec<_>>(),
        vec![Some(computed_sri.as_str()), Some(computed_sri.as_str())]
    );
}

#[test]
fn experimental_resolver_rejects_malformed_required_peer_range() {
    let info = info_with_peers("1.0.0", &[("runtime", "~X0^.00")]);
    let mut consumer = fake_draft("consumer", "1.0.0", &[]);
    consumer.info = Arc::new(info);
    let mut packages = HashMap::from([
        (("consumer".to_string(), "1.0.0".to_string()), consumer),
        (
            ("runtime".to_string(), "1.0.0".to_string()),
            fake_draft("runtime", "1.0.0", &[]),
        ),
    ]);

    let requirement_error = collect_peer_requirements(&packages)
        .expect_err("ambient peer collection must reject a malformed required range");
    let requirement_message = requirement_error.to_string();
    assert!(requirement_message.contains("consumer"));
    assert!(requirement_message.contains("runtime"));
    assert!(requirement_message.contains("~X0^.00"));

    let edge_error = attach_peer_edges_to_drafts(&mut packages)
        .expect_err("peer-edge attachment must reject a malformed required range");
    let edge_message = edge_error.to_string();
    assert!(edge_message.contains("consumer"));
    assert!(edge_message.contains("runtime"));
    assert!(edge_message.contains("~X0^.00"));
}

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
