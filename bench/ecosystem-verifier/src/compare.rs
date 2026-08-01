use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};

use lpm_resolver::{NpmRange, NpmVersion};
use serde::{Deserialize, Serialize};

use crate::canonical::{
    CanonicalGraph, DependencyEdge, Diagnostic, DiagnosticSeverity, GraphTelemetry, ImporterGraph,
    PackageInstance, TargetKind, TargetReference,
};

pub const COMPARISON_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct CompatibilityPolicy {
    #[serde(default)]
    pub minimum_release_age_exclude: Vec<String>,
    #[serde(default)]
    pub overrides: BTreeMap<String, String>,
    #[serde(default)]
    pub reference_peer_overrides: BTreeMap<String, String>,
    #[serde(default)]
    pub patched_dependencies: BTreeMap<String, String>,
    #[serde(default)]
    pub package_extensions: BTreeMap<String, serde_json::Value>,
    #[serde(default)]
    pub pnpm_compatibility_database_extensions: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ComparisonReport {
    pub schema_version: u32,
    pub reference_manager: String,
    pub candidate_manager: String,
    pub passed: bool,
    pub summary: ComparisonSummary,
    pub reference_telemetry: GraphTelemetry,
    pub candidate_telemetry: GraphTelemetry,
    pub peer_amplification: PeerAmplificationComparison,
    pub capability_gaps: Vec<String>,
    pub compatibility_gaps: Vec<String>,
    pub discrepancies: Vec<Discrepancy>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct ComparisonSummary {
    pub importer_matches: usize,
    pub importer_missing: usize,
    pub importer_extra: usize,
    pub package_identity_matches: usize,
    pub package_identity_missing: usize,
    pub package_identity_extra: usize,
    pub direct_edge_mismatches: usize,
    pub dependency_edge_mismatches: usize,
    pub peer_binding_mismatches: usize,
    pub source_mismatches: usize,
    pub integrity_mismatches: usize,
    pub platform_mismatches: usize,
    pub optional_reachability_mismatches: usize,
    pub required_peer_violations: usize,
    pub errors: usize,
    pub warnings: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PeerAmplificationComparison {
    pub reference: PeerAmplification,
    pub candidate: PeerAmplification,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PeerAmplification {
    pub unique_identities: usize,
    pub unique_instances: usize,
    pub additional_peer_instances: usize,
    pub amplification_basis_points: usize,
    pub peer_context_instances: usize,
    pub peer_binding_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Discrepancy {
    pub severity: DiagnosticSeverity,
    pub category: String,
    pub importer: Option<String>,
    pub subject: Option<String>,
    pub message: String,
    pub expected: Option<serde_json::Value>,
    pub actual: Option<serde_json::Value>,
}

#[cfg(test)]
pub fn compare(reference: &CanonicalGraph, candidate: &CanonicalGraph) -> ComparisonReport {
    compare_with_policy(reference, candidate, &CompatibilityPolicy::default())
}

pub fn compare_with_policy(
    reference: &CanonicalGraph,
    candidate: &CanonicalGraph,
    compatibility: &CompatibilityPolicy,
) -> ComparisonReport {
    let mut state = ComparisonState {
        capability_gaps: capability_gaps(reference, candidate),
        compatibility_gaps: compatibility.gaps(),
        compatibility: compatibility.clone(),
        ..ComparisonState::default()
    };
    append_graph_diagnostics(&mut state, "reference", &reference.diagnostics);
    append_graph_diagnostics(&mut state, "candidate", &candidate.diagnostics);

    let reference_importers: BTreeSet<&str> =
        reference.importers.keys().map(String::as_str).collect();
    let candidate_importers: BTreeSet<&str> =
        candidate.importers.keys().map(String::as_str).collect();
    for importer in reference_importers.difference(&candidate_importers) {
        state.summary.importer_missing += 1;
        state.error(
            "missing_importer",
            Some(importer),
            None,
            "candidate graph has no corresponding importer",
            Some(serde_json::json!(importer)),
            None,
        );
    }
    for importer in candidate_importers.difference(&reference_importers) {
        state.summary.importer_extra += 1;
        state.error(
            "extra_importer",
            Some(importer),
            None,
            "candidate graph contains an importer absent from the reference",
            None,
            Some(serde_json::json!(importer)),
        );
    }
    for importer_path in reference_importers.intersection(&candidate_importers) {
        state.summary.importer_matches += 1;
        compare_importer(
            importer_path,
            &reference.importers[*importer_path],
            &candidate.importers[*importer_path],
            reference,
            candidate,
            &mut state,
        );
    }

    state.discrepancies.sort_by(|left, right| {
        left.importer
            .cmp(&right.importer)
            .then_with(|| left.category.cmp(&right.category))
            .then_with(|| left.subject.cmp(&right.subject))
            .then_with(|| left.message.cmp(&right.message))
    });
    state.summary.errors = state
        .discrepancies
        .iter()
        .filter(|item| item.severity == DiagnosticSeverity::Error)
        .count();
    state.summary.warnings = state
        .discrepancies
        .iter()
        .filter(|item| item.severity == DiagnosticSeverity::Warning)
        .count()
        + state.capability_gaps.len()
        + state.compatibility_gaps.len();

    ComparisonReport {
        schema_version: COMPARISON_SCHEMA_VERSION,
        reference_manager: reference.manager.name.clone(),
        candidate_manager: candidate.manager.name.clone(),
        passed: state.summary.errors == 0,
        summary: state.summary,
        reference_telemetry: reference.telemetry.clone(),
        candidate_telemetry: candidate.telemetry.clone(),
        peer_amplification: PeerAmplificationComparison {
            reference: peer_amplification(&reference.telemetry),
            candidate: peer_amplification(&candidate.telemetry),
        },
        capability_gaps: state.capability_gaps,
        compatibility_gaps: state.compatibility_gaps,
        discrepancies: state.discrepancies,
    }
}

fn compare_importer(
    importer_path: &str,
    reference: &ImporterGraph,
    candidate: &ImporterGraph,
    reference_graph: &CanonicalGraph,
    candidate_graph: &CanonicalGraph,
    state: &mut ComparisonState,
) {
    let exact_importer_closures = reference_graph.capabilities.exact_importer_resolutions
        && candidate_graph.capabilities.exact_importer_resolutions;
    compare_edge_sets(
        EdgeComparisonScope {
            importer_path,
            category: "direct_edge",
            parent: None,
            compare_kinds: true,
            conclusive: exact_importer_closures,
        },
        &reference.direct_dependencies,
        &candidate.direct_dependencies,
        state,
    );

    let reference_by_identity = packages_by_identity(reference);
    let candidate_by_identity = packages_by_identity(candidate);
    let reference_identities: BTreeSet<&str> =
        reference_by_identity.keys().map(String::as_str).collect();
    let candidate_identities: BTreeSet<&str> =
        candidate_by_identity.keys().map(String::as_str).collect();
    for identity in reference_identities.difference(&candidate_identities) {
        state.summary.package_identity_missing += 1;
        let (category, message) = if exact_importer_closures {
            (
                "package_identity_selection_difference",
                "reference package identity is absent from the candidate closure; different satisfying version selections are not by themselves a correction failure",
            )
        } else {
            (
                "inconclusive_missing_package_identity",
                "observed package identity is absent from the candidate's inferred importer closure; at least one lock format does not record exact importer resolutions",
            )
        };
        state.warning(
            category,
            Some(importer_path),
            Some(identity),
            message,
            Some(serde_json::json!(identity)),
            None,
        );
    }
    for identity in candidate_identities.difference(&reference_identities) {
        state.summary.package_identity_extra += 1;
        let (category, message) = if exact_importer_closures {
            (
                "package_identity_selection_difference",
                "candidate package identity is absent from the reference closure; different satisfying version selections are not by themselves a correction failure",
            )
        } else {
            (
                "inconclusive_extra_package_identity",
                "observed package identity is absent from the reference closure; at least one lock format does not record exact importer resolutions",
            )
        };
        state.warning(
            category,
            Some(importer_path),
            Some(identity),
            message,
            None,
            Some(serde_json::json!(identity)),
        );
    }
    for identity in reference_identities.intersection(&candidate_identities) {
        state.summary.package_identity_matches += 1;
        compare_package_variants(
            importer_path,
            identity,
            &reference_by_identity[*identity],
            &candidate_by_identity[*identity],
            reference_graph,
            candidate_graph,
            state,
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn compare_package_variants(
    importer_path: &str,
    identity: &str,
    reference: &[&PackageInstance],
    candidate: &[&PackageInstance],
    reference_graph: &CanonicalGraph,
    candidate_graph: &CanonicalGraph,
    state: &mut ComparisonState,
) {
    let reference_by_context = packages_by_context(reference);
    let candidate_by_context = packages_by_context(candidate);
    let reference_contexts: BTreeSet<&str> =
        reference_by_context.keys().map(String::as_str).collect();
    let candidate_contexts: BTreeSet<&str> =
        candidate_by_context.keys().map(String::as_str).collect();
    if reference_contexts != candidate_contexts {
        state.summary.peer_binding_mismatches += 1;
        state.warning(
            "peer_binding_mismatch",
            Some(importer_path),
            Some(identity),
            "resolved peer-context variants differ",
            Some(serde_json::json!(reference_contexts)),
            Some(serde_json::json!(candidate_contexts)),
        );
    }

    let compare_kinds = candidate_graph.capabilities.optional_dependency_edge_kinds;
    if let Some(expected_contract) = reference.first() {
        for actual in candidate {
            let expected = reference_by_context
                .get(&peer_context_signature(actual))
                .copied()
                .or_else(|| {
                    reference.iter().copied().find(|expected| {
                        let expected_dependencies = comparable_dependencies(expected, None);
                        let actual_dependencies = comparable_dependencies(actual, Some(expected));
                        edge_shapes_match(
                            &expected_dependencies,
                            &actual_dependencies,
                            compare_kinds,
                        )
                    })
                })
                .unwrap_or(expected_contract);
            compare_package_attributes(importer_path, identity, expected, actual, state);
            let expected_dependencies = comparable_dependencies(expected, None);
            let actual_dependencies = comparable_dependencies(actual, Some(expected));
            compare_edge_sets(
                EdgeComparisonScope {
                    importer_path,
                    category: "dependency_edge",
                    parent: Some(identity),
                    compare_kinds,
                    conclusive: true,
                },
                &expected_dependencies,
                &actual_dependencies,
                state,
            );
        }
    }

    if reference_graph.capabilities.declared_peer_ranges
        && let Some(expected_contract) = reference.first()
    {
        for actual in candidate {
            validate_required_peers(importer_path, expected_contract, actual, state);
        }
    }
}

fn comparable_dependencies<'a>(
    package: &'a PackageInstance,
    peer_contract: Option<&PackageInstance>,
) -> Cow<'a, [DependencyEdge]> {
    if !package.dependencies.iter().any(|edge| {
        is_exact_package_self_dependency(package, edge)
            || peer_contract
                .is_some_and(|expected| dependency_satisfies_declared_peer(expected, edge))
    }) {
        return Cow::Borrowed(&package.dependencies);
    }
    Cow::Owned(
        package
            .dependencies
            .iter()
            .filter(|edge| {
                !is_exact_package_self_dependency(package, edge)
                    && !peer_contract
                        .is_some_and(|expected| dependency_satisfies_declared_peer(expected, edge))
            })
            .cloned()
            .collect(),
    )
}

fn is_exact_package_self_dependency(package: &PackageInstance, edge: &DependencyEdge) -> bool {
    edge.target.kind == TargetKind::Package
        && edge.local_name == package.name
        && edge.target.name.as_deref() == Some(package.name.as_str())
        && edge.target.version.as_deref() == Some(package.version.as_str())
}

fn dependency_satisfies_declared_peer(expected: &PackageInstance, edge: &DependencyEdge) -> bool {
    let Some(range) = expected.declared_peers.get(&edge.local_name) else {
        return false;
    };
    if !expected.peer_bindings.contains_key(&edge.local_name)
        && !expected.optional_peers.contains(&edge.local_name)
    {
        return false;
    }
    edge.target.kind == TargetKind::Package
        && edge
            .target
            .version
            .as_deref()
            .is_some_and(|version| peer_version_satisfies(range, version))
}

fn edge_shapes_match(
    expected: &[DependencyEdge],
    actual: &[DependencyEdge],
    compare_kinds: bool,
) -> bool {
    let expected: BTreeSet<String> = expected
        .iter()
        .map(|edge| edge_shape_signature(edge, compare_kinds))
        .collect();
    let actual: BTreeSet<String> = actual
        .iter()
        .map(|edge| edge_shape_signature(edge, compare_kinds))
        .collect();
    expected == actual
}

fn compare_package_attributes(
    importer_path: &str,
    identity: &str,
    expected: &PackageInstance,
    actual: &PackageInstance,
    state: &mut ComparisonState,
) {
    if expected.source.kind != actual.source.kind
        || expected.source.locator != actual.source.locator
    {
        state.summary.source_mismatches += 1;
        state.error(
            "source_mismatch",
            Some(importer_path),
            Some(identity),
            "package source identity differs",
            serde_json::to_value(&expected.source).ok(),
            serde_json::to_value(&actual.source).ok(),
        );
    }
    if expected.source.integrity.is_some()
        && actual.source.integrity.is_some()
        && expected.source.integrity != actual.source.integrity
    {
        state.summary.integrity_mismatches += 1;
        state.error(
            "integrity_mismatch",
            Some(importer_path),
            Some(identity),
            "package integrity differs",
            serde_json::to_value(&expected.source.integrity).ok(),
            serde_json::to_value(&actual.source.integrity).ok(),
        );
    }
    if expected.platform != actual.platform {
        state.summary.platform_mismatches += 1;
        state.error(
            "platform_constraints_mismatch",
            Some(importer_path),
            Some(identity),
            "package OS, CPU, or libc constraints differ",
            serde_json::to_value(&expected.platform).ok(),
            serde_json::to_value(&actual.platform).ok(),
        );
    }
    if let (Some(expected_optional), Some(actual_optional)) = (expected.optional, actual.optional)
        && expected_optional != actual_optional
    {
        state.summary.optional_reachability_mismatches += 1;
        state.error(
            "optional_reachability_mismatch",
            Some(importer_path),
            Some(identity),
            "package optional reachability differs",
            Some(serde_json::json!(expected_optional)),
            Some(serde_json::json!(actual_optional)),
        );
    }
}

struct EdgeComparisonScope<'a> {
    importer_path: &'a str,
    category: &'a str,
    parent: Option<&'a str>,
    compare_kinds: bool,
    conclusive: bool,
}

fn compare_edge_sets(
    scope: EdgeComparisonScope<'_>,
    expected_edges: &[DependencyEdge],
    actual_edges: &[DependencyEdge],
    state: &mut ComparisonState,
) {
    let EdgeComparisonScope {
        importer_path,
        category,
        parent,
        compare_kinds,
        conclusive,
    } = scope;
    let expected: BTreeSet<String> = expected_edges
        .iter()
        .map(|edge| edge_signature(edge, compare_kinds))
        .collect();
    let actual: BTreeSet<String> = actual_edges
        .iter()
        .map(|edge| edge_signature(edge, compare_kinds))
        .collect();
    if expected == actual {
        return;
    }
    if category == "direct_edge" {
        state.summary.direct_edge_mismatches += 1;
    } else {
        state.summary.dependency_edge_mismatches += 1;
    }
    let expected_by_name = edge_refs_by_local_name(expected_edges);
    let actual_by_name = edge_refs_by_local_name(actual_edges);
    let names: BTreeSet<&str> = expected_by_name
        .keys()
        .chain(actual_by_name.keys())
        .copied()
        .collect();
    let mut version_differences = Vec::new();
    let mut optional_evidence_gaps = Vec::new();
    let mut compatibility_reasons = BTreeSet::new();
    let mut unaccounted = Vec::new();
    for name in names {
        let expected_named: &[&DependencyEdge] =
            expected_by_name.get(name).map_or(&[], Vec::as_slice);
        let actual_named: &[&DependencyEdge] = actual_by_name.get(name).map_or(&[], Vec::as_slice);
        let expected_signatures: BTreeSet<String> = expected_named
            .iter()
            .map(|edge| edge_signature(edge, compare_kinds))
            .collect();
        let actual_signatures: BTreeSet<String> = actual_named
            .iter()
            .map(|edge| edge_signature(edge, compare_kinds))
            .collect();
        if expected_signatures == actual_signatures {
            continue;
        }
        let expected_shapes: BTreeSet<String> = expected_named
            .iter()
            .map(|edge| edge_shape_signature(edge, compare_kinds))
            .collect();
        let actual_shapes: BTreeSet<String> = actual_named
            .iter()
            .map(|edge| edge_shape_signature(edge, compare_kinds))
            .collect();
        if expected_shapes == actual_shapes {
            version_differences.push(name);
            continue;
        }
        let missing_shapes: BTreeSet<String> = expected_shapes
            .difference(&actual_shapes)
            .cloned()
            .collect();
        let optional_evidence_gap = !compare_kinds
            && actual_shapes.difference(&expected_shapes).next().is_none()
            && expected_named
                .iter()
                .filter(|edge| missing_shapes.contains(&edge_shape_signature(edge, compare_kinds)))
                .all(|edge| edge.kind == crate::canonical::DependencyKind::Optional);
        if optional_evidence_gap {
            optional_evidence_gaps.push(name);
            continue;
        }
        if let Some(reason) = state.compatibility.explain_edge(parent, name) {
            compatibility_reasons.insert(reason);
            continue;
        }
        unaccounted.push(name);
    }

    if !version_differences.is_empty() {
        state.warning(
            format!(
                "{}_version_selection_mismatch",
                category.trim_end_matches("_edge")
            ),
            Some(importer_path),
            parent,
            format!(
                "dependency targets have the same topology but select different exact versions for {}",
                version_differences.join(", ")
            ),
            Some(serde_json::json!(expected)),
            Some(serde_json::json!(actual)),
        );
    }
    if !optional_evidence_gaps.is_empty() {
        state.warning(
            format!("inconclusive_optional_{category}_mismatch"),
            Some(importer_path),
            parent,
            format!(
                "reference closure contains portable optional edges that the candidate lock format cannot classify for {}",
                optional_evidence_gaps.join(", ")
            ),
            Some(serde_json::json!(expected)),
            Some(serde_json::json!(actual)),
        );
    }
    if !compatibility_reasons.is_empty() {
        state.warning(
            format!("unsupported_policy_{category}_mismatch"),
            Some(importer_path),
            parent,
            format!(
                "dependency edge parity is inconclusive because pnpm policy is unsupported by LPM: {}",
                compatibility_reasons.into_iter().collect::<Vec<_>>().join(", ")
            ),
            Some(serde_json::json!(expected)),
            Some(serde_json::json!(actual)),
        );
    }
    if unaccounted.is_empty() {
        return;
    }
    if conclusive {
        state.error(
            format!("{category}_mismatch"),
            Some(importer_path),
            parent,
            format!("dependency edge sets differ for {}", unaccounted.join(", ")),
            Some(serde_json::json!(expected)),
            Some(serde_json::json!(actual)),
        );
    } else {
        state.warning(
            format!("inconclusive_{category}_mismatch"),
            Some(importer_path),
            parent,
            format!(
                "dependency edge sets differ for {}, but at least one lock format does not record the exact importer resolution",
                unaccounted.join(", ")
            ),
            Some(serde_json::json!(expected)),
            Some(serde_json::json!(actual)),
        );
    }
}

fn edge_shape_signature(edge: &DependencyEdge, compare_kind: bool) -> String {
    let kind = if compare_kind {
        format!("{:?}:", edge.kind)
    } else {
        String::new()
    };
    let target = match edge.target.kind {
        TargetKind::Package => format!("package:{}", edge.target.name.as_deref().unwrap_or("?")),
        TargetKind::Workspace => format!(
            "workspace:{}:{}",
            edge.target.name.as_deref().unwrap_or("?"),
            edge.target.path.as_deref().unwrap_or("?")
        ),
        TargetKind::External => format!(
            "external:{}:{}",
            edge.target.name.as_deref().unwrap_or("?"),
            edge.target.path.as_deref().unwrap_or("?")
        ),
        TargetKind::Unresolved => {
            format!("unresolved:{}", edge.target.name.as_deref().unwrap_or("?"))
        }
    };
    format!("{kind}{}=>{target}", edge.local_name)
}

fn validate_required_peers(
    importer_path: &str,
    expected: &PackageInstance,
    actual: &PackageInstance,
    state: &mut ComparisonState,
) {
    let actual_identity = format!("{}@{}", actual.name, actual.version);
    for (peer, range) in &expected.declared_peers {
        if expected.optional_peers.contains(peer) {
            continue;
        }
        let reference_version = expected
            .peer_bindings
            .get(peer)
            .and_then(|binding| binding.version.as_deref());
        if reference_version.is_none()
            && (state.compatibility.explain_peer(peer).is_none()
                || actual.peer_bindings.contains_key(peer))
        {
            state.warning(
                "reference_required_peer_missing",
                Some(importer_path),
                Some(&actual.id),
                format!(
                    "the reference manager also has no resolved binding for required peer {peer}@{range}"
                ),
                Some(serde_json::json!({"name": peer, "range": range})),
                actual.peer_bindings.get(peer).map(|binding| serde_json::json!(binding)),
            );
            continue;
        }
        if let Some(reference_version) = reference_version
            && !peer_version_satisfies(range, reference_version)
        {
            state.warning(
                "reference_required_peer_out_of_range",
                Some(importer_path),
                Some(&actual.id),
                format!(
                    "the reference manager also resolves required peer {peer}@{reference_version} outside {range}"
                ),
                Some(serde_json::json!({"name": peer, "range": range, "version": reference_version})),
                actual.peer_bindings.get(peer).map(|binding| serde_json::json!(binding)),
            );
            continue;
        }
        let binding = actual.peer_bindings.get(peer).or_else(|| {
            actual.dependencies.iter().find_map(|edge| {
                (edge.local_name == *peer
                    && edge.target.kind == TargetKind::Package
                    && edge
                        .target
                        .version
                        .as_deref()
                        .is_some_and(|version| peer_version_satisfies(range, version)))
                .then_some(&edge.target)
            })
        });
        let Some(binding) = binding else {
            state.summary.required_peer_violations += 1;
            if let Some(reason) = state.compatibility.explain_peer(peer) {
                state.warning(
                    "unsupported_policy_required_peer_missing",
                    Some(importer_path),
                    Some(&actual.id),
                    format!(
                        "required peer {peer}@{range} cannot be compared because pnpm policy is unsupported by LPM: {reason}"
                    ),
                    Some(serde_json::json!({"name": peer, "range": range})),
                    None,
                );
            } else {
                state.error(
                    "required_peer_missing",
                    Some(importer_path),
                    Some(&actual.id),
                    format!("required peer {peer}@{range} has no resolved binding"),
                    Some(serde_json::json!({"name": peer, "range": range})),
                    None,
                );
            }
            continue;
        };
        let Some(version) = binding.version.as_deref() else {
            continue;
        };
        let satisfies = peer_version_satisfies(range, version);
        if !satisfies {
            state.summary.required_peer_violations += 1;
            if let Some(reason) = state
                .compatibility
                .explain_reference_peer_override(&actual_identity, peer)
            {
                state.warning(
                    "inconclusive_override_rewritten_peer_range",
                    Some(importer_path),
                    Some(&actual.id),
                    format!(
                        "resolved peer {peer}@{version} differs from the reference lockfile range {range}, which may have been rewritten by {reason}"
                    ),
                    Some(serde_json::json!({"name": peer, "range": range})),
                    Some(serde_json::json!({"name": peer, "version": version})),
                );
            } else {
                state.error(
                    "required_peer_out_of_range",
                    Some(importer_path),
                    Some(&actual.id),
                    format!("resolved peer {peer}@{version} does not satisfy {range}"),
                    Some(serde_json::json!({"name": peer, "range": range})),
                    Some(serde_json::json!({"name": peer, "version": version})),
                );
            }
        }
    }
}

fn peer_version_satisfies(range: &str, version: &str) -> bool {
    NpmRange::parse(range)
        .ok()
        .zip(NpmVersion::parse(version).ok())
        .is_none_or(|(range, version)| range.satisfies(&version))
}

fn packages_by_identity(importer: &ImporterGraph) -> BTreeMap<String, Vec<&PackageInstance>> {
    let mut packages = BTreeMap::<String, Vec<&PackageInstance>>::new();
    for package in importer.packages.values() {
        packages
            .entry(format!("{}@{}", package.name, package.version))
            .or_default()
            .push(package);
    }
    packages
}

fn packages_by_context<'a>(
    packages: &[&'a PackageInstance],
) -> BTreeMap<String, &'a PackageInstance> {
    packages
        .iter()
        .map(|package| (peer_context_signature(package), *package))
        .collect()
}

fn peer_context_signature(package: &PackageInstance) -> String {
    package
        .peer_bindings
        .iter()
        .map(|(name, target)| format!("{name}={}", target_signature(target)))
        .collect::<Vec<_>>()
        .join("|")
}

fn edge_signature(edge: &DependencyEdge, compare_kind: bool) -> String {
    let kind = if compare_kind {
        format!("{:?}:", edge.kind)
    } else {
        String::new()
    };
    format!(
        "{kind}{}=>{}",
        edge.local_name,
        target_signature(&edge.target)
    )
}

fn target_signature(target: &TargetReference) -> String {
    match target.kind {
        TargetKind::Package => format!(
            "package:{}@{}",
            target.name.as_deref().unwrap_or("?"),
            target.version.as_deref().unwrap_or("?")
        ),
        TargetKind::Workspace => format!(
            "workspace:{}:{}",
            target.name.as_deref().unwrap_or("?"),
            target.path.as_deref().unwrap_or("?")
        ),
        TargetKind::External => format!(
            "external:{}:{}",
            target.name.as_deref().unwrap_or("?"),
            target.path.as_deref().unwrap_or("?")
        ),
        TargetKind::Unresolved => format!(
            "unresolved:{}@{}",
            target.name.as_deref().unwrap_or("?"),
            target.version.as_deref().unwrap_or("?")
        ),
    }
}

fn append_graph_diagnostics(state: &mut ComparisonState, manager_role: &str, items: &[Diagnostic]) {
    state
        .discrepancies
        .extend(items.iter().map(|item| Discrepancy {
            severity: item.severity,
            category: format!("{manager_role}_diagnostic_{}", item.code),
            importer: item.importer.clone(),
            subject: item.subject.clone(),
            message: item.message.clone(),
            expected: None,
            actual: None,
        }));
}

fn capability_gaps(reference: &CanonicalGraph, candidate: &CanonicalGraph) -> Vec<String> {
    let mut gaps = Vec::new();
    let capabilities = [
        (
            "exact_importer_resolutions",
            reference.capabilities.exact_importer_resolutions,
            candidate.capabilities.exact_importer_resolutions,
        ),
        (
            "dependency_edges",
            reference.capabilities.dependency_edges,
            candidate.capabilities.dependency_edges,
        ),
        (
            "optional_dependency_edge_kinds",
            reference.capabilities.optional_dependency_edge_kinds,
            candidate.capabilities.optional_dependency_edge_kinds,
        ),
        (
            "resolved_peer_bindings",
            reference.capabilities.resolved_peer_bindings,
            candidate.capabilities.resolved_peer_bindings,
        ),
        (
            "declared_peer_ranges",
            reference.capabilities.declared_peer_ranges,
            candidate.capabilities.declared_peer_ranges,
        ),
        (
            "source_identity",
            reference.capabilities.source_identity,
            candidate.capabilities.source_identity,
        ),
        (
            "integrity",
            reference.capabilities.integrity,
            candidate.capabilities.integrity,
        ),
        (
            "platform_constraints",
            reference.capabilities.platform_constraints,
            candidate.capabilities.platform_constraints,
        ),
        (
            "optional_reachability",
            reference.capabilities.optional_reachability,
            candidate.capabilities.optional_reachability,
        ),
        (
            "workspace_links",
            reference.capabilities.workspace_links,
            candidate.capabilities.workspace_links,
        ),
    ];
    for (name, reference_has, candidate_has) in capabilities {
        if reference_has && !candidate_has {
            gaps.push(name.into());
        }
    }
    gaps
}

fn peer_amplification(telemetry: &GraphTelemetry) -> PeerAmplification {
    let unique_identities = telemetry.unique_package_identities;
    let unique_instances = telemetry.unique_package_instances;
    PeerAmplification {
        unique_identities,
        unique_instances,
        additional_peer_instances: unique_instances.saturating_sub(unique_identities),
        amplification_basis_points: if unique_identities == 0 {
            0
        } else {
            unique_instances.saturating_mul(10_000) / unique_identities
        },
        peer_context_instances: telemetry.peer_context_instances,
        peer_binding_count: telemetry.peer_binding_count,
    }
}

#[derive(Default)]
struct ComparisonState {
    summary: ComparisonSummary,
    capability_gaps: Vec<String>,
    compatibility_gaps: Vec<String>,
    discrepancies: Vec<Discrepancy>,
    compatibility: CompatibilityPolicy,
}

impl CompatibilityPolicy {
    fn gaps(&self) -> Vec<String> {
        let mut gaps = Vec::with_capacity(
            self.minimum_release_age_exclude.len()
                + self.overrides.len()
                + self.patched_dependencies.len()
                + self.package_extensions.len()
                + self.pnpm_compatibility_database_extensions.len(),
        );
        gaps.extend(
            self.minimum_release_age_exclude
                .iter()
                .map(|selector| format!("minimumReleaseAgeExclude {selector}")),
        );
        gaps.extend(
            self.overrides
                .iter()
                .map(|(selector, target)| format!("override {selector} => {target}")),
        );
        gaps.extend(
            self.patched_dependencies
                .keys()
                .map(|selector| format!("patchedDependency {selector}")),
        );
        gaps.extend(
            self.package_extensions
                .keys()
                .map(|selector| format!("packageExtension {selector}")),
        );
        gaps.extend(
            self.pnpm_compatibility_database_extensions
                .keys()
                .map(|selector| format!("pnpmCompatibilityDatabaseExtension {selector}")),
        );
        gaps
    }

    fn explain_edge(&self, parent: Option<&str>, dependency: &str) -> Option<String> {
        if let Some((selector, target)) = self
            .overrides
            .iter()
            .find(|(selector, _)| override_applies(selector, parent, dependency))
        {
            return Some(format!("override {selector} => {target}"));
        }
        if let Some((selector, _)) = self
            .package_extensions
            .iter()
            .find(|(selector, extension)| {
                parent.is_some_and(|identity| package_selector_matches(selector, identity))
                    && extension_dependency_names(extension).contains(dependency)
            })
        {
            return Some(format!("packageExtension {selector} adds {dependency}"));
        }
        self.pnpm_compatibility_database_extensions
            .iter()
            .find(|(selector, extension)| {
                parent.is_some_and(|identity| package_selector_matches(selector, identity))
                    && extension_dependency_names(extension).contains(dependency)
            })
            .map(|(selector, _)| {
                format!("pnpm compatibility database extension {selector} adds {dependency}")
            })
    }

    fn explain_peer(&self, peer: &str) -> Option<String> {
        self.overrides.iter().find_map(|(selector, target)| {
            override_applies(selector, None, peer)
                .then(|| format!("override {selector} => {target}"))
        })
    }

    fn explain_reference_peer_override(&self, parent: &str, peer: &str) -> Option<String> {
        self.reference_peer_overrides
            .iter()
            .chain(&self.overrides)
            .find_map(|(selector, target)| {
                override_applies(selector, Some(parent), peer)
                    .then(|| format!("override {selector} => {target}"))
            })
    }
}

fn edge_refs_by_local_name(edges: &[DependencyEdge]) -> BTreeMap<&str, Vec<&DependencyEdge>> {
    let mut by_name = BTreeMap::<&str, Vec<&DependencyEdge>>::new();
    for edge in edges {
        by_name.entry(&edge.local_name).or_default().push(edge);
    }
    by_name
}

fn override_applies(selector: &str, parent: Option<&str>, dependency: &str) -> bool {
    let (parent_selector, dependency_selector) = selector
        .rsplit_once('>')
        .map_or((None, selector), |(parent, dependency)| {
            (Some(parent), dependency)
        });
    selector_package_name(dependency_selector) == Some(dependency)
        && parent_selector.is_none_or(|selector| {
            parent.is_some_and(|identity| package_selector_matches(selector, identity))
        })
}

fn package_selector_matches(selector: &str, identity: &str) -> bool {
    let Some((identity_name, identity_version)) = split_package_identity(identity) else {
        return false;
    };
    let Some(selector_name) = selector_package_name(selector) else {
        return false;
    };
    if selector_name != identity_name {
        return false;
    }
    let range = &selector[selector_name.len()..];
    if range.is_empty() {
        return true;
    }
    let Some(range) = range.strip_prefix('@') else {
        return false;
    };
    NpmRange::parse(range)
        .ok()
        .zip(NpmVersion::parse(identity_version).ok())
        .is_some_and(|(range, version)| range.satisfies(&version))
}

fn split_package_identity(identity: &str) -> Option<(&str, &str)> {
    let separator = identity.rfind('@')?;
    (separator > 0 && separator + 1 < identity.len())
        .then(|| (&identity[..separator], &identity[separator + 1..]))
}

fn selector_package_name(selector: &str) -> Option<&str> {
    if selector.starts_with('@') {
        let slash = selector.find('/')?;
        let suffix = &selector[slash + 1..];
        let version = suffix
            .find('@')
            .map_or(selector.len(), |offset| slash + 1 + offset);
        Some(&selector[..version])
    } else {
        Some(selector.split_once('@').map_or(selector, |(name, _)| name))
    }
}

fn extension_dependency_names(extension: &serde_json::Value) -> BTreeSet<&str> {
    ["dependencies", "optionalDependencies", "peerDependencies"]
        .into_iter()
        .filter_map(|field| extension.get(field)?.as_object())
        .flat_map(|dependencies| dependencies.keys().map(String::as_str))
        .collect()
}

impl ComparisonState {
    #[allow(clippy::too_many_arguments)]
    fn error(
        &mut self,
        category: impl Into<String>,
        importer: Option<&str>,
        subject: Option<&str>,
        message: impl Into<String>,
        expected: Option<serde_json::Value>,
        actual: Option<serde_json::Value>,
    ) {
        self.push_discrepancy(
            DiagnosticSeverity::Error,
            category,
            importer,
            subject,
            message,
            expected,
            actual,
        );
    }

    #[allow(clippy::too_many_arguments)]
    fn warning(
        &mut self,
        category: impl Into<String>,
        importer: Option<&str>,
        subject: Option<&str>,
        message: impl Into<String>,
        expected: Option<serde_json::Value>,
        actual: Option<serde_json::Value>,
    ) {
        self.push_discrepancy(
            DiagnosticSeverity::Warning,
            category,
            importer,
            subject,
            message,
            expected,
            actual,
        );
    }

    #[allow(clippy::too_many_arguments)]
    fn push_discrepancy(
        &mut self,
        severity: DiagnosticSeverity,
        category: impl Into<String>,
        importer: Option<&str>,
        subject: Option<&str>,
        message: impl Into<String>,
        expected: Option<serde_json::Value>,
        actual: Option<serde_json::Value>,
    ) {
        self.discrepancies.push(Discrepancy {
            severity,
            category: category.into(),
            importer: importer.map(str::to_string),
            subject: subject.map(str::to_string),
            message: message.into(),
            expected,
            actual,
        });
    }
}

#[cfg(test)]
mod tests {
    use crate::canonical::{
        Capabilities, DependencyKind, Manager, PackageSource, PlatformConstraints,
    };

    use super::*;

    fn package(name: &str, version: &str) -> PackageInstance {
        PackageInstance {
            id: format!("{name}@{version}"),
            name: name.into(),
            version: version.into(),
            source: PackageSource {
                kind: Some("registry".into()),
                locator: Some("https://registry.npmjs.org".into()),
                integrity: Some(format!("sha512-{name}")),
            },
            optional: None,
            dev: None,
            platform: PlatformConstraints::default(),
            dependencies: Vec::new(),
            peer_bindings: BTreeMap::new(),
            declared_peers: BTreeMap::new(),
            optional_peers: BTreeSet::new(),
            patch_hash: None,
        }
    }

    fn graph(manager: &str, packages: Vec<PackageInstance>) -> CanonicalGraph {
        let mut graph = CanonicalGraph {
            schema_version: 1,
            manager: Manager {
                name: manager.into(),
                lockfile_version: "1".into(),
            },
            workspace: "/fixture".into(),
            capabilities: Capabilities {
                exact_importer_resolutions: true,
                dependency_edges: true,
                optional_dependency_edge_kinds: true,
                resolved_peer_bindings: true,
                declared_peer_ranges: true,
                source_identity: true,
                integrity: true,
                platform_constraints: true,
                optional_reachability: true,
                workspace_links: true,
            },
            importers: BTreeMap::from([(
                ".".into(),
                ImporterGraph {
                    path: ".".into(),
                    direct_dependencies: packages
                        .first()
                        .map(|package| {
                            vec![DependencyEdge {
                                kind: DependencyKind::Production,
                                local_name: package.name.clone(),
                                specifier: Some(format!("^{}", package.version)),
                                target: TargetReference::package(
                                    &package.name,
                                    &package.version,
                                    package.id.clone(),
                                ),
                            }]
                        })
                        .unwrap_or_default(),
                    packages: packages
                        .into_iter()
                        .map(|package| (package.id.clone(), package))
                        .collect(),
                },
            )]),
            diagnostics: Vec::new(),
            telemetry: GraphTelemetry::default(),
        };
        graph.finalize();
        graph
    }

    #[test]
    fn identical_graphs_pass_with_no_discrepancies() {
        let expected = graph("pnpm", vec![package("react", "19.1.0")]);
        let actual = graph("lpm", vec![package("react", "19.1.0")]);

        let report = compare(&expected, &actual);

        assert!(report.passed);
        assert!(report.discrepancies.is_empty());
        assert_eq!(report.summary.package_identity_matches, 1);
    }

    #[test]
    fn missing_package_and_out_of_range_peer_are_correction_failures() {
        let mut renderer = package("react-dom", "19.1.0");
        renderer.declared_peers.insert("react".into(), "^19".into());
        renderer.peer_bindings.insert(
            "react".into(),
            TargetReference::package("react", "19.1.0", "react@19.1.0".into()),
        );
        renderer.id = "react-dom@19.1.0(react@19.1.0)".into();
        let expected = graph("pnpm", vec![renderer.clone(), package("react", "19.1.0")]);
        let mut actual_renderer = renderer;
        actual_renderer.peer_bindings.insert(
            "react".into(),
            TargetReference::package("react", "18.3.1", "react@18.3.1".into()),
        );
        actual_renderer.id = "react-dom@19.1.0(react@18.3.1)".into();
        let actual = graph("lpm", vec![actual_renderer]);

        let report = compare(&expected, &actual);

        assert!(!report.passed);
        assert_eq!(report.summary.package_identity_missing, 1);
        assert_eq!(report.summary.peer_binding_mismatches, 1);
    }

    #[test]
    fn peer_range_violation_shared_with_the_reference_is_advisory() {
        let mut renderer = package("legacy-renderer", "1.0.0");
        renderer.declared_peers.insert("react".into(), "^17".into());
        renderer.peer_bindings.insert(
            "react".into(),
            TargetReference::package("react", "19.1.0", "react@19.1.0".into()),
        );
        renderer.id = "legacy-renderer@1.0.0(react@19.1.0)".into();
        let expected = graph("pnpm", vec![renderer.clone(), package("react", "19.1.0")]);
        let actual = graph("lpm", vec![renderer, package("react", "19.1.0")]);

        let report = compare(&expected, &actual);

        assert!(report.passed);
        assert!(report.discrepancies.iter().any(|discrepancy| {
            discrepancy.severity == DiagnosticSeverity::Warning
                && discrepancy.category == "reference_required_peer_out_of_range"
        }));
    }

    #[test]
    fn package_identity_difference_is_inconclusive_without_exact_importer_closures() {
        let expected = graph(
            "pnpm",
            vec![package("react", "19.1.0"), package("scheduler", "0.26.0")],
        );
        let mut actual = graph("lpm", vec![package("react", "19.1.0")]);
        actual.capabilities.exact_importer_resolutions = false;

        let report = compare(&expected, &actual);

        assert!(report.passed);
        assert_eq!(report.summary.package_identity_missing, 1);
        assert_eq!(report.summary.errors, 0);
        assert!(report.discrepancies.iter().any(|discrepancy| {
            discrepancy.severity == DiagnosticSeverity::Warning
                && discrepancy.category == "inconclusive_missing_package_identity"
        }));
    }

    #[test]
    fn valid_transitive_version_selection_difference_is_advisory() {
        let mut expected_parent = package("parent", "1.0.0");
        expected_parent.dependencies.push(DependencyEdge {
            kind: DependencyKind::Production,
            local_name: "child".into(),
            specifier: None,
            target: TargetReference::package("child", "1.0.0", "child@1.0.0".into()),
        });
        let mut actual_parent = expected_parent.clone();
        actual_parent.dependencies[0].target =
            TargetReference::package("child", "1.1.0", "child@1.1.0".into());
        let expected = graph("pnpm", vec![expected_parent, package("child", "1.0.0")]);
        let actual = graph("lpm", vec![actual_parent, package("child", "1.1.0")]);

        let report = compare(&expected, &actual);

        assert!(report.passed);
        assert!(report.discrepancies.iter().any(|discrepancy| {
            discrepancy.severity == DiagnosticSeverity::Warning
                && discrepancy.category == "dependency_version_selection_mismatch"
        }));
    }

    #[test]
    fn absent_portable_optional_edge_is_inconclusive_without_candidate_edge_kinds() {
        let mut expected_parent = package("parent", "1.0.0");
        expected_parent.dependencies.push(DependencyEdge {
            kind: DependencyKind::Optional,
            local_name: "native-child".into(),
            specifier: None,
            target: TargetReference::package("native-child", "1.0.0", "native-child@1.0.0".into()),
        });
        let actual_parent = package("parent", "1.0.0");
        let expected = graph(
            "pnpm",
            vec![expected_parent, package("native-child", "1.0.0")],
        );
        let mut actual = graph("lpm", vec![actual_parent]);
        actual.capabilities.optional_dependency_edge_kinds = false;

        let report = compare(&expected, &actual);

        assert!(report.passed);
        assert!(report.discrepancies.iter().any(|discrepancy| {
            discrepancy.severity == DiagnosticSeverity::Warning
                && discrepancy.category == "inconclusive_optional_dependency_edge_mismatch"
        }));
    }

    #[test]
    fn missing_optional_peer_context_is_advisory() {
        let mut expected_renderer = package("renderer", "1.0.0");
        expected_renderer
            .declared_peers
            .insert("typescript".into(), "^6".into());
        expected_renderer.optional_peers.insert("typescript".into());
        expected_renderer.peer_bindings.insert(
            "typescript".into(),
            TargetReference::package("typescript", "6.0.3", "typescript@6.0.3".into()),
        );
        let mut actual_renderer = expected_renderer.clone();
        actual_renderer.peer_bindings.clear();
        let expected = graph("pnpm", vec![expected_renderer]);
        let actual = graph("lpm", vec![actual_renderer]);

        let report = compare(&expected, &actual);

        assert!(report.passed);
        assert_eq!(report.summary.required_peer_violations, 0);
        assert!(report.discrepancies.iter().any(|discrepancy| {
            discrepancy.severity == DiagnosticSeverity::Warning
                && discrepancy.category == "peer_binding_mismatch"
        }));
    }

    #[test]
    fn package_dependency_satisfies_same_named_peer_contract() {
        let mut expected_parent = package("parent", "1.0.0");
        expected_parent
            .declared_peers
            .insert("host".into(), "^1.0.0".into());
        expected_parent.peer_bindings.insert(
            "host".into(),
            TargetReference::package("host", "1.2.0", "host@1.2.0".into()),
        );
        expected_parent.id = "parent@1.0.0(host@1.2.0)".into();
        let mut actual_parent = package("parent", "1.0.0");
        actual_parent.dependencies.push(DependencyEdge {
            kind: DependencyKind::Production,
            local_name: "host".into(),
            specifier: None,
            target: TargetReference::package("host", "1.2.0", "host@1.2.0".into()),
        });
        let expected = graph("pnpm", vec![expected_parent, package("host", "1.2.0")]);
        let actual = graph("lpm", vec![actual_parent, package("host", "1.2.0")]);

        let report = compare(&expected, &actual);

        assert!(report.passed, "{:#?}", report.discrepancies);
        assert_eq!(report.summary.dependency_edge_mismatches, 0);
        assert_eq!(report.summary.required_peer_violations, 0);
    }

    #[test]
    fn package_dependency_is_equivalent_to_unbound_optional_peer() {
        let mut expected_parent = package("parent", "1.0.0");
        expected_parent
            .declared_peers
            .insert("optional-host".into(), "^1.0.0".into());
        expected_parent
            .optional_peers
            .insert("optional-host".into());
        let mut actual_parent = package("parent", "1.0.0");
        actual_parent.dependencies.push(DependencyEdge {
            kind: DependencyKind::Production,
            local_name: "optional-host".into(),
            specifier: None,
            target: TargetReference::package(
                "optional-host",
                "1.2.0",
                "optional-host@1.2.0".into(),
            ),
        });
        let expected = graph("pnpm", vec![expected_parent]);
        let actual = graph(
            "lpm",
            vec![actual_parent, package("optional-host", "1.2.0")],
        );

        let report = compare(&expected, &actual);

        assert!(report.passed, "{:#?}", report.discrepancies);
        assert_eq!(report.summary.dependency_edge_mismatches, 0);
    }

    #[test]
    fn package_self_dependency_does_not_change_runtime_topology() {
        let expected_parent = package("parent", "1.0.0");
        let mut actual_parent = expected_parent.clone();
        actual_parent.dependencies.push(DependencyEdge {
            kind: DependencyKind::Production,
            local_name: "parent".into(),
            specifier: None,
            target: TargetReference::package("parent", "1.0.0", "parent@1.0.0".into()),
        });
        let expected = graph("pnpm", vec![expected_parent]);
        let actual = graph("lpm", vec![actual_parent]);

        let report = compare(&expected, &actual);

        assert!(report.passed, "{:#?}", report.discrepancies);
        assert_eq!(report.summary.dependency_edge_mismatches, 0);
    }

    #[test]
    fn package_dependency_to_different_self_version_remains_topological() {
        let expected_parent = package("parent", "1.0.0");
        let mut actual_parent = expected_parent.clone();
        actual_parent.dependencies.push(DependencyEdge {
            kind: DependencyKind::Production,
            local_name: "parent".into(),
            specifier: None,
            target: TargetReference::package("parent", "2.0.0", "parent@2.0.0".into()),
        });
        let expected = graph("pnpm", vec![expected_parent]);
        let actual = graph("lpm", vec![actual_parent, package("parent", "2.0.0")]);

        let report = compare(&expected, &actual);

        assert!(!report.passed);
        assert_eq!(report.summary.dependency_edge_mismatches, 1);
    }

    #[test]
    fn peer_context_difference_does_not_hide_dependency_topology_failure() {
        let mut expected_parent = package("parent", "1.0.0");
        expected_parent.peer_bindings.insert(
            "peer".into(),
            TargetReference::package("peer", "1.0.0", "peer@1.0.0".into()),
        );
        expected_parent.dependencies.push(DependencyEdge {
            kind: DependencyKind::Production,
            local_name: "child".into(),
            specifier: None,
            target: TargetReference::package("child", "1.0.0", "child@1.0.0".into()),
        });
        let mut actual_parent = package("parent", "1.0.0");
        actual_parent.peer_bindings.insert(
            "peer".into(),
            TargetReference::package("peer", "2.0.0", "peer@2.0.0".into()),
        );
        let expected = graph("pnpm", vec![expected_parent, package("child", "1.0.0")]);
        let actual = graph("lpm", vec![actual_parent]);

        let report = compare(&expected, &actual);

        assert!(!report.passed);
        assert!(report.discrepancies.iter().any(|discrepancy| {
            discrepancy.severity == DiagnosticSeverity::Error
                && discrepancy.category == "dependency_edge_mismatch"
        }));
    }

    #[test]
    fn dependency_kind_difference_is_a_failure_when_both_formats_record_kinds() {
        let mut expected_parent = package("parent", "1.0.0");
        expected_parent.dependencies.push(DependencyEdge {
            kind: DependencyKind::Optional,
            local_name: "child".into(),
            specifier: None,
            target: TargetReference::package("child", "1.0.0", "child@1.0.0".into()),
        });
        let mut actual_parent = expected_parent.clone();
        actual_parent.dependencies[0].kind = DependencyKind::Production;
        let expected = graph("pnpm", vec![expected_parent, package("child", "1.0.0")]);
        let actual = graph("lpm", vec![actual_parent, package("child", "1.0.0")]);

        let report = compare(&expected, &actual);

        assert!(!report.passed);
        assert!(report.discrepancies.iter().any(|discrepancy| {
            discrepancy.severity == DiagnosticSeverity::Error
                && discrepancy.category == "dependency_edge_mismatch"
        }));
    }

    #[test]
    fn unsupported_alias_override_difference_is_an_explicit_compatibility_warning() {
        let mut expected_parent = package("parent", "1.0.0");
        expected_parent.dependencies.push(DependencyEdge {
            kind: DependencyKind::Production,
            local_name: "debug".into(),
            specifier: None,
            target: TargetReference::package("obug", "1.0.2", "obug@1.0.2".into()),
        });
        let mut actual_parent = expected_parent.clone();
        actual_parent.dependencies[0].target =
            TargetReference::package("debug", "4.4.3", "debug@4.4.3".into());
        let expected = graph("pnpm", vec![expected_parent, package("obug", "1.0.2")]);
        let actual = graph("lpm", vec![actual_parent, package("debug", "4.4.3")]);
        let policy = CompatibilityPolicy {
            overrides: BTreeMap::from([("debug".into(), "npm:obug@^1.0.2".into())]),
            ..CompatibilityPolicy::default()
        };

        let report = compare_with_policy(&expected, &actual, &policy);

        assert!(report.passed);
        assert!(report.discrepancies.iter().any(|discrepancy| {
            discrepancy.severity == DiagnosticSeverity::Warning
                && discrepancy.category == "unsupported_policy_dependency_edge_mismatch"
        }));
    }

    #[test]
    fn unsupported_package_extension_difference_is_an_explicit_compatibility_warning() {
        let mut expected_parent = package("parent", "1.0.0");
        expected_parent.dependencies.push(DependencyEdge {
            kind: DependencyKind::Production,
            local_name: "injected".into(),
            specifier: None,
            target: TargetReference::package("injected", "1.0.0", "injected@1.0.0".into()),
        });
        let expected = graph("pnpm", vec![expected_parent, package("injected", "1.0.0")]);
        let actual = graph("lpm", vec![package("parent", "1.0.0")]);
        let policy = CompatibilityPolicy {
            package_extensions: BTreeMap::from([(
                "parent".into(),
                serde_json::json!({"dependencies": {"injected": "^1"}}),
            )]),
            ..CompatibilityPolicy::default()
        };

        let report = compare_with_policy(&expected, &actual, &policy);

        assert!(report.passed);
        assert!(report.discrepancies.iter().any(|discrepancy| {
            discrepancy.severity == DiagnosticSeverity::Warning
                && discrepancy.category == "unsupported_policy_dependency_edge_mismatch"
        }));
    }

    #[test]
    fn pnpm_compatibility_database_extension_is_an_explicit_advisory() {
        let mut expected_parent = package("notistack", "3.0.2");
        expected_parent.dependencies.push(DependencyEdge {
            kind: DependencyKind::Production,
            local_name: "csstype".into(),
            specifier: None,
            target: TargetReference::package("csstype", "3.2.3", "csstype@3.2.3".into()),
        });
        let expected = graph("pnpm", vec![expected_parent, package("csstype", "3.2.3")]);
        let actual = graph("lpm", vec![package("notistack", "3.0.2")]);
        let policy = CompatibilityPolicy {
            pnpm_compatibility_database_extensions: BTreeMap::from([(
                "notistack@^3.0.0".into(),
                serde_json::json!({"dependencies": {"csstype": "^3.0.10"}}),
            )]),
            ..CompatibilityPolicy::default()
        };

        let report = compare_with_policy(&expected, &actual, &policy);

        assert!(report.passed);
        assert!(
            report
                .compatibility_gaps
                .iter()
                .any(|gap| { gap == "pnpmCompatibilityDatabaseExtension notistack@^3.0.0" })
        );
        assert!(report.discrepancies.iter().any(|discrepancy| {
            discrepancy.severity == DiagnosticSeverity::Warning
                && discrepancy.category == "unsupported_policy_dependency_edge_mismatch"
                && discrepancy.message.contains("pnpm compatibility database")
        }));
    }

    #[test]
    fn unsupported_workspace_override_peer_is_an_explicit_compatibility_warning() {
        let mut expected_parent = package("parent", "1.0.0");
        expected_parent
            .declared_peers
            .insert("vite".into(), "workspace:*".into());
        let expected = graph("pnpm", vec![expected_parent.clone()]);
        let actual = graph("lpm", vec![expected_parent]);
        let policy = CompatibilityPolicy {
            overrides: BTreeMap::from([("vite".into(), "workspace:*".into())]),
            ..CompatibilityPolicy::default()
        };

        let report = compare_with_policy(&expected, &actual, &policy);

        assert!(report.passed);
        assert_eq!(report.summary.required_peer_violations, 1);
        assert!(report.discrepancies.iter().any(|discrepancy| {
            discrepancy.severity == DiagnosticSeverity::Warning
                && discrepancy.category == "unsupported_policy_required_peer_missing"
        }));
    }

    #[test]
    fn reference_peer_override_makes_rewritten_range_inconclusive() {
        let mut expected_parent = package("parent", "1.0.0");
        expected_parent
            .declared_peers
            .insert("host".into(), "1.0.0".into());
        expected_parent.peer_bindings.insert(
            "host".into(),
            TargetReference::package("host", "1.0.0", "host@1.0.0".into()),
        );
        expected_parent.id = "parent@1.0.0(host@1.0.0)".into();
        let mut actual_parent = expected_parent.clone();
        actual_parent.peer_bindings.insert(
            "host".into(),
            TargetReference::package("host", "2.0.0", "host@2.0.0".into()),
        );
        actual_parent.id = "parent@1.0.0(host@2.0.0)".into();
        let expected = graph("pnpm", vec![expected_parent, package("host", "1.0.0")]);
        let actual = graph("lpm", vec![actual_parent, package("host", "2.0.0")]);
        let policy = CompatibilityPolicy {
            reference_peer_overrides: BTreeMap::from([("host".into(), "1.0.0".into())]),
            ..CompatibilityPolicy::default()
        };

        let report = compare_with_policy(&expected, &actual, &policy);

        assert!(report.passed, "{:#?}", report.discrepancies);
        assert!(report.discrepancies.iter().any(|discrepancy| {
            discrepancy.severity == DiagnosticSeverity::Warning
                && discrepancy.category == "inconclusive_override_rewritten_peer_range"
        }));
    }

    #[test]
    fn unsupported_policy_and_valid_version_selection_are_independent_advisories() {
        let mut expected_parent = package("parent", "1.0.0");
        expected_parent.dependencies.extend([
            DependencyEdge {
                kind: DependencyKind::Production,
                local_name: "debug".into(),
                specifier: None,
                target: TargetReference::package("obug", "1.0.2", "obug@1.0.2".into()),
            },
            DependencyEdge {
                kind: DependencyKind::Production,
                local_name: "sax".into(),
                specifier: None,
                target: TargetReference::package("sax", "1.6.1", "sax@1.6.1".into()),
            },
        ]);
        let mut actual_parent = expected_parent.clone();
        actual_parent.dependencies[0].target =
            TargetReference::package("debug", "4.4.3", "debug@4.4.3".into());
        actual_parent.dependencies[1].target =
            TargetReference::package("sax", "1.4.4", "sax@1.4.4".into());
        let expected = graph(
            "pnpm",
            vec![
                expected_parent,
                package("obug", "1.0.2"),
                package("sax", "1.6.1"),
            ],
        );
        let actual = graph(
            "lpm",
            vec![
                actual_parent,
                package("debug", "4.4.3"),
                package("sax", "1.4.4"),
            ],
        );
        let policy = CompatibilityPolicy {
            overrides: BTreeMap::from([("debug".into(), "npm:obug@^1.0.2".into())]),
            ..CompatibilityPolicy::default()
        };

        let report = compare_with_policy(&expected, &actual, &policy);

        assert!(report.passed);
        assert!(report.discrepancies.iter().any(|discrepancy| {
            discrepancy.category == "unsupported_policy_dependency_edge_mismatch"
        }));
        assert!(report.discrepancies.iter().any(|discrepancy| {
            discrepancy.category == "dependency_version_selection_mismatch"
        }));
    }
}
