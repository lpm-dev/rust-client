use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

pub const CANONICAL_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CanonicalGraph {
    pub schema_version: u32,
    pub manager: Manager,
    pub workspace: String,
    pub capabilities: Capabilities,
    pub importers: BTreeMap<String, ImporterGraph>,
    pub diagnostics: Vec<Diagnostic>,
    pub telemetry: GraphTelemetry,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Manager {
    pub name: String,
    pub lockfile_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct Capabilities {
    pub exact_importer_resolutions: bool,
    pub dependency_edges: bool,
    pub optional_dependency_edge_kinds: bool,
    pub resolved_peer_bindings: bool,
    pub declared_peer_ranges: bool,
    pub source_identity: bool,
    pub integrity: bool,
    pub platform_constraints: bool,
    pub optional_reachability: bool,
    pub workspace_links: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ImporterGraph {
    pub path: String,
    pub direct_dependencies: Vec<DependencyEdge>,
    pub packages: BTreeMap<String, PackageInstance>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PackageInstance {
    pub id: String,
    pub name: String,
    pub version: String,
    pub source: PackageSource,
    pub optional: Option<bool>,
    pub dev: Option<bool>,
    pub platform: PlatformConstraints,
    pub dependencies: Vec<DependencyEdge>,
    pub peer_bindings: BTreeMap<String, TargetReference>,
    pub declared_peers: BTreeMap<String, String>,
    pub optional_peers: BTreeSet<String>,
    pub patch_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct DependencyEdge {
    pub kind: DependencyKind,
    pub local_name: String,
    pub specifier: Option<String>,
    pub target: TargetReference,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum DependencyKind {
    Production,
    Development,
    Optional,
    Peer,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct TargetReference {
    pub kind: TargetKind,
    pub name: Option<String>,
    pub version: Option<String>,
    pub instance: Option<String>,
    pub path: Option<String>,
}

impl TargetReference {
    pub fn package(name: impl Into<String>, version: impl Into<String>, instance: String) -> Self {
        Self {
            kind: TargetKind::Package,
            name: Some(name.into()),
            version: Some(version.into()),
            instance: Some(instance),
            path: None,
        }
    }

    pub fn workspace(name: Option<String>, path: impl Into<String>) -> Self {
        Self {
            kind: TargetKind::Workspace,
            name,
            version: None,
            instance: None,
            path: Some(path.into()),
        }
    }

    pub fn unresolved(name: Option<String>, version: Option<String>) -> Self {
        Self {
            kind: TargetKind::Unresolved,
            name,
            version,
            instance: None,
            path: None,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum TargetKind {
    Package,
    Workspace,
    External,
    Unresolved,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct PackageSource {
    pub kind: Option<String>,
    pub locator: Option<String>,
    pub integrity: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct PlatformConstraints {
    pub os: Vec<String>,
    pub cpu: Vec<String>,
    pub libc: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Diagnostic {
    pub severity: DiagnosticSeverity,
    pub code: String,
    pub message: String,
    pub importer: Option<String>,
    pub subject: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticSeverity {
    Info,
    Warning,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct GraphTelemetry {
    pub importer_count: usize,
    pub package_instance_occurrences: usize,
    pub unique_package_identities: usize,
    pub unique_package_instances: usize,
    pub peer_context_instances: usize,
    pub peer_binding_count: usize,
    pub unresolved_edge_count: usize,
    pub workspace_link_count: usize,
}

impl CanonicalGraph {
    pub fn finalize(&mut self) {
        let mut identities = BTreeSet::new();
        let mut instances = BTreeSet::new();
        let mut occurrence_count = 0;
        let mut peer_context_instances = 0;
        let mut peer_binding_count = 0;
        let mut unresolved_edge_count = 0;
        let mut workspace_link_count = 0;

        for importer in self.importers.values_mut() {
            importer.direct_dependencies.sort();
            count_edges(
                &importer.direct_dependencies,
                &mut unresolved_edge_count,
                &mut workspace_link_count,
            );
            for package in importer.packages.values_mut() {
                package.dependencies.sort();
                occurrence_count += 1;
                identities.insert(format!("{}@{}", package.name, package.version));
                instances.insert(package.id.clone());
                peer_binding_count += package.peer_bindings.len();
                peer_context_instances += usize::from(!package.peer_bindings.is_empty());
                count_edges(
                    &package.dependencies,
                    &mut unresolved_edge_count,
                    &mut workspace_link_count,
                );
            }
        }

        self.diagnostics.sort_by(|left, right| {
            left.importer
                .cmp(&right.importer)
                .then_with(|| left.code.cmp(&right.code))
                .then_with(|| left.subject.cmp(&right.subject))
                .then_with(|| left.message.cmp(&right.message))
        });
        self.telemetry = GraphTelemetry {
            importer_count: self.importers.len(),
            package_instance_occurrences: occurrence_count,
            unique_package_identities: identities.len(),
            unique_package_instances: instances.len(),
            peer_context_instances,
            peer_binding_count,
            unresolved_edge_count,
            workspace_link_count,
        };
    }
}

fn count_edges(edges: &[DependencyEdge], unresolved: &mut usize, workspace: &mut usize) {
    for edge in edges {
        *unresolved += usize::from(edge.target.kind == TargetKind::Unresolved);
        *workspace += usize::from(edge.target.kind == TargetKind::Workspace);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finalize_deduplicates_identities_without_collapsing_importer_occurrences() {
        let package = PackageInstance {
            id: "react-dom@19.1.0(react@19.1.0)".into(),
            name: "react-dom".into(),
            version: "19.1.0".into(),
            source: PackageSource::default(),
            optional: None,
            dev: None,
            platform: PlatformConstraints::default(),
            dependencies: Vec::new(),
            peer_bindings: BTreeMap::from([(
                "react".into(),
                TargetReference::package("react", "19.1.0", "react@19.1.0".into()),
            )]),
            declared_peers: BTreeMap::new(),
            optional_peers: BTreeSet::new(),
            patch_hash: None,
        };
        let importer = |path: &str| ImporterGraph {
            path: path.into(),
            direct_dependencies: Vec::new(),
            packages: BTreeMap::from([(package.id.clone(), package.clone())]),
        };
        let mut graph = CanonicalGraph {
            schema_version: CANONICAL_SCHEMA_VERSION,
            manager: Manager {
                name: "test".into(),
                lockfile_version: "1".into(),
            },
            workspace: "fixture".into(),
            capabilities: Capabilities::default(),
            importers: BTreeMap::from([
                (".".into(), importer(".")),
                ("packages/app".into(), importer("packages/app")),
            ]),
            diagnostics: Vec::new(),
            telemetry: GraphTelemetry::default(),
        };

        graph.finalize();

        assert_eq!(graph.telemetry.package_instance_occurrences, 2);
        assert_eq!(graph.telemetry.unique_package_identities, 1);
        assert_eq!(graph.telemetry.unique_package_instances, 1);
        assert_eq!(graph.telemetry.peer_context_instances, 2);
    }
}
