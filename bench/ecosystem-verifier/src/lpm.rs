use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::Path;

use lpm_lockfile::{LockedPackage, Lockfile, Source};
use lpm_resolver::{NpmRange, NpmVersion, Specifier};

use crate::canonical::{
    CANONICAL_SCHEMA_VERSION, CanonicalGraph, Capabilities, DependencyEdge, DependencyKind,
    Diagnostic, DiagnosticSeverity, GraphTelemetry, ImporterGraph, Manager, PackageInstance,
    PackageSource, PlatformConstraints, TargetKind, TargetReference,
};
use crate::error::{Result, VerifierError};
use crate::workspace::{
    canonical_workspace, discover_files, discover_workspace_packages, normalize_relative_path,
    relative_path,
};

pub fn normalize(workspace: &Path) -> Result<CanonicalGraph> {
    let workspace = canonical_workspace(workspace)?;
    let lockfiles = discover_files(&workspace, lpm_lockfile::LOCKFILE_NAME)?;
    if lockfiles.is_empty() {
        return Err(VerifierError::NoLpmLockfiles { path: workspace });
    }
    let workspace_packages = discover_workspace_packages(&workspace)?;
    let mut versions = BTreeSet::new();
    let mut graph = CanonicalGraph {
        schema_version: CANONICAL_SCHEMA_VERSION,
        manager: Manager {
            name: "lpm".into(),
            lockfile_version: String::new(),
        },
        workspace: workspace.display().to_string(),
        capabilities: Capabilities {
            exact_importer_resolutions: true,
            dependency_edges: true,
            optional_dependency_edge_kinds: false,
            resolved_peer_bindings: true,
            declared_peer_ranges: false,
            source_identity: true,
            integrity: true,
            platform_constraints: true,
            optional_reachability: true,
            workspace_links: true,
        },
        importers: BTreeMap::new(),
        diagnostics: Vec::new(),
        telemetry: GraphTelemetry::default(),
    };

    for lockfile_path in lockfiles {
        let lockfile = Lockfile::read_from_file(&lockfile_path).map_err(|error| {
            VerifierError::LpmLockfile {
                path: lockfile_path.clone(),
                message: error.to_string(),
            }
        })?;
        versions.insert(lockfile.metadata.lockfile_version);
        let directory = lockfile_path
            .parent()
            .expect("discovered lpm.lock has a parent");
        let importer_path = relative_path(&workspace, directory);
        graph.capabilities.exact_importer_resolutions &=
            importer_has_exact_package_resolutions(&lockfile);
        let (importer, mut diagnostics) =
            normalize_importer(&importer_path, &lockfile, &workspace_packages);
        graph.diagnostics.append(&mut diagnostics);
        if graph
            .importers
            .insert(importer_path.clone(), importer)
            .is_some()
        {
            graph.diagnostics.push(Diagnostic {
                severity: DiagnosticSeverity::Error,
                code: "duplicate_lpm_importer".into(),
                message: format!("multiple lpm.lock files normalized as importer {importer_path}"),
                importer: Some(importer_path.clone()),
                subject: Some(lockfile_path.display().to_string()),
            });
        }
    }
    graph.manager.lockfile_version = versions
        .iter()
        .map(u32::to_string)
        .collect::<Vec<_>>()
        .join(",");
    graph.finalize();
    Ok(graph)
}

fn importer_has_exact_package_resolutions(lockfile: &Lockfile) -> bool {
    let Some(importer) = lockfile.importers.get(".") else {
        return false;
    };
    importer
        .dependencies
        .iter()
        .chain(&importer.dev_dependencies)
        .chain(&importer.optional_dependencies)
        .all(|(local_name, specifier)| {
            matches!(
                Specifier::parse(specifier),
                Ok(Specifier::Workspace(_) | Specifier::File { .. } | Specifier::Link { .. })
            ) || lockfile.root_resolutions.contains_key(local_name)
        })
        && lockfile.ambient_peer_installs.iter().all(|reference| {
            split_name_version(reference)
                .is_some_and(|(name, _)| lockfile.root_resolutions.contains_key(name))
        })
}

fn normalize_importer(
    importer_path: &str,
    lockfile: &Lockfile,
    workspace_packages: &BTreeMap<String, String>,
) -> (ImporterGraph, Vec<Diagnostic>) {
    let mut diagnostics = Vec::new();
    let mut package_ids = BTreeMap::<(String, String), Vec<String>>::new();
    let mut package_templates = Vec::with_capacity(lockfile.packages.len());
    for package in &lockfile.packages {
        let id = lpm_instance_id(package);
        package_ids
            .entry((package.name.clone(), package.version.clone()))
            .or_default()
            .push(id.clone());
        package_templates.push((id, package));
    }
    for ids in package_ids.values_mut() {
        ids.sort();
        ids.dedup();
    }

    let mut packages = BTreeMap::new();
    for (id, package) in package_templates {
        let dependencies = lpm_package_edges(
            importer_path,
            package,
            &package_ids,
            workspace_packages,
            &mut diagnostics,
        );
        let peer_bindings = parse_peer_bindings(
            importer_path,
            package,
            &package_ids,
            workspace_packages,
            &mut diagnostics,
        );
        let patch_hash = lockfile
            .patches
            .get(&format!("{}@{}", package.name, package.version))
            .map(|patch| patch.sha256.clone());
        let instance = PackageInstance {
            id: id.clone(),
            name: package.name.clone(),
            version: package.version.clone(),
            source: lpm_source(package),
            optional: Some(package.optional),
            dev: None,
            platform: PlatformConstraints {
                os: sorted(package.os.clone()),
                cpu: sorted(package.cpu.clone()),
                libc: sorted(package.libc.clone()),
            },
            dependencies,
            peer_bindings,
            declared_peers: BTreeMap::new(),
            optional_peers: BTreeSet::new(),
            patch_hash,
        };
        if let Some(previous) = packages.insert(id.clone(), instance)
            && previous != packages[&id]
        {
            diagnostics.push(Diagnostic {
                severity: DiagnosticSeverity::Error,
                code: "lpm_instance_identity_collision".into(),
                message: "two locked packages share an instance identity but differ in content"
                    .into(),
                importer: Some(importer_path.into()),
                subject: Some(id),
            });
        }
    }

    let importer_snapshot = lockfile.importers.get(".");
    let mut direct_dependencies = importer_snapshot.map_or_else(Vec::new, |snapshot| {
        let capacity = snapshot.dependencies.len()
            + snapshot.dev_dependencies.len()
            + snapshot.optional_dependencies.len()
            + lockfile.ambient_peer_installs.len();
        let mut edges = Vec::with_capacity(capacity);
        append_direct_edges(
            &mut edges,
            importer_path,
            &snapshot.dependencies,
            DependencyKind::Production,
            lockfile,
            &package_ids,
            workspace_packages,
            &mut diagnostics,
        );
        append_direct_edges(
            &mut edges,
            importer_path,
            &snapshot.dev_dependencies,
            DependencyKind::Development,
            lockfile,
            &package_ids,
            workspace_packages,
            &mut diagnostics,
        );
        append_direct_edges(
            &mut edges,
            importer_path,
            &snapshot.optional_dependencies,
            DependencyKind::Optional,
            lockfile,
            &package_ids,
            workspace_packages,
            &mut diagnostics,
        );
        edges
    });
    deduplicate_importer_edges(&mut direct_dependencies);
    append_ambient_peer_edges(
        &mut direct_dependencies,
        importer_path,
        lockfile,
        &package_ids,
        workspace_packages,
        &mut diagnostics,
    );
    retain_reachable_packages(&mut packages, &direct_dependencies, &package_ids);

    (
        ImporterGraph {
            path: importer_path.into(),
            direct_dependencies,
            packages,
        },
        diagnostics,
    )
}

fn deduplicate_importer_edges(edges: &mut Vec<DependencyEdge>) {
    let mut by_name = BTreeMap::<String, DependencyEdge>::new();
    for edge in edges.drain(..) {
        match by_name.entry(edge.local_name.clone()) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(edge);
            }
            std::collections::btree_map::Entry::Occupied(mut entry)
                if dependency_kind_precedence(edge.kind)
                    > dependency_kind_precedence(entry.get().kind) =>
            {
                entry.insert(edge);
            }
            std::collections::btree_map::Entry::Occupied(_) => {}
        }
    }
    edges.extend(by_name.into_values());
}

fn dependency_kind_precedence(kind: DependencyKind) -> u8 {
    match kind {
        DependencyKind::Optional => 3,
        DependencyKind::Production => 2,
        DependencyKind::Development => 1,
        DependencyKind::Peer => 0,
    }
}

fn append_ambient_peer_edges(
    edges: &mut Vec<DependencyEdge>,
    importer_path: &str,
    lockfile: &Lockfile,
    package_ids: &BTreeMap<(String, String), Vec<String>>,
    workspace_packages: &BTreeMap<String, String>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let mut linked_names = edges
        .iter()
        .map(|edge| edge.local_name.clone())
        .collect::<BTreeSet<_>>();
    for reference in &lockfile.ambient_peer_installs {
        let Some(selection) = lockfile.root_resolutions.get(reference) else {
            diagnostics.push(Diagnostic {
                severity: DiagnosticSeverity::Error,
                code: "lpm_ambient_peer_selection_missing".into(),
                message: "ambient peer install has no exact root resolution".into(),
                importer: Some(importer_path.into()),
                subject: Some(reference.clone()),
            });
            continue;
        };
        if !linked_names.insert(reference.clone()) {
            continue;
        }
        edges.push(DependencyEdge {
            kind: DependencyKind::Production,
            local_name: reference.clone(),
            specifier: Some(selection.version.clone()),
            target: direct_target(
                importer_path,
                reference,
                &selection.package,
                &selection.version,
                lockfile,
                package_ids,
                workspace_packages,
                diagnostics,
            ),
        });
    }
}

fn retain_reachable_packages(
    packages: &mut BTreeMap<String, PackageInstance>,
    direct_dependencies: &[DependencyEdge],
    package_ids: &BTreeMap<(String, String), Vec<String>>,
) {
    let mut pending = VecDeque::new();
    for edge in direct_dependencies {
        enqueue_target(&edge.target, package_ids, &mut pending);
    }
    let mut reachable = BTreeSet::new();
    while let Some(id) = pending.pop_front() {
        if !reachable.insert(id.clone()) {
            continue;
        }
        let Some(package) = packages.get(&id) else {
            continue;
        };
        for edge in &package.dependencies {
            enqueue_target(&edge.target, package_ids, &mut pending);
        }
        for target in package.peer_bindings.values() {
            enqueue_target(target, package_ids, &mut pending);
        }
    }
    packages.retain(|id, _| reachable.contains(id));
}

fn enqueue_target(
    target: &TargetReference,
    package_ids: &BTreeMap<(String, String), Vec<String>>,
    pending: &mut VecDeque<String>,
) {
    if let Some(instance) = &target.instance {
        pending.push_back(instance.clone());
        return;
    }
    if target.kind != TargetKind::Unresolved {
        return;
    }
    let (Some(name), Some(version)) = (&target.name, &target.version) else {
        return;
    };
    if let Some(ids) = package_ids.get(&(name.clone(), version.clone())) {
        pending.extend(ids.iter().cloned());
    }
}

#[allow(clippy::too_many_arguments)]
fn append_direct_edges(
    edges: &mut Vec<DependencyEdge>,
    importer_path: &str,
    dependencies: &BTreeMap<String, String>,
    kind: DependencyKind,
    lockfile: &Lockfile,
    package_ids: &BTreeMap<(String, String), Vec<String>>,
    workspace_packages: &BTreeMap<String, String>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    for (local_name, specifier) in dependencies {
        let target_name = lockfile
            .root_aliases
            .get(local_name)
            .cloned()
            .unwrap_or_else(|| alias_target(local_name, specifier));
        let target = direct_target(
            importer_path,
            local_name,
            &target_name,
            specifier,
            lockfile,
            package_ids,
            workspace_packages,
            diagnostics,
        );
        edges.push(DependencyEdge {
            kind,
            local_name: local_name.clone(),
            specifier: Some(specifier.clone()),
            target,
        });
    }
}

#[allow(clippy::too_many_arguments)]
fn direct_target(
    importer_path: &str,
    local_name: &str,
    target_name: &str,
    specifier: &str,
    lockfile: &Lockfile,
    package_ids: &BTreeMap<(String, String), Vec<String>>,
    workspace_packages: &BTreeMap<String, String>,
    diagnostics: &mut Vec<Diagnostic>,
) -> TargetReference {
    if specifier.starts_with("workspace:") {
        return workspace_packages.get(target_name).map_or_else(
            || {
                unresolved_edge(
                    importer_path,
                    local_name,
                    Some(target_name),
                    None,
                    "workspace package name is not present in discovered manifests",
                    diagnostics,
                )
            },
            |path| TargetReference::workspace(Some(target_name.into()), path.clone()),
        );
    }
    if let Some(path) = specifier.strip_prefix("link:") {
        let normalized = normalize_relative_path(importer_path, path);
        let workspace_name = workspace_packages
            .iter()
            .find_map(|(name, package_path)| (package_path == &normalized).then_some(name.clone()));
        return TargetReference::workspace(workspace_name, normalized);
    }
    if let Some(path) = specifier.strip_prefix("file:") {
        let normalized_path = normalize_relative_path(importer_path, path);
        let target_name = workspace_packages.iter().find_map(|(name, package_path)| {
            (package_path == &normalized_path).then_some(name.clone())
        });
        return TargetReference {
            kind: TargetKind::External,
            name: target_name,
            version: None,
            instance: None,
            path: Some(format!("file:{normalized_path}")),
        };
    }

    if let Some(selection) = lockfile.root_resolutions.get(local_name) {
        if selection.package != target_name {
            return unresolved_edge(
                importer_path,
                local_name,
                Some(target_name),
                Some(&selection.version),
                "exact root selection disagrees with the importer target",
                diagnostics,
            );
        }
        let mut matches = lockfile.packages.iter().filter(|package| {
            package.name == selection.package
                && package.version == selection.version
                && package.source == selection.source
        });
        let Some(package) = matches.next() else {
            return unresolved_edge(
                importer_path,
                local_name,
                Some(target_name),
                Some(&selection.version),
                "exact root selection is absent from the lockfile package closure",
                diagnostics,
            );
        };
        if matches.next().is_some() {
            return unresolved_edge(
                importer_path,
                local_name,
                Some(target_name),
                Some(&selection.version),
                "exact root selection matches multiple locked package rows",
                diagnostics,
            );
        }
        return TargetReference::package(&package.name, &package.version, lpm_instance_id(package));
    }

    let catalog_version = catalog_resolution(lockfile, local_name, specifier);
    let range = match Specifier::parse(specifier) {
        Ok(Specifier::NpmAlias { range, .. }) => Some(range),
        Ok(Specifier::SemverRange(range)) => Some(range),
        Ok(Specifier::Workspace(_)) => None,
        Ok(_) | Err(_) => None,
    };
    let candidates: Vec<&LockedPackage> = lockfile
        .packages
        .iter()
        .filter(|package| package.name == target_name)
        .collect();
    let selected = catalog_version
        .as_deref()
        .and_then(|version| {
            candidates
                .iter()
                .copied()
                .find(|package| package.version == version)
        })
        .or_else(|| select_satisfying_candidate(&candidates, range.as_deref()))
        .or_else(|| (candidates.len() == 1).then(|| candidates[0]));
    let Some(package) = selected else {
        return unresolved_edge(
            importer_path,
            local_name,
            Some(target_name),
            None,
            "no unique locked package satisfies the importer specifier",
            diagnostics,
        );
    };
    exact_target(
        importer_path,
        local_name,
        &package.name,
        &package.version,
        package_ids,
        workspace_packages,
        diagnostics,
    )
}

fn lpm_package_edges(
    importer_path: &str,
    package: &LockedPackage,
    package_ids: &BTreeMap<(String, String), Vec<String>>,
    workspace_packages: &BTreeMap<String, String>,
    diagnostics: &mut Vec<Diagnostic>,
) -> Vec<DependencyEdge> {
    let aliases: BTreeMap<&str, &str> = package
        .alias_dependencies
        .iter()
        .map(|entry| (entry[0].as_str(), entry[1].as_str()))
        .collect();
    let peer_names = package
        .peers
        .iter()
        .filter_map(|raw| split_name_version(raw).map(|(name, _)| name))
        .collect::<BTreeSet<_>>();
    let mut edges = Vec::with_capacity(package.dependencies.len());
    for raw in &package.dependencies {
        let Some((local_name, version)) = split_name_version(raw) else {
            edges.push(DependencyEdge {
                kind: DependencyKind::Production,
                local_name: raw.clone(),
                specifier: None,
                target: unresolved_edge(
                    importer_path,
                    raw,
                    None,
                    None,
                    "locked dependency is not name@version",
                    diagnostics,
                ),
            });
            continue;
        };
        if peer_names.contains(local_name) {
            continue;
        }
        let target_name = aliases.get(local_name).copied().unwrap_or(local_name);
        edges.push(DependencyEdge {
            kind: DependencyKind::Production,
            local_name: local_name.into(),
            specifier: None,
            target: exact_target(
                importer_path,
                local_name,
                target_name,
                version,
                package_ids,
                workspace_packages,
                diagnostics,
            ),
        });
    }
    edges
}

fn parse_peer_bindings(
    importer_path: &str,
    package: &LockedPackage,
    package_ids: &BTreeMap<(String, String), Vec<String>>,
    workspace_packages: &BTreeMap<String, String>,
    diagnostics: &mut Vec<Diagnostic>,
) -> BTreeMap<String, TargetReference> {
    let mut peers = BTreeMap::new();
    for raw in &package.peers {
        let Some((name, version)) = split_name_version(raw) else {
            diagnostics.push(Diagnostic {
                severity: DiagnosticSeverity::Error,
                code: "lpm_peer_binding_unparseable".into(),
                message: "locked peer binding is not name@version".into(),
                importer: Some(importer_path.into()),
                subject: Some(raw.clone()),
            });
            continue;
        };
        peers.insert(
            name.into(),
            exact_target(
                importer_path,
                name,
                name,
                version,
                package_ids,
                workspace_packages,
                diagnostics,
            ),
        );
    }
    peers
}

fn exact_target(
    importer_path: &str,
    local_name: &str,
    target_name: &str,
    version: &str,
    package_ids: &BTreeMap<(String, String), Vec<String>>,
    workspace_packages: &BTreeMap<String, String>,
    diagnostics: &mut Vec<Diagnostic>,
) -> TargetReference {
    let key = (target_name.to_string(), version.to_string());
    match package_ids.get(&key).map(Vec::as_slice) {
        Some([id]) => TargetReference::package(target_name, version, id.clone()),
        Some(ids) => unresolved_edge(
            importer_path,
            local_name,
            Some(target_name),
            Some(version),
            &format!(
                "{} package instances share this name and version",
                ids.len()
            ),
            diagnostics,
        ),
        None => workspace_packages.get(target_name).map_or_else(
            || {
                unresolved_edge(
                    importer_path,
                    local_name,
                    Some(target_name),
                    Some(version),
                    "dependency target is absent from the importer lock closure",
                    diagnostics,
                )
            },
            |path| TargetReference::workspace(Some(target_name.into()), path.clone()),
        ),
    }
}

fn unresolved_edge(
    importer_path: &str,
    local_name: &str,
    target_name: Option<&str>,
    version: Option<&str>,
    reason: &str,
    diagnostics: &mut Vec<Diagnostic>,
) -> TargetReference {
    diagnostics.push(Diagnostic {
        severity: DiagnosticSeverity::Error,
        code: "lpm_edge_unresolved".into(),
        message: reason.into(),
        importer: Some(importer_path.into()),
        subject: Some(local_name.into()),
    });
    TargetReference::unresolved(target_name.map(str::to_string), version.map(str::to_string))
}

fn select_satisfying_candidate<'a>(
    candidates: &[&'a LockedPackage],
    range: Option<&str>,
) -> Option<&'a LockedPackage> {
    let range = NpmRange::parse(range?).ok()?;
    candidates
        .iter()
        .filter_map(|package| {
            let version = NpmVersion::parse(&package.version).ok()?;
            range.satisfies(&version).then_some((version, *package))
        })
        .max_by(|left, right| left.0.cmp(&right.0))
        .map(|(_, package)| package)
}

fn catalog_resolution(lockfile: &Lockfile, name: &str, specifier: &str) -> Option<String> {
    lockfile.catalogs.values().find_map(|entries| {
        entries
            .get(name)
            .filter(|entry| entry.reference == specifier)
            .map(|entry| entry.version.clone())
    })
}

fn alias_target(local_name: &str, specifier: &str) -> String {
    match Specifier::parse(specifier) {
        Ok(Specifier::NpmAlias { target, .. }) => target,
        _ => local_name.into(),
    }
}

fn lpm_instance_id(package: &LockedPackage) -> String {
    let mut id = format!("{}@{}", package.name, package.version);
    let mut peers = package.peers.clone();
    peers.sort();
    for peer in peers {
        id.push('(');
        id.push_str(&peer);
        id.push(')');
    }
    if let Some(source) = package.source.as_deref()
        && !source
            .trim_end_matches('/')
            .eq_ignore_ascii_case("registry+https://registry.npmjs.org")
    {
        id.push_str("[source=");
        id.push_str(source);
        id.push(']');
    }
    id
}

fn lpm_source(package: &LockedPackage) -> PackageSource {
    let (kind, locator) = package
        .source
        .as_deref()
        .and_then(|raw| Source::parse(raw).ok())
        .map_or((None, package.source.clone()), |source| match source {
            Source::Registry { url } => (
                Some("registry".into()),
                Some(url.trim_end_matches('/').to_string()),
            ),
            Source::Tarball { url } => (Some("tarball".into()), Some(url)),
            Source::Directory { path } => (Some("directory".into()), Some(path)),
            Source::Link { path } => (Some("link".into()), Some(path)),
            Source::Git { url } => (Some("git".into()), Some(url)),
        });
    PackageSource {
        kind,
        locator,
        integrity: package.integrity.clone(),
    }
}

fn split_name_version(reference: &str) -> Option<(&str, &str)> {
    let position = reference
        .char_indices()
        .rev()
        .find(|(index, character)| *character == '@' && *index > 0)
        .map(|(index, _)| index)?;
    let version = &reference[position + 1..];
    (!version.is_empty()).then_some((&reference[..position], version))
}

fn sorted(mut values: Vec<String>) -> Vec<String> {
    values.sort();
    values
}

#[cfg(test)]
mod tests {
    use crate::canonical::TargetKind;
    use lpm_lockfile::{ImporterSnapshot, LockfileMetadata};

    use super::*;

    fn registry_package(name: &str, version: &str) -> LockedPackage {
        LockedPackage {
            name: name.into(),
            version: version.into(),
            source: Some("registry+https://registry.npmjs.org".into()),
            integrity: Some(format!("sha512-{name}")),
            ..LockedPackage::default()
        }
    }

    #[test]
    fn normalization_keeps_alias_peer_and_workspace_targets_importer_scoped() {
        let mut react = registry_package("react", "19.1.0");
        let mut renderer = registry_package("react-dom", "19.1.0");
        renderer.dependencies.push("scheduler@0.26.0".into());
        renderer.dependencies.push("react@19.1.0".into());
        renderer.peers.push("react@19.1.0".into());
        let scheduler = registry_package("scheduler", "0.26.0");
        let unused = registry_package("workspace-materialization-only", "1.0.0");
        let lockfile = Lockfile {
            metadata: LockfileMetadata {
                lockfile_version: 7,
                resolved_with: Some("greedy-fusion".into()),
                auto_isolated_peer_conflicts: false,
            },
            importers: BTreeMap::from([(
                ".".into(),
                ImporterSnapshot {
                    dependencies: BTreeMap::from([
                        ("app".into(), "workspace:*".into()),
                        ("react".into(), "^19.0.0".into()),
                        ("renderer".into(), "npm:react-dom@^19.0.0".into()),
                    ]),
                    ..ImporterSnapshot::default()
                },
            )]),
            patches: BTreeMap::new(),
            catalogs: BTreeMap::new(),
            provenance: BTreeMap::new(),
            packages: vec![react.clone(), renderer, scheduler, unused],
            root_aliases: BTreeMap::from([("renderer".into(), "react-dom".into())]),
            root_resolutions: BTreeMap::new(),
            ambient_peer_installs: Vec::new(),
        };
        react.dependencies.clear();
        let workspace_packages = BTreeMap::from([("app".into(), "packages/app".into())]);

        let (importer, diagnostics) = normalize_importer(".", &lockfile, &workspace_packages);

        assert!(diagnostics.is_empty(), "{diagnostics:#?}");
        assert_eq!(importer.packages.len(), 3);
        assert!(
            !importer
                .packages
                .contains_key("workspace-materialization-only@1.0.0")
        );
        let alias = importer
            .direct_dependencies
            .iter()
            .find(|edge| edge.local_name == "renderer")
            .expect("alias dependency");
        assert_eq!(alias.target.name.as_deref(), Some("react-dom"));
        let app = importer
            .direct_dependencies
            .iter()
            .find(|edge| edge.local_name == "app")
            .expect("workspace dependency");
        assert_eq!(app.target.kind, TargetKind::Workspace);
        assert_eq!(app.target.path.as_deref(), Some("packages/app"));
        let renderer = importer
            .packages
            .get("react-dom@19.1.0(react@19.1.0)")
            .expect("renderer instance");
        assert_eq!(
            renderer.peer_bindings["react"].instance.as_deref(),
            Some("react@19.1.0")
        );
        assert_eq!(
            renderer
                .dependencies
                .iter()
                .map(|edge| edge.local_name.as_str())
                .collect::<Vec<_>>(),
            vec!["scheduler"]
        );
    }

    #[test]
    fn exact_root_selection_wins_over_newer_satisfying_locked_version() {
        let source = "registry+https://registry.npmjs.org";
        let lockfile = Lockfile {
            metadata: LockfileMetadata {
                lockfile_version: lpm_lockfile::LOCKFILE_VERSION,
                resolved_with: Some("greedy-fusion".into()),
                auto_isolated_peer_conflicts: false,
            },
            importers: BTreeMap::from([(
                ".".into(),
                ImporterSnapshot {
                    dependencies: BTreeMap::from([("peer-host".into(), "^1.0.0".into())]),
                    ..ImporterSnapshot::default()
                },
            )]),
            packages: vec![
                registry_package("peer-host", "1.0.0"),
                registry_package("peer-host", "1.1.0"),
            ],
            root_resolutions: BTreeMap::from([(
                "peer-host".into(),
                lpm_lockfile::LockedRootResolution {
                    package: "peer-host".into(),
                    version: "1.0.0".into(),
                    source: Some(source.into()),
                },
            )]),
            ..Lockfile::default()
        };

        let (importer, diagnostics) = normalize_importer(".", &lockfile, &BTreeMap::new());

        assert!(diagnostics.is_empty(), "{diagnostics:#?}");
        assert_eq!(
            importer.direct_dependencies[0].target.version.as_deref(),
            Some("1.0.0")
        );
    }

    #[test]
    fn ambient_peer_install_normalizes_as_a_direct_production_edge() {
        let source = "registry+https://registry.npmjs.org";
        let lockfile = Lockfile {
            metadata: LockfileMetadata {
                lockfile_version: lpm_lockfile::LOCKFILE_VERSION,
                resolved_with: Some("greedy-fusion".into()),
                auto_isolated_peer_conflicts: false,
            },
            importers: BTreeMap::from([(".".into(), ImporterSnapshot::default())]),
            packages: vec![registry_package("react", "19.2.8")],
            root_resolutions: BTreeMap::from([(
                "react".into(),
                lpm_lockfile::LockedRootResolution {
                    package: "react".into(),
                    version: "19.2.8".into(),
                    source: Some(source.into()),
                },
            )]),
            ambient_peer_installs: vec!["react".into()],
            ..Lockfile::default()
        };

        let (importer, diagnostics) = normalize_importer(".", &lockfile, &BTreeMap::new());

        assert!(diagnostics.is_empty(), "{diagnostics:#?}");
        assert_eq!(
            importer.direct_dependencies,
            vec![DependencyEdge {
                kind: DependencyKind::Production,
                local_name: "react".into(),
                specifier: Some("19.2.8".into()),
                target: TargetReference::package("react", "19.2.8", "react@19.2.8".into()),
            }],
        );
    }

    #[test]
    fn ambient_peer_without_exact_root_resolution_is_reported_as_unresolved() {
        let lockfile = Lockfile {
            metadata: LockfileMetadata {
                lockfile_version: lpm_lockfile::LOCKFILE_VERSION,
                resolved_with: Some("greedy-fusion".into()),
                auto_isolated_peer_conflicts: false,
            },
            importers: BTreeMap::from([(".".into(), ImporterSnapshot::default())]),
            packages: vec![registry_package("react", "19.2.8")],
            ambient_peer_installs: vec!["react".into()],
            ..Lockfile::default()
        };

        let (importer, diagnostics) = normalize_importer(".", &lockfile, &BTreeMap::new());

        assert!(importer.direct_dependencies.is_empty());
        assert_eq!(diagnostics[0].code, "lpm_ambient_peer_selection_missing");
    }

    #[test]
    fn duplicate_importer_sections_keep_the_runtime_dependency_kind() {
        let lockfile = Lockfile {
            metadata: LockfileMetadata {
                lockfile_version: lpm_lockfile::LOCKFILE_VERSION,
                resolved_with: Some("greedy-fusion".into()),
                auto_isolated_peer_conflicts: false,
            },
            importers: BTreeMap::from([(
                ".".into(),
                ImporterSnapshot {
                    dependencies: BTreeMap::from([("shared".into(), "1.0.0".into())]),
                    dev_dependencies: BTreeMap::from([("shared".into(), "1.0.0".into())]),
                    ..ImporterSnapshot::default()
                },
            )]),
            packages: vec![registry_package("shared", "1.0.0")],
            root_resolutions: BTreeMap::from([(
                "shared".into(),
                lpm_lockfile::LockedRootResolution {
                    package: "shared".into(),
                    version: "1.0.0".into(),
                    source: Some("registry+https://registry.npmjs.org".into()),
                },
            )]),
            ..Lockfile::default()
        };

        let (importer, diagnostics) = normalize_importer(".", &lockfile, &BTreeMap::new());

        assert!(diagnostics.is_empty(), "{diagnostics:#?}");
        assert_eq!(importer.direct_dependencies.len(), 1);
        assert_eq!(
            importer.direct_dependencies[0].kind,
            DependencyKind::Production,
        );
    }

    #[test]
    fn duplicate_name_version_peer_variants_make_edges_explicitly_unresolved() {
        let react = registry_package("react", "19.1.0");
        let mut first = registry_package("plugin", "1.0.0");
        first.peers.push("react@19.1.0".into());
        let mut second = registry_package("plugin", "1.0.0");
        second.peers.push("react@18.3.1".into());
        let mut parent = registry_package("parent", "1.0.0");
        parent.dependencies.push("plugin@1.0.0".into());
        let lockfile = Lockfile {
            metadata: LockfileMetadata {
                lockfile_version: 7,
                resolved_with: None,
                auto_isolated_peer_conflicts: false,
            },
            importers: BTreeMap::from([(
                ".".into(),
                ImporterSnapshot {
                    dependencies: BTreeMap::from([("parent".into(), "*".into())]),
                    ..ImporterSnapshot::default()
                },
            )]),
            patches: BTreeMap::new(),
            catalogs: BTreeMap::new(),
            provenance: BTreeMap::new(),
            packages: vec![first, parent, react, second],
            root_aliases: BTreeMap::new(),
            root_resolutions: BTreeMap::new(),
            ambient_peer_installs: Vec::new(),
        };

        let (importer, diagnostics) = normalize_importer(".", &lockfile, &BTreeMap::new());

        let parent = importer.packages.get("parent@1.0.0").expect("parent");
        assert_eq!(parent.dependencies[0].target.kind, TargetKind::Unresolved);
        assert!(
            diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "lpm_edge_unresolved")
        );
    }

    #[test]
    fn missing_direct_target_is_reported_as_unresolved_without_panicking() {
        let lockfile = Lockfile {
            metadata: LockfileMetadata {
                lockfile_version: 7,
                resolved_with: None,
                auto_isolated_peer_conflicts: false,
            },
            importers: BTreeMap::from([(
                ".".into(),
                ImporterSnapshot {
                    dependencies: BTreeMap::from([("missing".into(), "^1.0.0".into())]),
                    ..ImporterSnapshot::default()
                },
            )]),
            patches: BTreeMap::new(),
            catalogs: BTreeMap::new(),
            provenance: BTreeMap::new(),
            packages: Vec::new(),
            root_aliases: BTreeMap::new(),
            root_resolutions: BTreeMap::new(),
            ambient_peer_installs: Vec::new(),
        };

        let (importer, diagnostics) = normalize_importer(".", &lockfile, &BTreeMap::new());

        assert_eq!(
            importer.direct_dependencies[0].target.kind,
            TargetKind::Unresolved
        );
        assert!(
            diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "lpm_edge_unresolved")
        );
    }

    #[test]
    fn empty_lockfile_without_importer_snapshot_normalizes_as_an_empty_importer() {
        let lockfile = Lockfile {
            metadata: LockfileMetadata {
                lockfile_version: 7,
                resolved_with: Some("greedy-fusion".into()),
                auto_isolated_peer_conflicts: false,
            },
            ..Lockfile::default()
        };

        let (importer, diagnostics) =
            normalize_importer("fixtures/empty", &lockfile, &BTreeMap::new());

        assert!(importer.direct_dependencies.is_empty());
        assert!(diagnostics.is_empty(), "{diagnostics:#?}");
    }

    #[test]
    fn importer_peer_declarations_are_not_materialized_as_direct_edges() {
        let lockfile = Lockfile {
            metadata: LockfileMetadata {
                lockfile_version: 7,
                resolved_with: Some("greedy-fusion".into()),
                auto_isolated_peer_conflicts: false,
            },
            importers: BTreeMap::from([(
                ".".into(),
                ImporterSnapshot {
                    peer_dependencies: BTreeMap::from([("vite".into(), "^8.0.0".into())]),
                    ..ImporterSnapshot::default()
                },
            )]),
            ..Lockfile::default()
        };

        let (importer, diagnostics) = normalize_importer(".", &lockfile, &BTreeMap::new());

        assert!(importer.direct_dependencies.is_empty());
        assert!(diagnostics.is_empty(), "{diagnostics:#?}");
    }

    #[test]
    fn file_dependency_is_external_with_a_workspace_root_relative_path() {
        let lockfile = Lockfile {
            metadata: LockfileMetadata {
                lockfile_version: 7,
                resolved_with: Some("greedy-fusion".into()),
                auto_isolated_peer_conflicts: false,
            },
            importers: BTreeMap::from([(
                ".".into(),
                ImporterSnapshot {
                    dependencies: BTreeMap::from([(
                        "aliased-module".into(),
                        "file:./dir/module".into(),
                    )]),
                    ..ImporterSnapshot::default()
                },
            )]),
            ..Lockfile::default()
        };

        let (importer, diagnostics) = normalize_importer(
            "playground/alias",
            &lockfile,
            &BTreeMap::from([(
                "aliased-module".into(),
                "playground/alias/dir/module".into(),
            )]),
        );

        let target = &importer.direct_dependencies[0].target;
        assert_eq!(target.kind, TargetKind::External);
        assert_eq!(target.name.as_deref(), Some("aliased-module"));
        assert_eq!(
            target.path.as_deref(),
            Some("file:playground/alias/dir/module")
        );
        assert!(diagnostics.is_empty(), "{diagnostics:#?}");
    }

    #[test]
    fn file_dependency_uses_the_target_manifest_name_as_an_external_boundary() {
        let lockfile = Lockfile::default();
        let package_ids = BTreeMap::new();
        let workspace_packages =
            BTreeMap::from([("@fixture/target".into(), "fixtures/target".into())]);
        let mut diagnostics = Vec::new();

        let target = direct_target(
            ".",
            "aliased-target",
            "aliased-target",
            "file:fixtures/target",
            &lockfile,
            &package_ids,
            &workspace_packages,
            &mut diagnostics,
        );

        assert!(diagnostics.is_empty());
        assert_eq!(target.kind, TargetKind::External);
        assert_eq!(target.name.as_deref(), Some("@fixture/target"));
        assert_eq!(target.path.as_deref(), Some("file:fixtures/target"));
        assert!(target.instance.is_none());
    }
}
